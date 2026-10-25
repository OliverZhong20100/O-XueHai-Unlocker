# -*- coding: utf-8 -*-
"""npcap_8089.py -- 链路层冒充 :8089 服务, 记录端侧的完整请求。

背景(2026-10-04 实测):
  pad_wide 抓到 39 次 `TCP out -> 47.111.168.116:8089 [S]` 且**零响应** ——
  端侧在死循环重试这个服务。被动嗅探只能看到 SYN; 要拿到它的 HTTP 请求体,
  必须在链路层冒充服务器把三次握手做完(与 npcap_http80 同一套手法)。

本脚本:
  1) 冒充 SYNACK / ACK, 完成握手;
  2) 把端侧的完整请求(方法/路径/全部头/body hex+ascii)落盘;
  3) 回 200 OK + "{}" 保持连接可用(可用 HTTP8089_RESP 环境变量改应答体)。

用法: python npcap_8089.py [watch_seconds]
"""
import datetime
import json
import os
import random
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scapy.all import Ether, IP, Raw, TCP, AsyncSniffer   # noqa: E402
from scapy.config import conf                            # noqa: E402

import npcap_http80 as H                                 # noqa: E402

PORT = int(os.environ.get("HTTP8089_PORT") or 8089)
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 3600
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "npcap_8089.log")
RESP_BODY = (os.environ.get("HTTP8089_RESP") or "{}").encode("utf-8")

stat = {"syn": 0, "est": 0, "req": 0, "resp": 0, "dst": {}}
flows = {}
_sock = None
_lock = None
import threading                                          # noqa: E402
_lock = threading.Lock()


def wlog(msg):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], msg)
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


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
    stat["resp"] += 1


def http_resp(body):
    head = ("HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json; charset=UTF-8\r\n"
            "Content-Length: %d\r\n"
            "Connection: keep-alive\r\n\r\n" % len(body))
    return head.encode("utf-8") + body


def decode_body(raw):
    """尽力解码端侧上报体: 可能是 urlencoded / base64 / gzip 的任意组合。"""
    out = []
    txt = raw.decode("latin1", "replace")
    # 1) urlencoded 表单
    try:
        from urllib.parse import parse_qsl, unquote_plus
    except Exception:
        parse_qsl = None
    cands = []
    if parse_qsl is not None and "=" in txt:
        try:
            for k, v in parse_qsl(txt[:4000], keep_blank_values=True):
                cands.append((k, v))
        except Exception:
            pass
    if cands:
        out.append("form keys=%s" % [k for k, _ in cands][:20])
        for k, v in cands[:6]:
            out.append("  %s = %s" % (k, v[:160]))
            cands_b64 = v
            break
    else:
        cands_b64 = txt
    # 2) base64 -> gzip/zlib/plain
    import base64 as _b64
    import gzip as _gz
    import zlib as _zl
    s = "".join(cands_b64.split())
    for tag, dec in (("url", lambda x: unquote_plus(x)), ("raw", lambda x: x)):
        t = dec(s)
        pad = (-len(t)) % 4
        try:
            b = _b64.b64decode(t + "=" * pad, validate=False)
        except Exception:
            continue
        for name, fn in (("gzip", lambda x: _gz.decompress(x)),
                         ("zlib", lambda x: _zl.decompress(x)),
                         ("deflate-raw", lambda x: _zl.decompress(x, -15))):
            try:
                d = fn(b)
                out.append("[%s/%s] 解压成功 %d B -> %s" % (tag, name, len(d), d[:1500].decode("utf-8", "replace")))
                return "\n".join(out)
            except Exception:
                pass
        out.append("[%s] base64 解出 %d B, 无压缩头, 前 300B: %s" % (
            tag, len(b), b[:300].decode("utf-8", "replace")))
    return "\n".join(out) if out else "(无法解码)"


def on_pkt(p):
    try:
        if not (p.haslayer(TCP) and p.haslayer(IP)):
            return
        ip, t = p[IP], p[TCP]
        pad = H.pad_now()
        if ip.src != pad or t.dport != PORT:
            return
        server = ip.dst
        key = (server, t.sport)
        f = flows.get(key)
        pl = bytes(t.payload) if t.payload else b""

        if t.flags & 0x02 and not t.flags & 0x10:      # SYN
            isn = random.randint(0x40000000, 0x7FFFFFFF)
            flows[key] = {"next": (t.seq + 1) & 0xFFFFFFFF,
                          "mine": (isn + 1) & 0xFFFFFFFF, "est": False,
                          "buf": b"", "head": None, "clen": 0, "body": b""}
            stat["syn"] += 1
            stat["dst"][server] = stat["dst"].get(server, 0) + 1
            emit(server, PORT, t.sport, "SA", isn, (t.seq + 1) & 0xFFFFFFFF)
            wlog("SYN %s:%d <- %s:%d -> 冒充 SYNACK (第%d次)" % (
                server, PORT, pad, t.sport, stat["syn"]))
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

        if pl:
            f["next"] = (t.seq + len(pl)) & 0xFFFFFFFF
            f["buf"] += pl
            emit(server, PORT, t.sport, "A", f["mine"], f["next"])

            # 【修正】按 Content-Length 严格取 body, 不再用 \r\n\r\n 猜测,
            # 否则 body 内部的 \r\n\r\n 会被误判成"新请求头"(之前 body 全丢)。
            if f["head"] is None:
                i = f["buf"].find(b"\r\n\r\n")
                if i < 0:
                    return
                f["head"] = f["buf"][:i]
                f["buf"] = f["buf"][i + 4:]
                m = re.search(rb"content-length:\s*(\d+)", f["head"], re.I)
                f["clen"] = int(m.group(1)) if m else 0
                stat["req"] += 1
                wlog("=== 请求 #%d  头部 %d B, 声明 body %d B ===\n%s" % (
                    stat["req"], len(f["head"]), f["clen"],
                    f["head"].decode("utf-8", "replace")))

            if f["head"] is not None:
                if f["clen"] == 0 or len(f["buf"]) >= f["clen"]:
                    body = f["buf"][:f["clen"]] if f["clen"] else f["buf"]
                    f["buf"] = f["buf"][f["clen"]:] if f["clen"] else b""
                    # 【落盘完整 body】之前的日志只留 400 字节 hex, 不够解码;
                    # 这里把原始 body 存成文件, 供离线还原(gzip+base64)。
                    try:
                        bodir = os.path.join(BASE, "up_bodies")
                        os.makedirs(bodir, exist_ok=True)
                        bp = os.path.join(bodir, "req%03d_%d.bin" % (stat["req"], len(body)))
                        with open(bp, "wb") as bf:
                            bf.write(body)
                    except Exception as e:
                        wlog("body 落盘失败: %s" % e)
                    wlog("--- 请求 #%d 完整 body %d B (已落盘) ---\n%s\n--- body hex(前 400) ---\n%s" % (
                        stat["req"], len(body), decode_body(body), body[:400].hex()))
                    data = http_resp(RESP_BODY)
                    emit(server, PORT, t.sport, "PA", f["mine"], f["next"], data)
                    f["mine"] = (f["mine"] + len(data)) & 0xFFFFFFFF
                    f["head"] = None
                    f["clen"] = 0
        elif t.flags & 0x01:
            emit(server, PORT, t.sport, "FA", f["mine"], (t.seq + 1) & 0xFFFFFFFF)
            flows.pop(key, None)
        else:
            emit(server, PORT, t.sport, "A", f["mine"], f["next"])
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def main():
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n===== npcap_8089 start %s port=%d watch=%ds resp=%r =====\n" % (
            datetime.datetime.now(), PORT, WATCH, RESP_BODY))
    wlog("iface=%s pad=%s 冒充 :%d" % (H.iface_name(), H.pad_now(), PORT))
    sn = AsyncSniffer(iface=H.iface_name(), store=False, prn=on_pkt,
                      filter="tcp and port %d" % PORT)
    sn.start()
    t0 = time.time()
    while time.time() - t0 < WATCH:
        time.sleep(10)
        wlog("[stat] %s" % json.dumps(stat, ensure_ascii=False))
    sn.stop()
    wlog("[end] %s" % stat)


if __name__ == "__main__":
    main()
