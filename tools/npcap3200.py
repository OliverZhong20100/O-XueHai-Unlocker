# -*- coding: utf-8 -*-
"""npcap3200.py -- 纯用户态 TCP 应答器: 用 npcap 在链路层完成"伪造源=真云IP"的
3200 明文协议通道, 复用 cloud_3200.classify_frame() 的注册/心跳应答规则。

为什么: WinDivert 注入伪造源帧被本机栈丢弃; npcap(NDIS)发送可穿透(已 A/B 实测,
平板对伪造 SYNACK 回 ACK 并上送 120B 注册帧)。故把 3200 整条链放到用户态完成:
  pad SYN(->47.99.85.219:3200)  -> 我们回 SYNACK(src=47.99.85.219:3200)
  pad ACK                       -> 建链
  pad REG(120B)                 -> 回 REG_RESP
  pad L7/HB                     -> 回 HB_RESP
全部不经过内核协议栈, 不碰 ICS 网卡配置。

用法: python npcap3200.py [watch_seconds]
"""
import sys, os, time, random, datetime, threading

import warnings
warnings.filterwarnings("ignore")
from scapy.all import Ether, IP, TCP, Raw, conf, AsyncSniffer
from scapy.arch.windows import get_windows_if_list

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cloud_3200 import classify_frame, REG_RESP, HB_RESP  # noqa: E402

def _detect_pad(mac="80:20:fd:8b:4b:fa"):
    """按平板 MAC 从 ARP 表解析其当前 IP, 解决 DHCP 漂移导致写死 IP 失效。"""
    import re as _re
    import subprocess as _sp
    want = mac.replace(":", "-").lower()
    try:
        out = _sp.check_output(["arp", "-a"], creationflags=0x08000000).decode("utf-8", "replace")
        for line in out.splitlines():
            if want in line.lower():
                m = _re.search(r"(192\.168\.137\.\d+)", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "192.168.137.73"


PAD = _detect_pad()
PAD_MAC = "80:20:fd:8b:4b:fa"

# 平板 IP 会在重启/DHCP 续租后漂移(历史: .35 -> .73)。按 MAC 周期重解析并就地更新
# 全局 PAD, 使 on_pkt 判定与日志始终跟随真机, 无需重启进程。
_pad_ttl = {"t": 0.0}


def pad_now():
    global PAD
    if time.time() - _pad_ttl["t"] > 20:
        _pad_ttl["t"] = time.time()
        new = _detect_pad()
        if new != PAD:
            wlog("PAD 漂移: %s -> %s (按 MAC 自动跟随)" % (PAD, new))
            PAD = new
    return PAD
ICS_MAC = "52:bb:b5:4f:7f:3e"
IFINDEX = 12
PORT = 3200
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 60
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "npcap3200.log")

_sock = None
_lock = threading.Lock()
flows = {}
stat = {"syn": 0, "est": 0, "rx_frames": 0, "tx_frames": 0, "dup": 0, "unknown": 0}


def wlog(s):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], s)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)


def iface_name():
    for d in get_windows_if_list():
        if d.get("index") == IFINDEX:
            return r"\Device\NPF_" + d["guid"]


def send(frame):
    global _sock
    if _sock is None:
        _sock = conf.L2socket(iface=iface_name())
    _sock.send(frame)


def emit(dst_ip, sport, dport, flags, seq, ack, payload=b""):
    pkt = (Ether(dst=PAD_MAC, src=ICS_MAC) /
           IP(src=dst_ip, dst=PAD, ttl=64) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240))
    if payload:
        pkt = pkt / Raw(payload)
    send(pkt)
    stat["tx_frames"] += 1


def on_pkt(p):
    try:
        if not (p.haslayer(TCP) and p.haslayer(IP)):
            return
        ip, t = p[IP], p[TCP]
        pad_now()
        if ip.src != PAD or t.dport != PORT:
            return
        cloud = ip.dst
        key = (cloud, t.sport)
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        f = flows.get(key)
        pl = bytes(t.payload) if t.payload else b""

        if t.flags & 0x02 and not t.flags & 0x10:  # SYN
            isn = random.randint(0x40000000, 0x7FFFFFFF)
            flows[key] = {"next": (t.seq + 1) & 0xFFFFFFFF, "mine": (isn + 1) & 0xFFFFFFFF,
                          "isn": isn, "est": False, "rx": 0, "log_buf": b""}
            stat["syn"] += 1
            emit(cloud, PORT, t.sport, "SA", isn, (t.seq + 1) & 0xFFFFFFFF)
            wlog("SYN %s:%d <- %s:%d -> SYNACK isn=%08x  (第%d次)" % (cloud, PORT, PAD, t.sport, isn, stat["syn"]))
            return

        if f is None:
            return

        # RST from pad
        if t.flags & 0x04:
            wlog("RST from pad %s:%d  (flow drop)" % (PAD, t.sport))
            flows.pop(key, None)
            return

        acked_us = (t.ack == f["mine"]) or ((t.ack - f["mine"]) & 0xFFFFFFFF) < 0x80000000
        if not f["est"] and t.flags & 0x10 and acked_us:
            f["est"] = True
            stat["est"] += 1
            wlog("ESTABLISHED %s:%d <-> %s:%d (pad ack=%08x ours=%08x)" % (cloud, PORT, PAD, t.sport, t.ack, f["mine"]))

        if pl:
            seq = t.seq
            if ((seq - f["next"]) & 0xFFFFFFFF) > 0x30000000:  # 重传/旧数据
                stat["dup"] += 1
                emit(cloud, PORT, t.sport, "A", f["mine"], f["next"])
                wlog("DUP seq=%08x (expect %08x) len=%d -> 仅ACK" % (seq, f["next"], len(pl)))
            else:
                if seq != f["next"]:
                    wlog("GAP seq=%08x expect=%08x len=%d (按序强制推进)" % (seq, f["next"], len(pl)))
                f["next"] = (seq + len(pl)) & 0xFFFFFFFF
                f["rx"] += len(pl)
                f["log_buf"] += pl
                stat["rx_frames"] += 1
                kind, resp = classify_frame(f["log_buf"])
                wlog("RX %s:%d <- %s:%d len=%d kind=%s hex=%s" % (cloud, PORT, PAD, t.sport, len(pl), kind, pl.hex()[:140]))
                emit(cloud, PORT, t.sport, "A", f["mine"], f["next"])
                if resp is not None:
                    emit(cloud, PORT, t.sport, "PA", f["mine"], f["next"], resp)
                    f["mine"] = (f["mine"] + len(resp)) & 0xFFFFFFFF
                    wlog("TX -> pad kind=%s %dB hex=%s" % (kind, len(resp), resp.hex()[:140]))
                else:
                    wlog("NO-RESP for kind=%s (仅记)" % kind)
                f["log_buf"] = b""
        elif t.flags & 0x01:  # FIN
            emit(cloud, PORT, t.sport, "FA", f["mine"], (t.seq + 1) & 0xFFFFFFFF)
            wlog("FIN from pad -> FINACK, 关流" % ())
            flows.pop(key, None)
        else:
            emit(cloud, PORT, t.sport, "A", f["mine"], f["next"])
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def main():
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n===== npcap3200 start %s watch=%ds =====\n" % (datetime.datetime.now(), WATCH))
    wlog("iface=%s 监听 pad=%s -> 端口 %d (BPF 不绑 IP, 漂移自愈)" % (iface_name(), PAD, PORT))
    # BPF 只按端口过滤, 不绑平板 IP: 否则重启/DHCP 换 IP 后过滤器会永久失配。
    sn = AsyncSniffer(iface=iface_name(), store=False, prn=on_pkt, filter="tcp and port %d" % PORT)
    sn.start()
    t0 = time.time()
    while time.time() - t0 < WATCH:
        time.sleep(5)
        wlog("[stat] %s" % stat)
    sn.stop()
    wlog("[end] %s" % stat)


if __name__ == "__main__":
    main()
