# -*- coding: utf-8 -*-
"""watch_pad.py [seconds] -- log every *meaningful* pad packet, with TLS SNI.

Purpose: detect whether a pushed assist-notify actually causes the pad to open
a NEW TCP connection (requestAssistTask -> HTTP(S) to the assist base URL).
Logs: new SYN, any segment carrying payload, TLS ClientHello SNI, UDP/ICMP counts.
Admin required (Npcap capture is admin-only).
"""
import sys, os, time, datetime, warnings
from collections import Counter
warnings.filterwarnings("ignore")
from scapy.all import IP, TCP, UDP, conf, AsyncSniffer
from scapy.arch.windows import get_windows_if_list

BASE = os.path.dirname(os.path.abspath(__file__))
IFINDEX = 30
PAD_IP_FALLBACK = "192.168.137.13"
PAD_MAC = "02:00:00:00:00:01"
SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 300
LOG = os.path.join(BASE, "watch_pad.log")

seen_hosts = set()
cnt = Counter()


def iface_name():
    for d in get_windows_if_list():
        ips = d.get("ips") or []
        if any(str(x).startswith("192.168.137.1") for x in ips):
            wlog("hotspot iface idx=%s guid=%s ips=%s" % (d.get("index"), d.get("guid"), ips))
            return r"\Device\NPF_" + d["guid"]
    for d in get_windows_if_list():
        if d.get("index") == IFINDEX:
            return r"\Device\NPF_" + d["guid"]


def wlog(s):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], s)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def sni_of(payload):
    """Best-effort TLS ClientHello SNI extraction."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        b = payload
        if b[5] != 0x01:
            return None
        i = 9 + 2 + 32  # skip record hdr, handshake hdr, version, random
        if i >= len(b):
            return None
        sid_len = b[i]; i += 1 + sid_len
        if i + 2 > len(b):
            return None
        cs_len = int.from_bytes(b[i:i + 2], "big"); i += 2 + cs_len
        if i >= len(b):
            return None
        cm_len = b[i]; i += 1 + cm_len
        if i + 2 > len(b):
            return None
        ext_len = int.from_bytes(b[i:i + 2], "big"); i += 2
        end = min(len(b), i + ext_len)
        while i + 4 <= end:
            et = int.from_bytes(b[i:i + 2], "big")
            el = int.from_bytes(b[i + 2:i + 4], "big")
            i += 4
            if et == 0x0000:  # server_name
                seg = b[i:i + el]
                if len(seg) >= 5:
                    nl = int.from_bytes(seg[3:5], "big")
                    return seg[5:5 + nl].decode("utf-8", "replace")
            i += el
    except Exception:
        pass
    return None


def on_pkt(p):
    try:
        if not p.haslayer(IP):
            return
        ip = p[IP]
        pad_in = ip.src == PAD_IP_FALLBACK
        pad_out = ip.dst == PAD_IP_FALLBACK
        if not (pad_in or pad_out):
            return
        if p.haslayer(TCP):
            t = p[TCP]
            pl = bytes(t.payload) if t.payload else b""
            fl = str(t.flags)
            if "S" in fl and "A" not in fl:
                key = "%s:%d -> %s:%d" % (ip.src, t.sport, ip.dst, t.dport)
                cnt["SYN " + key] += 1
                wlog("SYN  %s:%d -> %s:%d" % (ip.src, t.sport, ip.dst, t.dport))
                return
            if pl:
                key = "%s:%d -> %s:%d" % (ip.src, t.sport, ip.dst, t.dport)
                cnt["DATA " + key] += 1
                tag = ""
                if pad_in and t.dport == 443:
                    s = sni_of(pl)
                    if s:
                        tag = " SNI=%s" % s
                wlog("DATA %s:%d -> %s:%d len=%d%s" % (ip.src, t.sport, ip.dst, t.dport, len(pl), tag))
            else:
                cnt["ACK+"] += 1
        elif p.haslayer(UDP):
            u = p[UDP]
            cnt["UDP %d->%d" % (u.sport, u.dport)] += 1
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def main():
    wlog("===== watch_pad start %s secs=%d =====" % (datetime.datetime.now(), SECS))
    sn = AsyncSniffer(iface=iface_name(), store=False, prn=on_pkt, filter="ip")
    sn.start()
    t0 = time.time()
    while time.time() - t0 < SECS:
        time.sleep(15)
        wlog("[stat] %s" % dict(cnt.most_common(12)))
    sn.stop()
    wlog("[end] %s" % dict(cnt.most_common(40)))


if __name__ == "__main__":
    main()
