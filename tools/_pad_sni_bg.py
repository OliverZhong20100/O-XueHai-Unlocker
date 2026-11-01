# -*- coding: utf-8 -*-
"""_pad_sni_bg.py — 后台抓 90 秒平板 443 ClientHello，写日志"""
import struct
import time

from scapy.all import IP, TCP, Raw, AsyncSniffer

PAD = "192.168.137.10"
LOG = r"C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest\pad_sni_capture.log"
t0 = time.time()


def parse_sni(buf):
    try:
        if len(buf) < 5 or buf[0] != 0x16:
            return None
        pos = 5 + 4 + 2 + 32
        sid_len = buf[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack(">H", buf[pos:pos + 2])[0]
        pos += 2 + cs_len
        cm_len = buf[pos]
        pos += 1 + cm_len
        ext_total = struct.unpack(">H", buf[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            etype, elen = struct.unpack(">HH", buf[pos:pos + 4])
            pos += 4
            if etype == 0:
                p = pos + 2
                ntype = buf[p]
                nlen = struct.unpack(">H", buf[p + 1:p + 3])[0]
                if ntype == 0:
                    return buf[p + 3:p + 3 + nlen].decode("ascii", "replace")
            pos += elen
    except Exception:
        return None
    return None


seen = set()


def cb(p):
    if time.time() - t0 > 90:
        return
    try:
        if not (p.haslayer(IP) and p[IP].src == PAD and p.haslayer(TCP)):
            return
        t = p[TCP]
        if t.dport != 443:
            return
        d = p[Raw].load if p.haslayer(Raw) else b""
        flags = int(t.flags)
        line = ""
        if d and d[0] == 0x16:
            sni = parse_sni(d)
            line = "CH dst=%s:%d sni=%s" % (p[IP].dst, t.dport, sni if sni else "<NO-SNI>")
        elif flags & 0x02:
            line = "SYN dst=%s:%d" % (p[IP].dst, t.dport)
        if line and line not in seen:
            seen.add(line)
            with open(LOG, "a", encoding="utf-8") as f:
                f.write("%s %s\n" % (time.strftime("%H:%M:%S"), line))
    except Exception:
        pass


sn = AsyncSniffer(iface=r"\Device\NPF_{6E5C648D-1355-4F48-B5BA-047951DDDFA3}",
                  prn=cb, store=False, filter="host 192.168.137.10 and tcp")
sn.start()
time.sleep(90)
sn.stop()
with open(LOG, "a", encoding="utf-8") as f:
    f.write("%s DONE\n" % time.strftime("%H:%M:%S"))
