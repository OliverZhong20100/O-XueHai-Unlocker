# -*- coding: utf-8 -*-
"""reg_parse.py [seconds] -- decode the pad's push AUTHORIZATION frame.

The pad's Authorization carries (in order, each 1-byte length + UTF-8):
accessKey, deviceId, clientId, signature, token, uid, tags
`uid` is exactly String.valueOf(PushConfig.getUserId()) -- i.e. the value
LauncherPushService compares PushMessage.getUserId() against.

If no registration shows up within `force_after` seconds, a spoofed RST is sent
to the pad's current push flow so the SDK reconnects and re-registers.

Admin required.
"""
import sys, os, time, datetime, struct, warnings
warnings.filterwarnings("ignore")
from scapy.all import IP, TCP, Raw, conf, AsyncSniffer
from scapy.arch.windows import get_windows_if_list

BASE = os.path.dirname(os.path.abspath(__file__))
PAD_MAC = "80:20:fd:8b:4b:fa"
ICS_MAC = "8c:81:2b:20:7b:42"
IFINDEX = 30
PORT = 3200
SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 120
FORCE_AFTER = int(os.environ.get("FORCE_AFTER") or 12)
LOG = os.path.join(BASE, "reg_parse.log")


def wlog(s):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], s)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def iface_name():
    for d in get_windows_if_list():
        if d.get("index") == IFINDEX:
            return r"\Device\NPF_" + d["guid"]


_sock = None


def send(frame):
    global _sock
    if _sock is None:
        _sock = conf.L2socket(iface=iface_name())
    _sock.send(frame)


def frame_len(b):
    """Return (n, value) for a header's 4th byte, or (None, None)."""
    if len(b) < 4:
        return None, None
    lb = b[3]
    n = (lb >> 6) & 3
    if len(b) < 4 + n:
        return n, None
    val = lb & 0x3F
    if n:
        val = (val << (8 * n)) | int.from_bytes(b[4:4 + n], "big")
    return n, val


def parse_auth(content):
    pos = 0
    out = []
    names = ["accessKey", "deviceId", "clientId", "signature", "token", "uid", "tags"]
    while pos < len(content) and len(out) < len(names):
        ln = content[pos]
        pos += 1
        if pos + ln > len(content):
            break
        val = content[pos:pos + ln]
        pos += ln
        try:
            out.append(val.decode("utf-8", "replace"))
        except Exception:
            out.append(repr(val))
    res = {}
    for i, v in enumerate(out):
        res[names[i] if i < len(names) else "f%d" % i] = v
    res["_rest"] = content[pos:].hex()
    return res


flows = {}   # sport -> dict
live = {}    # sport -> latest pad->cloud state (any packet)
seen = [0]


def on_pkt(p):
    try:
        if not (p.haslayer(TCP) and p.haslayer(IP)):
            return
        ip, t = p[IP], p[TCP]
        if not ip.src.startswith("192.168.137.") or t.dport != PORT:
            return
        live[t.sport] = {"pad": ip.src, "cloud": ip.dst, "ack": t.ack,
                         "seq": t.seq, "ts": time.time()}
        pl = bytes(t.payload) if t.payload else b""
        if not pl:
            return
        seen[0] += 1
        n, val = frame_len(pl)
        if n is None or val is None:
            return
        body = val - 3
        total_needed = 4 + n + body
        content = pl[4 + n:]
        cmd = pl[2]
        flows[t.sport] = {"seq": t.seq, "len": len(pl), "ack": t.ack,
                          "cloud": ip.dst, "pad": ip.src}
        if cmd == 0x02:
            info = parse_auth(content[:body])
            wlog("REG sport=%d framelen=%d body=%d" % (t.sport, len(pl), body))
            for k in ["accessKey", "deviceId", "clientId", "signature", "token", "uid", "tags"]:
                if k in info:
                    wlog("   %-10s = %r" % (k, info[k]))
            wlog("   rest_hex = %s" % info.get("_rest", ""))
            wlog("   FULL_HEX = %s" % pl.hex())
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def force_rst():
    """Send a RST from the cloud side into the pad's newest push flow."""
    if not live:
        return False
    sport = max(live, key=lambda k: live[k]["ts"])
    st = live[sport]
    send(Ether(dst=PAD_MAC, src=ICS_MAC) /
         IP(src=st["cloud"], dst=st["pad"], ttl=64) /
         TCP(sport=PORT, dport=sport, flags="R", seq=st["ack"], ack=st["seq"]))
    wlog("RST sent -> %s:%d seq=%08x" % (st["pad"], sport, st["ack"]))
    return True


def main():
    wlog("===== reg_parse start %s secs=%d force=%d =====" %
         (datetime.datetime.now(), SECS, FORCE_AFTER))
    sn = AsyncSniffer(iface=iface_name(), store=False, prn=on_pkt, filter="ip")
    sn.start()
    t0 = time.time()
    forced = False
    while time.time() - t0 < SECS:
        time.sleep(2)
        if not forced and time.time() - t0 > FORCE_AFTER:
            forced = True
            if not flows:
                force_rst()
            else:
                wlog("already got a registration, no RST needed")
    sn.stop()
    wlog("[end] packets_with_payload=%d flows=%s" % (seen[0], list(flows.keys())))


if __name__ == "__main__":
    main()
