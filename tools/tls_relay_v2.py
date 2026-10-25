#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tls_relay_v2.py — 443/8443 SNI 分流中继（passthrough / mitm 双模）

相比 v1 的三处关键改进:
  R2  SNI 分流: 命中 mitm_sni.txt 的域名走【本地 TLS 终止 MITM】, 其余透传真云
  R2  模式热切换: relay_mode.txt 内容 passthrough|mitm, 免重启生效
  R1  心跳文件: 每 5s 写 relay_v2.heartbeat, 供 orchestrator 做存活巡检

用法:
  python tls_relay_v2.py
  切 MITM :  echo mitm > relay_mode.txt          （验证证书信任 / 抓 assist）
  回透传   :  echo passthrough > relay_mode.txt  （保证平板日常可用）

红线: 不动网卡 / 不改路由 / 不断平板 WiFi; 纯用户态端口转发, kill 即回滚。
"""
import os
import socket
import ssl
import select
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "tls_relay_v2.log")
MODE_FILE = os.path.join(BASE, "relay_mode.txt")
SNI_FILE = os.path.join(BASE, "mitm_sni.txt")
HEARTBEAT = os.path.join(BASE, "relay_v2.heartbeat")

UPSTREAM_HOST = os.environ.get("RELAY_UPSTREAM", "47.110.67.143")
UPSTREAM_PORT = int(os.environ.get("RELAY_UPSTREAM_PORT", "443"))
LISTEN_PORTS = [int(x) for x in os.environ.get("RELAY_PORTS", "443,8443").split(",")]
MITM_BACKEND = ("127.0.0.1", int(os.environ.get("MITM_BACKEND_PORT", "8000")))

# 默认 MITM 目标: 全部云域(装 CA 后应全部落入本地); 透传模式下本列表不生效
DEFAULT_MITM_SNI = [
    "ztp.yunzuoye.net",
    "ms.yunzuoye.net",
    "logdata.yunzuoye.net",
    "trackdata.yunzuoye.net",
    "bigdata.yunzuoye.net",
]

_lock = threading.Lock()
STATS = {"conn": 0, "pass": 0, "mitm": 0, "mitm_ok": 0, "fail": 0, "sni": {}}


def ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    line = f"{ts()} {msg}\n"
    with _lock:
        try:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass


def find_cert():
    """探测可用的服务端证书/私钥"""
    cands = [
        ("server.crt", "server.key"),
        ("server.pem", "server.key"),
        ("fullchain.pem", "privkey.pem"),
        ("cert.pem", "key.pem"),
    ]
    for c, k in cands:
        cp, kp = os.path.join(BASE, c), os.path.join(BASE, k)
        if os.path.exists(cp) and os.path.exists(kp):
            return cp, kp
    return None, None


def get_cfg():
    """每次调用热重载配置(模式 + SNI 列表), 失败回落安全值"""
    mode = "passthrough"
    try:
        with open(MODE_FILE, "r", encoding="utf-8") as f:
            v = f.read().strip().lower()
            if v in ("mitm", "passthrough"):
                mode = v
    except OSError:
        pass
    sni_list = DEFAULT_MITM_SNI
    try:
        with open(SNI_FILE, "r", encoding="utf-8") as f:
            items = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if items:
                sni_list = items
    except OSError:
        pass
    return {"mode": mode, "mitm_sni": set(sni_list)}


def parse_sni(data):
    """从 TLS ClientHello 提取 SNI(尽力而为, 失败返回 None)"""
    try:
        if len(data) < 44 or data[0] != 0x16:
            return None
        pos = 5 + 4 + 2 + 32
        sid_len = data[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cs_len
        cm_len = data[pos]
        pos += 1 + cm_len
        if pos + 2 > len(data):
            return None
        ext_total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(pos + ext_total, len(data))
        while pos + 4 <= end:
            et = int.from_bytes(data[pos:pos + 2], "big")
            el = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if et == 0 and pos + 5 <= len(data):
                p = pos + 2
                nl = int.from_bytes(data[p + 1:p + 3], "big")
                return data[p + 3:p + 3 + nl].decode("ascii", "ignore")
            pos += el
    except Exception:
        return None
    return None


def bidir(a, b, tag=""):
    """双向转发直到任一端关闭"""
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 120)
            if not r:
                break
            for s in r:
                chunk = s.recv(65536)
                if not chunk:
                    return
                (b if s is a else a).sendall(chunk)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


def make_ssl_ctx():
    cp, kp = find_cert()
    if not cp:
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cp, kp)
        return ctx
    except Exception as e:
        log(f"[MITM-ERR] load cert failed: {e}")
        return None


_SSL_CTX = None
_SSL_CTX_LOCK = threading.Lock()


def ssl_ctx():
    global _SSL_CTX
    with _SSL_CTX_LOCK:
        if _SSL_CTX is None:
            _SSL_CTX = make_ssl_ctx()
        return _SSL_CTX


import struct as _st

REAL_DNS_SERVERS = [("223.5.5.5", 53), ("119.29.29.29", 53), ("114.114.114.114", 53)]
_REAL_CACHE = {}
_REAL_CACHE_LOCK = threading.Lock()
_FALLBACK_REAL = {"yunzuoye.net": "47.99.85.219"}
LOCAL_ALIASES = {"47.99.85.219", "47.111.87.154", "47.111.168.116", "39.173.108.47", "52.80.72.178"}


def _dns_query_a(host, timeout=2.0):
    """自建 UDP DNS 查询: 绕开本机被劫持的 53 端口解析"""
    tid = 0x4D76
    q = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in host.split("."):
        q += bytes([len(part)]) + part.encode("ascii")
    q += b"\x00" + _st.pack(">HH", 1, 1)
    for srv in REAL_DNS_SERVERS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(q, srv)
            r, _ = s.recvfrom(4096)
            if len(r) < 12:
                continue
            rid, _fl, qd, an, _ns, _ar = _st.unpack(">HHHHHH", r[:12])
            if rid != tid or an == 0:
                continue
            pos = 12
            for _i in range(qd):
                while pos < len(r) and r[pos]:
                    pos += 1 + r[pos]
                pos += 1 + 4
            for _i in range(an):
                if pos + 2 > len(r):
                    break
                if r[pos] & 0xC0 == 0xC0:
                    pos += 2
                else:
                    while pos < len(r) and r[pos]:
                        pos += 1 + r[pos]
                    pos += 1
                if pos + 10 > len(r):
                    break
                atype, _ac, _ttl, rdlen = _st.unpack(">HHIH", r[pos:pos + 10])
                pos += 10
                if atype == 1 and rdlen == 4 and pos + 4 <= len(r):
                    return ".".join(str(b) for b in r[pos:pos + 4])
                pos += rdlen
        except Exception:
            pass
        finally:
            s.close()
    return None


def resolve_real(sni):
    """passthrough 时按 SNI 解析真云 IP(带 5 分钟缓存 + 域名兜底)"""
    if not sni:
        return None
    now = time.time()
    with _REAL_CACHE_LOCK:
        hit = _REAL_CACHE.get(sni)
        if hit and now - hit[1] < 300:
            return hit[0]
    ip = _dns_query_a(sni)
    if ip:
        with _REAL_CACHE_LOCK:
            _REAL_CACHE[sni] = (ip, now)
        return ip
    for suf, fb in _FALLBACK_REAL.items():
        if sni.endswith(suf):
            log(f"[REAL-DNS-FALLBACK] {sni} -> {fb}")
            return fb
    return None


# === 接管模式开关（默认关闭，不改变现有行为）===
# 设置环境变量 RELAY_BLOCK_SUFFIX="yunzuoye.net" 后：
#   凡 SNI 命中该后缀的 443 连接，直接断开，不再透传到真云。
#   目的：端侧 443 失败后回落 80 明文兜底地址（http://control.yunzuoye.net /
#   http://pnlogin.yunzuoye.net / http://ztp.yunzuoye.net 明文面），由本机 cloud_api 接管。
RELAY_BLOCK_SUFFIX = os.environ.get("RELAY_BLOCK_SUFFIX", "").strip()
# 文件开关兜底：supervisor 经 WMI Create 拉起子进程时不继承调用者环境变量，
# 故支持同目录 relay_block_suffix.txt（内容即后缀，例如 yunzuoye.net）。删除该文件即关闭。
BLOCK_SUFFIX_FILE = os.path.join(BASE, "relay_block_suffix.txt")
if not RELAY_BLOCK_SUFFIX and os.path.exists(BLOCK_SUFFIX_FILE):
    try:
        with open(BLOCK_SUFFIX_FILE, encoding="utf-8") as _f:
            RELAY_BLOCK_SUFFIX = _f.read().strip()
    except OSError:
        pass


def handle_passthrough(cs, addr, sni):
    """透传真云: 端侧与真云端到端 TLS, 我们只做字节搬运"""
    if RELAY_BLOCK_SUFFIX and sni and sni.endswith(RELAY_BLOCK_SUFFIX):
        log(f"[BLOCK-SUFFIX] {addr[0]} sni={sni!r} 命中阻断名单({RELAY_BLOCK_SUFFIX}), 直接断开以迫使端侧回落80明文")
        try:
            cs.close()
        except Exception:
            pass
        return
    try:
        cs.settimeout(10)
        first = cs.recv(4096)
        if not first:
            cs.close()
            return
        target = resolve_real(sni) or UPSTREAM_HOST
        if target in LOCAL_ALIASES:
            # 解析落点命中本机别名 IP（DNS 劫持预留），无法直连；回退到可达真云上游，避免平板 HTTPS 全断
            log("[LOOP-GUARD-FALLBACK] %s -> %s 命中本地别名, 改走上游 %s" % (sni, target, UPSTREAM_HOST))
            target = UPSTREAM_HOST
            if target in LOCAL_ALIASES:
                log("[LOOP-GUARD] %s 上游 %s 也是本地别名, 跳过(防自环)" % (sni, target))
                try:
                    cs.close()
                except Exception:
                    pass
                return
        us = socket.create_connection((target, UPSTREAM_PORT), timeout=8)
        us.settimeout(None)
        cs.settimeout(None)
        us.sendall(first)
        with _lock:
            STATS["pass"] += 1
        log(f"[RELAY-PASS] {addr[0]} sni={sni!r} -> {target}:{UPSTREAM_PORT}")
        bidir(cs, us, "pass")
    except Exception as e:
        with _lock:
            STATS["fail"] += 1
        log(f"[RELAY-FAIL] {addr[0]} sni={sni!r} {type(e).__name__}: {e}")
        try:
            cs.close()
        except Exception:
            pass


def handle_mitm(cs, addr, sni):
    """本地 TLS 终止: 用我们的证书应答, 明文 HTTP 转发到 cloud_api"""
    ctx = ssl_ctx()
    if ctx is None:
        # 无证书则退回透传, 保证不中断
        log(f"[MITM-SKIP] {addr[0]} sni={sni!r} 无可用证书, 退回透传")
        return handle_passthrough(cs, addr, sni)
    try:
        cs.settimeout(15)
        tls = ctx.wrap_socket(cs, server_side=True)
    except ssl.SSLError as e:
        with _lock:
            STATS["fail"] += 1
        # certificate_unknown = 端侧不信任我们的 CA —— 这是路 A 的判定信号
        log(f"[MITM-TLSFAIL] {addr[0]} sni={sni!r} {type(e).__name__}: {e}")
        try:
            cs.close()
        except Exception:
            pass
        return
    except Exception as e:
        log(f"[MITM-ERR] {addr[0]} sni={sni!r} {type(e).__name__}: {e}")
        try:
            cs.close()
        except Exception:
            pass
        return

    with _lock:
        STATS["mitm"] += 1
    try:
        tls.settimeout(15)
        # 读取首个 HTTP 请求(含 body 由 bidir 继续搬运)
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 65536:
            chunk = tls.recv(4096)
            if not chunk:
                break
            head += chunk
        req_line = head.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
        with _lock:
            STATS["mitm_ok"] += 1
        log(f"[MITM-HIT] {addr[0]} sni={sni!r} {req_line}")

        be = socket.create_connection(MITM_BACKEND, timeout=8)
        be.settimeout(None)
        if head:
            be.sendall(head)
        bidir(tls, be, "mitm")
    except Exception as e:
        log(f"[MITM-FAIL] {addr[0]} sni={sni!r} {type(e).__name__}: {e}")
        try:
            tls.close()
        except Exception:
            pass


def handle(cs, addr):
    sni = None
    try:
        cs.settimeout(10)
        # MSG_PEEK: 窥探 ClientHello 但不消费, 保证后续握手/转发数据完整
        peek = cs.recv(4096, socket.MSG_PEEK)
        if not peek:
            cs.close()
            return
        sni = parse_sni(peek)
        if sni is None:
            sni = parse_sni(cs.recv(8192, socket.MSG_PEEK))

        with _lock:
            STATS["conn"] += 1
            if sni:
                STATS["sni"][sni] = STATS["sni"].get(sni, 0) + 1

        cfg = get_cfg()
        if cfg["mode"] == "mitm" and sni and sni in cfg["mitm_sni"]:
            handle_mitm(cs, addr, sni)
        else:
            handle_passthrough(cs, addr, sni)
    except Exception as e:
        with _lock:
            STATS["fail"] += 1
        log(f"[RELAY-ERR] {addr[0]} sni={sni!r} {type(e).__name__}: {e}")
        try:
            cs.close()
        except Exception:
            pass


def listen(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError as e:
        log(f"[RELAY-ERR] bind :{port} failed: {e}")
        print(f"[RELAY-ERR] bind :{port} failed: {e}", flush=True)
        return
    srv.listen(256)
    log(f"[RELAY-UP] :{port} -> upstream={UPSTREAM_HOST}:{UPSTREAM_PORT} backend={MITM_BACKEND}")
    print(f"tls_relay_v2 listening :{port}", flush=True)
    while True:
        try:
            cs, addr = srv.accept()
        except OSError:
            continue
        threading.Thread(target=handle, args=(cs, addr), daemon=True).start()


def heartbeat_loop():
    while True:
        try:
            with open(HEARTBEAT, "w", encoding="utf-8") as f:
                f.write(str(int(time.time())))
        except OSError:
            pass
        time.sleep(5)


def main():
    log("=" * 50)
    cp, kp = find_cert()
    log(f"tls_relay_v2 start cert={cp} ports={LISTEN_PORTS} backend={MITM_BACKEND}")
    if not cp:
        log("[MITM-WARN] 未找到 server.crt/server.key, MITM 将不可用(自动透传)")
    try:
        with open(MODE_FILE, "r", encoding="utf-8") as f:
            log(f"mode={f.read().strip()!r}")
    except OSError:
        with open(MODE_FILE, "w", encoding="utf-8") as f:
            f.write("passthrough")
        log("mode 文件不存在, 已初始化为 passthrough")

    threading.Thread(target=heartbeat_loop, daemon=True).start()
    for p in LISTEN_PORTS:
        threading.Thread(target=listen, args=(p,), daemon=True).start()

    # 每 60s 打印一次统计, 便于遥测
    while True:
        time.sleep(60)
        with _lock:
            snap = dict(STATS)
        log(f"[STATS] {snap}")


if __name__ == "__main__":
    main()
