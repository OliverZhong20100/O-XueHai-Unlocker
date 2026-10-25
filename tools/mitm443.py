# -*- coding: utf-8 -*-
"""mitm443.py — 443 上的真·TLS 中间人(可读可改)。

与 tls_passthrough 的区别:
  · 直通: 只按 SNI 转发, 看不到内容
  · 本脚本: 用自签 CA 给每个 SNI 现签证书, 终止 TLS, 于是能【读到并改写】App 的全部 HTTPS
            (业务 API 全在 ms.yunzuoye.net / smarterclassgray.yunzuoye.net 等)

工作方式:
  1) 监听 443, 读 ClientHello 取 SNI
  2) 用 mitm_ca 现签该域名的叶子证书(缓存), 与本机 App 完成 TLS
  3) 解析 HTTP/1.1 请求:
       · 命中 CONTROL 规则  -> 回我们的应答(即可驱动 App: 版本变更/升级包/应用列表/资源地址)
       · 其它               -> 用真实 IP 建 TLS 转发(保证 App 仍正常)
  4) 全程落盘 mitm443.log + mitm_capture.log(请求/响应摘要, 用于找 token/接口)

前置: 平板需安装 mitm_ca/ca.pem(设置 -> 安全 -> 从存储安装 -> 应用/VPN 证书)
"""
import datetime
import io
import os
import socket
import ssl
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BASE = os.path.dirname(os.path.abspath(__file__))
CA_DIR = os.path.join(BASE, "mitm_ca")
LOG = os.path.join(BASE, "mitm443.log")
CAP = os.path.join(BASE, "mitm_capture.log")
LEAF_DIR = os.path.join(CA_DIR, "leaf")
PORT = int(os.environ.get("MITM_PORT") or 443)
WATCH_H = int(os.environ.get("MITM_WATCH_H") or 12)

os.makedirs(LEAF_DIR, exist_ok=True)
_CA_CERT = x509.load_pem_x509_certificate(io.open(os.path.join(CA_DIR, "ca.pem"), "rb").read())
_CA_KEY = serialization.load_pem_private_key(
    io.open(os.path.join(CA_DIR, "ca.key"), "rb").read(), password=None)

_stat = {"conn": 0, "tls_ok": 0, "tls_fail": 0, "req": 0, "sni": {}, "ctl": 0, "fwd": 0}
_lock = threading.Lock()
_leaf_cache = {}


def wlog(m):
    with io.open(LOG, "a", encoding="utf-8") as f:
        f.write("%s %s\n" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], m))


def wcap(m):
    with io.open(CAP, "a", encoding="utf-8") as f:
        f.write("%s %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), m))


def dns_public(host, servers=("223.5.5.5", "114.114.114.114", "8.8.8.8")):
    """绕开 hosts 自环, 用公共 DNS 拿真实 IP。"""
    import random
    import struct
    q = b"".join(struct.pack("!B", len(p)) + p.encode() for p in host.split(".")) + b"\x00"
    pkt = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    for srv in servers:
        try:
            s.sendto(pkt, (srv, 53))
            data, _ = s.recvfrom(2048)
        except Exception:
            continue
        finally:
            pass
        try:
            ancount = struct.unpack("!H", data[6:8])[0]
            off = len(pkt)
            ips = []
            for _ in range(ancount):
                if data[off] & 0xC0 == 0xC0:
                    off += 2
                else:
                    while data[off] != 0:
                        off += 1 + data[off]
                    off += 1
                rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
                off += 10
                if rtype == 1 and rdlen == 4:
                    ips.append(".".join(str(b) for b in data[off:off + 4]))
                off += rdlen
            if ips:
                s.close()
                return ips[0]
        except Exception:
            continue
    s.close()
    return None


def parse_sni(buf):
    """从 TLS ClientHello 取 SNI(按 RFC 结构逐字段走, 修正版)。"""
    try:
        if len(buf) < 45 or buf[0] != 0x16:
            return None
        p = 5                       # 跳过 record header(5B)
        if buf[p] != 0x01:          # handshake type = ClientHello
            return None
        p += 1 + 3                  # handshake type + length(3B)
        p += 2                      # client_version
        p += 32                     # random
        sid = buf[p]
        p += 1 + sid                # session_id
        cs = int.from_bytes(buf[p:p + 2], "big")
        p += 2 + cs                 # cipher_suites
        cm = buf[p]
        p += 1 + cm                 # compression_methods
        if p + 2 > len(buf):
            return None
        ext_len = int.from_bytes(buf[p:p + 2], "big")
        p += 2
        end = min(p + ext_len, len(buf))
        while p + 4 <= end:
            et = int.from_bytes(buf[p:p + 2], "big")
            el = int.from_bytes(buf[p + 2:p + 4], "big")
            p += 4
            if et == 0 and p + 5 <= min(p + el, len(buf)):   # server_name
                # 结构: list_len(2) + name_type(1) + name_len(2) + name
                q = p + 3                                    # 跳过 list_len 与 name_type
                nl = int.from_bytes(buf[q:q + 2], "big")
                return buf[q + 2:q + 2 + nl].decode("latin1", "replace")
            p += el
    except Exception:
        return None
    return None


def leaf_for(sni):
    """为 SNI 现签叶子证书(带缓存)。"""
    safe = sni.replace("/", "_").replace(":", "_")
    ck = os.path.join(LEAF_DIR, safe + ".pem")
    kk = os.path.join(LEAF_DIR, safe + ".key")
    if safe in _leaf_cache:
        return _leaf_cache[safe]
    if os.path.exists(ck) and os.path.exists(kk) and (time.time() - os.path.getmtime(ck)) < 30 * 86400:
        _leaf_cache[safe] = (ck, kk)
        return ck, kk
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sni[:64])])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(_CA_CERT.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(sni)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(_CA_KEY, hashes.SHA256()))
    io.open(ck, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    io.open(kk, "wb").write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    _leaf_cache[safe] = (ck, kk)
    return ck, kk


def read_request(f):
    """读一个 HTTP/1.1 请求头, 返回 (head_bytes, body_bytes) 或 (None, None)。"""
    head = b""
    while b"\r\n\r\n" not in head:
        ch = f.read(1)
        if not ch:
            return None, None
        head += ch
        if len(head) > 65536:
            return None, None
    body = b""
    m = [l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")]
    if m:
        try:
            n = int(m[0].split(b":", 1)[1].strip())
            body = f.read(n) if n else b""
        except Exception:
            body = b""
    return head, body


# ★★★ MITM_SNI 白名单 (2026-10-16): 只对"不校验证书"的通道做中间人终结,
#     其余一律透明直通(避免打断会校验证书的业务)。
#     依据: com.xh.answer.classroom.network.core
#            XHAnswerDeviceX509TrustManager.checkServerTrusted() 空实现 => 任意证书可接受
#            XHAnswerDeviceHostnameVerifier.verify()            => return 非空 => 任意主机名放行
#            => answering-machine.yunzuoye.net 可直接被我们终结 TLS, 无需装 CA
_MITM_SNI = [x.strip().lower() for x in (os.environ.get("MITM_SNI") or "").split(",") if x.strip()]


def _pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except Exception:
        pass
    try:
        a.close()
    except Exception:
        pass
    try:
        b.close()
    except Exception:
        pass


def relay(c, head, sni):
    """把连接透明转发到真实服务器(不做解密)。"""
    ip = dns_public(sni)
    if not ip:
        wlog("[RELAY-NO-IP] %s sni=%s -> 关闭" % (c.getpeername()[0], sni))
        try:
            c.close()
        except Exception:
            pass
        return
    try:
        s = socket.create_connection((ip, 443), timeout=8)
        # ★ BUGFIX (2026-10-16): 绝不能 s.sendall(head)!
        #   head 是 recv(MSG_PEEK) 得到的"窥探副本", 客户端数据仍在 socket 缓冲里未被消费,
        #   重发会造成 ClientHello 重复/截断 => 端侧报 "ssl handshake aborted"。
        #   正确做法与 tls_passthrough 一致: 只建连, 然后双向 pipe 原样转发。
        wlog("[RELAY] %s sni=%s -> %s:443" % (c.getpeername()[0], sni, ip))
        c.settimeout(None)
        s.settimeout(None)
        t1 = threading.Thread(target=_pipe, args=(c, s), daemon=True)
        t2 = threading.Thread(target=_pipe, args=(s, c), daemon=True)
        t1.start()
        t2.start()
    except Exception as e:
        wlog("[RELAY-ERR] %s sni=%s %r" % (c.getpeername()[0], sni, e))
        try:
            c.close()
        except Exception:
            pass


def handle(c, addr):
    src = addr[0]
    c.settimeout(20)
    try:
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    head = b""
    # PEEK-FIX: 必须用 MSG_PEEK 窥探 ClientHello(不能消费), 否则 wrap_socket 拿不到握手数据
    try:
        c.settimeout(6)
        for _ in range(40):
            try:
                head = c.recv(4096, socket.MSG_PEEK)
            except Exception:
                head = b""
            if len(head) >= 5:
                if head[0] == 0x16:
                    rec_len = int.from_bytes(head[3:5], "big")
                    if len(head) >= 5 + rec_len:
                        break
                elif b"\r\n\r\n" in head:
                    break
            time.sleep(0.05)
    except Exception:
        pass
    sni = parse_sni(head)
    with _lock:
        _stat["conn"] += 1
        if sni:
            _stat["sni"][sni] = _stat["sni"].get(sni, 0) + 1
    if not sni:
        wlog("[DIRECT] %s 无 SNI/非 TLS -> 关闭 (%dB)" % (src, len(head)))
        try:
            c.close()
        except Exception:
            pass
        return

    # ★ MITM_SNI 白名单: 命中的才做中间人终结, 其余透明直通(不打断会校验证书的业务)
    if _MITM_SNI and sni.lower() not in _MITM_SNI:
        with _lock:
            _stat["fwd"] = _stat.get("fwd", 0) + 1
        relay(c, head, sni)
        return
    with _lock:
        _stat["ctl"] = _stat.get("ctl", 0) + 1
    wlog("!!!!!! [MITM-HIT] %s sni=%s -> 终结 TLS(该通道免 CA)" % (src, sni))

    ck, kk = leaf_for(sni)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(ck, kk)
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    try:
        tls = ctx.wrap_socket(c, server_side=True)
        with _lock:
            _stat["tls_ok"] += 1
    except Exception as e:
        with _lock:
            _stat["tls_fail"] += 1
        wlog("[TLS-FAIL] %s sni=%s %r (证书可能未安装)" % (src, sni, e))
        try:
            c.close()
        except Exception:
            pass
        return

    # 上游(真实服务器)
    up = None
    up_ip = None
    try:
        tls.settimeout(15)
        while True:
            h, b = read_request(tls)
            if not h:
                break
            with _lock:
                _stat["req"] += 1
            first = h.split(b"\r\n", 1)[0].decode("latin1", "replace")
            wcap("%s | sni=%s | %s | body=%dB" % (src, sni, first[:150], len(b)))
            # 转发到真实服务器(HTTP/1.1 over TLS)
            if up is None:
                up_ip = dns_public(sni)
                if not up_ip:
                    wlog("[UP-NO-IP] %s sni=%s" % (src, sni))
                    break
                uctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                uctx.check_hostname = False
                uctx.verify_mode = ssl.CERT_NONE
                up = uctx.wrap_socket(socket.create_connection((up_ip, 443), timeout=10), server_hostname=sni)
                up.settimeout(15)
            up.sendall(h + b)
            # 读响应头
            rh = b""
            while b"\r\n\r\n" not in rh:
                ch = up.recv(4096)
                if not ch:
                    break
                rh += ch
            if not rh:
                break
            tls.sendall(rh)
            with _lock:
                _stat["fwd"] += 1
            # 按 Content-Length 继续转发正文
            cl = 0
            for line in rh.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    try:
                        cl = int(line.split(b":", 1)[1].strip())
                    except Exception:
                        cl = 0
            body_len = len(rh.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in rh else 0
            need = max(0, cl - body_len)
            while need > 0:
                ch = up.recv(min(65536, need))
                if not ch:
                    break
                tls.sendall(ch)
                need -= len(ch)
                with _lock:
                    _stat["bytes"] = _stat.get("bytes", 0) + len(ch)
    except Exception as e:
        wlog("[HANDLE-ERR] %s sni=%s %r" % (src, sni, e))
    finally:
        for s in (tls, up):
            try:
                if s:
                    s.close()
            except Exception:
                pass
        try:
            c.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(128)
    wlog("===== mitm443 start :%d watch=%dh CA=%s =====" % (
        PORT, WATCH_H, _CA_CERT.subject.rfc4514_string()))
    srv.settimeout(60)
    t0 = time.time()
    while time.time() - t0 < WATCH_H * 3600:
        try:
            c, addr = srv.accept()
        except socket.timeout:
            with _lock:
                wlog("[STATS] %s" % {k: v for k, v in _stat.items() if k != "bytes"})
            continue
        except Exception:
            continue
        threading.Thread(target=handle, args=(c, addr), daemon=True).start()
    wlog("===== mitm443 exit =====")


if __name__ == "__main__":
    main()
