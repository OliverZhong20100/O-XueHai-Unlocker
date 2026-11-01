# -*- coding: utf-8 -*-
"""tls_mitm.py — 443 透明中继 + 【空SNI(IP直连) 的 TLS 终止 MITM】

原理：
  - 有 SNI（域名）：按真实 IP 直通（与 tls_passthrough 相同，不解密）
  - 无 SNI（App 连的是 IP，正好命中 XHHostnameVerifier.verifyIpAddress() 无条件放行）：
      * 用 Let's Encrypt 证书(CN=oliversmcserver.site) 完成 TLS 握手 —— 平板系统信任库认这张链
      * 解出明文请求，落盘日志
      * 再向【原始目标 IP:443】建一条真实 TLS，明文转发，实现完整 MITM
"""
import hashlib
import json
import os
import select
import socket
import ssl
import struct
import sys
import threading
import time

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tls_mitm.log")
CERT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(CERT_DIR, "mitm_fullchain.pem")
KEY = os.path.join(CERT_DIR, "mitm_server.key")
WATCH_H = int(os.environ.get("WATCH_H", "86400"))
_lock = threading.Lock()
_stat = {"conn": 0, "mitm": 0, "fail": 0, "sni": {}}

# 已知真机可达 IP（与 tls_passthrough.py / npcap_http80.py 的 REAL_IP 一致）
FALLBACK = {
    "ms.yunzuoye.net": "47.111.87.154",
    "ztp.yunzuoye.net": "47.111.87.154",
    "control.yunzuoye.net": "47.111.87.154",
    "logdata.yunzuoye.net": "47.111.87.154",
    "survey.yunzuoye.net": "47.111.87.154",
    "filesoss.yunzuoye.net": "47.110.67.143",
    "sentry.yunzuoye.net": "47.111.87.154",
    "response.yunzuoye.net": "47.111.87.154",
    "bigdata.yunzuoye.net": "47.111.87.154",
    "cloudwk.yunzuoye.net": "47.111.87.154",
    "pptserver.yunzuoye.net": "47.111.87.154",
}


def wlog(m):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + m + "\n"
    try:
        with _lock:
            with open(LOG, "a", encoding="utf-8", errors="replace") as f:
                f.write(line)
    except Exception:
        pass


def parse_sni(buf):
    try:
        if len(buf) < 5 or buf[0] != 0x16:
            return None
        pos = 5 + 4 + 2 + 32
        sid_len = buf[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack(">H", buf[pos:pos + 2])[0]
        pos += 2 + cs_len
        cm_len = buf[pos]
        pos += 1 + cm_len
        ext_total = struct.unpack(">H", buf[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            etype, elen = struct.unpack(">HH", buf[pos:pos + 4])
            pos += 4
            if etype == 0:
                p = pos + 2
                ntype = buf[p]
                nlen = struct.unpack(">H", buf[p + 1:p + 3])[0]
                if ntype == 0:
                    return buf[p + 3:p + 3 + nlen].decode("ascii", "replace")
            pos += elen
    except Exception:
        return None
    return None


def dns_public(host, servers=("223.5.5.5", "114.114.114.114", "8.8.8.8")):
    import random
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in host.rstrip(".").split("."):
        if not part:
            continue
        q += bytes([len(part)]) + part.encode("ascii", "replace")
    q += b"\x00\x00\x01\x00\x01"
    for srv in servers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            s.sendto(q, (srv, 53))
            data, _ = s.recvfrom(2048)
            s.close()
            idx = 12
            while idx < len(data):
                if data[idx] & 0xC0:
                    break
                idx += 1
                if idx >= len(data):
                    return None
                ln = data[idx - 1]
                if ln == 0:
                    break
            if idx + 4 > len(data):
                continue
            an = struct.unpack(">H", data[6:8])[0]
            if an == 0:
                continue
            idx += 4
            idx += 4
            ips = []
            idx += 4
            idx += 2
            for _ in range(an):
                idx += 2
                if data[idx - 2] & 0xC0:
                    idx += 0
                typ = struct.unpack(">H", data[idx:idx + 2])[0]
                idx += 2 + 2 + 4
                if typ == 1:
                    ips.append(".".join(str(b) for b in data[idx:idx + 4]))
                    idx += 4
                else:
                    rdlen = struct.unpack(">H", data[idx - 2:idx])[0]
                    idx += rdlen
            if ips:
                return ips[0]
        except Exception:
            continue
    return None


def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 30)
            if not r:
                break
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


RESP_SIGN_KEY = b"GHU^B_)+*&^%3~]"


def _build_resp(body, status=b"200 OK", ctype=b"application/json; charset=UTF-8"):
    if isinstance(body, str):
        body = body.encode("utf-8")
    sig = hashlib.md5(RESP_SIGN_KEY + body).hexdigest()
    return (b"HTTP/1.1 " + status + b"\r\nContent-Type: " + ctype +
            b"\r\nContent-Length: " + str(len(body)).encode() +
            b"\r\nX-Content-Sign-Token: " + sig.encode() +
            b"\r\nConnection: keep-alive\r\n\r\n" + body)


def _read_http(s):
    """读一个完整 HTTP 请求（含 body），返回原始 bytes 或 None。"""
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            return None
        buf += d
        if len(buf) > 2_000_000:
            return None
    head, rest = buf.split(b"\r\n\r\n", 1)
    clen = 0
    for ln in head.split(b"\r\n"):
        if ln.lower().startswith(b"content-length:"):
            try:
                clen = int(ln.split(b":", 1)[1].strip())
            except Exception:
                clen = 0
    while len(rest) < clen:
        d = s.recv(65536)
        if not d:
            break
        rest += d
    return head + b"\r\n\r\n" + rest[:clen]


def _fake_for(req):
    """按请求路径返回伪造响应（带响应签名）。"""
    try:
        text = req.split(b"\r\n\r\n", 1)[0]
        first = text.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        path = first.split(" ")[1] if " " in first else ""
        body = req.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in req else b""
        if "/api/v2/platform/login" in path:
            fake = json.dumps({
                "userId": 2112229, "userName": "zhonghaoyang7", "userType": 0,
                "schoolId": 0, "schoolName": "",
                "accessToken": "FAKE." + hashlib.md5(body).hexdigest(),
                "refreshToken": "FAKEREF." + hashlib.md5(body).hexdigest(),
                "expiresIn": 7200, "activated": True,
                "microAddressDTOList": []}).encode()
            return _build_resp(fake), path
        if ("/activation/verify" in path) or ("/activation/status" in path) or ("/check/device" in path):
            return _build_resp(b'{"code":200,"message":"success","data":true}'), path
        return _build_resp(b"{}"), path
    except Exception:
        return _build_resp(b"{}"), "?"


def mitm_ip(c, addr):
    """空 SNI（URL host=IP）：证书终止 TLS → 记录明文 → 返回伪造响应。"""
    dst = None
    try:
        dst = c.getsockname()[0]
    except Exception:
        pass
    with _lock:
        _stat["mitm"] += 1
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
        s = ctx.wrap_socket(c, server_side=True)
    except Exception as e:
        wlog("[MITM-FAIL] %s dst=%s hs=%s" % (addr[0], dst, str(e)[:120]))
        with _lock:
            _stat["fail"] += 1
        try:
            c.close()
        except Exception:
            pass
        return
    wlog("[MITM-OK] %s dst=%s 握手成功(IP绕过生效)" % (addr[0], dst))
    try:
        s.settimeout(15)
        while True:
            req = _read_http(s)
            if not req:
                break
            head = req.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
            body = req.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in req else b""
            with open(LOG, "a", encoding="utf-8", errors="replace") as f:
                f.write("===== MITM-REQ %s dst=%s =====\n%s\n--- body ---\n%s\n\n" %
                        (addr[0], dst, head, body[:2048].decode("latin-1", "replace")))
            resp, path = _fake_for(req)
            s.sendall(resp)
            with open(LOG, "a", encoding="utf-8", errors="replace") as f:
                f.write("----- MITM-RESP %s -----\n%s\n\n" % (path, resp[:300].decode("latin-1", "replace")))
    except Exception as e:
        wlog("[MITM-ERR] %s %s" % (addr[0], str(e)[:120]))
    finally:
        try:
            s.close()
        except Exception:
            pass


def handle(c, addr):
    try:
        c.settimeout(8)
        head = c.recv(4096, socket.MSG_PEEK)
        if not head:
            c.close()
            return
        sni = parse_sni(head)
        # ==== DROP-RULE: TLS_DROP_SNI 里列出的域名直接断链(逼端侧回退明文 HTTP) ====
        _drop = os.environ.get("TLS_DROP_SNI", "")
        if _drop and sni and any(d.strip() and sni == d.strip() for d in _drop.split(",")):
            wlog("[DROP] %s sni=%s -> 主动断链(逼回退明文)" % (addr[0], sni))
            try:
                c.close()
            except Exception:
                pass
            return
        if not sni:
            # 空 SNI = IP 直连 → MITM
            mitm_ip(c, addr)
            return
        ip = FALLBACK.get(sni) or dns_public(sni)
        if not ip:
            wlog("[NO-IP] %s sni=%r -> 关闭" % (addr[0], sni))
            c.close()
            return
        s = socket.create_connection((ip, 443), timeout=8)
        with _lock:
            _stat["conn"] += 1
            _stat["sni"][sni] = _stat["sni"].get(sni, 0) + 1
        wlog("[PASS] %s sni=%s -> %s:443" % (addr[0], sni, ip))
        c.settimeout(None)
        s.settimeout(None)
        pipe(c, s)
    except Exception:
        with _lock:
            _stat["fail"] += 1
        try:
            c.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 443))
    srv.listen(64)
    srv.settimeout(1.0)
    wlog("===== tls_mitm start :443 (空SNI=IP直连 → 证书终止MITM) =====")
    t0 = time.time()

    def stat_loop():
        while time.time() - t0 < WATCH_H * 3600:
            time.sleep(60)
            with _lock:
                wlog("[STATS] pass=%d mitm=%d fail=%d sni=%s" %
                     (_stat["conn"], _stat["mitm"], _stat["fail"], _stat["sni"]))
    threading.Thread(target=stat_loop, daemon=True).start()

    while time.time() - t0 < WATCH_H * 3600:
        try:
            c, addr = srv.accept()
            threading.Thread(target=handle, args=(c, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break


if __name__ == "__main__":
    main()
