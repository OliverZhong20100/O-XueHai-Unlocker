# -*- coding: utf-8 -*-
"""_mitm_selftest.py — 本机连 47.99.85.219:443 验证 MITM 握手（模拟平板的 IP 直连）"""
import socket
import ssl
import sys

TARGET = "47.99.85.219"

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_default_certs()
ctx.check_hostname = False   # 模拟 verifyIpAddress 无条件放行
ctx.verify_mode = ssl.CERT_REQUIRED

try:
    raw = socket.create_connection((TARGET, 443), timeout=10)
    s = ctx.wrap_socket(raw, server_hostname=TARGET)
    print("HANDSHAKE OK  proto=%s  cipher=%s" % (s.version(), s.cipher()[0]))
    cert = s.getpeercert()
    print("cert subject:", cert.get("subject"))
    print("cert issuer :", cert.get("issuer"))
    s.sendall(b"GET /selftest HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % TARGET.encode())
    print("response:", s.recv(500))
    s.close()
except Exception as e:
    print("FAIL:", str(e)[:300])
    sys.exit(1)
