#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tls_passthrough.py — 443 上的【按 SNI 直通】中继（不解密、不改内容）。

为什么需要它:
  本机 hosts 里写死了
      192.168.137.1 ms.yunzuoye.net
      192.168.137.1 filesoss.yunzuoye.net
  而无权限修改 hosts。平板的 ICS DNS 遵守了这些条目 ⇒ 平板把这两个**业务域名**
  解析到本机(192.168.137.1)并去连 443，而 443 无人监听 ⇒ 账号/文件接口失败。
  本中继就监听 443，收到连接后读 TLS ClientHello 取出 SNI，
  **按真实 IP 转发**（dns_public 绕开本机 hosts），从而实现"名字被劫到本机但功能正常"。

与失败的 tls_relay_v2 的关键区别:
  tls_relay_v2 把它拦到的所有 HTTPS 都转给**写死的 upstream 47.110.67.143:443**
  ⇒ ms.yunzuoye.net 被送到非对应后端 ⇒ 应用报"资源或接口不存在"。
  本脚本按 SNI 现查真实 IP，逐个域名转发到正确的服务器；只做透传，不终止 TLS。

用法: python tls_passthrough.py [hours]
"""
import datetime
import os
import select
import socket
import struct
import sys
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "tls_passthrough.log")
WATCH_H = float(sys.argv[1]) if len(sys.argv) > 1 else 12.0

# 已知真机可达 IP（与 npcap_http80 的 REAL_IP 对齐；查不到 SNI 时兜底）
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

_stat = {"conn": 0, "bytes": 0, "err": 0, "sni": {}}
_lock = threading.Lock()


def wlog(m):
    line = "%s %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), m)
    print(line)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def dns_public(host, servers=("223.5.5.5", "114.114.114.114", "8.8.8.8")):
    """公共 DNS 解析（手工构造报文，完全绕开本机 hosts）。"""
    import random
    for srv in servers:
        try:
            tid = random.randint(0, 65535)
            q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            for part in host.split("."):
                q += bytes([len(part)]) + part.encode()
            q += b"\x00" + struct.pack(">HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.5)
            try:
                s.sendto(q, (srv, 53))
                data, _ = s.recvfrom(2048)
            finally:
                s.close()
            an = struct.unpack(">H", data[6:8])[0]
            idx = len(q)
            ips = []
            for _ in range(an):
                if data[idx] & 0xC0 == 0xC0:
                    idx += 2
                else:
                    while data[idx] != 0:
                        idx += 1 + data[idx]
                    idx += 1
                rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
                idx += 10
                if rtype == 1 and rdlen == 4:
                    ips.append(".".join(str(b) for b in data[idx:idx + 4]))
                idx += rdlen
            if ips:
                return ips[0]
        except Exception:
            continue
    return None


def parse_sni(buf):
    """从 TLS ClientHello 中取 SNI。"""
    try:
        if len(buf) < 5 or buf[0] != 0x16:
            return None
        pos = 5 + 4 + 2 + 32           # record + handshake hdr + version + random
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
            if etype == 0:                # server_name
                p = pos + 2               # list len
                ntype = buf[p]
                nlen = struct.unpack(">H", buf[p + 1:p + 3])[0]
                if ntype == 0:
                    return buf[p + 3:p + 3 + nlen].decode("ascii", "replace")
            pos += elen
    except Exception:
        return None
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
                with _lock:
                    _stat["bytes"] += len(d)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


def handle(c, addr):
    try:
        c.settimeout(8)
        head = c.recv(4096)
        if not head:
            c.close()
            return
        sni = parse_sni(head)
        # ==== DROP-RULE: TLS_DROP_SNI 里列出的域名直接断链(逼端侧回退明文 HTTP) ====
        _drop = os.environ.get("TLS_DROP_SNI", "")
        if _drop and sni and any(d.strip() and sni == d.strip() for d in _drop.split(",")):
            wlog("[DROP] %s sni=%s -> \u4e3b\u52a8\u65ad\u94fe(\u9010\u56de\u9000\u660e\u6587)" % (addr[0], sni))
            with _lock:
                _stat["err"] += 1
            try:
                c.close()
            except Exception:
                pass
            return
        ip = FALLBACK.get(sni or "")
        if not ip and sni:
            ip = dns_public(sni)
        if not ip:
            wlog("[NO-SNI-IP] %s sni=%r -> 关闭" % (addr[0], sni))
            with _lock:
                _stat["err"] += 1
            c.close()
            return
        s = socket.create_connection((ip, 443), timeout=8)
        s.sendall(head)
        with _lock:
            _stat["conn"] += 1
            _stat["sni"][sni or "?"] = _stat["sni"].get(sni or "?", 0) + 1
        wlog("[PASS] %s sni=%s -> %s:443" % (addr[0], sni, ip))
        c.settimeout(None)
        s.settimeout(None)
        pipe(c, s)
    except Exception as e:
        with _lock:
            _stat["err"] += 1
        try:
            c.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 443))
    srv.listen(64)
    wlog("===== tls_passthrough start :443 watch=%sh (按 SNI 直通真服务器) =====" % WATCH_H)
    t0 = time.time()
    srv.settimeout(1.0)

    def stat_loop():
        while time.time() - t0 < WATCH_H * 3600:
            time.sleep(60)
            with _lock:
                wlog("[STATS] conn=%d bytes=%d err=%d sni=%s" %
                     (_stat["conn"], _stat["bytes"], _stat["err"], _stat["sni"]))
    threading.Thread(target=stat_loop, daemon=True).start()

    while time.time() - t0 < WATCH_H * 3600:
        try:
            c, a = srv.accept()
            threading.Thread(target=handle, args=(c, a), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as e:
            wlog("[ACCEPT-ERR] %s" % e)
            time.sleep(0.5)
    wlog("===== 到时退出 =====")


if __name__ == "__main__":
    main()
