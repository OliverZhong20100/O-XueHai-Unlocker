# -*- coding: utf-8 -*-
"""tls_redirect.py — 透明重定向：平板发往【真实 IP:443】的 TLS → 本地 127.0.0.1:443

WinDivert 要点：
  * forward 关键字只在 NETWORK_FORWARD 层合法（默认 NETWORK 层会 WinError 87）
  * 正向：NETWORK_FORWARD 层拦平板 → 改 dst 为 127.0.0.1 → 交给本地 MITM
  * 反向：NETWORK 层拦 MITM 回包（src=127.0.0.1:443）→ 把 src 改回真实 IP → 交给平板
"""
import os
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.isdir(os.path.join(_HERE, "pylibs")):
    sys.path.insert(0, os.path.join(_HERE, "pylibs"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import pydivert
from pydivert import Layer
from pydivert.consts import Direction

PAD = "192.168.137.10"
LOCAL = "192.168.137.1"
LOG_PATH = os.path.join(_HERE, "tls_redirect.log")

orig = {}
_lock = threading.Lock()
_loglock = threading.Lock()


def wlog(m):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + m
    print(line, flush=True)
    try:
        with _loglock:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass


def fwd_loop():
    flt = "ip.SrcAddr == %s and tcp.DstPort == 443 and ip.DstAddr != %s" % (PAD, LOCAL)
    wlog("[FWD] filter: " + flt)
    w = pydivert.WinDivert(flt, layer=Layer.NETWORK_FORWARD)
    w.open()
    wlog("[FWD] opened OK")
    seen = set()
    while True:
        try:
            pkt = w.recv()
            key = (pkt.src_addr, pkt.src_port)
            with _lock:
                if key not in orig:
                    orig[key] = (pkt.dst_addr, pkt.dst_port)
            if key not in seen:
                seen.add(key)
                wlog("[REDIR] pad %s:%d -> %s:%d  => %s:443" %
                     (pkt.src_addr, pkt.src_port, pkt.dst_addr, pkt.dst_port, LOCAL))
            pkt.dst_addr = LOCAL
            pkt.dst_port = 443
            w.send(pkt)
        except Exception as e:
            wlog("[FWD-ERR] " + str(e)[:120])
            time.sleep(0.2)


def out_loop():
    flt = "outbound and ip.DstAddr == %s and tcp.SrcPort == 443" % PAD
    wlog("[OUT] filter: " + flt)
    w = pydivert.WinDivert(flt, layer=Layer.NETWORK)
    w.open()
    wlog("[OUT] opened OK")
    while True:
        try:
            pkt = w.recv()
            key = (pkt.dst_addr, pkt.dst_port)
            with _lock:
                real = orig.get(key)
            if real:
                pkt.src_addr, pkt.src_port = real
            w.send(pkt)
        except Exception as e:
            wlog("[OUT-ERR] " + str(e)[:120])
            time.sleep(0.2)


def main():
    wlog("===== tls_redirect v2 start (NETWORK_FORWARD + NETWORK) =====")
    t1 = threading.Thread(target=fwd_loop, daemon=True)
    t2 = threading.Thread(target=out_loop, daemon=True)
    t1.start()
    t2.start()
    while True:
        time.sleep(60)
        wlog("[HB] orig=%d threads=%s/%s" % (len(orig), t1.is_alive(), t2.is_alive()))


if __name__ == "__main__":
    main()
