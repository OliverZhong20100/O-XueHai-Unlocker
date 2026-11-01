# -*- coding: utf-8 -*-
"""_windivert_diag.py — 诊断 WinDivert 各层/过滤器组合"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "pylibs"))
sys.path.insert(0, _HERE)

LOG = os.path.join(_HERE, "windivert_diag.log")


def log(m):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(m + "\n")
    print(m, flush=True)


try:
    import pydivert
    from pydivert import Layer
except Exception as e:
    log("import pydivert FAIL: " + str(e))
    sys.exit(1)

log("pydivert import OK")
try:
    log("layers: " + ", ".join(str(x) for x in Layer))
except Exception as e:
    log("layers enum: " + str(e))

PAD = "192.168.137.10"
LOCAL = "192.168.137.1"

tests = [
    ("LAYER NETWORK", "inbound and ip.SrcAddr == %s and tcp.DstPort == 443" % PAD),
    ("LAYER NETWORK", "outbound and ip.DstAddr == %s and tcp.SrcPort == 443" % PAD),
    ("LAYER NETWORK", "forward and ip.SrcAddr == %s" % PAD),
    ("LAYER NETWORK_FORWARD", "tcp.DstPort == 443"),
    ("LAYER NETWORK_FORWARD", "ip.SrcAddr == %s and tcp.DstPort == 443" % PAD),
    ("LAYER NETWORK_FORWARD", "ip.SrcAddr == %s and tcp.DstPort == 443 and ip.DstAddr != %s" % (PAD, LOCAL)),
    ("LAYER NETWORK_FORWARD", "forward and ip.SrcAddr == %s and tcp.DstPort == 443" % PAD),
    ("LAYER FLOW", "ip.SrcAddr == %s" % PAD),
    ("LAYER SOCKET", "tcp.DstPort == 443"),
]

for layer_name, flt in tests:
    try:
        layer = getattr(Layer, layer_name.replace("LAYER ", ""))
    except Exception as e:
        log("%-22s %-70s LAYER ERR %s" % (layer_name, flt, e))
        continue
    try:
        w = pydivert.WinDivert(flt, layer=layer)
        w.open()
        log("%-22s %-70s OK" % (layer_name, flt))
        w.close()
    except Exception as e:
        log("%-22s %-70s FAIL %s" % (layer_name, flt, str(e)[:80]))

log("DIAG DONE")
