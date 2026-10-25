# -*- coding: utf-8 -*-
"""find_unzip_callers2.py - 全 cls_dec 搜索 HttpUtil.unzip 的调用者"""
import io
import os

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "cls_dec")
PAT = "HttpUtil;->unzip"
hits = []
for dp, dn, fs in os.walk(ROOT):
    for fn in fs:
        if not fn.endswith(".smali"):
            continue
        p = os.path.join(dp, fn)
        try:
            s = io.open(p, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        if PAT in s:
            for i, ln in enumerate(s.splitlines(), 1):
                if PAT in ln:
                    hits.append((p.replace(ROOT + os.sep, ""), i, ln.strip()))
print("callers:", len(hits))
for h in hits:
    print("  %s :%d  %s" % (h[0].replace(os.sep, "|"), h[1], h[2][:110]))
