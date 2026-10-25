# -*- coding: utf-8 -*-
"""find_downloader.py - 全 cls_dec 搜索下载器的多文件解压标志与代理类"""
import io
import os

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "cls_dec")
PATS = ["isDownloadMultiFiles", "XHDownloadOkHttpProxy", "readResponseBodyContent"]

found = {p: [] for p in PATS}
n = 0
for dp, dn, fs in os.walk(ROOT):
    for fn in fs:
        if not fn.endswith(".smali"):
            continue
        n += 1
        p = os.path.join(dp, fn)
        try:
            s = io.open(p, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for pat in PATS:
            if pat in s:
                for i, ln in enumerate(s.splitlines(), 1):
                    if pat in ln and len(found[pat]) < 25:
                        found[pat].append((p.replace(ROOT + os.sep, ""), i, ln.strip()[:120]))
print("scanned:", n)
for pat in PATS:
    print("\n=== %s (%d hits shown) ===" % (pat, len(found[pat])))
    for h in found[pat]:
        print("  %s :%d  %s" % (h[0].replace(os.sep, "|"), h[1], h[2]))
