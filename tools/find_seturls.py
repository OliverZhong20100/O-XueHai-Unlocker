# -*- coding: utf-8 -*-
"""find_seturls.py - 全 cls_dec 搜索 setUrls(多文件下载/解压)的调用者"""
import io
import os

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "cls_dec")
PATS = ["->setUrls(", "DownloadFileManager;->downloadFiles", "downloadMultiFiles",
        "setDownloadMultiFiles"]
found = {p: [] for p in PATS}
for dp, dn, fs in os.walk(ROOT):
    for fn in fs:
        if not fn.endswith(".smali"):
            continue
        p = os.path.join(dp, fn)
        try:
            s = io.open(p, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for pat in PATS:
            if pat in s:
                for i, ln in enumerate(s.splitlines(), 1):
                    if pat in ln and len(found[pat]) < 20:
                        found[pat].append((p.replace(ROOT + os.sep, ""), i, ln.strip()[:120]))
for pat in PATS:
    print("\n=== %s (%d) ===" % (pat, len(found[pat])))
    for h in found[pat]:
        print("  %s :%d  %s" % (h[0].replace(os.sep, "|"), h[1], h[2]))
