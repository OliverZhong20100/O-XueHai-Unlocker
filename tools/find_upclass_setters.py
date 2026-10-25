# -*- coding: utf-8 -*-
"""find_upclass_setters.py - 精确查找 UpClassStateHelper 状态设置的所有调用者
决定: 是否有非 HTTPS 的途径(消息/本地)能把课堂状态置为"上课中"
"""
import io
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "cls_dec")

# 目标: 设置状态的方法名(setUpClassState / setUpClassState2 / UP_CLASS_STATE 等)
targets = [
    "UpClassStateHelper;->setUpClassState",
    "UpClassStateHelper;->setUpClassStatus",
    "UpClassStateHelper;->setState",
    "UpClassStateHelper;->isEndUpClass",
    "UpClassStateHelper;->isUpClass",
    "UpClassStateHelper;->clearAllConfig",
]
hits = {t: [] for t in targets}
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
        if "UpClassStateHelper" not in s:
            continue
        for i, ln in enumerate(s.splitlines(), 1):
            for t in targets:
                if t in ln:
                    hits[t].append("%s :%d  %s" % (
                        p.replace(ROOT + os.sep, "").replace(os.sep, "|"), i, ln.strip()[:110]))

print("scanned smali:", n)
for t, lst in hits.items():
    print("\n=== %s : %d 处 ===" % (t, len(lst)))
    for h in lst[:25]:
        print("  " + h)
