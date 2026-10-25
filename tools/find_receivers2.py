# -*- coding: utf-8 -*-
"""find_receivers.py - 枚举所有注册 ContextMessage 监听的类 + 它们监听的动作"""
import io
import os

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "cls_dec")
out = []
n = 0
for dp, dn, fs in os.walk(ROOT):
    for fn in fs:
        if not fn.endswith(".smali"):
            continue
        p = os.path.join(dp, fn)
        try:
            s = io.open(p, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        if "addMessageListener" not in s:
            continue
        n += 1
        lines = s.splitlines()
        actions = []
        for i, ln in enumerate(lines):
            if "addMessageListener" in ln:
                # 往前找最近 30 行里的 const-string 动作名
                for j in range(i, max(0, i - 30), -1):
                    if 'const-string' in lines[j] and '"' in lines[j]:
                        a = lines[j].split('"')
                        if len(a) >= 2:
                            actions.append(a[1])
                            break
        rel = p.replace(ROOT + os.sep, "").replace(os.sep, "|")
        out.append((rel, sorted(set(actions))))

out.sort()
print("classes with addMessageListener:", len(out))
for rel, acts in out:
    print("  %s" % rel)
    for a in acts[:6]:
        print("      <- %s" % a)
