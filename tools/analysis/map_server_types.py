# -*- coding: utf-8 -*-
"""map_server_types.py - 把 MessageHandleForServerHelper 的 type <-> action 映射解出来。
做法: 解析 smali 里的 :sswitch_N / :pswitch_N 标签块, 提取每个块里的 sendMsg action 名,
      再读 sparse-switch / packed-switch 表, 得到 type -> label -> action。
"""
import io
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
F = None
for root, dirs, files in os.walk(os.path.join(BASE, "cls_dec")):
    for fn in files:
        if fn == "MessageHandleForServerHelper.smali":
            F = os.path.join(root, fn)
            break
    if F:
        break
if not F:
    raise SystemExit("not found")

lines = io.open(F, "r", encoding="utf-8", errors="replace").read().splitlines()
print("file:", F, "lines:", len(lines))

# 1) 收集每个 label -> actions
label_actions = {}
cur = None
for i, ln in enumerate(lines):
    m = re.match(r"\s*:(s?pswitch_[0-9a-f]+)\s*$", ln)
    if m:
        cur = m.group(1)
        label_actions.setdefault(cur, [])
        continue
    if re.match(r"\s*:(cond_|goto_|sswitch|pswitch)", ln):
        cur = None
    if cur and "ContextMessage;->sendMsg" in ln:
        for j in range(i, max(0, i - 40), -1):
            mm = re.search(r'const-string [vp]\d+, "([^"]+)"', lines[j])
            if mm:
                label_actions[cur].append(mm.group(1))
                break

# 2) 解析 switch 表
tables = []  # (kind, [types], [labels])
i = 0
while i < len(lines):
    m = re.match(r"\s*\.((?:sparse|packed)-switch)\s*(\S*)", lines[i])
    if m:
        kind = m.group(1)
        types, labels = [], []
        j = i + 1
        if kind == "sparse-switch":
            while j < len(lines) and ".end sparse-switch" not in lines[j]:
                mm = re.match(r"\s*(0x[0-9a-f]+)\s*->\s*:(\S+)", lines[j])
                if mm:
                    types.append(int(mm.group(1), 16))
                    labels.append(mm.group(2))
                j += 1
        else:
            base = int(m.group(2), 16)
            while j < len(lines) and ".end packed-switch" not in lines[j]:
                mm = re.match(r"\s*:(\S+)", lines[j])
                if mm:
                    labels.append(mm.group(1))
                j += 1
            types = [base + k for k in range(len(labels))]
        tables.append((kind, types, labels))
        i = j
    i += 1

print("\n=== type -> action ===")
seen = set()
for kind, types, labels in tables:
    for t, lb in zip(types, labels):
        for a in label_actions.get(lb, []):
            key = (t, a)
            if key in seen:
                continue
            seen.add(key)
            print("  type=%-8d (%#x)  %-22s  %s" % (t, t, lb, a))
