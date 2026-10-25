# -*- coding: utf-8 -*-
"""extract_frames.py - 从 ws_frames.log 提取端侧真实消息(去重), 输出类型与样本"""
import io
import json
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
F = os.path.join(BASE, "ws_frames.log")
OUT = os.path.join(BASE, "ws_real_messages.txt")

lines = io.open(F, "r", encoding="utf-8", errors="replace").read().splitlines()
frames = []  # (ts, direction, opcode, text)
i = 0
while i < len(lines):
    m = re.match(r"^([\d\.:]+) ### \[(.*?)\] WS (\w+) len=(\d+)$", lines[i])
    if m:
        ts, direction, op, ln = m.groups()
        # 下一行应是 --- text ---
        if i + 1 < len(lines) and "--- text ---" in lines[i + 1]:
            txt = lines[i + 2] if i + 2 < len(lines) else ""
            frames.append((ts, direction, op, txt))
            i += 3
            continue
    i += 1

print("frames parsed:", len(frames))
texts = [(d, t) for ts, d, op, t in frames if op == "text" and t.strip()]
print("text frames:", len(texts))

# 去重
uniq = {}
for d, t in texts:
    try:
        j = json.loads(t)
        key = (d, j.get("smsg", {}).get("type"), j.get("smsg", {}).get("createTag"))
    except Exception:
        key = (d, "?", t[:40])
    uniq.setdefault(key, []).append(t)

print("unique (direction,type,tag):", len(uniq))
with io.open(OUT, "w", encoding="utf-8") as f:
    for key, samples in sorted(uniq.items(), key=lambda x: str(x[0])):
        f.write("\n===== %s  count=%d =====\n" % (str(key), len(samples)))
        f.write(samples[0][:1200] + "\n")
print("written:", OUT)
for key, samples in sorted(uniq.items(), key=lambda x: str(x[0]))[:30]:
    print("  %-46s x%d" % (str(key)[:46], len(samples)))
    print("     " + samples[0][:160])
