# -*- coding: utf-8 -*-
"""map_all_handlers.py - 解析 9 个消息处理器的 type <-> action 映射, 输出到 ws_message_map.txt"""
import io
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "ws_message_map.txt")

NAMES = [
    "MessageHandleForCanvasHelper", "MessageHandleForDefaultHelper",
    "MessageHandleForFzlHelper", "MessageHandleForOnlineHelper",
    "MessageHandleForServerHelper", "MessageHandleForWwzHelper",
    "MessageHandleHelperForStudentList", "MessageHelperFromSimpleStudent",
    "MessageHelperFromSimpleTeacher",
]


def find_file(name):
    for root, dirs, files in os.walk(os.path.join(BASE, "cls_dec")):
        if name + ".smali" in files:
            return os.path.join(root, name + ".smali")
    return None


def parse(path):
    lines = io.open(path, "r", encoding="utf-8", errors="replace").read().splitlines()
    # label -> actions
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
    # switch tables
    tables = []
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
    # tag
    tag = "?"
    for ln in lines:
        if 'const-string' in ln and ('_tag' in ln or 'simple_' in ln or 'StudentList' in ln):
            mm = re.search(r'const-string [vp]\d+, "([^"]+)"', ln)
            if mm:
                tag = mm.group(1)
                break
    rows = []
    seen = set()
    for kind, types, labels in tables:
        for t, lb in zip(types, labels):
            for a in label_actions.get(lb, []):
                if (t, a) in seen:
                    continue
                seen.add((t, a))
                rows.append((t, lb, a))
    return tag, rows


def main():
    out = []
    for n in NAMES:
        p = find_file(n)
        if not p:
            out.append("##### %s : NOT FOUND" % n)
            continue
        tag, rows = parse(p)
        out.append("")
        out.append("##### %s   tag=%s   entries=%d" % (n, tag, len(rows)))
        for t, lb, a in rows:
            out.append("  type=%-10d (0x%x)  %-14s %s" % (t, t, lb, a))
    io.open(OUT, "w", encoding="utf-8").write("\n".join(out))
    print("written %s (%d lines)" % (OUT, len(out)))
    for ln in out:
        if any(k in ln for k in ("class", "studying", "record", "task", "resource",
                                 "download", "web", "ppt", "res")):
            print(ln)


if __name__ == "__main__":
    main()
