# -*- coding: utf-8 -*-
"""enum_js_bridges.py - 枚举所有 WebView JS 桥及其暴露的 public 方法
策略:
  1) 找所有含 addJavascriptInterface 的 smali
  2) 从调用处取桥对象类型
  3) 列出该类型的 @JavascriptInterface / public 方法
"""
import io
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "cls_dec")

bridges = {}   # class -> [callers]


def cls_path(name):
    # Lcom/xh/foo/Bar; -> smali path (search any classes dir)
    p = name.replace("L", "", 1).rstrip(";").replace("/", os.sep)
    for d in sorted(os.listdir(ROOT)):
        f = os.path.join(ROOT, d, p + ".smali")
        if os.path.isfile(f):
            return f
    return None


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
        if "addJavascriptInterface" not in s:
            continue
        lines = s.splitlines()
        for i, ln in enumerate(lines):
            if "addJavascriptInterface" not in ln:
                continue
            # 往前找 new-instance 的类
            for j in range(i, max(0, i - 25), -1):
                m = re.search(r"new-instance [vp]\d+, (L[^;]+;)", lines[j])
                if m:
                    c = m.group(1)
                    bridges.setdefault(c, []).append(p.replace(ROOT + os.sep, "").replace(os.sep, "|"))
                    break

print("scanned:", n)
print("bridge classes:", len(bridges))
for c, callers in sorted(bridges.items()):
    print("\n=== %s ===" % c)
    print("  registered in: %s" % ", ".join(sorted(set(callers))[:3]))
    f = cls_path(c)
    if not f:
        print("  (class file not found)")
        continue
    try:
        s = io.open(f, "r", encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    lines = s.splitlines()
    pub = []
    for i, ln in enumerate(lines):
        if ln.startswith(".method"):
            # 方法名
            m = re.search(r"\.method\s+(.+?)\s+(\w+)\(([^)]*)\)", ln)
            if m:
                name = m.group(2)
                if name in ("<init>",):
                    continue
                # 检查后续 20 行有无 @JavascriptInterface
                js = any("@JavascriptInterface" in lines[k] for k in range(i, min(i + 12, len(lines))))
                pub.append((name, js))
    if not pub:
        continue
    for name, js in pub[:40]:
        print("  %s %s" % ("[JS]" if js else "    ", name))
