# -*- coding: utf-8 -*-
"""find_teacher_jwt.py - 在所有反编译目录里找 JWT 令牌(尤其教师令牌)
特征:
  JWT 头:  eyJhbGciOiJIUzUxMiJ9
  teacher payload base64: YXV0aG9yaXR5IjoidGVhY2hlciI  ("authority":"teacher")
  student payload base64: YXV0aG9yaXR5Ijoic3R1ZGVudCI  ("authority":"student")
输出命中的完整 token 串。
"""
import io
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
DIRS = ["ztpt_dec", "launcher_dec", "xhsettings_dec", "wm_dec", "verify_dec", "payload_src"]
PATS = {
    "JWT": re.compile(r"eyJhbGciOiJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "TEACHER_PAYLOAD": re.compile(r"YXV0aG9yaXR5IjoidGVhY2hlciI"),
    "STUDENT_PAYLOAD": re.compile(r"YXV0aG9yaXR5Ijoic3R1ZGVudCI"),
}
hits = []
n = 0
for d in DIRS:
    root = os.path.join(BASE, d)
    if not os.path.isdir(root):
        continue
    for dp, dn, fs in os.walk(root):
        for fn in fs:
            p = os.path.join(dp, fn)
            n += 1
            try:
                s = io.open(p, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for name, pt in PATS.items():
                for m in pt.finditer(s):
                    hits.append((name, p.replace(BASE + os.sep, ""), m.group(0)))
print("scanned:", n, " hits:", len(hits))
for name, p, val in hits[:40]:
    print("%-16s %s" % (name, p.replace(os.sep, "|")))
    print("    " + val[:300])
