# -*- coding: utf-8 -*-
"""_devtoken_fix.py — 修正 year/mday 顺序后的开发者令牌"""
import base64
import hashlib
from datetime import datetime

S1, S2, S3, S4 = "!@#xuehai3", "&zhitongyun3", "$100fen!@#", "@"


def md5h(s, up=False):
    h = hashlib.md5(s.encode()).hexdigest()
    return h.upper() if up else h


def enc(s, b64, up):
    return md5h((base64.b64encode(s.encode()).decode() + "\n") if b64 else s, up)


def change(hour, s, rev):
    pm = hour >= 12
    out = []
    rng = range(len(s) - 1, -1, -1) if rev else range(len(s))
    for i in rng:
        if (i % 2 == 0) if pm else (i % 2 == 1):
            out.append(s[i])
    return "".join(out)


def gen(year, mon, mday, hour, up=False):
    # 修正后的顺序: 盐1 + hour + 盐2 + mon + 盐3 + YEAR + @ + MDAY
    raw = "%s%d%s%d%s%d%s%d" % (S1, hour, S2, mon, S3, year, S4, mday)
    s = enc(raw, True, up)
    s = change(hour, s, True)
    for i in range(hour + 1):
        odd = (i % 2 != 0)
        s = change(hour, enc(s, odd, up), odd)
    return s


now = datetime.now()
print("现在:", now.strftime("%Y-%m-%d %H:%M:%S"))
for h in (now.hour - 1, now.hour, now.hour + 1):
    if h < 0 or h > 23:
        continue
    dt = now.replace(hour=h)
    for up in (False, True):
        t = gen(dt.year, dt.month, dt.day, h, up)
        tag = "大写" if up else "小写"
        print("  %02d点 %s  16位=%s  QR前8=%s" % (h, tag, t, t[:8]))
