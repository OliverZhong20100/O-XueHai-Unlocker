# -*- coding: utf-8 -*-
"""全链逐项实测: 每个环节都实际发一次请求/读一次文件, 只输出测量结果。"""
import io
import json
import os
import socket
import subprocess
import sys

R = r'C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover'
PT = os.path.join(R, 'pentest')
OK, BAD, WARN = "[OK]", "[FAIL]", "[WARN]"
res = []


def say(tag, msg):
    res.append("%s %s" % (tag, msg))
    print("%s %s" % (tag, msg))


def http(port, path, host='192.168.137.1', method='GET'):
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=8)
        s.sendall(('%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n'
                   % (method, path, host)).encode())
        d = b''
        while True:
            c = s.recv(8192)
            if not c:
                break
            d += c
        s.close()
        head, _, body = d.partition(b'\r\n\r\n')
        return head.decode('latin1', 'replace'), body
    except Exception as e:
        return 'ERR %s' % e, b''


def listen(p):
    try:
        out = subprocess.run(['powershell', '-NoProfile', '-Command',
                              "(Get-NetTCPConnection -LocalPort %d -State Listen -EA 0 | Measure-Object).Count" % p],
                             capture_output=True, text=True, timeout=25,
                             creationflags=0x08000000).stdout.strip()
        return out == '1'
    except Exception:
        return False


print("========== \u5168\u94fe\u9010\u9879\u5b9e\u6d4b ==========")

# 1 ports
for p in (80, 8000, 8089, 8099, 5555):
    pass
import subprocess as sp
for p in (8000, 8089, 8099, 5555):
    say(OK if listen(p) else BAD, "\u7aef\u53e3 %d \u76d1\u542c" % p)

# 2 processes
try:
    ps = sp.run(['powershell', '-NoProfile', '-Command',
                 "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | ForEach-Object { $_.CommandLine }"],
                capture_output=True, text=True, timeout=30).stdout
    for name in ('npcap_http80', 'probe8099', 'cloud_api', 'tls_relay_v2', 'watch_auto'):
        say(OK if name in ps else BAD, "\u8fdb\u7a0b %s" % name)
except Exception as e:
    say(BAD, "\u8fdb\u7a0b\u68c0\u67e5\u5931\u8d25 %s" % e)

# 3 table (cloud_api 8000)
h, b = http(8000, '/api/v1/pub/microServer/?serverTypes=SA106003,SB103015,SB103013')
try:
    obj = json.loads(b.decode('utf-8'))
    dl = obj['microServerDtoList']
    # \u65b0\u683c\u5f0f\u955c\u50cf\u771f\u670d\u52a1\u5668: domainOrIp \u7eaf IP, \u65e0\u534f\u8bae\u5934
    byt = {}
    for e in dl:
        byt.setdefault(e['serverType'], []).append(e)
    a = byt.get('SA106003', [])
    c = byt.get('SB103015', [])
    say(OK if a and a[0]['domainOrIp'] == '192.168.137.1' and a[0]['port'] == 8099 else BAD,
        "\u8868 SA106003 -> %s:%s (\u7eafIP)" % (a[0]['domainOrIp'], a[0]['port']) if a else "\u8868 SA106003 \u7f3a\u5931")
    say(OK if c and c[0]['domainOrIp'] == '192.168.137.1' and c[0]['port'] == 8000 else BAD,
        "\u8868 SB103015 -> %s:%s" % (c[0]['domainOrIp'], c[0]['port']) if c else "\u8868 SB103015 \u7f3a\u5931")
    real_fields = {'serverId', 'domainOrIp', 'port', 'dirLocation', 'serverType', 'schList', 'mode', 'index'}
    got = set(a[0].keys()) if a else set()
    say(OK if real_fields <= got else BAD,
        "\u8868\u5b57\u6bb5\u96c6\u5408\u8986\u76d6\u771f\u670d\u52a1\u5668: \u7f3a %s" % sorted(real_fields - got))
    say(OK if a and a[0]['mode'] == 1 and a[0]['schList'] == [0] else BAD,
        "mode/schList \u5bf9\u9f50\u771f\u683c\u5f0f: mode=%s schList=%s" % (a[0]['mode'] if a else '?', a[0]['schList'] if a else '?'))
    say(OK if obj.get('updateTime') == 1702524647 else BAD,
        "updateTime \u5bf9\u9f50\u771f\u503c: %s" % obj.get('updateTime'))
    say(OK if len(a) >= 2 else WARN, "\u6bcf\u7c7b\u578b\u5019\u9009\u6570: %d" % len(a))
except Exception as e:
    say(BAD, "\u8868\u89e3\u6790\u5931\u8d25: %s  body=%r" % (e, b[:120]))

# 4 release note (8000)
h, b = http(8000, '/api/v1/pub/distribution/apps/com.xh.zhitongyunstu/versions/1/check')
try:
    o = json.loads(b.decode('utf-8'))
    say(OK if o.get('versionCode') == 999999 and o.get('url') else BAD,
        "\u66f4\u65b0\u68c0\u67e5 -> versionCode=%s url=%s" % (o.get('versionCode'), o.get('url')))
    say(OK if str(o.get('url', '')).endswith('/note.html') else WARN,
        "url \u6307\u5411\u6211\u4eec\u7684\u9875\u9762: %s" % o.get('url'))
except Exception as e:
    say(BAD, "\u66f4\u65b0\u68c0\u67e5\u89e3\u6790\u5931\u8d25 %s %r" % (e, b[:120]))

# 5 assist chain (8000)
h, b = http(8000, '/api/v1/users/2112229/devices/R52N9067SSF/assists')
try:
    o = json.loads(b.decode('utf-8'))
    say(OK if o.get('id') else BAD, "\u534f\u52a9\u4f1a\u8bdd -> %s" % o.get('id'))
except Exception as e:
    say(BAD, "\u534f\u52a9\u4f1a\u8bdd\u5931\u8d25 %s %r" % (e, b[:120]))
h, b = http(8000, '/api/v1/users/2112229/devices/R52N9067SSF/assists/assist_marvis_0001/tasks')
try:
    o = json.loads(b.decode('utf-8'))
    n = len(o) if isinstance(o, list) else -1
    instr = json.dumps(o)[:80] if o else ''
    say(OK if n > 0 else BAD, "\u534f\u52a9\u4efb\u52a1 %d \u6761, \u9996\u6761\u542b executeCmd=%s"
        % (n, 'executeCmd' in json.dumps(o)))
except Exception as e:
    say(BAD, "\u534f\u52a9\u4efb\u52a1\u5931\u8d25 %s %r" % (e, b[:120]))

# 6 probe 8099 same handlers
h, b = http(8099, '/api/v1/pub/distribution/apps/x/versions/1/check')
say(OK if b'999999' in b else BAD, "8099 \u66f4\u65b0\u68c0\u67e5\u54cd\u5e94 %r" % b[:80])
h, b = http(8099, '/api/v1/users/1/devices/2/assists/assist_marvis_0001/tasks')
say(OK if b'tasks' in b or b'executeCmd' in b or b'oadb' in b else BAD, "8099 \u534f\u52a9\u4efb\u52a1 %r" % b[:100])

# 7 payloads on disk
for f, minsz in (('agent.apk', 1000000), ('zipslip.bin', 100), ('note.html', 100)):
    p = os.path.join(PT, f)
    sz = os.path.getsize(p) if os.path.exists(p) else -1
    say(OK if sz >= minsz else BAD, "\u8f7d\u8377 %s = %d B" % (f, sz))

# 8 note.html route exists in spoofer source
src = io.open(os.path.join(PT, 'npcap_http80.py'), encoding='utf-8', errors='surrogateescape').read()
for tag, needle in (("note.html \u8def\u7531", 'NOTEHTML-ROUTE'),
                    ("TOKENLEAK \u8def\u7531", 'TOKENLEAK'),
                    ("captive \u5f00\u5173", 'CAPTIVE-MODE-TOGGLE'),
                    ("RELEASENOTE \u5904\u7406\u5668", 'RELEASENOTE-INJECT')):
    say(OK if needle in src else BAD, "%s \u5df2\u6ce8\u5165\u6e90\u7801" % tag)

# 9 captive mode
cm = os.path.join(PT, 'captive_mode.txt')
say(OK if os.path.exists(cm) else BAD, "captive_mode = %s" % (io.open(cm, encoding='ascii').read().strip() if os.path.exists(cm) else 'MISSING'))

# 10 token leak route reachable? (不能从本机直连 80, 只能确认源码里有)
say(OK if 'TOKENLEAK' in src else BAD, "TOKENLEAK \u56de\u4f20\u8def\u7531\u5b58\u5728(\u5192\u5145\u5668\u7aef\u53e3 80)")

# 11 mode + watcher
md = os.path.join(PT, 'cmd_mode.txt')
say(OK, "cmd_mode = %s" % (io.open(md, encoding='ascii').read().strip() if os.path.exists(md) else 'MISSING'))
wlog = os.path.join(PT, 'watch_auto.log')
say(OK if os.path.exists(wlog) else WARN, "\u54e8\u5175\u65e5\u5fd7\u5b58\u5728")

print()
print("========== \u6c47\u603b ==========")
okn = sum(1 for r in res if r.startswith(OK))
badn = sum(1 for r in res if r.startswith(BAD))
warnn = sum(1 for r in res if r.startswith(WARN))
print("OK=%d FAIL=%d WARN=%d" % (okn, badn, warnn))
for r in res:
    if not r.startswith(OK):
        print("  " + r)
