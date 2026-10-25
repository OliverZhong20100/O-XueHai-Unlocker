#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent_connect.py — 轮询连接平板上 agent 的 shell 服务 (0.0.0.0:4711)。

发现(2026-10-06, 反编译「网络检测」com.zhitongyun.wifimanager 得到):
  * com.olive.agent.AgentService: PORT = 0x1267 = 4711, new ServerSocket(4711) -> 0.0.0.0:4711
  * 协议: 连上后服务器先发 "READY uid=<uid>"
          每行一条命令 (/system/bin/sh -c <cmd>)
          回包: "<<<BEGIN>>>" + 输出 + "<<<END>>>"
          发送 "exit" 结束
  * 启动路径: com.olive.agent.MainActivity(桌面图标 label=SysUpdate).onCreate -> startService(AgentService)
             或 BootReceiver(BOOT_COMPLETED) -> startService
用法: python agent_connect.py [minutes]
"""
import os
import socket
import sys
import time
import datetime
import threading

# === PAD-AUTODETECT (patch_pad_ip.py): 按 MAC 找平板当前 IP, 免受 DHCP 换址影响 ===
_PAD_MAC = "80:20:fd:8b:4b:fa"
_pad_cache = {"ip": None, "t": 0.0}


def _p200_ip():
    import time as _t
    import subprocess as _sp
    import re as _re
    now = _t.time()
    if _pad_cache["ip"] and now - _pad_cache["t"] < 15:
        return _pad_cache["ip"]
    want = _PAD_MAC.replace(":", "-").lower()
    try:
        out = _sp.check_output(["arp", "-a"], creationflags=0x08000000).decode("utf-8", "replace")
        for line in out.splitlines():
            if want in line.lower():
                m = _re.search(r"(192\.168\.137\.\d+)", line)
                if m:
                    _pad_cache["ip"] = m.group(1)
                    _pad_cache["t"] = now
                    return m.group(1)
    except Exception:
        pass
    _pad_cache["ip"] = _pad_cache["ip"] or "192.168.137.154"
    _pad_cache["t"] = now
    return _pad_cache["ip"]
# === /PAD-AUTODETECT ===


BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "agent_shell.log")
OUT = os.path.join(BASE, "agent_shell_out.txt")
PAD = os.environ.get("AGENT_PAD", _p200_ip())
PORT = int(os.environ.get("AGENT_PORT", "4711"))
MINUTES = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0
PROBE_CMDS = [
    "id",
    "getprop ro.product.model",
    "getprop ro.build.version.release",
    "ls -la /sdcard | head -20",
    "cat /proc/version",
]


def wlog(msg):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg)
    try:
        with open(LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def interactive(sock):
    """连上后: 读 banner -> 跑一批侦察命令 -> 保持为交互 shell 写日志"""
    sock.settimeout(10)
    buf = b""
    try:
        buf = sock.recv(4096)
    except Exception:
        pass
    banner = buf.decode("utf-8", "replace").strip()
    wlog("!!!!!! [AGENT-UP] banner=%r" % banner[:120])
    with open(OUT, "a", encoding="utf-8", errors="replace") as f:
        f.write("===== %s  banner=%s =====\n" % (datetime.datetime.now(), banner))

    for cmd in PROBE_CMDS:
        try:
            sock.sendall((cmd + "\n").encode())
            time.sleep(0.8)
            data = b""
            sock.settimeout(6)
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if b"<<<END>>>" in data:
                        break
            except socket.timeout:
                pass
            txt = data.decode("utf-8", "replace")
            wlog("[CMD] %s -> %s" % (cmd, txt.replace("\n", " | ")[:400]))
            with open(OUT, "a", encoding="utf-8", errors="replace") as f:
                f.write("\n$ %s\n%s\n" % (cmd, txt))
        except Exception as e:
            wlog("[CMD-ERR] %s -> %s" % (cmd, e))
            break
    wlog("!!!!!! [AGENT-SHELL-READY] \u53ef\u4ee5\u4e0b\u547d\u4ee4\u4e86 (\u5199\u5165 agent_cmd.txt \u5373\u6267\u884c)")
    # 保持连接: 监听 agent_cmd.txt, 有新内容就执行
    last = ""
    cf = os.path.join(BASE, "agent_cmd.txt")
    t0 = time.time()
    while time.time() - t0 < 3600:
        try:
            if os.path.exists(cf):
                c = open(cf, encoding="utf-8", errors="replace").read().strip()
                if c and c != last:
                    last = c
                    for line in c.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        sock.sendall((line + "\n").encode())
                        time.sleep(0.8)
                        d = b""
                        try:
                            while True:
                                ch = sock.recv(65536)
                                if not ch:
                                    break
                                d += ch
                                if b"<<<END>>>" in d:
                                    break
                        except socket.timeout:
                            pass
                        txt = d.decode("utf-8", "replace")
                        wlog("[EXEC] %s -> %s" % (line, txt.replace("\n", " | ")[:500]))
                        with open(OUT, "a", encoding="utf-8", errors="replace") as f:
                            f.write("\n$ %s\n%s\n" % (line, txt))
        except Exception as e:
            wlog("[LOOP-ERR] %s" % e)
            break
        time.sleep(2)
    try:
        sock.close()
    except Exception:
        pass


def main():
    wlog("===== agent_connect \u542f\u52a8: %s:%d, \u8f6e\u8be2 %.0f \u5206\u949f =====" % (PAD, PORT, MINUTES))
    t0 = time.time()
    n = 0
    while time.time() - t0 < MINUTES * 60:
        n += 1
        try:
            s = socket.create_connection((PAD, PORT), timeout=4)
            wlog("!!!!!! [AGENT-ACCEPT] \u8fde\u4e0a\u4e86! (第 %d \u6b21\u5c1d\u8bd5)" % n)
            interactive(s)
            return
        except socket.timeout:
            if n % 30 == 1:
                wlog("[wait] \u7b2c %d \u6b21\u5c1d\u8bd5: \u8d85\u65f6" % n)
        except ConnectionRefusedError:
            if n % 30 == 1:
                wlog("[wait] \u7b2c %d \u6b21\u5c1d\u8bd5: \u7aef\u53e3\u62d2\u7edd(\u670d\u52a1\u672a\u542f\u52a8)" % n)
        except Exception as e:
            if n % 30 == 1:
                wlog("[wait] \u7b2c %d \u6b21\u5c1d\u8bd5: %s" % (n, e))
        time.sleep(2)
    wlog("[exit] \u8f6e\u8be2\u7ed3\u675f, \u672a\u8fde\u4e0a")


if __name__ == "__main__":
    main()