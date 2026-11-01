#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""env_percept.py — 学海平板链路「环境信息感知控件」

自感知（无需任何硬编码的账号/设备信息）：
  * 网卡 / 网关 / 本机在实验网中的地址
  * 平板的 IP 与 MAC（从 ARP 表 + 主动探测推断，不写死）
  * 证书与私钥（Let's Encrypt 链）路径
  * 端口占用 / 进程 / 管理员权限
  * 链路组件是否在运行

输出 xh_env.json，供 xh_chain.py 与各组件自适应读取。
"""
import ctypes
import json
import os
import re
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "xh_env.json")


def run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def local_ipv4():
    """本机默认出口 IP + 各网卡 IPv4。"""
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 53))
        ips.append({"addr": s.getsockname()[0], "role": "outbound"})
        s.close()
    except Exception:
        pass
    out = run(["ipconfig"])
    cur = None
    for ln in out.splitlines():
        m = re.search(r"适配器\s+(.+?):|adapter\s+(.+?):", ln)
        if m:
            cur = (m.group(1) or m.group(2) or "").strip()
            continue
        m = re.search(r"IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)", ln)
        if m and cur:
            ips.append({"addr": m.group(1), "role": "iface", "iface": cur})
    # 去重
    seen, uniq = set(), []
    for it in ips:
        if it["addr"] not in seen:
            seen.add(it["addr"])
            uniq.append(it)
    return uniq


def arp_table():
    out = run(["arp", "-a"])
    rows = []
    for ln in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", ln)
        if m:
            ip, mac = m.group(1), m.group(2).lower().replace("-", ":")
            if ip.startswith(("224.", "239.", "255.")):
                continue
            rows.append({"ip": ip, "mac": mac})
    return rows


def find_pad(ips, arp):
    """平板 = 实验网段内、非网关、有 ARP 记录的设备。优先选网段最小的私网。"""
    cands = [r for r in arp if not r["ip"].endswith(".255")]
    if not cands:
        return None
    # 选出与某个本机私网地址同网段的
    best = None
    for it in ips:
        a = it["addr"]
        if not (a.startswith("192.168.") or a.startswith("10.") or a.startswith("172.")):
            continue
        pref = ".".join(a.split(".")[:3]) + "."
        for r in cands:
            if r["ip"].startswith(pref) and r["ip"] != a:
                # 优先取其网段内最后一个（常见 DHCP 地址）
                if best is None or r["ip"] > best["ip"]:
                    best = dict(r, net=".".join(a.split(".")[:3]) + ".0/24")
    return best


def port_state(ports):
    res = {}
    out = run(["netstat", "-ano", "-p", "TCP"])
    for p in ports:
        hit = None
        for ln in out.splitlines():
            if (":%d " % p) in ln and "LISTENING" in ln.upper():
                m = re.search(r"\s(\d+)\s*$", ln)
                hit = {"listening": True, "pid": int(m.group(1)) if m else None}
                break
        res[p] = hit or {"listening": False, "pid": None}
    return res


def components():
    out = run(["powershell", "-NoProfile", "-Command",
               "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' } | "
               "ForEach-Object { $_.ProcessId.ToString() + '|' + $_.CommandLine }"])
    comp = {"spoofer": [], "arp": [], "mitm": [], "cert": [], "other": []}
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or "|" not in ln:
            continue
        pid, cmd = ln.split("|", 1)
        try:
            pid = int(pid)
        except Exception:
            continue
        for key, pat in (("spoofer", "npcap_http80"), ("arp", "arp_captive"),
                         ("mitm", "tls_mitm"), ("cert", "tls_redirect")):
            if pat in cmd:
                comp[key].append(pid)
                break
        else:
            comp["other"].append(pid)
    return comp


def cert_info():
    cert = os.path.join(HERE, "mitm_fullchain.pem")
    key = os.path.join(HERE, "mitm_server.key")
    info = {"cert": cert, "key": key, "cert_exists": os.path.exists(cert),
            "key_exists": os.path.exists(key), "subject": None, "issuer": None, "not_after": None}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        c = x509.load_pem_x509_certificate(open(cert, "rb").read())
        info["subject"] = c.subject.rfc4514_string()
        info["issuer"] = c.issuer.rfc4514_string()
        info["not_after"] = str(c.not_valid_after_utc)
    except Exception as e:
        info["cert_err"] = str(e)[:120]
    return info


def main():
    print("[*] env_percept: 感知环境...")
    env = {
        "generated_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        "is_admin": is_admin(),
        "ipv4": local_ipv4(),
        "arp": arp_table(),
        "pad": None,
        "ports": port_state([80, 443, 8000, 8889, 8099]),
        "components": components(),
        "cert": cert_info(),
        "hints": [],
    }
    env["pad"] = find_pad(env["ipv4"], env["arp"])
    if not env["pad"]:
        env["hints"].append("未从 ARP 表找到平板；请在平板联网后重试，或用 --pad-ip 指定")
    if not env["is_admin"]:
        env["hints"].append("当前非管理员：WinDivert/ip 别名等需提权（xh_chain.py setup 会发起 UAC）")
    if not env["cert"]["cert_exists"]:
        env["hints"].append("未找到 mitm_fullchain.pem；请先放置证书")
    json.dump(env, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("[+] 已写入 " + OUT)
    print("    pad        = %s" % (env["pad"]["ip"] if env["pad"] else "?"))
    print("    pad_mac    = %s" % (env["pad"]["mac"] if env["pad"] else "?"))
    print("    admin      = %s" % env["is_admin"])
    print("    cert       = %s" % (env["cert"]["subject"] or env["cert"].get("cert_err")))
    return 0 if env["pad"] else 2


if __name__ == "__main__":
    sys.exit(main())
