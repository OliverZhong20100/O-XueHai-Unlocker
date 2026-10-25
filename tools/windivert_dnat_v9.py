# -*- coding: utf-8 -*-
"""
windivert_dnat_v9.py -- 回包改走 ndis 链路层裸帧（热点零风险版）

与 v8 唯一差异：
  v8 的 downlink 把会话回包用内核栈 w.send() 发出（源IP改为真云别名）。
  但该别名挂在 Loopback(ifIndex=1) 上，Windows 强主机发送检查判定
  "源地址不属于热点网卡" => 包被内核丢弃（weakhostsend 已开仍无效，
  因为 WinDivert 注入路径不走 weakhost 判定），平板永远收不到 SYN-ACK。

  v9 改为：session 回包不再回注内核，直接在热点网卡(ifIndex=12)上用
  Npcap 的 L2socket 发**链路层原始帧**（Ether/IP/TCP 全部自己构造，
  源IP=真云别名，校验和手工重算）。
  该手段已在 npcap3200.py 上实机验证：本机栈丢弃的伪造源帧，Npcap(NDIS)
  发送可穿透，平板对伪造 SYNACK 正常回 ACK。

  关键：全程不修改任何网卡地址/别名/路由/ICS 服务配置 —— 历史崩溃根因是
  "把 /32 别名挂到 ICS 私有网卡触发 ipnathlp.dll 访问违例"，本版根本不碰
  网卡地址，故热点不会崩。
"""
import datetime
import os
import queue
import struct
import subprocess
import threading
import time

import pydivert
from pydivert import Direction, Layer

def _detect_pad(mac="80:20:fd:8b:4b:fa"):
    """按平板 MAC 从 ARP 表解析其当前 IP, 解决 DHCP 漂移导致写死 IP 失效。"""
    import re as _re
    import subprocess as _sp
    want = mac.replace(":", "-").lower()
    try:
        out = _sp.check_output(["arp", "-a"], creationflags=0x08000000).decode("utf-8", "replace")
        for line in out.splitlines():
            if want in line.lower():
                m = _re.search(r"(192\.168\.137\.\d+)", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "192.168.137.73"


PAD = _detect_pad()
PAD_MAC = "80:20:fd:8b:4b:fa"
MY_IP = "192.168.137.1"
LAN = "192.168.137."
IF_INDEX = 12
ICS_MAC = "52:bb:b5:4f:7f:3e"
REDIR_PORTS = {80, 443, 3200, 8000, 8089, 8443, 20000}

FALLBACK_ALIASES = {"47.99.85.219", "47.111.87.154", "43.227.195.99",
                    "39.173.108.47", "52.80.72.178", "47.111.168.116"}

DIR = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(DIR, "windivert_dnat_v9.log")

sess = {}
_lock = threading.Lock()
_h_inj = None
_stats = {"redir": 0, "back": 0, "pass": 0, "own_pass": 0, "drop_cloud": 0,
          "tx_ok": 0, "tx_err": 0}

_own = {}
_own_lock = threading.Lock()

_txq = queue.Queue(maxsize=8192)
_l2sock = None
_l2_lock = threading.Lock()


def detect_aliases():
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -like 'Loopback*'}).IPAddress"],
            timeout=20, stderr=subprocess.DEVNULL).decode("utf-8", "replace")
        s = {x.strip() for x in out.split() if x.strip() and x.strip() != "127.0.0.1"}
        return s or set(FALLBACK_ALIASES)
    except Exception:
        return set(FALLBACK_ALIASES)


ALIASES = detect_aliases()


def _sig(pkt):
    t = pkt.tcp
    if t is None:
        return None
    seq = getattr(t, "seq_num", None)
    if seq is None:
        seq = getattr(t, "seq", 0) or 0
    ackn = getattr(t, "ack_num", None)
    if ackn is None:
        ackn = getattr(t, "ack_num", 0) or 0
    return (pkt.src_addr, pkt.dst_addr, int(pkt.src_port or 0), int(pkt.dst_port or 0),
            int(seq), int(ackn),
            bool(t.syn), bool(t.ack), bool(t.psh), bool(t.fin), bool(t.rst))


def mark_own(pkt):
    sig = _sig(pkt)
    if sig is None:
        return
    with _own_lock:
        _own[sig] = time.time()
        if len(_own) > 4000:
            now = time.time()
            for k in [k for k, t in _own.items() if now - t > 120]:
                _own.pop(k, None)


def is_own(pkt, pop=True):
    sig = _sig(pkt)
    if sig is None:
        return False
    with _own_lock:
        if pop:
            return _own.pop(sig, None) is not None
        return sig in _own


def wlog(s):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S"), s)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)


# ---------------- 链路层裸帧发送 ----------------

def iface_name():
    from scapy.arch.windows import get_windows_if_list
    for d in get_windows_if_list():
        if d.get("index") == IF_INDEX:
            return r"\Device\NPF_" + d["guid"]
    return None


def _l2():
    global _l2sock
    with _l2_lock:
        if _l2sock is None:
            from scapy.all import conf
            nm = iface_name()
            if not nm:
                raise RuntimeError("找不到 ifIndex=%d 的 Npcap 接口" % IF_INDEX)
            _l2sock = conf.L2socket(iface=nm)
        return _l2sock


def _ck16(data):
    s = 0
    n = len(data)
    for i in range(0, n - 1, 2):
        s += (data[i] << 8) | data[i + 1]
    if n % 2:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def forge_frame(raw, new_src):
    """把 WinDivert 抓到的原始 IP 包改源IP并重算校验和，套上以太头。
    纯字节级操作，不依赖 scapy 解析重建，确保字节级正确。"""
    b = bytearray(raw)
    if len(b) < 20:
        return None
    ihl = (b[0] & 0x0F) * 4
    if b[9] != 6 or len(b) < ihl + 20:      # 非 TCP 或过短
        return None
    src = bytes(int(x) for x in new_src.split("."))
    dst = bytes(b[16:20])
    b[12:16] = src
    # IP 头校验和
    b[10:12] = b"\x00\x00"
    b[10:12] = struct.pack("!H", _ck16(bytes(b[:ihl])))
    # TCP 校验和（含伪头）
    tcp = bytearray(b[ihl:])
    tcp[16:18] = b"\x00\x00"
    ph = src + dst + b"\x00\x06" + struct.pack("!H", len(tcp))
    ck = _ck16(ph + bytes(tcp))
    if ck == 0:
        ck = 0xFFFF
    b[ihl + 16:ihl + 18] = struct.pack("!H", ck)
    eth = (bytes.fromhex(PAD_MAC.replace(":", ""))
           + bytes.fromhex(ICS_MAC.replace(":", ""))
           + b"\x08\x00")
    return eth + bytes(b)


def tx_worker():
    """串行发送线程：避免 L2 send 阻塞 WinDivert recv 循环造成 RST 延迟。"""
    while True:
        item = _txq.get()
        if item is None:
            return
        raw, orig, meta = item
        try:
            frame = forge_frame(raw, orig)
            if frame is None:
                _stats["tx_err"] += 1
                wlog("[TXERR] 无法构造裸帧 orig=%s" % orig)
                continue
            _l2().send(frame)
            _stats["tx_ok"] += 1
            if meta:
                wlog("[TX] %s" % meta)
        except Exception as e:
            _stats["tx_err"] += 1
            if _stats["tx_err"] <= 20 or _stats["tx_err"] % 50 == 0:
                wlog("[TXERR] %s: %s" % (type(e).__name__, e))


# ---------------- WinDivert 两条链 ----------------

def uplink():
    flt = "tcp and (ip.SrcAddr == %s or ip.DstAddr == %s)" % (PAD, PAD)
    w = pydivert.WinDivert(flt, layer=Layer.NETWORK_FORWARD)
    w.open()
    wlog("[FWD] open ok 别名=%s (别名目的也走REDIR)" % sorted(ALIASES))
    while True:
        try:
            pkt = w.recv()
        except Exception as e:
            wlog("[ERR-RECV] %s: %s" % (type(e).__name__, e))
            continue
        try:
            src, dst = pkt.src_addr, pkt.dst_addr
            sp, dp = int(pkt.src_port or 0), int(pkt.dst_port or 0)
            if src == PAD and not dst.startswith(LAN):
                if dp in REDIR_PORTS:
                    with _lock:
                        sess[(dp, sp)] = (dst, time.time())
                    raw = bytes(pkt.raw)
                    loc = pydivert.Packet(raw, interface=(IF_INDEX, 0),
                                          direction=Direction.INBOUND, layer=Layer.NETWORK)
                    loc.dst_addr = MY_IP
                    loc.recalculate_checksums()
                    _h_inj.send(loc)
                    _stats["redir"] += 1
                    if pkt.tcp and pkt.tcp.syn and not pkt.tcp.ack:
                        wlog("[REDIR] %s:%d -> %s:%d => %s:%d (sess=%d)"
                             % (src, sp, dst, dp, MY_IP, dp, len(sess)))
                else:
                    _stats["pass"] += 1
                    w.send(pkt)
            elif dst == PAD and not src.startswith(LAN):
                if src in ALIASES and not is_own(pkt, pop=False):
                    _stats["drop_cloud"] += 1
                    if pkt.tcp and pkt.tcp.syn and pkt.tcp.ack:
                        wlog("[DROP] 真云回包 %s:%d -> %s:%d" % (src, sp, PAD, dp))
                    continue
                if is_own(pkt):
                    _stats["own_pass"] += 1
                w.send(pkt)
            else:
                w.send(pkt)
        except Exception as e:
            wlog("[ERR-FWD] %s: %s" % (type(e).__name__, e))


def downlink():
    flt = "tcp and ip.SrcAddr == %s and ip.DstAddr == %s" % (MY_IP, PAD)
    w = pydivert.WinDivert(flt, layer=Layer.NETWORK)
    w.open()
    wlog("[NET] open ok (NETWORK) 会话回包改走 ndis 裸帧")
    while True:
        try:
            pkt = w.recv()
        except Exception as e:
            wlog("[ERR-RECVNET] %s: %s" % (type(e).__name__, e))
            continue
        try:
            sp, dp = int(pkt.src_port or 0), int(pkt.dst_port or 0)
            with _lock:
                rec = sess.get((sp, dp))
            if rec:
                orig = rec[0]
                _stats["back"] += 1
                meta = None
                if pkt.tcp and pkt.tcp.syn and pkt.tcp.ack:
                    meta = ("SYNACK %s:%d -> %s:%d 伪装源=%s seq=%d ack=%d"
                            % (MY_IP, sp, PAD, dp, orig,
                               int(getattr(pkt.tcp, "seq_num", 0)),
                               int(getattr(pkt.tcp, "ack_num", 0))))
                try:
                    _txq.put_nowait((bytes(pkt.raw), orig, meta))
                except queue.Full:
                    _stats["tx_err"] += 1
                continue    # 原件丢弃，绝不让内核栈尝试发送
            else:
                if pkt.tcp and pkt.tcp.syn and pkt.tcp.ack:
                    wlog("[BACK?] 无会话记录(放行) %s:%d -> %s:%d" % (MY_IP, sp, PAD, dp))
                mark_own(pkt)
                w.send(pkt)
        except Exception as e:
            wlog("[ERR-NET] %s: %s" % (type(e).__name__, e))


def heartbeat():
    last = 0
    while True:
        time.sleep(20)
        now = time.time()
        with _lock:
            dead = [k for k, v in sess.items() if now - v[1] > 1800]
            for k in dead:
                sess.pop(k, None)
            n = len(sess)
        if now - last > 60:
            last = now
            wlog("[BEAT] %s sess=%d" % (_stats, n))


if __name__ == "__main__":
    wlog("windivert_dnat_v9 start (下行回包改 ndis 裸帧, 不动任何网卡配置)")
    _h_inj = pydivert.WinDivert("ip.SrcAddr == 0.0.0.0 and ip.DstAddr == 0.0.0.0",
                                layer=Layer.NETWORK)
    _h_inj.open()
    wlog("[INJ] open ok (NETWORK, 仅用于注入)")
    threading.Thread(target=tx_worker, daemon=True).start()
    threading.Thread(target=downlink, daemon=True).start()
    threading.Thread(target=heartbeat, daemon=True).start()
    # 预热 L2 socket 并自检裸帧通道
    try:
        nm = iface_name()
        _l2()
        wlog("[L2] iface=%s ready" % nm)
    except Exception as e:
        wlog("[L2ERR] %s: %s" % (type(e).__name__, e))
    uplink()
