# -*- coding: utf-8 -*-
"""ws_server_local.py - 真实 WebSocket 服务端(局域网), 用于接收平板被重定向过来的教室 WS 连接。

用途: 先通过教室 WS 注入 canvas_tag/type=6 消息(data="ws://<our_ip>:<port>"),
      端侧 StudentWebSocketHelper 会把下次重连目标改为该地址 => 平板主动连我们。
      本服务完整实现 RFC6455 握手 + text/binary/ping/pong/close, 并记录每一条收到/发出的帧。

默认监听 0.0.0.0:8890 (避开 8889 的链路层冒充器)。
"""
import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "ws_local.log")
FRAMES = os.path.join(BASE, "ws_local_frames.log")
PORT = int(os.environ.get("WS_LOCAL_PORT") or 8890)
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_lock = threading.Lock()
_stat = {"conn": 0, "open": 0, "frame_in": 0, "frame_out": 0, "ping": 0, "text_in": 0}
_clients = []


def wlog(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)


def wframe(m):
    try:
        with open(FRAMES, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (time.strftime("%H:%M:%S"), m))
    except Exception:
        pass


def ws_accept(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def build_frame(opcode, payload, mask=False):
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([(0x80 if mask else 0) | n])
    elif n < 65536:
        head += bytes([(0x80 if mask else 0) | 126]) + struct.pack("!H", n)
    else:
        head += bytes([(0x80 if mask else 0) | 127]) + struct.pack("!Q", n)
    if mask:
        mk = os.urandom(4)
        head += mk
        payload = bytes(b ^ mk[i % 4] for i, b in enumerate(payload))
    return head + payload


def parse_frames(buf):
    """返回 [(fin,opcode,payload,consumed)]"""
    out = []
    i = 0
    while True:
        if len(buf) - i < 2:
            break
        b0, b1 = buf[i], buf[i + 1]
        fin = b0 & 0x80
        op = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        p = i + 2
        if ln == 126:
            if len(buf) - p < 2:
                break
            ln = struct.unpack("!H", buf[p:p + 2])[0]
            p += 2
        elif ln == 127:
            if len(buf) - p < 8:
                break
            ln = struct.unpack("!Q", buf[p:p + 8])[0]
            p += 8
        mk = b""
        if masked:
            if len(buf) - p < 4:
                break
            mk = buf[p:p + 4]
            p += 4
        if len(buf) - p < ln:
            break
        pay = bytearray(buf[p:p + ln])
        if masked:
            for j in range(ln):
                pay[j] ^= mk[j % 4]
        out.append((fin, op, bytes(pay), p + ln - i))
        i = p + ln
    return out, i


def broadcast(payload):
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    n = 0
    for c in list(_clients):
        try:
            c.sendall(build_frame(0x1, data))
            n += 1
        except Exception:
            try:
                _clients.remove(c)
            except Exception:
                pass
    with _lock:
        _stat["frame_out"] += n
    return n


def handle(c, addr):
    src = addr[0]
    try:
        c.settimeout(15)
        req = b""
        while b"\r\n\r\n" not in req and len(req) < 16384:
            d = c.recv(4096)
            if not d:
                return
            req += d
        head = req.decode("utf-8", "replace")
        key = ""
        for ln in head.split("\r\n"):
            if ln.lower().startswith("sec-websocket-key:"):
                key = ln.split(":", 1)[1].strip()
        if not key:
            wlog("[WS] %s 非 WS 握手, 关闭: %s" % (src, head.split("\r\n")[0][:80]))
            c.close()
            return
        resp = ("HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n\r\n" % ws_accept(key))
        c.sendall(resp.encode())
        with _lock:
            _stat["conn"] += 1
            _stat["open"] += 1
        _clients.append(c)
        wlog("!!!!!! [WS-OPEN] %s:%d 已连入(平板被重定向成功?) 请求头:\n%s" % (src, addr[1], head[:600]))
        wframe("[OPEN %s] %s" % (src, head.replace("\r\n", " | ")[:400]))
        c.settimeout(None)
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
            frames, used = parse_frames(buf)
            buf = buf[used:]
            for fin, op, pay, _ in frames:
                if op == 0x1:
                    with _lock:
                        _stat["frame_in"] += 1
                        _stat["text_in"] += 1
                    wlog("[TEXT-IN] %s %dB %s" % (src, len(pay), pay[:260].decode("utf-8", "replace")))
                    wframe("[IN %s] %s" % (src, pay[:600].decode("utf-8", "replace")))
                elif op == 0x9:
                    with _lock:
                        _stat["ping"] += 1
                    c.sendall(build_frame(0xA, pay))
                elif op == 0x8:
                    wlog("[CLOSE] %s" % src)
                    raise SystemExit if False else None
    except Exception as e:
        wlog("[WS-ERR] %s %r" % (src, e))
    finally:
        try:
            _clients.remove(c)
        except Exception:
            pass
        try:
            c.close()
        except Exception:
            pass


def main():
    wlog("===== ws_server_local start :%d (真WS服务, 用于接管被重定向的教室通道) =====" % PORT)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(16)
    wlog("listening 0.0.0.0:%d" % PORT)

    def stats():
        while True:
            time.sleep(60)
            wlog("[STATS] %s" % json.dumps(_stat))
    threading.Thread(target=stats, daemon=True).start()

    # 外部注入文件: ws_local_send.txt 内容会被广播给所有已连接客户端
    send_file = os.path.join(BASE, "ws_local_send.txt")
    def injector():
        last = None
        while True:
            try:
                if os.path.exists(send_file):
                    txt = open(send_file, encoding="utf-8").read().strip()
                    if txt and txt != last:
                        n = broadcast(txt)
                        wlog("[INJECT] 已广播 %dB -> %d 个连接" % (len(txt), n))
                        last = txt
            except Exception as e:
                wlog("[INJECT-ERR] %r" % (e,))
            time.sleep(3)
    threading.Thread(target=injector, daemon=True).start()

    while True:
        try:
            c, addr = s.accept()
            threading.Thread(target=handle, args=(c, addr), daemon=True).start()
        except Exception as e:
            wlog("[ACCEPT-ERR] %r" % (e,))


if __name__ == "__main__":
    main()
