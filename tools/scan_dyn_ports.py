# -*- coding: utf-8 -*-
"""scan_dyn_ports.py - 并行扫描平板的动态端口段(找 com.xh.ftp.HttpServer 文件共享服务)。
用法: PAD_IP=192.168.137.30 python scan_dyn_ports.py [起始] [结束]
输出: 开放端口 + 对开放端口发一个 HTTP GET 看是否返回 HttpServer 特征。
"""
import os
import socket
import sys
import threading
import time

PAD = os.environ.get("PAD_IP", "192.168.137.30")
START = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
END = int(sys.argv[2]) if len(sys.argv) > 2 else 60000
TIMEOUT = 0.6
WORKERS = 300
open_ports = []
lock = threading.Lock()


def probe(port):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((PAD, port)) == 0:
            with lock:
                open_ports.append(port)
    except Exception:
        pass
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def main():
    t0 = time.time()
    ports = list(range(START, END + 1))
    idx = [0]
    ilock = threading.Lock()

    def worker():
        while True:
            with ilock:
                if idx[0] >= len(ports):
                    return
                p = ports[idx[0]]
                idx[0] += 1
            probe(p)

    ths = [threading.Thread(target=worker, daemon=True) for _ in range(WORKERS)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    print("scan %d-%d done in %.1fs" % (START, END, time.time() - t0), flush=True)
    print("OPEN: %s" % sorted(open_ports), flush=True)
    for p in sorted(open_ports):
        try:
            s = socket.create_connection((PAD, p), timeout=2)
            s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % PAD.encode())
            s.settimeout(2)
            data = b""
            try:
                while len(data) < 2000:
                    c = s.recv(4096)
                    if not c:
                        break
                    data += c
            except Exception:
                pass
            s.close()
            head = data[:300].decode("latin1", "replace").replace("\r\n", " | ")
            print("PORT %d -> %s" % (p, head), flush=True)
        except Exception as e:
            print("PORT %d -> ERR %r" % (p, e), flush=True)


if __name__ == "__main__":
    main()
