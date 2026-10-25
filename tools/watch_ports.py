# -*- coding: utf-8 -*-
"""watch_ports.py - 循环扫描平板动态端口段, 一旦发现开放端口立刻输出并做 HTTP 探测。
"""
import os
import socket
import sys
import threading
import time

PAD = os.environ.get("PAD_IP", "192.168.137.30")
START = int(os.environ.get("P_START", "10000"))
END = int(os.environ.get("P_END", "60000"))
ROUNDS = int(os.environ.get("ROUNDS", "6"))
TIMEOUT = 0.5
WORKERS = 400
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "port_watch.log")


def w(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def scan_once():
    found = []
    lock = threading.Lock()
    idx = [0]
    ports = list(range(START, END + 1))
    ilock = threading.Lock()

    def probe(p):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            if s.connect_ex((PAD, p)) == 0:
                with lock:
                    found.append(p)
        except Exception:
            pass
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass

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
    return sorted(found)


def http_probe(port):
    try:
        s = socket.create_connection((PAD, port), timeout=2)
        s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % PAD.encode())
        s.settimeout(2)
        data = b""
        try:
            while len(data) < 1500:
                c = s.recv(4096)
                if not c:
                    break
                data += c
        except Exception:
            pass
        s.close()
        return data[:260].decode("latin1", "replace").replace("\r\n", " | ")
    except Exception as e:
        return "ERR %r" % (e,)


def main():
    w("===== port_watch start %s range=%d-%d rounds=%d =====" % (PAD, START, END, ROUNDS))
    for r in range(1, ROUNDS + 1):
        t0 = time.time()
        found = scan_once()
        w("round %d: %.1fs open=%s" % (r, time.time() - t0, found))
        for p in found:
            w("  ★ PORT %d -> %s" % (p, http_probe(p)))
        time.sleep(2)
    w("===== port_watch done =====")


if __name__ == "__main__":
    main()
