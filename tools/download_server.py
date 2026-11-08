#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dl_server.py -- APK download canary server for the 3200 push chain.

Serves files from BASE over plain HTTP on 0.0.0.0:PORT and appends every
request (client ip, method, path, UA, Range, bytes sent) to dl_server.log.

Purpose: the app-upgrade-prepare push path
    LauncherPushService.disposeMessage("app-upgrade-prepare", payload)
      -> PrepareAppUpgradeNotification.transformAppUpdateTask()
      -> AppUpdateModel.preDownloadApp(task)
      -> AppUpdateManager.preDownloadApp(task)
      -> realDownloadApp(): LRequest.url(task.downloadUrl) + setMd5(task.md5)
      -> DownloadManager.downloadFromBox(...)
  The URL is taken verbatim from the push payload, so a hit on this server is
  code-level proof that the push message was dispatched on the pad and that
  the box/MDM download+install channel is reachable with attacker-controlled
  URL and MD5.
"""
import os
import sys
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "dl_server.log")
PORT = int(os.environ.get("DL_PORT") or "8080")


def log(msg):
    line = "%s %s" % (time.strftime("%H:%M:%S") + (".%03d" % (int(time.time() * 1000) % 1000)), msg)
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


class Handler(SimpleHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    sys_version = ""

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=BASE, **kw)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        ua = self.headers.get("User-Agent", "-")
        rng = self.headers.get("Range", "-")
        host = self.headers.get("Host", "-")
        log("GET %s host=%s ua=%s range=%s%s" % (
            self.path, host, ua, rng,
            "" if self.headers.get("Referer") is None else " referer=" + str(self.headers.get("Referer"))))
        try:
            f = self.send_head()
            if f:
                n = 0
                try:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        n += len(chunk)
                except Exception as e:
                    log("SEND-ERR %s %s" % (type(e).__name__, e))
                finally:
                    f.close()
                log("DONE %s bytes=%d" % (self.path, n))
        except Exception as e:
            log("ERR %s %s" % (type(e).__name__, e))

    def do_HEAD(self):
        log("HEAD %s ua=%s" % (self.path, self.headers.get("User-Agent", "-")))
        try:
            f = self.send_head()
            if f:
                f.close()
        except Exception as e:
            log("ERR %s %s" % (type(e).__name__, e))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        log("POST %s len=%d body=%r" % (self.path, n, body[:200]))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def main():
    log("===== dl_server start base=%s port=%d =====" % (BASE, PORT))
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log("listening on 0.0.0.0:%d" % PORT)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
