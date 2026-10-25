@echo off
rem ============================================================
rem  rebuild14.cmd - 热点 ifIndex 变为 14 后的全栈重建
rem ============================================================
set PYTHONIOENCODING=utf-8
set PYTHONPATH=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest\pylibs
set BASE=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest
set PYW=D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\pythonw.exe
set DNS_IFINDEX=14
set WS8889_ONLY_DST=*
set WS8889_PORT=8889
set TABLE_FORCE_OURS=1
echo [1/3] kill pythonw
taskkill /F /IM pythonw.exe >nul 2>&1
timeout /t 5 /nobreak >nul
echo [2/3] start core stack
start "" /B "%PYW%" "%BASE%\npcap_http80.py" 86400
timeout /t 4 /nobreak >nul
start "" /B "%PYW%" "%BASE%\ws8889.py" 86400
timeout /t 3 /nobreak >nul
start "" /B "%PYW%" "%BASE%\dns_hijack.py" 86400
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\proxy8888.py"
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\cloud_api.py"
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\tls_passthrough.py"
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\post_reboot_watch.py"
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\fast_handshake_inject.py"
timeout /t 8 /nobreak >nul
echo [3/3] done
