@echo off
set PYTHONIOENCODING=utf-8
set PYTHONPATH=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest\pylibs
set WS_LOCAL_PORT=8890
set BASE=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest
set PYW=D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\pythonw.exe
set PYS=D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\python.exe
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'ws_server_local' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\ws_server_local.py"
timeout /t 5 /nobreak >nul
"%PYS%" "%BASE%\extract_trigger.py" > "%BASE%\extract_trigger_out.txt" 2>&1
echo extract_trigger_done
