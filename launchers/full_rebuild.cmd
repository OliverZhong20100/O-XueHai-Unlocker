@echo off
rem 全栈重建 + 热点重启(强制平板重连 => ws8889 抓到新手握)
set PYTHONIOENCODING=utf-8
set PYTHONPATH=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest\pylibs
set BASE=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover
set PYW=D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\pythonw.exe
set DNS_IFINDEX=13
set WS8889_ONLY_DST=*
set WS8889_PORT=8889
set TABLE_FORCE_OURS=1

echo [1/4] kill all pythonw
taskkill /F /IM pythonw.exe >nul 2>&1
timeout /t 5 /nobreak >nul

echo [2/4] restart core stack
start "" /B "%PYW%" "%BASE%\pentest\npcap_http80.py" 86400
timeout /t 4 /nobreak >nul
start "" /B "%PYW%" "%BASE%\pentest\ws8889.py" 86400
timeout /t 3 /nobreak >nul
start "" /B "%PYW%" "%BASE%\pentest\dns_hijack.py" 86400
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\pentest\proxy8888.py"
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\pentest\cloud_api.py"
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\pentest\tls_passthrough.py"
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%BASE%\pentest\ws_reconnect_autoburst.py"
timeout /t 8 /nobreak >nul

echo [3/4] restart hotspot (forces tablet reconnect)
powershell -NoProfile -Command "[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null; $c=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile(); $m=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($c); try { $m.StopTetheringAsync() | Out-Null } catch {}; Start-Sleep -Seconds 4; try { $m.StartTetheringAsync() | Out-Null } catch {}"
timeout /t 20 /nobreak >nul

echo [4/4] done
