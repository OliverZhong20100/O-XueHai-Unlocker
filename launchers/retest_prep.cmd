@echo off
rem full retest prep: kill ws8889 clean, restart one, restart hotspot to force reconnect
set PYTHONIOENCODING=utf-8
set PYTHONPATH=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest\pylibs
set BASE=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest
set PYW=D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\pythonw.exe
set WS8889_ONLY_DST=*
set DNS_IFINDEX=13

:kill
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'ws8889\.py' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
timeout /t 5 /nobreak >nul
powershell -NoProfile -Command "$n=(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'ws8889\.py' } | Measure-Object).Count; if($n -gt 0){ exit 1 } else { exit 0 }"
if errorlevel 1 goto kill
start "" /B "%PYW%" "%BASE%\ws8889.py" 86400
timeout /t 10 /nobreak >nul
echo [1/2] ws8889 single instance started
powershell -NoProfile -Command "[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]|Out-Null;$c=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile();$m=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($c);try{$m.StopTetheringAsync()|Out-Null}catch{};Start-Sleep -Seconds 5;try{$m.StartTetheringAsync()|Out-Null}catch{}" >nul 2>&1
timeout /t 15 /nobreak >nul
echo [2/2] hotspot restarted
echo retest_prep_done
