$ErrorActionPreference = 'SilentlyContinue'
$R = 'C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest'
$log = Join-Path $R 'swap3200.log'
function L($m) { "$([DateTime]::Now.ToString('HH:mm:ss.fff')) $m" | Add-Content -Path $log -Encoding UTF8 }

L "=== swap3200 start (elevated=$([bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) ==="

$pat = 'npcap3200|np3200push|push_probe|push_canary|push_inject|vis_probe|watch_pad|force_rst|sniff_pad|reg_parse'
$procs = Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'"
foreach ($p in $procs) {
    if ($p.CommandLine -match $pat) {
        L "kill $($p.ProcessId) :: $($p.CommandLine)"
        Stop-Process -Id $p.ProcessId -Force
    } else {
        L "keep $($p.ProcessId) :: $($p.CommandLine)"
    }
}

Start-Sleep -Seconds 2
$pyw = 'D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\pythonw.exe'
$script = Join-Path $R 'np3200push.py'
$cfg = Join-Path $R 'probe_order.txt'
if (Test-Path $cfg) {
    $env:PUSH_PROBES = (Get-Content $cfg -Raw).Trim()
    L "PUSH_PROBES=$($env:PUSH_PROBES)"
}
$env:PUSH_ENABLE = '0'
Remove-Item (Join-Path $R 'inject_cmd.txt') -Force
L "PUSH_ENABLE=0, inject_cmd.txt cleared"
Start-Process -FilePath $pyw -ArgumentList ('"' + $script + '" 3600')
L "started np3200push.py 3600"

Start-Sleep -Seconds 3
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" | ForEach-Object { L "now $($_.ProcessId) :: $($_.CommandLine)" }
L "=== swap3200 end ==="
