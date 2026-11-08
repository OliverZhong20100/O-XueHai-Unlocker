$ErrorActionPreference = 'Continue'
$R = 'C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest'
$log = Join-Path $R 'resume_all.log'
function W([string]$m) { $ts = (Get-Date).ToString('HH:mm:ss.fff'); Add-Content -Path $log -Value "$ts $m" -Encoding UTF8 }
W "==== resume ===="

$pyw = 'D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\pythonw.exe'

# ---- 1. find hotspot interface ----
$ip = Get-NetIPAddress -AddressFamily IPv4 -EA 0 | Where-Object { $_.IPAddress -eq '192.168.137.1' } | Select-Object -First 1
if (-not $ip) {
    W "NO_HOTSPOT: 192.168.137.1 not present"
    exit 3
}
$alias = $ip.InterfaceAlias
$idx = $ip.InterfaceIndex
$ad = Get-NetAdapter -InterfaceIndex $idx -EA 0
$mac = ($ad.MacAddress -replace '-', ':').ToLower()
$guid = $ad.InterfaceGuid
W "hotspot iface='$alias' idx=$idx mac=$mac guid=$guid"

# ---- 2. find pad ip ----
$padIp = ''
# 只认热点网段内的邻居表，避免拿到平板在别的网段(<SSID>)的地址
$nb = Get-NetNeighbor -InterfaceIndex $idx -AddressFamily IPv4 -EA 0 |
      Where-Object { ($_.LinkLayerAddress -replace '-', ':').ToLower() -eq '02:00:00:00:00:01' } |
      Select-Object -First 1
if ($nb) { $padIp = $nb.IPAddress }
if (-not $padIp) {
    $arp = (arp -a -N 192.168.137.1) -join "`n"
    $m = [regex]::Match($arp, '(192\.168\.137\.\d+)\s+80-20-fd-8b-4b-fa')
    if ($m.Success) { $padIp = $m.Groups[1].Value }
}
if (-not $padIp) { $padIp = '192.168.137.13' }
W "pad ip = $padIp"

# ---- 3. patch responder scripts ----
function Patch([string]$file, [hashtable]$repl) {
    $p = Join-Path $R $file
    if (-not (Test-Path $p)) { W "patch skip (missing) $file"; return }
    $t = [IO.File]::ReadAllText($p)
    $orig = $t
    foreach ($k in $repl.Keys) {
        $t = [regex]::Replace($t, $repl[$k][0], $repl[$k][1])
    }
    if ($t -ne $orig) {
        [IO.File]::WriteAllText($p, $t, (New-Object System.Text.UTF8Encoding($false)))
        W "patched $file"
    } else {
        W "patch no-change $file"
    }
}

$quotedMac = '"' + $mac + '"'
Patch 'np3200push.py'  @{ mac = @('(?m)^ICS_MAC\s*=\s*"[^"]*"', "ICS_MAC = $quotedMac"); idx = @('(?m)^IFINDEX\s*=\s*\d+', "IFINDEX = $idx") }
Patch 'npcap_pbs.py'   @{ mac = @('(?m)^ICS_MAC\s*=\s*"[^"]*"', "ICS_MAC = $quotedMac"); idx = @('(?m)^IFINDEX\s*=\s*\d+', "IFINDEX = $idx") }
Patch 'npcap_http80.py' @{
    mac  = @('(?m)^ICS_MAC\s*=\s*"[^"]*"', "ICS_MAC = $quotedMac")
    idx  = @('(?m)^IFINDEX\s*=\s*\d+', "IFINDEX = $idx")
    want = @('(?m)^_want\s*=\s*"\{[^"]*\}"\.lower\(\)', ('_want = "{' + $guid + '}".lower()'))
}

# also rewrite the pad-ip fallback inside http80 detector
$hp = Join-Path $R 'npcap_http80.py'
if (Test-Path $hp) {
    $t = [IO.File]::ReadAllText($hp)
    $t2 = [regex]::Replace($t, '_pad_cache\["ip"\]\s*=\s*_pad_cache\["ip"\]\s*or\s*"\d+\.\d+\.\d+\.\d+"', ('_pad_cache["ip"] = _pad_cache["ip"] or "' + $padIp + '"'))
    if ($t2 -ne $t) { [IO.File]::WriteAllText($hp, $t2, (New-Object System.Text.UTF8Encoding($false))); W "patched http80 pad fallback -> $padIp" }
}

# ---- 4. restart responders ----
Get-CimInstance Win32_Process -EA 0 | Where-Object { $_.Name -match '^python' } | ForEach-Object {
    $cl = ''
    try { $cl = $_.CommandLine } catch {}
    if ($cl -match 'np3200push|npcap3200|npcap_http80|npcap_pbs|watch_pad|dl_server') {
        W "kill $($_.ProcessId) $($_.Name)"
        Stop-Process -Id $_.ProcessId -Force -EA 0
    }
}
Start-Sleep -Milliseconds 400

foreach ($pair in @(@('np3200push.py', '86400'), @('npcap_http80.py', '86400'), @('npcap_pbs.py', '86400'), @('dl_server.py', ''))) {
    $f = $pair[0]; $arg = $pair[1]
    $fp = Join-Path $R $f
    if (-not (Test-Path $fp)) { W "skip start $f"; continue }
    if ($arg) { Start-Process -FilePath $pyw -ArgumentList "`"$fp`" $arg" -WorkingDirectory $R -WindowStyle Hidden }
    else { Start-Process -FilePath $pyw -ArgumentList "`"$fp`"" -WorkingDirectory $R -WindowStyle Hidden }
    W "started $f $arg"
}
Start-Sleep -Seconds 4
Get-CimInstance Win32_Process -EA 0 | Where-Object { $_.Name -match '^python' } | ForEach-Object {
    $cl = ''; try { $cl = $_.CommandLine } catch {}
    W ("running {0} {1} {2}" -f $_.ProcessId, $_.Name, $(if ($cl) { Split-Path $cl -Leaf } else { '?' }))
}
W "==== resume done ===="
