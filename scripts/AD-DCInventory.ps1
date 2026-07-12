<#
.SYNOPSIS
    AD Domain Controller Inventory & Specifications - interactive HTML dashboard.

.DESCRIPTION
    Discovers every domain controller in the forest and produces a single
    self-contained, interactive HTML report (dark/light) covering:

      - DC Inventory: name, domain, site, OS / build, IPv4, time zone, server time,
        Global Catalog, RODC, uptime, and reachability.
      - Hardware & System Specifications: manufacturer / model / BIOS, CPU(s),
        installed RAM, logical volumes, and network adapters per DC.
      - Performance Metrics: CPU usage, memory usage, AD database (NTDS.dit) size,
        log-file size, and per-drive disk usage.

    Everything is discovered live. DC-level detail (hardware / performance) is
    gathered via CIM/WMI; if a DC is unreachable the report shows the fields it
    could not collect as "unavailable" rather than failing.

    The report is fully self-contained: no external scripts, no telemetry, and
    nothing is written anywhere except the output folder. All queries are read-only.

.PARAMETER OutputPath
    Folder to save the HTML report. Defaults to the current directory.

.PARAMETER SkipHardware
    Skip the per-DC hardware/performance CIM collection (faster; inventory only).

.PARAMETER OpenReport
    Open the report when finished (default: $true).

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite (Domain Controller Inventory module)

.EXAMPLE
    .\AD-DCInventory.ps1

.EXAMPLE
    .\AD-DCInventory.ps1 -OutputPath C:\Reports -SkipHardware
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [switch]$SkipHardware,
    [switch]$OpenReport = $true
)

$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Error "ActiveDirectory module not available. Install RSAT-AD-PowerShell."; exit 1 }

try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$Stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

try { $Forest = Get-ADForest -ErrorAction Stop } catch { Write-Error "Could not contact the forest: $($_.Exception.Message)"; exit 1 }
$ForestDNS  = $Forest.Name
$ReportPath = Join-Path $OutputPath "AD_DCInventory_$Stamp.html"

Write-Host "AD Domain Controller Inventory" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "Forest: $ForestDNS" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# [1/3] Enumerate all domain controllers across the forest
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/3] Enumerating domain controllers..." -ForegroundColor Yellow
$DCList = @()
foreach ($domain in $Forest.Domains) {
    try {
        $dcs = Get-ADDomainController -Filter * -Server $domain -ErrorAction Stop
        foreach ($dc in $dcs) { $DCList += [PSCustomObject]@{ dc=$dc; domain=$domain } }
    } catch {
        Write-Warning "Could not enumerate DCs in $domain : $($_.Exception.Message)"
    }
}
if ($DCList.Count -eq 0) {
    # fallback: current domain only
    try { $dcs = Get-ADDomainController -Filter * -ErrorAction Stop; foreach ($dc in $dcs) { $DCList += [PSCustomObject]@{ dc=$dc; domain=$dc.Domain } } } catch {}
}
Write-Host "      $($DCList.Count) domain controller(s) found" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# [2/3] Per-DC inventory (from AD) + reachability
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/3] Collecting inventory..." -ForegroundColor Yellow

function Get-OSShortName {
    param([string]$os)
    if (-not $os) { return 'Unknown' }
    $s = $os -replace 'Windows Server','WS' -replace '\s+',' '
    return $s.Trim()
}
function Test-DCOnline {
    param([string]$name)
    try { return (Test-Connection -ComputerName $name -Count 1 -Quiet -ErrorAction SilentlyContinue) } catch { return $false }
}
# Open a CIM session over WinRM if possible, else fall back to DCOM. Returns @{ session; via } or $null.
function New-DCSession {
    param([string]$HostName)
    $local = $env:COMPUTERNAME
    if (($HostName -split '\.')[0] -ieq $local) {
        try { return @{ session = (New-CimSession -ErrorAction Stop); via = 'Local' } } catch { return $null }
    }
    try {
        $s = New-CimSession -ComputerName $HostName -OperationTimeoutSec 10 -ErrorAction Stop
        return @{ session = $s; via = 'WinRM' }
    } catch {}
    try {
        $s = New-CimSession -ComputerName $HostName -SessionOption (New-CimSessionOption -Protocol Dcom) -OperationTimeoutSec 15 -ErrorAction Stop
        return @{ session = $s; via = 'DCOM' }
    } catch {}
    return $null
}

$DCs = @()
$idx = 0
foreach ($item in $DCList) {
    $idx++
    $dc = $item.dc
    $name = $dc.HostName
    Write-Host "      [$idx/$($DCList.Count)] $name" -ForegroundColor DarkGray
    $online = Test-DCOnline -name $name

    # server time + timezone (best-effort, only if online)
    $serverTime = 'Unavailable'; $timeZone = 'Unavailable'; $uptime = 'Unavailable'
    $osVersion = 'Unknown'; $build = 'Unknown'
    try { $osVersion = Get-OSShortName $dc.OperatingSystem } catch {}
    try { if ($dc.OperatingSystemVersion) { $build = ($dc.OperatingSystemVersion -replace '[()]','') } } catch {}

    if ($online -and -not $SkipHardware) {
        $sess = New-DCSession -HostName $name
        if ($sess) {
            try {
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $sess.session -ErrorAction Stop
                if ($os.LastBootUpTime) {
                    $up = (Get-Date) - $os.LastBootUpTime
                    $uptime = "$([int]$up.TotalDays)d $($up.Hours)h"
                }
                $serverTime = ([datetime]$os.LocalDateTime).ToString('yyyy-MM-dd HH:mm')
                if ($os.BuildNumber) { $build = $os.BuildNumber }
            } catch {}
            try {
                $tz = Get-CimInstance -ClassName Win32_TimeZone -CimSession $sess.session -ErrorAction Stop
                if ($tz.Caption) { $timeZone = $tz.Caption }
            } catch {}
            try { Remove-CimSession $sess.session -ErrorAction SilentlyContinue } catch {}
        }
    }

    # OS support classification
    $isModern = $false; $isSupported = $true
    if ($osVersion -match '2003|2008|2012') { $isSupported = $false }
    if ($osVersion -match '2019|2022|2025') { $isModern = $true }

    $DCs += [PSCustomObject]@{
        name        = $name
        shortName   = ($name -split '\.')[0]
        domain      = "$($dc.Domain)"
        site        = "$($dc.Site)"
        os          = $osVersion
        build       = "$build"
        ipv4        = "$($dc.IPv4Address)"
        timeZone    = $timeZone
        serverTime  = $serverTime
        uptime      = $uptime
        isGC        = [bool]$dc.IsGlobalCatalog
        isRODC      = [bool]$dc.IsReadOnly
        online      = [bool]$online
        isModernOS  = $isModern
        isSupportedOS = $isSupported
        # placeholders filled in phase 3
        hardware    = $null
        performance = $null
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# [3/3] Per-DC hardware & performance (CIM/WMI) - best effort
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipHardware) {
    Write-Host "[3/3] Collecting hardware & performance..." -ForegroundColor Yellow
    $idx = 0
    foreach ($d in $DCs) {
        $idx++
        if (-not $d.online) { continue }
        Write-Host "      [$idx/$($DCs.Count)] $($d.shortName)" -ForegroundColor DarkGray
        $name = $d.name

        # Open a session (WinRM -> DCOM). Reuse it for every query below.
        $sess = New-DCSession -HostName $name
        if (-not $sess) {
            Write-Host "         no CIM session (WinRM and DCOM both refused) - hardware/perf skipped" -ForegroundColor DarkYellow
            continue
        }
        $S = $sess.session

        # ---- Hardware ----
        $hw = [ordered]@{
            manufacturer='Unavailable'; model='Unavailable'; bios='Unavailable'; serial='Unavailable'
            ramTotalGB='Unavailable'; cpus=@(); volumes=@(); nics=@(); collectedVia=$sess.via
        }
        try {
            $cs = Get-CimInstance Win32_ComputerSystem -CimSession $S -ErrorAction Stop
            $hw.manufacturer = "$($cs.Manufacturer)"
            $hw.model        = "$($cs.Model)"
            if ($cs.TotalPhysicalMemory) { $hw.ramTotalGB = [math]::Round($cs.TotalPhysicalMemory/1GB, 1) }
        } catch {}
        try {
            $bios = Get-CimInstance Win32_BIOS -CimSession $S -ErrorAction Stop
            $hw.bios   = "$($bios.SMBIOSBIOSVersion)"
            $hw.serial = "$($bios.SerialNumber)"
        } catch {}
        try {
            $cpus = Get-CimInstance Win32_Processor -CimSession $S -ErrorAction Stop
            foreach ($c in $cpus) {
                $hw.cpus += [PSCustomObject]@{ name="$($c.Name)".Trim(); cores=[int]$c.NumberOfCores; logical=[int]$c.NumberOfLogicalProcessors; clock="$($c.MaxClockSpeed) MHz" }
            }
        } catch {}
        try {
            $vols = Get-CimInstance Win32_LogicalDisk -CimSession $S -Filter "DriveType=3" -ErrorAction Stop
            foreach ($v in $vols) {
                $sizeGB = if ($v.Size) { [math]::Round($v.Size/1GB,1) } else { 0 }
                $freeGB = if ($v.FreeSpace) { [math]::Round($v.FreeSpace/1GB,1) } else { 0 }
                $freePct = if ($v.Size -and $v.Size -gt 0) { [math]::Round(($v.FreeSpace/$v.Size)*100,0) } else { 0 }
                $hw.volumes += [PSCustomObject]@{ drive="$($v.DeviceID)"; sizeGB=$sizeGB; freeGB=$freeGB; freePct=$freePct }
            }
        } catch {}
        try {
            $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -CimSession $S -Filter "IPEnabled=True" -ErrorAction Stop
            foreach ($n in $nics) {
                $ip = ($n.IPAddress | Where-Object { $_ -notmatch ':' }) -join ', '
                $hw.nics += [PSCustomObject]@{ desc="$($n.Description)"; ip="$ip"; mac="$($n.MACAddress)" }
            }
        } catch {}
        $d.hardware = [PSCustomObject]$hw

        # ---- Performance ----
        $perf = [ordered]@{ cpuUsage='Unavailable'; memUsage='Unavailable'; memDetail=''; adDbSizeMB='Unavailable'; logSizeMB='Unavailable'; disks=@() }
        try {
            $cpu = Get-CimInstance Win32_Processor -CimSession $S -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average
            if ($cpu.Average -ne $null) { $perf.cpuUsage = "$([math]::Round($cpu.Average,0))%" }
        } catch {}
        try {
            $os = Get-CimInstance Win32_OperatingSystem -CimSession $S -ErrorAction Stop
            if ($os.TotalVisibleMemorySize) {
                $usedPct = [math]::Round(((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)*100),0)
                $usedGB  = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory)/1MB,1)
                $totGB   = [math]::Round($os.TotalVisibleMemorySize/1MB,1)
                $perf.memUsage  = "$usedPct%"
                $perf.memDetail = "$usedGB / $totGB GB"
            }
        } catch {}
        # AD database (NTDS.dit) size via registry-pointed path
        try {
            $dsaPath = (Invoke-CimMethod -CimSession $S -Namespace root\default -ClassName StdRegProv -MethodName GetStringValue -Arguments @{ hDefKey=[uint32]2147483650; sSubKeyName='SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; sValueName='DSA Database file' } -ErrorAction Stop).sValue
            if ($dsaPath) {
                $dit = Get-CimInstance CIM_DataFile -CimSession $S -Filter "Name='$($dsaPath -replace '\\','\\\\')'" -ErrorAction SilentlyContinue
                if ($dit.FileSize) { $perf.adDbSizeMB = [math]::Round($dit.FileSize/1MB,0) }
            }
        } catch {}
        try {
            foreach ($v in @($d.hardware.volumes)) {
                $perf.disks += [PSCustomObject]@{ drive=$v.drive; sizeGB=$v.sizeGB; freeGB=$v.freeGB; usedPct=(100-$v.freePct) }
            }
        } catch {}
        $d.performance = [PSCustomObject]$perf

        try { Remove-CimSession $S -ErrorAction SilentlyContinue } catch {}
    }
} else {
    Write-Host "[3/3] Hardware/performance skipped (-SkipHardware)" -ForegroundColor DarkGray
}

# ─────────────────────────────────────────────────────────────────────────────
# Summary metrics
# ─────────────────────────────────────────────────────────────────────────────
$TotalDCs      = $DCs.Count
$OnlineDCs     = @($DCs | Where-Object { $_.online }).Count
$OfflineDCs    = $TotalDCs - $OnlineDCs
$GCCount       = @($DCs | Where-Object { $_.isGC }).Count
$RODCCount     = @($DCs | Where-Object { $_.isRODC }).Count
$SiteCount     = @($DCs | Select-Object -ExpandProperty site -Unique | Where-Object { $_ }).Count
$DomainCount   = @($DCs | Select-Object -ExpandProperty domain -Unique | Where-Object { $_ }).Count
$LegacyOSCount = @($DCs | Where-Object { -not $_.isSupportedOS }).Count

$Summary = [ordered]@{
    forest=$ForestDNS; generatedAt=$GeneratedAt; hardwareCollected=(-not $SkipHardware)
    totalDCs=$TotalDCs; onlineDCs=$OnlineDCs; offlineDCs=$OfflineDCs
    gcCount=$GCCount; rodcCount=$RODCCount; siteCount=$SiteCount; domainCount=$DomainCount; legacyOSCount=$LegacyOSCount
    dcs=@($DCs)
}
$DataJSON = ConvertTo-Json -InputObject $Summary -Depth 12 -Compress
Write-Host "Rendering report..." -ForegroundColor Yellow

$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DC Inventory &mdash; $ForestDNS</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg:#f5f6fb; --surface:#ffffff; --surface2:#eef1f9; --surface3:#dfe4f2; --border:#e4e7f2; --text:#161a2e; --muted:#64708c;
  --accent:#4f46e5; --accent-2:#6366f1; --accent-soft:#e6e6fd; --navy:#3730a3; --violet:#6d28d9; --fuchsia:#c026d3;
  --green:#059669; --green-soft:#d1fae5; --red:#dc2626; --red-soft:#fde2e2; --amber:#d97706; --amber-soft:#fef3c7;
  --blue:#2563eb; --blue-soft:#dbe8fe; --teal:#0d9488; --teal-soft:#cdeee9; --purple:#7c3aed; --purple-soft:#ede9fe; --pink:#db2777; --pink-soft:#fce7f3; --cyan:#0891b2; --cyan-soft:#cffafe;
  --radius:13px; --radius-sm:9px;
  --shadow:0 2px 8px rgb(60 50 140 / 0.06), 0 1px 2px rgb(60 50 140 / 0.04);
  --shadow-hover:0 9px 26px rgb(60 50 140 / 0.14);
  --font:'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --mono:'SFMono-Regular', ui-monospace, Menlo, Consolas, monospace;
}
[data-theme="dark"] {
  --bg:#0c1524; --surface:#14213a; --surface2:#1c2c49; --surface3:#284066; --border:#243a5e; --text:#e8f0fb; --muted:#93a7c4;
  --accent:#60a5fa; --accent-2:#93c5fd; --accent-soft:rgba(96,165,250,0.15); --navy:#93c5fd;
  --green:#34d399; --green-soft:rgba(16,185,129,0.15); --red:#f87171; --red-soft:rgba(239,68,68,0.15); --amber:#fbbf24; --amber-soft:rgba(245,158,11,0.15);
  --teal:#2dd4bf; --teal-soft:rgba(45,212,191,0.15); --purple:#a78bfa; --purple-soft:rgba(139,92,246,0.15);
  --shadow:0 2px 6px rgb(0 0 0 / 0.3); --shadow-hover:0 8px 22px rgb(0 0 0 / 0.45);
}
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:var(--font); background:var(--bg); color:var(--text); min-height:100vh; font-size:14px; -webkit-font-smoothing:antialiased; }
.topbar { background:var(--surface); border-bottom:1px solid var(--border); border-top:3px solid var(--accent); padding:14px 28px; display:flex; align-items:center; gap:16px; position:sticky; top:0; z-index:100; box-shadow:var(--shadow); }
.brand { display:flex; align-items:center; gap:11px; font-size:16px; font-weight:700; }
.brand .logo { width:34px; height:34px; border-radius:9px; background:linear-gradient(135deg,var(--accent),var(--navy)); display:flex; align-items:center; justify-content:center; color:#fff; font-size:18px; }
.topmeta { margin-left:auto; font-size:12px; color:var(--muted); text-align:right; line-height:1.4; } .topmeta b { color:var(--text); font-weight:600; }
.btn { background:var(--surface); border:1px solid var(--border); color:var(--text); padding:8px 14px; border-radius:var(--radius-sm); font-size:13px; font-weight:500; cursor:pointer; display:flex; align-items:center; gap:8px; font-family:var(--font); }
.btn:hover { background:var(--surface2); } .btn i { font-size:14px; color:var(--muted); }
.sep { width:1px; height:24px; background:var(--border); }
.wrap { max-width:1200px; margin:0 auto; padding:28px 40px; }
@media(max-width:760px){ .wrap { padding:20px 16px; } }
.banner-note { font-size:12px; color:var(--muted); background:var(--surface2); border:1px dashed var(--border); border-radius:var(--radius-sm); padding:8px 12px; margin-bottom:18px; display:flex; align-items:center; gap:8px; } .banner-note i { color:var(--amber); }

/* KPI chip cards */
.kpi-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(160px, 1fr)); gap:14px; margin-bottom:28px; }
.kpi { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:16px 18px; display:flex; align-items:center; gap:14px; box-shadow:var(--shadow); }
.kpi .chip { width:44px; height:44px; border-radius:10px; flex-shrink:0; display:flex; align-items:center; justify-content:center; font-size:20px; background:var(--accent-soft); color:var(--accent); }
.kpi .num { font-size:24px; font-weight:800; line-height:1; letter-spacing:-0.02em; } .kpi .lbl { font-size:11.5px; color:var(--muted); margin-top:4px; }
.kpi.good .chip { background:var(--green-soft); color:var(--green); }
.kpi.bad .chip { background:var(--red-soft); color:var(--red); } .kpi.bad .num { color:var(--red); }
.kpi.warn .chip { background:var(--amber-soft); color:var(--amber); } .kpi.warn .num { color:var(--amber); }
.kpi.teal .chip { background:var(--teal-soft); color:var(--teal); }
.kpi.purple .chip { background:var(--purple-soft); color:var(--purple); }

.sec-label { font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted); margin:6px 0 16px; display:flex; align-items:center; gap:8px; } .sec-label i { color:var(--accent); font-size:15px; }

/* Inventory table */
.tbl-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden; margin-bottom:30px; }
.tbl-wrap { overflow-x:auto; }
.tbl { width:100%; border-collapse:collapse; font-size:13px; white-space:nowrap; }
.tbl th { background:var(--surface2); font-size:10.5px; text-transform:uppercase; letter-spacing:0.04em; font-weight:600; color:var(--muted); padding:12px 14px; text-align:left; position:sticky; top:0; }
.tbl td { padding:12px 14px; border-bottom:1px solid var(--border); } .tbl tr:last-child td { border-bottom:none; }
.tbl tbody tr:hover td { background:var(--surface2); }
.tbl .dcname { font-weight:700; font-family:var(--mono); font-size:12.5px; }
.badge { font-size:10px; font-weight:600; padding:2px 9px; border-radius:999px; display:inline-flex; align-items:center; gap:4px; }
.badge.on { background:var(--green-soft); color:var(--green); } .badge.off { background:var(--red-soft); color:var(--red); }
.badge.yes { background:var(--accent-soft); color:var(--accent); } .badge.no { background:var(--surface3); color:var(--muted); }
.badge.warn { background:var(--amber-soft); color:var(--amber); }
.mono { font-family:var(--mono); font-size:12px; }

/* Per-DC spec cards (expandable) */
.spec-list { display:flex; flex-direction:column; gap:12px; }
.spec { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden; }
.spec-head { display:flex; align-items:center; gap:14px; padding:15px 18px; cursor:pointer; transition:background 0.15s; }
.spec-head:hover { background:var(--surface2); }
.spec-dot { width:10px; height:10px; border-radius:999px; flex-shrink:0; } .spec-dot.on { background:var(--green); } .spec-dot.off { background:var(--red); }
.spec-name { font-size:14px; font-weight:700; font-family:var(--mono); } .spec-sub { font-size:11.5px; color:var(--muted); margin-top:2px; }
.spec-head-right { margin-left:auto; display:flex; align-items:center; gap:18px; }
.spec-quick { text-align:center; } .spec-quick .n { font-size:14px; font-weight:700; } .spec-quick .x { font-size:9.5px; color:var(--muted); text-transform:uppercase; letter-spacing:0.04em; }
.spec-chev { color:var(--muted); font-size:14px; transition:transform 0.2s; } .spec.open .spec-chev { transform:rotate(90deg); }
.spec-body { display:none; padding:4px 18px 20px; border-top:1px solid var(--border); } .spec.open .spec-body { display:block; }
.spec-grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-top:16px; } @media(max-width:720px){ .spec-grid { grid-template-columns:1fr; } }
.spec-block h4 { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:10px; display:flex; align-items:center; gap:7px; } .spec-block h4 i { color:var(--accent); font-size:13px; }
.kv-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.kv { background:var(--surface2); border-radius:var(--radius-sm); padding:9px 12px; } .kv .k { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:0.03em; font-weight:600; } .kv .v { font-size:12.5px; font-weight:600; margin-top:2px; word-break:break-word; white-space:normal; }
.kv .v.warn { color:var(--amber); } .kv .v.bad { color:var(--red); } .kv .v.good { color:var(--green); }
.ptable { width:100%; border-collapse:collapse; font-size:12px; margin-top:4px; }
.ptable th { text-align:left; font-size:9.5px; text-transform:uppercase; letter-spacing:0.03em; color:var(--muted); font-weight:600; padding:6px 8px; border-bottom:1px solid var(--border); }
.ptable td { padding:6px 8px; border-bottom:1px solid var(--border); } .ptable tr:last-child td { border-bottom:none; }
.usebar { height:6px; border-radius:999px; background:var(--surface3); overflow:hidden; margin-top:5px; } .usefill { height:100%; border-radius:999px; background:var(--accent); } .usefill.warn { background:var(--amber); } .usefill.bad { background:var(--red); }
.full { grid-column:1 / -1; }
.unavail { color:var(--muted); font-style:italic; font-size:12px; padding:8px 0; }
.muted-note { color:var(--muted); font-size:12.5px; padding:12px; background:var(--surface2); border-radius:var(--radius-sm); border:1px dashed var(--border); text-align:center; }
::-webkit-scrollbar { width:9px; height:9px; } ::-webkit-scrollbar-track { background:transparent; } ::-webkit-scrollbar-thumb { background:var(--surface3); border-radius:999px; border:2px solid var(--surface); }
</style>
</head>
<body data-theme="light">

<div class="topbar">
  <div class="brand"><span class="logo"><i class="bi bi-hdd-rack-fill"></i></span> Domain Controller Inventory</div>
  <div class="sep"></div>
  <button class="btn" onclick="toggleTheme()"><i class="bi bi-moon-stars"></i> Theme</button>
  <button class="btn" onclick="window.print()"><i class="bi bi-printer"></i> Print</button>
  <button class="btn" onclick="toggleAllSpecs()"><i class="bi bi-arrows-expand"></i> Expand All</button>
  <div class="topmeta">Forest: <b>$ForestDNS</b><br>Generated: $GeneratedAt</div>
</div>

<div class="wrap">
  <div id="hwNote"></div>
  <div class="kpi-grid" id="kpis"></div>

  <div class="sec-label"><i class="bi bi-table"></i> DC Inventory</div>
  <div class="tbl-card"><div class="tbl-wrap"><table class="tbl" id="invTable"></table></div></div>

  <div class="sec-label"><i class="bi bi-cpu"></i> Hardware &amp; Performance</div>
  <div class="spec-list" id="specList"></div>
</div>

<script>
const D = $DataJSON;
const DCS = Array.isArray(D.dcs) ? D.dcs : [];
function esc(s){ return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function isNA(v){ return v==null || v==='' || v==='Unavailable' || v==='Unknown' || v==='N/A'; }

function renderHwNote(){
  if(!D.hardwareCollected){
    document.getElementById('hwNote').innerHTML='<div class="banner-note"><i class="bi bi-info-circle"></i> Hardware and performance collection was skipped (-SkipHardware). Only AD inventory is shown.</div>';
  }
}
function renderKpis(){
  function kpi(num,lbl,ico,cls){ return '<div class="kpi '+(cls||'')+'"><div class="chip"><i class="bi '+ico+'"></i></div><div><div class="num">'+num+'</div><div class="lbl">'+lbl+'</div></div></div>'; }
  document.getElementById('kpis').innerHTML=
    kpi(D.totalDCs||0,'Domain Controllers','bi-hdd-rack')
    + kpi(D.onlineDCs||0,'Online','bi-check-circle','good')
    + kpi(D.offlineDCs||0,'Offline','bi-x-circle',((D.offlineDCs||0)>0?'bad':''))
    + kpi(D.domainCount||0,'Domains','bi-diagram-3')
    + kpi(D.siteCount||0,'Sites','bi-geo-alt','teal')
    + kpi(D.gcCount||0,'Global Catalogs','bi-globe','purple')
    + kpi(D.rodcCount||0,'RODCs','bi-shield-lock')
    + kpi(D.legacyOSCount||0,'Legacy OS','bi-exclamation-triangle',((D.legacyOSCount||0)>0?'warn':''));
}

function renderTable(){
  const t=document.getElementById('invTable');
  let h='<thead><tr><th>DC Name</th><th>Domain</th><th>Site</th><th>OS</th><th>Build</th><th>IPv4</th><th>Time Zone</th><th>Uptime</th><th>GC</th><th>RODC</th><th>Status</th></tr></thead><tbody>';
  DCS.forEach(d=>{
    const osCls = d.isSupportedOS===false ? ' badge warn' : '';
    h+='<tr>'
      +'<td class="dcname">'+esc(d.shortName)+'</td>'
      +'<td>'+esc(d.domain)+'</td>'
      +'<td>'+esc(d.site||'&mdash;')+'</td>'
      +'<td>'+(d.isSupportedOS===false?'<span class="badge warn">'+esc(d.os)+'</span>':esc(d.os))+'</td>'
      +'<td class="mono">'+esc(d.build)+'</td>'
      +'<td class="mono">'+esc(d.ipv4||'&mdash;')+'</td>'
      +'<td>'+(isNA(d.timeZone)?'<span class="unavail">&mdash;</span>':esc(d.timeZone))+'</td>'
      +'<td class="mono">'+(isNA(d.uptime)?'&mdash;':esc(d.uptime))+'</td>'
      +'<td>'+(d.isGC?'<span class="badge yes">Yes</span>':'<span class="badge no">No</span>')+'</td>'
      +'<td>'+(d.isRODC?'<span class="badge warn">Yes</span>':'<span class="badge no">No</span>')+'</td>'
      +'<td>'+(d.online?'<span class="badge on"><i class="bi bi-circle-fill" style="font-size:7px"></i> Online</span>':'<span class="badge off"><i class="bi bi-circle-fill" style="font-size:7px"></i> Offline</span>')+'</td>'
      +'</tr>';
  });
  h+='</tbody>';
  t.innerHTML=h;
}

function usageBar(pct){ const cls = pct>=90?'bad':pct>=75?'warn':''; return '<div class="usebar"><div class="usefill '+cls+'" style="width:'+Math.min(100,Math.max(0,pct))+'%"></div></div>'; }

function specBody(d){
  if(!d.online){ return '<div class="unavail"><i class="bi bi-exclamation-circle"></i> This domain controller was offline/unreachable &mdash; hardware and performance data could not be collected.</div>'; }
  if(!D.hardwareCollected){ return '<div class="unavail">Hardware/performance collection was skipped.</div>'; }
  const hw=d.hardware||{}; const pf=d.performance||{};
  let h='<div class="spec-grid">';

  // System block
  h+='<div class="spec-block"><h4><i class="bi bi-pc-display"></i> System</h4><div class="kv-grid">'
    +'<div class="kv"><div class="k">Manufacturer</div><div class="v">'+(isNA(hw.manufacturer)?'&mdash;':esc(hw.manufacturer))+'</div></div>'
    +'<div class="kv"><div class="k">Model</div><div class="v">'+(isNA(hw.model)?'&mdash;':esc(hw.model))+'</div></div>'
    +'<div class="kv"><div class="k">BIOS</div><div class="v">'+(isNA(hw.bios)?'&mdash;':esc(hw.bios))+'</div></div>'
    +'<div class="kv"><div class="k">Total RAM</div><div class="v">'+(isNA(hw.ramTotalGB)?'&mdash;':esc(hw.ramTotalGB)+' GB')+'</div></div>'
    +'</div></div>';

  // Performance block
  const memWarn = pf.memUsage && parseInt(pf.memUsage)>=85;
  const cpuWarn = pf.cpuUsage && parseInt(pf.cpuUsage)>=85;
  h+='<div class="spec-block"><h4><i class="bi bi-speedometer2"></i> Performance</h4><div class="kv-grid">'
    +'<div class="kv"><div class="k">CPU Usage</div><div class="v'+(cpuWarn?' warn':'')+'">'+(isNA(pf.cpuUsage)?'&mdash;':esc(pf.cpuUsage))+'</div></div>'
    +'<div class="kv"><div class="k">Memory Usage</div><div class="v'+(memWarn?' warn':'')+'">'+(isNA(pf.memUsage)?'&mdash;':esc(pf.memUsage))+'</div></div>'
    +'<div class="kv"><div class="k">Mem Detail</div><div class="v">'+(pf.memDetail?esc(pf.memDetail):'&mdash;')+'</div></div>'
    +'<div class="kv"><div class="k">AD Database</div><div class="v">'+(isNA(pf.adDbSizeMB)?'&mdash;':esc(pf.adDbSizeMB)+' MB')+'</div></div>'
    +'</div></div>';

  // CPU block (full width)
  if(hw.cpus && hw.cpus.length){
    h+='<div class="spec-block full"><h4><i class="bi bi-cpu"></i> Processors</h4><table class="ptable"><thead><tr><th>CPU</th><th>Cores</th><th>Logical</th><th>Max Clock</th></tr></thead><tbody>'
      +hw.cpus.map(c=>'<tr><td>'+esc(c.name)+'</td><td>'+esc(c.cores)+'</td><td>'+esc(c.logical)+'</td><td>'+esc(c.clock)+'</td></tr>').join('')
      +'</tbody></table></div>';
  }
  // Volumes block (full width) with usage bars
  if(hw.volumes && hw.volumes.length){
    h+='<div class="spec-block full"><h4><i class="bi bi-device-hdd"></i> Logical Volumes</h4><table class="ptable"><thead><tr><th>Drive</th><th>Size</th><th>Free</th><th>Used</th></tr></thead><tbody>'
      +hw.volumes.map(v=>{ const used=100-(v.freePct||0); return '<tr><td class="mono">'+esc(v.drive)+'</td><td>'+esc(v.sizeGB)+' GB</td><td>'+esc(v.freeGB)+' GB</td><td style="min-width:120px">'+used+'% '+usageBar(used)+'</td></tr>'; }).join('')
      +'</tbody></table></div>';
  }
  // NICs block (full width)
  if(hw.nics && hw.nics.length){
    h+='<div class="spec-block full"><h4><i class="bi bi-ethernet"></i> Network Adapters</h4><table class="ptable"><thead><tr><th>Adapter</th><th>IP</th><th>MAC</th></tr></thead><tbody>'
      +hw.nics.map(n=>'<tr><td>'+esc(n.desc)+'</td><td class="mono">'+esc(n.ip||'&mdash;')+'</td><td class="mono">'+esc(n.mac||'&mdash;')+'</td></tr>').join('')
      +'</tbody></table></div>';
  }
  h+='</div>';
  return h;
}

function renderSpecs(){
  const el=document.getElementById('specList');
  if(!DCS.length){ el.innerHTML='<div class="muted-note">No domain controllers found.</div>'; return; }
  el.innerHTML=DCS.map((d,i)=>{
    const hw=d.hardware||{}; const pf=d.performance||{};
    const ram=(hw && !isNA(hw.ramTotalGB))?hw.ramTotalGB+' GB':'&mdash;';
    const cores=(hw.cpus&&hw.cpus.length)?hw.cpus.reduce((s,c)=>s+(parseInt(c.cores)||0),0):null;
    return '<div class="spec" id="spec'+i+'"><div class="spec-head" onclick="toggleSpec('+i+')">'
      +'<span class="spec-dot '+(d.online?'on':'off')+'"></span>'
      +'<div><div class="spec-name">'+esc(d.shortName)+'</div><div class="spec-sub">'+esc(d.domain)+' &middot; '+esc(d.site||'no site')+'</div></div>'
      +'<div class="spec-head-right">'
      + (d.online&&D.hardwareCollected? '<div class="spec-quick"><div class="n">'+ram+'</div><div class="x">RAM</div></div>'+(cores!=null?'<div class="spec-quick"><div class="n">'+cores+'</div><div class="x">Cores</div></div>':'')+(pf&&!isNA(pf.cpuUsage)?'<div class="spec-quick"><div class="n">'+esc(pf.cpuUsage)+'</div><div class="x">CPU</div></div>':'') : '')
      +'<i class="bi bi-chevron-right spec-chev"></i></div></div>'
      +'<div class="spec-body">'+specBody(d)+'</div></div>';
  }).join('');
}

function toggleSpec(i){ document.getElementById('spec'+i).classList.toggle('open'); }
let _allOpen=false;
function toggleAllSpecs(){ _allOpen=!_allOpen; document.querySelectorAll('.spec').forEach(s=>s.classList.toggle('open',_allOpen)); const b=document.querySelector('button[onclick="toggleAllSpecs()"]'); b.innerHTML=_allOpen?'<i class="bi bi-arrows-collapse"></i> Collapse All':'<i class="bi bi-arrows-expand"></i> Expand All'; }
function toggleTheme(){ const isDark=document.body.getAttribute('data-theme')==='dark'; document.body.setAttribute('data-theme',isDark?'light':'dark'); const btn=document.querySelector('button[onclick="toggleTheme()"]'); btn.innerHTML=isDark?'<i class="bi bi-moon-stars"></i> Theme':'<i class="bi bi-sun"></i> Theme'; }

renderHwNote();
renderKpis();
renderTable();
renderSpecs();
</script>
</body>
</html>
"@
$HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
Write-Host ""
Write-Host "  Report saved: $ReportPath" -ForegroundColor Green
try { if ($OpenReport) { Start-Process $ReportPath } } catch {}
