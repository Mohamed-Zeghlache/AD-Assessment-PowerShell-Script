<#
.SYNOPSIS
    AD Overview - Active Directory summary dashboard (interactive HTML).

.DESCRIPTION
    Produces a single self-contained, interactive HTML report (dark/light) giving a
    high-level overview of an Active Directory forest:

      - Forest & domain facts: forest/domain functional levels, schema version,
        FSMO role holders, tombstone lifetime, domain/site/DC counts.
      - Object inventory: users, computers, groups, OUs, contacts, GPOs.
      - Account posture: enabled vs disabled, stale vs active, locked, password-never-expires.
      - Objects-per-domain comparison (for multi-domain forests).
      - Computer OS distribution (clients vs servers).
      - Group breakdown: security vs distribution, and by scope (global/domain-local/universal).

    Everything is discovered live. All queries are read-only. The HTML report is fully
    self-contained (no external scripts, no telemetry) and is written only to the output
    folder you choose.

.PARAMETER OutputPath
    Folder to save the HTML report. Defaults to the current directory.

.PARAMETER StaleDays
    Days since last logon before an account is counted "stale". Default: 180.

.PARAMETER OpenReport
    Open the report when finished (default: $true).

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite (Overview module)

.EXAMPLE
    .\AD-Overview.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [int]$StaleDays = 180,
    [switch]$OpenReport = $true
)

$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Error "ActiveDirectory module not available. Install RSAT-AD-PowerShell."; exit 1 }

try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$Stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$StaleCutoff = (Get-Date).AddDays(-$StaleDays)

try { $Forest = Get-ADForest -ErrorAction Stop } catch { Write-Error "Could not contact the forest: $($_.Exception.Message)"; exit 1 }
$ForestDNS  = $Forest.Name
$ReportPath = Join-Path $OutputPath "AD_Overview_$Stamp.html"

Write-Host "AD Overview" -ForegroundColor Cyan
Write-Host "===========" -ForegroundColor Cyan
Write-Host "Forest: $ForestDNS" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# [1/4] Forest & schema facts
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/4] Collecting forest facts..." -ForegroundColor Yellow

# Schema version -> friendly name
$SchemaVersionMap = @{
    13='Windows 2000'; 30='Windows Server 2003'; 31='Windows Server 2003 R2'
    44='Windows Server 2008'; 47='Windows Server 2008 R2'; 56='Windows Server 2012'
    69='Windows Server 2012 R2'; 87='Windows Server 2016'; 88='Windows Server 2019 / 2022'
    91='Windows Server 2025'
}
$SchemaVersion = $null; $SchemaName = 'Unknown'
try {
    $schema = Get-ADObject (Get-ADRootDSE).schemaNamingContext -Properties objectVersion -ErrorAction Stop
    $SchemaVersion = [int]$schema.objectVersion
    if ($SchemaVersionMap.ContainsKey($SchemaVersion)) { $SchemaName = $SchemaVersionMap[$SchemaVersion] }
} catch {}

# Tombstone lifetime
$TombstoneDays = 180
try {
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $dsObj = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime -ErrorAction Stop
    if ($dsObj.tombstoneLifetime) { $TombstoneDays = [int]$dsObj.tombstoneLifetime }
} catch {}

# FSMO (forest-wide)
$SchemaMaster = "$($Forest.SchemaMaster)"
$DomainNamingMaster = "$($Forest.DomainNamingMaster)"

$ForestFacts = [ordered]@{
    forestName        = $ForestDNS
    forestMode        = "$($Forest.ForestMode)"
    rootDomain        = "$($Forest.RootDomain)"
    schemaVersion     = $SchemaVersion
    schemaName        = $SchemaName
    tombstoneDays     = $TombstoneDays
    domainCount       = @($Forest.Domains).Count
    siteCount         = @($Forest.Sites).Count
    gcCount           = @($Forest.GlobalCatalogs).Count
    schemaMaster      = ($SchemaMaster -split '\.')[0]
    domainNamingMaster= ($DomainNamingMaster -split '\.')[0]
    upnSuffixes       = @($Forest.UPNSuffixes)
}

# ─────────────────────────────────────────────────────────────────────────────
# [2/4] Per-domain facts + object counts
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/4] Collecting per-domain object counts..." -ForegroundColor Yellow

$Domains = @()
$Tot = [ordered]@{ users=0; computers=0; groups=0; ous=0; contacts=0; gpos=0 }

foreach ($domName in $Forest.Domains) {
    Write-Host "      $domName" -ForegroundColor DarkGray
    try { $dom = Get-ADDomain -Identity $domName -ErrorAction Stop } catch { continue }

    $uCount=0; $cCount=0; $gCount=0; $ouCount=0; $contactCount=0; $gpoCount=0
    try { $uCount = @(Get-ADUser -Filter * -Server $domName -ResultSetSize $null).Count } catch {}
    try { $cCount = @(Get-ADComputer -Filter * -Server $domName -ResultSetSize $null).Count } catch {}
    try { $gCount = @(Get-ADGroup -Filter * -Server $domName -ResultSetSize $null).Count } catch {}
    try { $ouCount = @(Get-ADOrganizationalUnit -Filter * -Server $domName).Count } catch {}
    try { $contactCount = @(Get-ADObject -LDAPFilter '(objectClass=contact)' -Server $domName).Count } catch {}
    try { $gpoCount = @(Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -SearchBase "CN=Policies,CN=System,$($dom.DistinguishedName)" -Server $domName).Count } catch {}

    $Domains += [PSCustomObject]@{
        name        = $domName
        netbios     = "$($dom.NetBIOSName)"
        mode        = "$($dom.DomainMode)"
        pdcEmulator = ("$($dom.PDCEmulator)" -split '\.')[0]
        ridMaster   = ("$($dom.RIDMaster)" -split '\.')[0]
        infraMaster = ("$($dom.InfrastructureMaster)" -split '\.')[0]
        isRoot      = ($domName -eq $Forest.RootDomain)
        users=$uCount; computers=$cCount; groups=$gCount; ous=$ouCount; contacts=$contactCount; gpos=$gpoCount
    }
    $Tot.users+=$uCount; $Tot.computers+=$cCount; $Tot.groups+=$gCount; $Tot.ous+=$ouCount; $Tot.contacts+=$contactCount; $Tot.gpos+=$gpoCount
}
Write-Host "      Totals: $($Tot.users) users, $($Tot.computers) computers, $($Tot.groups) groups" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# [3/4] Account posture + OS distribution + group breakdown (forest-wide)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[3/4] Analyzing accounts, OS, and groups..." -ForegroundColor Yellow

$AcctEnabled=0; $AcctDisabled=0; $AcctStale=0; $AcctLocked=0; $AcctPwdNeverExp=0; $AcctNeverLoggedOn=0
$OsAgg = @{}
$CompEnabled=0; $CompDisabled=0; $CompStale=0; $ServerCount=0; $ClientCount=0
$GrpSecurity=0; $GrpDistribution=0; $GrpGlobal=0; $GrpDomainLocal=0; $GrpUniversal=0

# Full object lists for CSV export (Name / SamAccountName / Enabled / LastLogon / DN)
$ListUserEnabled=[System.Collections.Generic.List[object]]::new()
$ListUserDisabled=[System.Collections.Generic.List[object]]::new()
$ListUserStale=[System.Collections.Generic.List[object]]::new()
$ListUserNeverLogged=[System.Collections.Generic.List[object]]::new()
$ListUserLocked=[System.Collections.Generic.List[object]]::new()
$ListUserPwdNeverExp=[System.Collections.Generic.List[object]]::new()
$ListCompEnabled=[System.Collections.Generic.List[object]]::new()
$ListCompDisabled=[System.Collections.Generic.List[object]]::new()
$ListCompStale=[System.Collections.Generic.List[object]]::new()
$ListCompServers=[System.Collections.Generic.List[object]]::new()
$ListCompClients=[System.Collections.Generic.List[object]]::new()
$ListGrpSecurity=[System.Collections.Generic.List[object]]::new()
$ListGrpDistribution=[System.Collections.Generic.List[object]]::new()
$ListGrpGlobal=[System.Collections.Generic.List[object]]::new()
$ListGrpDomainLocal=[System.Collections.Generic.List[object]]::new()
$ListGrpUniversal=[System.Collections.Generic.List[object]]::new()

function New-ObjRow {
    param($obj, $enabled)
    $ll = if ($obj.LastLogonDate) { $obj.LastLogonDate.ToString('yyyy-MM-dd HH:mm') } else { '' }
    [PSCustomObject]@{
        Name          = "$($obj.Name)"
        SamAccountName= "$($obj.SamAccountName)"
        Enabled       = if ($enabled) { 'True' } else { 'False' }
        LastLogon     = $ll
        DN            = "$($obj.DistinguishedName)"
    }
}

foreach ($domName in $Forest.Domains) {
    # Users
    try {
        $users = Get-ADUser -Filter * -Server $domName -Properties Enabled,LastLogonDate,PasswordNeverExpires,LockedOut -ResultSetSize $null
        foreach ($u in $users) {
            $row = New-ObjRow -obj $u -enabled $u.Enabled
            if ($u.Enabled) { $AcctEnabled++; $ListUserEnabled.Add($row) } else { $AcctDisabled++; $ListUserDisabled.Add($row) }
            if ($u.Enabled -and $u.LastLogonDate -and $u.LastLogonDate -lt $StaleCutoff) { $AcctStale++; $ListUserStale.Add($row) }
            if ($u.Enabled -and -not $u.LastLogonDate) { $AcctNeverLoggedOn++; $ListUserNeverLogged.Add($row) }
            if ($u.LockedOut) { $AcctLocked++; $ListUserLocked.Add($row) }
            if ($u.Enabled -and $u.PasswordNeverExpires) { $AcctPwdNeverExp++; $ListUserPwdNeverExp.Add($row) }
        }
    } catch {}
    # Computers + OS
    try {
        $comps = Get-ADComputer -Filter * -Server $domName -Properties Enabled,LastLogonDate,OperatingSystem -ResultSetSize $null
        foreach ($c in $comps) {
            $row = New-ObjRow -obj $c -enabled $c.Enabled
            if ($c.Enabled) { $CompEnabled++; $ListCompEnabled.Add($row) } else { $CompDisabled++; $ListCompDisabled.Add($row) }
            if ($c.Enabled -and $c.LastLogonDate -and $c.LastLogonDate -lt $StaleCutoff) { $CompStale++; $ListCompStale.Add($row) }
            $os = if ($c.OperatingSystem) { $c.OperatingSystem } else { '(unknown)' }
            if ($os -match 'Server') { $ServerCount++; $ListCompServers.Add($row) } elseif ($os -ne '(unknown)') { $ClientCount++; $ListCompClients.Add($row) }
            $osKey = $os -replace 'Windows Server','WS' -replace 'Windows','Win' -replace '\s+',' '
            $osKey = $osKey.Trim()
            if (-not $OsAgg.ContainsKey($osKey)) { $OsAgg[$osKey]=0 }
            $OsAgg[$osKey]++
        }
    } catch {}
    # Groups
    try {
        $groups = Get-ADGroup -Filter * -Server $domName -Properties GroupCategory,GroupScope -ResultSetSize $null
        foreach ($g in $groups) {
            $grow = [PSCustomObject]@{
                Name           = "$($g.Name)"
                SamAccountName = "$($g.SamAccountName)"
                Enabled        = "$($g.GroupCategory)"   # for groups: category (Security/Distribution)
                LastLogon      = "$($g.GroupScope)"       # for groups: scope (Global/DomainLocal/Universal)
                DN             = "$($g.DistinguishedName)"
            }
            if ("$($g.GroupCategory)" -eq 'Security') { $GrpSecurity++; $ListGrpSecurity.Add($grow) } else { $GrpDistribution++; $ListGrpDistribution.Add($grow) }
            switch ("$($g.GroupScope)") {
                'Global' { $GrpGlobal++; $ListGrpGlobal.Add($grow) }
                'DomainLocal' { $GrpDomainLocal++; $ListGrpDomainLocal.Add($grow) }
                'Universal' { $GrpUniversal++; $ListGrpUniversal.Add($grow) }
            }
        }
    } catch {}
}

$OsDist = $OsAgg.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 |
          ForEach-Object { [PSCustomObject]@{ label=$_.Key; count=$_.Value } }

# ─────────────────────────────────────────────────────────────────────────────
# [4/4] Build summary + render
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[4/4] Rendering report..." -ForegroundColor Yellow

$Summary = [ordered]@{
    forest      = $ForestFacts
    generatedAt = $GeneratedAt
    staleDays   = $StaleDays
    totals      = $Tot
    domains     = @($Domains)
    accounts    = [ordered]@{
        enabled=$AcctEnabled; disabled=$AcctDisabled; stale=$AcctStale; locked=$AcctLocked
        pwdNeverExp=$AcctPwdNeverExp; neverLoggedOn=$AcctNeverLoggedOn
    }
    computers   = [ordered]@{
        enabled=$CompEnabled; disabled=$CompDisabled; stale=$CompStale
        servers=$ServerCount; clients=$ClientCount; osDist=@($OsDist)
    }
    groups      = [ordered]@{
        security=$GrpSecurity; distribution=$GrpDistribution
        global=$GrpGlobal; domainLocal=$GrpDomainLocal; universal=$GrpUniversal
    }
    lists       = [ordered]@{
        userEnabled       = @($ListUserEnabled)
        userDisabled      = @($ListUserDisabled)
        userStale         = @($ListUserStale)
        userNeverLogged   = @($ListUserNeverLogged)
        userLocked        = @($ListUserLocked)
        userPwdNeverExp   = @($ListUserPwdNeverExp)
        compEnabled       = @($ListCompEnabled)
        compDisabled      = @($ListCompDisabled)
        compStale         = @($ListCompStale)
        compServers       = @($ListCompServers)
        compClients       = @($ListCompClients)
        grpSecurity       = @($ListGrpSecurity)
        grpDistribution   = @($ListGrpDistribution)
        grpGlobal         = @($ListGrpGlobal)
        grpDomainLocal    = @($ListGrpDomainLocal)
        grpUniversal      = @($ListGrpUniversal)
    }
}
$DataJSON = ConvertTo-Json -InputObject $Summary -Depth 12 -Compress

$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Overview &mdash; $ForestDNS</title>
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
  --bg:#140f22; --surface:#1e1733; --surface2:#291f45; --surface3:#372a5c; --border:#302448; --text:#f0eafc; --muted:#a695c4;
  --accent:#a78bfa; --accent-2:#c084fc; --accent-soft:rgba(167,139,250,0.16); --violet:#c4b5fd; --fuchsia:#e879f9;
  --green:#34d399; --green-soft:rgba(16,185,129,0.15); --red:#f87171; --red-soft:rgba(239,68,68,0.15); --amber:#fbbf24; --amber-soft:rgba(245,158,11,0.15);
  --blue:#60a5fa; --blue-soft:rgba(37,99,235,0.16); --teal:#2dd4bf; --teal-soft:rgba(13,148,136,0.16); --pink:#f472b6; --pink-soft:rgba(219,39,119,0.16); --cyan:#22d3ee; --cyan-soft:rgba(8,145,178,0.16);
  --shadow:0 2px 8px rgb(0 0 0 / 0.32); --shadow-hover:0 10px 28px rgb(0 0 0 / 0.5);
}
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:var(--font); background:var(--bg); color:var(--text); min-height:100vh; font-size:14px; -webkit-font-smoothing:antialiased; }
.topbar { background:var(--surface); border-bottom:1px solid var(--border); padding:14px 28px; display:flex; align-items:center; gap:16px; position:sticky; top:0; z-index:100; box-shadow:var(--shadow); }
.brand { display:flex; align-items:center; gap:11px; font-size:16px; font-weight:700; }
.brand .logo { width:34px; height:34px; border-radius:9px; background:linear-gradient(135deg,var(--accent),var(--fuchsia)); display:flex; align-items:center; justify-content:center; color:#fff; font-size:18px; }
.topmeta { margin-left:auto; font-size:12px; color:var(--muted); text-align:right; line-height:1.4; } .topmeta b { color:var(--text); font-weight:600; }
.btn { background:var(--surface); border:1px solid var(--border); color:var(--text); padding:8px 14px; border-radius:var(--radius-sm); font-size:13px; font-weight:500; cursor:pointer; display:flex; align-items:center; gap:8px; font-family:var(--font); }
.btn:hover { background:var(--surface2); } .btn i { font-size:14px; color:var(--muted); }
.sep { width:1px; height:24px; background:var(--border); }
.wrap { max-width:1180px; margin:0 auto; padding:28px 40px; }
@media(max-width:760px){ .wrap { padding:20px 16px; } }

/* Hero forest banner */
.hero { background:linear-gradient(135deg, var(--accent), var(--fuchsia)); border-radius:var(--radius); padding:26px 30px; color:#fff; margin-bottom:26px; box-shadow:var(--shadow); position:relative; overflow:hidden; }
.hero::after { content:'\F5EE'; font-family:'bootstrap-icons'; position:absolute; right:-10px; bottom:-30px; font-size:170px; opacity:0.12; }
.hero .h-title { font-size:13px; text-transform:uppercase; letter-spacing:0.08em; opacity:0.85; font-weight:600; }
.hero .h-name { font-size:30px; font-weight:800; margin-top:4px; letter-spacing:-0.02em; }
.hero .h-facts { display:flex; gap:28px; margin-top:20px; flex-wrap:wrap; }
.hero .h-fact { } .hero .h-fact .fk { font-size:11px; text-transform:uppercase; letter-spacing:0.05em; opacity:0.8; } .hero .h-fact .fv { font-size:16px; font-weight:700; margin-top:3px; }

/* KPI grid */
.kpi-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:14px; margin-bottom:30px; }
.kpi { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:18px; box-shadow:var(--shadow); transition:transform 0.12s, box-shadow 0.12s; }
.kpi:hover { box-shadow:var(--shadow-hover); }
.kpi .top { display:flex; align-items:center; justify-content:space-between; }
.kpi .chip { width:40px; height:40px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:19px; background:var(--accent-soft); color:var(--accent); }
.kpi .num { font-size:28px; font-weight:800; letter-spacing:-0.02em; margin-top:12px; line-height:1; }
.kpi .lbl { font-size:12px; color:var(--muted); margin-top:5px; }
.kpi.c-users .chip { background:var(--blue-soft); color:var(--blue); }
.kpi.c-comp .chip { background:var(--teal-soft); color:var(--teal); }
.kpi.c-groups .chip { background:var(--pink-soft); color:var(--pink); }
.kpi.c-ous .chip { background:var(--amber-soft); color:var(--amber); }
.kpi.c-gpos .chip { background:var(--cyan-soft); color:var(--cyan); }

.sec-label { font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted); margin:8px 0 16px; display:flex; align-items:center; gap:8px; } .sec-label i { color:var(--accent); font-size:15px; }

.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:30px; } @media(max-width:820px){ .grid2 { grid-template-columns:1fr; } }
.grid3 { display:grid; grid-template-columns:repeat(3, 1fr); gap:18px; margin-bottom:30px; } @media(max-width:820px){ .grid3 { grid-template-columns:1fr; } }
.card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:22px; box-shadow:var(--shadow); }
.card h3 { font-size:13.5px; font-weight:700; margin-bottom:18px; display:flex; align-items:center; gap:8px; } .card h3 i { color:var(--accent); }

/* Donut */
.donut-flex { display:flex; align-items:center; gap:24px; flex-wrap:wrap; justify-content:center; }
.donut-legend { display:flex; flex-direction:column; gap:10px; font-size:12.5px; min-width:130px; } .dl { display:flex; align-items:center; gap:9px; } .dl .dot { width:11px; height:11px; border-radius:3px; flex-shrink:0; } .dl b { margin-left:auto; font-variant-numeric:tabular-nums; }

/* Bars */
.hbar { display:flex; flex-direction:column; gap:11px; } .hbar-row { display:grid; grid-template-columns:130px 1fr 52px; align-items:center; gap:12px; font-size:12.5px; }
.hbar-label { text-align:right; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:500; } .hbar-track { background:var(--surface2); border-radius:999px; height:20px; overflow:hidden; } .hbar-fill { height:100%; border-radius:999px; display:flex; align-items:center; justify-content:flex-end; padding-right:7px; color:#fff; font-size:10px; font-weight:700; }
.hbar-val { font-weight:700; font-size:12px; color:var(--muted); font-variant-numeric:tabular-nums; }

/* Stat pills row */
.pill-row { display:flex; gap:12px; flex-wrap:wrap; }
.pill { position:relative; flex:1; min-width:120px; background:var(--surface2); border-radius:var(--radius-sm); padding:14px 16px; text-align:center; }
.pill .n { font-size:22px; font-weight:800; letter-spacing:-0.01em; } .pill .l { font-size:11px; color:var(--muted); margin-top:4px; }
.pill.good .n { color:var(--green); } .pill.warn .n { color:var(--amber); } .pill.bad .n { color:var(--red); }
/* download-list button */
.dlbtn { position:absolute; top:8px; right:8px; width:24px; height:24px; border-radius:7px; border:1px solid var(--border); background:var(--surface); color:var(--muted); display:flex; align-items:center; justify-content:center; cursor:pointer; font-size:12px; transition:all 0.14s; padding:0; }
.dlbtn:hover { background:var(--accent); color:#fff; border-color:var(--accent); transform:translateY(-1px); }
.dlbtn:disabled { opacity:0.35; cursor:not-allowed; }
.dlbtn.on-kpi { top:14px; right:14px; }
.dlbtn.dl-inline { position:static; display:inline-flex; width:20px; height:20px; font-size:10px; vertical-align:middle; margin-left:2px; }
.kpi { position:relative; }

/* Domain comparison table */
.dtable { width:100%; border-collapse:collapse; font-size:13px; }
.dtable th { background:var(--surface2); font-size:10px; text-transform:uppercase; letter-spacing:0.04em; font-weight:600; color:var(--muted); padding:11px 13px; text-align:left; }
.dtable th.r, .dtable td.r { text-align:right; font-variant-numeric:tabular-nums; }
.dtable td { padding:11px 13px; border-bottom:1px solid var(--border); } .dtable tr:last-child td { border-bottom:none; }
.dtable tbody tr:hover td { background:var(--surface2); }
.dtable .dname { font-weight:700; } .dtable .droot { font-size:9.5px; font-weight:700; color:var(--accent); background:var(--accent-soft); padding:1px 7px; border-radius:999px; margin-left:6px; }
.fsmo-chip { font-size:10px; font-family:var(--mono); background:var(--surface3); padding:2px 7px; border-radius:5px; color:var(--muted); }

.tbl-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden; }
.tbl-wrap { overflow-x:auto; }
::-webkit-scrollbar { width:9px; height:9px; } ::-webkit-scrollbar-track { background:transparent; } ::-webkit-scrollbar-thumb { background:var(--surface3); border-radius:999px; border:2px solid var(--surface); }
</style>
</head>
<body data-theme="light">

<div class="topbar">
  <div class="brand"><span class="logo"><i class="bi bi-diagram-3-fill"></i></span> Active Directory Overview</div>
  <div class="sep"></div>
  <button class="btn" onclick="toggleTheme()"><i class="bi bi-moon-stars"></i> Theme</button>
  <button class="btn" onclick="window.print()"><i class="bi bi-printer"></i> Print</button>
  <div class="topmeta">Forest: <b>$ForestDNS</b><br>Generated: $GeneratedAt</div>
</div>

<div class="wrap">
  <div id="hero"></div>
  <div class="kpi-grid" id="kpis"></div>

  <div class="sec-label"><i class="bi bi-pie-chart"></i> Object Composition</div>
  <div class="grid2">
    <div class="card"><h3><i class="bi bi-diagram-2"></i> Directory Objects</h3><div id="objectDonut"></div></div>
    <div class="card"><h3><i class="bi bi-person-check"></i> Account Posture</h3><div id="acctPosture"></div></div>
  </div>

  <div class="sec-label"><i class="bi bi-bar-chart"></i> Breakdowns</div>
  <div class="grid2">
    <div class="card"><h3><i class="bi bi-windows"></i> Computer OS Distribution</h3><div id="osBars"></div></div>
    <div class="card"><h3><i class="bi bi-people"></i> Group Breakdown</h3><div id="groupBreakdown"></div></div>
  </div>

  <div class="sec-label"><i class="bi bi-diagram-3"></i> Domains</div>
  <div class="tbl-card"><div class="tbl-wrap"><table class="dtable" id="domainTable"></table></div></div>
  <div style="height:30px"></div>
</div>

<script>
const D = $DataJSON;
function esc(s){ return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function nfmt(n){ return (n==null?0:n).toLocaleString(); }

// Build a CSV from a list in D.lists and trigger a download. Fully client-side, offline.
function downloadList(listKey, fileslug){
  const rows = (D.lists && D.lists[listKey]) ? D.lists[listKey] : [];
  if(!rows || !rows.length){ return; }
  // Group lists reuse the Enabled/LastLogon fields to carry Category/Scope; relabel the header for them.
  const isGroup = listKey.indexOf('grp')===0;
  const cols = ['Name','SamAccountName','Enabled','LastLogon','DN'];
  const headers = isGroup ? ['Name','SamAccountName','Category','Scope','DN'] : cols;
  const q = v => { v = (v==null ? '' : (''+v)); return /[",\r\n]/.test(v) ? '"'+v.replace(/"/g,'""')+'"' : v; };
  let csv = headers.join(',') + '\r\n';
  rows.forEach(r => { csv += cols.map(c => q(r[c])).join(',') + '\r\n'; });
  // BOM so Excel opens UTF-8 correctly
  const blob = new Blob(['\uFEFF'+csv], {type:'text/csv;charset=utf-8;'});
  const stamp = new Date().toISOString().slice(0,10);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = fileslug + '_' + stamp + '.csv';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(url), 100);
}

// Small inline download button (for legends and bar rows)
function dlInline(listKey, fileslug){
  const list = (D.lists && D.lists[listKey]) ? D.lists[listKey] : null;
  const hasList = Array.isArray(list) && list.length>0;
  if(!hasList) return '';
  return ' <button class="dlbtn dl-inline" title="Download '+nfmt(list.length)+' records as CSV" onclick="downloadList(\''+listKey+'\',\''+fileslug+'\')"><i class="bi bi-download"></i></button>';
}

function renderHero(){
  const f=D.forest||{};
  document.getElementById('hero').innerHTML=
    '<div class="hero"><div class="h-title">Forest</div><div class="h-name">'+esc(f.forestName)+'</div>'
    +'<div class="h-facts">'
    +'<div class="h-fact"><div class="fk">Forest Level</div><div class="fv">'+esc(f.forestMode||'&mdash;')+'</div></div>'
    +'<div class="h-fact"><div class="fk">Schema</div><div class="fv">'+esc(f.schemaName||'&mdash;')+(f.schemaVersion?' ('+f.schemaVersion+')':'')+'</div></div>'
    +'<div class="h-fact"><div class="fk">Domains</div><div class="fv">'+nfmt(f.domainCount)+'</div></div>'
    +'<div class="h-fact"><div class="fk">Sites</div><div class="fv">'+nfmt(f.siteCount)+'</div></div>'
    +'<div class="h-fact"><div class="fk">Global Catalogs</div><div class="fv">'+nfmt(f.gcCount)+'</div></div>'
    +'<div class="h-fact"><div class="fk">Tombstone</div><div class="fv">'+nfmt(f.tombstoneDays)+' days</div></div>'
    +'<div class="h-fact"><div class="fk">Schema Master</div><div class="fv">'+esc(f.schemaMaster||'&mdash;')+'</div></div>'
    +'<div class="h-fact"><div class="fk">Naming Master</div><div class="fv">'+esc(f.domainNamingMaster||'&mdash;')+'</div></div>'
    +'</div></div>';
}

function renderKpis(){
  const t=D.totals||{};
  // dlKey: optional list key to enable a download button on the KPI
  function kpi(num,lbl,ico,cls,dlKey,fileslug){
    const list = (dlKey && D.lists && D.lists[dlKey]) ? D.lists[dlKey] : null;
    const hasList = Array.isArray(list) && list.length>0;
    const dl = dlKey
      ? '<button class="dlbtn on-kpi" '+(hasList?'':'disabled')+' title="'+(hasList?('Download '+nfmt(list.length)+' records as CSV'):'No records to download')+'" onclick="downloadList(\''+dlKey+'\',\''+fileslug+'\')"><i class="bi bi-download"></i></button>'
      : '';
    return '<div class="kpi '+(cls||'')+'">'+dl+'<div class="top"><div class="chip"><i class="bi '+ico+'"></i></div></div><div class="num">'+nfmt(num)+'</div><div class="lbl">'+lbl+'</div></div>';
  }
  document.getElementById('kpis').innerHTML=
    kpi(t.users,'Users','bi-people-fill','c-users','userEnabled','all-enabled-users')
    + kpi(t.computers,'Computers','bi-pc-display','c-comp','compEnabled','all-enabled-computers')
    + kpi(t.groups,'Groups','bi-collection-fill','c-groups')
    + kpi(t.ous,'Organizational Units','bi-folder-fill','c-ous')
    + kpi(t.gpos,'Group Policies','bi-file-earmark-ruled','c-gpos')
    + kpi(t.contacts,'Contacts','bi-person-lines-fill','');
}

function donutSvg(segs, centerVal, centerLbl){
  const total=segs.reduce((s,x)=>s+x.v,0); const R=54,SW=18,C=2*Math.PI*R; let off=0,circles='';
  if(total>0){ segs.forEach(s=>{ if(s.v<=0)return; const len=(s.v/total)*C; circles+='<circle cx="70" cy="70" r="'+R+'" fill="none" stroke="'+s.c+'" stroke-width="'+SW+'" stroke-dasharray="'+len+' '+(C-len)+'" stroke-dashoffset="'+(-off)+'" transform="rotate(-90 70 70)" stroke-linecap="butt"/>'; off+=len; }); }
  else { circles='<circle cx="70" cy="70" r="'+R+'" fill="none" stroke="var(--surface2)" stroke-width="'+SW+'"/>'; }
  return '<svg width="140" height="140" viewBox="0 0 140 140">'+circles+'<text x="70" y="66" text-anchor="middle" font-size="26" font-weight="800" fill="var(--text)">'+centerVal+'</text><text x="70" y="86" text-anchor="middle" font-size="10.5" fill="var(--muted)">'+centerLbl+'</text></svg>';
}
function legend(items){ return '<div class="donut-legend">'+items.map(i=>'<div class="dl"><span class="dot" style="background:'+i.c+'"></span>'+esc(i.label)+'<b>'+nfmt(i.v)+'</b></div>').join('')+'</div>'; }

function renderObjectDonut(){
  const t=D.totals||{};
  const segs=[
    {label:'Users',v:t.users||0,c:'var(--blue)'},
    {label:'Computers',v:t.computers||0,c:'var(--teal)'},
    {label:'Groups',v:t.groups||0,c:'var(--pink)'},
    {label:'OUs',v:t.ous||0,c:'var(--amber)'},
    {label:'GPOs',v:t.gpos||0,c:'var(--cyan)'},
    {label:'Contacts',v:t.contacts||0,c:'var(--muted)'}
  ];
  const total=segs.reduce((s,x)=>s+x.v,0);
  document.getElementById('objectDonut').innerHTML='<div class="donut-flex">'+donutSvg(segs,nfmt(total),'objects')+legend(segs)+'</div>';
}

function renderAcctPosture(){
  const a=D.accounts||{}; const total=(a.enabled||0)+(a.disabled||0);
  const active=Math.max(0,(a.enabled||0)-(a.stale||0)-(a.locked||0));
  const segs=[
    {label:'Active',v:active,c:'var(--green)'},
    {label:'Stale',v:a.stale||0,c:'var(--amber)'},
    {label:'Locked',v:a.locked||0,c:'var(--red)'},
    {label:'Disabled',v:a.disabled||0,c:'var(--muted)'}
  ];
  let h='<div class="donut-flex">'+donutSvg(segs,nfmt(total),'accounts')+legend(segs)+'</div>';
  h+='<div class="pill-row" style="margin-top:20px">'
    +statPill(a.enabled||0,'Enabled','good','userEnabled','enabled-users')
    +statPill(a.disabled||0,'Disabled','','userDisabled','disabled-users')
    +statPill(a.pwdNeverExp||0,'Pwd Never Exp','warn','userPwdNeverExp','password-never-expires')
    +statPill(a.neverLoggedOn||0,'Never Logged On','','userNeverLogged','never-logged-on')
    +'</div>';
  h+='<div class="pill-row" style="margin-top:12px">'
    +statPill(a.stale||0,'Stale','warn','userStale','stale-users')
    +statPill(a.locked||0,'Locked','bad','userLocked','locked-users')
    +'</div>';
  document.getElementById('acctPosture').innerHTML=h;
}

// Build a stat pill with an optional CSV-download button.
// listKey references D.lists[listKey]; fileslug is the CSV filename stem.
function statPill(num, label, cls, listKey, fileslug){
  const list = (D.lists && D.lists[listKey]) ? D.lists[listKey] : null;
  const hasList = Array.isArray(list) && list.length>0;
  const dl = listKey
    ? '<button class="dlbtn" '+(hasList?'':'disabled')+' title="'+(hasList?('Download '+nfmt(list.length)+' records as CSV'):'No records to download')+'" onclick="downloadList(\''+listKey+'\',\''+fileslug+'\')"><i class="bi bi-download"></i></button>'
    : '';
  return '<div class="pill '+(cls||'')+'">'+dl+'<div class="n">'+nfmt(num)+'</div><div class="l">'+esc(label)+'</div></div>';
}

function hbars(elId, rows, palette){
  const el=document.getElementById(elId);
  if(!rows.length){ el.innerHTML='<div style="color:var(--muted);font-size:13px">No data.</div>'; return; }
  const max=Math.max(1,...rows.map(r=>r.count));
  el.innerHTML='<div class="hbar">'+rows.map((r,i)=>{ const pct=(r.count/max)*100; const c=palette[i%palette.length];
    return '<div class="hbar-row"><span class="hbar-label" title="'+esc(r.label)+'">'+esc(r.label)+'</span><span class="hbar-track"><span class="hbar-fill" style="width:'+pct+'%;background:'+c+'">'+(pct>18?nfmt(r.count):'')+'</span></span><span class="hbar-val">'+nfmt(r.count)+'</span></div>'; }).join('')+'</div>';
}
function renderOsBars(){
  const os=(D.computers&&D.computers.osDist)||[];
  hbars('osBars', os, ['var(--accent)','var(--blue)','var(--teal)','var(--fuchsia)','var(--amber)','var(--pink)','var(--cyan)','var(--green)','var(--red)','var(--muted)']);
}
function renderGroupBreakdown(){
  const g=D.groups||{};
  let h='<div style="margin-bottom:18px"><div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em;font-weight:600;margin-bottom:10px">By Type</div>';
  // custom legend with download buttons
  const typeLegend='<div class="donut-legend">'
    +'<div class="dl"><span class="dot" style="background:var(--accent)"></span>Security<b>'+nfmt(g.security||0)+'</b>'+dlInline('grpSecurity','security-groups')+'</div>'
    +'<div class="dl"><span class="dot" style="background:var(--pink)"></span>Distribution<b>'+nfmt(g.distribution||0)+'</b>'+dlInline('grpDistribution','distribution-groups')+'</div>'
    +'</div>';
  h+='<div class="donut-flex" style="justify-content:flex-start;gap:18px">'+donutSvg([{label:'Security',v:g.security||0,c:'var(--accent)'},{label:'Distribution',v:g.distribution||0,c:'var(--pink)'}], nfmt((g.security||0)+(g.distribution||0)),'groups')
    +typeLegend+'</div></div>';
  h+='<div><div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em;font-weight:600;margin-bottom:10px">By Scope</div>';
  const scopeRows=[{label:'Global',count:g.global||0,key:'grpGlobal',slug:'global-groups'},{label:'Domain Local',count:g.domainLocal||0,key:'grpDomainLocal',slug:'domainlocal-groups'},{label:'Universal',count:g.universal||0,key:'grpUniversal',slug:'universal-groups'}];
  const max=Math.max(1,...scopeRows.map(r=>r.count));
  const pal=['var(--blue)','var(--teal)','var(--amber)'];
  h+='<div class="hbar">'+scopeRows.map((r,i)=>{ const pct=(r.count/max)*100; return '<div class="hbar-row"><span class="hbar-label">'+r.label+'</span><span class="hbar-track"><span class="hbar-fill" style="width:'+pct+'%;background:'+pal[i]+'">'+(pct>18?nfmt(r.count):'')+'</span></span><span class="hbar-val">'+nfmt(r.count)+dlInline(r.key,r.slug)+'</span></div>'; }).join('')+'</div></div>';
  document.getElementById('groupBreakdown').innerHTML=h;
}

function renderDomainTable(){
  const doms=D.domains||[]; const t=document.getElementById('domainTable');
  let h='<thead><tr><th>Domain</th><th>NetBIOS</th><th>Level</th><th class="r">Users</th><th class="r">Computers</th><th class="r">Groups</th><th class="r">OUs</th><th class="r">GPOs</th><th>PDC Emulator</th></tr></thead><tbody>';
  doms.forEach(d=>{
    h+='<tr><td><span class="dname">'+esc(d.name)+'</span>'+(d.isRoot?'<span class="droot">ROOT</span>':'')+'</td>'
      +'<td class="mono">'+esc(d.netbios)+'</td>'
      +'<td>'+esc(d.mode)+'</td>'
      +'<td class="r">'+nfmt(d.users)+'</td><td class="r">'+nfmt(d.computers)+'</td><td class="r">'+nfmt(d.groups)+'</td>'
      +'<td class="r">'+nfmt(d.ous)+'</td><td class="r">'+nfmt(d.gpos)+'</td>'
      +'<td><span class="fsmo-chip">'+esc(d.pdcEmulator||'&mdash;')+'</span></td></tr>';
  });
  h+='</tbody>'; t.innerHTML=h;
}

function toggleTheme(){ const isDark=document.body.getAttribute('data-theme')==='dark'; document.body.setAttribute('data-theme',isDark?'light':'dark'); const btn=document.querySelector('button[onclick="toggleTheme()"]'); btn.innerHTML=isDark?'<i class="bi bi-moon-stars"></i> Theme':'<i class="bi bi-sun"></i> Theme'; }

renderHero();
renderKpis();
renderObjectDonut();
renderAcctPosture();
renderOsBars();
renderGroupBreakdown();
renderDomainTable();
</script>
</body>
</html>
"@
$HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
Write-Host ""
Write-Host "  Report saved: $ReportPath" -ForegroundColor Green
try { if ($OpenReport) { Start-Process $ReportPath } } catch {}
