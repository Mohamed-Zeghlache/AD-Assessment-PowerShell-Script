<#
.SYNOPSIS
    AD Server Inventory - every server in the forest: OS, lifecycle, roles, SQL Server, failover clusters,
    hardware, patching, and what blocks the servers that cannot be read (interactive HTML report).

.DESCRIPTION
    Standalone script for the Active Directory Audit Suite. One self-contained, offline, interactive
    HTML report (light/dark).

      1. DISCOVERY FROM AD (every domain in the forest, no connection to the servers)
           Server computer objects (Windows and non-Windows), OU, last activity, stale and disabled
           objects. Roles AD already knows about: domain controllers, SQL Server (MSSQLSvc SPNs),
           failover clusters (cluster name objects), Exchange servers, certificate
           authorities and Configuration Manager management points. AD site of each server from
           the AD subnets.
      2. INVENTORY OF EACH SERVER (WMI over DCOM, WinRM as fallback, several servers at a time)
           Manufacturer, model, physical or virtual, serial, CPU sockets / cores / logical
           processors, memory, IP addresses, Windows edition,
           build, install date, last boot and uptime, roles and features, last installed update, pending
           restart, services running under domain accounts, SQL Server instances (edition, version,
           service account), failover cluster nodes and roles.
      3. CHECKS
           Windows Server and SQL Server end of support (Microsoft lifecycle dates), update age,
           servers not restarted for -PatchDays days, pending restart, DNS record vs real IP
           address, IP not in any AD subnet.
      4. MANAGEMENT ACCESS
           For every server that could not be read: DNS, RPC (135), WinRM (5985), and - when both
           are closed - SMB (445) and RDP (3389) to tell a blocked server from one that does not
           answer at all. Grouped by subnet and AD site, with what to open from the audit host.
      5. CHANGES SINCE AN EARLIER RUN (-CompareWith)
           Servers added to or removed from AD, servers read now and not before (or the reverse),
           Windows version changes, updates installed since, SQL Server instances added or removed,
           and each finding before and now. The earlier run's data is copied into the new report.

    -IncludeActivation adds the Windows activation channel and status (slow WMI class).

    The report keeps the two apart: what AD gives for every server (OS version, lifecycle, roles
    registered in AD) and what could only be read from the servers that answered
    (hardware, installed roles, updates, services). Info tips (i) say where each figure comes from.

    READ-ONLY. Servers that are disabled, inactive in AD for more than -StaleDays days, or not
    Windows are listed from AD only and not contacted. Servers that cannot be reached are reported,
    never waited on for more than -ServerTimeoutSec seconds.

.PARAMETER OutputPath        Folder for the HTML report (default: current dir).
.PARAMETER SearchBase        Only servers under this OU (distinguished name).
.PARAMETER StaleDays         Servers with no activity in AD for more than this many days are listed but
                             not contacted (default 90).
.PARAMETER PatchDays         An update older than this many days is flagged (default 60).
.PARAMETER Throttle          How many servers are inventoried at the same time (default 20).
.PARAMETER ServerTimeoutSec  Maximum time spent on one server (default 90).
.PARAMETER IncludeActivation Also read the Windows activation channel and status (slow).
.PARAMETER SkipRemote        Discovery from AD only, no connection to the servers.
.PARAMETER OpenReport        Open the report when done (default: $true).
.PARAMETER CompareWith       An earlier Server Inventory report (.html) or data file (.json) to compare with.
.PARAMETER ExportJson        Also save the report data as a .json file next to the report.

.EXAMPLE
    .\AD-ServerInventory.ps1
.EXAMPLE
    .\AD-ServerInventory.ps1 -SearchBase "OU=Servers,DC=contoso,DC=com"
.EXAMPLE
    # Compare with last month's report
    .\AD-ServerInventory.ps1 -CompareWith .\AD_ServerInventory_20261012_090000.html

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite
    Requires: ActiveDirectory module (RSAT-AD-PowerShell). Windows PowerShell 5.1 or later.
              Full inventory needs local administrator rights on the servers and RPC/DCOM
              (or WinRM) access from the machine running the report.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [string]$SearchBase,
    [ValidateRange(1,3650)][int]$StaleDays = 90,
    [ValidateRange(1,3650)][int]$PatchDays = 60,
    [ValidateRange(1,64)][int]$Throttle = 20,
    [ValidateRange(10,900)][int]$ServerTimeoutSec = 90,
    [switch]$IncludeActivation,
    [switch]$SkipRemote,
    [switch]$OpenReport = $true,
    [string]$CompareWith,
    [switch]$ExportJson
)

$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Error "ActiveDirectory module not available. Install RSAT-AD-PowerShell."; exit 1 }
try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'; $GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $Now = Get-Date
try { $Domain = Get-ADDomain -ErrorAction Stop } catch { Write-Error "Could not contact the domain: $($_.Exception.Message)"; exit 1 }
try { $Forest = Get-ADForest -ErrorAction SilentlyContinue } catch { $Forest = $null }
$DomainDNS = [string]$Domain.DNSRoot
$ForestDNS = if ($Forest) { [string]$Forest.Name } else { $DomainDNS }
$ReportPath = Join-Path $OutputPath "AD_ServerInventory_$Stamp.html"
$Watch = [System.Diagnostics.Stopwatch]::StartNew()

# Earlier run to compare with: read now, so a wrong path fails before the inventory starts
$PrevJSON = $null
if ($CompareWith) {
    try {
        $t = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $CompareWith -ErrorAction Stop).ProviderPath)
        if ($t.TrimStart().StartsWith('{')) { $PrevJSON = $t.Trim() }
        else {
            $i = $t.IndexOf('var D = {')
            if ($i -ge 0) { $i += 8; $j = $t.IndexOf([char]10, $i); if ($j -lt 0) { $j = $t.Length }; $PrevJSON = $t.Substring($i, $j - $i).Trim().TrimEnd(';') }
        }
        if (-not $PrevJSON -or $PrevJSON.IndexOf('"servers":') -lt 0) { throw 'no Server Inventory data found in this file' }
        # Keep one level only: drop the run that the earlier report was itself compared with
        $k = $PrevJSON.IndexOf(',"prevRun":'); if ($k -gt 0) { $PrevJSON = $PrevJSON.Substring(0, $k) + '}' }
    } catch { Write-Error "-CompareWith '$CompareWith': $($_.Exception.Message)"; exit 1 }
}

Write-Host "AD Server Inventory" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan
Write-Host "build: v7" -ForegroundColor DarkGray
Write-Host "Forest: $ForestDNS   Current domain: $DomainDNS" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# Helpers (PS 5.1-safe: hashtables, ArrayList, no pscustomobject in data)
# ─────────────────────────────────────────────────────────────────────────────
$HKLM = [uint32]2147483650
# Step header with the elapsed time, so a slow step is easy to spot
function Show-Step { param([string]$Text) Write-Host ("{0}  ({1})" -f $Text,$Watch.Elapsed.ToString('mm\:ss')) -ForegroundColor Yellow }
function Fmt-Date { param($D) if ($D) { try { return ([datetime]$D).ToString('yyyy-MM-dd HH:mm') } catch { return '' } } return '' }
function Fmt-Day  { param($D) if ($D) { try { return ([datetime]$D).ToString('yyyy-MM-dd') } catch { return '' } } return '' }
# Sort helper without Sort-Object: fills $Out in place, ordered by string key.
function Fill-Sorted { param([System.Collections.ArrayList]$Items,[System.Collections.ArrayList]$Keys,[System.Collections.ArrayList]$Out)
    $map=@{}; $keyArr = [string[]]::new($Keys.Count)
    for ($i=0; $i -lt $Keys.Count; $i++) { $k = ([string]$Keys[$i]) + '|' + $i.ToString('D6'); $keyArr[$i]=$k; $map[$k]=$Items[$i] }
    [System.Array]::Sort($keyArr)
    foreach ($k in $keyArr) { [void]$Out.Add($map[$k]) }
}
function Test-Port {
    # Resolves the name once, then tries each IPv4 address with its own timeout.
    param([string]$ComputerName,[int]$Port,[int]$TimeoutMs=1500)
    $targets = [System.Collections.ArrayList]::new()
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($ComputerName,[ref]$ip)) { [void]$targets.Add($ip) }
    else {
        try { foreach ($a in [System.Net.Dns]::GetHostAddresses($ComputerName)) { if ($a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$targets.Add($a) } } } catch {}
        if ($targets.Count -eq 0) { [void]$targets.Add($ComputerName) }
    }
    foreach ($t in $targets) {
        $c = [System.Net.Sockets.TcpClient]::new()
        try {
            $iar = $c.BeginConnect($t,$Port,$null,$null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs,$false) -and $c.Connected) { $c.EndConnect($iar); return $true }
        } catch {} finally { $c.Close() }
    }
    return $false
}
# CIM session over DCOM (packet privacy is on by default, as the cluster namespace requires) or WinRM.
function New-SrvCimSession { param([string]$Name,[switch]$Wsman)
    if ($Wsman) { return New-CimSession -ComputerName $Name -OperationTimeoutSec 20 -ErrorAction Stop }
    $opt = New-CimSessionOption -Protocol Dcom
    return New-CimSession -ComputerName $Name -SessionOption $opt -OperationTimeoutSec 20 -ErrorAction Stop
}
function Get-Cim { param($S,[string]$Class,[string]$Ns='root/cimv2',[string]$Filter='',[string[]]$Prop=$null)
    $p = @{ CimSession=$S; Namespace=$Ns; ClassName=$Class; ErrorAction='Stop' }
    if ($Filter) { $p['Filter'] = $Filter }
    if ($Prop) { $p['Property'] = $Prop }
    return @(Get-CimInstance @p)
}
function Get-RegDword { param($S,[string]$Key,[string]$Name)
    try {
        $r = Invoke-CimMethod -CimSession $S -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName 'GetDWORDValue' -Arguments @{ hDefKey=$HKLM; sSubKeyName=$Key; sValueName=$Name } -ErrorAction Stop
        if ([int]$r.ReturnValue -eq 0 -and $null -ne $r.uValue) { return [int64]$r.uValue }
    } catch {}
    return $null
}
function Get-RegString { param($S,[string]$Key,[string]$Name)
    try {
        $r = Invoke-CimMethod -CimSession $S -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName 'GetStringValue' -Arguments @{ hDefKey=$HKLM; sSubKeyName=$Key; sValueName=$Name } -ErrorAction Stop
        if ([int]$r.ReturnValue -eq 0 -and $null -ne $r.sValue) { return [string]$r.sValue }
    } catch {}
    return $null
}
function Get-RegValueNames { param($S,[string]$Key)
    try {
        $r = Invoke-CimMethod -CimSession $S -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName 'EnumValues' -Arguments @{ hDefKey=$HKLM; sSubKeyName=$Key } -ErrorAction Stop
        if ([int]$r.ReturnValue -eq 0 -and $r.sNames) { return @($r.sNames) }
    } catch {}
    return @()
}
function Test-RegKey { param($S,[string]$Key)
    try { $r = Invoke-CimMethod -CimSession $S -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName 'EnumKey' -Arguments @{ hDefKey=$HKLM; sSubKeyName=$Key } -ErrorAction Stop; return ([int]$r.ReturnValue -eq 0) } catch { return $false }
}
# InstalledOn of Win32_QuickFixEngineering is a string, usually M/d/yyyy.
function Parse-QfeDate { param($V)
    if ($null -eq $V) { return $null }
    if ($V -is [datetime]) { return $V }
    $s = ([string]$V).Trim(); if (-not $s) { return $null }
    $limit = (Get-Date).AddDays(2)
    foreach ($f in 'M/d/yyyy','MM/dd/yyyy','M/d/yyyy h:mm:ss tt','yyyyMMdd','yyyy-MM-dd','d/M/yyyy','dd/MM/yyyy','d.M.yyyy') {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($s,$f,[System.Globalization.CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::None,[ref]$d)) { if ($d -le $limit) { return $d } }
    }
    if ($s -match '^[0-9a-fA-F]{16}$') { try { return [datetime]::FromFileTime([Convert]::ToInt64($s,16)) } catch {} }
    return $null
}
function Resolve-IPv4 { param([string]$Name)
    $o = [System.Collections.ArrayList]::new()
    try { foreach ($a in [System.Net.Dns]::GetHostAddresses($Name)) { if ([string]$a.AddressFamily -eq 'InterNetwork') { [void]$o.Add($a.IPAddressToString) } } } catch {}
    return ,$o
}
function ConvertTo-IPv4Num { param([string]$Ip)
    $a = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip,[ref]$a)) { return $null }
    if ($a.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    $b = $a.GetAddressBytes()
    return ([int64]$b[0] * 16777216) + ([int64]$b[1] * 65536) + ([int64]$b[2] * 256) + [int64]$b[3]
}

# Runs a script block once per item on a pool of runspaces (Windows PowerShell 5.1).
# The script block gets the item hashtable, stores its start time in $item['start'] and its
# result in $item['r']. An item that runs longer than -ItemTimeoutSec is stopped and skipped.
function Invoke-Parallel {
    param([System.Collections.IList]$Items,[scriptblock]$Script,[string[]]$Functions=@(),[hashtable]$Variables=@{},[int]$Throttle=20,[int]$ItemTimeoutSec=0,[string]$Noun='server')
    $tasks = [System.Collections.ArrayList]::new()
    if (-not $Items -or $Items.Count -eq 0) { return ,$tasks }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in $Functions) { [void]$iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($fn,(Get-Item ("Function:\" + $fn)).Definition)) }
    foreach ($k in @($Variables.Keys)) { [void]$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($k,$Variables[$k],'')) }
    $max = [math]::Max(1,[math]::Min($Throttle,$Items.Count))
    $pool = [runspacefactory]::CreateRunspacePool(1,$max,$iss,$Host)
    $pool.Open()
    $anyTimeout = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        foreach ($it in $Items) {
            $ps = [powershell]::Create(); $ps.RunspacePool = $pool
            [void]$ps.AddScript($Script.ToString()).AddArgument($it)
            [void]$tasks.Add(@{ ps=$ps; h=$ps.BeginInvoke(); item=$it; done=$false; error=''; timedOut=$false })
        }
        $total = $tasks.Count; $left = $total; $n = 0
        $step = [math]::Max(1,[int][math]::Floor($total / 20)); $next = $step
        while ($left -gt 0) {
            $now = Get-Date
            foreach ($t in $tasks) {
                if ($t['done']) { continue }
                if ($t['h'].IsCompleted) {
                    $t['done'] = $true; $left--; $n++
                    try { [void]$t['ps'].EndInvoke($t['h']) } catch { $t['error'] = [string]$_.Exception.Message }
                    $t['ps'].Dispose()
                } elseif ($ItemTimeoutSec -gt 0) {
                    $st = $t['item']['start']
                    if ($st -is [datetime] -and ($now - $st).TotalSeconds -gt $ItemTimeoutSec) {
                        $t['done'] = $true; $t['timedOut'] = $true; $anyTimeout = $true; $left--; $n++
                        try { [void]$t['ps'].BeginStop($null,$null) } catch {}
                    }
                }
            }
            if ($n -ge $next -or $left -eq 0) {
                $eta = ''
                if ($left -gt 0 -and $n -gt 0) { $sec = $sw.Elapsed.TotalSeconds / $n * $left; $eta = if ($sec -ge 90) { ' - about ' + [math]::Ceiling($sec / 60) + ' min left' } else { ' - about ' + [math]::Ceiling($sec) + ' s left' } }
                Write-Host ("  {0} / {1} {2}s ({3}%){4}" -f $n,$total,$Noun,[math]::Floor(100 * $n / $total),$eta) -ForegroundColor DarkGray
                while ($next -le $n) { $next += $step }
            }
            if ($left -le 0) { break }
            Start-Sleep -Milliseconds 200
        }
    } finally {
        # Work that did not finish in time is stopped in the background, not waited on.
        if ($anyTimeout) { try { [void]$pool.BeginClose($null,$null) } catch {} } else { $pool.Close(); $pool.Dispose() }
    }
    return ,$tasks
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Domains and server objects (every domain in the forest)
# ─────────────────────────────────────────────────────────────────────────────
Show-Step "[1/5] Reading server objects from AD..."
$domRaw = [System.Collections.ArrayList]::new()
if ($Forest -and @($Forest.Domains).Count) { foreach ($x in @($Forest.Domains)) { [void]$domRaw.Add([string]$x) } } else { [void]$domRaw.Add($DomainDNS) }
$domKeys = [System.Collections.ArrayList]::new(); foreach ($x in $domRaw) { [void]$domKeys.Add($(if ($x -eq $ForestDNS) { '0' } else { '1' }) + $x.ToLower()) }
$AllDomains = [System.Collections.ArrayList]::new(); Fill-Sorted -Items $domRaw -Keys $domKeys -Out $AllDomains
$DomInfo = @{}; $DomNotes = [System.Collections.ArrayList]::new()
foreach ($dom in $AllDomains) {
    try { $di = Get-ADDomain -Identity $dom -Server $dom -ErrorAction Stop; $DomInfo[$dom] = @{ dn=[string]$di.DistinguishedName } }
    catch { [void]$DomNotes.Add("Domain $dom could not be contacted from this host, so its servers are not in this report."); Write-Host "  $dom could not be contacted: $($_.Exception.Message)" -ForegroundColor DarkYellow }
}
# -SearchBase limits the run to the domain that contains it
$SbDomain = ''
if ($SearchBase) {
    $best = -1
    foreach ($k in @($DomInfo.Keys)) { $dn = [string]$DomInfo[$k]['dn']; if ($SearchBase.ToLower().EndsWith($dn.ToLower()) -and $dn.Length -gt $best) { $best = $dn.Length; $SbDomain = $k } }
    if (-not $SbDomain) { Write-Error "SearchBase '$SearchBase' is not in any domain of the forest."; exit 1 }
}
$Multi = [bool]($AllDomains.Count -gt 1 -and -not $SbDomain)

function Get-OuPath { param([string]$Dn)
    $parts = [regex]::Split($Dn,'(?<!\\),')
    $o = [System.Collections.ArrayList]::new()
    for ($i = $parts.Count - 1; $i -ge 1; $i--) { $p = $parts[$i]; if ($p -match '^(OU|CN)=(.+)$') { [void]$o.Add(($Matches[2] -replace '\\,',',')) } }
    return ($o -join '/')
}

$Attrs = @('name','dNSHostName','operatingSystem','operatingSystemVersion','lastLogonTimestamp','pwdLastSet','whenCreated','userAccountControl','servicePrincipalName','description','primaryGroupID')
$SrvFilter = '(&(objectCategory=computer)(|(operatingSystem=*server*)(&(operatingSystem=*)(!(operatingSystem=*windows*)))))'
$Recs = [System.Collections.ArrayList]::new(); $RecKeys = [System.Collections.ArrayList]::new()
$ByFqdn = @{}; $ByShort = @{}
$Cno = [System.Collections.ArrayList]::new(); $VcoNames = @{}
foreach ($dom in $AllDomains) {
    if (-not $DomInfo.ContainsKey($dom)) { continue }
    if ($SbDomain -and $dom -ne $SbDomain) { continue }
    $p = @{ LDAPFilter=$SrvFilter; Properties=$Attrs; Server=$dom; ResultPageSize=1000; ErrorAction='Stop' }
    if ($SbDomain) { $p['SearchBase'] = $SearchBase }
    $objs = @()
    try { $objs = @(Get-ADObject @p) } catch { [void]$DomNotes.Add("Server objects of $dom could not be read: $($_.Exception.Message)"); continue }
    $dk = if ($dom -eq $ForestDNS) { '0' } else { '1' }
    foreach ($o in $objs) {
        $spn = @($o.servicePrincipalName)
        if (@($spn | Where-Object { $_ -like 'MSServerClusterMgmtAPI/*' -or $_ -like 'MSClusterVirtualServer/*' }).Count) { continue }   # cluster names, listed under clusters
        $uac = [int]$o.userAccountControl; $enabled = -not ($uac -band 2)
        $llt = $null; if ($o.lastLogonTimestamp) { try { $llt = [datetime]::FromFileTime([int64]$o.lastLogonTimestamp) } catch {} }
        $pls = $null; if ($o.pwdLastSet -and [int64]$o.pwdLastSet -gt 0) { try { $pls = [datetime]::FromFileTime([int64]$o.pwdLastSet) } catch {} }
        $act = $llt; if ($pls -and (-not $act -or $pls -gt $act)) { $act = $pls }
        $actDays = $null; if ($act) { $actDays = [int][math]::Floor(($Now - $act).TotalDays) }
        $osAd = [string]$o.operatingSystem; $isWin = [bool]($osAd -match 'Windows')
        $short = ([string]$o.Name).ToUpper()
        $fq = [string]$o.dNSHostName; if (-not $fq) { $fq = $short.ToLower() + '.' + $dom }
        $pg = [int]$o.primaryGroupID
        $bAd = 0; if ([string]$o.operatingSystemVersion -match '\((\d+)\)') { $bAd = [int]$Matches[1] }
        $rec = @{ name=$short; fqdn=$fq.ToLower(); domain=$dom; ou=(Get-OuPath ([string]$o.DistinguishedName)); desc=[string]$o.description
                  osAd=$osAd; osVerAd=[string]$o.operatingSystemVersion; buildAd=$bAd; isWin=$isWin; enabled=[bool]$enabled
                  isDc=[bool]($pg -eq 516 -or $pg -eq 521); rodc=[bool]($pg -eq 521); lastActive=(Fmt-Date $act); lastActiveDays=$actDays; created=(Fmt-Day $o.whenCreated)
                  adRoles=[System.Collections.ArrayList]::new(); dnsIps=[System.Collections.ArrayList]::new(); ips=[System.Collections.ArrayList]::new(); site=''; status=''; statusText='' }
        if ($rec['isDc']) { [void]$rec['adRoles'].Add($(if ($rec['rodc']) { 'Read-only domain controller' } else { 'Domain controller' })) }
        if (-not $enabled) { $rec['status'] = 'disabled'; $rec['statusText'] = 'Disabled in AD - not contacted.' }
        elseif (-not $isWin) { $rec['status'] = 'nonwin'; $rec['statusText'] = 'Not a Windows server - listed from AD only.' }
        elseif ($null -eq $actDays -or $actDays -gt $StaleDays) { $rec['status'] = 'stale'; $rec['statusText'] = "No activity in AD for more than $StaleDays days - not contacted." }
        elseif ($SkipRemote) { $rec['status'] = 'skipped'; $rec['statusText'] = 'Listed from AD only (-SkipRemote).' }
        [void]$Recs.Add($rec); [void]$RecKeys.Add($dk + $dom.ToLower() + '|' + $short)
        $ByFqdn[$rec['fqdn']] = $rec
        if ($ByShort.ContainsKey($short)) { $ByShort[$short] = $null } else { $ByShort[$short] = $rec }   # ambiguous short names are not used
    }
    # Cluster name objects (CNO) and clustered roles (VCO)
    try {
        $cp = @{ LDAPFilter='(&(objectCategory=computer)(servicePrincipalName=MSServerClusterMgmtAPI/*))'; Properties=@('dNSHostName','userAccountControl'); Server=$dom; ResultPageSize=1000; ErrorAction='Stop' }
        if ($SbDomain) { $cp['SearchBase'] = $SearchBase }
        foreach ($c in @(Get-ADObject @cp)) {
            [void]$Cno.Add(@{ name=([string]$c.Name).ToUpper(); fqdn=([string]$c.dNSHostName).ToLower(); domain=$dom; enabled=[bool](-not ([int]$c.userAccountControl -band 2)) })
        }
        foreach ($c in @(Get-ADObject -LDAPFilter '(&(objectCategory=computer)(servicePrincipalName=MSClusterVirtualServer/*))' -Properties dNSHostName -Server $dom -ResultPageSize 1000 -ErrorAction Stop)) {
            $VcoNames[([string]$c.Name).ToUpper()] = $true; if ($c.dNSHostName) { $VcoNames[([string]$c.dNSHostName).ToLower()] = $true }
        }
    } catch {}
}
$Servers = [System.Collections.ArrayList]::new(); Fill-Sorted -Items $Recs -Keys $RecKeys -Out $Servers
function Find-Rec { param([string]$HostName)
    $h = $HostName.ToLower().TrimEnd('.')
    if ($ByFqdn.ContainsKey($h)) { return $ByFqdn[$h] }
    $s = ($h -split '\.')[0].ToUpper()
    if ($ByShort.ContainsKey($s)) { return $ByShort[$s] }
    return $null
}
function Add-Role { param($Rec,[string]$Role) if ($Rec -and -not ($Rec['adRoles'] -contains $Role)) { [void]$Rec['adRoles'].Add($Role) } }
$nDom = if ($SbDomain) { 1 } else { @($DomInfo.Keys).Count }
Write-Host "  $($Servers.Count) server object(s) in $nDom domain(s), $($Cno.Count) cluster name(s)$(if ($SbDomain) { " under $SearchBase" })" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# 2. Roles AD already knows about (no connection to the servers)
# ─────────────────────────────────────────────────────────────────────────────
Show-Step "[2/5] Reading roles registered in AD..."
$AdSql = [System.Collections.ArrayList]::new()
try { $cfg = [string](Get-ADRootDSE -ErrorAction Stop).configurationNamingContext } catch { $cfg = '' }
foreach ($dom in $AllDomains) {
    if (-not $DomInfo.ContainsKey($dom)) { continue }
    if ($SbDomain -and $dom -ne $SbDomain) { continue }
    # SQL Server: MSSQLSvc SPNs, on the computer or on the service account
    try {
        foreach ($o in @(Get-ADObject -LDAPFilter '(servicePrincipalName=MSSQLSvc/*)' -Properties servicePrincipalName,sAMAccountName,objectClass -Server $dom -ResultPageSize 1000 -ErrorAction Stop)) {
            foreach ($sp in @($o.servicePrincipalName)) {
                if ([string]$sp -notmatch '^MSSQLSvc/([^:/]+)(?::(.+))?$') { continue }
                $h = $Matches[1].ToLower(); $ip = [string]$Matches[2]
                $cls = @($o.objectClass)[-1]
                [void]$AdSql.Add(@{ host=$h; port=$ip; account=([string]$o.sAMAccountName); kind=$(if ([string]$cls -eq 'computer') { 'computer' } elseif ([string]$cls -like 'msDS-*ManagedServiceAccount') { 'gMSA' } else { 'user' }); domain=$dom })
                Add-Role (Find-Rec $h) 'SQL Server (SPN)'
            }
        }
    } catch {}
    # Configuration Manager management points (only if the schema was extended)
    try {
        foreach ($o in @(Get-ADObject -SearchBase ('CN=System Management,CN=System,' + $DomInfo[$dom]['dn']) -LDAPFilter '(objectClass=mSSMSManagementPoint)' -Properties mSSMSMPName,mSSMSSiteCode -Server $dom -ErrorAction Stop)) {
            Add-Role (Find-Rec ([string]$o.mSSMSMPName)) ('Configuration Manager management point (' + [string]$o.mSSMSSiteCode + ')')
        }
    } catch {}
}
if ($cfg) {
    try {
        foreach ($o in @(Get-ADObject -SearchBase ('CN=Enrollment Services,CN=Public Key Services,CN=Services,' + $cfg) -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName -ErrorAction Stop)) {
            Add-Role (Find-Rec ([string]$o.dNSHostName)) ('Certificate authority (' + [string]$o.Name + ')')
        }
    } catch {}
    try {
        foreach ($o in @(Get-ADObject -SearchBase ('CN=Microsoft Exchange,CN=Services,' + $cfg) -LDAPFilter '(objectCategory=msExchExchangeServer)' -Properties serialNumber -ErrorAction Stop)) {
            $sn = [string](@($o.serialNumber)[0]); $lbl = 'Exchange Server'
            if ($sn -match 'Version 15\.2') { $lbl = 'Exchange 2019 / SE' } elseif ($sn -match 'Version 15\.1') { $lbl = 'Exchange 2016' } elseif ($sn -match 'Version 15\.0') { $lbl = 'Exchange 2013' } elseif ($sn -match 'Version 14\.') { $lbl = 'Exchange 2010' }
            Add-Role (Find-Rec ([string]$o.Name)) $lbl
        }
    } catch {}
}
# AD sites from subnets (longest prefix wins)
$Subnets = [System.Collections.ArrayList]::new()
if ($cfg) {
    try {
        $sl = [System.Collections.ArrayList]::new(); $sk = [System.Collections.ArrayList]::new()
        foreach ($o in @(Get-ADObject -SearchBase ('CN=Subnets,CN=Sites,' + $cfg) -LDAPFilter '(objectClass=subnet)' -Properties siteObject -ErrorAction Stop)) {
            if ([string]$o.Name -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { continue }
            $net = ConvertTo-IPv4Num $Matches[1]; $bits = [int]$Matches[2]; if ($null -eq $net -or $bits -gt 32) { continue }
            $mask = [int64]4294967296 - [int64][math]::Pow(2, 32 - $bits)
            $site = ''; if ([string]$o.siteObject -match '^CN=([^,]+),') { $site = $Matches[1] }
            [void]$sl.Add(@{ net=($net -band $mask); mask=$mask; site=$site; name=[string]$o.Name }); [void]$sk.Add((99 - $bits).ToString('D2'))
        }
        Fill-Sorted -Items $sl -Keys $sk -Out $Subnets
    } catch {}
}
# AD subnet and site of an IP; an IP outside every AD subnet is grouped by its /24
function Find-Net { param([string]$Ip)
    $n = ConvertTo-IPv4Num $Ip; if ($null -eq $n) { return @{ site=''; subnet=''; inAd=$false } }
    foreach ($s in $Subnets) { if (($n -band $s['mask']) -eq $s['net']) { return @{ site=[string]$s['site']; subnet=[string]$s['name']; inAd=$true } } }
    return @{ site=''; subnet=(($Ip -replace '\.\d+$','.0') + '/24'); inAd=$false }
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. Inventory of each server (several at a time)
# ─────────────────────────────────────────────────────────────────────────────
# One runspace per server. Builds its result in a local hashtable and stores it in $j['r'] at the end.
$SrvScript = {
    param($j)
    $j['start'] = Get-Date
    $n = [string]$j['fqdn']
    $r = @{ dns=[System.Collections.ArrayList]::new(); status=''; statusText='' }
    foreach ($a in (Resolve-IPv4 $n)) { [void]$r['dns'].Add([string]$a) }
    if (-not $j['contact']) { $j['r'] = $r; return }
    if ($r['dns'].Count -eq 0) { $r['status'] = 'unreachable'; $r['access'] = 'dns'; $r['statusText'] = 'The name does not resolve in DNS from the audit host.'; $j['r'] = $r; return }
    # Which way in: RPC (DCOM) on 135 or WinRM on 5985
    $p135 = Test-Port -ComputerName $n -Port 135 -TimeoutMs 1500
    $p5985 = Test-Port -ComputerName $n -Port 5985 -TimeoutMs 1500
    $r['ports'] = @{ p135=$p135; p5985=$p5985 }
    if (-not $p135 -and -not $p5985) {
        # Both closed: is the server up (SMB or RDP answers) or not answering at all?
        $p445 = Test-Port -ComputerName $n -Port 445 -TimeoutMs 1500
        $p3389 = $false; if (-not $p445) { $p3389 = Test-Port -ComputerName $n -Port 3389 -TimeoutMs 1500 }
        $r['ports']['p445'] = $p445; $r['ports']['p3389'] = $p3389
        $r['status'] = 'unreachable'
        if ($p445 -or $p3389) { $r['access'] = 'blocked'; $r['statusText'] = 'The server answers (' + $(if ($p445) { 'SMB' } else { 'RDP' }) + '), but RPC (135) and WinRM (5985) are blocked from the audit host.' }
        else { $r['access'] = 'noanswer'; $r['statusText'] = 'No answer on ports 135, 445, 3389 or 5985 from the audit host: server off, wrong IP in DNS, or a network firewall.' }
        $j['r'] = $r; return
    }
    $s = $null
    try {
        # Connect: DCOM first, WinRM if DCOM is blocked or does not answer
        $os = $null; $msg = ''
        if ($p135) {
            try { $s = New-SrvCimSession -Name $n; $os = @(Get-Cim $s 'Win32_OperatingSystem' -Prop @('Caption','Version','BuildNumber','InstallDate','LastBootUpTime','OSArchitecture'))[0]; $r['via'] = 'DCOM' }
            catch { $msg = [string]$_.Exception.Message }
        }
        if (-not $os -and $msg -notmatch 'denied|0x80070005' -and $p5985) {
            if ($s) { try { Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue } catch {}; $s = $null }
            try { $s = New-SrvCimSession -Name $n -Wsman; $os = @(Get-Cim $s 'Win32_OperatingSystem' -Prop @('Caption','Version','BuildNumber','InstallDate','LastBootUpTime','OSArchitecture'))[0]; $r['via'] = 'WinRM' }
            catch { $msg = [string]$_.Exception.Message }
        }
        if (-not $os) {
            if ($msg -match 'denied|0x80070005') { $r['status'] = 'denied'; $r['access'] = 'denied'; $r['statusText'] = 'Access denied - the account running the report is not an administrator on this server.' }
            elseif ($p135 -and -not $p5985 -and $msg -match '0x800706BA|RPC server is unavailable') { $r['status'] = 'unreachable'; $r['access'] = 'rpcdyn'; $r['statusText'] = 'Port 135 answers but WMI over DCOM does not: the dynamic RPC ports (49152-65535) are probably blocked, and WinRM (5985) is closed.' }
            else { $r['status'] = 'unreachable'; $r['access'] = 'wmi'; $r['statusText'] = 'WMI did not answer (' + $(if ($p5985) { 'WinRM' } else { 'DCOM' }) + '): ' + ($msg -replace '\s+',' ').Trim() }
            $j['r'] = $r; return
        }
        # Operating system
        $r['os'] = (([string]$os.Caption) -replace '^Microsoft\s+','' -replace '\s+',' ').Trim()
        $r['build'] = [int]$os.BuildNumber; $r['version'] = [string]$os.Version; $r['arch'] = [string]$os.OSArchitecture
        $r['installDate'] = Fmt-Day $os.InstallDate; $r['lastBoot'] = Fmt-Date $os.LastBootUpTime
        if ($os.LastBootUpTime) { $r['uptimeDays'] = [int][math]::Floor(((Get-Date) - [datetime]$os.LastBootUpTime).TotalDays) }
        # Hardware
        try { $cs = @(Get-Cim $s 'Win32_ComputerSystem' -Prop @('Manufacturer','Model','TotalPhysicalMemory'))[0]; $r['mfr'] = ([string]$cs.Manufacturer).Trim(); $r['model'] = ([string]$cs.Model).Trim(); $r['ramGB'] = [math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1) } catch {}
        try {
            $cpus = @(Get-Cim $s 'Win32_Processor' -Prop @('Name','NumberOfCores','NumberOfLogicalProcessors'))
            $co = 0; $lo = 0; foreach ($c in $cpus) { $co += [int]$c.NumberOfCores; $lo += [int]$c.NumberOfLogicalProcessors }
            $r['sockets'] = $cpus.Count; $r['cores'] = $co; $r['logical'] = $lo
            if ($cpus.Count) { $r['cpu'] = (([string]$cpus[0].Name) -replace '\s+',' ').Trim() }
        } catch {}
        try { $b = @(Get-Cim $s 'Win32_BIOS' -Prop @('SerialNumber','SMBIOSBIOSVersion','ReleaseDate'))[0]; $r['serial'] = ([string]$b.SerialNumber).Trim(); $r['biosVer'] = [string]$b.SMBIOSBIOSVersion; $r['biosDate'] = Fmt-Day $b.ReleaseDate } catch {}
        # Physical or virtual (the hypervisor itself is not reported)
        $man = [string]$r['mfr']; $mod = [string]$r['model']
        $r['platform'] = if (-not $man) { 'Unknown' } elseif (($man + ' ' + $mod) -match 'VMware|Virtual|Hyper-V|Amazon|HVM domU|Google|Nutanix|AHV|VirtualBox|KVM|QEMU|Xen|Bochs|Standard PC|innotek|Red Hat|oVirt|Parallels|Proxmox') { 'Virtual' } else { 'Physical' }
        # IP addresses
        $ipl = [System.Collections.ArrayList]::new()
        try { foreach ($nic in @(Get-Cim $s 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=True' -Prop @('IPAddress'))) { foreach ($ip in @($nic.IPAddress)) { $ip = [string]$ip; if ($ip -match '^\d+\.\d+\.\d+\.\d+$' -and $ip -notlike '169.254.*' -and -not ($ipl -contains $ip)) { [void]$ipl.Add($ip) } } } } catch {}
        $r['ips'] = $ipl
        # Roles and features (top level)
        $fl = [System.Collections.ArrayList]::new()
        # Top-level roles and features, plus the file-server role services that Windows lists under File and Storage Services
        $keep = @('File Server','DFS Namespaces','DFS Replication','Data Deduplication','iSCSI Target Server','Server for NFS','Work Folders','BranchCache for Network Files','File Server Resource Manager')
        try { foreach ($f in @(Get-Cim $s 'Win32_ServerFeature' -Prop @('ID','Name','ParentID'))) { if ([int]$f.ParentID -eq 0 -or $keep -contains [string]$f.Name) { [void]$fl.Add([string]$f.Name) } } } catch {}
        $r['features'] = $fl
        # Last installed update
        try {
            $best = $null; $kb = ''
            foreach ($q in @(Get-Cim $s 'Win32_QuickFixEngineering' -Prop @('HotFixID','InstalledOn'))) { $d = Parse-QfeDate $q.InstalledOn; if ($d -and ($null -eq $best -or $d -gt $best)) { $best = $d; $kb = [string]$q.HotFixID } }
            if ($best) { $r['lastUpdate'] = Fmt-Day $best; $r['lastUpdateKb'] = $kb; $r['patchDays'] = [int][math]::Floor(((Get-Date).Date - $best.Date).TotalDays) }
        } catch {}
        # Pending restart
        $why = [System.Collections.ArrayList]::new()
        if (Test-RegKey $s 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { [void]$why.Add('Component servicing') }
        if (Test-RegKey $s 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { [void]$why.Add('Windows Update') }
        $an = Get-RegString $s 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
        $cn = Get-RegString $s 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
        if ($an -and $cn -and $an -ne $cn) { [void]$why.Add('Computer rename') }
        $r['pending'] = [bool]($why.Count -gt 0); $r['pendingWhy'] = $why
        # Services: the ones running under domain accounts, plus the map used for SQL and the cluster check
        $svcMap = @{}; $svl = [System.Collections.ArrayList]::new()
        try {
            foreach ($x in @(Get-Cim $s 'Win32_Service' -Prop @('Name','DisplayName','StartName','State','StartMode'))) {
                $svcMap[[string]$x.Name] = $x
                $acc = [string]$x.StartName
                if (-not $acc -or $acc -eq 'LocalSystem' -or $acc -like 'NT AUTHORITY\*' -or $acc -like 'NT SERVICE\*' -or $acc -like 'NT VIRTUAL MACHINE\*' -or $acc -like '.\*') { continue }
                if ($acc -notmatch '\\|@') { continue }
                if ($acc -like ($j['short'] + '\*')) { continue }   # local account of this server
                [void]$svl.Add(@{ name=[string]$x.Name; display=[string]$x.DisplayName; account=$acc; state=[string]$x.State; mode=[string]$x.StartMode; gmsa=[bool]($acc.EndsWith([string][char]36)) })
            }
        } catch {}
        $r['svc'] = $svl
        # SQL Server instances (registry)
        $sql = [System.Collections.ArrayList]::new(); $seen = @{}
        foreach ($root in 'SOFTWARE\Microsoft\Microsoft SQL Server','SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server') {
            foreach ($inst in (Get-RegValueNames $s ($root + '\Instance Names\SQL'))) {
                $inst = [string]$inst; if (-not $inst -or $seen.ContainsKey($inst)) { continue }; $seen[$inst] = $true
                $id = Get-RegString $s ($root + '\Instance Names\SQL') $inst; if (-not $id) { continue }
                $set = $root + '\' + $id + '\Setup'
                $ver = Get-RegString $s $set 'PatchLevel'; if (-not $ver) { $ver = Get-RegString $s $set 'Version' }
                $fci = Get-RegString $s ($root + '\' + $id + '\Cluster') 'ClusterName'
                $svn = if ($inst -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { 'MSSQL' + [string][char]36 + $inst }
                $sv = $svcMap[$svn]
                [void]$sql.Add(@{ instance=$inst; edition=[string](Get-RegString $s $set 'Edition'); version=[string]$ver; fci=[string]$fci; account=$(if ($sv) { [string]$sv.StartName } else { '' }); state=$(if ($sv) { [string]$sv.State } else { '' }); mode=$(if ($sv) { [string]$sv.StartMode } else { '' }) })
            }
        }
        $r['sql'] = $sql
        # Failover cluster (only on nodes where the cluster service runs)
        $cl = $svcMap['ClusSvc']
        if ($cl -and [string]$cl.State -eq 'Running') {
            $c = @{ name=''; nodes=[System.Collections.ArrayList]::new(); groups=[System.Collections.ArrayList]::new(); error='' }
            try {
                $cc = @(Get-Cim $s 'MSCluster_Cluster' -Ns 'root/MSCluster')
                if ($cc.Count) { $c['name'] = ([string]$cc[0].Name).ToUpper() }
                $ns = @{ 0='Up'; 1='Down'; 2='Paused'; 3='Joining' }
                foreach ($x in @(Get-Cim $s 'MSCluster_Node' -Ns 'root/MSCluster')) { $st = $ns[[int]$x.State]; if (-not $st) { $st = 'Unknown' }; [void]$c['nodes'].Add(@{ name=([string]$x.Name).ToUpper(); state=$st }) }
                $gs = @{ 0='Online'; 1='Offline'; 2='Failed'; 3='Partially online'; 4='Pending' }
                foreach ($x in @(Get-Cim $s 'MSCluster_ResourceGroup' -Ns 'root/MSCluster')) {
                    $st = $gs[[int]$x.State]; if (-not $st) { $st = 'Unknown' }
                    $ow = ''; try { $ow = ([string]$x.OwnerNode).ToUpper() } catch {}
                    [void]$c['groups'].Add(@{ name=[string]$x.Name; type=[int]$x.GroupType; state=$st; owner=$ow })
                }
            } catch { $c['error'] = [string]$_.Exception.Message }
            $r['cluster'] = $c
        }
        # Windows activation (optional, slow)
        if ($j['act']) {
            try {
                $lp = @(Get-Cim $s 'SoftwareLicensingProduct' -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -Prop @('Name','Description','LicenseStatus'))
                if ($lp.Count) {
                    $d = [string]$lp[0].Description
                    $ch = if ($d -match 'VIRTUAL_MACHINE_ACTIVATION') { 'AVMA' } elseif ($d -match 'VOLUME_KMSCLIENT') { 'KMS client' } elseif ($d -match 'VOLUME_MAK') { 'MAK' } elseif ($d -match 'OEM') { 'OEM' } elseif ($d -match 'RETAIL') { 'Retail' } elseif ($d -match 'VOLUME') { 'Volume' } else { 'Other' }
                    $ls = [int]$lp[0].LicenseStatus
                    $st = switch ($ls) { 0 { 'Unlicensed' } 1 { 'Licensed' } 2 { 'Initial grace period' } 3 { 'Additional grace period' } 4 { 'Non-genuine grace period' } 5 { 'Notification' } 6 { 'Extended grace period' } default { 'Unknown' } }
                    $r['act'] = @{ channel=$ch; status=$st; ok=[bool]($ls -eq 1) }
                } else { $r['act'] = @{ channel=''; status='No product key found'; ok=$false } }
            } catch { $r['act'] = @{ channel=''; status='Could not be read'; ok=$null } }
        }
        $r['status'] = 'ok'
    } catch { $r['status'] = 'error'; $r['statusText'] = 'Collection error: ' + [string]$_.Exception.Message }
    finally { if ($s) { try { Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue } catch {} } }
    $j['r'] = $r
}

$Jobs = [System.Collections.ArrayList]::new()
foreach ($rec in $Servers) { [void]$Jobs.Add(@{ fqdn=$rec['fqdn']; short=$rec['name']; contact=[bool](-not $rec['status']); isDc=$rec['isDc']; act=[bool]$IncludeActivation; start=$null; r=$null; rec=$rec }) }
$nContact = @($Jobs | Where-Object { $_['contact'] }).Count
if ($SkipRemote) { Show-Step "[3/5] Inventory skipped (-SkipRemote) - resolving DNS names only..." }
else { Show-Step "[3/5] Inventorying $nContact server(s), $Throttle at a time ($($Jobs.Count - $nContact) listed from AD only)..." }
$tasks = Invoke-Parallel -Items $Jobs -Script $SrvScript -Throttle $Throttle -ItemTimeoutSec $ServerTimeoutSec `
    -Functions @('Test-Port','Resolve-IPv4','New-SrvCimSession','Get-Cim','Get-RegDword','Get-RegString','Get-RegValueNames','Test-RegKey','Fmt-Date','Fmt-Day','Parse-QfeDate') `
    -Variables @{ HKLM=$HKLM }

# ─────────────────────────────────────────────────────────────────────────────
# 4. Merge, sites, DNS check, clusters, SQL Server
# ─────────────────────────────────────────────────────────────────────────────
Show-Step "[4/5] Analysing..."
foreach ($t in $tasks) {
    $j = $t['item']; $rec = $j['rec']; $r = $j['r']
    if ($t['timedOut']) { $rec['status'] = 'timeout'; $rec['access'] = 'timeout'; $rec['statusText'] = "No complete answer within $ServerTimeoutSec seconds - the server was skipped."; $r = $null }
    elseif (-not $r) { if ($j['contact']) { $rec['status'] = 'error'; $rec['statusText'] = 'Collection error: ' + [string]$t['error'] } }
    if ($r) {
        foreach ($d in $r['dns']) { [void]$rec['dnsIps'].Add([string]$d) }
        if ($j['contact']) {
            foreach ($k in @($r.Keys)) { if ($k -ne 'dns') { $rec[$k] = $r[$k] } }
        }
    }
    $j.Remove('rec')
    if (-not $rec['dnsIps'].Count -and ($rec['status'] -eq 'timeout' -or $rec['status'] -eq 'error')) { foreach ($d in (Resolve-IPv4 $rec['fqdn'])) { [void]$rec['dnsIps'].Add([string]$d) } }
    # AD site and DNS consistency
    $ip0 = ''; if ($rec['ips'].Count) { $ip0 = [string]$rec['ips'][0] } elseif ($rec['dnsIps'].Count) { $ip0 = [string]$rec['dnsIps'][0] }
    $rec['subnet'] = ''; $rec['subnetInAd'] = $false
    if ($ip0) { $nt = Find-Net $ip0; $rec['site'] = $nt['site']; $rec['subnet'] = $nt['subnet']; $rec['subnetInAd'] = $nt['inAd'] }
    $rec['dnsState'] = ''
    if ($rec['status'] -eq 'ok' -and $rec['ips'].Count) {
        $both = 0; $extra = 0
        foreach ($d in $rec['dnsIps']) { if ($rec['ips'] -contains $d) { $both++ } else { $extra++ } }
        $rec['dnsState'] = if ($rec['dnsIps'].Count -eq 0) { 'missing' } elseif ($both -eq 0) { 'mismatch' } elseif ($extra -gt 0) { 'partial' } else { 'ok' }
    }
}
# Failover clusters: from the nodes, plus cluster name objects found only in AD
$CL = [System.Collections.ArrayList]::new(); $clIdx = @{}
foreach ($rec in $Servers) {
    $c = $rec['cluster']; if (-not $c -or -not $c['name']) { continue }
    $k = [string]$c['name']
    if (-not $clIdx.ContainsKey($k)) {
        $e = @{ name=$k; domain=$rec['domain']; nodes=$c['nodes']; groups=$c['groups']; source='inventory'; inAd=$false; seenFrom=[System.Collections.ArrayList]::new() }
        $clIdx[$k] = $e; [void]$CL.Add($e)
    }
    [void]$clIdx[$k]['seenFrom'].Add($rec['name'])
    $rec['clusterName'] = $k
}
foreach ($c in $Cno) {
    if ($clIdx.ContainsKey($c['name'])) { $clIdx[$c['name']]['inAd'] = $true; continue }
    $e = @{ name=$c['name']; domain=$c['domain']; nodes=[System.Collections.ArrayList]::new(); groups=[System.Collections.ArrayList]::new(); source='ad'; inAd=$true; enabled=$c['enabled']; seenFrom=[System.Collections.ArrayList]::new() }
    $clIdx[$c['name']] = $e; [void]$CL.Add($e)
}
foreach ($rec in $Servers) { if ($rec['cluster']) { $rec.Remove('cluster') } }
# SQL Server: inventoried instances, plus SPNs in AD for hosts that were not inventoried
$SQL = [System.Collections.ArrayList]::new(); $sqlHosts = @{}
foreach ($rec in $Servers) {
    foreach ($i in @($rec['sql'])) {
        if (-not $i) { continue }
        [void]$SQL.Add(@{ server=$rec['name']; fqdn=$rec['fqdn']; domain=$rec['domain']; instance=$i['instance']; edition=$i['edition']; version=$i['version']; fci=$i['fci']; account=$i['account']; state=$i['state']; mode=$i['mode']; source='inventory' })
        $sqlHosts[$rec['fqdn']] = $true
    }
}
# One row per host for SPNs whose host was not inventoried (or has no instance)
$adHost = @{}; $adOrder = [System.Collections.ArrayList]::new()
foreach ($a in $AdSql) {
    $rec = Find-Rec $a['host']
    if ($rec -and $sqlHosts.ContainsKey($rec['fqdn'])) { continue }
    if ($SbDomain -and -not $rec) { continue }   # with -SearchBase, only hosts in scope
    $h = $a['host']
    if (-not $adHost.ContainsKey($h)) { $adHost[$h] = @{ rec=$rec; a=$a; inst=[System.Collections.ArrayList]::new(); acc=[System.Collections.ArrayList]::new() }; [void]$adOrder.Add($h) }
    $e = $adHost[$h]
    $p = [string]$a['port']; $lbl = if ($p -match '^\d+$') { 'Port ' + $p } elseif ($p) { $p } else { '' }
    if ($lbl -and -not ($e['inst'] -contains $lbl)) { [void]$e['inst'].Add($lbl) }
    $acc = $a['account'] + $(if ($a['kind'] -ne 'computer') { ' (' + $a['kind'] + ')' } else { '' })
    if (-not ($e['acc'] -contains $acc)) { [void]$e['acc'].Add($acc) }
}
foreach ($h in $adOrder) {
    $e = $adHost[$h]; $rec = $e['rec']; $a = $e['a']
    $isVco = [bool]($VcoNames.ContainsKey($h) -or $VcoNames.ContainsKey((($h -split '\.')[0]).ToUpper()))
    $src = if ($isVco) { 'ad-clustered' } elseif ($rec -and $rec['status'] -eq 'ok') { 'ad-stale' } else { 'ad' }
    [void]$SQL.Add(@{ server=$(if ($rec) { $rec['name'] } else { (($h -split '\.')[0]).ToUpper() }); fqdn=$h; domain=$(if ($rec) { $rec['domain'] } else { $a['domain'] }); instance=$(if ($e['inst'].Count) { $e['inst'] -join ', ' } else { 'Default' }); edition=''; version=''; fci=''
                     account=($e['acc'] -join ', '); state=''; mode=''; source=$src })
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. Report data
# ─────────────────────────────────────────────────────────────────────────────
function ConvertTo-JsonStr {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return '""' }
    if ($s -notmatch '[^\x20\x21\x23-\x5B\x5D-\x7E]') { return '"' + $s + '"' }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('"')
    foreach ($ch in $s.ToCharArray()) {
        $code = [int][char]$ch
        if     ($code -eq 34) { [void]$sb.Append('\"') }
        elseif ($code -eq 92) { [void]$sb.Append('\\') }
        elseif ($code -lt 32 -or $code -gt 126) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"'); $sb.ToString()
}
function Write-JsonValue {
    param($o, [System.Text.StringBuilder]$sb)
    if ($null -eq $o) { [void]$sb.Append('null'); return }
    if ($o -is [bool])   { [void]$sb.Append($(if ($o) { 'true' } else { 'false' })); return }
    if ($o -is [string]) { [void]$sb.Append((ConvertTo-JsonStr $o)); return }
    if ($o -is [int] -or $o -is [long] -or $o -is [double] -or $o -is [decimal]) { [void]$sb.Append(([string]$o).Replace(',','.')); return }
    if ($o -is [System.Collections.IDictionary]) {
        [void]$sb.Append('{'); $f=$true
        foreach ($k in $o.Keys) { if (-not $f) { [void]$sb.Append(',') }; $f=$false; [void]$sb.Append((ConvertTo-JsonStr ([string]$k))); [void]$sb.Append(':'); Write-JsonValue $o[$k] $sb }
        [void]$sb.Append('}'); return
    }
    if ($o -is [System.Collections.IEnumerable]) {
        [void]$sb.Append('['); $f=$true
        foreach ($item in $o) { if (-not $f) { [void]$sb.Append(',') }; $f=$false; Write-JsonValue $item $sb }
        [void]$sb.Append(']'); return
    }
    [void]$sb.Append((ConvertTo-JsonStr ([string]$o)))
}

Show-Step "[5/5] Building the report..."
$stage = 'summary'
try {
    $okN = @($Servers | Where-Object { $_['status'] -eq 'ok' }).Count
    $Summary = @{ forest=$ForestDNS; domain=$DomainDNS; generated=$GeneratedAt; domains=$(if ($SbDomain) { ,@($SbDomain) } else { ,@($AllDomains) }); notes=$DomNotes
                  params=@{ auditHost=[Environment]::MachineName; auditUser=([Environment]::UserDomainName + '\' + [Environment]::UserName); staleDays=$StaleDays; patchDays=$PatchDays; activation=[bool]$IncludeActivation; skipRemote=[bool]$SkipRemote; searchBase=[string]$SearchBase; throttle=$Throttle; timeout=$ServerTimeoutSec; duration=[int]$Watch.Elapsed.TotalSeconds }
                  servers=$Servers; clusters=$CL; sql=$SQL }
    $stage = 'serialize'
    # Own JSON writer: the .NET JavaScriptSerializer can spend a very long time on PowerShell-wrapped values before failing
    $__jsb = [System.Text.StringBuilder]::new(); Write-JsonValue $Summary $__jsb; $DataJSON = $__jsb.ToString()
    if ($ExportJson) { $JsonPath = [System.IO.Path]::ChangeExtension($ReportPath, '.json'); [System.IO.File]::WriteAllText($JsonPath, $DataJSON, [System.Text.UTF8Encoding]::new($false)); Write-Host "  Data saved: $JsonPath" -ForegroundColor Gray }
    if ($PrevJSON) { $DataJSON = $DataJSON.Substring(0, $DataJSON.LastIndexOf('}')) + ',"prevRun":' + $PrevJSON + '}'; Write-Host "  Compared with: $CompareWith" -ForegroundColor Gray }
    Write-Host ("  {0} server(s), {1} read, {2} SQL Server instance(s), {3} cluster(s) - JSON {4} MB" -f $Servers.Count,$okN,$SQL.Count,$CL.Count,[math]::Round($DataJSON.Length/1MB,2)) -ForegroundColor Gray
} catch {
    Write-Host ""
    Write-Host ">>> FAILED at stage '$stage': $($_.Exception.GetType().Name) - $($_.Exception.Message)" -ForegroundColor Red
    throw
}

$HTML = @"
<!DOCTYPE html>
<html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Server Inventory - $ForestDNS</title>
<style>

:root{
  --bg:#f5f6fb; --surface:#ffffff; --surface2:#eef1f9; --surface3:#dfe4f2; --border:#e4e7f2; --text:#161a2e; --muted:#64708c;
  --accent:#4f46e5; --accent-hover:#6366f1; --accent-soft:#e6e6fd;
  --blue:#2563eb; --blue-soft:#dbe8fe; --green:#059669; --green-soft:#d1fae5; --red:#dc2626; --red-soft:#fde2e2;
  --amber:#d97706; --amber-soft:#fef3c7; --teal:#0d9488; --teal-soft:#cdeee9; --purple:#7c3aed; --purple-soft:#ede9fe;
  --radius:13px; --radius-sm:9px;
  --shadow:0 2px 8px rgb(60 50 140 / 0.06), 0 1px 2px rgb(60 50 140 / 0.04);
  --shadow-hover:0 10px 15px -3px rgb(0 0 0 / 0.08), 0 4px 6px -4px rgb(0 0 0 / 0.08);
  --font:'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --mono:'SFMono-Regular', ui-monospace, Menlo, Consolas, monospace;
}
[data-theme="dark"]{
  --bg:#0c1524; --surface:#14213a; --surface2:#1c2c49; --surface3:#284066; --border:#243a5e; --text:#e8f0fb; --muted:#93a7c4;
  --accent:#60a5fa; --accent-hover:#93c5fd; --accent-soft:rgba(96,165,250,0.15);
  --blue:#60a5fa; --blue-soft:rgba(59,130,246,0.15); --green:#34d399; --green-soft:rgba(16,185,129,0.15); --red:#f87171; --red-soft:rgba(239,68,68,0.15);
  --amber:#fbbf24; --amber-soft:rgba(245,158,11,0.15); --teal:#2dd4bf; --teal-soft:rgba(20,184,166,0.15); --purple:#a78bfa; --purple-soft:rgba(139,92,246,0.15);
  --shadow:0 4px 6px -1px rgb(0 0 0 / 0.2), 0 2px 4px -2px rgb(0 0 0 / 0.2); --shadow-hover:0 10px 15px -3px rgb(0 0 0 / 0.3), 0 4px 6px -4px rgb(0 0 0 / 0.3);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;font-size:14px;-webkit-font-smoothing:antialiased}
i.ic{display:inline-flex;width:1em;height:1em;flex-shrink:0}i.ic svg{width:100%;height:100%}
.mono{font-family:var(--mono);font-size:12px}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100;box-shadow:var(--shadow)}
.brand{display:flex;align-items:center;gap:10px;font-size:16px;font-weight:700;color:var(--text)}
.brand i{font-size:22px;color:var(--accent)}
.topmeta{margin-left:auto;font-size:12px;color:var(--muted);text-align:right;line-height:1.4}.topmeta b{color:var(--text);font-weight:600}
.btn{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:8px;transition:all .2s ease;font-family:var(--font)}
.btn:hover{background:var(--surface2);border-color:var(--surface3)}.btn i{font-size:14px;color:var(--muted)}
.mini-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;font-weight:500;display:inline-flex;align-items:center;gap:5px;font-family:var(--font);margin-left:auto}
.mini-btn:hover{background:var(--surface3)}.mini-btn i{font-size:12px;color:var(--muted)}
.sep{width:1px;height:24px;background:var(--border)}
.wrap{max-width:1080px;margin:0 auto;padding:28px 64px 70px}
@media(max-width:760px){.wrap{padding:20px 18px}}
.section-label{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:44px 0 14px;display:flex;align-items:center;gap:8px}
.section-label:first-child{margin-top:4px}.section-label i{color:var(--accent);font-size:15px}
.section-label .cnt{font-size:11px;font-weight:700;background:var(--surface3);color:var(--muted);border-radius:999px;padding:1px 8px;letter-spacing:0}
.banner-note{font-size:12px;color:var(--muted);background:var(--surface2);border:1px dashed var(--border);border-radius:var(--radius-sm);padding:8px 12px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.banner-note i{color:var(--amber)}
/* KPI */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:44px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 14px;display:flex;align-items:center;gap:12px;box-shadow:var(--shadow);transition:box-shadow .2s ease,border-color .2s ease;position:relative}
.kpi.clickable{cursor:pointer}.kpi.clickable:hover{box-shadow:var(--shadow-hover);border-color:var(--accent-soft)}
.kpi.active{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft),var(--shadow)}
.kpi .chip{width:44px;height:44px;border-radius:var(--radius-sm);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:22px;background:var(--accent-soft);color:var(--accent)}
.kpi .body{min-width:0}
.kpi .val{font-size:26px;font-weight:800;color:var(--text);line-height:1.1;letter-spacing:-.02em}
.kpi .lbl{font-size:11.5px;color:var(--muted);font-weight:500;margin-top:4px;line-height:1.3}
.kpi .hint{font-size:11px;color:var(--accent);margin-top:4px;display:flex;align-items:center;gap:4px;font-weight:500;visibility:hidden;height:14px}
.kpi.clickable:hover .hint{visibility:visible}
.kpi.k-amber .chip{background:var(--amber-soft);color:var(--amber)}.kpi.k-amber.active{border-color:var(--amber);box-shadow:0 0 0 3px var(--amber-soft)}
.kpi.k-red .chip{background:var(--red-soft);color:var(--red)}.kpi.k-red.active{border-color:var(--red);box-shadow:0 0 0 3px var(--red-soft)}
.kpi.k-green .chip{background:var(--green-soft);color:var(--green)}.kpi.k-blue .chip{background:var(--blue-soft);color:var(--blue)}.kpi.k-teal .chip{background:var(--teal-soft);color:var(--teal)}
.filter-banner{background:var(--surface);border:1px solid var(--accent);border-radius:var(--radius);padding:16px 20px;margin-bottom:20px;box-shadow:0 0 0 3px var(--accent-soft),var(--shadow)}
.filter-banner-head{display:flex;align-items:center;gap:10px;font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text)}
.filter-banner-head i{color:var(--accent);font-size:16px}
.fb-list{display:flex;flex-direction:column;gap:6px;max-height:320px;overflow-y:auto}
.fb-row{display:flex;align-items:center;gap:12px;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;transition:all .15s}
.fb-row:hover{background:var(--surface);border-color:var(--accent)}
.fb-row .nm{flex:1;min-width:0;font-size:13px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fb-row .cx{font-size:11px;font-weight:600;color:var(--muted);background:var(--surface);border:1px solid var(--border);border-radius:999px;padding:3px 10px}
/* panels */
.layout{display:grid;grid-template-columns:340px 1fr;gap:24px}
.layout>.panel-card{height:540px;min-height:0}
.layout .item-list{max-height:none;min-height:0}
.layout .detail{min-height:0;height:100%}
.layout .item{padding:9px 12px}.layout .item-ico{width:32px;height:32px;font-size:15px}
@media(max-width:900px){.layout{grid-template-columns:1fr}.layout>.panel-card{height:auto}.layout .item-list{max-height:360px}}
.panel-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow);display:flex;flex-direction:column;margin-bottom:20px}
.panel-head{padding:16px 20px;border-bottom:1px solid var(--border);font-size:14px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:10px}
.panel-head i{color:var(--muted);font-size:16px}
.panel-head .sub{font-size:12px;color:var(--muted);font-weight:500}
.panel-body{padding:16px 20px}
.list-search{padding:12px 20px;border-bottom:1px solid var(--border)}
.list-search input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 14px;color:var(--text);font-size:13px;outline:none;font-family:var(--font)}
.list-search input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);background:var(--surface)}
.item-list{padding:10px;max-height:620px;overflow-y:auto;display:flex;flex-direction:column;gap:8px;flex:1}
.item{display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;transition:all .15s;background:var(--surface)}
.item:hover{background:var(--surface2);border-color:var(--accent-soft)}.item.sel{background:var(--accent-soft);border-color:var(--accent)}.item.hide{display:none}
.item-ico{width:38px;height:38px;border-radius:var(--radius-sm);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:17px;background:var(--accent-soft);color:var(--accent)}
.item-ico.sev-high{background:var(--red-soft);color:var(--red)}.item-ico.sev-medium{background:var(--amber-soft);color:var(--amber)}.item-ico.sev-low{background:var(--blue-soft);color:var(--blue)}.item-ico.sev-ok{background:var(--green-soft);color:var(--green)}
.item-body{flex:1;min-width:0}
.item-name{font-size:13.5px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.item-sub{font-size:11px;color:var(--muted);margin-top:2px}
.detail{flex:1;display:flex;flex-direction:column;min-height:420px}
.detail-head{padding:20px;border-bottom:1px solid var(--border)}
.detail-title{font-size:18px;font-weight:700;display:flex;align-items:center;gap:10px;word-break:break-word}
.detail-sub{font-size:12px;color:var(--muted);margin-top:6px}
.detail-body{padding:24px 20px;overflow-y:auto;flex:1}
.dsec{margin-bottom:26px}.dsec:last-child{margin-bottom:0}
.dsec-t{font-size:12px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.05em;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.dsec-t::after{content:'';flex:1;height:1px;background:var(--border);margin-left:8px}
.dsec p{font-size:13px;line-height:1.55;color:var(--text)}
.kv-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
@media(max-width:600px){.kv-grid{grid-template-columns:1fr}}
.kv{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:11px 13px}
.kv .k{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;font-weight:600}
.kv .v{font-size:14px;font-weight:600;color:var(--text);margin-top:3px;word-break:break-word}
.kv .v.good{color:var(--green)}.kv .v.bad{color:var(--red)}.kv .v.warn{color:var(--amber)}.kv .v.mut{color:var(--muted)}
.findings{display:flex;flex-direction:column;gap:8px}
.finding{display:flex;align-items:flex-start;gap:10px;padding:11px 13px;border-radius:var(--radius-sm);font-size:12.5px;line-height:1.5;border:1px solid var(--border)}
.finding i{font-size:15px;flex-shrink:0;margin-top:1px}
.finding.high{background:var(--red-soft);border-color:rgba(239,68,68,.25)}.finding.high i{color:var(--red)}
.finding.medium{background:var(--amber-soft);border-color:rgba(245,158,11,.25)}.finding.medium i{color:var(--amber)}
.finding.low{background:var(--blue-soft);border-color:rgba(59,130,246,.25)}.finding.low i{color:var(--blue)}
.finding b{display:block;font-size:13px;margin-bottom:2px}
.finding .aff{color:var(--muted);font-size:12px;margin-top:3px}
.no-findings{color:var(--green);font-size:13px;display:flex;align-items:center;gap:8px;padding:12px;background:var(--green-soft);border-radius:var(--radius-sm)}
.muted-note{color:var(--muted);font-size:13px;padding:16px;background:var(--surface2);border-radius:var(--radius-sm);border:1px dashed var(--border);text-align:center}
/* tables */
.tbl-wrap{overflow:auto;max-height:520px}
table.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{position:sticky;top:0;background:var(--surface2);text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);padding:10px 14px;border-bottom:1px solid var(--border);white-space:nowrap}
.tbl td{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:var(--surface2)}
.tbl td.num{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.tag{font-size:11px;font-weight:600;padding:2px 9px;border-radius:999px;white-space:nowrap;display:inline-block}
.tag.ok{background:var(--green-soft);color:var(--green)}.tag.warn{background:var(--amber-soft);color:var(--amber)}.tag.high{background:var(--red-soft);color:var(--red)}.tag.low{background:var(--blue-soft);color:var(--blue)}.tag.mut{background:var(--surface3);color:var(--muted)}
.dot{width:9px;height:9px;border-radius:999px;display:inline-block;flex-shrink:0}
.dot.high{background:var(--red)}.dot.medium{background:var(--amber)}.dot.low{background:var(--blue)}.dot.ok{background:var(--green)}.dot.mut{background:var(--surface3)}
.stat-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:20px}
.stat-pill{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px;text-align:center;box-shadow:var(--shadow)}
.stat-pill .v{font-size:22px;font-weight:800}.stat-pill .l{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-top:3px;font-weight:600}
.two{display:grid;grid-template-columns:1fr 1fr;gap:20px}@media(max-width:900px){.two{grid-template-columns:1fr}}
.two .panel-card{margin-bottom:0}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:999px;border:2px solid var(--surface)}
.flist{display:flex;flex-direction:column}
.frow{border-bottom:1px solid var(--border)}.frow:last-child{border-bottom:none}
.fh{display:flex;align-items:center;gap:12px;padding:11px 18px;cursor:pointer}
.fh:hover{background:var(--surface2)}
.fh .t{flex:1;min-width:0;font-size:13.5px;font-weight:600}
.fh .m{font-size:12px;color:var(--muted);white-space:nowrap}
.fh .s{font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:1px 9px;white-space:nowrap}
.fh .cv{width:12px;height:12px;color:var(--muted);transition:transform .15s}.frow.open .fh .cv{transform:rotate(90deg)}
.fb{display:none;padding:0 18px 14px 39px;font-size:13px;line-height:1.55}
.frow.open .fb{display:block}
.fb .who{color:var(--muted);font-size:12px;margin-top:6px}
.fb a{color:var(--accent);cursor:pointer;font-weight:600;font-size:12px}
.fmore{display:flex;align-items:center;justify-content:center;gap:6px;padding:10px;border-top:1px solid var(--border);font-size:12.5px;font-weight:600;color:var(--accent);cursor:pointer;background:var(--surface)}
.fmore:hover{background:var(--surface2)}
.fgroup{border-top:1px solid var(--border);background:var(--surface2)}
.fgroup .fh .t{font-weight:700;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.fgroup .flist{background:var(--surface)}
.rowhide{display:none}
.tmore{display:block;width:100%;text-align:center;padding:9px;font-size:12.5px;font-weight:600;color:var(--accent);cursor:pointer;background:var(--surface);border:none;border-top:1px solid var(--border);font-family:var(--font)}
.tmore:hover{background:var(--surface2)}
.okline{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:center;font-size:12.5px;color:var(--muted);padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:20px}
.okline b{color:var(--green);display:inline-flex;align-items:center;gap:6px}
.side{position:fixed;left:0;top:0;bottom:0;width:252px;background:linear-gradient(180deg,#1c2044 0%,#141731 100%);color:#c9cde6;display:flex;flex-direction:column;padding:22px 14px 18px;z-index:100;overflow-y:auto}
[data-theme="dark"] .side{background:linear-gradient(180deg,#0a1222 0%,#070d19 100%);border-right:1px solid var(--border)}
.sbrand{display:flex;align-items:center;gap:12px;padding:0 8px 18px;border-bottom:1px solid rgba(255,255,255,.08)}
.slogo{width:40px;height:40px;border-radius:11px;background:linear-gradient(135deg,#6366f1,#4338ca);display:flex;align-items:center;justify-content:center;color:#fff;font-size:20px;flex-shrink:0;box-shadow:0 4px 12px rgba(79,70,229,.4)}
.skick{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:#8a90b8;font-weight:700}
.stitle{font-size:14.5px;font-weight:700;color:#fff;line-height:1.25;margin-top:2px}
.smeta{font-size:11.5px;color:#8f95ba;line-height:1.45;padding:14px 8px;border-bottom:1px solid rgba(255,255,255,.08)}
.smeta div{margin-bottom:8px}.smeta div:last-child{margin-bottom:0}.smeta b{display:block;color:#e6e8f5;font-weight:600;word-break:break-all;font-size:12px}
.sdom{padding:14px 8px 4px}
.sdom label{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:#8a90b8;font-weight:700;margin-bottom:6px}
.sdom select{width:100%;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.16);color:#fff;border-radius:9px;padding:9px 10px;font-size:13px;font-weight:600;font-family:var(--font);cursor:pointer;outline:none}
.sdom select:hover{background:rgba(255,255,255,.12)}.sdom select:focus{border-color:#a5b4fc;box-shadow:0 0 0 3px rgba(99,102,241,.35)}
.sdom select option{color:#161a2e;background:#fff}
.dsub{display:block;font-size:11px;color:var(--muted);font-weight:400;margin-top:1px}
.sgroup{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:#6f76a3;font-weight:700;padding:18px 10px 8px}
#secnav a{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:9px;font-size:13px;color:#c9cde6;cursor:pointer;font-weight:500;margin-bottom:2px;text-decoration:none;transition:background .15s}
#secnav a:hover{background:rgba(255,255,255,.06);color:#fff}
#secnav a.on{background:rgba(99,102,241,.25);color:#fff;font-weight:600}
#secnav a i{font-size:15px;color:#8a90b8}#secnav a.on i{color:#a5b4fc}
#secnav a .n{margin-left:auto;font-size:10.5px;font-weight:700;padding:1px 7px;border-radius:999px;background:rgba(255,255,255,.1);color:#c9cde6}
#secnav a .n.high{background:rgba(239,68,68,.28);color:#fecaca}#secnav a .n.medium{background:rgba(245,158,11,.25);color:#fde68a}
.sfoot{margin-top:auto;padding-top:14px;border-top:1px solid rgba(255,255,255,.08)}
.sbtn{width:100%;display:flex;align-items:center;gap:9px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#e6e8f5;padding:9px 12px;border-radius:9px;font-size:12.5px;font-weight:500;cursor:pointer;font-family:var(--font)}
.sbtn:hover{background:rgba(255,255,255,.1)}
.main{margin-left:252px;padding:30px 44px 70px;max-width:1300px}
.phead{margin-bottom:28px}.phead h1{font-size:22px;font-weight:800;letter-spacing:-.02em}.psub{font-size:13px;color:var(--muted);margin-top:4px}
.anchor{scroll-margin-top:20px}
.sect{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);margin-bottom:56px;overflow:hidden}
.sect-head{display:flex;align-items:center;gap:10px;padding:14px 20px;border-bottom:1px solid var(--border);background:var(--surface2);font-size:14.5px;font-weight:700}
.sect-head>i{color:var(--accent);font-size:16px}
.sect-head .cnt{font-size:11px;font-weight:700;background:var(--surface3);color:var(--muted);border-radius:999px;padding:1px 8px}
.sect-body{padding:20px}.sect-body.flush{padding:0}
.sect .panel-card{box-shadow:none}
.sect-body>.panel-card:last-child,.sect-body>.okline:last-child,.sect-body>.no-findings:last-child{margin-bottom:0}
@media(max-width:900px){.side{position:static;width:auto;height:auto}.main{margin-left:0;padding:20px 16px}}
.evcats{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.evcat{display:inline-flex;align-items:center;gap:8px;font-family:var(--font);font-size:12.5px;font-weight:600;color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:999px;padding:7px 14px;cursor:pointer;transition:all .15s}
.evcat:hover{border-color:var(--accent-soft);background:var(--surface2)}
.evcat.on{background:var(--accent-soft);border-color:var(--accent);color:var(--accent)}
.evcat .c{font-size:11px;font-weight:700;background:var(--surface3);color:var(--muted);border-radius:999px;padding:0 7px}
.evcat.on .c{background:var(--accent);color:#fff}
.evcat.zero{color:var(--muted);opacity:.7}
.evcat .w{width:7px;height:7px;border-radius:999px;background:var(--amber)}.evcat .w.high{background:var(--red)}
.evhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.evhead .sub{font-size:12px;color:var(--muted);font-weight:500}
.evnote{font-size:12.5px;color:var(--muted);padding:12px 16px;border-bottom:1px solid var(--border);background:var(--surface2)}
.w25v{display:flex;align-items:center;gap:16px;padding:16px 18px;border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:18px;background:var(--surface2)}
.w25v .bar{width:6px;align-self:stretch;border-radius:4px}.w25v .bar.high{background:var(--red)}.w25v .bar.medium{background:var(--amber)}.w25v .bar.ok{background:var(--green)}
.w25v b{display:block;font-size:16px;margin-bottom:2px}.w25v span{font-size:13px;color:var(--muted)}
.chk{border:1px solid var(--border);border-radius:var(--radius-sm);overflow:hidden}
.chk .frow .fh{padding:11px 16px}.chk .frow .fh .res{font-size:12.5px;color:var(--muted);text-align:right;max-width:46%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chk .frow .fh .tg{width:118px;flex-shrink:0}
.chk .fb{padding:2px 16px 16px 146px}
.chk .fb .adv{font-size:13px;margin-bottom:10px}
.chk .fb .tbl-wrap{max-height:300px;border:1px solid var(--border);border-radius:var(--radius-sm)}
.chk .fb .lnote{font-size:12px;color:var(--muted);margin-top:6px}
@media(max-width:900px){.chk .fb{padding-left:16px}.chk .frow .fh .res{display:none}}
.tiss{display:flex;align-items:center;gap:7px;font-size:12.5px;white-space:nowrap;line-height:1.6}
tr.trow{cursor:pointer}tr.trow .cv{width:12px;height:12px;color:var(--muted);transition:transform .15s}tr.trow.open .cv{transform:rotate(90deg)}tr.trow.open td{background:var(--accent-soft)}
tr.tdet td{background:var(--surface)!important;padding:12px 16px 16px}
.w25hero{display:flex;gap:20px;align-items:stretch;padding:20px 22px;border-radius:var(--radius);border:1px solid var(--border);margin-bottom:22px;background:var(--surface2);flex-wrap:wrap}
.w25hero.high{background:linear-gradient(135deg,var(--red-soft),var(--surface2) 70%)}.w25hero.medium{background:linear-gradient(135deg,var(--amber-soft),var(--surface2) 70%)}.w25hero.ok{background:linear-gradient(135deg,var(--green-soft),var(--surface2) 70%)}
.w25ico{width:52px;height:52px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0;background:var(--surface)}
.w25hero.high .w25ico{color:var(--red)}.w25hero.medium .w25ico{color:var(--amber)}.w25hero.ok .w25ico{color:var(--green)}
.w25txt{flex:1;min-width:260px}.w25t{font-size:19px;font-weight:800;letter-spacing:-.02em}.w25s{font-size:13px;color:var(--muted);margin-top:3px}
.w25bar{height:8px;background:var(--surface3);border-radius:999px;margin:14px 0 10px;overflow:hidden;max-width:520px}.w25bar div{height:100%;background:var(--green);border-radius:999px}
.w25pills{display:flex;gap:16px;flex-wrap:wrap;font-size:12.5px;font-weight:600}.w25pills>span{display:inline-flex;align-items:center;gap:6px}
.w25path{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 16px;font-size:12.5px;min-width:210px}
.w25path b{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:6px}
.w25path ol{margin:0;padding-left:18px;line-height:1.75}
.w25cols{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
@media(max-width:1100px){.w25cols{grid-template-columns:1fr}}
.w25col{border:1px solid var(--border);border-radius:var(--radius-sm);overflow:hidden;background:var(--surface)}
.w25ch{display:flex;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border);background:var(--surface2)}
.w25ch b{display:block;font-size:13.5px}.w25ch span{font-size:11.5px;color:var(--muted)}
.w25ci{width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.w25ci.high{background:var(--red-soft);color:var(--red)}.w25ci.medium{background:var(--amber-soft);color:var(--amber)}.w25ci.low{background:var(--blue-soft);color:var(--blue)}.w25ci.ok{background:var(--green-soft);color:var(--green)}
.w25it{display:flex;gap:11px;align-items:flex-start;padding:11px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.w25it:last-child{border-bottom:none}.w25it:hover{background:var(--surface2)}.w25it.sel{background:var(--accent-soft);box-shadow:inset 3px 0 0 var(--accent)}
.w25st{width:20px;height:20px;border-radius:999px;display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0;margin-top:1px}
.w25st.high{background:var(--red);color:#fff}.w25st.medium{background:var(--amber);color:#fff}.w25st.low{background:var(--blue);color:#fff}.w25st.ok{background:var(--green-soft);color:var(--green)}
.w25n{font-size:13px;font-weight:600;line-height:1.35}.w25r{font-size:11.5px;color:var(--muted);margin-top:2px;line-height:1.4}
.w25det:not(:empty){margin-top:18px;border:1px solid var(--accent);border-radius:var(--radius-sm);box-shadow:0 0 0 3px var(--accent-soft);overflow:hidden}
.w25dh{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--surface2);flex-wrap:wrap}
.w25dh b{font-size:14px}.w25dh span{font-size:12.5px;color:var(--muted)}
.w25db{padding:16px}
.srclink{display:inline-flex;align-items:center;gap:6px;margin-top:14px;font-size:12.5px;font-weight:600;color:var(--accent);text-decoration:none}.srclink:hover{text-decoration:underline}
.w25note{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);margin-top:10px}
.flash{animation:flash 1.2s ease}@keyframes flash{0%{box-shadow:0 0 0 4px var(--accent-soft)}100%{box-shadow:var(--shadow)}}
.ov-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px;margin-bottom:56px}.ov-grid.two{margin-bottom:20px}.ov-grid .panel-card{margin-bottom:0}
@media(max-width:1150px){.ov-grid{grid-template-columns:1fr}}
.bars{display:flex;flex-direction:column;gap:6px}
.bar-row{display:grid;grid-template-columns:minmax(120px,40%) 1fr 56px;align-items:center;gap:10px;font-size:12.5px;padding:3px 6px;border-radius:6px}
.bar-row[onclick]{cursor:pointer}.bar-row[onclick]:hover{background:var(--surface2)}
.bar-row .bl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}
.bar-row .bt{height:9px;background:var(--surface2);border-radius:999px;overflow:hidden}
.bar-row .bf{display:block;height:100%;background:var(--accent);border-radius:999px}.bar-row .bf.red{background:var(--red)}.bar-row .bf.amber{background:var(--amber)}
.bar-row .bn{text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:14px}.tools .mini-btn{margin-left:auto}
.inp{font-family:var(--font);font-size:13px;padding:8px 11px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--text);outline:none}
.inp:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
#srvq{flex:1;min-width:220px}
.fchip{display:inline-flex;align-items:center;gap:6px;background:var(--accent-soft);color:var(--accent);border:1px solid var(--accent);border-radius:999px;padding:4px 6px 4px 12px;font-size:12px;font-weight:600}
.fchip button{border:none;background:none;color:inherit;cursor:pointer;display:inline-flex;padding:2px}
.trow{cursor:pointer}
.lnk{color:var(--accent);cursor:pointer;font-weight:600;text-decoration:none}.lnk:hover{text-decoration:underline}
.muted{color:var(--muted)}
.blade{position:fixed;top:0;right:0;bottom:0;width:min(700px,96vw);background:var(--surface);border-left:1px solid var(--border);box-shadow:-12px 0 30px rgb(0 0 0 / .18);transform:translateX(105%);transition:transform .22s ease;z-index:300;display:flex;flex-direction:column}
.blade.open{transform:none}
#bladebg{position:fixed;inset:0;background:rgb(10 15 30 / .35);opacity:0;pointer-events:none;transition:opacity .2s;z-index:290}#bladebg.open{opacity:1;pointer-events:auto}
.bl-head{display:flex;align-items:flex-start;gap:12px;padding:18px 22px;border-bottom:1px solid var(--border);background:var(--surface2)}
.bl-head>div{flex:1;min-width:0}.bl-head .mini-btn{margin-left:0}
.bl-title{font-size:18px;font-weight:800;display:flex;align-items:center;gap:10px;flex-wrap:wrap}.bl-sub{font-size:12px;color:var(--muted);margin-top:4px;word-break:break-all}
.bl-body{padding:18px 22px;overflow-y:auto;flex:1}
.kv-grid.kv3{grid-template-columns:repeat(3,1fr)}
@media(max-width:700px){.kv-grid.kv3{grid-template-columns:repeat(2,1fr)}}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip-s{font-size:12px;font-weight:600;background:var(--surface2);border:1px solid var(--border);border-radius:999px;padding:4px 10px}.chip-s.warn{background:var(--amber-soft);color:var(--amber);border-color:transparent}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:16px}
.ccard{border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);overflow:hidden}
.cc-head{display:flex;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border);background:var(--surface2)}.cc-head b{font-size:14px}
.cc-ico{width:36px;height:36px;border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;font-size:18px;background:var(--green-soft);color:var(--green);flex-shrink:0}.cc-ico.warn{background:var(--amber-soft);color:var(--amber)}.cc-ico.mut{background:var(--surface3);color:var(--muted)}
.cc-body{padding:14px 16px}
.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.stat{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;font-size:12px;color:var(--muted)}.stat b{display:block;font-size:20px;color:var(--text);font-weight:800;margin-bottom:2px}.stat b.amber{color:var(--amber)}.stat b.blue{color:var(--blue)}
.pbar{display:inline-block;width:70px;height:7px;background:var(--surface3);border-radius:999px;overflow:hidden;vertical-align:middle}.pbar .pf{display:block;height:100%;background:var(--green)}.pbar .pf.amber{background:var(--amber)}.pbar .pf.red{background:var(--red)}
.finding .aff{font-size:12px;color:var(--muted);margin-top:6px}
.dsec .tbl td,.ccard .tbl td{padding:8px 12px}
.kpi .val{white-space:nowrap}
/* version cards */
.kpi.wide{grid-column:span 2;align-items:flex-start}
@media(min-width:1000px){.main .kpi-grid{grid-template-columns:repeat(6,minmax(0,1fr))}}
.kpi .val{font-size:24px}
.vchips{display:flex;flex-wrap:wrap;gap:5px;margin-top:9px}
.vchip{font-size:11.5px;font-weight:600;padding:3px 9px;border-radius:999px;background:var(--surface2);border:1px solid var(--border);cursor:pointer;white-space:nowrap;color:var(--text)}
.vchip b{margin-left:5px;font-weight:800}.vchip:hover{border-color:var(--accent)}
.vchip.crit{background:var(--red-soft);color:var(--red);border-color:transparent}.vchip.warn{background:var(--amber-soft);color:var(--amber);border-color:transparent}.vchip.mut{color:var(--muted)}
@media(max-width:900px){.kpi.wide{grid-column:auto}}
/* whole report scaled down (set from the window width) */
body{zoom:var(--z,1)}
.side{bottom:auto!important;height:calc(100vh / var(--z,1))}
.blade{bottom:auto!important;height:calc(100vh / var(--z,1))}
#bladebg{inset:auto!important;top:0!important;left:0!important;width:calc(100vw / var(--z,1));height:calc(100vh / var(--z,1))}
.main{max-width:1560px}
.tbl-wrap.fit{max-height:520px}
#srvtbl .tbl td,#srvtbl .tbl th{padding-left:10px;padding-right:10px}#srvtbl .tbl td{font-size:13px}#srvtbl .tbl td.mono{font-size:12px}
@media(max-width:1440px){#srvtbl .tbl td:nth-child(3),#srvtbl .tbl td:nth-child(4){white-space:normal!important}#srvtbl .tbl td:nth-child(3){min-width:140px}}.kpi-grid{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.kgrp{font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:0 0 10px 2px}
#kpis .kpi-grid{margin-bottom:22px}#kpis .kpi-grid:last-child{margin-bottom:40px}
.kpi.clink{cursor:pointer}.kpi.clink:hover{box-shadow:var(--shadow-hover);border-color:var(--accent-soft)}
.tip{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;border-radius:50%;border:1px solid currentColor;color:var(--muted);opacity:.75;font:italic 700 9.5px/1 Georgia,'Times New Roman',serif;margin-left:6px;cursor:help;vertical-align:1px;flex-shrink:0;text-transform:none;letter-spacing:0}
.tip:hover,.tip:focus{opacity:1;color:var(--accent);outline:none}
.stat .tip{vertical-align:0}
#tipbox{position:fixed;z-index:9999;max-width:300px;background:#1b2238;color:#f3f6fc;font:400 12px/1.45 'Segoe UI',system-ui,-apple-system,sans-serif;padding:8px 11px;border-radius:7px;box-shadow:0 6px 20px rgba(0,0,0,.25);pointer-events:none;display:none}
.covnote{display:flex;align-items:flex-start;gap:8px;font-size:12px;color:var(--muted);margin:12px 0 0;line-height:1.45}.covnote .ic{flex-shrink:0;margin-top:1px}
.sect-body>.covnote:first-child{margin:0 0 16px}
#srvtbl td.why{color:var(--muted);font-size:12.5px;font-style:italic}
.stat b.green{color:var(--green)}
.kdelta{display:inline-block;margin-left:8px;font-size:11.5px;font-weight:700;padding:1px 7px;border-radius:999px;vertical-align:4px;letter-spacing:0}
.kdelta.good{background:var(--green-soft);color:var(--green)}.kdelta.bad{background:var(--red-soft);color:var(--red)}.kdelta.neu{background:var(--surface3);color:var(--muted)}
td .kdelta{margin-left:0;vertical-align:0}
.chglist{margin:0;padding-left:18px;font-size:13px;line-height:1.7}
</style></head><body>
<aside class="side">
  <div class="sbrand"><div class="slogo"><i class="ic" data-i="srv"></i></div><div><div class="skick">AD Audit Suite</div><div class="stitle">Server Inventory</div></div></div>
  <div class="smeta" id="topmeta"></div>
  <div class="sdom" id="sdomwrap" style="display:none"><label for="domsel">Domain</label><select id="domsel"></select></div>
  <div class="sgroup">Report</div>
  <nav id="secnav"></nav>
  <div class="sfoot"><button class="sbtn" id="themebtn"><i class="ic" data-i="moon"></i><span id="themetxt">Dark mode</span></button></div>
</aside>
<main class="main">
  <header class="phead anchor" id="sec-overview"><h1>Server Inventory</h1><div class="psub">Operating systems, lifecycle, roles, SQL Server, clusters, hardware and patching of the servers in the forest, and what blocks the ones that cannot be read</div></header>
  <div id="coverage"></div>
  <div id="kpis"></div>
  <div id="fbanner"></div>
  <div id="ovw"></div>
  <section class="sect anchor" id="sec-changes" style="display:none"><div class="sect-head"><i class="ic" data-i="refresh"></i>Changes since the last run</div><div class="sect-body" id="chgb"></div></section>
  <section class="sect anchor" id="sec-servers"><div class="sect-head"><i class="ic" data-i="srv"></i>Servers <span class="cnt" id="srvcount"></span></div><div class="sect-body"><div class="tools" id="srvtools"></div><div class="panel-card" style="margin-bottom:0" id="srvtbl"></div></div></section>
  <section class="sect anchor" id="sec-life"><div class="sect-head"><i class="ic" data-i="calendar"></i>Lifecycle</div><div class="sect-body" id="lifeb"></div></section>
  <section class="sect anchor" id="sec-sql"><div class="sect-head"><i class="ic" data-i="db"></i>SQL Server</div><div class="sect-body" id="sqlb"></div></section>
  <section class="sect anchor" id="sec-clusters"><div class="sect-head"><i class="ic" data-i="cluster"></i>Failover clusters</div><div class="sect-body" id="clb"></div></section>
  <section class="sect anchor" id="sec-access"><div class="sect-head"><i class="ic" data-i="lock"></i>Management access</div><div class="sect-body" id="accb"></div></section>
  <section class="sect anchor" id="sec-patch"><div class="sect-head"><i class="ic" data-i="refresh"></i>Updates &amp; restart</div><div class="sect-body" id="patchb"></div></section>
  <section class="sect anchor" id="sec-svc"><div class="sect-head"><i class="ic" data-i="people"></i>Service accounts</div><div class="sect-body" id="svcb"></div></section>
  <section class="sect anchor" id="sec-ext"><div class="sect-head"><i class="ic" data-i="checklist"></i>Windows activation</div><div class="sect-body" id="extb"></div></section>
</main>
<div id="bladebg"></div><aside id="blade" class="blade"></aside>
<script>
(function(){function z(){var w=window.innerWidth||1920;document.documentElement.style.setProperty('--z',w<1500?0.72:(w<1900?0.8:0.88));}z();window.addEventListener('resize',z);})();
var D = $DataJSON;
function arr(x){if(x==null)return[];if(!Array.isArray(x))return[x];while(x.length===1&&Array.isArray(x[0]))x=x[0];return x;}
function esc(s){s=(s==null?'':''+s);return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function qs(s){return document.querySelector(s);}
function plural(n,w){return n+' '+w+(n===1?'':'s');}
var P='<svg viewBox="0 0 16 16" fill="currentColor">';
var ICONS={
 octagon:P+'<path d="M11.46.146A.5.5 0 0 0 11.107 0H4.893a.5.5 0 0 0-.353.146L.146 4.54A.5.5 0 0 0 0 4.893v6.214a.5.5 0 0 0 .146.353l4.394 4.394a.5.5 0 0 0 .353.146h6.214a.5.5 0 0 0 .353-.146l4.394-4.394a.5.5 0 0 0 .146-.353V4.893a.5.5 0 0 0-.146-.353zM8 4c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 4.995A.905.905 0 0 1 8 4m.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2"/></svg>',
 bulb:P+'<path d="M2 6a6 6 0 1 1 10.174 4.31c-.203.196-.359.4-.453.619l-.762 1.769A.5.5 0 0 1 10.5 13a.5.5 0 0 1 0 1 .5.5 0 0 1 0 1l-.224.447a1 1 0 0 1-.894.553H6.618a1 1 0 0 1-.894-.553L5.5 15a.5.5 0 0 1 0-1 .5.5 0 0 1 0-1 .5.5 0 0 1-.46-.302l-.761-1.77a2 2 0 0 0-.453-.618A5.98 5.98 0 0 1 2 6m6-5a5 5 0 0 0-3.479 8.592c.263.254.514.564.676.941L5.83 12h4.342l.632-1.467c.162-.377.413-.687.676-.941A5 5 0 0 0 8 1"/></svg>',
 checklist:P+'<path d="M14.5 3a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5zm-13-1A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2z"/><path d="M7 5.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m-1.496-.854a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 1 1 .708-.708l.146.147 1.146-1.147a.5.5 0 0 1 .708 0M7 9.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m-1.496-.854a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 0 1 .708-.708l.146.147 1.146-1.147a.5.5 0 0 1 .708 0"/></svg>',
 key:P+'<path d="M3.5 11.5a3.5 3.5 0 1 1 3.163-5H14L15.5 8 14 9.5l-1-1-1 1-1-1-1 1-1-1-1 1H6.663a3.5 3.5 0 0 1-3.163 2M2.5 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2"/></svg>',
 moon:P+'<path d="M6 .278a.77.77 0 0 1 .08.858 7.2 7.2 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277q.792-.001 1.533-.16a.79.79 0 0 1 .81.316.73.73 0 0 1-.031.893A8.35 8.35 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.75.75 0 0 1 6 .278"/></svg>',
 sun:P+'<path d="M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8M8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0m0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13m8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5M3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8"/></svg>',
 alert:P+'<path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5m.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2"/></svg>',
 info:P+'<path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16m.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2"/></svg>',
 check:P+'<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0m-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>',
 shield:P+'<path d="M5.338 1.59a61 61 0 0 0-2.837.856.48.48 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.7 10.7 0 0 0 2.287 2.233c.346.244.652.42.893.533q.18.085.293.118a1 1 0 0 0 .101.025 1 1 0 0 0 .1-.025q.114-.034.294-.118c.24-.113.547-.29.893-.533a10.7 10.7 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.8 11.8 0 0 1-2.517 2.453 7 7 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7 7 0 0 1-1.048-.625 11.8 11.8 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 63 63 0 0 1 5.072.56"/></svg>',
 server:P+'<path d="M1.333 2.667C1.333 1.194 4.318 0 8 0s6.667 1.194 6.667 2.667V4c0 1.473-2.985 2.667-6.667 2.667S1.333 5.473 1.333 4z"/><path d="M1.333 6.334v3C1.333 10.805 4.318 12 8 12s6.667-1.194 6.667-2.667V6.334a6.5 6.5 0 0 1-1.458.79C11.81 7.684 9.967 8 8 8s-3.809-.317-5.208-.876a6.5 6.5 0 0 1-1.458-.79z"/><path d="M14.667 11.668a6.5 6.5 0 0 1-1.458.789c-1.4.56-3.242.876-5.21.876-1.966 0-3.809-.316-5.208-.876a6.5 6.5 0 0 1-1.458-.79v1.666C1.333 14.806 4.318 16 8 16s6.667-1.194 6.667-2.667z"/></svg>',
 list:P+'<path fill-rule="evenodd" d="M5 11.5a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5m0-4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5m0-4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5m-3 1a1 1 0 1 0 0-2 1 1 0 0 0 0 2m0 4a1 1 0 1 0 0-2 1 1 0 0 0 0 2m0 4a1 1 0 1 0 0-2 1 1 0 0 0 0 2"/></svg>',
 journal:P+'<path d="M3 0h10a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2v-1h1v1a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H3a1 1 0 0 0-1 1v1H1V2a2 2 0 0 1 2-2"/><path d="M1 5v-.5a.5.5 0 0 1 1 0V5h.5a.5.5 0 0 1 0 1h-2a.5.5 0 0 1 0-1zm0 3v-.5a.5.5 0 0 1 1 0V8h.5a.5.5 0 0 1 0 1h-2a.5.5 0 0 1 0-1zm0 3v-.5a.5.5 0 0 1 1 0v.5h.5a.5.5 0 0 1 0 1h-2a.5.5 0 0 1 0-1z"/></svg>',
 clock:P+'<path d="M8 3.5a.5.5 0 0 0-1 0V9a.5.5 0 0 0 .252.434l3.5 2a.5.5 0 0 0 .496-.868L8 8.71z"/><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16m7-8A7 7 0 1 1 1 8a7 7 0 0 1 14 0"/></svg>',
 archive:P+'<path d="M0 2a1 1 0 0 1 1-1h14a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1v7.5a2.5 2.5 0 0 1-2.5 2.5h-9A2.5 2.5 0 0 1 1 12.5V5a1 1 0 0 1-1-1zm2 3v7.5A1.5 1.5 0 0 0 3.5 14h9a1.5 1.5 0 0 0 1.5-1.5V5zm13-3H1v2h14zM5 7.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5"/></svg>',
 download:P+'<path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5"/><path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708z"/></svg>',
 lock:P+'<path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2m3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2"/></svg>',
 x:P+'<path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8z"/></svg>',
 up:P+'<path d="M16 8A8 8 0 1 0 0 8a8 8 0 0 0 16 0m-7.5 3.5a.5.5 0 0 1-1 0V5.707L5.354 7.854a.5.5 0 1 1-.708-.708l3-3a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1-.708.708L8.5 5.707z"/></svg>',
 people:P+'<path d="M7 14s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1zm4-6a3 3 0 1 0 0-6 3 3 0 0 0 0 6m-5.784 6A2.24 2.24 0 0 1 5 13c0-1.355.68-2.75 1.936-3.72A6.3 6.3 0 0 0 5 9c-4 0-5 3-5 4s1 1 1 1zM4.5 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5"/></svg>',
 srv:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><rect x="1.8" y="1.8" width="12.4" height="5.2" rx="1.2"/><rect x="1.8" y="9" width="12.4" height="5.2" rx="1.2"/><path d="M4.4 4.4h.01M4.4 11.6h.01M7.2 4.4h4.4M7.2 11.6h4.4"/></svg>',
 layers:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1.8 1.6 5 8 8.2 14.4 5z"/><path d="M1.6 8 8 11.2 14.4 8"/><path d="M1.6 11 8 14.2 14.4 11"/></svg>',
 cpu:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="8" height="8" rx="1.2"/><rect x="6.3" y="6.3" width="3.4" height="3.4" rx=".4"/><path d="M6 1.6v2.2M10 1.6v2.2M6 12.2v2.2M10 12.2v2.2M1.6 6h2.2M1.6 10h2.2M12.2 6h2.2M12.2 10h2.2"/></svg>',
 db:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="8" cy="3.6" rx="5.4" ry="2"/><path d="M2.6 3.6v8.8c0 1.1 2.4 2 5.4 2s5.4-.9 5.4-2V3.6"/><path d="M2.6 8c0 1.1 2.4 2 5.4 2s5.4-.9 5.4-2"/></svg>',
 cluster:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><rect x="5.6" y="1.4" width="4.8" height="3.6" rx=".8"/><rect x="1.2" y="11" width="4.8" height="3.6" rx=".8"/><rect x="10" y="11" width="4.8" height="3.6" rx=".8"/><path d="M8 5v3M3.6 11V8h8.8v3"/></svg>',
 calendar:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><rect x="1.8" y="2.8" width="12.4" height="11.4" rx="1.4"/><path d="M1.8 6.4h12.4M5 1.4v2.8M11 1.4v2.8"/></svg>',
 search:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="7" cy="7" r="4.6"/><path d="m10.4 10.4 3.8 3.8"/></svg>',
 refresh:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M13.6 8A5.6 5.6 0 1 1 11.8 3.8"/><path d="M13.8 1.6v3.2h-3.2"/></svg>',
 hdd:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><rect x="1.6" y="8.4" width="12.8" height="5.2" rx="1.2"/><path d="M3.2 8.4 5 2.6h6l1.8 5.8"/><path d="M11.4 11h.01"/></svg>',
 trash:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M2.4 4h11.2M6.2 4V2.4h3.6V4M3.8 4l.7 9.6c0 .5.4.9.9.9h5.2c.5 0 .9-.4.9-.9L12.2 4"/><path d="M6.6 6.6v5M9.4 6.6v5"/></svg>'
};
function ic(n){return '<i class="ic">'+(ICONS[n]||'')+'</i>';}
function paintIcons(root){Array.prototype.forEach.call((root||document).querySelectorAll('i.ic[data-i]'),function(e){e.innerHTML=ICONS[e.getAttribute('data-i')]||'';e.removeAttribute('data-i');});}
var SEVMAP={crit:'high',warn:'medium',info:'low',ok:'ok'};
var SEVWORD={crit:'Critical',warn:'Warning',info:'Recommendation',ok:'OK'};
var RANK={crit:3,warn:2,info:1,ok:0,'':-1};
function worstOf(l){var w='';l.forEach(function(s){if(s&&RANK[s]>RANK[w])w=s;});return w;}
function tag(sev,txt){return '<span class="tag '+(sev==='crit'?'high':(sev==='warn'?'warn':(sev==='info'?'low':(sev==='ok'?'ok':'mut'))))+'">'+esc(txt)+'</span>';}
function dl(name,rows){var csv='\ufeff'+rows.map(function(r){return r.map(function(c){c=(c==null?'':''+c);return '"'+c.replace(/"/g,'""')+'"';}).join(',');}).join('\r\n');var b=new Blob([csv],{type:'text/csv'});var u=URL.createObjectURL(b);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(u);}


/* ---------------- domain selector: the report is rebuilt for one domain, without reloading the page ---------------- */
var D0=D, DOMS=arr(D0.domains);
function viewFor(sel){var X=JSON.parse(JSON.stringify(D0));if(!sel||DOMS.indexOf(sel)<0)return X;
  var lc=sel.toLowerCase();function inD(x){return !!x&&(''+(x.domain||'')).toLowerCase()===lc;}
  X.view=sel;X.servers=arr(X.servers).filter(inD);X.clusters=arr(X.clusters).filter(inD);X.sql=arr(X.sql).filter(inD);X.notes=[];
  if(X.prevRun){X.prevRun.servers=arr(X.prevRun.servers).filter(inD);X.prevRun.sql=arr(X.prevRun.sql).filter(inD);X.prevRun.clusters=arr(X.prevRun.clusters).filter(inD);}return X;}
</script>
<script type="text/plain" id="app">
var SV=arr(D.servers), CL=arr(D.clusters), SQ=arr(D.sql), P=D.params||{};
SV.forEach(function(s,i){s._i=i;});
var MULTI=DOMS.length>1, SHOWDOM=MULTI&&!D.view;
function domSub(x){return SHOWDOM&&x.domain?'<span class="dsub">'+esc(x.domain)+'</span>':'';}
var GEN=parseD(D.generated)||new Date();
function parseD(s){var m=/^(\d{4})-(\d{2})-(\d{2})(?: (\d{2}):(\d{2}))?/.exec(s||'');return m?new Date(+m[1],+m[2]-1,+m[3],+(m[4]||0),+(m[5]||0)):null;}
function daysTo(s){var d=parseD(s);return d?Math.round((d-GEN)/864e5):null;}
function num(x){var n=+x;return isFinite(n)?n:0;}
function fmt(n){return num(n).toLocaleString('en-US');}
qs('#topmeta').innerHTML=(SHOWDOM?'<div>Forest<b>'+esc(D.forest)+'</b></div><div>Domains<b>'+DOMS.length+'</b></div>':'<div>Domain<b>'+esc(D.view||(DOMS[0]||D.domain))+'</b></div>')+'<div>Generated<b>'+esc(D.generated)+'</b></div>'+(P.searchBase?'<div>Scope<b>'+esc(P.searchBase)+'</b></div>':'');
qs('#themebtn').onclick=function(){var d=document.documentElement.getAttribute('data-theme')==='dark';document.documentElement.setAttribute('data-theme',d?'light':'dark');qs('#themetxt').textContent=d?'Dark mode':'Light mode';qs('#themebtn i').innerHTML=ICONS[d?'moon':'sun'];};

/* ---------------- lifecycle (Microsoft lifecycle dates, end of extended support) ---------------- */
var LCU='https://learn.microsoft.com/lifecycle/products/';
var LOS=[[26100,'Windows Server 2025','2034-11-14','windows-server-2025',/2025/],[20348,'Windows Server 2022','2031-10-14','windows-server-2022',/2022/],[17763,'Windows Server 2019','2029-01-09','windows-server-2019',/2019/],
 [14393,'Windows Server 2016','2027-01-12','windows-server-2016',/2016/],[9600,'Windows Server 2012 R2','2023-10-10','windows-server-2012-r2',/2012 R2/],[9200,'Windows Server 2012','2023-10-10','windows-server-2012',/2012/],
 [7601,'Windows Server 2008 R2','2020-01-14','windows-server-2008-r2',/2008 R2/],[7600,'Windows Server 2008 R2','2020-01-14','windows-server-2008-r2',null],[6003,'Windows Server 2008','2020-01-14','windows-server-2008',/2008/],[6002,'Windows Server 2008','2020-01-14','windows-server-2008',null],[6001,'Windows Server 2008','2020-01-14','windows-server-2008',null],[3790,'Windows Server 2003','2015-07-14','windows-server-2003',/2003/]];
var LSQL={'17':['SQL Server 2025','2036-01-06','sql-server-2025'],'16':['SQL Server 2022','2033-01-11','sql-server-2022'],'15':['SQL Server 2019','2030-01-08','sql-server-2019'],'14':['SQL Server 2017','2027-10-12','sql-server-2017'],
 '13':['SQL Server 2016','2026-07-14','sql-server-2016'],'12':['SQL Server 2014','2024-07-09','sql-server-2014'],'11':['SQL Server 2012','2022-07-12','sql-server-2012'],'10.5':['SQL Server 2008 R2','2019-07-09','sql-server-2008-r2'],'10':['SQL Server 2008','2019-07-09','sql-server-2008']};
function lifeOf(name,end,slug){var d=daysTo(end);return {name:name,end:end,url:LCU+slug,days:d,sev:d<0?'crit':(d<=365?'warn':'ok')};}
function osLife(s){if(!s.isWin)return null;var b=num(s.build)||num(s.buildAd),i,o=s.os||s.osAd||'';
  for(i=0;i<LOS.length;i++)if(b&&LOS[i][0]===b)return lifeOf(LOS[i][1],LOS[i][2],LOS[i][3]);
  if(!b)for(i=0;i<LOS.length;i++)if(LOS[i][4]&&LOS[i][4].test(o))return lifeOf(LOS[i][1],LOS[i][2],LOS[i][3]);
  return null;}
/* Features Windows installs on every server: left out of the roles chart, still listed in the server details */
var DEFFEAT=/^(File and Storage Services|Storage Services|Windows PowerShell|WoW64 Support|Remote Differential Compression|System Data Archiver|XPS Viewer|\.NET Framework [34]\.\d+( Features)?|(Windows|Microsoft) Defender( Antivirus| Features)?|SMB 1\.0\/CIFS File Sharing Support|SMB Bandwidth Limit|User Interfaces and Infrastructure|Azure Arc Setup|Remote Server Administration Tools|Group Policy Management|Windows Internal Database|Wireless LAN Service|Windows Biometric Framework|Quality Windows Audio Video Experience|Ink and Handwriting Services|Media Foundation|Windows Search Service|TFTP Client|Telnet Client|Simple TCP\/IP Services)$/;
function isRole(n){return !DEFFEAT.test(n)||n==='Windows Internal Database';}
function realRoles(s){return arr(s.adRoles).concat(arr(s.features).filter(function(x){return isRole(x)&&arr(s.adRoles).indexOf(x)<0;}));}
/* Base builds of each SQL Server version and service pack: an instance still on one of them has no update installed */
var SQLBASE={'17':['1000'],'16':['1000'],'15':['2000'],'14':['1000'],'13':['1601','4001','5026','6300'],'12':['2000','4100','5000','6024'],'11':['2100','3000','5058','6020','7001'],'10':['1600','2531','4000','5500','6000','1600','2500','4000','6000']};
function sqlNoUpd(v){var m=/^(\d+)\.\d+\.(\d+)\./.exec(v||'');return !!(m&&SQLBASE[m[1]]&&SQLBASE[m[1]].indexOf(m[2])>=0);}
function osName(s){var L=osLife(s);return L?L.name:(s.os||s.osAd||'Unknown');}
function sqlLife(v){var m=/^(\d+)\.(\d+)/.exec(v||'');if(!m)return null;var k=(m[1]==='10'&&+m[2]>=50)?'10.5':m[1];var L=LSQL[k];return L?lifeOf(L[0],L[1],L[2]):null;}
function gbTxt(g){g=num(g);return g>=1024?fmt(Math.round(g/1024*10)/10)+' TB':fmt(Math.round(g))+' GB';}
function tip(t){return '<span class="tip" tabindex="0" data-tip="'+esc(t)+'">i</span>';}
function covNote(what){var n=SV.filter(function(s){return s.status==='ok';}).length,c=SV.filter(contacted).length;
  return '<div class="covnote">'+ic('info')+'<span>'+(what?what+' ':'')+'Based on the '+plural(n,'server')+' that could be read'+(c>n?', out of '+fmt(c)+' contacted. <a class="lnk" onclick="jump(\'access\')">Why not the others</a>':'.')+'</span></div>';}
function fitRows(w,n){var t=w.querySelector('table');if(!t)return;var R=t.rows;if(R.length<=n+1){w.style.maxHeight='none';return;}var h=0;for(var i=0;i<=n;i++)h+=R[i].offsetHeight;if(h>0)w.style.maxHeight=(h+1)+'px';}
function fitAll(root){Array.prototype.forEach.call((root||document).querySelectorAll('.tbl-wrap.fit'),function(w){fitRows(w,w.classList.contains('fit10')?10:20);});}
function lifeTag(L){if(!L)return '';return L.sev==='crit'?tag('crit','Out of support'):(L.sev==='warn'?tag('warn','Ends '+L.end):tag('ok','Supported'));}

/* ---------------- statuses ---------------- */
var STAT={ok:['ok','Read'],unreachable:['warn','Unreachable'],denied:['warn','Access denied'],timeout:['warn','Timed out'],error:['warn','Error'],stale:['mut','Stale in AD'],disabled:['mut','Disabled'],nonwin:['mut','Not Windows'],skipped:['mut','AD only']};
function stTag(s){var x=STAT[s.status]||['mut',s.status||'-'];return tag(x[0]==='warn'?'warn':x[0],x[1]);}
function contacted(s){return ['ok','unreachable','denied','timeout','error'].indexOf(s.status)>=0;}
var WHY={dns:'Name not in DNS',blocked:'RPC and WinRM blocked from the audit host',noanswer:'No answer from the audit host',rpcdyn:'Dynamic RPC ports blocked',wmi:'WMI did not answer',denied:'Access denied (not local admin)',timeout:'Timed out'};
function whyNot(s){if(s.status==='ok')return '';if(s.status==='stale')return 'Not contacted: inactive in AD for more than '+num(P.staleDays)+' days';if(s.status==='disabled')return 'Not contacted: disabled in AD';if(s.status==='nonwin')return 'Not Windows: AD data only';if(s.status==='skipped')return 'AD data only (-SkipRemote)';return WHY[s.access]||s.statusText||'Not read';}

/* ---------------- findings per server ---------------- */
var CAT={life:'Lifecycle',patch:'Updates & restart',dns:'DNS',site:'AD sites',access:'Management access',act:'Activation'};
var CATSEC={life:'life',patch:'patch',dns:'servers',site:'servers',access:'access',act:'ext'};
function srvF(s){if(s._f)return s._f;var f=[],pd=num(P.patchDays)||60;
  function add(cat,sev,t,d){f.push({cat:cat,sev:sev,t:t,d:d||''});}
  var L=osLife(s);if(L&&L.sev!=='ok'&&s.status!=='disabled')add('life',L.sev,L.days<0?'Windows Server version out of support':'Windows Server support ends within a year',L.name+(L.days<0?' - support ended ':' - support ends ')+L.end);
  arr(s.sql).forEach(function(i){if(sqlNoUpd(i.version))add('patch','info','SQL Server without any update',i.instance+': '+i.version+' is the release or service pack build, with no cumulative or security update installed');});
  arr(s.sql).forEach(function(i){var Q=sqlLife(i.version);if(Q&&Q.sev!=='ok')add('life',Q.sev,Q.days<0?'SQL Server version out of support':'SQL Server support ends within a year',i.instance+': '+Q.name+(Q.days<0?' - support ended ':' - support ends ')+Q.end);});
  if(s.status==='ok'){
    if(s.patchDays!=null&&s.patchDays>pd)add('patch',s.patchDays>pd*2?'crit':'warn','No update installed in the last '+pd+' days','Last update '+s.lastUpdate+(s.lastUpdateKb?' ('+s.lastUpdateKb+')':'')+', '+s.patchDays+' days ago');
    if(s.uptimeDays!=null&&s.uptimeDays>pd)add('patch','warn','Not restarted in the last '+pd+' days','Last boot '+s.lastBoot+', '+s.uptimeDays+' days ago');
    if(s.pending)add('patch','info','Restart pending',arr(s.pendingWhy).join(', '));
    if(s.dnsState==='mismatch')add('dns','warn','DNS record does not match the server IP','DNS: '+arr(s.dnsIps).join(', ')+' - server: '+arr(s.ips).join(', '));
    if(s.dnsState==='missing')add('dns','warn','No DNS record','The server name does not resolve from the audit host.');
    if(s.dnsState==='partial')add('dns','info','Extra DNS records','DNS also returns '+arr(s.dnsIps).filter(function(x){return arr(s.ips).indexOf(x)<0;}).join(', ')+', not configured on the server.');
    if(s.act&&s.act.ok===false)add('act','warn','Windows not activated',s.act.status+(s.act.channel?' ('+s.act.channel+')':''));
  }
  if(!s.site&&(arr(s.ips).length||arr(s.dnsIps).length)&&s.status!=='disabled')add('site','info','IP address not in any AD subnet',(arr(s.ips)[0]||arr(s.dnsIps)[0])+' does not match an AD subnet, so the server cannot find the closest domain controller by site.');
  if(['unreachable','denied','timeout','error'].indexOf(s.status)>=0)add('access','info','Could not be read from the audit host',whyNot(s));
  s._f=f;return f;}
var ADV={'Windows Server version out of support':'Plan the upgrade or migration of these servers. They no longer receive security updates unless they are enrolled in Extended Security Updates.',
 'Windows Server support ends within a year':'Plan the upgrade or migration before the end of support date.',
 'SQL Server version out of support':'Upgrade these instances to a supported SQL Server version, or enrol them in Extended Security Updates.',
 'SQL Server support ends within a year':'Plan the SQL Server upgrade before the end of support date.',
 'Restart pending':'Restart these servers in the next maintenance window so installed updates take effect.',
 'SQL Server without any update':'Install the latest cumulative update for that SQL Server version (or at least the latest security update).',
 'DNS record does not match the server IP':'Update or remove the stale DNS record so clients reach the right server.','No DNS record':'Register the server in DNS (check dynamic DNS registration on its network adapter).',
 'Extra DNS records':'Remove the DNS records that point to addresses the server no longer uses.','IP address not in any AD subnet':'Add the missing subnets in AD Sites and Services and link them to the right site.',
 'Could not be read from the audit host':'See Management access: it shows, per subnet, what blocks these servers and what to open.',
 'Windows not activated':'Activate Windows on these servers (KMS host reachable, or a valid product key).'};
function advFor(f){if(f.t.indexOf('Not restarted in the last')===0)return 'Restart these servers in the next maintenance window: updates installed since the last boot only take effect after a restart.';if(f.t.indexOf('No update installed')===0)return 'Install the latest cumulative update on these servers and check that patching runs on them.';return ADV[f.t]||'';}
var FL={};SV.forEach(function(s){srvF(s).forEach(function(f){var k=f.t;if(!FL[k])FL[k]={t:f.t,cat:f.cat,sev:f.sev,srv:[]};if(RANK[f.sev]>RANK[FL[k].sev])FL[k].sev=f.sev;if(FL[k].srv.indexOf(s)<0)FL[k].srv.push(s);});});
var FLL=Object.keys(FL).map(function(k){return FL[k];}).sort(function(a,b){return (RANK[b.sev]-RANK[a.sev])||(b.srv.length-a.srv.length);});

/* ---------------- changes since the last run (-CompareWith) ---------------- */
var PR=D.prevRun||null, CHG=null;
function skey(s){return (''+(s.fqdn||((s.name||'')+'.'+(s.domain||'')))).toLowerCase();}
function bld(s){return num(s.build)||num(s.buildAd);}
function osShort(s){var L=osLife(s);return L?L.name:(s.os||s.osAd||'Unknown');}
if(PR){(function(){
  var pv=arr(PR.servers),PM={},CM={},C={rows:[],per:{},n:{added:0,removed:0,nowRead:0,lostRead:0,os:0,updated:0,inactive:0,notUpd:0,sqlAdd:0,sqlDel:0},PF:{},pk:{}};
  pv.forEach(function(s){PM[skey(s)]=s;});SV.forEach(function(s){CM[skey(s)]=s;});
  function row(k,lbl,s,d,cur){C.n[k]++;C.rows.push({k:k,lbl:lbl,s:s,d:d||'',cur:cur});if(cur){var q=skey(s);(C.per[q]=C.per[q]||[]).push(lbl+(d?': '+d:''));}}
  var pd=num(P.patchDays)||60, INA=['stale','disabled'];
  SV.forEach(function(s){var p=PM[skey(s)];
    if(!p){row('added','New in AD',s,osShort(s),1);return;}
    if(INA.indexOf(s.status)>=0&&INA.indexOf(p.status)<0){row('inactive',s.status==='disabled'?'Disabled in AD':'Became stale in AD',s,s.status==='stale'?(s.lastActiveDays==null?'Never active':'No activity for '+s.lastActiveDays+' days'):'',1);return;}
    if(s.status==='ok'&&p.status!=='ok')row('nowRead','Read now, not before',s,'Before: '+(whyNot(p)||p.status),1);
    else if(p.status==='ok'&&contacted(s)&&s.status!=='ok')row('lostRead','Read before, not now',s,whyNot(s),1);
    if(s.isWin&&bld(s)&&bld(p)&&bld(s)!==bld(p))row('os','Windows version changed',s,osShort(p)+' to '+osShort(s),1);
    if(s.status==='ok'&&p.status==='ok'&&s.lastUpdate&&p.lastUpdate){
      if(s.lastUpdate>p.lastUpdate)row('updated','Updated since',s,p.lastUpdate+' to '+s.lastUpdate+(s.lastUpdateKb?' ('+s.lastUpdateKb+')':''),1);
      else if(s.patchDays>pd)C.n.notUpd++;}
  });
  pv.forEach(function(p){if(!CM[skey(p)])row('removed','No longer in AD',p,osShort(p),0);});
  function qk(i){return (''+(i.fqdn||i.server)+'|'+(i.instance||'')).toLowerCase();}
  var PQ={},CQ={};arr(PR.sql).forEach(function(i){PQ[qk(i)]=i;});SQ.forEach(function(i){CQ[qk(i)]=i;});
  function qs2(i,list){for(var k=0;k<list.length;k++)if(skey(list[k])===(''+(i.fqdn||'')).toLowerCase())return list[k];return {name:i.server,domain:i.domain,fqdn:i.fqdn};}
  SQ.forEach(function(i){if(!PQ[qk(i)]){var s=qs2(i,SV);row('sqlAdd','SQL Server instance added',s,(i.instance||'')+(i.version?' ('+(sqlLife(i.version)?sqlLife(i.version).name:i.version)+')':''),!!CM[skey(s)]);}});
  arr(PR.sql).forEach(function(i){if(!CQ[qk(i)]){var s=qs2(i,SV);row('sqlDel','SQL Server instance removed',s,i.instance||'',!!CM[skey(s)]);}});
  // findings of the earlier run, as of its own date and settings
  var G0=GEN,P0=P;GEN=parseD(PR.generated)||GEN;P=PR.params||P;
  try{pv.forEach(function(p){var seen={};delete p._f;srvF(p).forEach(function(f){if(seen[f.t])return;seen[f.t]=1;var e=C.PF[f.t]=C.PF[f.t]||{t:f.t,sev:f.sev,cat:f.cat,n:0};e.n++;if(RANK[f.sev]>RANK[e.sev])e.sev=f.sev;});});
    var pOK=pv.filter(function(s){return s.status==='ok';});
    C.pk={srv:pv.length,sql:arr(PR.sql).length,cl:arr(PR.clusters).length,eos:pv.filter(function(s){var L=s.status!=='disabled'&&osLife(s);return !!L&&L.sev==='crit';}).length,
      read:pOK.length,nr:pv.filter(function(s){return contacted(s)&&s.status!=='ok';}).length,cores:pOK.reduce(function(a,s){return a+num(s.cores);},0),mem:pOK.reduce(function(a,s){return a+num(s.ramGB);},0)};}
  finally{GEN=G0;P=P0;}
  C.days=Math.round((GEN-(parseD(PR.generated)||GEN))/864e5);
  CHG=C;})();}
function dlt(v,good,fmtf){if(!CHG||v==null||!isFinite(v)||Math.abs(v)<0.5)return '';var c=good===0?'neu':((v>0)===(good>0)?'good':'bad');
  return '<span class="kdelta '+c+'" title="Change since the last run ('+esc(PR.generated.slice(0,10))+')">'+(v>0?'+':'&minus;')+(fmtf?fmtf(Math.abs(v)):fmt(Math.abs(v)))+'</span>';}

/* ---------------- KPIs ---------------- */
var OK=SV.filter(function(s){return s.status==='ok';}), CT=SV.filter(contacted);
var phys=OK.filter(function(s){return s.platform==='Physical';}).length, virt=OK.filter(function(s){return s.platform==='Virtual';}).length;
var cores=OK.reduce(function(a,s){return a+num(s.cores);},0), mem=OK.reduce(function(a,s){return a+num(s.ramGB);},0);
var NR=CT.filter(function(s){return s.status!=='ok';}), STL=SV.filter(function(s){return s.status==='stale'||s.status==='disabled';});
var nC=FLL.filter(function(f){return f.sev==='crit';}), nW=FLL.filter(function(f){return f.sev==='warn';});
function osChips(){var m={},o=[];SV.forEach(function(s){if(s.status==='disabled')return;var k;if(!s.isWin)k='Other OS';else{var L=osLife(s);k=L?L.name:'Other Windows';}if(!m[k]){m[k]={n:0,L:s.isWin?osLife(s):null};o.push(k);}m[k].n++;});
  o.sort(function(a,b){function ix(k){for(var i=0;i<LOS.length;i++)if(LOS[i][1]===k)return i;return 99;}return ix(a)-ix(b);});
  return '<div class="vchips">'+o.map(function(k){var L=m[k].L,c=L?(L.sev==='crit'?'crit':(L.sev==='warn'?'warn':'')):'mut';var lb=k.replace('Windows Server ','');
    var f=k==='Other OS'?'srvFilter({st:\'nonwin\'})':(L?'srvFilter({os:\''+k+'\'})':'jump(\'servers\')');
    return '<span class="vchip '+c+'" title="'+esc(k)+(L?' - support ends '+L.end:'')+'" onclick="event.stopPropagation();'+f+'">'+esc(lb)+'<b>'+fmt(m[k].n)+'</b></span>';}).join('')+'</div>';}
function sqlChips(){var m={},o=[],ad=0;SQ.forEach(function(i){if(i.source!=='inventory'){ad++;return;}var Q=sqlLife(i.version),k=Q?Q.name:'Unknown';if(!m[k]){m[k]={n:0,Q:Q};o.push(k);}m[k].n++;});
  o.sort(function(a,b){return (+(b.replace(/\D/g,'').slice(0,4))||0)-(+(a.replace(/\D/g,'').slice(0,4))||0);});
  return '<div class="vchips">'+o.map(function(k){var Q=m[k].Q,c=Q?(Q.sev==='crit'?'crit':(Q.sev==='warn'?'warn':'')):'mut';
    return '<span class="vchip '+c+'" title="'+esc(k)+(Q?' - support ends '+Q.end:'')+'" onclick="event.stopPropagation();jump(\'sql\')">'+esc(k.replace('SQL Server ',''))+'<b>'+fmt(m[k].n)+'</b></span>';}).join('')+
    (ad?'<span class="vchip mut" title="MSSQLSvc names in AD whose host could not be read" onclick="event.stopPropagation();jump(\'sql\')">Found in AD only<b>'+fmt(ad)+'</b></span>':'')+'</div>';}
var NF=nC.concat(nW), EOS=SV.filter(function(s){var L=s.status!=='disabled'&&osLife(s);return !!L&&L.sev==='crit';});
var KPIS=[
 {k:'srv',g:1,wide:1,icon:'srv',cls:'k-blue',val:fmt(SV.length),lbl:'Servers in AD',chips:osChips(),tip:'Computer objects with a server operating system in AD, plus non-Windows systems. Versions come from the operating system recorded in AD, so servers that could not be read are counted too.'},
 {k:'sql',g:1,wide:1,icon:'db',cls:'k-blue',val:fmt(SQ.length),lbl:'SQL Server instances',chips:sqlChips(),tip:'Instances read from the registry of the servers that could be read, plus SQL Server names registered in AD (MSSQLSvc) for the servers that could not be read.'},
 {k:'cl',g:1,icon:'cluster',cls:'k-blue',val:fmt(CL.length),lbl:'Failover clusters',tip:'Cluster name objects in AD. Nodes and roles are shown when at least one node could be read.'},
 {k:'eos',g:1,icon:'calendar',cls:(EOS.length?'k-red':'k-green'),val:fmt(EOS.length),lbl:'Windows out of support',jump:'life',tip:'Servers whose Windows Server version no longer gets security updates. From the operating system recorded in AD, so servers that could not be read are included.'},
 {k:'inv',g:2,icon:'checklist',cls:(OK.length===CT.length?'k-green':'k-amber'),val:fmt(OK.length)+' / '+fmt(CT.length),lbl:'Read / contacted',tip:'Contacted: enabled Windows servers active in AD in the last '+num(P.staleDays)+' days. Read: WMI answered, over DCOM or WinRM.'},
 {k:'nr',g:2,icon:'lock',cls:(NR.length?'k-amber':'k-green'),val:fmt(NR.length),lbl:'Could not be read',jump:'access',tip:'Contacted but not read. Management access shows the reason per subnet and what to open.'},
 {k:'pv',g:2,icon:'layers',cls:'k-blue',val:fmt(phys)+' / '+fmt(virt),lbl:'Physical / virtual',tip:'Servers that could be read only. Virtual is detected from the hardware model the server reports.'},
 {k:'cores',g:2,icon:'cpu',cls:'k-blue',val:fmt(cores),lbl:'CPU cores',tip:'Total physical cores of the servers that could be read.'},
 {k:'mem',g:2,icon:'server',cls:'k-blue',val:gbTxt(mem),lbl:'Memory',tip:'Total memory of the servers that could be read.'},
 {k:'fnd',g:2,icon:'octagon',cls:(nC.length?'k-red':(nW.length?'k-amber':'k-green')),val:nC.length+' / '+nW.length,lbl:'Critical / warnings',list:NF,tip:'Types of finding, all servers included (AD data and data read from the servers). Click to list them.'}];
var KD=CHG?{srv:[SV.length-CHG.pk.srv,0],sql:[SQ.length-CHG.pk.sql,0],cl:[CL.length-CHG.pk.cl,0],eos:[EOS.length-CHG.pk.eos,-1],inv:[OK.length-CHG.pk.read,1],nr:[NR.length-CHG.pk.nr,-1],cores:[cores-CHG.pk.cores,0],mem:[mem-CHG.pk.mem,0,gbTxt]}:{};
function kpiHtml(k){var dd=KD[k.k];return '<div class="kpi '+k.cls+(k.list?' clickable':'')+(k.jump?' clink':'')+(k.wide?' wide':'')+'" data-k="'+k.k+'"><div class="chip">'+ic(k.icon)+'</div><div class="body"><div class="val">'+k.val+(dd?dlt(dd[0],dd[1],dd[2]):'')+'</div><div class="lbl">'+k.lbl+(k.tip?tip(k.tip):'')+'</div>'+(k.chips||'')+(k.list?'<div class="hint">Click to list</div>':'')+'</div></div>';}
qs('#kpis').innerHTML='<div class="kgrp">Known from Active Directory &middot; all '+plural(SV.length,'server')+'</div><div class="kpi-grid">'+KPIS.filter(function(k){return k.g===1;}).map(kpiHtml).join('')+'</div>'+
  '<div class="kgrp">Read from the servers &middot; '+fmt(OK.length)+' of '+fmt(CT.length)+' contacted</div><div class="kpi-grid">'+KPIS.filter(function(k){return k.g===2;}).map(kpiHtml).join('')+'</div>';
KPIS.forEach(function(k){if(!k.jump)return;var el=qs('.kpi[data-k="'+k.k+'"]');if(el)el.onclick=function(){jump(k.jump);};});
var curK='';
Array.prototype.forEach.call(document.querySelectorAll('.kpi.clickable'),function(el){el.onclick=function(){var k=el.getAttribute('data-k');curK=(curK===k)?'':k;
  Array.prototype.forEach.call(document.querySelectorAll('.kpi'),function(x){x.classList.toggle('active',x.getAttribute('data-k')===curK);});
  if(!curK){qs('#fbanner').innerHTML='';return;}
  var K=KPIS.filter(function(x){return x.k===curK;})[0];
  qs('#fbanner').innerHTML='<div class="filter-banner"><div class="filter-banner-head">'+ic(K.icon)+K.lbl+' ('+K.list.length+')<button class="mini-btn" onclick="document.querySelector(\'.kpi.active\').click()">'+ic('x')+'Close</button></div><div class="fb-list">'+
    (K.list.length?K.list.map(function(f){return '<div class="fb-row" onclick="showFindingI('+FLL.indexOf(f)+')"><span class="dot '+SEVMAP[f.sev]+'"></span><span class="nm">'+esc(f.t)+'</span><span class="cx">'+esc(CAT[f.cat])+'</span><span class="cx">'+plural(f.srv.length,'server')+'</span></div>';}).join(''):'<div class="muted-note">Nothing in this category.</div>')+'</div></div>';};});
(function(){var h='';
  if(arr(D.notes).length)h+='<div class="banner-note">'+ic('alert')+arr(D.notes).map(esc).join(' &middot; ')+'</div>';
  if(P.skipRemote)h+='<div class="banner-note">'+ic('info')+'Run with -SkipRemote: servers are listed from AD only, without hardware, roles or patch details.</div>';
  var nr=CT.length-OK.length;if(nr>0)h+='<div class="banner-note">'+ic('alert')+'<span>'+plural(nr,'server')+' of '+fmt(CT.length)+' contacted could not be read from '+esc(P.auditHost||'the audit host')+'. Operating system, lifecycle and roles registered in AD still cover them. <a class="lnk" onclick="jump(\'access\')">See why</a></span></div>';
  if(CHG){var fx=0,nw=0;FLL.concat([]).forEach(function(f){var b=CHG.PF[f.t]?CHG.PF[f.t].n:0;if(f.sev!=='info'&&f.srv.length>b)nw+=f.srv.length-b;});Object.keys(CHG.PF).forEach(function(t){var e=CHG.PF[t],n=FL[t]?FL[t].srv.length:0;if(e.sev!=='info'&&n<e.n)fx+=e.n-n;});
    h+='<div class="banner-note chg">'+ic('refresh')+'<span>Since the run of <b>'+esc(PR.generated.slice(0,10))+'</b>: '+[CHG.n.added?'+'+plural(CHG.n.added,'server'):'',CHG.n.removed?'&minus;'+plural(CHG.n.removed,'server'):'',CHG.n.nowRead?fmt(CHG.n.nowRead)+' now read':'',CHG.n.updated?fmt(CHG.n.updated)+' updated':'',fx?fmt(fx)+' finding'+(fx>1?'s':'')+' resolved':'',nw?fmt(nw)+' new finding'+(nw>1?'s':''):''].filter(Boolean).join(', ')+'. <a class="lnk" onclick="jump(\'changes\')">See changes</a></span></div>';}
  qs('#coverage').innerHTML=h;})();

/* ---------------- overview: priority findings + charts ---------------- */
function bars(rows,total,cls){if(!rows.length)return '<div class="muted-note">No data.</div>';var mx=Math.max.apply(null,rows.map(function(r){return r[1];}));
  return '<div class="bars">'+rows.map(function(r){return '<div class="bar-row"'+(r[2]?' onclick="'+r[2]+'"':'')+'><span class="bl">'+esc(r[0])+'</span><span class="bt"><span class="bf '+(r[3]||cls||'')+'" style="width:'+Math.max(2,Math.round(r[1]*100/mx))+'%"></span></span><span class="bn">'+fmt(r[1])+'</span></div>';}).join('')+'</div>';}
function capTbl(){var g={Physical:{n:0,c:0,m:0},Virtual:{n:0,c:0,m:0}};OK.forEach(function(s){var k=s.platform;if(!g[k])return;g[k].n++;g[k].c+=num(s.cores);g[k].m+=num(s.ramGB);});
  return '<div class="tbl-wrap"><table class="tbl"><tr><th></th><th style="text-align:right">Servers</th><th style="text-align:right">Cores</th><th style="text-align:right">Memory</th></tr>'+['Physical','Virtual'].map(function(k){return '<tr class="trow" onclick="srvFilter({pl:\''+k+'\'})"><td><b>'+k+'</b></td><td class="num">'+fmt(g[k].n)+'</td><td class="num">'+fmt(g[k].c)+'</td><td class="num">'+gbTxt(g[k].m)+'</td></tr>';}).join('')+'</table></div>';}
function countBy(list,fn){var m={};list.forEach(function(x){var k=fn(x);if(k==null||k==='')return;m[k]=(m[k]||0)+1;});return Object.keys(m).map(function(k){return [k,m[k]];}).sort(function(a,b){return b[1]-a[1]||(''+a[0]).localeCompare(''+b[0]);});}
(function(){
  var osRows=countBy(SV.filter(function(s){return s.isWin&&s.status!=='disabled';}),osName).map(function(r){var L=null;for(var i=0;i<LOS.length;i++)if(LOS[i][1]===r[0])L=lifeOf(LOS[i][1],LOS[i][2],LOS[i][3]);return [r[0],r[1],'srvFilter({os:\''+r[0]+'\'})',L?(L.sev==='crit'?'red':(L.sev==='warn'?'amber':'')):''];});
  var roleM={};SV.forEach(function(s){var seen={};arr(s.adRoles).map(function(r){return (''+r).replace(/ \(.*\)$/,'');}).concat(arr(s.features).filter(isRole)).forEach(function(r){if(seen[r])return;seen[r]=1;roleM[r]=(roleM[r]||0)+1;});});
  var roRows=Object.keys(roleM).map(function(k){return [k,roleM[k],'srvFilter({q:\''+k.replace(/'/g,'')+'\'})'];}).sort(function(a,b){return b[1]-a[1];}).slice(0,12);
  var top=FLL.slice(0,8);
  qs('#ovw').innerHTML='<div class="ov-grid">'+
    '<div class="panel-card"><div class="panel-head">'+ic('alert')+'Top findings'+tip('The findings that affect the most servers, worst first. Click one to list its servers.')+'<span class="sub">'+plural(FLL.length,'type')+' of finding</span></div><div class="panel-body">'+(top.length?'<div class="fb-list">'+top.map(function(f){return '<div class="fb-row" onclick="showFindingI('+FLL.indexOf(f)+')"><span class="dot '+SEVMAP[f.sev]+'"></span><span class="nm">'+esc(f.t)+'</span><span class="cx">'+plural(f.srv.length,'server')+'</span></div>';}).join('')+'</div>':'<div class="no-findings">'+ic('check')+'No findings.</div>')+'</div></div>'+
    '<div class="panel-card"><div class="panel-head">'+ic('server')+'Operating systems'+tip('From the operating system recorded in AD, so every Windows server is counted, read or not. Red: out of support. Orange: support ends within a year.')+'<span class="sub">All Windows servers</span></div><div class="panel-body">'+bars(osRows)+'</div></div>'+
    '<div class="panel-card"><div class="panel-head">'+ic('layers')+'Physical and virtual'+tip('Detected from the hardware model each server reports, so only servers that could be read are counted.')+'</div><div class="panel-body">'+capTbl()+covNote()+'</div></div>'+
    '<div class="panel-card"><div class="panel-head">'+ic('list')+'Roles'+tip('Roles registered in AD (domain controllers, SQL Server, certificate authorities, Exchange, Configuration Manager, clusters) cover every server. Roles installed are only known for the servers that could be read. Features Windows installs on every server are left out.')+'<span class="sub">Registered in AD and installed</span></div><div class="panel-body">'+bars(roRows)+'</div></div></div>';
})();

/* ---------------- servers: table + detail blade ---------------- */
var SF={q:'',st:'',os:'',pl:'',fi:''};
function srvMatch(s){
  if(SF.st){if(SF.st==='notinv'){if(['unreachable','denied','timeout','error'].indexOf(s.status)<0)return false;}else if(s.status!==SF.st)return false;}
  if(SF.os&&osName(s)!==SF.os)return false;
  if(SF.pl&&s.platform!==SF.pl)return false;
  if(SF.fi&&!srvF(s).some(function(f){return f.t===SF.fi;}))return false;
  if(SF.q){var q=SF.q.toLowerCase();var hay=[s.name,s.fqdn,s.domain,s.ou,s.desc,s.os,s.osAd,s.platform,s.model,s.mfr,s.site,s.subnet,s.serial,s.clusterName,whyNot(s)].concat(arr(s.ips),arr(s.dnsIps),arr(s.features),arr(s.adRoles),arr(s.sql).map(function(i){return i.instance+' '+i.edition;})).join(' ').toLowerCase();if(hay.indexOf(q)<0)return false;}
  return true;}
function srvFilter(o){SF={q:o.q||'',st:o.st||'',os:o.os||'',pl:o.pl||'',fi:o.fi||''};renderSrvTools();renderSrv();jump('servers');}
function showFindingI(i){var f=FLL[i];if(!f)return;var t=f.t;SF={q:'',st:'',os:'',pl:'',fi:t};renderSrvTools();renderSrv();jump('servers');}
function opts(list,cur,all){return '<option value="">'+all+'</option>'+list.map(function(x){return '<option value="'+esc(x)+'"'+(x===cur?' selected':'')+'>'+esc(x)+'</option>';}).join('');}
function renderSrvTools(){
  var osl=countBy(SV.filter(function(s){return s.isWin;}),osName).map(function(r){return r[0];}).sort();
  var pll=countBy(OK,function(s){return s.platform;}).map(function(r){return r[0];});
  var stl=[['','All statuses'],['ok','Read'],['notinv','Could not be read'],['stale','Stale in AD'],['disabled','Disabled'],['nonwin','Not Windows']].concat(P.skipRemote?[['skipped','AD only']]:[]);
  qs('#srvtools').innerHTML='<input id="srvq" class="inp" placeholder="Search name, IP, OS, role, model, OU..." value="'+esc(SF.q)+'">'+
    '<select id="srvst" class="inp">'+stl.map(function(x){return '<option value="'+x[0]+'"'+(x[0]===SF.st?' selected':'')+'>'+x[1]+'</option>';}).join('')+'</select>'+
    '<select id="srvos" class="inp">'+opts(osl,SF.os,'All operating systems')+'</select><select id="srvpl" class="inp">'+opts(pll,SF.pl,'Physical and virtual')+'</select>'+
    (SF.fi?'<span class="fchip">'+esc(SF.fi)+'<button onclick="SF.fi=\'\';renderSrvTools();renderSrv();">'+ic('x')+'</button></span>':'')+
    '<button class="mini-btn" onclick="csvServers()">'+ic('download')+'CSV</button>';
  qs('#srvq').oninput=function(){SF.q=this.value;renderSrv();};
  qs('#srvst').onchange=function(){SF.st=this.value;renderSrv();};
  qs('#srvos').onchange=function(){SF.os=this.value;renderSrv();};
  qs('#srvpl').onchange=function(){SF.pl=this.value;renderSrv();};}
function srvSev(s){return worstOf(srvF(s).map(function(f){return f.sev;}));}
function renderSrv(){
  var L=SV.filter(srvMatch);
  var rows=L.map(function(s){var i=s._i,w=srvSev(s),ol=osLife(s),ips=arr(s.ips).length?arr(s.ips):arr(s.dnsIps);
    return '<tr class="trow" onclick="openSrv('+i+')"><td style="white-space:nowrap"><span class="dot '+(SEVMAP[w]||'ok')+'" style="margin-right:7px"></span><b>'+esc(s.name)+'</b>'+(s.isDc?' '+tag('info','DC'):'')+domSub(s)+'</td>'+
      '<td class="mono" style="white-space:nowrap">'+(ips.length?esc(ips[0])+(ips.length>1?' <span class="muted">+'+(ips.length-1)+'</span>':''):'-')+'</td><td style="white-space:nowrap">'+esc(osName(s))+(ol&&ol.sev!=='ok'?'<span class="dsub">'+lifeTag(ol)+'</span>':'')+'</td><td style="white-space:nowrap">'+esc(s.site||'-')+'</td>'+
      (s.status==='ok'?'<td style="white-space:nowrap">'+esc(s.platform||'-')+'</td><td class="num">'+(s.cores?s.cores:'-')+'</td><td class="num">'+(s.ramGB?s.ramGB+' GB':'-')+'</td><td style="white-space:nowrap">'+(s.lastUpdate?esc(s.lastUpdate)+(s.patchDays>num(P.patchDays||60)?' '+tag('warn',s.patchDays+' d'):''):'-')+(s.uptimeDays!=null?'<span class="dsub">Up '+fmt(s.uptimeDays)+' days</span>':'')+'</td>'
        :'<td colspan="4" class="why">'+esc(whyNot(s))+'</td>')+'<td>'+stTag(s)+'</td></tr>';}).join('');
  qs('#srvcount').textContent=L.length===SV.length?plural(SV.length,'server'):fmt(L.length)+' of '+plural(SV.length,'server');
  qs('#srvtbl').innerHTML=L.length?'<div class="tbl-wrap fit fit10"><table class="tbl"><tr><th>Server</th><th>IP address</th><th>Operating system</th><th>AD site</th><th>Platform</th><th style="text-align:right">Cores</th><th style="text-align:right">Memory</th><th>Last update</th><th>Status</th></tr>'+rows+'</table></div>':'<div class="panel-body"><div class="muted-note">No server matches the filters.</div></div>';fitAll(qs('#srvtbl'));}
function kv(k,v,cls){return '<div class="kv"><div class="k">'+k+'</div><div class="v'+(cls?' '+cls:'')+'">'+(v==null||v===''?'-':v)+'</div></div>';}
function miniTbl(cols,rows){return '<div class="tbl-wrap" style="max-height:300px;border:1px solid var(--border);border-radius:var(--radius-sm)"><table class="tbl"><tr>'+cols.map(function(c){return '<th>'+c+'</th>';}).join('')+'</tr>'+rows.map(function(r){return '<tr>'+r.map(function(v){return '<td>'+v+'</td>';}).join('')+'</tr>';}).join('')+'</table></div>';}
function openSrv(i){var s=SV[i];if(!s)return;var f=srvF(s).slice().sort(function(a,b){return RANK[b.sev]-RANK[a.sev];}),ol=osLife(s),h='';
  h+='<div class="bl-head"><div><div class="bl-title">'+esc(s.name)+' '+stTag(s)+'</div><div class="bl-sub">'+esc(s.fqdn)+(s.ou?' &middot; '+esc(s.ou):'')+'</div></div><button class="mini-btn" onclick="closeBlade()">'+ic('x')+'Close</button></div><div class="bl-body">';
  if(s.status!=='ok')h+='<div class="banner-note">'+ic('info')+'<span><b>'+esc(whyNot(s))+'.</b> '+(s.statusText&&s.statusText!==whyNot(s)?esc(s.statusText)+' ':'')+'Hardware, installed roles and updates are not available; operating system, lifecycle and roles registered in AD are.</span></div>';
  if(f.length)h+='<div class="dsec"><div class="dsec-t">Findings</div><div class="findings">'+f.map(function(x){return findingHtml(x);}).join('')+'</div></div>';
  h+='<div class="dsec"><div class="dsec-t">Server</div><div class="kv-grid kv3">'+kv('Operating system',esc(s.os||s.osAd)+(ol?' '+lifeTag(ol):''))+kv('Build',esc(s.build||s.buildAd||''))+kv('Domain',esc(s.domain))+kv('AD site',esc(s.site)+(s.subnet?'<span class="dsub mono">'+esc(s.subnet)+(s.subnetInAd?'':' (not an AD subnet)')+'</span>':''))+kv('Last activity in AD',esc(s.lastActive))+kv('Created',esc(s.created))+
     (s.status==='ok'?kv('Installed',esc(s.installDate))+kv('Last boot',esc(s.lastBoot)+(s.uptimeDays!=null?' ('+s.uptimeDays+' d)':''))+kv('Last update',esc(s.lastUpdate)+(s.lastUpdateKb?' &middot; '+esc(s.lastUpdateKb):''),s.patchDays>num(P.patchDays||60)?'warn':'')+kv('Restart pending',s.pending?'Yes ('+esc(arr(s.pendingWhy).join(', '))+')':'No',s.pending?'warn':''):'')+
     (s.desc?kv('Description',esc(s.desc)):'')+(s.act?kv('Activation',esc(s.act.status)+(s.act.channel?' &middot; '+esc(s.act.channel):''),s.act.ok===false?'warn':''):'')+'</div></div>';
  if(s.status==='ok')h+='<div class="dsec"><div class="dsec-t">Hardware</div><div class="kv-grid kv3">'+kv('Platform',esc(s.platform))+kv('Manufacturer',esc(s.mfr))+kv('Model',esc(s.model))+kv('Serial number','<span class="mono">'+esc(s.serial)+'</span>')+kv('Processor',esc(s.cpu))+kv('Sockets / cores / logical',(s.sockets||0)+' / '+(s.cores||0)+' / '+(s.logical||0))+kv('Memory',s.ramGB?s.ramGB+' GB':'')+kv('Architecture',esc(s.arch))+kv('BIOS',esc(s.biosVer)+(s.biosDate?' ('+esc(s.biosDate)+')':''))+'</div></div>';
  h+='<div class="dsec"><div class="dsec-t">Network</div><div class="kv-grid">'+kv('Server IP addresses',esc(arr(s.ips).join(', ')))+kv('DNS record',esc(arr(s.dnsIps).join(', '))+(s.dnsState&&s.dnsState!=='ok'?' '+tag('warn',s.dnsState==='partial'?'extra records':s.dnsState):''))+'</div></div>';
  var roles=realRoles(s),other=arr(s.features).filter(function(x){return !isRole(x);});
  if(roles.length||other.length)h+='<div class="dsec"><div class="dsec-t">Roles</div>'+(roles.length?'<div class="chips">'+roles.map(function(r){return '<span class="chip-s">'+esc(r)+'</span>';}).join('')+'</div>':'<div class="muted-note">No role besides the Windows defaults.</div>')+
    (other.length?'<div class="muted" style="font-size:12px;margin-top:10px">Other features: '+other.map(esc).join(', ')+'</div>':'')+'</div>';
  if(arr(s.sql).length)h+='<div class="dsec"><div class="dsec-t">SQL Server</div>'+miniTbl(['Instance','Edition','Version','Service account','State'],arr(s.sql).map(function(i){var Q=sqlLife(i.version);return ['<b>'+esc(i.instance)+'</b>'+(i.fci?'<span class="dsub">Clustered: '+esc(i.fci)+'</span>':''),esc(i.edition),esc(Q?Q.name:'')+'<span class="dsub mono">'+esc(i.version)+'</span>'+(Q&&Q.sev!=='ok'?lifeTag(Q):''),'<span class="mono">'+esc(i.account)+'</span>',esc(i.state)];}))+'</div>';
  if(CHG&&CHG.per[skey(s)])h+='<div class="dsec"><div class="dsec-t">Since the last run ('+esc(PR.generated.slice(0,10))+')</div><ul class="chglist">'+CHG.per[skey(s)].map(function(t){return '<li>'+esc(t)+'</li>';}).join('')+'</ul></div>';
  if(s.clusterName)h+='<div class="dsec"><div class="dsec-t">Cluster</div><div class="kv-grid">'+kv('Failover cluster','<a class="lnk" onclick="closeBlade();jump(\'clusters\')">'+esc(s.clusterName)+'</a>')+'</div></div>';
  if(arr(s.svc).length)h+='<div class="dsec"><div class="dsec-t">Services running under domain accounts</div>'+miniTbl(['Service','Account','State'],arr(s.svc).map(function(x){return [esc(x.display)+'<span class="dsub mono">'+esc(x.name)+'</span>','<span class="mono">'+esc(x.account)+'</span>'+(x.gmsa?' '+tag('ok','gMSA'):''),esc(x.state)+' &middot; '+esc(x.mode)];}))+'</div>';
  h+='</div>';qs('#blade').innerHTML=h;qs('#blade').classList.add('open');qs('#bladebg').classList.add('open');paintIcons(qs('#blade'));}
function closeBlade(){qs('#blade').classList.remove('open');qs('#bladebg').classList.remove('open');}
function findingHtml(f){var cls=SEVMAP[f.sev];return '<div class="finding '+cls+'">'+ic(f.sev==='info'?'info':'alert')+'<div style="flex:1;min-width:0"><b>'+esc(f.t)+'</b>'+esc(f.d)+(advFor(f)?'<div class="aff">'+esc(advFor(f))+'</div>':'')+'</div></div>';}
function csvServers(){var rows=[['Server','FQDN','Domain','OU','Status','OS','Build','Support ends','Platform','Manufacturer','Model','Serial','Sockets','Cores','Logical','Memory GB','IP addresses','DNS','AD site','Last update','Days since update','Restart pending','Last boot','Roles','Cluster','SQL instances','Subnet','Not read because','Last activity in AD']];
  SV.filter(srvMatch).forEach(function(s){var L=osLife(s);rows.push([s.name,s.fqdn,s.domain,s.ou,(STAT[s.status]||['',s.status])[1],s.os||s.osAd,s.build||s.buildAd,L?L.end:'',s.platform,s.mfr,s.model,s.serial,s.sockets,s.cores,s.logical,s.ramGB,arr(s.ips).join(' '),arr(s.dnsIps).join(' '),s.site,s.lastUpdate,s.patchDays,s.pending?'Yes':'',s.lastBoot,realRoles(s).join(' | '),s.clusterName,arr(s.sql).map(function(i){return i.instance+' '+i.edition+' '+i.version;}).join(' | '),s.subnet,whyNot(s),s.lastActive]);});
  dl('servers.csv',rows);}
renderSrvTools();renderSrv();

/* ---------------- SQL Server ---------------- */
(function(){
  if(!SQ.length){qs('#sqlb').innerHTML='<div class="no-findings">'+ic('info')+'No SQL Server instance found, neither on the servers that could be read nor as MSSQLSvc names in AD.</div>';return;}
  var inv=SQ.filter(function(i){return i.source==='inventory';}).sort(function(a,b){var x=sqlLife(a.version),y=sqlLife(b.version);return (RANK[y?y.sev:'']-RANK[x?x.sev:''])||(''+a.server).localeCompare(''+b.server);}),ad=SQ.filter(function(i){return i.source!=='inventory';});
  var eds=countBy(inv,function(i){return (i.edition||'Unknown').replace(/ Edition.*$/,'').replace(/: Core-based Licensing/,' (core-based)');});
  var vers=countBy(inv,function(i){var Q=sqlLife(i.version);return Q?Q.name:'Unknown';});
  var rows=inv.map(function(i){var Q=sqlLife(i.version),s=SV.filter(function(x){return x.fqdn===i.fqdn;})[0];return ['<b>'+esc(i.server)+'</b>'+domSub(i),'<b>'+esc(i.instance)+'</b>'+(i.fci?'<span class="dsub">Clustered: '+esc(i.fci)+'</span>':''),esc(i.edition),esc(Q?Q.name:'-')+'<span class="dsub mono">'+esc(i.version)+'</span>'+(sqlNoUpd(i.version)?' '+tag('info','No update'):''),lifeTag(Q),(s&&s.cores?s.cores+' cores':'-'),'<span class="mono">'+esc(i.account)+'</span>',esc(i.state)];});
  var h='<div class="ov-grid two"><div class="panel-card"><div class="panel-head">'+ic('db')+'Editions</div><div class="panel-body">'+bars(eds)+'</div></div><div class="panel-card"><div class="panel-head">'+ic('calendar')+'Versions</div><div class="panel-body">'+bars(vers.map(function(v){var Q=null;Object.keys(LSQL).forEach(function(k){if(LSQL[k][0]===v[0])Q=lifeOf(LSQL[k][0],LSQL[k][1],LSQL[k][2]);});return [v[0],v[1],'',Q?(Q.sev==='crit'?'red':(Q.sev==='warn'?'amber':'')):''];}))+'</div></div></div>';
  h+=covNote('Editions, versions and the instance list come from the registry of each server.');
  h+=panel('db','Instances read from the servers'+tip('Read from the registry of each server that could be read. Host cores are those of the server or virtual machine the instance runs on.'),plural(inv.length,'instance'),inv.length?miniTblX(['Server','Instance','Edition','Version','Support','Host cores','Service account','State'],rows,true):'<div class="panel-body"><div class="muted-note">None.</div></div>','csvSql()');
  if(ad.length)h+=panel('search','Found in AD only','SQL Server names registered in AD (MSSQLSvc) whose host could not be read, was not contacted, or is a clustered name or listener',miniTblX(['Host','Instance / port','Registered on','Note'],ad.map(function(i){return ['<b>'+esc(i.fqdn)+'</b>',esc(i.instance),'<span class="mono">'+esc(i.account)+'</span>',i.source==='ad-clustered'?tag('info','Clustered name / listener'):(i.source==='ad-stale'?tag('warn','No instance found on this server - stale SPN?'):tag('mut','Not inventoried'))];})));
  qs('#sqlb').innerHTML=h;})();
function miniTblX(cols,rows,n10){return '<div class="tbl-wrap fit'+(n10?' fit10':'')+'"><table class="tbl"><tr>'+cols.map(function(c){return '<th>'+c+'</th>';}).join('')+'</tr>'+rows.map(function(r){return '<tr>'+r.map(function(v){return '<td>'+v+'</td>';}).join('')+'</tr>';}).join('')+'</table></div>';}
function panel(icon,title,sub,body,csv){return '<div class="panel-card"><div class="panel-head">'+ic(icon)+title+(sub?' <span class="sub">'+sub+'</span>':'')+(csv?'<button class="mini-btn" onclick="'+csv+'">'+ic('download')+'CSV</button>':'')+'</div>'+body+'</div>';}
function csvSql(){var rows=[['Server','Domain','Instance','Edition','Version','Product','Support ends','Clustered','Service account','State','Start mode','Source']];SQ.forEach(function(i){var Q=sqlLife(i.version);rows.push([i.server,i.domain,i.instance,i.edition,i.version,Q?Q.name:'',Q?Q.end:'',i.fci,i.account,i.state,i.mode,i.source==='inventory'?'Inventory':'AD SPN']);});dl('sql_instances.csv',rows);}

/* ---------------- clusters ---------------- */
var GT={1:'Core cluster',2:'Available storage',3:'Cluster Shared Volume',5:'Storage pool',100:'File server',101:'Print server',102:'DHCP server',103:'DTC',104:'MSMQ',105:'WINS',106:'File server',107:'Generic application',108:'Generic service',109:'Generic script',110:'iSNS',111:'Virtual machine',112:'RD Connection Broker',113:'iSCSI target',114:'Scale-out file server',115:'Hyper-V Replica Broker',116:'Task scheduler',117:'Cluster-Aware Updating',118:'Scale-out cluster',119:'Storage Replica',120:'VM replica coordinator',121:'Cross-cluster orchestrator',122:'Infrastructure file server',9999:'Other (e.g. SQL Server, availability group)'};
var CLS=[],CSEL=0;
function clInfo(c){var g=arr(c.groups).filter(function(x){return x.type!==1&&x.type!==2;}),vms=g.filter(function(x){return x.type===111;}),other=g.filter(function(x){return x.type!==111;}),
  down=arr(c.nodes).filter(function(n){return n.state!=='Up';}),fail=g.filter(function(x){return x.state!=='Online';});
  return {vms:vms,other:other,down:down,fail:fail,st:c.source==='ad'?'mut':((down.length||fail.length)?'warn':'ok')};}
function clSub(c,I){if(c.source==='ad')return 'Found in AD only'+(SHOWDOM?' &middot; '+esc(c.domain):'');
  return plural(arr(c.nodes).length,'node')+(I.down.length?' ('+I.down.length+' not up)':'')+' &middot; '+(I.vms.length?plural(I.vms.length,'VM')+' &middot; ':'')+(I.other.length?plural(I.other.length,'role'):'no other roles')+(I.fail.length?' ('+I.fail.length+' not online)':'')+(SHOWDOM?' &middot; '+esc(c.domain):'');}
function renderClList(){var q=((qs('#clq')||{}).value||'').toLowerCase();
  qs('#cllist').innerHTML=CLS.map(function(c,i){var I=clInfo(c),hay=(c.name+' '+c.domain+' '+arr(c.nodes).map(function(n){return n.name;}).join(' ')+' '+arr(c.groups).map(function(g){return g.name;}).join(' ')).toLowerCase();
    return '<div class="item'+(i===CSEL?' sel':'')+(q&&hay.indexOf(q)<0?' hide':'')+'" onclick="selCl('+i+')"><div class="item-ico sev-'+(I.st==='warn'?'medium':(I.st==='mut'?'low':'ok'))+'">'+ic('cluster')+'</div><div class="item-body"><div class="item-name">'+esc(c.name)+'</div><div class="item-sub">'+clSub(c,I)+'</div></div></div>';}).join('');}
function selCl(i){CSEL=i;renderClList();var c=CLS[i];if(!c)return;var I=clInfo(c),h;
  h='<div class="detail-head"><div class="detail-title"><span class="dot '+(I.st==='warn'?'medium':(I.st==='mut'?'mut':'ok'))+'"></span>'+esc(c.name)+'</div><div class="detail-sub">'+esc(c.domain)+(c.source==='ad'?' &middot; cluster name object found in AD only':' &middot; read from '+esc(arr(c.seenFrom).join(', ')))+'</div></div><div class="detail-body">';
  if(c.source==='ad')h+='<div class="muted-note">Cluster name object found in AD'+(c.enabled===false?' (disabled)':'')+', but none of its nodes could be read. If the cluster was retired, its cluster name object can be removed.</div>';
  else{h+='<div class="dsec"><div class="kv-grid kv3">'+kv('Nodes',arr(c.nodes).length+(I.down.length?' ('+I.down.length+' not up)':''),I.down.length?'warn':'')+kv('Clustered VMs',I.vms.length)+kv('Other roles',I.other.length+(I.fail.length?' ('+I.fail.length+' not online)':''),I.fail.length?'warn':'')+'</div></div>'+
    '<div class="dsec"><div class="dsec-t">Nodes</div><div class="chips">'+arr(c.nodes).map(function(n){return '<span class="chip-s '+(n.state==='Up'?'':'warn')+'">'+esc(n.name)+' &middot; '+esc(n.state)+'</span>';}).join('')+'</div></div>';
    var R=I.other.concat(I.vms.filter(function(x){return x.state!=='Online';}));
    h+='<div class="dsec"><div class="dsec-t">Roles</div>'+(R.length?miniTbl(['Role','Type','Owner','State'],R.map(function(x){return [esc(x.name),esc(GT[x.type]||'Other'),esc(x.owner),x.state==='Online'?tag('ok','Online'):tag('warn',x.state)];})):'')+
      (I.vms.length?'<div class="okline" style="margin-top:8px">'+plural(I.vms.length,'virtual machine')+' clustered'+(I.vms.filter(function(x){return x.state!=='Online';}).length?'':', all online')+'</div>':'')+(!R.length&&!I.vms.length?'<div class="muted-note">No clustered roles.</div>':'')+'</div>';}
  qs('#cldetail').innerHTML=h+'</div>';}
(function(){
  if(!CL.length){qs('#clb').innerHTML='<div class="no-findings">'+ic('info')+'No failover cluster found.</div>';return;}
  var R={warn:0,ok:1,mut:2};CLS=CL.slice().sort(function(a,b){return (R[clInfo(a).st]-R[clInfo(b).st])||(''+a.name).localeCompare(''+b.name);});CSEL=0;
  var bad=CLS.filter(function(c){return clInfo(c).st==='warn';}).length,ado=CLS.filter(function(c){return c.source==='ad';}).length;
  qs('#clb').innerHTML='<div class="stat-row"><div class="stat"><b>'+fmt(CLS.length)+'</b>Clusters</div><div class="stat"><b>'+fmt(CLS.reduce(function(a,c){return a+arr(c.nodes).length;},0))+'</b>Nodes</div><div class="stat"><b class="'+(bad?'amber':'')+'">'+fmt(bad)+'</b>With a node or role not online</div><div class="stat"><b>'+fmt(ado)+'</b>Found in AD only</div></div>'+
    '<div class="layout"><div class="panel-card" style="margin-bottom:0"><div class="list-search"><input id="clq" placeholder="Filter clusters, nodes or roles..."></div><div class="item-list" id="cllist"></div></div><div class="panel-card" style="margin-bottom:0"><div class="detail" id="cldetail"></div></div></div>';
  qs('#clq').addEventListener('input',renderClList);selCl(0);
})();

/* ---------------- lifecycle ---------------- */
(function(){
  var om={};SV.filter(function(s){return s.isWin&&s.status!=='disabled';}).forEach(function(s){var L=osLife(s),k=L?L.name:(s.os||s.osAd||'Unknown');if(!om[k])om[k]={L:L,n:0};om[k].n++;});
  var orow=Object.keys(om).map(function(k){return {k:k,L:om[k].L,n:om[k].n};}).sort(function(a,b){return (a.L?a.L.days:99999)-(b.L?b.L.days:99999);});
  var sm={};SQ.filter(function(i){return i.source==='inventory';}).forEach(function(i){var Q=sqlLife(i.version),k=Q?Q.name:'Unknown';if(!sm[k])sm[k]={L:Q,n:0};sm[k].n++;});
  var srow=Object.keys(sm).map(function(k){return {k:k,L:sm[k].L,n:sm[k].n};}).sort(function(a,b){return (a.L?a.L.days:99999)-(b.L?b.L.days:99999);});
  function lt(rows,noun,click){return miniTblX(['Version',noun,'End of support','Status','Microsoft source'],rows.map(function(r){var L=r.L;return ['<b>'+esc(r.k)+'</b>',click?'<a class="lnk" onclick="srvFilter({os:\''+r.k+'\'})">'+fmt(r.n)+'</a>':fmt(r.n),L?esc(L.end)+(L.days<0?'<span class="dsub">'+fmt(-L.days)+' days ago</span>':'<span class="dsub">in '+fmt(L.days)+' days</span>'):'-',L?lifeTag(L):tag('mut','Unknown'),L?'<a class="lnk" href="'+L.url+'" target="_blank" rel="noopener">Lifecycle page &rarr;</a>':''];}));}
  qs('#lifeb').innerHTML='<div class="banner-note">'+ic('info')+'End of extended support from the Microsoft lifecycle pages. Servers enrolled in Extended Security Updates still get security updates until the ESU end date.</div>'+
    panel('server','Windows Server'+tip('From the operating system recorded in AD: every Windows server is included, read or not.'),plural(orow.reduce(function(a,r){return a+r.n;},0),'server'),orow.length?lt(orow,'Servers',true):'<div class="panel-body"><div class="muted-note">No Windows server.</div></div>')+
    panel('db','SQL Server'+tip('Instances read from the servers only: the version of SQL Server names found in AD alone is not known.'),'Instances read from the servers',srow.length?lt(srow,'Instances',false):'<div class="panel-body"><div class="muted-note">No inventoried SQL Server instance.</div></div>');
})();

/* ---------------- management access ---------------- */
var ACCN=0;
var ACOL={blocked:'blk',rpcdyn:'blk',noanswer:'none',denied:'den'};
function accK(s){if(s.status==='ok')return 'ok';return ACOL[s.access]||'oth';}
function accTodo(g){var t=[];
  if(g.blk)t.push('Open TCP 5985 (WinRM), or 135 plus 49152-65535 (DCOM), from the audit host');
  if(g.none)t.push(g.none===g.n?'No answer on any port: check routing and network firewalls to this subnet, or run the report from a machine inside it':'Check that the servers that do not answer are running and their DNS records are right');
  if(g.den)t.push('Make the audit account a local administrator on these servers');
  if(g.dns)t.push('Fix the DNS records of these servers');
  if(g.tmo)t.push('Check these servers, or run again with a higher -ServerTimeoutSec');
  if(g.wmi)t.push('Check the WMI service on these servers (reason in each server)');
  return t;}
(function(){
  var G={},L=[];CT.forEach(function(s){var key=s.subnet||'';if(!G[key]){G[key]={subnet:key,inAd:!!s.subnetInAd,sites:{},n:0,ok:0,blk:0,none:0,den:0,oth:0,dns:0,tmo:0,wmi:0};L.push(G[key]);}var g=G[key];g.n++;if(s.site)g.sites[s.site]=1;
    var k=accK(s);g[k]++;if(k==='oth'){if(s.access==='dns')g.dns++;else if(s.access==='timeout')g.tmo++;else g.wmi++;}});
  L.sort(function(a,b){return (b.n-b.ok)-(a.n-a.ok)||b.n-a.n;});
  var tot={n:0,ok:0,blk:0,none:0,den:0,oth:0};L.forEach(function(g){for(var k in tot)tot[k]+=g[k];});ACCN=tot.n-tot.ok;
  var h='<div class="banner-note">'+ic('info')+'<span>Contacted from <b>'+esc(P.auditHost||'-')+'</b> as <b>'+esc(P.auditUser||'-')+'</b>. Servers are read with WMI over DCOM (TCP 135 and the dynamic RPC ports 49152-65535) or over WinRM (TCP 5985), and the account must be a local administrator. When both 135 and 5985 are closed, TCP 445 and 3389 are tried to tell a blocked server from one that does not answer.</span></div>';
  h+='<div class="stat-row"><div class="stat"><b>'+fmt(tot.n)+'</b>Contacted'+tip('Enabled Windows servers with activity in AD in the last '+num(P.staleDays)+' days.')+'</div><div class="stat"><b class="'+(tot.ok===tot.n?'':'amber')+'">'+fmt(tot.ok)+'</b>Read</div>'+
    '<div class="stat"><b class="'+(tot.blk?'amber':'')+'">'+fmt(tot.blk)+'</b>Up, but blocked'+tip('The server answers on 445 (SMB) or 3389 (RDP), but RPC and WinRM are blocked, or port 135 answers and the dynamic RPC ports do not.')+'</div>'+
    '<div class="stat"><b class="'+(tot.none?'amber':'')+'">'+fmt(tot.none)+'</b>No answer'+tip('No answer on 135, 445, 3389 or 5985: server off, wrong IP in DNS, or a network firewall that blocks everything from the audit host.')+'</div>'+
    '<div class="stat"><b class="'+(tot.den?'amber':'')+'">'+fmt(tot.den)+'</b>Access denied'+tip('The server answers, but the account running the report is not a local administrator on it.')+'</div>'+
    '<div class="stat"><b>'+fmt(tot.oth)+'</b>Other'+tip('Name not in DNS, timed out, or WMI did not answer.')+'</div></div>';
  if(!ACCN)h+='<div class="no-findings">'+ic('check')+'Every contacted server could be read.</div>';
  else h+=panel('lock','By subnet'+tip('Subnet from the AD subnets the server IP belongs to; /24 when the IP is in no AD subnet. Click a row to list its servers that could not be read.'),'Worst first',
    '<div class="tbl-wrap fit fit10"><table class="tbl"><tr><th>Subnet</th><th>AD site</th><th style="text-align:right">Contacted</th><th style="text-align:right">Read</th><th style="text-align:right">Blocked</th><th style="text-align:right">No answer</th><th style="text-align:right">Denied</th><th style="text-align:right">Other</th><th>To do</th></tr>'+
    L.map(function(g){var td=accTodo(g),bad=g.n-g.ok;function c(v){return '<td class="num">'+(v?'<b>'+fmt(v)+'</b>':'<span class="muted">-</span>')+'</td>';}
      return '<tr class="trow"'+(bad?' onclick="srvFilter({q:\''+esc(g.subnet)+'\',st:\'notinv\'})"':'')+'><td class="mono" style="white-space:nowrap"><b>'+esc(g.subnet||'IP not known')+'</b>'+(g.subnet&&!g.inAd?'<span class="dsub">Not an AD subnet</span>':'')+'</td><td>'+esc(Object.keys(g.sites).join(', ')||'-')+'</td><td class="num">'+fmt(g.n)+'</td>'+c(g.ok)+c(g.blk)+c(g.none)+c(g.den)+c(g.oth)+
        '<td style="font-size:12.5px">'+(td.length?td.map(esc).join('<br>'):tag('ok','Nothing to do'))+'</td></tr>';}).join('')+'</table></div>','csvAccess()');
  qs('#accb').innerHTML=h;})();
function csvAccess(){var rows=[['Server','FQDN','Domain','Subnet','AD subnet','AD site','IP','Status','Reason','Detail']];CT.forEach(function(s){rows.push([s.name,s.fqdn,s.domain,s.subnet,s.subnetInAd?'Yes':'No',s.site,arr(s.ips).concat(arr(s.dnsIps))[0]||'',(STAT[s.status]||['',s.status])[1],whyNot(s),s.status==='ok'?'':s.statusText]);});dl('management_access.csv',rows);}

/* ---------------- changes section ---------------- */
var CM2={};SV.forEach(function(s){CM2[skey(s)]=s;});
(function(){if(!CHG)return;qs('#sec-changes').style.display='';var C=CHG,n=C.n;
  var h='<div class="banner-note">'+ic('info')+'<span>Compared with the report of <b>'+esc(PR.generated)+'</b>'+(PR.params&&PR.params.auditHost?' run from <b>'+esc(PR.params.auditHost)+'</b>':'')+', '+plural(C.days,'day')+' earlier. Lifecycle findings of that run are counted as of its own date.</span></div>';
  if(PR.forest&&D.forest&&(''+PR.forest).toLowerCase()!==(''+D.forest).toLowerCase())h+='<div class="banner-note">'+ic('alert')+'<span>The earlier report is for another forest ('+esc(PR.forest)+'): most servers show as added or removed.</span></div>';
  if(PR.params&&P.auditHost&&PR.params.auditHost&&PR.params.auditHost!==P.auditHost)h+='<div class="banner-note">'+ic('alert')+'<span>This run was made from another machine ('+esc(P.auditHost)+'): servers read or not read can change because of that alone.</span></div>';
  function st(v,l,c,t){return '<div class="stat"><b class="'+(v?c:'')+'">'+fmt(v)+'</b>'+l+(t?tip(t):'')+'</div>';}
  h+='<div class="stat-row">'+st(n.added,'New in AD','blue')+st(n.removed,'No longer in AD','blue')+st(n.nowRead,'Read now, not before','green','Usually after a firewall rule or permission change.')+st(n.lostRead,'Read before, not now','amber')+st(n.updated,'Updated since','green','Servers read in both runs with a more recent update installed now.')+st(n.notUpd,'Still not updated','amber','Read in both runs, same last update, older than '+num(P.patchDays||60)+' days.')+'</div>';
  var ft=Object.keys(C.PF).concat(FLL.map(function(f){return f.t;})).filter(function(t,i,a){return a.indexOf(t)===i;}).map(function(t){var b=C.PF[t]?C.PF[t].n:0,c=FL[t]?FL[t].srv.length:0,sv=FL[t]?FL[t].sev:C.PF[t].sev;return {t:t,b:b,c:c,sev:sv,fl:FL[t]};}).filter(function(x){return x.b||x.c;})
    .sort(function(a,b){return (RANK[b.sev]-RANK[a.sev])||(Math.abs(b.c-b.b)-Math.abs(a.c-a.b));});
  h+=panel('alert','Findings, before and now'+tip('Number of servers with each finding in the earlier run and now. Click a finding to list its servers now.'),'Worst first',
    '<div class="tbl-wrap fit fit10"><table class="tbl"><tr><th>Finding</th><th>Severity</th><th style="text-align:right">Before</th><th style="text-align:right">Now</th><th style="text-align:right">Change</th></tr>'+
    ft.map(function(x){var d=x.c-x.b;return '<tr class="trow"'+(x.fl?' onclick="showFindingI('+FLL.indexOf(x.fl)+')"':'')+'><td><b>'+esc(x.t)+'</b></td><td>'+tag(x.sev==='info'?'mut':x.sev,x.sev==='crit'?'Critical':(x.sev==='warn'?'Warning':'Info'))+'</td><td class="num">'+fmt(x.b)+'</td><td class="num">'+fmt(x.c)+'</td><td class="num">'+(d?dlt(d,x.sev==='info'?0:-1):'<span class="muted">-</span>')+'</td></tr>';}).join('')+'</table></div>');
  var ord=['added','removed','inactive','nowRead','lostRead','os','sqlAdd','sqlDel','updated'],R=C.rows.slice().sort(function(a,b){return ord.indexOf(a.k)-ord.indexOf(b.k)||(''+a.s.name).localeCompare(''+b.s.name);});
  var cls={added:'info',removed:'mut',inactive:'mut',nowRead:'ok',lostRead:'warn',os:'info',sqlAdd:'info',sqlDel:'mut',updated:'ok'};
  h+=panel('srv','Servers'+tip('Every server-level change between the two runs. Servers still in AD open their details.'),plural(R.length,'change'),R.length?'<div class="tbl-wrap fit"><table class="tbl"><tr><th>Change</th><th>Server</th><th>Detail</th></tr>'+
    R.map(function(x){var cur=x.cur&&CM2[skey(x.s)];return '<tr class="trow"'+(cur?' onclick="openSrv('+cur._i+')"':'')+'><td style="white-space:nowrap">'+tag(cls[x.k],x.lbl)+'</td><td style="white-space:nowrap"><b>'+esc(x.s.name)+'</b>'+domSub(x.s)+'</td><td>'+esc(x.d)+'</td></tr>';}).join('')+'</table></div>'
    :'<div class="panel-body"><div class="no-findings">'+ic('check')+'No server-level change.</div></div>','csvChanges()');
  qs('#chgb').innerHTML=h;})();
function csvChanges(){var rows=[['Change','Server','Domain','Detail']];CHG.rows.slice().sort(function(a,b){return a.lbl.localeCompare(b.lbl)||(''+a.s.name).localeCompare(''+b.s.name);}).forEach(function(x){rows.push([x.lbl,x.s.name,x.s.domain,x.d]);});dl('changes.csv',rows);}

/* ---------------- updates & restart ---------------- */
function renderPatch(){var pd=num(P.patchDays)||60,L=OK.slice().sort(function(a,b){return num(b.patchDays)-num(a.patchDays)||(b.pending?1:0)-(a.pending?1:0);});
  var old=L.filter(function(s){return s.patchDays>pd;}).length,pend=L.filter(function(s){return s.pending;}).length,unk=L.filter(function(s){return s.patchDays==null;}).length,upl=L.filter(function(s){return s.uptimeDays!=null&&s.uptimeDays>pd;}).length;
  var h='<div class="stat-row"><div class="stat"><b class="'+(old?'amber':'')+'">'+fmt(old)+'</b>No update in '+pd+'+ days</div><div class="stat"><b class="'+(pend?'blue':'')+'">'+fmt(pend)+'</b>Restart pending</div><div class="stat"><b class="'+(upl?'amber':'')+'">'+fmt(upl)+'</b>Not restarted in '+pd+'+ days'+tip('Cumulative updates installed since the last boot are not active until the server restarts.')+'</div><div class="stat"><b>'+fmt(L.length-old-unk)+'</b>Up to date</div>'+(unk?'<div class="stat"><b>'+fmt(unk)+'</b>Last update not reported</div>':'')+'</div>';
  h+=panel('refresh','Servers'+tip('Servers that could be read. Days are counted from the install date of the most recent update.'),'Most outdated first',L.length?miniTblX(['Server','Last update','Days','Restart pending','Last boot','Uptime'],L.map(function(s){return ['<b>'+esc(s.name)+'</b>'+domSub(s),esc(s.lastUpdate||'-')+(s.lastUpdateKb?'<span class="dsub mono">'+esc(s.lastUpdateKb)+'</span>':''),s.patchDays==null?'-':(s.patchDays>pd*2?tag('crit',s.patchDays+' days'):(s.patchDays>pd?tag('warn',s.patchDays+' days'):s.patchDays+' days')),s.pending?tag('info',arr(s.pendingWhy).join(', ')):'No',esc(s.lastBoot||'-'),s.uptimeDays==null?'-':(s.uptimeDays>pd?tag('warn',fmt(s.uptimeDays)+' days'):fmt(s.uptimeDays)+' days')];})):'<div class="panel-body"><div class="muted-note">No inventoried server.</div></div>','csvPatch()');
  qs('#patchb').innerHTML=covNote('Last update is the most recent update installed (Win32_QuickFixEngineering); restart pending comes from the registry.')+h;}
function csvPatch(){var rows=[['Server','Domain','Last update','KB','Days since update','Restart pending','Reasons','Last boot','Uptime days']];OK.forEach(function(s){rows.push([s.name,s.domain,s.lastUpdate,s.lastUpdateKb,s.patchDays,s.pending?'Yes':'No',arr(s.pendingWhy).join(' | '),s.lastBoot,s.uptimeDays]);});dl('updates.csv',rows);}
renderPatch();

/* ---------------- service accounts ---------------- */
(function(){var A={};OK.forEach(function(s){arr(s.svc).forEach(function(x){var k=(''+x.account).toLowerCase();if(!A[k])A[k]={acc:x.account,gmsa:x.gmsa,list:[]};A[k].list.push({s:s,x:x});});});
  var L=Object.keys(A).map(function(k){return A[k];}).sort(function(a,b){return b.list.length-a.list.length;});
  qs('#svcb').innerHTML=covNote()+(L.length?'<div class="banner-note">'+ic('info')+'Services running under a domain account on the servers that could be read. Changing one of these passwords means updating every service listed. Group managed service accounts (gMSA) change their password on their own.</div>'+
    panel('people','Accounts',plural(L.length,'account')+', '+plural(L.filter(function(a){return a.gmsa;}).length,'gMSA'),'<div class="tbl-wrap"><table class="tbl"><tr><th>Account</th><th style="text-align:right">Services</th><th style="text-align:right">Servers</th><th>Where</th></tr>'+L.map(function(a){var sv={};a.list.forEach(function(e){sv[e.s.name]=1;});var where=a.list.slice(0,6).map(function(e){return esc(e.s.name)+' <span class="muted">('+esc(e.x.display)+')</span>';}).join(', ')+(a.list.length>6?' &hellip;':'');
      return '<tr><td><span class="mono"><b>'+esc(a.acc)+'</b></span>'+(a.gmsa?' '+tag('ok','gMSA'):'')+'</td><td class="num">'+a.list.length+'</td><td class="num">'+Object.keys(sv).length+'</td><td style="font-size:12.5px">'+where+'</td></tr>';}).join('')+'</table></div>','csvSvc()'):'<div class="no-findings">'+ic('check')+'No service runs under a domain account on the servers that could be read.</div>');})();
function csvSvc(){var rows=[['Account','gMSA','Server','Domain','Service','Display name','State','Start mode']];OK.forEach(function(s){arr(s.svc).forEach(function(x){rows.push([x.account,x.gmsa?'Yes':'',s.name,s.domain,x.name,x.display,x.state,x.mode]);});});dl('service_accounts.csv',rows);}

/* ---------------- Windows activation (-IncludeActivation) ---------------- */
(function(){if(!P.activation)return;var T=OK.filter(function(s){return s.act;});var ch=countBy(T,function(s){return s.act.channel||'Unknown';}),na=T.filter(function(s){return s.act.ok===false;});
  qs('#extb').innerHTML=covNote()+'<div class="ov-grid two"><div class="panel-card"><div class="panel-head">'+ic('key')+'Activation channel</div><div class="panel-body">'+bars(ch)+'</div></div><div class="panel-card"><div class="panel-head">'+ic('alert')+'Not activated<span class="sub">'+plural(na.length,'server')+'</span></div><div class="panel-body">'+(na.length?na.map(function(s){return '<div class="okline"><b>'+esc(s.name)+'</b> &middot; '+esc(s.act.status)+'</div>';}).join(''):'<div class="no-findings">'+ic('check')+'All inventoried servers are activated.</div>')+'</div></div></div>';})();

/* ---------------- navigation ---------------- */
function jump(sec){var el=qs('#sec-'+sec);if(el)el.scrollIntoView({behavior:'smooth',block:'start'});}
(function(){
  function cnt(cats){var l=FLL.filter(function(f){return cats.indexOf(f.cat)>=0&&f.sev!=='info';});var w=worstOf(l.map(function(f){return f.sev;}));var n=0;l.forEach(function(f){n+=f.srv.length;});return l.length?'<span class="n '+SEVMAP[w]+'">'+n+'</span>':'';}
  var S=[['overview','Overview','key','']].concat(CHG?[['changes','Changes','refresh',(CHG.rows.length?'<span class="n mut">'+CHG.rows.length+'</span>':'')]]:[]).concat([['servers','Servers','srv',''],['life','Lifecycle','calendar',cnt(['life'])],['sql','SQL Server','db',''],['clusters','Clusters','cluster',''],['access','Management access','lock',ACCN?'<span class="n medium">'+ACCN+'</span>':''],['patch','Updates & restart','refresh',cnt(['patch'])],['svc','Service accounts','people','']]);
  if(P.activation)S.push(['ext','Activation','checklist',cnt(['act'])]);else{var e=qs('#sec-ext');if(e)e.style.display='none';}
  qs('#secnav').innerHTML=S.map(function(x){return '<a data-s="'+x[0]+'">'+ic(x[2])+'<span>'+esc(x[1])+'</span>'+x[3]+'</a>';}).join('');
  Array.prototype.forEach.call(document.querySelectorAll('#secnav a'),function(a){a.onclick=function(){var s=a.getAttribute('data-s');if(s==='overview')window.scrollTo({top:0,behavior:'smooth'});else jump(s);};});
  function spy(){var cur='overview';S.forEach(function(x){var el=qs('#sec-'+x[0]);if(el&&el.getBoundingClientRect().top<90)cur=x[0];});
    if(window.innerHeight+window.scrollY>=document.body.scrollHeight-4)cur=S[S.length-1][0];
    Array.prototype.forEach.call(document.querySelectorAll('#secnav a'),function(a){a.classList.toggle('on',a.getAttribute('data-s')===cur);});}
  if(window.__spy)window.removeEventListener('scroll',window.__spy);window.__spy=spy;window.addEventListener('scroll',spy,{passive:true});spy();
  qs('#bladebg').onclick=closeBlade;
  if(!window.__esc){window.__esc=1;document.addEventListener('keydown',function(e){if(e.key==='Escape')closeBlade();});}
})();
(function(){var T={
  servers:'Every server object in AD. Operating system, OU, AD site and last activity come from AD; platform, cores, memory and last update only for the servers that could be read.',
  life:'Windows Server versions come from AD and cover every server. SQL Server versions only for the instances read from the servers.',
  sql:'Instances read from the registry of each server, plus SQL Server names registered in AD (MSSQLSvc) for the servers that could not be read.',
  clusters:'Cluster name objects in AD, with nodes and roles read from the nodes that could be read.',
  access:'What the audit host could reach on each server, grouped by subnet, with what to open so the next run reads more servers.',
  patch:'Servers that could be read only. Last update: most recent update installed (Win32_QuickFixEngineering). Restart pending: from the registry.',
  svc:'Servers that could be read only: Windows services running under a domain account.',
  ext:'Servers that could be read only: activation status and channel (KMS, MAK, retail, AVMA).'};
  Object.keys(T).forEach(function(k){var h=qs('#sec-'+k+' .sect-head');if(h&&!h.querySelector('.tip'))h.insertAdjacentHTML('beforeend',tip(T[k]));});})();
(function(){if(window.__tipOn)return;window.__tipOn=1;
  var box=document.createElement('div');box.id='tipbox';document.documentElement.appendChild(box);
  function show(el){box.textContent=el.getAttribute('data-tip');box.style.display='block';var r=el.getBoundingClientRect(),w=box.offsetWidth,h=box.offsetHeight,x=r.left+r.width/2-w/2,y=r.top-h-8;
    if(y<6)y=r.bottom+8;x=Math.max(6,Math.min(x,window.innerWidth-w-6));box.style.left=x+'px';box.style.top=y+'px';}
  function hide(){box.style.display='none';}
  document.addEventListener('mouseover',function(e){var el=e.target.closest&&e.target.closest('.tip');if(el)show(el);else hide();});
  document.addEventListener('focusin',function(e){if(e.target.classList&&e.target.classList.contains('tip'))show(e.target);});
  document.addEventListener('focusout',hide);window.addEventListener('scroll',hide,{passive:true});
  document.addEventListener('click',function(e){var el=e.target.closest&&e.target.closest('.tip');if(el){e.stopPropagation();e.preventDefault();show(el);}},true);})();
fitAll();
paintIcons();
</script>
<script>
var MAIN0=document.querySelector('main').innerHTML, SEL='';
function runApp(){var b=document.getElementById('blade');if(b)b.classList.remove('open');var g=document.getElementById('bladebg');if(g)g.classList.remove('open');
  document.querySelector('main').innerHTML=MAIN0;D=viewFor(SEL);(0,eval)(document.getElementById('app').textContent);}
(function(){var w=qs('#sdomwrap'),s=qs('#domsel');if(DOMS.length<2)return;w.style.display='';
  var cnt=function(d){return arr(D0.servers).filter(function(x){return x.domain===d;}).length;};
  s.innerHTML='<option value="">All domains ('+arr(D0.servers).length+' servers)</option>'+DOMS.map(function(d){return '<option value="'+esc(d)+'">'+esc(d)+' ('+cnt(d)+')</option>';}).join('');
  s.onchange=function(){SEL=s.value;runApp();window.scrollTo(0,0);};})();
runApp();
</script>
</body></html>
"@

$stage = 'write-file'
Write-Host "Writing file..." -ForegroundColor Yellow
try {
    [System.IO.File]::WriteAllText($ReportPath, $HTML, [System.Text.UTF8Encoding]::new($true))
} catch {
    Write-Host ""
    Write-Host ">>> FAILED at stage '$stage': $($_.Exception.GetType().Name) - $($_.Exception.Message)" -ForegroundColor Red
    throw
}
Write-Host ""
Write-Host ("  Report saved: {0}  ({1:mm\:ss})" -f $ReportPath,$Watch.Elapsed) -ForegroundColor Green
try { if ($OpenReport) { Start-Process $ReportPath } } catch {}
