<#
.SYNOPSIS
    AD Infrastructure Topology - interactive, self-contained HTML viewer.

.DESCRIPTION
    Discovers the Active Directory forest, its domains, sites, and domain
    controllers live from the current environment and renders a single
    self-contained, interactive dark-mode HTML report.

    The report shows the forest -> domain -> site -> domain controller hierarchy
    as nested cards, colour-codes each DC by health, and exposes a slide-in detail
    panel (click a forest, domain, site, or DC) with FSMO roles, subnets,
    services, replication status, resource usage, and dcdiag results.

    The HTML is fully offline: no external scripts, no telemetry, no internet
    required to open it. Nothing is written anywhere except the output folder.

    If a compatible $AuditResults object from a broader audit run is present in
    the current session it will be reused; otherwise the script queries AD live.

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite (this is the Topology module)
    License : See repository

.PARAMETER OutputPath
    Folder to save the report. Defaults to the current directory.

.PARAMETER OpenReport
    Auto-open the report in the default browser. Defaults to $true.

.EXAMPLE
    .\AD-Topology.ps1

.EXAMPLE
    .\AD-Topology.ps1 -OutputPath C:\Reports -OpenReport:$false
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [switch]$OpenReport = $true,
    # A partner is flagged "delayed" when its last successful replication is older than
    # these thresholds. Inter-site defaults to 6h because the DEFAULT site-link schedule
    # is 180 minutes - a flat 3h threshold produces false positives.
    [int]$ReplDelayIntraSiteHours = 1,
    [int]$ReplDelayInterSiteHours = 6
)

# ─────────────────────────────────────────────────────────────────────────────
# 0. PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = 'Stop'

try { Import-Module ActiveDirectory -ErrorAction Stop }
catch {
    Write-Error "ActiveDirectory module not available. Install RSAT-AD-PowerShell."
    exit 1
}

# Resolve to absolute path
try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$Stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$ExportStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$ReportPath  = Join-Path $OutputPath "AD_Topology_$Stamp.html"

Write-Host "Building AD topology report..." -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# 1. BUILD TOPOLOGY JSON  (always queries AD live + live per-DC deep collection)
#    Per-DC health is collected live via CIM (WinRM first, DCOM fallback).
#    Also detects orphaned NTDS metadata (server objects in Sites & Services
#    with no matching replicating DC).
# ─────────────────────────────────────────────────────────────────────────────

# Helper: live per-DC deep collection with WinRM -> DCOM fallback
function Get-DCLiveHealth {
    param([string]$HostName, [string]$LocalName)
    $r = [ordered]@{
        status='Unreachable'; collectVia='None'; uptime='N/A'
        pendingReboot='N/A'; ntlmv1='N/A'
        ntds='N/A'; kdc='N/A'; adws='N/A'; netlogon='N/A'; w32time='N/A'
        ramTotalGB='N/A'; ramFreePct='N/A'; cpuFreePct='N/A'
        osDiskFreeGB='N/A'; osDiskFreePct='N/A'
        timeSkew='N/A'; sysvolShare='N/A'; netlogonShare='N/A'
        replErrors='N/A'; maxReplDelayH='N/A'; dcdiag=''; ntpSource='N/A'
    }
    $short = $HostName.Split('.')[0]
    $isLocal = ($short -ieq $LocalName)

    # Ping
    if (Test-Connection -ComputerName $HostName -Count 1 -Quiet -ErrorAction SilentlyContinue) { $r.status='Online' }
    else { $r.status='Offline'; return $r }

    # CIM session: WinRM then DCOM
    $cim=$null; $proto='None'
    if ($isLocal) {
        try { $cim=New-CimSession -ErrorAction Stop; $proto='Local' } catch {}
    } else {
        try { $cim=New-CimSession -ComputerName $HostName -OperationTimeoutSec 10 -ErrorAction Stop; $proto='WinRM' } catch { $cim=$null }
        if (-not $cim) {
            try { $cim=New-CimSession -ComputerName $HostName -SessionOption (New-CimSessionOption -Protocol Dcom) -OperationTimeoutSec 15 -ErrorAction Stop; $proto='DCOM' } catch { $cim=$null }
        }
    }
    $r.collectVia=$proto

    if ($cim) {
        try {
            $os=Get-CimInstance Win32_OperatingSystem -CimSession $cim -ErrorAction SilentlyContinue
            if ($os) {
                if ($os.LastBootUpTime) { $up=(Get-Date)-$os.LastBootUpTime; $r.uptime="$([math]::Floor($up.TotalDays))d $($up.Hours)h" }
                $r.timeSkew=[math]::Round(((Get-Date)-$os.LocalDateTime).TotalSeconds,1)
                if ($os.TotalVisibleMemorySize -and $os.FreePhysicalMemory) {
                    $r.ramTotalGB=[math]::Round($os.TotalVisibleMemorySize/1MB,1)
                    $r.ramFreePct=[math]::Round(($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,0)
                }
            }
        } catch {}
        try {
            $cpu=Get-CimInstance Win32_Processor -CimSession $cim -ErrorAction SilentlyContinue | Measure-Object -Property LoadPercentage -Average
            if ($cpu -and $cpu.Average -ne $null) { $r.cpuFreePct=[math]::Round(100-$cpu.Average,0) }
        } catch {}
        try {
            $disk=Get-CimInstance Win32_LogicalDisk -CimSession $cim -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
            if ($disk -and $disk.Size) { $r.osDiskFreeGB=[math]::Round($disk.FreeSpace/1GB,1); $r.osDiskFreePct=[math]::Round(($disk.FreeSpace/$disk.Size)*100,0) }
        } catch {}
        try {
            $svcMap=@{ NTDS='ntds'; KDC='kdc'; ADWS='adws'; Netlogon='netlogon'; W32Time='w32time' }
            $svcs=Get-CimInstance Win32_Service -CimSession $cim -ErrorAction SilentlyContinue | Where-Object { $svcMap.ContainsKey($_.Name) }
            foreach ($s in $svcs) { $r[$svcMap[$s.Name]]=$s.State }
        } catch {}
        # Pending reboot + NTLMv1 via remote registry (StdRegProv methods work directly)
        try {
            $pending=$false; $regOk=$false
            foreach ($k in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
                $res=Invoke-CimMethod -CimSession $cim -Namespace root\default -ClassName StdRegProv -MethodName EnumKey -Arguments @{ hDefKey=[uint32]2147483650; sSubKeyName=$k } -ErrorAction SilentlyContinue
                if ($res -ne $null) { $regOk=$true }
                if ($res -and $res.ReturnValue -eq 0) { $pending=$true }
            }
            if ($regOk) { $r.pendingReboot=if($pending){'Pending'}else{'OK'} }
            $lm=Invoke-CimMethod -CimSession $cim -Namespace root\default -ClassName StdRegProv -MethodName GetDWORDValue -Arguments @{ hDefKey=[uint32]2147483650; sSubKeyName='SYSTEM\CurrentControlSet\Control\Lsa'; sValueName='LmCompatibilityLevel' } -ErrorAction SilentlyContinue
            if ($lm -and $lm.ReturnValue -eq 0 -and $lm.uValue -ne $null) {
                $r.ntlmv1=if($lm.uValue -lt 3){'Enabled (level '+$lm.uValue+')'}else{'Disabled (level '+$lm.uValue+')'}
            } elseif ($lm -and $lm.ReturnValue -eq 0) {
                # value exists but is 0 - which is NTLMv1 enabled
                $r.ntlmv1='Enabled (level 0)'
            }
            # NTP source (configured NtpServer under W32Time Parameters)
            $ntp=Invoke-CimMethod -CimSession $cim -Namespace root\default -ClassName StdRegProv -MethodName GetStringValue -Arguments @{ hDefKey=[uint32]2147483650; sSubKeyName='SYSTEM\CurrentControlSet\Services\W32Time\Parameters'; sValueName='NtpServer' } -ErrorAction SilentlyContinue
            if ($ntp -and $ntp.ReturnValue -eq 0 -and $ntp.sValue) {
                # Strip the ",0x9" flags that AD DCs append
                $r.ntpSource=($ntp.sValue -split '\s+' | ForEach-Object { ($_ -split ',')[0] } | Where-Object { $_ }) -join ', '
            }
        } catch {}
        try { Remove-CimSession $cim -ErrorAction SilentlyContinue } catch {}
    }

    # SMB shares
    try { $r.sysvolShare=if(Test-Path "\\$HostName\SYSVOL" -EA SilentlyContinue){'OK'}else{'Fail'} } catch {}
    try { $r.netlogonShare=if(Test-Path "\\$HostName\NETLOGON" -EA SilentlyContinue){'OK'}else{'Fail'} } catch {}

    # Replication failures + oldest partner delay (worst-case time since last successful replication)
    try { $rf=Get-ADReplicationFailure -Target $HostName -ErrorAction SilentlyContinue; $r.replErrors=if($rf){@($rf).Count}else{0} } catch {}
    try {
        $meta=@(Get-ADReplicationPartnerMetadata -Target $HostName -Scope Server -ErrorAction SilentlyContinue)
        if ($meta.Count -gt 0) {
            $now=Get-Date
            $oldestHours=0.0
            foreach ($p in $meta) {
                if ($p.LastReplicationSuccess -and $p.LastReplicationSuccess.Year -gt 1900) {
                    $h=($now - $p.LastReplicationSuccess).TotalHours
                    if ($h -gt $oldestHours) { $oldestHours=$h }
                }
            }
            if ($oldestHours -lt 1) { $r.maxReplDelayH="$([math]::Round($oldestHours*60,0)) min" }
            elseif ($oldestHours -lt 48) { $r.maxReplDelayH="$([math]::Round($oldestHours,1)) h" }
            else { $r.maxReplDelayH="$([math]::Round($oldestHours/24,1)) d" }
        }
    } catch {}

    # dcdiag (key tests). Parse the dotted result lines with word boundaries so
    # e.g. "Services" doesn't mis-match and report a false failure.
    try {
        $short = $HostName.Split('.')[0]
        $raw = & dcdiag /s:$HostName /test:Connectivity /test:Advertising /test:Replications /test:Services /test:FSMOCheck /test:SysVolCheck 2>&1 | Out-String
        $parts=@()
        foreach ($t in @('Connectivity','Advertising','Replications','Services','FsmoCheck','SysVolCheck')) {
            # Match the result line: ".......... <DC> passed|failed test <Test>" with a word boundary after the test name
            if ($raw -match "(?im)\b(passed|failed)\s+test\s+$t\b") {
                $parts += "${t}:$(if($Matches[1] -ieq 'passed'){'Pass'}else{'Fail'})"
            } else {
                $parts += "${t}:"
            }
        }
        $r.dcdiag = $parts -join '|'
    } catch {}

    return $r
}

Write-Host "  Querying AD for topology data..." -ForegroundColor Yellow
$orphanedDCs = @()
try {
    $Forest  = Get-ADForest -ErrorAction Stop
    $ADTopo  = @()
    $Domains = @()
    $LocalName = $env:COMPUTERNAME

    # ── Orphaned NTDS metadata detection (config partition vs real DCs) ──
    Write-Host "  Checking for orphaned DC metadata..." -ForegroundColor Yellow
    try {
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $ntdsObjs = @(Get-ADObject -SearchBase "CN=Sites,$configNC" -LDAPFilter '(objectClass=nTDSDSA)' -ErrorAction SilentlyContinue)
        $ntdsServers = @()
        foreach ($n in $ntdsObjs) {
            # NTDS Settings DN: CN=NTDS Settings,CN=<DC>,CN=Servers,CN=<Site>,CN=Sites,...
            # Server object = parent of NTDS Settings
            $serverDN = ($n.DistinguishedName -split ',',2)[1]
            $rdns = $serverDN -split ','
            # rdns[0] = CN=<DC>; site is the RDN immediately before "CN=Sites"
            $srvName = ($rdns[0]) -replace '^CN='
            $srvSite = 'Unknown'
            for ($k=0; $k -lt $rdns.Count; $k++) {
                if ($rdns[$k] -eq 'CN=Sites' -and $k -ge 1) { $srvSite = ($rdns[$k-1]) -replace '^CN='; break }
            }
            $ntdsServers += [PSCustomObject]@{ name=$srvName; site=$srvSite; dn=$serverDN }
        }
        $realDCNames = @((Get-ADDomainController -Filter * -ErrorAction SilentlyContinue) | ForEach-Object { $_.Name })
        foreach ($srv in $ntdsServers) {
            if ($realDCNames -notcontains $srv.name) {
                Write-Host "    ORPHAN: $($srv.name) (site $($srv.site)) - in Sites&Services but not a replicating DC" -ForegroundColor Red
                $orphanedDCs += @{ name=$srv.name; site=$srv.site; reason='NTDS Settings object exists in Sites & Services but this DC is not in the replicating DC list (likely a failed/incomplete demotion - needs metadata cleanup)' }
            }
        }
        Write-Host "    NTDS objects: $($ntdsServers.Count), real DCs: $($realDCNames.Count), orphaned: $($orphanedDCs.Count)" -ForegroundColor DarkGray
    } catch {
        Write-Host "    Orphan check failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    foreach ($DomainName in $Forest.Domains) {
        try { $Domain = Get-ADDomain -Identity $DomainName -Server $DomainName -ErrorAction Stop }
        catch { Write-Warning "  Skipping domain '$DomainName': $($_.Exception.Message)"; continue }

        $AllDCs   = @(Get-ADDomainController -Filter * -Server $DomainName -ErrorAction SilentlyContinue)
        $AllSites = @(Get-ADReplicationSite  -Filter * -Server $DomainName -ErrorAction SilentlyContinue)

        $SiteNames = @($AllSites | ForEach-Object { $_.Name })
        foreach ($DC in $AllDCs) {
            if ($DC.Site -and ($SiteNames -notcontains $DC.Site)) {
                $AllSites += [PSCustomObject]@{ Name = $DC.Site; Description = "Site: $($DC.Site)" }
                $SiteNames += $DC.Site
            }
        }

        $Sites = @()
        foreach ($Site in $AllSites) {
            $DCs = @()
            $SiteDCs = @($AllDCs | Where-Object { $_.Site -eq $Site.Name })
            foreach ($DC in $SiteDCs) {
                $Roles = @()
                if ($Domain.PDCEmulator          -eq $DC.HostName) { $Roles += "PDC" }
                if ($Domain.RIDMaster            -eq $DC.HostName) { $Roles += "RID" }
                if ($Domain.InfrastructureMaster -eq $DC.HostName) { $Roles += "Infra" }
                if ($Forest.SchemaMaster         -eq $DC.HostName) { $Roles += "Schema" }
                if ($Forest.DomainNamingMaster   -eq $DC.HostName) { $Roles += "DN" }
                if ($DC.IsGlobalCatalog)                           { $Roles += "GC" }

                Write-Host "    collecting $($DC.HostName.Split('.')[0])..." -ForegroundColor DarkGray
                try {
                    $H = Get-DCLiveHealth -HostName $DC.HostName -LocalName $LocalName
                } catch {
                    Write-Host "      (collection error for $($DC.HostName.Split('.')[0]): $($_.Exception.Message))" -ForegroundColor DarkYellow
                    $H = [ordered]@{ status='Unreachable'; collectVia='None'; uptime='N/A'; pendingReboot='N/A'; ntlmv1='N/A'; ntds='N/A'; kdc='N/A'; adws='N/A'; netlogon='N/A'; w32time='N/A'; ramTotalGB='N/A'; ramFreePct='N/A'; cpuFreePct='N/A'; osDiskFreeGB='N/A'; osDiskFreePct='N/A'; timeSkew='N/A'; sysvolShare='N/A'; netlogonShare='N/A'; replErrors='N/A'; maxReplDelayH='N/A'; dcdiag='' }
                }

                $DCs += @{
                    name             = $DC.HostName
                    ip               = if ($DC.IPv4Address) { $DC.IPv4Address } else { "Unknown" }
                    roles            = if ($Roles.Count -gt 0) { $Roles } else { @("DC") }
                    os               = $DC.OperatingSystem
                    site             = $DC.Site
                    isGC             = $DC.IsGlobalCatalog
                    isRODC           = $DC.IsReadOnly
                    status           = $H.status
                    collectVia       = $H.collectVia
                    uptime           = $H.uptime
                    pendingReboot    = "$($H.pendingReboot)"
                    ntlmv1           = "$($H.ntlmv1)"
                    ntdsService      = "$($H.ntds)"
                    kdcService       = "$($H.kdc)"
                    adwsService      = "$($H.adws)"
                    netlogonService  = "$($H.netlogon)"
                    w32timeService   = "$($H.w32time)"
                    ramTotalGB       = "$($H.ramTotalGB)"
                    ramFreePercent   = "$($H.ramFreePct)"
                    cpuFreePercent   = "$($H.cpuFreePct)"
                    osDriveFreeGB    = "$($H.osDiskFreeGB)"
                    osDriveFreePC    = "$($H.osDiskFreePct)"
                    replErrors       = "$($H.replErrors)"
                    maxReplDelayH    = "$($H.maxReplDelayH)"
                    sysvolReplMethod = if ($H.sysvolShare -eq 'OK') { 'Share OK' } else { "$($H.sysvolShare)" }
                    timeDiff         = if ($H.timeSkew -ne 'N/A') { "$($H.timeSkew)s" } else { 'N/A' }
                    ntpSource        = "$($H.ntpSource)"
                    dcdiag           = $H.dcdiag
                }
            }
            if ($DCs.Count -gt 0) {
                $Sites += @{
                    siteName          = $Site.Name
                    description       = if ($Site.Description) { $Site.Description } else { "Site: $($Site.Name)" }
                    domainControllers = $DCs
                }
            }
        }

        $Domains += @{
            domainName            = $Domain.DNSRoot
            domainFunctionalLevel = "$($Domain.DomainMode)"
            netbiosName           = $Domain.NetBIOSName
            sites                 = $Sites
        }
    }

    $ADTopo += @{
        forestName            = $Forest.Name
        forestFunctionalLevel = "$($Forest.ForestMode)"
        rootDomain            = $Forest.RootDomain
        domains               = $Domains
        orphanedDCs           = $orphanedDCs
    }

    $TopologyJSON = ConvertTo-Json -InputObject @($ADTopo) -Depth 12 -Compress
    $totalDCs = @($ADTopo.domains.sites.domainControllers).Count
    Write-Host "  Topology built ($totalDCs DCs, $($orphanedDCs.Count) orphaned metadata object(s))" -ForegroundColor Green
} catch {
    Write-Warning "AD query failed: $($_.Exception.Message)"
    Write-Host "  Error at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    Write-Host "  Full error: $($_.Exception.GetType().FullName)" -ForegroundColor Red
    # If we got partial data, still try to use it rather than blanking the canvas
    if ($ADTopo -and $ADTopo.Count -gt 0) {
        Write-Host "  Using partial topology that was collected before the error." -ForegroundColor Yellow
        try { $TopologyJSON = ConvertTo-Json -InputObject @($ADTopo) -Depth 12 -Compress } catch { $TopologyJSON = '[]' }
    } else {
        $TopologyJSON = '[]'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. SITE LINKS JSON (always live)
# ─────────────────────────────────────────────────────────────────────────────
$SiteLinksJSON = "[]"
try {
    $links = @(Get-ADReplicationSiteLink -Filter * -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            Name                          = $_.Name
            Cost                          = $_.Cost
            ReplicationFrequencyInMinutes = $_.ReplicationFrequencyInMinutes
            SitesIncluded                 = ($_.SitesIncluded | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }) -join ", "
            ReplicationSchedule           = if ($_.ReplicationSchedule) { "Custom" } else { "Always Available" }
            InterSiteTransport            = "IP"
        }
    })
    if ($links.Count -gt 0) { $SiteLinksJSON = ConvertTo-Json -InputObject $links -Depth 5 -Compress }
} catch {}

# ─────────────────────────────────────────────────────────────────────────────
# 3. REPLICATION ISSUES JSON (opportunistic &mdash; only present if ADAudit ran)
# ─────────────────────────────────────────────────────────────────────────────
$ReplJSON = "[]"
if ($AuditResults -and $AuditResults.ReplicationHealth -is [array]) {
    $ReplJSON = ConvertTo-Json -InputObject @($AuditResults.ReplicationHealth) -Depth 5 -Compress
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. SUBNET MAP JSON (always live)
# ─────────────────────────────────────────────────────────────────────────────
$SubnetsJSON = "{}"
$SubnetMap = @{}
try {
    foreach ($site in (Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue)) {
        $subnets = Get-ADReplicationSubnet -Filter "Site -eq '$($site.Name)'" -ErrorAction SilentlyContinue
        $SubnetMap[$site.Name] = if ($subnets) { ($subnets | ForEach-Object { $_.Name }) -join ", " } else { "" }
    }
} catch {}
if ($SubnetMap.Count -gt 0) { $SubnetsJSON = $SubnetMap | ConvertTo-Json -Compress }

# ─────────────────────────────────────────────────────────────────────────────
# 5. REPLICATION HEALTH MATRIX (passive - reads metadata AD already tracks)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "  Building replication health matrix..." -ForegroundColor Yellow

# Enumerate every DC in EVERY domain of the forest (Get-ADDomainController -Filter *
# on its own only returns the CURRENT domain's DCs).
$AllDCObjs = @()
try {
    $forestDomains = @((Get-ADForest -ErrorAction Stop).Domains)
} catch {
    $forestDomains = @()
}
if ($forestDomains.Count -eq 0) {
    try { $forestDomains = @((Get-ADDomain -ErrorAction Stop).DNSRoot) } catch {}
}
foreach ($domDNS in $forestDomains) {
    try { $AllDCObjs += @(Get-ADDomainController -Filter * -Server $domDNS -ErrorAction SilentlyContinue) } catch {}
}
$AllDCObjs = @($AllDCObjs | Sort-Object -Property Name -Unique | Sort-Object Site,Name)
$DCList = @($AllDCObjs | ForEach-Object { [PSCustomObject]@{ short=$_.Name; fqdn=$_.HostName; site=$_.Site } })
Write-Host "    $($DCList.Count) DC(s) across $($forestDomains.Count) domain(s)" -ForegroundColor DarkGray

# Friendly text for common replication error codes.
function Get-ReplErrorText {
    param([int]$code)
    switch ($code) {
        0     { 'Success' }
        5     { 'Access denied' }
        1256  { 'Remote system not available (target DC unreachable)' }
        1722  { 'RPC server unavailable (port/firewall blocked or DC down)' }
        1753  { 'No endpoints available from endpoint mapper (RPC/port issue)' }
        8451  { 'Replication encountered a database error' }
        8452  { 'Naming context in process of being removed' }
        8453  { 'Replication access denied (permissions)' }
        8456  { 'Source DC currently rejecting replication requests' }
        8457  { 'Destination DC currently rejecting replication requests' }
        8461  { 'Replication is blocked until initial sync completes' }
        8524  { 'DSA operation failed - DNS lookup failure (check DNS/SRV records)' }
        8545  { 'Replication cannot proceed - schema mismatch' }
        8606  { 'Insufficient attributes to create object (lingering object)' }
        8614  { 'Replication has not occurred within the tombstone lifetime' }
        default { "Replication error $code" }
    }
}
# Short partition label from a naming-context DN.
function Get-PartitionLabel {
    param([string]$dn)
    if (-not $dn) { return '?' }
    if ($dn -match '^CN=Schema,')        { return 'Schema' }
    if ($dn -match '^CN=Configuration,')  { return 'Configuration' }
    if ($dn -match '^DC=ForestDnsZones,') { return 'ForestDnsZones' }
    if ($dn -match '^DC=DomainDnsZones,') { return 'DomainDnsZones' }
    if ($dn -match '^DC=') { return (($dn -split ',')[0] -replace 'DC=','') }
    return (($dn -split ',')[0])
}
# Look up a DC's site by its short name (case-insensitive).
function Get-DCSite {
    param([string]$short)
    $m = $DCList | Where-Object { $_.short -eq $short } | Select-Object -First 1
    if ($m) { return $m.site } else { return '' }
}

$ReplMatrix = @()          # one row per (source -> destination -> partition)
$UnknownPartners = @()     # partners reported by AD that are not in $DCList
$MatrixSourceNote = 'ADWS' # which mechanism produced the data

foreach ($dc in $DCList) {
    $partners = $null
    $viaRepadmin = $false

    # Primary path: AD Web Services (TCP 9389). Ask for EVERY partition, not just the
    # default naming context - Configuration/Schema failures are otherwise invisible.
    try {
        $partners = @(Get-ADReplicationPartnerMetadata -Target $dc.fqdn -Scope Server -PartnerType Inbound -Partition * -ErrorAction Stop)
    } catch {
        $partners = $null
    }

    # Fallback: repadmin uses RPC (135 + dynamic), a DIFFERENT path from ADWS. In hardened
    # networks one often works when the other does not, so try it before giving up.
    if ($null -eq $partners) {
        try {
            $csv = & repadmin /showrepl $dc.fqdn /csv 2>$null
            if ($LASTEXITCODE -eq 0 -and $csv) {
                $rows = @($csv | ConvertFrom-Csv | Where-Object { $_.'Showrepl_COLUMNS' -eq 'Showrepl_INFO' })
                if ($rows.Count -gt 0) {
                    $partners = @($rows | ForEach-Object {
                        $ls = $null; $lf = $null
                        if ($_.'Last Success Time') { try { $ls = [datetime]$_.'Last Success Time' } catch {} }
                        [PSCustomObject]@{
                            PartnerShort                  = "$($_.'Source DSA')"
                            PartitionDN                   = "$($_.'Naming Context')"
                            LastReplicationSuccess        = $ls
                            LastReplicationResult         = [int]("0$($_.'Last Failure Status')")
                            ConsecutiveReplicationFailures= [int]("0$($_.'Number of Failures')")
                        }
                    })
                    $viaRepadmin = $true
                }
            }
        } catch { $partners = $null }
    }

    if ($null -eq $partners) {
        # Neither ADWS nor repadmin could read this DC. Its INBOUND partnerships are unknown,
        # so it is unqueryable as a DESTINATION (its column) - not as a source.
        $ReplMatrix += [ordered]@{
            src='(unqueryable)'; dst=$dc.short; srcSite=''; dstSite=$dc.site
            partition='-'; lastSuccess=''; lastError=1256
            errorText='Could not read this DC''s replication metadata over ADWS (TCP 9389) or repadmin/RPC. Its inbound replication partnerships are unknown.'
            failures=0; state='unqueryable'; direction='inbound'
        }
        continue
    }

    foreach ($p in $partners) {
        # --- source DC short name ---
        $partnerShort = ''
        if ($viaRepadmin) {
            $partnerShort = "$($p.PartnerShort)"
        } elseif ($p.Partner) {
            # Partner DN: CN=NTDS Settings,CN=DC02,CN=Servers,CN=<site>,CN=Sites,...
            if ("$($p.Partner)" -match 'CN=NTDS Settings,CN=([^,]+),') { $partnerShort = $Matches[1] }
            else { $partnerShort = (("$($p.Partner)" -split ',')[0]) -replace 'CN=','' }
        }
        if (-not $partnerShort) { continue }

        # Track partners AD reports that we never enumerated, instead of silently dropping them.
        if (-not ($DCList | Where-Object { $_.short -eq $partnerShort })) {
            if ($UnknownPartners -notcontains $partnerShort) { $UnknownPartners += $partnerShort }
        }

        # --- result code / failures / last success ---
        $code = 0
        if ($null -ne $p.LastReplicationResult) { $code = [int]$p.LastReplicationResult }
        $consecFail = 0
        if ($null -ne $p.ConsecutiveReplicationFailures) { $consecFail = [int]$p.ConsecutiveReplicationFailures }

        $lastOk = ''
        $everReplicated = $false
        if ($p.LastReplicationSuccess -and $p.LastReplicationSuccess.Year -gt 1900) {
            $lastOk = $p.LastReplicationSuccess.ToString('yyyy-MM-dd HH:mm')
            $everReplicated = $true
        }

        # --- partition ---
        $partDN = if ($viaRepadmin) { "$($p.PartitionDN)" } else { "$($p.Partition)" }
        $partition = Get-PartitionLabel -dn $partDN

        # --- site-aware delay threshold ---
        # Intra-site replication runs every ~15s-1min. Inter-site follows the site-link
        # schedule, whose DEFAULT is 180 minutes - so a flat 3h threshold produced false
        # "delayed" flags on perfectly healthy inter-site partners.
        $partnerSite = Get-DCSite -short $partnerShort
        $sameSite = ($partnerSite -and $partnerSite -eq $dc.site)
        $delayLimitH = if ($sameSite) { $ReplDelayIntraSiteHours } else { $ReplDelayInterSiteHours }

        $state = 'ok'
        $errText = Get-ReplErrorText -code $code
        if ($code -ne 0 -or $consecFail -gt 0) {
            $state = 'fail'
        } elseif (-not $everReplicated) {
            # No error recorded, but replication has never succeeded on this partition.
            $state = 'fail'
            $errText = 'No successful replication has ever been recorded for this partition (initial sync may not have completed).'
        } elseif ($p.LastReplicationSuccess -lt (Get-Date).AddHours(-$delayLimitH)) {
            $state = 'delayed'
            $errText = "Last successful replication is older than the $delayLimitH h threshold for a $(if($sameSite){'intra-site'}else{'inter-site'}) partner."
        }

        $ReplMatrix += [ordered]@{
            src=$partnerShort; dst=$dc.short; srcSite=$partnerSite; dstSite=$dc.site
            partition=$partition; lastSuccess=$lastOk; lastError=$code
            errorText=$errText; failures=$consecFail
            state=$state; direction='inbound'; via=$(if($viaRepadmin){'repadmin'}else{'ADWS'})
        }
    }
    if ($viaRepadmin) { $MatrixSourceNote = 'ADWS + repadmin fallback' }
}

# Any partner AD reported that we did not enumerate still deserves a row/column.
foreach ($u in $UnknownPartners) {
    if (-not ($DCList | Where-Object { $_.short -eq $u })) {
        $DCList += [PSCustomObject]@{ short=$u; fqdn=$u; site='(not enumerated)' }
        Write-Host "    note: partner '$u' was reported by AD but is not an enumerated DC - added to the matrix" -ForegroundColor DarkYellow
    }
}

$ReplMeta = [ordered]@{
    via              = $MatrixSourceNote
    partitionsChecked= 'all (domain, configuration, schema, DNS zones)'
    intraSiteDelayH  = $ReplDelayIntraSiteHours
    interSiteDelayH  = $ReplDelayInterSiteHours
    domains          = $forestDomains.Count
}
$ReplMatrixJSON = if ($ReplMatrix.Count -gt 0) { ConvertTo-Json -InputObject @($ReplMatrix) -Depth 5 -Compress } else { '[]' }
$DCListJSON     = if ($DCList.Count -gt 0) { ConvertTo-Json -InputObject @($DCList) -Depth 3 -Compress } else { '[]' }
$ReplMetaJSON   = ConvertTo-Json -InputObject $ReplMeta -Compress
Write-Host "    $($ReplMatrix.Count) partnership/partition record(s) across $($DCList.Count) DC(s)" -ForegroundColor DarkGray

# ─────────────────────────────────────────────────────────────────────────────
# 6. STALE / LINGERING OBJECTS (passive - scans Configuration + Sites & Services)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "  Scanning for stale / lingering objects..." -ForegroundColor Yellow
$StaleFindings = @()   # {category, severity, name, detail, dn, remediation}
try {
    $cfgNC   = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
    $liveDCNames = @($AllDCObjs | ForEach-Object { $_.Name })
    $allSites = @(Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue)
    $allSubnets = @(Get-ADReplicationSubnet -Filter * -Properties Site -ErrorAction SilentlyContinue)

    # a) Orphaned NTDS Settings / server objects (server object with no live DC)
    try {
        $serverObjs = @(Get-ADObject -SearchBase "CN=Sites,$cfgNC" -LDAPFilter '(objectClass=server)' -Properties name,distinguishedName -ErrorAction SilentlyContinue)
        foreach ($so in $serverObjs) {
            if ($liveDCNames -notcontains $so.name) {
                $siteName = if ($so.distinguishedName -match 'CN=Servers,CN=([^,]+),CN=Sites') { $Matches[1] } else { '?' }
                $StaleFindings += [ordered]@{
                    category='Orphaned DC metadata'; severity='high'; name=$so.name
                    detail="Server object in site '$siteName' has no matching live domain controller."
                    dn=$so.distinguishedName
                    remediation="Verify the DC is truly decommissioned, then run: ntdsutil metadata cleanup (or remove via AD Sites &amp; Services)."
                }
            }
        }
    } catch {}

    # b) Empty sites (no DCs)
    foreach ($site in $allSites) {
        $dcInSite = @($AllDCObjs | Where-Object { $_.Site -eq $site.Name })
        if ($dcInSite.Count -eq 0) {
            $StaleFindings += [ordered]@{
                category='Empty site'; severity='medium'; name=$site.Name
                detail="Site has no domain controllers."
                dn="$($site.DistinguishedName)"
                remediation="If the site is no longer used, remove it (and its subnets/site links). If intentional (e.g. a client-only site), no action needed."
            }
        }
    }

    # c) Sites with no subnets
    foreach ($site in $allSites) {
        $subForSite = @($allSubnets | Where-Object { "$($_.Site)" -match "CN=$([regex]::Escape($site.Name))," })
        if ($subForSite.Count -eq 0) {
            $StaleFindings += [ordered]@{
                category='Site without subnets'; severity='low'; name=$site.Name
                detail="Site has no associated subnets - clients may not map to it correctly."
                dn="$($site.DistinguishedName)"
                remediation="Associate the correct IP subnet(s) with this site in AD Sites &amp; Services."
            }
        }
    }

    # d) Unlinked subnets (subnet with no site)
    foreach ($sn in $allSubnets) {
        if (-not $sn.Site) {
            $StaleFindings += [ordered]@{
                category='Unlinked subnet'; severity='low'; name=$sn.Name
                detail="Subnet is not associated with any site."
                dn="$($sn.DistinguishedName)"
                remediation="Assign this subnet to the appropriate site, or remove it if obsolete."
            }
        }
    }

    # e) Lingering connection objects (NTDS connection whose 'fromServer' points to a dead server)
    try {
        $connObjs = @(Get-ADObject -SearchBase "CN=Sites,$cfgNC" -LDAPFilter '(objectClass=nTDSConnection)' -Properties fromServer,distinguishedName -ErrorAction SilentlyContinue)
        foreach ($co in $connObjs) {
            if ($co.fromServer -and $co.fromServer -match 'CN=NTDS Settings,CN=([^,]+),') {
                $fromDC = $Matches[1]
                if ($liveDCNames -notcontains $fromDC) {
                    $StaleFindings += [ordered]@{
                        category='Lingering replication connection'; severity='medium'; name="from $fromDC"
                        detail="A replication connection object references source server '$fromDC', which is not a live DC."
                        dn="$($co.distinguishedName)"
                        remediation="Remove the stale connection object; the KCC will rebuild valid connections automatically."
                    }
                }
            }
        }
    } catch {}

} catch {
    Write-Host "    Stale-object scan limited: $($_.Exception.Message)" -ForegroundColor DarkYellow
}
$StaleJSON = if ($StaleFindings.Count -gt 0) { ConvertTo-Json -InputObject @($StaleFindings) -Depth 5 -Compress } else { '[]' }
Write-Host "    $($StaleFindings.Count) stale/lingering finding(s)" -ForegroundColor DarkGray

# ─────────────────────────────────────────────────────────────────────────────
# 7. META
# ─────────────────────────────────────────────────────────────────────────────
$ForestName = try { (Get-ADForest -ErrorAction Stop).Name } catch { "Active Directory" }

Write-Host "  Rendering HTML..." -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# 6. HTML OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Infrastructure Topology &mdash; $ForestName</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg:#0d1117; --surface:#161b22; --surface2:#21262d; --border:#30363d;
  --text:#e6edf3; --muted:#8b949e;
  --blue:#58a6ff; --green:#3fb950; --yellow:#d29922; --red:#f85149;
  --purple:#bc8cff; --teal:#39d3c3;
  --forest-c:#388bfd; --domain-c:#3fb950; --site-c:#8b949e;
}
[data-theme="light"] {
  --bg:#f5f6fb; --surface:#ffffff; --surface2:#eef1f9; --surface3:#dfe4f2; --border:#e4e7f2; --text:#161a2e; --muted:#64708c;
  --accent:#4f46e5; --accent-2:#6366f1; --accent-soft:#e6e6fd; --navy:#3730a3; --violet:#6d28d9; --fuchsia:#c026d3;
  --green:#059669; --green-soft:#d1fae5; --red:#dc2626; --red-soft:#fde2e2; --amber:#d97706; --amber-soft:#fef3c7; --yellow:#d97706;
  --blue:#2563eb; --blue-soft:#dbe8fe; --teal:#0d9488; --teal-soft:#cdeee9; --purple:#7c3aed; --purple-soft:#ede9fe; --pink:#db2777; --pink-soft:#fce7f3; --cyan:#0891b2; --cyan-soft:#cffafe;
  --forest-c:#4f46e5; --domain-c:#059669; --site-c:#5b6b8c;
  --radius:13px; --radius-sm:9px;
  --shadow:0 2px 8px rgb(60 50 140 / 0.06), 0 1px 2px rgb(60 50 140 / 0.04);
  --shadow-hover:0 9px 26px rgb(60 50 140 / 0.14);
  --font:'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --mono:'SFMono-Regular', ui-monospace, Menlo, Consolas, monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.topo-view{height:calc(100vh - 48px);display:flex;flex-direction:column;position:relative}
.scrolldown{position:absolute;bottom:46px;left:50%;transform:translateX(-50%);z-index:60;display:flex;flex-direction:column;align-items:center;gap:2px;background:var(--surface);border:1px solid var(--border);color:var(--accent,var(--forest-c));border-radius:22px;padding:7px 16px;cursor:pointer;font-size:11px;font-weight:600;box-shadow:var(--shadow,0 4px 14px rgba(0,0,0,.12));transition:transform .15s ease,box-shadow .15s ease}
.scrolldown:hover{transform:translateX(-50%) translateY(2px);box-shadow:var(--shadow-hover,0 8px 22px rgba(0,0,0,.18))}
.scrolldown i{font-size:15px;animation:bob 1.6s ease-in-out infinite}
@keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(3px)}}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:8px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;position:sticky;top:0;z-index:100;min-height:48px}
.brand{display:flex;align-items:center;gap:7px;font-size:13px;font-weight:700;color:var(--text);white-space:nowrap}
.brand i{color:var(--blue);font-size:17px}
.sep{width:1px;height:22px;background:var(--border);flex-shrink:0}
.search{display:flex;align-items:center;gap:5px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:4px 9px;flex:1;min-width:160px;max-width:260px}
.search input{background:none;border:none;outline:none;color:var(--text);font-size:12px;width:100%}
.search input::placeholder{color:var(--muted)}
.search i{color:var(--muted);font-size:12px}
.bgrp{display:flex;gap:4px;flex-wrap:wrap}
.btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:5px;font-size:11px;cursor:pointer;display:flex;align-items:center;gap:4px;transition:all .15s;white-space:nowrap}
.btn:hover{background:var(--border)}
.btn.on{background:var(--blue);border-color:var(--blue);color:#fff}
.btn.grn{border-color:var(--green);color:var(--green)}.btn.grn:hover{background:var(--green);color:#fff}
.meta{font-size:10px;color:var(--muted);margin-left:auto;white-space:nowrap}
.cw{flex:1;position:relative;overflow:hidden;cursor:grab;margin:0 56px;border:1px solid var(--border);border-radius:12px;background:var(--surface);box-shadow:var(--shadow)}
.cw.drag{cursor:grabbing}
.grid-bg{position:absolute;inset:0;border-radius:12px;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:40px 40px;opacity:.18;pointer-events:none}
#replSvg{position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:5}
.cc{position:absolute;top:0;left:0;transform-origin:0 0;padding:50px;display:flex;flex-direction:column;gap:50px}
.fb{position:relative;border:2px solid var(--forest-c);border-radius:14px;background:color-mix(in srgb,var(--forest-c) 5%,var(--surface));padding:44px 28px 28px;min-width:400px}
.ftag{position:absolute;top:-13px;left:22px;background:var(--forest-c);color:#fff;font-size:10px;font-weight:700;padding:2px 11px;border-radius:20px;display:flex;align-items:center;gap:4px;letter-spacing:.4px}
.fn{font-size:12px;font-weight:700;color:var(--forest-c);margin-bottom:2px}
.ffl{font-size:10px;color:var(--muted);margin-bottom:16px}
.orphan-banner{background:color-mix(in srgb,var(--red) 10%,var(--surface));border:1px solid var(--red);border-radius:10px;padding:12px 14px;margin-bottom:16px}
.orphan-head{font-size:12px;font-weight:700;color:var(--red);display:flex;align-items:center;gap:7px;margin-bottom:8px}
.orphan-item{font-size:11px;padding:6px 0;border-top:1px solid color-mix(in srgb,var(--red) 25%,transparent)}
.orphan-site{color:var(--muted);font-weight:400}
.orphan-reason{font-size:10px;color:var(--muted);margin-top:2px}
.orphan-fix{font-size:10px;color:var(--text);margin-top:8px;padding-top:8px;border-top:1px solid color-mix(in srgb,var(--red) 25%,transparent)}
.orphan-fix code{background:var(--surface2);padding:1px 5px;border-radius:3px;font-size:10px}
.db{border:1.5px solid var(--domain-c);border-radius:11px;background:color-mix(in srgb,var(--domain-c) 4%,var(--surface));padding:38px 22px 22px;position:relative;margin-bottom:16px}
.dtag{position:absolute;top:-11px;left:18px;background:var(--domain-c);color:#fff;font-size:9px;font-weight:700;padding:2px 9px;border-radius:20px;display:flex;align-items:center;gap:3px}
.dn-name{font-size:11px;font-weight:700;color:var(--domain-c);margin-bottom:2px}
.dn-fl{font-size:10px;color:var(--muted);margin-bottom:14px}
.fl-good{--domain-c:var(--green)}
.fl-warn{--domain-c:var(--yellow)}
.fl-bad {--domain-c:var(--red)}
.sr{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start}
.sb{background:var(--surface2);border:1px solid var(--border);border-radius:9px;min-width:190px;max-width:300px;overflow:hidden}
.sb:hover{box-shadow:0 0 0 1px var(--site-c)}
.sh{background:var(--site-c);padding:5px 10px;display:flex;align-items:center;gap:5px;cursor:pointer;transition:filter .15s}
.sh:hover{filter:brightness(1.15)}
.sh-name{font-size:10px;font-weight:700;color:#fff}
.sbody{padding:10px}
.subnets{font-size:9px;color:var(--muted);margin-bottom:8px;font-family:monospace;line-height:1.5;max-height:48px;overflow:hidden}
.subnet-more{color:var(--blue);font-weight:700;font-family:'Inter',sans-serif}
.dcgrid{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-start}
.dcc{position:relative;width:78px;display:flex;flex-direction:column;align-items:center;gap:3px;padding:7px 5px;border-radius:7px;background:var(--surface);border:1px solid var(--border);cursor:pointer;transition:all .18s}
.dcc:hover{border-color:var(--blue);transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.3)}
.dcc.off{border-color:var(--red)!important;background:color-mix(in srgb,var(--red) 8%,var(--surface))}
.dcc.unreach{border-color:var(--muted)!important;opacity:.55}
.dcc.dim{opacity:.18;pointer-events:none}
.dcc.hi{box-shadow:0 0 0 2px var(--yellow)}
.iw{position:relative;width:44px;height:50px;display:flex;align-items:center;justify-content:center}
.srv{width:40px;height:50px;border-radius:4px;position:relative;border:3px solid;display:flex;flex-direction:column;justify-content:flex-start;align-items:center;padding-top:5px;gap:3px}
.srv.h-ok  {border-color:var(--green)}
.srv.h-warn{border-color:var(--yellow)}
.srv.h-bad {border-color:var(--red)}
.srv.gc-icon{background:color-mix(in srgb,var(--blue) 15%,var(--surface2))}
.srv.dc-icon{background:#1f2937}
.srv.off-icon{background:color-mix(in srgb,var(--red) 12%,var(--surface2))}
.gc-badge{position:absolute;bottom:-3px;right:-3px;width:12px;height:12px;border-radius:50%;background:var(--blue);border:2px solid var(--surface);display:flex;align-items:center;justify-content:center}
.gc-badge i{font-size:6px;color:#fff}
.led{width:22px;height:2px;border-radius:1px;background:var(--green)}
.led.r{background:var(--red)}
.disk{width:22px;height:5px;border-radius:1px;background:var(--surface);border:1px solid var(--border);margin-top:2px}
.dc-lbl{font-size:8px;font-weight:700;color:var(--text);text-align:center;line-height:1.2;max-width:76px;word-break:break-all}
.pills{display:flex;flex-wrap:wrap;gap:2px;justify-content:center}
.pill{font-size:6px;font-weight:700;color:#fff;padding:1px 3px;border-radius:2px;text-transform:uppercase;letter-spacing:.3px}
.p-pdc{background:#dc2626}.p-rid{background:#ea580c}.p-infra{background:#0891b2}
.p-schema{background:#7c3aed}.p-dn{background:#6366f1}.p-gc{background:#0d9488}
.p-dc{background:#475569}.p-rodc{background:#d97706}
.p-offline,.p-unreachable{background:#6b7280}
.reboot-dot{position:absolute;top:2px;right:2px;width:7px;height:7px;border-radius:50%;background:var(--yellow);border:1px solid var(--bg);animation:pulse 2s infinite}
.ntlm-dot{position:absolute;top:2px;left:2px;width:7px;height:7px;border-radius:50%;background:var(--red);border:1px solid var(--bg)}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.35)}}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:200}
.overlay.on{display:block}
.panel{position:fixed;top:0;right:0;width:370px;height:100vh;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .22s ease;overflow:hidden}
.panel.on{transform:translateX(0)}
.ph{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;background:var(--surface2)}
.ph-title{font-size:13px;font-weight:700;color:var(--text)}
.ph-sub{font-size:10px;color:var(--muted);margin-top:2px}
.pclose{background:none;border:none;color:var(--muted);cursor:pointer;font-size:17px;line-height:1;padding:0}
.pclose:hover{color:var(--text)}
.pbody{flex:1;overflow-y:auto;padding:14px 18px}
.psec{margin-bottom:18px}
.psec-title{font-size:9px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:7px;display:flex;align-items:center;gap:5px}
.psec-title::after{content:'';flex:1;height:1px;background:var(--border)}
.kvg{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.kv{background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:7px 9px}
.kv-k{font-size:9px;color:var(--muted);margin-bottom:2px}
.kv-v{font-size:11px;font-weight:600;color:var(--text);word-break:break-all}
.kv-v.ok{color:var(--green)}.kv-v.warn{color:var(--yellow)}.kv-v.bad{color:var(--red)}.kv-v.info{color:var(--blue)}
.kv-wide{grid-column:span 2}
.svc-row{display:flex;align-items:center;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border);font-size:11px}
.svc-row:last-child{border:none}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0}
.dot.s{background:var(--red)}.dot.u{background:var(--muted)}
.bar-w{background:var(--surface2);border-radius:3px;height:5px;overflow:hidden;margin-top:3px}
.bar-f{height:100%;border-radius:3px;background:var(--green);transition:width .4s}
.bar-f.w{background:var(--yellow)}.bar-f.b{background:var(--red)}
.ddt{display:flex;flex-direction:column;gap:3px}
.ddi{display:flex;align-items:center;gap:6px;font-size:10px;padding:3px 7px;border-radius:3px;background:var(--surface2)}
.ddi.pass{border-left:3px solid var(--green)}.ddi.fail{border-left:3px solid var(--red)}.ddi.unk{border-left:3px solid var(--muted)}
.lb{background:var(--surface);border-top:1px solid var(--border);padding:6px 18px;display:flex;align-items:center;flex-wrap:wrap;gap:16px}
.li{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--muted)}
.ld{width:10px;height:10px;border-radius:50%}
.lsq{width:10px;height:10px;border-radius:2px}
.ltt{position:fixed;background:var(--surface);border:1px solid var(--border);border-radius:5px;padding:7px 11px;font-size:10px;color:var(--text);pointer-events:none;z-index:300;display:none;max-width:210px;line-height:1.6}
.ltt.on{display:block}
/* Analysis sections below the topology */
.analysis{background:var(--bg);border-top:3px solid var(--border);padding:8px 26px 60px}
.asec{max-width:1200px;margin:0 auto;padding:26px 0;border-bottom:1px solid var(--border)}
.asec:last-child{border-bottom:none}
.asec-h{font-size:17px;font-weight:800;display:flex;align-items:center;gap:10px;margin-bottom:6px}
.asec-h i{color:var(--accent,var(--forest-c))}
.rmsub{font-size:12px;color:var(--muted);margin-bottom:16px;line-height:1.6}
.rmsub code{background:var(--surface2);padding:1px 6px;border-radius:4px;font-size:11px}
/* summary chips */
.rchips{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.rchip{background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:9px 14px;min-width:96px}
.rchip .n{font-size:19px;font-weight:800}.rchip .l{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.rchip.g .n{color:var(--green)}.rchip.a .n{color:var(--yellow)}.rchip.r .n{color:var(--red)}
/* matrix */
.mwrap{overflow:auto;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
table.mtx{border-collapse:collapse;font-size:11px;width:100%}
table.mtx th,table.mtx td{border:1px solid var(--border);padding:0;text-align:center}
table.mtx thead th{background:var(--surface2);padding:7px 6px;font-weight:600;white-space:nowrap;position:sticky;top:0;z-index:2}
table.mtx tbody th{background:var(--surface2);padding:7px 10px;text-align:left;font-weight:600;white-space:nowrap;position:sticky;left:0;z-index:1}
.mcell{width:100%;min-width:34px;height:32px;display:flex;align-items:center;justify-content:center;cursor:default;font-size:12px}
.mcell.ok{background:color-mix(in srgb,var(--green) 18%,transparent);color:var(--green)}
.mcell.delayed{background:color-mix(in srgb,var(--yellow) 20%,transparent);color:var(--yellow);cursor:pointer}
.mcell.fail{background:color-mix(in srgb,var(--red) 20%,transparent);color:var(--red);cursor:pointer;font-weight:700}
.mcell.unq{background:color-mix(in srgb,var(--red) 12%,transparent);color:var(--red);cursor:pointer}
.mcell.none{color:var(--border)}
.mcell.self{background:repeating-linear-gradient(45deg,var(--surface2),var(--surface2) 4px,var(--surface) 4px,var(--surface) 8px)}
table.mtx thead th.unq-col{background:color-mix(in srgb,var(--red) 10%,var(--surface2));border-bottom:3px solid var(--red);color:var(--red)}
.unq-badge{display:block;margin-top:3px;padding:1px 7px;font-size:8px;font-weight:600;letter-spacing:.03em;text-transform:uppercase;background:var(--red);color:#fff;border-radius:20px;cursor:pointer}
.unq-badge:hover{filter:brightness(1.08)}
.mlabel{font-size:9px;color:var(--muted);margin:2px 0 12px}
table.pt{width:100%;border-collapse:collapse;font-size:11px;margin-top:10px;background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
table.pt th,table.pt td{border-bottom:1px solid var(--border);padding:6px 10px;text-align:left;vertical-align:top}
table.pt thead th{background:var(--surface2);font-weight:600;color:var(--muted);text-transform:uppercase;font-size:9px;letter-spacing:.04em}
table.pt tbody tr:last-child td{border-bottom:none}
/* stale cards */
.scard{border:1px solid var(--border);border-left-width:3px;border-radius:9px;padding:12px 15px;margin-bottom:10px;background:var(--surface)}
.scard.high{border-left-color:var(--red)}.scard.medium{border-left-color:var(--yellow)}.scard.low{border-left-color:var(--muted)}
.scard-h{display:flex;align-items:center;gap:9px;margin-bottom:5px}
.scard-cat{font-weight:700;font-size:13px}
.sev{font-size:9px;text-transform:uppercase;letter-spacing:.04em;padding:2px 7px;border-radius:20px;font-weight:600}
.sev.high{background:color-mix(in srgb,var(--red) 16%,transparent);color:var(--red)}
.sev.medium{background:color-mix(in srgb,var(--yellow) 18%,transparent);color:var(--yellow)}
.sev.low{background:var(--surface2);color:var(--muted)}
.scard-name{font-family:var(--mono,monospace);font-size:12px;color:var(--accent,var(--forest-c));margin-bottom:3px}
.scard-det{font-size:12px;color:var(--text);line-height:1.5;margin-bottom:6px}
.scard-dn{font-family:var(--mono,monospace);font-size:10px;color:var(--muted);word-break:break-all;margin-bottom:6px}
.scard-fix{font-size:11px;color:var(--muted);background:var(--surface2);border-radius:6px;padding:7px 10px;line-height:1.5}
.scard-fix b{color:var(--text)}
.rempty{text-align:center;padding:40px 20px;color:var(--muted);background:var(--surface);border:1px solid var(--border);border-radius:10px}
.rempty i{font-size:36px;color:var(--green);display:block;margin-bottom:12px}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--surface2)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body data-theme="light">

<div class="topbar">
  <div class="brand"><i class="bi bi-diagram-3-fill"></i>AD Infrastructure Topology</div>
  <div class="sep"></div>
  <div class="search"><i class="bi bi-search"></i><input id="srch" type="text" placeholder="Search DC or site&hellip;" oninput="doSearch(this.value)"></div>
  <div class="bgrp" id="fltBtns">
    <button class="btn" id="f-fsmo"    onclick="flt('fsmo')">   <i class="bi bi-star-fill"></i> FSMO</button>
    <button class="btn" id="f-offline" onclick="flt('offline')"><i class="bi bi-x-circle"></i> Offline</button>
    <button class="btn" id="f-gc"      onclick="flt('gc')">     <i class="bi bi-globe"></i> GC</button>
    <button class="btn" id="f-repl"    onclick="flt('repl')">   <i class="bi bi-arrow-repeat"></i> Repl issues</button>
  </div>
  <div class="sep"></div>
  <div class="bgrp">
    <button class="btn" onclick="doZoom(.1)"  title="Zoom in"><i class="bi bi-zoom-in"></i></button>
    <button class="btn" onclick="doZoom(-.1)" title="Zoom out"><i class="bi bi-zoom-out"></i></button>
    <button class="btn" onclick="fitAll()"    title="Fit all"><i class="bi bi-fullscreen"></i> Fit</button>
    <button class="btn" onclick="resetView()"><i class="bi bi-arrow-counterclockwise"></i></button>
  </div>
  <div class="sep"></div>
  <div class="bgrp">
    <button class="btn" onclick="toggleTheme()"><i class="bi bi-circle-half"></i> Theme</button>
    <button class="btn" id="replBtn" onclick="toggleRepl()"><i class="bi bi-diagram-2"></i> Repl links</button>
  </div>
  <div class="meta">Forest: $ForestName &nbsp;|&nbsp; $GeneratedAt</div>
</div>

<div class="topo-view">
<div class="cw" id="cw">
  <div class="grid-bg"></div>
  <svg id="replSvg"></svg>
  <div class="cc" id="cc"></div>
</div>

<div class="lb">
  <div class="li"><div class="lsq" style="border:2px solid var(--forest-c)"></div>Forest</div>
  <div class="li"><div class="lsq" style="border:2px solid var(--domain-c)"></div>Domain</div>
  <div class="li"><div class="lsq" style="background:var(--site-c)"></div>Site</div>
  <div class="li"><div class="ld" style="background:var(--blue)"></div>GC</div>
  <div class="li"><div class="ld" style="background:#4b5563"></div>DC</div>
  <div class="li"><div class="ld" style="background:var(--red)"></div>Offline</div>
  <div class="li"><div class="ld" style="background:var(--green)"></div>Healthy</div>
  <div class="li"><div class="ld" style="background:var(--yellow)"></div>Warning &nbsp;<small>(&#10227; dot = pending reboot)</small></div>
  <div class="li"><div class="ld" style="background:var(--red)"></div>Critical &nbsp;<small>(&#9679; dot = NTLMv1)</small></div>
  <span style="margin-left:auto;font-size:10px;color:var(--muted)">Click any DC for full details &middot; scroll down for analysis</span>
</div>
<div class="scrolldown" onclick="document.getElementById('sec-repl').scrollIntoView({behavior:'smooth'})" title="Jump to analysis sections"><i class="bi bi-chevron-double-down"></i>Analysis below</div>
</div>

<div class="analysis">
  <section class="asec" id="sec-repl">
    <h2 class="asec-h"><i class="bi bi-grid-3x3-gap"></i> Replication Health Matrix</h2>
    <div id="replBody"></div>
  </section>
  <section class="asec" id="sec-stale">
    <h2 class="asec-h"><i class="bi bi-trash3"></i> Stale / Lingering Objects</h2>
    <div id="staleBody"></div>
  </section>
</div>

<div class="overlay" id="ov" onclick="closePanel()"></div>
<div class="panel" id="panel">
  <div class="ph">
    <div><div class="ph-title" id="ptitle">DC Details</div><div class="ph-sub" id="psub"></div></div>
    <button class="pclose" onclick="closePanel()"><i class="bi bi-x-lg"></i></button>
  </div>
  <div class="pbody" id="pbody"></div>
</div>

<div class="ltt" id="ltt"></div>

<script>
const topo      = $TopologyJSON;
const siteLinks = $SiteLinksJSON;
const replIssues= $ReplJSON;
const subnetMap = $SubnetsJSON;
const replMatrix = $ReplMatrixJSON;
const replMeta   = $ReplMetaJSON;
const dcList     = $DCListJSON;
const staleObjects = $StaleJSON;

// PowerShell's ConvertTo-Json collapses single-element arrays into scalars.
// Normalise the shape so the renderer can always rely on arrays being arrays.
(function normalizeTopo(){
  const arr = v => v==null ? [] : (Array.isArray(v) ? v : [v]);
  (Array.isArray(topo)?topo:[]).forEach(forest=>{
    forest.domains = arr(forest.domains);
    forest.orphanedDCs = arr(forest.orphanedDCs);
    forest.domains.forEach(d=>{
      d.sites = arr(d.sites);
      d.sites.forEach(s=>{
        s.domainControllers = arr(s.domainControllers);
        s.domainControllers.forEach(dc=>{
          dc.roles = arr(dc.roles);
          dc.dcdiag = (dc.dcdiag==null) ? '' : dc.dcdiag;
        });
      });
    });
  });
})();

let Z=1, TX=0, TY=0, dragging=false, dsx, dsy;
let filters=new Set(), showRepl=false;
const dcCards=new Map(), dcData=new Map(), siteData=new Map(), forestData=new Map(), domainData=new Map();

function flCls(fl){
  if(!fl) return '';
  const f=fl.toLowerCase();
  if(f.includes('2025')||f.includes('2022')||f.includes('2019')||f.includes('2016')) return 'fl-good';
  if(f.includes('2012')) return 'fl-warn';
  return 'fl-bad';
}
function hColor(dc){
  if(dc.status!=='Online') return '#f85149';
  if(dc.replErrors&&dc.replErrors!=='N/A'&&dc.replErrors!=='0'&&!dc.replErrors.includes('0 err')) return '#d29922';
  if(dc.pendingReboot==='Pending') return '#d29922';
  if(dc.ntlmv1&&dc.ntlmv1.toLowerCase().includes('enabled')) return '#d29922';
  return '#3fb950';
}
function hClass(dc){
  const c=hColor(dc);
  return c==='#3fb950'?'h-ok':c==='#d29922'?'h-warn':'h-bad';
}

function renderAll(){
  const c=document.getElementById('cc');
  c.innerHTML='';
  const forests=Array.isArray(topo)?topo:[topo];
  forests.forEach((f,fi)=>{
    const fb=document.createElement('div');
    fb.className='fb';
    const fkey='forest-'+fi;
    const orphansF = !f.orphanedDCs ? [] : (Array.isArray(f.orphanedDCs) ? f.orphanedDCs : [f.orphanedDCs]);
    const domsArr=Array.isArray(f.domains)?f.domains:[];
    // total sites & DCs across the forest for the panel
    let fSiteCount=0, fDCCount=0;
    domsArr.forEach(d=>{ const ss=Array.isArray(d.sites)?d.sites:[]; fSiteCount+=ss.length; ss.forEach(s=>{ fDCCount+=(Array.isArray(s.domainControllers)?s.domainControllers.length:0); }); });
    forestData.set(fkey,{name:f.forestName,fl:f.forestFunctionalLevel,rootDomain:f.rootDomain,domains:domsArr.map(d=>d.domainName),domainCount:domsArr.length,siteCount:fSiteCount,dcCount:fDCCount,orphans:orphansF});
    fb.innerHTML='<div class="ftag" style="cursor:pointer" title="Forest details" onclick="openForestPanel(\''+fkey+'\')"><i class="bi bi-tree-fill"></i>FOREST</div>'
      +'<div class="fn" style="cursor:pointer" onclick="openForestPanel(\''+fkey+'\')">'+f.forestName+' <i class="bi bi-info-circle" style="font-size:11px;opacity:.6"></i></div>'
      +'<div class="ffl">Functional Level: '+f.forestFunctionalLevel+'</div>';
    // Orphaned NTDS metadata warning (normalise single object -> array)
    const orphans = orphansF;
    if(orphans.length){
      let ob='<div class="orphan-banner"><div class="orphan-head"><i class="bi bi-exclamation-octagon-fill"></i> '+orphans.length+' orphaned DC metadata object(s) detected</div>';
      orphans.forEach(o=>{ ob+='<div class="orphan-item"><b>'+o.name+'</b> <span class="orphan-site">(site: '+o.site+')</span><div class="orphan-reason">'+o.reason+'</div></div>'; });
      ob+='<div class="orphan-fix">Fix: run metadata cleanup &mdash; <code>ntdsutil</code> &rarr; metadata cleanup, or <code>Remove-ADDomainController -Identity &lt;name&gt; -ForceRemoval</code> if partially present.</div></div>';
      fb.innerHTML+=ob;
    }
    const doms=domsArr;
    doms.forEach((d,di)=>{
      const db=document.createElement('div');
      db.className='db '+flCls(d.domainFunctionalLevel);
      const dkey='domain-'+fi+'-'+di;
      const dSites=Array.isArray(d.sites)?d.sites:[];
      let dDCCount=0; dSites.forEach(s=>{ dDCCount+=(Array.isArray(s.domainControllers)?s.domainControllers.length:0); });
      // collect FSMO holders within this domain
      const fsmo={};
      dSites.forEach(s=>{ (s.domainControllers||[]).forEach(dc=>{ (dc.roles||[]).forEach(r=>{ if(['PDC','RID','Infra','Schema','DN'].includes(r)) fsmo[r]=dc.name.split('.')[0]; }); }); });
      domainData.set(dkey,{name:d.domainName,netbios:d.netbiosName,fl:d.domainFunctionalLevel,forest:f.forestName,sites:dSites.map(s=>s.siteName),siteCount:dSites.length,dcCount:dDCCount,fsmo:fsmo});
      db.innerHTML='<div class="dtag" style="cursor:pointer" title="Domain details" onclick="openDomainPanel(\''+dkey+'\')"><i class="bi bi-hexagon-fill"></i>DOMAIN</div>'
        +'<div class="dn-name" style="cursor:pointer" onclick="openDomainPanel(\''+dkey+'\')">'+d.domainName+(d.netbiosName?' ('+d.netbiosName+')':'')+' <i class="bi bi-info-circle" style="font-size:10px;opacity:.6"></i></div>'
        +'<div class="dn-fl">FL: '+d.domainFunctionalLevel+'</div>';
      const sr=document.createElement('div'); sr.className='sr';
      const sites=dSites;
      sites.forEach(s=>{
        const sb=document.createElement('div');
        sb.className='sb'; sb.setAttribute('data-site',s.siteName);
        const sn=subnetMap[s.siteName]||'';
        const dcs=Array.isArray(s.domainControllers)?s.domainControllers:[];
        // store site metadata for the click panel
        siteData.set(s.siteName, {name:s.siteName, description:s.description, subnets:sn, domain:d.domainName, dcs:dcs.map(x=>x.name)});
        // Only preview a few subnets inline; the rest live in the site panel (avoids a giant text wall)
        let subnetHtml='';
        if(sn){
          const list=sn.split(',').map(x=>x.trim()).filter(Boolean);
          const shown=list.slice(0,4).join(', ');
          const extra=list.length>4?(' <span class="subnet-more">+'+(list.length-4)+' more</span>'):'';
          subnetHtml='<div class="subnets">'+shown+extra+'</div>';
        }
        sb.innerHTML='<div class="sh" title="Click for site details" onclick="openSitePanel(\''+s.siteName.replace(/'/g,"\\'")+'\')"><i class="bi bi-building" style="color:#fff;font-size:10px"></i>'
          +'<span class="sh-name">'+s.siteName+'</span><i class="bi bi-info-circle" style="color:#fff;font-size:10px;margin-left:auto;opacity:.7"></i></div>'
          +'<div class="sbody">'+subnetHtml
          +'<div class="dcgrid" id="g-'+s.siteName.replace(/[^a-zA-Z0-9]/g,'_')+'"></div></div>';
        dcs.forEach(dc=>{ dcData.set(dc.name,dc); dcCards.set(dc.name,buildCard(dc)); });
        sr.appendChild(sb);
      });
      db.appendChild(sr); fb.appendChild(db);
    });
    c.appendChild(fb);
  });
  dcData.forEach((dc,n)=>{
    const gid='g-'+(dc.site||'').replace(/[^a-zA-Z0-9]/g,'_');
    const g=document.getElementById(gid);
    if(g&&dcCards.has(n)) g.appendChild(dcCards.get(n));
  });
  setTimeout(()=>{ fitAll(); },120);
}

function buildCard(dc){
  const hc=hColor(dc);
  const offline=dc.status!=='Online';
  const roles=Array.isArray(dc.roles)?dc.roles:[dc.roles];
  const sn=dc.name.split('.')[0];
  const el=document.createElement('div');
  el.className='dcc'+(offline?(dc.status==='Unreachable'?' unreach':' off'):'');
  el.setAttribute('data-dc',dc.name);
  el.setAttribute('data-roles',roles.join(',').toLowerCase());
  el.setAttribute('data-hc',hc);
  el.onclick=()=>openPanel(dc.name);
  const rdot=dc.pendingReboot==='Pending'?'<div class="reboot-dot" title="Pending reboot"></div>':'';
  const ndot=(dc.ntlmv1&&dc.ntlmv1.toLowerCase().includes('enabled'))?'<div class="ntlm-dot" title="NTLMv1 enabled"></div>':'';
  const ic=offline?'off-icon':dc.isGC?'gc-icon':'dc-icon';
  const hcls=hClass(dc);
  const lr=offline?' r':'';
  const gcBadge=dc.isGC?'<div class="gc-badge" title="Global Catalog"><i class="bi bi-globe"></i></div>':'';
  const pills=roles.map(r=>'<span class="pill p-'+r.toLowerCase().replace(/\s+/g,'')+'">'+r+'</span>').join('');
  el.innerHTML=rdot+ndot
    +'<div class="iw">'
    +'<div class="srv '+ic+' '+hcls+'"><div class="led'+lr+'"></div><div class="led'+lr+'"></div><div class="led'+lr+'"></div><div class="disk"></div>'+gcBadge+'</div></div>'
    +'<div class="dc-lbl">'+sn+'</div>'
    +'<div class="pills">'+pills+'</div>';
  return el;
}

function openPanel(n){
  const dc=dcData.get(n); if(!dc) return;
  document.getElementById('ptitle').textContent=dc.name.split('.')[0];
  document.getElementById('psub').textContent=dc.name;
  // Normalise unavailable values (ADAudit may store 'Error'/'Unreachable'/'') -> em-dash, muted
  function norm(v){
    if(v==null) return null;
    const s=(''+v).trim();
    if(s===''||s==='Error'||s==='Unreachable'||s==='Unknown'||s==='N/A') return null;
    return s;
  }
  function isBad(v){ const s=norm(v); return s===null; } // unavailable
  const st=dc.status==='Online'
    ?'<span style="color:var(--green)"><i class="bi bi-check-circle-fill"></i> Online</span>'
    :'<span style="color:var(--red)"><i class="bi bi-x-circle-fill"></i> '+dc.status+'</span>';
  // kv: shows '&mdash;' (muted) when value is unavailable instead of the raw 'Error' text
  function kv(k,v,c=''){
    const nv=norm(v);
    const disp = nv===null ? '<span style="color:var(--muted)">&mdash;</span>' : nv;
    const cls  = nv===null ? '' : c;   // don't apply ok/bad colour to an unavailable value
    return '<div class="kv"><div class="kv-k">'+k+'</div><div class="kv-v '+cls+'">'+disp+'</div></div>';
  }
  function bar(pct,lbl){
    const nv=norm(pct);
    if(nv===null) return '<div class="kv kv-wide"><div class="kv-k">'+lbl+'</div><div class="kv-v" style="color:var(--muted)">data unavailable</div></div>';
    const v=parseFloat(nv)||0;
    const bc=v>90?'b':v>75?'w':'';
    return '<div class="kv kv-wide"><div class="kv-k">'+lbl+'</div><div class="bar-w"><div class="bar-f '+bc+'" style="width:'+Math.min(v,100)+'%"></div></div></div>';
  }
  function svc(nm,val){
    const nv=norm(val);
    if(nv===null){ return '<div class="svc-row"><span>'+nm+'</span><span style="display:flex;align-items:center;gap:5px"><span class="dot u"></span><span style="font-size:10px;color:var(--muted)">unavailable</span></span></div>'; }
    const run=nv.toLowerCase().includes('running');
    const stop=nv.toLowerCase().includes('stopped');
    const dc2=run?'':stop?'s':'u';
    return '<div class="svc-row"><span>'+nm+'</span><span style="display:flex;align-items:center;gap:5px"><span class="dot '+dc2+'"></span><span style="font-size:10px;color:var(--muted)">'+nv+'</span></span></div>';
  }
  let ddhtml='';
  if(dc.dcdiag){
    const pairs=dc.dcdiag.split('|').filter(Boolean);
    ddhtml=pairs.map(p=>{
      const idx=p.indexOf(':');
      const nm = idx>=0 ? p.slice(0,idx) : p;
      const vl = idx>=0 ? p.slice(idx+1).trim() : '';
      const lv = vl.toLowerCase();
      const c = lv.includes('pass') ? 'pass' : lv.includes('fail') ? 'fail' : 'unk';
      const ic = c==='pass' ? '<i class="bi bi-check-circle-fill" style="color:var(--green)"></i>'
               : c==='fail' ? '<i class="bi bi-x-circle-fill" style="color:var(--red)"></i>'
               : '<i class="bi bi-dash-circle" style="color:var(--muted)"></i>';
      const tail = (c==='unk' && vl) ? ' <span style="color:var(--muted);font-size:9px">('+vl+')</span>' : '';
      return '<div class="ddi '+c+'">'+ic+' '+nm+tail+'</div>';
    }).join('');
  }
  const ramUsed=isBad(dc.ramFreePercent)?null:100-parseFloat(dc.ramFreePercent||'0');
  const cpuUsed=isBad(dc.cpuFreePercent)?null:100-parseFloat(dc.cpuFreePercent||'0');
  const dskUsed=isBad(dc.osDriveFreePC)?null:100-parseFloat(dc.osDriveFreePC||'0');
  const ramTotal = norm(dc.ramTotalGB) || '?';
  const dskFree  = norm(dc.osDriveFreeGB) || '?';
  document.getElementById('pbody').innerHTML=
    '<div class="psec"><div class="psec-title"><i class="bi bi-info-circle"></i> Identity</div>'
    +'<div class="kvg">'+kv('Status',st)+kv('IP',dc.ip,'info')+kv('Site',dc.site)+kv('Uptime',dc.uptime)
    +kv('GC',dc.isGC?'Yes':'No',dc.isGC?'ok':'')+kv('RODC',dc.isRODC?'Yes':'No')
    +kv('SYSVOL Repl',dc.sysvolReplMethod)+kv('NTP',dc.ntpSource)
    +kv('Collected via',dc.collectVia,dc.collectVia==='None'?'bad':dc.collectVia==='DCOM'?'warn':'ok')
    +kv('Time Skew',dc.timeDiff,(parseFloat(dc.timeDiff)>5)?'bad':(parseFloat(dc.timeDiff)>2)?'warn':'ok')
    +kv('Pending Reboot',dc.pendingReboot,norm(dc.pendingReboot)==='Pending'?'warn':(norm(dc.pendingReboot)?'ok':''))
    +kv('NTLMv1',dc.ntlmv1,(norm(dc.ntlmv1)&&dc.ntlmv1.toLowerCase().includes('enabled'))?'bad':(norm(dc.ntlmv1)?'ok':''))
    +'</div></div>'
    +'<div class="psec"><div class="psec-title"><i class="bi bi-cpu"></i> Resources</div>'
    +'<div class="kvg">'
    +bar(ramUsed,'RAM used &mdash; '+ramTotal+' GB total')
    +bar(cpuUsed,'CPU used')
    +bar(dskUsed,'OS Disk used &mdash; '+dskFree+' GB free')
    +'</div></div>'
    +'<div class="psec"><div class="psec-title"><i class="bi bi-gear"></i> Services</div>'
    +svc('NTDS',dc.ntdsService)+svc('KDC',dc.kdcService)+svc('ADWS',dc.adwsService)
    +svc('NETLOGON',dc.netlogonService)+svc('W32Time',dc.w32timeService)+'</div>'
    +'<div class="psec"><div class="psec-title"><i class="bi bi-arrow-repeat"></i> Replication</div>'
    +'<div class="kvg">'+kv('Errors',dc.replErrors,(norm(dc.replErrors)&&dc.replErrors!=='0')?'bad':'ok')
    +kv('Max Delay',dc.maxReplDelayH)+'</div></div>'
    +(ddhtml?'<div class="psec"><div class="psec-title"><i class="bi bi-clipboard-check"></i> DCDiag</div>'
    +'<div class="ddt">'+ddhtml+'</div></div>':'');
  document.getElementById('ov').classList.add('on');
  document.getElementById('panel').classList.add('on');
}
function closePanel(){
  document.getElementById('ov').classList.remove('on');
  document.getElementById('panel').classList.remove('on');
}

function openSitePanel(siteName){
  const s=siteData.get(siteName); if(!s) return;
  document.getElementById('ptitle').textContent=s.name;
  document.getElementById('psub').textContent='Site \u00B7 '+(s.domain||'');
  function kv(k,v,c){return '<div class="kv"><div class="kv-k">'+k+'</div><div class="kv-v '+(c||'')+'">'+((v==null||v==='')?'&mdash;':v)+'</div></div>';}
  // DC list with quick health dot + clickable to open the DC panel
  const dcRows=(s.dcs||[]).map(n=>{
    const dc=dcData.get(n);
    const hc=dc?hColor(dc):'#8b949e';
    const sn=n.split('.')[0];
    const roles=dc?((dc.roles||[]).join(', ')):'';
    return '<div class="svc-row" style="cursor:pointer" onclick="openPanel(\''+n.replace(/'/g,"\\'")+'\')">'
      +'<span style="display:flex;align-items:center;gap:7px"><span class="dot" style="background:'+hc+'"></span>'+sn+'</span>'
      +'<span style="font-size:9px;color:var(--muted)">'+roles+'</span></div>';
  }).join('');
  const subnetList=(s.subnets&&s.subnets.length)
    ? s.subnets.split(',').map(x=>'<div class="ddi" style="border-left:3px solid var(--blue)">'+x.trim()+'</div>').join('')
    : '<div style="color:var(--muted);font-size:11px">No subnets associated with this site</div>';
  document.getElementById('pbody').innerHTML=
    '<div class="psec"><div class="psec-title"><i class="bi bi-building"></i> Site</div>'
    +'<div class="kvg">'+kv('Name',s.name,'info')+kv('Domain',s.domain)
    +kv('Domain Controllers',(s.dcs||[]).length)+kv('Subnets',(s.subnets&&s.subnets.length)?s.subnets.split(',').length:0)
    +'</div></div>'
    +'<div class="psec"><div class="psec-title"><i class="bi bi-diagram-3"></i> Subnets</div><div class="ddt">'+subnetList+'</div></div>'
    +'<div class="psec"><div class="psec-title"><i class="bi bi-hdd-stack"></i> Domain Controllers ('+(s.dcs||[]).length+')</div>'+(dcRows||'<div style="color:var(--muted);font-size:11px">None</div>')+'</div>';
  document.getElementById('ov').classList.add('on');
  document.getElementById('panel').classList.add('on');
}

function openForestPanel(key){
  const f=forestData.get(key); if(!f) return;
  document.getElementById('ptitle').textContent=f.name;
  document.getElementById('psub').textContent='Forest';
  function kv(k,v,c){return '<div class="kv"><div class="kv-k">'+k+'</div><div class="kv-v '+(c||'')+'">'+((v==null||v==='')?'&mdash;':v)+'</div></div>';}
  const flCl=flCls(f.fl)==='fl-good'?'ok':flCls(f.fl)==='fl-warn'?'warn':'bad';
  const domRows=(f.domains||[]).map(n=>'<div class="ddi" style="border-left:3px solid var(--domain-c)"><i class="bi bi-hexagon-fill" style="color:var(--green)"></i> '+n+'</div>').join('');
  let orphanSec='';
  if(f.orphans&&f.orphans.length){
    orphanSec='<div class="psec"><div class="psec-title"><i class="bi bi-exclamation-octagon" style="color:var(--red)"></i> Orphaned Metadata</div>'
      +f.orphans.map(o=>'<div class="ddi fail"><i class="bi bi-x-circle-fill" style="color:var(--red)"></i> '+o.name+' (site '+o.site+')</div>').join('')+'</div>';
  }
  document.getElementById('pbody').innerHTML=
    '<div class="psec"><div class="psec-title"><i class="bi bi-tree-fill"></i> Forest</div><div class="kvg">'
    +kv('Name',f.name,'info')+kv('Root Domain',f.rootDomain,'info')
    +kv('Functional Level',f.fl,flCl)+kv('Domains',f.domainCount)
    +kv('Sites',f.siteCount)+kv('Domain Controllers',f.dcCount)
    +'</div></div>'
    +'<div class="psec"><div class="psec-title"><i class="bi bi-hexagon"></i> Domains ('+(f.domains||[]).length+')</div><div class="ddt">'+(domRows||'<span style="color:var(--muted);font-size:11px">None</span>')+'</div></div>'
    +orphanSec;
  document.getElementById('ov').classList.add('on');
  document.getElementById('panel').classList.add('on');
}

function openDomainPanel(key){
  const d=domainData.get(key); if(!d) return;
  document.getElementById('ptitle').textContent=d.name;
  document.getElementById('psub').textContent='Domain'+(d.netbios?' \u00B7 '+d.netbios:'');
  function kv(k,v,c){return '<div class="kv"><div class="kv-k">'+k+'</div><div class="kv-v '+(c||'')+'">'+((v==null||v==='')?'&mdash;':v)+'</div></div>';}
  const flCl=flCls(d.fl)==='fl-good'?'ok':flCls(d.fl)==='fl-warn'?'warn':'bad';
  const siteRows=(d.sites||[]).map(n=>'<div class="ddi" style="border-left:3px solid var(--site-c);cursor:pointer" onclick="openSitePanel(\''+n.replace(/'/g,"\\'")+'\')"><i class="bi bi-building"></i> '+n+'</div>').join('');
  const f=d.fsmo||{};
  const fsmoRows=['PDC','RID','Infra','Schema','DN'].map(r=>{
    const holder=f[r];
    return '<div class="svc-row"><span>'+r+'</span><span style="font-size:10px;color:'+(holder?'var(--text)':'var(--muted)')+'">'+(holder||'&mdash;')+'</span></div>';
  }).join('');
  document.getElementById('pbody').innerHTML=
    '<div class="psec"><div class="psec-title"><i class="bi bi-hexagon-fill"></i> Domain</div><div class="kvg">'
    +kv('DNS Root',d.name,'info')+kv('NetBIOS',d.netbios)
    +kv('Functional Level',d.fl,flCl)+kv('Forest',d.forest)
    +kv('Sites',d.siteCount)+kv('Domain Controllers',d.dcCount)
    +'</div></div>'
    +'<div class="psec"><div class="psec-title"><i class="bi bi-star"></i> FSMO Role Holders</div>'+fsmoRows+'</div>'
    +'<div class="psec"><div class="psec-title"><i class="bi bi-building"></i> Sites ('+(d.sites||[]).length+')</div><div class="ddt">'+(siteRows||'<span style="color:var(--muted);font-size:11px">None</span>')+'</div></div>';
  document.getElementById('ov').classList.add('on');
  document.getElementById('panel').classList.add('on');
}

function toggleRepl(){
  // Normalise: handle case where ConvertTo-Json emitted a single object instead of an array
  const links = !siteLinks ? [] : (Array.isArray(siteLinks) ? siteLinks : [siteLinks]);
  // Count actual rendered sites
  const siteCount = document.querySelectorAll('.sb').length;

  if (links.length === 0 || siteCount < 2) {
    // Nothing to draw &mdash; show a transient notice on the button
    const btn = document.getElementById('replBtn');
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-info-circle"></i> No inter-site links';
    btn.disabled = true;
    setTimeout(() => { btn.innerHTML = original; btn.disabled = false; }, 2000);
    return;
  }

  showRepl = !showRepl;
  document.getElementById('replBtn').classList.toggle('on', showRepl);
  if (showRepl) setTimeout(drawRepl, 100);
  else document.getElementById('replSvg').innerHTML = '';
}
function drawRepl(){
  const svg=document.getElementById('replSvg');
  svg.innerHTML='';
  const links = !siteLinks ? [] : (Array.isArray(siteLinks) ? siteLinks : [siteLinks]);
  if (links.length === 0) return;
  const wr=document.getElementById('cw').getBoundingClientRect();
  let linkIdx=0;
  links.forEach(lk=>{
    if(!lk.SitesIncluded) return;
    const sites=lk.SitesIncluded.split(',').map(s=>s.trim()).filter(Boolean);
    if (sites.length < 2) return;
    for(let i=0;i<sites.length-1;i++){
      const sA=document.querySelector('[data-site="'+sites[i]+'"]');
      const sB=document.querySelector('[data-site="'+sites[i+1]+'"]');
      if(!sA||!sB) continue;
      const rA=sA.getBoundingClientRect(), rB=sB.getBoundingClientRect();
      // Connect from the TOP edge of each site box so the line arcs above the DC cards
      const x1=rA.left+rA.width/2-wr.left, y1=rA.top-wr.top;
      const x2=rB.left+rB.width/2-wr.left, y2=rB.top-wr.top;
      const hasIssue=replIssues&&Array.isArray(replIssues)&&replIssues.some(r=>(r.SourceDC&&sites.some(s=>r.SourceDC.includes(s)))||(r.DestinationDC&&sites.some(s=>r.DestinationDC&&r.DestinationDC.includes(s))));
      const col=hasIssue?'#f85149':'#58a6ff';
      const dash=lk.ReplicationSchedule==='Custom'?'8 4':'none';
      // Stagger arc apex height per link so multiple links don't overlap at the same Y
      const arcLift=50+(linkIdx%4)*34;
      const cx_ctrl=(x1+x2)/2, cy_ctrl=Math.min(y1,y2)-arcLift;
      const path=document.createElementNS('http://www.w3.org/2000/svg','path');
      path.setAttribute('d','M '+x1+' '+y1+' Q '+cx_ctrl+' '+cy_ctrl+' '+x2+' '+y2);
      path.setAttribute('fill','none');
      path.setAttribute('stroke',col);path.setAttribute('stroke-width','2');
      path.setAttribute('stroke-dasharray',dash);path.setAttribute('opacity','.75');
      path.style.cursor='pointer';
      path.setAttribute('data-lk',JSON.stringify({name:lk.Name,cost:lk.Cost,freq:lk.ReplicationFrequencyInMinutes,sched:lk.ReplicationSchedule,transport:lk.InterSiteTransport||'IP',hasIssue}));
      path.addEventListener('mouseenter',showLTT);path.addEventListener('mouseleave',hideLTT);
      svg.appendChild(path);
      // Label at the TRUE midpoint of the quadratic curve: B(0.5) = 0.25*P0 + 0.5*Ctrl + 0.25*P2
      const lx=0.25*x1+0.5*cx_ctrl+0.25*x2;
      const ly=0.25*y1+0.5*cy_ctrl+0.25*y2;
      const lblText=(lk.ReplicationFrequencyInMinutes||'?')+'min \u00B7 cost '+(lk.Cost||'?');
      const lblW=lblText.length*6+10;
      const rect=document.createElementNS('http://www.w3.org/2000/svg','rect');
      rect.setAttribute('x',lx-lblW/2);rect.setAttribute('y',ly-9);rect.setAttribute('width',lblW);rect.setAttribute('height',16);
      rect.setAttribute('rx','8');rect.setAttribute('fill','var(--surface)');rect.setAttribute('stroke',col);rect.setAttribute('stroke-width','1');
      svg.appendChild(rect);
      const txt=document.createElementNS('http://www.w3.org/2000/svg','text');
      txt.setAttribute('x',lx);txt.setAttribute('y',ly+3);txt.setAttribute('text-anchor','middle');
      txt.setAttribute('fill',col);txt.setAttribute('font-size','9');txt.setAttribute('font-family','monospace');
      txt.textContent=lblText;
      svg.appendChild(txt);
      linkIdx++;
    }
  });
}
function showLTT(e){
  try{
    const d=JSON.parse(e.target.getAttribute('data-lk'));
    const t=document.getElementById('ltt');
    t.innerHTML='<strong>'+d.name+'</strong><br>Cost: '+d.cost+' &nbsp;|&nbsp; Freq: '+d.freq+'min<br>Schedule: '+d.sched+' &nbsp;|&nbsp; Transport: '+d.transport+'<br>'+(d.hasIssue?'<span style="color:var(--red)"><i class="bi bi-exclamation-triangle-fill"></i> Replication issues</span>':'<span style="color:var(--green)">&#10003; No issues</span>');
    t.style.left=(e.clientX+10)+'px';t.style.top=(e.clientY+10)+'px';t.classList.add('on');
  }catch(ex){}
}
function hideLTT(){document.getElementById('ltt').classList.remove('on');}

function flt(t){
  const b=document.getElementById('f-'+t);
  filters.has(t)?filters.delete(t):filters.add(t);
  b.classList.toggle('on',filters.has(t));
  applyFilters();
}
function applyFilters(){
  dcCards.forEach((card,n)=>{
    const dc=dcData.get(n);
    const roles=(card.getAttribute('data-roles')||'').split(',');
    let show=true;
    if(filters.has('fsmo')) show=show&&roles.some(r=>['pdc','rid','infra','schema','dn'].includes(r));
    if(filters.has('offline')) show=show&&dc.status!=='Online';
    if(filters.has('gc')) show=show&&dc.isGC;
    if(filters.has('repl')) show=show&&(dc.replErrors&&dc.replErrors!=='0'&&dc.replErrors!=='N/A');
    card.classList.toggle('dim',!show);
  });
}
function doSearch(v){
  const q=v.toLowerCase().trim();
  dcCards.forEach((card,n)=>{
    const dc=dcData.get(n);
    const hit=!q||n.toLowerCase().includes(q)||(dc.site&&dc.site.toLowerCase().includes(q))||(dc.ip&&dc.ip.includes(q));
    card.classList.toggle('dim',!hit&&!!q);
    card.classList.toggle('hi',hit&&!!q);
    if(hit&&q) setTimeout(()=>card.scrollIntoView({behavior:'smooth',block:'center',inline:'center'}),50);
  });
}

const cw=document.getElementById('cw'), cc=document.getElementById('cc');
function applyT(){
  cc.style.transform='translate('+TX+'px,'+TY+'px) scale('+Z+')';
  if(showRepl) drawRepl();
}
function doZoom(d){
  const prev=Z; Z=Math.min(Math.max(Z+d,.2),3);
  const f=Z/prev, cx=cw.clientWidth/2, cy=cw.clientHeight/2;
  TX=cx-f*(cx-TX); TY=cy-f*(cy-TY); applyT();
}
function fitAll(){
  Z=.8; TX=50; TY=50; applyT();
  setTimeout(()=>{
    const cr=cc.getBoundingClientRect(), wr=cw.getBoundingClientRect();
    // If layout isn't ready (zero-size measurements), keep the safe default rather than shrinking to a corner
    if(!cr.width || !cr.height || !wr.width || !wr.height){ Z=.8; TX=50; TY=50; applyT(); return; }
    const nW=cr.width/Z, nH=cr.height/Z;
    const fit=Math.min((wr.width-80)/nW,(wr.height-80)/nH,2);
    // Never shrink below 0.5 &mdash; at smaller zooms content is effectively invisible
    Z=Math.max(.5,fit);
    TX=Math.max(20,(wr.width-nW*Z)/2); TY=Math.max(20,(wr.height-nH*Z)/2); applyT();
  },80);
}
function resetView(){Z=1;TX=60;TY=40;applyT();}

cw.addEventListener('mousedown',e=>{
  if(e.target.closest('.dcc')||e.target.closest('.panel')) return;
  dragging=true; dsx=e.clientX-TX; dsy=e.clientY-TY; cw.classList.add('drag');
});
window.addEventListener('mousemove',e=>{if(!dragging)return;TX=e.clientX-dsx;TY=e.clientY-dsy;applyT();});
window.addEventListener('mouseup',()=>{dragging=false;cw.classList.remove('drag');});
cw.addEventListener('wheel',e=>{
  // If already fully zoomed out and the user keeps scrolling down, let the page
  // scroll to the analysis sections instead of trapping the wheel.
  if(e.deltaY>0 && Z<=0.2){ return; }
  e.preventDefault();
  const r=cw.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top,prev=Z;
  Z=Math.min(Math.max(Z-e.deltaY*.001,.2),3);
  const f=Z/prev; TX=mx-f*(mx-TX); TY=my-f*(my-TY); applyT();
},{passive:false});

function toggleTheme(){
  document.body.setAttribute('data-theme',document.body.getAttribute('data-theme')==='dark'?'light':'dark');
}

// ============ Analysis sections: replication matrix / ports / stale objects ============
function esc(s){ return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function renderAnalysis(){
  document.getElementById('replBody').innerHTML = buildReplMatrix();
  document.getElementById('staleBody').innerHTML = buildStale();
}

// ---- Replication matrix ----
function buildReplMatrix(){
  const dcs=(Array.isArray(dcList)?dcList:[]).map(d=>d.short);
  const M=Array.isArray(replMatrix)?replMatrix:[];
  const meta=(typeof replMeta!=='undefined'&&replMeta)?replMeta:{};
  if(!dcs.length){ return '<div class="rempty"><i class="bi bi-info-circle"></i>No domain controllers were enumerated.</div>'; }

  // AD reports one record per (source, destination, PARTITION). Aggregate them into one
  // cell per DC pair, with the WORST partition state winning, and keep the per-partition
  // breakdown for the detail card. A pair that is fine on the domain NC but failing on
  // Configuration or Schema must NOT render as healthy.
  const RANK={ok:0,delayed:1,fail:2};
  const pairs={};      // "src|dst" -> { src,dst,state,parts:[] }
  const unqDst={};     // destination DC -> marker row (its inbound partners are unknown)
  M.forEach(r=>{
    if(r.state==='unqueryable' || r.src==='(unqueryable)'){ unqDst[r.dst]=r; return; }
    if(r.dst==='(all partners)'){ unqDst[r.src]=r; return; }   // back-compat with older reports
    const k=r.src+'|'+r.dst;
    if(!pairs[k]) pairs[k]={src:r.src,dst:r.dst,state:r.state,parts:[]};
    pairs[k].parts.push(r);
    if((RANK[r.state]||0) > (RANK[pairs[k].state]||0)) pairs[k].state=r.state;
  });

  const pairList=Object.values(pairs);
  let ok=0,delayed=0,fail=0;
  pairList.forEach(p=>{ if(p.state==='ok')ok++; else if(p.state==='delayed')delayed++; else fail++; });
  const unqCount=Object.keys(unqDst).length;

  let h='<div class="rmsub">Each cell is a directional replication partnership: <b>row&nbsp;&rarr;&nbsp;column</b> (source replicates to destination). '
    +'Read from the metadata AD already tracks &mdash; no network probing. Every naming context is checked '
    +'(domain, Configuration, Schema, DNS zones); a cell shows the <b>worst</b> partition, so a pair that is healthy on the domain NC '
    +'but failing on Configuration still shows as failing. Click any cell for the full partition breakdown. '
    +'Grey cells mean the KCC built no direct connection for that pair (normal).'
    +(unqCount>0 ? ' <b>Unqueryable</b> columns are DCs whose own metadata could not be read, so their <i>inbound</i> partnerships are unknown &mdash; their outbound rows may still show valid data reported by other DCs.' : '')
    +'</div>';

  h+='<div class="rchips">'
    +'<div class="rchip"><div class="n">'+dcs.length+'</div><div class="l">DCs</div></div>'
    +'<div class="rchip"><div class="n">'+pairList.length+'</div><div class="l">Partnerships</div></div>'
    +'<div class="rchip g"><div class="n">'+ok+'</div><div class="l">Healthy</div></div>'
    +'<div class="rchip a"><div class="n">'+delayed+'</div><div class="l">Delayed</div></div>'
    +'<div class="rchip r"><div class="n">'+fail+'</div><div class="l">Failing</div></div>'
    +(unqCount>0 ? '<div class="rchip r"><div class="n">'+unqCount+'</div><div class="l">Unqueryable DCs</div></div>' : '')
    +'</div>';

  if(meta.via){
    h+='<div class="mlabel">source: '+esc(meta.via)+' &middot; partitions: all &middot; delay thresholds: '
      +esc(meta.intraSiteDelayH)+'h intra-site, '+esc(meta.interSiteDelayH)+'h inter-site</div>';
  }
  h+='<div class="mlabel">rows = source DC&nbsp; &rarr; &nbsp;columns = destination DC</div>';
  h+='<div class="mwrap"><table class="mtx"><thead><tr><th>src &rarr; dst</th>';
  dcs.forEach(d=>{
    const unq=!!unqDst[d];
    h+='<th'+(unq?' class="unq-col"':'')+'>'+esc(d)
      +(unq?'<div class="unq-badge" title="Click for details" onclick="replCellInfo(\'(unqueryable)\',\''+esc(d)+'\')">unqueryable</div>':'')
      +'</th>';
  });
  h+='</tr></thead><tbody>';
  dcs.forEach(src=>{
    h+='<tr><th>'+esc(src)+'</th>';
    dcs.forEach(dst=>{
      if(src===dst){ h+='<td><div class="mcell self"></div></td>'; return; }
      const p=pairs[src+'|'+dst];
      if(p){
        let ic='&check;'; if(p.state==='fail'){ic='&times;';} else if(p.state==='delayed'){ic='!';}
        const bad=p.parts.filter(x=>x.state!=='ok');
        const tip=esc(src+' \u2192 '+dst+' | '+p.parts.length+' partition(s)'
          +(bad.length?(' | issue on: '+bad.map(x=>x.partition).join(', ')):' | all healthy'));
        h+='<td><div class="mcell '+p.state+'" title="'+tip+'" onclick="replCellInfo(\''+esc(src)+'\',\''+esc(dst)+'\')">'+ic+'</div></td>';
        return;
      }
      if(unqDst[dst]){
        h+='<td><div class="mcell unq" title="'+esc(dst+' metadata could not be read - inbound partnerships unknown')+'" onclick="replCellInfo(\'(unqueryable)\',\''+esc(dst)+'\')">?</div></td>';
        return;
      }
      h+='<td><div class="mcell none">&middot;</div></td>';
    });
    h+='</tr>';
  });
  h+='</tbody></table></div>';
  h+='<div id="replCellDetail" style="margin-top:16px"></div>';
  return h;
}
function replCellInfo(src,dst){
  const M=Array.isArray(replMatrix)?replMatrix:[];
  const el=document.getElementById('replCellDetail');
  if(!el) return;
  // Unqueryable destination: find the marker row for this DC (new or legacy shape)
  if(src==='(unqueryable)'){
    const u=M.find(r=>(r.state==='unqueryable'&&r.dst===dst)||(r.dst==='(all partners)'&&r.src===dst));
    if(!u) return;
    el.innerHTML='<div class="scard high">'
      +'<div class="scard-h"><span class="scard-cat">'+esc(dst)+'</span>'
      +'<span class="sev high">unqueryable</span></div>'
      +'<div class="scard-det">This DC\'s own replication metadata could not be read, so its <b>inbound</b> replication partnerships are unknown. '
      +'Any healthy cells in its row were reported by <i>other</i> DCs and are still valid.</div>'
      +'<div class="scard-fix"><b>Error '+u.lastError+':</b> '+esc(u.errorText)
      +'<br><br><b>Common causes:</b> the DC is down; <b>ADWS (TCP 9389)</b> is blocked or the Active Directory Web Services service is not running on it; '
      +'RPC (135 + dynamic range) is also blocked, so the repadmin fallback could not reach it either &mdash; Azure NSGs and hardened firewalls commonly block both; '
      +'or the account running this script lacks rights on that DC.</div></div>';
    return;
  }
  const rows=M.filter(r=>r.src===src&&r.dst===dst);
  if(!rows.length) return;
  const RANK={ok:0,delayed:1,fail:2};
  let worst='ok'; rows.forEach(r=>{ if((RANK[r.state]||0)>(RANK[worst]||0)) worst=r.state; });
  const sev=(worst==='ok')?'low':((worst==='delayed')?'medium':'high');
  let t='<table class="pt"><thead><tr><th>Partition</th><th>State</th><th>Last success</th><th>Failures</th><th>Result</th></tr></thead><tbody>';
  rows.forEach(r=>{
    t+='<tr><td><b>'+esc(r.partition)+'</b></td>'
      +'<td><span class="sev '+(r.state==='ok'?'low':(r.state==='delayed'?'medium':'high'))+'">'+esc(r.state)+'</span></td>'
      +'<td>'+(r.lastSuccess?esc(r.lastSuccess):'&mdash;')+'</td>'
      +'<td>'+(r.failures||0)+'</td>'
      +'<td>'+(r.lastError?('<b>'+r.lastError+'</b> '+esc(r.errorText)):esc(r.errorText||'Success'))+'</td></tr>';
  });
  t+='</tbody></table>';
  el.innerHTML='<div class="scard '+sev+'">'
    +'<div class="scard-h"><span class="scard-cat">'+esc(src)+' &rarr; '+esc(dst)+'</span>'
    +'<span class="sev '+sev+'">'+esc(worst)+'</span></div>'
    +'<div class="scard-det">'+rows.length+' naming context(s) replicate over this partnership. The cell colour reflects the worst one.</div>'
    +t+'</div>';
}

// ---- Stale objects ----
function buildStale(){
  const F=Array.isArray(staleObjects)?staleObjects:[];
  if(!F.length){
    return '<div class="rempty"><i class="bi bi-check-circle-fill"></i>No stale or lingering objects found.<br>'
      +'<span style="font-size:12px">Configuration, Sites &amp; Services, and DC metadata all look clean.</span></div>';
  }
  const sev={high:0,medium:0,low:0};
  F.forEach(f=>{ sev[f.severity]=(sev[f.severity]||0)+1; });
  let h='<div class="rmsub">Read-only scan of the Configuration partition and Sites &amp; Services for leftover infrastructure objects. '
    +'Nothing is modified &mdash; each finding lists the recommended remediation.</div>';
  h+='<div class="rchips">'
    +'<div class="rchip r"><div class="n">'+(sev.high||0)+'</div><div class="l">High</div></div>'
    +'<div class="rchip a"><div class="n">'+(sev.medium||0)+'</div><div class="l">Medium</div></div>'
    +'<div class="rchip"><div class="n">'+(sev.low||0)+'</div><div class="l">Low</div></div>'
    +'</div>';
  // group by category
  const cats={};
  F.forEach(f=>{ (cats[f.category]=cats[f.category]||[]).push(f); });
  Object.keys(cats).forEach(cat=>{
    h+='<div style="font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:700;margin:16px 0 8px">'+esc(cat)+' ('+cats[cat].length+')</div>';
    cats[cat].forEach(f=>{
      h+='<div class="scard '+esc(f.severity)+'">'
        +'<div class="scard-h"><span class="scard-cat">'+esc(f.name)+'</span><span class="sev '+esc(f.severity)+'">'+esc(f.severity)+'</span></div>'
        +'<div class="scard-det">'+esc(f.detail)+'</div>'
        +(f.dn?('<div class="scard-dn">'+esc(f.dn)+'</div>'):'')
        +'<div class="scard-fix"><b>Remediation:</b> '+f.remediation+'</div>'
        +'</div>';
    });
  });
  return h;
}

renderAll();
renderAnalysis();
</script>
</body>
</html>
"@

$HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
Write-Host ""
Write-Host "  Report saved: $ReportPath" -ForegroundColor Green
if ($OpenReport -and -not [Environment]::UserInteractive -eq $false) {
    try { Start-Process $ReportPath } catch { Write-Host "  (Could not auto-open. Open the file manually.)" -ForegroundColor Yellow }
}
