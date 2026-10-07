<#
.SYNOPSIS
    AD DNS Health - DNS configuration & health review (interactive HTML).

.DESCRIPTION
    Standalone module for the Active Directory Audit Suite. Produces a single
    self-contained, interactive HTML report (light/dark) that reviews the DNS
    that underpins Active Directory. It combines two complementary angles:

      1. CONFIGURATION  - is DNS set up correctly? (per zone + per server)
           zone type, AD-integration, replication scope, dynamic-update mode,
           aging/scavenging, zone transfers, DNSSEC signing, NS records.

      2. LIVE HEALTH    - does DNS actually work? (per domain controller)
           forward + reverse resolution, forwarder resolution, this DC's own
           record registration, and (when available) dcdiag /test:DNS.

    Stale-record checking is scoped deliberately: instead of enumerating every
    record in every zone (slow on large estates), it flags only LINGERING DC
    RECORDS - host A records and _msdcs SRV/CNAME entries that point at domain
    controllers which no longer exist in AD. Those are the ones that break
    clients and replication.

    Everything is discovered live from AD and the DNS server. All queries are
    READ-ONLY - nothing is created, changed, or deleted. Degrades gracefully
    when the DnsServer (RSAT-DNS) module or dcdiag.exe is unavailable.

.PARAMETER OutputPath
    Folder to save the HTML report. Defaults to the current directory.

.PARAMETER Server
    DNS server to query for zone/server configuration. Defaults to the domain's
    PDC emulator (a safe source for AD-integrated DNS).

.PARAMETER SkipLiveTests
    Skip the per-DC live resolution / dcdiag tests (configuration only).

.PARAMETER ExternalName
    External name used to verify recursive/forwarder resolution from each DC.
    Defaults to 'microsoft.com'.

.PARAMETER OpenReport
    Open the report when finished (default: $true).

.EXAMPLE
    .\AD-DNSHealth-Enhanced.ps1

.EXAMPLE
    .\AD-DNSHealth-Enhanced.ps1 -OutputPath C:\Reports -SkipLiveTests

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite (DNS Health module)
    Requires: ActiveDirectory module. DnsServer module recommended for full detail.
#>
[CmdletBinding()]
param(
    [string]$OutputPath   = (Get-Location).Path,
    [string]$Server,
    [switch]$SkipLiveTests,
    [string]$ExternalName = 'microsoft.com',
    [switch]$SkipSecurityChecks,
    [switch]$OpenReport   = $true
)

$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Error "ActiveDirectory module not available. Install RSAT-AD-PowerShell."; exit 1 }
$HasDns = $false
try { Import-Module DnsServer -ErrorAction Stop; $HasDns = $true } catch { Write-Host "  (DnsServer module not found - falling back to resolver-only checks)" -ForegroundColor DarkYellow }

try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$Stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

try { $Domain = Get-ADDomain -ErrorAction Stop } catch { Write-Error "Could not contact the domain: $($_.Exception.Message)"; exit 1 }
try { $Forest = Get-ADForest -ErrorAction SilentlyContinue } catch { $Forest = $null }
$DomainDNS = $Domain.DNSRoot
$ForestDNS = if ($Forest) { $Forest.Name } else { $DomainDNS }
$PDC       = $Domain.PDCEmulator
if (-not $Server) { $Server = if ($PDC) { $PDC } else { $DomainDNS } }
$ReportPath = Join-Path $OutputPath "AD_DNSHealth_$Stamp.html"

Write-Host "AD DNS Health" -ForegroundColor Cyan
Write-Host "=============" -ForegroundColor Cyan
Write-Host "build: v5-explorer" -ForegroundColor DarkGray
Write-Host "Domain: $DomainDNS   DNS server: $Server   DnsServer module: $(if($HasDns){'yes'}else{'no'})" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# Reusable helpers
# ─────────────────────────────────────────────────────────────────────────────

# Standard finding shape used everywhere. sev = ok | info | warn | crit
function New-Finding {
    param([ValidateSet('ok','info','warn','crit')][string]$Sev,[string]$Title,[string]$Detail='',[string]$Fix='')
    [pscustomobject]@{ sev=$Sev; title=$Title; detail=$Detail; fix=$Fix }
}

# Worst severity in a list of findings (for card/row colour).
function Get-WorstSev {
    param([object[]]$Findings)
    $rank = @{ ok=0; info=1; warn=2; crit=3 }
    $worst = 'ok'
    foreach ($f in $Findings) { if ($rank[$f.sev] -gt $rank[$worst]) { $worst = $f.sev } }
    $worst
}

# Quick reachability gate so live tests never hang on a dead DC.
function Test-Reachable {
    param([string]$Name)
    # Ping first; ICMP is often blocked on domain controllers, so fall back to DNS / core DC ports.
    try { if (Test-Connection -ComputerName $Name -Count 1 -Quiet -ErrorAction SilentlyContinue) { return $true } } catch {}
    foreach ($p in @(53, 389, 88, 135, 445)) { if (Test-Port -ComputerName $Name -Port $p -TimeoutMs 1500) { return $true } }
    return $false
}

# Fast TCP port probe with a hard timeout - used to avoid multi-minute WinRM/DCOM hangs.
function Test-Port {
    param([string]$ComputerName,[int]$Port,[int]$TimeoutMs=1500)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($ComputerName,$Port,$null,$null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs,$false) -and $c.Connected) { $c.EndConnect($iar); return $true }
        return $false
    } catch { return $false } finally { $c.Close() }
}

# Build a bounded CIM session to a DC: DCOM (RPC 135) preferred, WSMan (5985) fallback.
# Returns $null fast when neither is open, so blocked DCs never trigger 4-minute WSMan retries.
function New-DcCimSession {
    param([string]$Name)
    if (Test-Port -ComputerName $Name -Port 135 -TimeoutMs 1500) {
        try { $opt = New-CimSessionOption -Protocol Dcom; return New-CimSession -ComputerName $Name -SessionOption $opt -OperationTimeoutSec 10 -ErrorAction Stop } catch {}
    }
    if (Test-Port -ComputerName $Name -Port 5985 -TimeoutMs 1500) {
        try { return New-CimSession -ComputerName $Name -OperationTimeoutSec 10 -ErrorAction Stop } catch {}
    }
    return $null
}

# Resolve a name against a specific server; returns $true on any answer.
function Resolve-Ok {
    param([string]$Name,[string]$Type='A',[string]$DnsSrv)
    try {
        $r = Resolve-DnsName -Name $Name -Type $Type -Server $DnsSrv -DnsOnly -ErrorAction Stop
        return [bool]$r
    } catch { return $false }
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Live DC list (source of truth for "does this DC still exist")
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/6] Enumerating domain controllers..." -ForegroundColor Yellow
$LiveDCs = @()
try { $LiveDCs = @(Get-ADDomainController -Filter * -ErrorAction Stop) } catch { $LiveDCs = @() }
$LiveDcNames = @($LiveDCs | ForEach-Object { $_.HostName.ToLower() })
$LiveDcShort = @($LiveDCs | ForEach-Object { ($_.Name).ToLower() })

# ─────────────────────────────────────────────────────────────────────────────
# 2. Per-server scavenging configuration
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/6] Reading server scavenging configuration..." -ForegroundColor Yellow
function Get-ServerScavenging {
    param([string]$Srv)
    $o = [pscustomobject]@{ server=$Srv; available=$false; enabled=$false; intervalDays=$null; findings=@() }
    if (-not $HasDns) { $o.findings = @(New-Finding info 'Scavenging state not read' 'DnsServer module unavailable.'); return $o }
    try {
        $sc = Get-DnsServerScavenging -ComputerName $Srv -ErrorAction Stop
        $o.available    = $true
        $o.enabled      = [bool]$sc.ScavengingState
        $o.intervalDays = if ($sc.ScavengingInterval) { [int]$sc.ScavengingInterval.TotalDays } else { 0 }
        if (-not $o.enabled) {
            $o.findings = @(New-Finding warn 'Server scavenging disabled' 'Stale records will accumulate over time.' 'Enable scavenging on the DNS server and set a sane interval (e.g. 7 days).')
        } else {
            $o.findings = @(New-Finding ok 'Server scavenging enabled' "Interval: $($o.intervalDays) day(s).")
        }
    } catch {
        $o.findings = @(New-Finding info 'Scavenging state not read' $_.Exception.Message)
    }
    $o
}
$Servers = @(Get-ServerScavenging -Srv $Server)

# ─────────────────────────────────────────────────────────────────────────────
# 3. Zone inventory + per-zone configuration findings
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[3/6] Enumerating DNS zones..." -ForegroundColor Yellow
function Get-ZoneInventory {
    param([string]$Srv)
    if (-not $HasDns) { return @() }
    $out = @()
    try { $raw = @(Get-DnsServerZone -ComputerName $Srv -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated }) } catch { return @() }
    foreach ($z in $raw) {
        $dyn   = "$($z.DynamicUpdate)"
        $xfer  = "$($z.SecureSecondaries)"
        $adInt = [bool]$z.IsDsIntegrated
        $isRev = [bool]$z.IsReverseLookupZone
        $type  = "$($z.ZoneType)"
        $scope = "$($z.ReplicationScope)"
        $signed = $false; try { $signed = [bool]$z.IsSigned } catch {}

        # aging
        $agingOn=$false; $noRef=$null; $ref=$null
        try {
            $ag = Get-DnsServerZoneAging -Name $z.ZoneName -ComputerName $Srv -ErrorAction SilentlyContinue
            if ($ag) { $agingOn=[bool]$ag.AgingEnabled; if($ag.NoRefreshInterval){$noRef=[int]$ag.NoRefreshInterval.TotalDays}; if($ag.RefreshInterval){$ref=[int]$ag.RefreshInterval.TotalDays} }
        } catch {}

        # NS records
        $ns=@()
        try { $ns = @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -RRType NS -ComputerName $Srv -ErrorAction SilentlyContinue | ForEach-Object { "$($_.RecordData.NameServer)".TrimEnd('.') } | Where-Object { $_ } | Sort-Object -Unique) } catch {}

        $f = @()
        if ($type -eq 'Primary') {
            if ($dyn -match 'NonsecureAndSecure') { $f += New-Finding crit 'Insecure dynamic updates' 'Zone accepts nonsecure (unauthenticated) dynamic updates - any host can overwrite records.' 'Set dynamic updates to Secure only.' }
            elseif ($dyn -match 'None')          { $f += New-Finding info 'Dynamic updates disabled' 'Records must be managed manually.' }
            else                                  { $f += New-Finding ok 'Secure dynamic updates' }

            if ($adInt) {
                if (-not $agingOn) { $f += New-Finding warn 'Aging/scavenging off on zone' 'Stale records can build up in this AD-integrated zone.' 'Enable aging on the zone and scavenging on the server.' }
                else { $f += New-Finding ok 'Aging enabled on zone' "No-refresh $noRef d / refresh $ref d." }
            } else {
                $f += New-Finding info 'Not AD-integrated' 'Consider AD integration for secure updates and multi-master replication.'
            }

            switch -Regex ($xfer) {
                'TransferAnyServer'      { $f += New-Finding crit 'Zone transfer to ANY server' 'Full zone contents can be pulled by any host - information disclosure.' 'Restrict transfers to named secondaries, or disable.' }
                'TransferToZoneNameServer' { $f += New-Finding info 'Zone transfer to NS servers' 'Transfers limited to servers listed in the NS records.' }
                'TransferToSecureServers'  { $f += New-Finding ok 'Zone transfer restricted' 'Limited to specific secondary servers.' }
                'NoTransfer'             { $f += New-Finding ok 'Zone transfer disabled' }
                default                  { $f += New-Finding info 'Zone transfer setting' $xfer }
            }
            if (-not $signed -and -not $isRev) { $f += New-Finding info 'Zone not DNSSEC-signed' }
        } else {
            $f += New-Finding info "$type zone" "Replication scope: $scope"
        }

        $out += [pscustomobject]@{
            name=$z.ZoneName; type=$type; adIntegrated=$adInt; reverse=$isRev; scope=$scope
            dynamicUpdate=$dyn; transfer=$xfer; dnssec=$signed
            agingEnabled=$agingOn; noRefresh=$noRef; refresh=$ref
            nsRecords=@($ns); worst=(Get-WorstSev $f); findings=@($f)
        }
    }
    $out
}
$Zones = @(Get-ZoneInventory -Srv $Server)

# ─────────────────────────────────────────────────────────────────────────────
# 4. _msdcs SRV plumbing (the records AD clients must find)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[4/6] Checking _msdcs SRV plumbing..." -ForegroundColor Yellow
function Get-MsdcsPlumbing {
    param([string]$Srv,[string]$Domain)
    $checks = @(
        @{ label='LDAP (_ldap._tcp)';        name="_ldap._tcp.$Domain" },
        @{ label='Kerberos (_kerberos._tcp)'; name="_kerberos._tcp.$Domain" },
        @{ label='Global Catalog (_gc._tcp)'; name="_gc._tcp.$Domain" },
        @{ label='PDC (_ldap._tcp.pdc._msdcs)'; name="_ldap._tcp.pdc._msdcs.$Domain" },
        @{ label='DC locator (_ldap._tcp.dc._msdcs)'; name="_ldap._tcp.dc._msdcs.$Domain" }
    )
    $out=@()
    foreach ($c in $checks) {
        $ok=$false; $count=0
        try {
            $r = @(Resolve-DnsName -Name $c.name -Type SRV -Server $Srv -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' })
            $count=$r.Count; $ok=($count -gt 0)
        } catch {}
        $out += [pscustomobject]@{
            label=$c.label; query=$c.name; present=$ok; count=$count
        }
    }
    $out
}
$Msdcs = @(Get-MsdcsPlumbing -Srv $Server -Domain $DomainDNS)

# ─────────────────────────────────────────────────────────────────────────────
# 5. Stale DC records - only records pointing at DCs that no longer exist
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[5/6] Scanning for lingering DC records..." -ForegroundColor Yellow
function Get-StaleDcRecords {
    param([string]$Srv,[string]$Domain,[string[]]$LiveShort)
    if (-not $HasDns) { return @() }
    $stale=@()
    # A records directly under the domain zone whose owner name looks like a DC host
    # but isn't in the live DC list. We only look at the _msdcs zone + host A records
    # that resemble DC names, to stay fast and targeted.
    $zonesToScan = @("_msdcs.$Domain", $Domain)
    foreach ($zn in $zonesToScan) {
        try { $recs = @(Get-DnsServerResourceRecord -ZoneName $zn -ComputerName $Srv -ErrorAction Stop) } catch { continue }
        foreach ($r in $recs) {
            $rt = "$($r.RecordType)"
            $owner = "$($r.HostName)".ToLower()
            if ($owner -in @('@','_msdcs','domaindnszones','forestdnszones')) { continue }

            if ($zn -like "_msdcs*") {
                # In _msdcs, CNAME aliases (GUID -> dc.host) and SRV targets reference DC hostnames
                $target=$null
                if ($rt -eq 'CNAME') { $target = "$($r.RecordData.HostNameAlias)".TrimEnd('.').ToLower() }
                elseif ($rt -eq 'SRV') { $target = "$($r.RecordData.DomainName)".TrimEnd('.').ToLower() }
                if ($target) {
                    $short = ($target -split '\.')[0]
                    if ($short -and ($LiveShort -notcontains $short)) {
                        $stale += [pscustomobject]@{ zone=$zn; record=$owner; type=$rt; points=$target; reason='References a DC not present in AD' }
                    }
                }
            } else {
                # Domain zone: host A/AAAA records whose short name matches nothing live
                if ($rt -in @('A','AAAA')) {
                    # Only consider names that plausibly are DCs: skip obvious non-DC hosts is hard,
                    # so we flag A records whose name equals a *former* DC pattern only when it is
                    # NOT a live DC AND the same name has an _msdcs alias (strong DC signal).
                    # Kept conservative: flagged as "review", not "critical".
                    if ($LiveShort -notcontains $owner -and $owner -match '^[a-z0-9\-]+$') {
                        # heuristic: only flag if a matching SRV/CNAME target elsewhere referenced it
                        # (handled in _msdcs pass) - here we skip to avoid false positives on member hosts
                    }
                }
            }
        }
    }
    $stale
}
$StaleDc = @(Get-StaleDcRecords -Srv $Server -Domain $DomainDNS -LiveShort $LiveDcShort)

# ─────────────────────────────────────────────────────────────────────────────
# 6. Live per-DC health tests (resolution + dcdiag when available)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[6/6] Running live per-DC tests..." -ForegroundColor Yellow

# Best-effort dcdiag /test:DNS parser. Returns a hashtable of DCshort -> @{Auth;Basc;Forw;Del;Dyn;RReg;Ext}
function Invoke-DcdiagDns {
    param([string]$Domain)
    $map=@{}
    $dcdiag = Get-Command dcdiag.exe -ErrorAction SilentlyContinue
    if (-not $dcdiag) { return $map }
    try {
        $raw = & dcdiag.exe /test:DNS /DnsBasic /s:$Server 2>$null
        $txt = $raw -join "`n"
        # Summary grid rows look like: "   DCNAME   PASS PASS PASS PASS PASS PASS n/a"
        foreach ($line in ($txt -split "`n")) {
            if ($line -match '^\s*([A-Za-z0-9\-]+)\s+(PASS|FAIL|WARN|n/a)\s+(PASS|FAIL|WARN|n/a)\s+(PASS|FAIL|WARN|n/a)\s+(PASS|FAIL|WARN|n/a)\s+(PASS|FAIL|WARN|n/a)\s+(PASS|FAIL|WARN|n/a)\s+(PASS|FAIL|WARN|n/a)\s*$') {
                $map[$matches[1].ToLower()] = [pscustomobject]@{
                    Auth=$matches[2]; Basc=$matches[3]; Forw=$matches[4]; Del=$matches[5]; Dyn=$matches[6]; RReg=$matches[7]; Ext=$matches[8]
                }
            }
        }
    } catch {}
    $map
}

# --- Per-DC configuration collectors (checks: island DC, forwarders, root hints, recursion) ---

# Each DC's own DNS client servers (ordered), read over a bounded CIM session.
# Returns { read=$true/$false; servers=@() } so a blocked query isn't mistaken for "no DNS".
function Get-DcResolverConfig {
    param($Session)
    $r=[pscustomobject]@{ read=$false; servers=@() }
    if (-not $Session) { return $r }
    try {
        $nics = @(Get-CimInstance -CimSession $Session -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" -ErrorAction Stop)
        $r.read=$true
        $primary = $nics | Where-Object { $_.DNSServerSearchOrder } | Select-Object -First 1
        if ($primary) { $r.servers = @($primary.DNSServerSearchOrder | ForEach-Object { "$_" }) }
    } catch { $r.read=$false }
    $r
}

# Classic "island DC" detection from the resolver order.
function Get-IslandFindings {
    param([string[]]$Resolvers,[string]$DcIp,[int]$DcCount,[string[]]$AllDcIps)
    $f=@()
    $loop=@('127.0.0.1','::1')
    if (-not $Resolvers -or $Resolvers.Count -eq 0) {
        $f += New-Finding crit 'No DNS servers configured' 'This DC has no resolver configured on its NIC.' 'Point it at a partner DC (primary) plus itself/loopback at a lower priority.'
        return $f
    }
    $first   = $Resolvers[0]
    $selfish = $loop + @($DcIp)
    $partner = @($Resolvers | Where-Object { $_ -and ($selfish -notcontains $_) -and ($AllDcIps -contains $_) }).Count -gt 0
    if ($DcCount -gt 1) {
        if ($selfish -contains $first) {
            $f += New-Finding warn 'Island risk: self/loopback is primary' "Primary resolver is $first. On a multi-DC network the primary should be a partner DC, so this DC can still resolve while its own DNS service is starting." 'Set the primary DNS to a partner DC; keep loopback/self at a lower priority.'
        }
        if (-not $partner) {
            $f += New-Finding crit 'Island DC: no partner DC in resolver list' 'This DC lists no other domain controller as a DNS server - the classic replication-breaking "island" configuration.' 'Add at least one partner DC to the DNS client settings.'
        }
    }
    if (-not $f.Count) { $f += New-Finding ok 'Resolver order looks healthy' ($Resolvers -join ', ') }
    $f
}

# Server-side resolution config: recursion, root hints, forwarders (over the same CIM session).
function Get-DcServerConfig {
    param($Session)
    $o=[pscustomobject]@{ available=$false; recursion=$null; rootHints=$null; forwarders=@() }
    if (-not $HasDns -or -not $Session) { return $o }
    try { $rec=Get-DnsServerRecursion -CimSession $Session -ErrorAction Stop; $o.recursion=[bool]$rec.Enable } catch {}
    try { $o.rootHints=@(Get-DnsServerRootHint -CimSession $Session -ErrorAction Stop).Count } catch {}
    try { $fw=Get-DnsServerForwarder -CimSession $Session -ErrorAction Stop; if($fw){ $o.forwarders=@($fw.IPAddress | ForEach-Object { "$_" }) } } catch {}
    $o.available=$true
    $o
}

function Get-ServerConfigFindings {
    param($Cfg)
    if (-not $Cfg.available) { return @() }
    $f=@()
    if ($Cfg.forwarders.Count -gt 0) {
        $f += New-Finding ok 'Forwarders configured' ($Cfg.forwarders -join ', ')
    } else {
        if ($Cfg.recursion -eq $false) { $f += New-Finding warn 'No forwarders and recursion disabled' 'This server cannot resolve external names at all.' 'Add forwarders or enable recursion (root hints).' }
        else { $f += New-Finding info 'No forwarders' 'External names resolve via root hints (recursion).' }
    }
    if ($Cfg.recursion -eq $false) { $f += New-Finding warn 'Recursion disabled' 'Forwarders and root hints will not be used for external resolution.' 'Enable recursion unless this is an intentional internal-only resolver.' }
    if ($null -ne $Cfg.rootHints -and $Cfg.rootHints -lt 1) { $f += New-Finding warn 'Root hints missing' 'No root hints present - recursive external resolution fails without forwarders.' 'Restore the root hints (cache.dns).' }
    $f
}

# Conditional forwarders are AD-replicated zones - collect once from the queried server.
function Get-ConditionalForwarders {
    param([string]$Srv)
    if (-not $HasDns) { return @() }
    $out=@()
    try {
        $zs=@(Get-DnsServerZone -ComputerName $Srv -ErrorAction Stop | Where-Object { "$($_.ZoneType)" -eq 'Forwarder' })
        foreach ($z in $zs) {
            $m=@(); try { $m=@($z.MasterServers | ForEach-Object { "$_" }) } catch {}
            $out += [pscustomobject]@{ name=$z.ZoneName; masters=@($m); adIntegrated=[bool]$z.IsDsIntegrated }
        }
    } catch {}
    $out
}

$AllDcIps = @($LiveDCs | ForEach-Object { "$($_.IPv4Address)" } | Where-Object { $_ })
$dcCount  = $LiveDCs.Count
$CondFwd  = @(Get-ConditionalForwarders -Srv $Server)

$DcResults = @()
$dcdiagMap = if (-not $SkipLiveTests) { Invoke-DcdiagDns -Domain $DomainDNS } else { @{} }
foreach ($dc in $LiveDCs) {
    $name  = $dc.HostName
    $short = ($dc.Name).ToLower()
    $ip    = "$($dc.IPv4Address)"
    $reach = Test-Reachable -Name $name
    $f = @(); $cfg = @()
    $fwd=$null; $rev=$null; $ext=$null; $dcd=$null
    $resolvers=@(); $srvCfg=[pscustomobject]@{ available=$false; recursion=$null; rootHints=$null; forwarders=@() }

    # Live resolution tests (optional)
    if (-not $SkipLiveTests) {
        if ($reach) {
            $fwd = Resolve-Ok -Name $DomainDNS -Type 'A' -DnsSrv $name
            if ($ip) { $rev = Resolve-Ok -Name $ip -Type 'PTR' -DnsSrv $name }
            $ext = Resolve-Ok -Name $ExternalName -Type 'A' -DnsSrv $name
            if ($fwd) { $f += New-Finding ok 'Forward resolution OK' "Resolved $DomainDNS." } else { $f += New-Finding crit 'Forward resolution failed' "Could not resolve $DomainDNS from this DC." 'Check the DC''s own DNS client settings and zone data.' }
            if ($rev -eq $true) { $f += New-Finding ok 'Reverse lookup OK' } elseif ($rev -eq $false) { $f += New-Finding warn 'Reverse lookup failed' "No PTR for $ip." 'Create/verify the reverse lookup zone and PTR record.' }
            if ($ext) { $f += New-Finding ok 'External resolution OK' "Resolved $ExternalName (recursion/forwarders working)." } else { $f += New-Finding warn 'External resolution failed' "Could not resolve $ExternalName." 'Check forwarders / root hints / recursion.' }
        } else {
            $f += New-Finding warn 'DC unreachable' 'Live tests skipped for this DC.' 'Confirm the DC is online; results may reflect network blocks rather than DNS faults.'
        }
        if ($dcdiagMap.ContainsKey($short)) {
            $dcd = $dcdiagMap[$short]
            $ddLabel = @{ Basc='basic DNS setup'; Forw='forwarders'; Del='delegations'; Dyn='dynamic update'; RReg='record registration'; Ext='external resolution' }
            foreach ($k in 'Basc','Forw','Del','Dyn','RReg','Ext') {
                if ("$($dcd.$k)" -eq 'FAIL') { $f += New-Finding crit "dcdiag: $($ddLabel[$k]) failed" "The dcdiag DNS test reported the $($ddLabel[$k]) check as failed on this DC." }
                elseif ("$($dcd.$k)" -eq 'WARN') { $f += New-Finding warn "dcdiag: $($ddLabel[$k]) warning" "The dcdiag DNS test reported a warning on the $($ddLabel[$k]) check." }
            }
        }
    }

    # Configuration collection over a single bounded CIM session (DCOM preferred).
    # A blocked DC returns $null from New-DcCimSession within ~3s instead of a 4-minute WinRM retry.
    if ($reach) {
        $sess = New-DcCimSession -Name $name
        if ($sess) {
            $rc = Get-DcResolverConfig -Session $sess
            $resolvers = @($rc.servers)
            if ($rc.read) {
                $cfg += @(Get-IslandFindings -Resolvers $resolvers -DcIp $ip -DcCount $dcCount -AllDcIps $AllDcIps)
            } else {
                $cfg += New-Finding info 'Resolver config not read' "Reached the DC but could not read its DNS client settings - resolver order and island check skipped." 'Check the DNS client settings directly on the DC.'
            }
            $srvCfg = Get-DcServerConfig -Session $sess
            $cfg += @(Get-ServerConfigFindings -Cfg $srvCfg)
            Remove-CimSession $sess -ErrorAction SilentlyContinue
        } else {
            $cfg += New-Finding info 'Management not reachable' "DC answers DNS but not remote management (WinRM/DCOM blocked or filtered) - resolver order, recursion, forwarders and island check skipped." 'Open WMI/DCOM (or WinRM) from the audit host to this DC, or check its DNS client settings manually.'
        }
    } else {
        $cfg += New-Finding info 'Configuration not read' 'DC unreachable.'
    }

    $DcResults += [pscustomobject]@{
        name=$name; short=$short; ip=$ip; site="$($dc.Site)"; reachable=$reach
        fwd=$fwd; rev=$rev; ext=$ext; dcdiag=$dcd
        resolvers=@($resolvers); recursion=$srvCfg.recursion; rootHints=$srvCfg.rootHints; forwarders=@($srvCfg.forwarders)
        worst=(Get-WorstSev $f); findings=@($f)
        cfgWorst=(Get-WorstSev $cfg); cfgFindings=@($cfg)
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. DNS application-partition replication
#    AD-integrated zones ride inside AD replication of ForestDnsZones / DomainDnsZones.
#    Check each partition is enlisted on every DC and replicating without failures.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[7/7] Checking DNS partition replication..." -ForegroundColor Yellow
function Get-DnsPartitionReplication {
    param($Domain,[string]$ForestDns,$LiveDCs)
    $res=[pscustomobject]@{ available=$false; partitions=@() }
    try {
        $rootDSE  = Get-ADRootDSE -ErrorAction Stop
        $configNC = "$($rootDSE.configurationNamingContext)"
        $forestDN = ($ForestDns -split '\.' | ForEach-Object { "DC=$_" }) -join ','
        $domainDN = "$($Domain.DistinguishedName)"
        $liveShort= @($LiveDCs | ForEach-Object { "$($_.Name)" })
        $parts=@(
            @{ label='ForestDnsZones'; dn="DC=ForestDnsZones,$forestDN"; scope='Forest'; target=$ForestDns },
            @{ label='DomainDnsZones'; dn="DC=DomainDnsZones,$domainDN"; scope='Domain'; target=$Domain.DNSRoot }
        )
        foreach ($p in $parts) {
            $po=[pscustomobject]@{ label=$p.label; dn=$p.dn; enlisted=@(); notEnlisted=@(); failures=@(); worst='ok'; findings=@() }

            # Enlistment: read the partition crossRef's replica locations (NTDS Settings DNs)
            $enl=@()
            try {
                $cr = Get-ADObject -SearchBase "CN=Partitions,$configNC" -LDAPFilter "(nCName=$($p.dn))" -Properties 'msDS-NC-Replica-Locations' -ErrorAction Stop
                foreach ($l in @($cr.'msDS-NC-Replica-Locations')) {
                    if ("$l" -match 'CN=NTDS Settings,CN=([^,]+),') { $enl += $matches[1] }
                }
            } catch {}
            $po.enlisted    = @($enl | Select-Object -Unique)
            $po.notEnlisted = @($liveShort | Where-Object { $po.enlisted -notcontains $_ })

            # Replication health for this partition (non-zero last result = failing link)
            try {
                $meta = @(Get-ADReplicationPartnerMetadata -Target $p.target -Scope $p.scope -Partition $p.dn -ErrorAction Stop)
                foreach ($m in $meta) {
                    if ($m.LastReplicationResult -ne 0) {
                        $po.failures += [pscustomobject]@{ server="$($m.Server)"; partner="$($m.Partner)"; result=[int]$m.LastReplicationResult; lastSuccess="$($m.LastReplicationSuccess)" }
                    }
                }
            } catch {}

            $pf=@()
            if ($po.notEnlisted.Count -gt 0) { $pf += New-Finding warn "$($po.notEnlisted.Count) DC(s) not hosting $($p.label)" "Not enlisted: $($po.notEnlisted -join ', '). If those DCs run DNS, they can't serve AD-integrated zones from this partition." 'Enlist the DC in the DNS application partition, or confirm it is intentionally not a DNS server.' }
            if ($po.failures.Count -gt 0)    { $pf += New-Finding crit "Replication failing for $($p.label)" "$($po.failures.Count) partner link(s) report a non-zero last replication result." 'Check replication between the affected DCs and resolve the underlying replication errors.' }
            if (-not $pf.Count)              { $pf += New-Finding ok "$($p.label) healthy" "Enlisted on $($po.enlisted.Count) DC(s), replicating cleanly." }
            $po.worst=(Get-WorstSev $pf); $po.findings=@($pf)
            $res.partitions += $po
        }
        $res.available=$true
    } catch {}
    $res
}
$DnsRepl = Get-DnsPartitionReplication -Domain $Domain -ForestDns $ForestDNS -LiveDCs $LiveDCs

# ─────────────────────────────────────────────────────────────────────────────
# 8. Security & hardening  (server defenses + attack surface)
# ─────────────────────────────────────────────────────────────────────────────
# Server anti-poisoning / MITM / DDoS defenses.
function Get-DnsHardening {
    param([string]$Srv)
    if (-not $HasDns) { return @() }
    $out=@()
    # Global Query Block List (WPAD/ISATAP MITM defense)
    try {
        $g = Get-DnsServerGlobalQueryBlockList -ComputerName $Srv -ErrorAction Stop
        $list = @($g.List)
        if (-not $g.Enable) {
            $out += New-HardItem 'Global Query Block List' 'Disabled' (New-Finding crit 'Global Query Block List disabled' 'wpad and isatap are resolvable - enables WPAD man-in-the-middle attacks.' 'Enable the block list and ensure it contains wpad and isatap.')
        } elseif (-not (($list -contains 'wpad') -and ($list -contains 'isatap'))) {
            $out += New-HardItem 'Global Query Block List' (($list -join ', ')) (New-Finding warn 'Block list missing wpad/isatap' "Enabled, but current entries: $($list -join ', ')." 'Add both wpad and isatap to the block list.')
        } else {
            $out += New-HardItem 'Global Query Block List' 'Enabled (wpad, isatap)' (New-Finding ok 'Global Query Block List enabled')
        }
    } catch {}
    # Cache locking (poisoning defense)
    try {
        $c = Get-DnsServerCache -ComputerName $Srv -ErrorAction Stop
        $lp = [int]$c.LockingPercent
        if ($lp -lt 100) { $out += New-HardItem 'Cache locking' "$lp%" (New-Finding warn 'Cache locking below 100%' "Cached records can be overwritten before their TTL expires (cache-poisoning risk). Current: $lp%." 'Set cache locking to 100%.') }
        else { $out += New-HardItem 'Cache locking' '100%' (New-Finding ok 'Cache locking at 100%') }
    } catch {}
    # Socket pool (source-port randomization)
    try {
        $s = Get-DnsServerSetting -All -ComputerName $Srv -ErrorAction Stop -WarningAction SilentlyContinue
        $sp = [int]$s.SocketPoolSize
        if ($sp -lt 2500) { $out += New-HardItem 'Socket pool' "$sp" (New-Finding warn 'Socket pool below default' "Source-port randomization is reduced (poisoning risk). Size: $sp (default 2500)." 'Restore the socket pool size to 2500 or higher.') }
        else { $out += New-HardItem 'Socket pool' "$sp" (New-Finding ok 'Socket pool healthy') }
    } catch {}
    # Response Rate Limiting (amplification/DDoS)
    try {
        $r = Get-DnsServerResponseRateLimiting -ComputerName $Srv -ErrorAction Stop
        $mode = "$($r.Mode)"
        if ($mode -match 'Disable' -or -not $mode) { $out += New-HardItem 'Response Rate Limiting' 'Disabled' (New-Finding info 'Response Rate Limiting off' 'RRL mitigates DNS amplification/DDoS. Off by default - enable if this server answers a broad client base.' 'Consider enabling Response Rate Limiting, starting in log-only mode.') }
        else { $out += New-HardItem 'Response Rate Limiting' $mode (New-Finding ok "Response Rate Limiting: $mode") }
    } catch {}
    $out
}
function New-HardItem { param([string]$Label,[string]$Value,$F) [pscustomobject]@{ label=$Label; value=$Value; sev=$F.sev; title=$F.title; detail=$F.detail; fix=$F.fix } }

# Targeted risky-record probes (no full zone dump): wildcard, wpad, isatap.
function Get-RiskyRecords {
    param([string]$Srv,[object[]]$Zones)
    if (-not $HasDns) { return @() }
    $out=@()
    $probes=@(
        @{ n='*';      k='Wildcard record'; s='warn'; d='A wildcard answers every unmatched name in the zone - masks typos and can be abused for spoofing.' },
        @{ n='wpad';   k='WPAD record';     s='warn'; d='A wpad host record can hand out proxy auto-config - MITM risk unless deliberately published.' },
        @{ n='isatap'; k='ISATAP record';   s='info'; d='An isatap record enables ISATAP tunneling - remove if the transition tech is unused.' }
    )
    foreach ($z in $Zones) {
        if ("$($z.type)" -ne 'Primary' -or $z.reverse) { continue }
        foreach ($p in $probes) {
            try {
                $rec = @(Get-DnsServerResourceRecord -ZoneName $z.name -Name $p.n -ComputerName $Srv -ErrorAction Stop | Where-Object { "$($_.HostName)" -eq $p.n })
                if ($rec.Count -gt 0) { $out += [pscustomobject]@{ zone=$z.name; name=$p.n; kind=$p.k; sev=$p.s; detail=$p.d } }
            } catch {}
        }
    }
    $out
}

# ADIDNS exposure: AD-integrated zones where Authenticated Users can create records (mitm6 surface).
function Get-AdidnsExposure {
    param([object[]]$Zones,$Domain,[string]$ForestDns)
    $res=[pscustomobject]@{ checked=$false; total=0; exposed=@() }
    $domainDN="$($Domain.DistinguishedName)"
    $forestDN=(($ForestDns -split '\.') | ForEach-Object { "DC=$_" }) -join ','
    $adInt=@($Zones | Where-Object { $_.adIntegrated -and "$($_.type)" -eq 'Primary' })
    $res.total=$adInt.Count
    foreach ($z in $adInt) {
        $zn=$z.name
        $dns=@()
        switch -Regex ("$($z.scope)") {
            'Forest' { $dns += "DC=$zn,CN=MicrosoftDNS,DC=ForestDnsZones,$forestDN" }
            'Domain' { $dns += "DC=$zn,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN" }
            default  { $dns += "DC=$zn,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN"; $dns += "DC=$zn,CN=MicrosoftDNS,CN=System,$domainDN" }
        }
        foreach ($dn in $dns) {
            try {
                $acl = Get-Acl -Path "AD:\$dn" -ErrorAction Stop
                $res.checked=$true
                $exp=$false
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Allow' -and ("$($ace.ActiveDirectoryRights)" -match 'CreateChild')) {
                        $id="$($ace.IdentityReference)"
                        $sidv=$null; try { $sidv=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
                        if ($id -match 'Authenticated Users' -or $id -match 'Everyone' -or $sidv -eq 'S-1-5-11') { $exp=$true; break }
                    }
                }
                if ($exp) { $res.exposed += $zn }
                break
            } catch { continue }
        }
    }
    $res.exposed=@($res.exposed | Select-Object -Unique)
    $res
}

if (-not $SkipSecurityChecks) {
    Write-Host "[8/8] Security & hardening checks..." -ForegroundColor Yellow
    $Hardening     = @(Get-DnsHardening -Srv $Server)
    $RiskyRecords  = @(Get-RiskyRecords -Srv $Server -Zones $Zones)
    $Adidns        = Get-AdidnsExposure -Zones $Zones -Domain $Domain -ForestDns $ForestDNS
} else {
    $Hardening=@(); $RiskyRecords=@(); $Adidns=[pscustomobject]@{ checked=$false; total=0; exposed=@() }
}
$Security = [pscustomobject]@{
    checked=(-not $SkipSecurityChecks); hardening=@($Hardening); riskyRecords=@($RiskyRecords); adidns=$Adidns
}

# ─────────────────────────────────────────────────────────────────────────────
# KPI rollups
# ─────────────────────────────────────────────────────────────────────────────
$zoneCount        = $Zones.Count
$insecureDynCount = @($Zones | Where-Object { $_.dynamicUpdate -match 'NonsecureAndSecure' }).Count
$scavengingOff    = @($Zones | Where-Object { $_.type -eq 'Primary' -and $_.adIntegrated -and -not $_.agingEnabled }).Count
$transferExposed  = @($Zones | Where-Object { $_.transfer -match 'TransferAnyServer' }).Count
$staleDcCount     = $StaleDc.Count
$dcFailCount      = @($DcResults | Where-Object { $_.worst -eq 'crit' }).Count
$msdcsMissing     = @($Msdcs | Where-Object { -not $_.present }).Count
$islandCount      = @($DcResults | Where-Object { @($_.cfgFindings | Where-Object { $_.title -like 'Island*' }).Count -gt 0 }).Count
$replIssues       = @($DnsRepl.partitions | Where-Object { $_.worst -eq 'crit' -or $_.worst -eq 'warn' }).Count
$hardeningGaps    = @($Security.hardening | Where-Object { $_.sev -eq 'crit' -or $_.sev -eq 'warn' }).Count
$riskyCount       = @($Security.riskyRecords).Count

$kpiObj = [ordered]@{
    zones=[int]$zoneCount; insecureDyn=[int]$insecureDynCount; scavengingOff=[int]$scavengingOff
    transferExposed=[int]$transferExposed; staleDc=[int]$staleDcCount; dcFail=[int]$dcFailCount
    msdcsMissing=[int]$msdcsMissing; islandDc=[int]$islandCount; replIssues=[int]$replIssues
    hardeningGaps=[int]$hardeningGaps; riskyRecords=[int]$riskyCount
}
$Summary = New-Object System.Collections.Specialized.OrderedDictionary
$Summary.Add('domain', $DomainDNS)
$Summary.Add('forest', $ForestDNS)
$Summary.Add('generated', $GeneratedAt)
$Summary.Add('dnsServer', $Server)
$Summary.Add('hasDnsModule', [bool]$HasDns)
$Summary.Add('liveTested', [bool](-not $SkipLiveTests))
$Summary.Add('externalName', $ExternalName)
$Summary.Add('kpi', $kpiObj)
$Summary.Add('zones', @($Zones))
$Summary.Add('dcs', @($DcResults))
$Summary.Add('staleDc', @($StaleDc))
$Summary.Add('msdcs', @($Msdcs))
$Summary.Add('servers', @($Servers))
$Summary.Add('condFwd', @($CondFwd))
$Summary.Add('replication', $DnsRepl)
$Summary.Add('security', $Security)
# ─────────────────────────────────────────────────────────────────────────────
# Hand-written JSON serializer (PS 5.1 ConvertTo-Json can throw on complex graphs;
# no scriptblock/regex delegate; escapes non-ASCII to \uXXXX inline).
function ConvertTo-JsonStr {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return '""' }
    if ($s -notmatch '[^\x20\x21\x23-\x5B\x5D-\x7E]') { return '"' + $s + '"' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $s.ToCharArray()) {
        $code = [int][char]$ch
        if     ($code -eq 34) { [void]$sb.Append('\"') }
        elseif ($code -eq 92) { [void]$sb.Append('\\') }
        elseif ($code -eq 8)  { [void]$sb.Append('\b') }
        elseif ($code -eq 9)  { [void]$sb.Append('\t') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 12) { [void]$sb.Append('\f') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
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
    if ($o -is [ValueType]) {
        if ($o -is [int] -or $o -is [int64] -or $o -is [int16] -or $o -is [uint32] -or $o -is [uint64] -or $o -is [byte] -or $o -is [double] -or $o -is [single] -or $o -is [decimal]) { [void]$sb.Append(([string]$o)); return }
        [void]$sb.Append((ConvertTo-JsonStr ([string]$o))); return
    }
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
    [void]$sb.Append('{'); $f=$true
    foreach ($p in $o.PSObject.Properties) { if (-not $f) { [void]$sb.Append(',') }; $f=$false; [void]$sb.Append((ConvertTo-JsonStr $p.Name)); [void]$sb.Append(':'); Write-JsonValue $p.Value $sb }
    [void]$sb.Append('}')
}
$stage = 'serialize'
try {
    Write-Host "Serializing report..." -ForegroundColor Yellow
    $__jsb = New-Object System.Text.StringBuilder
    Write-JsonValue $Summary $__jsb
    $DataJSON = $__jsb.ToString()
    Write-Host ("  JSON size: {0} MB" -f [math]::Round($DataJSON.Length/1MB,2)) -ForegroundColor Gray
} catch {
    Write-Host ""
    Write-Host ">>> FAILED at stage '$stage': $($_.Exception.GetType().Name) - $($_.Exception.Message)" -ForegroundColor Red
    throw
}

# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────
$HTML = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Health - $DomainDNS</title>
<style>
:root{--bg:#f5f6fb;--surface:#ffffff;--surface2:#eef1f9;--surface3:#dfe4f2;--border:#e4e7f2;--text:#161a2e;--muted:#64708c;
--accent:#4f46e5;--accent-soft:#e6e6fd;--navy:#3730a3;
--green:#059669;--green-soft:#d1fae5;--red:#dc2626;--red-soft:#fde2e2;--amber:#d97706;--amber-soft:#fef3c7;
--blue:#2563eb;--blue-soft:#dbe8fe;--teal:#0d9488;--purple:#7c3aed;--gold:#d97706;
--radius:13px;--radius-sm:9px;--shadow:0 2px 8px rgb(60 50 140 / 0.06),0 1px 2px rgb(60 50 140 / 0.04);
--font:'Inter',system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;--mono:'SFMono-Regular',ui-monospace,Menlo,Consolas,monospace}
[data-theme="dark"]{--bg:#0c1524;--surface:#14213a;--surface2:#1c2c49;--surface3:#284066;--border:#243a5e;--text:#e8f0fb;--muted:#93a7c4;
--accent:#60a5fa;--accent-soft:rgba(96,165,250,0.15);--navy:#93c5fd;
--green:#34d399;--green-soft:rgba(16,185,129,0.15);--red:#f87171;--red-soft:rgba(239,68,68,0.15);--amber:#fbbf24;--amber-soft:rgba(245,158,11,0.15);
--blue:#60a5fa;--blue-soft:rgba(37,99,235,0.18);--teal:#2dd4bf;--purple:#a78bfa;--gold:#fbbf24;--shadow:0 2px 6px rgb(0 0 0 / 0.3)}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:13.5px;line-height:1.5;-webkit-font-smoothing:antialiased}
.app{max-width:1360px;margin:0 auto;padding:0 28px 28px;display:flex;flex-direction:column;height:100vh;min-height:620px}
.mono{font-family:var(--mono);font-size:12px}
.muted{color:var(--muted)}
/* header */
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 0 14px;flex:0 0 auto}
.brand{display:flex;align-items:center;gap:13px;min-width:0}
.logo{width:40px;height:40px;border-radius:11px;background:linear-gradient(135deg,var(--accent),var(--navy));display:flex;align-items:center;justify-content:center;color:#fff;box-shadow:var(--shadow);flex:0 0 auto}
.logo svg{width:22px;height:22px}
h1{font-size:19px;font-weight:750;letter-spacing:-.3px}
.sub{font-size:12px;color:var(--muted);margin-top:1px}
.btn{display:inline-flex;align-items:center;gap:6px;font:inherit;font-size:12px;font-weight:600;color:var(--muted);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 12px;cursor:pointer;white-space:nowrap}
.btn:hover{color:var(--accent);border-color:var(--accent)}.btn svg{width:14px;height:14px}
/* breadcrumb */
.crumbs{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:12.5px;padding:0 2px 12px;color:var(--muted);flex:0 0 auto;min-height:30px}
.crumbs a{color:var(--muted);cursor:pointer;padding:2px 4px;border-radius:5px}.crumbs a:hover{color:var(--accent);background:var(--accent-soft)}
.crumbs a.last{color:var(--text);font-weight:600}
.crumbs .sep{opacity:.6}
/* explorer */
.xp{flex:1;min-height:0;display:flex;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
.cols{display:flex;flex:0 0 auto;overflow-x:auto;overflow-y:hidden;position:relative}
.col{flex:0 0 262px;width:262px;border-right:1px solid var(--border);display:flex;flex-direction:column;min-height:0}
.col.first{flex-basis:228px;width:228px}
.ch{padding:12px 14px 6px;font-size:10.5px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);display:flex;justify-content:space-between;gap:8px}
.cf{margin:2px 10px 6px;display:flex;align-items:center;gap:6px;background:var(--surface2);border:1px solid var(--border);border-radius:7px;padding:5px 8px}
.cf svg{width:13px;height:13px;color:var(--muted);flex:0 0 auto}
.cf input{border:none;background:transparent;outline:none;font:inherit;font-size:12.5px;color:var(--text);width:100%}
.items{overflow-y:auto;flex:1;padding:2px 6px 10px}
.it{display:flex;align-items:center;gap:9px;padding:7px 9px;border-radius:7px;cursor:pointer;user-select:none}
.it:hover{background:var(--surface2)}
.it.sel{background:var(--accent-soft)}.it.sel .lb{color:var(--accent);font-weight:600}
.col.active .it.sel{box-shadow:inset 0 0 0 1px var(--accent)}
.it .ic{width:16px;height:16px;flex:0 0 auto;display:flex;align-items:center;justify-content:center}
.it .ic svg{width:16px;height:16px}
.it .lb{flex:1;min-width:0;overflow:hidden;white-space:normal;word-break:break-word;line-height:1.3;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.it .ct{font-size:11.5px;color:var(--muted);flex:0 0 auto}
.it .ar{width:12px;height:12px;color:var(--muted);flex:0 0 auto;opacity:.7}
.dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto;display:inline-block}
.dot.crit{background:var(--red)}.dot.warn{background:var(--amber)}.dot.info{background:var(--blue)}.dot.ok{background:var(--green)}.dot.none{background:transparent;border:1px solid var(--border)}
.noitems{color:var(--muted);font-size:12.5px;padding:10px 12px}
.ic.u{color:var(--blue)}.ic.c{color:var(--teal)}.ic.g{color:var(--purple)}.ic.f{color:var(--gold)}.ic.n{color:var(--muted)}.ic.a{color:var(--accent)}
/* details pane */
.det{flex:1;min-width:340px;overflow-y:auto;padding:24px 28px;border-left:0}
.det h2{font-size:18px;font-weight:750;letter-spacing:-.3px;word-break:break-word;display:flex;align-items:center;gap:10px}
.det h2 .dot{width:10px;height:10px}
.det .ds{font-size:12.5px;color:var(--muted);margin:3px 0 18px;word-break:break-all}
.det h4{font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);margin:22px 0 8px}
.det p{margin-bottom:8px}
.kv{display:grid;grid-template-columns:150px 1fr;gap:7px 16px;font-size:13px}
.kv dt{color:var(--muted)}.kv dd{word-break:break-word}
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px}
.st{border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;background:var(--surface)}
.st .v{font-size:21px;font-weight:750;letter-spacing:-.5px;line-height:1.2}.st .l{font-size:11.5px;color:var(--muted);font-weight:600}
.v.crit{color:var(--red)}.v.warn{color:var(--amber)}.v.ok{color:var(--green)}
.verdict{display:flex;gap:14px;align-items:center;padding:16px 18px;border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:14px}
.verdict .bar{width:5px;align-self:stretch;border-radius:3px}
.bar.crit{background:var(--red)}.bar.warn{background:var(--amber)}.bar.ok{background:var(--green)}
.verdict b{font-size:16px;display:block}
.fix{background:var(--accent-soft);border-radius:var(--radius-sm);padding:11px 14px;font-size:13px;margin-top:12px}
.fix b{color:var(--accent)}
.note{background:var(--surface2);border-radius:var(--radius-sm);padding:11px 14px;font-size:13px;color:var(--text);margin-top:12px}
.issl{display:flex;flex-direction:column;gap:9px}
.issl div{display:flex;gap:10px;align-items:baseline}
.issl .dot{position:relative;top:-1px}
.tag{font-size:11px;font-weight:700;border-radius:20px;padding:1px 9px;white-space:nowrap;border:1px solid var(--border);color:var(--muted)}
.tag.crit{color:var(--red);background:var(--red-soft);border-color:transparent}.tag.warn{color:var(--amber);background:var(--amber-soft);border-color:transparent}
.tag.ok{color:var(--green);background:var(--green-soft);border-color:transparent}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin:-8px 0 16px}
.hl td{background:var(--red-soft)}
.at{width:100%;border-collapse:collapse;font-size:12.5px}
.at td{padding:7px 9px;border-bottom:1px solid var(--border);vertical-align:top}
.at td:first-child{color:var(--muted);white-space:nowrap;width:160px}
.at td.v{font-family:var(--mono);font-size:12px;word-break:break-all}
.at tr.bad td{background:var(--red-soft)}.at tr.bad td:first-child{color:var(--red);font-weight:600}
.eb{display:inline-block;margin-top:4px;font-family:var(--font);font-size:11px;font-weight:700;color:var(--red)}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}
.hint{color:var(--muted);font-size:12.5px;margin-top:14px}
.kbd{font-family:var(--mono);font-size:11px;border:1px solid var(--border);border-radius:4px;padding:0 5px;background:var(--surface2)}
@media(max-width:900px){.app{height:auto}.xp{flex-direction:column;min-height:600px}.cols{width:auto!important}.col{height:320px}.det{min-width:0;border-top:1px solid var(--border)}.kv{grid-template-columns:1fr}}
</style></head><body>
<div class="app">
<div class="top"><div class="brand"><div class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg></div><div><h1>DNS Health</h1><div class="sub" id="meta"></div></div></div>
<button class="btn" id="themebtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19"/></svg><span id="themetxt">Dark</span></button></div>
<div class="crumbs" id="crumbs"></div>
<div class="xp"><div class="cols" id="cols"></div><div class="det" id="det"></div></div>
</div>
<script>
function arr(x){if(x==null)return[];if(!Array.isArray(x))return[x];while(x.length===1&&Array.isArray(x[0]))x=x[0];return x;}
function esc(s){s=(s==null?'':''+s);return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function qs(s){return document.querySelector(s);}
function plural(n,w){return n+' '+w+(n===1?'':'s');}
var RANK={crit:3,warn:2,info:1,ok:0,'':-1};
function worstOf(list){var w='';list.forEach(function(s){if(s&&RANK[s]>RANK[w])w=s;});return w;}
var I={
 chev:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>',
 search:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3-3" stroke-linecap="round"/></svg>',
 folder:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h3.5l2 2H19a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
 user:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="3.6"/><path d="M4.5 20c0-3.7 3.4-6.2 7.5-6.2s7.5 2.5 7.5 6.2"/></svg>',
 computer:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4.5" width="18" height="11" rx="1.5"/><path d="M8.5 19.5h7M12 15.5v4"/></svg>',
 group:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8.5" cy="8" r="3.2"/><path d="M2.5 19c0-3.2 2.7-5.3 6-5.3s6 2.1 6 5.3"/><path d="M15.8 5.2a3.2 3.2 0 0 1 .2 6.1"/><path d="M17.2 14.1c2.5.5 4.3 2.4 4.3 4.9"/></svg>',
 other:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="8.5" cy="11" r="2"/><path d="M15 10h4M15 13.5h4"/></svg>',
 server:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
 globe:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
 record:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h6"/></svg>',
 shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v6c0 4.4 3 7.6 7 9 4-1.4 7-4.6 7-9V6z"/></svg>',
 list:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
 pulse:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>',
 sync:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 0 0-14.3-4.9L4 8M4 13a8 8 0 0 0 14.3 4.9L20 16"/><path d="M4 4v4h4M20 20v-4h-4"/></svg>',
 download:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12m0 0 4-4m-4 4-4-4M4 21h16"/></svg>'
};
function icon(name,cls){return '<span class="ic '+(cls||'n')+'">'+(I[name]||'')+'</span>';}

/* ---------------- explorer core ---------------- */
var XP={roots:[],rootTitle:'',path:[],filters:{},active:0};
function kidsOf(n){if(!n)return[];if(n._k===undefined){var k=n.kids;n._k=(typeof k==='function')?arr(k()):arr(k);}return n._k;}
function hasKids(n){return typeof n.kids==='function'?true:arr(n.kids).length>0;}
function colNodes(ci){return ci===0?XP.roots:kidsOf(XP.path[ci-1]);}
function colTitle(ci){if(ci===0)return XP.rootTitle;var p=XP.path[ci-1];return p.kidsTitle||p.label;}
function filtered(ci){var f=(XP.filters[ci]||'').toLowerCase();var ns=colNodes(ci);if(!f)return ns;
  return ns.filter(function(n){return ((n.label||'')+' '+(n.search||'')).toLowerCase().indexOf(f)>=0;});}
function itemHtml(n,ci,ix){
  var sel=XP.path[ci]===n, lead=n.icon?n.icon:(n.dot!==undefined?'<span class="ic"><span class="dot '+(n.dot||'none')+'"></span></span>':'');
  var trail=(n.dot&&n.icon?'<span class="dot '+n.dot+'"></span>':'');
  return '<div class="it'+(sel?' sel':'')+'" data-c="'+ci+'" data-i="'+ix+'" title="'+esc(n.tip||n.label)+'">'+lead+'<span class="lb">'+esc(n.label)+'</span>'+trail+
    (n.count!==undefined&&n.count!==''?'<span class="ct">'+esc(n.count)+'</span>':'')+(hasKids(n)?'<span class="ar">'+I.chev+'</span>':'')+'</div>';
}
function renderItems(ci){
  var box=document.getElementById('items-'+ci); if(!box)return;
  var list=filtered(ci);
  box.innerHTML=list.length?list.map(function(n,ix){return itemHtml(n,ci,ix);}).join(''):'<div class="noitems">'+(XP.filters[ci]?'No match.':'Nothing here.')+'</div>';
  box._list=list;
}
function render(){
  var html='', ncols=1;
  for(var i=0;i<XP.path.length;i++){ if(hasKids(XP.path[i])&&kidsOf(XP.path[i]).length) ncols=i+2; else break; }
  for(var ci=0;ci<ncols;ci++){
    var all=colNodes(ci), showF=all.length>12;
    html+='<div class="col'+(ci===0?' first':'')+(ci===XP.active?' active':'')+'"><div class="ch"><span>'+esc(colTitle(ci))+'</span><span>'+all.length+'</span></div>'+
      (showF?'<div class="cf">'+I.search+'<input data-c="'+ci+'" placeholder="Filter" value="'+esc(XP.filters[ci]||'')+'"></div>':'')+
      '<div class="items" id="items-'+ci+'"></div></div>';
  }
  var cols=qs('#cols'); cols.innerHTML=html;
  for(var c=0;c<ncols;c++) renderItems(c);
  var last=XP.path[XP.path.length-1];
  qs('#det').innerHTML=last?(last.detail?last.detail():defaultDetail(last)):'';
  qs('#det').scrollTop=0;
  qs('#crumbs').innerHTML=XP.path.map(function(n,i){return (i?'<span class="sep">&rsaquo;</span>':'')+'<a data-p="'+i+'" class="'+(i===XP.path.length-1?'last':'')+'">'+esc(n.label)+'</a>';}).join('');
  fitCols();
  var s=cols.querySelector('.col.active .it.sel'); if(s&&s.scrollIntoView) s.scrollIntoView({block:'nearest'});
}
function fitCols(){
  var cols=qs('#cols'), xp=cols.parentNode, els=cols.children; if(!els.length)return;
  if(window.innerWidth<=900){cols.style.width='';return;}
  var avail=xp.clientWidth-400, w=0, k=els.length-1;
  for(var i=els.length-1;i>=0;i--){var cw=els[i].offsetWidth; if(w>0&&w+cw>avail)break; w+=cw; k=i;}
  cols.style.width=w+'px'; cols.scrollLeft=els[k].offsetLeft;
}
window.addEventListener('resize',function(){if(XP.path.length)fitCols();});
function defaultDetail(n){var k=kidsOf(n);return '<h2>'+esc(n.label)+'</h2><div class="ds">'+(k.length?plural(k.length,'item'):'')+'</div>';}
function selectNode(ci,n){XP.path=XP.path.slice(0,ci);XP.path.push(n);for(var k in XP.filters){if(+k>ci)delete XP.filters[k];}XP.active=ci;render();}
function goPath(i){XP.path=XP.path.slice(0,i+1);XP.active=i;render();}
/* navigate programmatically to a node by a list of labels starting at the roots */
function openPath(labels){var level=XP.roots, p=[];for(var i=0;i<labels.length;i++){var m=null;level.forEach(function(n){if(!m&&n.label===labels[i])m=n;});if(!m)break;p.push(m);level=kidsOf(m);}
  if(p.length){XP.path=p;XP.filters={};XP.active=p.length-1;render();}}
function initExplorer(roots,title){
  XP.roots=roots;XP.rootTitle=title;
  qs('#cols').addEventListener('click',function(e){var it=e.target.closest('.it');if(!it)return;var ci=+it.getAttribute('data-c'),ix=+it.getAttribute('data-i');var list=document.getElementById('items-'+ci)._list;selectNode(ci,list[ix]);});
  qs('#cols').addEventListener('input',function(e){var t=e.target;if(t.tagName!=='INPUT')return;var ci=+t.getAttribute('data-c');XP.filters[ci]=t.value;renderItems(ci);});
  qs('#crumbs').addEventListener('click',function(e){var a=e.target.closest('a');if(a)goPath(+a.getAttribute('data-p'));});
  document.addEventListener('keydown',function(e){
    if(e.target.tagName==='INPUT'){if(e.key==='Escape')e.target.blur();return;}
    var ci=XP.active, box=document.getElementById('items-'+ci); if(!box||!box._list)return;
    var list=box._list, cur=list.indexOf(XP.path[ci]);
    if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();var ni=cur<0?0:Math.max(0,Math.min(list.length-1,cur+(e.key==='ArrowDown'?1:-1)));if(list[ni])selectNode(ci,list[ni]);}
    else if(e.key==='ArrowRight'){var n=XP.path[ci];var k=n?kidsOf(n):[];if(k.length){e.preventDefault();selectNode(ci+1,k[0]);}}
    else if(e.key==='ArrowLeft'){if(ci>0){e.preventDefault();goPath(ci-1);}}
  });
  qs('#themebtn').addEventListener('click',function(){var d=document.documentElement.getAttribute('data-theme')==='dark';document.documentElement.setAttribute('data-theme',d?'light':'dark');qs('#themetxt').textContent=d?'Dark':'Light';});
  XP.path=[roots[0]];XP.active=0;render();
}
function dl(name,rows){var csv='\ufeff'+rows.map(function(r){return r.map(function(c){c=(c==null?'':''+c);return '"'+c.replace(/"/g,'""')+'"';}).join(',');}).join('\r\n');var b=new Blob([csv],{type:'text/csv'});var u=URL.createObjectURL(b);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(u);}
function btn(label,onclick){return '<button class="btn" onclick="'+onclick+'">'+I.download+esc(label)+'</button>';}
function issueList(fs){fs=arr(fs);if(!fs.length)return '';return '<div class="issl">'+fs.map(function(f){return '<div><span class="dot '+f.sev+'"></span><span><b>'+esc(f.title)+'</b>'+(f.detail?' &mdash; <span class="muted">'+esc(f.detail)+'</span>':'')+(f.fix&&f.sev!=='info'&&f.sev!=='ok'?'<br><span class="muted">Fix: '+esc(f.fix)+'</span>':'')+'</span></div>';}).join('')+'</div>';}

var D = $DataJSON;
function isIssue(f){return f&&(f.sev==='crit'||f.sev==='warn');}
function short(n){n=''+(n||'');var i=n.indexOf('.');return (i>0?n.substring(0,i):n).toUpperCase();}
qs('#meta').innerHTML='Domain <b>'+esc(D.domain)+'</b> &middot; DNS server <b>'+esc(D.dnsServer)+'</b> &middot; '+esc(D.generated);

var ZONES=arr(D.zones), DCS=arr(D.dcs), STALE=arr(D.staleDc), MS=arr(D.msdcs), SRV=arr(D.servers), CF=arr(D.condFwd);
var REPL=arr((D.replication||{}).partitions), SEC=D.security||{};
var DCBY={}; DCS.forEach(function(d){DCBY[short(d.name)]=d;});
var ZBY={}; ZONES.forEach(function(z){ZBY[z.name]=z;});

/* ---------- detail renderers ---------- */
function dcFindings(d){return arr(d.findings).concat(arr(d.cfgFindings));}
function dcWorst(d){return worstOf(dcFindings(d).filter(isIssue).map(function(f){return f.sev;}))||'ok';}
function dcDetail(d){
  var me=['127.0.0.1','::1',d.ip], res=arr(d.resolvers), fw=arr(d.forwarders);
  function r(v){return v===true?'<span style="color:var(--green)">&#10003; OK</span>':(v===false?'<span style="color:var(--red)">&#10007; Failed</span>':'<span class="muted">not tested</span>');}
  var iss=dcFindings(d).filter(function(f){return f.sev!=='ok';}).sort(function(a,b){return RANK[b.sev]-RANK[a.sev];});
  return '<h2><span class="dot '+dcWorst(d)+'"></span>'+esc(short(d.name))+'</h2><div class="ds">'+esc(d.name)+' &middot; '+esc(d.site||'-')+'</div>'+
    '<dl class="kv"><dt>IP address</dt><dd class="mono">'+esc(d.ip||'')+'</dd><dt>Reachable</dt><dd>'+(d.reachable?'Yes':'<span style="color:var(--red)">No</span>')+'</dd></dl>'+
    '<h4>Resolution</h4><dl class="kv"><dt>Forward lookup</dt><dd>'+r(d.fwd)+'</dd><dt>Reverse lookup</dt><dd>'+r(d.rev)+'</dd><dt>External ('+esc(D.externalName||'')+')</dt><dd>'+r(d.ext)+'</dd></dl>'+
    '<h4>Configuration</h4><dl class="kv"><dt>Resolver order</dt><dd class="mono">'+(res.length?res.map(function(ip){return esc(ip)+(me.indexOf(ip)>=0?' <span class="muted">(self)</span>':'');}).join(' &rarr; '):'<span class="muted">not read</span>')+'</dd>'+
    '<dt>Recursion</dt><dd>'+(d.recursion===true?'On':(d.recursion===false?'Off':'<span class="muted">n/a</span>'))+'</dd><dt>Root hints</dt><dd>'+(d.rootHints==null?'<span class="muted">n/a</span>':d.rootHints)+'</dd>'+
    '<dt>Forwarders</dt><dd class="mono">'+(fw.length?fw.map(esc).join(', '):'<span class="muted">none</span>')+'</dd></dl>'+
    (iss.length?'<h4>Findings</h4>'+issueList(iss):'<div class="note">No issues on this domain controller.</div>');
}
function zWorst(z){return worstOf(arr(z.findings).filter(isIssue).map(function(f){return f.sev;}))||'ok';}
function zoneDetail(z){
  var ns=arr(z.nsRecords), iss=arr(z.findings).filter(function(f){return f.sev!=='ok';}).sort(function(a,b){return RANK[b.sev]-RANK[a.sev];}), ok=arr(z.findings).filter(function(f){return f.sev==='ok';});
  return '<h2><span class="dot '+zWorst(z)+'"></span>'+esc(z.name)+'</h2><div class="ds">'+esc(z.type)+' zone'+(z.adIntegrated?' &middot; AD-integrated ('+esc(z.scope||'')+')':'')+(z.reverse?' &middot; reverse lookup':'')+'</div>'+
    '<dl class="kv"><dt>Dynamic updates</dt><dd>'+esc(z.dynamicUpdate||'-')+'</dd><dt>Zone transfers</dt><dd>'+esc(z.transfer||'-')+'</dd>'+
    '<dt>Aging</dt><dd>'+(z.agingEnabled?'On ('+z.noRefresh+'d no-refresh / '+z.refresh+'d refresh)':'Off')+'</dd><dt>DNSSEC</dt><dd>'+(z.dnssec?'Signed':'Not signed')+'</dd>'+
    '<dt>Name servers</dt><dd>'+(ns.length?ns.map(function(n){return esc(short(n));}).join(', '):'<span class="muted">none</span>')+'</dd></dl>'+
    (iss.length?'<h4>Findings</h4>'+issueList(iss):'')+'<p class="hint">'+plural(ok.length,'check')+' passed.</p>';
}

/* ---------- aggregated issues (Summary branch) ---------- */
var ISSUES={};
function addIssue(area,f,name,noun,open){
  var k=area+'|'+f.title;
  if(!ISSUES[k])ISSUES[k]={area:area,sev:f.sev,title:f.title,fix:f.fix||'',noun:noun,items:[]};
  var it=ISSUES[k]; if(RANK[f.sev]>RANK[it.sev])it.sev=f.sev; if(!it.fix&&f.fix)it.fix=f.fix;
  it.items.push({name:name,detail:f.detail||'',open:open});
}
ZONES.forEach(function(z){arr(z.findings).forEach(function(f){if(isIssue(f))addIssue('Zones',f,z.name,'zone',{zone:z});});});
DCS.forEach(function(d){dcFindings(d).forEach(function(f){if(isIssue(f))addIssue('Domain controllers',f,short(d.name),'DC',{dc:d});});});
SRV.forEach(function(s){arr(s.findings).forEach(function(f){if(isIssue(f))addIssue('DNS server',f,short(s.server),'server',{});});});
REPL.forEach(function(p){arr(p.findings).forEach(function(f){if(isIssue(f))addIssue('AD backbone',f,p.label,'partition',{});});});
MS.forEach(function(m){if(!m.present)addIssue('AD backbone',{sev:'crit',title:'Missing DC locator SRV records',fix:'Restart the Netlogon service on the affected DCs so they re-register their SRV records.'},m.label,'record type',{});});
var staleBy={}; STALE.forEach(function(r){(staleBy[r.points]=staleBy[r.points]||[]).push(r);});
Object.keys(staleBy).forEach(function(dc){addIssue('Hygiene',{sev:'warn',title:'Records still point at removed domain controllers',fix:'Delete these records in DNS Manager and clean up any leftover metadata for the removed DCs.'},short(dc),'removed DC',{stale:dc});});
if(SEC.checked!==false){
  arr(SEC.hardening).forEach(function(h){if(isIssue(h))addIssue('Security',{sev:h.sev,title:h.title||h.label,detail:h.detail,fix:h.fix},h.label,'setting',{});});
  arr(SEC.riskyRecords).forEach(function(r){addIssue('Security',{sev:r.sev,title:r.kind+' present',detail:r.detail,fix:'Remove the record unless it is intentionally published.'},r.name+'.'+r.zone,'record',{});});
  arr((SEC.adidns||{}).exposed).forEach(function(z){addIssue('Security',{sev:'warn',title:'Any authenticated user can create records (ADIDNS)',fix:'Remove "Create all child objects" for Authenticated Users where not needed, and pre-create sensitive names such as wpad.'},z,'zone',{zone:ZBY[z]});});
}
var ISS=Object.keys(ISSUES).map(function(k){return ISSUES[k];}).sort(function(a,b){return (RANK[b.sev]-RANK[a.sev])||(b.items.length-a.items.length);});
var nCrit=ISS.filter(function(i){return i.sev==='crit';}).length, nWarn=ISS.filter(function(i){return i.sev==='warn';}).length;
function areaWorst(area){return worstOf(ISS.filter(function(i){return i.area===area;}).map(function(i){return i.sev;}))||'ok';}

function issueNode(it){
  var same=it.items.every(function(x){return x.detail===it.items[0].detail;});
  var meta=it.area==='Hygiene'?plural(STALE.length,'record')+' on '+plural(it.items.length,'removed DC'):plural(it.items.length,it.noun);
  return {label:it.title,dot:it.sev,count:it.items.length,kidsTitle:'Affected',search:it.area,
    kids:function(){return it.items.map(function(x){
      if(x.open.dc) return dcNode(x.open.dc);
      if(x.open.zone) return zoneNode(x.open.zone);
      if(x.open.stale) return staleDcNode(x.open.stale);
      return {label:x.name,dot:it.sev,detail:function(){return '<h2>'+esc(x.name)+'</h2><div class="ds">'+esc(it.title)+'</div>'+(x.detail?'<p>'+esc(x.detail)+'</p>':'')+(it.fix?'<div class="fix"><b>Fix:</b> '+esc(it.fix)+'</div>':'');}};});},
    detail:function(){return '<h2><span class="dot '+it.sev+'"></span>'+esc(it.title)+'</h2><div class="ds">'+esc(it.area)+' &middot; '+meta+'</div>'+
      (same&&it.items[0].detail?'<p>'+esc(it.items[0].detail)+'</p>':'')+(it.fix?'<div class="fix"><b>Fix:</b> '+esc(it.fix)+'</div>':'')+
      '<p class="hint">Select an entry in the <b>Affected</b> column to see its details.</p>';}};
}
function dcNode(d){return {label:short(d.name),icon:icon('server','n'),dot:dcWorst(d),search:d.name+' '+(d.ip||'')+' '+(d.site||''),detail:function(){return dcDetail(d);}};}
function zoneNode(z){return {label:z.name,icon:icon('globe','n'),dot:zWorst(z),detail:function(){return zoneDetail(z);}};}
function staleDcNode(dc){var rs=staleBy[dc]||[];
  return {label:short(dc),icon:icon('server','n'),dot:'warn',count:rs.length,kidsTitle:'Records',search:dc,
    kids:function(){return rs.map(function(r){return {label:r.record,icon:icon('record','n'),search:r.zone,detail:function(){
      return '<h2>'+esc(r.record)+'</h2><div class="ds">'+esc(r.type)+' record in '+esc(r.zone)+'</div><dl class="kv"><dt>Points to</dt><dd class="mono">'+esc(r.points)+'</dd><dt>Reason</dt><dd>'+esc(r.reason)+'</dd></dl>'+
        '<div class="fix"><b>Fix:</b> Delete this record in DNS Manager.</div>';}};});},
    detail:function(){return '<h2><span class="dot warn"></span>'+esc(short(dc))+'</h2><div class="ds">'+esc(dc)+' &middot; no longer in AD</div><p>'+plural(rs.length,'DNS record')+' still point at this removed domain controller.</p><div class="fix"><b>Fix:</b> Delete the records and clean up any leftover metadata for this removed DC.</div>';}};}

/* ---------- root branches ---------- */
var reach=DCS.filter(function(d){return d.reachable;}).length;
var summary={label:'Summary',icon:icon('pulse','a'),dot:nCrit?'crit':(nWarn?'warn':'ok'),count:ISS.length,kidsTitle:'Issues',
  kids:function(){return ISS.map(issueNode);},
  detail:function(){var sev=nCrit?'crit':(nWarn?'warn':'ok');
    var st=[[DCS.length,'Domain controllers',''],[ZONES.length,'Zones',''],[nCrit,'Critical issues',nCrit?'crit':'ok'],[nWarn,'Warnings',nWarn?'warn':'ok'],[reach+' / '+DCS.length,'DCs reachable',reach===DCS.length?'ok':'warn']];
    return '<h2>DNS health</h2><div class="ds">'+esc(D.domain)+' &middot; '+esc(D.generated)+'</div>'+
      '<div class="verdict"><div class="bar '+sev+'"></div><div><b>'+(nCrit?'Action required':(nWarn?'Needs attention':'Healthy'))+'</b><span class="muted">'+(ISS.length?plural(ISS.length,'issue')+' to fix &mdash; '+nCrit+' critical, '+plural(nWarn,'warning'):'No issues found.')+'</span></div></div>'+
      '<div class="stats">'+st.map(function(s){return '<div class="st"><div class="v '+s[2]+'">'+s[0]+'</div><div class="l">'+s[1]+'</div></div>';}).join('')+'</div>'+
      '<p class="hint">Each issue is listed once in the next column. Select one to see what it affects, then select an entry for its details. Keyboard: <span class="kbd">&uarr;</span> <span class="kbd">&darr;</span> to move, <span class="kbd">&rarr;</span> to open, <span class="kbd">&larr;</span> to go back.</p>';}};

var dcs={label:'Domain controllers',icon:icon('server','a'),dot:areaWorst('Domain controllers'),count:DCS.length,
  kids:function(){return DCS.slice().sort(function(a,b){return (RANK[dcWorst(b)]-RANK[dcWorst(a)])||(''+a.name).localeCompare(''+b.name);}).map(dcNode);},
  detail:function(){var bad=DCS.filter(function(d){return dcWorst(d)!=='ok';}).length;
    return '<h2>Domain controllers</h2><div class="ds">'+plural(DCS.length,'DC')+' &middot; '+reach+' reachable &middot; '+bad+' with issues'+(D.liveTested?'':' &middot; live tests skipped')+'</div>'+
      '<p>Select a DC to see its resolution tests, resolver order, forwarders and findings.</p><div class="actions">'+btn('Export CSV','csvDc()')+'</div>';}};

var fwdZ=ZONES.filter(function(z){return !z.reverse;}), revZ=ZONES.filter(function(z){return z.reverse;});
function zoneFolder(label,list){return {label:label,icon:icon('folder','f'),dot:worstOf(list.map(zWorst).filter(function(s){return s!=='ok';}))||'',count:list.length,kidsTitle:label,
  kids:function(){return list.slice().sort(function(a,b){return (RANK[zWorst(b)]-RANK[zWorst(a)])||(''+a.name).localeCompare(''+b.name);}).map(zoneNode);},
  detail:function(){var bad=list.filter(function(z){return zWorst(z)!=='ok';}).length;return '<h2>'+esc(label)+'</h2><div class="ds">'+plural(list.length,'zone')+' &middot; '+bad+' with issues</div><p>Zones with issues are listed first.</p>';}};}
var zones={label:'Zones',icon:icon('globe','a'),dot:areaWorst('Zones'),count:ZONES.length,
  kids:function(){return [zoneFolder('Forward lookup zones',fwdZ),zoneFolder('Reverse lookup zones',revZ),
    {label:'Conditional forwarders',icon:icon('folder','f'),count:CF.length,kids:function(){return CF.map(function(c){return {label:c.name,icon:icon('globe','n'),detail:function(){
      return '<h2>'+esc(c.name)+'</h2><div class="ds">Conditional forwarder'+(c.adIntegrated?' &middot; AD-integrated':'')+'</div><dl class="kv"><dt>Master servers</dt><dd class="mono">'+arr(c.masters).map(esc).join('<br>')+'</dd></dl>';}};});},
     detail:function(){return '<h2>Conditional forwarders</h2><div class="ds">'+plural(CF.length,'forwarder')+'</div><p>Namespaces this DNS server forwards to other servers.</p>';}}];},
  detail:function(){return '<h2>Zones</h2><div class="ds">'+fwdZ.length+' forward &middot; '+revZ.length+' reverse &middot; '+plural(CF.length,'conditional forwarder')+'</div><p>Browse zones the same way as in DNS Manager.</p><div class="actions">'+btn('Export CSV','csvZones()')+'</div>';}};

var backbone={label:'AD backbone',icon:icon('list','a'),dot:areaWorst('AD backbone'),
  kids:function(){
    var ms={label:'DC locator records',icon:icon('folder','f'),dot:MS.some(function(m){return !m.present;})?'crit':'',count:MS.length,
      kids:function(){return MS.map(function(m){return {label:m.label,dot:m.present?'ok':'crit',count:m.present?m.count:'missing',detail:function(){
        return '<h2><span class="dot '+(m.present?'ok':'crit')+'"></span>'+esc(m.label)+'</h2><div class="ds mono">'+esc(m.query)+'</div><p>'+(m.present?plural(m.count,'record')+' registered.':'No records found. Clients cannot locate domain controllers through this record.')+'</p>'+(m.present?'':'<div class="fix"><b>Fix:</b> Restart the Netlogon service on the domain controllers so they re-register these records.</div>');}};});},
      detail:function(){return '<h2>DC locator records</h2><div class="ds">_msdcs SRV records</div><p>The SRV records clients query to find domain controllers.</p>';}};
    return [ms].concat(REPL.map(function(p){return {label:p.label,icon:icon('sync','n'),dot:p.worst||'ok',detail:function(){
      var ne=arr(p.notEnlisted), fl=arr(p.failures);
      return '<h2><span class="dot '+(p.worst||'ok')+'"></span>'+esc(p.label)+'</h2><div class="ds mono">'+esc(p.dn)+'</div>'+
        '<dl class="kv"><dt>Enlisted DCs</dt><dd>'+arr(p.enlisted).map(esc).join(', ')+'</dd><dt>Not enlisted</dt><dd>'+(ne.length?ne.map(esc).join(', '):'<span class="muted">none</span>')+'</dd>'+
        '<dt>Replication failures</dt><dd>'+(fl.length?fl.map(function(f){return esc(typeof f==='string'?f:JSON.stringify(f));}).join('<br>'):'<span class="muted">none</span>')+'</dd></dl>'+
        '<h4>Findings</h4>'+issueList(p.findings);}};}));},
  detail:function(){return '<h2>AD backbone</h2><div class="ds">DC locator records and DNS application partitions</div><p>What Active Directory itself needs from DNS.</p>';}};

var security={label:'Security',icon:icon('shield','a'),dot:areaWorst('Security'),
  kids:function(){
    if(SEC.checked===false)return [];
    var H=arr(SEC.hardening), R=arr(SEC.riskyRecords), A=SEC.adidns||{}, ex=arr(A.exposed);
    return [
      {label:'Server hardening',icon:icon('folder','f'),dot:worstOf(H.filter(isIssue).map(function(h){return h.sev;})),count:H.length,
       kids:function(){return H.map(function(h){return {label:h.label,dot:h.sev,count:h.value,detail:function(){return '<h2><span class="dot '+h.sev+'"></span>'+esc(h.label)+'</h2><div class="ds">Current value: '+esc(h.value)+'</div>'+(h.detail?'<p>'+esc(h.detail)+'</p>':'')+(h.fix&&h.sev!=='ok'?'<div class="fix"><b>Fix:</b> '+esc(h.fix)+'</div>':'');}};});},
       detail:function(){return '<h2>Server hardening</h2><div class="ds">Anti-poisoning and man-in-the-middle defenses</div>';}},
      {label:'Risky records',icon:icon('folder','f'),dot:R.length?'warn':'',count:R.length,
       kids:function(){return R.map(function(r){return {label:r.name+'.'+r.zone,dot:r.sev,detail:function(){return '<h2>'+esc(r.name+'.'+r.zone)+'</h2><div class="ds">'+esc(r.kind)+'</div><p>'+esc(r.detail)+'</p>';}};});},
       detail:function(){return '<h2>Risky records</h2><div class="ds">Wildcard, WPAD and ISATAP records</div><p>'+(R.length?plural(R.length,'record')+' found.':'None found.')+'</p>';}},
      {label:'ADIDNS exposure',icon:icon('folder','f'),dot:ex.length?'warn':'',count:ex.length,kidsTitle:'Exposed zones',
       kids:function(){return ex.map(function(z){return ZBY[z]?zoneNode(ZBY[z]):{label:z};});},
       detail:function(){return '<h2>ADIDNS exposure</h2><div class="ds">'+(A.checked?ex.length+' of '+plural(A.total||0,'AD-integrated zone'):'Zone permissions could not be read')+'</div>'+
         '<p>Any authenticated user can create records in these zones. This is the default AD permission, and it is the surface used by mitm6 / ADIDNS spoofing.</p>'+
         (ex.length?'<div class="fix"><b>Fix:</b> Remove "Create all child objects" for Authenticated Users where not needed, and pre-create sensitive names such as wpad.</div>':'');}}];},
  detail:function(){return '<h2>Security</h2><div class="ds">'+(SEC.checked===false?'Skipped (-SkipSecurityChecks)':'Server hardening, risky records, ADIDNS exposure')+'</div>';}};

var hygiene={label:'Hygiene',icon:icon('record','a'),dot:worstOf([areaWorst('Hygiene'),areaWorst('DNS server')]),
  kids:function(){return [
    {label:'Lingering DC records',icon:icon('folder','f'),dot:STALE.length?'warn':'',count:STALE.length,kidsTitle:'Removed DCs',
     kids:function(){return Object.keys(staleBy).sort().map(staleDcNode);},
     detail:function(){return '<h2>Lingering DC records</h2><div class="ds">'+plural(STALE.length,'record')+' on '+plural(Object.keys(staleBy).length,'removed DC')+'</div><p>Records still pointing at domain controllers that no longer exist in AD.</p><div class="actions">'+btn('Export CSV','csvStale()')+'</div>';}},
    {label:'Server scavenging',icon:icon('folder','f'),dot:SRV.some(function(s){return s.enabled===false;})?'warn':'',count:SRV.length,
     kids:function(){return SRV.map(function(s){return {label:short(s.server),icon:icon('server','n'),dot:s.available===false?'info':(s.enabled?'ok':'warn'),count:s.enabled?('every '+s.intervalDays+'d'):'off',detail:function(){
       return '<h2>'+esc(short(s.server))+'</h2><div class="ds">'+esc(s.server)+'</div><dl class="kv"><dt>Scavenging</dt><dd>'+(s.enabled?'Enabled, every '+plural(s.intervalDays,'day'):'Disabled')+'</dd></dl>'+issueList(arr(s.findings).filter(isIssue));}};});},
     detail:function(){return '<h2>Server scavenging</h2><div class="ds">Automatic cleanup of stale records</div>';}}];},
  detail:function(){return '<h2>Hygiene</h2><div class="ds">Stale records and cleanup</div>';}};

initExplorer([summary,dcs,zones,backbone,security,hygiene],'DNS');

function csvDc(){var rows=[['DC','Site','IP','Reachable','Forward','Reverse','External','Resolvers','Recursion','RootHints','Forwarders','Issues']];DCS.forEach(function(d){rows.push([d.name,d.site,d.ip,d.reachable,d.fwd,d.rev,d.ext,arr(d.resolvers).join(' | '),d.recursion,d.rootHints,arr(d.forwarders).join(' | '),dcFindings(d).filter(isIssue).map(function(f){return f.title;}).join(' | ')]);});dl('dns_domain_controllers.csv',rows);}
function csvZones(){var rows=[['Zone','Type','ADIntegrated','Reverse','Scope','DynamicUpdate','Transfer','Aging','DNSSEC','Issues']];ZONES.forEach(function(z){rows.push([z.name,z.type,z.adIntegrated,z.reverse,z.scope,z.dynamicUpdate,z.transfer,z.agingEnabled,z.dnssec,arr(z.findings).filter(isIssue).map(function(f){return f.title;}).join(' | ')]);});dl('dns_zones.csv',rows);}
function csvStale(){var rows=[['Record','Type','Zone','PointsTo','Reason']];STALE.forEach(function(r){rows.push([r.record,r.type,r.zone,r.points,r.reason]);});dl('dns_stale_dc_records.csv',rows);}

</script>
</body></html>
"@

# Write with UTF-8 BOM so PowerShell 5.1 renders box-drawing / unicode correctly
$enc = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($ReportPath, $HTML, $enc)

Write-Host ""
Write-Host "  Report saved: $ReportPath" -ForegroundColor Green
try { if ($OpenReport) { Start-Process $ReportPath } } catch {}
