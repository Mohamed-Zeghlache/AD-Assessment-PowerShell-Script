<#
.SYNOPSIS
    AD DC Posture - domain controller hardening, security events, time sync, backup and Windows Server 2025 readiness (interactive HTML report).

.DESCRIPTION
    Standalone module for the Active Directory Audit Suite. One self-contained,
    offline, interactive HTML report (light/dark) covering five areas:

      1. PROTOCOLS & HARDENING (per domain controller)
           LDAP signing, LDAP channel binding, LDAP client logging (event 2889), LDAPS
           certificate, NTLM level,
           NTLM auditing, LM hash storage, SMB signing, SMBv1, SSL/TLS versions,
           LLMNR, NetBIOS, WDigest, LSA protection, Kerberos encryption types,
           Print Spooler on DCs, plus DES-only accounts in every domain.
      2. SECURITY EVENTS (last N days, every DC)
           Lockouts (4740), failed logons (4625) incl. password-spray detection,
           Kerberos pre-auth failures (4771), privileged group changes,
           audit log cleared (1102), and unsigned / clear-text LDAP binds
           (2887 / 2889) with the list of offending clients.
           Old protocols still in use, with the clients behind them: LDAPS without
           channel binding (3039), NTLMv1 logons (4624), Kerberos tickets issued with
           RC4 or DES (4768 / 4769), NTLM authentications (8004 or 4776, workstation
           names), SMBv1 clients (3000). Where a DC does not log one of these, the
           report says what to turn on.
      3. TIME SYNC HIERARCHY
           Configured type and NTP server, actual source, offset vs the PDC of
           the DC's own domain, Hyper-V time provider. Only the forest-root PDC
           emulator should use external NTP.
      4. BACKUP & RECOVERY READINESS
           AD Recycle Bin, tombstone lifetime, last backup per partition,
           SYSVOL replication (DFSR vs FRS) in every domain.
      5. WINDOWS SERVER 2025 READINESS
           Forest and domain functional levels, DC versions forest-wide, SYSVOL
           on DFSR, DES-only accounts, NTLMv1, Exchange versions.

    MULTI-DOMAIN FORESTS: every domain in the forest is covered. In the report,
    a domain selector shows the whole forest or one domain at a time.

    LARGE ENVIRONMENTS: domain controllers are checked several at a time
    (-Throttle), on Windows PowerShell 5.1 - no PowerShell 7 needed.

    READ-ONLY. Registry values are read over CIM/DCOM (no WinRM needed);
    event logs over RPC. Unreachable DCs are reported, never waited on.

.PARAMETER OutputPath       Folder for the HTML report (default: current dir).
.PARAMETER EventDays        How many days of security events to analyse (default 30).
.PARAMETER MaxEventsPerDc   Cap per event query per DC (default 5000, newest first).
.PARAMETER SkipEvents       Skip event log collection.
.PARAMETER SkipTime         Skip w32tm time-source and offset checks.
.PARAMETER Throttle         How many domain controllers are checked at the same time
                            (default 10). Use 1 to check them one by one.
.PARAMETER OpenReport       Open the report when done (default: $true).

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite
    Requires: ActiveDirectory module (RSAT-AD-PowerShell). Run as a domain admin
              (or with Event Log Readers + remote registry read on DCs).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [int]$EventDays = 30,
    [int]$MaxEventsPerDc = 5000,
    [switch]$SkipEvents,
    [switch]$SkipTime,
    [ValidateRange(1,64)][int]$Throttle = 10,
    [switch]$OpenReport = $true
)

$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Error "ActiveDirectory module not available. Install RSAT-AD-PowerShell."; exit 1 }
try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'; $GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
try { $Domain = Get-ADDomain -ErrorAction Stop } catch { Write-Error "Could not contact the domain: $($_.Exception.Message)"; exit 1 }
try { $Forest = Get-ADForest -ErrorAction SilentlyContinue } catch { $Forest = $null }
$DomainDNS = [string]$Domain.DNSRoot
$ForestDNS = if ($Forest) { [string]$Forest.Name } else { $DomainDNS }
$DomainDN  = [string]$Domain.DistinguishedName
$PdcName   = [string]$Domain.PDCEmulator
$ReportPath = Join-Path $OutputPath "AD_DCPosture_$Stamp.html"

Write-Host "AD DC Posture" -ForegroundColor Cyan
Write-Host "=============" -ForegroundColor Cyan
Write-Host "build: v23" -ForegroundColor DarkGray
Write-Host "Forest: $ForestDNS   Current domain: $DomainDNS" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# Helpers (PS 5.1-safe: hashtables, ArrayList, no pscustomobject in data)
# ─────────────────────────────────────────────────────────────────────────────
$HKLM = [uint32]2147483650
function Test-Port {
    # Resolves the name once, then tries each IPv4 address with its own timeout, so a slow
    # DNS answer or a stale extra A record does not make a reachable DC look unreachable.
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
function New-DcCimSession {
    param([string]$Name)
    if (Test-Port -ComputerName $Name -Port 135 -TimeoutMs 1500) {
        try { $opt = New-CimSessionOption -Protocol Dcom; return New-CimSession -ComputerName $Name -SessionOption $opt -OperationTimeoutSec 15 -ErrorAction Stop } catch {}
    }
    if (Test-Port -ComputerName $Name -Port 5985 -TimeoutMs 1500) {
        try { return New-CimSession -ComputerName $Name -OperationTimeoutSec 15 -ErrorAction Stop } catch {}
    }
    return $null
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
function Test-RegKey { param($S,[string]$Key)
    try { $r = Invoke-CimMethod -CimSession $S -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName 'EnumKey' -Arguments @{ hDefKey=$HKLM; sSubKeyName=$Key } -ErrorAction Stop; return ([int]$r.ReturnValue -eq 0) } catch { return $false }
}
function Fmt-Date { param($D) if ($D) { try { return ([datetime]$D).ToString('yyyy-MM-dd HH:mm') } catch { return '' } } return '' }
# A single evaluated setting for one DC.
function New-Setting { param([string]$Id,[string]$Value,[string]$Sev,[string]$Title,[string]$Advice)
    @{ id=$Id; value=$Value; sev=$Sev; title=$Title; advice=$Advice } }
# Sort helper without Sort-Object: fills $Out in place, ordered by string key.
function Fill-Sorted { param([System.Collections.ArrayList]$Items,[System.Collections.ArrayList]$Keys,[System.Collections.ArrayList]$Out)
    $map=@{}; $keyArr = [string[]]::new($Keys.Count)
    for ($i=0; $i -lt $Keys.Count; $i++) { $k = ([string]$Keys[$i]) + '|' + $i.ToString('D6'); $keyArr[$i]=$k; $map[$k]=$Items[$i] }
    [System.Array]::Sort($keyArr)
    foreach ($k in $keyArr) { [void]$Out.Add($map[$k]) }
}
function CountKey { param([int]$N,[string]$Name) (999999999 - $N).ToString('D9') + ([string]$Name).ToLower() }

# LDAPS: connect to 636 from this host and read the certificate.
function Test-Ldaps { param([string]$HostName)
    $res = @{ listening=$false; subject=''; issuer=''; expires=''; days=$null; error='' }
    $tcp = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $tcp.BeginConnect($HostName,636,$null,$null)
        if ((-not $iar.AsyncWaitHandle.WaitOne(2000,$false)) -or (-not $tcp.Connected)) { $res['error'] = 'Port 636 not reachable'; return $res }
        $tcp.EndConnect($iar); $res['listening'] = $true
        $tcp.ReceiveTimeout = 5000; $tcp.SendTimeout = 5000
        $cb = [System.Net.Security.RemoteCertificateValidationCallback]{ param($a,$b,$c,$d) $true }
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $cb)
        try {
            $protos = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls11 -bor [System.Security.Authentication.SslProtocols]::Tls
            $ssl.AuthenticateAsClient($HostName, $null, $protos, $false)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
            $res['subject'] = [string]$cert.Subject; $res['issuer'] = [string]$cert.Issuer
            $res['expires'] = $cert.NotAfter.ToString('yyyy-MM-dd')
            $res['days'] = [int][math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        } finally { $ssl.Dispose() }
    } catch { $res['error'] = [string]$_.Exception.Message } finally { $tcp.Close() }
    return $res
}

# Runs a script block once per domain controller on a pool of runspaces (Windows PowerShell 5.1).
# The script block gets the DC hashtable and writes its results into it. The listed helper
# functions and variables are copied into every runspace. -Throttle 1 runs the DCs one by one.
function Invoke-DcParallel {
    param([System.Collections.IList]$Items,[scriptblock]$Script,[string[]]$Functions=@(),[hashtable]$Variables=@{},[int]$Throttle=10,[int]$TimeoutSec=0)
    $tasks = [System.Collections.ArrayList]::new()
    if (-not $Items -or $Items.Count -eq 0) { return ,$tasks }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in $Functions) { [void]$iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($fn,(Get-Item ("Function:\" + $fn)).Definition)) }
    foreach ($k in @($Variables.Keys)) { [void]$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($k,$Variables[$k],'')) }
    $max = [math]::Max(1,[math]::Min($Throttle,$Items.Count))
    $pool = [runspacefactory]::CreateRunspacePool(1,$max,$iss,$Host)
    $pool.Open()
    $timedOut = $false
    try {
        foreach ($it in $Items) {
            $ps = [powershell]::Create(); $ps.RunspacePool = $pool
            [void]$ps.AddScript($Script.ToString()).AddArgument($it)
            [void]$tasks.Add(@{ ps=$ps; h=$ps.BeginInvoke(); item=$it; done=$false; error=''; timedOut=$false })
        }
        $deadline = [datetime]::MaxValue; if ($TimeoutSec -gt 0) { $deadline = (Get-Date).AddSeconds($TimeoutSec) }
        $left = $tasks.Count; $n = 0
        while ($left -gt 0) {
            foreach ($t in $tasks) {
                if ($t['done'] -or -not $t['h'].IsCompleted) { continue }
                $t['done'] = $true; $left--; $n++
                try { [void]$t['ps'].EndInvoke($t['h']) } catch { $t['error'] = [string]$_.Exception.Message }
                $t['ps'].Dispose()
                $nm = ''; if ($t['item'] -is [hashtable]) { $nm = [string]$t['item']['short'] }
                Write-Host ("  {0} ({1}/{2})" -f $nm,$n,$tasks.Count) -ForegroundColor DarkGray
            }
            if ($left -le 0) { break }
            if ((Get-Date) -gt $deadline) {
                foreach ($t in $tasks) { if (-not $t['done']) { $t['done'] = $true; $t['timedOut'] = $true; $timedOut = $true; try { [void]$t['ps'].BeginStop($null,$null) } catch {} } }
                break
            }
            Start-Sleep -Milliseconds 150
        }
    } finally {
        # A pipeline that did not answer in time is stopped in the background, not waited on.
        if ($timedOut) { try { [void]$pool.BeginClose($null,$null) } catch {} } else { $pool.Close(); $pool.Dispose() }
    }
    return ,$tasks
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Domain controllers (every domain in the forest)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/6] Enumerating domain controllers..." -ForegroundColor Yellow
# Forest root first, then the other domains alphabetically
$AllDomains = [System.Collections.ArrayList]::new()
$domRaw = [System.Collections.ArrayList]::new()
if ($Forest -and @($Forest.Domains).Count) { foreach ($x in @($Forest.Domains)) { [void]$domRaw.Add([string]$x) } } else { [void]$domRaw.Add($DomainDNS) }
$domKeys = [System.Collections.ArrayList]::new(); foreach ($x in $domRaw) { [void]$domKeys.Add($(if ($x -eq $ForestDNS) { '0' } else { '1' }) + $x.ToLower()) }
Fill-Sorted -Items $domRaw -Keys $domKeys -Out $AllDomains
$Multi = [bool]($AllDomains.Count -gt 1)
$DomInfo = @{}; $DomNotes = [System.Collections.ArrayList]::new()
$DcList = [System.Collections.ArrayList]::new()
$DcKeys = [System.Collections.ArrayList]::new()
foreach ($dom in $AllDomains) {
    try {
        $di = Get-ADDomain -Identity $dom -Server $dom -ErrorAction Stop
        $DomInfo[$dom] = @{ pdc=[string]$di.PDCEmulator; dn=[string]$di.DistinguishedName }
        $dcObjs = @(Get-ADDomainController -Filter * -Server $dom -ErrorAction Stop)
    } catch {
        Write-Host "  $dom could not be contacted: $($_.Exception.Message)" -ForegroundColor DarkYellow
        [void]$DomNotes.Add("Domain $dom could not be contacted from this host, so its domain controllers are not in this report.")
        $DomInfo.Remove($dom); continue
    }
    $dPdc = [string]$DomInfo[$dom]['pdc']
    $dk = if ($dom -eq $ForestDNS) { '0' } else { '1' }
    foreach ($d in $dcObjs) {
        $name = [string]$d.HostName
        $short = ($name -split '\.')[0].ToUpper()
        $os = [string]$d.OperatingSystem
        $build = 0; try { $build = [int](([string]$d.OperatingSystemVersion) -replace '^.*\((\d+)\).*$','$1') } catch {}
        $isPdc = [bool]($name -eq $dPdc)
        [void]$DcList.Add(@{ name=$name; short=$short; domain=$dom; site=[string]$d.Site; ip=[string]$d.IPv4Address; os=$os; build=$build;
            isPdc=$isPdc; rodc=[bool]$d.IsReadOnly; reachable=$false; regRead=$false; platform='Unknown'; model=''; settings=[System.Collections.ArrayList]::new();
            ldaps=@{}; time=@{}; notes=[System.Collections.ArrayList]::new() })
        $pk = if ($isPdc) { '0' } else { '1' }
        [void]$DcKeys.Add($dk + $dom.ToLower() + '|' + $pk + $short)
    }
}
$DCS = [System.Collections.ArrayList]::new(); Fill-Sorted -Items $DcList -Keys $DcKeys -Out $DCS
$PdcMap = @{}; foreach ($k in @($DomInfo.Keys)) { $PdcMap[$k] = [string]$DomInfo[$k]['pdc'] }
$RootPdc = $PdcName; if ($PdcMap.ContainsKey($ForestDNS)) { $RootPdc = [string]$PdcMap[$ForestDNS] }
Write-Host "  $($DCS.Count) domain controller(s) in $($AllDomains.Count) domain(s)" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# 2. Protocols & hardening (per DC)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/6] Reading protocol and hardening settings..." -ForegroundColor Yellow
$kNtds   = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$kNtdsDg = 'SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
$kLsa    = 'SYSTEM\CurrentControlSet\Control\Lsa'
$kMsv    = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$kNetlog = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$kSmb    = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$kSchan  = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$kDnsC   = 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$kWd     = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$kKerb   = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
$kW32    = 'SYSTEM\CurrentControlSet\Services\W32Time'
# One runspace per DC: the results are written into the DC hashtable
$SetScript = {
  param($dc)
  $n = $dc['name']
  try {
    # LDAPS is tested from this host (does not need registry access)
    $l = Test-Ldaps -HostName $n
    $dc['ldaps'] = $l
    if (-not $l['listening']) { [void]$dc['settings'].Add((New-Setting 'ldaps' 'Not listening on 636' 'warn' 'LDAPS not available' 'Enroll a domain controller certificate (Kerberos Authentication or Domain Controller Authentication template) so LDAPS is available before enforcing LDAP signing.')) }
    elseif ($null -eq $l['days']) { [void]$dc['settings'].Add((New-Setting 'ldaps' 'Handshake failed' 'warn' 'LDAPS certificate could not be read' 'Check that the domain controller has a valid server authentication certificate.')) }
    elseif ([int]$l['days'] -lt 0) { [void]$dc['settings'].Add((New-Setting 'ldaps' ("Expired " + $l['expires']) 'crit' 'LDAPS certificate expired' 'Renew the domain controller certificate; LDAPS clients will fail until it is replaced.')) }
    elseif ([int]$l['days'] -lt 30) { [void]$dc['settings'].Add((New-Setting 'ldaps' ("Expires " + $l['expires']) 'warn' 'LDAPS certificate expires within 30 days' 'Renew the domain controller certificate before it expires.')) }
    else { [void]$dc['settings'].Add((New-Setting 'ldaps' ("Valid until " + $l['expires']) 'ok' 'LDAPS certificate valid' '')) }

    $s = New-DcCimSession -Name $n
    if (-not $s) { [void]$dc['notes'].Add('Remote management (DCOM/WinRM) not reachable - registry settings were not read.'); return }
    $dc['reachable'] = $true
    try {
      $probe = Get-RegString $s 'SYSTEM\CurrentControlSet\Control\ProductOptions' 'ProductType'
      if ($null -eq $probe) { [void]$dc['notes'].Add('Registry could not be read (StdRegProv access denied?).') }
      else {
        $dc['regRead'] = $true
        # LDAP signing
        $v = Get-RegDword $s $kNtds 'LDAPServerIntegrity'
        if ($v -eq 2) { [void]$dc['settings'].Add((New-Setting 'ldapSign' 'Required' 'ok' 'LDAP signing required' '')) }
        elseif ($v -eq 0) { [void]$dc['settings'].Add((New-Setting 'ldapSign' 'None' 'crit' 'LDAP signing disabled' 'Set the domain controller LDAP server signing requirement to at least negotiate, then to require once unsigned clients are fixed.')) }
        else { [void]$dc['settings'].Add((New-Setting 'ldapSign' 'Negotiated (not required)' 'warn' 'LDAP signing not required' 'Require LDAP signing on domain controllers once the clients listed under Security events > Unsigned LDAP binds are fixed.')) }
        # LDAP channel binding
        $v = Get-RegDword $s $kNtds 'LdapEnforceChannelBinding'
        if ($v -eq 2) { [void]$dc['settings'].Add((New-Setting 'ldapCbt' 'Always' 'ok' 'LDAP channel binding enforced' '')) }
        elseif ($v -eq 1) { [void]$dc['settings'].Add((New-Setting 'ldapCbt' 'When supported' 'warn' 'LDAP channel binding not enforced' 'Move LDAP channel binding to Always once all LDAPS clients support it.')) }
        elseif ($v -eq 0) { [void]$dc['settings'].Add((New-Setting 'ldapCbt' 'Never' 'warn' 'LDAP channel binding disabled' 'Enable LDAP channel binding (When supported first, then Always).')) }
        else { [void]$dc['settings'].Add((New-Setting 'ldapCbt' 'Not configured' 'warn' 'LDAP channel binding not configured' 'Configure LDAP channel binding explicitly (When supported first, then Always) rather than relying on the OS default.')) }
        # LDAP client logging: event 2889 (IP and account of each unsigned or clear-text bind) is only written at level 2 or more
        $lg = Get-RegDword $s $kNtdsDg '16 LDAP Interface Events'
        $sg = Get-RegDword $s $kNtds 'LDAPServerIntegrity'
        $lgTxt = if ($null -eq $lg -or $lg -eq 0) { 'Off' } else { "Level $lg" }
        if ($sg -eq 2) { [void]$dc['settings'].Add((New-Setting 'ldapLog' ($lgTxt + ' (not needed: signing required)') 'ok' 'LDAP client logging not needed' '')) }
        elseif ($null -ne $lg -and $lg -ge 2) { [void]$dc['settings'].Add((New-Setting 'ldapLog' ($lgTxt + ' (event 2889 logged)') 'ok' 'LDAP client logging on' '')) }
        else { [void]$dc['settings'].Add((New-Setting 'ldapLog' ($lgTxt + ' (event 2889 not logged)') 'info' 'LDAP client logging off' 'Raise LDAP interface event logging to 2 on this domain controller for a day or two, so each client making an unsigned or clear-text bind is recorded (event 2889) before LDAP signing is required. Set it back to 0 afterwards.')) }
        # NTLM level
        $v = Get-RegDword $s $kLsa 'LmCompatibilityLevel'
        $lv = if ($null -eq $v) { 3 } else { [int]$v }
        $lvTxt = if ($null -eq $v) { 'Not set (default 3)' } else { "Level $lv" }
        if ($lv -ge 5) { [void]$dc['settings'].Add((New-Setting 'ntlmLevel' $lvTxt 'ok' 'Only NTLMv2 accepted' '')) }
        elseif ($lv -le 2) { [void]$dc['settings'].Add((New-Setting 'ntlmLevel' $lvTxt 'crit' 'LM/NTLMv1 sent and accepted' 'Raise the LAN Manager authentication level to "Send NTLMv2 response only. Refuse LM & NTLM" after confirming no NTLMv1 clients remain.')) }
        else { [void]$dc['settings'].Add((New-Setting 'ntlmLevel' $lvTxt 'warn' 'DC still accepts LM/NTLMv1' 'Raise the LAN Manager authentication level to "Send NTLMv2 response only. Refuse LM & NTLM" after confirming no NTLMv1 clients remain.')) }
        # NTLM auditing / restriction
        $au = Get-RegDword $s $kNetlog 'AuditNTLMInDomain'; $re = Get-RegDword $s $kNetlog 'RestrictNTLMInDomain'
        if ($re -and $re -gt 0) { [void]$dc['settings'].Add((New-Setting 'ntlmAudit' "Restricted (level $re)" 'ok' 'NTLM restricted in domain' '')) }
        elseif ($au -and $au -gt 0) { [void]$dc['settings'].Add((New-Setting 'ntlmAudit' "Auditing (level $au)" 'ok' 'NTLM auditing enabled' '')) }
        else { [void]$dc['settings'].Add((New-Setting 'ntlmAudit' 'Off' 'info' 'NTLM usage not audited' 'Enable NTLM auditing on domain controllers to see which clients still use NTLM before restricting it.')) }
        # LM hash storage
        $v = Get-RegDword $s $kLsa 'NoLMHash'
        if ($v -eq 1 -or $null -eq $v) { [void]$dc['settings'].Add((New-Setting 'noLm' $(if ($null -eq $v) { 'Default (not stored)' } else { 'Not stored' }) 'ok' 'LM hashes not stored' '')) }
        else { [void]$dc['settings'].Add((New-Setting 'noLm' 'Stored' 'crit' 'LM hashes stored' 'Turn on "Do not store LAN Manager hash value on next password change", then have affected accounts change their passwords.')) }
        # SMB signing
        $v = Get-RegDword $s $kSmb 'RequireSecuritySignature'
        if ($v -eq 1) { [void]$dc['settings'].Add((New-Setting 'smbSign' 'Required' 'ok' 'SMB signing required' '')) }
        else { [void]$dc['settings'].Add((New-Setting 'smbSign' $(if ($null -eq $v) { 'Not set' } else { 'Not required' }) 'crit' 'SMB signing not required' 'Require SMB signing on domain controllers (Default Domain Controllers Policy) to block NTLM relay against them.')) }
        # SMBv1
        $v = Get-RegDword $s $kSmb 'SMB1'
        $smb1On = $null
        try { $f = @(Get-CimInstance -CimSession $s -ClassName Win32_OptionalFeature -Filter "Name='SMB1Protocol'" -ErrorAction Stop); if ($f.Count) { $smb1On = ([int]$f[0].InstallState -eq 1) } } catch {}
        if ($v -eq 0 -or $smb1On -eq $false) { [void]$dc['settings'].Add((New-Setting 'smb1' 'Disabled' 'ok' 'SMBv1 disabled' '')) }
        elseif ($smb1On -eq $true -or $v -eq 1) { [void]$dc['settings'].Add((New-Setting 'smb1' 'Enabled' 'crit' 'SMBv1 enabled' 'Remove the SMB 1.0 feature from domain controllers after confirming no legacy clients depend on it.')) }
        else { [void]$dc['settings'].Add((New-Setting 'smb1' 'Unknown' 'info' 'SMBv1 state could not be determined' 'Verify that the SMB 1.0 feature is removed.')) }
        # What this DC logs about old protocols (used by the Security events step)
        $dc['logcfg'] = @{ ldap=$lg; ntlmAudit=$au; smb1Off=[bool]($v -eq 0 -or $smb1On -eq $false); smb1Audit=(Get-RegDword $s $kSmb 'AuditSmb1Access') }
        # SSL / TLS (server side)
        $parts = [System.Collections.ArrayList]::new(); $tlsSev = 'ok'
        foreach ($p in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2') {
            $en = Get-RegDword $s ($kSchan + '\' + $p + '\Server') 'Enabled'
            $state = if ($null -eq $en) { 'default' } elseif ($en -eq 0) { 'off' } else { 'on' }
            if ($p -like 'SSL*' -and $state -eq 'on') { $tlsSev = 'crit' }
            if ($p -in @('TLS 1.0','TLS 1.1') -and $state -ne 'off' -and $tlsSev -ne 'crit') { $tlsSev = 'warn' }
            if ($p -eq 'TLS 1.2' -and $state -eq 'off') { $tlsSev = 'crit' }
            [void]$parts.Add("$p $state")
        }
        $tlsAdv = if ($tlsSev -eq 'crit') { 'Disable SSL 2.0/3.0 and make sure TLS 1.2 is enabled.' } elseif ($tlsSev -eq 'warn') { 'Explicitly disable TLS 1.0 and 1.1 on domain controllers once no clients depend on them.' } else { '' }
        $tlsTitle = if ($tlsSev -eq 'crit') { 'Insecure SSL/TLS configuration' } elseif ($tlsSev -eq 'warn') { 'TLS 1.0/1.1 not disabled' } else { 'Legacy SSL/TLS disabled' }
        [void]$dc['settings'].Add((New-Setting 'tls' ($parts -join ' | ') $tlsSev $tlsTitle $tlsAdv))
        # LLMNR
        $v = Get-RegDword $s $kDnsC 'EnableMulticast'
        if ($v -eq 0) { [void]$dc['settings'].Add((New-Setting 'llmnr' 'Disabled' 'ok' 'LLMNR disabled' '')) }
        else { [void]$dc['settings'].Add((New-Setting 'llmnr' 'Enabled' 'warn' 'LLMNR enabled' 'Turn off multicast name resolution by Group Policy to prevent name-poisoning attacks.')) }
        # NetBIOS over TCP/IP
        try {
            $nics = @(Get-CimInstance -CimSession $s -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' -ErrorAction Stop)
            $nbOn = 0; foreach ($nic in $nics) { if ([int]$nic.TcpipNetbiosOptions -ne 2) { $nbOn++ } }
            if ($nbOn -eq 0) { [void]$dc['settings'].Add((New-Setting 'netbios' 'Disabled' 'ok' 'NetBIOS over TCP/IP disabled' '')) }
            else { [void]$dc['settings'].Add((New-Setting 'netbios' "Enabled on $nbOn adapter(s)" 'info' 'NetBIOS over TCP/IP enabled' 'Disable NetBIOS over TCP/IP on domain controller adapters if no legacy applications need it.')) }
        } catch {}
        # WDigest
        $v = Get-RegDword $s $kWd 'UseLogonCredential'
        if ($v -eq 1) { [void]$dc['settings'].Add((New-Setting 'wdigest' 'Enabled' 'crit' 'WDigest stores clear-text passwords' 'Turn off WDigest authentication so clear-text credentials are not kept in memory.')) }
        else { [void]$dc['settings'].Add((New-Setting 'wdigest' 'Disabled' 'ok' 'WDigest clear-text credentials off' '')) }
        # LSA protection
        $v = Get-RegDword $s $kLsa 'RunAsPPL'
        if ($v -ge 1) { [void]$dc['settings'].Add((New-Setting 'lsaPpl' 'Enabled' 'ok' 'LSA protection enabled' '')) }
        else { [void]$dc['settings'].Add((New-Setting 'lsaPpl' 'Off' 'warn' 'LSA protection off' 'Enable LSA protection (RunAsPPL) on domain controllers after testing third-party authentication components.')) }
        # Kerberos encryption types
        $v = Get-RegDword $s $kKerb 'SupportedEncryptionTypes'
        if ($null -eq $v) { [void]$dc['settings'].Add((New-Setting 'kerbEnc' 'Not configured' 'info' 'Kerberos encryption types not configured' 'Configure allowed Kerberos encryption types to AES only once RC4 dependencies are removed.')) }
        else {
            $t = [System.Collections.ArrayList]::new()
            if ($v -band 1) { [void]$t.Add('DES-CRC') }; if ($v -band 2) { [void]$t.Add('DES-MD5') }; if ($v -band 4) { [void]$t.Add('RC4') }
            if ($v -band 8) { [void]$t.Add('AES128') }; if ($v -band 16) { [void]$t.Add('AES256') }
            $txt = $t -join ', '
            if ($v -band 3) { [void]$dc['settings'].Add((New-Setting 'kerbEnc' $txt 'crit' 'DES allowed for Kerberos' 'Remove DES from the allowed Kerberos encryption types.')) }
            elseif ($v -band 4) { [void]$dc['settings'].Add((New-Setting 'kerbEnc' $txt 'warn' 'RC4 allowed for Kerberos' 'Plan to remove RC4 from the allowed Kerberos encryption types once no accounts depend on it.')) }
            else { [void]$dc['settings'].Add((New-Setting 'kerbEnc' $txt 'ok' 'AES-only Kerberos' '')) }
        }
        # Print Spooler
        try {
            $sp = @(Get-CimInstance -CimSession $s -ClassName Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop)
            if ($sp.Count) {
                $st = [string]$sp[0].State; $sm = [string]$sp[0].StartMode
                if ($st -eq 'Running') { [void]$dc['settings'].Add((New-Setting 'spooler' "Running ($sm)" 'warn' 'Print Spooler running on DC' 'Stop and disable the Print Spooler service on domain controllers (coercion and PrintNightmare exposure).')) }
                else { [void]$dc['settings'].Add((New-Setting 'spooler' "$st ($sm)" 'ok' 'Print Spooler not running' '')) }
            }
        } catch {}
        # Platform: physical / VMware / Hyper-V / Azure (decides whether the Hyper-V time provider matters)
        $plat = 'Unknown'; $model = ''
        try {
            $cs = @(Get-CimInstance -CimSession $s -ClassName Win32_ComputerSystem -ErrorAction Stop)
            if ($cs.Count) {
                $man = [string]$cs[0].Manufacturer; $model = [string]$cs[0].Model
                if ($man -match 'VMware' -or $model -match 'VMware') { $plat = 'VMware' }
                elseif ($man -match 'Microsoft' -and $model -match 'Virtual') { $plat = 'Hyper-V'; if (Test-RegKey $s 'SOFTWARE\Microsoft\Windows Azure') { $plat = 'Azure' } }
                elseif ($model -match 'VirtualBox|KVM|QEMU|Xen|Nutanix|AHV|Bochs' -or $man -match 'QEMU|Xen|Nutanix|innotek|Red Hat|oVirt') { $plat = 'Other virtual' }
                else { $plat = 'Physical' }
            }
        } catch {}
        $dc['platform'] = $plat; $dc['model'] = $model
        # Time configuration: Group Policy settings override the local registry
        $pType = Get-RegString $s 'SOFTWARE\Policies\Microsoft\W32Time\Parameters' 'Type'
        $pNtp  = Get-RegString $s 'SOFTWARE\Policies\Microsoft\W32Time\Parameters' 'NtpServer'
        $lType = Get-RegString $s ($kW32 + '\Parameters') 'Type'
        $lNtp  = Get-RegString $s ($kW32 + '\Parameters') 'NtpServer'
        $tType = [string]$lType; $tNtp = [string]$lNtp; $tBy = 'Local'
        if ($pType) { $tType = [string]$pType; $tBy = 'Group Policy' }
        if ($pNtp)  { $tNtp = [string]$pNtp }
        $dc['time'] = @{
            type=$tType; ntpServer=$tNtp; cfgBy=$tBy
            announce=(Get-RegDword $s ($kW32 + '\Config') 'AnnounceFlags')
            vmic=(Get-RegDword $s ($kW32 + '\TimeProviders\VMICTimeProvider') 'Enabled')
            source=''; offset=$null; offsetPdc=$null; error=''; lastSync=''; lastSyncDays=$null; stratum=''
        }
      }
    } finally { Remove-CimSession $s -ErrorAction SilentlyContinue }
  } catch { [void]$dc['notes'].Add("Collection error: $($_.Exception.Message)") }
}
$tasks = Invoke-DcParallel -Items $DCS -Script $SetScript -Functions @('Test-Port','New-DcCimSession','Get-RegDword','Get-RegString','Test-RegKey','New-Setting','Test-Ldaps') -Variables @{ HKLM=$HKLM; kNtds=$kNtds; kNtdsDg=$kNtdsDg; kLsa=$kLsa; kMsv=$kMsv; kNetlog=$kNetlog; kSmb=$kSmb; kSchan=$kSchan; kDnsC=$kDnsC; kWd=$kWd; kKerb=$kKerb; kW32=$kW32 } -Throttle $Throttle
foreach ($t in $tasks) { if ($t['error']) { [void]$t['item']['notes'].Add('Collection error: ' + $t['error']) } }

# Accounts with DES-only Kerberos, in every domain
$DesOnly = [System.Collections.ArrayList]::new()
foreach ($dom in $AllDomains) {
    if (-not $DomInfo.ContainsKey($dom)) { continue }
    try {
        $des = @(Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2097152)' -Properties sAMAccountName -Server $dom -ResultSetSize 500 -ErrorAction Stop)
        foreach ($o in $des) { [void]$DesOnly.Add(@{ name=[string]$o.Name; sam=[string]$o.sAMAccountName; dn=[string]$o.DistinguishedName; domain=$dom }) }
    } catch {}
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. Security events
# ─────────────────────────────────────────────────────────────────────────────
$Since = (Get-Date).AddDays(-$EventDays)
$SinceMs = [int64]((Get-Date) - $Since).TotalMilliseconds
$EV = @{ collected=$false; days=$EventDays; ok=[System.Collections.ArrayList]::new(); failed=[System.Collections.ArrayList]::new();
         lockouts=[System.Collections.ArrayList]::new(); failAccounts=[System.Collections.ArrayList]::new(); failSources=[System.Collections.ArrayList]::new(); failTotal=0;
         kerbAccounts=[System.Collections.ArrayList]::new(); kerbTotal=0; privChanges=[System.Collections.ArrayList]::new(); cleared=[System.Collections.ArrayList]::new();
         ldapDc=[System.Collections.ArrayList]::new(); ldapClients=[System.Collections.ArrayList]::new() }
$PrivGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Cert Publishers','Enterprise Key Admins','Key Admins')
# Events are read with the .NET event log reader: newest first, filtered on the DC (XPath), and only the
# event data is fetched. Get-WinEvent also formats the full message of every event, which over the network
# costs an extra round trip per event and made this step slow.
function Read-Events { param([string]$Dc,[string]$Log,[string]$XPath,[int]$Max,[switch]$Named)
    $out = [System.Collections.ArrayList]::new()
    $ses = [System.Diagnostics.Eventing.Reader.EventLogSession]::new($Dc)
    try {
        $q = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($Log, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $XPath)
        $q.Session = $ses; $q.ReverseDirection = $true
        $rd = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($q)
        # Keep only what is used (values, and the XML when fields are read by name), then release each record
        try { $rd.BatchSize = 500
              while ($out.Count -lt $Max) { $e = $rd.ReadEvent(); if ($null -eq $e) { break }
                  # First event of each ID: keep its full Windows text as an example for the report (one lookup per ID)
                  if ($EvSamples -is [hashtable]) { $sid = [int]$e.Id
                      if (-not $EvSamples.ContainsKey($sid)) { $m = ''; try { $m = [string]$e.FormatDescription() } catch {}
                          $EvSamples[$sid] = $(if ($m) { @{ msg=$(if ($m.Length -gt 6000) { $m.Substring(0,6000) } else { $m }); time=(Fmt-Date $e.TimeCreated) } } else { $null }) } }
                  try { [void]$out.Add([pscustomobject]@{ Id=$e.Id; TimeCreated=$e.TimeCreated; Properties=@($e.Properties); Xml=$(if ($Named) { $e.ToXml() } else { '' }) }) } finally { $e.Dispose() } } }
        finally { $rd.Dispose() }
    } finally { $ses.Dispose() }
    $out   # one item per event (callers wrap it in @())
}
function XIds { param([int[]]$Ids) '*[System[(' + (($Ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ") and TimeCreated[timediff(@SystemTime) <= $SinceMs]]]" }
function Get-Events { param([string]$Dc,[string]$Log,[int[]]$Ids,[int]$Max=0,[switch]$Named)
    if ($Max -le 0) { $Max = $MaxEventsPerDc }
    Read-Events $Dc $Log (XIds $Ids) $Max -Named:$Named
}
function PropVal { param($E,[int]$I) try { return [string]$E.Properties[$I].Value } catch { return '' } }
# Filtered read (XPath), so busy logs such as 4624 / 4769 only return the events that matter
function Get-EventsX { param([string]$Dc,[string]$Log,[string]$XPath) Read-Events $Dc $Log $XPath $MaxEventsPerDc -Named }
# $true: the event is recorded in the period; $false: not one; $null: the log could not be read
function Test-AnyEvent { param([string]$Dc,[string]$Log,[int]$Id)
    try { return [bool](@(Read-Events $Dc $Log (XIds @($Id)) 1).Count) } catch { return $null }
}
function EvData { param($E) $h = @{}; try { foreach ($d in ([xml]$E.Xml).Event.EventData.Data) { $h[[string]$d.Name] = [string]$d.InnerText } } catch {}; $h }
# Raw events keep their domain, so the report can show the whole forest or one domain
$EVByDomain = @{}
$RAW = @{ lock=[System.Collections.ArrayList]::new(); fail=[System.Collections.ArrayList]::new(); kerb=[System.Collections.ArrayList]::new();
          priv=[System.Collections.ArrayList]::new(); clear=[System.Collections.ArrayList]::new(); ldapDc=[System.Collections.ArrayList]::new();
          ldapCli=[System.Collections.ArrayList]::new(); samples=[System.Collections.ArrayList]::new(); ok=[System.Collections.ArrayList]::new(); failed=[System.Collections.ArrayList]::new();
          cbt=[System.Collections.ArrayList]::new(); ntlm1=[System.Collections.ArrayList]::new(); weak=[System.Collections.ArrayList]::new();
          ntlm=[System.Collections.ArrayList]::new(); smb1=[System.Collections.ArrayList]::new(); cov=[System.Collections.ArrayList]::new() }

function Bump-Day { param([hashtable]$Daily,$When,[string]$T) try { $k=([datetime]$When).ToString('yyyy-MM-dd'); if (-not $Daily.ContainsKey($k)) { $Daily[$k]=@{ f=0; k=0; l=0 } }; $Daily[$k][$T] = [int]$Daily[$k][$T] + 1 } catch {} }
function Agg { param([hashtable]$T,[string]$Key,[string]$Label,[string]$Dc,[datetime]$When,[string]$Other)
    if (-not $T.ContainsKey($Key)) { $T[$Key] = @{ name=$Label; count=0; dcs=@{}; others=@{}; last=[datetime]::MinValue } }
    $e = $T[$Key]; $e['count'] = [int]$e['count'] + 1; $e['dcs'][$Dc] = $true
    if ($Other) { if ($e['others'].ContainsKey($Other)) { $e['others'][$Other] = [int]$e['others'][$Other] + 1 } else { $e['others'][$Other] = 1 } }
    if ($When -gt $e['last']) { $e['last'] = $When }
}
function Flatten-Agg { param([hashtable]$T,[int]$Cap)
    $items=[System.Collections.ArrayList]::new(); $keys=[System.Collections.ArrayList]::new()
    foreach ($k in @($T.Keys)) {
        $e = $T[$k]
        $oi=[System.Collections.ArrayList]::new(); $ok=[System.Collections.ArrayList]::new()
        foreach ($o in @($e['others'].Keys)) { [void]$oi.Add(@{ name=[string]$o; count=[int]$e['others'][$o] }); [void]$ok.Add((CountKey ([int]$e['others'][$o]) $o)) }
        $oSorted=[System.Collections.ArrayList]::new(); Fill-Sorted -Items $oi -Keys $ok -Out $oSorted
        $top=[System.Collections.ArrayList]::new(); foreach ($x in $oSorted) { if ($top.Count -ge 50) { break }; [void]$top.Add($x) }
        $dcl=[System.Collections.ArrayList]::new(); foreach ($d in @($e['dcs'].Keys)) { [void]$dcl.Add(([string]$d -split '\.')[0].ToUpper()) }
        [void]$items.Add(@{ name=[string]$e['name']; count=[int]$e['count']; distinct=[int]$e['others'].Count; others=$top; dcs=$dcl; last=(Fmt-Date $e['last']) })
        [void]$keys.Add((CountKey ([int]$e['count']) ([string]$e['name'])))
    }
    $sorted=[System.Collections.ArrayList]::new(); Fill-Sorted -Items $items -Keys $keys -Out $sorted
    $out=[System.Collections.ArrayList]::new(); foreach ($x in $sorted) { if ($out.Count -ge $Cap) { break }; [void]$out.Add($x) }
    ,$out
}

$EV['skipped'] = [bool]$SkipEvents
if (-not $SkipEvents) {
    Write-Host "[3/6] Reading security events (last $EventDays days)..." -ForegroundColor Yellow
    $EV['collected'] = $true
    # One runspace per DC: reads the logs and stores the raw events in $dc['ev']
    $EvScript = {
        param($dc)
        $n = $dc['name']; $sn = $dc['short']; $dom = [string]$dc['domain']
        $r = @{ lock=[System.Collections.ArrayList]::new(); fail=[System.Collections.ArrayList]::new(); kerb=[System.Collections.ArrayList]::new();
                priv=[System.Collections.ArrayList]::new(); clear=[System.Collections.ArrayList]::new(); ldapDc=[System.Collections.ArrayList]::new();
                ldapCli=[System.Collections.ArrayList]::new(); ok=$false; reason='';
                cbt=[System.Collections.ArrayList]::new(); ntlm1=[System.Collections.ArrayList]::new(); weak=[System.Collections.ArrayList]::new();
                ntlm=[System.Collections.ArrayList]::new(); smb1=[System.Collections.ArrayList]::new(); cov=$null }
        $dc['ev'] = $r
        $EvSamples = @{}; $r['samples'] = $EvSamples
        if (-not $dc['reachable'] -and -not (Test-Port -ComputerName $n -Port 135 -TimeoutMs 1500)) { $r['reason'] = 'RPC (135) not reachable'; return }
        try {
            foreach ($e in (Get-Events $n 'Security' @(4740))) { [void]$r['lock'].Add(@{ acc=(PropVal $e 0); src=(PropVal $e 1); dc=$n; domain=$dom; time=$e.TimeCreated }) }
            foreach ($e in (Get-Events $n 'Security' @(4625))) {
                $acc=PropVal $e 5; $ip=PropVal $e 19; $ws=PropVal $e 13
                $src = if ($ip -and $ip -ne '-') { $ip } elseif ($ws -and $ws -ne '-') { $ws } else { 'unknown' }
                [void]$r['fail'].Add(@{ acc=$acc; src=$src; dc=$n; domain=$dom; time=$e.TimeCreated })
            }
            foreach ($e in (Get-Events $n 'Security' @(4771))) { [void]$r['kerb'].Add(@{ acc=(PropVal $e 0); src=((PropVal $e 6) -replace '^::ffff:',''); dc=$n; domain=$dom; time=$e.TimeCreated }) }
            foreach ($e in (Get-Events $n 'Security' @(4728,4732,4756,4729,4733,4757))) {
                $grp = PropVal $e 2
                if ($PrivGroups -contains $grp) {
                    $act = if (@(4728,4732,4756) -contains [int]$e.Id) { 'added' } else { 'removed' }
                    $mem = PropVal $e 0; if ($mem -match '^CN=([^,]+)') { $mem = $Matches[1] }
                    [void]$r['priv'].Add(@{ time=(Fmt-Date $e.TimeCreated); dc=$sn; domain=$dom; group=$grp; member=$mem; action=$act; by=(PropVal $e 6); id=[int]$e.Id })
                }
            }
            foreach ($e in (Get-Events $n 'Security' @(1102))) { [void]$r['clear'].Add(@{ time=(Fmt-Date $e.TimeCreated); dc=$sn; domain=$dom; by=(PropVal $e 1) }) }
            # LDAP binds (Directory Service log)
            $s2887 = @(Get-Events $n 'Directory Service' @(2887) 1)
            if ($s2887.Count) { $last=$s2887[0]; [void]$r['ldapDc'].Add(@{ dc=$sn; domain=$dom; simple=[int](PropVal $last 0); unsignedSasl=[int](PropVal $last 1); when=(Fmt-Date $last.TimeCreated) }) }
            foreach ($e in (Get-Events $n 'Directory Service' @(2889))) {
                $ipPort = PropVal $e 0; $ip = ($ipPort -replace ':\d+$','') -replace '^\[|\]$',''
                [void]$r['ldapCli'].Add(@{ ip=$ip; who=(PropVal $e 1); bt=(PropVal $e 2); dc=$n; domain=$dom; time=$e.TimeCreated })
            }
            # Old protocols: who still uses them. Each read stands alone, so a missing log does not stop the others.
            $lc = $dc['logcfg']
            $cov = @{ dc=$sn; domain=$dom; known=[bool]$lc; ldap=$(if ($lc) { $lc['ldap'] } else { $null }); ntlmAudit=$(if ($lc) { $lc['ntlmAudit'] } else { $null });
                      smb1Off=$(if ($lc) { $lc['smb1Off'] } else { $null }); smb1Audit=$(if ($lc) { $lc['smb1Audit'] } else { $null });
                      n4624=$null; n4769=$null; n4776=$null; capNtlm1=$false; capWeak=$false; capNtlm=$false; ntlmFrom=''; err=[System.Collections.ArrayList]::new() }
            $r['cov'] = $cov
            try { foreach ($e in (Get-Events $n 'Directory Service' @(3039))) {
                $ipPort = PropVal $e 0; $ip = ($ipPort -replace ':\d+$','') -replace '^\[|\]$',''
                [void]$r['cbt'].Add(@{ ip=$ip; who=(PropVal $e 1); dc=$sn; domain=$dom; time=$e.TimeCreated }) } } catch { [void]$cov['err'].Add('3039') }
            try {
                $x = @(Get-EventsX $n 'Security' "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $SinceMs]]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]")
                foreach ($e in $x) { $d = EvData $e; [void]$r['ntlm1'].Add(@{ acc=($d['TargetDomainName'] + '\' + $d['TargetUserName']); ws=$d['WorkstationName']; ip=$d['IpAddress']; dc=$sn; domain=$dom; time=$e.TimeCreated }) }
                $cov['capNtlm1'] = ($x.Count -ge $MaxEventsPerDc); $cov['n4624'] = Test-AnyEvent $n 'Security' 4624
            } catch { [void]$cov['err'].Add('4624') }
            try {
                $x = @(Get-EventsX $n 'Security' ("*[System[(EventID=4768 or EventID=4769) and TimeCreated[timediff(@SystemTime) <= $SinceMs]]] and *[EventData[Data[@Name='Status']='0x0' and (" +
                    "Data[@Name='TicketEncryptionType']='0x17' or Data[@Name='TicketEncryptionType']='0x18' or Data[@Name='TicketEncryptionType']='0x1' or Data[@Name='TicketEncryptionType']='0x3')]]"))
                foreach ($e in $x) { $d = EvData $e
                    $et = [string]$d['TicketEncryptionType']; $enc = if ($et -eq '0x17' -or $et -eq '0x18') { 'RC4' } else { 'DES' }
                    [void]$r['weak'].Add(@{ acc=(($d['TargetUserName'] -split '@')[0]); svc=$d['ServiceName']; ip=(([string]$d['IpAddress']) -replace '^::ffff:',''); enc=$enc; id=[int]$e.Id; dc=$sn; domain=$dom; time=$e.TimeCreated }) }
                $cov['capWeak'] = ($x.Count -ge $MaxEventsPerDc); $cov['n4769'] = Test-AnyEvent $n 'Security' 4769
            } catch { [void]$cov['err'].Add('4769') }
            # NTLM in use: NTLM auditing (8004, with the server) when it is on, else credential validation (4776)
            try {
                $x = @()
                if ($lc -and $lc['ntlmAudit'] -gt 0) { try { $x = @(Get-Events $n 'Microsoft-Windows-NTLM/Operational' @(8004) -Named); $cov['ntlmFrom'] = '8004' } catch {} }
                if ($cov['ntlmFrom'] -eq '8004') { foreach ($e in $x) { $d = EvData $e; [void]$r['ntlm'].Add(@{ acc=($d['DomainName'] + '\' + $d['UserName']); ws=$d['WorkstationName']; srv=$d['SChannelName']; dc=$sn; domain=$dom; time=$e.TimeCreated }) } }
                else {
                    $x = @(Get-Events $n 'Security' @(4776)); $cov['ntlmFrom'] = '4776'
                    # 4776 fields by position (PackageName, TargetUserName, Workstation, Status): the busiest log, so no XML here
                    foreach ($e in $x) { $st = PropVal $e 3; if ($st -and $st -ne '0' -and $st -ne '0x0') { continue }; [void]$r['ntlm'].Add(@{ acc=(PropVal $e 1); ws=(PropVal $e 2); srv=''; dc=$sn; domain=$dom; time=$e.TimeCreated }) }
                    $cov['n4776'] = [bool]$x.Count
                }
                $cov['capNtlm'] = ($x.Count -ge $MaxEventsPerDc)
            } catch { [void]$cov['err'].Add('ntlm') }
            if (-not ($lc -and $lc['smb1Off'])) {
                try { foreach ($e in (Get-Events $n 'Microsoft-Windows-SMBServer/Audit' @(3000) -Named)) { $d = EvData $e; $c = [string]$d['ClientName']; if (-not $c) { $c = PropVal $e 0 }
                    [void]$r['smb1'].Add(@{ ip=($c -replace '^::ffff:','' -replace '^\[|\]$',''); dc=$sn; domain=$dom; time=$e.TimeCreated }) } } catch { [void]$cov['err'].Add('3000') }
            }
            $r['ok'] = $true
        } catch { $r['reason'] = [string]$_.Exception.Message }
    }
    $tasks = Invoke-DcParallel -Items $DCS -Script $EvScript -Functions @('Test-Port','Read-Events','XIds','Get-Events','Get-EventsX','Test-AnyEvent','EvData','PropVal','Fmt-Date') -Variables @{ Since=$Since; SinceMs=$SinceMs; MaxEventsPerDc=$MaxEventsPerDc; PrivGroups=$PrivGroups } -Throttle $Throttle
    foreach ($t in $tasks) {
        $dc = $t['item']; $r = $dc['ev']; $sn = $dc['short']; $dom = [string]$dc['domain']
        if ($r) {
            foreach ($k in 'lock','fail','kerb','priv','clear','ldapDc','ldapCli','cbt','ntlm1','weak','ntlm','smb1') { foreach ($x in $r[$k]) { [void]$RAW[$k].Add($x) } }
            if ($r['samples']) { foreach ($k in @($r['samples'].Keys)) { $v = $r['samples'][$k]; if ($v) { [void]$RAW['samples'].Add(@{ id=[int]$k; dc=$sn; domain=$dom; time=$v['time']; msg=$v['msg'] }) } } }
            if ($r['cov']) { [void]$RAW['cov'].Add($r['cov']) }
            if ($r['ok']) { [void]$RAW['ok'].Add(@{ dc=$sn; domain=$dom }) } else { [void]$RAW['failed'].Add(@{ dc=$sn; domain=$dom; reason=[string]$r['reason'] }) }
        } else { [void]$RAW['failed'].Add(@{ dc=$sn; domain=$dom; reason=$(if ($t['error']) { [string]$t['error'] } else { 'Event logs could not be read' }) }) }
        $dc.Remove('ev')
    }
    # Aggregates for one domain, or for the whole forest when $Dom is empty
    function Build-EventSet { param([string]$Dom)
        $set = @{ collected=$true; skipped=$false; days=$EventDays; ok=[System.Collections.ArrayList]::new(); failed=[System.Collections.ArrayList]::new(); failTotal=0; kerbTotal=0;
                  privChanges=[System.Collections.ArrayList]::new(); cleared=[System.Collections.ArrayList]::new(); ldapDc=[System.Collections.ArrayList]::new() }
        foreach ($x in $RAW['ok'])     { if (-not $Dom -or $x['domain'] -eq $Dom) { [void]$set['ok'].Add([string]$x['dc']) } }
        foreach ($x in $RAW['failed']) { if (-not $Dom -or $x['domain'] -eq $Dom) { [void]$set['failed'].Add(@{ dc=$x['dc']; reason=$x['reason'] }) } }
        foreach ($x in $RAW['priv'])   { if (-not $Dom -or $x['domain'] -eq $Dom) { [void]$set['privChanges'].Add($x) } }
        foreach ($x in $RAW['clear'])  { if (-not $Dom -or $x['domain'] -eq $Dom) { [void]$set['cleared'].Add($x) } }
        foreach ($x in $RAW['ldapDc']) { if (-not $Dom -or $x['domain'] -eq $Dom) { [void]$set['ldapDc'].Add($x) } }
        $aLock=@{}; $aFailAcc=@{}; $aFailSrc=@{}; $aKerb=@{}; $aLdapCli=@{}; $daily=@{}
        foreach ($x in $RAW['lock']) { if ($Dom -and $x['domain'] -ne $Dom) { continue }; $acc=[string]$x['acc']; Agg $aLock $acc.ToLower() $acc $x['dc'] $x['time'] ([string]$x['src']); Bump-Day $daily $x['time'] 'l' }
        foreach ($x in $RAW['fail']) {
            if ($Dom -and $x['domain'] -ne $Dom) { continue }
            $acc=[string]$x['acc']; $src=[string]$x['src']
            Agg $aFailAcc $acc.ToLower() $acc $x['dc'] $x['time'] $src
            Agg $aFailSrc $src.ToLower() $src $x['dc'] $x['time'] $acc.ToLower()
            $set['failTotal'] = [int]$set['failTotal'] + 1; Bump-Day $daily $x['time'] 'f'
        }
        foreach ($x in $RAW['kerb']) { if ($Dom -and $x['domain'] -ne $Dom) { continue }; $acc=[string]$x['acc']; Agg $aKerb $acc.ToLower() $acc $x['dc'] $x['time'] ([string]$x['src']); $set['kerbTotal'] = [int]$set['kerbTotal'] + 1; Bump-Day $daily $x['time'] 'k' }
        foreach ($x in $RAW['ldapCli']) {
            if ($Dom -and $x['domain'] -ne $Dom) { continue }
            $ip=[string]$x['ip']; $who=[string]$x['who']
            $btTxt = if ([string]$x['bt'] -eq '1') { 'Simple bind without SSL/TLS' } else { 'Unsigned SASL bind' }
            Agg $aLdapCli ($ip.ToLower() + '|' + $who.ToLower()) ($ip + '  (' + $who + ')') $x['dc'] $x['time'] $btTxt
        }
        $set['lockouts'] = Flatten-Agg $aLock 200
        $set['failAccounts'] = Flatten-Agg $aFailAcc 200
        $set['failSources'] = Flatten-Agg $aFailSrc 200
        $set['kerbAccounts'] = Flatten-Agg $aKerb 200
        $set['ldapClients'] = Flatten-Agg $aLdapCli 500
        # Old protocols, one row per client
        $aCbt=@{}; $aN1=@{}; $aWeak=@{}; $aNtlm=@{}; $aSmb=@{}; $set['oldCov'] = [System.Collections.ArrayList]::new()
        foreach ($x in $RAW['cov']) { if (-not $Dom -or $x['domain'] -eq $Dom) { [void]$set['oldCov'].Add($x) } }
        foreach ($x in $RAW['cbt']) { if ($Dom -and $x['domain'] -ne $Dom) { continue }; $ip=[string]$x['ip']; Agg $aCbt $ip.ToLower() $ip $x['dc'] $x['time'] ([string]$x['who']) }
        foreach ($x in $RAW['ntlm1']) {
            if ($Dom -and $x['domain'] -ne $Dom) { continue }
            $ip=[string]$x['ip']; $ws=[string]$x['ws']; if ($ip -eq '-') { $ip='' }; if ($ws -eq '-') { $ws='' }
            $src = if ($ip -and $ws) { $ip + '  (' + $ws + ')' } elseif ($ip) { $ip } elseif ($ws) { $ws } else { 'unknown' }
            Agg $aN1 $src.ToLower() $src $x['dc'] $x['time'] ([string]$x['acc'])
        }
        foreach ($x in $RAW['weak']) {
            if ($Dom -and $x['domain'] -ne $Dom) { continue }
            $ip=[string]$x['ip']; if (-not $ip -or $ip -eq '-') { $ip='unknown' }
            Agg $aWeak $ip.ToLower() $ip $x['dc'] $x['time'] ([string]$x['enc'] + ': ' + [string]$x['acc'] + ' > ' + [string]$x['svc'])
        }
        foreach ($x in $RAW['ntlm']) {
            if ($Dom -and $x['domain'] -ne $Dom) { continue }
            $ws=[string]$x['ws']; if (-not $ws -or $ws -eq '-') { $ws='unknown' }
            Agg $aNtlm $ws.ToLower() $ws $x['dc'] $x['time'] ([string]$x['acc'] + $(if ($x['srv']) { ' > ' + [string]$x['srv'] } else { '' }))
        }
        foreach ($x in $RAW['smb1']) { if ($Dom -and $x['domain'] -ne $Dom) { continue }; $ip=[string]$x['ip']; Agg $aSmb $ip.ToLower() $ip $x['dc'] $x['time'] '' }
        $set['cbtClients'] = Flatten-Agg $aCbt 500
        $set['ntlm1Clients'] = Flatten-Agg $aN1 500
        $set['weakClients'] = Flatten-Agg $aWeak 500
        $set['ntlmClients'] = Flatten-Agg $aNtlm 500
        $set['smb1Clients'] = Flatten-Agg $aSmb 500
        # One real event text per event ID (from the first DC that has one)
        $smp = @{}; foreach ($x in $RAW['samples']) { if ($Dom -and $x['domain'] -ne $Dom) { continue }; $k = [string]$x['id']; if (-not $smp.ContainsKey($k)) { $smp[$k] = @{ dc=$x['dc']; time=$x['time']; msg=$x['msg'] } } }
        $set['samples'] = $smp
        $dl = [System.Collections.ArrayList]::new()
        for ($i = $EventDays - 1; $i -ge 0; $i--) {
            $dk = (Get-Date).AddDays(-$i).ToString('yyyy-MM-dd'); $dv = @{ f=0; k=0; l=0 }; if ($daily.ContainsKey($dk)) { $dv = $daily[$dk] }
            [void]$dl.Add(@{ day=$dk; f=[int]$dv['f']; k=[int]$dv['k']; l=[int]$dv['l'] })
        }
        $set['daily'] = $dl
        return $set
    }
    $fs = Build-EventSet ''
    foreach ($k in @($fs.Keys)) { $EV[$k] = $fs[$k] }
    if ($Multi) { foreach ($d in $AllDomains) { $EVByDomain[[string]$d] = Build-EventSet ([string]$d) } }
} else { Write-Host "[3/6] Security events skipped" -ForegroundColor DarkGray }

# ─────────────────────────────────────────────────────────────────────────────
# 4. Time sync (source + offset via w32tm, several DCs at a time, with a timeout)
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipTime) {
    Write-Host "[4/6] Checking time sources and offsets..." -ForegroundColor Yellow
    $TimeScript = {
        param($dc)
        $c = $dc['name']
        if (-not $dc['reachable'] -and -not (Test-Port -ComputerName $c -Port 135 -TimeoutMs 1500)) { return }
        if (-not $dc['time'].Count) { $dc['time'] = @{ type=''; ntpServer=''; cfgBy=''; announce=$null; vmic=$null; source=''; offset=$null; offsetPdc=$null; error=''; lastSync=''; lastSyncDays=$null; stratum='' } }
        $t = $dc['time']
        try {
            $src = (& w32tm /query /computer:$c /source 2>&1 | Out-String)
            $sc  = (& w32tm /stripchart /computer:$c /samples:1 /dataonly 2>&1 | Out-String)
            $st  = (& w32tm /query /computer:$c /status 2>&1 | Out-String)
            $last = ''; $strat = ''
            foreach ($line in ($st -split '\r?\n')) {
                if ($line -match '^\s*Last Successful Sync Time:\s*(.+)$') { $raw = $Matches[1].Trim(); try { $last = ([datetime]::Parse($raw)).ToString('yyyy-MM-dd HH:mm') } catch { $last = $raw } }
                if ($line -match '^\s*Stratum:\s*(\d+)') { $strat = $Matches[1] }
            }
            $src = $src.Trim()
            if ($src -match 'error|0x8') { $t['error'] = $src } else { $t['source'] = $src }
            if ($sc -match '([+-]\d+\.\d+)s') { $t['offset'] = [double]$Matches[1] }
            $t['lastSync'] = $last
            try { $lsd = [datetime]::ParseExact($last,'yyyy-MM-dd HH:mm',[System.Globalization.CultureInfo]::InvariantCulture); $t['lastSyncDays'] = [int][math]::Floor(((Get-Date) - $lsd).TotalDays) } catch {}
            $t['stratum'] = $strat
        } catch { $t['error'] = [string]$_.Exception.Message }
    }
    $thr = [math]::Max(1,$Throttle)
    $tmo = 45 * [int][math]::Ceiling($DCS.Count / $thr) + 15
    $tasks = Invoke-DcParallel -Items $DCS -Script $TimeScript -Functions @('Test-Port') -Throttle $Throttle -TimeoutSec $tmo
    foreach ($t in $tasks) {
        if (-not $t['timedOut']) { continue }
        $dc = $t['item']
        if (-not $dc['time'].Count) { $dc['time'] = @{ type=''; ntpServer=''; cfgBy=''; announce=$null; vmic=$null; source=''; offset=$null; offsetPdc=$null; error=''; lastSync=''; lastSyncDays=$null; stratum='' } }
        $dc['time']['error'] = 'w32tm did not answer in time'
    }
    # Offset is measured against the PDC emulator of the DC's own domain
    $pdcOff = @{}
    foreach ($dc in $DCS) { if ($dc['isPdc'] -and $dc['time'].Count -and $null -ne $dc['time']['offset']) { $pdcOff[[string]$dc['domain']] = [double]$dc['time']['offset'] } }
    foreach ($dc in $DCS) {
        $ref = $pdcOff[[string]$dc['domain']]
        if ($null -ne $ref -and $dc['time'].Count -and $null -ne $dc['time']['offset']) { $dc['time']['offsetPdc'] = [math]::Round(([double]$dc['time']['offset'] - [double]$ref),3) }
    }
} else { Write-Host "[4/6] Time checks skipped" -ForegroundColor DarkGray }

# Evaluate time findings per DC
foreach ($dc in $DCS) {
    $t = $dc['time']; if (-not $t -or -not $t.Count) { continue }
    $f = [System.Collections.ArrayList]::new()
    $src = [string]$t['source']; $type = [string]$t['type']; $plat = [string]$dc['platform']
    $local = [bool]($src -match 'Local CMOS Clock|Free-running')
    $gpo = ''; if ($t['cfgBy'] -eq 'Group Policy') { $gpo = ' This setting comes from Group Policy, so change it in the GPO that applies to this DC.' }
    # Only the forest-root PDC emulator syncs from external NTP; child-domain PDCs follow the hierarchy
    $isRootPdc = [bool]($dc['isPdc'] -and ([string]$dc['domain'] -eq $ForestDNS))
    if ($isRootPdc) {
        if ($local -or ($type -and $type -ne 'NTP' -and $type -ne 'AllSync')) {
            $why = 'It is running on its own clock.'
            if ($type -eq 'NT5DS') { $why = 'It is set to follow the domain hierarchy (NT5DS), but as PDC emulator it is the top of that hierarchy, so it has no source and runs on its own clock.' }
            elseif (-not $local -and $type) { $why = "Its time type is $type." }
            [void]$f.Add(@{ sev='crit'; title='PDC has no external time source'; advice=($why + ' Configure the PDC emulator to sync from reliable external NTP servers (type NTP, marked as a reliable time source) and allow UDP 123 to them.' + $gpo) })
        }
    } else {
        if ($local) { [void]$f.Add(@{ sev='crit'; title='DC not syncing from the domain hierarchy'; advice=('It is running on its own clock. Check that it can reach other domain controllers on UDP 123 and that its time type is NT5DS (domain hierarchy).' + $gpo) }) }
        if ($type -eq 'NTP') {
            if ($dc['isPdc']) { [void]$f.Add(@{ sev='warn'; title='Manual NTP source on a child-domain PDC'; advice=('Only the PDC emulator of the forest root domain should use external NTP. Set this PDC back to domain hierarchy sync (NT5DS) so it follows the parent domain.' + $gpo) }) }
            else { [void]$f.Add(@{ sev='warn'; title='Manual NTP source on a non-PDC DC'; advice=('Set this DC back to domain hierarchy sync (NT5DS) so only the forest-root PDC emulator uses external NTP.' + $gpo) }) }
        }
    }
    # The Hyper-V time provider only matters on Hyper-V and Azure
    if ($src -match 'VM IC Time') { [void]$f.Add(@{ sev='warn'; title='Syncing from the Hyper-V host'; advice='Disable the Hyper-V time synchronization provider on this domain controller so it follows the domain hierarchy.' }) }
    elseif ($t['vmic'] -eq 1 -and ($plat -eq 'Hyper-V' -or $plat -eq 'Azure')) { [void]$f.Add(@{ sev='info'; title='Hyper-V time provider enabled'; advice="On $plat this provider can override the domain hierarchy. Disable it on domain controllers." }) }
    if ($null -ne $t['offsetPdc'] -and -not $dc['isPdc']) {
        $ab = [math]::Abs([double]$t['offsetPdc'])
        if ($ab -ge 300) { [void]$f.Add(@{ sev='crit'; title='Clock more than 5 minutes off the PDC'; advice='Fix time sync on this DC; Kerberos fails beyond a 5-minute skew.' }) }
        elseif ($ab -ge 2) { [void]$f.Add(@{ sev='warn'; title='Clock drifting from the PDC'; advice='Check the time source and the network path (UDP 123) to the PDC.' }) }
    }
    if ((-not $local) -and $null -ne $t['lastSyncDays'] -and [int]$t['lastSyncDays'] -ge 1) { [void]$f.Add(@{ sev='warn'; title='No recent successful time sync'; advice=('Last successful sync was ' + $t['lastSyncDays'] + ' day(s) ago. Check that the time source answers on UDP 123.') }) }
    if ($t['error']) { [void]$f.Add(@{ sev='info'; title='Time source could not be queried'; advice='Check that the Windows Time service is reachable on this DC.' }) }
    $t['findings'] = $f
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. Backup & recovery readiness (forest settings + every domain)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[5/6] Backup and recovery readiness..." -ForegroundColor Yellow
$BK = @{ recycleBin=$null; recycleBinEnabled=$false; tombstone=$null; partitions=[System.Collections.ArrayList]::new(); sysvol=@{ mode=''; state=''; sev='' }; sysvolDomains=[System.Collections.ArrayList]::new() }
try {
    $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    if ($rb) { $BK['recycleBin'] = $true; $sc = 0; foreach ($x in $rb.EnabledScopes) { if ($x) { $sc++ } }; $BK['recycleBinEnabled'] = [bool]($sc -gt 0) }
    else { $BK['recycleBin'] = $false }
} catch { $BK['recycleBin'] = $false }
try {
    $root = Get-ADRootDSE -ErrorAction Stop
    $cfg = [string]$root.configurationNamingContext
    $ds = Get-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + $cfg) -Properties tombstoneLifetime -ErrorAction Stop
    $tsl = 60; if ($ds.tombstoneLifetime) { $tsl = [int]$ds.tombstoneLifetime }
    $BK['tombstone'] = $tsl
} catch {}
# Domain partitions of the other domains are skipped when a DC lists them (each domain reports its own)
$DomDNs = @{}; foreach ($k in @($DomInfo.Keys)) { $DomDNs[[string]$DomInfo[$k]['dn']] = $k }
$SeenNC = @{}
foreach ($dom in $AllDomains) {
    if (-not $DomInfo.ContainsKey($dom)) { continue }
    $ddn = [string]$DomInfo[$dom]['dn']; $srv = [string]$DomInfo[$dom]['pdc']
    $rootD = $null
    try { $rootD = Get-ADRootDSE -Server $srv -ErrorAction Stop }
    catch { try { $rootD = Get-ADRootDSE -Server $dom -ErrorAction Stop; $srv = [string]$rootD.dnsHostName } catch {} }
    if ($rootD) {
        $sfx = ''; if ($Multi) { $sfx = " ($dom)" }
        foreach ($nc in @($rootD.namingContexts)) {
            $ncs = [string]$nc; $last = $null; $err = ''
            if ($SeenNC.ContainsKey($ncs)) { continue }
            if ($DomDNs.ContainsKey($ncs) -and $ncs -ne $ddn) { continue }
            if ($ncs -like 'DC=DomainDnsZones,*' -and $ncs -ne ('DC=DomainDnsZones,' + $ddn)) { continue }
            $SeenNC[$ncs] = $true
            try {
                $md = Get-ADReplicationAttributeMetadata -Object $ncs -Server $srv -Properties dSASignature -ErrorAction Stop
                foreach ($m in @($md)) { if ([string]$m.AttributeName -eq 'dSASignature') { $last = $m.LastOriginatingChangeTime } }
            } catch { $err = [string]$_.Exception.Message }
            $days = $null; if ($last) { $days = [int][math]::Floor(((Get-Date) - [datetime]$last).TotalDays) }
            $label = if ($ncs -eq $ddn) { 'Domain' + $sfx } elseif ($ncs -like 'CN=Configuration,*') { 'Configuration' } elseif ($ncs -like 'CN=Schema,*') { 'Schema' } elseif ($ncs -like 'DC=DomainDnsZones,*') { 'DomainDnsZones' + $sfx } elseif ($ncs -like 'DC=ForestDnsZones,*') { 'ForestDnsZones' } else { $ncs }
            $ncDom = ''; if ($ncs -eq $ddn -or $ncs -like 'DC=DomainDnsZones,*') { $ncDom = $dom }
            [void]$BK['partitions'].Add(@{ name=$label; dn=$ncs; domain=$ncDom; last=(Fmt-Date $last); days=$days; error=$err })
        }
    }
    # SYSVOL replication of this domain
    $flRaw = $null; $dfsrGroup = $false
    try { $gs = Get-ADObject ("CN=DFSR-GlobalSettings,CN=System," + $ddn) -Server $srv -Properties 'msDFSR-Flags' -ErrorAction Stop; $flRaw = $gs.'msDFSR-Flags' } catch {}
    try { $null = Get-ADObject ("CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System," + $ddn) -Server $srv -ErrorAction Stop; $dfsrGroup = $true } catch {}
    $sv = if ($null -ne $flRaw -and [int]$flRaw -eq 48) { @{ mode='DFSR'; state='Migrated from FRS (Eliminated state)'; sev='ok' } }
          elseif ($dfsrGroup -and $null -eq $flRaw) { @{ mode='DFSR'; state='DFSR from the start'; sev='ok' } }
          elseif ($null -ne $flRaw -and ([int]$flRaw -eq 16 -or [int]$flRaw -eq 32)) { @{ mode='FRS to DFSR migration'; state=$(if ([int]$flRaw -eq 16) { 'Prepared state - migration not finished' } else { 'Redirected state - migration not finished' }); sev='warn' } }
          else { @{ mode='FRS'; state='SYSVOL is still replicated by FRS'; sev='crit' } }
    $sv['domain'] = $dom
    [void]$BK['sysvolDomains'].Add($sv)
}
# One SYSVOL line for the forest: the worst domain
$svL = $BK['sysvolDomains']
if ($svL.Count -eq 1) { $BK['sysvol'] = @{ mode=$svL[0]['mode']; state=$svL[0]['state']; sev=$svL[0]['sev'] } }
elseif ($svL.Count -gt 1) {
    $R = @{ crit=3; warn=2; info=1; ok=0 }; $worst = $null; $bad = 0
    foreach ($x in $svL) { if ($x['sev'] -ne 'ok') { $bad++ }; if ($null -eq $worst -or $R[[string]$x['sev']] -gt $R[[string]$worst['sev']]) { $worst = $x } }
    if ($bad -eq 0) { $BK['sysvol'] = @{ mode='DFSR'; state=('DFSR in all ' + $svL.Count + ' domains'); sev='ok' } }
    else {
        $more = ''; if ($bad -gt 1) { $more = ' and ' + ($bad - 1) + ' other domain(s)' }
        $BK['sysvol'] = @{ mode=$worst['mode']; state=($worst['state'] + ' (' + $worst['domain'] + $more + ')'); sev=$worst['sev'] }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. Windows Server 2025 migration readiness
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[6/6] Windows Server 2025 readiness..." -ForegroundColor Yellow
$W25 = @{ ffl=$null; dfl=$null; dfls=@{}; schema=$null; dcs=[System.Collections.ArrayList]::new(); exchange=[System.Collections.ArrayList]::new(); notes=[System.Collections.ArrayList]::new() }
try {
    $root6 = Get-ADRootDSE -ErrorAction Stop
    $cfg6  = [string]$root6.configurationNamingContext
    try { $p = Get-ADObject ("CN=Partitions," + $cfg6) -Properties 'msDS-Behavior-Version' -ErrorAction Stop; $W25['ffl'] = [int]$p.'msDS-Behavior-Version' } catch { [void]$W25['notes'].Add('Forest functional level could not be read.') }
    try { $sc = Get-ADObject ([string]$root6.schemaNamingContext) -Properties objectVersion -ErrorAction Stop; $W25['schema'] = [int]$sc.objectVersion } catch {}
    # Domain functional level of every domain; the lowest one is what blocks
    foreach ($dom in $AllDomains) {
        if (-not $DomInfo.ContainsKey($dom)) { continue }
        try { $dh = Get-ADObject ([string]$DomInfo[$dom]['dn']) -Server $dom -Properties 'msDS-Behavior-Version' -ErrorAction Stop; $W25['dfls'][$dom] = [int]$dh.'msDS-Behavior-Version' }
        catch { [void]$W25['notes'].Add("Domain functional level of $dom could not be read.") }
    }
    foreach ($v in @($W25['dfls'].Values)) { if ($null -eq $W25['dfl'] -or [int]$v -lt [int]$W25['dfl']) { $W25['dfl'] = [int]$v } }
    # Every DC in the forest (functional level 2016 needs all of them on 2016+)
    foreach ($dc in $DCS) { [void]$W25['dcs'].Add(@{ name=$dc['name']; domain=$dc['domain']; os=$dc['os']; build=$dc['build']; ok=[bool]([int]$dc['build'] -ge 14393) }) }
    # Exchange servers in the forest
    try {
        $ex = @(Get-ADObject -SearchBase ("CN=Microsoft Exchange,CN=Services," + $cfg6) -LDAPFilter '(objectCategory=msExchExchangeServer)' -Properties serialNumber -ErrorAction Stop)
        foreach ($e in $ex) {
            $sn = [string](@($e.serialNumber)[0]); $ver=''
            if ($sn -match 'Version (\d+\.\d+)') { $ver = $Matches[1] }
            $label = switch ($ver) { '15.2' { 'Exchange 2019 / SE' } '15.1' { 'Exchange 2016' } '15.0' { 'Exchange 2013' } '14.3' { 'Exchange 2010' } '14.2' { 'Exchange 2010' } '14.1' { 'Exchange 2010' } '14.0' { 'Exchange 2010' } default { if ($ver) { "Exchange $ver" } else { 'Exchange (version unknown)' } } }
            [void]$W25['exchange'].Add(@{ name=[string]$e.Name; version=$sn; ver=$ver; label=$label })
        }
    } catch {}
} catch { [void]$W25['notes'].Add("Readiness checks failed: $($_.Exception.Message)") }

# ─────────────────────────────────────────────────────────────────────────────
# JSON: own writer (handles PowerShell-wrapped values).
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
    if ($o -is [int] -or $o -is [long] -or $o -is [double]) { [void]$sb.Append(([string]$o).Replace(',','.')); return }
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

Write-Host "Assembling report data..." -ForegroundColor Yellow
$stage = 'summary'
try {
    $Summary = @{ domain=$DomainDNS; forest=$ForestDNS; generated=$GeneratedAt; pdc=$RootPdc; domains=$AllDomains; pdcs=$PdcMap; domNotes=$DomNotes; dcs=$DCS; desOnly=$DesOnly; events=$EV; eventsByDomain=$EVByDomain; backup=$BK; w25=$W25; maxEvents=$MaxEventsPerDc }
    $stage = 'serialize'
    $DataJSON = $null
    # Own JSON writer: the .NET JavaScriptSerializer can spend a very long time on PowerShell-wrapped values before failing
    $__jsb = [System.Text.StringBuilder]::new(); Write-JsonValue $Summary $__jsb; $DataJSON = $__jsb.ToString()
    Write-Host ("  JSON size: {0} MB" -f [math]::Round($DataJSON.Length/1MB,2)) -ForegroundColor Gray
} catch {
    Write-Host ""
    Write-Host ">>> FAILED at stage '$stage': $($_.Exception.GetType().Name) - $($_.Exception.Message)" -ForegroundColor Red
    throw
}

Write-Host "Composing HTML..." -ForegroundColor Yellow
$HTML = @"
<!DOCTYPE html>
<html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD DC Posture - $ForestDNS</title>
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
.evgap{display:flex;gap:9px;align-items:flex-start;margin:0 18px 10px;padding:10px 13px;border-radius:9px;background:var(--amber-soft,#fff7e6);color:var(--text);font-size:13px;line-height:1.5}
.evgap .ic{flex-shrink:0;margin-top:2px;color:var(--amber,#b45309)}
.evgap:first-child{margin-top:14px}
.evabout{display:flex;align-items:center;flex-wrap:wrap;gap:6px;padding:10px 16px;border-bottom:1px solid var(--border);font-size:12.5px;color:var(--muted)}
.evchip{font:600 12px/1 inherit;font-family:inherit;padding:5px 10px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--accent);cursor:pointer}
.evchip:hover,.evchip.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.evhint{margin-left:auto;font-size:12px}
.evdesc{margin:12px 16px;padding:12px 14px;border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;background:var(--surface2)}
.evdt{font-weight:700;font-size:13.5px;display:flex;align-items:center;gap:8px}
.evid{font:700 11.5px/1 ui-monospace,Consolas,monospace;padding:3px 7px;border-radius:5px;background:var(--accent);color:#fff}
.evdd{font-size:13px;line-height:1.55;margin:6px 0 8px}
.evdm{display:flex;flex-wrap:wrap;gap:6px 18px;justify-content:space-between;font-size:12.5px;color:var(--muted)}
.evdm a{color:var(--accent);font-weight:600;text-decoration:none}
tr.evr{cursor:pointer}tr.evr:hover td{background:var(--surface2)}tr.evr.open td{background:var(--surface2)}
tr.evdet>td{background:var(--surface2);padding:4px 0 8px!important}
.evkvs{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px 18px;padding:10px 16px}
.evkv .k{font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);margin-bottom:3px}
.evkv .v{font-size:13px;word-break:break-word}.evkv ul{margin:0;padding-left:16px;max-height:180px;overflow:auto}
tr.evdet .evdesc{margin:6px 16px}
.evlbl{display:block;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);margin-bottom:2px}
.evraw{margin-top:10px;border-top:1px solid var(--border);padding-top:8px}
.evraw summary{cursor:pointer;font-size:12.5px;font-weight:600;color:var(--accent)}
.evraw pre{margin:8px 0 0;padding:10px 12px;max-height:340px;overflow:auto;background:var(--surface);border:1px solid var(--border);border-radius:6px;font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-word;color:var(--text)}
.evnoraw{margin-top:8px;font-size:12px;color:var(--muted)}
</style></head><body>
<aside class="side">
  <div class="sbrand"><div class="slogo"><i class="ic" data-i="key"></i></div><div><div class="skick">AD Audit Suite</div><div class="stitle">DC Posture</div></div></div>
  <div class="smeta" id="topmeta"></div>
  <div class="sdom" id="sdomwrap" style="display:none"><label for="domsel">Domain</label><select id="domsel"></select></div>
  <div class="sgroup">Report</div>
  <nav id="secnav"></nav>
  <div class="sfoot"><button class="sbtn" id="themebtn"><i class="ic" data-i="moon"></i><span id="themetxt">Dark mode</span></button></div>
</aside>
<main class="main">
  <header class="phead anchor" id="sec-overview"><h1>Domain Controller Posture</h1><div class="psub">Protocol hardening, security events, time sync and recovery readiness across all domain controllers</div></header>
  <div id="coverage"></div>
  <div class="kpi-grid" id="kpis"></div>
  <div id="fbanner"></div>

  <section class="sect anchor" id="sec-w25"><div class="sect-head"><i class="ic" data-i="up"></i>Windows Server 2025 readiness <span class="cnt" id="w25cnt"></span></div><div class="sect-body" id="w25"></div></section>

  <section class="sect anchor" id="sec-proto"><div class="sect-head"><i class="ic" data-i="shield"></i>Protocols &amp; hardening<button class="mini-btn" onclick="csvSettings()"><i class="ic" data-i="download"></i>CSV</button></div><div class="sect-body">
    <div class="layout">
      <div class="panel-card" style="margin-bottom:0"><div class="list-search"><input id="setq" placeholder="Filter settings..."></div><div class="item-list" id="setlist"></div></div>
      <div class="panel-card" style="margin-bottom:0"><div class="detail" id="setdetail"></div></div>
    </div></div></section>

  <section class="sect anchor" id="sec-events"><div class="sect-head"><i class="ic" data-i="journal"></i>Security events <span class="cnt" id="evdays"></span></div><div class="sect-body" id="events"></div></section>

  <section class="sect anchor" id="sec-time"><div class="sect-head"><i class="ic" data-i="clock"></i>Time sync hierarchy</div><div class="sect-body" id="time"></div></section>

  <section class="sect anchor" id="sec-backup"><div class="sect-head"><i class="ic" data-i="archive"></i>Backup &amp; recovery readiness</div><div class="sect-body" id="backup"></div></section>
</main>

<script>
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
 people:P+'<path d="M7 14s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1zm4-6a3 3 0 1 0 0-6 3 3 0 0 0 0 6m-5.784 6A2.24 2.24 0 0 1 5 13c0-1.355.68-2.75 1.936-3.72A6.3 6.3 0 0 0 5 9c-4 0-5 3-5 4s1 1 1 1zM4.5 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5"/></svg>'
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
  X.view=sel;X.domain=sel;X.pdc=(X.pdcs||{})[sel]||'';X.dcs=arr(X.dcs).filter(inD);X.desOnly=arr(X.desOnly).filter(inD);X.domNotes=[];
  if(X.eventsByDomain&&X.eventsByDomain[sel])X.events=X.eventsByDomain[sel];
  if(X.backup){X.backup.partitions=arr(X.backup.partitions).filter(function(q){return !q.domain||(''+q.domain).toLowerCase()===lc;});var sv=arr(X.backup.sysvolDomains).filter(inD)[0];if(sv)X.backup.sysvol={mode:sv.mode,state:sv.state,sev:sv.sev};}
  if(X.w25){X.w25.dcs=arr(X.w25.dcs).filter(inD);var fl=(X.w25.dfls||{})[sel];X.w25.dfl=(fl==null?null:fl);var o={};if(fl!=null)o[sel]=fl;X.w25.dfls=o;}
  return X;}
</script>
<script type="text/plain" id="app">
var DCS=arr(D.dcs), EV=D.events||{}, BK=D.backup||{}, DES=arr(D.desOnly);
var MULTI=DOMS.length>1, SHOWDOM=MULTI&&!D.view;
function domSub(dc){return SHOWDOM&&dc.domain?'<span class="dsub">'+esc(dc.domain)+'</span>':'';}
function dcWho(dc){return SHOWDOM&&dc.domain?dc.short+' ('+(''+dc.domain).split('.')[0]+')':dc.short;}
qs('#topmeta').innerHTML=(SHOWDOM?'<div>Forest<b>'+esc(D.forest)+'</b></div><div>PDC emulator (forest root)<b>'+esc(D.pdc)+'</b></div>':'<div>Domain<b>'+esc(D.domain)+'</b></div><div>PDC emulator<b>'+esc(D.pdc)+'</b></div>')+'<div>Generated<b>'+esc(D.generated)+'</b></div>';
qs('#themebtn').onclick=function(){var d=document.documentElement.getAttribute('data-theme')==='dark';document.documentElement.setAttribute('data-theme',d?'light':'dark');qs('#themetxt').textContent=d?'Dark mode':'Light mode';qs('#themebtn i').innerHTML=ICONS[d?'moon':'sun'];};

/* ---------------- settings metadata ---------------- */
var SET=[
 ['ldapSign','LDAP signing','Whether the domain controller requires LDAP clients to sign their binds. Unsigned binds can be intercepted and relayed.','Required'],
 ['ldapCbt','LDAP channel binding','Ties LDAPS sessions to the TLS channel so credentials cannot be relayed over LDAPS.','Always'],
 ['ldapLog','LDAP client logging','LDAP interface event logging (NTDS Diagnostics, "16 LDAP Interface Events"). At level 2 the DC records the IP address and account of each client making an unsigned or clear-text bind (event 2889). Without it, only a daily count is logged (event 2887).','2 while finding unsigned clients, then 0; not needed once signing is required'],
 ['ldaps','LDAPS certificate','Tested from the machine that ran this report: port 636 and the certificate it presents.','Valid certificate, not expiring within 30 days'],
 ['ntlmLevel','NTLM level','LAN Manager authentication level (LmCompatibilityLevel). Below 5 the DC still accepts LM and NTLMv1.','5 - Send NTLMv2 only, refuse LM & NTLM'],
 ['ntlmAudit','NTLM auditing','Auditing or restricting NTLM in the domain shows which clients still depend on it.','Auditing enabled, then restriction'],
 ['noLm','LM hash storage','Whether LM password hashes (trivially crackable) are stored.','Not stored'],
 ['smbSign','SMB signing','Required SMB signing blocks NTLM relay to the domain controller over SMB.','Required'],
 ['smb1','SMBv1','The legacy SMB 1.0 protocol.','Disabled / removed'],
 ['tls','SSL / TLS protocols','Server-side Schannel protocol settings. "default" means not configured, so the OS default applies.','SSL 2.0/3.0 and TLS 1.0/1.1 off, TLS 1.2 on'],
 ['llmnr','LLMNR','Link-Local Multicast Name Resolution, a common name-poisoning target.','Disabled'],
 ['netbios','NetBIOS over TCP/IP','NetBIOS name resolution on the DC network adapters.','Disabled'],
 ['wdigest','WDigest','When on, clear-text passwords are kept in memory.','Disabled'],
 ['lsaPpl','LSA protection','Runs LSASS as a protected process to resist credential dumping.','Enabled'],
 ['kerbEnc','Kerberos encryption types','Encryption types the DC allows for Kerberos.','AES only'],
 ['spooler','Print Spooler','A running spooler on a DC enables authentication coercion attacks.','Stopped and disabled']];
function dcSetting(dc,id){var r=null;arr(dc.settings).forEach(function(s){if(s.id===id)r=s;});return r;}
function covDc(c){return c.dc+(SHOWDOM&&c.domain?' ('+(''+c.domain).split('.')[0]+')':'');}
function covWho(fn){return arr(EV.oldCov).filter(fn).map(covDc);}
var OLDGAP={
 cbt:function(){var g=[],a=covWho(function(c){return c.known&&!(c.ldap>=2);}),u=covWho(function(c){return !c.known;});
   if(a.length)g.push(['Not logged on '+a.join(', '),'Raise LDAP client logging to 2 on these domain controllers (see Protocols &rsaquo; LDAP client logging). Event 3039 is written at that level only.']);
   if(u.length)g.push(['Not known on '+u.join(', '),'The settings of these domain controllers could not be read, so it is not known whether event 3039 is logged.']);return g;},
 ntlm1:function(){var g=[],a=covWho(function(c){return c.n4624===false;}),k=covWho(function(c){return c.capNtlm1;});
   if(a.length)g.push(['No logon event (4624) on '+a.join(', '),'Turn on success auditing for Audit Logon (Advanced Audit Policy &rsaquo; Logon/Logoff) for the domain controllers, and make the Security log large enough to cover the period.']);
   if(k.length)g.push(['Limit reached on '+k.join(', '),'Only the newest '+(+D.maxEvents||5000)+' events were read on these domain controllers. Run the report with a higher -MaxEventsPerDc to see more.']);return g;},
 weak:function(){var g=[],a=covWho(function(c){return c.n4769===false;}),k=covWho(function(c){return c.capWeak;});
   if(a.length)g.push(['No Kerberos ticket event (4769) on '+a.join(', '),'Turn on success auditing for Audit Kerberos Authentication Service and Audit Kerberos Service Ticket Operations (Advanced Audit Policy &rsaquo; Account Logon) for the domain controllers.']);
   if(k.length)g.push(['Limit reached on '+k.join(', '),'Only the newest '+(+D.maxEvents||5000)+' events were read on these domain controllers. Run the report with a higher -MaxEventsPerDc to see more.']);return g;},
 ntlm:function(){var g=[],a=covWho(function(c){return c.ntlmFrom==='4776';}),z=covWho(function(c){return c.ntlmFrom==='4776'&&c.n4776===false;}),k=covWho(function(c){return c.capNtlm;});
   if(a.length)g.push(['Workstation and account only on '+a.join(', '),'These domain controllers do not audit NTLM, so the list comes from event 4776. To also see the server each NTLM logon is for (event 8004), set "Network security: Restrict NTLM: Audit NTLM authentication in this domain" to "Enable all" on the domain controllers.']);
   if(z.length)g.push(['Nothing recorded on '+z.join(', '),'Turn on success auditing for Audit Credential Validation (Advanced Audit Policy &rsaquo; Account Logon) for the domain controllers.']);
   if(k.length)g.push(['Limit reached on '+k.join(', '),'Only the newest '+(+D.maxEvents||5000)+' events were read on these domain controllers, so this is a sample of recent NTLM use. Run the report with a higher -MaxEventsPerDc to see more.']);return g;},
 smb1:function(){var g=[],o=covWho(function(c){return c.smb1Off===true;}),a=covWho(function(c){return c.known&&c.smb1Off!==true&&!(c.smb1Audit>=1);});
   if(a.length)g.push(['Not audited on '+a.join(', '),'SMBv1 is enabled on these domain controllers but its use is not logged. Turn on SMBv1 access auditing in the SMB server configuration (AuditSmb1Access), then run the report again after a few days.']);
   if(o.length)g.push(['Disabled on '+o.join(', '),'SMBv1 is off on these domain controllers, so no client can use it there.']);return g;}};
function gapHtml(g){return g.map(function(x){return '<div class="evgap">'+ic('info')+'<span><b>'+esc(x[0])+'.</b> '+x[1]+'</span></div>';}).join('');}
function logOff(){return DCS.filter(function(dc){var s=dcSetting(dc,'ldapLog');return s&&s.sev!=='ok';}).map(function(dc){return dcWho(dc);});}
function roleTxt(dc){return (dc.isPdc?'PDC emulator':'Domain controller')+(dc.rodc?' (read-only)':'');}
function offTxt(o){o=+o;return (o>=0?'+':'')+o.toFixed(3)+' s';}
var TSL=BK.tombstone||180;
function partSev(p){if(p.error&&p.days==null)return 'info';if(p.days==null)return 'crit';if(p.days>TSL/2)return 'crit';if(p.days>7)return 'warn';return 'ok';}

/* ---------------- aggregate findings ---------------- */
var F={};
function addF(sec,sev,title,advice,who){var k=sec+'|'+title;if(!F[k])F[k]={sec:sec,sev:sev,title:title,advice:advice,who:[]};var f=F[k];if(RANK[sev]>RANK[f.sev])f.sev=sev;if(!f.advice)f.advice=advice;if(who&&f.who.indexOf(who)<0)f.who.push(who);}
DCS.forEach(function(dc){
  arr(dc.settings).forEach(function(s){if(s.sev!=='ok')addF('proto',s.sev,s.title,s.advice,dcWho(dc));});
  arr((dc.time||{}).findings).forEach(function(t){addF('time',t.sev,t.title,t.advice,dcWho(dc));});
  if(!dc.regRead)addF('proto','info','Settings could not be read on some DCs','Run the report from a host that can reach these DCs over DCOM (or WinRM) with admin rights.',dcWho(dc));
});
DES.forEach(function(a){addF('proto','crit','Accounts restricted to DES Kerberos','Clear "Use only Kerberos DES encryption types" on these accounts and reset their passwords so AES keys are created.',a.name);});
if(EV.collected){
  arr(EV.lockouts).forEach(function(x){if(x.count>=5)addF('events','warn','Accounts locked out repeatedly','Find the device or service still using an old password (see the caller computers) and update it.',x.name);});
  arr(EV.failSources).forEach(function(x){if(x.distinct>=10)addF('events','warn','Possible password spraying','Identify the source machine and investigate; consider blocking it and resetting passwords for targeted accounts.',x.name);});
  arr(EV.privChanges).forEach(function(c){addF('events','warn','Privileged group membership changed','Confirm each change was authorised.',c.member+' '+c.action+' '+(c.action==='added'?'to':'from')+' '+c.group);});
  arr(EV.cleared).forEach(function(c){addF('events','crit','Security log was cleared','Confirm who cleared the log and why; this is a common step to hide an intrusion.',c.dc);});
  arr(EV.ldapDc).forEach(function(x){if(x.simple>0||x.unsignedSasl>0)addF('events','warn','Clients using unsigned or clear-text LDAP','Move these clients to LDAPS or signed binds, then require LDAP signing.'+(logOff().length?' To see each client (event 2889), raise LDAP client logging to 2 on: '+logOff().join(', ')+'.':''),x.dc);});
  arr(EV.cbtClients).forEach(function(x){addF('events','warn','LDAPS clients without channel binding','Update these clients so they support LDAP channel binding before setting it to Always on the domain controllers.',x.name);});
  arr(EV.ntlm1Clients).forEach(function(x){addF('events','warn','Clients using NTLMv1','NTLMv1 is removed in Windows Server 2025. Move these clients and applications to NTLMv2 or Kerberos, then refuse LM and NTLMv1 on the domain controllers.',x.name);});
  arr(EV.weakClients).forEach(function(x){addF('events','warn','Kerberos tickets issued with RC4 or DES','Find why each client or service still gets RC4 or DES tickets (accounts without AES keys, services limited to RC4, old clients) and fix it before allowing AES only.',x.name);});
  arr(EV.smb1Clients).forEach(function(x){addF('events','warn','Clients using SMBv1','Update or replace these clients, then remove SMB 1.0 from the domain controllers.',x.name);});
  if(arr(EV.ntlmClients).length)addF('events','info','NTLM still in use','Review the computers that still use NTLM before restricting it in the domain; most can use Kerberos once they connect by DNS name to servers with the right SPNs.',plural(arr(EV.ntlmClients).length,'computer'));
  (function(){var w={};['cbt','ntlm1','weak','ntlm','smb1'].forEach(function(k){OLDGAP[k]().forEach(function(g){if(/^(Not logged|No |Not audited|Nothing recorded)/.test(g[0]))w[g[0].replace(/^.* on /,'')]=1;});});
    Object.keys(w).forEach(function(k){k.split(', ').forEach(function(dc){addF('events','info','Old-protocol use not fully logged','See Security events: each list says what to turn on and on which domain controllers.',dc);});});})();
  arr(EV.failed).forEach(function(f){addF('events','info','Event logs could not be read on some DCs','Check RPC access and Event Log Readers rights from the host running the report.',f.dc);});
}
var rbSev=BK.recycleBin===false?'info':(BK.recycleBinEnabled?'ok':'warn');
if(rbSev==='warn')addF('backup','warn','AD Recycle Bin not enabled','Enable the AD Recycle Bin so deleted objects can be restored with all their attributes. It requires forest functional level 2008 R2 or higher and cannot be turned off afterwards.','Forest');
if(TSL<180)addF('backup','info','Tombstone lifetime below 180 days','Consider raising the tombstone lifetime to 180 days to widen the window for restores.','Forest');
var SV=BK.sysvol||{};
if(SV.sev==='crit')addF('backup','crit','SYSVOL still replicated by FRS','Migrate SYSVOL replication from FRS to DFSR. FRS is deprecated and newer Windows Server versions cannot be promoted in an FRS domain.','Domain');
if(SV.sev==='warn')addF('backup','warn','SYSVOL migration to DFSR not finished','Complete the SYSVOL migration to the Eliminated state.','Domain');
arr(BK.partitions).forEach(function(p){var s=partSev(p);if(s==='crit'||s==='warn')addF('backup',s,s==='crit'?(p.days==null?'Partition never backed up':'Last backup older than half the tombstone lifetime'):'No backup in the last 7 days','Back up at least one domain controller (system state) regularly - daily is typical - and well within the tombstone lifetime.',p.name);});
/* ---------------- readiness checks: Windows Server 2025 + Kerberos RC4 hardening ---------------- */
var W=D.w25||{}, FLNAME={0:'2000',1:'2003 interim',2:'2003',3:'2008',4:'2008 R2',5:'2012',6:'2012 R2',7:'2016',10:'2025'};
function flTxt(v){return v==null?'unknown':('Windows Server '+(FLNAME[v]||('level '+v)));}
var MS={
 whatsnew:{u:'https://learn.microsoft.com/windows-server/get-started/whats-new-windows-server-2025',t:"What's new in Windows Server 2025 (AD DS functional levels)"},
 fl:{u:'https://learn.microsoft.com/windows-server/identity/ad-ds/active-directory-functional-levels',t:'Active Directory functional levels'},
 frs:{u:'https://learn.microsoft.com/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr',t:'Migrate SYSVOL replication to DFS Replication'},
 removed:{u:'https://learn.microsoft.com/windows-server/get-started/removed-deprecated-features-windows-server',t:'Features removed or deprecated in Windows Server'},
 exch:{u:'https://learn.microsoft.com/exchange/plan-and-deploy/supportability-matrix',t:'Exchange Server supportability matrix'},
 rc4:{u:'https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos',t:'Detect and remediate RC4 usage in Kerberos'},
 kb:{u:'https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc',t:'KDC usage of RC4 - changes related to CVE-2026-20833'}
};
var CHK=[], CURG='w25', CURS=null;
function wc(sev,title,result,advice,cols,rows,note,noF){rows=rows||[];CHK.push({grp:CURG,src:CURS,sev:sev,title:title,result:result,advice:advice||'',cols:cols||[],rows:rows,note:note||''});
  if(sev==='ok'||noF)return;
  if(rows.length)rows.forEach(function(r){addF(CURG,sev,title,advice,''+r[0]);});else addF(CURG,sev,title,advice,result);}
var W25C=CHK; /* kept for compatibility */
(function(){
  if(!D.w25)return;
  /* ===== Windows Server 2025 readiness: Microsoft-documented requirements only ===== */
  CURG='w25'; CURS=MS.whatsnew;
  var DFL=W.dfls||{},DK=Object.keys(DFL).sort();
  [['Forest functional level',W.ffl,'forest',[]],['Domain functional level',W.dfl,'domain',DK.length>1?DK:[]]].forEach(function(x){
    var many=x[3].length>1,cols=many?['Domain','Functional level','Status']:[],rows=x[3].map(function(d){return [d,flTxt(DFL[d]),DFL[d]>=7?tag('ok','supported'):tag('crit','too low')];});
    var res=flTxt(x[1])+(many?', lowest of '+x[3].length+' domains':'');
    if(x[1]==null)wc('info',x[0],'Could not be read','Check the functional level manually before planning the migration.',[],[]);
    else if(x[1]>=7)wc('ok',x[0],res,'',cols,rows);
    else{var adv='Microsoft requires the '+x[2]+' functional level to be Windows Server 2016 or later before a Windows Server 2025 domain controller can be promoted. Raising it first requires every domain controller in the '+x[2]+' to run Windows Server 2016 or later.';
      wc('crit',x[0]+' too low',res+' (2016 required)',adv,cols,rows,'',many);
      if(many)x[3].forEach(function(d){if(DFL[d]<7)addF('w25','crit',x[0]+' too low',adv,d);});}});
  CURS=MS.fl;
  var dcs=arr(W.dcs), bad=dcs.filter(function(d){return !d.ok;});
  var osCount={};dcs.forEach(function(d){osCount[d.os]=(osCount[d.os]||0)+1;});
  var osTxt=Object.keys(osCount).map(function(k){return osCount[k]+' x '+k.replace('Windows Server ','WS ');}).join(', ');
  var dcRows=dcs.slice().sort(function(a,b){return (a.ok-b.ok)||(''+a.name).localeCompare(''+b.name);}).map(function(d){return [d.name,d.domain,d.os,d.ok?tag('ok','supported'):tag('crit','too old')];});
  if(!dcs.length)wc('info','Domain controller versions','Could not be listed','',[],[]);
  else if(bad.length)wc('crit','Domain controllers older than Windows Server 2016',bad.length+' of '+plural(dcs.length,'DC'),'Retire or upgrade these domain controllers first. Functional level 2016, which Windows Server 2025 requires, cannot be reached while they remain.',['Domain controller','Domain','Operating system','Status'],dcRows);
  else wc('ok','Domain controller versions',osTxt,'',['Domain controller','Domain','Operating system','Status'],dcRows);
  CURS=MS.frs;
  var sv=BK.sysvol||{};
  if(sv.sev==='ok')wc('ok','SYSVOL replication',sv.mode+' - '+sv.state,'',[],[]);
  else if(sv.sev)wc('crit','SYSVOL not fully on DFSR',sv.state,'Complete the SYSVOL migration from FRS to DFSR (Eliminated state). FRS is no longer available in current Windows Server versions, so a Windows Server 2025 domain controller cannot be promoted while SYSVOL still uses FRS.',[],[]);
  CURS=MS.removed;
  var des=arr(D.desOnly);
  if(des.length)wc('crit','Accounts restricted to DES',plural(des.length,'account'),'DES is removed from Windows Server 2025. Clear "Use only Kerberos DES encryption types" on these accounts and reset their passwords so AES keys are created.',['Account','Name'],des.map(function(a){return [a.sam,a.name];}),'',true);
  else wc('ok','No accounts restricted to DES','','',[],[]);
  var nt=DCS.filter(function(dc){var s=dcSetting(dc,'ntlmLevel');return s&&s.sev!=='ok';});
  if(nt.length)wc('warn','Domain controllers still accept NTLMv1',plural(nt.length,'DC'),'NTLMv1 is removed from Windows Server 2025, so any client still using it will fail against a Windows Server 2025 domain controller. Find NTLMv1 clients (NTLM auditing), fix them, then raise the LAN Manager authentication level on all domain controllers.',['Domain controller','Current level'],nt.map(function(dc){return [dc.short,dcSetting(dc,'ntlmLevel').value];}));
  else if(DCS.some(function(dc){return dcSetting(dc,'ntlmLevel');}))wc('ok','Domain controllers refuse NTLMv1','','',[],[]);
  CURS=MS.exch;
  var ex=arr(W.exchange);
  function exBuild(e){var m=/Build\s+(\d+)/i.exec(e.version||'');return m?+m[1]:null;}
  var exOld=ex.filter(function(e){var v=e.ver||'';if(v.indexOf('14.')===0||v.indexOf('15.0')===0||v.indexOf('15.1')===0)return true;var b=exBuild(e);return v.indexOf('15.2')===0&&b!=null&&b<1544;});
  var exRows=ex.map(function(e){var b=exBuild(e),old=exOld.indexOf(e)>=0;return [e.name,(e.ver==='15.2'&&b!=null&&b<1544)?'Exchange 2019 (before CU14)':e.label,e.version,old?tag('crit','not supported'):tag('ok','supported')];});
  if(exOld.length)wc('crit','Exchange version not supported with Windows Server 2025 DCs',plural(exOld.length,'server'),'Microsoft supports Windows Server 2025 domain controllers only with Exchange Server 2019 CU14 or later, or Exchange Server SE. Upgrade or migrate these servers before introducing Windows Server 2025 domain controllers.',['Server','Version','Build','Status'],exRows);
  else if(ex.length)wc('ok','Exchange version supported',plural(ex.length,'server'),'',['Server','Version','Build','Status'],exRows);
  CURS=null;
  if(W.schema!=null)wc('ok','Schema version',W.schema+(W.schema>=91?' (Windows Server 2025)':' - updated automatically when the first Windows Server 2025 DC is promoted'),'',[],[]);

  CURG='w25'; CURS=null;
})();

var FL=Object.keys(F).map(function(k){return F[k];}).sort(function(a,b){return (RANK[b.sev]-RANK[a.sev])||(b.who.length-a.who.length);});
var SECNAME={w25:'Server 2025 readiness',proto:'Protocols & hardening',dcs:'Domain controllers',events:'Security events',time:'Time sync',backup:'Backup & recovery'};
function findingHtml(f){var cls=SEVMAP[f.sev];
  return '<div class="finding '+cls+'">'+ic(f.sev==='info'?'info':'alert')+'<div style="flex:1;min-width:0"><b>'+esc(f.title)+'</b>'+esc(f.advice)+
    (f.who.length?'<div class="aff">'+esc(SECNAME[f.sec])+' &middot; '+esc(f.who.slice(0,12).join(', '))+(f.who.length>12?' +'+(f.who.length-12)+' more':'')+'</div>':'')+'</div></div>';}
function jump(sec){var el=qs('#sec-'+sec);if(el){el.scrollIntoView({behavior:'smooth',block:'start'});}}

/* ---------------- KPIs + filter banner ---------------- */
var nC=FL.filter(function(f){return f.sev==='crit';}),nW=FL.filter(function(f){return f.sev==='warn';}),nI=FL.filter(function(f){return f.sev==='info';});
var reach=DCS.filter(function(d){return d.regRead;}).length;
var KPIS=[
 {k:'dcs',icon:'server',cls:'k-blue',val:DCS.length,lbl:'Domain controllers'},
 {k:'read',icon:'checklist',cls:reach===DCS.length?'k-green':'k-amber',val:reach+' / '+DCS.length,lbl:'Settings read'},
 {k:'crit',icon:'octagon',cls:'k-red',val:nC.length,lbl:'Critical findings',list:nC},
 {k:'warn',icon:'alert',cls:'k-amber',val:nW.length,lbl:'Warnings',list:nW},
 {k:'info',icon:'bulb',cls:'k-blue',val:nI.length,lbl:'Recommended changes',list:nI}];
qs('#kpis').innerHTML=KPIS.map(function(k){return '<div class="kpi '+k.cls+(k.list?' clickable':'')+'" data-k="'+k.k+'"><div class="chip">'+ic(k.icon)+'</div><div class="body"><div class="val">'+k.val+'</div><div class="lbl">'+k.lbl+'</div>'+(k.list?'<div class="hint">Click to list</div>':'')+'</div></div>';}).join('');
var curK='';
Array.prototype.forEach.call(document.querySelectorAll('.kpi.clickable'),function(el){el.onclick=function(){var k=el.getAttribute('data-k');curK=(curK===k)?'':k;
  Array.prototype.forEach.call(document.querySelectorAll('.kpi'),function(x){x.classList.toggle('active',x.getAttribute('data-k')===curK);});
  if(!curK){qs('#fbanner').innerHTML='';return;}
  var K=KPIS.filter(function(x){return x.k===curK;})[0];
  qs('#fbanner').innerHTML='<div class="filter-banner"><div class="filter-banner-head">'+ic(K.icon)+K.lbl+' ('+K.list.length+')<button class="mini-btn" onclick="document.querySelector(\'.kpi.active\').click()">'+ic('x')+'Close</button></div><div class="fb-list">'+
    (K.list.length?K.list.map(function(f){return '<div class="fb-row" onclick="jump(\''+f.sec+'\')"><span class="dot '+SEVMAP[f.sev]+'"></span><span class="nm">'+esc(f.title)+'</span><span class="cx">'+esc(SECNAME[f.sec])+'</span><span class="cx">'+plural(f.who.length,'item')+'</span></div>';}).join(''):'<div class="muted-note">Nothing in this category.</div>')+'</div></div>';};});
(function(){var h='';if(arr(D.domNotes).length)h+='<div class="banner-note">'+ic('alert')+arr(D.domNotes).map(esc).join(' &middot; ')+'</div>';
  if(DCS.some(function(d){return !d.regRead;}))h+='<div class="banner-note">'+ic('alert')+'Settings could not be read on '+DCS.filter(function(d){return !d.regRead;}).map(function(d){return esc(dcWho(d));}).join(', ')+' (remote management not reachable). Those DCs are listed but only partially assessed.</div>';
  qs('#coverage').innerHTML=h;})();

/* ---------------- priority findings ---------------- */
var CHEV='<svg class="cv" viewBox="0 0 16 16" fill="currentColor"><path d="M4.646 1.646a.5.5 0 0 1 .708 0l6 6a.5.5 0 0 1 0 .708l-6 6a.5.5 0 0 1-.708-.708L10.293 8 4.646 2.354a.5.5 0 0 1 0-.708"/></svg>';
var WHONOUN={proto:'DC',dcs:'DC',events:'item',time:'DC',backup:'item'};
function frow(f){var n=f.who.length, noun=(f.title.indexOf('Accounts')===0?'account':(f.title.indexOf('Partition')===0||f.title.indexOf('No backup')===0||f.title.indexOf('Last backup')===0?'partition':WHONOUN[f.sec]));
  return '<div class="frow"><div class="fh" onclick="this.parentNode.classList.toggle(\'open\')"><span class="dot '+SEVMAP[f.sev]+'"></span><span class="t">'+esc(f.title)+'</span><span class="m">'+plural(n,noun)+'</span><span class="s">'+esc(SECNAME[f.sec])+'</span>'+CHEV+'</div>'+
    '<div class="fb">'+esc(f.advice)+'<div class="who">'+esc(f.who.slice(0,30).join(', '))+(n>30?' +'+(n-30)+' more':'')+'</div><a onclick="jump(\''+f.sec+'\')">Go to '+esc(SECNAME[f.sec])+' &rarr;</a></div></div>';}


/* ---------------- protocols: master-detail ---------------- */
var setSel=null;
function setStats(id){var list=DCS.map(function(dc){return {dc:dc,s:dcSetting(dc,id)};}).filter(function(x){return x.s;});var bad=list.filter(function(x){return x.s.sev!=='ok';});return {list:list,bad:bad,w:worstOf(bad.map(function(x){return x.s.sev;}))};}
function renderSetList(){var q=(qs('#setq').value||'').toLowerCase();
  var items=SET.map(function(m){var st=setStats(m[0]);var sev=st.list.length?(st.w||'ok'):'';
    return '<div class="item'+(setSel===m[0]?' sel':'')+(q&&m[1].toLowerCase().indexOf(q)<0?' hide':'')+'" onclick="selSet(\''+m[0]+'\')"><div class="item-ico sev-'+(SEVMAP[sev]||'ok')+'">'+ic(sev==='ok'?'check':(sev?'alert':'info'))+'</div><div class="item-body"><div class="item-name">'+esc(m[1])+'</div><div class="item-sub">'+(st.list.length?(st.bad.length?st.bad.length+' of '+plural(st.list.length,'DC')+' not as recommended':'All '+plural(st.list.length,'DC')+' as recommended'):'Not read')+'</div></div></div>';});
  var desSev=DES.length?'crit':'ok';
  items.push('<div class="item'+(setSel==='des'?' sel':'')+(q&&'des-only accounts'.indexOf(q)<0?' hide':'')+'" onclick="selSet(\'des\')"><div class="item-ico sev-'+SEVMAP[desSev]+'">'+ic(DES.length?'alert':'check')+'</div><div class="item-body"><div class="item-name">DES-only accounts</div><div class="item-sub">'+plural(DES.length,'account')+'</div></div></div>');
  qs('#setlist').innerHTML=items.join('');}
function selSet(id){setSel=id;renderSetList();var h;
  if(id==='des'){h='<div class="detail-head"><div class="detail-title"><span class="dot '+(DES.length?'high':'ok')+'"></span>DES-only accounts</div><div class="detail-sub">Accounts flagged "Use only Kerberos DES encryption types"</div></div><div class="detail-body">'+
    (DES.length?'<div class="dsec"><div class="dsec-t">Accounts</div><div class="tbl-wrap"><table class="tbl"><tr><th>Name</th><th>Account</th>'+(SHOWDOM?'<th>Domain</th>':'')+'</tr>'+DES.map(function(a){return '<tr><td>'+esc(a.name)+'</td><td class="mono">'+esc(a.sam)+'</td>'+(SHOWDOM?'<td>'+esc(a.domain||'')+'</td>':'')+'</tr>';}).join('')+'</table></div></div><div class="dsec"><div class="dsec-t">Recommendation</div><div class="findings">'+findingHtml({sec:'proto',sev:'crit',title:'Remove DES',advice:'Clear "Use only Kerberos DES encryption types" on these accounts and reset their passwords so AES keys are created.',who:[]})+'</div></div>':'<div class="no-findings">'+ic('check')+'No accounts are restricted to DES.</div>')+'</div>';
    qs('#setdetail').innerHTML=h;return;}
  var m=SET.filter(function(x){return x[0]===id;})[0], st=setStats(id);
  var advs={};st.bad.forEach(function(x){if(x.s.advice)advs[x.s.advice]=x.s;});
  h='<div class="detail-head"><div class="detail-title"><span class="dot '+(SEVMAP[st.w]||'ok')+'"></span>'+esc(m[1])+'</div><div class="detail-sub">'+esc(m[2])+'</div></div><div class="detail-body">'+
    '<div class="dsec"><div class="kv-grid"><div class="kv"><div class="k">Recommended</div><div class="v">'+esc(m[3])+'</div></div><div class="kv"><div class="k">Domain controllers</div><div class="v '+(st.bad.length?'warn':'good')+'">'+(st.list.length?(st.bad.length?st.bad.length+' of '+st.list.length+' not as recommended':'All as recommended'):'Not read')+'</div></div></div></div>'+
    (st.list.length?'<div class="dsec"><div class="dsec-t">Per domain controller</div><div class="tbl-wrap"><table class="tbl"><tr><th>DC</th><th>Value</th><th>Status</th></tr>'+st.list.map(function(x){return '<tr><td><b>'+esc(x.dc.short)+'</b>'+domSub(x.dc)+'</td><td class="mono">'+esc(x.s.value)+'</td><td>'+tag(x.s.sev,x.s.sev==='ok'?'OK':SEVWORD[x.s.sev])+'</td></tr>';}).join('')+'</table></div></div>':'')+
    (Object.keys(advs).length?'<div class="dsec"><div class="dsec-t">Recommendation</div><div class="findings">'+Object.keys(advs).map(function(a){var s=advs[a];return findingHtml({sec:'proto',sev:s.sev,title:s.title,advice:a,who:[]});}).join('')+'</div></div>':'')+'</div>';
  qs('#setdetail').innerHTML=h;}
qs('#setq').addEventListener('input',renderSetList);
renderSetList();(function(){var first=SET.map(function(m){return {id:m[0],st:setStats(m[0])};}).sort(function(a,b){return RANK[b.st.w||'ok']-RANK[a.st.w||'ok'];})[0];selSet(first?first.id:'ldapSign');})();

/* ---------------- event descriptions (click an event ID or a row) ---------------- */
var MSEV='https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-';
var EVD={
 4740:['A user account was locked out','Logged on the domain controller that processed the lockout, usually the PDC emulator. "Caller Computer Name" is the computer the bad password attempts came from.','Audit User Account Management (success)',MSEV+'4740'],
 4625:['An account failed to log on','Logged by the computer where the logon was attempted, here the domain controllers. Gives the account, the reason (status code), the logon type and the source address or workstation.','Audit Logon (failure)',MSEV+'4625'],
 4771:['Kerberos pre-authentication failed','Logged on the domain controller when a Kerberos logon fails before a ticket is issued, most often a wrong password (failure code 0x18). Gives the account and the client address.','Audit Kerberos Authentication Service (failure)',MSEV+'4771'],
 4728:['A member was added to a security-enabled global group','Logged on the domain controller that made the change, with the member, the group and who made the change.','Audit Security Group Management (success)',MSEV+'4728'],
 4732:['A member was added to a security-enabled local group','Logged on the domain controller that made the change, with the member, the group and who made the change. Built-in groups such as Administrators are domain local groups.','Audit Security Group Management (success)',MSEV+'4732'],
 4756:['A member was added to a security-enabled universal group','Logged on the domain controller that made the change, with the member, the group and who made the change. Enterprise Admins and Schema Admins are universal groups.','Audit Security Group Management (success)',MSEV+'4756'],
 4729:['A member was removed from a security-enabled global group','Logged on the domain controller that made the change, with the member, the group and who made the change.','Audit Security Group Management (success)',MSEV+'4729'],
 4733:['A member was removed from a security-enabled local group','Logged on the domain controller that made the change, with the member, the group and who made the change.','Audit Security Group Management (success)',MSEV+'4733'],
 4757:['A member was removed from a security-enabled universal group','Logged on the domain controller that made the change, with the member, the group and who made the change.','Audit Security Group Management (success)',MSEV+'4757'],
 1102:['The audit log was cleared','Logged whenever the Security log is cleared, with the account that cleared it. Always written, whatever the audit policy.','Always logged',MSEV+'1102'],
 2887:['Unsigned and clear-text LDAP binds in the last 24 hours','Logged once a day by a domain controller that does not require LDAP signing, with the number of unsigned SASL binds and simple binds without SSL/TLS it accepted. No client details.','Logged by default (Directory Service log)','https://support.microsoft.com/help/4520412'],
 2889:['An LDAP client made an unsigned or clear-text bind','One event per bind, in the Directory Service log, with the client IP address and port, the account, and the bind type (0 = unsigned SASL, 1 = simple bind without SSL/TLS).','LDAP client logging (16 LDAP Interface Events) at 2','https://support.microsoft.com/help/4520412'],
 3039:['An LDAPS client did not provide a channel binding token','Logged in the Directory Service log when a client binds over LDAPS without channel binding, so it would be rejected once LDAP channel binding is set to Always. Gives the client IP address and the account.','LDAP client logging (16 LDAP Interface Events) at 2','https://support.microsoft.com/help/4520412'],
 4624:['An account was successfully logged on','Logged by the computer being logged on to. "Authentication Package" shows NTLM or Kerberos, and "Package Name (NTLM only)" shows NTLM V1 or NTLM V2. Gives the account, the workstation name and the source address.','Audit Logon (success)',MSEV+'4624'],
 4768:['A Kerberos authentication ticket (TGT) was requested','Logged on the domain controller at each Kerberos logon. "Ticket Encryption Type" 0x17 or 0x18 means RC4, 0x1 or 0x3 means DES, 0x11 or 0x12 means AES. Gives the account and the client address.','Audit Kerberos Authentication Service (success)',MSEV+'4768'],
 4769:['A Kerberos service ticket was requested','Logged on the domain controller each time a client asks for a ticket to a service. The ticket encryption type shows whether RC4 or DES was used for that service. Gives the account, the service and the client address.','Audit Kerberos Service Ticket Operations (success)',MSEV+'4769'],
 8004:['NTLM authentication processed by the domain controller','Logged in the Microsoft-Windows-NTLM/Operational log of the domain controller for each NTLM authentication it validates, with the account, the client workstation and the server that passed the request on (secure channel name).','Network security: Restrict NTLM: Audit NTLM authentication in this domain','https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain'],
 4776:['The domain controller attempted to validate the credentials for an account','Logged on the domain controller for each NTLM credential validation, with the account and the client workstation name. It does not show the IP address or the NTLM version.','Audit Credential Validation (success)',MSEV+'4776'],
 3000:['SMB1 access','Logged in the Microsoft-Windows-SMBServer/Audit log when a client connects with SMBv1, with the client address.','SMBv1 access auditing (AuditSmb1Access)','https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3']};
var EVIDS={lock:[4740],fsrc:[4625],facc:[4625],kerb:[4771],priv:[4728,4732,4756,4729,4733,4757],clear:[1102],ldap:[2887,2889],cbt:[3039],ntlm1:[4624],weak:[4768,4769],ntlm:[8004,4776],smb1:[3000]};
function evDescHtml(id,open){var d=EVD[id];if(!d)return '';var sm=(EV.samples||{})[id];
  return '<div class="evdesc"><div class="evdt"><span class="evid">'+id+'</span>'+esc(d[0])+'</div><div class="evdd"><span class="evlbl">In this report</span>'+esc(d[1])+'</div><div class="evdm"><span><b>Logged when:</b> '+esc(d[2])+'</span><a href="'+d[3]+'" target="_blank" rel="noopener">Microsoft documentation &rarr;</a></div>'+
    (sm&&sm.msg?'<details class="evraw"'+(open?' open':'')+'><summary>Event text, as Windows wrote it on '+esc(sm.dc)+(sm.time?' ('+esc(sm.time)+')':'')+'</summary><pre>'+esc(sm.msg)+'</pre></details>'
      :'<div class="evnoraw">No example of this event\'s text in this report: none was found in the period, or its text could not be read.</div>')+'</div>';}
function evAbout(id,btn){var box=qs('#evdesc'),on=btn.classList.contains('on');
  Array.prototype.forEach.call(document.querySelectorAll('.evchip'),function(b){b.classList.remove('on');});
  if(on){box.innerHTML='';return;}btn.classList.add('on');box.innerHTML=evDescHtml(id,true);}
function evRow(tr,ri){var nx=tr.nextElementSibling;if(nx&&nx.classList.contains('evdet')){nx.parentNode.removeChild(nx);tr.classList.remove('open');return;}
  var c=EVC[EVCUR],x=c.rows[ri],v=c.csv(x),n=c.cols.length;tr.classList.add('open');
  var kv=c.cols.map(function(h,i){var val=''+(v[i]==null?'':v[i]);var parts=val.split(' | ');
    return '<div class="evkv"><div class="k">'+h+'</div><div class="v">'+(parts.length>1?'<ul>'+parts.map(function(p){return '<li>'+esc(p)+'</li>';}).join('')+'</ul>':esc(val||'-'))+'</div></div>';}).join('');
  var d=document.createElement('tr');d.className='evdet';
  d.innerHTML='<td colspan="'+n+'"><div class="evkvs">'+kv+'</div>'+(x.id?[x.id]:arr(EVIDS[c.k])).map(evDescHtml).join('')+'</td>';
  tr.parentNode.insertBefore(d,tr.nextSibling);}

/* ---------------- security events: one table, filtered by category ---------------- */
function panel(icon,title,sub,body,csv){return '<div class="panel-card"><div class="panel-head">'+ic(icon)+title+(sub?' <span class="sub">'+sub+'</span>':'')+(csv?'<button class="mini-btn" onclick="'+csv+'">'+ic('download')+'CSV</button>':'')+'</div>'+body+'</div>';}
function othTxt(x){return arr(x.others).slice(0,4).map(function(o){return esc(o.name)+' <span style="color:var(--muted)">('+o.count+')</span>';}).join(', ')+(arr(x.others).length>4?' &hellip;':'');}
function othCsv(x){return arr(x.others).map(function(o){return o.name+' ('+o.count+')';}).join(' | ');}
var EVC=[];
(function(){
  if(!D.events){qs('#events').innerHTML='<div class="muted-note">Event data is missing from this report. Re-run the latest version of the script.</div>';return;}
  if(!EV.collected){qs('#events').innerHTML='<div class="muted-note">Security events were not collected'+(EV.skipped?' (the script was run with -SkipEvents)':'')+'.</div>';return;}
  qs('#evdays').textContent='last '+plural(EV.days,'day');
  var ld=arr(EV.ldapDc).filter(function(x){return x.simple>0||x.unsignedSasl>0;});
  EVC=[
   {k:'lock',label:'Account lockouts',sub:'Event 4740 &middot; accounts locked out, with the computers the bad passwords came from',rows:arr(EV.lockouts),
    cols:['Account','Lockouts','Caller computers','Domain controllers','Last'],
    cell:function(x){return ['<b>'+esc(x.name||'(empty)')+'</b>'+(x.count>=5?' '+tag('warn','repeated'):''),x.count,othTxt(x),esc(arr(x.dcs).join(', ')),esc(x.last)];},
    csv:function(x){return [x.name,x.count,othCsv(x),arr(x.dcs).join(' | '),x.last];},num:[1],sev:function(x){return x.count>=5?'warn':'';}},
   {k:'fsrc',label:'Failed logons by source',sub:'Event 4625 &middot; a source trying 10 or more accounts is flagged as possible password spraying',rows:arr(EV.failSources),
    cols:['Source','Attempts','Accounts','Accounts tried','Last'],
    cell:function(x){return ['<b>'+esc(x.name||'(empty)')+'</b>'+(x.distinct>=10?' '+tag('warn','possible spray'):''),x.count,x.distinct,othTxt(x),esc(x.last)];},
    csv:function(x){return [x.name,x.count,x.distinct,othCsv(x),x.last];},num:[1,2],sev:function(x){return x.distinct>=10?'warn':'';}},
   {k:'facc',label:'Failed logons by account',sub:'Event 4625 &middot; '+plural(EV.failTotal||0,'failed logon')+' in total',rows:arr(EV.failAccounts),
    cols:['Account','Attempts','Sources','Last'],cell:function(x){return ['<b>'+esc(x.name||'(empty)')+'</b>',x.count,othTxt(x),esc(x.last)];},
    csv:function(x){return [x.name,x.count,othCsv(x),x.last];},num:[1],sev:function(){return '';}},
   {k:'kerb',label:'Kerberos pre-auth failures',sub:'Event 4771 &middot; mostly wrong passwords over Kerberos, '+plural(EV.kerbTotal||0,'event')+' in total',rows:arr(EV.kerbAccounts),
    cols:['Account','Failures','Source addresses','Last'],cell:function(x){return ['<b>'+esc(x.name||'(empty)')+'</b>',x.count,othTxt(x),esc(x.last)];},
    csv:function(x){return [x.name,x.count,othCsv(x),x.last];},num:[1],sev:function(){return '';}},
   {k:'priv',label:'Privileged group changes',sub:'Events 4728 / 4732 / 4756 and removals &middot; confirm every change was authorised',rows:arr(EV.privChanges),
    cols:['When','Group','Member','Action','Changed by','DC'],cell:function(c){return [esc(c.time),'<b>'+esc(c.group)+'</b>',esc(c.member),tag(c.action==='added'?'warn':'info',c.action),esc(c.by),esc(c.dc)];},
    csv:function(c){return [c.time,c.group,c.member,c.action,c.by,c.dc];},num:[],sev:function(){return 'warn';}},
   {k:'clear',label:'Audit log cleared',sub:'Event 1102 &middot; the security log was cleared on a domain controller',rows:arr(EV.cleared),
    cols:['When','DC','Cleared by'],cell:function(c){return [esc(c.time),'<b>'+esc(c.dc)+'</b>',esc(c.by)];},
    csv:function(c){return [c.time,c.dc,c.by];},num:[],sev:function(){return 'crit';}},
   {k:'ldap',label:'Unsigned / clear-text LDAP',sub:'Events 2887 / 2889 &middot; clients that will break when LDAP signing is required',rows:arr(EV.ldapClients),
    note:ld.length?('Last 24-hour summary: '+ld.map(function(x){return '<b>'+esc(x.dc)+'</b> '+x.simple+' simple / '+x.unsignedSasl+' unsigned SASL binds';}).join(' &middot; ')+(logOff().length?' &mdash; per-client events (2889) are not logged on '+esc(logOff().join(', '))+': LDAP client logging is off there (see Protocols).':'')):'',
    extra:ld.length,
    cols:['Client (account)','Binds','Bind type','Domain controllers','Last'],cell:function(x){return ['<b>'+esc(x.name)+'</b>',x.count,othTxt(x),esc(arr(x.dcs).join(', ')),esc(x.last)];},
    csv:function(x){return [x.name,x.count,othCsv(x),arr(x.dcs).join(' | '),x.last];},num:[1],sev:function(){return 'warn';}},
   {k:'cbt',label:'LDAP channel binding',sub:'Event 3039 &middot; LDAPS clients that will fail when channel binding is set to Always',rows:arr(EV.cbtClients),gap:OLDGAP.cbt(),
    cols:['Client','Binds','Accounts','Domain controllers','Last'],cell:function(x){return ['<b>'+esc(x.name)+'</b>',x.count,othTxt(x),esc(arr(x.dcs).join(', ')),esc(x.last)];},
    csv:function(x){return [x.name,x.count,othCsv(x),arr(x.dcs).join(' | '),x.last];},num:[1],sev:function(){return 'warn';}},
   {k:'ntlm1',label:'NTLMv1 logons',sub:'Event 4624 (NTLM V1) &middot; removed in Windows Server 2025',rows:arr(EV.ntlm1Clients),gap:OLDGAP.ntlm1(),
    pre:'Event 4624 is written by the server being logged on to: these are NTLMv1 logons to the domain controllers. NTLMv1 logons to other servers are in their own Security logs.',
    cols:['Source','Logons','Accounts','Domain controllers','Last'],cell:function(x){return ['<b>'+esc(x.name)+'</b>',x.count,othTxt(x),esc(arr(x.dcs).join(', ')),esc(x.last)];},
    csv:function(x){return [x.name,x.count,othCsv(x),arr(x.dcs).join(' | '),x.last];},num:[1],sev:function(){return 'warn';}},
   {k:'weak',label:'RC4 / DES Kerberos tickets',sub:'Events 4768 / 4769 &middot; clients and services that will break when only AES is allowed',rows:arr(EV.weakClients),gap:OLDGAP.weak(),
    cols:['Client','Tickets','Encryption: account &gt; service','Domain controllers','Last'],cell:function(x){return ['<b>'+esc(x.name)+'</b>',x.count,othTxt(x),esc(arr(x.dcs).join(', ')),esc(x.last)];},
    csv:function(x){return [x.name,x.count,othCsv(x),arr(x.dcs).join(' | '),x.last];},num:[1],sev:function(){return 'warn';}},
   {k:'ntlm',label:'NTLM authentications',sub:'Events 8004 / 4776 &middot; computers still using NTLM (workstation names, no IP)',rows:arr(EV.ntlmClients),gap:OLDGAP.ntlm(),
    cols:['Workstation','Authentications','Accounts (&gt; server)','Domain controllers','Last'],cell:function(x){return ['<b>'+esc(x.name)+'</b>',x.count,othTxt(x),esc(arr(x.dcs).join(', ')),esc(x.last)];},
    csv:function(x){return [x.name,x.count,othCsv(x),arr(x.dcs).join(' | '),x.last];},num:[1],sev:function(){return '';}},
   {k:'smb1',label:'SMBv1 clients',sub:'Event 3000 &middot; clients connecting to the domain controllers with SMBv1',rows:arr(EV.smb1Clients),gap:OLDGAP.smb1(),
    cols:['Client','Connections','Domain controllers','Last'],cell:function(x){return ['<b>'+esc(x.name)+'</b>',x.count,esc(arr(x.dcs).join(', ')),esc(x.last)];},
    csv:function(x){return [x.name,x.count,arr(x.dcs).join(' | '),x.last];},num:[1],sev:function(){return 'warn';}}];
  EVC.forEach(function(c){if(c.gap&&c.gap.length&&!c.extra)c.extra=c.gap.length;});
  var h='';
  if(arr(EV.failed).length)h+='<div class="banner-note">'+ic('alert')+'Not read on: '+arr(EV.failed).map(function(f){return esc(f.dc)+' ('+esc(f.reason)+')';}).join(', ')+'</div>';
  h+='<div class="evcats">'+EVC.map(function(c,i){var n=c.rows.length, w=worstOf(c.rows.map(c.sev));
     return '<button class="evcat'+(n||c.extra?'':' zero')+'" data-i="'+i+'">'+(w&&n?'<span class="w '+SEVMAP[w]+'"></span>':'')+esc(c.label)+'<span class="c">'+n+'</span></button>';}).join('')+'</div>';
  h+='<div class="panel-card" style="margin-bottom:0"><div class="panel-head evhead" id="evhead"></div><div id="evbody"></div></div>';
  qs('#events').innerHTML=h;
  Array.prototype.forEach.call(document.querySelectorAll('.evcat'),function(b){b.onclick=function(){showEv(+b.getAttribute('data-i'));};});
  var first=0;for(var i=0;i<EVC.length;i++){if(EVC[i].rows.length){first=i;break;}}
  showEv(first);
})();
var EVCUR=0;
function showEv(i){EVCUR=i;var c=EVC[i];
  Array.prototype.forEach.call(document.querySelectorAll('.evcat'),function(b){b.classList.toggle('on',+b.getAttribute('data-i')===i);});
  qs('#evhead').innerHTML=ic('journal')+'<span>'+esc(c.label)+'</span><span class="sub">'+c.sub+'</span>'+(c.rows.length?'<button class="mini-btn" onclick="csvEv()">'+ic('download')+'CSV</button>':'');
  var body='<div class="evabout"><span>About the events:</span>'+arr(EVIDS[c.k]).map(function(id){return '<button class="evchip" onclick="evAbout('+id+',this)" title="'+esc(EVD[id]?EVD[id][0]:'')+'">'+id+'</button>';}).join('')+'<span class="evhint">Click a row for its details</span></div><div id="evdesc"></div>'+(c.note?'<div class="evnote">'+c.note+'</div>':'')+(c.pre?'<div class="evnote">'+esc(c.pre)+'</div>':'')+(c.gap&&c.gap.length?gapHtml(c.gap):'');
  var blind=c.gap&&c.gap.some(function(g){return !/^Disabled on /.test(g[0]);});
  if(!c.rows.length){body+='<div class="panel-body"><div class="no-findings">'+ic(blind?'info':'check')+(blind?'Nothing recorded in this period on the domain controllers that log it.':'Nothing recorded in this period.')+'</div></div>';}
  else{var LIM=10;
    body+='<div class="tbl-wrap"><table class="tbl"><tr>'+c.cols.map(function(h,ci){return '<th'+(c.num.indexOf(ci)>=0?' style="text-align:right"':'')+'>'+h+'</th>';}).join('')+'</tr>'+
      c.rows.map(function(x,ri){var cells=c.cell(x);return '<tr class="evr'+(ri>=LIM?' rowhide evx':'')+'" onclick="evRow(this,'+ri+')">'+cells.map(function(v,ci){return '<td'+(c.num.indexOf(ci)>=0?' class="num"':'')+'>'+v+'</td>';}).join('')+'</tr>';}).join('')+'</table></div>'+
      (c.rows.length>LIM?'<button class="tmore" onclick="Array.prototype.forEach.call(document.querySelectorAll(\'.evx\'),function(e){e.classList.remove(\'rowhide\');});this.style.display=\'none\';">Show '+(c.rows.length-LIM)+' more</button>':'');}
  qs('#evbody').innerHTML=body;}
function csvEv(){var c=EVC[EVCUR];var rows=[c.cols];c.rows.forEach(function(x){rows.push(c.csv(x));});dl('events_'+c.k+'.csv',rows);}

/* ---------------- readiness boards (Windows Server 2025 + Kerberos RC4) ---------------- */
var BOARDS={
 w25:{cats:[['platform','Platform','server','Functional levels, domain controllers, SYSVOL and schema'],['removed','Removed in Windows Server 2025','x','DES and NTLMv1 are removed in Windows Server 2025'],['apps','Applications','people','Exchange Server support for 2025 domain controllers']],
   catOf:function(c){var x=c.title.toLowerCase();if(/des\b|ntlmv1/.test(x))return 'removed';if(/exchange/.test(x))return 'apps';return 'platform';},
   hero:function(nC,nW){return nC?['Not ready yet','Resolve the '+plural(nC,'blocker')+' before promoting the first Windows Server 2025 domain controller.']:(nW?['Ready, with risks to address','Nothing blocks the migration, but address the risks below first.']:['Ready for Windows Server 2025','No blockers or risks found.']);},
   path:['Resolve blockers','Add new 2025 DCs','Move FSMO roles','Retire older DCs'],
   note:'Only requirements documented by Microsoft are checked here. Each check links to its Microsoft source.'}
};
var BSEL={};
function renderBoard(key){
  var cfg=BOARDS[key],el=qs('#'+key);if(!el)return;
  if(!D.w25){el.innerHTML='<div class="muted-note">These checks were not collected by this version of the script.</div>';return;}
  var order={crit:0,warn:1,info:2,ok:3};
  var list=CHK.filter(function(c){return c.grp===key;});
  CHK.forEach(function(c,i){c.i=i;});list.forEach(function(c){c.cat=cfg.catOf(c);});
  var nC=list.filter(function(c){return c.sev==='crit';}).length,nW=list.filter(function(c){return c.sev==='warn';}).length,nI=list.filter(function(c){return c.sev==='info';}).length,nOk=list.filter(function(c){return c.sev==='ok';}).length,N=list.length;
  var cnt=qs('#'+key+'cnt');if(cnt)cnt.textContent=nOk+' / '+N+' passed';
  var vs=nC?'high':(nW?'medium':'ok'),hv=cfg.hero(nC,nW),pct=N?Math.round(nOk*100/N):0;
  var h='<div class="w25hero '+vs+'"><div class="w25ico">'+ic(nC?'x':(nW?'alert':'check'))+'</div><div class="w25txt"><div class="w25t">'+hv[0]+'</div><div class="w25s">'+hv[1]+'</div>'+
    '<div class="w25bar"><div style="width:'+pct+'%"></div></div><div class="w25pills">'+
    '<span><span class="dot high"></span>'+plural(nC,key==='w25'?'blocker':'critical item')+'</span><span><span class="dot medium"></span>'+plural(nW,'risk')+'</span><span><span class="dot low"></span>'+nI+' to verify</span><span><span class="dot ok"></span>'+nOk+' passed</span></div>'+
    '<div class="w25note">'+ic('info')+esc(cfg.note)+'</div></div>'+
    '<div class="w25path"><b>Recommended path</b><ol>'+cfg.path.map(function(p){return '<li>'+esc(p)+'</li>';}).join('')+'</ol></div></div>';
  h+='<div class="w25cols" style="grid-template-columns:repeat('+cfg.cats.length+',1fr)">'+cfg.cats.map(function(cat){var cs=list.filter(function(c){return c.cat===cat[0];}).sort(function(a,b){return order[a.sev]-order[b.sev];});
    var cw=worstOf(cs.filter(function(c){return c.sev!=='ok';}).map(function(c){return c.sev;}));var cOk=cs.filter(function(c){return c.sev==='ok';}).length;
    return '<div class="w25col"><div class="w25ch"><span class="w25ci '+(SEVMAP[cw]||'ok')+'">'+ic(cat[2])+'</span><div><b>'+cat[1]+'</b><span>'+cOk+' of '+cs.length+' passed</span></div></div>'+
      (cs.length?cs.map(function(c){return '<div class="w25it" data-b="'+key+'" data-i="'+c.i+'"><span class="w25st '+SEVMAP[c.sev]+'">'+ic(c.sev==='ok'?'check':(c.sev==='crit'?'x':(c.sev==='warn'?'alert':'info')))+'</span><div class="w25b"><div class="w25n">'+esc(c.title)+'</div>'+(c.result?'<div class="w25r">'+esc(c.result)+'</div>':'')+'</div></div>';}).join(''):'<div class="w25r" style="padding:12px 16px">No checks in this category.</div>')+'</div>';}).join('')+'</div>';
  h+='<div class="w25det" id="'+key+'det"></div>';
  if(key==='w25'&&arr(W.notes).length)h+='<div class="banner-note" style="margin-top:14px;margin-bottom:0">'+ic('alert')+arr(W.notes).map(esc).join(' &middot; ')+'</div>';
  el.innerHTML=h;
  Array.prototype.forEach.call(el.querySelectorAll('.w25it'),function(it){it.onclick=function(){boardShow(key,+it.getAttribute('data-i'),true);};});
  var first=list.slice().sort(function(a,b){return order[a.sev]-order[b.sev];})[0];if(first&&first.sev!=='ok')boardShow(key,first.i,false);
}
function boardShow(key,i,scroll){
  var c=CHK[i],el=qs('#'+key);if(!c||!el)return;var det=qs('#'+key+'det');
  if(BSEL[key]===i){BSEL[key]=-1;det.innerHTML='';Array.prototype.forEach.call(el.querySelectorAll('.w25it'),function(e){e.classList.remove('sel');});return;}
  BSEL[key]=i;
  Array.prototype.forEach.call(el.querySelectorAll('.w25it'),function(e){e.classList.toggle('sel',+e.getAttribute('data-i')===i);});
  var st=c.sev==='ok'?tag('ok','Pass'):(c.sev==='crit'?tag('crit',key==='w25'?'Blocker':'Critical'):(c.sev==='warn'?tag('warn','Risk'):tag('info','Verify')));
  det.innerHTML='<div class="w25dh">'+st+'<b>'+esc(c.title)+'</b><span>'+esc(c.result)+'</span><button class="mini-btn" onclick="boardShow(\''+key+'\','+i+')">'+ic('x')+'Close</button></div>'+
    '<div class="w25db">'+(c.advice?'<div class="finding '+(c.sev==='crit'?'high':(c.sev==='warn'?'medium':'low'))+'">'+ic(c.sev==='info'?'info':'alert')+'<div><b>What to do</b>'+esc(c.advice)+'</div></div>':'<div class="no-findings">'+ic('check')+'Nothing to do for this check.</div>')+
    (c.rows.length?'<div class="tbl-wrap" style="margin-top:14px;max-height:320px;border:1px solid var(--border);border-radius:var(--radius-sm)"><table class="tbl"><tr>'+c.cols.map(function(x){return '<th>'+x+'</th>';}).join('')+'</tr>'+c.rows.map(function(r){return '<tr>'+r.map(function(v,j){return '<td>'+(j===r.length-1&&(''+v).indexOf('<span')===0?v:esc(v))+'</td>';}).join('')+'</tr>';}).join('')+'</table></div>'+(c.note?'<div class="lnote" style="font-size:12px;color:var(--muted);margin-top:6px">'+esc(c.note)+'</div>':''):'')+
    (c.src?'<a class="srclink" href="'+c.src.u+'" target="_blank" rel="noopener">'+ic('info')+'Microsoft source: '+esc(c.src.t)+' &rarr;</a>':'')+'</div>';
  if(scroll&&det.getBoundingClientRect().top>window.innerHeight-120)det.scrollIntoView({behavior:'smooth',block:'nearest'});
}
renderBoard('w25');

/* ---------------- time sync ---------------- */
(function(){
  var anyVm=DCS.some(function(dc){return dc.platform==='VMware';});
  var rows=DCS.map(function(dc){var t=dc.time||{},f=arr(t.findings).slice().sort(function(a,b){return RANK[b.sev]-RANK[a.sev];});
    var read=!!(t.type||t.source);
    var st=!read?tag('','not read'):(f.length?f.map(function(x){return '<div class="tiss"><span class="dot '+SEVMAP[x.sev]+'"></span>'+esc(x.title)+'</div>';}).join(''):tag('ok','OK'));
    var typ=esc(t.type||'-')+(t.cfgBy==='Group Policy'?' '+tag('info','GPO'):'');
    var main='<tr class="trow" onclick="var d=this.nextElementSibling;var o=d.style.display===\'none\';d.style.display=o?\'\':\'none\';this.classList.toggle(\'open\',o);"><td style="white-space:nowrap"><b>'+esc(dc.short)+'</b>'+(dc.isPdc?' '+tag('info','PDC'):'')+domSub(dc)+'</td><td>'+esc(dc.platform||'Unknown')+'</td><td>'+typ+'</td><td class="mono">'+esc(t.source||t.error||'-')+'</td><td style="white-space:nowrap">'+esc(t.lastSync||'-')+'</td><td class="num">'+(t.offsetPdc==null||dc.isPdc?'':offTxt(t.offsetPdc))+'</td><td>'+st+'</td><td style="width:22px">'+CHEV+'</td></tr>';
    var kv='<div class="kv-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:'+(f.length?'12px':'0')+'">'+
      '<div class="kv"><div class="k">NTP server</div><div class="v mono" style="font-size:12px">'+esc(t.ntpServer||'-')+'</div></div>'+
      '<div class="kv"><div class="k">Configured by</div><div class="v">'+esc(t.cfgBy||'-')+'</div></div>'+
      '<div class="kv"><div class="k">Stratum</div><div class="v">'+esc(t.stratum||'-')+'</div></div>'+
      '<div class="kv"><div class="k">Hardware / VM</div><div class="v" style="font-size:12.5px">'+esc(dc.model||dc.platform||'-')+'</div></div></div>';
    var det='<tr class="tdet" style="display:none"><td colspan="8">'+kv+(f.length?'<div class="findings">'+f.map(function(x){return findingHtml({sec:'time',sev:x.sev,title:x.title,advice:x.advice,who:[]});}).join('')+'</div>':'')+'</td></tr>';
    return main+det;}).join('');
  var fl=FL.filter(function(f){return f.sec==='time';});
  qs('#time').innerHTML=panel('clock','Domain controllers',(MULTI?'The PDC emulator of the forest root domain should sync from reliable external NTP; every other DC, including the PDC of each child domain, follows the domain hierarchy. Offsets are measured against the PDC of each DC&rsquo;s own domain.':'The PDC emulator should sync from reliable external NTP; every other DC follows the domain hierarchy.')+' Click a DC for details.','<div class="tbl-wrap"><table class="tbl"><tr><th>DC</th><th>Platform</th><th>Type</th><th>Current source</th><th>Last sync</th><th>Offset vs PDC</th><th>Issues</th><th></th></tr>'+rows+'</table></div>')+
    (anyVm?'<div class="banner-note" style="margin-bottom:12px">'+ic('info')+'VMware domain controllers: make sure VMware Tools periodic time synchronization is turned off, so the host does not fight the Windows Time service.</div>':'')+
    (fl.length?'':'<div class="no-findings">'+ic('check')+'Time hierarchy looks correct.</div>');
})();

/* ---------------- backup ---------------- */
(function(){
  var sv=BK.sysvol||{};
  var kv='<div class="kv-grid" style="margin-bottom:20px">'+
    '<div class="kv"><div class="k">AD Recycle Bin</div><div class="v '+(rbSev==='ok'?'good':(rbSev==='warn'?'warn':'mut'))+'">'+(BK.recycleBin===false?'Unknown':(BK.recycleBinEnabled?'Enabled':'Not enabled'))+'</div></div>'+
    '<div class="kv"><div class="k">Tombstone lifetime</div><div class="v '+(TSL<180?'warn':'')+'">'+TSL+' days</div></div>'+
    '<div class="kv"><div class="k">SYSVOL replication</div><div class="v '+(sv.sev==='ok'?'good':(sv.sev==='crit'?'bad':'warn'))+'">'+esc(sv.mode||'Unknown')+'</div></div>'+
    '<div class="kv"><div class="k">SYSVOL state</div><div class="v">'+esc(sv.state||'-')+'</div></div></div>';
  var parts=arr(BK.partitions);
  var tb=panel('archive','Last backup per partition','Recommended: at least daily, and always well within the '+TSL+'-day tombstone lifetime',parts.length?'<div class="tbl-wrap"><table class="tbl"><tr><th>Partition</th><th>Last backup</th><th>Age</th><th>Status</th></tr>'+parts.map(function(p){var s=partSev(p);
    return '<tr><td><b>'+esc(p.name)+'</b><div class="mono" style="color:var(--muted);font-size:11px">'+esc(p.dn)+'</div></td><td>'+(p.last?esc(p.last):(p.error?'<span style="color:var(--muted)">could not be read</span>':'Never'))+'</td><td class="num">'+(p.days==null?'-':p.days+' d')+'</td><td>'+tag(s,s==='ok'?'OK':(s==='info'?'Unknown':SEVWORD[s]))+'</td></tr>';}).join('')+'</table></div>':'<div class="panel-body"><div class="muted-note">Partition backup times could not be read.</div></div>');
  var fl=FL.filter(function(f){return f.sec==='backup';});
  qs('#backup').innerHTML=kv+tb+(fl.length?'':'<div class="no-findings">'+ic('check')+'Recovery readiness looks good.</div>');
})();

function csvSettings(){var rows=[['DC','Site','Role'].concat(SET.map(function(x){return x[1];}))];DCS.forEach(function(d){rows.push([d.name,d.site,roleTxt(d)].concat(SET.map(function(x){var s=dcSetting(d,x[0]);return s?s.value:'';})));});dl('auth_settings.csv',rows);}
function csvAgg(key){var rows=[['Name','Count','Distinct','Details','DCs','Last']];arr(EV[key]).forEach(function(x){rows.push([x.name,x.count,x.distinct,arr(x.others).map(function(o){return o.name+' ('+o.count+')';}).join(' | '),arr(x.dcs).join(' | '),x.last]);});dl(key+'.csv',rows);}
(function(){
  function cnt(sec){var l=FL.filter(function(f){return f.sec===sec&&f.sev!=='info';});var w=worstOf(l.map(function(f){return f.sev;}));return l.length?'<span class="n '+SEVMAP[w]+'">'+l.length+'</span>':'';}
  var S=[['overview','Overview','key',''],['w25','Server 2025 readiness','up',cnt('w25')],['proto','Protocols & hardening','shield',cnt('proto')],['events','Security events','journal',cnt('events')],['time','Time sync','clock',cnt('time')],['backup','Backup & recovery','archive',cnt('backup')]];
  qs('#secnav').innerHTML=S.map(function(x){return '<a data-s="'+x[0]+'">'+ic(x[2])+'<span>'+esc(x[1])+'</span>'+x[3]+'</a>';}).join('');
  Array.prototype.forEach.call(document.querySelectorAll('#secnav a'),function(a){a.onclick=function(){var s=a.getAttribute('data-s');if(s==='overview')window.scrollTo({top:0,behavior:'smooth'});else{var el=qs('#sec-'+s);if(el)el.scrollIntoView({behavior:'smooth',block:'start'});}};});
  function spy(){var cur='overview';S.forEach(function(x){var el=qs('#sec-'+x[0]);if(el&&el.getBoundingClientRect().top<90)cur=x[0];});
    if(window.innerHeight+window.scrollY>=document.body.scrollHeight-4)cur=S[S.length-1][0];
    Array.prototype.forEach.call(document.querySelectorAll('#secnav a'),function(a){a.classList.toggle('on',a.getAttribute('data-s')===cur);});}
  if(window.__spy)window.removeEventListener('scroll',window.__spy);window.__spy=spy;window.addEventListener('scroll',spy,{passive:true});spy();
})();
paintIcons();
</script>
<script>
var MAIN0=document.querySelector('main').innerHTML, SEL='';
function runApp(){document.querySelector('main').innerHTML=MAIN0;D=viewFor(SEL);(0,eval)(document.getElementById('app').textContent);}
(function(){var w=qs('#sdomwrap'),s=qs('#domsel');if(DOMS.length<2)return;w.style.display='';
  var cnt=function(d){return arr(D0.dcs).filter(function(x){return x.domain===d;}).length;};
  s.innerHTML='<option value="">All domains ('+arr(D0.dcs).length+' DCs)</option>'+DOMS.map(function(d){return '<option value="'+esc(d)+'">'+esc(d)+' ('+cnt(d)+')</option>';}).join('');
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
Write-Host "  Report saved: $ReportPath" -ForegroundColor Green
try { if ($OpenReport) { Start-Process $ReportPath } } catch {}
