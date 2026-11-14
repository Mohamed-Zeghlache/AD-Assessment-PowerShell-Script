<#
.SYNOPSIS
    Test-ServerAccess - shows what blocks the inventory of a server from this machine:
    DNS, ping, firewall ports, WMI over DCOM, WinRM, or permissions.

.DESCRIPTION
    Companion to AD-ServerInventory.ps1. Run it from the same machine and with the same account.
    For each server:
      1. DNS        name resolves, and to which IPv4 address
      2. Ping       ICMP echo (information only - often blocked on purpose)
      3. Ports      135 (RPC), 445 (SMB), 3389 (RDP), 5985 / 5986 (WinRM HTTP / HTTPS)
      4. DCOM       real WMI query over DCOM (port 135 + dynamic RPC ports 49152-65535)
      5. WinRM      Test-WSMan, then a real WMI query over WinRM
      6. Verdict    what to fix, in one sentence
    Ports are tested on every server at the same time; DCOM and WinRM are only tried where a
    port answers. Read-only: nothing is changed on the servers.

.PARAMETER ComputerName  One or more server names (FQDN preferred). Accepts pipeline input.
.PARAMETER TimeoutMs     Port and ping timeout in milliseconds (default 1500).
.PARAMETER OutCsv        Optional: also save the results to this CSV file.

.EXAMPLE
    .\Test-ServerAccess.ps1 -ComputerName app01.contoso.com
.EXAMPLE
    # Every server the inventory could not reach, from the report's Servers CSV export
    Import-Csv .\servers.csv | Where-Object { $_.Status -ne 'Read' -and $_.Status -notmatch 'Stale|Disabled|Not Windows' } |
        ForEach-Object { $_.FQDN } | .\Test-ServerAccess.ps1 -OutCsv .\access.csv

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite
    Requires: Windows PowerShell 5.1 or later.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string[]]$ComputerName,
    [ValidateRange(200,10000)][int]$TimeoutMs = 1500,
    [string]$OutCsv
)
begin { $All = [System.Collections.ArrayList]::new() }
process { foreach ($c in $ComputerName) { if ($c -and $c.Trim()) { [void]$All.Add($c.Trim()) } } }
end {
$Ports = @(135, 445, 3389, 5985, 5986)
Write-Host "Test-ServerAccess - $($All.Count) server(s), from $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan

# 1. DNS
Write-Host "[1/4] DNS..." -ForegroundColor Yellow
$Rows = [System.Collections.ArrayList]::new()
foreach ($n in $All) {
    $ips = @()
    try { $ips = @([System.Net.Dns]::GetHostAddresses($n) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | ForEach-Object { $_.IPAddressToString }) } catch {}
    [void]$Rows.Add([ordered]@{ Server=$n; IP=($ips -join ' '); DNS=$(if ($ips.Count) { 'OK' } else { 'Not found' }); Ping=''
        P135=''; P445=''; P3389=''; P5985=''; P5986=''; DCOM=''; WinRM=''; Verdict='' })
}

# 2. Ping and ports, every server at the same time
Write-Host "[2/4] Ping and ports ($($Ports -join ', '))..." -ForegroundColor Yellow
$pings = @{}; $conns = [System.Collections.ArrayList]::new()
foreach ($r in $Rows) {
    if ($r.DNS -ne 'OK') { continue }
    $ip = ($r.IP -split ' ')[0]
    try { $pings[$r.Server] = ([System.Net.NetworkInformation.Ping]::new()).SendPingAsync($ip, $TimeoutMs) } catch {}
    foreach ($p in $Ports) {
        $c = [System.Net.Sockets.TcpClient]::new()
        try { [void]$conns.Add(@{ r=$r; port=$p; c=$c; h=$c.BeginConnect($ip, $p, $null, $null) }) } catch { $c.Close() }
    }
}
$deadline = (Get-Date).AddMilliseconds($TimeoutMs + 300)
while ((Get-Date) -lt $deadline -and @($conns | Where-Object { -not $_['h'].IsCompleted }).Count) { Start-Sleep -Milliseconds 100 }
foreach ($x in $conns) {
    $open = $false
    try { if ($x['h'].IsCompleted -and $x['c'].Connected) { $x['c'].EndConnect($x['h']); $open = $true } } catch {}
    $x['r'][('P' + $x['port'])] = $(if ($open) { 'Open' } else { 'Closed' })
    try { $x['c'].Close() } catch {}
}
foreach ($r in $Rows) {
    $t = $pings[$r.Server]
    if ($t) { try { [void]$t.Wait($TimeoutMs + 500); $r.Ping = $(if ($t.Status -eq 'RanToCompletion' -and [string]$t.Result.Status -eq 'Success') { 'Reply' } else { 'No reply' }) } catch { $r.Ping = 'No reply' } }
}

# 3 and 4. WMI over DCOM and over WinRM, where a port answers
function Get-Reason { param([string]$Msg)
    if ($Msg -match '0x80070005|Access is denied|Access denied') { return 'Access denied' }
    if ($Msg -match '0x800706BA|RPC server is unavailable') { return 'RPC unavailable' }
    if ($Msg -match '0x80070776|0x800706BF|timed out|timeout') { return 'Timed out' }
    if ($Msg -match 'Kerberos|0x8009030[ce]|authentication|TrustedHosts') { return 'Authentication' }
    if ($Msg -match 'cannot complete the operation|WinRM client cannot|0x80338012|not listening') { return 'Not listening' }
    return ($Msg -replace '\s+',' ').Trim()
}
Write-Host "[3/4] WMI over DCOM..." -ForegroundColor Yellow
foreach ($r in $Rows) {
    if ($r.P135 -ne 'Open') { $r.DCOM = $(if ($r.DNS -eq 'OK') { 'Port 135 closed' } else { '-' }); continue }
    $s = $null
    try {
        $s = New-CimSession -ComputerName $r.Server -SessionOption (New-CimSessionOption -Protocol Dcom) -OperationTimeoutSec 15 -ErrorAction Stop
        $null = Get-CimInstance -CimSession $s -ClassName Win32_OperatingSystem -Property Caption -ErrorAction Stop
        $r.DCOM = 'OK'
    } catch { $r.DCOM = Get-Reason ([string]$_.Exception.Message) }
    finally { if ($s) { Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue } }
}
Write-Host "[4/4] WinRM..." -ForegroundColor Yellow
foreach ($r in $Rows) {
    if ($r.P5985 -ne 'Open') { $r.WinRM = $(if ($r.DNS -eq 'OK') { 'Port 5985 closed' } else { '-' }); continue }
    try { $null = Test-WSMan -ComputerName $r.Server -ErrorAction Stop } catch { $r.WinRM = Get-Reason ([string]$_.Exception.Message); continue }
    $s = $null
    try {
        $s = New-CimSession -ComputerName $r.Server -OperationTimeoutSec 15 -ErrorAction Stop
        $null = Get-CimInstance -CimSession $s -ClassName Win32_OperatingSystem -Property Caption -ErrorAction Stop
        $r.WinRM = 'OK'
    } catch { $r.WinRM = Get-Reason ([string]$_.Exception.Message) }
    finally { if ($s) { Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue } }
}

# Verdict
foreach ($r in $Rows) {
    $up = ($r.Ping -eq 'Reply' -or $r.P445 -eq 'Open' -or $r.P3389 -eq 'Open' -or $r.P135 -eq 'Open' -or $r.P5985 -eq 'Open' -or $r.P5986 -eq 'Open')
    $r.Verdict =
        if ($r.DNS -ne 'OK') { 'Name not found in DNS from this machine: check the name, the DNS record, or the DNS suffix.' }
        elseif ($r.DCOM -eq 'OK' -or $r.WinRM -eq 'OK') { 'Reachable - the inventory can read this server' + $(if ($r.DCOM -eq 'OK') { ' (DCOM).' } else { ' (WinRM).' }) }
        elseif (-not $up) { 'No answer at all (no ping, no port): server off, wrong IP in DNS, or a network firewall blocks everything from this machine.' }
        elseif ($r.P135 -ne 'Open' -and $r.P5985 -ne 'Open') { 'Server is up, but RPC (135) and WinRM (5985) are blocked: a firewall rule from this machine is needed for one of them.' }
        elseif ($r.DCOM -eq 'Access denied' -or $r.WinRM -eq 'Access denied') { 'Access denied: the account running the report is not a local administrator on this server.' }
        elseif ($r.DCOM -eq 'RPC unavailable' -and $r.P5985 -ne 'Open') { 'Port 135 is open but the dynamic RPC ports (49152-65535) are blocked: allow them, or open WinRM (5985).' }
        elseif ($r.WinRM -eq 'Authentication') { 'WinRM answers but authentication fails (Kerberos): use the FQDN, check the SPN and the time sync, or the domain trust.' }
        elseif ($r.WinRM -eq 'Not listening' -and $r.P135 -ne 'Open') { 'Port 5985 is open but WinRM does not answer: run "winrm quickconfig" on the server or check the WinRM service.' }
        else { 'Not readable: DCOM - ' + $r.DCOM + '; WinRM - ' + $r.WinRM + '.' }
}

$Out = foreach ($r in $Rows) { [pscustomobject]$r }
$Out | Format-Table Server, IP, DNS, Ping, P135, P445, P3389, P5985, P5986, DCOM, WinRM -AutoSize | Out-String -Width 250 | Write-Host
Write-Host "Verdicts" -ForegroundColor Cyan
foreach ($r in $Rows) { Write-Host ("  {0,-40} {1}" -f $r.Server, $r.Verdict) -ForegroundColor $(if ($r.Verdict -like 'Reachable*') { 'Green' } else { 'Yellow' }) }
Write-Host ""
$grp = $Rows | Group-Object { ($_.Verdict -split ':')[0] } | Sort-Object Count -Descending
Write-Host "Summary" -ForegroundColor Cyan
foreach ($g in $grp) { Write-Host ("  {0,4}  {1}" -f $g.Count, $g.Name) }
if ($OutCsv) { $Out | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8; Write-Host "`nSaved: $OutCsv" -ForegroundColor Green }
}
