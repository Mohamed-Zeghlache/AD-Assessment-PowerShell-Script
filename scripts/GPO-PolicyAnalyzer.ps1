<#
.SYNOPSIS
    GPO Policy Analyzer - Enhanced Dashboard (Automated Policy Analyzer equivalent)
.DESCRIPTION
    Automates what Microsoft's Policy Analyzer does manually:
      1. EXPORT  - backs up every GPO in the domain (or a chosen subset) to a local folder
      2. PARSE   - reads the raw Registry.pol (binary) and GptTmpl.inf (security template)
                   files directly from each backup - no Get-GPOReport, no RSOP, no AD calls
      3. RESOLVE - maps registry key/value pairs to friendly policy names using the
                   ADMX/ADML policy definition files (same templates GPME uses)
      4. COMPARE - pivots every setting across all GPOs into one table and flags any
                   setting where GPOs disagree (the same "conflict" concept Policy
                   Analyzer highlights in yellow)
      5. REPORT  - renders an interactive dark-mode HTML comparison grid

    The export step is the only part that talks to AD/SYSVOL and is therefore the only
    slow part. Once GPOs are backed up locally, parsing + comparing is pure in-memory
    work and completes in seconds even for large GPO counts - re-running -SkipExport
    re-analyzes the same backups instantly.
.PARAMETER BackupPath
    Folder used to store/read GPO backups. Defaults to .\GPOBackups under -OutputPath.
.PARAMETER OutputPath
    Folder to save the HTML report. Defaults to the current directory.
.PARAMETER SkipExport
    Skip Backup-GPO and re-analyze whatever backups already exist in -BackupPath.
.PARAMETER GPONames
    Optional list of GPO display names to limit scope. Defaults to all GPOs in the domain.
.PARAMETER AdmxPath
    Folder containing .admx definition files. Defaults to the SYSVOL central store if
    present, otherwise the local PolicyDefinitions folder.
.PARAMETER AdmxLanguage
    ADML language folder to use for friendly-name strings. Defaults to en-US.
.EXAMPLE
    .\GPO-PolicyAnalyzer.ps1
.EXAMPLE
    .\GPO-PolicyAnalyzer.ps1 -SkipExport
.EXAMPLE
    .\GPO-PolicyAnalyzer.ps1 -GPONames "Default Domain Policy","Server-Hardening-Baseline"
.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite (GPO Policy Analyzer module)

#>
[CmdletBinding()]
param(
    [string]$BackupPath   = (Join-Path (Get-Location).Path 'GPOBackups'),
    [string]$OutputPath   = (Get-Location).Path,
    [switch]$SkipExport,
    [string[]]$GPONames,
    [string]$AdmxPath,
    [string]$AdmxLanguage = 'en-US',
    [switch]$OpenReport   = $true
)

$ErrorActionPreference = 'Stop'
try { Import-Module GroupPolicy -ErrorAction Stop } catch { Write-Error "GroupPolicy module not available. Install RSAT-GPMC."; exit 1 }
try { Import-Module ActiveDirectory -ErrorAction SilentlyContinue } catch {}

# Guard against running from a protected location (e.g. C:\Windows\system32 when launched
# "as administrator"). If the working dir is under the Windows folder, fall back to a
# location any administrator can write to. ProgramData is used rather than the user
# profile because an elevated session may run under a different admin identity that
# doesn't own the launching user's profile folder.
$cwd = (Get-Location).Path
$winDir = $env:SystemRoot
$cwdIsProtected = $false
try { if ($cwd -like "$winDir*") { $cwdIsProtected = $true } } catch {}
if ($cwdIsProtected) {
    $safeBase = Join-Path $env:ProgramData 'GPO-PolicyAnalyzer'
    Write-Host "NOTE: current directory is '$cwd' (protected)." -ForegroundColor Yellow
    Write-Host "      Redirecting output to '$safeBase' so writes don't fail." -ForegroundColor Yellow
    if ($OutputPath -like "$winDir*" -or $OutputPath -eq $cwd) { $OutputPath = $safeBase }
    if ($BackupPath -like "$winDir*") { $BackupPath = Join-Path $safeBase 'GPOBackups' }
}

try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
try { $BackupPath = [System.IO.Path]::GetFullPath($BackupPath) } catch {}
if (!(Test-Path $BackupPath)) { New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null }

# Verify the backup path is actually writable using the SAME mechanism as the manifest
# (Export-Clixml), so we catch ACL problems before paying for the slow export.
$ManifestPath = Join-Path $BackupPath 'manifest.xml'
$manifestWritable = $true
try {
    [PSCustomObject]@{ probe = (Get-Date) } | Export-Clixml -Path $ManifestPath -ErrorAction Stop
    Remove-Item $ManifestPath -Force -ErrorAction SilentlyContinue
} catch {
    $manifestWritable = $false
    Write-Warning "Backup path '$BackupPath' is not writable by this account ($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))."
    Write-Warning "Backups will still be analyzed in-memory, but -SkipExport won't be available next time."
    Write-Warning "For a reusable backup set, re-run with -BackupPath set to a folder you own, e.g.  -BackupPath C:\Temp\GPOBackups"
}

$Stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$ReportPath  = Join-Path $OutputPath "GPO_PolicyAnalysis_$Stamp.html"

try { $Domain = Get-ADDomain -ErrorAction SilentlyContinue } catch { $Domain = $null }
$DomainDNS = if ($Domain) { $Domain.DNSRoot } else { $env:USERDNSDOMAIN }

Write-Host "GPO Policy Analyzer" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1: EXPORT - Backup-GPO is a native backup operation (fast), NOT a report
# generation or RSOP computation (slow). This is the only phase that touches AD/SYSVOL.
# ─────────────────────────────────────────────────────────────────────────────
$Manifest = @()

if ($SkipExport -and (Test-Path $ManifestPath)) {
    Write-Host "[1/5] Skipping export - reusing existing backups in $BackupPath" -ForegroundColor Yellow
    $Manifest = Import-Clixml -Path $ManifestPath
    Write-Host "      $($Manifest.Count) GPO backup(s) loaded from manifest" -ForegroundColor Green
} else {
    Write-Host "[1/5] Exporting GPOs..." -ForegroundColor Yellow
    try {
        $TargetGPOs = if ($GPONames -and $GPONames.Count -gt 0) {
            $GPONames | ForEach-Object {
                $g = Get-GPO -Name $_ -ErrorAction SilentlyContinue
                if (-not $g) { Write-Warning "  GPO not found: $_" }
                $g
            } | Where-Object { $_ }
        } else {
            Get-GPO -All -ErrorAction Stop
        }
    } catch {
        Write-Error "Could not enumerate GPOs: $($_.Exception.Message)"; exit 1
    }

    Write-Host "      $($TargetGPOs.Count) GPO(s) to back up" -ForegroundColor Gray

    # Pre-build a map of GPO GUID -> links (OU/domain DN, link order, enforced, enabled).
    # Walk every OU + the domain root, read Get-GPInheritance once each, and record where
    # each GPO is linked. This is what enables precedence calculation later.
    Write-Host "      Mapping GPO links across the domain..." -ForegroundColor DarkGray
    $LinkMap = @{}   # GUID(lower) -> array of link objects
    try {
        $containers = @()
        if ($Domain) { $containers += $Domain.DistinguishedName }
        $containers += @(Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue | ForEach-Object { $_.DistinguishedName })
        foreach ($dn in $containers) {
            try {
                $inh = Get-GPInheritance -Target $dn -ErrorAction SilentlyContinue
                if ($inh -and $inh.GpoLinks) {
                    foreach ($lnk in $inh.GpoLinks) {
                        $gid = "$($lnk.GpoId)".ToLowerInvariant().Trim('{','}')
                        if (-not $LinkMap.ContainsKey($gid)) { $LinkMap[$gid] = @() }
                        $LinkMap[$gid] += [PSCustomObject]@{
                            Target    = $dn
                            Order     = $lnk.Order
                            Enforced  = [bool]$lnk.Enforced
                            Enabled   = [bool]$lnk.Enabled
                            Depth     = ([regex]::Matches($dn,'OU=')).Count
                        }
                    }
                }
            } catch {}
        }
    } catch { Write-Warning "      Link mapping partial: $($_.Exception.Message)" }

    $i = 0
    foreach ($gpo in $TargetGPOs) {
        $i++
        Write-Host "      [$i/$($TargetGPOs.Count)] $($gpo.DisplayName)" -ForegroundColor DarkGray
        try {
            $bk = Backup-GPO -Guid $gpo.Id -Path $BackupPath -ErrorAction Stop
            $gidLower = "$($gpo.Id)".ToLowerInvariant().Trim('{','}')
            $links = if ($LinkMap.ContainsKey($gidLower)) { $LinkMap[$gidLower] } else { @() }
            # GPO status: are Computer / User sections enabled?
            $gpoStatus = "$($gpo.GpoStatus)"   # AllSettingsEnabled / UserSettingsDisabled / ComputerSettingsDisabled / AllSettingsDisabled
            $Manifest += [PSCustomObject]@{
                Name         = $gpo.DisplayName
                Id           = $gpo.Id.ToString()
                BackupId     = $bk.Id.ToString()
                BackupFolder = Join-Path $BackupPath "{$($bk.Id)}"
                Created      = $gpo.CreationTime
                Modified     = $gpo.ModificationTime
                GpoStatus    = $gpoStatus
                CompDS       = $(if ($gpo.Computer) { [int]$gpo.Computer.DSVersion } else { $null })
                CompSys      = $(if ($gpo.Computer) { [int]$gpo.Computer.SysvolVersion } else { $null })
                UserDS       = $(if ($gpo.User) { [int]$gpo.User.DSVersion } else { $null })
                UserSys      = $(if ($gpo.User) { [int]$gpo.User.SysvolVersion } else { $null })
                LinksCount   = @($links).Count
                Links        = @($links)
            }
        } catch {
            Write-Warning "        Backup failed for $($gpo.DisplayName): $($_.Exception.Message)"
        }
    }
    if ($manifestWritable) {
        try {
            $Manifest | Export-Clixml -Path $ManifestPath -ErrorAction Stop
            Write-Host "      Exported $($Manifest.Count) GPO(s) to $BackupPath" -ForegroundColor Green
        } catch {
            Write-Warning "      Could not write manifest: $($_.Exception.Message)"
            Write-Warning "      Backups created; continuing in-memory (-SkipExport unavailable)."
        }
    } else {
        Write-Host "      Exported $($Manifest.Count) GPO(s) to $BackupPath (manifest not saved - see warning above)" -ForegroundColor Green
    }
}

if ($Manifest.Count -eq 0) {
    Write-Error "No GPO backups available to analyze."; exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2a: Registry.pol binary parser
# Format ([MS-GPREG]): signature "PReg" (4 bytes) + version DWORD(4 bytes), then
# repeated records: '[' Key ';' ValueName ';' Type(DWORD) ';' Size(DWORD) ';' Data ']'
# Key/ValueName are null-terminated UTF-16LE strings. This reads the file directly -
# no GPMC API calls - which is what makes parsing effectively instant.
# ─────────────────────────────────────────────────────────────────────────────
function Read-NullTermUnicodeString {
    param([byte[]]$Bytes, [int]$Start)
    $i = $Start
    $len = $Bytes.Length
    while ($true) {
        if ($i + 1 -ge $len) { break }
        if ($Bytes[$i] -eq 0 -and $Bytes[$i+1] -eq 0) { break }
        $i += 2
    }
    $strLen = $i - $Start
    $s = if ($strLen -gt 0) { [System.Text.Encoding]::Unicode.GetString($Bytes, $Start, $strLen) } else { '' }
    # Return both the string and the offset just past the null terminator
    [PSCustomObject]@{ Value = $s; NextOffset = [Math]::Min($i + 2, $len) }
}

function Convert-PolicyValueData {
    param([int]$Type, [byte[]]$Bytes)
    switch ($Type) {
        1 { ([System.Text.Encoding]::Unicode.GetString($Bytes)).TrimEnd([char]0) }                 # REG_SZ
        2 { ([System.Text.Encoding]::Unicode.GetString($Bytes)).TrimEnd([char]0) }                 # REG_EXPAND_SZ
        3 { ($Bytes | ForEach-Object { $_.ToString('X2') }) -join '' }                              # REG_BINARY
        4 { if ($Bytes.Length -ge 4) { [BitConverter]::ToUInt32($Bytes,0) } else { 0 } }             # REG_DWORD
        5 { if ($Bytes.Length -ge 4) { $r=$Bytes[0..3]; [Array]::Reverse($r); [BitConverter]::ToUInt32($r,0) } else { 0 } } # REG_DWORD_BIG_ENDIAN
        7 { (([System.Text.Encoding]::Unicode.GetString($Bytes)) -split [char]0 | Where-Object { $_ -ne '' }) -join '; ' } # REG_MULTI_SZ
        11{ if ($Bytes.Length -ge 8) { [BitConverter]::ToUInt64($Bytes,0) } else { 0 } }             # REG_QWORD
        default { ($Bytes | ForEach-Object { $_.ToString('X2') }) -join '' }
    }
}

function Parse-RegistryPol {
    param([string]$Path, [string]$Hive, [string]$SourceName)
    $rows = @()
    if (-not (Test-Path $Path)) { return $rows }
    try { $bytes = [System.IO.File]::ReadAllBytes($Path) } catch { return $rows }
    if ($bytes.Length -lt 8) { return $rows }
    # Signature "PReg" = bytes 0x50,0x52,0x65,0x67
    if (-not ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x52 -and $bytes[2] -eq 0x65 -and $bytes[3] -eq 0x67)) {
        Write-Warning "    Not a recognised Registry.pol: $Path"
        return $rows
    }
    $offset = 8
    $len = $bytes.Length
    while ($offset -lt ($len - 1)) {
        if (-not ($bytes[$offset] -eq 0x5B -and $bytes[$offset+1] -eq 0x00)) { break }   # expect '['
        $offset += 2
        $r = Read-NullTermUnicodeString -Bytes $bytes -Start $offset
        $key = $r.Value; $offset = $r.NextOffset
        if ($offset + 1 -ge $len) { break }
        $offset += 2   # skip ';'
        $r = Read-NullTermUnicodeString -Bytes $bytes -Start $offset
        $valueName = $r.Value; $offset = $r.NextOffset
        $offset += 2   # skip ';'
        if ($offset + 4 -gt $len) { break }
        $type = [BitConverter]::ToInt32($bytes, $offset); $offset += 4
        $offset += 2   # skip ';'
        if ($offset + 4 -gt $len) { break }
        $size = [BitConverter]::ToInt32($bytes, $offset); $offset += 4
        $offset += 2   # skip ';'
        $data = ''
        if ($size -gt 0) {
            if (($offset + $size) -gt $len) { break }
            $raw = $bytes[$offset..($offset + $size - 1)]
            $data = Convert-PolicyValueData -Type $type -Bytes $raw
            $offset += $size
        }
        if ($offset + 1 -lt $len -and $bytes[$offset] -eq 0x5D -and $bytes[$offset+1] -eq 0x00) { $offset += 2 } # ']'
        if ($key) {
            $rows += [PSCustomObject]@{ Hive=$Hive; Key=$key; ValueName=$valueName; Type=$type; Data="$data"; Source=$SourceName }
        }
    }
    return $rows
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2b: Security template (GptTmpl.inf) + advanced audit (audit.csv) parsers
# These settings (user rights, password policy, security options, audit policy)
# are NOT in Registry.pol - GptTmpl.inf is plain-text INI, audit.csv is plain CSV.
# Friendly names for these are well-known/fixed, so they're hardcoded here rather
# than resolved via ADMX (which only covers registry-based "Administrative Templates").
# ─────────────────────────────────────────────────────────────────────────────
$Script:UserRightNames = @{
    'SeTrustedCredManAccessPrivilege'='Access Credential Manager as a trusted caller'
    'SeNetworkLogonRight'='Access this computer from the network'
    'SeTcbPrivilege'='Act as part of the operating system'
    'SeMachineAccountPrivilege'='Add workstations to domain'
    'SeIncreaseQuotaPrivilege'='Adjust memory quotas for a process'
    'SeInteractiveLogonRight'='Allow log on locally'
    'SeRemoteInteractiveLogonRight'='Allow log on through Remote Desktop Services'
    'SeBackupPrivilege'='Back up files and directories'
    'SeChangeNotifyPrivilege'='Bypass traverse checking'
    'SeSystemtimePrivilege'='Change the system time'
    'SeTimeZonePrivilege'='Change the time zone'
    'SeCreatePagefilePrivilege'='Create a pagefile'
    'SeCreateTokenPrivilege'='Create a token object'
    'SeCreateGlobalPrivilege'='Create global objects'
    'SeCreatePermanentPrivilege'='Create permanent shared objects'
    'SeCreateSymbolicLinkPrivilege'='Create symbolic links'
    'SeDebugPrivilege'='Debug programs'
    'SeDenyNetworkLogonRight'='Deny access to this computer from the network'
    'SeDenyBatchLogonRight'='Deny log on as a batch job'
    'SeDenyServiceLogonRight'='Deny log on as a service'
    'SeDenyInteractiveLogonRight'='Deny log on locally'
    'SeDenyRemoteInteractiveLogonRight'='Deny log on through Remote Desktop Services'
    'SeEnableDelegationPrivilege'='Enable computer and user accounts to be trusted for delegation'
    'SeRemoteShutdownPrivilege'='Force shutdown from a remote system'
    'SeAuditPrivilege'='Generate security audits'
    'SeImpersonatePrivilege'='Impersonate a client after authentication'
    'SeIncreaseWorkingSetPrivilege'='Increase a process working set'
    'SeIncreaseBasePriorityPrivilege'='Increase scheduling priority'
    'SeLoadDriverPrivilege'='Load and unload device drivers'
    'SeLockMemoryPrivilege'='Lock pages in memory'
    'SeBatchLogonRight'='Log on as a batch job'
    'SeServiceLogonRight'='Log on as a service'
    'SeSecurityPrivilege'='Manage auditing and security log'
    'SeRelabelPrivilege'='Modify an object label'
    'SeSystemEnvironmentPrivilege'='Modify firmware environment values'
    'SeManageVolumePrivilege'='Perform volume maintenance tasks'
    'SeProfileSingleProcessPrivilege'='Profile single process'
    'SeSystemProfilePrivilege'='Profile system performance'
    'SeUndockPrivilege'='Remove computer from docking station'
    'SeAssignPrimaryTokenPrivilege'='Replace a process level token'
    'SeRestorePrivilege'='Restore files and directories'
    'SeShutdownPrivilege'='Shut down the system'
    'SeSyncAgentPrivilege'='Synchronize directory service data'
    'SeTakeOwnershipPrivilege'='Take ownership of files or other objects'
}

$Script:SystemAccessNames = @{
    'MinimumPasswordAge'='Minimum password age (days)'
    'MaximumPasswordAge'='Maximum password age (days)'
    'MinimumPasswordLength'='Minimum password length'
    'PasswordComplexity'='Password must meet complexity requirements'
    'PasswordHistorySize'='Enforce password history (passwords remembered)'
    'LockoutBadCount'='Account lockout threshold'
    'ResetLockoutCount'='Reset account lockout counter after (minutes)'
    'LockoutDuration'='Account lockout duration (minutes)'
    'ForceLogoffWhenHourExpire'='Force logoff when logon hours expire'
    'NewAdministratorName'='Rename administrator account'
    'NewGuestName'='Rename guest account'
    'EnableAdminAccount'='Accounts: Administrator account status'
    'EnableGuestAccount'='Accounts: Guest account status'
    'ClearTextPassword'='Store passwords using reversible encryption'
    'LSAAnonymousNameLookup'='Network access: Allow anonymous SID/Name translation'
    'RequireLogonToChangePassword'='User must log on to change password'
}

$Script:KerberosPolicyNames = @{
    'MaxTicketAge'='Maximum lifetime for user ticket (hours)'
    'MaxRenewAge'='Maximum lifetime for user ticket renewal (days)'
    'MaxServiceAge'='Maximum lifetime for service ticket (minutes)'
    'MaxClockSkew'='Maximum tolerance for computer clock synchronization (minutes)'
    'TicketValidateClient'='Enforce user logon restrictions'
}

# Common "Security Options" registry-backed settings (GptTmpl.inf [Registry Values]).
# Keyed by lowercase "RegPath|ValueName" -> friendly name. Not exhaustive - covers the
# most commonly audited/STIG'd settings; unmatched ones fall back to raw key\value.
$Script:SecurityOptionNames = @{
    'software\microsoft\windows\currentversion\policies\system|legalnoticecaption'        = 'Interactive logon: Message title for users attempting to log on'
    'software\microsoft\windows\currentversion\policies\system|legalnoticetext'            = 'Interactive logon: Message text for users attempting to log on'
    'software\microsoft\windows\currentversion\policies\system|dontdisplaylastusername'    = 'Interactive logon: Do not display last signed-in'
    'software\microsoft\windows\currentversion\policies\system|disablecad'                 = 'Interactive logon: Do not require CTRL+ALT+DEL'
    'software\microsoft\windows\currentversion\policies\system|scremoveoption'             = 'Interactive logon: Smart card removal behavior'
    'software\microsoft\windows\currentversion\policies\system|shutdownwithoutlogon'       = 'Shutdown: Allow system to be shut down without having to log on'
    'software\microsoft\windows\currentversion\policies\system|undockwithoutlogon'         = 'Devices: Allow undock without having to log on'
    'software\microsoft\windows\currentversion\policies\system|enableinstallerdetection'   = 'User Account Control: Detect application installations and prompt for elevation'
    'software\microsoft\windows\currentversion\policies\system|enablelua'                  = 'User Account Control: Run all administrators in Admin Approval Mode'
    'software\microsoft\windows\currentversion\policies\system|consentpromptbehavioradmin' = 'User Account Control: Behavior of the elevation prompt for administrators'
    'software\microsoft\windows\currentversion\policies\system|consentpromptbehavioruser'  = 'User Account Control: Behavior of the elevation prompt for standard users'
    'software\microsoft\windows\currentversion\policies\system|promptonsecuredesktop'      = 'User Account Control: Switch to the secure desktop when prompting for elevation'
    'software\microsoft\windows\currentversion\policies\system|filteradministratortoken'   = 'User Account Control: Admin Approval Mode for the built-in Administrator account'
    'system\currentcontrolset\control\lsa|restrictanonymous'                               = 'Network access: Do not allow anonymous enumeration of SAM accounts'
    'system\currentcontrolset\control\lsa|restrictanonymoussam'                            = 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'
    'system\currentcontrolset\control\lsa|lmcompatibilitylevel'                            = 'Network security: LAN Manager authentication level'
    'system\currentcontrolset\control\lsa|noLMHash'                                        = 'Network security: Do not store LAN Manager hash value on next password change'
    'system\currentcontrolset\control\lsa|forceguest'                                      = 'Network access: Sharing and security model for local accounts'
    'system\currentcontrolset\control\lsa|everyoneincludesanonymous'                       = 'Network access: Let Everyone permissions apply to anonymous users'
    'system\currentcontrolset\services\lanmanserver\parameters|smb1'                       = 'SMBv1 protocol enabled'
    'system\currentcontrolset\services\netbt\parameters|nodetype'                          = 'NetBIOS node type'
    'microsoft\windows nt\currentversion\winlogon|autoadminlogon'                          = 'Automatically sign in'
}

function Resolve-SidList {
    param([string]$RawList, [hashtable]$Cache)
    if (-not $RawList) { return '' }
    $items = $RawList -split ',' | Where-Object { $_ -ne '' }
    $resolved = foreach ($item in $items) {
        $sidStr = $item.TrimStart('*')
        if ($Cache.ContainsKey($sidStr)) { $Cache[$sidStr] }
        else {
            $name = $sidStr
            try {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
                $name = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
            } catch {}
            $Cache[$sidStr] = $name
            $name
        }
    }
    return ($resolved -join ', ')
}

function Parse-SecurityTemplate {
    param([string]$Path, [string]$SourceName)
    $rows = @()
    if (-not (Test-Path $Path)) { return $rows }
    $lines = $null
    try { $lines = Get-Content -Path $Path -Encoding Unicode -ErrorAction Stop } catch {}
    if (-not $lines -or (($lines -join '') -notmatch '\[')) {
        try { $lines = Get-Content -Path $Path -Encoding Default -ErrorAction Stop } catch {}
    }
    if (-not $lines) { return $rows }

    $section = ''
    foreach ($line in $lines) {
        $t = "$line".Trim()
        if ($t -eq '' -or $t.StartsWith(';')) { continue }
        if ($t.StartsWith('[') -and $t.EndsWith(']')) { $section = $t.Substring(1, $t.Length-2); continue }
        $eq = $t.IndexOf('=')
        if ($eq -lt 0) { continue }
        $k = $t.Substring(0,$eq).Trim()
        $v = $t.Substring($eq+1).Trim()

        switch ($section) {
            'System Access' {
                $rows += [PSCustomObject]@{ Category='SystemAccess'; Hive=''; Key='System Access'; Setting=$k; Data=$v; Source=$SourceName }
            }
            'Kerberos Policy' {
                $rows += [PSCustomObject]@{ Category='KerberosPolicy'; Hive=''; Key='Kerberos Policy'; Setting=$k; Data=$v; Source=$SourceName }
            }
            'Privilege Rights' {
                $rows += [PSCustomObject]@{ Category='UserRight'; Hive=''; Key='Privilege Rights'; Setting=$k; Data=$v; Source=$SourceName }
            }
            'Registry Values' {
                $lastSlash = $k.LastIndexOf('\')
                if ($lastSlash -gt 0) {
                    $fullPath = $k.Substring(0,$lastSlash)
                    $valueName = $k.Substring($lastSlash+1)
                    $hive = 'HKLM'; $regPath = $fullPath
                    if ($fullPath -match '^(MACHINE|USER)\\(.*)$') {
                        $hive = if ($Matches[1] -eq 'MACHINE') { 'HKLM' } else { 'HKCU' }
                        $regPath = $Matches[2]
                    }
                    $comma = $v.IndexOf(',')
                    $dataVal = if ($comma -ge 0) { $v.Substring($comma+1) } else { $v }
                    $rows += [PSCustomObject]@{ Category='SecurityOption'; Hive=$hive; Key=$regPath; Setting=$valueName; Data=$dataVal; Source=$SourceName }
                }
            }
            'Event Audit' {
                $rows += [PSCustomObject]@{ Category='AuditPolicy'; Hive=''; Key='Event Audit (legacy)'; Setting=$k; Data=$v; Source=$SourceName }
            }
            'Group Membership' {
                $rows += [PSCustomObject]@{ Category='GroupMembership'; Hive=''; Key='Group Membership'; Setting=$k; Data=$v; Source=$SourceName }
            }
        }
    }
    return $rows
}

function Parse-AuditCsv {
    param([string]$Path, [string]$SourceName)
    $rows = @()
    if (-not (Test-Path $Path)) { return $rows }
    try { $csv = Import-Csv -Path $Path -ErrorAction Stop } catch { return $rows }
    foreach ($r in $csv) {
        $sub = $r.Subcategory
        if (-not $sub) { continue }
        $val = if ($r.'Setting Value') { $r.'Setting Value' } elseif ($r.'Inclusion Setting') { $r.'Inclusion Setting' } else { '' }
        $rows += [PSCustomObject]@{ Category='AuditPolicy'; Hive=''; Key='Advanced Audit Policy'; Setting=$sub; Data="$val"; Source=$SourceName }
    }
    return $rows
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2c: ADMX/ADML parser - builds a (Hive|Key|ValueName) -> friendly-name
# lookup from the same policy definition templates GPME itself uses.
# ─────────────────────────────────────────────────────────────────────────────
function Resolve-AdmlToken {
    param([string]$Token, [hashtable]$StringTable)
    if (-not $Token) { return $null }
    if ($Token -match '^\$\(string\.(.+)\)$') {
        $id = $Matches[1]
        if ($StringTable.ContainsKey($id)) { return $StringTable[$id] }
    }
    return $null
}

function Import-AdmxFriendlyNames {
    param([string]$AdmxFolder, [string]$Language)
    $byKeyValue = @{}
    $byKeyOnly  = @{}
    $parsed = 0; $failed = 0
    if (-not (Test-Path $AdmxFolder)) { return @{ ByKeyValue=$byKeyValue; ByKeyOnly=$byKeyOnly; FilesParsed=0; FilesFailed=0 } }
    $admxFiles = Get-ChildItem -Path $AdmxFolder -Filter '*.admx' -File -ErrorAction SilentlyContinue

    foreach ($admxFile in $admxFiles) {
        try { [xml]$doc = Get-Content -Path $admxFile.FullName -Raw -ErrorAction Stop } catch { $failed++; continue }
        $nsUri = $doc.DocumentElement.NamespaceURI
        $nsmgr = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
        $nsmgr.AddNamespace('p', $nsUri)

        $stringTable = @{}
        $admlCandidates = @(
            (Join-Path (Join-Path $AdmxFolder $Language) ($admxFile.BaseName + '.adml')),
            (Join-Path (Join-Path $AdmxFolder 'en-US')   ($admxFile.BaseName + '.adml'))
        )
        $admlPath = $admlCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($admlPath) {
            try {
                [xml]$admlDoc = Get-Content -Path $admlPath -Raw -ErrorAction Stop
                $admlNsmgr = New-Object System.Xml.XmlNamespaceManager($admlDoc.NameTable)
                $admlNsmgr.AddNamespace('p', $admlDoc.DocumentElement.NamespaceURI)
                foreach ($sn in $admlDoc.SelectNodes('//p:stringTable/p:string', $admlNsmgr)) {
                    $id = $sn.GetAttribute('id')
                    if ($id) { $stringTable[$id] = $sn.InnerText }
                }
            } catch {}
        }

        $policyNodes = $doc.SelectNodes('//p:policies/p:policy', $nsmgr)
        foreach ($pol in $policyNodes) {
            $class = $pol.GetAttribute('class')
            $hives = switch ($class) { 'Machine'{@('HKLM')} 'User'{@('HKCU')} default {@('HKLM','HKCU')} }
            $polKey = $pol.GetAttribute('key')
            if (-not $polKey) { continue }
            $polValueName = $pol.GetAttribute('valueName')
            $friendly = Resolve-AdmlToken -Token $pol.GetAttribute('displayName') -StringTable $stringTable
            if (-not $friendly) { $friendly = $pol.GetAttribute('name') }
            $keyLower = $polKey.ToLowerInvariant()

            if ($polValueName) {
                foreach ($h in $hives) { $byKeyValue["$h|$keyLower|$($polValueName.ToLowerInvariant())"] = $friendly }
            } else {
                foreach ($h in $hives) { if (-not $byKeyOnly.ContainsKey("$h|$keyLower")) { $byKeyOnly["$h|$keyLower"] = $friendly } }
            }

            foreach ($el in $pol.SelectNodes('.//p:elements/p:*[@valueName]', $nsmgr)) {
                $elKey = $el.GetAttribute('key'); if (-not $elKey) { $elKey = $polKey }
                $elValueName = $el.GetAttribute('valueName')
                if ($elKey -and $elValueName) {
                    $ekLower = $elKey.ToLowerInvariant()
                    foreach ($h in $hives) { $byKeyValue["$h|$ekLower|$($elValueName.ToLowerInvariant())"] = $friendly }
                }
            }
            foreach ($el in $pol.SelectNodes('.//p:elements/p:list', $nsmgr)) {
                $elKey = $el.GetAttribute('key'); if (-not $elKey) { $elKey = $polKey }
                if ($elKey) {
                    $ekLower = $elKey.ToLowerInvariant()
                    foreach ($h in $hives) { if (-not $byKeyOnly.ContainsKey("$h|$ekLower")) { $byKeyOnly["$h|$ekLower"] = $friendly } }
                }
            }
        }
        $parsed++
    }
    return @{ ByKeyValue=$byKeyValue; ByKeyOnly=$byKeyOnly; FilesParsed=$parsed; FilesFailed=$failed }
}

function Get-FriendlyName {
    param([string]$Category, [string]$Hive, [string]$Key, [string]$Setting, [hashtable]$ByKeyValue, [hashtable]$ByKeyOnly)
    switch ($Category) {
        'Registry' {
            $k1 = "$Hive|$($Key.ToLowerInvariant())|$($Setting.ToLowerInvariant())"
            if ($ByKeyValue.ContainsKey($k1)) { return $ByKeyValue[$k1] }
            $k2 = "$Hive|$($Key.ToLowerInvariant())"
            if ($ByKeyOnly.ContainsKey($k2)) { return $ByKeyOnly[$k2] }
            return "$Key\$Setting"
        }
        'SecurityOption' {
            $k = "$($Key.ToLowerInvariant())|$($Setting.ToLowerInvariant())"
            if ($Script:SecurityOptionNames.ContainsKey($k)) { return $Script:SecurityOptionNames[$k] }
            return "$Key\$Setting"
        }
        'UserRight'       { if ($Script:UserRightNames.ContainsKey($Setting))     { $Script:UserRightNames[$Setting] }     else { $Setting } }
        'SystemAccess'    { if ($Script:SystemAccessNames.ContainsKey($Setting))  { $Script:SystemAccessNames[$Setting] }  else { $Setting } }
        'KerberosPolicy'  { if ($Script:KerberosPolicyNames.ContainsKey($Setting)){ $Script:KerberosPolicyNames[$Setting] }else { $Setting } }
        default { $Setting }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2: Resolve ADMX path, load friendly names, then parse every GPO backup
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/5] Loading policy definitions (ADMX/ADML) for friendly names..." -ForegroundColor Yellow
if (-not $AdmxPath) {
    $centralStore = if ($DomainDNS) { "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\PolicyDefinitions" } else { $null }
    if ($centralStore -and (Test-Path $centralStore)) { $AdmxPath = $centralStore }
    else { $AdmxPath = Join-Path $env:SystemRoot 'PolicyDefinitions' }
}
Write-Host "      Using: $AdmxPath" -ForegroundColor Gray
$Admx = Import-AdmxFriendlyNames -AdmxFolder $AdmxPath -Language $AdmxLanguage
Write-Host "      Parsed $($Admx.FilesParsed) ADMX file(s), $($Admx.ByKeyValue.Count + $Admx.ByKeyOnly.Count) friendly-name mapping(s) loaded" -ForegroundColor Green
if ($Admx.FilesFailed -gt 0) { Write-Host "      ($($Admx.FilesFailed) ADMX file(s) failed to parse and were skipped)" -ForegroundColor DarkYellow }

Write-Host "[3/5] Parsing GPO backups (Registry.pol + GptTmpl.inf + audit.csv)..." -ForegroundColor Yellow
$AllRegistryRows = @()
$AllSecurityRows = @()
$SidCache = @{}
$i = 0
foreach ($entry in $Manifest) {
    $i++
    Write-Host "      [$i/$($Manifest.Count)] $($entry.Name)" -ForegroundColor DarkGray
    $folder = $entry.BackupFolder
    if (-not (Test-Path $folder)) { Write-Warning "        Backup folder missing: $folder"; continue }

    $machinePol = Get-ChildItem -Path (Join-Path $folder 'DomainSysvol\GPO\Machine') -Filter 'Registry.pol' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    $userPol    = Get-ChildItem -Path (Join-Path $folder 'DomainSysvol\GPO\User')    -Filter 'Registry.pol' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    $gptTmpl    = Get-ChildItem -Path (Join-Path $folder 'DomainSysvol\GPO\Machine') -Filter 'GptTmpl.inf'  -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    $auditCsv   = Get-ChildItem -Path $folder -Filter 'audit.csv' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($machinePol) { $AllRegistryRows += Parse-RegistryPol -Path $machinePol.FullName -Hive 'HKLM' -SourceName $entry.Name }
    if ($userPol)    { $AllRegistryRows += Parse-RegistryPol -Path $userPol.FullName    -Hive 'HKCU' -SourceName $entry.Name }
    if ($gptTmpl)    { $AllSecurityRows += Parse-SecurityTemplate -Path $gptTmpl.FullName -SourceName $entry.Name }
    if ($auditCsv)   { $AllSecurityRows += Parse-AuditCsv -Path $auditCsv.FullName -SourceName $entry.Name }
}
Write-Host "      $($AllRegistryRows.Count) registry setting instance(s), $($AllSecurityRows.Count) security-template setting instance(s) parsed" -ForegroundColor Green

# Resolve SIDs in User Rights / Group Membership values now, once, with a shared cache
foreach ($row in $AllSecurityRows) {
    if ($row.Category -in @('UserRight','GroupMembership') -and $row.Data) {
        $row.Data = Resolve-SidList -RawList $row.Data -Cache $SidCache
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3: PIVOT / COMPARE - pure in-memory hashtable work, no AD calls.
# Every setting across every GPO collapses into one row; a setting is flagged as
# a conflict when more than one distinct configured value exists across the GPOs
# that set it - the same concept as Policy Analyzer's yellow highlighting.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[4/5] Comparing settings across all GPOs..." -ForegroundColor Yellow

function Get-PolicyScope {
    param([string]$Category, [string]$Hive)
    # Computer config = HKLM / machine security settings; User config = HKCU
    if ($Hive -eq 'HKCU') { return 'User' }
    if ($Hive -eq 'HKLM') { return 'Computer' }
    # Security-template categories are all Computer Configuration
    switch ($Category) {
        'SystemAccess'    { 'Computer' }
        'KerberosPolicy'  { 'Computer' }
        'UserRight'       { 'Computer' }
        'SecurityOption'  { 'Computer' }
        'AuditPolicy'     { 'Computer' }
        'GroupMembership' { 'Computer' }
        default           { 'Computer' }
    }
}

function Convert-RegTypeName {
    param($Type)
    switch ([int]$Type) {
        1 {'REG_SZ'} 2 {'REG_EXPAND_SZ'} 3 {'REG_BINARY'} 4 {'REG_DWORD'}
        5 {'REG_DWORD_BIG_ENDIAN'} 7 {'REG_MULTI_SZ'} 11 {'REG_QWORD'} default {''}
    }
}

function Add-PivotRow {
    param([hashtable]$Pivot, [string]$Category, [string]$Hive, [string]$Key, [string]$Setting, [string]$FriendlyName, [string]$Source, [string]$Data, [string]$ValueType)
    $pkey = "$Category|$($Hive.ToLowerInvariant())|$($Key.ToLowerInvariant())|$($Setting.ToLowerInvariant())"
    if (-not $Pivot.ContainsKey($pkey)) {
        $Pivot[$pkey] = [PSCustomObject]@{
            Category=$Category; Hive=$Hive; Key=$Key; Setting=$Setting; FriendlyName=$FriendlyName
            Scope=(Get-PolicyScope -Category $Category -Hive $Hive)
            ValueType=$ValueType
            Values=[ordered]@{}
        }
    }
    $entry = $Pivot[$pkey]
    $rawFallback = "$($entry.Key)\$($entry.Setting)"
    if ($entry.FriendlyName -eq $rawFallback -and $FriendlyName -ne "$Key\$Setting") { $entry.FriendlyName = $FriendlyName }
    if (-not $entry.ValueType -and $ValueType) { $entry.ValueType = $ValueType }
    $entry.Values[$Source] = $Data
}

function Build-Pivot {
    param($RegistryRows, $SecurityRows, $Admx)
    $pivot = @{}
    foreach ($row in $RegistryRows) {
        $friendly = Get-FriendlyName -Category 'Registry' -Hive $row.Hive -Key $row.Key -Setting $row.ValueName -ByKeyValue $Admx.ByKeyValue -ByKeyOnly $Admx.ByKeyOnly
        $typeName = Convert-RegTypeName -Type $row.Type
        Add-PivotRow -Pivot $pivot -Category 'Registry' -Hive $row.Hive -Key $row.Key -Setting $row.ValueName -FriendlyName $friendly -Source $row.Source -Data $row.Data -ValueType $typeName
    }
    foreach ($row in $SecurityRows) {
        $friendly = Get-FriendlyName -Category $row.Category -Hive $row.Hive -Key $row.Key -Setting $row.Setting -ByKeyValue $Admx.ByKeyValue -ByKeyOnly $Admx.ByKeyOnly
        Add-PivotRow -Pivot $pivot -Category $row.Category -Hive $row.Hive -Key $row.Key -Setting $row.Setting -FriendlyName $friendly -Source $row.Source -Data $row.Data -ValueType ''
    }
    foreach ($entry in $pivot.Values) {
        $distinctVals = @($entry.Values.Values | Where-Object { $null -ne $_ -and "$_".Trim() -ne '' } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Select-Object -Unique)
        $entry | Add-Member -NotePropertyName ConfiguredCount -NotePropertyValue ($entry.Values.Count) -Force
        $entry | Add-Member -NotePropertyName Conflict -NotePropertyValue ($distinctVals.Count -gt 1) -Force
        $entry | Add-Member -NotePropertyName DistinctCount -NotePropertyValue ($distinctVals.Count) -Force
    }
    return $pivot
}

$Pivot = Build-Pivot -RegistryRows $AllRegistryRows -SecurityRows $AllSecurityRows -Admx $Admx
$PivotRows = @($Pivot.Values)
$ConflictRows = @($PivotRows | Where-Object { $_.Conflict })
Write-Host "      $($PivotRows.Count) unique setting(s) across $($Manifest.Count) GPO(s) - $($ConflictRows.Count) conflict(s) found" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# EXTRA 1: PRECEDENCE - for each conflict, determine which GPO actually wins.
# AD precedence rules (highest wins): Enforced link > lower link order > deeper OU.
# A GPO with no enabled link can't win (its value is configured but never applied).
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "      Computing GPO precedence for conflicts..." -ForegroundColor Yellow
# Build a quick GPO -> best-link descriptor for ranking
$GpoLinkInfo = @{}
foreach ($m in $Manifest) {
    $best = $null
    foreach ($lnk in @($m.Links)) {
        if (-not $lnk.Enabled) { continue }
        # Rank key: enforced first (0), then link order asc, then deeper OU first (negative depth)
        $rank = @([int](-not $lnk.Enforced), [int]$lnk.Order, [int](-$lnk.Depth))
        if (-not $best -or
            ($rank[0] -lt $best.Rank[0]) -or
            ($rank[0] -eq $best.Rank[0] -and $rank[1] -lt $best.Rank[1]) -or
            ($rank[0] -eq $best.Rank[0] -and $rank[1] -eq $best.Rank[1] -and $rank[2] -lt $best.Rank[2])) {
            $best = [PSCustomObject]@{ Rank=$rank; Target=$lnk.Target; Enforced=$lnk.Enforced; Order=$lnk.Order }
        }
    }
    $GpoLinkInfo[$m.Name] = [PSCustomObject]@{
        LinksCount = $m.LinksCount
        BestLink   = $best
        Linked     = ($m.LinksCount -gt 0)
        HasEnabledLink = ($null -ne $best)
    }
}

function Compare-GpoPrecedence {
    param($GpoNameA, $GpoNameB)
    # returns the winning GPO name between two (the one that applies last / highest precedence)
    $a = $GpoLinkInfo[$GpoNameA]; $b = $GpoLinkInfo[$GpoNameB]
    if (-not $a.HasEnabledLink -and -not $b.HasEnabledLink) { return $null }
    if (-not $a.HasEnabledLink) { return $GpoNameB }
    if (-not $b.HasEnabledLink) { return $GpoNameA }
    $ra = $a.BestLink.Rank; $rb = $b.BestLink.Rank
    for ($k=0; $k -lt 3; $k++) { if ($ra[$k] -ne $rb[$k]) { return ($(if ($ra[$k] -lt $rb[$k]) { $GpoNameA } else { $GpoNameB })) } }
    return $GpoNameA  # tie - effectively indeterminate, pick one deterministically
}

# Attach winner info to each conflict row
foreach ($entry in $ConflictRows) {
    $configuredGpos = @($entry.Values.Keys)
    $winner = $null
    foreach ($g in $configuredGpos) {
        if (-not $winner) { $winner = $g; continue }
        $w = Compare-GpoPrecedence -GpoNameA $winner -GpoNameB $g
        if ($w) { $winner = $w }
    }
    $winnerValue = if ($winner -and $entry.Values.Contains($winner)) { $entry.Values[$winner] } else { $null }
    $anyApplies = $false
    foreach ($g in $configuredGpos) { if ($GpoLinkInfo[$g].HasEnabledLink) { $anyApplies = $true; break } }
    $entry | Add-Member -NotePropertyName Winner      -NotePropertyValue $winner -Force
    $entry | Add-Member -NotePropertyName WinnerValue -NotePropertyValue "$winnerValue" -Force
    $entry | Add-Member -NotePropertyName Applies     -NotePropertyValue $anyApplies -Force
}

# ─────────────────────────────────────────────────────────────────────────────
# EXTRA 2: EMPTY / REDUNDANT / UNLINKED GPO detection
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "      Analyzing GPOs for empty / redundant / unlinked status..." -ForegroundColor Yellow
# Per-GPO set of "key => value" for every setting it configures
$GpoSettings = @{}
foreach ($m in $Manifest) { $GpoSettings[$m.Name] = @{} }
foreach ($entry in $PivotRows) {
    $sigKey = "$($entry.Category)|$($entry.Hive)|$($entry.Key)|$($entry.Setting)"
    foreach ($src in $entry.Values.Keys) {
        if ($GpoSettings.ContainsKey($src)) { $GpoSettings[$src][$sigKey] = "$($entry.Values[$src])" }
    }
}

$GpoAnalysis = @()
foreach ($m in $Manifest) {
    $settings = $GpoSettings[$m.Name]
    $count = $settings.Count
    $linked = ($m.LinksCount -gt 0)
    $hasEnabledLink = $GpoLinkInfo[$m.Name].HasEnabledLink
    $issues = @()
    if ($count -eq 0) { $issues += 'Empty (configures no settings)' }
    if (-not $linked) { $issues += 'Unlinked (not linked anywhere)' }
    elseif (-not $hasEnabledLink) { $issues += 'No enabled link (linked but all links disabled)' }

    # Redundancy: is this GPO's entire settings set a subset of another GPO that has >= these settings identically?
    $redundantWith = $null
    if ($count -gt 0) {
        foreach ($other in $Manifest) {
            if ($other.Name -eq $m.Name) { continue }
            $otherSet = $GpoSettings[$other.Name]
            if ($otherSet.Count -lt $count) { continue }
            $allMatch = $true
            foreach ($k in $settings.Keys) {
                if (-not $otherSet.ContainsKey($k) -or $otherSet[$k] -ne $settings[$k]) { $allMatch = $false; break }
            }
            if ($allMatch) { $redundantWith = $other.Name; break }
        }
    }
    if ($redundantWith) { $issues += "Fully redundant (all settings duplicated by '$redundantWith')" }

    $statusDisabled = ($m.GpoStatus -eq 'AllSettingsDisabled')
    if ($statusDisabled) { $issues += 'GPO status: All settings disabled' }
    $statusPartial = ($m.GpoStatus -eq 'UserSettingsDisabled' -or $m.GpoStatus -eq 'ComputerSettingsDisabled')

    $GpoAnalysis += [PSCustomObject]@{
        name          = $m.Name
        settingCount  = $count
        linksCount    = $m.LinksCount
        linked        = $linked
        hasEnabledLink= $hasEnabledLink
        gpoStatus     = $m.GpoStatus
        redundantWith = $redundantWith
        issues        = $issues
        healthy       = ($issues.Count -eq 0)
        # structured flags for dashboard aggregation
        isEmpty       = ($count -eq 0)
        isUnlinked    = (-not $linked)
        isDisabledLink= ($linked -and -not $hasEnabledLink)
        isRedundant   = ($null -ne $redundantWith)
        isDisabled    = $statusDisabled
        isPartial     = $statusPartial
        modified      = "$($m.Modified)"
    }
}
$ProblemGpoCount = @($GpoAnalysis | Where-Object { -not $_.healthy }).Count
Write-Host "      $ProblemGpoCount GPO(s) flagged (empty / unlinked / redundant / disabled)" -ForegroundColor $(if ($ProblemGpoCount -gt 0) { 'Yellow' } else { 'Green' })

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4: Assemble JSON for the report
# ─────────────────────────────────────────────────────────────────────────────
$PivotForJson = $PivotRows | ForEach-Object {
    [PSCustomObject]@{
        category        = $_.Category
        scope           = $_.Scope
        hive            = $_.Hive
        key             = $_.Key
        setting         = $_.Setting
        friendlyName    = $_.FriendlyName
        valueType       = $_.ValueType
        conflict        = $_.Conflict
        configuredCount = $_.ConfiguredCount
        distinctCount   = $_.DistinctCount
        winner          = $_.Winner
        winnerValue     = $_.WinnerValue
        applies         = $_.Applies
        values          = $_.Values
    }
}
$GPONamesForJson = @($Manifest | ForEach-Object { $_.Name })

# Link descriptor per GPO for the report (where linked, enforced, order)
$GpoLinksForJson = @{}
foreach ($m in $Manifest) {
    $GpoLinksForJson[$m.Name] = @(@($m.Links) | ForEach-Object {
        [PSCustomObject]@{ target=$_.Target; order=$_.Order; enforced=$_.Enforced; enabled=$_.Enabled }
    })
}

# ─────────────────────────────────────────────────────────────────────────────
# EXTRA 3: SECURITY BASELINE COMPLIANCE (hardcoded starter baseline)
# Matches a small, well-known hardening set against the parsed settings. A check
# is Compliant if ANY loaded GPO sets it to the expected value, Wrong Value if it
# is configured but never to the expected value, and Missing if no GPO sets it.
# Extend $Baseline with more items or swap in a Microsoft Security Baseline later.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "      Checking settings against starter hardening baseline..." -ForegroundColor Yellow
$Baseline = @(
  [pscustomobject]@{ cat='Password Policy';       name='Minimum password length';                type='sysaccess'; setting='minimumpasswordlength'; cmp='gte';   exp='14';    why='Short passwords fall to spraying/brute force; 14+ is the common hardening floor.' }
  [pscustomobject]@{ cat='Password Policy';       name='Enforce password history';               type='sysaccess'; setting='passwordhistorysize';  cmp='gte';   exp='24';    why='Prevents reuse of recent passwords.' }
  [pscustomobject]@{ cat='Password Policy';       name='Maximum password age (days)';            type='sysaccess'; setting='maximumpasswordage';   cmp='range'; exp='1|365'; why='0 = never expires; keep within a bounded window.' }
  [pscustomobject]@{ cat='Password Policy';       name='Minimum password age (days)';            type='sysaccess'; setting='minimumpasswordage';   cmp='gte';   exp='1';     why='Stops users cycling straight back to an old password.' }
  [pscustomobject]@{ cat='Password Policy';       name='Password must meet complexity';          type='sysaccess'; setting='passwordcomplexity';   cmp='eq';    exp='1';     why='Enforces character-class variety.' }
  [pscustomobject]@{ cat='Password Policy';       name='Store passwords with reversible encryption'; type='sysaccess'; setting='cleartextpassword'; cmp='eq'; exp='0';       why='Reversible storage is plaintext-equivalent; must be disabled.' }
  [pscustomobject]@{ cat='Account Lockout';       name='Account lockout threshold';              type='sysaccess'; setting='lockoutbadcount';      cmp='range'; exp='1|10';  why='0 = no lockout; a low bound blocks online guessing.' }
  [pscustomobject]@{ cat='Account Lockout';       name='Account lockout duration (min)';         type='sysaccess'; setting='lockoutduration';      cmp='gte';   exp='15';    why='Keeps a locked account locked long enough to matter.' }
  [pscustomobject]@{ cat='Account Lockout';       name='Reset lockout counter after (min)';      type='sysaccess'; setting='resetlockoutcount';    cmp='gte';   exp='15';    why='Window over which bad attempts accumulate.' }
  [pscustomobject]@{ cat='Network Security';      name='LAN Manager authentication level';       type='reg'; valueName='lmcompatibilitylevel'; keyContains='lsa';               cmp='eq'; exp='5';  why='5 = send NTLMv2 only, refuse LM/NTLM.' }
  [pscustomobject]@{ cat='Network Security';      name='Do not store LM hash on next change';    type='reg'; valueName='nolmhash';             keyContains='lsa';               cmp='eq'; exp='1';  why='LM hashes are trivially cracked.' }
  [pscustomobject]@{ cat='Network Security';      name='Restrict anonymous enumeration (SAM)';   type='reg'; valueName='restrictanonymoussam'; keyContains='lsa';               cmp='eq'; exp='1';  why='Blocks anonymous account enumeration.' }
  [pscustomobject]@{ cat='Network Security';      name='Restrict anonymous enumeration (shares)';type='reg'; valueName='restrictanonymous';    keyContains='lsa';               cmp='eq'; exp='1';  why='Blocks anonymous share/named-pipe enumeration.' }
  [pscustomobject]@{ cat='User Account Control';  name='Run all admins in Admin Approval Mode';  type='reg'; valueName='enablelua';            keyContains='policies\system';   cmp='eq'; exp='1';  why='Disabling EnableLUA turns UAC off entirely.' }
  [pscustomobject]@{ cat='User Account Control';  name='Admin Approval Mode for built-in Admin'; type='reg'; valueName='filteradministratortoken'; keyContains='policies\system';cmp='eq'; exp='1';  why='Applies UAC to the built-in Administrator.' }
  [pscustomobject]@{ cat='Credential Protection'; name='WDigest cleartext credentials';          type='reg'; valueName='uselogoncredential';   keyContains='wdigest';           cmp='eq'; exp='0';  why='1 leaves plaintext creds in LSASS memory.' }
  [pscustomobject]@{ cat='Credential Protection'; name='LSASS run as protected process (RunAsPPL)'; type='reg'; valueName='runasppl';         keyContains='lsa';               cmp='eq'; exp='1';  why='Hardens LSASS against credential dumping.' }
  [pscustomobject]@{ cat='Legacy Protocols';      name='SMBv1 server disabled';                  type='reg'; valueName='smb1';                keyContains='lanmanserver';      cmp='eq'; exp='0';  why='SMBv1 is obsolete and wormable.' }
  [pscustomobject]@{ cat='Legacy Protocols';      name='SMB server signing required';            type='reg'; valueName='requiresecuritysignature'; keyContains='lanmanserver';  cmp='eq'; exp='1';  why='Prevents SMB relay/tampering.' }
  [pscustomobject]@{ cat='Legacy Protocols';      name='LLMNR disabled';                         type='reg'; valueName='enablemulticast';     keyContains='dnsclient';         cmp='eq'; exp='0';  why='LLMNR enables name-poisoning/credential theft.' }
)
function Get-ExpDisp {
    param($it)
    switch($it.cmp){ 'gte'{">= $($it.exp)"} 'lte'{"<= $($it.exp)"} 'eq'{"= $($it.exp)"} 'ne'{"<> $($it.exp)"} 'range'{ ($it.exp -replace '\|','-') } default{"$($it.exp)"} } }
function Test-BaselineValue { param($v,$it)
    $vv="$v".Trim()
    switch($it.cmp){
        'eq'   { return ($vv -eq $it.exp) }
        'ne'   { return ($vv -ne $it.exp) }
        'gte'  { $n=0; if([int]::TryParse($vv,[ref]$n)){ return $n -ge [int]$it.exp } return $false }
        'lte'  { $n=0; if([int]::TryParse($vv,[ref]$n)){ return $n -le [int]$it.exp } return $false }
        'range'{ $n=0; if([int]::TryParse($vv,[ref]$n)){ $mm=$it.exp -split '\|'; return ($n -ge [int]$mm[0] -and $n -le [int]$mm[1]) } return $false }
        default{ return $false }
    }
}
function Get-BaselineMatches { param($it)
    $vals=@()
    foreach($row in $PivotRows){
        $ok=$false
        if($it.type -eq 'sysaccess'){ if($row.Category -eq 'SystemAccess' -and "$($row.Setting)".ToLower() -eq $it.setting){ $ok=$true } }
        else { if("$($row.Setting)".ToLower() -eq $it.valueName -and "$($row.Key)".ToLower().Contains($it.keyContains)){ $ok=$true } }
        if($ok){ foreach($kv in $row.Values.GetEnumerator()){ if($null -ne $kv.Value -and "$($kv.Value)" -ne ''){ $vals += [pscustomobject]@{ gpo=$kv.Key; value="$($kv.Value)" } } } }
    }
    return $vals
}
$BaselineResults=@(); $bl_comp=0; $bl_wrong=0; $bl_miss=0
foreach($it in $Baseline){
    $m = @(Get-BaselineMatches $it)
    $status='Missing'; $found=''
    if(@($m).Count -gt 0){
        $pass=@($m | Where-Object { Test-BaselineValue $_.value $it })
        if($pass.Count -gt 0){ $status='Compliant'; $found=(($pass | ForEach-Object { "$($_.gpo)=$($_.value)" }) -join '; ') }
        else { $status='Wrong Value'; $found=(($m | ForEach-Object { "$($_.gpo)=$($_.value)" }) -join '; ') }
    }
    switch($status){ 'Compliant'{$bl_comp++} 'Wrong Value'{$bl_wrong++} 'Missing'{$bl_miss++} }
    $BaselineResults += [pscustomobject]@{ cat=$it.cat; name=$it.name; expected=(Get-ExpDisp $it); status=$status; found=$found; why=$it.why }
}
Write-Host "      Baseline: $bl_comp compliant, $bl_wrong wrong value, $bl_miss missing (of $($Baseline.Count))" -ForegroundColor Green

# ── GPO / SYSVOL integrity: AD GPO objects vs SYSVOL policy folders ────────────
# Compares the GPOs that exist as AD objects against the {GUID} policy folders in
# SYSVOL. AD-only = broken GPO with missing SYSVOL data; SYSVOL-only = orphaned
# folder left behind. A count mismatch is the "not the same number of objects" case.
$GpoIntegrity = [ordered]@{ sysvolChecked=$false; adCount=0; sysvolCount=0; adOnly=@(); sysvolOnly=@(); sysvolPath='' }
try {
    $__sysvolPolicies = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies"
    $GpoIntegrity.sysvolPath = $__sysvolPolicies
    $__adMap = @{}
    foreach ($__g in @($TargetGPOs)) {
        $__gid = "$($__g.Id)".ToLowerInvariant().Trim('{','}')
        if ($__gid) { $__adMap[$__gid] = "$($__g.DisplayName)" }
    }
    $GpoIntegrity.adCount = $__adMap.Count
    if (Test-Path -LiteralPath $__sysvolPolicies) {
        $__sysGuids = @()
        Get-ChildItem -LiteralPath $__sysvolPolicies -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $__n = $_.Name.Trim('{','}').ToLowerInvariant()
            if ($__n -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $__sysGuids += $__n }
        }
        $__sysSet = @{}; foreach ($__s in $__sysGuids) { $__sysSet[$__s] = $true }
        $GpoIntegrity.sysvolChecked = $true
        $GpoIntegrity.sysvolCount   = $__sysGuids.Count
        $__adOnly = @(); foreach ($__k in $__adMap.Keys) { if (-not $__sysSet.ContainsKey($__k)) { $__adOnly += [PSCustomObject]@{ guid=$__k; name=$__adMap[$__k] } } }
        $__sysOnly = @(); foreach ($__s in $__sysGuids) { if (-not $__adMap.ContainsKey($__s)) { $__sysOnly += [PSCustomObject]@{ guid=$__s } } }
        $GpoIntegrity.adOnly     = @($__adOnly)
        $GpoIntegrity.sysvolOnly = @($__sysOnly)
    } else {
        Write-Warning "  SYSVOL policies path not reachable: $__sysvolPolicies"
    }
} catch {
    Write-Warning "  SYSVOL integrity check skipped: $($_.Exception.Message)"
}

# ── Built-in policy health: Default Domain Policy & Default DC Policy ──────────
# Read-only health of the two well-known default GPOs: present, enabled, AD vs
# SYSVOL version consistency (a mismatch signals corruption/replication trouble),
# still configures settings, and linked (enabled) at its expected location.
$__ddpGuid = '31b2f340-016d-11d2-945f-00c04fb984f9'
$__ddcGuid = '6ac1786c-016f-11d2-945f-00c04fb984f9'
$__domDN   = if ($Domain) { $Domain.DistinguishedName } else { '' }
$WellKnownGpos = @(
    [PSCustomObject]@{ Key='ddp';  Label='Default Domain Policy';             Guid=$__ddpGuid; ExpectLink=$__domDN;                            ExpectLabel='domain root' },
    [PSCustomObject]@{ Key='ddcp'; Label='Default Domain Controllers Policy'; Guid=$__ddcGuid; ExpectLink=("OU=Domain Controllers,$__domDN"); ExpectLabel='Domain Controllers OU' }
)
$BuiltinHealth = @()
foreach ($wk in $WellKnownGpos) {
    $m = $Manifest | Where-Object { "$($_.Id)".ToLowerInvariant().Trim('{','}') -eq $wk.Guid } | Select-Object -First 1
    $present  = [bool]$m
    $issues   = @()
    $linkedOk = $false
    $sc       = 0
    if (-not $present) {
        $issues += 'GPO is missing (not found in the domain)'
    } else {
        switch ("$($m.GpoStatus)") {
            'AllSettingsDisabled'      { $issues += 'All settings are disabled' }
            'ComputerSettingsDisabled' { $issues += 'Computer settings are disabled' }
            'UserSettingsDisabled'     { $issues += 'User settings are disabled' }
        }
        if ($null -ne $m.CompDS -and $null -ne $m.CompSys -and $m.CompDS -ne $m.CompSys) { $issues += "Computer AD/SYSVOL version mismatch (AD $($m.CompDS) vs SYSVOL $($m.CompSys)) - possible corruption or replication issue" }
        if ($null -ne $m.UserDS -and $null -ne $m.UserSys -and $m.UserDS -ne $m.UserSys) { $issues += "User AD/SYSVOL version mismatch (AD $($m.UserDS) vs SYSVOL $($m.UserSys)) - possible corruption or replication issue" }
        if ($GpoSettings.ContainsKey($m.Name)) { $sc = @($GpoSettings[$m.Name]).Count }
        if ($sc -eq 0) { $issues += 'Configures no settings (unexpected for a built-in default)' }
        foreach ($lnk in @($m.Links)) { if ("$($lnk.Target)" -eq $wk.ExpectLink -and $lnk.Enabled) { $linkedOk = $true; break } }
        if (-not $linkedOk) { $issues += "Not linked (enabled) at the expected $($wk.ExpectLabel)" }
    }
    $BuiltinHealth += [PSCustomObject]@{
        key          = $wk.Key
        label        = $wk.Label
        present      = $present
        status       = $(if ($m) { "$($m.GpoStatus)" } else { '' })
        compDS       = $(if ($m) { $m.CompDS } else { $null })
        compSys      = $(if ($m) { $m.CompSys } else { $null })
        userDS       = $(if ($m) { $m.UserDS } else { $null })
        userSys      = $(if ($m) { $m.UserSys } else { $null })
        settingCount = $sc
        linkedOk     = $linkedOk
        expectLabel  = $wk.ExpectLabel
        issues       = @($issues)
        healthy      = ($present -and $issues.Count -eq 0)
    }
}

$Summary = [ordered]@{
    domain              = $DomainDNS
    generatedAt         = $GeneratedAt
    gpoCount            = $Manifest.Count
    gpoNames            = $GPONamesForJson
    totalSettings       = $PivotRows.Count
    conflictCount       = $ConflictRows.Count
    registryCount       = @($PivotRows | Where-Object { $_.Category -eq 'Registry' }).Count
    securityOptionCount = @($PivotRows | Where-Object { $_.Category -eq 'SecurityOption' }).Count
    userRightCount      = @($PivotRows | Where-Object { $_.Category -eq 'UserRight' }).Count
    systemAccessCount   = @($PivotRows | Where-Object { $_.Category -eq 'SystemAccess' }).Count
    kerberosCount       = @($PivotRows | Where-Object { $_.Category -eq 'KerberosPolicy' }).Count
    auditCount          = @($PivotRows | Where-Object { $_.Category -eq 'AuditPolicy' }).Count
    computerCount       = @($PivotRows | Where-Object { $_.Scope -eq 'Computer' }).Count
    userCount           = @($PivotRows | Where-Object { $_.Scope -eq 'User' }).Count
    problemGpoCount     = $ProblemGpoCount
    gpoAnalysis         = $GpoAnalysis
    gpoLinks            = $GpoLinksForJson
    rows                = $PivotForJson
    baseline            = [ordered]@{ name='Starter hardening baseline'; total=$Baseline.Count; compliant=$bl_comp; wrong=$bl_wrong; missing=$bl_miss; results=@($BaselineResults) }
    builtinHealth       = @($BuiltinHealth)
    integrity           = $GpoIntegrity
}
$DataJSON = ConvertTo-Json -InputObject $Summary -Depth 10 -Compress
Write-Host "[5/5] Rendering HTML..." -ForegroundColor Cyan

$HTML = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GPO Policy Analysis — $DomainDNS</title>
<style id="bi-icons">/* Bootstrap Icons 1.10.0 - subset (38 glyphs) embedded for offline use */
@font-face{font-display:block;font-family:"bootstrap-icons";src:url(data:font/woff2;base64,d09GMgABAAAAAA6AAAsAAAAAIMwAAA4xAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHCoGYACCVAq4YK4BATYCJANSC1AABCAFgRAHIBtaGrMDLWwcmHHgsGT/RYJtiNgftlmjGKWNhoNWOS6OYrnGk5eic3HPiX5+g3uLbrjZX0ZIMvv/42b9DXkkL0bSpIJVoBDq1E6bdpVOqDBiyagx44wqo0Y7Mys6Qnb//13RsuJS/jkr2jUFyjr3DF650JmCS+mTu2j+n633IekuSYfERNp8cWYopvuvaqCFlgszuxHb3ZGIS5WT/PfnN7uVLEtiEkITnaqxBc7ZlO39/VxpN5crk0MWtuyrXFX+S3b349JRcsQ5znGuRNkUyNUBoDzsXgFQdqo8oK6QdRWuNc5VzZwnh8euUuTHbwpj80OfiVEYjQnW/58HBACwoFKBTe8cYYBj6ew1y8EJAgDIgZsVETU6DnYxHiavl6JqO/I4ccDIo9vAToLS7JgvOg8evVvmedUMTY+6oFiiiRDC9pRIkh8YoQxAxNWhEeD32w78D1vuU7Wk9pfUZ/VNsz9d1ieb+r3+/edaN/hKj/ZUJ/yq3/CgvwzxS1XC0RLPkqyNFc9nM3lumDJnARktoPb/Szn2OI6rCmeELYImlAke/l/+FX4jH+Ob+UIuy33CvcE9wd3P3cp1cVFO4xo4N/sj+x37GXs/ew97O7uBtTqavYp5iVnHJJjJILixEKRRHqs7831v9rM+hGQisAFJggOjTNWFlDFEtitCpJ0BGBC41UCIjPpBLLDXIaoQQkGnIChYQNIdC7ZnhRQqdgpmfDHjcMiFsbBQZCUF57uqgpDHyIF8LF7Axzgx8nqEZiWG4QVvgYNhFbaDVGIz+RJN0QITYN15BUJxiVwQ5RRmHdJZnQLP8xJC9MrqU1d4HUJeC017eahymbGAhLCANsICn1xWjDLiMJmmIMxgAU2BAJszLgH4mhCLO/qM0nHYR0/iCkmA6DyHCEf0Nh0tBmVI+bYyNf4bOX5Bph33UPj5HeDNrLvxRJ9IMVrxT9gY2SVvwnd2pDDPG+yO4QBsUbciQKmPecflnUHhnlM5J7OW3PCyabRK2Y0bC5Y7ToaErBDSQFUFUIhWTuOI7k9TQB6GdsOdng05DGJPt+btSbQ4hnM3J5f34kdOLJuaj8/O8mZ0C+D7kgKD+q+VkvixHiAnyhwrquQiXDc9XninZpZlQK55DJXpEwlofI4uV04wUSDnsABkUmbjEfICYNMgl4gkfnAu96p5YKzwUxMFFcLVyNaS1BKCXQoPtMihrtdMBhC2JBsb1i8z2nUXE4EMSJWztqzYkqCAAlyruNHJviNlghwaThlVg1uEFNch69nSEcZzrQk4sGnJad3Y+l7Ccn5pqYZEEXqtivsq1zg1Fmz7uEDkur5WS6nolekxxRQbtPzvPiK3bC8lNv+XQ8lCJxOMNdAqMhgC6oWWHK80k3RxB2y1u6ufHX5M6q6/74FlsRkt3xS9lPz1kSXUD97V7NvTV+8+XpoZUzkIsaq/BbxM/Sre7VXiOlrxyylEChzmhvz1N5j6F13+NnmTS0pTmE2tfRrUyTwe9ZJzxKbmx6LvnVLpZKybTqiURuNNI3TWXpZsHdwzz+cP11Us/4xm/hWYkU/Eu8yjG2ULRnlgv4bLBD0dztlz3efaJlBOz4kE/FMozFHhuXD4A1EnRxumft3lRZFYFGypp05lNfxMKJCUYXC9b21n7BP/zD2+f5XoJD2oOmPJ19ia17UEYlRjpXsenl7of4CYWZWPvNCCCYG43EknxE4KMBsM0G7mmTxlklO/LnITnrtH957Yp//Z1vfjIXSFjRxkNQZ1arxxFtZPFuM6J896t0gfkVR3vtiPzcYQNnqlBejux3/9/9cizwOmoVCkpugAlMDPha8sFF7+cR+B3aHgujB1ALpdX4X51s1w6dazd/tJu/D049pKCwzZydJeeeAfXXPXH4eHV6vL6yI/v/zM5m4zCtFgv/Ctw8pza5KcbrjnD9wP+yfrEcWFVae3tZviZT+V/ZZrKy6uzVnNitG+wVLCVsRyzs/tyjQazyY4A0WSH6ja1ziv8nXdrcvyQ3kInWBkdqtKC9/aSTA77k95Qkxz5qanxpAWS7VnCTffKnlL+Dj+5+o3LHqT6DuXiw/VZrxw/s3abb4b2NSnzwEJ2hOuvj8WdNYsGQXKECMOAoipwdwUDd/oyQ+TOn7dpIaM3yxNidr06hjJSmVsbSeE4pHy4HppwsOr9soDgNl1d22DFgSEnNJefXiHPF4kj04nP7gy0O/Lcuyaur0sax45CaI4jPi1eBcpq6NZbaRJpiVx2o/Gg0rLY9t0alTgMO7laSMd3QtjQct1ge9UWepJ960o81e9RNEWVmmLHmRRFOvIjXSs17Matmg1kcaakgzCmK8pKSvqoNr6aVJNalpQg5u+RCa5lR/iMnyOz3Aiv5U0cXRWgHSUgQLDOHB5/cwzkEFHUdeZPj82sb/vTBcysI4gJQfurO6uvrN707ixUg+F9HEh3QXH7W9j1ssEcfW4eFP/eq4pr4lvjk17pezjEu004IrRHCSc2gxNwRbWmDiDpkWXPtWme4jpKLnYmpyRhEhGiktmrEhOB0DDOnNaxZdCOtpNhrfPCokv+aF+uR84mc/xShiZSEYmjiJmBoOi2FYbhZX+If49b/+zxNjIw40nNZblRuAHUBQKqeKLyToxwihIIiIXSgwQoeBagFciA4WxhQdpC4fbOnZYNKVPJVMMI/1AuR/717PUwPK+87wa5/fJo3fnh4uO/NP86fwd77eE09iG0+GWk2fxOYqKIBObiIpQ5+gV2JLuI+G0nQDlHIGK2wzXtrjJ5wvDLktsQNoado2GUmoE1Dt3SqbUy9hi1hGV4p7xnMgH49iiB9kD95p3wk9bk9vFQ6Y0IFow7KIhZUTT8VPa8URf1aEz2Hriktp1gMoNb23un3bgY8EIJEnpZd1zB3p3rxvEhtoKg5+It8QG47NWX0YmApmiLVrFzx44WDE9SFn4ANSYFqSxcoRtHmwNwInjUlqmVSWiJiBjhB5peiUEggWIAFgQBefwtABEEJ3DtE9RudZpkAbic84cj1pl2Gk56p5uhE/7T4eNmaRBfsZv9POpg8Iq4aA+QUaL3P+wn7H/uBchWWzvru1/pwtXXi2TwtXd+fiXZloXXcr2XpPEqvDC/TKW98kN/AN+bNA+k/Dj4ysysoTqZURFkfE5nJE1nOkxPcOK6AXT2WhiA7FMlRtFav2J90m+YNx9ULRHwlBtTGU2XUJ6F3/BZ5/eXFYgoodWNe/6durh6Sz/RWxMwZ+T3s1jdnEuoPjczij5hQEZA5r9WN5K5S/v/w1b0jlt3oKzjoaGw7EOrmPp0qTIKrbimFa54WqjV0b8K6TR4KvkqWFi/36og3DOd2Bju/0eq/zkRx3jFshWqVlqfVddt98Df2s94+W8vG+rhQNRMyAi/qFm4Rg5kjNSJtGH6qsGKuvITJpGJjZQ2r0sifzKnF+Re+fYi2SAgU0vFq7XWSaDjWfAVmLjK4tirxDPK1ZIObGFExQUpRU9HMJmpMNmmRo4ik3P75mwGYVGFtQtAJqjBooedvJDYzHRDC43hnd4fA8n+3eM4go4g6Rt7HosbDvl2aYvrz61XMDrI3aCAEpt39AyBloXtqtULCGZpfeRXYEiCL8V8dMhZ3L0Lf005d/mObVNkJXRrWyJFn+KKdXsofaFLaGrjFCkjkmbxWRpsJFqPqY1lOFJFG3BvcnGbYqV/44UnZaak97Jf1C5oY4Xud0p5vPzVn885+PV8yCVKoKw+CpngmdEs8x0RJvGzuN9EXvGHin5a75l6sMTHp56y9EaSu3ZkP51YvvEX7sNPSoFh53jHvTqXM+hyZPztm3aVFowdvKB7f3l7+9hdc9tBXWVI1I7pUJdqtmQ2vTGXZIpqnIiGmF0JUsJjWgSllUk7Qr0SKraG/Lh8ncunc7SVI1oCbThNE4wsY0+/Bngg0UVWyb//uSmF9gXjqWe2QU9MV2yJD16wvvw19pf/9X+96f21SMwV7hwJoLmv3zhmHPH3lVz5qzau8N57MLL81Hk/r1t3gOLyhate2/l7fTi7IM3t92yp41v23NL280PZhfTt6+8tG/kDHLy/Abhw1l9k5fFmet2rUWddoe9E609ebPuiXwyz7URf9OP5UTCh82PDd6h+CEKivSFbnwtfNp3+ipVUa9K+VJhSxkf46BILMpRcNIlrMDIO7F52FIkOsVdZWLWq7JaX9cos2SI/P2NTz1vyv862ChH+nU/jpZErz6BTCEPYx2pxlkkefJ0Ok0A04x6jc3WO5l81YEWDR+cZuE5tegcGK4NV6Dj9Gmy1mBF4MuRJMfY4RmaQdYKsVfzlLwEk1M+4lrm6uTJffwQ50VRxIt0jjemlxvif573KCZ75pw9yGLL3x6ko595+vwfe/w9P3JbLCKfFiiNFY1KgeZtrWkFTx3DleVlu+UrY65Dl9wJ96VDjdsMqPP/Ir53UfhxzrUjO5/L9n33UrbyfKTD5SvIH0ZmyGH5BT5XR+R8Zfal7/qyz3WOvHbOjwulH/GoE9kbHijNnhiFf6yMRyh/lKFnlqoasq4zXbVh2W7/eLjlETVyk0XWqrYQfqZ0lB67ow4qML2qkm7ueBqJJKOWn+1dathnJK1GctZD/qU4UFOkN8hJE6CCJrp7CwhyvVTqV1RWtJsHWgs/VKrxvnKWHgKebbxxQ/9M8Vgwxy7ccvotva4//F89xF4AMNgAInuT85oAwKo3biNuIJTb+U3uDVtt62e6lwQ2ElEeUpDa4t3hZqdgFCQQiNmRSjRznA0cUOIkWU6EcXYopIZRMOawQo01rGZzq5hNgloWMXcuLbePYz5x1rJ0VdkhE0Zk1QpbRJYto4E66iE58tHZAAAAAA==) format("woff2")}
.bi::before,[class^="bi-"]::before,[class*=" bi-"]::before{display:inline-block;font-family:bootstrap-icons!important;font-style:normal;font-weight:normal!important;font-variant:normal;text-transform:none;line-height:1;vertical-align:-.125em;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
.bi-bar-chart-line::before{content:"\f17c"}
.bi-box-arrow-up-right::before{content:"\f1c5"}
.bi-check-circle::before{content:"\f26b"}
.bi-circle-half::before{content:"\f288"}
.bi-columns-gap::before{content:"\f2cd"}
.bi-dash-circle::before{content:"\f2e6"}
.bi-diagram-2::before{content:"\f2ec"}
.bi-download::before{content:"\f30a"}
.bi-exclamation-triangle::before{content:"\f33b"}
.bi-exclamation-triangle-fill::before{content:"\f33a"}
.bi-file-earmark::before{content:"\f392"}
.bi-files::before{content:"\f3c2"}
.bi-folder2::before{content:"\f3d9"}
.bi-grid-3x3-gap-fill::before{content:"\f3f8"}
.bi-inbox::before{content:"\f42d"}
.bi-info-circle::before{content:"\f431"}
.bi-journal-check::before{content:"\f43e"}
.bi-key::before{content:"\f44f"}
.bi-layers::before{content:"\f45b"}
.bi-link-45deg::before{content:"\f470"}
.bi-list-columns-reverse::before{content:"\f69f"}
.bi-pc-display::before{content:"\f6a6"}
.bi-people::before{content:"\f4d0"}
.bi-person::before{content:"\f4e1"}
.bi-person-badge::before{content:"\f4d3"}
.bi-pie-chart::before{content:"\f4e9"}
.bi-printer::before{content:"\f501"}
.bi-search::before{content:"\f52a"}
.bi-shield-check::before{content:"\f52f"}
.bi-shield-lock::before{content:"\f538"}
.bi-slash-circle::before{content:"\f567"}
.bi-sliders::before{content:"\f56b"}
.bi-sort-down::before{content:"\f575"}
.bi-table::before{content:"\f5aa"}
.bi-ticket-perforated::before{content:"\f6ca"}
.bi-toggle-off::before{content:"\f5d5"}
.bi-trophy-fill::before{content:"\f5e6"}
.bi-x-lg::before{content:"\f659"}
</style>
<style>
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#334155;--surface3:#475569;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#6366f1;--accent-soft:rgba(99,102,241,0.15);
--blue:#60a5fa;--green:#34d399;--yellow:#fbbf24;--red:#f87171;--purple:#a78bfa;--teal:#2dd4bf;--amber:#fbbf24;}
[data-theme="light"]{--bg:#f7fafd;--surface:#ffffff;--surface2:#f4f6fb;--surface3:#eef2f8;--border:rgba(24,36,60,.10);--text:#28323f;--muted:#8b95a6;--accent:#6366f1;--accent-soft:#eef0ff;--blue:#3b82f6;--green:#16a34a;--yellow:#f59e0b;--red:#ef4444;--purple:#8b5cf6;--teal:#14b8a6;--amber:#f59e0b;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:8px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;position:sticky;top:0;z-index:100;min-height:48px}
.brand{display:flex;align-items:center;gap:7px;font-size:13px;font-weight:700;white-space:nowrap}
.brand i{color:var(--amber);font-size:17px}
.sep{width:1px;height:22px;background:var(--border)}
.search{display:flex;align-items:center;gap:5px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:4px 9px;flex:1;min-width:160px;max-width:280px}
.search input{background:none;border:none;outline:none;color:var(--text);font-size:12px;width:100%}
.search input::placeholder{color:var(--muted)}.search i{color:var(--muted);font-size:12px}
.bgrp{display:flex;gap:4px;flex-wrap:wrap}
.btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:5px;font-size:11px;cursor:pointer;display:flex;align-items:center;gap:4px;transition:all .15s;white-space:nowrap}
.btn:hover{background:var(--border)}.btn.on{background:var(--blue);border-color:var(--blue);color:#fff}
.scope-toggle{display:flex;background:var(--surface2);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.sbtn{background:none;border:none;color:var(--muted);padding:4px 10px;font-size:11px;cursor:pointer;display:flex;align-items:center;gap:4px;transition:all .15s}
.sbtn:not(:last-child){border-right:1px solid var(--border)}
.sbtn:hover{color:var(--text)}
.sbtn.on{background:var(--blue);color:#fff;font-weight:600}
.scope-hdr td{background:color-mix(in srgb,var(--blue) 12%,var(--surface2));padding:8px 12px !important;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--blue);position:sticky;left:0}
.scope-hdr.user td{background:color-mix(in srgb,var(--teal) 12%,var(--surface2));color:var(--teal)}
.scope-hdr i{margin-right:6px}
.meta{font-size:10px;color:var(--muted);margin-left:auto;white-space:nowrap}
.wrap{max-width:1180px;margin:0 auto;padding:18px 48px}
@media(max-width:900px){.wrap{padding:14px 16px}}
.summary-bar{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:center;font-size:12px;padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:10px}
.summary-bar .sb-item{display:flex;align-items:center;gap:6px;color:var(--muted)}
.summary-bar .sb-item b{color:var(--text);font-weight:700}
.summary-bar .sb-item.bad b{color:var(--red)}
.summary-bar .sb-item.warn b{color:var(--amber)}
.summary-bar .sb-sep{width:1px;height:16px;background:var(--border)}
.stats-row{display:grid;grid-template-columns:1fr;gap:14px;margin-bottom:16px}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:13px 14px;box-shadow:0 1px 3px rgba(20,40,80,.05);position:relative;overflow:hidden;display:flex;flex-direction:column;gap:3px}
.kpi .kpi-ico{position:absolute;right:10px;top:9px;font-size:20px;opacity:.16}
.kpi .kpi-val{font-size:23px;font-weight:800;line-height:1}
.kpi .kpi-lbl{font-size:10px;color:var(--muted);font-weight:600;letter-spacing:.2px}
.kpi.k-blue .kpi-val{color:var(--blue)} .kpi.k-blue .kpi-ico{color:var(--blue)}
.kpi.k-red .kpi-val{color:var(--red)} .kpi.k-red .kpi-ico{color:var(--red)}
.kpi.k-amber .kpi-val{color:var(--amber)} .kpi.k-amber .kpi-ico{color:var(--amber)}
.kpi.k-green .kpi-val{color:var(--green)} .kpi.k-green .kpi-ico{color:var(--green)}
.kpi.k-purple .kpi-val{color:var(--purple)} .kpi.k-purple .kpi-ico{color:var(--purple)}
.kpi.k-teal .kpi-val{color:var(--teal)} .kpi.k-teal .kpi-ico{color:var(--teal)}
.charts-grid{display:grid;grid-template-columns:1.5fr 1fr;gap:14px}
@media(max-width:820px){.charts-grid{grid-template-columns:1fr}}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;box-shadow:0 1px 3px rgba(20,40,80,.05)}
.stat-card-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:12px;display:flex;align-items:center;gap:6px}
.stat-card-title i{color:var(--blue)}
.bar-row{display:flex;align-items:center;gap:8px;margin-bottom:7px;font-size:11px}
.bar-row:last-child{margin-bottom:0}
.bar-label{width:130px;flex-shrink:0;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right}
.bar-track{flex:1;background:var(--surface2);border-radius:4px;height:16px;position:relative;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--blue),color-mix(in srgb,var(--blue) 70%,var(--teal)));min-width:3px;transition:width .4s}
.bar-val{width:30px;flex-shrink:0;font-weight:700;font-size:10px;color:var(--muted);text-align:right}
.donut-wrap{display:flex;align-items:center;gap:18px;justify-content:center}
.donut-legend{font-size:11px;display:flex;flex-direction:column;gap:7px}
.donut-legend .dl{display:flex;align-items:center;gap:7px}
.donut-legend .dot{width:11px;height:11px;border-radius:3px;flex-shrink:0}
.cat-stack{display:flex;height:26px;border-radius:6px;overflow:hidden;border:1px solid var(--border);margin-bottom:10px}
.cat-stack .seg{height:100%}
.cat-legend{display:grid;grid-template-columns:1fr 1fr;gap:5px 14px;font-size:10.5px}
.cat-legend .cl{display:flex;align-items:center;gap:6px;color:var(--muted)}
.cat-legend .cl b{color:var(--text);margin-left:auto}
.cat-legend .dot{width:9px;height:9px;border-radius:2px;flex-shrink:0}
.scope-split{display:flex;gap:10px;margin-top:4px}
.scope-pill{flex:1;background:var(--surface2);border-radius:8px;padding:10px 12px;text-align:center}
.scope-pill .sp-val{font-size:18px;font-weight:800}
.scope-pill .sp-lbl{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-top:2px}

.section-title{font-size:18px;font-weight:700;color:#465262;margin:30px 0 12px;display:flex;align-items:center;gap:8px}
.section-title::after{content:'';flex:1;height:1px;background:var(--border)}
.section-title i{color:inherit;font-size:16px}.section-title:first-child{margin-top:6px}
.gpo-health-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.ghc{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:11px 13px;border-left:3px solid var(--green)}
.ghc.warn{border-left-color:var(--amber)}
.ghc-name{font-size:12px;font-weight:700;display:flex;align-items:center;gap:6px;margin-bottom:6px;word-break:break-word}
.ghc-meta{font-size:10px;color:var(--muted);display:flex;gap:12px;flex-wrap:wrap;margin-bottom:6px}
.ghc-issue{font-size:10px;padding:3px 7px;border-radius:4px;background:color-mix(in srgb,var(--amber) 16%,transparent);color:var(--amber);margin-top:4px;display:flex;align-items:center;gap:5px}
.ghc-ok{font-size:10px;color:var(--green);display:flex;align-items:center;gap:5px}
.winner-badge{display:inline-flex;align-items:center;gap:4px;font-size:9px;font-weight:700;padding:1px 6px;border-radius:4px;background:color-mix(in srgb,var(--green) 18%,transparent);color:var(--green)}
.winner-none{background:color-mix(in srgb,var(--red) 16%,transparent);color:var(--red)}
.cellval.winner-val{font-weight:700;text-decoration:underline;text-decoration-color:var(--green);text-underline-offset:2px}

.hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:13px 15px;position:relative;overflow:hidden;cursor:pointer;transition:transform .12s}
.stat:hover{transform:translateY(-1px)}
.stat::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--blue)}
.stat.s-bad::before{background:var(--red)}.stat.s-warn::before{background:var(--amber)}.stat.s-good::before{background:var(--green)}
.stat-label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px}
.stat-val{font-size:20px;font-weight:700}
.bl-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;box-shadow:0 1px 3px rgba(20,40,80,.05);margin-bottom:14px}
.bl-scoreline{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:12px}
.bl-score{font-size:30px;font-weight:800}
.bl-bar{flex:1;min-width:220px;display:flex;height:20px;border-radius:5px;overflow:hidden;background:var(--surface2)}
.bl-seg{height:100%}
.bl-legend{display:flex;gap:16px;font-size:11px;color:var(--muted);flex-wrap:wrap;margin-bottom:12px}
.bl-legend .dot{width:10px;height:10px;border-radius:3px;display:inline-block;margin-right:5px}
.bl-filters{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.bl-tbl{width:100%;border-collapse:collapse;font-size:12px}
.bl-tbl th{text-align:left;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;border-bottom:1px solid var(--border)}
.bl-tbl td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top}
.bl-tbl tr:last-child td{border-bottom:none}
.bl-tag{font-size:10px;font-weight:700;padding:2px 9px;border-radius:999px;white-space:nowrap}
.bl-tag.ok{background:color-mix(in srgb,var(--green) 18%,transparent);color:var(--green)}
.bl-tag.wrong{background:color-mix(in srgb,var(--amber) 20%,transparent);color:var(--amber)}
.bl-tag.miss{background:color-mix(in srgb,var(--red) 16%,transparent);color:var(--red)}
.bl-why{color:var(--muted);font-size:11px;margin-top:3px}

.filter-row{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.chip{background:var(--surface2);border:1px solid var(--border);color:var(--muted);padding:5px 12px;border-radius:20px;font-size:11px;cursor:pointer;display:flex;align-items:center;gap:5px;transition:all .15s}
.chip:hover{color:var(--text)}
.chip.on{background:var(--blue);border-color:var(--blue);color:#fff;font-weight:600}
.chip .ct{background:rgba(0,0,0,.2);border-radius:8px;padding:0 5px;font-size:9px}

.gpo-picker{position:relative}
.gpo-pop{display:none;position:absolute;top:32px;left:0;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px;z-index:50;min-width:220px;max-height:320px;overflow-y:auto;box-shadow:0 8px 24px rgba(0,0,0,.4)}
.gpo-pop.on{display:block}
.gpo-pop label{display:flex;align-items:center;gap:7px;font-size:11px;padding:5px 4px;cursor:pointer;border-radius:4px}
.gpo-pop label:hover{background:var(--surface2)}
.gpo-pop-actions{display:flex;gap:6px;margin-bottom:8px;padding-bottom:8px;border-bottom:1px solid var(--border)}
.gpo-pop-actions button{flex:1;font-size:10px;padding:4px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);cursor:pointer}

.matrix-wrap{background:var(--surface);border:1px solid var(--border);border-radius:6px;overflow:auto;max-height:74vh}
table.matrix{width:auto;border-collapse:collapse;font-size:11px;table-layout:fixed}
table.matrix thead th{background:var(--surface2);color:var(--muted);text-align:left;padding:6px 8px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.3px;border-bottom:1px solid var(--border);border-right:1px solid var(--border);position:sticky;top:0;z-index:5;cursor:pointer;width:130px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
table.matrix thead th:hover{color:var(--text)}
table.matrix thead th.colname{position:sticky;left:0;z-index:6;width:300px;max-width:300px;min-width:300px}
table.matrix thead th.statuscol{width:90px;max-width:90px}
table.matrix tbody td{padding:3px 8px;border-bottom:1px solid var(--border);border-right:1px solid var(--border);vertical-align:top;width:130px;max-width:130px;overflow:hidden}
table.matrix tbody td.colname{position:sticky;left:0;background:var(--surface);z-index:4;border-right:1px solid var(--border);width:300px;max-width:300px;min-width:300px;overflow:visible}
table.matrix tbody tr:hover td.colname{background:var(--surface2)}
table.matrix tbody tr.conflict td.colname{border-left:3px solid var(--amber)}
table.matrix tbody tr:hover{background:color-mix(in srgb,var(--surface2) 60%,transparent)}
.fname{font-weight:600;display:flex;align-items:center;gap:6px;cursor:pointer;white-space:normal;line-height:1.3}
.fname i{color:var(--muted);font-size:10px;opacity:.7;flex-shrink:0}
.rawpath{font-size:9px;color:var(--muted);font-family:monospace;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cat-badge{display:inline-block;font-size:8px;font-weight:700;padding:1px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.3px;margin-bottom:3px}
.cb-Registry{background:color-mix(in srgb,var(--blue) 18%,transparent);color:var(--blue)}
.cb-SecurityOption{background:color-mix(in srgb,var(--purple) 18%,transparent);color:var(--purple)}
.cb-UserRight{background:color-mix(in srgb,var(--teal) 18%,transparent);color:var(--teal)}
.cb-SystemAccess{background:color-mix(in srgb,var(--green) 18%,transparent);color:var(--green)}
.cb-KerberosPolicy{background:color-mix(in srgb,var(--red) 18%,transparent);color:var(--red)}
.cb-AuditPolicy{background:color-mix(in srgb,var(--amber) 18%,transparent);color:var(--amber)}
.cb-GroupMembership{background:var(--surface2);color:var(--muted)}
.cellval{font-size:10.5px;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cellval.empty{color:var(--muted);font-style:italic}
/* Merged (Policy-Analyzer-style) view */
table.matrix.merged{table-layout:fixed;width:100%}
table.matrix.merged th, table.matrix.merged td{max-width:none}
table.matrix.merged .m-type{width:120px;white-space:nowrap;vertical-align:top;color:var(--muted)}
table.matrix.merged .m-key{width:38%;word-break:break-word;white-space:normal;font-family:'Segoe UI',sans-serif;vertical-align:top;line-height:1.4}
table.matrix.merged .m-set{width:34%;word-break:break-word;white-space:normal;vertical-align:top;line-height:1.4}
table.matrix.merged .m-rules{width:170px;vertical-align:top}
table.matrix.merged tbody td{overflow:hidden}
table.matrix.merged tbody tr:hover{background:color-mix(in srgb,var(--surface2) 70%,transparent)}
.rules-cell{font-size:10.5px;word-break:break-word;white-space:normal;line-height:1.4}
.rules-cell .cellval{white-space:normal;word-break:break-word}
td.conflict-cell.rules-cell{font-weight:700;letter-spacing:.3px}
td.conflict-cell{background:#f6e8c3;color:#6b5320}
[data-theme="dark"] td.conflict-cell{background:color-mix(in srgb,var(--amber) 22%,transparent);color:var(--text)}
.conflict-flag{display:inline-flex;align-items:center;gap:4px;color:var(--amber);font-weight:700;font-size:10px}
.empty-note{color:var(--muted);font-size:12px;padding:30px;text-align:center}

.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:200}.overlay.on{display:block}
.panel{position:fixed;top:0;right:0;width:680px;max-width:96vw;height:100vh;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .22s}.panel.on{transform:translateX(0)}
.ph{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;background:var(--surface2)}
.ph-title{font-size:13px;font-weight:700;line-height:1.4}.ph-sub{font-size:10px;color:var(--muted);margin-top:4px;font-family:monospace}
.pclose{background:none;border:none;color:var(--muted);cursor:pointer;font-size:17px;flex-shrink:0}
.pbody{flex:1;overflow-y:auto;padding:16px 18px}
.psec{margin-bottom:18px}.psec-t{font-size:10px;font-weight:700;color:var(--title);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;display:flex;align-items:center;gap:5px}.psec-t::after{content:'';flex:1;height:1px;background:var(--border)}
.valrow{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:9px 11px;border-radius:6px;background:var(--surface2);margin-bottom:6px;font-size:12px}
.valrow.diff{border-left:3px solid var(--amber)}
.valrow .vn{font-weight:600;color:var(--text);flex-shrink:0;max-width:160px;word-break:break-word}
.valrow .vv{color:var(--text);text-align:right;word-break:break-all}
.valrow .vv.empty{font-style:italic}

::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-track{background:var(--surface2)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
</style><style id="premium-theme">
:root{--shadow-1:0 12px 34px rgba(31,45,80,.09),0 2px 6px rgba(31,45,80,.05);}
body[data-theme="light"]{background:radial-gradient(1200px 600px at 20% -10%,#ffffff 0%,#eaf1fb 55%,#f7fafd 100%) fixed;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif}
body[data-theme="light"] .topbar{background:rgba(255,255,255,.82);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
body[data-theme="light"] .brand i{color:var(--accent)}
body[data-theme="light"] .kpi{border-radius:16px;box-shadow:var(--shadow-1);padding:16px 18px}
body[data-theme="light"] .kpi .kpi-val{font-size:26px;letter-spacing:-.02em}
body[data-theme="light"] .stat{border-radius:16px;box-shadow:0 6px 18px rgba(31,45,80,.06);padding:15px 16px}
body[data-theme="light"] .card{border-radius:18px;box-shadow:var(--shadow-1)}
body[data-theme="light"] .chip{border-radius:20px;background:#fff;border:1px solid var(--border);color:#59637a;font-weight:600}
body[data-theme="light"] .chip.on{background:var(--accent-soft);border-color:var(--accent);color:var(--accent)}
body[data-theme="light"] .chip.on .ct{background:rgba(99,102,241,.16);color:var(--accent)}
body[data-theme="light"] .kv{background-image:radial-gradient(rgba(24,36,60,.03) 1px,transparent 1px);background-size:9px 9px;border-radius:12px}
body[data-theme="light"] .panel{box-shadow:-18px 0 50px rgba(20,30,60,.14)}
body[data-theme="light"] .btn{border-radius:9px}
body[data-theme="light"] .btn.on,body[data-theme="light"] .sbtn.on{background:var(--accent-soft)!important;border-color:var(--accent)!important;color:var(--accent)!important}
/* card numbers black */
body[data-theme="light"] .kpi .kpi-val{color:var(--text)!important}
/* huge margin between sections */
body[data-theme="light"] .section-title{margin-top:66px}
body[data-theme="light"] .section-title:first-child{margin-top:10px}
/* brighter warning yellow for conflicts */
body[data-theme="light"] td.conflict-cell{background:#fcd34d;color:#5c3d00;box-shadow:inset 0 0 0 1.5px rgba(176,120,12,.5)}
body[data-theme="light"] td.redundant-cell{background:#e8f0fe;color:#2f5fa0}
body[data-theme="light"] td.differs-cell{background:#eef1f5;color:#5c6678}
body[data-theme="light"] table.matrix tbody tr.conflict td.colname{border-left-color:#f59e0b}
body[data-theme="light"] .conflict-flag{color:#d97706}
body[data-theme="light"] td.absent-cell{background:#d7dee7}
.lp-hint{font-size:11.5px;color:#5c6678;line-height:1.6;margin-bottom:10px}
.pl-legend{font-size:11.5px;color:#5c6678;line-height:1.6;margin-bottom:12px}
.pl-legend b{color:var(--title)}
.pl-ladder{display:flex;flex-direction:column}
.pl-item{display:flex;gap:10px;align-items:stretch}
.pl-item.enf>.pl-card{border-color:var(--accent)}
.pl-item.win>.pl-card{border-color:#16a34a;background:#f2fbf5}
.pl-rank{width:26px;flex:0 0 auto;display:flex;align-items:flex-start;justify-content:center;padding-top:11px;font-weight:800;font-size:13px;color:var(--muted)}
.pl-item.win .pl-rank{color:#16a34a;font-size:15px}
.pl-card{flex:1;min-width:0;border:1px solid var(--border);border-radius:10px;padding:10px 12px;background:var(--surface)}
.pl-top{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.pl-gpo{font-weight:700;font-size:12.5px;color:var(--text)}
.pl-val{margin-left:auto;font-family:monospace;font-size:11.5px;font-weight:700;color:var(--text)}
.pl-badge{font-size:9px;font-weight:800;padding:2px 7px;border-radius:20px;text-transform:uppercase;letter-spacing:.03em}
.pl-badge.enf{background:var(--accent-soft);color:var(--accent)}
.pl-badge.off{background:var(--surface3);color:var(--muted)}
.pl-badge.win{background:#e7f6ec;color:#16a34a}
.pl-crumbs{margin-top:8px;display:flex;flex-direction:column;gap:5px}
.pl-crumb{display:flex;align-items:center;flex-wrap:wrap;gap:3px;font-size:11px;color:#5c6678;background:var(--surface2);border-radius:6px;padding:5px 9px}
.pl-crumb.enf{color:var(--accent);background:var(--accent-soft)}
.pl-crumb.off{opacity:.7}
.pl-seg{font-weight:600}
.pl-sep{color:#aeb7c6;margin:0 1px}
.pl-depth{margin-left:6px;font-size:9px;font-weight:700;color:var(--muted);background:#fff;border:1px solid var(--border);border-radius:4px;padding:0 5px}
.pl-tag{font-size:9px;font-weight:700;padding:1px 6px;border-radius:4px;margin-left:4px}
.pl-tag.enf{background:var(--accent);color:#fff}
.pl-tag.off{background:var(--surface3);color:var(--muted)}
.pl-arrow{margin:3px 0 3px 8px;font-size:10px;font-weight:700;color:var(--muted);letter-spacing:.04em}
.ou-legend{font-size:11.5px;color:#5c6678;line-height:1.6;margin-bottom:12px}
.ou-legend b{color:var(--title)}
.ou-tree{border:1px solid var(--border);border-radius:10px;padding:10px 12px;background:var(--surface2)}
.ou-node{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:5px 0}
.ou-name{font-size:12px;font-weight:700;color:var(--title);display:flex;align-items:center;gap:6px;white-space:nowrap}
.ou-name i{color:var(--muted);font-size:12px}
.ou-gpos{display:flex;gap:6px;flex-wrap:wrap}
.ou-gpo{font-size:10.5px;font-weight:600;padding:3px 9px;border-radius:20px;background:#fff;border:1px solid var(--border);color:var(--text);display:inline-flex;align-items:center;gap:4px}
.ou-gpo.win{border-color:#16a34a;background:#f2fbf5;color:#16a34a}
.ou-gpo.enf{border-color:var(--accent)}
.ou-gpo.off{opacity:.55}
.ou-gpo i{font-size:10px;color:#16a34a}
.ou-e{font-size:8.5px;font-weight:800;text-transform:uppercase;letter-spacing:.03em;color:var(--accent);background:var(--accent-soft);padding:0 5px;border-radius:4px}
.ou-e.off{color:var(--muted);background:var(--surface3)}
.lp-list{display:flex;flex-direction:column;gap:8px}
.lp-row{display:flex;gap:10px;padding:10px 11px;border:1px solid var(--border);border-radius:9px;background:var(--surface)}
.lp-row.win{border-color:#16a34a;background:#f2fbf5}
.lp-rank{width:18px;flex:0 0 auto;color:#16a34a;font-size:13px;display:flex;justify-content:center;padding-top:1px}
.lp-body{flex:1;min-width:0}
.lp-top{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.lp-gpo{font-weight:700;font-size:12.5px;color:var(--text)}
.lp-val{margin-left:auto;font-family:monospace;font-size:11.5px;color:var(--text);font-weight:700}
.lp-badge{font-size:9px;font-weight:700;padding:2px 7px;border-radius:20px;text-transform:uppercase;letter-spacing:.03em}
.lp-badge.enf{background:var(--accent-soft);color:var(--accent)}
.lp-badge.off{background:var(--surface3);color:var(--muted)}
.lp-badge.win{background:#e7f6ec;color:#16a34a}
.lp-locs{margin-top:6px;display:flex;flex-direction:column;gap:3px}
.lp-loc{font-size:11.5px;color:#5c6678;display:flex;align-items:center;gap:6px}
.lp-loc i{font-size:12px;flex:0 0 auto}
.lp-loc span{word-break:break-all}
.lp-loc.enf{color:var(--accent)}
.lp-loc.dis{opacity:.75}
.lp-tag{font-size:9px;font-weight:700;padding:1px 5px;border-radius:4px;background:var(--accent-soft);color:var(--accent);white-space:nowrap}
.lp-tag.off{background:var(--surface3);color:var(--muted)}
.matrix-note{display:flex;gap:9px;align-items:flex-start;background:#f4f6fb;border:1px solid var(--border);border-left:3px solid var(--muted);border-radius:10px;padding:10px 14px;font-size:12px;color:#5c6678;line-height:1.55;margin:0 0 14px}
.matrix-note i{color:var(--muted);font-size:14px;flex:0 0 auto;margin-top:1px}
.matrix-note b{color:var(--title);font-weight:700}
.cf-mark{color:#b45309;font-size:11px;font-weight:700}
.cls-summary{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
.cs-b{font-size:11px;font-weight:700;padding:4px 11px;border-radius:20px;border:1px solid var(--border)}
.cs-b.conflict{background:#fdf0e1;color:#b45309;border-color:#f6dcb8}
.cs-b.redu{background:#e8f0fe;color:#2f6fd0;border-color:#cfe0fb}
.cs-b.diff{background:var(--surface2);color:var(--muted)}
.cs-b{cursor:pointer;user-select:none}
.cs-b.active{outline:2px solid currentColor;outline-offset:1px}
.cs-clear{cursor:pointer;font-size:11px;font-weight:600;color:var(--muted);display:inline-flex;align-items:center;gap:4px;padding:4px 6px}
.cs-clear:hover{color:var(--text)}
.cs-help{cursor:pointer;font-size:11px;font-weight:600;color:var(--accent);margin-left:auto;padding:4px 6px}
.cls-help-panel{display:none;margin:0 0 12px;padding:12px 14px;background:var(--surface);border:1px solid var(--border);border-radius:12px}
.cls-help-panel.on{display:block}
.ch-row{display:flex;gap:10px;align-items:flex-start;padding:6px 0;font-size:12px;color:#4b5566;line-height:1.5}
.ch-row .cs-b{flex:0 0 auto;min-width:78px;text-align:center}
.ch-txt{flex:1}
.ch-note{margin-top:8px;padding-top:8px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);line-height:1.5}
.cls-tag{font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.03em;padding:1px 6px;border-radius:4px}
.cls-tag.redu{background:#e8f0fe;color:#2f6fd0}
.cls-tag.diff{background:var(--surface3);color:var(--muted)}
.cls-tag.addi{background:#d9f2ee;color:#0f766e}
body[data-theme="light"] td.additive-cell{background:#d9f2ee;color:#0f766e}
.cs-b.addi{background:#d9f2ee;color:#0f766e;border-color:#b9e6df}
.vb-addi{background:#d9f2ee;border-color:#b9e6df}.vb-addi .vb-ic,.vb-addi b{color:#0f766e}
.m-vn{font-size:9.5px;color:var(--muted);font-weight:500;margin-top:2px;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.gp-reg{color:var(--muted);font-weight:500;font-size:10px}
.diff-cell{color:var(--muted);font-style:italic;font-size:11px}
.verdict{display:flex;gap:11px;align-items:flex-start;padding:12px 14px;border-radius:10px;margin-bottom:14px;border:1px solid var(--border)}
.verdict .vb-ic{font-size:18px;line-height:1;flex:0 0 auto}
.verdict b{font-size:13px}
.vb-sub{font-size:11.5px;color:#5c6678;margin-top:2px;line-height:1.5}
.vb-conflict{background:#fdf0e1;border-color:#f6dcb8}.vb-conflict .vb-ic,.vb-conflict b{color:#b45309}
.vb-redu{background:#e8f0fe;border-color:#cfe0fb}.vb-redu .vb-ic,.vb-redu b{color:#2f6fd0}
.vb-diff{background:var(--surface2)}.vb-diff .vb-ic,.vb-diff b{color:var(--muted)}
.matrix-toolbar{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin:0 0 12px}
.matrix-toolbar .search{flex:0 1 240px}
.ck-list{display:flex;flex-direction:column;gap:1px;background:var(--border);border:1px solid var(--border);border-radius:14px;overflow:hidden;margin-top:6px}
.ck-row{display:flex;align-items:flex-start;gap:12px;padding:13px 16px;background:#fff}
.ck-ic{width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;flex:0 0 auto;margin-top:1px}
.ck-ok .ck-ic{background:#e7f6ec;color:#16a34a}
.ck-warn .ck-ic{background:#fdf0e1;color:#c2740c}
.ck-na .ck-ic{background:var(--surface2);color:var(--muted)}
.ck-label{font-weight:700;font-size:13px;color:var(--title)}
.ck-detail{font-size:12px;color:var(--muted);margin-top:2px;line-height:1.5;word-break:break-word}
.ck-warn .ck-detail{color:#8a5a12}
/* colored settings-per-GPO bars (no color-mix, always renders) */
body[data-theme="light"] .bar-fill{display:block;background:linear-gradient(90deg,var(--accent),var(--blue))}
/* small per-card CSV / list buttons */
.kpi-acts{display:flex;gap:5px;margin-top:9px}
.kpi-act{display:inline-flex;align-items:center;justify-content:center;gap:4px;font-size:9.5px;font-weight:600;color:#59637a;background:#fff;border:1px solid var(--border);border-radius:7px;padding:3px 7px;cursor:pointer;line-height:1}
body[data-theme="light"] .kpi-act:hover{background:var(--accent-soft);border-color:var(--accent);color:var(--accent)}
.kpi-act i{font-size:10px}
body[data-theme="light"] .kpi .kpi-ico{opacity:.7;font-size:22px}
.kpi.clk{cursor:pointer;transition:transform .12s,box-shadow .12s}
body[data-theme="light"] .kpi.clk:hover{transform:translateY(-2px);box-shadow:0 10px 24px rgba(31,45,80,.12)}
.kmodal-overlay{position:fixed;inset:0;background:rgba(18,24,40,.5);display:none;align-items:center;justify-content:center;z-index:300;padding:24px}
.kmodal-overlay.on{display:flex}
.kmodal{background:#fff;border-radius:18px;box-shadow:0 24px 60px rgba(20,30,60,.3);width:100%;max-width:740px;max-height:82vh;display:flex;flex-direction:column;overflow:hidden}
.kmodal-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:15px;color:var(--title)}
.kmodal-x{background:transparent;border:none;font-size:22px;line-height:1;color:var(--muted);cursor:pointer;padding:0 4px}
.kmodal-x:hover{color:var(--text)}
.kmodal-body{overflow:auto;padding:10px 14px}
.kmodal-tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.kmodal-tbl th{text-align:left;padding:8px 10px;color:var(--muted);font-weight:700;border-bottom:1px solid var(--border);position:sticky;top:0;background:#fff}
.kmodal-tbl td{padding:8px 10px;border-bottom:1px solid var(--border);color:var(--text);vertical-align:top}
.kmodal-tbl tr:hover td{background:var(--surface2)}
</style>
</head>
<body data-theme="light">

<div class="topbar">
  <div class="brand"><i class="bi bi-grid-3x3-gap-fill"></i>GPO Policy Analyzer</div>
  <div class="sep"></div>
  <div style="flex:1"></div>
    <button class="btn" onclick="toggleTheme()"><i class="bi bi-circle-half"></i> Theme</button>
    <button class="btn" onclick="window.print()"><i class="bi bi-printer"></i> Print</button>
  <div class="meta">$DomainDNS &nbsp;|&nbsp; $GeneratedAt</div>
</div>

<div class="wrap">
  <div class="summary-bar" id="summaryBar"></div>
  <div class="stats-row" id="statsRow"></div>
  <div class="section-title"><i class="bi bi-shield-check"></i> GPO Integrity <i class="bi bi-info-circle" style="font-size:13px;color:var(--muted);cursor:help" title="Integrity checks for Group Policy: the two built-in default GPOs (present, enabled, AD/SYSVOL version match, linked correctly), plus AD-vs-SYSVOL consistency — AD GPO objects with no SYSVOL folder (broken), orphaned SYSVOL folders with no AD object, and any object-count mismatch."></i></div>
  <div id="integritySection"></div>
  <div class="section-title"><i class="bi bi-shield-check"></i> Security Baseline Compliance <i class="bi bi-info-circle" style="font-size:13px;color:var(--muted);cursor:help" title="Starter hardening baseline — a built-in starter set of common Microsoft/CIS-aligned GPO hardening checks (password &amp; lockout policy, key security options, audit settings). Each configured setting is scored Compliant, Wrong value, or Missing against the recommended value. It is a starting point, not an exhaustive or official benchmark — adjust it to your environment."></i></div>
  <div id="baselineSection"></div>
  <div class="section-title"><i class="bi bi-table"></i> Policy Settings &amp; Conflicts <i class="bi bi-info-circle" style="font-size:13px;color:var(--muted);cursor:help" title="Every configured policy setting across all analyzed GPOs. Rows where two or more GPOs set different values for the same setting are flagged as conflicts and highlighted; the winning value (highest precedence) is marked with a trophy."></i></div>
  <div class="matrix-note"><i class="bi bi-info-circle"></i><div>This compares configured <b>values</b> across GPOs (like Microsoft Policy Analyzer) — it is <b>not</b> effective/resultant policy. OU scope, block inheritance, link-enforcement interplay, security filtering and WMI filters are not evaluated, so a flagged conflict may not actually collide on a given object. Open a setting and use <b>Link precedence &amp; where applied</b> to judge real overlap.</div></div>
  <div class="cls-summary" id="clsSummary"></div>
  <div class="cls-help-panel" id="clsHelp"></div>
  <div class="matrix-toolbar">
    <div class="search"><i class="bi bi-search"></i><input id="srch" type="text" placeholder="Search setting or key…" oninput="render()"></div>
    <button class="btn on" id="f-conflicts" onclick="toggleConflictsOnly()"><i class="bi bi-sort-down"></i> Conflicts first</button>
    <button class="btn" id="f-conflicts-only" onclick="toggleConflictsOnlyFilter()"><i class="bi bi-exclamation-triangle"></i> Conflicts only</button>
    <div class="scope-toggle">
      <button class="sbtn on" id="vm-merged" onclick="setViewMode('merged')"><i class="bi bi-list-columns-reverse"></i> Merged</button>
      <button class="sbtn" id="vm-expanded" onclick="setViewMode('expanded')"><i class="bi bi-table"></i> Per-GPO</button>
    </div>
    <div class="scope-toggle">
      <button class="sbtn on" id="sc-all" onclick="setScope('All')">All</button>
      <button class="sbtn" id="sc-computer" onclick="setScope('Computer')"><i class="bi bi-pc-display"></i> Computer</button>
      <button class="sbtn" id="sc-user" onclick="setScope('User')"><i class="bi bi-person"></i> User</button>
    </div>
    <div class="gpo-picker">
      <button class="btn" onclick="toggleGpoPop()"><i class="bi bi-columns-gap"></i> GPO columns</button>
      <div class="gpo-pop" id="gpoPop"></div>
    </div>
  </div>
  <div class="filter-row" id="catFilters"></div>
  <div class="matrix-wrap"><table class="matrix" id="matrix"><thead></thead><tbody></tbody></table></div>
</div>

<div class="overlay" id="ov" onclick="closePanel()"></div>
<div class="panel" id="panel">
  <div class="ph"><div><div class="ph-title" id="ptitle"></div><div class="ph-sub" id="psub"></div></div>
  <button class="pclose" onclick="closePanel()"><i class="bi bi-x-lg"></i></button></div>
  <div class="pbody" id="pbody"></div>
</div>

<script>
const D = $DataJSON;
const ROWS = Array.isArray(D.rows) ? D.rows : [];
function _scopesOf(g){ var L=(D.gpoLinks||{})[g]||[]; return L.filter(function(l){return l.enabled;}).map(function(l){return (''+l.target).toLowerCase(); }); }
function _isAnc(a,b){ if(a===b) return true; return b.length>a.length && b.slice(b.length-a.length-1)===(','+a); }
function _ovl(sa,sb){ for(var i=0;i<sa.length;i++){ for(var j=0;j<sb.length;j++){ if(_isAnc(sa[i],sb[j])||_isAnc(sb[j],sa[i])) return true; } } return false; }
function _additive(r){
  var k=((r.key||'')+'').toLowerCase(), sset=((r.setting||'')+'').toLowerCase(), c=r.category;
  if(k.indexOf('firewallrules')>=0) return true;
  if(k.indexOf('globallyopenports')>=0) return true;
  if(k.indexOf('authorizedapplications')>=0) return true;
  if(k.indexOf('codeidentifiers')>=0) return true;
  if(c==='GroupMembership' && sset.indexOf('memberof')>=0) return true;
  return false;
}
function vnSub(r){ var sv=r.setting; if(!sv) return ''; var fn=''+(r.friendlyName||''); if(fn.toLowerCase().indexOf((''+sv).toLowerCase())>=0) return ''; if(r.category==='Registry'||r.category==='SecurityOption'||r.category==='AuditPolicy'||r.category==='UserRight') return '<div class="m-vn">'+escapeHtml(sv)+'</div>'; return ''; }
function classifyRow(r){
  var av=r.values||{}; var cfg=Object.keys(av).filter(function(g){ return av[g]!=null && (''+av[g]).trim()!==''; });
  if(cfg.length<2) return {cls:'none',label:''};
  if(_additive(r)) return {cls:'additive',label:'Combined additive setting: every GPO entry applies (firewall rules, port/app lists, or group memberships merge), so there is no single winner. Not a conflict.'};
  var norm={}; cfg.forEach(function(g){ norm[g]=(''+av[g]).trim().toLowerCase(); });
  var sc={}; cfg.forEach(function(g){ sc[g]=_scopesOf(g); });
  var real=false, anyOv=false;
  for(var i=0;i<cfg.length;i++){ for(var j=i+1;j<cfg.length;j++){ if(_ovl(sc[cfg[i]],sc[cfg[j]])){ anyOv=true; if(norm[cfg[i]]!==norm[cfg[j]]) real=true; } } }
  var d={}; cfg.forEach(function(g){ d[norm[g]]=1; }); var distinct=Object.keys(d).length;
  if(real) return {cls:'conflict',label:'Conflict \u2014 GPOs overlap on the same OU branch, so an object receives both with different values.'};
  if(distinct>1) return {cls:'differs',label:'Differs \u2014 GPOs set different values but are linked to separate subtrees, so no single object gets both. Likely not a real conflict.'};
  return {cls:'redundant',label:anyOv?'Redundant \u2014 the same value is set by GPOs that overlap; harmless duplication.':'Redundant \u2014 the same value is duplicated across separate subtrees; consider consolidating.'};
}
ROWS.forEach(function(r){ var c=classifyRow(r); r._cls=c.cls; r._clsLabel=c.label; r.conflict=(c.cls==='conflict'); });
D.conflictCount = ROWS.filter(function(r){return r._cls==='conflict';}).length;
var REDUNDANT_COUNT = ROWS.filter(function(r){return r._cls==='redundant';}).length;
var DIFFERS_COUNT = ROWS.filter(function(r){return r._cls==='differs';}).length;
var ADDITIVE_COUNT = ROWS.filter(function(r){return r._cls==='additive';}).length;
function clsTag(r){
  if(r._cls==='conflict') return '<span class="cf-mark" title="Real conflict \u2014 GPOs share an OU branch">&#9888;</span> ';
  if(r._cls==='redundant') return '<span class="cls-tag redu" title="'+escapeHtml(r._clsLabel)+'">redundant</span> ';
  if(r._cls==='differs') return '<span class="cls-tag diff" title="'+escapeHtml(r._clsLabel)+'">separate scopes</span> ';
  if(r._cls==='additive') return '<span class="cls-tag addi" title="'+escapeHtml(r._clsLabel)+'">additive</span> ';
  return '';
}
function clsVerdict(r){
  if(!r._cls||r._cls==='none') return '';
  var m={conflict:['vb-conflict','&#9888;','Conflict'],additive:['vb-addi','&#8853;','Additive (combined)'],redundant:['vb-redu','&#8801;','Redundant'],differs:['vb-diff','&#8942;','Differs \u2014 separate scopes']};
  var x=m[r._cls]; return '<div class="verdict '+x[0]+'"><span class="vb-ic">'+x[1]+'</span><div><b>'+x[2]+'</b><div class="vb-sub">'+escapeHtml(r._clsLabel)+'</div></div></div>';
}
var CLS_HELP={
 conflict:'Two or more GPOs set this exact setting to DIFFERENT values, and their links overlap on the same OU branch - so a machine in that branch receives both. Precedence picks one winner; the other value is discarded. This is the only class that is a genuine problem.',
 redundant:'Two or more GPOs set this setting to the SAME value. Harmless duplication if they overlap, or the same value repeated across separate OU subtrees (worth consolidating to reduce sprawl).',
 differs:'GPOs set DIFFERENT values but are linked to separate OU subtrees, so no single object ever receives both. Not a real conflict - each subtree just gets its own value.',
 additive:'Additive setting type - firewall rules, port/app lists, Restricted Groups member-of, or GPP group-add. Every GPO entry COMBINES (merges); there is no single winner, so different values are not a conflict.'
};
function setClsFilter(c){ clsFilter=(clsFilter===c)?null:c; renderClsSummary(); renderMatrix(); }
function renderClsSummary(){ var el=document.getElementById('clsSummary'); if(!el) return;
  function b(c,label,cls){ var on=(clsFilter===c); return '<span class="cs-b '+cls+(on?' active':'')+'" onclick="setClsFilter(&#39;'+c+'&#39;)" title="'+CLS_HELP[c]+'">'+label+'</span>'; }
  el.innerHTML=b('conflict',(D.conflictCount||0)+' real conflict'+((D.conflictCount||0)===1?'':'s'),'conflict')
    +b('redundant',REDUNDANT_COUNT+' redundant','redu')
    +b('differs',DIFFERS_COUNT+' separate-scope difference'+(DIFFERS_COUNT===1?'':'s'),'diff')
    +b('additive',ADDITIVE_COUNT+' additive','addi')
    +(clsFilter?'<span class="cs-clear" onclick="setClsFilter(clsFilter)"><i class="bi bi-x-circle"></i> clear filter</span>':'')
    +'<span class="cs-help" onclick="document.getElementById(&#39;clsHelp&#39;).classList.toggle(&#39;on&#39;)" title="What do these mean?">? what do these mean</span>';
  var h=document.getElementById('clsHelp'); if(h){
    function row(c,name,cls){ return '<div class="ch-row"><span class="cs-b '+cls+'" style="cursor:default">'+name+'</span><span class="ch-txt">'+CLS_HELP[c]+'</span></div>'; }
    h.innerHTML=row('conflict','conflict','conflict')+row('redundant','redundant','redu')+row('differs','separate scopes','diff')+row('additive','additive','addi')
      +'<div class="ch-note">Classification is by OU linking and setting type only - security-group and WMI filtering are not evaluated, so confirm borderline cases with the OU tree in a setting\u2019s detail pane.</div>';
  }
}
const GPOS = Array.isArray(D.gpoNames) ? D.gpoNames : [];
let activeCats = new Set(['Registry','SecurityOption','UserRight','SystemAccess','KerberosPolicy','AuditPolicy','GroupMembership']);
let visibleGpos = new Set(GPOS);
let conflictsFirst = true;
let conflictsOnly = false;
let clsFilter = null;
let activeScope = 'All';
let viewMode = 'merged';

const CATS = [
  {k:'Registry',t:'Registry (Admin Templates)',i:'bi-sliders'},
  {k:'SecurityOption',t:'Security Options',i:'bi-shield-lock'},
  {k:'UserRight',t:'User Rights',i:'bi-person-badge'},
  {k:'SystemAccess',t:'Password/Lockout Policy',i:'bi-key'},
  {k:'KerberosPolicy',t:'Kerberos Policy',i:'bi-ticket-perforated'},
  {k:'AuditPolicy',t:'Audit Policy',i:'bi-journal-check'},
  {k:'GroupMembership',t:'Group Membership',i:'bi-people'}
];

// GPO name -> health record, for use in the detail pane
const GPO_HEALTH = {};
(Array.isArray(D.gpoAnalysis)?D.gpoAnalysis:[]).forEach(g=>{ GPO_HEALTH[g.name]=g; });

function renderSummaryBar(){
  const b=document.getElementById('summaryBar');
  function item(lbl,val,cls){ return '<span class="sb-item '+(cls||'')+'">'+lbl+': <b>'+val+'</b></span>'; }
  b.innerHTML =
    item('GPOs', D.gpoCount||0)
    + '<span class="sb-sep"></span>'
    + item('Settings', D.totalSettings||0)
    + item('Conflicts', D.conflictCount||0, (D.conflictCount>0?'bad':''))
    + item('Flagged GPOs', D.problemGpoCount||0, ((D.problemGpoCount||0)>0?'warn':''))
    + '<span class="sb-sep"></span>'
    + '<span class="sb-item" style="color:var(--muted);font-size:11px">'+escapeHtml(D.domain||'')+' · '+escapeHtml(D.generatedAt||'')+'</span>';
}

var GPO_HDR=['GPO','Settings','Links','Status','Issues'];
  function _gpoRows(list){ return list.map(function(g){ return [g.name,g.settingCount,g.linksCount,g.gpoStatus,(g.issues||[]).join('; ')]; }); }
  function enforcedList(){ var GL=D.gpoLinks||{}; var out=[]; Object.keys(GL).forEach(function(name){ var links=GL[name]||[]; var enf=links.filter(function(l){return l.enforced;}); if(enf.length) out.push({name:name,targets:enf.map(function(l){return l.target;}).join('; '),total:links.length}); }); return out; }
  function kpiData(key){ var A=Array.isArray(D.gpoAnalysis)?D.gpoAnalysis:[];
    if(key==='total') return {title:'All GPOs',headers:GPO_HDR,rows:_gpoRows(A)};
    if(key==='healthy') return {title:'Healthy GPOs',headers:GPO_HDR,rows:_gpoRows(A.filter(function(g){return g.healthy;}))};
    if(key==='empty') return {title:'Empty GPOs',headers:GPO_HDR,rows:_gpoRows(A.filter(function(g){return g.isEmpty;}))};
    if(key==='unlinked') return {title:'Unlinked GPOs',headers:GPO_HDR,rows:_gpoRows(A.filter(function(g){return g.isUnlinked&&!g.isEmpty;}))};
    if(key==='linkdisabled') return {title:'Link-Disabled GPOs',headers:GPO_HDR,rows:_gpoRows(A.filter(function(g){return g.isDisabledLink;}))};
    if(key==='redundant') return {title:'Redundant GPOs',headers:GPO_HDR,rows:_gpoRows(A.filter(function(g){return g.isRedundant;}))};
    if(key==='disabled') return {title:'Disabled GPOs',headers:GPO_HDR,rows:_gpoRows(A.filter(function(g){return g.isDisabled;}))};
    if(key==='conflicts') return {title:'Conflicting Settings',headers:['Setting','Category','Winner GPO','Winner Value','Configured In'],rows:ROWS.filter(function(r){return r.conflict;}).map(function(r){return [r.friendlyName||r.setting,catLabel(r.category),r.winner||'',(r.winnerValue==null?'':''+r.winnerValue),r.configuredCount];})};
    if(key==='enforced'){ var L=enforcedList(); return {title:'Enforced GPO Links',headers:['GPO','Enforced Link Target(s)','Total Links'],rows:L.map(function(e){return [e.name,e.targets,e.total];})}; }
    return {title:'',headers:[],rows:[]}; }
  function kpiList(key){ var d=kpiData(key); openReport(d.title,(D.domain||''),d.headers,d.rows); }
  function kpiCsv(key){ var d=kpiData(key); downloadCsv(d.title.replace(/\s+/g,'_').toLowerCase()+'.csv',d.headers,d.rows); }

function openKpiModal(key){ var d=kpiData(key); document.getElementById('kpiModalTitle').textContent=d.title+' ('+d.rows.length+')'; document.getElementById('kpiModalCsvBtn').setAttribute('data-key',key); var h; if(!d.rows.length){ h='<div style="color:var(--muted);padding:26px;text-align:center">Nothing to show.</div>'; } else { h='<table class="kmodal-tbl"><thead><tr>'+d.headers.map(function(x){return '<th>'+escapeHtml(x)+'</th>';}).join('')+'</tr></thead><tbody>'+d.rows.map(function(r){return '<tr>'+r.map(function(c){return '<td>'+escapeHtml(c==null?'':''+c)+'</td>';}).join('')+'</tr>';}).join('')+'</tbody></table>'; } document.getElementById('kpiModalBody').innerHTML=h; document.getElementById('kpiModalOverlay').classList.add('on'); }
function closeKpiModal(){ document.getElementById('kpiModalOverlay').classList.remove('on'); }
document.addEventListener('keydown',function(e){ if(e.key==='Escape') closeKpiModal(); });

function renderStats(){
  const el=document.getElementById('statsRow');
  const analysis = Array.isArray(D.gpoAnalysis) ? D.gpoAnalysis : [];

  // ---- KPI tiles: GPO health states ----
  const cEmpty    = analysis.filter(g=>g.isEmpty).length;
  const cUnlinked = analysis.filter(g=>g.isUnlinked && !g.isEmpty).length;
  const cDisLink  = analysis.filter(g=>g.isDisabledLink).length;
  const cRedund   = analysis.filter(g=>g.isRedundant).length;
  const cDisabled = analysis.filter(g=>g.isDisabled).length;
  const cHealthy  = analysis.filter(g=>g.healthy).length;
  const cEnforced = enforcedList().length;
  function kpi(val,lbl,ico,cls,key){ return '<div class="kpi '+cls+' clk" onclick="openKpiModal(\''+key+'\')"><i class="bi '+ico+' kpi-ico"></i><span class="kpi-val">'+val+'</span><span class="kpi-lbl">'+lbl+'</span><div class="kpi-acts"><button class="kpi-act" onclick="event.stopPropagation();kpiCsv(\''+key+'\')" title="Download CSV"><i class="bi bi-download"></i>CSV</button></div></div>'; }


  const kpis = '<div class="kpi-grid">'
    + kpi(D.gpoCount||0,'Total GPOs','bi-folder2','k-blue','total')
    + kpi(cEmpty,'Empty','bi-file-earmark','k-amber','empty')
    + kpi(cUnlinked,'Unlinked','bi-link-45deg','k-purple','unlinked')
    + kpi(cDisLink,'Link Disabled','bi-toggle-off','k-teal','linkdisabled')
    + kpi(cRedund,'Redundant','bi-files','k-amber','redundant')
    + kpi(cDisabled,'Disabled','bi-slash-circle','k-red','disabled')
    + kpi(cEnforced,'Enforced','bi-shield-check','k-purple','enforced')
    + kpi(D.conflictCount||0,'Conflicts','bi-exclamation-triangle','k-red','conflicts')
    + '</div>';

  // ---- Chart 1: Settings per GPO (horizontal bars, top 10) ----
  const perGpo = GPOS.map(g=>{
    let n=0; ROWS.forEach(r=>{ if(r.values && r.values[g]!=null && r.values[g]!=='') n++; });
    return {name:g, n};
  }).sort((a,b)=>b.n-a.n).slice(0,10);
  const maxGpo = Math.max(1, ...perGpo.map(x=>x.n));
  const gpoBars = perGpo.map(x=>{
    const pct=(x.n/maxGpo)*100;
    return '<div class="bar-row"><span class="bar-label" title="'+escapeHtml(x.name)+'">'+escapeHtml(x.name)+'</span>'
      +'<span class="bar-track"><span class="bar-fill" style="width:'+pct+'%"></span></span>'
      +'<span class="bar-val">'+x.n+'</span></div>';
  }).join('');
  const barCard = '<div class="stat-card"><div class="stat-card-title"><i class="bi bi-bar-chart-line"></i> Settings per GPO (top 10)</div>'+gpoBars+'</div>';

  // ---- Chart 2: Conflict donut ----
  const conf = D.conflictCount||0, total = D.totalSettings||0;
  const consistent = Math.max(0, total-conf);
  const pctConf = total? (conf/total) : 0;
  const R=42, C=2*Math.PI*R, dash=C*pctConf;
  const donut = '<svg width="108" height="108" viewBox="0 0 108 108">'
    + '<circle cx="54" cy="54" r="'+R+'" fill="none" stroke="var(--surface2)" stroke-width="13"/>'
    + '<circle cx="54" cy="54" r="'+R+'" fill="none" stroke="var(--red)" stroke-width="13" stroke-linecap="round" stroke-dasharray="'+dash+' '+(C-dash)+'" transform="rotate(-90 54 54)"/>'
    + '<text x="54" y="51" text-anchor="middle" font-size="21" font-weight="800" fill="var(--text)">'+conf+'</text>'
    + '<text x="54" y="66" text-anchor="middle" font-size="9" fill="var(--muted)">conflicts</text></svg>';
  const donutCard = '<div class="stat-card"><div class="stat-card-title"><i class="bi bi-pie-chart"></i> Conflict Overview</div>'
    + '<div class="donut-wrap">'+donut
    + '<div class="donut-legend">'
    + '<div class="dl"><span class="dot" style="background:var(--red)"></span><b>'+conf+'</b>&nbsp;conflicting</div>'
    + '<div class="dl"><span class="dot" style="background:var(--surface2);border:1px solid var(--border)"></span><b>'+consistent+'</b>&nbsp;consistent</div>'
    + '<div class="dl" style="color:var(--muted);margin-top:3px">'+(total?Math.round(pctConf*100):0)+'% conflict rate</div>'
    + '</div></div></div>';

  // ---- Chart 3: Category breakdown (stacked bar + legend) ----
  const catColors={Registry:'var(--blue)',SecurityOption:'var(--purple)',UserRight:'var(--teal)',SystemAccess:'var(--green)',KerberosPolicy:'var(--red)',AuditPolicy:'var(--amber)',GroupMembership:'var(--muted)'};
  const catCounts=CATS.map(cat=>({k:cat.k,t:cat.t,n:ROWS.filter(r=>r.category===cat.k).length})).filter(x=>x.n>0);
  const catTotal=catCounts.reduce((s,x)=>s+x.n,0)||1;
  const stack=catCounts.map(x=>'<div class="seg" style="width:'+((x.n/catTotal)*100)+'%;background:'+(catColors[x.k]||'var(--muted)')+'" title="'+escapeHtml(x.t)+': '+x.n+'"></div>').join('');
  const catLegend=catCounts.map(x=>'<div class="cl"><span class="dot" style="background:'+(catColors[x.k]||'var(--muted)')+'"></span>'+escapeHtml(x.t.split(' ')[0])+' <b>'+x.n+'</b></div>').join('');
  const catCard='<div class="stat-card"><div class="stat-card-title"><i class="bi bi-layers"></i> Settings by Category</div>'
    + '<div class="cat-stack">'+stack+'</div><div class="cat-legend">'+catLegend+'</div>'
    + '<div class="scope-split"><div class="scope-pill"><div class="sp-val" style="color:var(--blue)">'+(D.computerCount||0)+'</div><div class="sp-lbl">Computer</div></div>'
    + '<div class="scope-pill"><div class="sp-val" style="color:var(--teal)">'+(D.userCount||0)+'</div><div class="sp-lbl">User</div></div></div></div>';

  el.innerHTML = kpis + '<div class="charts-grid">'+barCard+donutCard+'</div>' + '<div class="charts-grid" style="grid-template-columns:1fr">'+catCard+'</div>';
}

function renderCatFilters(){
  const c=document.getElementById('catFilters');
  c.innerHTML = CATS.map(cat=>{
    const cnt = ROWS.filter(r=>r.category===cat.k).length;
    if(cnt===0) return '';
    const on = activeCats.has(cat.k) ? 'on' : '';
    return '<div class="chip '+on+'" onclick="toggleCat(\''+cat.k+'\')"><i class="bi '+cat.i+'"></i>'+cat.t+'<span class="ct">'+cnt+'</span></div>';
  }).join('');
}

function toggleCat(k){
  if(activeCats.has(k)) activeCats.delete(k); else activeCats.add(k);
  renderCatFilters(); renderMatrix();
}
function toggleConflictsOnly(){
  conflictsFirst = !conflictsFirst;
  document.getElementById('f-conflicts').classList.toggle('on', conflictsFirst);
  renderMatrix();
}
function toggleConflictsOnlyFilter(){
  conflictsOnly = !conflictsOnly;
  document.getElementById('f-conflicts-only').classList.toggle('on', conflictsOnly);
  renderMatrix();
}

function setScope(scope){
  activeScope = scope;
  document.getElementById('sc-all').classList.toggle('on', scope==='All');
  document.getElementById('sc-computer').classList.toggle('on', scope==='Computer');
  document.getElementById('sc-user').classList.toggle('on', scope==='User');
  renderMatrix();
}

function setViewMode(mode){
  viewMode = mode;
  document.getElementById('vm-merged').classList.toggle('on', mode==='merged');
  document.getElementById('vm-expanded').classList.toggle('on', mode==='expanded');
  // GPO column picker only matters in expanded mode
  const picker = document.querySelector('.gpo-picker');
  if(picker) picker.style.display = (mode==='expanded') ? '' : 'none';
  renderMatrix();
}

function toggleGpoPop(){ document.getElementById('gpoPop').classList.toggle('on'); }
function renderGpoPicker(){
  const p=document.getElementById('gpoPop');
  let html='<div class="gpo-pop-actions"><button onclick="setAllGpos(true)">All</button><button onclick="setAllGpos(false)">None</button></div>';
  html += GPOS.map(g=>'<label><input type="checkbox" '+(visibleGpos.has(g)?'checked':'')+' onchange="toggleGpo(\''+g.replace(/'/g,"\\'")+'\')"> '+g+'</label>').join('');
  p.innerHTML = html;
}
function toggleGpo(g){ if(visibleGpos.has(g)) visibleGpos.delete(g); else visibleGpos.add(g); renderMatrix(); }
function setAllGpos(all){ visibleGpos = all ? new Set(GPOS) : new Set(); renderGpoPicker(); renderMatrix(); }

function filteredRows(){
  const q = (document.getElementById('srch').value||'').toLowerCase().trim();
  let rows = ROWS.filter(r=>{
    if(!activeCats.has(r.category)) return false;
    if(activeScope!=='All' && (r.scope||'Computer')!==activeScope) return false;
    if(clsFilter && r._cls!==clsFilter) return false;
    if(conflictsOnly && !r.conflict) return false;
    if(q){
      const hay = (r.friendlyName+' '+r.key+' '+r.setting).toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  });
  // Always group by scope (Computer first, then User), then by conflict/name within each scope
  rows = rows.slice().sort((a,b)=>{
    const sa=(a.scope||'Computer'), sb=(b.scope||'Computer');
    if(sa!==sb) return sa==='Computer'?-1:1;
    if(conflictsFirst && (b.conflict-a.conflict)!==0) return b.conflict-a.conflict;
    return a.friendlyName.localeCompare(b.friendlyName);
  });
  return rows;
}

function renderMatrix(){
  const rows = filteredRows();
  const thead = document.querySelector('#matrix thead');
  const tbody = document.querySelector('#matrix tbody');
  const matrixEl = document.getElementById('matrix');

  if(viewMode==='merged'){
    matrixEl.classList.add('merged'); matrixEl.classList.remove('expanded');
    renderMerged(rows, thead, tbody);
  } else {
    matrixEl.classList.add('expanded'); matrixEl.classList.remove('merged');
    renderExpanded(rows, thead, tbody);
  }
  window._currentRows = rows;
}

// Merged: Policy-Analyzer-style 4 columns (Type / Key / Setting / rules)
function renderMerged(rows, thead, tbody){
  thead.innerHTML = '<tr><th class="m-type">Policy Type</th><th class="m-key">Policy Group or Registry Key</th><th class="m-set">Policy Setting</th><th class="m-rules">rules</th></tr>';
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="4" class="empty-note"><i class="bi bi-inbox"></i> No settings match the current filters.</td></tr>'; return; }
  let html=''; let lastScope=null;
  rows.forEach((r,idx)=>{
    const scope = r.scope || 'Computer';
    if(scope !== lastScope){
      const icon = scope==='Computer' ? 'bi-pc-display' : 'bi-person';
      const label = scope==='Computer' ? 'Computer Configuration' : 'User Configuration';
      const cnt = rows.filter(x=>(x.scope||'Computer')===scope).length;
      html += '<tr class="scope-hdr '+(scope==='User'?'user':'')+'"><td colspan="4"><i class="bi '+icon+'"></i>'+label+' ('+cnt+')</td></tr>';
      lastScope = scope;
    }
    // "rules" cell: the agreed value if consistent, ***CONFLICT*** (yellow) if not
    let rulesCell;
    if(r.conflict){
      rulesCell = '<td class="conflict-cell rules-cell">***CONFLICT***</td>';
    } else if(r._cls==='differs'){
      rulesCell = '<td class="rules-cell diff-cell" title="Values differ but GPOs are on separate subtrees">differs (separate scopes)</td>';
    } else if(r._cls==='additive'){
      rulesCell = '<td class="rules-cell additive-cell" title="Additive setting - all GPOs entries apply">combined (additive)</td>';
    } else {
      // single agreed value (first configured value)
      const vals = Object.values(r.values||{}).filter(v=>v!=null && v!=='');
      const v = vals.length ? (''+vals[0]) : '';
      rulesCell = '<td class="rules-cell'+(r._cls==='redundant'?' redundant-cell':'')+'"><span class="cellval'+(v===''?' empty':'')+'" title="'+escapeHtml(v)+'">'+(v===''?'—':escapeHtml(v))+'</span></td>';
    }
    const typeLabel = policyTypeLabel(r);
    html += '<tr class="'+(r.conflict?'conflict':'')+'" data-idx="'+idx+'" onclick="openDetail('+idx+')" style="cursor:pointer">'
      + '<td class="m-type">'+escapeHtml(typeLabel)+'</td>'
      + '<td class="m-key" title="'+escapeHtml(r.key)+'">'+escapeHtml(r.key)+'</td>'
      + '<td class="m-set" title="'+escapeHtml(r.friendlyName)+'">'+clsTag(r)+escapeHtml(r.friendlyName)+vnSub(r)+'</td>'
      + rulesCell + '</tr>';
  });
  tbody.innerHTML = html;
}

// Expanded: one column per GPO (the grid)
function renderExpanded(rows, thead, tbody){
  const cols = GPOS.filter(g=>visibleGpos.has(g));
  thead.innerHTML = '<tr><th class="m-type">Policy Type</th><th class="m-key">Policy Group or Registry Key</th><th class="m-set">Policy Setting</th>' + cols.map(g=>'<th title="'+escapeHtml(g)+'">'+escapeHtml(g)+'</th>').join('') + '</tr>';
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="'+(cols.length+3)+'" class="empty-note"><i class="bi bi-inbox"></i> No settings match the current filters.</td></tr>'; return; }
  const totalCols = cols.length + 3;
  let html=''; let lastScope=null;
  rows.forEach((r,idx)=>{
    const scope = r.scope || 'Computer';
    if(scope !== lastScope){
      const icon = scope==='Computer' ? 'bi-pc-display' : 'bi-person';
      const label = scope==='Computer' ? 'Computer Configuration' : 'User Configuration';
      const cnt = rows.filter(x=>(x.scope||'Computer')===scope).length;
      html += '<tr class="scope-hdr '+(scope==='User'?'user':'')+'"><td colspan="'+totalCols+'"><i class="bi '+icon+'"></i>'+label+' ('+cnt+')</td></tr>';
      lastScope = scope;
    }
    const cells = cols.map(g=>{
      const v = r.values && r.values[g] != null ? (''+r.values[g]) : '';
      const cls = v==='' ? 'absent-cell' : (r._cls==='conflict' ? 'conflict-cell' : (r._cls==='redundant' ? 'redundant-cell' : (r._cls==='differs' ? 'differs-cell' : (r._cls==='additive' ? 'additive-cell' : ''))));
      const isWinner = r.conflict && r.winner && g===r.winner && v!=='';
      const valCls = isWinner ? 'cellval winner-val' : 'cellval';
      const tip = v==='' ? '' : escapeHtml(v) + (isWinner?'  (winning value)':'');
      const disp = v==='' ? '<span class="cellval empty">—</span>' : '<span class="'+valCls+'" title="'+tip+'">'+escapeHtml(v)+'</span>';
      return '<td class="'+cls+'">'+disp+'</td>';
    }).join('');
    const statusCell = r.conflict
      ? '<span class="conflict-flag"><i class="bi bi-exclamation-triangle-fill"></i> Conflict</span>'
      : '<span style="color:var(--muted);font-size:10px"><i class="bi bi-check-circle"></i> Consistent</span>';
    html += '<tr class="'+(r.conflict?'conflict':'')+'" data-idx="'+idx+'" onclick="openDetail('+idx+')" style="cursor:pointer">'
      +'<td class="m-type">'+escapeHtml(catLabel(r.category))+'</td>'
      +'<td class="m-key" title="'+escapeHtml(r.key)+'">'+escapeHtml(r.key)+'</td>'
      +'<td class="m-set" title="'+escapeHtml(r.friendlyName)+'">'+clsTag(r)+escapeHtml(r.friendlyName)+' <i class="bi bi-info-circle" style="font-size:10px;color:var(--muted)"></i>'+vnSub(r)+'</td>'
      +cells+'</tr>';
  });
  tbody.innerHTML = html;
}

function policyTypeLabel(r){
  // Mirror Policy Analyzer's "Policy Type" column
  switch(r.category){
    case 'Registry': return r.hive || 'Registry';
    case 'SecurityOption': return r.hive || 'Security';
    case 'UserRight': return 'User Rights';
    case 'SystemAccess': return 'Account Policy';
    case 'KerberosPolicy': return 'Kerberos Policy';
    case 'AuditPolicy': return 'Audit Policy';
    case 'GroupMembership': return 'Group Membership';
    default: return r.category;
  }
}
function catLabel(k){ const c=CATS.find(x=>x.k===k); return c?c.t.split(' ')[0]:k; }
function escapeHtml(s){ return (''+s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

var AUDIT_CAT={
 'credential validation':'Account Logon','kerberos authentication service':'Account Logon','kerberos service ticket operations':'Account Logon','other account logon events':'Account Logon',
 'application group management':'Account Management','computer account management':'Account Management','distribution group management':'Account Management','other account management events':'Account Management','security group management':'Account Management','user account management':'Account Management',
 'dpapi activity':'Detailed Tracking','plug and play events':'Detailed Tracking','process creation':'Detailed Tracking','process termination':'Detailed Tracking','rpc events':'Detailed Tracking','token right adjusted events':'Detailed Tracking',
 'detailed directory service replication':'DS Access','directory service access':'DS Access','directory service changes':'DS Access','directory service replication':'DS Access',
 'account lockout':'Logon/Logoff','user / device claims':'Logon/Logoff','ipsec extended mode':'Logon/Logoff','ipsec main mode':'Logon/Logoff','ipsec quick mode':'Logon/Logoff','logoff':'Logon/Logoff','logon':'Logon/Logoff','network policy server':'Logon/Logoff','other logon/logoff events':'Logon/Logoff','special logon':'Logon/Logoff',
 'application generated':'Object Access','certification services':'Object Access','detailed file share':'Object Access','file share':'Object Access','file system':'Object Access','filtering platform connection':'Object Access','filtering platform packet drop':'Object Access','handle manipulation':'Object Access','kernel object':'Object Access','other object access events':'Object Access','registry':'Object Access','removable storage':'Object Access','sam':'Object Access','central access policy staging':'Object Access',
 'audit policy change':'Policy Change','authentication policy change':'Policy Change','authorization policy change':'Policy Change','filtering platform policy change':'Policy Change','mpssvc rule-level policy change':'Policy Change','other policy change events':'Policy Change',
 'non sensitive privilege use':'Privilege Use','other privilege use events':'Privilege Use','sensitive privilege use':'Privilege Use',
 'ipsec driver':'System','other system events':'System','security state change':'System','security system extension':'System','system integrity':'System'
};
function auditCategoryOf(name){ var n=(''+name).toLowerCase().replace(/^audit\s+/,'').trim(); return AUDIT_CAT[n]||'(subcategory)'; }
function gpmcPath(r){
  var sc=(r.scope==='User')?'User Configuration':'Computer Configuration';
  var sec=sc+' \u203a Policies \u203a Windows Settings \u203a Security Settings';
  var c=r.category, s=r.setting||'', fn=r.friendlyName||s;
  if(c==='AuditPolicy'){
    if(((''+r.key).toLowerCase()).indexOf('advanced')>=0) return sec+' \u203a Advanced Audit Policy Configuration \u203a Audit Policies \u203a '+auditCategoryOf(fn||s)+' \u203a '+(fn||s);
    return sec+' \u203a Local Policies \u203a Audit Policy \u203a '+(fn||s);
  }
  if(c==='UserRight') return sec+' \u203a Local Policies \u203a User Rights Assignment \u203a '+(fn||s);
  if(c==='SecurityOption') return sec+' \u203a Local Policies \u203a Security Options \u203a '+(fn||s);
  if(c==='SystemAccess') return sec+' \u203a Account Policies \u203a Password &amp; Lockout Policy \u203a '+(fn||s);
  if(c==='KerberosPolicy') return sec+' \u203a Account Policies \u203a Kerberos Policy \u203a '+(fn||s);
  if(c==='GroupMembership') return sec+' \u203a Restricted Groups \u203a '+(fn||s);
  if(c==='Registry') return sc+' \u203a Policies \u203a Administrative Templates \u203a '+escapeHtml(fn)+'  <span class="gp-reg">(registry: '+escapeHtml(r.key)+'\\\\'+escapeHtml(s)+')</span>';
  return escapeHtml(fn||s);
}

function dnCrumb(dn){
  if(!dn) return ['(unknown)'];
  var parts=(''+dn).split(',').map(function(p){return p.trim();});
  var ous=[], dcs=[], leaf=[];
  parts.forEach(function(p){
    var eq=p.indexOf('='); if(eq<0) return;
    var t=p.slice(0,eq).toUpperCase(), v=p.slice(eq+1);
    if(t==='DC') dcs.push(v);
    else if(t==='OU') ous.push(v);
    else leaf.push(v);
  });
  var domain=dcs.join('.');
  var chain=(domain?[domain]:[]).concat(ous.reverse()).concat(leaf);
  return chain.length?chain:['(domain root)'];
}
function buildLinkPrec(r){
  var GL=D.gpoLinks||{}; var allVals=r.values||{};
  var cfg=GPOS.filter(function(g){ var v=allVals[g]; return v!=null && v!==''; });
  if(!cfg.length) return '';
  cfg.sort(function(a,b){
    if(a===r.winner) return -1; if(b===r.winner) return 1;
    var ea=(GL[a]||[]).some(function(l){return l.enforced;}), eb=(GL[b]||[]).some(function(l){return l.enforced;});
    if(ea!==eb) return ea?-1:1;
    return a.localeCompare(b);
  });
  var last=cfg.length-1;
  var ladder=cfg.map(function(g,i){
    var links=GL[g]||[];
    var enf=links.some(function(l){return l.enforced;});
    var hasEnabled=links.some(function(l){return l.enabled;});
    var isWin=(g===r.winner);
    var val=allVals[g];
    var crumbs = links.length ? links.map(function(l){
        var chain=dnCrumb(l.target);
        var segs=chain.map(function(seg,ci){ return (ci?'<span class="pl-sep">\u203a</span>':'')+'<span class="pl-seg">'+escapeHtml(seg)+'</span>'; }).join('');
        var depth=Math.max(0,chain.length-1);
        return '<div class="pl-crumb'+(l.enforced?' enf':'')+(l.enabled?'':' off')+'">'+segs
          +'<span class="pl-depth" title="OU depth on this branch">L'+depth+'</span>'
          +(l.enforced?'<span class="pl-tag enf">enforced</span>':'')
          +(l.enabled?'':'<span class="pl-tag off">disabled</span>')+'</div>';
      }).join('') : '<div class="pl-crumb off"><span class="pl-seg">Not linked anywhere</span></div>';
    var h=(typeof GPO_HEALTH!=='undefined')?GPO_HEALTH[g]:null;
    var hflag=(h && !h.healthy)?' <span title="'+escapeHtml((h.issues||[]).join('; '))+'" style="color:var(--amber);font-weight:700">\u26a0</span>':'';
    return '<div class="pl-item'+(isWin?' win':'')+(enf?' enf':'')+'">'
      +'<div class="pl-rank">'+(isWin?'<i class="bi bi-trophy-fill"></i>':(i+1))+'</div>'
      +'<div class="pl-card"><div class="pl-top"><span class="pl-gpo">'+escapeHtml(g)+hflag+'</span>'
        +(enf?'<span class="pl-badge enf">Enforced</span>':'')
        +(hasEnabled?'':'<span class="pl-badge off">no enabled link</span>')
        +(isWin?'<span class="pl-badge win">Winner</span>':'')
        +'<span class="pl-val">'+escapeHtml(''+val)+'</span></div>'
        +'<div class="pl-crumbs">'+crumbs+'</div></div></div>'
      +(i<last?'<div class="pl-arrow">\u2193 overrides</div>':'');
  }).join('');
  return '<div class="psec"><div class="psec-t"><i class="bi bi-diagram-2"></i> Precedence, enforcement &amp; linking ('+cfg.length+' GPOs)</div>'
    +'<div class="pl-legend">Ranked top-to-bottom \u2014 the top GPO wins. <b>Enforced</b> links override normal order; otherwise the GPO linked to the <b>deepest OU</b> (higher L number) on the object\u2019s path wins. Compare the link paths: GPOs on <b>different branches</b> never meet on the same object, so it may not be a real conflict.</div>'
    +'<div class="pl-ladder">'+ladder+'</div></div>';
}

function buildOuTree(r){
  var GL=D.gpoLinks||{}; var allVals=r.values||{};
  var cfg=GPOS.filter(function(g){ var v=allVals[g]; return v!=null && v!==''; });
  if(!cfg.length) return '';
  var root={name:'',children:{},gpos:[]};
  function ensurePath(chain){ var node=root; chain.forEach(function(seg){ if(!node.children[seg]) node.children[seg]={name:seg,children:{},gpos:[]}; node=node.children[seg]; }); return node; }
  var anyLinked=false;
  cfg.forEach(function(g){ (GL[g]||[]).forEach(function(l){ var node=ensurePath(dnCrumb(l.target)); node.gpos.push({name:g,enforced:l.enforced,enabled:l.enabled,win:(g===r.winner)}); anyLinked=true; }); });
  if(!anyLinked) return '';
  function chips(node){ return node.gpos.map(function(gp){
      return '<span class="ou-gpo'+(gp.win?' win':'')+(gp.enforced?' enf':'')+(gp.enabled?'':' off')+'">'+(gp.win?'<i class="bi bi-trophy-fill"></i> ':'')+escapeHtml(gp.name)+(gp.enforced?' <span class="ou-e">enforced</span>':'')+(gp.enabled?'':' <span class="ou-e off">disabled</span>')+'</span>';
    }).join(''); }
  function renderNode(node,depth){
    var kids=Object.keys(node.children).sort();
    var c=chips(node);
    var self='<div class="ou-node" style="margin-left:'+(depth*18)+'px"><span class="ou-name"><i class="bi bi-folder2"></i> '+escapeHtml(node.name)+'</span>'+(c?'<span class="ou-gpos">'+c+'</span>':'')+'</div>';
    return self+kids.map(function(k){return renderNode(node.children[k],depth+1);}).join('');
  }
  var body=Object.keys(root.children).sort().map(function(k){return renderNode(root.children[k],0);}).join('');
  return '<div class="psec"><div class="psec-t"><i class="bi bi-diagram-2"></i> OU structure of the linked scopes</div>'
    +'<div class="ou-legend">Where each involved GPO sits in the OU tree. GPOs under the <b>same branch</b> can collide on objects in that subtree; GPOs on <b>separate branches</b> apply to different objects and don\u2019t truly conflict.</div>'
    +'<div class="ou-tree">'+body+'</div></div>';
}

function openDetail(idx){
  const r = window._currentRows[idx]; if(!r) return;
  document.getElementById('ptitle').innerHTML = '<div class="cat-badge cb-'+r.category+'" style="margin-bottom:6px">'+catLabel(r.category)+'</div>'+escapeHtml(r.friendlyName);
  document.getElementById('psub').textContent = r.key + (r.setting ? ('\\' + r.setting) : '');
  const allVals = r.values || {};
  const distinctVals = new Set(Object.values(allVals).filter(v=>v!=null && (''+v).trim()!=='').map(v=>(''+v).trim().toLowerCase()));
  const scope = r.scope || 'Computer';
  const scopeIcon = scope==='Computer' ? 'bi-pc-display' : 'bi-person';

  // Metadata section (Policy Analyzer's bottom-pane detail: path, type, scope, hive)
  function meta(k,v){ return v ? '<div class="valrow"><span class="vn">'+k+'</span><span class="vv" style="font-family:monospace">'+escapeHtml(v)+'</span></div>' : ''; }
  const metaHtml =
      meta('GPO editor path', gpmcPath(r))
    + meta('Configuration', scope+' Configuration')
    + meta('Category', catLabel(r.category))
    + (r.hive ? meta('Hive', r.hive) : '')
    + meta('Registry Key', r.key)
    + (r.setting ? meta('Value Name', r.setting) : '')
    + (r.valueType ? meta('Value Type', r.valueType) : '');

  // Per-GPO values; for a conflict, group identical values so the disagreement is obvious
  let rowsHtml = GPOS.filter(function(g){ var _v=allVals[g]; return _v!=null && _v!==''; }).map(g=>{
    const v = allVals[g];
    const has = v!=null && v!=='';
    const diff = r.conflict && has;
    // Small health flag if this GPO has an issue (only shown for GPOs that configure the setting)
    let flag = '';
    if(has){
      const h = GPO_HEALTH[g];
      if(h && !h.healthy){
        const tip = (h.issues||[]).join('; ');
        flag = ' <i class="bi bi-exclamation-triangle-fill" style="color:var(--amber);font-size:9px" title="'+escapeHtml(tip)+'"></i>';
      }
      if(r.conflict && r.winner && g===r.winner){
        flag += ' <i class="bi bi-trophy-fill" style="color:var(--green);font-size:9px" title="Winning value (highest precedence)"></i>';
      }
    }
    return '<div class="valrow'+(diff?' diff':'')+'"><span class="vn">'+escapeHtml(g)+flag+'</span><span class="vv'+(has?'':' empty')+'">'+(has?escapeHtml(''+v):'not configured')+'</span></div>';
  }).join('');

  // Conflict breakdown: which distinct values exist and which GPOs hold each
  let conflictHtml = '';
  if(r.conflict){
    const groups = {};
    Object.keys(allVals).forEach(g=>{
      const v = allVals[g]; if(v==null||v==='') return;
      const key = ''+v;
      (groups[key] = groups[key] || []).push(g);
    });
    const groupRows = Object.keys(groups).map(val=>
      '<div class="valrow diff"><span class="vn" style="color:var(--amber)">'+escapeHtml(val)+'</span><span class="vv">'+groups[val].map(escapeHtml).join(', ')+'</span></div>'
    ).join('');
    const winnerBlock = r.winner
      ? '<div style="background:color-mix(in srgb,var(--green) 10%,transparent);border:1px solid var(--green);border-radius:6px;padding:9px 11px;margin-bottom:10px;font-size:11px"><b style="color:var(--green)"><i class="bi bi-trophy-fill"></i> Effective winner: '+escapeHtml(r.winner)+'</b><div style="color:var(--muted);margin-top:4px">Applied value: <b style="color:var(--text)">'+escapeHtml(''+r.winnerValue)+'</b><br>This GPO has the highest precedence among those configuring this setting (enforced links, then link order, then OU depth).</div></div>'
      : '<div style="background:color-mix(in srgb,var(--red) 10%,transparent);border:1px solid var(--red);border-radius:6px;padding:9px 11px;margin-bottom:10px;font-size:11px"><b style="color:var(--red)"><i class="bi bi-dash-circle"></i> No GPO applies this setting</b><div style="color:var(--muted);margin-top:4px">All GPOs configuring this setting are unlinked or have disabled links, so none takes effect.</div></div>';
    conflictHtml =
      '<div class="psec"><div class="psec-t"><i class="bi bi-exclamation-triangle" style="color:var(--amber)"></i> Conflict — '+distinctVals.size+' distinct values</div>'
      + winnerBlock
      + '<div style="font-size:11px;color:var(--muted);line-height:1.6;margin-bottom:8px">Configured with '+distinctVals.size+' different values across '+Object.keys(allVals).length+' GPO(s). Values grouped below:</div>'
      + groupRows + '</div>';
  } else if(Object.keys(allVals).length > 1){
    conflictHtml = '<div class="psec"><div class="psec-t"><i class="bi bi-check-circle" style="color:var(--green)"></i> Consistent</div><div style="font-size:11px;color:var(--muted);line-height:1.6">All '+Object.keys(allVals).length+' GPOs that configure this setting use the same value — no conflict.</div></div>';
  }

  document.getElementById('pbody').innerHTML =
      clsVerdict(r)
    + '<div class="psec"><div class="psec-t"><i class="bi '+scopeIcon+'"></i> Setting Details</div>'+metaHtml+'</div>'
    + conflictHtml
    + buildLinkPrec(r)
    + buildOuTree(r);
  document.getElementById('ov').classList.add('on');
  document.getElementById('panel').classList.add('on');
}
function closePanel(){ document.getElementById('ov').classList.remove('on'); document.getElementById('panel').classList.remove('on'); }

/* ---- CSV + companion-HTML export (offline) ---- */
function csvCell(v){ v=(v==null?'':''+v); if(/[",\n]/.test(v)){ v='"'+v.replace(/"/g,'""')+'"'; } return v; }
function downloadCsv(filename, headers, rows){
  let out = headers.map(csvCell).join(',')+'\n';
  rows.forEach(r=>{ out += r.map(csvCell).join(',')+'\n'; });
  const blob = new Blob(['\ufeff'+out], {type:'text/csv;charset=utf-8'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=filename;
  document.body.appendChild(a); a.click(); setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); },200);
}
function openReport(title, subtitle, headers, rows){
  const w=window.open('','_blank'); if(!w){ alert('Popup blocked - allow popups to open the detail view.'); return; }
  const E=function(s){return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');};
  const emb = JSON.stringify({h:headers, r:rows}).replace(/</g,'\\u003c');
  const css='body{font-family:system-ui,Arial,sans-serif;margin:0;background:#f8fafc;color:#0f172a}'
    +'.hd{padding:16px 26px;border-bottom:1px solid #e2e8f0;background:#fff;position:sticky;top:0;z-index:3}'
    +'.hd h1{font-size:17px;margin:0}.sub{font-size:12px;color:#64748b;margin-top:4px}'
    +'.fbar{padding:10px 26px;background:#fff;border-bottom:1px solid #e2e8f0;position:sticky;top:62px;z-index:2}'
    +'#f{width:100%;max-width:440px;padding:8px 12px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;outline:none;font-family:inherit}'
    +'#f:focus{border-color:#4f46e5;box-shadow:0 0 0 3px #e0e7ff}'
    +'table{border-collapse:collapse;width:100%;background:#fff}'
    +'th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#64748b;padding:10px 16px;border-bottom:2px solid #e2e8f0;background:#f1f5f9;position:sticky;top:0}'
    +'td{padding:9px 16px;border-bottom:1px solid #eef2f6;font-size:13px}tr:hover td{background:#f8fafc}'
    +'@media print{.hd,.fbar,th{position:static}}';
  let scr='var D='+emb+';'
    +'function ce(s){return (""+(s==null?"":s)).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}'
    +'function draw(q){q=(q||"").toLowerCase();var n=0;var b=D.r.map(function(row){var hay=row.join(" ").toLowerCase();if(q&&hay.indexOf(q)<0)return "";n++;return "<tr>"+row.map(function(c){return "<td>"+ce(c)+"</td>";}).join("")+"</tr>";}).join("");'
    +'var head="<tr>"+D.h.map(function(h){return "<th>"+ce(h)+"</th>";}).join("")+"</tr>";'
    +'document.getElementById("t").innerHTML="<table><thead>"+head+"</thead><tbody>"+b+"</tbody></table>";'
    +'document.getElementById("cnt").textContent=n+" of "+D.r.length+" row(s)";}'
    +'document.getElementById("f").addEventListener("input",function(e){draw(e.target.value);});draw("");';
  const doc='<!DOCTYPE html><html><head><meta charset="UTF-8"><title>'+E(title)+'</title><style>'+css+'</style></head><body>'
    +'<div class="hd"><h1>'+E(title)+'</h1><div class="sub">'+E(subtitle)+' &middot; <span id="cnt"></span></div></div>'
    +'<div class="fbar"><input id="f" placeholder="Filter rows..." autocomplete="off"></div><div id="t"></div>'
    +'<scr'+'ipt>'+scr+'<\/scr'+'ipt></body></html>';
  w.document.open(); w.document.write(doc); w.document.close();
}
/* ---- baseline compliance ---- */
let blFilter='all';
function blStatusTag(st){ return st==='Compliant'?'<span class="bl-tag ok">Compliant</span>':st==='Wrong Value'?'<span class="bl-tag wrong">Wrong Value</span>':'<span class="bl-tag miss">Missing</span>'; }
function blAllRows(){ return (D.baseline&&D.baseline.results)?D.baseline.results:[]; }
function blRows(){ const r=blAllRows(); if(blFilter==='all')return r; return r.filter(x=>(blFilter==='comp'&&x.status==='Compliant')||(blFilter==='wrong'&&x.status==='Wrong Value')||(blFilter==='miss'&&x.status==='Missing')); }
function setBlFilter(f){ blFilter=f; drawBaseline(); }
function blFilterBtn(f,label,n){ return '<button class="btn'+(blFilter===f?' on':'')+'" onclick="setBlFilter(\''+f+'\')">'+label+' ('+n+')</button>'; }
function blDataRows(){ return blAllRows().map(r=>[r.cat,r.name,r.expected,r.found||'',r.status]); }
function csvBaseline(){ downloadCsv('baseline_compliance.csv',['Category','Setting','Expected','Configured','Status'],blDataRows()); }
function openBaseline(){ openReport('Security Baseline Compliance',(D.domain||''),['Category','Setting','Expected','Configured','Status'],blDataRows()); }
function drawBaseline(){
  const bl=D.baseline||{}; const total=bl.total||0, comp=bl.compliant||0, wrong=bl.wrong||0, miss=bl.missing||0;
  const pct= total? Math.round(comp*100/total):0;
  const seg=(n,c)=> n? '<div class="bl-seg" style="width:'+(n/total*100)+'%;background:'+c+'" title="'+n+'"></div>':'';
  const scoreColor = pct>=80?'var(--green)':pct>=50?'var(--amber)':'var(--red)';
  let h='<div class="bl-card"><div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">'
    +'<div class="stat-card-title" style="margin:0"><i class="bi bi-shield-check"></i> '+escapeHtml(bl.name||'Baseline')+' <i class="bi bi-info-circle" style="font-size:12px;color:var(--muted);cursor:help" title="Starter hardening baseline: a built-in starter set of common Microsoft/CIS-aligned GPO hardening checks (password &amp; lockout policy, key security options, audit settings), each scored Compliant, Wrong value, or Missing against the recommended value. A starting point, not an official benchmark - adjust it to your environment."></i></div>'
    +'<div style="margin-left:auto;display:flex;gap:6px"><button class="btn" onclick="openBaseline()"><i class="bi bi-box-arrow-up-right"></i> Open</button><button class="btn" onclick="csvBaseline()"><i class="bi bi-download"></i> CSV</button></div></div>'
    +'<div class="bl-scoreline"><div class="bl-score" style="color:'+scoreColor+'">'+pct+'%</div>'
    +'<div class="bl-bar">'+seg(comp,'var(--green)')+seg(wrong,'var(--amber)')+seg(miss,'var(--red)')+'</div></div>'
    +'<div class="bl-legend"><span><span class="dot" style="background:var(--green)"></span>Compliant '+comp+'</span>'
    +'<span><span class="dot" style="background:var(--amber)"></span>Wrong Value '+wrong+'</span>'
    +'<span><span class="dot" style="background:var(--red)"></span>Missing '+miss+'</span>'
    +'<span style="color:var(--muted)">of '+total+' checks</span></div>'
    +'<div class="bl-filters">'+blFilterBtn('all','All',total)+blFilterBtn('miss','Missing',miss)+blFilterBtn('wrong','Wrong Value',wrong)+blFilterBtn('comp','Compliant',comp)+'</div>';
  const rows=blRows();
  h+='<table class="bl-tbl"><thead><tr><th>Category</th><th>Setting</th><th>Expected</th><th>Configured</th><th>Status</th></tr></thead><tbody>';
  if(!rows.length){ h+='<tr><td colspan="5" style="color:var(--muted);padding:14px">No checks in this filter.</td></tr>'; }
  rows.forEach(r=>{ h+='<tr><td style="color:var(--muted)">'+escapeHtml(r.cat)+'</td><td><b>'+escapeHtml(r.name)+'</b><div class="bl-why">'+escapeHtml(r.why||'')+'</div></td><td>'+escapeHtml(r.expected)+'</td><td style="color:var(--muted)">'+(r.found?escapeHtml(r.found):'&mdash;')+'</td><td>'+blStatusTag(r.status)+'</td></tr>'; });
  h+='</tbody></table></div>';
  document.getElementById('baselineSection').innerHTML=h;
}
function renderIntegrity(){ var el=document.getElementById('integritySection'); if(!el) return;
  var bh=Array.isArray(D.builtinHealth)?D.builtinHealth:[]; var it=D.integrity||{}; var checks=[];
  bh.forEach(function(b){
    checks.push({ na:!b.present, ok:b.healthy, label:b.label, detail: !b.present ? 'Missing from the domain' : (b.healthy ? 'Present, enabled, AD/SYSVOL versions consistent, linked correctly' : b.issues.join('; ')) });
  });
  if(it.sysvolChecked){
    var adOnly=it.adOnly||[], sysOnly=it.sysvolOnly||[];
    checks.push({ ok:(it.adCount===it.sysvolCount && adOnly.length===0 && sysOnly.length===0), label:'AD \u2194 SYSVOL object count', detail: it.adCount+' GPO object(s) in AD vs '+it.sysvolCount+' policy folder(s) in SYSVOL'+(it.adCount===it.sysvolCount?' (match)':' (mismatch)') });
    checks.push({ ok:(adOnly.length===0), label:'AD GPOs with SYSVOL data', detail: adOnly.length===0 ? 'Every AD GPO has a matching SYSVOL policy folder' : (adOnly.length+' GPO(s) in AD have no SYSVOL folder (broken / missing GPT): '+adOnly.map(function(x){return x.name;}).join(', ')) });
    checks.push({ ok:(sysOnly.length===0), label:'Orphaned SYSVOL folders', detail: sysOnly.length===0 ? 'No orphaned SYSVOL policy folders' : (sysOnly.length+' SYSVOL folder(s) have no AD GPO object: '+sysOnly.map(function(x){return '{'+x.guid+'}';}).join(', ')) });
  } else {
    checks.push({ na:true, label:'AD \u2194 SYSVOL integrity', detail:'SYSVOL policies path was not reachable — this check was skipped' });
  }
  el.innerHTML='<div class="ck-list">'+checks.map(function(c){
    var st=c.na?'na':(c.ok?'ok':'warn'); var ico=c.na?'\u2013':(c.ok?'\u2713':'!');
    return '<div class="ck-row ck-'+st+'"><span class="ck-ic">'+ico+'</span><div class="ck-body"><div class="ck-label">'+escapeHtml(c.label)+'</div><div class="ck-detail">'+escapeHtml(c.detail)+'</div></div></div>';
  }).join('')+'</div>';
}
function renderBaseline(){ if(!D.baseline){ document.getElementById('baselineSection').innerHTML=''; return; } drawBaseline(); }

function render(){ renderSummaryBar(); renderStats(); renderClsSummary(); renderCatFilters(); renderGpoPicker(); renderMatrix(); renderIntegrity(); renderBaseline(); }
function toggleTheme(){ document.body.setAttribute('data-theme', document.body.getAttribute('data-theme')==='dark'?'light':'dark'); }

document.addEventListener('click', function(e){
  const pop = document.getElementById('gpoPop');
  const picker = document.querySelector('.gpo-picker');
  if(pop.classList.contains('on') && picker && !picker.contains(e.target)) pop.classList.remove('on');
});

render();
setViewMode('merged');
</script>
<div class="kmodal-overlay" id="kpiModalOverlay" onclick="if(event.target===this)closeKpiModal()"><div class="kmodal"><div class="kmodal-head"><span id="kpiModalTitle"></span><div style="display:flex;gap:8px;align-items:center"><button class="btn" id="kpiModalCsvBtn" onclick="kpiCsv(this.getAttribute('data-key'))"><i class="bi bi-download"></i> CSV</button><button class="kmodal-x" onclick="closeKpiModal()">&times;</button></div></div><div class="kmodal-body" id="kpiModalBody"></div></div></div>
</body></html>
"@
$HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
Write-Host ""
Write-Host "  Report saved: $ReportPath" -ForegroundColor Green
Write-Host "  Re-run with -SkipExport to re-analyze these same backups instantly." -ForegroundColor Gray
try { if ($OpenReport) { Start-Process $ReportPath } } catch { Write-Host "  (Open the file manually.)" -ForegroundColor Yellow }
