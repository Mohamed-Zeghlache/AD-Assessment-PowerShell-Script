<#
.SYNOPSIS
    AD Credential Hygiene - Enhanced Dashboard
.DESCRIPTION
    Standalone dashboard assessing the password, lockout, and credential posture of a domain.
    Emits a single self-contained interactive HTML report (dark/light) with an insights
    dashboard, KPI tiles, contextual recommendations, and drill-downs. Long lists are kept off
    the main page behind per-category "Open" (full-page HTML view, generated client-side) and
    "CSV" (download) actions, so a large tenant stays readable.

    Collected and assessed (all read-only, live from the current domain):
      - PASSWORD & LOCKOUT POLICY: default domain policy scored against a recommended baseline.
      - FINE-GRAINED PASSWORD POLICIES (PSOs): each PSO, precedence, and who it applies to.
      - MANAGED ACCOUNTS: gMSA / sMSA, retrieval principals, rotation interval, KDS root key.
      - LAPS: Windows or Legacy LAPS coverage across enabled computers (missing / expired).
      - RISKY USER ACCOUNTS: never-expires, password-not-required, unconstrained delegation, SID history, inactive-but-enabled,
        unconstrained delegation, SID history, inactive-but-enabled accounts, stale service passwords, SPNs.
      - COMPUTER ACCOUNTS: stale logons, old machine passwords, legacy / end-of-life OS,
        unconstrained delegation, disabled objects.
      - krbtgt password age.

    Optional sources degrade gracefully (LAPS schema absent, KDS module missing, no rights) and
    are reported as "Not available" rather than failing. No object is modified.
.PARAMETER OutputPath
    Folder to save the HTML report. Defaults to the current directory.
.PARAMETER ServiceAccountStalePasswordDays
    Age (days) beyond which a service account's password is flagged stale. Default 365.
.PARAMETER InactiveDays
    Last-logon age (days) beyond which an enabled USER account is considered inactive. Default 90.
.PARAMETER StaleComputerDays
    Last-logon age (days) beyond which an enabled COMPUTER is considered stale. Default 90.
.PARAMETER OpenReport
    Open the report when finished (default: $true). Use -OpenReport:$false to skip.
.EXAMPLE
    .\AD-CredentialHygiene-Enhanced.ps1
.EXAMPLE
    .\AD-CredentialHygiene-Enhanced.ps1 -OutputPath C:\Reports -StaleComputerDays 60
.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite (Credential Hygiene module)
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [int]$ServiceAccountStalePasswordDays = 365,
    [int]$InactiveDays = 90,
    [int]$StaleComputerDays = 90,
    [int]$InactiveAccountDays = 90,
    [switch]$IncludeComputerAcls,
    [string]$OrphanedSidSearchBase = '',
    [switch]$SkipOrphanedSids,
    [switch]$OpenReport = $true
)

$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Error "ActiveDirectory module not available. Install RSAT-AD-PowerShell."; exit 1 }

try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$Stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$Now         = Get-Date

try { $Domain = Get-ADDomain -ErrorAction Stop } catch { Write-Error "Could not contact the domain: $($_.Exception.Message)"; exit 1 }
$DomainDNS  = $Domain.DNSRoot
$ReportPath = Join-Path $OutputPath "AD_AccountSecurity_$Stamp.html"

Write-Host "AD Account & Credential Security" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host "Domain: $DomainDNS" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function ConvertFrom-FileTimeSafe { param($v)
    if ($null -eq $v) { return $null }
    try { if ($v -is [datetime]) { return $v } } catch {}
    try {
        $n = [int64]$v
        if ($n -le 0 -or $n -eq 9223372036854775807) { return $null }
        return [datetime]::FromFileTime($n)
    } catch { return $null }
}
function Get-AgeDays { param($dt)
    if ($null -eq $dt) { return $null }
    try { return [int]([math]::Round(($script:Now - $dt).TotalDays)) } catch { return $null }
}
function Get-EncAssessment { param($val)
    if ($null -eq $val -or "$val" -eq '') { return @{ Label='Not set (default RC4)'; Class='warn' } }
    $n = 0; try { $n = [int]$val } catch { return @{ Label="$val"; Class='warn' } }
    $des = ($n -band 0x1) -or ($n -band 0x2)
    $rc4 = ($n -band 0x4)
    $aes = ($n -band 0x8) -or ($n -band 0x10)
    if ($des) { return @{ Label='DES enabled'; Class='high' } }
    if ($aes) { return @{ Label=('AES' + $(if($rc4){' + RC4'}else{''})); Class='ok' } }
    if ($rc4) { return @{ Label='RC4 only (no AES)'; Class='medium' } }
    return @{ Label="0x$($n.ToString('X'))"; Class='warn' }
}

# ---------------------------------------------------------------------------
# 1. Default password & lockout policy
# ---------------------------------------------------------------------------
Write-Host "[1/8] Reading default password & lockout policy..." -ForegroundColor Yellow
$PolRows = @(); $PolFail = 0; $PolWarn = 0; $PolOk = $false
try {
    $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    function Add-PolRow { param($name,$value,$class,$rec)
        $script:PolRows += [PSCustomObject]@{ setting=$name; value="$value"; class=$class; recommended=$rec }
        if ($class -eq 'high') { $script:PolFail++ } elseif ($class -eq 'medium') { $script:PolWarn++ }
    }
    $minLen = [int]$pp.MinPasswordLength
    Add-PolRow 'Minimum password length' $minLen ($(if($minLen -ge 14){'ok'}elseif($minLen -ge 8){'medium'}else{'high'})) '>= 14'
    $hist = [int]$pp.PasswordHistoryCount
    Add-PolRow 'Password history count' $hist ($(if($hist -ge 24){'ok'}elseif($hist -ge 12){'medium'}else{'high'})) '>= 24'
    $cx = [bool]$pp.ComplexityEnabled
    Add-PolRow 'Complexity enabled' $cx ($(if($cx){'ok'}else{'high'})) 'Enabled'
    $rev = [bool]$pp.ReversibleEncryptionEnabled
    Add-PolRow 'Reversible encryption' $rev ($(if($rev){'high'}else{'ok'})) 'Disabled'
    $maxAge = [int]$pp.MaxPasswordAge.TotalDays
    Add-PolRow 'Maximum password age (days)' $maxAge ($(if($maxAge -eq 0){'high'}elseif($maxAge -le 365){'ok'}else{'medium'})) '1-365, not 0'
    $minAge = [int]$pp.MinPasswordAge.TotalDays
    Add-PolRow 'Minimum password age (days)' $minAge ($(if($minAge -ge 1){'ok'}else{'medium'})) '>= 1'
    $lt = [int]$pp.LockoutThreshold
    Add-PolRow 'Lockout threshold' $lt ($(if($lt -eq 0){'high'}elseif($lt -le 10){'ok'}else{'medium'})) '1-10, not 0'
    $ld = [int]$pp.LockoutDuration.TotalMinutes
    Add-PolRow 'Lockout duration (minutes)' $ld ($(if($lt -eq 0){'mut'}elseif($ld -ge 15){'ok'}else{'medium'})) '>= 15'
    $lw = [int]$pp.LockoutObservationWindow.TotalMinutes
    Add-PolRow 'Lockout observation window (minutes)' $lw ($(if($lt -eq 0){'mut'}elseif($lw -ge 15){'ok'}else{'medium'})) '>= 15'
    $PolOk = $true
} catch { Write-Host "      Could not read default policy: $($_.Exception.Message)" -ForegroundColor DarkYellow }
Write-Host "      $($PolRows.Count) setting(s): $PolFail fail, $PolWarn warn" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Fine-grained password policies (PSOs)
# ---------------------------------------------------------------------------
Write-Host "[2/8] Enumerating fine-grained password policies..." -ForegroundColor Yellow
$PsoData = @()
try {
    foreach ($p in (Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop)) {
        $applies = @()
        try { $applies = @($p.AppliesTo | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }) } catch {}
        $PsoData += [PSCustomObject]@{
            name="$($p.Name)"; precedence=[int]$p.Precedence; minLength=[int]$p.MinPasswordLength
            history=[int]$p.PasswordHistoryCount; complexity=[bool]$p.ComplexityEnabled
            maxAgeDays=[int]$p.MaxPasswordAge.TotalDays; lockoutThr=[int]$p.LockoutThreshold
            appliesTo=@($applies); appliesCount=@($applies).Count
        }
    }
    $PsoData = @($PsoData | Sort-Object precedence)
} catch { Write-Host "      PSOs not readable." -ForegroundColor DarkYellow }
Write-Host "      $($PsoData.Count) PSO(s)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Managed accounts + KDS
# ---------------------------------------------------------------------------
Write-Host "[3/8] Enumerating managed service accounts..." -ForegroundColor Yellow
$MsaData = @()
try {
    foreach ($m in (Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword,msDS-ManagedPasswordInterval,Enabled,objectClass -ErrorAction Stop)) {
        $isG = ("$($m.objectClass)" -like '*GroupManagedServiceAccount*')
        $princ = @()
        try { $princ = @($m.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }) } catch {}
        $MsaData += [PSCustomObject]@{
            name="$($m.Name)"; kind=$(if($isG){'gMSA'}else{'sMSA'}); enabled=[bool]$m.Enabled
            interval=$(if($m.'msDS-ManagedPasswordInterval'){[int]$m.'msDS-ManagedPasswordInterval'}else{$null})
            principals=@($princ); princCount=@($princ).Count
        }
    }
} catch { Write-Host "      No managed accounts or not readable." -ForegroundColor DarkYellow }
$KdsPresent = $null
try { $KdsPresent = @(Get-KdsRootKey -ErrorAction Stop).Count -gt 0 } catch { $KdsPresent = $null }
$gmsaCount = @($MsaData | Where-Object { $_.kind -eq 'gMSA' }).Count
Write-Host "      $($MsaData.Count) managed account(s) ($gmsaCount gMSA); KDS: $(if($KdsPresent -eq $true){'present'}elseif($KdsPresent -eq $false){'MISSING'}else{'unknown'})" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. LAPS
# ---------------------------------------------------------------------------
Write-Host "[4/8] Checking LAPS coverage..." -ForegroundColor Yellow
$LapsMode='None'; $LapsTotal=0; $LapsCovered=0; $LapsExpired=0; $LapsMissing=0; $LapsMissingList=@()
try {
    $schema = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
    $hasWin=$false; $hasLeg=$false
    try { $hasWin=[bool](Get-ADObject -SearchBase $schema -Filter "name -eq 'ms-LAPS-Password-Expiration-Time'" -ErrorAction SilentlyContinue) } catch {}
    try { $hasLeg=[bool](Get-ADObject -SearchBase $schema -Filter "name -eq 'ms-Mcs-AdmPwdExpirationTime'" -ErrorAction SilentlyContinue) } catch {}
    $attr=$null
    if ($hasWin) { $LapsMode='Windows LAPS'; $attr='msLAPS-PasswordExpirationTime' }
    elseif ($hasLeg) { $LapsMode='Legacy LAPS'; $attr='ms-Mcs-AdmPwdExpirationTime' }
    if ($attr) {
        foreach ($c in (Get-ADComputer -Filter 'Enabled -eq $true' -Properties $attr,operatingSystem -ErrorAction Stop)) {
            $LapsTotal++
            $exp = ConvertFrom-FileTimeSafe $c.$attr
            if ($null -ne $exp) { $LapsCovered++; if ($exp -lt $script:Now) { $LapsExpired++ } }
            else { $LapsMissing++; if ($LapsMissingList.Count -lt 2000) { $LapsMissingList += [PSCustomObject]@{ name="$($c.Name)"; os="$($c.operatingSystem)" } } }
        }
    }
} catch { Write-Host "      LAPS check unavailable: $($_.Exception.Message)" -ForegroundColor DarkYellow }
$LapsPct = $(if($LapsTotal -gt 0){[int]([math]::Round(($LapsCovered*100.0)/$LapsTotal))}else{0})
Write-Host "      LAPS: $LapsMode; $LapsCovered/$LapsTotal covered ($LapsPct%), $LapsExpired expired, $LapsMissing missing" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. LAPS read delegation (who can READ the LAPS password attribute)
# ---------------------------------------------------------------------------
Write-Host "[5/8] Auditing LAPS read delegation..." -ForegroundColor Yellow
$LapsDeleg=@(); $ld_total=0; $ld_susp=0; $ld_excess=0; $LapsDelegRan=$false
$ExpectedSidExact  = @('S-1-5-18','S-1-5-10','S-1-3-0','S-1-5-9','S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551')
$ExpectedRidSuffix = @('-512','-519','-518','-516','-521','-498','-500')
function Test-ExpectedPrincipal { param($sid)
    if(-not $sid){ return $false }
    if($ExpectedSidExact -contains $sid){ return $true }
    foreach($r in $ExpectedRidSuffix){ if($sid.EndsWith($r)){ return $true } }
    return $false
}
$sidCache=@{}
function Resolve-Principal { param($idref)
    $name="$idref"; $sid=$null
    try { $sid = ([System.Security.Principal.NTAccount]"$idref").Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
    if(-not $sid -and "$idref" -match '^S-\d-'){ $sid="$idref" }
    if($sid -and $sidCache.ContainsKey($sid)){ return $sidCache[$sid] }
    $info=[ordered]@{ name=$name; sid=$sid; type='Unknown'; enabled=$null; created=$null; isPriv=$false }
    if($sid){
        try {
            $o = Get-ADObject -Filter "objectSid -eq '$sid'" -Properties objectClass,adminCount,whenCreated,userAccountControl,samAccountName -ErrorAction SilentlyContinue | Select-Object -First 1
            if($o){
                $info.name = if($o.samAccountName){"$($o.samAccountName)"}else{"$($o.Name)"}
                $info.type = switch -Wildcard ("$($o.objectClass)"){ '*group*'{'Group';break} '*computer*'{'Computer';break} '*user*'{'User';break} default{"$($o.objectClass)"} }
                if($o.whenCreated){ $info.created=$o.whenCreated.ToString('yyyy-MM-dd') }
                if("$($o.objectClass)" -eq 'user' -or "$($o.objectClass)" -eq 'computer'){ $info.enabled = -not [bool]([int]($o.userAccountControl) -band 0x2) }
                if([int]($o.adminCount) -ge 1){ $info.isPriv=$true }
            }
        } catch {}
    }
    if(Test-ExpectedPrincipal $sid){ $info.isPriv=$true }
    $res=[pscustomobject]$info
    if($sid){ $sidCache[$sid]=$res }
    return $res
}
if($LapsMode -ne 'None'){
    $LapsDelegRan=$true
    try {
        $schemaNC=(Get-ADRootDSE).schemaNamingContext
        $lapsGuids=@{}
        $wanted = if($LapsMode -eq 'Legacy LAPS'){ @('ms-Mcs-AdmPwd') } else { @('msLAPS-Password','msLAPS-EncryptedPassword') }
        foreach($ld in $wanted){
            try { $o = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$ld)" -Properties schemaIDGUID -ErrorAction SilentlyContinue | Select-Object -First 1
                  if($o){ $lapsGuids[[guid]$o.schemaIDGUID]=$ld } } catch {}
        }
        $scopes = New-Object System.Collections.ArrayList
        [void]$scopes.Add([pscustomobject]@{ dn=$Domain.DistinguishedName; type='Domain' })
        foreach($ou in (Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue)){ [void]$scopes.Add([pscustomobject]@{ dn=$ou.DistinguishedName; type='OU' }) }
        if($IncludeComputerAcls){ foreach($cx in (Get-ADComputer -Filter * -ErrorAction SilentlyContinue)){ [void]$scopes.Add([pscustomobject]@{ dn=$cx.DistinguishedName; type='Computer' }) } }
        foreach($sc in $scopes){
            $sd=$null
            try { $sd=(Get-ADObject -Identity $sc.dn -Properties nTSecurityDescriptor -ErrorAction Stop).nTSecurityDescriptor } catch { continue }
            if(-not $sd){ continue }
            foreach($ace in $sd.Access){
                if("$($ace.AccessControlType)" -ne 'Allow'){ continue }
                if($ace.IsInherited){ continue }   # only explicit delegations; inherited ACEs repeat on every child OU
                $rights="$($ace.ActiveDirectoryRights)"; $ot=$ace.ObjectType; $kind=$null; $excessive=$false
                # The LAPS password is a CONFIDENTIAL attribute: generic ReadProperty/GenericRead does NOT expose it.
                # Only a grant on the specific LAPS attribute GUID (ReadProperty/ControlAccess) or full control (GenericAll) reads it.
                if($rights -match 'GenericAll'){ $kind='All properties (GenericAll)'; $excessive=$true }
                elseif($lapsGuids.ContainsKey($ot) -and ($rights -match 'ReadProperty' -or $rights -match 'ExtendedRight')){ $kind=$lapsGuids[$ot] }
                if(-not $kind){ continue }
                $p = Resolve-Principal $ace.IdentityReference
                if(Test-ExpectedPrincipal $p.sid){ continue }
                if($p.isPriv){ $class='Expected (privileged)'; $sev='low' }
                elseif($excessive){ $class='Excessive privilege'; $sev='high'; $ld_excess++ }
                else { $class='Suspicious delegation'; $sev='medium' }
                if($sev -ne 'low'){ $ld_susp++ }
                $ld_total++
                $LapsDeleg += [pscustomobject]@{
                    scope="$($sc.dn)"; scopeType=$sc.type; principal=$p.name; principalType=$p.type
                    enabled=$p.enabled; created=$p.created; isPriv=$p.isPriv
                    rights=$rights; attribute=$kind; inherited=[bool]$ace.IsInherited; class=$class; severity=$sev
                }
            }
        }
        $LapsDeleg=@($LapsDeleg | Sort-Object @{e={ switch($_.severity){'high'{0}'medium'{1}default{2}} }}, scope)
    } catch { Write-Host "      LAPS delegation scan failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
}
Write-Host "      $ld_total delegated grant(s); $ld_susp suspicious, $ld_excess excessive" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Risky user accounts
# ---------------------------------------------------------------------------
Write-Host "[6/8] Scanning user accounts for credential risks..." -ForegroundColor Yellow
$uprops = 'ServicePrincipalNames','PasswordNeverExpires','PasswordNotRequired','pwdLastSet','lastLogonTimestamp',
          'msDS-SupportedEncryptionTypes','adminCount','TrustedForDelegation','SIDHistory','Enabled'
$Accounts=@(); $c_spn=0;$c_never=0;$c_notreq=0;$c_deleg=0;$c_sidhist=0;$c_inactive=0;$c_stalesvc=0;$c_priv=0
try {
    foreach ($u in (Get-ADUser -Filter * -Properties $uprops -ErrorAction Stop)) {
        $spns=@($u.ServicePrincipalNames); $isSvc=$spns.Count -gt 0
        $pAge=Get-AgeDays (ConvertFrom-FileTimeSafe $u.pwdLastSet)
        $ll=ConvertFrom-FileTimeSafe $u.lastLogonTimestamp
        $enc=Get-EncAssessment $u.'msDS-SupportedEncryptionTypes'
        $priv=([int]($u.adminCount) -ge 1)
        $fNever=[bool]$u.PasswordNeverExpires
        $fNotReq=[bool]$u.PasswordNotRequired
        $fDeleg=[bool]$u.TrustedForDelegation
        $fSidHist=(@($u.SIDHistory).Count -gt 0)
        $llAge=Get-AgeDays $ll
        $fInactive=([bool]$u.Enabled -and $null -ne $llAge -and $llAge -gt $InactiveAccountDays)
        $fStale=($isSvc -and $pAge -ne $null -and $pAge -gt $ServiceAccountStalePasswordDays)
        $findings=@()
        if($fNever){$findings+='Password never expires';$c_never++}
        if($fNotReq){$findings+='Password not required';$c_notreq++}
        if($fDeleg){$findings+='Trusted for unconstrained delegation';$c_deleg++}
        if($fSidHist){$findings+='SID history present';$c_sidhist++}
        if($fInactive){$findings+="Enabled but inactive ($llAge days)";$c_inactive++}
        if($fStale){$findings+="Service-account password $pAge days old";$c_stalesvc++}
        if($isSvc){$c_spn++}
        if($priv){$c_priv++}
        if($findings.Count -gt 0 -or $isSvc -or $priv){
            $sev='low'
            if($fNotReq -or $fDeleg -or $fSidHist){$sev='high'}
            elseif($findings.Count -gt 0){$sev='medium'}
            $Accounts += [PSCustomObject]@{
                name="$($u.SamAccountName)"; enabled=[bool]$u.Enabled; isService=$isSvc; privileged=$priv
                spnCount=$spns.Count; pwdAgeDays=$pAge; lastLogon=$(if($ll){$ll.ToString('yyyy-MM-dd')}else{'never / unknown'})
                enc=$enc.Label; encClass=$enc.Class; severity=$sev; findings=@($findings)
                flags=[ordered]@{ neverExpires=$fNever; notRequired=$fNotReq; deleg=$fDeleg; sidHist=$fSidHist; inactive=$fInactive; staleSvc=$fStale }
            }
        }
    }
    $Accounts=@($Accounts | Sort-Object @{e={ switch($_.severity){'high'{0}'medium'{1}default{2}} }}, name)
} catch { Write-Host "      Account scan failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
Write-Host "      $($Accounts.Count) account(s) of interest; SPN:$c_spn neverExp:$c_never notReq:$c_notreq deleg:$c_deleg sidHist:$c_sidhist inactive:$c_inactive staleSvc:$c_stalesvc" -ForegroundColor Green

$KrbtgtAge=$null
try { $k=Get-ADUser 'krbtgt' -Properties pwdLastSet -ErrorAction Stop; $KrbtgtAge=Get-AgeDays (ConvertFrom-FileTimeSafe $k.pwdLastSet) } catch {}

# ---------------------------------------------------------------------------
# 6. Computer accounts
# ---------------------------------------------------------------------------
Write-Host "[7/8] Scanning computer accounts..." -ForegroundColor Yellow
$Computers=@(); $cc_stale=0;$cc_oldpwd=0;$cc_legacy=0;$cc_deleg=0;$cc_disabled=0; $CompTotal=0
try {
    foreach ($c in (Get-ADComputer -Filter * -Properties OperatingSystem,lastLogonTimestamp,pwdLastSet,Enabled,TrustedForDelegation -ErrorAction Stop)) {
        $CompTotal++
        $llDays=Get-AgeDays (ConvertFrom-FileTimeSafe $c.lastLogonTimestamp)
        $pwDays=Get-AgeDays (ConvertFrom-FileTimeSafe $c.pwdLastSet)
        $os="$($c.OperatingSystem)"
        $stale=($c.Enabled -and $llDays -ne $null -and $llDays -gt $StaleComputerDays)
        $oldpwd=($c.Enabled -and $pwDays -ne $null -and $pwDays -gt 90)
        $legacy=($os -match '2000|Windows XP|Server 2003|Server 2008|Windows 7|Windows 8|Server 2012|Vista')
        $deleg=[bool]$c.TrustedForDelegation
        $disabled=(-not $c.Enabled)
        $f=@()
        if($stale){$f+="No logon in $llDays days";$cc_stale++}
        if($oldpwd){$f+="Machine password $pwDays days old";$cc_oldpwd++}
        if($legacy){$f+='Legacy / end-of-life OS';$cc_legacy++}
        if($deleg){$f+='Unconstrained delegation (verify - DCs expected)';$cc_deleg++}
        if($disabled){$cc_disabled++}
        if($f.Count -gt 0 -or $disabled){
            $sev='low'
            if($legacy -or $deleg){$sev='high'} elseif($stale -or $oldpwd){$sev='medium'}
            $Computers += [PSCustomObject]@{
                name="$($c.Name)"; enabled=[bool]$c.Enabled; os=$os; lastLogonDays=$llDays; pwdAgeDays=$pwDays
                severity=$sev; findings=@($f)
                flags=[ordered]@{ stale=$stale; oldPwd=$oldpwd; legacyOS=[bool]$legacy; deleg=$deleg; disabled=$disabled }
            }
        }
    }
    $Computers=@($Computers | Sort-Object @{e={ switch($_.severity){'high'{0}'medium'{1}default{2}} }}, name)
} catch { Write-Host "      Computer scan failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
Write-Host "      $CompTotal computer(s); stale:$cc_stale oldPwd:$cc_oldpwd legacyOS:$cc_legacy deleg:$cc_deleg disabled:$cc_disabled" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6c. Foreign Security Principals (external/trusted-domain principals in local groups)
# ---------------------------------------------------------------------------
Write-Host "[+]   Enumerating foreign security principals..." -ForegroundColor Yellow
$Fsps=@(); $fsp_orphaned=0; $fsp_priv=0
$WellKnownFsp = @('S-1-5-4','S-1-5-11','S-1-5-9','S-1-1-0','S-1-5-2','S-1-5-3','S-1-5-6','S-1-5-7','S-1-5-10','S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-14','S-1-5-15','S-1-5-17')
try {
    $fspBase = "CN=ForeignSecurityPrincipals,$($Domain.DistinguishedName)"
    foreach($o in @(Get-ADObject -SearchBase $fspBase -LDAPFilter '(objectClass=foreignSecurityPrincipal)' -Properties objectSid,memberOf,name -ErrorAction Stop)) {
        $sid = if($o.objectSid){ "$($o.objectSid.Value)" } else { "$($o.Name)" }
        if($WellKnownFsp -contains $sid) { continue }        # built-in well-known identities
        if($sid -like 'S-1-5-32-*') { continue }             # built-in local groups
        if($sid -notlike 'S-1-5-21-*') { continue }          # keep only real domain/forest principals
        $resolved=$null
        try { $resolved = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value } catch {}
        $orphaned = (-not $resolved)
        $groups = @($o.memberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' })
        $priv = (@($groups | Where-Object { $_ -match 'Admin|Operator|Domain Controllers|Key Admins' }).Count -gt 0)
        if($orphaned){ $fsp_orphaned++ }
        if($priv){ $fsp_priv++ }
        $Fsps += [pscustomobject]@{
            sid=$sid; resolved=$(if($resolved){$resolved}else{'(unresolved)'}); orphaned=$orphaned
            groups=@($groups); groupCount=@($groups).Count; privileged=$priv
            severity=$(if($priv){'high'}elseif($orphaned){'medium'}else{'low'})
        }
    }
    $Fsps=@($Fsps | Sort-Object @{e={ switch($_.severity){'high'{0}'medium'{1}default{2}} }}, sid)
} catch { Write-Host "      FSP container not readable: $($_.Exception.Message)" -ForegroundColor DarkYellow }
Write-Host "      $($Fsps.Count) external principal(s); $fsp_orphaned orphaned, $fsp_priv in privileged groups" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6d. Orphaned SIDs in object ACLs (read-only: detect + count, never remove)
# An ACE whose identity is still a raw domain SID string = the referenced account
# was deleted, leaving a dangling permission. Inspired by Ali Tajran's cleanup script.
# ---------------------------------------------------------------------------
$OrphanRan=$false; $orphanScanned=0; $orphanObjWith=0; $orphanAces=0
$OrphanSids=@{}
if (-not $SkipOrphanedSids) {
    if (-not $OrphanedSidSearchBase) { $OrphanedSidSearchBase = $Domain.DistinguishedName }
    $domSid = "$($Domain.DomainSID.Value)"
    Write-Host "[+]   Scanning object ACLs for orphaned SIDs (can take a while on large domains)..." -ForegroundColor Yellow
    try {
        Get-ADObject -LDAPFilter '(objectClass=*)' -SearchBase $OrphanedSidSearchBase -SearchScope Subtree -Properties nTSecurityDescriptor -ResultPageSize 500 -ErrorAction Stop | ForEach-Object {
            $script:orphanScanned++
            $sd = $_.nTSecurityDescriptor
            if ($null -eq $sd) { return }
            $dn = $_.DistinguishedName
            $seen = @{}
            foreach ($ace in $sd.Access) {
                $val = "$($ace.IdentityReference)"
                if ($val -like "$domSid-*") {      # unresolved SID from THIS domain
                    $script:orphanAces++
                    if (-not $script:OrphanSids.ContainsKey($val)) { $script:OrphanSids[$val] = [pscustomobject]@{ sid=$val; aces=0; objects=0; sample=$dn } }
                    $script:OrphanSids[$val].aces++
                    if (-not $seen.ContainsKey($val)) { $script:OrphanSids[$val].objects++; $seen[$val]=$true }
                }
            }
            if ($seen.Count -gt 0) { $script:orphanObjWith++ }
        }
        $OrphanRan = $true
    } catch { Write-Host "      Orphaned-SID scan failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    Write-Host "      $orphanScanned object(s) scanned; $($OrphanSids.Count) distinct orphaned SID(s) across $orphanObjWith object(s), $orphanAces ACE(s)" -ForegroundColor Green
} else {
    Write-Host "[+]   Orphaned-SID scan skipped (-SkipOrphanedSids)" -ForegroundColor DarkGray
}
$OrphanList = @($OrphanSids.Values | Sort-Object aces -Descending | Select-Object -First 500)

# ---------------------------------------------------------------------------
# 7. Assemble + render
# ---------------------------------------------------------------------------
Write-Host "[8/8] Rendering HTML..." -ForegroundColor Yellow
$Summary = [ordered]@{
    domain=$DomainDNS; generatedAt=$GeneratedAt
    policyOk=[bool]$PolOk; policy=@($PolRows); policyFail=$PolFail; policyWarn=$PolWarn
    psos=@($PsoData); psoCount=@($PsoData).Count
    msas=@($MsaData); msaCount=@($MsaData).Count; gmsaCount=$gmsaCount; kdsPresent=$KdsPresent
    laps=[ordered]@{ mode=$LapsMode; total=$LapsTotal; covered=$LapsCovered; expired=$LapsExpired; missing=$LapsMissing; pct=$LapsPct; missingList=@($LapsMissingList) }
    accounts=@($Accounts)
    counts=[ordered]@{ spn=$c_spn; privileged=$c_priv; neverExpires=$c_never; notRequired=$c_notreq; deleg=$c_deleg; sidHist=$c_sidhist; inactive=$c_inactive; staleSvc=$c_stalesvc }
    computers=@($Computers); computerTotal=$CompTotal
    compCounts=[ordered]@{ stale=$cc_stale; oldPwd=$cc_oldpwd; legacyOS=$cc_legacy; deleg=$cc_deleg; disabled=$cc_disabled }
    lapsDeleg=@($LapsDeleg); lapsDelegRan=[bool]$LapsDelegRan; ldCounts=[ordered]@{ total=$ld_total; suspicious=$ld_susp; excessive=$ld_excess }
    fsps=@($Fsps); fspCount=@($Fsps).Count; fspCounts=[ordered]@{ orphaned=$fsp_orphaned; privileged=$fsp_priv }
    orphanSids=[ordered]@{ ran=[bool]$OrphanRan; scanned=$orphanScanned; objects=$orphanObjWith; distinct=$OrphanSids.Count; aces=$orphanAces; list=@($OrphanList) }
    krbtgtAge=$KrbtgtAge; staleDays=$ServiceAccountStalePasswordDays; staleComputerDays=$StaleComputerDays
}
$DataJSON = ConvertTo-Json -InputObject $Summary -Depth 12 -Compress

$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Account &amp; Credential Security — $DomainDNS</title>
<style id="bi-icons">/* Bootstrap Icons 1.10.0 - subset (37 glyphs) embedded for offline use */
@font-face{font-display:block;font-family:"bootstrap-icons";src:url(data:font/woff2;base64,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) format("woff2")}
.bi::before,[class^="bi-"]::before,[class*=" bi-"]::before{display:inline-block;font-family:bootstrap-icons!important;font-style:normal;font-weight:normal!important;font-variant:normal;text-transform:none;line-height:1;vertical-align:-.125em;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
.bi-bar-chart-line::before{content:"\f17c"}
.bi-box-arrow-up-right::before{content:"\f1c5"}
.bi-check-circle-fill::before{content:"\f26a"}
.bi-clock-history::before{content:"\f292"}
.bi-collection::before{content:"\f2cc"}
.bi-diagram-3::before{content:"\f2ee"}
.bi-download::before{content:"\f30a"}
.bi-exclamation-octagon::before{content:"\f337"}
.bi-exclamation-octagon-fill::before{content:"\f336"}
.bi-exclamation-triangle::before{content:"\f33b"}
.bi-exclamation-triangle-fill::before{content:"\f33a"}
.bi-eye::before{content:"\f341"}
.bi-globe::before{content:"\f3ee"}
.bi-hand-index-thumb::before{content:"\f402"}
.bi-hourglass-split::before{content:"\f41f"}
.bi-info-circle::before{content:"\f431"}
.bi-info-circle-fill::before{content:"\f430"}
.bi-key::before{content:"\f44f"}
.bi-key-fill::before{content:"\f44e"}
.bi-layers::before{content:"\f45b"}
.bi-lightbulb::before{content:"\f46b"}
.bi-list-ul::before{content:"\f478"}
.bi-moon-stars::before{content:"\f496"}
.bi-pc-display::before{content:"\f6a6"}
.bi-pc-display-horizontal::before{content:"\f6a5"}
.bi-person-badge::before{content:"\f4d3"}
.bi-person-dash::before{content:"\f4d9"}
.bi-person-x::before{content:"\f4e0"}
.bi-printer::before{content:"\f501"}
.bi-robot::before{content:"\f6b1"}
.bi-search::before{content:"\f52a"}
.bi-shield-check::before{content:"\f52f"}
.bi-shield-exclamation::before{content:"\f530"}
.bi-shield-lock::before{content:"\f538"}
.bi-shield-slash::before{content:"\f53d"}
.bi-slash-circle::before{content:"\f567"}
.bi-sliders::before{content:"\f56b"}
</style>
<style>
:root {
  --bg:#f8fafc; --surface:#ffffff; --surface2:#f1f5f9; --surface3:#e2e8f0;
  --border:#e2e8f0; --text:#0f172a; --muted:#64748b;
  --accent:#4f46e5; --accent-soft:#e0e7ff;
  --blue:#3b82f6; --blue-soft:#dbeafe; --green:#10b981; --green-soft:#d1fae5;
  --red:#ef4444; --red-soft:#fee2e2; --amber:#f59e0b; --amber-soft:#fef3c7;
  --teal:#14b8a6; --teal-soft:#ccfbf1; --purple:#8b5cf6; --purple-soft:#ede9fe;
  --radius:12px; --radius-sm:8px;
  --shadow:0 4px 6px -1px rgb(0 0 0 / 0.05), 0 2px 4px -2px rgb(0 0 0 / 0.05);
  --shadow-hover:0 10px 15px -3px rgb(0 0 0 / 0.08), 0 4px 6px -4px rgb(0 0 0 / 0.08);
  --font:'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
[data-theme="dark"] {
  --bg:#0f172a; --surface:#1e293b; --surface2:#334155; --surface3:#475569;
  --border:#334155; --text:#f8fafc; --muted:#94a3b8;
  --accent:#6366f1; --accent-soft:rgba(99,102,241,0.15);
  --blue:#60a5fa; --blue-soft:rgba(59,130,246,0.15); --green:#34d399; --green-soft:rgba(16,185,129,0.15);
  --red:#f87171; --red-soft:rgba(239,68,68,0.15); --amber:#fbbf24; --amber-soft:rgba(245,158,11,0.15);
  --teal:#2dd4bf; --teal-soft:rgba(20,184,166,0.15); --purple:#a78bfa; --purple-soft:rgba(139,92,246,0.15);
  --shadow:0 4px 6px -1px rgb(0 0 0 / 0.2), 0 2px 4px -2px rgb(0 0 0 / 0.2);
  --shadow-hover:0 10px 15px -3px rgb(0 0 0 / 0.3), 0 4px 6px -4px rgb(0 0 0 / 0.3);
}
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:var(--font); background:var(--bg); color:var(--text); min-height:100vh; font-size:14px; -webkit-font-smoothing:antialiased; }
.topbar { background:var(--surface); border-bottom:1px solid var(--border); padding:14px 28px; display:flex; align-items:center; gap:16px; position:sticky; top:0; z-index:100; box-shadow:var(--shadow); }
.brand { display:flex; align-items:center; gap:10px; font-size:16px; font-weight:700; }
.brand i { font-size:22px; color:var(--accent); }
.topmeta { margin-left:auto; font-size:12px; color:var(--muted); text-align:right; line-height:1.4; }
.topmeta b { color:var(--text); font-weight:600; }
.btn { background:var(--surface); border:1px solid var(--border); color:var(--text); padding:8px 14px; border-radius:var(--radius-sm); font-size:13px; font-weight:500; cursor:pointer; display:flex; align-items:center; gap:8px; font-family:var(--font); }
.btn:hover { background:var(--surface2); }
.btn i { font-size:14px; color:var(--muted); }
.sep { width:1px; height:24px; background:var(--border); }
.wrap { max-width:1080px; margin:0 auto; padding:28px 64px; }
@media(max-width:760px){ .wrap { padding:20px 18px; } }
.section-label { font-size:18px; font-weight:700; color:#465262; margin:30px 0 16px; display:flex; align-items:center; gap:8px; }
.section-label:first-child { margin-top:4px; }
.section-label i { color:inherit; font-size:16px; }
.section-label .tools { margin-left:auto; display:flex; gap:8px; }
.mini-btn { background:var(--surface); border:1px solid var(--border); color:var(--muted); font-size:11px; font-weight:600; padding:5px 10px; border-radius:var(--radius-sm); cursor:pointer; display:inline-flex; align-items:center; gap:5px; letter-spacing:0; text-transform:none; font-family:var(--font); }
.mini-btn:hover { background:var(--surface2); color:var(--text); border-color:var(--accent-soft); }
.mini-btn i { font-size:12px; }
.kpi-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:16px; margin-bottom:24px; }
.kpi { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:18px; display:flex; align-items:center; gap:16px; box-shadow:var(--shadow); }
.kpi .chip { width:48px; height:48px; border-radius:var(--radius-sm); flex-shrink:0; display:flex; align-items:center; justify-content:center; font-size:22px; background:transparent; color:var(--text); }
.kpi .val { font-size:26px; font-weight:800; line-height:1.1; letter-spacing:-0.02em; }
.kpi .lbl { font-size:12px; color:var(--muted); font-weight:500; margin-top:4px; }
/* card icons are plain (no chip background); risk shown via tags */
.dash-grid { display:grid; grid-template-columns:repeat(12, 1fr); gap:16px; margin-bottom:28px; }
.chart-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:18px 20px; box-shadow:var(--shadow); display:flex; flex-direction:column; }
.chart-card h3 { font-size:13px; font-weight:600; margin-bottom:16px; display:flex; align-items:center; gap:8px; }
.chart-card h3 i { color:var(--accent); font-size:15px; }
.col-4 { grid-column:span 4; } .col-6 { grid-column:span 6; } .col-8 { grid-column:span 8; } .col-12 { grid-column:span 12; }
@media(max-width:900px){ .col-4,.col-6,.col-8 { grid-column:span 12; } }
.donut-flex { display:flex; align-items:center; gap:20px; flex-wrap:wrap; justify-content:center; }
.donut-legend { display:flex; flex-direction:column; gap:9px; font-size:12.5px; }
.donut-legend .dl { display:flex; align-items:center; gap:8px; }
.donut-legend .dl .dot { width:11px; height:11px; border-radius:3px; }
.donut-legend .dl b { margin-left:4px; }
.hbar { display:flex; flex-direction:column; gap:11px; }
.hbar-row { display:grid; grid-template-columns:160px 1fr 34px; align-items:center; gap:10px; font-size:12.5px; }
.hbar-label { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; text-align:right; font-weight:500; }
.hbar-track { background:var(--surface2); border-radius:999px; height:18px; overflow:hidden; }
.hbar-fill { height:100%; border-radius:999px; transition:width 0.5s ease; }
.hbar-val { font-weight:700; font-size:11px; color:var(--muted); }
.tbl { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; box-shadow:var(--shadow); }
.tbl th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted); font-weight:600; padding:12px 16px; border-bottom:1px solid var(--border); background:var(--surface2); }
.tbl td { padding:12px 16px; border-bottom:1px solid var(--border); font-size:13px; }
.tbl tr:last-child td { border-bottom:none; }
.tag { font-size:11px; font-weight:700; padding:3px 9px; border-radius:999px; display:inline-block; }
.tag.ok { background:var(--green-soft); color:var(--green); }
.tag.medium,.tag.warn { background:var(--amber-soft); color:var(--amber); }
.tag.high { background:var(--red-soft); color:var(--red); }
.tag.mut { background:var(--surface3); color:var(--muted); }
.muted-note { color:var(--muted); font-size:13px; padding:16px; background:var(--surface2); border-radius:var(--radius-sm); border:1px dashed var(--border); text-align:center; }
.hint { display:flex; gap:10px; padding:12px 14px; border-radius:var(--radius-sm); font-size:12.5px; line-height:1.55; border:1px solid var(--border); margin-bottom:14px; }
.hint i { font-size:16px; flex-shrink:0; margin-top:1px; }
.hint b { font-weight:700; }
.hint.info { background:var(--blue-soft); border-color:rgba(59,130,246,0.25); } .hint.info i { color:var(--blue); }
.hint.warn { background:var(--amber-soft); border-color:rgba(245,158,11,0.25); } .hint.warn i { color:var(--amber); }
.hint.tip { background:var(--purple-soft); border-color:rgba(139,92,246,0.25); } .hint.tip i { color:var(--purple); }
.cat-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(232px, 1fr)); gap:14px; margin-bottom:8px; }
.cat-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:16px; box-shadow:var(--shadow); display:flex; flex-direction:column; gap:10px; }
.cat-top { display:flex; align-items:center; gap:12px; }
.cat-ico { width:48px; height:48px; border-radius:var(--radius-sm); display:flex; align-items:center; justify-content:center; font-size:22px; background:transparent; color:var(--text); flex-shrink:0; }
.sev-tag { font-size:10px; font-weight:700; padding:3px 9px; border-radius:999px; text-transform:uppercase; letter-spacing:0.03em; margin-left:auto; align-self:flex-start; } .sev-tag.high { background:var(--red-soft); color:var(--red); } .sev-tag.medium { background:var(--amber-soft); color:var(--amber); } .sev-tag.low { background:var(--blue-soft); color:var(--blue); }
.cat-count { font-size:26px; font-weight:800; line-height:1.1; letter-spacing:-0.02em; }
.cat-label { font-size:12px; color:var(--muted); font-weight:500; }
.cat-actions { display:flex; gap:8px; }
.cat-actions .mini-btn { flex:1; justify-content:center; }
.cat-actions .mini-btn.dis { opacity:0.4; pointer-events:none; }
.layout { display:grid; grid-template-columns:1fr 1fr; gap:24px; }
@media(max-width:900px) { .layout { grid-template-columns:1fr; } }
.panel-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; box-shadow:var(--shadow); display:flex; flex-direction:column; }
.panel-head { padding:16px 20px; border-bottom:1px solid var(--border); font-size:14px; font-weight:600; display:flex; align-items:center; gap:10px; }
.panel-head i { color:var(--muted); font-size:16px; }
.list-search { padding:12px 20px; border-bottom:1px solid var(--border); }
.list-search input { width:100%; background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:10px 14px; color:var(--text); font-size:13px; outline:none; font-family:var(--font); }
.list-search input:focus { border-color:var(--accent); box-shadow:0 0 0 3px var(--accent-soft); background:var(--surface); }
.acct-list { padding:10px; max-height:620px; overflow-y:auto; display:flex; flex-direction:column; gap:8px; flex:1; }
.acct-item { display:flex; align-items:center; gap:12px; padding:12px 14px; border:1px solid var(--border); border-radius:var(--radius-sm); cursor:pointer; background:var(--surface); }
.acct-item:hover { background:var(--surface2); border-color:var(--accent-soft); }
.acct-item.sel { background:var(--accent-soft); border-color:var(--accent); }
.acct-item.dimmed { display:none; }
.acct-ico { width:38px; height:38px; border-radius:var(--radius-sm); flex-shrink:0; display:flex; align-items:center; justify-content:center; font-size:17px; background:var(--accent-soft); color:var(--accent); }
.acct-ico.sev-high { background:var(--red-soft); color:var(--red); }
.acct-ico.sev-medium { background:var(--amber-soft); color:var(--amber); }
.acct-ico.sev-low { background:var(--blue-soft); color:var(--blue); }
.acct-body { flex:1; min-width:0; }
.acct-name { font-size:13.5px; font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.acct-sub { font-size:11px; color:var(--muted); margin-top:2px; display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
.pill { font-size:10px; font-weight:600; padding:1px 7px; border-radius:999px; background:var(--surface3); color:var(--text); }
.detail { flex:1; display:flex; flex-direction:column; }
.detail-empty { padding:60px 20px; text-align:center; color:var(--muted); font-size:14px; margin:auto; }
.detail-empty i { font-size:32px; color:var(--border); margin-bottom:16px; display:block; }
.detail-head { padding:20px; border-bottom:1px solid var(--border); }
.detail-title { font-size:18px; font-weight:700; display:flex; align-items:center; gap:10px; word-break:break-word; }
.detail-sub { font-size:12px; color:var(--muted); margin-top:6px; }
.detail-body { padding:24px 20px; overflow-y:auto; flex:1; }
.dsec { margin-bottom:28px; } .dsec:last-child { margin-bottom:0; }
.dsec-t { font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:14px; display:flex; align-items:center; gap:8px; }
.dsec-t i { color:var(--muted); font-size:14px; }
.dsec-t::after { content:''; flex:1; height:1px; background:var(--border); margin-left:8px; }
.kv-grid { display:grid; grid-template-columns:repeat(2, 1fr); gap:10px; }
.kv { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:11px 13px; }
.kv .k { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:0.04em; font-weight:600; }
.kv .v { font-size:14px; font-weight:600; margin-top:3px; display:flex; align-items:center; gap:6px; }
.kv .v.good { color:var(--green); } .kv .v.bad { color:var(--red); } .kv .v.warn { color:var(--amber); } .kv .v.mut { color:var(--muted); }
.findings { display:flex; flex-direction:column; gap:8px; }
.finding { display:flex; align-items:flex-start; gap:10px; padding:11px 13px; border-radius:var(--radius-sm); font-size:12.5px; line-height:1.5; border:1px solid var(--border); }
.finding i { font-size:15px; flex-shrink:0; margin-top:1px; }
.finding.high { background:var(--red-soft); border-color:rgba(239,68,68,0.25); } .finding.high i { color:var(--red); }
.finding.medium { background:var(--amber-soft); border-color:rgba(245,158,11,0.25); } .finding.medium i { color:var(--amber); }
.finding.low { background:var(--blue-soft); border-color:rgba(59,130,246,0.25); } .finding.low i { color:var(--blue); }
.no-findings { color:var(--green); font-size:13px; display:flex; align-items:center; gap:8px; padding:12px; background:var(--green-soft); border-radius:var(--radius-sm); }
::-webkit-scrollbar { width:8px; height:8px; } ::-webkit-scrollbar-track { background:transparent; }
::-webkit-scrollbar-thumb { background:var(--surface3); border-radius:999px; border:2px solid var(--surface); }
/* ZTA-style app shell */
.app { display:flex; align-items:flex-start; max-width:1260px; margin:0 auto; }
.sidenav { width:232px; flex-shrink:0; position:sticky; top:56px; align-self:flex-start; padding:20px 12px; max-height:calc(100vh - 56px); overflow-y:auto; }
.navgroup { font-size:10px; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted); font-weight:700; padding:6px 12px 6px; }
.navitem { display:flex; align-items:center; gap:10px; padding:9px 12px; border-radius:var(--radius-sm); font-size:13px; color:var(--muted); cursor:pointer; font-weight:500; text-decoration:none; transition:all 0.15s; }
.navitem:hover { background:var(--surface2); color:var(--text); }
.navitem.active { background:var(--accent-soft); color:var(--accent); font-weight:600; }
.navitem i { font-size:15px; width:18px; text-align:center; }
.content { flex:1; min-width:0; padding:26px 40px; }
.section-label[id] { scroll-margin-top:78px; border-top:1px solid var(--border); padding-top:22px; margin-top:30px; }
.section-label:first-child { border-top:none; padding-top:0; margin-top:6px; }
@media(max-width:900px){ .app { flex-direction:column; } .sidenav { position:static; width:100%; max-height:none; display:flex; flex-wrap:wrap; gap:6px; padding:10px 16px; border-bottom:1px solid var(--border); } .navgroup { display:none; } .content { padding:20px 16px; } }
/* tooltip + scrollbox */
.scrollbox { max-height:440px; overflow:auto; border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow); }
.scrollbox .tbl { border:none; box-shadow:none; border-radius:0; overflow:visible; }
.scrollbox .tbl thead th { position:sticky; top:0; z-index:2; box-shadow:inset 0 -1px 0 var(--border); }
.tip { position:relative; display:inline-flex; align-items:center; cursor:help; color:var(--muted); margin-left:4px; }
.tip>i { font-size:14px; }
.tipbox { position:absolute; left:0; top:150%; background:var(--text); color:var(--surface); padding:9px 11px; border-radius:7px; font-size:11px; font-weight:500; width:290px; line-height:1.55; opacity:0; visibility:hidden; transition:.15s; z-index:60; text-transform:none; letter-spacing:0; box-shadow:var(--shadow-hover); }
.tip:hover .tipbox { opacity:1; visibility:visible; }
</style>
</head>
<body data-theme="light">

<div class="topbar">
  <div class="brand"><i class="bi bi-key"></i> Account &amp; Credential Security</div>
  <div class="sep"></div>
  <button class="btn" onclick="toggleTheme()"><i class="bi bi-moon-stars"></i> Theme</button>
  <button class="btn" onclick="window.print()"><i class="bi bi-printer"></i> Print</button>
  <div class="topmeta">Domain: <b>$DomainDNS</b><br>Generated: $GeneratedAt</div>
</div>

<div class="app">
  <nav class="sidenav" id="sidenav"></nav>
  <div class="content">
  <div class="section-label" id="sec-overview"><i class="bi bi-bar-chart-line"></i> Insights Dashboard</div>
  <div class="kpi-grid" id="kpis"></div>
  <div class="dash-grid" id="dashboard"></div>

  <div class="section-label" id="sec-policy"><i class="bi bi-shield-lock"></i> Password & Lockout Policy
  </div>
  <div id="policyHint"></div>
  <div id="policySection"></div>

  <div class="section-label" id="sec-pso"><i class="bi bi-sliders"></i> Fine-Grained Password Policies
    <div class="tools" id="psoTools"></div></div>
  <div id="psoSection"></div>

  <div class="section-label" id="sec-msa"><i class="bi bi-robot"></i> Managed Service Accounts
    <div class="tools" id="msaTools"></div></div>
  <div id="msaHint"></div>
  <div id="msaSection"></div>

  <div class="section-label" id="sec-laps"><i class="bi bi-pc-display"></i> LAPS Coverage
    <div class="tools" id="lapsTools"></div></div>
  <div id="lapsHint"></div>
  <div id="lapsSection"></div>

  <div class="section-label" id="sec-ldg"><i class="bi bi-diagram-3"></i> LAPS Read Delegation
    <div class="tools" id="ldgTools"></div></div>
  <div id="ldgHint"></div>
  <div class="kpi-grid" id="ldgCards" style="margin-bottom:14px"></div>
  <div id="ldgSection"></div>

  <div class="section-label" id="sec-krbtgt"><i class="bi bi-key-fill"></i> krbtgt</div>
  <div id="krbSection"></div>

  <div class="section-label" id="sec-users"><i class="bi bi-person-badge"></i> User Account Risks</div>
  <div id="acctHint"></div>
  <div class="cat-grid" id="acctCats"></div>
  <div class="section-label" style="margin-top:22px"><i class="bi bi-search"></i> High-severity explorer</div>
  <div class="layout">
    <div class="panel-card">
      <div class="panel-head"><i class="bi bi-list-ul"></i> High-severity accounts <span class="tools" id="highTools" style="margin-left:auto"></span></div>
      <div class="list-search"><input id="acctSearch" type="text" placeholder="Filter by name…" oninput="filterList()"></div>
      <div class="acct-list" id="acctList"></div>
    </div>
    <div class="panel-card">
      <div class="panel-head"><i class="bi bi-info-circle"></i> Details</div>
      <div class="detail" id="detail">
        <div class="detail-empty"><i class="bi bi-hand-index-thumb"></i>Select an account to view its attributes and findings.</div>
      </div>
    </div>
  </div>

  <div class="section-label" id="sec-computers" style="margin-top:30px"><i class="bi bi-pc-display-horizontal"></i> Computer Account Risks</div>
  <div id="compHint"></div>
  <div class="cat-grid" id="compCats"></div>

  <div class="section-label" id="sec-fsp"><i class="bi bi-globe"></i> Foreign Security Principals <span class="tip"><i class="bi bi-info-circle"></i><span class="tipbox">Placeholder objects for security principals from trusted external domains or forests that have been added to groups in this domain. Built-in well-known identities are excluded. Unresolved = the external account was likely deleted (stale membership).</span></span><div class="tools" id="fspTools"></div></div>
  <div id="fspHint"></div>
  <div id="fspSection"></div>

  <div class="section-label" id="sec-orphansid"><i class="bi bi-person-x"></i> Orphaned SIDs <span class="tip"><i class="bi bi-info-circle"></i><span class="tipbox">Permissions left in object ACLs that point to deleted accounts - SIDs that no longer resolve to a name. Detection only; nothing is removed.</span></span><div class="tools" id="orphTools"></div></div>
  <div id="orphHint"></div>
  <div class="kpi-grid" id="orphCards" style="margin-bottom:14px"></div>
  <div id="orphSection"></div>
  </div>
</div>

<script>
const D = $DataJSON;
const ACC = Array.isArray(D.accounts) ? D.accounts : [];
const COMP = Array.isArray(D.computers) ? D.computers : [];
const LDG = Array.isArray(D.lapsDeleg) ? D.lapsDeleg : [];
const FSP = Array.isArray(D.fsps) ? D.fsps : [];
const ORPH = D.orphanSids || {};
const ORPH_LIST = Array.isArray(ORPH.list) ? ORPH.list : [];
function esc(s){ return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function sevIco(s){ return s==='high'?'bi-exclamation-octagon-fill':s==='medium'?'bi-exclamation-triangle-fill':'bi-info-circle-fill'; }
function sevColor(s){ return s==='high'?'var(--red)':s==='medium'?'var(--amber)':'var(--blue)'; }

/* ---------- CSV + companion-HTML export (client-side, offline) ---------- */
function csvCell(v){ v=(v==null?'':''+v); if(/[",\n]/.test(v)){ v='"'+v.replace(/"/g,'""')+'"'; } return v; }
function downloadCsv(filename, headers, rows){
  let out = headers.map(csvCell).join(',')+'\n';
  rows.forEach(r=>{ out += r.map(csvCell).join(',')+'\n'; });
  const blob = new Blob(['\ufeff'+out], {type:'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 200);
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
function toolBtns(containerId, csvFn, openFn){
  const el = document.getElementById(containerId); if(!el) return;
  let h = '';
  if(openFn) h += '<button class="mini-btn" onclick="'+openFn+'"><i class="bi bi-box-arrow-up-right"></i> Open</button>';
  if(csvFn)  h += '<button class="mini-btn" onclick="'+csvFn+'"><i class="bi bi-download"></i> CSV</button>';
  el.innerHTML = h;
}

/* ---------- dashboard ---------- */
function kpiCard(v,l,ico,cls){ return '<div class="kpi '+(cls||'')+'"><div class="chip"><i class="bi '+ico+'"></i></div><div class="body"><div class="val">'+v+'</div><div class="lbl">'+l+'</div></div></div>'; }
function renderKpis(){
  const c=D.counts||{}, laps=D.laps||{}, cc=D.compCounts||{};
  let h='';
  h+=kpiCard((D.policyFail||0)+(D.policyWarn||0),'Policy issues','bi-shield-lock',(D.policyFail>0?'k-red':(D.policyWarn>0?'k-amber':'k-green')));
  h+=kpiCard(c.spn||0,'Service (SPN) accounts','bi-robot','k-blue');
  h+=kpiCard(D.gmsaCount||0,'gMSA accounts','bi-shield-check',(D.gmsaCount>0?'k-green':'k-teal'));
  h+=kpiCard((laps.mode&&laps.mode!=='None')?(laps.pct+'%'):'n/a','LAPS coverage','bi-pc-display',(laps.pct>=90?'k-green':(laps.pct>=50?'k-amber':'k-red')));
  h+=kpiCard((c.notRequired||0)+(c.deleg||0)+(c.sidHist||0),'High-risk user flags','bi-exclamation-octagon','k-red');
  h+=kpiCard((cc.legacyOS||0)+(cc.deleg||0),'Computer high-risks','bi-pc-display-horizontal',((cc.legacyOS||0)+(cc.deleg||0)>0?'k-red':'k-green'));
  document.getElementById('kpis').innerHTML=h;
}
function hbar(rows){
  const max=Math.max(1, ...rows.map(r=>r.v));
  return '<div class="hbar">'+rows.map(r=>'<div class="hbar-row"><div class="hbar-label">'+esc(r.l)+'</div><div class="hbar-track"><div class="hbar-fill" style="width:'+((r.v/max)*100)+'%;background:'+r.c+'"></div></div><div class="hbar-val">'+r.v+'</div></div>').join('')+'</div>';
}
function donut(pct,label,color){
  const r=42,c=2*Math.PI*r,off=c*(1-pct/100);
  return '<svg viewBox="0 0 110 110" width="130" height="130"><circle cx="55" cy="55" r="'+r+'" fill="none" stroke="var(--surface3)" stroke-width="12"/><circle cx="55" cy="55" r="'+r+'" fill="none" stroke="'+color+'" stroke-width="12" stroke-linecap="round" stroke-dasharray="'+c+'" stroke-dashoffset="'+off+'" transform="rotate(-90 55 55)"/><text x="55" y="52" text-anchor="middle" font-size="22" font-weight="800" fill="var(--text)">'+pct+'%</text><text x="55" y="70" text-anchor="middle" font-size="9" fill="var(--muted)">'+label+'</text></svg>';
}
function renderDashboard(){
  const c=D.counts||{}, laps=D.laps||{};
  const rows=[{l:'Never expires',v:c.neverExpires||0,c:'var(--amber)'},{l:'Password not required',v:c.notRequired||0,c:'var(--red)'},{l:'Unconstrained delegation',v:c.deleg||0,c:'var(--red)'},{l:'SID history',v:c.sidHist||0,c:'var(--red)'},{l:'Inactive but enabled',v:c.inactive||0,c:'var(--amber)'},{l:'Stale svc password',v:c.staleSvc||0,c:'var(--amber)'}];
  let h='<div class="chart-card col-8"><h3><i class="bi bi-exclamation-triangle"></i> User credential risk flags</h3>'+hbar(rows)+'</div>';
  const hasLaps=laps.mode&&laps.mode!=='None';
  h+='<div class="chart-card col-4"><h3><i class="bi bi-pc-display"></i> LAPS ('+esc(laps.mode||'None')+')</h3>'
    +(hasLaps?('<div class="donut-flex">'+donut(laps.pct||0,'covered',(laps.pct>=90?'var(--green)':(laps.pct>=50?'var(--amber)':'var(--red)')))
      +'<div class="donut-legend"><div class="dl"><span class="dot" style="background:var(--green)"></span>Covered <b>'+(laps.covered||0)+'</b></div><div class="dl"><span class="dot" style="background:var(--red)"></span>Missing <b>'+(laps.missing||0)+'</b></div><div class="dl"><span class="dot" style="background:var(--amber)"></span>Expired <b>'+(laps.expired||0)+'</b></div></div></div>')
     :'<div class="muted-note">LAPS schema not detected.</div>')+'</div>';
  document.getElementById('dashboard').innerHTML=h;
}

/* ---------- policy ---------- */
function csvPolicy(){ downloadCsv('password_policy.csv',['Setting','Value','Recommended','Status'],(D.policy||[]).map(r=>[r.setting,r.value,r.recommended,(r.class==='ok'?'Pass':r.class==='medium'?'Review':r.class==='high'?'Fail':'-')])); }
function renderPolicy(){
  const rows=D.policy||[];
  if(!D.policyOk||!rows.length){ document.getElementById('policySection').innerHTML='<div class="muted-note">Default domain password policy could not be read.</div>'; return; }
  let h='<table class="tbl"><thead><tr><th>Setting</th><th>Value</th><th>Recommended</th><th>Status</th></tr></thead><tbody>';
  rows.forEach(r=>{ const label=r.class==='ok'?'Pass':(r.class==='medium'?'Review':(r.class==='high'?'Fail':'-'));
    h+='<tr><td>'+esc(r.setting)+'</td><td><b>'+esc(r.value)+'</b></td><td style="color:var(--muted)">'+esc(r.recommended)+'</td><td><span class="tag '+r.class+'">'+label+'</span></td></tr>'; });
  document.getElementById('policySection').innerHTML=h+'</tbody></table>';
  if((D.policyFail||0)>0) document.getElementById('policyHint').innerHTML='<div class="hint warn"><i class="bi bi-exclamation-triangle"></i><div><b>'+D.policyFail+' setting(s) fail the baseline.</b> The baseline shown is a common hardening target (NIST / CIS-aligned); adjust to your organisation standard. Fine-grained policies below can raise requirements for specific groups without changing the domain default.</div></div>';
}

/* ---------- PSOs ---------- */
function csvPso(){ downloadCsv('fine_grained_policies.csv',['PSO','Precedence','MinLength','History','Complexity','MaxAgeDays','LockoutThreshold','AppliesTo'],(D.psos||[]).map(p=>[p.name,p.precedence,p.minLength,p.history,p.complexity?'Yes':'No',p.maxAgeDays,p.lockoutThr,(p.appliesTo||[]).join('; ')])); }
function renderPso(){
  const rows=D.psos||[];
  if(!rows.length){ document.getElementById('psoSection').innerHTML='<div class="muted-note">No fine-grained password policies defined.</div>'; return; }
  let h='<table class="tbl"><thead><tr><th>PSO</th><th>Prec.</th><th>Min len</th><th>History</th><th>Complexity</th><th>Max age</th><th>Applies to</th></tr></thead><tbody>';
  rows.forEach(p=>{ h+='<tr><td><b>'+esc(p.name)+'</b></td><td>'+p.precedence+'</td><td>'+p.minLength+'</td><td>'+p.history+'</td><td>'+(p.complexity?'<span class="tag ok">Yes</span>':'<span class="tag high">No</span>')+'</td><td>'+p.maxAgeDays+'d</td><td style="color:var(--muted)">'+(p.appliesCount?esc(p.appliesTo.join(', ')):'<span class="tag warn">none</span>')+'</td></tr>'; });
  document.getElementById('psoSection').innerHTML=h+'</tbody></table>';
}

/* ---------- MSA ---------- */
function csvMsa(){ downloadCsv('managed_service_accounts.csv',['Account','Type','Enabled','RotationDays','RetrievalPrincipals'],(D.msas||[]).map(m=>[m.name,m.kind,m.enabled?'Yes':'No',m.interval||'',(m.principals||[]).join('; ')])); }
function renderMsa(){
  const rows=D.msas||[], kds=D.kdsPresent;
  let hint='<div class="hint tip"><i class="bi bi-lightbulb"></i><div><b>Prefer gMSA over sMSA and manual service accounts.</b> gMSA passwords are 240+ chars and rotate automatically, which removes Kerberoasting value and manual rotation. sMSA is legacy and bound to a single host.</div></div>';
  if(kds===false) hint+='<div class="hint warn"><i class="bi bi-exclamation-triangle"></i><div><b>No KDS root key present.</b> gMSA passwords cannot be generated until one exists. Create it with <b>Add-KdsRootKey</b> (in a lab you can back-date the effective time; in production allow 10 hours for replication).</div></div>';
  else if(kds===null) hint+='<div class="hint info"><i class="bi bi-info-circle"></i><div>KDS root key status could not be determined (module or rights).</div></div>';
  document.getElementById('msaHint').innerHTML=hint;
  if(!rows.length){ document.getElementById('msaSection').innerHTML='<div class="muted-note">No managed service accounts found.</div>'; return; }
  let h='<table class="tbl"><thead><tr><th>Account</th><th>Type</th><th>Enabled</th><th>Rotation</th><th>Retrieval principals</th></tr></thead><tbody>';
  rows.forEach(m=>{ h+='<tr><td><b>'+esc(m.name)+'</b></td><td>'+(m.kind==='gMSA'?'<span class="tag ok">gMSA</span>':'<span class="tag warn">sMSA</span>')+'</td><td>'+(m.enabled?'Yes':'<span class="tag mut">No</span>')+'</td><td>'+(m.interval?(m.interval+'d'):'-')+'</td><td style="color:var(--muted)">'+(m.princCount?esc(m.principals.join(', ')):(m.kind==='gMSA'?'<span class="tag high">none set</span>':'n/a'))+'</td></tr>'; });
  document.getElementById('msaSection').innerHTML=h+'</tbody></table>';
}

/* ---------- LAPS ---------- */
function csvLaps(){ downloadCsv('laps_missing_computers.csv',['Computer','OperatingSystem'],((D.laps||{}).missingList||[]).map(c=>[c.name,c.os])); }
function openLaps(){ openReport('LAPS - computers without a managed password',(D.domain||'')+' &middot; '+(D.laps.mode||''),['Computer','Operating system'],((D.laps||{}).missingList||[]).map(c=>[c.name,c.os||'-'])); }
function renderLaps(){
  const laps=D.laps||{};
  if(!laps.mode||laps.mode==='None'){
    document.getElementById('lapsHint').innerHTML='<div class="hint tip"><i class="bi bi-lightbulb"></i><div><b>LAPS not detected.</b> Windows LAPS randomises and rotates the local administrator password per machine, blocking lateral movement via a shared local admin. Deploy it and extend the schema if it is not present.</div></div>';
    document.getElementById('lapsSection').innerHTML='<div class="muted-note">LAPS schema not detected in this domain.</div>'; return;
  }
  if((laps.missingList||[]).length) toolBtns('lapsTools','csvLaps()','openLaps()');
  if(laps.expired>0||laps.missing>0) document.getElementById('lapsHint').innerHTML='<div class="hint warn"><i class="bi bi-exclamation-triangle"></i><div><b>'+laps.missing+' computer(s) have no managed password and '+laps.expired+' are expired.</b> Missing usually means the machine has not applied the LAPS policy or lacks permission to write the attribute; expired means rotation has stalled.</div></div>';
  let h='<table class="tbl"><thead><tr><th>Mode</th><th>Total</th><th>Covered</th><th>Missing</th><th>Expired</th></tr></thead><tbody><tr><td><b>'+esc(laps.mode)+'</b></td><td>'+laps.total+'</td><td><span class="tag ok">'+laps.covered+'</span></td><td>'+(laps.missing?'<span class="tag high">'+laps.missing+'</span>':'0')+'</td><td>'+(laps.expired?'<span class="tag warn">'+laps.expired+'</span>':'0')+'</td></tr></tbody></table>';
  document.getElementById('lapsSection').innerHTML=h;
}

/* ---------- krbtgt ---------- */
function renderKrb(){
  const age=D.krbtgtAge;
  let card='';
  if(age==null){ card='<div class="muted-note">krbtgt password age could not be read.</div>'; }
  else {
    const bad=age>180;
    card='<div class="kpi '+(bad?'k-amber':'k-green')+'" style="max-width:320px;margin-bottom:14px"><div class="chip"><i class="bi bi-key-fill"></i></div><div class="body"><div class="val">'+age+' days</div><div class="lbl">krbtgt password age</div></div></div>';
    card+= bad
      ? '<div class="hint warn"><i class="bi bi-exclamation-triangle"></i><div><b>krbtgt password is '+age+' days old.</b> This key signs every Kerberos ticket, so a leaked hash enables Golden Ticket forgery. Rotate it <b>twice</b>, at least one replication cycle (10+ hours) apart, to fully invalidate old KRBTGT material - never both resets back-to-back.</div></div>'
      : '<div class="hint info"><i class="bi bi-info-circle"></i><div>krbtgt age is within a reasonable window. Rotate it periodically (twice, spaced by a replication cycle) as part of routine hygiene and after any suspected DC compromise.</div></div>';
  }
  document.getElementById('krbSection').innerHTML=card;
}

/* ---------- account categories ---------- */
const ACC_CATS=[
  {key:'notRequired',label:'Password not required',ico:'bi-shield-slash',sev:'high',pred:a=>a.flags.notRequired},
  {key:'deleg',label:'Unconstrained delegation',ico:'bi-diagram-3',sev:'high',pred:a=>a.flags.deleg},
  {key:'sidHist',label:'SID history present',ico:'bi-layers',sev:'high',pred:a=>a.flags.sidHist},
  {key:'inactive',label:'Inactive but enabled',ico:'bi-person-dash',sev:'medium',pred:a=>a.flags.inactive},
  {key:'never',label:'Password never expires',ico:'bi-clock-history',sev:'medium',pred:a=>a.flags.neverExpires},
  {key:'staleSvc',label:'Stale service password',ico:'bi-hourglass-split',sev:'medium',pred:a=>a.flags.staleSvc},
  {key:'spn',label:'Service (SPN) accounts',ico:'bi-robot',sev:'low',pred:a=>a.isService},
  {key:'priv',label:'Privileged (adminCount)',ico:'bi-person-badge',sev:'low',pred:a=>a.privileged}
];
function acctRows(pred){ return ACC.filter(pred).map(a=>[a.name,a.enabled?'Yes':'No',a.isService?'Yes':'No',a.privileged?'Yes':'No',a.spnCount,(a.pwdAgeDays==null?'':a.pwdAgeDays),a.lastLogon,a.enc,(a.findings||[]).join(' | ')]); }
const ACC_HDR=['Name','Enabled','Service','Privileged','SPNs','PwdAgeDays','LastLogon','KerberosCrypto','Findings'];
function csvAcc(key){ const cat=ACC_CATS.find(x=>x.key===key); downloadCsv('accounts_'+key+'.csv',ACC_HDR,acctRows(cat.pred)); }
function openAcc(key){ const cat=ACC_CATS.find(x=>x.key===key); openReport(cat.label,(D.domain||''),ACC_HDR,acctRows(cat.pred)); }
function renderAcctCats(){
  document.getElementById('acctHint').innerHTML='<div class="hint info"><i class="bi bi-info-circle"></i><div><b>SPN-bearing accounts are Kerberoastable.</b> An attacker can request their service ticket and crack it offline, so ensure long/complex passwords, enable AES, and migrate to gMSA where possible. Large categories are kept behind Open / CSV to keep this page fast.</div></div>';
  document.getElementById('acctCats').innerHTML=ACC_CATS.map(cat=>{
    const n=ACC.filter(cat.pred).length;
    const dis=n?'':' dis';
    return '<div class="cat-card sev-'+cat.sev+'"><div class="cat-top"><div class="cat-ico"><i class="bi '+cat.ico+'"></i></div><div><div class="cat-count">'+n+'</div><div class="cat-label">'+esc(cat.label)+'</div></div><span class="sev-tag '+cat.sev+'">'+({high:'High',medium:'Medium',low:'Low'}[cat.sev]||cat.sev)+'</span></div>'
      +'<div class="cat-actions"><button class="mini-btn'+dis+'" onclick="openAcc(\''+cat.key+'\')"><i class="bi bi-box-arrow-up-right"></i> Open</button><button class="mini-btn'+dis+'" onclick="csvAcc(\''+cat.key+'\')"><i class="bi bi-download"></i> CSV</button></div></div>';
  }).join('');
}

/* ---------- high-severity explorer ---------- */
const HIGH=ACC.filter(a=>a.severity==='high');
function renderList(){
  const box=document.getElementById('acctList');
  if(!HIGH.length){ box.innerHTML='<div class="muted-note">No high-severity accounts. Lower-severity categories are above.</div>'; return; }
  box.innerHTML=HIGH.map((a,i)=>{
    const sub=[]; if(a.isService)sub.push('<span class="pill">SPN '+a.spnCount+'</span>'); if(a.privileged)sub.push('<span class="pill">privileged</span>'); if(!a.enabled)sub.push('<span class="pill">disabled</span>');
    return '<div class="acct-item" data-name="'+esc(a.name.toLowerCase())+'" onclick="pick(this,'+i+')"><div class="acct-ico sev-'+a.severity+'"><i class="bi '+sevIco(a.severity)+'"></i></div><div class="acct-body"><div class="acct-name">'+esc(a.name)+'</div><div class="acct-sub">'+sub.join(' ')+(a.findings.length?'<span class="pill">'+a.findings.length+' finding'+(a.findings.length>1?'s':'')+'</span>':'')+'</div></div></div>';
  }).join('');
}
function pick(el,i){ document.querySelectorAll('.acct-item.sel').forEach(n=>n.classList.remove('sel')); el.classList.add('sel'); showDetail(i); }
function kv(k,v,cls){ return '<div class="kv"><div class="k">'+k+'</div><div class="v '+(cls||'')+'">'+v+'</div></div>'; }
function showDetail(i){
  const a=HIGH[i]; if(!a) return;
  let h='<div class="detail-head"><div class="detail-title"><i class="bi '+sevIco(a.severity)+'" style="color:'+sevColor(a.severity)+'"></i>'+esc(a.name)+'</div><div class="detail-sub">'+(a.isService?'Service account':'User account')+(a.privileged?' &middot; privileged':'')+(a.enabled?'':' &middot; disabled')+'</div></div><div class="detail-body">';
  h+='<div class="dsec"><div class="dsec-t"><i class="bi bi-info-circle"></i> Attributes</div><div class="kv-grid">'
    +kv('Enabled',a.enabled?'Yes':'No',a.enabled?'':'mut')
    +kv('SPNs',a.spnCount,a.spnCount?'warn':'mut')
    +kv('Password age',a.pwdAgeDays==null?'unknown':(a.pwdAgeDays+' days'),(a.pwdAgeDays!=null&&a.pwdAgeDays>D.staleDays)?'warn':'')
    +kv('Last logon',esc(a.lastLogon),'mut')
    +kv('Kerberos crypto',esc(a.enc),a.encClass==='ok'?'good':(a.encClass==='high'?'bad':'warn'))
    +kv('Privileged',a.privileged?'Yes':'No',a.privileged?'warn':'mut')+'</div></div>';
  h+='<div class="dsec"><div class="dsec-t"><i class="bi bi-exclamation-triangle"></i> Findings</div>';
  h+= a.findings.length ? '<div class="findings">'+a.findings.map(f=>'<div class="finding '+a.severity+'"><i class="bi '+sevIco(a.severity)+'"></i><div>'+esc(f)+'</div></div>').join('')+'</div>' : '<div class="no-findings"><i class="bi bi-check-circle-fill"></i> No findings.</div>';
  h+='</div></div>';
  document.getElementById('detail').innerHTML=h;
}
function filterList(){ const q=document.getElementById('acctSearch').value.toLowerCase(); document.querySelectorAll('.acct-item').forEach(el=>{ el.classList.toggle('dimmed', q && el.getAttribute('data-name').indexOf(q)<0); }); }

/* ---------- computer categories ---------- */
const COMP_CATS=[
  {key:'legacyOS',label:'Legacy / end-of-life OS',ico:'bi-pc-display-horizontal',sev:'high',pred:c=>c.flags.legacyOS},
  {key:'deleg',label:'Unconstrained delegation',ico:'bi-shield-exclamation',sev:'high',pred:c=>c.flags.deleg},
  {key:'stale',label:'Stale (no recent logon)',ico:'bi-clock-history',sev:'medium',pred:c=>c.flags.stale},
  {key:'oldPwd',label:'Old machine password',ico:'bi-hourglass-split',sev:'medium',pred:c=>c.flags.oldPwd},
  {key:'disabled',label:'Disabled objects',ico:'bi-slash-circle',sev:'low',pred:c=>c.flags.disabled}
];
function compRows(pred){ return COMP.filter(pred).map(c=>[c.name,c.enabled?'Yes':'No',c.os||'',(c.lastLogonDays==null?'':c.lastLogonDays),(c.pwdAgeDays==null?'':c.pwdAgeDays),(c.findings||[]).join(' | ')]); }
const COMP_HDR=['Name','Enabled','OS','LastLogonDays','PwdAgeDays','Findings'];
function csvComp(key){ const cat=COMP_CATS.find(x=>x.key===key); downloadCsv('computers_'+key+'.csv',COMP_HDR,compRows(cat.pred)); }
function openComp(key){ const cat=COMP_CATS.find(x=>x.key===key); openReport(cat.label,(D.domain||''),COMP_HDR,compRows(cat.pred)); }
function renderCompCats(){
  const cc=D.compCounts||{};
  let hint='<div class="hint info"><i class="bi bi-info-circle"></i><div><b>'+(D.computerTotal||0)+' computer object(s) scanned.</b> Stale machines and old machine passwords usually mean the device is gone - clean them up to shrink attack surface. Unconstrained delegation on a non-DC is high risk (it can capture and reuse any user\'s TGT).</div></div>';
  document.getElementById('compHint').innerHTML=hint;
  document.getElementById('compCats').innerHTML=COMP_CATS.map(cat=>{
    const n=COMP.filter(cat.pred).length; const dis=n?'':' dis';
    return '<div class="cat-card sev-'+cat.sev+'"><div class="cat-top"><div class="cat-ico"><i class="bi '+cat.ico+'"></i></div><div><div class="cat-count">'+n+'</div><div class="cat-label">'+esc(cat.label)+'</div></div><span class="sev-tag '+cat.sev+'">'+({high:'High',medium:'Medium',low:'Low'}[cat.sev]||cat.sev)+'</span></div><div class="cat-actions"><button class="mini-btn'+dis+'" onclick="openComp(\''+cat.key+'\')"><i class="bi bi-box-arrow-up-right"></i> Open</button><button class="mini-btn'+dis+'" onclick="csvComp(\''+cat.key+'\')"><i class="bi bi-download"></i> CSV</button></div></div>';
  }).join('');
}

function shortDn(dn){ if(!dn) return ''; return (''+dn).split(',').slice(0,2).join(','); }
const LDG_HDR=['Scope','ScopeType','Principal','PrincipalType','Enabled','Rights','Attribute','Inherited','Classification'];
function ldgRows(list){ return list.map(d=>[d.scope,d.scopeType,d.principal,d.principalType,(d.enabled==null?'':d.enabled?'Yes':'No'),d.rights,d.attribute,d.inherited?'Yes':'No',d.class]); }
function csvLdg(){ downloadCsv('laps_delegations.csv',LDG_HDR,ldgRows(LDG)); }
function openLdg(){ openReport('LAPS read delegation - all grants',(D.domain||''),LDG_HDR,ldgRows(LDG)); }
function renderLapsDeleg(){
  if(!D.lapsDelegRan){ document.getElementById('ldgSection').innerHTML='<div class="muted-note">LAPS schema not detected - delegation audit skipped.</div>'; return; }
  const c=D.ldCounts||{};
  document.getElementById('ldgHint').innerHTML='<div class="hint info"><i class="bi bi-eye"></i><div><b>Anyone who can read the LAPS password attribute effectively holds local-admin on those machines.</b> Read access should be limited to tier-0 / dedicated admin groups. Built-in privileged principals are excluded here. Grants are summarised per principal below; use Open / CSV for the full per-scope list.</div></div>';
  document.getElementById('ldgCards').innerHTML =
     kpiCard(c.total||0,'Delegated ACEs','bi-diagram-3','k-blue')
    +kpiCard(c.suspicious||0,'Suspicious / to review','bi-exclamation-triangle',(c.suspicious?'k-amber':'k-green'))
    +kpiCard(c.excessive||0,'Excessive (GenericAll)','bi-shield-exclamation',(c.excessive?'k-red':'k-green'));
  if(LDG.length) toolBtns('ldgTools','csvLdg()','openLdg()');
  // aggregate per principal (many scopes collapse to one row)
  const agg={};
  LDG.forEach(d=>{ const k=d.principal+'||'+d.rights+'||'+d.attribute+'||'+d.class;
    if(!agg[k]) agg[k]={principal:d.principal,type:d.principalType,rights:d.rights,attribute:d.attribute,cls:d.class,severity:d.severity,scopes:0};
    agg[k].scopes++; });
  const arr=Object.keys(agg).map(k=>agg[k]).filter(x=>x.severity!=='low').sort((a,b)=>(a.severity==='high'?0:1)-(b.severity==='high'?0:1) || b.scopes-a.scopes);
  if(!arr.length){ document.getElementById('ldgSection').innerHTML='<div class="no-findings" style="max-width:560px"><i class="bi bi-check-circle-fill"></i> No suspicious LAPS delegations outside expected admin principals.</div>'; return; }
  let h='<table class="tbl"><thead><tr><th>Principal</th><th>Type</th><th>Attribute / rights</th><th>Scopes</th><th>Classification</th></tr></thead><tbody>';
  arr.forEach(d=>{ const tg=d.severity==='high'?'high':'warn';
    h+='<tr><td><b>'+esc(d.principal)+'</b></td><td>'+esc(d.type||'Unknown')+'</td><td style="color:var(--muted)">'+esc(d.attribute)+'<br><span style="font-size:11px">'+esc(d.rights)+'</span></td><td><span class="tag mut">'+d.scopes+' OU'+(d.scopes>1?'s':'')+'</span></td><td><span class="tag '+tg+'">'+esc(d.cls)+'</span></td></tr>'; });
  document.getElementById('ldgSection').innerHTML='<div class="scrollbox">'+h+'</tbody></table></div>';
}
function toggleTheme(){ const b=document.body; b.setAttribute('data-theme', b.getAttribute('data-theme')==='dark'?'light':'dark'); }

const NAV=[
 {id:'sec-overview',label:'Overview',icon:'bi-bar-chart-line'},
 {id:'sec-policy',label:'Password Policy',icon:'bi-shield-lock'},
 {id:'sec-pso',label:'Fine-Grained Policies',icon:'bi-sliders'},
 {id:'sec-msa',label:'Managed Accounts',icon:'bi-robot'},
 {id:'sec-laps',label:'LAPS Coverage',icon:'bi-pc-display'},
 {id:'sec-ldg',label:'LAPS Delegation',icon:'bi-diagram-3'},
 {id:'sec-krbtgt',label:'krbtgt',icon:'bi-key-fill'},
 {id:'sec-users',label:'User Risks',icon:'bi-person-badge'},
 {id:'sec-computers',label:'Computer Risks',icon:'bi-pc-display-horizontal'},
 {id:'sec-fsp',label:'Foreign Principals',icon:'bi-globe'},
 {id:'sec-orphansid',label:'Orphaned SIDs',icon:'bi-person-x'}
];
function renderSidenav(){
  document.getElementById('sidenav').innerHTML='<div class="navgroup">Report</div>'+NAV.map(function(n){return '<a class="navitem" href="#'+n.id+'"><i class="bi '+n.icon+'"></i> '+n.label+'</a>';}).join('');
}
function initScrollSpy(){
  var items=Array.prototype.slice.call(document.querySelectorAll('.navitem'));
  var secs=NAV.map(function(n){return document.getElementById(n.id);});
  function onScroll(){ var idx=0, y=window.scrollY+92; secs.forEach(function(sc,i){ if(sc && sc.offsetTop<=y) idx=i; }); items.forEach(function(it,i){ it.classList.toggle('active',i===idx); }); }
  window.addEventListener('scroll',onScroll,{passive:true}); onScroll();
}
const ORPH_HDR=['OrphanedSID','ObjectsAffected','ACEs','SampleObject'];
function orphRows(){ return ORPH_LIST.map(o=>[o.sid,o.objects,o.aces,o.sample]); }
function csvOrph(){ downloadCsv('orphaned_sids.csv',ORPH_HDR,orphRows()); }
function openOrph(){ openReport('Orphaned SIDs in ACLs',(D.domain||''),ORPH_HDR,orphRows()); }
function renderOrphan(){
  if(!ORPH.ran){ document.getElementById('orphSection').innerHTML='<div class="muted-note">Orphaned-SID scan was skipped. Run without -SkipOrphanedSids to include it.</div>'; return; }
  document.getElementById('orphCards').innerHTML =
     kpiCard(ORPH.distinct||0,'Distinct orphaned SIDs','bi-person-x',((ORPH.distinct||0)?'k-red':'k-green'))
    +kpiCard(ORPH.objects||0,'Objects affected','bi-collection',((ORPH.objects||0)?'k-amber':'k-green'))
    +kpiCard(ORPH.aces||0,'Dangling ACEs','bi-shield-slash',((ORPH.aces||0)?'k-amber':'k-green'))
    +kpiCard(ORPH.scanned||0,'Objects scanned','bi-search','k-blue');
  document.getElementById('orphHint').innerHTML='<div class="hint info"><i class="bi bi-info-circle"></i><div><b>Orphaned SIDs</b> are ACEs whose account no longer exists, so the SID never resolves to a name. They clutter ACLs, complicate audits, and can cause permission-evaluation issues. This report only <b>detects</b> them - it removes nothing. Remediation should be run deliberately, with a backup.</div></div>';
  if(!ORPH_LIST.length){ document.getElementById('orphSection').innerHTML='<div class="no-findings" style="max-width:560px"><i class="bi bi-check-circle-fill"></i> No orphaned SIDs found in scanned object ACLs.</div>'; return; }
  var t=document.getElementById('orphTools'); if(t) t.innerHTML='<button class="mini-btn" onclick="openOrph()"><i class="bi bi-box-arrow-up-right"></i> Open</button><button class="mini-btn" onclick="csvOrph()"><i class="bi bi-download"></i> CSV</button>';
  var h='<table class="tbl"><thead><tr><th>Orphaned SID</th><th>Objects</th><th>ACEs</th><th>Sample object</th></tr></thead><tbody>';
  ORPH_LIST.slice(0,200).forEach(function(o){ h+='<tr><td style="font-family:ui-monospace,monospace;font-size:11px">'+esc(o.sid)+'</td><td>'+o.objects+'</td><td>'+o.aces+'</td><td style="color:var(--muted);font-size:11px">'+esc(o.sample)+'</td></tr>'; });
  document.getElementById('orphSection').innerHTML='<div class="scrollbox">'+h+'</tbody></table></div>'+(ORPH_LIST.length>200?'<div class="muted-note" style="margin-top:8px">Showing first 200 of '+ORPH_LIST.length+' distinct SIDs - use Open / CSV for all.</div>':'');
}
const FSP_HDR=['SID','ResolvesTo','Orphaned','InPrivilegedGroup','MemberOf'];
function fspRows(){ return FSP.map(f=>[f.sid,f.resolved,f.orphaned?'Yes':'No',f.privileged?'Yes':'No',(f.groups||[]).join('; ')]); }
function csvFsp(){ downloadCsv('foreign_security_principals.csv',FSP_HDR,fspRows()); }
function openFsp(){ openReport('Foreign Security Principals',(D.domain||''),FSP_HDR,fspRows()); }
function renderFsp(){
  document.getElementById('fspHint').innerHTML='<div class="hint info"><i class="bi bi-info-circle"></i><div><b>Foreign Security Principals (FSPs)</b> represent accounts from trusted external domains/forests added to groups here. An <b>unresolved</b> FSP usually means the source account was deleted, leaving a stale membership; an FSP inside a <b>privileged</b> group grants a cross-domain principal elevated rights and should be verified.</div></div>';
  if(!FSP.length){ document.getElementById('fspSection').innerHTML='<div class="no-findings" style="max-width:560px"><i class="bi bi-check-circle-fill"></i> No external (non-built-in) foreign security principals found.</div>'; return; }
  const t=document.getElementById('fspTools'); if(t) t.innerHTML='<button class="mini-btn" onclick="openFsp()"><i class="bi bi-box-arrow-up-right"></i> Open</button><button class="mini-btn" onclick="csvFsp()"><i class="bi bi-download"></i> CSV</button>';
  let h='<table class="tbl"><thead><tr><th>Principal (SID)</th><th>Resolves to</th><th>Member of</th><th>Status</th></tr></thead><tbody>';
  FSP.forEach(f=>{ const tags=[]; if(f.privileged)tags.push('<span class="tag high">privileged</span>'); if(f.orphaned)tags.push('<span class="tag warn">unresolved</span>'); if(!tags.length)tags.push('<span class="tag mut">external</span>');
    h+='<tr><td style="font-family:ui-monospace,monospace;font-size:11px">'+esc(f.sid)+'</td><td>'+esc(f.resolved)+'</td><td style="color:var(--muted)">'+(f.groupCount?esc(f.groups.join(', ')):'-')+'</td><td>'+tags.join(' ')+'</td></tr>'; });
  document.getElementById('fspSection').innerHTML=h+'</tbody></table>';
}
function csvHigh(){ downloadCsv('high_severity_accounts.csv',ACC_HDR,acctRows(a=>a.severity==='high')); }
function openHigh(){ openReport('High-severity accounts',(D.domain||''),ACC_HDR,acctRows(a=>a.severity==='high')); }
function wireHighTools(){ const t=document.getElementById('highTools'); if(t && ACC.filter(a=>a.severity==='high').length) t.innerHTML='<button class="mini-btn" onclick="openHigh()"><i class="bi bi-box-arrow-up-right"></i> Open</button><button class="mini-btn" onclick="csvHigh()"><i class="bi bi-download"></i> CSV</button>'; }
renderKpis(); renderDashboard(); renderPolicy(); renderPso(); renderMsa(); renderLaps(); renderLapsDeleg(); renderKrb(); renderAcctCats(); renderList(); renderCompCats(); renderFsp(); renderOrphan(); wireHighTools(); renderSidenav(); initScrollSpy();
</script>
</body>
</html>
"@

$HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
Write-Host ""
Write-Host "  Report saved: $ReportPath" -ForegroundColor Green
if ($OpenReport) { try { Start-Process $ReportPath } catch {} }
