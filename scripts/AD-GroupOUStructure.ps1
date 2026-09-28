<#
.SYNOPSIS
    AD Group Nesting, OU Structure & IDFix - interactive HTML report.

.DESCRIPTION
    Standalone module for the Active Directory Audit Suite. One self-contained,
    offline, interactive HTML report (light/dark) with three sections:

      1. GROUP NESTING  - security-group membership graph with fully recursive
                          nested-group expansion, circular-nesting detection,
                          empty groups, deep nesting, and large-membership flags.
                          Click a group to see its members (like ADUC).
      2. OU STRUCTURE   - the OU hierarchy with per-OU object counts, empty-OU
                          detection/filter, and a tiering-model recommendation.
                          Click an OU to see its direct contents (like ADUC).
      3. IDFIX          - a faithful reimplementation of Microsoft IDFix: scans
                          for attributes that break Entra ID / M365 sync. Click a
                          row to open the object and highlight the erroring value.

    READ-ONLY. Detection and suggested fixes only; no writes to AD.

.PARAMETER OutputPath           Folder for the HTML report (default: current dir).
.PARAMETER DeepNestingThreshold Depth at/above which a group is "deeply nested" (default 4).
.PARAMETER LargeGroupThreshold  Member count at/above which a group is "large" (default 100).
.PARAMETER MemberDisplayCap     Max members/children listed in a popup (default 200).
.PARAMETER MaxIdfixRows       Max IDFix rows embedded in the report (default 5000). The CSV on disk always has all.
.PARAMETER SearchBase           Optional DN to scope the whole scan.
.PARAMETER OpenReport           Open the report when done (default: $true).

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite
    Requires: ActiveDirectory module (RSAT-AD-PowerShell).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [int]$DeepNestingThreshold = 4,
    [int]$LargeGroupThreshold = 100,
    [int]$MemberDisplayCap = 50,
    [int]$MaxIdfixRows = 5000,
    [string]$SearchBase,
    [switch]$OpenReport = $true
)

$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Error "ActiveDirectory module not available. Install RSAT-AD-PowerShell."; exit 1 }
try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'; $GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
try { $Domain = Get-ADDomain -ErrorAction Stop } catch { Write-Error "Could not contact the domain: $($_.Exception.Message)"; exit 1 }
try { $Forest = Get-ADForest -ErrorAction SilentlyContinue } catch { $Forest = $null }
$DomainDNS = $Domain.DNSRoot; $ForestDNS = if ($Forest) { $Forest.Name } else { $DomainDNS }
$DomainDN = $Domain.DistinguishedName
$ReportPath = Join-Path $OutputPath "AD_GroupOU_$Stamp.html"

Write-Host "AD Group Nesting, OU Structure & IDFix" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "build: v6-console" -ForegroundColor DarkGray
Write-Host "Domain: $DomainDNS" -ForegroundColor Gray

function Get-ParentDN { param([string]$Dn) $i = $Dn.IndexOf(','); if ($i -lt 0) { return '' } $Dn.Substring($i + 1) }
function Get-CnFromDN { param([string]$Dn) $r = ($Dn -split ',')[0]; if ($r -match '^CN=') { return $r.Substring(3) } return $r }
function Fmt-Date { param($D) if ($D) { try { return ([datetime]$D).ToString('yyyy-MM-dd HH:mm') } catch { return '' } } return '' }
function Bump { param([hashtable]$Map,[string]$Key) $cur=0; if ($Map.ContainsKey($Key)) { $cur=[int]$Map[$Key] }; $Map[$Key]=$cur+1 }
# Sort helper without Sort-Object: fills $Out (in place) with items ordered by string key.
function Fill-Sorted { param([System.Collections.ArrayList]$Items,[System.Collections.ArrayList]$Keys,[System.Collections.ArrayList]$Out)
    $map=@{}; $keyArr = [string[]]::new($Keys.Count)
    for ($i=0; $i -lt $Keys.Count; $i++) { $k = ([string]$Keys[$i]) + '|' + $i.ToString('D6'); $keyArr[$i]=$k; $map[$k]=$Items[$i] }
    [System.Array]::Sort($keyArr)
    foreach ($k in $keyArr) { [void]$Out.Add($map[$k]) }
}
$baseArg = @{}; if ($SearchBase) { $baseArg.SearchBase = $SearchBase }

# ─────────────────────────────────────────────────────────────────────────────
# 1. Objects + resolution index
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/4] Reading users, computers, groups..." -ForegroundColor Yellow
$allGroups    = @(Get-ADGroup @baseArg -Filter * -Properties member, GroupScope, GroupCategory, whenChanged, sAMAccountName)
$allUsers     = @(Get-ADUser @baseArg -Filter * -Properties displayName)
$allComputers = @(Get-ADComputer @baseArg -Filter * -Properties Name)

$index = @{}      # dn(lower) -> @{ name; type }
$groupDnSet = @{}
foreach ($g in $allGroups)    { $k=([string]$g.DistinguishedName).ToLower(); $index[$k]=@{ name=[string]$g.Name; type='group' }; $groupDnSet[$k]=$true }
foreach ($u in $allUsers)     { $k=([string]$u.DistinguishedName).ToLower(); $n=[string]$u.displayName; if (-not $n) { $n=[string]$u.Name }; $index[$k]=@{ name=$n; type='user' } }
foreach ($c in $allComputers) { $k=([string]$c.DistinguishedName).ToLower(); $index[$k]=@{ name=[string]$c.Name; type='computer' } }

# ─────────────────────────────────────────────────────────────────────────────
# 2. Group nesting
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/4] Building nesting graph & members..." -ForegroundColor Yellow
$adj = @{}; $grpInfo = @{}
foreach ($g in $allGroups) {
  try {
    $dn = [string]$g.DistinguishedName; $key = $dn.ToLower()
    $memberDns = [System.Collections.ArrayList]::new()
    if ($null -ne $g.member) { foreach ($mm in $g.member) { if ($mm) { [void]$memberDns.Add([string]$mm) } } }
    $nested = [System.Collections.ArrayList]::new()
    $memberObjs = [System.Collections.ArrayList]::new()
    foreach ($mm in $memberDns) {
        $ml = $mm.ToLower()
        if ($groupDnSet.ContainsKey($ml)) { [void]$nested.Add($ml) }
        if ($memberObjs.Count -lt $MemberDisplayCap) {
            $hit = $index[$ml]
            if ($hit) { [void]$memberObjs.Add(@{ name=[string]$hit['name']; type=[string]$hit['type'] }) }
            else      { [void]$memberObjs.Add(@{ name=[string](Get-CnFromDN $mm); type='other' }) }
        }
    }
    $adj[$key] = $nested
    $sidVal = ''; if ($g.SID) { try { $sidVal = [string]$g.SID.Value } catch {} }
    $total = [int]$memberDns.Count
    $more = 0; if ($total -gt $memberObjs.Count) { $more = [int]($total - $memberObjs.Count) }
    $grpInfo[$key] = @{
        name=[string]$g.Name; sam=[string]$g.sAMAccountName; sid=$sidVal; modified=[string](Fmt-Date $g.whenChanged)
        dn=$dn; scope=[string]$g.GroupScope; category=[string]$g.GroupCategory
        total=$total; nestedCount=[int]$nested.Count; empty=[bool]($total -eq 0)
        members=$memberObjs; moreMembers=[int]$more
    }
  } catch { Write-Warning ("Group '{0}' skipped: {1}" -f $g.Name, $_.Exception.Message) }
}

# circular = group that can reach itself through nested-group links
function Test-ReachesSelf { param([string]$Start,[string]$Cur,[hashtable]$Adj,[hashtable]$Visited)
    $kids = $Adj[$Cur]; if ($null -eq $kids) { return $false }
    foreach ($c in $kids) {
        if (-not $c) { continue }
        if ($c -eq $Start) { return $true }
        if ((-not $Visited.ContainsKey($c)) -and $Adj.ContainsKey($c)) {
            $Visited[$c] = $true
            if (Test-ReachesSelf -Start $Start -Cur $c -Adj $Adj -Visited $Visited) { return $true }
        }
    }
    return $false
}
$circularSet = @{}
foreach ($k in @($adj.Keys)) { try { if (Test-ReachesSelf -Start $k -Cur $k -Adj $adj -Visited @{}) { $circularSet[$k] = $true } } catch {} }

# nesting depth with memo (cycle-guarded)
$depthMemo = @{}
function Get-Depth { param([string]$Dn,[hashtable]$Adj,[hashtable]$Seen)
    if ($depthMemo.ContainsKey($Dn)) { return [int]$depthMemo[$Dn] }
    if ($Seen.ContainsKey($Dn)) { return 0 }
    $Seen[$Dn]=$true; $max=0
    $kids = $Adj[$Dn]
    if ($null -ne $kids) { foreach ($c in $kids) { if ($c -and $Adj.ContainsKey($c)) { $d=[int](Get-Depth -Dn $c -Adj $Adj -Seen $Seen); if ($d -gt $max) { $max=$d } } } }
    $Seen.Remove($Dn)
    $res = $max + 1
    if (-not $circularSet.ContainsKey($Dn)) { $depthMemo[$Dn] = $res }
    return $res
}

$grpItems = [System.Collections.ArrayList]::new()
$grpKeys  = [System.Collections.ArrayList]::new()
$sSec=0; $sEmpty=0; $sCirc=0; $sDeep=0; $sLarge=0
foreach ($k in @($grpInfo.Keys)) {
  try {
    $gi = $grpInfo[$k]
    $depth = [int](Get-Depth -Dn $k -Adj $adj -Seen @{})
    $circ  = [bool]$circularSet.ContainsKey($k)
    $nestedNames = [System.Collections.ArrayList]::new()
    foreach ($nd in $adj[$k]) { $gg=$grpInfo[$nd]; if ($gg) { [void]$nestedNames.Add([string]$gg['name']) } }
    $deep  = [bool]($depth -ge $DeepNestingThreshold)
    $large = [bool]([int]$gi['total'] -ge $LargeGroupThreshold)
    $rec = @{
        name=$gi['name']; sam=$gi['sam']; sid=$gi['sid']; modified=$gi['modified']; dn=$gi['dn']; scope=$gi['scope']; category=$gi['category']
        total=[int]$gi['total']; nestedCount=[int]$gi['nestedCount']; nested=$nestedNames
        empty=[bool]$gi['empty']; circular=$circ; depth=$depth; deep=$deep; large=$large
        members=$gi['members']; moreMembers=[int]$gi['moreMembers']
    }
    [void]$grpItems.Add($rec)
    # sort: circular first, then largest, then name
    $ck = if ($circ) { '0' } else { '1' }
    [void]$grpKeys.Add($ck + (999999999 - [int]$gi['total']).ToString('D9') + ([string]$gi['name']).ToLower())
    if ($gi['category'] -eq 'Security') { $sSec++ }
    if ($gi['empty']) { $sEmpty++ }
    if ($circ) { $sCirc++ } elseif ($deep) { $sDeep++ }
    if ($large) { $sLarge++ }
  } catch { Write-Warning ("Group build skipped: {0}" -f $_.Exception.Message) }
}
$GroupsOut = [System.Collections.ArrayList]::new()
Fill-Sorted -Items $grpItems -Keys $grpKeys -Out $GroupsOut

# ─────────────────────────────────────────────────────────────────────────────
# 3. OU tree (+ children, empty flag, counts)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[3/4] Building OU tree & object counts..." -ForegroundColor Yellow
$ous = @(Get-ADOrganizationalUnit @baseArg -Filter * -Properties whenChanged)
$pU=@{}; $pC=@{}; $pG=@{}; $kidsMap=@{}
function Add-Child { param([hashtable]$Map,[string]$Key,[string]$Name,[string]$Type)
    if (-not $Map.ContainsKey($Key)) { $Map[$Key]=[System.Collections.ArrayList]::new() }
    if ($Map[$Key].Count -lt $MemberDisplayCap) { [void]$Map[$Key].Add(@{ name=[string]$Name; type=[string]$Type }) }
}
foreach ($u in $allUsers)     { try { $p=([string](Get-ParentDN ([string]$u.DistinguishedName))).ToLower(); if ($p) { Bump $pU $p; $nm=[string]$u.displayName; if (-not $nm) { $nm=[string]$u.Name }; Add-Child $kidsMap $p $nm 'user' } } catch {} }
foreach ($c in $allComputers) { try { $p=([string](Get-ParentDN ([string]$c.DistinguishedName))).ToLower(); if ($p) { Bump $pC $p; Add-Child $kidsMap $p ([string]$c.Name) 'computer' } } catch {} }
foreach ($g in $allGroups)    { try { $p=([string](Get-ParentDN ([string]$g.DistinguishedName))).ToLower(); if ($p) { Bump $pG $p; Add-Child $kidsMap $p ([string]$g.Name) 'group' } } catch {} }

$ouItems = [System.Collections.ArrayList]::new()
$ouKeys  = [System.Collections.ArrayList]::new()
$emptyOus = 0
foreach ($ou in $ous) {
  try {
    $dn=[string]$ou.DistinguishedName; $k=$dn.ToLower()
    $u=0;  if ($pU.ContainsKey($k)) { $u=[int]$pU[$k] }
    $c=0;  if ($pC.ContainsKey($k)) { $c=[int]$pC[$k] }
    $gr=0; if ($pG.ContainsKey($k)) { $gr=[int]$pG[$k] }
    $children = [System.Collections.ArrayList]::new()
    if ($kidsMap.ContainsKey($k)) { foreach ($ch in $kidsMap[$k]) { [void]$children.Add($ch) } }
    $totalObj = $u + $c + $gr
    $moreC = 0; if ($totalObj -gt $children.Count) { $moreC = [int]($totalObj - $children.Count) }
    $isEmpty = [bool]($totalObj -eq 0); if ($isEmpty) { $emptyOus++ }
    [void]$ouItems.Add(@{
        name=[string]$ou.Name; dn=$dn; parent=[string](Get-ParentDN $dn); modified=[string](Fmt-Date $ou.whenChanged)
        users=[int]$u; computers=[int]$c; groups=[int]$gr; empty=$isEmpty
        children=$children; moreChildren=[int]$moreC
    })
    [void]$ouKeys.Add($k)
  } catch { Write-Warning ("OU '{0}' skipped: {1}" -f $ou.Name, $_.Exception.Message) }
}
$OUsOut = [System.Collections.ArrayList]::new()
Fill-Sorted -Items $ouItems -Keys $ouKeys -Out $OUsOut

$usersCnDn="CN=Users,$DomainDN".ToLower(); $compCnDn="CN=Computers,$DomainDN".ToLower()
$dcU=0; if ($pU.ContainsKey($usersCnDn)) { $dcU=[int]$pU[$usersCnDn] }
$dcG=0; if ($pG.ContainsKey($usersCnDn)) { $dcG=[int]$pG[$usersCnDn] }
$dcC=0; if ($pC.ContainsKey($compCnDn))  { $dcC=[int]$pC[$compCnDn] }
$usersKids = [System.Collections.ArrayList]::new(); if ($kidsMap.ContainsKey($usersCnDn)) { foreach ($x in $kidsMap[$usersCnDn]) { [void]$usersKids.Add($x) } }
$compKids  = [System.Collections.ArrayList]::new(); if ($kidsMap.ContainsKey($compCnDn))  { foreach ($x in $kidsMap[$compCnDn])  { [void]$compKids.Add($x) } }
$usersMore = 0; if (($dcU + $dcG) -gt $usersKids.Count) { $usersMore = [int](($dcU + $dcG) - $usersKids.Count) }
$compMore  = 0; if ($dcC -gt $compKids.Count) { $compMore = [int]($dcC - $compKids.Count) }
$DefaultContainers = @{ usersUsers=$dcU; usersGroups=$dcG; compComputers=$dcC; usersDn=[string]"CN=Users,$DomainDN"; compDn=[string]"CN=Computers,$DomainDN"; usersChildren=$usersKids; usersMore=$usersMore; compChildren=$compKids; compMore=$compMore }

# ─────────────────────────────────────────────────────────────────────────────
# 4. IDFix - directory sync error scan
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[4/4] IDFix directory-sync scan..." -ForegroundColor Yellow
$NonRoutableTld = @('local','internal','lan','corp','home','localdomain','intranet','priv','private','test','example','invalid','localhost','domain','ad')
$reCtrl=[regex]'[\x00-\x1F\x7F]'; $reLocalBad=[regex]'[ ()<>,;:\\"\[\]]'; $reSamBad=[regex]'["\[\]:;|=+*?<>/\\,]'; $reNickBad=[regex]'[ "()<>,;:\\\[\]@]'
function Test-Tld { param([string]$D)
    if ([string]::IsNullOrWhiteSpace($D)) { return $false }; if ($D -notmatch '\.') { return $false }
    $t=($D -split '\.')[-1].ToLower(); if ($NonRoutableTld -contains $t) { return $false }; if ($t.Length -lt 2) { return $false }
    if ($t -notmatch '^[a-z0-9-]+$') { return $false }; return $true }
function Test-Email { param([string]$A)
    if ([string]::IsNullOrWhiteSpace($A)) { return 'Format' }
    $p=$A -split '@'; if ($p.Count -ne 2 -or $p[0] -eq '' -or $p[1] -eq '') { return 'Format' }
    if ($reLocalBad.IsMatch($p[0]) -or $reCtrl.IsMatch($p[0])) { return 'LocalPart' }
    if (-not (Test-Tld $p[1])) { return 'TopLevelDomain' }
    if ($p[1] -notmatch '^[A-Za-z0-9.-]+$') { return 'DomainPart' }
    return '' }
function Clean-Chars { param([string]$V,[regex]$Re) if ($null -eq $V) { return '' } ($Re.Replace($V,'')).Trim() }

$Findings = [System.Collections.ArrayList]::new()
function Add-Finding { param($O,[string]$Attr,[string]$E,[string]$V,[string]$U)
    [void]$Findings.Add(@{ objectClass=[string]$O._class; name=[string]$O._name; dn=[string]$O.DistinguishedName; attribute=$Attr; error=$E; value=[string]$V; update=[string]$U }) }

$props='cn','displayName','givenName','sn','sAMAccountName','userPrincipalName','mail','mailNickname','proxyAddresses','targetAddress','objectClass','userAccountControl','whenChanged'
$ldap='(|(&(objectCategory=person)(objectClass=user))(objectCategory=group)(objectCategory=contact))'
$objs=@(Get-ADObject @baseArg -LDAPFilter $ldap -Properties $props -ResultSetSize $null)
$objByDn=@{}
foreach ($o in $objs) {
    $cls= if ($o.objectClass -contains 'group') {'group'} elseif ($o.objectClass -contains 'contact') {'contact'} else {'user'}
    $nm=[string]$o.displayName; if (-not $nm) { $nm=[string]$o.cn }; if (-not $nm) { $nm=[string]$o.Name }
    Add-Member -InputObject $o -NotePropertyName _class -NotePropertyValue $cls -Force
    Add-Member -InputObject $o -NotePropertyName _name -NotePropertyValue $nm -Force
    $objByDn[[string]$o.DistinguishedName]=$o
}
$proxSeen=@{}; $upnSeen=@{}; $mailSeen=@{}
foreach ($o in $objs) {
  try {
    foreach ($p in $o.proxyAddresses) { $v=[string]$p; if ($v -match ':') { $v=($v -split ':',2)[1] }; $k=$v.ToLower(); if ($k) { Bump $proxSeen $k } }
    $upnL=([string]$o.userPrincipalName).ToLower(); if ($upnL) { Bump $upnSeen $upnL }
    $mailL=([string]$o.mail).ToLower();             if ($mailL) { Bump $mailSeen $mailL }
  } catch {}
}
foreach ($o in $objs) {
  try {
    foreach ($a in 'cn','displayName','givenName','sn') {
        $v=[string]$o.$a; if ($v -eq '') { continue }
        if ($reCtrl.IsMatch($v)) { Add-Finding $o $a 'Character' $v (Clean-Chars $v $reCtrl) }
        elseif ($v -ne $v.Trim()) { Add-Finding $o $a 'Character' $v ($v.Trim()) }
    }
    $sam=[string]$o.sAMAccountName
    if ($sam -ne '') {
        if ($sam.Length -gt 20) { Add-Finding $o 'sAMAccountName' 'Length' $sam $sam.Substring(0,20) }
        if ($reSamBad.IsMatch($sam) -or $reCtrl.IsMatch($sam) -or $sam -ne $sam.Trim()) { Add-Finding $o 'sAMAccountName' 'Character' $sam (Clean-Chars (Clean-Chars $sam $reSamBad) $reCtrl) }
    }
    $nick=[string]$o.mailNickname
    if ($nick -ne '') {
        if ($nick.Length -gt 64) { Add-Finding $o 'mailNickname' 'Length' $nick $nick.Substring(0,64) }
        if ($reNickBad.IsMatch($nick) -or $reCtrl.IsMatch($nick) -or $nick -ne $nick.Trim()) { Add-Finding $o 'mailNickname' 'Character' $nick (Clean-Chars (Clean-Chars $nick $reNickBad) $reCtrl) }
    }
    $upn=[string]$o.userPrincipalName
    if ($o._class -eq 'user') {
        $enabled=$true; try { $uac=[int]$o.userAccountControl; $enabled=-not (($uac -band 2) -eq 2) } catch {}
        if ($upn -eq '' -and $enabled) { Add-Finding $o 'userPrincipalName' 'Blank' '' '' }
    }
    if ($upn -ne '') { $err=Test-Email $upn; if ($err) { Add-Finding $o 'userPrincipalName' $err $upn '' } elseif ([int]$upnSeen[$upn.ToLower()] -gt 1) { Add-Finding $o 'userPrincipalName' 'Duplicate' $upn '' } }
    $mail=[string]$o.mail
    if ($mail -ne '') { $err=Test-Email $mail; if ($err) { Add-Finding $o 'mail' $err $mail '' } elseif ([int]$mailSeen[$mail.ToLower()] -gt 1) { Add-Finding $o 'mail' 'Duplicate' $mail '' } }
    $tgt=[string]$o.targetAddress
    if ($tgt -ne '') { if ($tgt -notmatch ':') { Add-Finding $o 'targetAddress' 'Format' $tgt '' } else { $err=Test-Email (($tgt -split ':',2)[1]); if ($err) { Add-Finding $o 'targetAddress' $err $tgt '' } } }
    $prox = [System.Collections.ArrayList]::new()
    foreach ($px in $o.proxyAddresses) { $s=[string]$px; if ($s -ne '') { [void]$prox.Add($s) } }
    if ($prox.Count -gt 0) {
        $primary = [System.Collections.ArrayList]::new()
        foreach ($s in $prox) { if ($s -cmatch '^SMTP:') { [void]$primary.Add($s) } }
        if ($primary.Count -gt 1) { Add-Finding $o 'proxyAddresses' 'Format' ("Multiple primary: " + ($primary -join '; ')) '' }
        foreach ($s in $prox) {
            if ($s -notmatch ':') { Add-Finding $o 'proxyAddresses' 'Format' $s ''; continue }
            $prefix=($s -split ':',2)[0]; $addr=($s -split ':',2)[1]
            if ($prefix.ToLower() -eq 'smtp') { $err=Test-Email $addr; if ($err) { Add-Finding $o 'proxyAddresses' $err $s ''; continue } }
            if ([int]$proxSeen[$addr.ToLower()] -gt 1) { Add-Finding $o 'proxyAddresses' 'Duplicate' $s '' }
        }
    }
  } catch { Write-Warning ("IDFix scan skipped object '{0}': {1}" -f $o._name, $_.Exception.Message) }
}

# stats in one pass
$idfByType=@{ Character=0; Format=0; TopLevelDomain=0; DomainPart=0; LocalPart=0; Length=0; Duplicate=0; Blank=0; MailMatch=0 }
$affSet=@{}
foreach ($f in $Findings) { $t=[string]$f['error']; if ($idfByType.ContainsKey($t)) { $idfByType[$t]=[int]$idfByType[$t]+1 }; $affSet[[string]$f['dn']]=$true }
$idfAffected = [int]$affSet.Count

# full findings -> CSV on disk (always complete)
$IdfCsvPath = Join-Path $OutputPath "AD_GroupOU_IDFix_$Stamp.csv"
try {
    $csb = [System.Text.StringBuilder]::new()
    [void]$csb.AppendLine('"DISTINGUISHEDNAME","OBJECTCLASS","ATTRIBUTE","ERROR","VALUE","UPDATE"')
    foreach ($f in $Findings) {
        [void]$csb.Append('"').Append(([string]$f['dn']).Replace('"','""')).Append('","')
        [void]$csb.Append(([string]$f['objectClass']).Replace('"','""')).Append('","')
        [void]$csb.Append(([string]$f['attribute']).Replace('"','""')).Append('","')
        [void]$csb.Append(([string]$f['error']).Replace('"','""')).Append('","')
        [void]$csb.Append(([string]$f['value']).Replace('"','""')).Append('","')
        [void]$csb.Append(([string]$f['update']).Replace('"','""')).AppendLine('"')
    }
    [System.IO.File]::WriteAllText($IdfCsvPath, $csb.ToString(), [System.Text.UTF8Encoding]::new($true))
} catch { Write-Warning ("IDFix CSV not written: {0}" -f $_.Exception.Message); $IdfCsvPath = '' }

# embedded rows (capped) + slim per-object store for the popup
$idfRows = [System.Collections.ArrayList]::new()
$idfObjMap = @{}
foreach ($f in $Findings) {
    if ($idfRows.Count -ge $MaxIdfixRows) { break }
    [void]$idfRows.Add($f)
    $dnK = [string]$f['dn']
    if (-not $idfObjMap.ContainsKey($dnK)) {
        $o = $objByDn[$dnK]
        $attrs = @{
            displayName=[string]$o.displayName; sAMAccountName=[string]$o.sAMAccountName
            userPrincipalName=[string]$o.userPrincipalName; whenChanged=[string](Fmt-Date $o.whenChanged)
        }
        $idfObjMap[$dnK] = @{ dn=$dnK; class=[string]$f['objectClass']; name=[string]$f['name']; attrs=$attrs; errors=([System.Collections.ArrayList]::new()) }
    }
    $entry = $idfObjMap[$dnK]
    $attrName = [string]$f['attribute']
    if (-not $entry['attrs'].ContainsKey($attrName)) {
        $o = $objByDn[$dnK]
        if ($attrName -eq 'proxyAddresses') {
            $pl = [System.Collections.ArrayList]::new()
            foreach ($px in $o.proxyAddresses) { [void]$pl.Add([string]$px) }
            $entry['attrs']['proxyAddresses'] = $pl
        } else {
            $entry['attrs'][$attrName] = [string]$o.$attrName
        }
    }
    [void]$entry['errors'].Add(@{ attribute=$attrName; error=[string]$f['error']; value=[string]$f['value']; update=[string]$f['update'] })
}
$idfObjects = [System.Collections.ArrayList]::new()
foreach ($v in $idfObjMap.Values) { [void]$idfObjects.Add($v) }

Write-Host ""
Write-Host ("  Groups: {0}  OUs: {1}  IDFix errors: {2} ({3} shown in report)" -f $allGroups.Count, $OUsOut.Count, $Findings.Count, $idfRows.Count) -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# JSON: .NET JavaScriptSerializer (compiled, fast). PowerShell serializer = fallback.
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
    if ($o -is [int] -or $o -is [long] -or $o -is [double]) { [void]$sb.Append(([string]$o)); return }
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

$csvLeaf = ''; if ($IdfCsvPath) { $csvLeaf = [string][System.IO.Path]::GetFileName($IdfCsvPath) }
Write-Host "Assembling report data..." -ForegroundColor Yellow
$stage = 'summary'
try {
    $Summary = @{
        forest=[string]$ForestDNS; domain=[string]$DomainDNS; generated=[string]$GeneratedAt
        stats=@{
            groups=[int]$allGroups.Count; security=[int]$sSec
            empty=[int]$sEmpty; circular=[int]$sCirc; deep=[int]$sDeep; large=[int]$sLarge
            ous=[int]$OUsOut.Count; emptyOus=[int]$emptyOus; defaultObjs=[int]($dcU+$dcG+$dcC)
            deepThreshold=[int]$DeepNestingThreshold; largeThreshold=[int]$LargeGroupThreshold
        }
        groups=$GroupsOut; ous=$OUsOut; defaultContainers=$DefaultContainers
        idfix=@{
            scanned=[int]$objs.Count; affected=$idfAffected; shown=[int]$idfRows.Count
            csvFile=$csvLeaf
            stats=@{ errors=[int]$Findings.Count; affected=$idfAffected
                character=[int]$idfByType['Character']; format=[int]$idfByType['Format']; tld=[int]$idfByType['TopLevelDomain']
                duplicate=[int]$idfByType['Duplicate']; length=[int]$idfByType['Length']; blank=[int]$idfByType['Blank'] }
            findings=$idfRows; objects=$idfObjects
        }
    }

    $stage = 'serialize'
    Write-Host "Serializing..." -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $DataJSON = $null
    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $ser = [System.Web.Script.Serialization.JavaScriptSerializer]::new()
        $ser.MaxJsonLength = [int]::MaxValue
        $ser.RecursionLimit = 256
        $DataJSON = $ser.Serialize($Summary)
        if ($DataJSON.Contains('"ImmediateBaseObject"')) { throw 'PowerShell wrapper detected in output' }
    } catch {
        Write-Host ("  .NET serializer unavailable ({0}) - using PowerShell fallback (slower)..." -f $_.Exception.Message) -ForegroundColor DarkYellow
        $__jsb = [System.Text.StringBuilder]::new()
        Write-JsonValue $Summary $__jsb
        $DataJSON = $__jsb.ToString()
    }
    $sw.Stop()
    Write-Host ("  JSON size: {0} MB  ({1:N1}s)" -f [math]::Round($DataJSON.Length/1MB,2), $sw.Elapsed.TotalSeconds) -ForegroundColor Gray
} catch {
    Write-Host ""
    Write-Host ">>> FAILED at stage '$stage': $($_.Exception.GetType().Name) - $($_.Exception.Message)" -ForegroundColor Red
    throw
}

Write-Host "Composing HTML..." -ForegroundColor Yellow
$HTML = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Groups, OUs &amp; Directory Sync - $DomainDNS</title>
<style>
:root{--bg:#f5f6fb;--surface:#ffffff;--surface2:#eef1f9;--surface3:#dfe4f2;--border:#e4e7f2;--line:#f0f2f8;--text:#161a2e;--muted:#64708c;
--accent:#4f46e5;--accent-soft:#e6e6fd;--navy:#3730a3;
--green:#059669;--green-soft:#d1fae5;--red:#dc2626;--red-soft:#fde2e2;--amber:#d97706;--amber-soft:#fef3c7;
--blue:#2563eb;--blue-soft:#dbe8fe;--teal:#0d9488;--purple:#7c3aed;--gold:#d97706;
--radius:13px;--radius-sm:9px;--shadow:0 2px 8px rgb(60 50 140 / 0.06),0 1px 2px rgb(60 50 140 / 0.04);
--font:'Inter',system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;--mono:'SFMono-Regular',ui-monospace,Menlo,Consolas,monospace}
[data-theme="dark"]{--bg:#0c1524;--surface:#14213a;--surface2:#1c2c49;--surface3:#284066;--border:#243a5e;--line:#1b2a45;--text:#e8f0fb;--muted:#93a7c4;
--accent:#60a5fa;--accent-soft:rgba(96,165,250,0.15);--navy:#93c5fd;
--green:#34d399;--green-soft:rgba(16,185,129,0.15);--red:#f87171;--red-soft:rgba(239,68,68,0.15);--amber:#fbbf24;--amber-soft:rgba(245,158,11,0.15);
--blue:#60a5fa;--blue-soft:rgba(37,99,235,0.18);--teal:#2dd4bf;--purple:#a78bfa;--gold:#fbbf24;--shadow:0 2px 6px rgb(0 0 0 / 0.3)}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:13.5px;line-height:1.45;-webkit-font-smoothing:antialiased}
.app{max-width:1400px;margin:0 auto;padding:0 28px 26px;height:100vh;min-height:640px;display:flex;flex-direction:column}
.mono{font-family:var(--mono);font-size:12px}.muted{color:var(--muted)}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 0 16px;flex:0 0 auto}
.brand{display:flex;align-items:center;gap:13px}
.logo{width:40px;height:40px;border-radius:11px;background:linear-gradient(135deg,var(--accent),var(--navy));display:flex;align-items:center;justify-content:center;color:#fff;box-shadow:var(--shadow)}
.logo svg{width:22px;height:22px}
h1{font-size:19px;font-weight:750;letter-spacing:-.3px}.sub{font-size:12px;color:var(--muted)}
.btn{display:inline-flex;align-items:center;gap:6px;font:inherit;font-size:12px;font-weight:600;color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:5px 10px;cursor:pointer;white-space:nowrap}
.btn:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}.btn:disabled{opacity:.4;cursor:default}
.btn svg{width:14px;height:14px}
/* console */
.console{flex:1;min-height:0;display:flex;flex-direction:column;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
.tbar{display:flex;align-items:center;gap:6px;padding:8px 10px;border-bottom:1px solid var(--border);background:var(--surface2);flex:0 0 auto}
.tbar .sep{width:1px;height:20px;background:var(--border);margin:0 4px}
.find{margin-left:auto;display:flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:7px;background:var(--surface);padding:5px 9px;width:300px}
.find svg{width:14px;height:14px;color:var(--muted)}.find input{border:none;outline:none;background:transparent;font:inherit;font-size:12.5px;color:var(--text);width:100%}
.body{flex:1;min-height:0;display:grid;grid-template-columns:290px 1fr}
/* tree */
.tree{border-right:1px solid var(--border);overflow:auto;padding:8px 6px 16px;font-size:13px}
.tn{display:flex;align-items:center;gap:6px;padding:4px 6px;border-radius:6px;cursor:pointer;white-space:nowrap;user-select:none}
.tn:hover{background:var(--surface2)}.tn.sel{background:var(--accent-soft);color:var(--accent);font-weight:600}
.tw{width:12px;flex:0 0 auto;color:var(--muted);display:flex;align-items:center;justify-content:center}
.tw svg{width:10px;height:10px;transition:transform .12s}.tw.open svg{transform:rotate(90deg)}
.ico{width:16px;height:16px;flex:0 0 auto;display:flex}.ico svg{width:16px;height:16px}
.ico.u{color:var(--blue)}.ico.c{color:var(--teal)}.ico.g{color:var(--purple)}.ico.f{color:var(--gold)}.ico.n{color:var(--muted)}.ico.a{color:var(--accent)}
.tn .lb{overflow:hidden;text-overflow:ellipsis}
.tn .ct{margin-left:auto;font-size:11px;color:var(--muted);font-weight:500;padding-left:8px}
.tsec{font-size:10.5px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);padding:16px 8px 5px}
.qd{width:8px;height:8px;border-radius:50%;flex:0 0 auto;margin:0 4px}
.qd.crit{background:var(--red)}.qd.warn{background:var(--amber)}.qd.info{background:var(--blue)}.qd.ok{background:var(--green)}.qd.mono{background:var(--text)}
/* pane */
.pane{display:flex;flex-direction:column;min-width:0;min-height:0}
.phead{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border);flex:0 0 auto}
.phead .ico{width:20px;height:20px}.phead .ico svg{width:20px;height:20px}
.phead b{font-size:14.5px}.phead .pd{font-size:11.5px;color:var(--muted);word-break:break-all}
.strip{display:flex;gap:10px;align-items:flex-start;padding:9px 16px;font-size:12.5px;border-bottom:1px solid var(--border);background:var(--surface2);flex:0 0 auto}
.strip.warn{background:var(--amber-soft)}.strip b{font-weight:650}
.strip .x{margin-left:auto;cursor:pointer;color:var(--muted);font-size:16px;line-height:1}
.lv{flex:1;overflow:auto;min-height:0}
table.lt{width:100%;border-collapse:collapse;font-size:13px}
.lt th{position:sticky;top:0;z-index:1;text-align:left;font-size:11.5px;font-weight:600;color:var(--muted);padding:8px 12px;background:var(--surface);border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none}
.lt th:hover{color:var(--text)}.lt th .so{font-size:9px;margin-left:4px}
.lt td{padding:6px 12px;border-bottom:1px solid var(--line);white-space:nowrap;max-width:360px;overflow:hidden;text-overflow:ellipsis}
.lt tr.r{cursor:default}.lt tr.r:hover td{background:var(--surface2)}.lt tr.r.sel td{background:var(--accent-soft)}
.lt .nm{display:flex;align-items:center;gap:8px}.lt .nm span.t{overflow:hidden;text-overflow:ellipsis}
.lt td.num{text-align:right;font-variant-numeric:tabular-nums}
.flag{font-size:10.5px;font-weight:700;border-radius:20px;padding:1px 8px;margin-right:4px;border:1px solid var(--border);color:var(--muted)}
.flag.crit{color:var(--red);background:var(--red-soft);border-color:transparent}.flag.warn{color:var(--amber);background:var(--amber-soft);border-color:transparent}
.empty{padding:40px;text-align:center;color:var(--muted)}
.status{display:flex;gap:16px;padding:6px 14px;border-top:1px solid var(--border);background:var(--surface2);font-size:11.5px;color:var(--muted);flex:0 0 auto}
.status .r{margin-left:auto}
/* dialog */
.ovl{position:fixed;inset:0;background:rgba(10,15,35,.35);display:none;align-items:center;justify-content:center;z-index:100;padding:20px}
.ovl.show{display:flex}
.dlg{width:560px;max-width:100%;height:580px;max-height:92vh;background:var(--surface);border:1px solid var(--border);border-radius:12px;box-shadow:0 24px 70px rgb(10 10 40 / .35);display:flex;flex-direction:column}
.dh{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border)}
.dh b{font-size:14px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dh .x{cursor:pointer;color:var(--muted);font-size:20px;line-height:1;background:none;border:none}
.dtabs{display:flex;gap:2px;padding:6px 12px 0;border-bottom:1px solid var(--border)}
.dtabs button{font:inherit;font-size:12.5px;font-weight:600;color:var(--muted);background:none;border:none;border-bottom:2px solid transparent;padding:7px 11px;cursor:pointer}
.dtabs button.on{color:var(--accent);border-bottom-color:var(--accent)}
.db{flex:1;overflow:auto;padding:16px 18px}
.df{display:flex;justify-content:flex-end;gap:8px;padding:10px 16px;border-top:1px solid var(--border)}
.idh{display:flex;align-items:center;gap:12px;padding-bottom:14px;margin-bottom:12px;border-bottom:1px solid var(--border)}
.idh .ico{width:32px;height:32px}.idh .ico svg{width:32px;height:32px}.idh b{font-size:15px;word-break:break-word}
.fg{display:grid;grid-template-columns:150px 1fr;gap:8px 14px;font-size:13px}
.fg dt{color:var(--muted)}.fg dd{word-break:break-word}
.advice{margin-top:14px;padding:10px 12px;border-radius:8px;background:var(--accent-soft);font-size:12.5px}
.ml{border:1px solid var(--border);border-radius:8px;overflow:hidden}
.ml .mh{display:grid;grid-template-columns:1fr 130px;padding:6px 10px;font-size:11.5px;font-weight:600;color:var(--muted);background:var(--surface2);border-bottom:1px solid var(--border)}
.ml .mr{display:grid;grid-template-columns:1fr 130px;padding:6px 10px;border-bottom:1px solid var(--line);font-size:13px;align-items:center}
.ml .mr:last-child{border-bottom:none}.ml .mr.lnk{cursor:pointer}.ml .mr.lnk:hover{background:var(--surface2)}
.ml .mr .nm{display:flex;align-items:center;gap:8px;min-width:0}.ml .mr .nm span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ml .more{padding:7px 10px;font-size:12px;color:var(--muted)}
.hint{font-size:12px;color:var(--muted);margin-top:10px}
.nt .nr{display:flex;align-items:center;gap:6px;padding:4px 4px;border-radius:5px;font-size:13px}
.nt .nr.x{cursor:pointer}.nt .nr.x:hover{background:var(--surface2)}
.nt .kids{margin-left:18px;border-left:1px solid var(--border);padding-left:6px}
.at{width:100%;border-collapse:collapse;font-size:12.5px}
.at th{text-align:left;font-size:11.5px;color:var(--muted);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--border)}
.at td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.at td.v{font-family:var(--mono);font-size:12px;word-break:break-all}
.at tr.bad td{background:var(--red-soft)}.at tr.bad td:first-child{color:var(--red);font-weight:600}
.eb{display:block;margin-top:3px;font-family:var(--font);font-size:11px;font-weight:700;color:var(--red)}
@media(max-width:900px){.app{height:auto}.body{grid-template-columns:1fr}.tree{border-right:none;border-bottom:1px solid var(--border);max-height:280px}.find{width:auto;flex:1}.lv{min-height:360px}}
</style></head><body>
<div class="app">
  <div class="top">
    <div class="brand"><div class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="2.4"/><circle cx="5" cy="19" r="2.4"/><circle cx="19" cy="19" r="2.4"/><path d="M12 7.4V12M12 12 5.8 16.8M12 12l6.2 4.8"/></svg></div>
      <div><h1>Groups, OUs &amp; Directory Sync</h1><div class="sub" id="meta"></div></div></div>
    <button class="btn" id="themebtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19"/></svg><span id="themetxt">Dark</span></button>
  </div>
  <div class="console">
    <div class="tbar">
      <button class="btn" id="bBack" title="Back (Alt+Left)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 6l-6 6 6 6"/></svg></button>
      <button class="btn" id="bFwd" title="Forward (Alt+Right)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg></button>
      <button class="btn" id="bUp" title="Up one level"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M6 11l6-6 6 6"/></svg></button>
      <span class="sep"></span>
      <button class="btn" id="bProps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>Properties</button>
      <button class="btn" id="bExport"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12m0 0 4-4m-4 4-4-4M4 21h16"/></svg>Export list</button>
      <div class="find"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3-3" stroke-linecap="round"/></svg><input id="find" placeholder="Find users, groups, OUs, SIDs..."></div>
    </div>
    <div class="body">
      <nav class="tree" id="tree"></nav>
      <section class="pane"><div class="phead" id="phead"></div><div id="strip"></div><div class="lv" id="lv" tabindex="0"></div></section>
    </div>
    <div class="status" id="status"></div>
  </div>
</div>
<div class="ovl" id="ovl"><div class="dlg">
  <div class="dh"><button class="btn" id="dBack" style="display:none" title="Back"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 6l-6 6 6 6"/></svg></button><b id="dTitle"></b><button class="x" id="dX">&times;</button></div>
  <div class="dtabs" id="dTabs"></div><div class="db" id="dBody"></div>
  <div class="df"><button class="btn" id="dClose">Close</button></div>
</div></div>
<script>
var D = $DataJSON;
function arr(x){if(x==null)return[];if(!Array.isArray(x))return[x];while(x.length===1&&Array.isArray(x[0]))x=x[0];return x;}
function esc(s){s=(s==null?'':''+s);return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function qs(s){return document.querySelector(s);}
function plural(n,w){return n+' '+w+(n===1?'':'s');}
var I={
 chev:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>',
 folder:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h3.5l2 2H19a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
 user:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="3.6"/><path d="M4.5 20c0-3.7 3.4-6.2 7.5-6.2s7.5 2.5 7.5 6.2"/></svg>',
 computer:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4.5" width="18" height="11" rx="1.5"/><path d="M8.5 19.5h7M12 15.5v4"/></svg>',
 group:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8.5" cy="8" r="3.2"/><path d="M2.5 19c0-3.2 2.7-5.3 6-5.3s6 2.1 6 5.3"/><path d="M15.8 5.2a3.2 3.2 0 0 1 .2 6.1"/><path d="M17.2 14.1c2.5.5 4.3 2.4 4.3 4.9"/></svg>',
 other:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="8.5" cy="11" r="2"/><path d="M15 10h4M15 13.5h4"/></svg>',
 domain:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
 query:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/></svg>',
 sync:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 0 0-14.3-4.9L4 8M4 13a8 8 0 0 0 14.3 4.9L20 16"/><path d="M4 4v4h4M20 20v-4h-4"/></svg>',
 list:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>'
};
function ic(name,cls){return '<span class="ico '+(cls||'n')+'">'+(I[name]||'')+'</span>';}
var KIND={user:['user','u','User'],computer:['computer','c','Computer'],group:['group','g','Group'],other:['other','n','Object'],contact:['other','n','Contact']};
function kindIcon(k){var x=KIND[k]||KIND.other;return ic(x[0],x[1]);}

/* ---------------- data ---------------- */
var S=D.stats||{}, GROUPS=arr(D.groups), OUS=arr(D.ous), DC=D.defaultContainers||{}, IDX=D.idfix||{}, IS=IDX.stats||{};
var IDF=arr(IDX.findings), IOBJ={}; arr(IDX.objects).forEach(function(o){IOBJ[o.dn]=o;});
qs('#meta').innerHTML='Domain <b>'+esc(D.domain)+'</b> &middot; Forest <b>'+esc(D.forest)+'</b> &middot; '+esc(D.generated);
var byName={}; GROUPS.forEach(function(g){if(!byName[g.name])byName[g.name]=g;});
var memberOf={}; GROUPS.forEach(function(g){arr(g.nested).forEach(function(n){(memberOf[n]=memberOf[n]||[]).push(g.name);});});
var ouBy={}, ouKids={}, ouRoots=[];
OUS.forEach(function(o){var k=o.dn.toLowerCase();ouBy[k]=o;ouKids[k]=[];});
OUS.forEach(function(o){var p=(o.parent||'').toLowerCase();if(ouKids[p])ouKids[p].push(o);else ouRoots.push(o);});
function cmpName(a,b){return (''+a.name).localeCompare(''+b.name);}
Object.keys(ouKids).forEach(function(k){ouKids[k].sort(cmpName);}); ouRoots.sort(cmpName);
var SEC=GROUPS.filter(function(g){return g.category==='Security';});
var EMPTYOUS=OUS.filter(function(o){return o.empty&&!(ouKids[o.dn.toLowerCase()]||[]).length;}).sort(cmpName);
function gDesc(g){return plural(g.total,'member');}
function gType(g){return (g.category==='Security'?'Security':'Distribution')+' group &ndash; '+esc(g.scope);}

/* ---------------- views ---------------- */
var QUERIES=[
 {id:'all',label:'All security groups',dot:'',list:function(){return SEC;},help:'Every security group in the domain. The Find box also matches account names and SIDs.'},
 {id:'circular',label:'Circular nesting',dot:'crit',list:function(){return SEC.filter(function(g){return g.circular;});},help:'<b>Circular nesting.</b> These groups end up containing themselves through nested membership, which confuses access evaluation and delegation. Open a group and check its Nesting tab to find the loop, then remove one of the memberships.'},
 {id:'deep',label:'Deeply nested groups',dot:'warn',list:function(){return SEC.filter(function(g){return g.deep&&!g.circular;});},help:'<b>Deep nesting.</b> Groups nested '+(S.deepThreshold||4)+' or more levels deep inflate Kerberos tokens and hide who really has access. Consider flattening the chain.'},
 {id:'large',label:'Large groups',dot:'info',list:function(){return SEC.filter(function(g){return g.large;});},help:'<b>Large groups.</b> '+(S.largeThreshold||100)+' or more members. Review whether they should be split into role-based groups.'},
 {id:'empty',label:'Empty groups',dot:'info',list:function(){return SEC.filter(function(g){return g.empty;});},help:'<b>Empty groups.</b> Security groups with no members. Confirm they are unused before removing them.'},
 {id:'emptyous',label:'Empty OUs',dot:'info',ous:true,list:function(){return EMPTYOUS;},help:'<b>Empty OUs.</b> No users, computers, groups or sub-OUs. Remove them if they are no longer part of your design.'}
];
var QBY={};QUERIES.forEach(function(q){QBY[q.id]=q;});
var ETYPES=['Character','Format','TopLevelDomain','Duplicate','Length','Blank','LocalPart','DomainPart','MailMatch'];
var ESTAT={Character:'character',Format:'format',TopLevelDomain:'tld',Duplicate:'duplicate',Length:'length',Blank:'blank'};
var EHELP={Character:'Invalid characters, control characters or leading/trailing spaces.',Format:'Value is not in the expected format (for example an address without @, or more than one primary SMTP address).',TopLevelDomain:'The domain suffix is not routable on the internet (for example .local or .internal).',Duplicate:'The same value is used by more than one object; sync requires it to be unique.',Length:'Value is longer than the allowed maximum.',Blank:'A required value is empty.',LocalPart:'The part before @ contains invalid characters.',DomainPart:'The part after @ contains invalid characters.',MailMatch:'mail does not match the primary SMTP address.'};
function etypeCount(t){return ESTAT[t]&&IS[ESTAT[t]]!=null?IS[ESTAT[t]]:IDF.filter(function(r){return r.error===t;}).length;}
var ETYPES_USED=ETYPES.filter(function(t){return etypeCount(t)>0;});

/* ---- a "view" = what the list pane shows ---- */
function viewKey(v){return v.t+':'+(v.id||'');}
function containerRows(kids,objs){
  var rows=kids.map(function(o){return {kind:'ou',ref:o,name:o.name,type:'Organizational Unit',desc:o.empty&&!(ouKids[o.dn.toLowerCase()]||[]).length?'Empty':plural((o.users||0)+(o.computers||0)+(o.groups||0),'object'),mod:o.modified||''};});
  arr(objs).forEach(function(c){var g=c.type==='group'?byName[c.name]:null;
    rows.push({kind:c.type,ref:g||c,name:c.name,type:g?gType(g):(KIND[c.type]||KIND.other)[2],desc:g?gDesc(g):'',mod:g?(g.modified||''):''});});
  return rows;
}
var COLS_OBJ=[{k:'name',t:'Name'},{k:'type',t:'Type',html:1},{k:'desc',t:'Description'},{k:'mod',t:'Modified'}];
var COLS_GRP=[{k:'name',t:'Name'},{k:'scope',t:'Scope'},{k:'members',t:'Members',num:1},{k:'depth',t:'Nesting depth',num:1},{k:'flags',t:'Notes',html:1},{k:'mod',t:'Modified'}];
function flagHtml(g){var f='';if(g.circular)f+='<span class="flag crit">circular</span>';if(g.deep)f+='<span class="flag warn">deep</span>';if(g.large)f+='<span class="flag">large</span>';if(g.empty)f+='<span class="flag">empty</span>';return f;}
function groupRows(list){return list.map(function(g){return {kind:'group',ref:g,name:g.name,scope:g.scope,members:g.total,depth:g.depth,flags:flagHtml(g),flagsTxt:[g.circular?'circular':'',g.deep?'deep':'',g.large?'large':'',g.empty?'empty':''].join(' ').trim(),mod:g.modified||''};});}
function build(v){
  var r={icon:'',title:'',sub:'',strip:'',cols:COLS_OBJ,rows:[],more:0,status:''};
  if(v.t==='dom'){
    r.icon=ic('domain','a');r.title=D.domain;r.sub='Domain root';
    var kids=ouRoots.slice(), extra=[];
    extra.push({kind:'container',ref:'users',name:'Users',type:'Container',desc:plural((DC.usersUsers||0)+(DC.usersGroups||0),'object'),mod:''});
    extra.push({kind:'container',ref:'computers',name:'Computers',type:'Container',desc:plural(DC.compComputers||0,'object'),mod:''});
    r.rows=extra.concat(containerRows(kids,[])).sort(cmpName);
    if(!TIPCLOSED)r.strip='<div class="strip" id="tipstrip"><div><b>Consider a tiered administration model.</b> A tool cannot tell which tier an OU belongs to &mdash; that is an ownership decision &mdash; but it is worth structuring for: keep Tier&nbsp;0 (DCs, AD CS, admin accounts), Tier&nbsp;1 (servers and apps) and Tier&nbsp;2 (workstations) in separate OU branches with their own admins and GPOs.</div><span class="x" onclick="closeTip()">&times;</span></div>';
  } else if(v.t==='ou'){
    var o=ouBy[v.id]; if(!o)return build({t:'dom'});
    r.icon=ic('folder','f');r.title=o.name;r.sub=o.dn;
    r.rows=containerRows(ouKids[v.id]||[],o.children);r.more=o.moreChildren||0;
  } else if(v.t==='cn'){
    var isU=v.id==='users';
    r.icon=ic('folder','n');r.title=isU?'Users':'Computers';r.sub=isU?DC.usersDn:DC.compDn;
    r.rows=containerRows([],isU?DC.usersChildren:DC.compChildren);r.more=isU?(DC.usersMore||0):(DC.compMore||0);
    r.strip='<div class="strip warn"><div><b>Default container, not an OU.</b> No GPO can be linked here and it sits outside any tiering structure. Move these objects into OUs'+(isU?'':', and change the default location for new computers to an OU')+'.</div></div>';
  } else if(v.t==='q'){
    var q=QBY[v.id]; r.icon=ic('query','a'); r.title=q.label; r.sub='Saved query';
    r.strip='<div class="strip"><div>'+q.help+'</div></div>';
    if(q.ous){r.cols=[{k:'name',t:'Name'},{k:'loc',t:'Location'},{k:'mod',t:'Modified'}];r.rows=q.list().map(function(o){return {kind:'ou',ref:o,name:o.name,loc:o.parent,mod:o.modified||''};});}
    else{r.cols=COLS_GRP;r.rows=groupRows(q.list());}
  } else if(v.t==='idf'){
    r.icon=ic('sync','n'); r.title='Directory sync errors'; r.sub='IDFix-style scan of '+plural(IDX.scanned||0,'object');
    var capped=(IS.errors||0)>IDF.length;
    r.strip='<div class="strip"><div><b>'+plural(IS.errors||0,'error')+'</b> on '+plural(IS.affected||0,'object')+'. These attributes will block or dirty synchronization to Entra ID / Microsoft 365.'+(capped?' The report includes the first '+IDF.length+'; the full list is in '+esc(IDX.csvFile||'the CSV next to this report')+'.':'')+'</div></div>';
    r.cols=[{k:'name',t:'Error type'},{k:'errors',t:'Errors',num:1},{k:'desc',t:'Meaning'}];
    r.rows=ETYPES_USED.map(function(t){return {kind:'etype',ref:t,name:t,errors:etypeCount(t),desc:EHELP[t]};});
  } else if(v.t==='idft'){
    r.icon=ic('list','n'); r.title=v.id; r.sub='Directory sync errors';
    r.strip='<div class="strip"><div>'+esc(EHELP[v.id]||'')+' Double-click an object to see all its attributes with the failing ones highlighted.</div></div>';
    r.cols=[{k:'name',t:'Name'},{k:'otype',t:'Type'},{k:'attr',t:'Attribute'},{k:'val',t:'Value'},{k:'upd',t:'Suggested update'}];
    r.rows=IDF.filter(function(x){return x.error===v.id;}).map(function(x){return {kind:'idfobj',ref:x.dn,name:x.name,otype:x.objectClass,attr:x.attribute,val:x.value,upd:x.update||''};});
  } else if(v.t==='find'){
    r.icon=ic('query','a'); r.title='Search results'; r.sub='for "'+v.id+'"';
    r.cols=[{k:'name',t:'Name'},{k:'type',t:'Type',html:1},{k:'loc',t:'Location'}]; r.rows=findRows(v.id);
    if(r.rows.length>=500)r.strip='<div class="strip"><div>Showing the first 500 matches. Refine your search.</div></div>';
  }
  return r;
}
function findRows(q){
  q=q.toLowerCase(); var out=[];
  function add(x){if(out.length<500)out.push(x);}
  GROUPS.forEach(function(g){if(((g.name||'')+' '+(g.sam||'')+' '+(g.sid||'')).toLowerCase().indexOf(q)>=0)add({kind:'group',ref:g,name:g.name,type:gType(g),loc:g.dn||''});});
  OUS.forEach(function(o){if((o.name||'').toLowerCase().indexOf(q)>=0)add({kind:'ou',ref:o,name:o.name,type:'Organizational Unit',loc:o.parent});
    arr(o.children).forEach(function(c){if(c.type!=='group'&&(c.name||'').toLowerCase().indexOf(q)>=0)add({kind:c.type,ref:c,name:c.name,type:(KIND[c.type]||KIND.other)[2],loc:o.dn,where:o});});});
  [['users',DC.usersChildren,DC.usersDn],['computers',DC.compChildren,DC.compDn]].forEach(function(x){arr(x[1]).forEach(function(c){if(c.type!=='group'&&(c.name||'').toLowerCase().indexOf(q)>=0)add({kind:c.type,ref:c,name:c.name,type:(KIND[c.type]||KIND.other)[2],loc:x[2]});});});
  return out;
}

/* ---------------- state / rendering ---------------- */
var ST={v:{t:'dom'},hist:[],fwd:[],sel:-1,sort:{},rows:[],cols:[]}, TIPCLOSED=false, EXP={'dom':true};
function closeTip(){TIPCLOSED=true;var t=qs('#tipstrip');if(t)t.parentNode.removeChild(t);}
function go(v,noHist){if(!noHist&&ST.v&&viewKey(ST.v)!==viewKey(v)){ST.hist.push(ST.v);ST.fwd=[];}ST.v=v;ST.sel=-1;expandTo(v);renderTree();renderList();}
function back(){if(!ST.hist.length)return;ST.fwd.push(ST.v);go(ST.hist.pop(),true);}
function fwd(){if(!ST.fwd.length)return;ST.hist.push(ST.v);go(ST.fwd.pop(),true);}
function up(){var v=ST.v;if(v.t==='ou'){var o=ouBy[v.id];var p=(o&&o.parent||'').toLowerCase();go(ouBy[p]?{t:'ou',id:p}:{t:'dom'});}else if(v.t==='cn')go({t:'dom'});else if(v.t==='idft')go({t:'idf'});}
function expandTo(v){if(v.t==='ou'){var o=ouBy[v.id];EXP['dom']=true;while(o){var p=(o.parent||'').toLowerCase();if(ouBy[p]){EXP['ou:'+p]=true;o=ouBy[p];}else break;}}if(v.t==='idft')EXP['idf']=true;}
function sortRows(rows,cols){var s=ST.sort[viewKey(ST.v)];if(!s)return rows;var col=cols[s.c];if(!col)return rows;
  var k=col.k, num=col.num, d=s.d;
  return rows.slice().sort(function(a,b){var x=a[k],y=b[k];if(k==='flags'){x=a.flagsTxt;y=b.flagsTxt;}
    if(num)return ((+x||0)-(+y||0))*d; return (''+(x==null?'':x)).localeCompare(''+(y==null?'':y))*d;});}
function renderList(){
  var r=build(ST.v); ST.cols=r.cols;
  var base=r.rows; if(ST.v.t==='dom'||ST.v.t==='ou'||ST.v.t==='cn'){if(!ST.sort[viewKey(ST.v)]){base=base.slice().sort(function(a,b){var ka=a.kind==='ou'||a.kind==='container'?0:1,kb=b.kind==='ou'||b.kind==='container'?0:1;return (ka-kb)||cmpName(a,b);});}}
  else if(ST.v.t==='q'&&!QBY[ST.v.id].ous&&!ST.sort[viewKey(ST.v)]){base=base.slice().sort(function(a,b){return ((b.ref.circular?1:0)-(a.ref.circular?1:0))||(b.members-a.members)||cmpName(a,b);});}
  ST.rows=sortRows(base,r.cols);
  qs('#phead').innerHTML=r.icon+'<div style="min-width:0"><b>'+esc(r.title)+'</b><div class="pd">'+esc(r.sub||'')+'</div></div>';
  qs('#strip').innerHTML=r.strip||'';
  var s=ST.sort[viewKey(ST.v)];
  var th='<tr>'+r.cols.map(function(c,i){return '<th data-c="'+i+'"'+(c.num?' style="text-align:right"':'')+'>'+c.t+(s&&s.c===i?'<span class="so">'+(s.d>0?'&#9650;':'&#9660;')+'</span>':'')+'</th>';}).join('')+'</tr>';
  var body=ST.rows.map(function(row,i){return '<tr class="r" data-i="'+i+'">'+r.cols.map(function(c,ci){
    var val=row[c.k];
    if(ci===0){var icon=row.kind==='ou'?ic('folder','f'):row.kind==='container'?ic('folder','n'):row.kind==='etype'?ic('list','n'):row.kind==='idfobj'?ic(row.otype==='group'?'group':'user','n'):kindIcon(row.kind);
      return '<td><span class="nm">'+icon+'<span class="t">'+esc(val)+'</span></span></td>';}
    return '<td'+(c.num?' class="num"':'')+(c.k==='val'||c.k==='upd'||c.k==='loc'?' title="'+esc(val)+'"':'')+'>'+(c.html?(val==null?'':val):esc(val))+'</td>';}).join('')+'</tr>';}).join('');
  qs('#lv').innerHTML=ST.rows.length?'<table class="lt"><thead>'+th+'</thead><tbody>'+body+'</tbody></table>':'<div class="empty">'+(ST.v.t==='find'?'No matches.':'There are no items to show in this view.')+'</div>';
  var parts=[plural(ST.rows.length,'object')];
  if(ST.v.t==='dom'||ST.v.t==='ou'||ST.v.t==='cn'){var c={ou:0,user:0,computer:0,group:0};ST.rows.forEach(function(x){var k=x.kind==='container'?'ou':x.kind;if(c[k]!=null)c[k]++;});
    var b=[];if(c.ou)b.push(plural(c.ou,'container'));if(c.user)b.push(plural(c.user,'user'));if(c.computer)b.push(plural(c.computer,'computer'));if(c.group)b.push(plural(c.group,'group'));if(b.length)parts.push(b.join(', '));}
  qs('#status').innerHTML='<span>'+parts.join(' &middot; ')+'</span>'+(r.more?'<span>+ '+r.more+' more not shown in this report (raise -MemberDisplayCap to include them)</span>':'')+'<span class="r">Double-click to open &middot; Enter for properties</span>';
  qs('#bBack').disabled=!ST.hist.length;qs('#bFwd').disabled=!ST.fwd.length;qs('#bUp').disabled=!(ST.v.t==='ou'||ST.v.t==='cn'||ST.v.t==='idft');
  qs('#lv').scrollTop=0;
}
function selRow(i){ST.sel=i;Array.prototype.forEach.call(document.querySelectorAll('#lv tr.r'),function(tr){tr.classList.toggle('sel',+tr.getAttribute('data-i')===i);});
  var tr=document.querySelector('#lv tr.r.sel');if(tr&&tr.scrollIntoView)tr.scrollIntoView({block:'nearest'});}
function openRow(i,props){var row=ST.rows[i];if(!row)return;
  if(!props&&row.kind==='ou')return go({t:'ou',id:row.ref.dn.toLowerCase()});
  if(!props&&row.kind==='container')return go({t:'cn',id:row.ref});
  if(row.kind==='etype')return go({t:'idft',id:row.ref});
  showProps(row);}

/* ---------------- tree ---------------- */
function tnode(key,depth,twisty,icon,label,count,dot){
  var sel=treeKeyOf(ST.v)===key, open=EXP[key];
  return '<div class="tn'+(sel?' sel':'')+'" data-k="'+esc(key)+'" style="padding-left:'+(6+depth*16)+'px">'+
    '<span class="tw'+(open?' open':'')+'"'+(twisty?' data-t="'+esc(key)+'"':'')+'>'+(twisty?I.chev:'')+'</span>'+(dot!==undefined?'<span class="qd '+dot+'"></span>':icon)+
    '<span class="lb">'+esc(label)+'</span>'+(count!==undefined&&count!==''?'<span class="ct">'+count+'</span>':'')+'</div>';}
function treeKeyOf(v){if(v.t==='dom')return 'dom';if(v.t==='ou')return 'ou:'+v.id;if(v.t==='cn')return 'cn:'+v.id;if(v.t==='q')return 'q:'+v.id;if(v.t==='idf')return 'idf';if(v.t==='idft')return 'idft:'+v.id;return '';}
function ouTree(list,depth){return list.map(function(o){var k=o.dn.toLowerCase(),kids=ouKids[k]||[];
  return tnode('ou:'+k,depth,kids.length>0,ic('folder','f'),o.name)+(EXP['ou:'+k]&&kids.length?ouTree(kids,depth+1):'');}).join('');}
function renderTree(){
  var h=tnode('dom',0,true,ic('domain','a'),D.domain);
  if(EXP['dom']){
    var top=ouRoots.map(function(o){return {o:o,name:o.name};}).concat([{cn:'computers',name:'Computers'},{cn:'users',name:'Users'}]).sort(cmpName);
    top.forEach(function(x){if(x.cn)h+=tnode('cn:'+x.cn,1,false,ic('folder','n'),x.name);else h+=ouTree([x.o],1);});
  }
  h+='<div class="tsec">Saved queries</div>';
  QUERIES.forEach(function(q){var n=q.list().length;h+=tnode('q:'+q.id,0,false,'',q.label,n,q.id==='all'?'':(n?q.dot:'ok'));});
  h+='<div class="tsec">Directory sync</div>';
  h+=tnode('idf',0,ETYPES_USED.length>0,ic('sync','n'),'Sync errors (IDFix)',IS.errors||0);
  if(EXP['idf'])ETYPES_USED.forEach(function(t){h+=tnode('idft:'+t,1,false,ic('list','n'),t,etypeCount(t));});
  qs('#tree').innerHTML=h;
}
qs('#tree').addEventListener('click',function(e){
  var tw=e.target.closest('.tw[data-t]'); if(tw){var k=tw.getAttribute('data-t');EXP[k]=!EXP[k];renderTree();return;}
  var n=e.target.closest('.tn'); if(!n)return; var k=n.getAttribute('data-k');
  if(k==='dom')go({t:'dom'});else if(k.indexOf('ou:')===0)go({t:'ou',id:k.substring(3)});else if(k.indexOf('cn:')===0)go({t:'cn',id:k.substring(3)});
  else if(k.indexOf('q:')===0)go({t:'q',id:k.substring(2)});else if(k==='idf')go({t:'idf'});else if(k.indexOf('idft:')===0)go({t:'idft',id:k.substring(5)});
});
qs('#tree').addEventListener('dblclick',function(e){var n=e.target.closest('.tn');if(!n)return;var k=n.getAttribute('data-k');if(n.querySelector('.tw[data-t]')){EXP[k]=!EXP[k];renderTree();}});

/* ---------------- list events ---------------- */
qs('#lv').addEventListener('click',function(e){var th=e.target.closest('th');if(th){var c=+th.getAttribute('data-c'),k=viewKey(ST.v),s=ST.sort[k];ST.sort[k]={c:c,d:s&&s.c===c?-s.d:1};renderList();return;}
  var tr=e.target.closest('tr.r');if(tr){selRow(+tr.getAttribute('data-i'));qs('#lv').focus();}});
qs('#lv').addEventListener('dblclick',function(e){var tr=e.target.closest('tr.r');if(tr)openRow(+tr.getAttribute('data-i'));});
document.addEventListener('keydown',function(e){
  if(qs('#ovl').classList.contains('show')){if(e.key==='Escape')closeProps();return;}
  if(e.target.tagName==='INPUT'){if(e.key==='Enter'&&e.target.id==='find'){var q=e.target.value.trim();if(q.length>=2)go({t:'find',id:q});}if(e.key==='Escape')e.target.blur();return;}
  if(e.altKey&&e.key==='ArrowLeft'){e.preventDefault();back();return;}
  if(e.altKey&&e.key==='ArrowRight'){e.preventDefault();fwd();return;}
  if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();var n=ST.rows.length;if(!n)return;var i=ST.sel<0?0:Math.max(0,Math.min(n-1,ST.sel+(e.key==='ArrowDown'?1:-1)));selRow(i);}
  else if(e.key==='Enter'){if(ST.sel>=0)openRow(ST.sel,e.shiftKey);}
  else if(e.key==='Backspace'){e.preventDefault();if(ST.v.t==='ou'||ST.v.t==='cn'||ST.v.t==='idft')up();else back();}
});
var findT=null;
qs('#find').addEventListener('input',function(e){clearTimeout(findT);var q=e.target.value.trim();findT=setTimeout(function(){if(q.length>=2)go({t:'find',id:q},ST.v.t==='find');},250);});
qs('#bBack').onclick=back;qs('#bFwd').onclick=fwd;qs('#bUp').onclick=up;
qs('#bProps').onclick=function(){if(ST.sel>=0)openRow(ST.sel,true);else if(ST.v.t==='ou')showProps({kind:'ou',ref:ouBy[ST.v.id],name:ouBy[ST.v.id].name});};
qs('#bExport').onclick=function(){var cols=ST.cols;var rows=[cols.map(function(c){return c.t;})];
  ST.rows.forEach(function(r){rows.push(cols.map(function(c){var v=c.k==='flags'?r.flagsTxt:(c.k==='type'?(''+(r.type||'')).replace(/&ndash;/g,'-'):r[c.k]);return v;}));});
  if(ST.v.t==='q'&&!QBY[ST.v.id].ous){rows[0].push('SamAccountName','SID','DistinguishedName');ST.rows.forEach(function(r,i){rows[i+1].push(r.ref.sam,r.ref.sid,r.ref.dn);});}
  dl(('export_'+build(ST.v).title).replace(/[^A-Za-z0-9_-]+/g,'_')+'.csv',rows);};
qs('#themebtn').onclick=function(){var d=document.documentElement.getAttribute('data-theme')==='dark';document.documentElement.setAttribute('data-theme',d?'light':'dark');qs('#themetxt').textContent=d?'Dark':'Light';};

/* ---------------- properties dialog ---------------- */
var DSTACK=[];
function showProps(row,push){if(push)DSTACK.push(DCUR);else DSTACK=[];DCUR=row;renderProps(0);qs('#ovl').classList.add('show');}
var DCUR=null;
function closeProps(){qs('#ovl').classList.remove('show');DSTACK=[];}
function dBack(){if(!DSTACK.length)return;DCUR=DSTACK.pop();renderProps(0);}
qs('#dX').onclick=closeProps;qs('#dClose').onclick=closeProps;qs('#dBack').onclick=dBack;
qs('#ovl').addEventListener('click',function(e){if(e.target.id==='ovl')closeProps();});
function openGroupByName(n){var g=byName[n];if(g)showProps({kind:'group',ref:g,name:g.name},true);}
function tabsFor(row){if(row.kind==='group')return ['General','Members','Member Of','Nesting'];if(row.kind==='idfobj')return ['General','Attribute Editor','Sync errors'];return ['General'];}
function renderProps(ti){
  var row=DCUR, tabs=tabsFor(row);
  qs('#dTitle').textContent=(row.name||'')+' Properties'; qs('#dBack').style.display=DSTACK.length?'':'none';
  qs('#dTabs').innerHTML=tabs.map(function(t,i){return '<button class="'+(i===ti?'on':'')+'" data-t="'+i+'">'+t+'</button>';}).join('');
  Array.prototype.forEach.call(document.querySelectorAll('#dTabs button'),function(b){b.onclick=function(){renderProps(+b.getAttribute('data-t'));};});
  qs('#dBody').innerHTML=propBody(row,tabs[ti]); qs('#dBody').scrollTop=0;
}
function idHead(icon,name,sub){return '<div class="idh">'+icon+'<div><b>'+esc(name)+'</b>'+(sub?'<div class="muted" style="font-size:12px">'+sub+'</div>':'')+'</div></div>';}
function memberRows(list,more){list=arr(list);if(!list.length)return '<div class="more">No members.</div>';
  return list.map(function(m){var isG=m.type==='group'&&byName[m.name];return '<div class="mr'+(isG?' lnk':'')+'"'+(isG?' ondblclick="openGroupByName(this.getAttribute(\'data-n\'))" data-n="'+esc(m.name)+'"':'')+'><span class="nm">'+kindIcon(m.type)+'<span>'+esc(m.name)+'</span></span><span class="muted">'+(KIND[m.type]||KIND.other)[2]+'</span></div>';}).join('')+(more>0?'<div class="more">+ '+more+' more not shown</div>':'');}
function nestTree(name,chain){var g=byName[name];if(!g)return '';var kids=arr(g.nested);if(!kids.length)return '';
  return '<div class="kids">'+kids.map(function(n){var loop=chain.indexOf(n)>=0, cg=byName[n], has=cg&&arr(cg.nested).length&&!loop;
    return '<div><div class="nr'+(has?' x':'')+'" data-n="'+esc(n)+'" data-ch="'+esc(chain.concat([n]).join('\u0001'))+'">'+(has?'<span class="tw">'+I.chev+'</span>':'<span class="tw"></span>')+ic('group','g')+'<span>'+esc(n)+'</span>'+(cg?'<span class="muted" style="font-size:11.5px">'+plural(cg.total,'member')+'</span>':'')+(loop?'<span class="flag crit">loop</span>':'')+'</div></div>';}).join('')+'</div>';}
function propBody(row,tab){
  if(row.kind==='group'){var g=row.ref;
    if(tab==='General'){var adv=g.circular?'This group is part of a nesting loop. Use the Nesting tab to find it, then remove one of the memberships.':g.deep?'This group is nested '+g.depth+' levels deep. Consider flattening the chain so access is easier to reason about.':g.empty?'This group has no members. Confirm it is unused before removing it.':g.large?'This group has many members. Consider splitting it into role-based groups.':'';
      return idHead(ic('group','g'),g.name,gType(g))+'<dl class="fg"><dt>Group name (pre-2000)</dt><dd class="mono">'+esc(g.sam||'')+'</dd><dt>Group scope</dt><dd>'+esc(g.scope)+'</dd><dt>Group type</dt><dd>'+esc(g.category)+'</dd>'+
        '<dt>Members</dt><dd>'+g.total+'</dd><dt>Nested groups</dt><dd>'+g.nestedCount+'</dd><dt>Nesting depth</dt><dd>'+g.depth+'</dd><dt>Member of</dt><dd>'+arr(memberOf[g.name]).length+' group(s)</dd><dt>Last modified</dt><dd>'+esc(g.modified||'n/a')+'</dd>'+
        '<dt>Distinguished name</dt><dd class="mono">'+esc(g.dn||'')+'</dd></dl>'+(flagHtml(g)?'<div style="margin-top:14px">'+flagHtml(g)+'</div>':'')+(adv?'<div class="advice">'+adv+'</div>':'');}
    if(tab==='Members')return '<div class="ml"><div class="mh"><span>Name</span><span>Type</span></div>'+memberRows(g.members,g.moreMembers)+'</div><div class="hint">Double-click a group to open its properties.</div>';
    if(tab==='Member Of'){var mo=arr(memberOf[g.name]);return mo.length?'<div class="ml"><div class="mh"><span>Name</span><span>Type</span></div>'+mo.map(function(n){return '<div class="mr lnk" data-n="'+esc(n)+'" ondblclick="openGroupByName(this.getAttribute(\'data-n\'))"><span class="nm">'+ic('group','g')+'<span>'+esc(n)+'</span></span><span class="muted">Group</span></div>';}).join('')+'</div><div class="hint">Only group-in-group memberships are collected.</div>':'<div class="more">This group is not a member of any other group.</div>';}
    if(tab==='Nesting'){var t=nestTree(g.name,[g.name]);return t?'<div class="nt"><div class="nr">'+ic('group','g')+'<b>'+esc(g.name)+'</b></div>'+t+'</div><div class="hint">Click a group with an arrow to expand it. Loops are marked and not expanded further.</div>':'<div class="more">This group has no nested groups.</div>';}
  }
  if(row.kind==='ou'){var o=row.ref,subs=(ouKids[o.dn.toLowerCase()]||[]).length;
    return idHead(ic('folder','f'),o.name,'Organizational Unit')+'<dl class="fg"><dt>Users</dt><dd>'+(o.users||0)+'</dd><dt>Computers</dt><dd>'+(o.computers||0)+'</dd><dt>Groups</dt><dd>'+(o.groups||0)+'</dd><dt>Sub-OUs</dt><dd>'+subs+'</dd><dt>Last modified</dt><dd>'+esc(o.modified||'n/a')+'</dd><dt>Distinguished name</dt><dd class="mono">'+esc(o.dn)+'</dd></dl>'+
      (o.empty&&!subs?'<div class="advice">This OU is empty. Remove it if it is no longer part of your design.</div>':'');}
  if(row.kind==='container'){var u=row.ref==='users';return idHead(ic('folder','n'),u?'Users':'Computers','Container')+'<dl class="fg"><dt>Distinguished name</dt><dd class="mono">'+esc(u?DC.usersDn:DC.compDn)+'</dd></dl><div class="advice">This is a default container, not an OU. No GPO can be linked to it.</div>';}
  if(row.kind==='idfobj'){var ob=IOBJ[row.ref]||{dn:row.ref,name:row.name,attrs:{},errors:[]}, a=ob.attrs||{}, errs=arr(ob.errors);
    if(tab==='General')return idHead(ic(ob['class']==='group'?'group':'user','n'),ob.name||row.name,esc(ob['class']||''))+'<dl class="fg"><dt>Sync errors</dt><dd>'+errs.length+'</dd><dt>Last modified</dt><dd>'+esc(a.whenChanged||'n/a')+'</dd><dt>Distinguished name</dt><dd class="mono">'+esc(ob.dn)+'</dd></dl><div class="hint">See the Attribute Editor tab for the failing values.</div>';
    if(tab==='Attribute Editor'){var em={};errs.forEach(function(e){(em[e.attribute]=em[e.attribute]||[]).push(e);});
      var order=['cn','displayName','givenName','sn','sAMAccountName','userPrincipalName','mail','mailNickname','proxyAddresses','targetAddress','whenChanged'];Object.keys(a).forEach(function(k){if(order.indexOf(k)<0)order.push(k);});
      return '<table class="at"><tr><th>Attribute</th><th>Value</th></tr>'+order.map(function(k){var v=a[k];if(Array.isArray(v))v=v.join('\n');if(v==null||v==='')return '';var bad=em[k];
        return '<tr'+(bad?' class="bad"':'')+'><td>'+esc(k)+'</td><td class="v">'+esc(v).replace(/\n/g,'<br>')+(bad?bad.map(function(e){return '<span class="eb">'+esc(e.error)+(e.update?' &rarr; suggested: '+esc(e.update):'')+'</span>';}).join(''):'')+'</td></tr>';}).join('')+'</table><div class="hint">Highlighted attributes will fail directory synchronization.</div>';}
    if(tab==='Sync errors')return '<table class="at"><tr><th>Attribute</th><th>Error</th><th>Value</th><th>Suggested</th></tr>'+errs.map(function(e){return '<tr><td>'+esc(e.attribute)+'</td><td>'+esc(e.error)+'</td><td class="v">'+esc(e.value)+'</td><td class="v">'+esc(e.update||'')+'</td></tr>';}).join('')+'</table>';
  }
  var k=KIND[row.kind]||KIND.other, loc=row.where?row.where.dn:(row.loc||(ST.v.t==='ou'?ouBy[ST.v.id].dn:(ST.v.t==='cn'?(ST.v.id==='users'?DC.usersDn:DC.compDn):'')));
  return idHead(kindIcon(row.kind),row.name,k[2])+'<dl class="fg"><dt>Location</dt><dd class="mono">'+esc(loc||'n/a')+'</dd></dl><div class="hint">Only group and OU details are collected for this report.</div>';
}
qs('#dBody').addEventListener('click',function(e){var nr=e.target.closest('.nr.x');if(!nr)return;var nxt=nr.parentNode.querySelector('.kids');
  if(nxt){nr.parentNode.removeChild(nxt);nr.querySelector('.tw').classList.remove('open');return;}
  var chain=nr.getAttribute('data-ch').split('\u0001');var html=nestTree(nr.getAttribute('data-n'),chain);if(html){nr.insertAdjacentHTML('afterend',html);nr.querySelector('.tw').classList.add('open');}});
function dl(name,rows){var csv='\ufeff'+rows.map(function(r){return r.map(function(c){c=(c==null?'':''+c);return '"'+c.replace(/"/g,'""')+'"';}).join(',');}).join('\r\n');var b=new Blob([csv],{type:'text/csv'});var u=URL.createObjectURL(b);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(u);}

renderTree(); renderList();
</script>
</body></html>
"@

$stage = 'write-file'
Write-Host "Writing file ($([math]::Round($HTML.Length/1MB,2)) MB)..." -ForegroundColor Yellow
try {
    [System.IO.File]::WriteAllText($ReportPath, $HTML, (New-Object System.Text.UTF8Encoding($true)))
} catch {
    Write-Host ""
    Write-Host ">>> FAILED at stage '$stage': $($_.Exception.GetType().Name) - $($_.Exception.Message)" -ForegroundColor Red
    throw
}
Write-Host ""
Write-Host "  Report saved: $ReportPath" -ForegroundColor Green
if ($IdfCsvPath) { Write-Host "  IDFix CSV:    $IdfCsvPath" -ForegroundColor Green }
try { if ($OpenReport) { Start-Process $ReportPath } } catch {}
