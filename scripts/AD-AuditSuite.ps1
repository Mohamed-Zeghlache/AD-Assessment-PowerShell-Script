<#
.SYNOPSIS
    AD Audit Suite - runs every module script and builds ONE all-in-one report.

.DESCRIPTION
    Runs the AD Audit Suite modules one after another (each in its own
    PowerShell process, so one failing module never stops the others), then
    combines their reports into a single self-contained HTML file:

      - a visual dashboard with figures and charts from every module
      - each module's complete report, unchanged, one section at a time
        (sidebar navigation, can be hidden with Ctrl+B)

    Modules (in report order):
      Environment            Overview, DCInventory, Topology, TrustRelationships
      Identity & access      AccountSecurity, GroupOUStructure
      Policy & configuration GPOPolicyAnalyzer, DNSHealth
      Security & readiness   DCPosture
      Servers                ServerInventory (contacts every server: can be the longest module)

    READ-ONLY: this script only starts the module scripts, which are read-only.

.PARAMETER OutputPath      Folder for the all-in-one report (default: current folder).
.PARAMETER ScriptsPath     Folder containing the module scripts (default: this script's folder).
.PARAMETER Modules         Run only these modules (names as listed above). Default: all.
.PARAMETER Skip            Modules to leave out.
.PARAMETER ModuleArguments Extra arguments per module, e.g. @{ DCPosture = '-EventDays 3' }.
.PARAMETER TimeoutMinutes  Maximum run time per module before it is stopped (default 60).
.PARAMETER KeepModuleReports  Keep each module's own HTML report in the run folder.
.PARAMETER OpenReport      Open the report when done (default: $true).
.PARAMETER ForestName      Optional: forest for the Topology module to report on. Default: the current forest.
.PARAMETER RebuildFrom     Build the report from an existing run folder (AD_AuditSuite_run_...) without running the modules again.

.EXAMPLE
    .\AD-AuditSuite.ps1
.EXAMPLE
    .\AD-AuditSuite.ps1 -RebuildFrom .\AD_AuditSuite_run_20261005_101849
.EXAMPLE
    .\AD-AuditSuite.ps1 -Skip GPOPolicyAnalyzer -ModuleArguments @{ DCPosture = '-EventDays 3' }
.EXAMPLE
    # Server inventory from AD only (no connection to the servers), or leave it out
    .\AD-AuditSuite.ps1 -ModuleArguments @{ ServerInventory = '-SkipRemote' }
    .\AD-AuditSuite.ps1 -Skip ServerInventory

.NOTES
    Author  : Mohamed ZEGHLACHE
    Project : Active Directory Audit Suite
    Requires: the module scripts in -ScriptsPath and the ActiveDirectory module.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [string]$ScriptsPath = $PSScriptRoot,
    [string[]]$Modules,
    [string[]]$Skip,
    [hashtable]$ModuleArguments = @{},
    [int]$TimeoutMinutes = 60,
    [switch]$KeepModuleReports,
    [switch]$OpenReport = $true,
    [string]$RebuildFrom,
    [string]$ForestName
)

$ErrorActionPreference = 'Stop'
try { $OutputPath = [System.IO.Path]::GetFullPath($OutputPath) } catch {}
if (-not $ScriptsPath) { $ScriptsPath = (Get-Location).Path }
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$Stamp = [string](Get-Date -Format 'yyyyMMdd_HHmmss')
if ($RebuildFrom) {
    if (!(Test-Path $RebuildFrom)) { Write-Error "Run folder not found: $RebuildFrom"; exit 1 }
    $RunDir = [string](Resolve-Path $RebuildFrom).Path
} else {
    $RunDir = Join-Path $OutputPath "AD_AuditSuite_run_$Stamp"
    New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
}

Write-Host "AD Audit Suite - all-in-one report" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "build: v15-suite" -ForegroundColor DarkGray

# id, name, title, part, script file
$Catalog = @(
    @('ov',   'Overview',           'Forest & domain overview',     'Environment',            'AD-Overview.ps1'),
    @('dc',   'DCInventory',        'Domain controller inventory',  'Environment',            'AD-DCInventory.ps1'),
    @('topo', 'Topology',           'Topology & replication',       'Environment',            'AD-Topology.ps1'),
    @('trust','TrustRelationships', 'Trust relationships',          'Environment',            'AD-TrustRelationships.ps1'),
    @('acct', 'AccountSecurity',    'Account security',             'Identity & access',      'AD-AccountSecurity.ps1'),
    @('gou',  'GroupOUStructure',   'Groups, OUs & directory sync', 'Identity & access',      'AD-GroupOUStructure.ps1'),
    @('gpo',  'GPOPolicyAnalyzer',  'Group Policy',                 'Policy & configuration', 'GPO-PolicyAnalyzer.ps1'),
    @('dns',  'DNSHealth',          'DNS health',                   'Policy & configuration', 'AD-DNSHealth.ps1'),
    @('auth', 'DCPosture',          'DC posture & readiness',       'Security & readiness',   'AD-DCPosture.ps1'),
    @('srv',  'ServerInventory',    'Server inventory',             'Servers',                'AD-ServerInventory.ps1')
)
# Accept the module's previous name (AuthReadiness) for compatibility
if ($Modules) { $Modules = @($Modules | ForEach-Object { if ($_ -eq 'AuthReadiness') { 'DCPosture' } else { $_ } }) }
if ($Skip)    { $Skip    = @($Skip    | ForEach-Object { if ($_ -eq 'AuthReadiness') { 'DCPosture' } else { $_ } }) }
if ($ModuleArguments.ContainsKey('AuthReadiness') -and -not $ModuleArguments.ContainsKey('DCPosture')) { $ModuleArguments['DCPosture'] = $ModuleArguments['AuthReadiness'] }
$ValidNames = @($Catalog | ForEach-Object { $_[1] })
foreach ($n in @($Modules) + @($Skip)) {
    if ($n -and ($ValidNames -notcontains $n)) { Write-Error "Unknown module '$n'. Valid names: $($ValidNames -join ', ')"; exit 1 }
}

$TargetForest = $ForestName
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    if ($TargetForest) { $ForestName = [string](Get-ADForest -Server $TargetForest -ErrorAction Stop).Name } else { $ForestName = [string](Get-ADForest -ErrorAction Stop).Name }
} catch { $ForestName = $(if ($TargetForest) { $TargetForest } else { $env:USERDNSDOMAIN }) }
if ($TargetForest) { Write-Host "  Note: Topology reports on $TargetForest. The other modules report on the forest/domain of this machine." -ForegroundColor DarkYellow }
if (-not $ForestName) { $ForestName = 'unknown forest' }
Write-Host "Forest : $ForestName" -ForegroundColor Gray
Write-Host "Scripts: $ScriptsPath" -ForegroundColor Gray
Write-Host "Run dir: $RunDir" -ForegroundColor Gray
Write-Host ""

function Format-Duration { param([double]$Sec)
    $s = [int][math]::Round($Sec); if ($s -lt 60) { return "$s s" }
    return ('{0} min {1:00} s' -f [math]::Floor($s / 60), ($s % 60)) }
function Quote-Arg { param([string]$S) "'" + ($S -replace "'", "''") + "'" }

$Results = [System.Collections.ArrayList]::new()
$SuiteStart = Get-Date
$ps = Join-Path $PSHOME 'powershell.exe'; if (-not (Test-Path $ps)) { $ps = 'powershell.exe' }
$idx = 0
foreach ($m in $Catalog) {
    $idx++
    $id = $m[0]; $name = $m[1]; $title = $m[2]; $part = $m[3]; $file = $m[4]
    $r = @{ id=$id; name=$name; title=$title; part=$part; script=$file; status='ok'; duration=''; error=''; log=''; html='' }
    [void]$Results.Add($r)
    $label = "[{0}/{1}] {2}" -f $idx, $Catalog.Count, $title
    if (($Modules -and ($Modules -notcontains $name)) -or ($Skip -and ($Skip -contains $name))) {
        $r['status'] = 'skipped'; $r['error'] = 'Not selected for this run.'
        Write-Host "$label - skipped" -ForegroundColor DarkGray; continue
    }
    # find the script (also accept the older -Enhanced file names)
    $path = Join-Path $ScriptsPath $file
    if (-not (Test-Path $path)) { $alt = Join-Path $ScriptsPath ($file -replace '\.ps1$', '-Enhanced.ps1'); if (Test-Path $alt) { $path = $alt } }
    if (-not (Test-Path $path) -and $file -eq 'AD-DCPosture.ps1') { $alt = Join-Path $ScriptsPath 'AD-AuthReadiness.ps1'; if (Test-Path $alt) { $path = $alt } }
    if (-not (Test-Path $path)) {
        $r['status'] = 'skipped'; $r['error'] = "Script not found: $file"
        Write-Host "$label - script not found ($file)" -ForegroundColor Yellow; continue
    }
    $modDir = Join-Path $RunDir $name
    if ($RebuildFrom -and $name -eq 'DCPosture' -and -not (Test-Path $modDir)) { $legacyDir = Join-Path $RunDir 'AuthReadiness'; if (Test-Path $legacyDir) { $modDir = $legacyDir } }
    if ($RebuildFrom) {
        $existing = @(Get-ChildItem -Path $modDir -Filter '*.html' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending) | Select-Object -First 1
        if ($existing) {
            $dfile = Join-Path $modDir 'duration.txt'
            if (Test-Path $dfile) { $r['duration'] = [string](Get-Content -Path $dfile -Raw).Trim() }
            $r['html'] = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($existing.FullName))
            Write-Host "$label - using existing report" -ForegroundColor Green
        } else {
            $r['status'] = 'failed'; $r['error'] = 'No report found in the run folder.'
            Write-Host "$label - no report in the run folder" -ForegroundColor Yellow
        }
        continue
    }
    New-Item -ItemType Directory -Path $modDir -Force | Out-Null
    $cmd = '& ' + (Quote-Arg $path) + ' -OutputPath ' + (Quote-Arg $modDir) + ' -OpenReport:$false'
    if ($id -eq 'gpo') { $cmd += ' -BackupPath ' + (Quote-Arg (Join-Path $modDir 'GPOBackups')) }
    if ($id -eq 'topo' -and $TargetForest -and -not ($ModuleArguments.ContainsKey($name) -and "$($ModuleArguments[$name])" -match '-ForestName')) { $cmd += ' -ForestName ' + (Quote-Arg $TargetForest) }
    if ($ModuleArguments.ContainsKey($name) -and $ModuleArguments[$name]) { $cmd += ' ' + [string]$ModuleArguments[$name] }
    $outLog = Join-Path $modDir 'console.log'; $errLog = Join-Path $modDir 'errors.log'
    Write-Host "$label - running..." -ForegroundColor Yellow
    $t0 = Get-Date
    try {
        $p = Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmd) `
             -RedirectStandardOutput $outLog -RedirectStandardError $errLog -WindowStyle Hidden -PassThru
        $done = $p.WaitForExit($TimeoutMinutes * 60 * 1000)
        if (-not $done) { try { $p.Kill() } catch {}; $r['status'] = 'failed'; $r['error'] = "Stopped after $TimeoutMinutes minutes (timeout)." }
    } catch { $r['status'] = 'failed'; $r['error'] = "Could not start: $($_.Exception.Message)" }
    $r['duration'] = [string](Format-Duration ((Get-Date) - $t0).TotalSeconds)
    try { Set-Content -Path (Join-Path $modDir 'duration.txt') -Value $r['duration'] -Encoding UTF8 } catch {}
    $report = @(Get-ChildItem -Path $modDir -Filter '*.html' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending) | Select-Object -First 1
    if ($r['status'] -eq 'ok' -and $report) {
        $bytes = [System.IO.File]::ReadAllBytes($report.FullName)
        $r['html'] = [Convert]::ToBase64String($bytes)
        Write-Host ("        done in {0}  ({1:N1} MB)" -f $r['duration'], ($bytes.Length / 1MB)) -ForegroundColor Green
    } else {
        if ($r['status'] -eq 'ok') { $r['status'] = 'failed'; $r['error'] = 'The module finished without producing a report.' }
        $tail = ''
        foreach ($lf in @($errLog, $outLog)) { if (Test-Path $lf) { $lines = @(Get-Content -Path $lf -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.Trim() }); if ($lines.Count) { $tail += (($lines | Select-Object -Last 25) -join "`n") + "`n" } } }
        $r['log'] = $tail.Trim()
        Write-Host "        FAILED: $($r['error'])" -ForegroundColor Red
    }
}
$SuiteDuration = [string](Format-Duration ((Get-Date) - $SuiteStart).TotalSeconds)
if ($RebuildFrom) { $SuiteDuration = 'rebuilt from ' + (Split-Path $RunDir -Leaf) }

# ─────────────────────────────────────────────────────────────────────────────
# Build the all-in-one report
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Building the all-in-one report..." -ForegroundColor Yellow
function ConvertTo-JsonText { param($Value)
    if ($null -eq $Value) { return '""' }
    $t = [string]$Value
    $sb = [System.Text.StringBuilder]::new($t.Length + 16)
    [void]$sb.Append('"')
    foreach ($ch in $t.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 34) { [void]$sb.Append('\"') }
        elseif ($code -eq 92) { [void]$sb.Append('\\') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -eq 9) { [void]$sb.Append('\t') }
        elseif ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}
$json = [System.Text.StringBuilder]::new()
[void]$json.Append('{"forest":' + (ConvertTo-JsonText $ForestName))
[void]$json.Append(',"generated":' + (ConvertTo-JsonText ([string](Get-Date -Format 'yyyy-MM-dd HH:mm'))))
[void]$json.Append(',"host":' + (ConvertTo-JsonText ([string]$env:COMPUTERNAME)))
[void]$json.Append(',"user":' + (ConvertTo-JsonText ([string]"$env:USERDOMAIN\$env:USERNAME")))
[void]$json.Append(',"duration":' + (ConvertTo-JsonText $SuiteDuration))
[void]$json.Append(',"modules":[')
$first = $true
foreach ($r in $Results) {
    if (-not $first) { [void]$json.Append(',') }; $first = $false
    [void]$json.Append('{')
    $kf = $true
    foreach ($k in @('id','name','title','part','script','status','duration','error','log')) {
        if (-not $kf) { [void]$json.Append(',') }; $kf = $false
        [void]$json.Append('"' + $k + '":' + (ConvertTo-JsonText $r[$k]))
    }
    # base64 never needs escaping - append it directly (fast for large reports)
    [void]$json.Append(',"html":"').Append([string]$r['html']).Append('"}')
}
[void]$json.Append(']}')
$SuiteJSON = $json.ToString()
# keep "</script>" out of the inline data
$SuiteJSON = $SuiteJSON.Replace('</', '<\/')

$Template = @'
<!DOCTYPE html><html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AD Audit Suite</title>
<style>
:root{--bg:#f5f6fb;--surface:#fff;--surface2:#eef1f9;--surface3:#dfe4f2;--border:#e4e7f2;--text:#161a2e;--muted:#64708c;--accent:#4f46e5;--accent2:#8b5cf6;--accent-soft:#e6e6fd;--red:#ef4444;--red-soft:#fde2e2;--amber:#f59e0b;--amber-soft:#fef3c7;--green:#10b981;--green-soft:#d1fae5;--blue:#3b82f6;--blue-soft:#dbe8fe;--teal:#14b8a6;--pink:#ec4899;--shadow:0 2px 8px rgb(60 50 140/.06),0 1px 2px rgb(60 50 140/.04);--font:'Inter',system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
[data-theme="dark"]{--bg:#0c1524;--surface:#14213a;--surface2:#1c2c49;--surface3:#284066;--border:#243a5e;--text:#e8f0fb;--muted:#93a7c4;--accent:#818cf8;--accent-soft:rgba(129,140,248,.15);--red-soft:rgba(239,68,68,.15);--amber-soft:rgba(245,158,11,.15);--green-soft:rgba(16,185,129,.15);--blue-soft:rgba(59,130,246,.15);--shadow:0 4px 10px rgb(0 0 0/.25)}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;-webkit-font-smoothing:antialiased;overflow-x:hidden}
.side{position:fixed;left:0;top:0;bottom:0;width:250px;background:linear-gradient(180deg,#1c2044,#141731);color:#c9cde6;padding:22px 14px;overflow-y:auto;z-index:10;display:flex;flex-direction:column;transition:transform .25s ease}
[data-theme="dark"] .side{background:linear-gradient(180deg,#0a1222,#070d19);border-right:1px solid var(--border)}
.sb{display:flex;align-items:center;gap:12px;padding:0 8px 16px;border-bottom:1px solid rgba(255,255,255,.08)}.sl{width:40px;height:40px;border-radius:11px;background:linear-gradient(135deg,#6366f1,#4338ca);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;box-shadow:0 4px 14px rgba(79,70,229,.45);flex-shrink:0}
.sk{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:#8a90b8;font-weight:700}.stt{font-size:15px;font-weight:800;color:#fff}
.sidetog{display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#e6e8f5;cursor:pointer;margin-left:auto;flex-shrink:0}.sidetog:hover{background:rgba(255,255,255,.14)}
.sm{font-size:11.5px;color:#8f95ba;padding:12px 8px;border-bottom:1px solid rgba(255,255,255,.08);line-height:1.5}.sm b{color:#e6e8f5}
.toc .g{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:#6f76a3;font-weight:700;padding:14px 10px 6px}
.toc a{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:8px;font-size:12.8px;color:#c9cde6;cursor:pointer}.toc a:hover{background:rgba(255,255,255,.06);color:#fff}.toc a.on{background:rgba(99,102,241,.28);color:#fff;font-weight:600}
.toc .no{width:16px;font-size:11px;color:#8a90b8}.toc .n{margin-left:auto;font-size:10.5px;font-weight:700;padding:1px 7px;border-radius:999px}.toc .n.crit{background:rgba(239,68,68,.28);color:#fecaca}.toc .n.warn{background:rgba(245,158,11,.25);color:#fde68a}.toc .n.ok{background:rgba(16,185,129,.25);color:#a7f3d0}.toc .n.fail{background:rgba(148,163,184,.25);color:#e2e8f0}
.sf{margin-top:auto;padding-top:12px;border-top:1px solid rgba(255,255,255,.08)}.sbtn{width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#e6e8f5;padding:8px;border-radius:9px;font-size:12px;cursor:pointer;font-family:var(--font)}
.main{margin-left:250px;transition:margin-left .25s ease}.view{display:none}.view.on{display:block}
body.noside .side{transform:translateX(-100%)}body.noside .main{margin-left:0}
.showside{position:fixed;left:16px;bottom:16px;z-index:20;width:40px;height:40px;border-radius:11px;background:linear-gradient(135deg,#6366f1,#4338ca);color:#fff;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:0 6px 18px rgba(79,70,229,.45);opacity:0;pointer-events:none;transition:opacity .2s ease}
body.noside .showside{opacity:1;pointer-events:auto}.sidetog svg,.showside svg{width:18px;height:18px}
iframe.rep{display:block;width:100%;height:100vh;border:none;background:var(--bg)}
.ph{margin:40px;padding:60px;color:var(--muted);border:2px dashed var(--border);border-radius:14px;max-width:960px}.ph b{display:block;color:var(--text);font-size:17px;margin-bottom:8px}.ph pre{margin-top:16px;text-align:left;background:var(--surface2);border-radius:10px;padding:14px;font-size:12px;white-space:pre-wrap;color:var(--text);max-height:420px;overflow:auto}
.dash{padding:30px 40px 60px;max-width:1500px}
.dh{display:flex;align-items:flex-end;gap:16px;margin-bottom:22px}.dh h1{font-size:28px;font-weight:800;letter-spacing:-.03em}.dh p{color:var(--muted);font-size:13px;margin-top:4px}.dh .stamp{margin-left:auto;font-size:12px;color:var(--muted);text-align:right}
.hero{display:grid;grid-template-columns:1.25fr 1fr 1fr 1fr 1fr;gap:16px;margin-bottom:16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;box-shadow:var(--shadow);padding:18px 20px;position:relative;overflow:hidden;min-width:0}
.card h4{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.card h4 a{white-space:nowrap;margin-left:auto;text-transform:none;letter-spacing:0;font-size:12px;color:var(--accent);cursor:pointer;font-weight:600}
.posture{background:linear-gradient(135deg,#4f46e5,#7c3aed 60%,#db2777);color:#fff;border:none}.posture.good{background:linear-gradient(135deg,#059669,#0d9488)}.posture h4{color:rgba(255,255,255,.75)}
.posture .big{font-size:25px;font-weight:800;letter-spacing:-.03em;line-height:1.05}.posture .sub{font-size:13px;opacity:.85;margin-top:6px}
.posture .bars{display:flex;gap:4px;margin-top:16px;height:8px;border-radius:9px;overflow:hidden;background:rgba(255,255,255,.2)}.posture .bars i{display:block;height:100%}.posture .leg{display:flex;gap:14px;font-size:11.5px;margin-top:8px;opacity:.9;flex-wrap:wrap}
.stat .v{font-size:30px;font-weight:800;letter-spacing:-.02em;line-height:1.1}.stat .l{font-size:12px;color:var(--muted);font-weight:600;margin-top:2px}.stat .d{font-size:11.5px;margin-top:10px;color:var(--muted)}
.stat .ico{position:absolute;right:16px;top:16px;width:38px;height:38px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800}
.row{display:grid;gap:16px;margin-bottom:16px}.r3{grid-template-columns:1.4fr 1fr 1fr}.r2{grid-template-columns:1.2fr 1fr}.r4{grid-template-columns:repeat(4,1fr)}.r1{grid-template-columns:1fr}
@media(max-width:1300px){.hero{grid-template-columns:1fr 1fr 1fr}.r3,.r2,.r4{grid-template-columns:1fr 1fr}}
.hb{display:flex;flex-direction:column;gap:10px}.hb .it{display:grid;grid-template-columns:170px 1fr 54px;gap:10px;align-items:center;font-size:12.5px;cursor:pointer}.hb .it:hover span:first-child{color:var(--accent)}
.hb .tr{height:12px;border-radius:9px;background:var(--surface2);display:flex;overflow:hidden}.hb .tr i{display:block;height:100%}.hb .it b{text-align:right;font-size:12px}
.donut{display:flex;align-items:center;gap:14px;min-width:0}.donut .lg{display:flex;flex-direction:column;gap:7px;font-size:12.5px;min-width:0;flex:1}.donut .lg div{display:flex;align-items:center;gap:7px;white-space:nowrap}.donut .lg b{margin-left:auto;padding-left:12px}
.sw{width:10px;height:10px;border-radius:3px;display:inline-block;flex-shrink:0}
.dcgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;max-height:420px;overflow:auto}
.dcc{border:1px solid var(--border);border-radius:12px;padding:12px;background:var(--surface2)}.dcc b{font-size:13px;display:flex;align-items:center;gap:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dcc small{font-size:11px;color:var(--muted);display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dcc .chk{display:flex;gap:6px;margin-top:9px}.dcc .chk span{flex:1;font-size:10px;text-align:center;padding:4px 0;border-radius:6px;font-weight:700}
.s-ok{background:var(--green-soft);color:var(--green)}.s-warn{background:var(--amber-soft);color:var(--amber)}.s-crit{background:var(--red-soft);color:var(--red)}.s-na{background:var(--surface3);color:var(--muted)}
.tag{font-size:10px;font-weight:700;padding:1px 6px;border-radius:999px;background:var(--accent-soft);color:var(--accent)}
.mini{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.mini div{background:var(--surface2);border-radius:10px;padding:10px 12px}.mini b{display:block;font-size:18px;font-weight:800;white-space:nowrap}.mini span{font-size:11px;color:var(--muted);font-weight:600}
.ring{display:flex;align-items:center;gap:16px}.ring .t b{font-size:22px;font-weight:800;display:block}.ring .t span{font-size:12px;color:var(--muted)}
.prio .p{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);cursor:pointer;font-size:13px}.prio .p:last-child{border-bottom:none}.prio .p:hover .t{color:var(--accent)}
.prio .t{flex:1;font-weight:600}.prio .m{font-size:11px;font-weight:700;color:var(--muted);background:var(--surface2);border-radius:999px;padding:2px 9px;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:9px;display:inline-block;flex-shrink:0}
.chart svg{display:block;width:100%}.chart .lg{display:flex;gap:16px;font-size:11.5px;color:var(--muted);margin-top:6px;flex-wrap:wrap}
.na{color:var(--muted);font-size:12.5px;padding:18px 0;text-align:center}
.runtbl{width:100%;border-collapse:collapse;font-size:12.5px}.runtbl th{text-align:left;font-size:11px;color:var(--muted);text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--border)}.runtbl td{padding:8px 10px;border-bottom:1px solid var(--border)}
.pill{font-size:11px;font-weight:700;padding:2px 9px;border-radius:999px}.pill.ok{background:var(--green-soft);color:var(--green)}.pill.fail{background:var(--red-soft);color:var(--red)}.pill.skip{background:var(--surface3);color:var(--muted)}
.xbtn{display:inline-flex;align-items:center;gap:7px;background:var(--accent);color:#fff;border:none;border-radius:10px;padding:9px 14px;font-size:12.5px;font-weight:700;cursor:pointer;font-family:var(--font);margin-bottom:8px}
.xbtn:hover{filter:brightness(1.08)}.xbtn svg{width:14px;height:14px}
.sbtn.pdf{margin-bottom:8px;background:rgba(99,102,241,.35);border-color:rgba(165,180,252,.35);font-weight:700;display:flex;align-items:center;justify-content:center;gap:7px}.sbtn.pdf svg{width:13px;height:13px}
#printdoc{display:none}
@media print{
 @page{size:A4;margin:16mm 14mm 18mm 14mm;@bottom-center{content:"Page " counter(page) " of " counter(pages);font-size:8.5pt;color:#64708c}@bottom-left{content:"AD Audit Suite - findings report";font-size:8.5pt;color:#64708c}}
 html,body{background:#fff!important}.side,.showside,.main,.topbar{display:none!important}#printdoc{display:block!important}
}
.pd{font-family:'Inter','Segoe UI',Roboto,Arial,sans-serif;color:#161a2e;font-size:10pt;line-height:1.45;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.pd .cover{min-height:245mm;display:flex;flex-direction:column;justify-content:center;break-after:page;page-break-after:always}
.pd .kick{font-size:9pt;letter-spacing:.18em;text-transform:uppercase;color:#4f46e5;font-weight:800}
.pd .cover h1{font-size:30pt;line-height:1.1;margin:8pt 0 6pt;letter-spacing:-.02em}
.pd .cover .for{font-size:15pt;color:#3730a3;font-weight:700}
.pd .meta{margin:22pt 0;border-top:1pt solid #e4e7f2}.pd .meta div{display:flex;padding:6pt 0;border-bottom:1pt solid #e4e7f2}.pd .meta span{width:40mm;color:#64708c}
.pd .kp{display:flex;gap:8pt;margin-top:6pt}.pd .kp div{flex:1;border:1pt solid #e4e7f2;border-radius:6pt;padding:10pt 12pt}.pd .kp b{display:block;font-size:22pt;line-height:1.1}.pd .kp span{font-size:8.5pt;color:#64708c;text-transform:uppercase;letter-spacing:.05em}
.pd .verdict{margin-top:16pt;padding:10pt 12pt;border-left:4pt solid #dc2626;background:#fdf2f2;font-size:11pt}.pd .verdict.ok{border-color:#059669;background:#ecfdf5}
.pd h2{font-size:15pt;margin:0 0 4pt;padding-bottom:5pt;border-bottom:2pt solid #4f46e5;letter-spacing:-.01em}
.pd h3{font-size:11pt;margin:14pt 0 6pt}
.pd .sub{color:#64708c;font-size:9pt;margin-bottom:10pt}
.pd section.pg{break-before:page;page-break-before:always}
.pd table{width:100%;border-collapse:collapse;font-size:9pt}.pd thead{display:table-header-group}
.pd th{text-align:left;background:#eef1f9;color:#3b4461;font-size:8pt;text-transform:uppercase;letter-spacing:.04em;padding:5pt 7pt;border-bottom:1pt solid #d6dbea}
.pd td{padding:6pt 7pt;border-bottom:1pt solid #e8ebf4;vertical-align:top}.pd tr{break-inside:avoid;page-break-inside:avoid}
.pd td.n{text-align:right;font-variant-numeric:tabular-nums;width:18mm}
.pd .sv{display:inline-block;font-size:7.5pt;font-weight:800;padding:1.5pt 6pt;border-radius:8pt;white-space:nowrap}
.pd .sv.crit{background:#fde2e2;color:#b91c1c}.pd .sv.warn{background:#fef3c7;color:#92400e}.pd .sv.info{background:#dbe8fe;color:#1d4ed8}.pd .sv.ok{background:#d1fae5;color:#047857}.pd .sv.fail{background:#e5e7eb;color:#374151}
.pd .ft{font-weight:600}.pd .adv{color:#3b4461}
.pd .none{padding:10pt;border:1pt dashed #d6dbea;border-radius:6pt;color:#64708c}
.pd .keep{break-inside:avoid;page-break-inside:avoid}
.pd{--bg:#fff;--surface:#fff;--surface2:#eef1f9;--surface3:#dfe4f2;--border:#e4e7f2;--text:#161a2e;--muted:#64708c;--accent:#4f46e5;--accent2:#8b5cf6;--red:#ef4444;--amber:#f59e0b;--green:#10b981;--blue:#3b82f6;--teal:#14b8a6}
.pd h3.st{font-size:10.5pt;margin:14pt 0 6pt;padding-bottom:3pt;border-bottom:1pt solid #e4e7f2;color:#3730a3;text-transform:uppercase;letter-spacing:.05em;break-after:avoid;page-break-after:avoid}
.pd .pfig{display:grid;grid-template-columns:repeat(4,1fr);gap:6pt;break-inside:avoid;page-break-inside:avoid}
.pd .pfig div{border:1pt solid #e4e7f2;border-radius:5pt;padding:6pt 8pt}.pd .pfig b{display:block;font-size:13pt;line-height:1.15}.pd .pfig span{font-size:7.5pt;color:#64708c;text-transform:uppercase;letter-spacing:.04em}
.pd .pfig b.c{color:#b91c1c}.pd .pfig b.w{color:#b45309}.pd .pfig b.g{color:#047857}
.pd .pcr{display:grid;grid-template-columns:1fr 1fr;gap:8pt;margin-top:8pt;break-inside:avoid;page-break-inside:avoid}.pd .pcr.one{grid-template-columns:1fr}
.pd .pch{border:1pt solid #e4e7f2;border-radius:5pt;padding:8pt 10pt;break-inside:avoid;page-break-inside:avoid}
.pd .pct{font-size:8pt;font-weight:800;color:#64708c;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6pt}
.pd .dn{display:flex;align-items:center;gap:10pt}.pd .dn .lg{flex:1;font-size:8.5pt;display:flex;flex-direction:column;gap:3pt}.pd .dn .lg div{display:flex;align-items:center;gap:5pt}.pd .dn .lg b{margin-left:auto}
.pd .sw{width:7pt;height:7pt;border-radius:2pt;display:inline-block;flex-shrink:0}
.pd .pb{display:flex;flex-direction:column;gap:4pt;font-size:8.5pt}.pd .pbi{display:grid;grid-template-columns:38% 1fr 12%;gap:6pt;align-items:center}
.pd .pbt{height:7pt;background:#eef1f9;border-radius:4pt;overflow:hidden;display:flex}.pd .pbt i{display:block;height:100%}.pd .pbi b{text-align:right}
.pd .more{font-size:8pt;color:#64708c;margin-top:4pt;font-style:italic}
.pd table.mx td,.pd table.mx th{text-align:center;padding:4pt 3pt;font-size:8pt}.pd table.mx td:first-child,.pd table.mx th:first-child{text-align:left}
.pd .cell{display:inline-flex;align-items:center;justify-content:center;width:14pt;height:14pt;min-height:14pt;max-height:14pt;overflow:hidden;line-height:1;border-radius:3pt;font-weight:800;font-size:8pt;white-space:nowrap;vertical-align:middle;padding:0!important;text-align:center}
.pd .cell.ok{background:#d1fae5;color:#047857}.pd .cell.warn{background:#fef3c7;color:#92400e}.pd .cell.crit{background:#fde2e2;color:#b91c1c}.pd .cell.info{background:#dbe8fe;color:#1d4ed8}.pd .cell.na{background:#e5e7eb;color:#6b7280}
.pd .chart svg{display:block;width:100%}.pd .lgd{display:flex;gap:10pt;font-size:8pt;color:#64708c;margin-top:4pt;flex-wrap:wrap}
.pd .mono{font-family:Consolas,'SFMono-Regular',monospace;font-size:8pt}
.pd p{margin:0 0 7pt;font-size:10pt;line-height:1.55;color:#262b40}
.pd .about{background:#f5f6fb;border-left:3pt solid #4f46e5;padding:8pt 11pt;margin:6pt 0 4pt;font-size:9.5pt;color:#3b4461;break-inside:avoid;page-break-inside:avoid}
.pd .about b{color:#161a2e}
.pd .dsc{font-size:9pt;color:#64708c;margin:-2pt 0 6pt;break-after:avoid;page-break-after:avoid}
.pd .tblk{break-inside:avoid-page}.pd .tblk table{break-before:avoid}
.pd ol.steps{margin:4pt 0 10pt 16pt;padding:0}.pd ol.steps li{margin:0 0 7pt;font-size:10pt;line-height:1.5;break-inside:avoid;page-break-inside:avoid}
.pd ol.steps li span{display:block;color:#3b4461;font-size:9.3pt}.pd ol.steps li small{color:#64708c;font-size:8.5pt}
.pd ul.plain{margin:2pt 0 10pt 16pt;padding:0}.pd ul.plain li{margin:0 0 3pt;font-size:9.5pt}
.pd .phase{font-size:11pt;font-weight:800;margin:14pt 0 4pt;color:#161a2e;break-after:avoid;page-break-after:avoid}
.pd .phase i{font-style:normal;display:inline-block;width:18pt;height:18pt;border-radius:9pt;text-align:center;line-height:18pt;color:#fff;margin-right:6pt;font-size:9pt}
.topbar{position:fixed;top:0;left:0;right:0;height:52px;z-index:30;background:#0f6cbd;color:#fff;display:flex;align-items:center;gap:14px;padding:0 16px 0 8px;font-family:'Segoe UI',var(--font)}
[data-theme="dark"] .topbar{background:#0c3b5e}
.tb-ic{width:38px;height:38px;border:none;background:transparent;color:#fff;border-radius:6px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0}.tb-ic:hover{background:rgba(255,255,255,.14)}.tb-ic svg{width:18px;height:18px}
.tb-brand{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600;white-space:nowrap}.tb-brand .waf svg{width:18px;height:18px;display:block}
.tb-search{position:relative;flex:1;max-width:620px;margin:0 auto;display:flex;align-items:center;gap:9px;background:#fff;border-radius:6px;padding:0 12px;height:34px;color:#605e5c}
.tb-search svg{width:15px;height:15px;flex-shrink:0;color:#0f6cbd}.tb-search input{border:none;outline:none;background:transparent;font:inherit;font-size:13.5px;color:#242424;width:100%}
.tb-res{display:none;position:absolute;top:40px;left:0;right:0;background:#fff;border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.18);max-height:420px;overflow:auto;padding:6px 0;z-index:40}
.qr{display:flex;align-items:center;gap:10px;padding:8px 14px;font-size:13px;color:#242424;cursor:pointer}.qr:hover{background:#f3f6fb}.qr .t{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.qr small{color:#605e5c;font-size:11.5px;white-space:nowrap}.qr.none{color:#605e5c;cursor:default}
.tb-act{display:flex;align-items:center;gap:4px}.tb-av{width:34px;height:34px;border-radius:50%;border:2px solid rgba(255,255,255,.75);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;margin-left:6px}
.side{top:52px!important;width:250px!important;background:#f5f5f5!important;color:#242424!important;padding:10px 8px 14px!important;border-right:1px solid #e1dfdd!important;box-shadow:none!important}
[data-theme="dark"] .side{background:#16202f!important;color:#e8f0fb!important;border-right-color:#243a5e!important}
.side .toc .g{color:#605e5c!important;font-size:11px!important;letter-spacing:.04em!important;padding:14px 14px 6px!important}
[data-theme="dark"] .side .toc .g{color:#93a7c4!important}
.side .toc a{color:#242424!important;font-size:14px!important;padding:9px 12px 9px 14px!important;border-radius:4px!important;position:relative;font-family:'Segoe UI',var(--font)}
[data-theme="dark"] .side .toc a{color:#e8f0fb!important}
.side .toc a:hover{background:#ebebeb!important}[data-theme="dark"] .side .toc a:hover{background:#1f2c40!important}
.side .toc a.on{background:#e5f1fb!important;color:#0f6cbd!important;font-weight:600!important}[data-theme="dark"] .side .toc a.on{background:#1b3554!important;color:#7cb8f0!important}
.side .toc a.on::before{content:'';position:absolute;left:0;top:8px;bottom:8px;width:3px;border-radius:2px;background:#0f6cbd}
.side .toc .no{color:#8a8886!important}
.side .toc .n.crit{background:#fde7e9!important;color:#a4262c!important}.side .toc .n.warn{background:#fff4ce!important;color:#8a5a00!important}.side .toc .n.ok{background:#dff6dd!important;color:#107c10!important}.side .toc .n.fail{background:#edebe9!important;color:#605e5c!important}
.sfoot{margin-top:auto;padding:12px 8px 0;border-top:1px solid #e1dfdd}[data-theme="dark"] .sfoot{border-top-color:#243a5e}
.sfoot .sm{color:#605e5c!important;border:none!important;padding:0 6px 10px!important;font-size:11.5px!important}.sfoot .sm b{color:#242424!important}[data-theme="dark"] .sfoot .sm b{color:#e8f0fb!important}
.sbrand{display:flex;align-items:center;gap:8px;font-size:12px;color:#605e5c;padding:0 6px}.sbrand .waf svg{width:16px;height:16px;display:block;color:#0f6cbd}
.main{margin-left:250px!important;padding-top:52px}body.noside .main{margin-left:0!important}
iframe.rep{height:calc(100vh - 52px)!important}
#v-dash{background:linear-gradient(180deg,#eef3fb 0,#f6f8fc 320px,#f6f8fc 100%)}[data-theme="dark"] #v-dash{background:var(--bg)}
.dash{max-width:1500px;padding:22px 30px 46px!important;font-family:'Segoe UI',var(--font)}
.mkick{font-size:14px;color:#323130}.mh1{font-size:27px;font-weight:700;letter-spacing:-.02em;margin:4px 0 6px;color:#161a2e}.msub{font-size:14px;color:#605e5c;margin-bottom:20px}.msub b{color:#323130}
[data-theme="dark"] .mkick,[data-theme="dark"] .mh1{color:#e8f0fb}[data-theme="dark"] .msub,[data-theme="dark"] .msub b{color:#93a7c4}
.mstatus{display:flex;align-items:center;gap:14px;background:var(--surface);border:1px solid var(--border);border-left:4px solid #107c10;border-radius:8px;padding:12px 16px;margin-bottom:18px;box-shadow:0 1px 2px rgba(0,0,0,.05)}
.mstatus.crit{border-left-color:#d13438}.mstatus.warn{border-left-color:#f7a700}
.msi{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#dff6dd;color:#107c10;flex-shrink:0}.mstatus.crit .msi{background:#fde7e9;color:#d13438}.mstatus.warn .msi{background:#fff4ce;color:#8a5a00}.msi svg{width:17px;height:17px}
.mst{flex:1}.mst b{display:block;font-size:15px}.mst span{font-size:13px;color:var(--muted)}
.mbtn{background:#0f6cbd;color:#fff;border:none;border-radius:4px;padding:8px 14px;font:inherit;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap}.mbtn:hover{background:#115ea3}
.msrv{display:grid;grid-template-columns:1fr 1fr;gap:28px;align-items:center}@media(max-width:1250px){.msrv{grid-template-columns:1fr}}
.mgrid{display:grid;gap:16px;margin-bottom:16px}.g4{grid-template-columns:repeat(4,1fr)}.g3{grid-template-columns:repeat(3,1fr)}.g21{grid-template-columns:2fr 1fr}.g1{grid-template-columns:1fr}.g12{grid-template-columns:1fr 2fr}
@media(max-width:1250px){.g4{grid-template-columns:repeat(2,1fr)}.g3,.g21,.g12{grid-template-columns:1fr}}
.mcard{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px 20px;box-shadow:0 1.6px 3.6px rgba(0,0,0,.06),0 .3px .9px rgba(0,0,0,.05);display:flex;flex-direction:column;min-width:0}
[data-theme="dark"] .mcard{box-shadow:0 2px 6px rgba(0,0,0,.3)}
.mkh{display:flex;align-items:center;gap:12px;font-size:16px;font-weight:600;margin-bottom:12px;line-height:1.25}
.mtile{width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0}.mtile svg{width:23px;height:23px}
[data-theme="dark"] .mtile{filter:saturate(1.1) brightness(.92)}
.mkb{display:flex;flex-direction:column;align-items:stretch;gap:12px;flex:1;min-width:0}.mkm{min-width:0}.mkm b{display:block;font-size:clamp(28px,2.4vw,38px);font-weight:700;line-height:1.05;letter-spacing:-.02em}.mkm span{font-size:14px;color:var(--muted)}
.mks{border-top:1px solid var(--border);padding-top:10px;display:flex;flex-direction:row;flex-wrap:wrap;gap:6px 26px}.mks b{display:block;font-size:18px;font-weight:700;line-height:1.1}.mks span{font-size:12.5px;color:var(--muted);white-space:nowrap}
.mlink{display:inline-flex;align-items:center;gap:6px;color:#0f6cbd!important;font-size:13.5px;font-weight:500;margin-top:14px;cursor:pointer;text-decoration:none;align-self:flex-start}.mlink:hover{text-decoration:underline}.mlink svg{width:14px;height:14px}
[data-theme="dark"] .mlink{color:#7cb8f0!important}.mlink.in{margin-top:0;font-size:13px}
.mhd{display:flex;align-items:center;gap:11px;font-size:16px;font-weight:600;margin-bottom:14px}.mhi svg{width:22px;height:22px;display:block}
.mdn{display:flex;align-items:center;gap:16px;flex:1;flex-wrap:wrap;justify-content:center}.mdn.col{gap:18px}
.mleg{flex:1;display:flex;flex-direction:column;font-size:13px;min-width:190px}.mleg div{display:grid;grid-template-columns:12px 1fr auto 36px;gap:7px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)}
.mleg div:last-child{border-bottom:none}.mleg b{text-align:right}.mleg small{text-align:right;color:var(--muted);font-size:12.5px}.mleg .mtot{border-top:1px solid #8a8886;border-bottom:none}
.mdot{width:10px;height:10px;border-radius:50%;display:inline-block;flex-shrink:0}
.mrows{display:flex;flex-direction:column;font-size:13.5px}.mrow{display:grid;grid-template-columns:1fr auto 86px;gap:10px;align-items:center;padding:8px 2px;border-bottom:1px solid var(--border)}.mrow:last-child{border-bottom:none}
.mrow b{text-align:right;font-size:14px}.mrow small{color:var(--muted);font-size:12px}
.mnote{display:flex;gap:10px;align-items:center;background:#eff6fc;color:#323130;border-radius:6px;padding:10px 12px;font-size:12.5px;margin-top:12px}.mnote svg{width:16px;height:16px;color:#0f6cbd;flex-shrink:0}
.mnote.bad{background:#fde7e9}.mnote.bad svg{color:#d13438}.mnote.good{background:#dff6dd}.mnote.good svg{color:#107c10}
[data-theme="dark"] .mnote{background:#1b3554;color:#e8f0fb}[data-theme="dark"] .mnote.bad{background:rgba(209,52,56,.18)}[data-theme="dark"] .mnote.good{background:rgba(16,124,16,.2)}
.mtbl{overflow:auto;max-height:330px}.mtbl table{width:100%;border-collapse:collapse;font-size:13px}.mtbl th{text-align:left;font-size:12px;font-weight:600;color:var(--muted);padding:6px 8px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface)}
.mtbl td{padding:8px;border-bottom:1px solid var(--border);vertical-align:middle;white-space:nowrap}.mtbl td b{font-weight:600}.mtbl td small{display:block;color:var(--muted);font-size:11.5px;margin-left:16px}.mtbl td .mdot{margin-right:6px;width:8px;height:8px}
.mpill{display:inline-block;font-size:11.5px;font-weight:600;padding:2px 9px;border-radius:999px;white-space:nowrap}
.mtag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;background:#e5f1fb;color:#0f6cbd;white-space:nowrap}[data-theme="dark"] .mtag{background:#1b3554;color:#7cb8f0}
.mlegh{display:flex;gap:18px;flex-wrap:wrap;font-size:12.5px;color:var(--muted);margin-top:6px}.mlegh span{display:inline-flex;align-items:center;gap:6px}.mlegh b{color:var(--text)}
.mprio{display:flex;flex-direction:column}.mp{display:flex;align-items:center;gap:12px;padding:10px 4px;border-bottom:1px solid var(--border);cursor:pointer;font-size:13.5px}.mp:last-child{border-bottom:none}.mp:hover{background:var(--surface2)}
.mp .t{flex:1;font-weight:600}.mp svg{width:13px;height:13px;color:var(--muted)}
#v-dash .na{padding:30px 0}
.side .toc .nic{width:18px;height:18px;display:inline-flex;flex-shrink:0;color:#323130}.side .toc .nic svg{width:18px;height:18px}.side .toc a.on .nic{color:#0f6cbd}[data-theme="dark"] .side .toc .nic{color:#c8d3e3}[data-theme="dark"] .side .toc a.on .nic{color:#7cb8f0}
.side .toc a{gap:10px!important;font-size:13px!important;line-height:1.3!important;padding:7px 10px 7px 12px!important}
.side .toc .g{padding:12px 12px 4px!important;font-size:10.5px!important}
:root{--grid:#edebe9}
body{zoom:var(--ui-zoom,1)}
iframe.rep{height:calc(100vh / var(--ui-zoom,1) - 52px)!important}
.side{bottom:auto!important;height:calc(100vh / var(--ui-zoom,1) - 52px)!important}
@media print{body{zoom:1!important}}[data-theme="dark"]{--grid:#243a5e}
</style></head><body>
<header class="topbar"><button class="tb-ic" id="menubtn" title="Show or hide navigation (Ctrl+B)"><svg viewBox="0 0 16 16" fill="currentColor"><path fill-rule="evenodd" d="M2.5 12a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5m0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5m0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5"/></svg></button><div class="tb-brand"><span class="waf"><svg viewBox="0 0 16 16" fill="currentColor"><rect x="1" y="1" width="6.3" height="6.3"/><rect x="8.7" y="1" width="6.3" height="6.3"/><rect x="1" y="8.7" width="6.3" height="6.3"/><rect x="8.7" y="8.7" width="6.3" height="6.3"/></svg></span>AD Audit Suite</div><div class="tb-search"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="9.5" cy="6.5" r="4.5"/><path d="M6.3 9.7 1.5 14.5"/></svg><input id="q" placeholder="Search findings and modules" autocomplete="off"><div class="tb-res" id="qres"></div></div><div class="tb-act"><button class="tb-ic" id="pdfbtn" title="Export findings (PDF)"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M9.5 1.5H4A1.5 1.5 0 0 0 2.5 3v10A1.5 1.5 0 0 0 4 14.5h8a1.5 1.5 0 0 0 1.5-1.5V5.5z"/><path d="M9.5 1.5v4h4M5.5 9.5h5M5.5 12h3"/></svg></button><button class="tb-ic" id="themebtn" title="Dark mode"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M13.5 9.6A6 6 0 0 1 6.4 2.5a6 6 0 1 0 7.1 7.1z"/></svg></button><span class="tb-av" title="Read-only assessment">AD</span></div></header>
<aside class="side"><nav class="toc" id="toc"></nav><div class="sfoot"><div class="sm" id="smeta"></div><div class="sbrand"><span class="waf"><svg viewBox="0 0 16 16" fill="currentColor"><rect x="1" y="1" width="6.3" height="6.3"/><rect x="8.7" y="1" width="6.3" height="6.3"/><rect x="1" y="8.7" width="6.3" height="6.3"/><rect x="8.7" y="8.7" width="6.3" height="6.3"/></svg></span>AD Audit Suite &middot; read-only</div></div></aside>
<div id="printdoc"></div>
<main class="main"><section class="view on" id="v-dash"><div class="dash" id="dash"></div></section><section class="view" id="v-rep"><div id="repbox"></div></section></main>
<script>
(function(){function z(){var w=window.innerWidth||1920;document.documentElement.style.setProperty('--ui-zoom',w<1700?0.7:0.85);}z();window.addEventListener('resize',z);})();
var S = __SUITE_DATA__;
function e(s){return (s==null?'':''+s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function arr(x){if(x==null)return[];if(!Array.isArray(x))return[x];while(x.length===1&&Array.isArray(x[0]))x=x[0];return x;}
function num(x){var n=+x;return isFinite(n)?n:0;}
function fmt(n){return num(n).toLocaleString('en-US');}
function b64(s){var bin=atob(s),u=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return new TextDecoder('utf-8').decode(u);}
/* read a JS variable's JSON value (const/var X = {...}) out of a module report */
function readVar(html,name){
  var m=new RegExp('(?:const|var|let)\\s+'+name+'\\s*=\\s*').exec(html);if(!m)return null;
  var i=m.index+m[0].length,c=html.charAt(i);if(c!=='{'&&c!=='['){var end=html.indexOf(';',i);try{return JSON.parse(html.substring(i,end));}catch(x){return null;}}
  var depth=0,inStr=false,esc=false,j=i;
  for(;j<html.length;j++){var ch=html.charAt(j);
    if(inStr){if(esc)esc=false;else if(ch==='\\')esc=true;else if(ch==='"')inStr=false;continue;}
    if(ch==='"')inStr=true;else if(ch==='{'||ch==='[')depth++;else if(ch==='}'||ch===']'){depth--;if(depth===0)break;}}
  try{return JSON.parse(html.substring(i,j+1));}catch(x){return null;}}
var R={crit:3,warn:2,info:1,ok:0};
/* ---------- per-module readers: data -> figures + findings ---------- */
function sing(t){if(!/^1 /.test(t))return t;t=t.replace(/\(s\)/,'');if(/^1 [^ ]+\(s\)/.test(t))return t;return t.replace(/^1 ((?:[a-z-]+ ){0,2}?)([a-z]*[a-rt-z])s\b/i,function(m,pre,w){return '1 '+(pre||'')+w;});}
function F(){var f={list:[],add:function(sev,title,count,adv){if(count===undefined||count===null||count>0)f.list.push({sev:sev,title:sing(title),adv:adv||''});}};return f;}
var ADAPT={
 ov:function(D){var f=F(),a=D.accounts||{},c=D.computers||{},t=D.totals||{},fm=''+((D.forest||{}).forestMode||'');
   if(/2000|2003|2008|2012/.test(fm))f.add('warn','Forest functional level is '+fm.replace(/Windows|Forest/g,' ').trim(),null,'Raise the forest and domain functional levels once every domain controller runs Windows Server 2016 or later.');
   f.add('warn',fmt(a.stale)+' stale user accounts',num(a.stale),'Review these accounts with their owners, then disable and later remove the ones no longer used.');
   f.add('warn',fmt(c.stale)+' stale computer accounts',num(c.stale),'Disable, and later remove, computer accounts that no longer sign in to the domain.');
   f.add('info',fmt(a.pwdNeverExp)+' users with never-expiring passwords',num(a.pwdNeverExp),'Put these accounts on regular password rotation, or move service accounts to group Managed Service Accounts.');
   f.add('info',fmt(a.neverLoggedOn)+' users never logged on',num(a.neverLoggedOn),'Confirm these accounts are needed and remove the ones that are not.');
   return {f:f.list,x:{users:num(t.users),computers:num(t.computers),groups:num(t.groups),gpos:num(t.gpos),ous:num(t.ous),acc:a,comp:c,forestMode:fm,sites:num((D.forest||{}).siteCount)}};},
 dc:function(D){var f=F(),dcs=arr(D.dcs);
   dcs.forEach(function(d){if(d.isSupportedOS===false)f.add('crit',(d.shortName||d.name)+' runs an unsupported OS ('+(d.os||'?')+')',null,'Add a domain controller running a supported Windows Server version, move any roles, then demote and retire this one.');});
   f.add('warn',fmt(D.offlineDCs)+' domain controller(s) not reachable from the audit host',num(D.offlineDCs),'Confirm whether these domain controllers are running (for example from their replication activity or the hypervisor), then check the network path and firewall rules from the audit host and re-run the assessment.');
   return {f:f.list,x:{dcs:dcs,total:num(D.totalDCs)||dcs.length,offline:num(D.offlineDCs)}};},
 topo:function(D){var f=F(),m=arr(D.replMatrix),st=arr(D.staleObjects),links=arr(D.siteLinks),dl=arr(D.dcList);
   var byDst={};m.forEach(function(r){var s=r.state==='fail'?'crit':(r.state==='delayed'||r.state==='unqueryable'?'warn':'ok');var k=(''+r.dst).toUpperCase();if(!byDst[k]||R[s]>R[byDst[k]])byDst[k]=s;});
   var fail=m.filter(function(r){return r.state==='fail';}),del=m.filter(function(r){return r.state==='delayed';}),unq=m.filter(function(r){return r.state==='unqueryable';});
   var pairs={};fail.forEach(function(r){var k=r.src+' -> '+r.dst;if(!pairs[k])pairs[k]=r.errorText||'';});
   Object.keys(pairs).forEach(function(p){f.add('crit','Replication failing: '+p,null,(pairs[p]?pairs[p]+'. ':'')+'Check network connectivity and name resolution between the two DCs, fix the replication error, then confirm replication catches up.');});
   f.add('warn',del.length+' delayed replication partnership(s)',del.length,'Check the site link schedule and the network path between the sites involved.');
   f.add('warn',unq.length+' DC(s) whose replication could not be read',unq.length,'Allow the audit host to query these domain controllers (Active Directory Web Services or RPC) and re-run.');
   st.forEach(function(o){var cat=o.category||'Stale object',adv=/orphan/i.test(cat)?'Confirm the domain controller is decommissioned, then remove its leftover metadata.':(/empty site/i.test(cat)?'Remove the site, its subnets and site links if it is no longer used.':(/subnet/i.test(cat)?'Assign the correct subnets to the site, or remove the site if unused.':'Review this object and clean it up if it is no longer needed.'));
     f.add(o.severity==='high'?'crit':(o.severity==='medium'?'warn':'info'),cat+': '+(o.name||''),null,adv);});
   var sites={};dl.forEach(function(d){sites[d.site]=1;});
   return {f:f.list,x:{byDst:byDst,sites:Object.keys(sites).length,links:links.length,fail:fail.length}};},
 trust:function(D){var f=F();
   f.add('crit',fmt(D.highRisk)+' high-risk trust(s)',num(D.highRisk),'Review these trusts: enable SID filtering and selective authentication where possible, and remove trusts that are no longer needed.');
   f.add('warn',fmt(D.mediumRisk)+' medium-risk trust(s)',num(D.mediumRisk),'Review the trust configuration and narrow the authentication scope where possible.');
   f.add('warn',fmt(D.noSidFilter)+' trust(s) without SID filtering',num(D.noSidFilter),'Enable SID filtering (quarantine) on these trusts unless a migration that needs SID history is in progress.');
   f.add('warn',fmt(D.unreachable)+' trust partner(s) unreachable',num(D.unreachable),'Confirm the partner domain still exists and is reachable; remove trusts that are no longer used.');
   return {f:f.list,x:{total:num(D.totalTrusts),external:num(D.externalCount)}};},
 acct:function(D){var f=F(),c=D.counts||{},cc=D.compCounts||{},l=D.laps||{};
   if(num(D.krbtgtAge)>180)f.add('crit','krbtgt password not changed for '+fmt(D.krbtgtAge)+' days',null,'Reset the krbtgt password twice, waiting for full replication between the two resets.');
   if(D.krbtgtNoAes)f.add('crit','krbtgt has no AES keys',null,'Domain controllers issue AES-only Kerberos tickets by default since the April 2026 hardening (CVE-2026-20833). Reset the krbtgt password twice, one replication cycle apart, so AES keys are created.');
   f.add('crit',fmt(c.noAesSvc)+' service accounts without AES keys',num(c.noAesSvc),'Their passwords predate AES support, so their Kerberos tickets fail now that domain controllers issue AES-only tickets by default (CVE-2026-20833). Reset the passwords (coordinate with application owners) or move the services to gMSA.');
   f.add('warn',fmt(num(c.noAes)-num(c.noAesSvc))+' user accounts without AES keys',num(c.noAes)-num(c.noAesSvc),'These users have not changed their password since before the domain supported AES. Have them change it, or force a change at next logon.');
   f.add('crit',fmt(c.notRequired)+' accounts with "password not required"',num(c.notRequired),'Clear the "password not required" flag and make sure each account has a strong password.');
   f.add('crit',fmt(c.deleg)+' accounts with unconstrained delegation',num(c.deleg),'Replace unconstrained delegation with constrained or resource-based constrained delegation.');
   f.add('crit',fmt(cc.legacyOS)+' computers on legacy operating systems',num(cc.legacyOS),'Retire or isolate computers running Windows versions that are out of support.');
   f.add('warn',fmt(D.policyFail)+' password policy setting(s) below baseline',num(D.policyFail),'Strengthen the domain password and lockout policy to meet the baseline.');
   f.add('warn',fmt(c.neverExpires)+' accounts with never-expiring passwords',num(c.neverExpires),'Put these accounts on password rotation, or move services to group Managed Service Accounts.');
   f.add('warn',fmt(c.sidHist)+' accounts with SID history',num(c.sidHist),'Remove SID history once the related migration is complete.');
   f.add('warn',fmt(c.staleSvc)+' service accounts with stale passwords',num(c.staleSvc),'Rotate these service account passwords, or move the services to group Managed Service Accounts.');
   f.add('warn',fmt(c.inactive)+' inactive accounts',num(c.inactive),'Disable, and later remove, accounts that are no longer used.');
   if(l.mode==='None'||(!num(l.total)&&l.mode!==undefined))f.add('crit','LAPS is not deployed',null,'Deploy Windows LAPS so every computer has a unique, automatically rotated local administrator password. Without it, one shared local password lets an attacker move from machine to machine.');
   else f.add('warn',fmt(l.missing)+' computers without LAPS',num(l.missing),'Deploy Windows LAPS to the remaining computers so each has a unique, rotated local administrator password.');
   f.add('info',fmt(cc.stale)+' stale computer accounts',num(cc.stale),'Disable, and later remove, computer accounts that no longer sign in.');
   f.add('info',fmt((D.orphanSids||{}).distinct)+' orphaned SIDs in ACLs',num((D.orphanSids||{}).distinct),'Remove permissions granted to SIDs that no longer resolve to an account.');
   return {f:f.list,x:{laps:l,counts:c,krbtgt:num(D.krbtgtAge)}};},
 gou:function(D){var f=F(),s=D.stats||{},ix=(D.idfix||{}).stats||{};
   f.add('crit',fmt(s.circular)+' group(s) in circular nesting',num(s.circular),'Remove one of the memberships in each nesting loop.');
   f.add('warn',fmt(s.deep)+' deeply nested group(s)',num(s.deep),'Flatten the nesting chains so effective access is easy to follow.');
   f.add('warn',fmt(ix.errors)+' directory sync (IDFix) errors',num(ix.errors),'Fix the listed attribute values before synchronising these objects to Entra ID.');
   f.add('info',fmt(s.empty)+' empty security groups',num(s.empty),'Confirm these groups are unused, then remove them.');
   f.add('info',fmt(s.emptyOus)+' empty OUs',num(s.emptyOus),'Remove OUs that are no longer part of the directory design.');
   f.add('info',fmt(s.defaultObjs)+' objects in default containers',num(s.defaultObjs),'Move users, groups and computers out of the default Users and Computers containers into OUs.');
   return {f:f.list,x:{s:s,sync:num(ix.errors)}};},
 gpo:function(D){var f=F(),ga=arr(D.gpoAnalysis),ig=D.integrity||{},bl=D.baseline||{};
   var n=function(k){return ga.filter(function(g){return g[k];}).length;};
   var ao=arr(ig.adOnly).length+arr(ig.sysvolOnly).length;
   f.add('crit',ao+' GPO(s) out of sync between AD and SYSVOL',ao,'Check SYSVOL replication and restore the missing part of each affected GPO.');
   var wm=(D.gpoWmi&&typeof D.gpoWmi==='object')?D.gpoWmi:{},wmc=arr(D.rows).filter(function(r){return r.conflict&&Object.keys(r.values||{}).some(function(g){return wm[g]&&wm[g].name&&r.values[g]!=null&&(''+r.values[g]).trim()!=='';});}).length;
   f.add('warn',fmt(D.conflictCount)+' conflicting settings between GPOs',num(D.conflictCount),'Consolidate conflicting settings so the result does not depend on link order.'+(wmc?' '+wmc+' of them involve GPOs with a WMI filter, which only apply to computers matching the filter; check whether those GPOs really reach the same computers before changing anything.':''));
   f.add('warn',n('isUnlinked')+' unlinked GPO(s)',n('isUnlinked'),'Link these GPOs where they are intended to apply, or remove them.');
   f.add('warn',fmt(bl.wrong)+' baseline setting(s) configured differently',num(bl.wrong),'Align these settings with the security baseline.');
   f.add('info',n('isEmpty')+' empty GPO(s)',n('isEmpty'),'Remove GPOs that configure no settings.');
   f.add('info',n('isDisabledLink')+' GPO(s) with only disabled links',n('isDisabledLink'),'Re-enable the links or remove the GPOs.');
   f.add('info',n('isRedundant')+' redundant GPO(s)',n('isRedundant'),'Merge or remove GPOs whose settings are fully duplicated elsewhere.');
   return {f:f.list,x:{total:num(D.gpoCount),unlinked:n('isUnlinked'),empty:n('isEmpty'),conflicts:num(D.conflictCount)}};},
 dns:function(D){var f=F(),seen={};function add(fs){arr(fs).forEach(function(x){if(x&&(x.sev==='crit'||x.sev==='warn')){var k=x.title;if(!seen[k])seen[k]={sev:x.sev,adv:x.fix||''};else if(R[x.sev]>R[seen[k].sev])seen[k].sev=x.sev;}});}
   arr(D.zones).forEach(function(z){add(z.findings);});arr(D.dcs).forEach(function(d){add(d.findings);add(d.cfgFindings);});arr(D.servers).forEach(function(s){add(s.findings);});arr((D.replication||{}).partitions).forEach(function(p){add(p.findings);});
   arr(D.msdcs).forEach(function(m){if(!m.present)seen['Missing DC locator SRV records']={sev:'crit',adv:'Restart the Netlogon service on the domain controllers so they re-register their locator records.'};});
   if(arr(D.staleDc).length)seen['Records still point at removed domain controllers']={sev:'warn',adv:'Delete the DNS records that point at removed domain controllers and clean up their leftover metadata.'};
   Object.keys(seen).forEach(function(k){f.add(seen[k].sev,k,null,seen[k].adv);});
   return {f:f.list,x:{zones:arr(D.zones).length,crit:f.list.filter(function(x){return x.sev==='crit';}).length,warn:f.list.filter(function(x){return x.sev==='warn';}).length}};},
 auth:function(D){var f=F(),seen={},dcs=arr(D.dcs),EV=D.events||{},W=D.w25||{},BK=D.backup||{};
   function add(sev,t,adv){if(!seen[t])seen[t]={sev:sev,adv:adv||''};else{if(R[sev]>R[seen[t].sev])seen[t].sev=sev;if(!seen[t].adv&&adv)seen[t].adv=adv;}}
   dcs.forEach(function(dc){arr(dc.settings).forEach(function(s){if(s.sev!=='ok')add(s.sev,s.title,s.advice);});arr((dc.time||{}).findings).forEach(function(t){add(t.sev,t.title,t.advice);});});
   if(arr(D.desOnly).length)add('crit','Accounts restricted to DES Kerberos','Clear "Use only Kerberos DES encryption types" on these accounts and reset their passwords so AES keys are created.');
   if(EV.collected){if(arr(EV.cleared).length)add('crit','Security log was cleared','Confirm who cleared the log and why; this is a common step to hide an intrusion.');
     if(arr(EV.privChanges).length)add('warn','Privileged group membership changed','Confirm each change to privileged groups was authorised.');
     if(arr(EV.failSources).some(function(x){return x.distinct>=10;}))add('warn','Possible password spraying','Identify the source machine and investigate; consider blocking it and resetting passwords of targeted accounts.');
     if(arr(EV.lockouts).some(function(x){return x.count>=5;}))add('warn','Accounts locked out repeatedly','Find the device or service still using an old password and update it.');}
   if(BK.recycleBin&&!BK.recycleBinEnabled)add('warn','AD Recycle Bin not enabled','Enable the AD Recycle Bin so deleted objects can be restored with all their attributes.');
   if((BK.sysvol||{}).sev==='crit')add('crit','SYSVOL still replicated by FRS','Migrate SYSVOL replication from FRS to DFSR.');
   arr(BK.partitions).forEach(function(p){if(p.days==null&&!p.error)add('crit','Partition never backed up','Back up at least one domain controller (system state) regularly and well within the tombstone lifetime.');else if(p.days>7)add('warn','No backup in the last 7 days','Back up at least one domain controller (system state) regularly - daily is typical.');});
   var wc=0,ww=0,wt=0,wl=[];function chk(bad,sev,name){wt++;wl.push({name:name||'',st:bad?sev:'ok'});if(bad){if(sev==='crit')wc++;else ww++;}}
   var exOld=arr(W.exchange).some(function(x){var v=x.ver||'',m=/Build\s+(\d+)/i.exec(x.version||'');return /^(14\.|15\.0|15\.1)/.test(v)||(v.indexOf('15.2')===0&&m&&+m[1]<1544);});
   var ntlm1=dcs.some(function(dc){return arr(dc.settings).some(function(x){return x.id==='ntlmLevel'&&x.sev!=='ok';});});
   chk(W.ffl!=null&&W.ffl<7,'crit','Forest functional level 2016 or higher');chk(W.dfl!=null&&W.dfl<7,'crit','Domain functional level 2016 or higher');chk(arr(W.dcs).some(function(d){return !d.ok;}),'crit','All domain controllers on Windows Server 2016 or later');chk((BK.sysvol||{}).sev&&(BK.sysvol||{}).sev!=='ok','crit','SYSVOL replicated by DFSR');
   chk(arr(D.desOnly).length,'crit','No accounts restricted to DES (removed in Windows Server 2025)');chk(exOld,'crit','Exchange 2019 CU14 or later, or Exchange SE');chk(ntlm1,'warn','No NTLMv1 (removed in Windows Server 2025)');
   if(wc)add('crit','Not ready for Windows Server 2025 ('+wc+' blocker'+(wc===1?'':'s')+')','Resolve the blockers listed in the Windows Server 2025 readiness section before promoting the first Windows Server 2025 domain controller. Each check there links to the Microsoft documentation it is based on.');
   Object.keys(seen).forEach(function(k){f.add(seen[k].sev,k,null,seen[k].adv);});
   return {f:f.list,x:{dcs:dcs,pdc:D.pdc,ev:EV,w25:{crit:wc,warn:ww,pass:wt-wc-ww,total:wt,list:wl},backup:BK}};},
 srv:function(D){var f=F(),P=D.params||{},pd=num(P.patchDays)||60,G=siDate(D.generated),SV=arr(D.servers),SQ=arr(D.sql);
   var win=0,eos=[],soon=[],os={},notUpd=0,notUpd2=0,notRst=0,pend=0,notRead=[],noNet=0,phys=0,virt=0,dnsBad=0,noAct=0,sqlNoUpd=0;
   SV.forEach(function(s){var L=s.status!=='disabled'?siOs(s):null;
     if(L){win++;var v=siSev(L[1],G);os[L[0]]=os[L[0]]||[0,v];os[L[0]][0]++;if(v==='crit')eos.push([s,L]);else if(v==='warn')soon.push([s,L]);}
     if(s.status==='ok'){if(s.patchDays!=null&&s.patchDays>pd){notUpd++;if(s.patchDays>pd*2)notUpd2++;}if(s.uptimeDays!=null&&s.uptimeDays>pd)notRst++;if(s.pending)pend++;if(s.platform==='Physical')phys++;else if(s.platform==='Virtual')virt++;
       if(s.dnsState==='mismatch'||s.dnsState==='missing')dnsBad++;if(s.act&&s.act.ok===false)noAct++;}
     if(!s.site&&(arr(s.ips).length||arr(s.dnsIps).length)&&s.status!=='disabled')noNet++;
     if(siContacted(s)&&s.status!=='ok')notRead.push(s);});
   var contacted=SV.filter(siContacted).length,sqlEos=[],sqlSoon=0;
   SQ.forEach(function(i){if(siSqlBase(i.version))sqlNoUpd++;var L=siSql(i.version);if(!L)return;var v=siSev(L[1],G);if(v==='crit')sqlEos.push([i,L]);else if(v==='warn')sqlSoon++;});
   f.add('crit',eos.length+' servers on a Windows version out of support',eos.length,'Upgrade or replace these servers: out-of-support versions get no security updates. Where that takes time, isolate them on the network and limit who can sign in to them.');
   f.add('warn',soon.length+' servers whose Windows support ends within a year',soon.length,'Plan the upgrade or replacement of these servers before their end-of-support date.');
   f.add('crit',sqlEos.length+' SQL Server instances out of support',sqlEos.length,'Upgrade these instances to a supported SQL Server version, or migrate their databases.');
   f.add('warn',sqlSoon+' SQL Server instances whose support ends within a year',sqlSoon,'Plan the upgrade of these instances before their end-of-support date.');
   f.add('crit',notUpd2+' servers with no update installed in more than '+(pd*2)+' days',notUpd2,'Update these servers first: they have missed several monthly security updates. Then check why they stopped getting updates.');
   f.add('warn',(notUpd-notUpd2)+' servers with no update installed for '+pd+' to '+(pd*2)+' days',notUpd-notUpd2,'Bring these servers back into the monthly update cycle and check why they stopped getting updates.');
   f.add('warn',notRst+' servers not restarted in the last '+pd+' days',notRst,'Restart these servers in the next maintenance window: updates installed since the last boot only take effect after a restart.');
   f.add('warn',dnsBad+' servers whose DNS record is missing or does not match their IP address',dnsBad,'Correct the DNS records of these servers, or enable dynamic DNS registration on them, so clients reach the right address.');
   f.add('warn',noAct+' servers where Windows is not activated',noAct,'Activate Windows on these servers (KMS, MAK or AVMA, depending on how the environment is licensed).');
   f.add('info',sqlNoUpd+' SQL Server instances with no update installed',sqlNoUpd,'Install the latest cumulative update for these instances; they still run the release or service pack build.');
   f.add('info',pend+' servers with a restart pending',pend,'Restart these servers to finish installing updates or configuration changes.');
   f.add('info',notRead.length+' servers that could not be read from the audit host',notRead.length,'See Management access in the Server Inventory report: it shows, per subnet, what blocks these servers and what to open. Until then, figures read from the servers do not cover them.');
   f.add('info',noNet+' servers with an IP address in no AD subnet',noNet,'Add the missing subnets to AD Sites and Services and link them to the right site, so these servers find their nearest domain controller.');
   var osl=Object.keys(os).map(function(k){return [k,os[k][0],os[k][1]];}).sort(function(a,b){return b[1]-a[1];});
   return {f:f.list,x:{total:SV.length,contacted:contacted,read:SV.filter(function(s){return s.status==='ok';}).length,win:win,eos:eos.length,soon:soon.length,ok:win-eos.length-soon.length,osl:osl,eosList:eos,
     sql:SQ.length,sqlEos:sqlEos.length,sqlEosList:sqlEos,clusters:arr(D.clusters).length,notUpd:notUpd,notRst:notRst,pend:pend,notRead:notRead,phys:phys,virt:virt,pd:pd}};}
};
/* Lifecycle dates for the Server Inventory reader: same table as AD-ServerInventory.ps1 (Microsoft lifecycle pages) */
var SILOS={26100:['Windows Server 2025','2034-11-14'],20348:['Windows Server 2022','2031-10-14'],17763:['Windows Server 2019','2029-01-09'],14393:['Windows Server 2016','2027-01-12'],9600:['Windows Server 2012 R2','2023-10-10'],9200:['Windows Server 2012','2023-10-10'],
  7601:['Windows Server 2008 R2','2020-01-14'],7600:['Windows Server 2008 R2','2020-01-14'],6003:['Windows Server 2008','2020-01-14'],6002:['Windows Server 2008','2020-01-14'],6001:['Windows Server 2008','2020-01-14'],3790:['Windows Server 2003','2015-07-14']};
var SIOSN=[[/2025/,26100],[/2022/,20348],[/2019/,17763],[/2016/,14393],[/2012 R2/,9600],[/2012/,9200],[/2008 R2/,7601],[/2008/,6003],[/2003/,3790]];
var SISQL={'17':['SQL Server 2025','2036-01-06'],'16':['SQL Server 2022','2033-01-11'],'15':['SQL Server 2019','2030-01-08'],'14':['SQL Server 2017','2027-10-12'],'13':['SQL Server 2016','2026-07-14'],'12':['SQL Server 2014','2024-07-09'],'11':['SQL Server 2012','2022-07-12'],'10.5':['SQL Server 2008 R2','2019-07-09'],'10':['SQL Server 2008','2019-07-09']};
function siDate(t){var d=new Date((''+(t||'')).replace(' ','T'));return isNaN(d)?new Date():d;}
function siSev(end,G){var d=(new Date(end+'T00:00:00')-G)/864e5;return d<0?'crit':(d<=365?'warn':'ok');}
function siOs(s){if(!s.isWin)return null;var b=num(s.build)||num(s.buildAd);if(SILOS[b])return SILOS[b];if(!b){var o=s.os||s.osAd||'';for(var i=0;i<SIOSN.length;i++)if(SIOSN[i][0].test(o))return SILOS[SIOSN[i][1]];}return null;}
function siSql(v){var m=/^(\d+)\.(\d+)/.exec(v||'');if(!m)return null;return SISQL[(m[1]==='10'&&+m[2]>=50)?'10.5':m[1]]||null;}
/* Base builds of each SQL Server version and service pack (no update installed): same list as AD-ServerInventory.ps1 */
var SIBASE={'17':['1000'],'16':['1000'],'15':['2000'],'14':['1000'],'13':['1601','4001','5026','6300'],'12':['2000','4100','5000','6024'],'11':['2100','3000','5058','6020','7001'],'10':['1600','2531','4000','5500','6000','2500']};
function siSqlBase(v){var m=/^(\d+)\.\d+\.(\d+)\./.exec(v||'');return !!(m&&SIBASE[m[1]]&&SIBASE[m[1]].indexOf(m[2])>=0);}
function siContacted(s){return ['ok','unreachable','denied','timeout','error'].indexOf(s.status)>=0;}
/* ---------- build module state ---------- */
var MODS=arr(S.modules),BY={},HTML={};
MODS.forEach(function(m,i){m.no=i+1;BY[m.id]=m;m.f=[];m.x={};
  if(m.status==='ok'&&m.html){try{var h=b64(m.html);HTML[m.id]=h;var d;
    if(m.id==='topo'){d={};['replMatrix','dcList','siteLinks','staleObjects','topo'].forEach(function(v){d[v]=readVar(h,v);});}else d=readVar(h,'D');
    if(d&&ADAPT[m.id]){var r=ADAPT[m.id](d);m.f=r.f;m.x=r.x;m.d=d;m.read=true;}}catch(x){m.readErr=''+x;}}
  m.crit=m.f.filter(function(x){return x.sev==='crit';}).length;m.warn=m.f.filter(function(x){return x.sev==='warn';}).length;m.info=m.f.filter(function(x){return x.sev==='info';}).length;});
function X(id){return (BY[id]&&BY[id].x)||{};}
var C={red:'var(--red)',amb:'var(--amber)',grn:'var(--green)',blu:'var(--blue)',acc:'var(--accent)',teal:'var(--teal)',vio:'var(--accent2)',mut:'var(--surface3)'};
/* ---------- charts (pure SVG) ---------- */
function donut(segs,size,th,center){var r=(size-th)/2,c=2*Math.PI*r,off=0,t=segs.reduce(function(a,s){return a+s[1];},0);
  var arcs=t?segs.map(function(s){var len=c*s[1]/t,a=s[1]?'<circle cx="'+size/2+'" cy="'+size/2+'" r="'+r+'" fill="none" stroke="'+s[2]+'" stroke-width="'+th+'" stroke-dasharray="'+Math.max(0,len-2)+' '+(c-len+2)+'" stroke-dashoffset="'+(-off)+'" transform="rotate(-90 '+size/2+' '+size/2+')"/>':'';off+=len;return a;}).join(''):'';
  return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 '+size+' '+size+'" style="flex-shrink:0"><circle cx="'+size/2+'" cy="'+size/2+'" r="'+r+'" fill="none" stroke="var(--surface2)" stroke-width="'+th+'"/>'+arcs+(center?'<text x="50%" y="48%" text-anchor="middle" font-size="'+(size/5.6)+'" font-weight="800" fill="var(--text)">'+center[0]+'</text><text x="50%" y="64%" text-anchor="middle" font-size="'+(size/12)+'" fill="var(--muted)">'+center[1]+'</text>':'')+'</svg>';}
function legend(segs){return '<div class="lg">'+segs.map(function(s){return '<div><span class="sw" style="background:'+s[2]+'"></span>'+e(s[0])+'<b>'+fmt(s[1])+'</b></div>';}).join('')+'</div>';}
function area(series,labels,w,h){var all=[];series.forEach(function(s){all=all.concat(s[1]);});var mx=Math.max.apply(null,all.concat([1]))*1.15,n=labels.length,px=function(i){return n<2?w/2:32+i*(w-64)/(n-1);},py=function(v){return h-22-(v/mx)*(h-34);};
  var g='';for(var k=0;k<4;k++){var y=12+k*(h-34)/3;g+='<line x1="30" x2="'+(w-10)+'" y1="'+y+'" y2="'+y+'" stroke="var(--border)"/>';}
  var body=series.map(function(s,si){var pts=s[1].map(function(v,i){return px(i)+','+py(v);}).join(' ');var id='ga'+si;
   return '<defs><linearGradient id="'+id+'" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="'+s[2]+'" stop-opacity=".35"/><stop offset="1" stop-color="'+s[2]+'" stop-opacity="0"/></linearGradient></defs><polygon points="'+px(0)+','+(h-22)+' '+pts+' '+px(n-1)+','+(h-22)+'" fill="url(#'+id+')"/><polyline points="'+pts+'" fill="none" stroke="'+s[2]+'" stroke-width="2.5" stroke-linejoin="round"/>'+s[1].map(function(v,i){return '<circle cx="'+px(i)+'" cy="'+py(v)+'" r="3" fill="var(--surface)" stroke="'+s[2]+'" stroke-width="2"><title>'+labels[i]+': '+v+'</title></circle>';}).join('');}).join('');
  return '<svg viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none" style="height:'+h+'px">'+g+body+labels.map(function(l,i){return '<text x="'+px(i)+'" y="'+(h-4)+'" text-anchor="middle" font-size="10.5" fill="var(--muted)">'+l+'</text>';}).join('')+'</svg>';}
function ring(v,max,col,size){var p=max?Math.round(v*100/max):0;return donut([['v',v,col],['r',Math.max(0,max-v),'transparent']],size||86,10,[p+'%','']);}
function na(t){return '<div class="na">'+e(t||'Module did not run or its data could not be read.')+'</div>';}
function open(id,t){return BY[id]?'<a data-v="'+id+'">'+(t||'Open')+' &rarr;</a>':'';}
/* ---------- dashboard (Microsoft 365 admin center style) ---------- */
var IC={
 dc:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/></svg>',
 user:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.6-3.6 3.2-5.6 6.5-5.6s5.9 2 6.5 5.6"/><path d="M16 4.7a3.4 3.4 0 0 1 0 6.6M18 14.6c1.9.6 3.2 2.3 3.5 5.4"/></svg>',
 pc:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="11" rx="1.6"/><path d="M2 19h20M9 19l.6-1.6h4.8L15 19"/></svg>',
 gpo:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3.5h6l.6 1.8H18A1.5 1.5 0 0 1 19.5 6.8v12.7A1.5 1.5 0 0 1 18 21H6a1.5 1.5 0 0 1-1.5-1.5V6.8A1.5 1.5 0 0 1 6 5.3h2.4z"/><path d="M8.5 11.5h7M8.5 15h4.5"/><path d="m14.6 16.6 1.4 1.4 2.6-2.8"/></svg>',
 pie:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M8 1.5A6.5 6.5 0 1 0 14.5 8H8z"/><path d="M10 1.8A6.5 6.5 0 0 1 14.2 6H10z"/></svg>',
 bars:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M2 14.5h12M4 12V8M7 12V4M10 12V6.5M13 12V9.5"/></svg>',
 heart:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M8 14S1.5 10.2 1.5 5.6A3.1 3.1 0 0 1 8 4a3.1 3.1 0 0 1 6.5 1.6C14.5 10.2 8 14 8 14z"/><path d="M3.5 8h2l1-1.8 1.6 3.4 1-1.6h3"/></svg>',
 key:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><circle cx="5" cy="10.5" r="3"/><path d="m7.2 8.3 6.3-6.3M11.5 4l1.5 1.5M10 5.5l1.2 1.2"/></svg>',
 grp:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><circle cx="5.5" cy="5" r="2.3"/><circle cx="11" cy="5.5" r="1.9"/><path d="M1.5 13.5c.4-2.4 2-3.7 4-3.7s3.6 1.3 4 3.7M10 9.8c2.1-.2 3.9.9 4.4 3.2"/></svg>',
 lock:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><rect x="3" y="7" width="10" height="7.5" rx="1.3"/><path d="M5.3 7V5a2.7 2.7 0 0 1 5.4 0v2"/></svg>',
 pulse:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M1.5 8.5h3l1.8-4.5 3.2 9 1.8-4.5h3.2"/></svg>',
 up:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><circle cx="8" cy="8" r="6.5"/><path d="M8 11.5v-7M5.2 7.2 8 4.4l2.8 2.8"/></svg>',
 flag:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M3 15V1.8M3 2.2h9.2l-1.7 3.1 1.7 3.1H3"/></svg>',
 clock:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><circle cx="8" cy="8" r="6.5"/><path d="M8 4.2V8l2.6 1.6"/></svg>',
 dns:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><circle cx="8" cy="8" r="6.5"/><path d="M1.5 8h13M8 1.5c2 2.2 2 10.8 0 13M8 1.5c-2 2.2-2 10.8 0 13"/></svg>',
 srv:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><rect x="2" y="1.8" width="12" height="5" rx="1"/><rect x="2" y="9.2" width="12" height="5" rx="1"/><path d="M4.5 4.3h.01M4.5 11.7h.01M7 4.3h4.5M7 11.7h4.5"/></svg>',
 home:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M2 7.2 8 2l6 5.2V14a.5.5 0 0 1-.5.5H10V10H6v4.5H2.5A.5.5 0 0 1 2 14z"/></svg>',
 arrow:'<svg viewBox="0 0 16 16" fill="currentColor"><path fill-rule="evenodd" d="M1 8a.5.5 0 0 1 .5-.5h11.793l-3.147-3.146a.5.5 0 0 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708-.708L13.293 8.5H1.5A.5.5 0 0 1 1 8"/></svg>'
};
var NAVIC={ov:'pie',dc:'dc',topo:'pulse',trust:'key',acct:'lock',gou:'grp',gpo:'gpo',dns:'dns',auth:'up',srv:'srv'};
var B={blue:'#0f6cbd',sky:'#2b88d8',purple:'#8764b8',teal:'#038387',grey:'#c8c6c4',red:'#d13438',amber:'#f7a700',green:'#107c10',info:'#0f6cbd'};
function tile(icon,bg,fg){return '<span class="mtile" style="background:'+bg+';color:'+fg+'">'+IC[icon]+'</span>';}
function mlink(id,t){return BY[id]?'<a class="mlink" data-v="'+id+'">'+e(t)+' '+IC.arrow+'</a>':'';}
function mhead(icon,title,col){return '<div class="mhd"><span class="mhi" style="color:'+(col||B.blue)+'">'+IC[icon]+'</span>'+e(title)+'</div>';}
function rowsTable(rows){return '<div class="mrows">'+rows.map(function(r){return '<div class="mrow"><span>'+e(r[0])+'</span><b'+(r[2]?' style="color:'+r[2]+'"':'')+'>'+r[1]+'</b><small>'+(r[3]||'')+'</small></div>';}).join('')+'</div>';}
function legTable(rows,total){return '<div class="mleg">'+rows.map(function(r){return '<div><span class="mdot" style="background:'+r[2]+'"></span><span>'+e(r[0])+'</span><b>'+fmt(r[1])+'</b><small>'+(total?Math.round(num(r[1])*100/total)+'%':'')+'</small></div>';}).join('')+(total!=null?'<div class="mtot"><span></span><span>Total</span><b>'+fmt(total)+'</b><small>100%</small></div>':'')+'</div>';}
function vbars(items,h){var w=400,mx=Math.max.apply(null,items.map(function(x){return num(x.a)+num(x.b);}).concat([1]));var step=Math.pow(10,Math.floor(Math.log10(mx)));var top=Math.ceil(mx/step)*step||1;
  var pl=30,pb=46,pt=16,ch=h-pb-pt,bw=Math.min(34,(w-pl-10)/items.length*0.55),gap=(w-pl-10)/items.length;var g='';
  for(var k=0;k<=4;k++){var v=top*k/4,y=pt+ch-ch*k/4;g+='<line x1="'+pl+'" x2="'+(w-6)+'" y1="'+y+'" y2="'+y+'" stroke="var(--grid)"/><text x="'+(pl-6)+'" y="'+(y+3.5)+'" text-anchor="end" font-size="10" fill="var(--muted)">'+(Math.round(v*10)/10)+'</text>';}
  var bars=items.map(function(x,i){var cx=pl+gap*i+gap/2,ha=ch*num(x.a)/top,hb=ch*num(x.b)/top,y0=pt+ch;
    return '<g data-v="'+x.id+'" style="cursor:pointer"><title>'+e(x.title)+': '+x.a+' critical, '+x.b+' warnings</title>'+(hb?'<rect x="'+(cx-bw/2)+'" y="'+(y0-ha-hb)+'" width="'+bw+'" height="'+hb+'" rx="2" fill="'+B.amber+'"/>':'')+(ha?'<rect x="'+(cx-bw/2)+'" y="'+(y0-ha)+'" width="'+bw+'" height="'+ha+'" rx="2" fill="'+B.red+'"/>':'')+
      '<text x="'+cx+'" y="'+(y0-ha-hb-5)+'" text-anchor="middle" font-size="10.5" font-weight="700" fill="var(--text)">'+(num(x.a)+num(x.b)||'')+'</text><text x="'+cx+'" y="'+(pt+ch+12)+'" text-anchor="end" font-size="10.5" fill="var(--muted)" transform="rotate(-35 '+cx+' '+(pt+ch+12)+')">'+e(x.short)+'</text></g>';}).join('');
  return '<svg viewBox="0 0 '+w+' '+h+'" style="width:100%;height:'+h+'px">'+g+bars+'</svg>';}
var SHORT={ov:'Overview',dc:'DCs',topo:'Topology',trust:'Trusts',acct:'Accounts',gou:'Groups',gpo:'GPO',dns:'DNS',auth:'DC posture',srv:'Servers'};
(function(){
  var ran=MODS.filter(function(m){return m.status==='ok';}),TC=0,TW=0,TI=0;MODS.forEach(function(m){TC+=m.crit;TW+=m.warn;TI+=m.info;});
  var withCrit=MODS.filter(function(m){return m.crit;}).length,TT=TC+TW+TI;
  var ov=X('ov'),dc=X('dc'),ac=X('acct'),gp=X('gpo'),A=ov.acc||{},L=ac.laps||{},G=X('gou').s||{},Cn=ac.counts||{};
  var h='<div class="mpage"><div class="mkick">Active Directory assessment</div><h1 class="mh1">AD Audit Suite Dashboard</h1><div class="msub">Forest <b>'+e(S.forest)+'</b> &mdash; everything the '+ran.length+' module'+(ran.length===1?'':'s')+' found, all in one place. Generated '+e(S.generated)+' on '+e(S.host)+(/^rebuilt/.test(S.duration)?' ('+e(S.duration)+')':' in '+e(S.duration))+'.</div>';
  var vs=TC?'crit':(TW?'warn':'ok');
  h+='<div class="mstatus '+vs+'"><span class="msi">'+IC[TC?'flag':'heart']+'</span><div class="mst"><b>'+(TC?'Action required':(TW?'Mostly healthy':'Healthy'))+'</b><span>'+(TC?TC+' critical finding'+(TC===1?'':'s')+' across '+withCrit+' of '+MODS.length+' modules, plus '+TW+' warning'+(TW===1?'':'s')+' and '+TI+' recommendation'+(TI===1?'':'s')+'.':(TW?TW+' warning'+(TW===1?'':'s')+' to review, no critical findings.':'No critical findings or warnings.'))+'</span></div><button class="mbtn" onclick="exportPdf()">Export findings (PDF)</button></div>';
  /* KPI cards */
  function kpi(icon,bg,fg,title,big,bigL,sec,link){return '<div class="mcard mk"><div class="mkh">'+tile(icon,bg,fg)+'<span>'+title+'</span></div><div class="mkb"><div class="mkm"><b>'+big+'</b><span>'+bigL+'</span></div>'+(sec.length?'<div class="mks">'+sec.map(function(s){return '<div><b'+(s[2]?' style="color:'+s[2]+'"':'')+'>'+s[0]+'</b><span>'+s[1]+'</span></div>';}).join('')+'</div>':'')+'</div>'+link+'</div>';}
  h+='<div class="mgrid g4">'+
    kpi('dc','#e5f1fb',B.blue,'Domain controllers',dc.total!=null?fmt(dc.total):'&ndash;','Domain controllers',dc.total!=null?[[fmt(dc.offline),'Unreachable',dc.offline?B.red:''],[fmt(X('topo').sites||num((ov.sites))),'Sites']]:[],mlink('dc','View DC inventory'))+
    kpi('user','#e5f1fb',B.blue,'Users',ov.users!=null?fmt(ov.users):'&ndash;','User accounts',ov.acc?[[fmt(A.stale),'Stale',num(A.stale)?B.amber:''],[fmt(A.disabled),'Disabled']]:[],mlink('ov','View overview'))+
    kpi('pc','#f1ecf9',B.purple,'Computers',ov.computers!=null?fmt(ov.computers):'&ndash;','Computers',(L.mode==='None'||(L.total!=null&&!num(L.total)))?[['Not deployed','LAPS',B.red]]:(L.total!=null?[[(L.pct!=null?L.pct:Math.round(num(L.covered)*100/(num(L.total)||1)))+'%','LAPS coverage'],[fmt(L.missing),'Without LAPS',num(L.missing)?B.amber:'']]:[]),mlink('acct','View account security'))+
    kpi('gpo','#def1f1',B.teal,'Group Policy',gp.total!=null?fmt(gp.total):(ov.gpos?fmt(ov.gpos):'&ndash;'),'Group Policy objects',gp.total!=null?[[fmt(gp.conflicts),'Conflicts',num(gp.conflicts)?B.amber:''],[fmt(gp.unlinked),'Unlinked']]:[],mlink('gpo','View Group Policy'))+'</div>';
  /* findings by severity / by module / DC health */
  var dcs=arr(dc.dcs),tp=X('topo'),au=X('auth'),authBy={};arr(au.dcs).forEach(function(d){authBy[(''+d.short).toUpperCase()]=d;});
  function lvl(list){var w='ok';list.forEach(function(s){if(R[s]>R[w])w=s;});return w;}
  var pill={ok:['OK','#dff6dd','#107c10'],warn:['Warning','#fff4ce','#8a5a00'],crit:['Critical','#fde7e9','#a4262c'],na:['n/a','#f3f2f1','#605e5c']};
  function pl2(s){var p=pill[s];return '<span class="mpill" style="background:'+p[1]+';color:'+p[2]+'">'+p[0]+'</span>';}
  var dcRows=dcs.map(function(d){var sn=(''+(d.shortName||d.name)).toUpperCase(),a=authBy[sn];
    var repl=tp.byDst?(tp.byDst[sn]||'na'):'na',time=a&&a.time&&(a.time.type||a.time.source)?lvl(arr(a.time.findings).map(function(x){return x.sev==='info'?'ok':x.sev;})):'na',auth=a&&a.regRead?lvl(arr(a.settings).map(function(x){return x.sev==='info'?'ok':x.sev;})):'na';
    return '<tr><td><b>'+e(sn)+'</b>'+(a&&a.isPdc?' <span class="mtag">PDC</span>':'')+'</td><td>'+e(d.site||'')+'</td><td>'+e((d.os||'').replace('Windows Server ','WS ').replace(/ (Standard|Datacenter).*/,''))+'</td><td>'+(d.online===false?pl2('crit').replace('Critical','Unreachable'):pl2('ok').replace('OK','Reachable'))+'</td><td>'+pl2(repl)+'</td><td>'+pl2(time)+'</td><td>'+pl2(auth)+'</td></tr>';}).join('');
  var act=Math.max(0,num(A.enabled)-num(A.stale));
  var cSev='<div class="mcard">'+mhead('pie','Findings by severity')+'<div class="mdn">'+donut([['Critical',TC,B.red],['Warnings',TW,B.amber],['Recommendations',TI,B.info]],136,22,[TT?Math.round(TC*100/TT)+'%':'0%','critical'])+legTable([['Critical',TC,B.red],['Warnings',TW,B.amber],['Recommendations',TI,B.info]],TT)+'</div><a class="mlink" onclick="document.getElementById(\'mprio\').scrollIntoView({behavior:\'smooth\'})">View top priorities '+IC.arrow+'</a></div>';
  var cMod='<div class="mcard">'+mhead('bars','Findings by module')+vbars(MODS.map(function(m){return {id:m.id,title:m.title,short:SHORT[m.id]||m.title,a:m.status==='ok'?m.crit:0,b:m.status==='ok'?m.warn:0};}),250)+'<div class="mnote">'+IC.flag+'<span><b style="color:'+B.red+'">Critical</b> and <b style="color:#8a5a00">warnings</b> per module. Click a bar to open the module.</span></div></div>';
  var cUsr='<div class="mcard">'+mhead('user','User accounts')+(ov.acc?'<div class="mdn">'+donut([['Active',act,B.blue],['Stale',num(A.stale),B.amber],['Disabled',num(A.disabled),B.grey]],136,22,[fmt(num(A.enabled)+num(A.disabled)),'users'])+legTable([['Active',act,B.blue],['Stale',num(A.stale),B.amber],['Disabled',num(A.disabled),B.grey]],num(A.enabled)+num(A.disabled))+'</div>':na())+mlink('ov','View all users')+'</div>';
  var cDc='<div class="mcard">'+mhead('heart','Domain controller health',B.teal)+(dcs.length?'<div class="mtbl"><table><tr><th>Domain controller</th><th>Site</th><th>Operating system</th><th>Online</th><th>Replication</th><th>Time</th><th>Protocols</th></tr>'+dcRows+'</table></div>':na('DC inventory did not run.'))+mlink('dc','View domain controllers')+'</div>';
  var ev=au.ev||{},daily=arr(ev.daily),W=au.w25||{};
  var cW25='<div class="mcard">'+mhead('up','Windows Server 2025 readiness',B.purple)+(W.total?'<div class="mdn">'+donut([['Blockers',W.crit,B.red],['Risks',W.warn,B.amber],['Passed',W.pass,B.green]],136,22,[W.pass+'/'+W.total,'passed'])+legTable([['Blockers',W.crit,B.red],['Risks',W.warn,B.amber],['Passed',W.pass,B.green]],null)+'</div><div class="mnote '+(W.crit?'bad':'good')+'">'+IC[W.crit?'flag':'heart']+'<span>'+(W.crit?'Not ready: resolve '+W.crit+' blocker'+(W.crit===1?'':'s')+' first.':'No blockers found.')+'</span></div>':na())+mlink('auth','View readiness')+'</div>';
  var cPriv='<div class="mcard">'+mhead('lock','Privileged & risky accounts',B.purple)+(ac.counts?rowsTable([['Privileged accounts',fmt(Cn.privileged)],['Service (SPN) accounts',fmt(Cn.spn)],['Never-expiring passwords',fmt(Cn.neverExpires),num(Cn.neverExpires)?'#8a5a00':''],['Unconstrained delegation',fmt(Cn.deleg),num(Cn.deleg)?B.red:''],['krbtgt password age',fmt(ac.krbtgt)+' days',ac.krbtgt>180?B.red:'',ac.krbtgt>180?'over 180 days':''],(L.mode==='None'||(L.total!=null&&!num(L.total)))?['LAPS','Not deployed',B.red,'']:['LAPS coverage',(L.pct!=null?L.pct+'%':'&ndash;'),'',fmt(L.missing)+' without']]):na())+mlink('acct','View account security')+'</div>';
  var cGrp='<div class="mcard">'+mhead('grp','Groups & directory sync',B.teal)+(G.security!=null?rowsTable([['Security groups',fmt(G.security)],['Circular nesting',fmt(G.circular),num(G.circular)?B.red:''],['Deeply nested',fmt(G.deep),num(G.deep)?'#8a5a00':''],['Empty groups',fmt(G.empty)],['Empty OUs',fmt(G.emptyOus)],['Directory sync errors',fmt(X('gou').sync),num(X('gou').sync)?'#8a5a00':'']]):na())+mlink('gou','View groups & OUs')+'</div>';
  var gx=X('gpo'),dx=X('dns'),tx=X('trust'),bk=au.backup||{},lastBk=null;arr(bk.partitions).forEach(function(p){if(p.days!=null&&(lastBk==null||p.days>lastBk))lastBk=p.days;});
  var cPol='<div class="mcard">'+mhead('dns','Policy, DNS & recovery',B.teal)+rowsTable([['Unlinked GPOs',gx.unlinked!=null?fmt(gx.unlinked):'&ndash;'],['Conflicting GPO settings',gx.conflicts!=null?fmt(gx.conflicts):'&ndash;',num(gx.conflicts)?'#8a5a00':''],['DNS critical issues',dx.crit!=null?fmt(dx.crit):'&ndash;',num(dx.crit)?B.red:''],['DNS zones',dx.zones!=null?dx.zones:'&ndash;'],['Trusts',tx.total!=null?tx.total:'&ndash;'],['Oldest partition backup',lastBk!=null?lastBk+' days':'&ndash;',lastBk>7?'#8a5a00':''],['AD Recycle Bin',bk.recycleBin==null?'&ndash;':(bk.recycleBinEnabled?'Enabled':'Not enabled'),bk.recycleBin&&!bk.recycleBinEnabled?'#8a5a00':'']])+mlink('dns','View DNS health')+'</div>';
  var evHtml=!ev.collected?na('Security events were not collected.'):(daily.length?area([['Failed logons',daily.map(function(d){return num(d.f);}),B.red],['Kerberos failures',daily.map(function(d){return num(d.k);}),B.blue]],daily.map(function(d){return (''+d.day).substring(5);}),1100,220)+
      '<div class="mlegh"><span><span class="mdot" style="background:'+B.red+'"></span>Failed logons <b>'+fmt(ev.failTotal)+'</b></span><span><span class="mdot" style="background:'+B.blue+'"></span>Kerberos pre-auth failures <b>'+fmt(ev.kerbTotal)+'</b></span><span><span class="mdot" style="background:'+B.grey+'"></span>Locked-out accounts <b>'+arr(ev.lockouts).length+'</b></span></div>':rowsTable([['Failed logons',fmt(ev.failTotal)],['Kerberos failures',fmt(ev.kerbTotal)],['Locked-out accounts',arr(ev.lockouts).length]]));
  var cEv='<div class="mcard">'+mhead('pulse','Security events'+(ev.days?' \u2014 last '+ev.days+' days':''))+evHtml+mlink('auth','View security events')+'</div>';
  var pri=[];MODS.forEach(function(m){m.f.forEach(function(f){if(f.sev!=='info')pri.push([f,m]);});});pri.sort(function(a,b){return R[b[0].sev]-R[a[0].sev];});
  var cPri='<div class="mcard" id="mprio">'+mhead('flag','Top priorities across all modules',B.red)+(pri.length?'<div class="mprio">'+pri.slice(0,10).map(function(p){return '<div class="mp" data-v="'+p[1].id+'"><span class="mdot" style="background:'+(p[0].sev==='crit'?B.red:B.amber)+'"></span><span class="t">'+e(p[0].title)+'</span><span class="mtag">'+e(p[1].title)+'</span>'+IC.arrow+'</div>';}).join('')+'</div>':na('No critical findings or warnings.'))+'</div>';
  var sx=X('srv'),cSrv='';if(BY.srv){var spd=sx.pd||60;
    cSrv='<div class="mcard">'+mhead('dc','Servers',B.blue)+(sx.total!=null?'<div class="msrv"><div class="mdn">'+donut([['Supported',sx.ok,B.green],['Ends within a year',sx.soon,B.amber],['Out of support',sx.eos,B.red]],136,22,[fmt(sx.win),'Windows'])+legTable([['Supported',sx.ok,B.green],['Ends within a year',sx.soon,B.amber],['Out of support',sx.eos,B.red]],sx.win)+'</div>'+
      rowsTable([['Servers in AD',fmt(sx.total)],['Read / contacted',fmt(sx.read)+' / '+fmt(sx.contacted),sx.read<sx.contacted?'#8a5a00':'',sx.read<sx.contacted?fmt(sx.contacted-sx.read)+' not read':''],['SQL Server instances',fmt(sx.sql),'',sx.sqlEos?'<span style="color:'+B.red+'">'+fmt(sx.sqlEos)+' out of support</span>':''],['Failover clusters',fmt(sx.clusters)],['No update in '+spd+'+ days',fmt(sx.notUpd),sx.notUpd?'#8a5a00':'','of the servers read'],['Not restarted in '+spd+'+ days',fmt(sx.notRst),sx.notRst?'#8a5a00':'','of the servers read']])+'</div>'
      :na('Server inventory did not run.'))+mlink('srv','View server inventory')+'</div>';}
  h+='<div class="mgrid g3">'+cSev+cMod+cUsr+'</div><div class="mgrid g21">'+cDc+cW25+'</div><div class="mgrid g3">'+cPriv+cGrp+cPol+'</div>'+(cSrv?'<div class="mgrid g1">'+cSrv+'</div>':'')+'<div class="mgrid g1">'+cEv+'</div><div class="mgrid g1">'+cPri+'</div>';
  /* run information */
  h+='<div class="mcard">'+mhead('clock','Run information')+'<div class="mtbl"><table><tr><th>#</th><th>Module</th><th>Script</th><th>Duration</th><th>Result</th></tr>'+MODS.map(function(m){
     return '<tr><td>'+m.no+'</td><td><a class="mlink in" data-v="'+m.id+'">'+e(m.title)+'</a></td><td>'+e(m.script)+'</td><td>'+e(m.duration||'')+'</td><td>'+(m.status==='ok'?'<span class="mpill" style="background:#dff6dd;color:#107c10">Completed</span>'+(m.read?'':' <small>data not read for the dashboard</small>'):(m.status==='skipped'?'<span class="mpill" style="background:#f3f2f1;color:#605e5c">Skipped</span> <small>'+e(m.error||'')+'</small>':'<span class="mpill" style="background:#fde7e9;color:#a4262c">Failed</span> <small>'+e(m.error||'')+'</small>'))+'</td></tr>';}).join('')+'</table></div></div></div>';
  document.getElementById('dash').innerHTML=h;
  document.getElementById('smeta').innerHTML='<b>'+e(S.forest)+'</b><br>'+e(S.generated)+' &middot; '+ran.length+'/'+MODS.length+' modules<br>'+e(S.duration);
  document.title='AD Audit Suite - '+S.forest;
})();
/* ---------- search (top bar): findings and modules ---------- */
(function(){var q=document.getElementById('q'),box=document.getElementById('qres');if(!q)return;
  var idx=[];MODS.forEach(function(m){idx.push({t:m.title,s:'Module',v:m.id,sev:''});m.f.forEach(function(f){idx.push({t:f.title,s:m.title,v:m.id,sev:f.sev});});});
  function render(){var v=q.value.trim().toLowerCase();if(!v){box.style.display='none';return;}
    var hits=idx.filter(function(x){return (x.t+' '+x.s).toLowerCase().indexOf(v)>=0;}).slice(0,12);
    box.innerHTML=hits.length?hits.map(function(x){return '<div class="qr" data-v="'+x.v+'"><span class="mdot" style="background:'+(x.sev==='crit'?B.red:(x.sev==='warn'?B.amber:(x.sev==='info'?B.info:'#8a8886')))+'"></span><span class="t">'+e(x.t)+'</span><small>'+e(x.s)+'</small></div>';}).join(''):'<div class="qr none">No matches</div>';
    box.style.display='block';}
  q.addEventListener('input',render);q.addEventListener('focus',render);
  q.addEventListener('keydown',function(ev){if(ev.key==='Escape'){q.value='';render();q.blur();}if(ev.key==='Enter'){var f=box.querySelector('.qr[data-v]');if(f){show(f.getAttribute('data-v'));q.blur();box.style.display='none';}}});
  document.addEventListener('click',function(ev){if(!ev.target.closest('.tb-search'))box.style.display='none';else if(ev.target.closest('.qr[data-v]')){box.style.display='none';q.blur();}});
})();

/* ---------- navigation: one section at a time ---------- */
(function(){var groups={},order=[];MODS.forEach(function(m){if(!groups[m.part]){groups[m.part]=[];order.push(m.part);}groups[m.part].push(m);});
  document.getElementById('toc').innerHTML='<a data-v="dash" class="on"><span class="nic">'+IC.home+'</span>Dashboard</a>'+order.map(function(g){return '<div class="g">'+e(g)+'</div>'+groups[g].map(function(m){
    var n=m.status!=='ok'?'<span class="n fail">'+(m.status==='skipped'?'skip':'!')+'</span>':(m.crit?'<span class="n crit">'+m.crit+'</span>':(m.warn?'<span class="n warn">'+m.warn+'</span>':'<span class="n ok">&#10003;</span>'));
    return '<a data-v="'+m.id+'"><span class="nic">'+IC[NAVIC[m.id]||'flag']+'</span>'+e(m.title)+n+'</a>';}).join('');}).join('');})();
var frames={};
function theme(){return document.documentElement.getAttribute('data-theme');}
function show(v){document.querySelectorAll('.toc a').forEach(function(a){a.classList.toggle('on',a.getAttribute('data-v')===v);});
  if(v==='dash'){document.getElementById('v-dash').classList.add('on');document.getElementById('v-rep').classList.remove('on');window.scrollTo(0,0);return;}
  var m=BY[v];if(!m)return;document.getElementById('v-dash').classList.remove('on');document.getElementById('v-rep').classList.add('on');
  Object.keys(frames).forEach(function(k){frames[k].style.display=k===v?'block':'none';});
  var ph=document.getElementById('ph');if(ph)ph.parentNode.removeChild(ph);
  if(HTML[v]){if(!frames[v]){var f=document.createElement('iframe');f.className='rep';document.getElementById('repbox').appendChild(f);
      f.onload=function(){try{var d=f.contentDocument;d.documentElement.setAttribute('data-theme',theme());d.addEventListener('keydown',function(ev){if((ev.ctrlKey||ev.metaKey)&&(ev.key==='b'||ev.key==='B')){ev.preventDefault();toggleSide();}});d.addEventListener('click',function(ev){var a=ev.target&&ev.target.closest?ev.target.closest('a[href]'):null;if(!a)return;var h=a.getAttribute('href')||'';if(h.charAt(0)==='#'){ev.preventDefault();var id=h.slice(1);try{id=decodeURIComponent(id);}catch(e2){}var t=id?(d.getElementById(id)||d.getElementsByName(id)[0]):null;if(t)t.scrollIntoView({behavior:'smooth',block:'start'});else f.contentWindow.scrollTo({top:0,behavior:'smooth'});}else if(/^https?:/i.test(h)&&!a.target){a.target='_blank';a.rel='noopener';}});}catch(x){}};
      f.srcdoc=HTML[v];frames[v]=f;}frames[v].style.display='block';}
  else{document.getElementById('repbox').insertAdjacentHTML('beforeend','<div class="ph" id="ph"><b>'+e(m.title)+' &mdash; '+(m.status==='skipped'?'skipped':'did not complete')+'</b>'+e(m.error||'')+(m.log?'<pre>'+e(m.log)+'</pre>':'')+'</div>');}
  window.scrollTo(0,0);}
/* ---------- PDF building blocks ---------- */
function pfig(items){return '<div class="pfig">'+items.filter(function(x){return x&&x[1]!==undefined&&x[1]!==null&&x[1]!=='';}).map(function(x){return '<div><b class="'+(x[2]||'')+'">'+x[1]+'</b><span>'+e(x[0])+'</span></div>';}).join('')+'</div>';}
function pdonut(title,segs,center){return '<div class="pch"><div class="pct">'+e(title)+'</div><div class="dn">'+donut(segs,104,15,center)+'<div class="lg">'+segs.map(function(x){return '<div><span class="sw" style="background:'+x[2]+'"></span>'+e(x[0])+'<b>'+fmt(x[1])+'</b></div>';}).join('')+'</div></div></div>';}
function pbars(title,items,max){max=max||Math.max.apply(null,items.map(function(x){return num(x[1]);}).concat([1]));return '<div class="pch"><div class="pct">'+e(title)+'</div><div class="pb">'+items.map(function(x){return '<div class="pbi"><span>'+e(x[0])+'</span><div class="pbt"><i style="width:'+Math.min(100,num(x[1])*100/max)+'%;background:'+(x[2]||'var(--accent)')+'"></i></div><b>'+fmt(x[1])+'</b></div>';}).join('')+'</div></div>';}
function pcr(a,b){return b?'<div class="pcr">'+a+b+'</div>':'<div class="pcr one">'+a+'</div>';}
function ptab(title,cols,rows,cap,raw){cap=cap||40;if(!rows.length)return '';var shown=rows.slice(0,cap);
  return '<div class="'+(shown.length<=12?'tblk':'')+'"><h3 class="st">'+e(title)+'</h3>'+(DESC[title]?'<p class="dsc">'+DESC[title]+'</p>':'')+'<table><thead><tr>'+cols.map(function(c){return '<th>'+e(c)+'</th>';}).join('')+'</tr></thead><tbody>'+shown.map(function(r){return '<tr>'+r.map(function(v,i){return '<td'+(i===0?' class="ft"':'')+'>'+(raw&&raw.indexOf(i)>=0?v:e(v))+'</td>';}).join('')+'</tr>';}).join('')+'</tbody></table>'+(rows.length>cap?'<div class="more">Showing '+cap+' of '+fmt(rows.length)+' rows; all rows are in the interactive report.</div>':'')+'</div>';}
function sv(s,t){var m={crit:'crit',high:'crit',warn:'warn',medium:'warn',info:'info',low:'info',ok:'ok'};return '<span class="sv '+(m[s]||'fail')+'">'+e(t||SVW[m[s]]||s||'')+'</span>';}
function yn(v){return v===true?'Yes':(v===false?'No':'');}
function lst(a){a=a.filter(Boolean);if(a.length<2)return a.join('');return a.slice(0,-1).join(', ')+' and '+a[a.length-1];}
function pl(n,w,ws){n=num(n);return fmt(n)+' '+(n===1?w:(ws||w+'s'));}
function q(t){return '&ldquo;'+e(t)+'&rdquo;';}
var ABOUT={
 ov:'This area describes the forest itself: its functional levels, schema, operations master roles and the size of the directory. It gives the context for every other part of this report and shows how much unused or unmanaged content the directory carries.',
 dc:'Domain controllers hold and serve the directory. Their operating system, reachability and resource headroom decide how reliable authentication is and how exposed the domain is to vulnerabilities in unsupported software.',
 topo:'Active Directory keeps domain controllers consistent through replication between sites. When replication fails, changes such as password resets, new accounts or disabled users do not reach every site, and domain controllers drift apart.',
 trust:'Trusts let users from other domains and forests access resources here. Each trust extends the security boundary, so its direction, SID filtering and authentication scope determine how much an incident in the partner domain could affect this one.',
 acct:'Accounts are the most common entry point in an attack. This area reviews the password policy, privileged and service accounts, delegation settings, stale accounts, LAPS coverage for local administrator passwords and the age of the krbtgt key that signs every Kerberos ticket.',
 gou:'Groups decide who can access what, and OUs decide which policies and delegations apply. Nesting loops and deep chains make effective access hard to understand, and the directory-sync checks show which objects would fail or be altered when synchronised to Entra ID.',
 gpo:'Group Policy configures security settings on every computer and user. This area inventories all GPOs, finds settings that conflict or are never applied, checks AD and SYSVOL consistency and compares key settings with a hardening baseline.',
 dns:'Active Directory depends on DNS to locate domain controllers and services. Misconfigured zones, insecure updates or stale records can break logons and replication, or let an attacker redirect traffic.',
 srv:'Servers run the applications that depend on Active Directory. This area covers every server object in the forest: the operating system and its end of support, SQL Server instances, failover clusters, updates and restarts, and the servers that could not be read from the audit host, with the reason. Figures read from the servers cover the servers that answered; operating system and lifecycle come from AD and cover every server.',
 auth:'This area reviews how domain controllers authenticate clients and how ready the environment is for recovery and for Windows Server 2025: protocol hardening (LDAP, NTLM, SMB, TLS), security events over the collection window, the time hierarchy that Kerberos depends on, backups and the migration prerequisites.'
};
var DESC={
 'Domains':'Each domain with its functional level, operations master roles and object counts.',
 'Forest':'Forest-wide properties and the holders of the forest-level operations master roles.',
 'Domain controllers':'Every domain controller with its site, operating system, address and reachability at the time of the assessment.',
 'Hardware and performance':'Resource figures collected from the reachable domain controllers.',
 'Replication problems':'Replication partnerships that are failing, delayed or could not be read, with the last successful replication and the error reported.',
 'Sites and domain controllers':'The domain controllers placed in each Active Directory site.',
 'Site links':'Links that connect sites, with their cost and replication interval.',
 'Stale and orphaned objects':'Topology objects that no longer match the live environment.',
 'Trusts':'Every trust with its direction, transitivity, SID filtering, selective authentication and assessed risk.',
 'Password and lockout policy':'The default domain password and lockout policy compared with common hardening recommendations.',
 'Accounts of interest':'User and service accounts with at least one risk flag, highest risk first.',
 'Computers of interest':'Computer accounts with at least one risk flag, highest risk first.',
 'Groups needing attention':'Groups caught in a nesting loop, nested deeply, or with an unusually large number of members.',
 'Empty OUs':'Organizational units that contain no objects.',
 'Directory sync errors':'Attribute values that would fail or be changed during synchronisation to Entra ID.',
 'Group Policy objects':'Every GPO with its number of settings, links, status and any issues found.',
 'Conflicting settings':'Settings configured with different values by more than one GPO, and the GPO whose value currently wins. Where a GPO has a WMI filter, it only applies to computers matching the filter, so check whether the GPOs really reach the same computers.',
 'Security baseline':'Key security settings compared with the starter hardening baseline.',
 'Zones':'Every DNS zone with its replication, update, transfer, aging and DNSSEC settings.',
 'Domain controller DNS':'Name resolution tests and DNS client configuration of each domain controller.',
 'Records pointing at removed domain controllers':'DNS records that still reference domain controllers which no longer exist.',
 'Windows Server 2025 readiness checks':'Requirements documented by Microsoft for promoting the first Windows Server 2025 domain controller.',
 'Time sync':'Time source and offset of each domain controller relative to the PDC emulator.',
 'Backups per partition':'Age of the last successful backup of each directory partition.',
 'Account lockouts':'Accounts locked out during the collection window and the computers the failed attempts came from.',
 'Failed logons by source':'Sources of failed logons; a source that tried many different accounts may indicate password spraying.',
 'Privileged group changes':'Membership changes to highly privileged groups during the collection window.',
 'Unsigned or clear-text LDAP clients':'Clients that bind to LDAP without signing or encryption and will fail once LDAP signing is required.'
};
var STORY={
 srv:function(m){var x=m.x;
   return '<p>The forest has <b>'+pl(x.total,'server object')+'</b>. '+pl(x.contacted,'server was','servers were')+' contacted and <b>'+fmt(x.read)+'</b> could be read'+(x.read?' ('+fmt(x.phys)+' physical, '+fmt(x.virt)+' virtual)':'')+'. '+(x.contacted>x.read?'The other '+pl(x.contacted-x.read,'server')+' could not be read from the audit host; the Server Inventory report shows, per subnet, what blocks them and what to open.':'')+'</p>'+
     '<p>'+(x.eos?'<b>'+pl(x.eos,'server runs','servers run')+' a Windows version that is out of support</b> and no longer gets security updates. ':'No server runs a Windows version that is out of support. ')+(x.soon?pl(x.soon,'server reaches','servers reach')+' end of support within a year. ':'')+
     pl(x.sql,'SQL Server instance')+' and '+pl(x.clusters,'failover cluster')+' were found'+(x.sqlEos?', and <b>'+pl(x.sqlEos,'instance is','instances are')+' out of support</b>':'')+'.</p>'+
     ((x.notUpd||x.notRst)?'<p>Among the servers that could be read, '+lst([x.notUpd?pl(x.notUpd,'server has','servers have')+' no update installed in the last '+x.pd+' days':'',x.notRst?pl(x.notRst,'server has','servers have')+' not restarted in that time, so updates installed since are not active':''])+'.</p>':'');},
 ov:function(m){var D=m.d,t=D.totals||{},a=D.accounts||{},fo=D.forest||{},lvl=(''+(fo.forestMode||'')).replace(/Windows|Forest/g,' ').trim(),old=/2003|2008|2012/.test(fo.forestMode);
   return '<p>The forest <b>'+e(fo.forestName||S.forest)+'</b> contains '+pl(fo.domainCount||arr(D.domains).length,'domain')+' across '+pl(fo.siteCount,'site')+' and runs at the <b>Windows Server '+e(lvl)+'</b> functional level'+(old?', which is below the level required by current Windows Server releases':'')+'. The directory holds '+pl(t.users,'user account')+', '+pl(t.computers,'computer')+', '+pl(t.groups,'group')+' and '+pl(t.ous,'organizational unit')+', managed by '+pl(t.gpos,'Group Policy object')+'.</p>'+
     '<p>Of the '+fmt(a.enabled)+' enabled user accounts, <b>'+fmt(a.stale)+'</b> have not signed in for more than '+fmt(D.staleDays||180)+' days and '+fmt(a.neverLoggedOn)+' have never signed in. '+pl(a.pwdNeverExp,'account has','accounts have')+' a password that never expires. Unused accounts are a common way into a domain, because nobody notices when they are misused.</p>';},
 dc:function(m){var D=m.d,dcs=arr(D.dcs),os={};dcs.forEach(function(d){var k=(d.os||'').replace(/ (Standard|Datacenter).*$/,'');os[k]=(os[k]||0)+1;});var top=Object.keys(os).sort(function(a,b){return os[b]-os[a];})[0];
   var uns=dcs.filter(function(d){return d.isSupportedOS===false;}).map(function(d){return d.shortName;});var off=dcs.filter(function(d){return !d.online;}).map(function(d){return d.shortName;});
   return '<p>The assessment found <b>'+pl(D.totalDCs,'domain controller')+'</b> in '+pl(D.siteCount,'site')+'. The most common operating system is '+e(top||'unknown')+'. '+(off.length?pl(off.length,'domain controller')+' ('+e(lst(off))+') could not be reached, so '+(off.length===1?'its':'their')+' configuration could only be partly assessed.':'All domain controllers responded.')+'</p>'+
     (uns.length?'<p><b>'+e(lst(uns))+'</b> '+(uns.length===1?'runs':'run')+' an operating system that no longer receives security updates. Besides the direct exposure, an unsupported domain controller prevents the functional level from being raised, which in turn blocks newer security features and Windows Server 2025.</p>':'<p>Every domain controller runs a supported operating system.</p>');},
 topo:function(m){var D=m.d,mx=arr(D.replMatrix),c=function(s){return mx.filter(function(r){return r.state===s;}).length;},f=mx.filter(function(r){return r.state==='fail';}),pairs={};f.forEach(function(r){pairs[r.src+' to '+r.dst]=r.errorText;});var pk=Object.keys(pairs),so=arr(D.staleObjects);
   return '<p>'+pl(mx.length,'replication partnership')+' were checked across '+pl(m.x.sites,'site')+' and '+pl(arr(D.siteLinks).length,'site link')+'. '+(c('fail')?'<b>'+pl(c('fail'),'partnership is','partnerships are')+' failing</b>':'No partnership is failing')+(c('delayed')?', '+pl(c('delayed'),'is','are')+' delayed':'')+(c('unqueryable')?' and '+pl(c('unqueryable'),'domain controller')+' could not be queried':'')+'.</p>'+
     (pk.length?'<p>Replication from '+e(lst(pk))+' is failing'+(pairs[pk[0]]?' (reported error: '+e(pairs[pk[0]])+')':'')+'. Until this is fixed, changes made on one side do not reach the other: new or disabled accounts, password resets and group changes stay local, and the longer it lasts the higher the risk of lingering objects.</p>':'')+
     (so.length?'<p>'+pl(so.length,'topology object')+' no longer '+(so.length===1?'matches':'match')+' the live environment, for example '+q((so[0].category||'')+': '+(so[0].name||''))+'.</p>':'');},
 trust:function(m){var D=m.d;return '<p>The domain has <b>'+pl(D.totalTrusts,'trust')+'</b>, of which '+fmt(D.externalCount)+' external and '+fmt(D.bidirectional)+' two-way. '+(num(D.highRisk)?'<b>'+pl(D.highRisk,'trust is','trusts are')+' rated high risk</b>':'No trust is rated high risk')+(num(D.mediumRisk)?' and '+pl(D.mediumRisk,'is','are')+' rated medium risk':'')+'.</p>'+
   (num(D.noSidFilter)?'<p>'+pl(D.noSidFilter,'trust does','trusts do')+' not filter SIDs. Without SID filtering, a compromised partner domain could present SID history that grants privileged access here.</p>':'')+(num(D.unreachable)?'<p>'+pl(D.unreachable,'trust partner')+' could not be reached. A trust to a domain that no longer exists should be removed.</p>':'');},
 acct:function(m){var D=m.d,c=D.counts||{},l=D.laps||{},age=num(D.krbtgtAge);
   var risks=[num(c.notRequired)?pl(c.notRequired,'account')+' may have no password at all':'',num(c.deleg)?pl(c.deleg,'account uses','accounts use')+' unconstrained delegation':'',num(c.neverExpires)?pl(c.neverExpires,'password never expires','passwords never expire'):''].filter(Boolean);
   return '<p>The <b>krbtgt</b> password, which protects every Kerberos ticket in the domain, was last changed <b>'+fmt(age)+' days ago</b>'+(age>180?', well beyond the recommended maximum of 180 days. A stolen krbtgt key (a &ldquo;Golden Ticket&rdquo;) stays usable until this password is reset twice.':', within the recommended interval.')+'</p>'+
     '<p>The review identified '+pl(c.privileged,'privileged account')+' and '+pl(c.spn,'account')+' with service principal names. '+(risks.length?risks.join('; ')+'.':'')+'</p>'+
     ((l.mode==='None'||(l.total!=null&&!num(l.total)))?'<p><b>LAPS is not deployed</b>, so local administrator passwords are not managed centrally and may be identical across computers. ':((num(c.noAes)||D.krbtgtNoAes)?'<p><b>'+(D.krbtgtNoAes?'The krbtgt account and ':'')+pl(c.noAes,'account')+' have no AES keys</b> because their passwords predate AES support. Since the April 2026 Kerberos hardening, domain controllers issue AES-only tickets by default, so these accounts, especially service accounts, can fail to authenticate.</p>':'')+'<p>LAPS protects the local administrator password on <b>'+(l.pct!=null?l.pct+'%':'an unknown share')+'</b> of computers ('+pl(l.missing,'computer')+' without it). ')+(num(D.policyFail)?pl(D.policyFail,'password policy setting falls','password policy settings fall')+' below the baseline.':'The password policy meets the baseline.')+'</p>';},
 gou:function(m){var D=m.d,s=D.stats||{},ix=(D.idfix||{}),is=ix.stats||{};
   return '<p>The directory contains '+pl(s.security,'security group')+' and '+pl(s.ous,'organizational unit')+'. '+(num(s.circular)?'<b>'+pl(s.circular,'group is','groups are')+' part of a nesting loop</b>, ':'')+(num(s.deep)?pl(s.deep,'group is','groups are')+' nested '+fmt(s.deepThreshold||4)+' or more levels deep, ':'')+pl(s.empty,'group has','groups have')+' no members and '+pl(s.emptyOus,'OU is','OUs are')+' empty.</p>'+
     '<p>The directory-sync scan examined '+fmt(ix.scanned)+' objects and found '+(num(is.errors)?'<b>'+pl(is.errors,'error')+'</b> on '+pl(is.affected,'object')+'. These objects will fail to synchronise, or will be changed during synchronisation, until the values are corrected.':'no errors.')+'</p>';},
 gpo:function(m){var D=m.d,bl=D.baseline||{},x=m.x;
   return '<p>The domain has <b>'+pl(D.gpoCount,'Group Policy object')+'</b> configuring '+fmt(D.totalSettings)+' settings. '+(num(D.conflictCount)?pl(D.conflictCount,'setting is','settings are')+' configured differently by more than one GPO, so the result depends on link order. ':'')+(x.unlinked?pl(x.unlinked,'GPO is','GPOs are')+' not linked anywhere':'')+(x.empty?(x.unlinked?' and ':'')+pl(x.empty,'GPO configures','GPOs configure')+' nothing':'')+(x.unlinked||x.empty?'.':'')+'</p>'+
     (bl.total?'<p>Against the starter hardening baseline, <b>'+fmt(bl.compliant)+' of '+fmt(bl.total)+'</b> checks comply, '+fmt(bl.wrong)+' are set differently and '+fmt(bl.missing)+' are not configured.</p>':'');},
 dns:function(m){var D=m.d,z=arr(D.zones),cr=m.f.filter(function(x){return x.sev==='crit';}).map(function(x){return x.title;});
   return '<p>'+pl(z.length,'DNS zone')+' ('+z.filter(function(x){return x.adIntegrated;}).length+' AD-integrated) were assessed on '+pl(arr(D.dcs).length,'domain controller')+'. The assessment raised <b>'+pl(m.x.crit,'critical issue')+'</b> and '+pl(m.x.warn,'warning')+'.</p>'+
     (cr.length?'<p>The most important issues are '+lst(cr.slice(0,3).map(q))+'. DNS problems of this kind can let any device register or overwrite records, expose the full zone contents, or stop clients and domain controllers from finding each other.</p>':'');},
 auth:function(m){var D=m.d,dcs=arr(D.dcs),EV=D.events||{},W=m.x.w25||{},BK=D.backup||{},read=dcs.filter(function(d){return d.regRead;}).length;
   var cnt={};dcs.forEach(function(d){arr(d.settings).forEach(function(x){if(x.sev==='crit'||x.sev==='warn')cnt[x.title]=(cnt[x.title]||0)+1;});});var topS=Object.keys(cnt).sort(function(a,b){return cnt[b]-cnt[a];}).slice(0,3);
   var pdc=dcs.filter(function(d){return d.isPdc;})[0],pt=pdc?(arr((pdc.time||{}).findings)[0]):null;var old=arr(BK.partitions).filter(function(p){return p.days==null||p.days>7;}).map(function(p){return p.name;});
   return '<p>Protocol settings were read on <b>'+read+' of '+pl(dcs.length,'domain controller')+'</b>. '+(topS.length?'The settings most often not as recommended are '+lst(topS.map(q))+'. Weak LDAP, NTLM and SMB settings are what relay and credential-theft attacks rely on.':'All settings read are as recommended.')+'</p>'+
     (EV.collected?'<p>Over the last '+pl(EV.days,'day')+', the domain controllers recorded '+pl(EV.failTotal,'failed logon')+', '+pl(EV.kerbTotal,'Kerberos pre-authentication failure')+' and '+pl(arr(EV.lockouts).length,'locked-out account')+'. '+(arr(EV.failSources).some(function(x){return x.distinct>=10;})?'<b>At least one source tried ten or more different accounts, a pattern typical of password spraying.</b> ':'')+(arr(EV.privChanges).length?pl(arr(EV.privChanges).length,'change')+' to privileged groups should be confirmed as authorised.':'')+'</p>':'<p>Security events were not collected in this run.</p>')+
     '<p><b>Windows Server 2025:</b> '+(W.crit?'the environment is not yet ready; '+pl(W.crit,'blocker')+' must be resolved before the first Windows Server 2025 domain controller is promoted.':'no blockers were found.')+' <b>Time:</b> '+(pt?'the PDC emulator reports '+q(pt.title)+'.':'the time hierarchy shows no issue at the PDC emulator.')+' <b>Recovery:</b> '+(BK.recycleBinEnabled?'the AD Recycle Bin is enabled':'the AD Recycle Bin is not enabled')+(old.length?' and the '+lst(old)+' '+(old.length===1?'partition has':'partitions have')+' no recent backup.':' and every partition has a recent backup.')+'</p>';}
};
var PR={
 srv:function(m){var x=m.x,cols={crit:C.red,warn:C.amb,ok:C.grn};
   return {top:pfig([['Servers in AD',fmt(x.total)],['Read / contacted',fmt(x.read)+' / '+fmt(x.contacted),x.read<x.contacted?'w':''],['Windows out of support',x.eos,x.eos?'c':'g'],['Support ends < 1 year',x.soon,x.soon?'w':''],['SQL Server instances',fmt(x.sql)],['SQL out of support',x.sqlEos,x.sqlEos?'c':''],['Failover clusters',x.clusters],['Not updated '+x.pd+'+ days',x.notUpd,x.notUpd?'w':'']])+
     pcr(pdonut('Windows support status',[['Supported',x.ok,C.grn],['Ends within a year',x.soon,C.amb],['Out of support',x.eos,C.red]],[fmt(x.win),'Windows']),pbars('Operating systems',x.osl.slice(0,8).map(function(o){return [o[0],o[1],cols[o[2]]];}))),
   det:ptab('Servers on a Windows version out of support',['Server','Domain','Operating system','End of support'],x.eosList.map(function(p){return [p[0].name,p[0].domain||'',p[1][0],p[1][1]];}),40)+
     ptab('SQL Server instances out of support',['Server','Instance','Version','End of support'],x.sqlEosList.map(function(p){return [p[0].server||'',p[0].instance||'',p[1][0]+(p[0].version?' ('+p[0].version+')':''),p[1][1]];}),40)+
     ptab('Servers that could not be read',['Server','Subnet','AD site','Reason'],x.notRead.map(function(s){return [s.name,s.subnet||'',s.site||'',s.statusText||''];}),40)};},
 ov:function(m){var D=m.d,t=D.totals||{},a=D.accounts||{},c=D.computers||{},fo=D.forest||{},g=D.groups||{};
   return {top:pfig([['Users',fmt(t.users)],['Computers',fmt(t.computers)],['Groups',fmt(t.groups)],['OUs',fmt(t.ous)],['Group Policies',fmt(t.gpos)],['Contacts',fmt(t.contacts)],['Domains',fo.domainCount],['Sites',fo.siteCount],['Global catalogs',fo.gcCount],['Tombstone',fo.tombstoneDays!=null?fo.tombstoneDays+' d':''],['Forest level',(''+(fo.forestMode||'')).replace(/Windows|Forest/g,' ').trim(),/2008|2012|2003/.test(fo.forestMode)?'w':''],['Schema',fo.schemaVersion]])+
     pcr(pdonut('User accounts',[['Active',Math.max(0,num(a.enabled)-num(a.stale)),C.grn],['Stale',num(a.stale),C.amb],['Disabled',num(a.disabled),'#cbd5e1'],['Locked',num(a.locked),C.red]],[fmt(num(a.enabled)+num(a.disabled)),'users']),
         pdonut('Computers',[['Servers',num(c.servers),C.blu],['Clients',num(c.clients),C.teal],['Stale',num(c.stale),C.amb],['Disabled',num(c.disabled),'#cbd5e1']],[fmt(num(c.enabled)+num(c.disabled)),'computers']))+
     pcr(pbars('Operating systems',arr(c.osDist).slice(0,8).map(function(o){return [o.label,o.count,/2003|2008|2012|XP|Windows 7/.test(o.label)?C.red:C.blu];})),pbars('Groups',[['Security',g.security],['Distribution',g.distribution],['Global',g.global],['Domain local',g.domainLocal],['Universal',g.universal]])),
   det:ptab('Domains',['Domain','NetBIOS','Functional level','PDC','RID','Infrastructure','Users','Computers','Groups'],arr(D.domains).map(function(d){return [d.name,d.netbios,(''+d.mode).replace(/Windows|Domain/g,' ').trim(),d.pdcEmulator,d.ridMaster,d.infraMaster,fmt(d.users),fmt(d.computers),fmt(d.groups)];}))+
     ptab('Forest',['Property','Value'],[['Forest',fo.forestName],['Root domain',fo.rootDomain],['Schema',fo.schemaName+' ('+fo.schemaVersion+')'],['Schema master',fo.schemaMaster],['Domain naming master',fo.domainNamingMaster],['UPN suffixes',arr(fo.upnSuffixes).join(', ')||'none']])};},
 dc:function(m){var D=m.d,dcs=arr(D.dcs),os={};dcs.forEach(function(d){var k=(d.os||'Unknown').replace(/ (Standard|Datacenter|Enterprise).*$/,'').replace('Windows Server ','WS ');os[k]=(os[k]||0)+1;});
   var pal=[C.grn,C.blu,C.vio,C.teal,C.amb];
   return {top:pfig([['Domain controllers',D.totalDCs],['Reachable',D.onlineDCs,'g'],['Unreachable',D.offlineDCs,num(D.offlineDCs)?'c':''],['Global catalogs',D.gcCount],['Read-only',D.rodcCount],['Sites',D.siteCount],['Domains',D.domainCount],['Unsupported OS',D.legacyOSCount,num(D.legacyOSCount)?'c':'']])+
     pcr(pdonut('Operating systems',Object.keys(os).sort().reverse().map(function(k,i){return [k,os[k],/2008|2012/.test(k)?C.red:pal[i%pal.length]];}),[dcs.length,'DCs']),pdonut('Reachability',[['Reachable',num(D.onlineDCs),C.grn],['Unreachable',num(D.offlineDCs),C.red]],[D.onlineDCs+'/'+D.totalDCs,'reachable'])),
   det:ptab('Domain controllers',['DC','Site','Operating system','IPv4','Status','GC','Uptime'],dcs.map(function(d){return [d.shortName||d.name,d.site,(d.os||'').replace('Windows Server ','WS '),d.ipv4,d.online?sv('ok','Reachable'):sv('crit','Unreachable'),d.isGC?'Yes':'',d.uptime||''];}),60,[4])+
     ptab('Hardware and performance',['DC','Model','RAM','CPU','Memory','AD database'],dcs.filter(function(d){return d.hardware;}).map(function(d){var h=d.hardware||{},p=d.performance||{};return [d.shortName,h.model,h.ramTotalGB!=null?h.ramTotalGB+' GB':'',p.cpuUsage||'',p.memUsage||'',p.adDbSizeMB&&p.adDbSizeMB!=='Unavailable'?fmt(p.adDbSizeMB)+' MB':''];}))};},
 topo:function(m){var D=m.d,mx=arr(D.replMatrix),links=arr(D.siteLinks),st=arr(D.staleObjects),T=arr(D.topo)[0]||{};
   var cnt=function(s){return mx.filter(function(r){return r.state===s;}).length;};var sites=[];arr(T.domains).forEach(function(dm){arr(dm.sites).forEach(function(si){sites.push([si.siteName,dm.domainName,arr(si.domainControllers).map(function(dc){return (''+dc.name).split('.')[0];}).join(', ')||'none']);});});
   return {top:pfig([['Sites',sites.length||m.x.sites],['Site links',links.length],['DCs',arr(D.dcList).length],['Partnerships checked',mx.length],['Failing',cnt('fail'),cnt('fail')?'c':'g'],['Delayed',cnt('delayed'),cnt('delayed')?'w':''],['Not readable',cnt('unqueryable'),cnt('unqueryable')?'w':''],['Stale objects',st.length,st.length?'w':'']])+
     pcr(pdonut('Replication partnerships',[['Healthy',cnt('ok'),C.grn],['Delayed',cnt('delayed'),C.amb],['Failing',cnt('fail'),C.red],['Not readable',cnt('unqueryable'),'#cbd5e1']],[mx.length,'links'])),
   det:ptab('Replication problems',['Source','Destination','Partition','Last success','State','Error'],mx.filter(function(r){return r.state!=='ok';}).map(function(r){return [r.src,r.dst,(''+(r.partition||'')).replace(/,DC=.*$/,'').replace(/^DC=|^CN=/,''),r.lastSuccess||'never',sv(r.state==='fail'?'crit':'warn',r.state==='fail'?'Failing':(r.state==='delayed'?'Delayed':'Not readable')),r.errorText||''];}),40,[4])+
     ptab('Sites and domain controllers',['Site','Domain','Domain controllers'],sites)+
     ptab('Site links',['Site link','Sites','Cost','Interval (min)','Schedule'],links.map(function(l){return [l.Name,l.SitesIncluded,l.Cost,l.ReplicationFrequencyInMinutes,l.ReplicationSchedule];}))+
     ptab('Stale and orphaned objects',['Category','Name','Severity','Detail'],st.map(function(o){return [o.category,o.name,sv(o.severity),o.detail||''];}),40,[2])};},
 trust:function(m){var D=m.d,tr=arr(D.trusts),kinds={};tr.forEach(function(t){kinds[t.kind||'Other']=(kinds[t.kind||'Other']||0)+1;});
   return {top:pfig([['Trusts',D.totalTrusts],['External',D.externalCount],['Bidirectional',D.bidirectional],['Reachable',D.reachable,'g'],['Unreachable',D.unreachable,num(D.unreachable)?'w':''],['High risk',D.highRisk,num(D.highRisk)?'c':''],['Medium risk',D.mediumRisk,num(D.mediumRisk)?'w':''],['No SID filtering',D.noSidFilter,num(D.noSidFilter)?'w':'']])+
     pcr(pdonut('Risk',[['High',num(D.highRisk),C.red],['Medium',num(D.mediumRisk),C.amb],['Low',num(D.lowRisk),C.grn]],[D.totalTrusts,'trusts']),pbars('Trust types',Object.keys(kinds).map(function(k){return [k,kinds[k]];}))),
   det:ptab('Trusts',['Partner','Type','Direction','Transitive','SID filtering','Selective auth','Connectivity','Risk'],tr.map(function(t){return [t.partner||t.name,t.kind,t.direction,yn(t.transitive),t.sidFiltering?'On':sv('warn','Off'),t.selectiveAuth?'On':'Off',t.connectivity||'',sv(t.severity,({high:'High',medium:'Medium',low:'Low'})[t.severity]||t.severity)];}),60,[4,7])};},
 acct:function(m){var D=m.d,c=D.counts||{},cc=D.compCounts||{},l=D.laps||{};
   return {top:pfig([['krbtgt password age',fmt(D.krbtgtAge)+' d',num(D.krbtgtAge)>180?'c':''],['Privileged accounts',c.privileged],['SPN accounts',c.spn],['Never-expiring',c.neverExpires,num(c.neverExpires)?'w':''],['Password not required',c.notRequired,num(c.notRequired)?'c':''],['Unconstrained delegation',c.deleg,num(c.deleg)?'c':''],['Inactive accounts',c.inactive],['LAPS coverage',(l.mode==='None'||(l.total!=null&&!num(l.total)))?'Not deployed':(l.pct!=null?l.pct+'%':''),(l.mode==='None'||(l.total!=null&&!num(l.total)))?'c':(num(l.pct)>=90?'g':'w')],['gMSAs',D.gmsaCount],['Fine-grained policies',(D.psoState==='unknown'||D.psoState==='denied')?'Not verified':D.psoCount,(D.psoState==='unknown'||D.psoState==='denied')?'w':''],['Policy settings failing',D.policyFail,num(D.policyFail)?'w':''],['Legacy OS computers',cc.legacyOS,num(cc.legacyOS)?'c':''],['No AES keys',num(c.noAes)+(D.krbtgtNoAes?' + krbtgt':''),(num(c.noAes)||D.krbtgtNoAes)?'c':'']])+
     pcr('<div class="pch"><div class="pct">LAPS coverage</div><div class="dn">'+ring(num(l.covered),num(l.total),C.teal,104)+'<div class="lg"><div><span class="sw" style="background:var(--teal)"></span>Covered<b>'+fmt(l.covered)+'</b></div><div><span class="sw" style="background:var(--red)"></span>Missing<b>'+fmt(l.missing)+'</b></div><div><span class="sw" style="background:var(--amber)"></span>Expired<b>'+fmt(l.expired)+'</b></div></div></div></div>',
         pbars('Account risk flags',[['Never expires',c.neverExpires,C.amb],['Password not required',c.notRequired,C.red],['Unconstrained delegation',c.deleg,C.red],['SID history',c.sidHist,C.amb],['Inactive',c.inactive,C.amb],['Stale service password',c.staleSvc,C.amb],['No AES keys',c.noAes,C.red]])),
   det:ptab('Password and lockout policy',['Setting','Value','Recommended','Status'],arr(D.policy).map(function(p){return [p.setting,p.value,p.recommended,sv(p.class==='high'?'crit':(p.class==='medium'?'warn':'ok'),p.class==='ok'?'OK':(p.class==='high'?'Fails':'Weak'))];}),40,[3])+
     ptab('Accounts of interest',['Account','Type','Password age','Last logon','Encryption','Risk','Findings'],arr(D.accounts).map(function(a){return [a.name,a.privileged?'Privileged':(a.isService?'Service':'User'),a.pwdAgeDays!=null?fmt(a.pwdAgeDays)+' d':'',a.lastLogon||'',a.enc||'',sv(a.severity,({high:'High',medium:'Medium',low:'Low'})[a.severity]||a.severity||''),arr(a.findings).join('; ')];}),40,[5])+
     ptab('Computers of interest',['Computer','Operating system','Last logon','Password age','Risk','Findings'],arr(D.computers).map(function(x){return [x.name,x.os||'',x.lastLogonDays!=null?x.lastLogonDays+' d ago':'',x.pwdAgeDays!=null?x.pwdAgeDays+' d':'',sv(x.severity,({high:'High',medium:'Medium',low:'Low'})[x.severity]||x.severity||''),arr(x.findings).join('; ')];}),30,[4])};},
 gou:function(m){var D=m.d,s=D.stats||{},ix=D.idfix||{},is=ix.stats||{},gr=arr(D.groups);
   var flagged=gr.filter(function(g){return g.circular||g.deep||g.large;}).sort(function(a,b){return (b.circular-a.circular)||(b.total-a.total);});
   return {top:pfig([['Groups',s.groups],['Security groups',s.security],['Circular nesting',s.circular,num(s.circular)?'c':''],['Deeply nested',s.deep,num(s.deep)?'w':''],['Large groups',s.large],['Empty groups',s.empty],['OUs',s.ous],['Empty OUs',s.emptyOus],['Default containers',s.defaultObjs],['Objects scanned (sync)',fmt(ix.scanned)],['Sync errors',is.errors,num(is.errors)?'w':''],['Objects affected',is.affected]])+
     pcr(pbars('Group issues',[['Circular nesting',s.circular,C.red],['Deeply nested',s.deep,C.amb],['Large',s.large,C.blu],['Empty',s.empty,'#94a3b8']]),pbars('Directory sync errors by type',[['Character',is.character],['Format',is.format],['Top-level domain',is.tld],['Duplicate',is.duplicate],['Length',is.length],['Blank',is.blank]].filter(function(x){return num(x[1]);}).map(function(x){return [x[0],x[1],C.amb];}))),
   det:ptab('Groups needing attention',['Group','Scope','Members','Nesting depth','Notes'],flagged.map(function(g){return [g.name,g.scope,fmt(g.total),g.depth,[g.circular?'circular':'',g.deep?'deep':'',g.large?'large':''].filter(Boolean).join(', ')];}))+
     ptab('Empty OUs',['OU','Distinguished name'],arr(D.ous).filter(function(o){return o.empty;}).map(function(o){return [o.name,o.dn];}))+
     ptab('Directory sync errors',['Object','Attribute','Error','Value'],arr(ix.findings).map(function(x){return [x.name,x.attribute,x.error,x.value];}),40)};},
 gpo:function(m){var D=m.d,bl=D.baseline||{},ga=arr(D.gpoAnalysis),rows=arr(D.rows);
   return {top:pfig([['GPOs',D.gpoCount],['Settings',fmt(D.totalSettings)],['Conflicts',D.conflictCount,num(D.conflictCount)?'w':''],['GPOs with issues',D.problemGpoCount,num(D.problemGpoCount)?'w':''],['Computer settings',D.computerCount],['User settings',D.userCount],['Baseline compliant',bl.compliant,'g'],['Baseline different',bl.wrong,num(bl.wrong)?'w':'']])+
     pcr(pbars('Settings by category',[['Registry',D.registryCount],['Security options',D.securityOptionCount],['User rights',D.userRightCount],['System access',D.systemAccessCount],['Kerberos',D.kerberosCount],['Audit',D.auditCount]]),pdonut('Security baseline',[['Compliant',num(bl.compliant),C.grn],['Different',num(bl.wrong),C.amb],['Missing',num(bl.missing),'#cbd5e1']],[bl.total,'checks'])),
   det:ptab('Group Policy objects',['GPO','Settings','Links','Status','Issues'],ga.map(function(g){return [g.name,g.settingCount,g.linksCount,(''+(g.gpoStatus||'')).replace(/([a-z])([A-Z])/g,'$1 $2'),arr(g.issues).join('; ')||'None'];}),60)+
     ptab('Conflicting settings',['Setting','Category','GPOs configuring it','Winning GPO','Winning value','WMI-filtered GPOs'],rows.filter(function(r){return r.conflict;}).map(function(r){var wm=(D.gpoWmi&&typeof D.gpoWmi==='object')?D.gpoWmi:{};var w=Object.keys(r.values||{}).filter(function(g){return wm[g]&&wm[g].name&&r.values[g]!=null&&(''+r.values[g]).trim()!=='';}).map(function(g){return g+' ('+wm[g].name+')';});return [r.friendlyName||r.setting,r.category,r.configuredCount,r.winner,r.winnerValue,w.join(', ')||'None'];}))+
     ptab('Security baseline',['Area','Setting','Expected','Status','Found'],arr(bl.results).map(function(b){return [b.cat,b.name,b.expected,sv(/Compliant/i.test(b.status)?'ok':(/Wrong|Different/i.test(b.status)?'warn':'info'),b.status),b.found||''];}),40,[3])};},
 dns:function(m){var D=m.d,z=arr(D.zones),dcs=arr(D.dcs);
   return {top:pfig([['Zones',z.length],['Domain controllers',dcs.length],['Critical issues',m.x.crit,m.x.crit?'c':'g'],['Warnings',m.x.warn,m.x.warn?'w':''],['Conditional forwarders',arr(D.condFwd).length],['Lingering DC records',arr(D.staleDc).length,arr(D.staleDc).length?'w':''],['AD-integrated zones',z.filter(function(x){return x.adIntegrated;}).length],['Reverse zones',z.filter(function(x){return x.reverse;}).length]])+
     pcr(pdonut('Issues',[['Critical',m.x.crit,C.red],['Warnings',m.x.warn,C.amb]],[m.x.crit+m.x.warn,'issues']),pbars('Zone settings',[['Secure-only updates',z.filter(function(x){return /^Secure$/i.test(x.dynamicUpdate);}).length,C.grn],['Aging enabled',z.filter(function(x){return x.agingEnabled;}).length,C.grn],['DNSSEC signed',z.filter(function(x){return x.dnssec;}).length,C.blu],['Open zone transfers',z.filter(function(x){return /any/i.test(x.transfer||'');}).length,C.red]],z.length||1)),
   det:ptab('Zones',['Zone','Type','AD-integrated','Dynamic updates','Transfers','Aging','DNSSEC'],z.map(function(x){return [x.name,x.type,yn(x.adIntegrated),x.dynamicUpdate,x.transfer,x.agingEnabled?'On':'Off',x.dnssec?'Signed':'No'];}),60)+
     ptab('Domain controller DNS',['DC','Site','Forward','Reverse','External','Resolvers','Forwarders'],dcs.map(function(d){var r=function(v){return v===true?sv('ok','OK'):(v===false?sv('crit','Failed'):'');};return [(''+d.name).split('.')[0],d.site||'',r(d.fwd),r(d.rev),r(d.ext),arr(d.resolvers).join(', '),arr(d.forwarders).join(', ')];}),40,[2,3,4])+
     ptab('Records pointing at removed domain controllers',['Record','Type','Zone','Points to'],arr(D.staleDc).map(function(r){return [r.record,r.type,r.zone,r.points];}))};},
 auth:function(m){var D=m.d,dcs=arr(D.dcs),EV=D.events||{},W=m.x.w25||{},BK=D.backup||{},daily=arr(EV.daily);
   var SETS=[['ldapSign','LDAP signing'],['ldapCbt','LDAP channel binding'],['ldaps','LDAPS certificate'],['ntlmLevel','NTLM level'],['ntlmAudit','NTLM auditing'],['noLm','LM hash storage'],['smbSign','SMB signing'],['smb1','SMBv1'],['tls','SSL / TLS'],['llmnr','LLMNR'],['netbios','NetBIOS'],['wdigest','WDigest'],['lsaPpl','LSA protection'],['kerbEnc','Kerberos encryption'],['spooler','Print Spooler']];
   var G={ok:'&#10003;',warn:'!',crit:'&#10005;',info:'i',na:'&ndash;'};function st(dc,id){var r='na';arr(dc.settings).forEach(function(x){if(x.id===id)r=x.sev;});return r;}
   var mxh='';for(var i=0;i<dcs.length;i+=8){var part=dcs.slice(i,i+8);mxh+='<table class="mx" style="margin-bottom:6pt"><thead><tr><th>Setting</th>'+part.map(function(d){return '<th>'+e(d.short)+'</th>';}).join('')+'</tr></thead><tbody>'+SETS.map(function(x){return '<tr><td class="ft">'+x[1]+'</td>'+part.map(function(d){var c=st(d,x[0]);return '<td><span class="cell '+c+'">'+G[c]+'</span></td>';}).join('')+'</tr>';}).join('')+'</tbody></table>';}
   var evc=EV.collected?(daily.length?'<div class="pch chart"><div class="pct">Security events per day</div>'+area([['Failed logons',daily.map(function(d){return num(d.f);}),C.red],['Kerberos failures',daily.map(function(d){return num(d.k);}),C.acc]],daily.map(function(d){return (''+d.day).substring(5);}),620,170)+'<div class="lgd"><span><span class="sw" style="background:var(--red)"></span> Failed logons ('+fmt(EV.failTotal)+')</span><span><span class="sw" style="background:var(--accent)"></span> Kerberos failures ('+fmt(EV.kerbTotal)+')</span></div></div>':''):'';
   var parts=arr(BK.partitions),tsl=BK.tombstone||180;
   return {top:pfig([['Domain controllers',dcs.length],['Settings read',dcs.filter(function(d){return d.regRead;}).length+' / '+dcs.length],['Server 2025 blockers',W.crit,W.crit?'c':'g'],['Failed logons',EV.collected?fmt(EV.failTotal):'n/a'],['Kerberos failures',EV.collected?fmt(EV.kerbTotal):'n/a'],['Locked-out accounts',EV.collected?arr(EV.lockouts).length:'n/a'],['Privileged changes',EV.collected?arr(EV.privChanges).length:'n/a',arr(EV.privChanges).length?'w':''],['AD Recycle Bin',BK.recycleBinEnabled?'Enabled':'Off',BK.recycleBinEnabled?'g':'w']])+
     pcr(pdonut('Windows Server 2025 readiness',[['Blockers',num(W.crit),C.red],['Risks',num(W.warn),C.amb],['Passed',num(W.pass),C.grn]],[W.pass+'/'+W.total,'passed']),
         pbars('Protocol settings not as recommended',SETS.map(function(x){return [x[1],dcs.filter(function(d){var c=st(d,x[0]);return c==='warn'||c==='crit';}).length,C.amb];}).filter(function(x){return x[1];}),dcs.length||1))+(evc?pcr(evc):''),
   det:'<h3 class="st">Protocol settings per domain controller</h3>'+mxh+'<div class="more">&#10003; as recommended &middot; ! warning &middot; &#10005; critical &middot; i recommendation &middot; &ndash; not read</div>'+
     ptab('Windows Server 2025 readiness checks',['Check','Result'],arr(W.list).map(function(c){return [c.name,sv(c.st,c.st==='ok'?'Pass':(c.st==='crit'?'Blocker':'Risk'))];}),40,[1])+
     ptab('Time sync',['DC','Type','Current source','Offset vs PDC','Issues'],dcs.map(function(d){var t=d.time||{};return [d.short+(d.isPdc?' (PDC)':''),t.type||'',t.source||t.error||'',t.offsetPdc!=null?(+t.offsetPdc).toFixed(3)+' s':'',arr(t.findings).map(function(x){return x.title;}).join('; ')||(t.type?'None':'Not read')];}))+
     ptab('Backups per partition',['Partition','Last backup','Age','Status'],parts.map(function(p){var s=p.days==null?(p.error?'info':'crit'):(p.days>tsl/2?'crit':(p.days>7?'warn':'ok'));return [p.name,p.last||(p.error?'could not be read':'Never'),p.days!=null?p.days+' d':'',sv(s,s==='ok'?'OK':(s==='info'?'Unknown':(p.days==null?'Never':'Old')))];}),20,[3])+
     (EV.collected?ptab('Account lockouts',['Account','Lockouts','Caller computers','Last'],arr(EV.lockouts).map(function(x){return [x.name,x.count,arr(x.others).slice(0,4).map(function(o){return o.name;}).join(', '),x.last];}),15)+
       ptab('Failed logons by source',['Source','Attempts','Accounts tried','Last'],arr(EV.failSources).map(function(x){return [x.name+(x.distinct>=10?' (possible spray)':''),fmt(x.count),x.distinct,x.last];}),15)+
       ptab('Privileged group changes',['When','Group','Member','Action','By'],arr(EV.privChanges).map(function(c){return [c.time,c.group,c.member,c.action,c.by];}),30)+
       ptab('Unsigned or clear-text LDAP clients',['Client','Binds','Bind type','Last'],arr(EV.ldapClients).map(function(x){return [x.name,fmt(x.count),arr(x.others).map(function(o){return o.name;}).join(', '),x.last];}),30):'')};}
};
/* ---------- findings PDF (browser print -> Save as PDF) ---------- */
var SVW={crit:'Critical',warn:'Warning',info:'Recommendation'};
function buildPrint(){
  var TC=0,TW=0,TI=0,ran=0;MODS.forEach(function(m){TC+=m.crit;TW+=m.warn;TI+=m.info;if(m.status==='ok')ran++;});
  var order={crit:0,warn:1,info:2};
  var h='<div class="pd"><div class="cover"><div class="kick">Active Directory assessment</div><h1>Findings report</h1><div class="for">'+e(S.forest)+'</div>'+
    '<div class="meta"><div><span>Generated</span>'+e(S.generated)+'</div><div><span>Run on</span>'+e(S.host)+(S.user?' as '+e(S.user):'')+'</div><div><span>Modules</span>'+ran+' of '+MODS.length+' completed &middot; '+e(S.duration)+'</div><div><span>Produced by</span>AD Audit Suite</div></div>'+
    '<div class="kp"><div><b style="color:#b91c1c">'+TC+'</b><span>Critical</span></div><div><b style="color:#b45309">'+TW+'</b><span>Warnings</span></div><div><b style="color:#1d4ed8">'+TI+'</b><span>Recommendations</span></div><div><b>'+ran+'/'+MODS.length+'</b><span>Modules</span></div></div>'+
    '<div class="verdict'+(TC?'':' ok')+'"><b>'+(TC?'Action required.':(TW?'Mostly healthy.':'Healthy.'))+'</b> '+(TC?TC+' critical finding'+(TC===1?'':'s')+' should be addressed first; they are listed on the next page.':(TW?'No critical findings; '+TW+' warning'+(TW===1?'':'s')+' to review.':'No critical findings or warnings.'))+'</div></div>';
  /* executive summary */
  var crit0=[];MODS.forEach(function(m){m.f.forEach(function(x){if(x.sev==='crit')crit0.push([x,m]);});});
  var ar={};MODS.forEach(function(m){ar[m.part]=(ar[m.part]||0)+m.crit;});var arS=Object.keys(ar).filter(function(k){return ar[k];}).sort(function(a,b){return ar[b]-ar[a];});
  var clean=MODS.filter(function(m){return m.status==='ok'&&m.read&&!m.crit;}).map(function(m){return m.title.toLowerCase();});var bad=MODS.filter(function(m){return m.status!=='ok';});
  h+='<section><h2>Executive summary</h2>'+
    '<p>This document reports the results of an automated, read-only assessment of the Active Directory forest <b>'+e(S.forest)+'</b>, carried out on '+e((''+S.generated).substring(0,10))+'. '+ran+' of '+pl(MODS.length,'assessment module')+' completed. Together they identified <b>'+pl(TC,'critical finding')+'</b>, '+pl(TW,'warning')+' and '+pl(TI,'recommendation')+'.</p>'+
    (TC?'<p>The risk is concentrated in '+lst(arS.slice(0,2).map(function(a){return '<b>'+e(a.toLowerCase())+'</b> ('+ar[a]+' critical)';}))+'. The most significant issues are '+lst((function(){var seen={},o=[];crit0.forEach(function(c){if(!seen[c[1].id]&&o.length<3){seen[c[1].id]=1;o.push(c);}});return o;})().map(function(c){return q(c[0].title);}))+'. These should be addressed before anything else, because each one either exposes the domain to a well-known attack or threatens its availability.</p>':'<p>No critical findings were identified. The warnings in this report should be reviewed and planned as part of regular maintenance.</p>')+
    (clean.length?'<p>No critical issues were found in '+e(lst(clean))+'.</p>':'')+
    (bad.length?'<p><b>Coverage:</b> '+e(lst(bad.map(function(m){return m.title;})))+' did not complete, so '+(bad.length===1?'this area is':'these areas are')+' not covered by this document.</p>':'')+
    '<p>The sections that follow describe each area in turn: what was assessed, what was found, and what to do about it. A prioritised plan closes the document.</p>';
  /* summary */
  h+='<h3 class="st">Results by module</h3><div class="sub">Findings per module. Each module has its own section with every finding and its recommendation.</div><table><thead><tr><th>#</th><th>Module</th><th>Critical</th><th>Warnings</th><th>Recommendations</th><th>Result</th></tr></thead><tbody>'+
    MODS.map(function(m){return '<tr><td>'+m.no+'</td><td class="ft">'+e(m.title)+'</td><td class="n">'+(m.status==='ok'?m.crit:'&ndash;')+'</td><td class="n">'+(m.status==='ok'?m.warn:'&ndash;')+'</td><td class="n">'+(m.status==='ok'?m.info:'&ndash;')+'</td><td>'+(m.status==='ok'?'<span class="sv ok">Completed</span>':'<span class="sv fail">'+(m.status==='skipped'?'Skipped':'Failed')+'</span>')+'</td></tr>';}).join('')+'</tbody></table>';
  var crit=[];MODS.forEach(function(m){m.f.forEach(function(x){if(x.sev==='crit')crit.push([x,m]);});});
  h+='<h3 class="st">Critical findings</h3>'+(crit.length?'<table><thead><tr><th style="width:8mm">#</th><th>Finding</th><th style="width:48mm">Module</th></tr></thead><tbody>'+crit.map(function(c,i){return '<tr><td>'+(i+1)+'</td><td class="ft">'+e(c[0].title)+'</td><td>'+c[1].no+'. '+e(c[1].title)+'</td></tr>';}).join('')+'</tbody></table>':'<div class="none">No critical findings.</div>')+'</section>';
  /* dashboard page */
  var areas={};MODS.forEach(function(m){areas[m.part]=areas[m.part]||[0,0];areas[m.part][0]+=m.crit;areas[m.part][1]+=m.warn;});
  var mxm=Math.max.apply(null,MODS.map(function(m){return m.crit+m.warn;}).concat([1]));
  h+='<section class="pg"><h2>Dashboard</h2><div class="sub">Findings across all modules at a glance.</div><p>The charts below show how the findings are distributed across modules, severities and areas, followed by the health of each domain controller as seen by the replication, time and protocol checks.</p>'+
    '<div class="pch"><div class="pct">Findings by module</div><div class="pb">'+MODS.map(function(m){return '<div class="pbi"><span>'+m.no+'. '+e(m.title)+'</span><div class="pbt"><i style="width:'+m.crit*100/mxm+'%;background:var(--red)"></i><i style="width:'+m.warn*100/mxm+'%;background:var(--amber)"></i></div><b>'+(m.status==='ok'?m.crit+' / '+m.warn:'&ndash;')+'</b></div>';}).join('')+'</div><div class="lgd"><span><span class="sw" style="background:var(--red)"></span> Critical</span><span><span class="sw" style="background:var(--amber)"></span> Warnings</span></div></div>'+
    pcr(pdonut('Findings by severity',[['Critical',TC,C.red],['Warning',TW,C.amb],['Recommendation',TI,C.blu]],[TC+TW+TI,'findings']),
        '<div class="pch"><div class="pct">Findings by area</div><div class="pb">'+Object.keys(areas).map(function(a){var v=areas[a],mx2=Math.max.apply(null,Object.keys(areas).map(function(k){return areas[k][0]+areas[k][1];}).concat([1]));return '<div class="pbi"><span>'+e(a)+'</span><div class="pbt"><i style="width:'+v[0]*100/mx2+'%;background:var(--red)"></i><i style="width:'+v[1]*100/mx2+'%;background:var(--amber)"></i></div><b>'+v[0]+' / '+v[1]+'</b></div>';}).join('')+'</div></div>');
  var dcx=X('dc'),dcs=arr(dcx.dcs),tp=X('topo'),au=X('auth'),authBy={};arr(au.dcs).forEach(function(d){authBy[(''+d.short).toUpperCase()]=d;});
  if(dcs.length){var lv=function(l){var w='ok';l.forEach(function(x){if(R[x]>R[w])w=x;});return w;};var G2={ok:'&#10003;',warn:'!',crit:'&#10005;',na:'&ndash;'};
    h+='<h3 class="st">Domain controller health</h3><table class="mx"><thead><tr><th>Domain controller</th><th>Site</th><th>Operating system</th><th>Online</th><th>Replication</th><th>Time</th><th>Protocols</th></tr></thead><tbody>'+dcs.map(function(d){var sn=(''+(d.shortName||d.name)).toUpperCase(),a=authBy[sn],rp=tp.byDst?(tp.byDst[sn]||'na'):'na',tm=a&&a.time&&(a.time.type||a.time.source)?lv(arr(a.time.findings).map(function(x){return x.sev==='info'?'ok':x.sev;})):'na',pr=a&&a.regRead?lv(arr(a.settings).map(function(x){return x.sev==='info'?'ok':x.sev;})):'na';
      return '<tr><td class="ft">'+e(sn)+(a&&a.isPdc?' (PDC)':'')+'</td><td>'+e(d.site||'')+'</td><td>'+e((d.os||'').replace('Windows Server ','WS ').replace(/ (Standard|Datacenter).*/,''))+'</td><td><span class="cell '+(d.online===false?'crit':'ok')+'">'+(d.online===false?G2.crit:G2.ok)+'</span></td><td><span class="cell '+rp+'">'+G2[rp]+'</span></td><td><span class="cell '+tm+'">'+G2[tm]+'</span></td><td><span class="cell '+pr+'">'+G2[pr]+'</span></td></tr>';}).join('')+'</tbody></table>';}
  h+='</section>';
  /* one section per module */
  MODS.forEach(function(m){
    h+='<section class="pg"><h2>'+m.no+'. '+e(m.title)+'</h2><div class="sub">'+e(m.part)+' &middot; '+e(m.script)+(m.duration?' &middot; ran in '+e(m.duration):'')+(m.status==='ok'?' &middot; '+m.crit+' critical, '+m.warn+' warnings, '+m.info+' recommendations':'')+'</div>';
    if(m.status!=='ok'){h+='<div class="none"><b>'+(m.status==='skipped'?'Skipped':'Did not complete')+'.</b> '+e(m.error||'')+'</div></section>';return;}
    if(!m.read){h+='<div class="none">The module ran, but its data could not be read for this report. See the module in the interactive report.</div></section>';return;}
    var list=m.f.slice().sort(function(a,b){return order[a.sev]-order[b.sev];}),P=null,ST='';try{P=PR[m.id]?PR[m.id](m):null;}catch(err){P=null;}try{ST=STORY[m.id]?STORY[m.id](m):'';}catch(err){ST='';}
    if(ABOUT[m.id])h+='<div class="about"><b>About this area.</b> '+ABOUT[m.id]+'</div>';
    if(ST)h+='<h3 class="st">Assessment</h3>'+ST;
    if(P&&P.top)h+='<h3 class="st">At a glance</h3>'+P.top;
    var lc=list.filter(function(x){return x.sev==='crit';});
    h+='<h3 class="st">Findings</h3><p>'+(list.length?'This area has '+pl(m.crit,'critical finding')+', '+pl(m.warn,'warning')+' and '+pl(m.info,'recommendation')+'. '+(lc.length?'The most urgent is '+q(lc[0].title)+'. ':'')+'Each finding is listed below with the recommended action, most severe first.':'No issues were found in this area.')+'</p>';
    h+=list.length?'<table><thead><tr><th style="width:27mm">Severity</th><th style="width:62mm">Finding</th><th>Recommendation</th></tr></thead><tbody>'+list.map(function(x){return '<tr><td><span class="sv '+x.sev+'">'+SVW[x.sev]+'</span></td><td class="ft">'+e(x.title)+'</td><td class="adv">'+e(x.adv||'See the module report for details.')+'</td></tr>';}).join('')+'</tbody></table>':'<div class="none">No findings in this area.</div>';
    if(P&&P.det)h+=P.det;
    h+='</section>';});
  /* recommended next steps */
  var cr=[],wr=[],inf=[];MODS.forEach(function(m){m.f.forEach(function(x){if(x.sev==='crit')cr.push([x,m]);else if(x.sev==='warn')wr.push([x,m]);else inf.push([x,m]);});});
  h+='<section class="pg"><h2>Recommended next steps</h2><div class="sub">A prioritised plan based on the findings in this document.</div>'+
    '<p>The actions below are grouped by urgency. Critical findings carry a direct security or availability risk and should be handled first. Warnings weaken the security posture and belong in the next planning cycle. Recommendations are good practice and housekeeping.</p>'+
    '<div class="phase"><i style="background:#dc2626">1</i>Address now &mdash; '+pl(cr.length,'critical finding')+'</div>'+(cr.length?'<ol class="steps">'+cr.map(function(c){return '<li><b>'+e(c[0].title)+'</b> <small>('+e(c[1].title)+')</small><span>'+e(c[0].adv||'See the module section for details.')+'</span></li>';}).join('')+'</ol>':'<p>No critical findings.</p>')+
    '<div class="phase"><i style="background:#d97706">2</i>Plan &mdash; '+pl(wr.length,'warning')+'</div>'+(wr.length?'<p>Schedule these as part of planned changes, starting with the ones affecting privileged access and authentication.</p><ol class="steps">'+wr.map(function(c){return '<li><b>'+e(c[0].title)+'</b> <small>('+e(c[1].title)+')</small><span>'+e(c[0].adv||'')+'</span></li>';}).join('')+'</ol>':'<p>No warnings.</p>')+
    '<div class="phase"><i style="background:#2563eb">3</i>Housekeeping &mdash; '+pl(inf.length,'recommendation')+'</div>'+(inf.length?'<ul class="plain">'+inf.map(function(c){return '<li>'+e(c[0].title)+' <small style="color:#64708c">('+e(c[1].title)+')</small></li>';}).join('')+'</ul>':'<p>No recommendations.</p>')+
    '<p>After the critical and warning items are resolved, run the assessment again to confirm the changes and to track progress over time.</p></section>';
  /* methodology */
  h+='<section class="pg"><h2>Methodology</h2><div class="sub">How the data in this document was collected, and its limits.</div>'+
    '<p>The assessment was carried out with the AD Audit Suite, a set of PowerShell modules that each examine one area of Active Directory. The suite ran every selected module in its own PowerShell process on <b>'+e(S.host)+'</b>'+(S.user?' as <b>'+e(S.user)+'</b>':'')+' and combined the results into the interactive report and this document.</p>'+
    '<p>All modules are <b>read-only</b>. They query Active Directory, DNS and Group Policy through the standard management interfaces, read domain controller settings from the registry and event logs remotely, and never change configuration. Findings are rated <b>critical</b> when they carry a direct security or availability risk, <b>warning</b> when they weaken the security posture, and <b>recommendation</b> when they are good practice.</p>'+
    '<p>The results reflect the state of the environment at the time of the assessment. Domain controllers that could not be reached were assessed only partly, and security events cover the collection window only. Recommendations describe the action to take; each change should be tested and applied through the organisation&rsquo;s change process.</p>';
  /* appendix */
  h+='<h3 class="st">Run information</h3><table><thead><tr><th>#</th><th>Module</th><th>Script</th><th>Duration</th><th>Result</th></tr></thead><tbody>'+
    MODS.map(function(m){return '<tr><td>'+m.no+'</td><td class="ft">'+e(m.title)+'</td><td>'+e(m.script)+'</td><td>'+e(m.duration||'')+'</td><td>'+(m.status==='ok'?'Completed':(m.status==='skipped'?'Skipped':'Failed'))+(m.error?' &mdash; '+e(m.error):'')+'</td></tr>';}).join('')+'</tbody></table>'+
    '<p style="margin-top:10pt">Every table, list and chart behind these findings is also in the interactive HTML report that accompanies this document.</p></section></div>';
  return h;}
function preparePrint(){document.getElementById('printdoc').innerHTML=buildPrint();}
var _title=document.title;
function exportPdf(){preparePrint();_title=document.title;document.title='AD_Findings_'+(''+S.forest).replace(/[^A-Za-z0-9.-]/g,'_')+'_'+(''+S.generated).substring(0,10);window.print();}
window.addEventListener('beforeprint',function(){if(!document.getElementById('printdoc').innerHTML)preparePrint();});
window.addEventListener('afterprint',function(){document.title=_title;});
function toggleSide(){document.body.classList.toggle('noside');}
document.addEventListener('click',function(ev){var a=ev.target.closest('[data-v]');if(a)show(a.getAttribute('data-v'));});
document.getElementById('pdfbtn').onclick=exportPdf;document.getElementById('menubtn').onclick=toggleSide;
document.addEventListener('keydown',function(ev){if((ev.ctrlKey||ev.metaKey)&&(ev.key==='b'||ev.key==='B')){ev.preventDefault();toggleSide();}});
document.getElementById('themebtn').onclick=function(){var d=theme()==='dark',n=d?'light':'dark';document.documentElement.setAttribute('data-theme',n);this.title=d?'Dark mode':'Light mode';Object.keys(frames).forEach(function(k){try{frames[k].contentDocument.documentElement.setAttribute('data-theme',n);}catch(x){}});};
</script></body></html>
'@
$HTML = $Template.Replace('__SUITE_DATA__', $SuiteJSON)
$ReportPath = Join-Path $OutputPath "AD_AuditSuite_$Stamp.html"
[System.IO.File]::WriteAllText($ReportPath, $HTML, [System.Text.UTF8Encoding]::new($true))

if (-not $KeepModuleReports -and -not $RebuildFrom) {
    foreach ($r in $Results) {
        if ($r['status'] -eq 'ok') { Remove-Item -Path (Join-Path $RunDir $r['name']) -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if (-not @(Get-ChildItem -Path $RunDir -ErrorAction SilentlyContinue).Count) { Remove-Item -Path $RunDir -Force -ErrorAction SilentlyContinue }
}

$ok = @($Results | Where-Object { $_['status'] -eq 'ok' }).Count
$failed = @($Results | Where-Object { $_['status'] -eq 'failed' }).Count
Write-Host ""
Write-Host ("  {0} of {1} modules completed{2} in {3}" -f $ok, $Results.Count, $(if ($failed) { ", $failed failed (logs kept in $RunDir)" } else { '' }), $SuiteDuration) -ForegroundColor $(if ($failed) { 'Yellow' } else { 'Green' })
Write-Host ("  Report saved: {0}  ({1:N1} MB)" -f $ReportPath, ((Get-Item $ReportPath).Length / 1MB)) -ForegroundColor Green
try { if ($OpenReport) { Start-Process $ReportPath } } catch {}
