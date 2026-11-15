# Active Directory Audit Suite

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white" alt="Platform: Windows">
  <img src="https://img.shields.io/badge/Active%20Directory-read--only-2ea44f" alt="Read-only">
  <img src="https://img.shields.io/badge/reports-offline%20HTML-blueviolet" alt="Offline HTML reports">
  <img src="https://img.shields.io/badge/modules-9%20%2B%20all--in--one-orange" alt="9 modules + all-in-one">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
</p>
<p align="center">
  <a href="https://github.com/Mohamed-Zeghlache/AD-Assessment-PowerShell-Script/stargazers"><img src="https://img.shields.io/github/stars/Mohamed-Zeghlache/AD-Assessment-PowerShell-Script?style=flat&logo=github" alt="GitHub stars"></a>
  <img src="https://img.shields.io/github/languages/code-size/Mohamed-Zeghlache/AD-Assessment-PowerShell-Script" alt="Code size">
</p>
<p align="center">
  <a href="https://mohamed-zeghlache.net"><img src="https://img.shields.io/badge/Website-mohamed--zeghlache.net-0A66C2?logo=googlechrome&logoColor=white" alt="Website"></a>
  <a href="https://www.linkedin.com/in/mohamed-zeghlache"><img src="https://img.shields.io/badge/LinkedIn-Mohamed%20Zeghlache-0A66C2" alt="LinkedIn"></a>
</p>

> A growing collection of standalone PowerShell scripts that each produce a single, self-contained, interactive HTML report for a different area of Active Directory health and security.

Every module is one script. Run it on a domain-joined machine with the AD PowerShell module, and it discovers the live environment and writes **one HTML file** you can open in any browser — no agents, no install, no internet, no telemetry. Each report is fully offline and portable: drop it in a ticket, attach it to an email, or hand it to an auditor.

Or run them **all at once** with the all-in-one report.

---

## All-in-one report

![AD Audit Suite demo](docs/AD-AuditSuite-demo.gif)

`AD-AuditSuite.ps1` runs every module and combines the results into **one interactive report**:

- **Dashboard** — findings by severity and by module, domain controller health (reachability, replication, time, protocol hardening), Windows Server 2025 readiness, security events, privileged and risky accounts, Group Policy, DNS and recovery figures, servers (Windows and SQL Server support status, servers read, updates and restarts), and the top priorities across all modules.
- **Search** across every finding and module from the top bar.
- **Every module's full report** in the same file, one section at a time.
- **Findings PDF** in one click (browser print → Save as PDF): an executive summary, each area explained in plain language with its key figures and charts, every finding with its recommendation, a prioritised remediation plan, and a methodology appendix.

Server Inventory contacts every server, so it is usually the longest module; leave it out with `-Skip ServerInventory` or run it from AD only with `-SkipRemote`. Each module runs in its own PowerShell process with a timeout, so one failing module never stops the others; the report shows what completed and why anything did not. Scales automatically to the screen (laptop or large monitor), with light and dark themes.

```powershell
.\scripts\AD-AuditSuite.ps1                                    # run all modules
.\scripts\AD-AuditSuite.ps1 -Skip GPOPolicyAnalyzer            # leave a module out
.\scripts\AD-AuditSuite.ps1 -ModuleArguments @{ DCPosture = '-EventDays 3' }
.\scripts\AD-AuditSuite.ps1 -ModuleArguments @{ ServerInventory = '-SkipRemote' }   # server inventory from AD only
.\scripts\AD-AuditSuite.ps1 -RebuildFrom .\AD_AuditSuite_run_20261005_101849   # rebuild the report without re-running anything
```

Keep all module scripts in the same folder as `AD-AuditSuite.ps1` (or point `-ScriptsPath` at them). Sample report: [`examples/AD-AuditSuite-EXAMPLE.html`](examples/AD-AuditSuite-EXAMPLE.html) (use its **Export findings (PDF)** button to see the PDF).

---

## Modules

| Module | Script | What it covers |
|---|---|---|
| **Overview** | `AD-Overview.ps1` | Forest & domain facts, object inventory, account posture, OS distribution, group breakdown |
| **Topology** | `AD-Topology.ps1` | Forest → domain → site → DC hierarchy across every domain, with health, FSMO roles, services, replication links, dcdiag, orphaned metadata and trusts to other forests |
| **DC Inventory** | `AD-DCInventory.ps1` | Per-DC inventory across every domain, plus hardware & performance specs (CPU, RAM, disks, NICs) |
| **Account Security** | `AD-AccountSecurity.ps1` | Password/lockout policy, fine-grained password policies, managed service accounts, LAPS coverage, risky user & computer accounts, accounts without AES keys, krbtgt age |
| **Trust Relationships** | `AD-TrustRelationships.ps1` | Every AD trust with direction/type/transitivity, SID filtering & selective auth posture, connectivity probe, derived risk findings, interactive trust map |
| **GPO Policy Analyzer** | `GPO-PolicyAnalyzer.ps1` | Backs up every GPO, parses Registry.pol/GptTmpl.inf directly, resolves settings via ADMX/ADML, flags every setting where GPOs disagree, and shows WMI filters that may explain them |
| **DNS Health** | `AD-DNSHealth.ps1` | Per-zone/per-server DNS configuration (AD-integration, dynamic updates, aging/scavenging, DNSSEC) plus live per-DC resolution health and lingering DC record detection |
| **Group & OU Structure** | `AD-GroupOUStructure.ps1` | Recursive group-nesting graph with circular-nesting/empty-group/large-group detection, OU hierarchy with per-OU counts and tiering recommendation, and an IDFix scan for Entra ID/M365 sync blockers |
| **DC Posture** | `AD-DCPosture.ps1` | Every domain in the forest: per-DC protocol/hardening checks (LDAP signing, SMB signing, NTLM, Kerberos encryption, etc.), security events (lockouts, failed logons, password spray), time-sync hierarchy, backup/recovery readiness, and Windows Server 2025 readiness |
| **Server Inventory** | `AD-ServerInventory.ps1` | Every server in the forest: OS and lifecycle, roles, SQL Server instances, failover clusters, hardware, physical or virtual, patching and uptime, service accounts, what blocks the servers that cannot be read, and what changed since an earlier run. Standalone (not part of the all-in-one report) |

Each module has its own distinct visual design so reports are instantly recognisable.

---

## Overview

![AD Overview demo](docs/overview-demo.gif)

The forest-wide summary — the natural landing page for the whole audit. Hero banner with forest facts (functional level, schema version, FSMO masters, tombstone lifetime), object-count KPI cards, donut charts for directory objects and account posture, bar charts for computer OS distribution and group breakdown, and a per-domain comparison table.

Stat cards that represent a list of objects (enabled / disabled / stale / never-logged-on / locked / password-never-expires accounts, computers, and security / distribution / scoped groups) include a **download icon** that exports that exact list to CSV — Name, SamAccountName, Enabled, LastLogon, and DN — entirely client-side, straight from the report.

```powershell
.\scripts\AD-Overview.ps1
```

---

## Topology

![AD Topology demo](docs/topology-demo.gif)

An interactive, pannable/zoomable map of the forest. Nested cards for forest → domain → site → DC, covering **every domain in the forest**, colour-coded by health. Click anything for a slide-in detail panel: forest info, domain FSMO holders, site subnets, or a rich DC panel with services, resources, replication status, and dcdiag results. Toggleable inter-site replication link overlay with cost and frequency labels. Trusts to other forests and external domains are shown on the forest card and in its detail panel.

A DC counts as reachable if it answers ping **or** any core DC port (LDAP, Kerberos, RPC, SMB, ADWS), so DCs with ICMP blocked are not mistaken for unreachable ones.

The toolbar also opens two analysis panels:

- **Replication Health Matrix** — a directional source → destination grid of every DC partnership across **every domain in the forest**, built from the replication metadata AD already tracks. It checks **all naming contexts** (domain, Configuration, Schema, DomainDnsZones, ForestDnsZones), not just the default partition, and each cell shows the **worst** partition — so a pair that is healthy on the domain NC but failing on Configuration still shows as failing. Click any cell for the full per-partition breakdown. Reads over ADWS (TCP 9389) and falls back to `repadmin`/RPC when ADWS is unreachable. "Delayed" thresholds are site-aware (`-ReplDelayIntraSiteHours`, default 1; `-ReplDelayInterSiteHours`, default 6) so healthy inter-site partners on the standard 180-minute schedule aren't flagged. Passive; no network probing.
- **Stale / Lingering Objects** — a read-only scan of the Configuration partition and Sites & Services for orphaned DC metadata (checked against the DCs of every domain in the forest), empty sites, sites without subnets, unlinked subnets, and lingering replication connections — each with the recommended remediation.

```powershell
.\scripts\AD-Topology.ps1
.\scripts\AD-Topology.ps1 -ForestName contoso.com   # optional: report on another (trusted) forest
```

---

## DC Inventory

![AD DC Inventory demo](docs/dcinventory-demo.gif)

Per-DC inventory plus deep hardware and performance detail. KPI cards for reachable/unreachable/GC/RODC/legacy-OS counts, a full inventory table (name, domain, site, OS, build, IPv4, time zone, uptime, GC, RODC, status), and an expandable card per DC with System (manufacturer, model, BIOS, RAM), Performance (CPU/memory usage, AD database size), Processors, Logical Volumes with usage bars, and Network Adapters. Reachability uses ping or any core DC port, and a DC that does not respond is reported as *unreachable from the audit host* rather than assumed to be down.

```powershell
.\scripts\AD-DCInventory.ps1
```

---

## Account Security

![AD Account Security demo](docs/AccountSecurity-demo.png)

Credential hygiene across the domain. Scores the default password & lockout policy against a recommended baseline, lists fine-grained password policies (PSOs) with precedence and who they apply to, inventories managed service accounts (gMSA/sMSA) and LAPS coverage (Windows and Legacy), and flags risky accounts — password-never-expires, password-not-required, unconstrained delegation, SID history, inactive-but-enabled users, stale service-account passwords, accounts (and krbtgt) with no AES keys because their password predates AES support, stale/legacy/EOL-OS computers — plus krbtgt password age. Long lists stay off the main page behind per-category **Open** (full-page view) and **CSV download** actions so a large tenant stays readable. Optional sources (LAPS schema, KDS root key, etc.) degrade gracefully to "Not available" instead of failing.

Reading fine-grained password policies requires read access to the Password Settings Container (Domain Admins by default). When the running account cannot see them, the report says they **could not be verified** instead of reporting that none exist.

```powershell
.\scripts\AD-AccountSecurity.ps1
```

---

## Trust Relationships

![AD Trust Relationships demo](docs/AD-TrustRelationships-demo.gif)

Enumerates every AD trust and assesses its security posture: partner domain, direction (inbound/outbound/bidirectional), trust type (external/forest/realm/parent-child/tree-root), and transitivity, plus SID filtering (quarantine), selective authentication, TGT delegation, and forest-transitive flags. Each trust gets a live connectivity probe (degrading gracefully to "Unavailable / Not tested" in locked-down environments) and derived risk findings — SID filtering disabled on an external/forest trust, selective authentication off, stale trusts, and more. Includes KPI tiles, a filterable trust explorer with detail panel, and an interactive trust map.

```powershell
.\scripts\AD-TrustRelationships.ps1
```

---

## GPO Policy Analyzer

![AD GPO Policy Analyzer demo](docs/GPO-PolicyAnalyzer-demo.gif)

Automates what Microsoft's Policy Analyzer does manually. Backs up every GPO in the domain (or a chosen subset) to a local folder, then parses the raw `Registry.pol` and `GptTmpl.inf` files directly from each backup — no `Get-GPOReport`, no RSOP, no repeated AD calls. Registry key/value pairs are resolved to friendly policy names via the same ADMX/ADML definition files GPME uses, pivoted into one comparison table, and any setting where GPOs disagree is flagged — the same "conflict" concept Policy Analyzer highlights in yellow. When a GPO involved in a conflict has a **WMI filter**, the setting's detail pane shows the filter and its query, since a WMI-filtered GPO only applies where the query is true and the "conflict" may never reach the same computer. The export step is the only part that talks to AD/SYSVOL; re-running with `-SkipExport` re-analyzes the same backups instantly, even for large GPO counts.

```powershell
.\scripts\GPO-PolicyAnalyzer.ps1
```

---

## DNS Health

![AD DNS Health demo](docs/AD-DNSHealth-demo.gif)

Reviews the DNS that underpins Active Directory from two angles. **Configuration** — per zone and per server: zone type, AD-integration, replication scope, dynamic-update mode, aging/scavenging, zone transfers, DNSSEC signing, and NS records. **Live health** — per domain controller: forward and reverse resolution, forwarder resolution, the DC's own record registration, and (when available) `dcdiag /test:DNS`. Stale-record checking is scoped to what actually breaks things — lingering DC records (`_msdcs` SRV/CNAME entries pointing at DCs that no longer exist, checked against the DCs of every domain in the forest) — rather than enumerating every record in every zone. Degrades gracefully when the DnsServer module or dcdiag.exe isn't available.

```powershell
.\scripts\AD-DNSHealth.ps1
```

---

## Group & OU Structure

![AD Group & OU Structure demo](docs/AD-GroupOUStructure-demo.gif)

Three sections in one report. **Group nesting** — a security-group membership graph with fully recursive nested-group expansion, circular-nesting detection, empty groups, deep-nesting and large-membership flags; click a group to see its members, like ADUC. **OU structure** — the OU hierarchy with per-OU object counts, empty-OU detection/filter, and a tiering-model recommendation; click an OU to see its direct contents. **IDFix** — a faithful reimplementation of Microsoft IDFix, scanning for attributes that break Entra ID/M365 sync, with click-through to the offending object and the erroring value highlighted. Read-only throughout — detection and suggested fixes only, no writes to AD.

```powershell
.\scripts\AD-GroupOUStructure.ps1
```

---

## DC Posture

![AD DC Posture demo](docs/AD-DCPosture-demo.gif)

Domain-controller hardening and operational readiness in five areas. **Protocols & hardening** — per DC: LDAP signing, LDAP channel binding, LDAP client logging (whether event 2889 is recorded), LDAPS certificate, NTLM level/auditing, LM hash storage, SMB signing, SMBv1, SSL/TLS versions, LLMNR, NetBIOS, WDigest, LSA protection, Kerberos encryption types, Print Spooler, plus DES-only accounts in every domain. **Security events** (last N days, every DC) — lockouts (4740), failed logons (4625) with password-spray detection, Kerberos pre-auth failures (4771), privileged group changes, cleared audit logs (1102), unsigned/clear-text LDAP binds with the offending clients, and the clients still using old protocols: LDAPS without channel binding (3039), NTLMv1 logons (4624), Kerberos tickets issued with RC4 or DES (4768/4769), NTLM authentications (8004, or 4776 with workstation names) and SMBv1 (3000). Where a DC does not log one of these, the report says what to turn on and on which DCs. **Time sync hierarchy** — platform (physical, VMware, Hyper-V, Azure), configured type and NTP server, whether the setting comes from Group Policy, actual source, last successful sync, and offset vs the PDC of the DC's own domain (only the forest-root PDC should use external NTP). **Backup & recovery readiness** — AD Recycle Bin, tombstone lifetime, last backup per partition, SYSVOL replication (DFSR vs FRS) in every domain. **Windows Server 2025 readiness** — only requirements documented by Microsoft, each linked to its Microsoft source: forest/domain functional level 2016+, DC versions, SYSVOL on DFSR, DES-only accounts and NTLMv1 (both removed in Windows Server 2025), and Exchange support (2019 CU14 or later, or Exchange SE). Registry values are read over CIM/DCOM (no WinRM needed); event logs over RPC. Unreachable DCs are reported, never waited on.

DC Posture covers every domain in the forest. In the report, a domain selector shows the whole forest or one domain at a time. Domain controllers are checked several at a time (`-Throttle`, default 10) on Windows PowerShell 5.1, so large environments don't need PowerShell 7.

```powershell
.\scripts\AD-DCPosture.ps1
```

---

## Server Inventory

![AD Server Inventory demo](docs/AD-ServerInventory-demo.gif)

An inventory of every server in the forest, in the spirit of a software-asset-management discovery. **From AD** (no connection to the servers): server objects in every domain (Windows and non-Windows), OU, last activity, and the roles AD already knows about — domain controllers, SQL Server (`MSSQLSvc` SPNs), failover clusters, Exchange, certificate authorities and Configuration Manager management points — plus the AD site of each server from the AD subnets. **From each server** (WMI over DCOM, WinRM as fallback): manufacturer, model, physical or virtual, serial number, CPU sockets / cores / logical processors, memory, IP addresses, Windows edition and build, last boot and uptime, installed roles and features, last installed update, pending restart, services running under domain accounts, SQL Server instances (edition, version, service account), and failover cluster nodes and roles. **Checks**: Windows Server and SQL Server end of support (Microsoft lifecycle dates, each linked to its source), update age, servers not restarted for `-PatchDays` days, pending restart, DNS record vs the server's real IP, IP not in any AD subnet. Stale and disabled computer objects are covered by Account Security.

The report keeps what AD gives for every server (OS version, lifecycle, roles registered in AD) apart from what could only be read from the servers that answered (hardware, installed roles, updates, services): the summary cards come in those two groups, sections built on the servers that were read say how many that is, and info tips (ⓘ) say where each figure comes from. Servers that could not be read show the reason in the server list instead of blank columns.

**Management access** explains the servers that could not be read, grouped by subnet and AD site: up but blocked (TCP 445 or 3389 answers while RPC 135 and WinRM 5985 do not, or 135 answers but the dynamic RPC ports don't), no answer at all, access denied, name not in DNS, timed out — with what to open or fix from the audit host. `Test-ServerAccess.ps1` runs the same tests on a list of servers from the console. `-IncludeActivation` adds the Windows activation channel (KMS, MAK, OEM…), which is slower to read.

Servers are inventoried 20 at a time (`-Throttle`) with a time limit per server (`-ServerTimeoutSec`, default 90 s), so a few hundred servers take minutes. Disabled servers, servers inactive in AD for more than `-StaleDays` (default 90) and non-Windows systems are listed from AD only and never contacted. A domain selector shows the whole forest or one domain at a time.

**Changes since an earlier run**: `-CompareWith` takes an earlier report (or a `.json` saved with `-ExportJson`) and adds a Changes section: servers new in AD or gone, servers read now and not before (after a firewall or permission change) or the reverse, Windows version changes, updates installed since, SQL Server instances added or removed, and every finding before and now. The summary cards show the change next to each figure, and each server's details list what changed for it. The earlier run's data is copied into the new report, so it stays readable on its own.

```powershell
.\scripts\AD-ServerInventory.ps1
.\scripts\AD-ServerInventory.ps1 -SearchBase "OU=Servers,DC=contoso,DC=com"
.\scripts\AD-ServerInventory.ps1 -SkipRemote          # from AD only, no connection to the servers
.\scripts\AD-ServerInventory.ps1 -CompareWith .\AD_ServerInventory_20261012_093000.html   # what changed since that run
.\scripts\Test-ServerAccess.ps1 -ComputerName app01.contoso.com, app02.contoso.com   # what blocks these servers
```

---

## Common parameters

Every module accepts:

| Parameter | Default | Description |
|---|---|---|
| `-OutputPath` | current directory | Folder to write the HTML report to |
| `-OpenReport` | `$true` | Open the report in the default browser when finished |

Some modules add their own (`-StaleDays` on Overview, `-ForestName`/`-ReplDelayIntraSiteHours`/`-ReplDelayInterSiteHours` on Topology, `-SkipHardware` on DC Inventory, `-InactiveDays`/`-StaleComputerDays`/`-ServiceAccountStalePasswordDays` on Account Security, `-TestConnectivity` on Trust Relationships, `-SkipExport`/`-GPONames` on GPO Policy Analyzer, `-SkipLiveTests`/`-Server` on DNS Health, `-DeepNestingThreshold`/`-SearchBase` on Group & OU Structure, `-EventDays`/`-SkipEvents`/`-SkipTime`/`-Throttle` on DC Posture, `-SearchBase`/`-StaleDays`/`-PatchDays`/`-Throttle`/`-ServerTimeoutSec`/`-IncludeActivation`/`-SkipRemote` on Server Inventory). Run `Get-Help .\scripts\<script>.ps1 -Full` for details.

> **Execution policy:** if a script is blocked, run it for the current process only:
> ```powershell
> powershell -ExecutionPolicy Bypass -File .\scripts\AD-Overview.ps1
> ```

---

## Requirements

| Requirement | Notes |
|---|---|
| Windows with **RSAT: Active Directory PowerShell** | `Import-Module ActiveDirectory` must work |
| **Domain-joined** machine (or one that can reach a DC) | Read-only AD queries |
| PowerShell **5.1+** | Windows PowerShell or PowerShell 7 |
| Account with **read access** to AD | No write operations are performed |

If the RSAT tools aren't installed yet, install the ones the modules use. Keep in mind they also install the GUI consoles, so prefer an admin workstation or a management server rather than a user's machine.

```powershell
# Windows 10 / 11
Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
Add-WindowsCapability -Online -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'   # GPO Policy Analyzer
Add-WindowsCapability -Online -Name 'Rsat.Dns.Tools~~~~0.0.1.0'                      # DNS Health (optional)

# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell, GPMC, RSAT-DNS-Server
```

For the richest per-DC detail (Topology and DC Inventory), the running account should be able to reach the DCs via **WinRM** or **WMI/DCOM**. When a DC can't be reached, the report degrades gracefully and shows the fields it could not collect as *unavailable* rather than failing.

**GPO Policy Analyzer** additionally requires the **GroupPolicy** module (RSAT-GPMC) to back up GPOs, and read access to SYSVOL. **DNS Health** benefits from the **DnsServer** module (RSAT-DNS) for full zone/server detail, but degrades to AD-only checks without it. **Account Security** needs read access to the Password Settings Container (Domain Admins by default, or a delegated read permission) to list fine-grained password policies. **DC Posture** reads registry values over CIM/DCOM and security event logs over RPC on every DC, so run it as a domain admin, or with Event Log Readers plus remote registry read granted on the DCs. **Server Inventory** needs local administrator rights on the servers and RPC/DCOM (or WinRM) access to them for the full inventory; without them, servers are still listed from AD.

---

## Sample reports

The [`examples/`](examples/) folder contains a sample HTML report for each module, built from **fictional data** (`corp.local`, `contoso.lab`, etc.). Open any of them in a browser to explore the interactive features without running anything.

---

## Read-only & safe to run

- Every module performs **read-only** AD and DC queries. Nothing is modified in Active Directory, Group Policy, or on any domain controller.
- The generated HTML is **fully self-contained and offline** — no external scripts, no trackers, no network calls when opened.
- Each module writes **only** its HTML report to your chosen `-OutputPath` (GPO Policy Analyzer also keeps the GPO backups it analyses). The all-in-one report uses a temporary run folder for the module reports and removes it when done, unless `-KeepModuleReports` is used or a module failed (its log is kept for troubleshooting).
- No credentials, passwords, or tokens are stored or transmitted.

The reports contain infrastructure and security-posture detail (domain/DC names, IPs, group memberships, password policy weaknesses, risky account lists, etc.), so treat them as confidential and store/share them accordingly.

---

## Part of a larger project

The nine modules and the all-in-one report make up the Active Directory Audit Suite. Additional modules covering other areas of AD health and security are in development and will be published here one by one, and added to the all-in-one report as they land.

Watch or ⭐ the repo to catch new modules as they land.

For more detail on the project direction, see [ROADMAP.md](ROADMAP.md).

---

## Acknowledgements

Thanks to [@red-erik](https://github.com/red-erik) for reporting the multi-domain orphaned-DC issue in Topology ([#1](../../issues/1)) and the fine-grained password policy permission issue in Account Security ([#2](../../issues/2)).

---

## License

Released under the [MIT License](LICENSE): free to use, modify and share, including commercially, as long as the copyright notice is kept.

---

## Author

**Mohamed ZEGHLACHE** — Hybrid Cloud & Systems Engineer.

If this is useful, a ⭐ on the repo is appreciated, and feedback / issues are welcome.
