# Changelog

All notable changes to this project are documented here.

## [1.11.1] — 2026-11-14

### Fixed
- **Overview, Topology, DC Inventory**: icons (CSV download, theme, print, section and card icons) were loaded from an internet CDN and did not show on machines without internet access, such as most domain controllers. They are now embedded in each report (Bootstrap Icons, MIT licence), and the reports load nothing from the internet, which also avoids a blank page while a blocked request times out. The Inter web font is no longer downloaded; the reports use Inter when it is installed and the system font otherwise.

## [1.11.0] — 2026-11-12

### Added
- **DC Posture**: LDAP client logging check in Protocols & hardening. It reads the LDAP interface event logging level on each domain controller and says whether the IP address and account of each unsigned or clear-text bind are recorded (event 2889). It is not needed once LDAP signing is required. The unsigned LDAP finding and the Security events note now name the domain controllers where this logging is off, instead of a general note.
- **DC Posture**: Security events list the clients still using old protocols: LDAPS without channel binding (event 3039), NTLMv1 logons (4624), Kerberos tickets issued with RC4 or DES (4768 / 4769), NTLM authentications (8004 when NTLM auditing is on, otherwise 4776, with workstation names) and SMBv1 clients (3000). Busy logs are filtered on the domain controller, so only the matching events are read. Where a domain controller does not log one of these (LDAP client logging, logon, Kerberos or credential validation auditing, NTLM auditing, SMBv1 access auditing), each list says what to turn on and where, and "nothing recorded" is not shown as a clean result. Each list raises a finding.
- **DC Posture**: in Security events, the event IDs of each list can be clicked for a description of the event (what it records, which audit setting writes it, link to the Microsoft documentation), and each row opens its full details with the description of its event.
- **DC Posture**: each event description also shows the real text of one such event, as Windows wrote it on a domain controller during the period (in the DC's language). The summary above it is labelled as the report's own explanation.

### Changed
- **DC Posture**: security events cover the last 30 days by default (was 7); `-EventDays` still sets it.
- **DC Posture**: security events are read much faster. Events are filtered on each domain controller and only their data is fetched; the full message text, which Get-WinEvent formats for every event at the cost of an extra round trip each over the network, is no longer built.

### Fixed
- **DC Posture, Server Inventory**: Exchange servers were also counted from their transport configuration objects ("Mailbox" and "Frontend" under each server), so one Exchange server showed as three in the Windows Server 2025 readiness check. Only the server objects are read now.

## [1.10.0] — 2026-11-10

### Added
- **Server Inventory — changes since an earlier run**: `-CompareWith` takes an earlier report (or a data file saved with the new `-ExportJson`) and adds a Changes section: servers new in AD or gone, servers read now and not before or the reverse, Windows version changes, updates installed since, SQL Server instances added or removed, and each finding before and now. Summary cards show the change next to each figure, and each server's details list what changed for it.
- **Server Inventory**: servers not restarted for `-PatchDays` days are flagged (updates installed since the last boot are not active yet), and uptime shows in the server list and in Updates & restart.
- **Server Inventory**: a "Windows out of support" summary card, from the operating system recorded in AD.

### Removed
- **Server Inventory**: the AD cleanup section and the stale and disabled server findings, already covered by Account Security. Stale and disabled servers stay in the server list, with the reason they were not contacted.

## [1.9.0] — 2026-11-08

### Added
- **Server Inventory** (`AD-ServerInventory.ps1`, standalone): every server in the forest, from AD and from each server. Hardware (manufacturer, model, physical or virtual, serial, sockets/cores, memory), Windows edition and build, roles and features, SQL Server instances, failover clusters and their roles, last update and pending restart, services running under domain accounts, AD site, DNS consistency, and stale or disabled server objects. Windows Server and SQL Server end-of-support status from the Microsoft lifecycle dates. Optional `-IncludeActivation` (Windows activation channel). Servers are inventoried in parallel with a time limit per server.
- **Server Inventory — management access**: for the servers that could not be read, the report tells a server that is up but blocked (SMB or RDP answers, RPC and WinRM don't, or the dynamic RPC ports are closed) from one that does not answer, an access-denied account, a DNS failure or a timeout, and groups them by subnet and AD site with what to open from the audit host.
- **Test-ServerAccess** (`Test-ServerAccess.ps1`): the same DNS, port, DCOM and WinRM tests for a list of servers, with a verdict per server.

### Changed
- **Server Inventory**: the summary cards are split into what AD gives for every server and what was read from the servers that answered; sections built on the servers that were read say how many that is; info tips say where each figure comes from; servers that could not be read show the reason instead of blank columns.

### Fixed
- **DC Posture**: the report data is written by the script's own JSON writer. The .NET serializer could spend a very long time on PowerShell-wrapped values before failing, which made some runs take many minutes longer than the checks themselves.
- **Server Inventory**: summary cards show Windows Server and SQL Server versions (coloured by support status, click to filter); the report is scaled down to fit more on screen.
- **Server Inventory**: the Roles chart leaves out the features Windows installs on every server (they stay listed in each server's details), file-server role services are read, and SQL Server instances with no update installed are flagged.
- **Server Inventory**: same JSON fix; DCOM connections (wrong session options) and servers reachable only over WinRM; the console shows the elapsed time at each step.

## [1.8.0] — 2026-11-08

### Changed
- **DC Posture**: covers every domain in the forest. Domain controllers, DES-only accounts, security events, time sync, partition backups, SYSVOL replication and domain functional levels are collected per domain, and the report has a domain selector to show the whole forest or one domain at a time.
- **DC Posture**: domain controllers are checked several at a time (settings, event logs, time sync) on Windows PowerShell 5.1. New `-Throttle` parameter (default 10; 1 checks them one by one).
- **DC Posture**: time sync follows the forest hierarchy. Only the forest-root PDC emulator should use external NTP, a child-domain PDC set to manual NTP is flagged, and each DC's offset is measured against the PDC of its own domain.
- **DC Posture**: no longer reads every user and computer in the domain. Those queries (accounts without AES keys, RC4-only accounts, legacy systems) were no longer shown in the report and made it slow in large domains.

### Fixed
- **DC Posture**: the port test resolves the DC name once and tries each IPv4 address, so a slow DNS answer or a stale record no longer makes a reachable DC look unreachable.
- **DC Posture**: event logs with no matching events are recognised on non-English Windows too.

## [1.7.1] — 2026-10-12

### Fixed
- **All-in-one report**: clicking a section link in Account security (Password Policy, krbtgt, LAPS…) loaded the whole suite inside the module pane. In-page links now scroll within the module report, and external links open in a new tab, for every module.
- **Account Security**: side navigation scrolls to the section directly instead of relying on `#` links, so it also works when the report is embedded elsewhere.

## [1.7.0] — 2026-10-11

### Added
- **All-in-one report** (`AD-AuditSuite.ps1`) — runs every module (each in its own PowerShell process, with a per-module timeout) and combines the results into a single interactive report: a dashboard with findings by severity and module, domain controller health, Windows Server 2025 readiness, security events, account, Group Policy, DNS and recovery figures and the top priorities; search across all findings; every module's full report in the same file; and a findings PDF (executive summary, per-area narrative, recommendations, prioritised remediation plan, methodology). Supports `-Modules`/`-Skip`, `-ModuleArguments`, `-TimeoutMinutes`, `-ForestName` (passed to Topology) and `-RebuildFrom` to rebuild the report from an earlier run without re-running the modules.

## [1.6.0] — 2026-10-07

### Added
- **Topology**: trusts to other forests and external domains are shown on the forest card and in its detail panel.
- **Topology**: optional `-ForestName` parameter to report on another (trusted) forest; defaults to the current forest. All forest-level queries (configuration partition, sites, site links, subnets) follow it.

### Fixed
- **Topology**: orphaned DC metadata is now checked against the DCs of every domain in the forest; DCs in child domains were wrongly reported as orphaned ([#1](../../issues/1), thanks @red-erik).
- **DNS Health**: lingering DC record detection now compares the forest-wide `_msdcs` zone against the DCs of every domain, so child-domain DCs are no longer flagged as removed.
- **Account Security**: when fine-grained password policies cannot be read (the Password Settings Container is readable by Domain Admins by default), the report now says they **could not be verified** instead of reporting that none exist ([#2](../../issues/2), thanks @red-erik).
- **Account Security, DNS Health, Trust Relationships**: corrected the script names used in the help examples ([#2](../../issues/2)).
- **Group & OU Structure**: the IDFix scan no longer fails in forests whose schema doesn't define some of the scanned attributes (e.g. `mailNickname`, `targetAddress`); those attributes are skipped and listed as not checked.

### Changed
- **Topology**: the orphaned-metadata fix text now describes the action instead of listing commands.

### Documentation
- README: project badges, RSAT install commands, updated module descriptions, acknowledgements.
- Added an MIT license.
- Roadmap: all-in-one report status and updated design principles.

## [1.5.0] — 2026-10-07

### Added
- **DC Posture** (`AD-DCPosture.ps1`) — new module covering per-DC protocol/hardening checks (LDAP signing & channel binding, LDAPS certificate, NTLM level/auditing, LM hash storage, SMB signing/SMBv1, SSL/TLS versions, LLMNR, NetBIOS, WDigest, LSA protection, Kerberos encryption types, Print Spooler, DES-only accounts), security events over the last N days (lockouts, failed logons with password-spray detection, Kerberos pre-auth failures, privileged group changes, cleared audit logs, unsigned/clear-text LDAP binds), time-sync hierarchy, backup & recovery readiness (Recycle Bin, tombstone lifetime, last backup, SYSVOL replication), and Windows Server 2025 readiness based on Microsoft-documented requirements (functional levels, DC versions, SYSVOL on DFSR, DES and NTLMv1 removal, Exchange support), each linked to its Microsoft source. Reads registry over CIM/DCOM and event logs over RPC; no WinRM required.
- **Account Security**: flags accounts (and krbtgt) with no AES keys because their password predates the domain's AES support — relevant to the Kerberos AES-only hardening (CVE-2026-20833).
- **GPO Policy Analyzer**: conflicts are now cross-checked against WMI filters — if a disagreeing GPO only applies when its WQL query is true, the report notes the conflict may never reach the same computer.

### Fixed
- **DC Inventory, Topology, DNS Health**: DC/host reachability no longer relies on ICMP ping alone (often blocked on domain controllers) — falls back to probing core DC/DNS ports (389/88/135/445/9389, or 53/389/88/135/445 for DNS). DC Inventory and Topology relabel "Online/Offline" as "Reachable/Unreachable" to match.

## [1.4.0] — 2026-09-28

### Added
- **GPO Policy Analyzer** (`GPO-PolicyAnalyzer.ps1`) — new module that backs up every GPO in the domain, parses `Registry.pol`/`GptTmpl.inf` directly from the backups (no `Get-GPOReport`, no RSOP), resolves settings to friendly names via ADMX/ADML, and pivots everything into one comparison grid that flags any setting where GPOs disagree. `-SkipExport` re-analyzes existing backups instantly.
- **DNS Health** (`AD-DNSHealth.ps1`) — new module reviewing DNS configuration (zone type, AD-integration, dynamic updates, aging/scavenging, zone transfers, DNSSEC, NS records) per zone and per server, plus live per-DC resolution health (forward/reverse/forwarder resolution, record registration, `dcdiag /test:DNS`) and lingering DC record detection.
- **Group & OU Structure** (`AD-GroupOUStructure.ps1`) — new module combining a recursive group-nesting graph (circular-nesting, empty-group, deep-nesting, large-membership detection), an OU hierarchy view with per-OU counts and a tiering-model recommendation, and an IDFix reimplementation that scans for attributes breaking Entra ID/M365 sync.

## [1.3.0] — 2026-08-08

### Added
- **Trust Relationships** (`AD-TrustRelationships.ps1`) — new module enumerating every AD trust and assessing its security posture: partner domain, direction, trust type, and transitivity; SID filtering, selective authentication, TGT delegation, and forest-transitive flags; a per-trust connectivity probe that degrades gracefully when a partner is unreachable; and derived risk findings (SID filtering disabled on an external/forest trust, selective auth off, stale trusts). Includes KPI tiles, a filterable trust explorer with detail panel, and an interactive trust map.

## [1.2.0] — 2026-08-03

### Added
- **Account Security** (`AD-AccountSecurity.ps1`) — new module covering default password & lockout policy (scored against a recommended baseline), fine-grained password policies (PSOs), managed service accounts (gMSA/sMSA), LAPS coverage (Windows and Legacy), LAPS read-delegation audit, risky user accounts (password-never-expires, password-not-required, unconstrained delegation, SID history, inactive-but-enabled, stale service-account passwords), risky computer accounts (stale logons, old machine passwords, legacy/EOL OS, unconstrained delegation), and krbtgt password age. Long lists stay off the main page behind per-category "Open" (full-page view) and CSV-download actions.

## [1.1.0] — 2026-07-10

### Added
- **Topology** now includes two analysis panels, opened from the toolbar:
  - **Replication Health Matrix** — directional source → destination grid of every DC replication partnership, from the metadata AD already tracks (last success, error code, consecutive failures). Click a failing cell for the specific error. Passive, no probing.
  - **Stale / Lingering Objects** — read-only scan of the Configuration partition and Sites & Services for orphaned DC metadata, empty sites, sites without subnets, unlinked subnets, and lingering replication connections, each with remediation guidance.
- **Overview**: CSV-download buttons on the account, computer, and group stat cards (exports the underlying object list straight from the report).

### Changed
- Unified the light theme across all three modules (shared indigo accent, backgrounds, typography); Topology now defaults to the light theme like the others.

## [1.0.0] — 2026-07-04

Initial public release of the Active Directory Audit Suite with three modules:

- **Overview** (`AD-Overview.ps1`) — forest & domain facts, object inventory, account posture, OS distribution, group breakdown.
- **Topology** (`AD-Topology.ps1`) — forest/domain/site/DC hierarchy with health, FSMO roles, services, replication links, dcdiag.
- **DC Inventory** (`AD-DCInventory.ps1`) — per-DC inventory plus hardware & performance specifications.

Each module is a standalone PowerShell script that produces a single self-contained, interactive HTML report. A sample report for every module (built from fictional data) is included in `examples/`.
