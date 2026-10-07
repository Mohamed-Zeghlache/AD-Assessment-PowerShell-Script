# Changelog

All notable changes to this project are documented here.

## [1.5.0] — 2026-10-07

### Added
- **DC Posture** (\`AD-DCPosture.ps1\`) — new module covering per-DC protocol/hardening checks (LDAP signing & channel binding, LDAPS certificate, NTLM level/auditing, LM hash storage, SMB signing/SMBv1, SSL/TLS versions, LLMNR, NetBIOS, WDigest, LSA protection, Kerberos encryption types, Print Spooler, DES-only accounts), security events over the last N days (lockouts, failed logons with password-spray detection, Kerberos pre-auth failures, privileged group changes, cleared audit logs, unsigned/clear-text LDAP binds), time-sync hierarchy, backup & recovery readiness (Recycle Bin, tombstone lifetime, last backup, SYSVOL replication), and Windows Server 2025 / AES-key readiness. Reads registry over CIM/DCOM and event logs over RPC; no WinRM required.
- **Account Security**: flags accounts (and krbtgt) with no AES keys because their password predates the domain's AES support — relevant to the Kerberos AES-only hardening (CVE-2026-20833).
- **GPO Policy Analyzer**: conflicts are now cross-checked against WMI filters — if a disagreeing GPO only applies when its WQL query is true, the report notes the conflict may never reach the same computer.

### Fixed
- **DC Inventory, Topology, DNS Health**: DC/host reachability no longer relies on ICMP ping alone (often blocked on domain controllers) — falls back to probing core DC/DNS ports (389/88/135/445/9389, or 53/389/88/135/445 for DNS). DC Inventory and Topology relabel "Online/Offline" as "Reachable/Unreachable" to match.

## [1.4.0] — 2026-09-28

### Added
- **GPO Policy Analyzer** (\`GPO-PolicyAnalyzer.ps1\`) — new module that backs up every GPO in the domain, parses \`Registry.pol\`/\`GptTmpl.inf\` directly from the backups (no \`Get-GPOReport\`, no RSOP), resolves settings to friendly names via ADMX/ADML, and pivots everything into one comparison grid that flags any setting where GPOs disagree. \`-SkipExport\` re-analyzes existing backups instantly.
- **DNS Health** (\`AD-DNSHealth.ps1\`) — new module reviewing DNS configuration (zone type, AD-integration, dynamic updates, aging/scavenging, zone transfers, DNSSEC, NS records) per zone and per server, plus live per-DC resolution health (forward/reverse/forwarder resolution, record registration, \`dcdiag /test:DNS\`) and lingering DC record detection.
- **Group & OU Structure** (\`AD-GroupOUStructure.ps1\`) — new module combining a recursive group-nesting graph (circular-nesting, empty-group, deep-nesting, large-membership detection), an OU hierarchy view with per-OU counts and a tiering-model recommendation, and an IDFix reimplementation that scans for attributes breaking Entra ID/M365 sync.

## [1.3.0] — 2026-08-08

### Added
- **Trust Relationships** (\`AD-TrustRelationships.ps1\`) — new module enumerating every AD trust and assessing its security posture: partner domain, direction, trust type, and transitivity; SID filtering, selective authentication, TGT delegation, and forest-transitive flags; a per-trust connectivity probe that degrades gracefully when a partner is unreachable; and derived risk findings (SID filtering disabled on an external/forest trust, selective auth off, stale trusts). Includes KPI tiles, a filterable trust explorer with detail panel, and an interactive trust map.

## [1.2.0] — 2026-08-03

### Added
- **Account Security** (\`AD-AccountSecurity.ps1\`) — new module covering default password & lockout policy (scored against a recommended baseline), fine-grained password policies (PSOs), managed service accounts (gMSA/sMSA), LAPS coverage (Windows and Legacy), LAPS read-delegation audit, risky user accounts (password-never-expires, password-not-required, unconstrained delegation, SID history, inactive-but-enabled, stale service-account passwords), risky computer accounts (stale logons, old machine passwords, legacy/EOL OS, unconstrained delegation), and krbtgt password age. Long lists stay off the main page behind per-category "Open" (full-page view) and CSV-download actions.

## [1.1.0] — 2026-07-10

### Added
- **Topology** now includes three analysis panels, opened from the toolbar:
  - **Replication Health Matrix** — directional source → destination grid of every DC replication partnership, from the metadata AD already tracks (last success, error code, consecutive failures). Click a failing cell for the specific error. Passive, no probing.
  - **Stale / Lingering Objects** — read-only scan of the Configuration partition and Sites & Services for orphaned DC metadata, empty sites, sites without subnets, unlinked subnets, and lingering replication connections, each with remediation guidance.
- **Overview**: CSV-download buttons on the account, computer, and group stat cards (exports the underlying object list straight from the report).

### Changed
- Unified the light theme across all three modules (shared indigo accent, backgrounds, typography); Topology now defaults to the light theme like the others.

## [1.0.0] — 2026-07-04

Initial public release of the Active Directory Audit Suite with three modules:

- **Overview** (\`AD-Overview.ps1\`) — forest & domain facts, object inventory, account posture, OS distribution, group breakdown.
- **Topology** (\`AD-Topology.ps1\`) — forest/domain/site/DC hierarchy with health, FSMO roles, services, replication links, dcdiag.
- **DC Inventory** (\`AD-DCInventory.ps1\`) — per-DC inventory plus hardware & performance specifications.

Each module is a standalone PowerShell script that produces a single self-contained, interactive HTML report. A sample report for every module (built from fictional data) is included in \`examples/\`.
