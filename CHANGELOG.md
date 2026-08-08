# Changelog

All notable changes to this project are documented here.

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
