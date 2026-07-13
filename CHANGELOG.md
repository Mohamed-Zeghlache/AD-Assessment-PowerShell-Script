# Changelog

All notable changes to this project are documented here.

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
