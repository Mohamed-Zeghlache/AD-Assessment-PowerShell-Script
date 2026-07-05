# Changelog

All notable changes to this project are documented here.

## [1.0.0] — 2026-07-04

Initial public release of the Active Directory Audit Suite with three modules:

- **Overview** (\`AD-Overview.ps1\`) — forest & domain facts, object inventory, account posture, OS distribution, group breakdown.
- **Topology** (\`AD-Topology.ps1\`) — forest/domain/site/DC hierarchy with health, FSMO roles, services, replication links, dcdiag.
- **DC Inventory** (\`AD-DCInventory.ps1\`) — per-DC inventory plus hardware & performance specifications.

Each module is a standalone PowerShell script that produces a single self-contained, interactive HTML report. A sample report for every module (built from fictional data) is included in \`examples/\`.
