# Roadmap

This repository is the beginning of a broader **Active Directory Audit Suite**.

## Shipped modules

Overview, Topology, DC Inventory, Account Security, Trust Relationships, GPO Policy Analyzer, DNS Health, Group & OU Structure, and DC Posture. Additional modules covering other areas of AD health and security are in development and will be added to this repository one by one as they are ready.

## Coming next: the all-in-one report

The end goal is a single orchestrator script that runs all modules together and produces one comprehensive AD audit report. It is in active development and testing, and will bring:

- A visual dashboard summarising every module (findings by severity and area, DC health, top priorities)
- Every module's full report in one offline file, one section at a time
- A findings report exported as a structured PDF, with recommendations and a prioritised remediation plan
- Isolated module runs, so one failing module never stops the others

## Design principles

Every module follows the same pattern:

- **One script, one HTML file.** No agents, no install, no dependencies beyond the AD PowerShell module (a couple of modules need one extra RSAT component for their specific area — GPO Policy Analyzer needs GroupPolicy, DNS Health benefits from DnsServer).
- **Read-only.** Nothing is modified in AD or on any DC.
- **Self-contained output.** The HTML report works fully offline.
- **Forest-aware.** Forest-wide checks cover the DCs of every domain in the forest, not just the current one.
- **Actionable findings.** Every finding comes with a recommendation describing what to do, and readiness checks are based on Microsoft's own documentation, with links to the source.
- **Honest results.** If something cannot be queried, the report shows what it could collect and says what it could not verify (an unreachable DC is "unreachable", not "down"; unreadable policies are "not verified", not "none").
- **Distinct visual identity.** Each module has its own look so reports are instantly recognisable.

Watch or ⭐ the repo to catch new modules and updates as they land.
