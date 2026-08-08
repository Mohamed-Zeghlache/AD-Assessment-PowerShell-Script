# Roadmap

This repository is the beginning of a broader **Active Directory Audit Suite**.

Overview, Topology, DC Inventory, Account Security, and Trust Relationships are the modules shipped so far. Additional modules covering other areas of AD health and security are in development and will be added to this repository one by one as they are ready.

The end goal is a single orchestrator script that runs all modules together and produces a comprehensive AD audit report.

## Design principles

Every module follows the same pattern:

- **One script, one HTML file.** No agents, no install, no dependencies beyond the AD PowerShell module.
- **Read-only.** Nothing is modified in AD or on any DC.
- **Self-contained output.** The HTML report works fully offline.
- **Graceful degradation.** If something can not be queried, the report shows what it could collect rather than failing.
- **Distinct visual identity.** Each module has its own look so reports are instantly recognisable.

Watch or ⭐ the repo to catch new modules and updates as they land.
