# ADR-001: Plugin Architecture for Extensibility

## Context
PatchPilot should be extensible so that:
- We can outsource parts of the system (scanners, evidence collectors, report formats)
- End users and their teams can write their own plugins
- Example: a team using AWS/GCP wants to collect cloud evidence to enrich IaC scanner findings for better resolution
- We're not building a CSPM, but users should be able to extend PatchPilot to pull in cloud posture data if they want

## Options Considered
1. **Monolithic** — all scanners, reporters, prioritizers built-in. Simple but rigid.
2. **Plugin system with registry** — define interfaces (Scanner, EvidenceCollector, Reporter, Prioritizer), let anyone implement them. Register via config or entry points.
3. **Full microservice/API** — over-engineered for a CLI tool.

## Decision
Option 2: Plugin architecture with well-defined interfaces.

## Rationale
- Core PatchPilot stays lean (Trivy + basic context + prioritizer)
- Community can add: new scanners (Checkov, Semgrep), evidence collectors (AWS SecurityHub, GCP SCC), report formats (CRA, SOC2), custom prioritization rules
- Uses Python entry points or a simple plugin directory — no framework overhead
- Aligns with open-source-core monetization: free plugins for community, premium plugins or hosted service for revenue

## Status
PROPOSED — pending spec update and GPT review
