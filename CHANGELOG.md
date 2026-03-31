# Changelog

## v0.1.0 (2026-03-31)

First public release. Smart vulnerability triage for developers.

### Features
- **Triage command** — `patchpilot triage --path . --target-name myapp` runs the full pipeline
- **Scoring model** — deterministic weighted formula ranking by reachability (25%), EPSS, KEV, CVSS, fix availability, dependency depth
- **Reachability analysis** — checks if vulnerable packages are actually imported in Python source code
- **EPSS enrichment** — fetches 30-day exploitation probability from FIRST.org
- **KEV enrichment** — checks CISA Known Exploited Vulnerabilities catalog
- **Fix availability** — assesses version bump type (patch/minor/major) and effort
- **CI gating** — `--fail-on critical|high|medium|low` returns exit code 1 for CI pipelines
- **Plugin architecture** — extensible via 4 ABCs: ScannerAdapter, EnrichmentPlugin, PrioritizationStrategy, OutputFormatter
- **Trivy adapter** — built-in scanner adapter with finding type classification (os_package vs language_dep)
- **Context builder** — repo structure detection, dependency extraction, token budgeting
- **AI-enhanced reports** — `patchpilot report --path .` sends triage data to Claude for enhanced action plans

### Infrastructure
- `pip install .` with `patchpilot` CLI entry point
- 171 tests passing
- Vulnerable sample app for demos (`vulnerable_app/`)
- Glossary and concepts documentation (`docs/concepts.md`)
- 8 ADRs documenting architectural decisions
- Spec-to-docs traceability map (`docs/MAP.md`)

### Architecture Decisions
- ADR-001: Plugin architecture for extensibility
- ADR-002: Canonical Finding schema as shared contract
- ADR-003: Reachability honesty — "unknown" over false confidence
- ADR-004: Finding type classifier — scope reachability correctly
- ADR-005: Competitive positioning — triage layer, not platform
- ADR-006: Alignment log for drift tracking
- ADR-007: Spec-to-docs traceability mapping
- ADR-008: Vision evolution — from scanner triage to security engineer assistant
