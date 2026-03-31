# PatchPilot — Claude Code Instructions

## What This Project Is
PatchPilot is a Python CLI tool for smart vulnerability triage. It sits between security scanners (Trivy) and developers, turning 200+ CVEs into "fix these 3 things this week" using reachability analysis, EPSS, KEV, and a deterministic scoring model. Plugin architecture for extensibility.

## Development Rules
- Read `.tat/plan.md` for current sprint and task state
- One task = one branch = one PR
- Branch naming: `tat/<epic>/<task-name>` or `tat/release/<task-name>`
- Conventional commits: `feat(cli):`, `fix(scoring):`, `test(workflow):`, `docs(plan):` etc
- Commit-msg hook enforces format — allowed scopes: skill, review, plan, config, workflow, install, hooks
- `.tat/` metadata (plan, lessons, decisions) can be committed directly on main
- Code changes must go through branches + PRs

## Project Structure
- `cli.py` — Click CLI: scan, triage, report, analyze, plan, review
- `agent/models.py` — Canonical Finding dataclass (ADR-002)
- `agent/context_builder.py` — Repo detection, deps, reachability, context bundle
- `agent/prioritizer.py` — Triage engine: scoring + ranked output
- `agent/scan.py` — Scan orchestrator
- `agent/security_summary.py` — Report generator (Claude)
- `agent/plugins/base.py` — Plugin ABCs (ADR-001)
- `agent/plugins/scanners/trivy.py` — Trivy scanner adapter
- `agent/plugins/enrichment/` — EPSS, KEV, fix availability plugins
- `agent/plugins/scoring/default.py` — Weighted scoring model
- `prompts/` — System prompts for Claude
- `tests/` — 171 pytest tests
- `docs/` — Concepts glossary, spec-docs mapping
- `.tat/` — TAT state: spec, plan, decisions, lessons, alignment log
- `sample_app/` — Clean FastAPI demo
- `vulnerable_app/` — Intentionally vulnerable demo for triage demos

## Key Patterns
- Scanner output → `reports/<target>_<scanner>_<date>.json`
- Summary → `reports/<target>_summary_<date>.json`
- Triage → `reports/<target>_triage_<date>.md` + `.json`
- Reports → `reports/<target>_security-report_<date>.md`
- Version defined in `agent/__init__.py` (single source of truth)
- Plugin interfaces: ScannerAdapter, EnrichmentPlugin, PrioritizationStrategy, OutputFormatter

## Important ADRs
- ADR-002: Finding schema — all modules use canonical Finding dataclass
- ADR-003: Reachability honesty — "unknown" over false confidence
- ADR-004: Finding type classifier — os_package vs language_dep
- ADR-005: Competitive positioning — triage layer, not platform
