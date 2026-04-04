# PatchPilot

## The Problem

Security scanners produce noise. Trivy finds 200 CVEs. Developers see the wall of alerts and either ignore everything or fix random things. Meanwhile, AI can generate fixes — but deciding WHAT to fix, in WHAT order, and WHY is the hard part.

## What PatchPilot Does

Triage brain between your scanner and your team. Takes raw scanner output and turns it into a prioritized, context-aware action plan.

```
Scanner output (Trivy/Checkov/Semgrep/SARIF)
    → PatchPilot reads your codebase context
    → Checks reachability, exploitability, fix availability
    → Scores and ranks by what actually matters
    → "Fix these 3 things. Here's why. Here's how."
```

## Target User

Small engineering teams (2-15 devs) without a dedicated security engineer. Startup CTOs who "own" security by default.

## Core Principles

1. **Signal over noise** — fewer, better recommendations
2. **Context is king** — a CVE in unused code ≠ a CVE in your auth module
3. **Zero friction** — under 60 seconds to value
4. **Honest confidence** — "unknown" over false certainty
5. **Cumulative memory** — learns from past triage decisions

## Architecture

- **CLI:** Python + Click
- **Scanners:** Trivy, Checkov, Gitleaks, Semgrep, generic SARIF adapter
- **Enrichment:** EPSS, KEV, fix availability
- **Scoring:** Weighted model (reachability 25%, EPSS 15%, KEV 15%, CVSS 20%, fix 15%, direct dep 10%)
- **Output:** Markdown triage, PR comments, GitHub Issues, weekly digest, executive summary
- **Compliance:** EU CRA (with deadline tracking), SOC2, ISO 27001, CycloneDX + SPDX SBOMs
- **State:** File-based in `.patchpilot/` (no database, no backend)
- **Plugin system:** ScannerAdapter, EnrichmentPlugin, PrioritizationStrategy, OutputFormatter ABCs

## Constraints

- Python CLI (Click framework)
- LLM APIs (Claude + GPT) — user provides own keys
- CLI + file output + CI integration only
- File-based state (.patchpilot/)

## DynoTrust (separate repo)

Commercial compliance dashboard built on PatchPilot. Separate brand, separate repo.
Full spec: `.tat/dashboard-dynotrust.md`
