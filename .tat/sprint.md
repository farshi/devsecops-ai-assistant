# Sprint 3 — Credibility + Features

**Goal:** Make PatchPilot credible for real adoption — LLM-enhanced reports, configurable behavior, CRA compliance, and state tracking so repeated scans don't re-surface dismissed findings.
**Date:** 2026-03-31

## Relevant Constraints
- **ADR-002 (Finding schema)** — All new features must operate on canonical Finding dataclass. No bypassing the schema.
- **ADR-003 (Reachability honesty)** — LLM narrative must NOT override algorithmic ranking. LLM explains, it doesn't re-rank.
- **ADR-005 (Competitive positioning)** — Stay triage layer, not platform. Config should be simple, not enterprise-grade.
- **ADR-008 (Vision evolution)** — CRA compliance is v0.1-v0.2 scope. Don't expand into full GRC.
- **Lesson 4** — Separate docs from code on branches. Keep PRs focused.
- **Lesson 6** — Reachability honesty > coverage. LLM narrative should surface confidence levels honestly.
- **Lesson 13** — Finding.fingerprint() needed before state tracking (task 4.3). Add this first.
- **Lesson 14** — Scoring model has unresolved input gaps for os_package and iac_misconfig. Don't promise what we can't compute.
- **Lesson 16** — Don't force-override hooks. Fix root causes.

## Scope
| # | Task | Epic |
|---|------|------|
| 1 | 3.3b LLM narrative enhancement | E3 |
| 2 | 4.4 Config and policy | E4 |
| 3 | 4.2 CRA disclosure format | E4 |
| 4 | 4.3 State and baseline tracking | E4 |
| 5 | 5.1 LLM provider abstraction | E5 |
| 6 | 7.2-7.4 Remaining docs | E7 |
| 7 | 6.2 GitHub Actions template | E6 |

## Out of Scope
- Dashboard / web UI (ADR-005: CLI-first)
- Auto-remediation / patch generation (ADR-008: v0.3+)
- Additional scanners (Checkov, Gitleaks, Semgrep) — backlog
- Security metrics / trends — backlog
- Guardrail design mode — backlog
- Risk dashboards — backlog

## Risks
1. **LLM narrative quality** — Claude's explanations might be generic. Mitigation: provide rich context (reachability evidence, EPSS score, fix details) in the prompt so Claude can be specific.
2. **CRA format ambiguity** — EU CRA reporting format not fully standardized yet. Mitigation: follow CSAF/VEX patterns, make it a plugin (OutputFormatter) so format can evolve.
3. **State tracking complexity** — Finding fingerprint + baseline diffing is tricky. Mitigation: start simple (CVE+package+version hash), iterate. Lesson 13 says do fingerprint first.
4. **LLM provider abstraction scope creep** — Could become over-engineered. Mitigation: thin wrapper only, Claude + GPT, no framework.

## Definition of Done
- All tasks shipped with review artifacts
- Tests pass (currently 171, expect 200+)
- CHANGELOG updated for v0.2.0
- docs/ updated per MAP.md traceability
- `patchpilot triage` still works end-to-end after all changes
- Config file documented in README
- CRA report format documented in docs/concepts.md
