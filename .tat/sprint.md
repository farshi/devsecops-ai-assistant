# Sprint 4 — Remediation + PR Review + PyPI

**Goal:** PatchPilot tells you what to change, catches new issues in PRs, installable via `pip install patchpilot`.
**Date:** 2026-03-31

## Relevant Constraints
- **ADR-001 (Plugin architecture)** — Fix suggestions should be implementable as a plugin if needed later
- **ADR-003 (Reachability honesty)** — Fix suggestions must reflect confidence. Don't suggest breaking upgrades without warning.
- **ADR-005 (Triage layer, not platform)** — Review command should be thin: flag risky changes, not full semantic PR analysis
- **ADR-008 (Vision evolution)** — Fix suggestions are v0.2-v0.3 scope. Auto-remediation (applying fixes) is v0.3+. We SUGGEST, not auto-apply.
- **Lesson 7** — Package→import name mismatch affects fix suggestions too. Use the mapping.
- **Lesson 10** — Plugin architecture: define interfaces early, implement late. Fix suggestions don't need a new ABC.
- **Lesson 14** — Scoring gaps for os_package/iac. Fix suggestions should handle "no fix available" gracefully.
- **Lesson T7** — Show what was built before asking for approval.

## Scope
| # | Task | Epic |
|---|------|------|
| 16 | 5.2 Context-aware fix suggestions | E5 |
| 17 | 5.3 Review command for PR diffs | E5 |
| 18 | R.5 PyPI publish + release process | Release |
| 19 | R.6 Fix suggestion guardrails | Release |

## Out of Scope
- New scanners (Checkov, Gitleaks, Semgrep)
- Auto-remediation (applying fixes automatically)
- Dashboards, Slack, ticket creation
- SBOM export
- Compliance mapping beyond existing CRA

## Risks
1. **Fix suggestion quality** — LLM might suggest wrong versions or breaking changes. Mitigation: guardrails + confidence levels + "SUGGESTION, not auto-patch" framing.
2. **PyPI namespace** — "patchpilot" might be taken. Mitigation: check availability, have backup names.
3. **Review command scope creep** — Could become a full SAST tool. Mitigation: keep it thin — diff analysis only, reuse existing scoring.

## Definition of Done
- All tasks shipped with review artifacts
- Tests pass (expect 280+)
- CHANGELOG updated for v0.3.0
- `pip install patchpilot` from PyPI works
- `patchpilot triage --path . --fix` shows fix suggestions
- `patchpilot review --diff` flags risky changes
- v0.3.0 tagged + released
