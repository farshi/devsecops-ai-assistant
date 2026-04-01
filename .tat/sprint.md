# Sprint 5 — Daily Driver (v0.4.0)

**Goal:** PatchPilot becomes part of the daily workflow — secret detection, actionable tickets, ownership routing, compliance SBOM, trend tracking.
**Date:** 2026-04-01

## Relevant Constraints

### From ADRs
- **ADR-001** (Plugin architecture) — Gitleaks must implement ScannerAdapter ABC
- **ADR-002** (Finding schema) — Secret findings must use canonical Finding with finding_type="secret"
- **ADR-004** (Type classifier) — Secret findings get reachable="not_applicable"
- **ADR-005** (Positioning) — Ticket creation stays thin, not project management
- **ADR-007** (Docs mapping) — New features need docs/MAP.md updates

### From Project Lessons
- **Lesson 10** — Plugin architecture: follow TrivyScannerAdapter pattern for Gitleaks
- **Lesson 13** — Finding.fingerprint() already exists — use it for ticket dedup
- **Lesson T7** — Show deliverables before asking approval

### From Global Lessons
- **GL-01** — Run code review after every task
- **GL-04** — Self-review before GPT review — always
- **GL-09** — Don't chain gh pr merge commands (GitHub 502s)
- **GL-11** — In auto-mode, announce what you're doing
- **GL-16** — Show deliverables before asking for approval
- **GL-17** — Auto-mode must not skip checkpoints

## Scope
| # | Task | Epic |
|---|------|------|
| 20 | Gitleaks scanner integration | E8 |
| 21 | Ticket creation (GitHub Issues from triage) | E8 |
| 22 | Finding ownership (git blame/CODEOWNERS) | E8 |
| 23 | SBOM export (CycloneDX) | E8 |
| 24 | Historical trend tracking | E8 |

## Out of Scope
- Checkov / Semgrep (next sprint)
- Auto-remediation
- Dashboards / web UI
- Slack notifications
- Policy-as-code generation

## Risks
1. **Gitleaks output format** — May vary across versions. Mitigation: target latest stable JSON.
2. **GitHub Issues API** — Needs GITHUB_TOKEN. Mitigation: use `gh` CLI, clear error if missing.
3. **git blame performance** — Slow on large repos. Mitigation: only blame files with findings, cap at 20 files.
4. **SBOM scope** — CycloneDX is a big spec. Mitigation: minimal SBOM from dependency extraction, not full spec compliance.
5. **OpenAI API key** — Currently invalid. Mitigation: GPT reviews deferred, proceed with Opus self-review. Fix key before next session.

## Definition of Done
- All tasks shipped with review artifacts
- Tests pass (expect 330+)
- CHANGELOG updated for v0.4.0
- `patchpilot triage` shows Gitleaks findings alongside Trivy
- `patchpilot triage --create-issues` creates GitHub Issues
- SBOM export documented in docs/concepts.md
- v0.4.0 tagged + released
