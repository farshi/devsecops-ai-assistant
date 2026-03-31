# Sprint 5 — Daily Driver (v0.4.0)

**Goal:** PatchPilot becomes part of the daily workflow — one more scanner, actionable tickets, ownership routing, compliance readiness.
**Date:** 2026-03-31
**GPT review:** Deferred (API key invalid). Based on prior GPT guidance: "deepen before broadening", "workflow integration drives adoption", "CRA deadline creates urgency".

## Relevant Constraints
- **ADR-001 (Plugin architecture)** — New scanner (Gitleaks) must implement ScannerAdapter ABC
- **ADR-002 (Finding schema)** — Gitleaks findings must map to canonical Finding with finding_type="secret"
- **ADR-004 (Finding type classifier)** — Secret findings get reachable="not_applicable"
- **ADR-005 (Positioning)** — Ticket creation should be thin integration, not a project management tool
- **ADR-008 (Vision)** — SBOM is v0.2-v0.3 scope. Finding ownership is from GPT strategy review.
- **Lesson 10** — Plugin architecture: define interfaces early. Gitleaks adapter follows TrivyScannerAdapter pattern.
- **Lesson T8** — Auto-mode must not skip checkpoints. Follow all checkpoint maps.

## Scope
| # | Task | Epic |
|---|------|------|
| 1 | Gitleaks scanner integration | Backlog→E8 |
| 2 | Ticket creation (GitHub Issues from triage) | Backlog→E8 |
| 3 | Finding ownership (git blame/CODEOWNERS) | Backlog→E8 |
| 4 | SBOM export (CycloneDX) | Backlog→E8 |
| 5 | Historical trend tracking (file-based) | Backlog→E8 |

## Out of Scope
- Checkov / Semgrep (next sprint)
- Auto-remediation (ADR-008: not yet)
- Dashboards / web UI
- Slack notifications
- Policy-as-code generation
- Hosted automation tier

## Risks
1. **Gitleaks integration** — May need to handle different output formats across versions. Mitigation: target latest stable Gitleaks JSON.
2. **GitHub Issues API** — Requires auth token. Mitigation: use `gh` CLI or GitHub API directly with GITHUB_TOKEN.
3. **git blame performance** — Slow on large repos. Mitigation: only blame files with findings, cache results.

## Definition of Done
- All tasks shipped with review artifacts
- Tests pass (expect 320+)
- CHANGELOG updated for v0.4.0
- Gitleaks findings appear in triage output alongside Trivy
- `patchpilot triage --create-issues` creates GitHub Issues
- SBOM export documented
- v0.4.0 tagged + released
