# Plan

## Next: v0.5.0 — CRA Readiness

### 37 — CRA timeline tracking [x]
- What: CRA Article 14 notification milestones (24h/72h/14d) + escalation alerts
- Files: agent/deadlines.py, agent/plugins/formatters/cra.py, tests/test_deadlines.py, tests/test_cra_formatter.py
- Done: deadline entries include notification milestones, escalation_level() detects overdue, CRA formatter shows timeline table
- [x] Notification milestones in deadline entries (24h/72h/14d from discovery)
- [x] Escalation logic (critical/escalated/warning levels)
- [x] Escalation summary formatter
- [x] CRA disclosure doc: Section 3 notification timeline table + per-finding milestones
- [x] 26 new tests, 72 total passing

### 38 — Multi-repo aggregation CLI
- What: Read .patchpilot/ from multiple repo paths, unified view
- Files: cli.py, agent/context_builder.py
- Done: `patchpilot aggregate --paths` merges findings across repos
- [ ] CLI subcommand for multi-path input
- [ ] Merge and deduplicate findings across repos
- [ ] Aggregated report output

## Next: v0.6.0 — Compliance Completeness

### 39 — SPDX SBOM format
- What: Complement CycloneDX with SPDX SBOM export
- Files: agent/plugins/, cli.py
- Done: `patchpilot sbom --format spdx` produces valid SPDX
- [ ] SPDX formatter plugin
- [ ] CLI flag for format selection
- [ ] Validation against SPDX spec

### 40 — Executive summary export
- What: One-page PDF for non-technical stakeholders
- Files: agent/security_summary.py, cli.py
- Done: `patchpilot report --executive` produces PDF summary
- [x] Shipped as PAPI-040

### 41 — Semgrep scanner integration
- What: SAST code pattern detection via Semgrep
- Files: agent/plugins/scanners/
- Done: `patchpilot scan --scanner semgrep` runs and parses results
- [x] Shipped as PAPI-041

## Done — v0.4.0 (Compliance & Workflow)

### 24 — Historical trend tracking [x]
### 25 — SARIF generic adapter [x]
### 26 — Checkov scanner integration (IaC) [x]
### 27 — PR comment integration (GitHub) [x]
### 28 — Compliance framework mapping (SOC2/ISO/CRA) [x]
### 29 — Weekly digest command [x]
### 30 — Digest "what changed" detection [x]
### 31 — GitHub Actions cron workflow template [x]
### 32 — Close command [x]
### 33 — Owner/team assignment in state [x]
### 34 — Digest PR comment mode [x]
### 35 — Audit trail — decision log [x]
### 36 — Recurring workflow docs + example cron YAML [x]

## Done — v0.3.0 (Remediation & Review)

### Fix suggestion guardrails [x]
### 22 — Context-aware fix suggestions [x]
### 23 — Review command for PR diffs [x]

## Done — v0.2.0 (Config & Compliance)

### 15 — LLM narrative enhancement [x]
### 16 — Config and policy [x]
### 17 — CRA disclosure format [x]
### 18 — State and baseline tracking [x]
### 19 — LLM provider abstraction [x]
### 20 — Remaining docs [x]
### 21 — GitHub Actions template [x]

## Done — v0.1.0 (MVP)

### 1 — Fix availability detection [x]
### 2 — Scoring model [x]
### 3 — Ranked triage output [x]
### 4 — Wire triage CLI command [x]
### 5 — Developer action plan [x]
### 6 — Glossary [x]
### 7 — Packaging [x]
### 8 — CI exit codes [x]
### 9 — Trivy binary error handling [x]
### 10 — Vulnerable sample app [x]
### 11 — End-to-end CLI test [x]
### 12 — README rewrite [x]
### 13 — Release metadata [x]
### 14 — Tag v0.1.0 + GitHub release [x]
### PyPI publish + release process [x]
### Gitleaks scanner integration [x]
### Ticket creation (GitHub Issues) [x]
### Finding ownership (git blame/CODEOWNERS) [x]
### SBOM export (CycloneDX) [x]

## Backlog

### CI/CD integration
- [ ] Guardrail / policy mode (configurable CI gate beyond --fail-on)
- [ ] PR label assignment (security-reviewed, needs-review, blocked)
- [ ] Policy-as-code generation (OPA, Sentinel)

### Scanner breadth
- [ ] Grype scanner adapter

### AI-Code Awareness (future)
- [ ] AI-authored commit detection (Co-Authored-By headers, tool signatures)
- [ ] AI-code risk multiplier in PR review scoring
- [ ] Audit log: which files/functions were AI-generated

### Deferred indefinitely
- Auto-remediation (low trust, high blast radius)
- Architecture risk assessment (consulting, not product)
- Dependency license compliance (different product category)
- Slack/email notifications (needs backend)
