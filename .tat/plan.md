# Plan

## Tasks

| ID | Task | Status |
|----|------|--------|
| 29 | Weekly digest command — summary from baseline + trends | [x] |
| 30 | Digest "what changed" — new/resolved/regression detection | [x] |
| 31 | GitHub Actions cron workflow template — scheduled triage | [x] |
| 32 | Close command — mark findings resolved | [ ] |
| 33 | Owner/team assignment in state | [ ] |
| 34 | Digest PR comment mode | [ ] |
| 35 | Audit trail — decision log with timestamps | [ ] |
| 36 | Recurring workflow docs + example cron YAML | [ ] |

## Done

| ID | Task | Status |
|----|------|--------|
| 1 | Fix availability detection | [x] |
| 2 | Scoring model | [x] |
| 3 | Ranked triage output | [x] |
| 4 | Wire triage CLI command | [x] |
| 5 | Developer action plan | [x] |
| 6 | Glossary (lightweight) | [x] |
| 7 | Packaging — pyproject.toml + entry point | [x] |
| 8 | CI exit codes — --fail-on flag | [x] |
| 9 | Trivy binary error handling | [x] |
| 10 | Vulnerable sample app | [x] |
| 11 | End-to-end CLI test | [x] |
| 12 | README rewrite | [x] |
| 13 | Release metadata — CHANGELOG + LICENSE | [x] |
| 14 | Tag v0.1.0 + GitHub release | [x] |
| 15 | LLM narrative enhancement | [x] |
| 16 | Config and policy | [x] |
| 17 | CRA disclosure format | [x] |
| 18 | State and baseline tracking | [x] |
| 19 | LLM provider abstraction | [x] |
| 20 | Remaining docs (architecture, plugins, decisions) | [x] |
| 21 | GitHub Actions template | [x] |
| 22 | Context-aware fix suggestions | [x] |
| 23 | Review command for PR diffs | [x] |
| -- | PyPI publish + release process | [x] |
| -- | Fix suggestion guardrails | [x] |
| -- | Gitleaks scanner integration | [x] |
| -- | Ticket creation (GitHub Issues) | [x] |
| -- | Finding ownership (git blame/CODEOWNERS) | [x] |
| -- | SBOM export (CycloneDX) | [x] |
| 24 | Historical trend tracking | [x] |
| 25 | SARIF generic adapter | [x] |
| 26 | Checkov scanner integration (IaC) | [x] |
| 27 | PR comment integration (GitHub) | [x] |
| 28 | Compliance framework mapping (SOC2/ISO/CRA) | [x] |

## Backlog

### Scanner breadth
- [ ] Semgrep scanner integration (SAST patterns)
- [ ] Grype scanner adapter

### CI/CD integration
- [ ] Guardrail / policy mode (configurable CI gate beyond --fail-on)
- [ ] Policy-as-code generation (OPA, Sentinel)

### Compliance
- [ ] SPDX SBOM format (complement CycloneDX)

### Deferred indefinitely
- Risk dashboards (needs UI — violates "no new workflow")
- Hosted automation / scheduled scans (needs backend)
- Auto-remediation (low trust, high blast radius)
- Architecture risk assessment (consulting, not product)
- Dependency license compliance (different product category)
- Slack/email notifications (needs backend)
