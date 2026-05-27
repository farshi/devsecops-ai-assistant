# PatchPilot

**CVE triage that speaks compliance.** PatchPilot turns noisy scanner output
into a ranked remediation plan, with each finding tied back to the compliance
controls it affects. Developers see what to fix first; security and risk teams
see why it matters.

```
Trivy scan
    → enrich with EPSS exploitability + CISA KEV
    → map each finding to NIST / CIS / PCI / ISO / OWASP controls
    → deterministic scoring → top 5 actions
    → output: "fix X — breaks NIST SC-8 and PCI 4.2.1"
```

## Why this exists

Most vulnerability tools sit in one of two worlds:

- **Developer tools** (Trivy, Snyk, Dependabot) speak CVE, CVSS, package versions.
  They don't know which compliance control each finding affects.
- **Security tools** (CSPM platforms) speak NIST, CIS, PCI at the posture level.
  They don't tell a developer *"this CVE in your dependency list breaks
  control X that your organisation is audited on."*

For a developer at a bank, health provider, or government agency, the
question is always the same: *"which of these 200 findings matters for the
audit next quarter?"*

PatchPilot is built to answer that — as an open-source CLI, in your CI pipeline,
without buying a SaaS platform.

## What PatchPilot does

PatchPilot is a DevSecOps triage assistant, not another scanner. It sits between
scanner output and engineering workflow:

- normalises findings from tools such as Trivy, Semgrep, Checkov, Gitleaks, and
  SARIF producers into one model
- enriches findings with EPSS exploitability, CISA KEV status, fix availability,
  ownership, deadlines, and project context
- maps findings to NIST 800-53, CIS v8, PCI DSS 4.0, ISO 27001, and OWASP ASVS
  controls
- ranks what to fix first with a deterministic scoring model
- produces developer-ready action items, audit trails, PR comments, digests, and
  portfolio rollups
- optionally uses AI to explain findings, review code changes, and summarise
  risk in security reports

The core security decision path is deterministic and testable. AI is used around
the workflow, not as an opaque risk engine.

## What PatchPilot is not

- **Not a scanner replacement.** It runs or consumes scanner output.
- **Not an auto-fix bot.** The value is prioritisation, evidence, and workflow.
- **Not a black-box AI gate.** Scoring and compliance mapping stay inspectable.
- **Not a SaaS platform.** It is a CLI-first tool that can run in CI.

## Install

```bash
pip install patchpilot
```

Requires Python 3.9+ and [Trivy](https://aquasecurity.github.io/trivy/).

## Quick start

```bash
# Run the full triage pipeline against a repo
patchpilot triage --path ./my-project

# Show only findings that break a PCI DSS 4.0 control
patchpilot triage --path ./my-project --framework pci-dss

# Fail CI if any high-tier finding is present
patchpilot triage --path ./my-project --fail-on high
```

The project path is the only required flag. Output files are scoped by
the path's basename unless you pass ``--target-name`` explicitly.

The triage pipeline runs Trivy, enriches findings with EPSS exploitability
scores and CISA KEV presence, then attaches the NIST 800-53 / CIS v8 / PCI
DSS 4.0 / ISO 27001 / OWASP ASVS controls each finding impacts. The number
of frameworks a finding breaks feeds the score, so compliance-relevant
findings rank above CVSS-only noise.

Each triage action item prints a ``Compliance impact:`` block listing the
controls affected, and the data also travels with the finding through the
JSON output for downstream tooling:

```bash
patchpilot triage --path ./my-project \
  | jq '.triage.action_items[] | {id, score: .priority_score, controls: .compliance.controls}'
```

## How findings are scored

Deterministic weighted model — no LLM guesswork in the scoring path.
Weights vary by finding type so that OS-package findings are not judged
on reachability signals that only apply to language deps.

| Signal            | What it measures                                             | Lang. dep | OS pkg |
|-------------------|--------------------------------------------------------------|-----------|--------|
| CVSS severity     | How bad if exploited                                         |   18%     |  30%   |
| EPSS              | Probability of exploitation in next 30 days (FIRST.org)      |   13%     |  17%   |
| KEV               | Listed in CISA Known Exploited Vulnerabilities catalog       |   12%     |  21%   |
| Usage signal      | Package declared in project's dependency manifest            |   22%     |   —    |
| Fix available     | Patch version exists                                         |   12%     |  17%   |
| Direct dep        | Your dep vs a transitive one                                 |    8%     |   —    |
| **Compliance hit**| Number of compliance frameworks whose controls this breaks   |   15%     |  15%   |

**Note on "usage signal":** PatchPilot currently checks whether the vulnerable
package is declared in your project's manifest (`pyproject.toml`,
`package.json`, `requirements.txt`, `Gemfile`). It is not a call-graph
reachability analysis. A declared-but-unused dependency still gets surfaced;
a transitive-only dependency is deprioritised. Future versions may add
deeper analysis.

## Compliance mappings

Mappings live as JSON files under `agent/mappings/patterns/` and are editable,
reviewable, and PR-able. Each pattern links a vulnerable package, config, or
vulnerability class to the public compliance controls it affects.

Supported frameworks in v1:

| Framework                      | Source                                          |
|--------------------------------|-------------------------------------------------|
| NIST SP 800-53 Rev 5           | nist.gov                                        |
| CIS Controls v8 / Benchmarks   | cisecurity.org                                  |
| PCI DSS 4.0                    | pcisecuritystandards.org                        |
| ISO/IEC 27001:2022 Annex A     | iso.org (control IDs only — non-copyrightable)  |
| OWASP ASVS                     | owasp.org                                       |

See [`agent/mappings/README.md`](agent/mappings/README.md) for schema, examples,
and how to contribute new mappings.

## Commands

| Command                 | Purpose                                                     |
|-------------------------|-------------------------------------------------------------|
| `patchpilot scan`       | Run security scanners and normalise findings                |
| `patchpilot triage`     | Full pipeline: scan → enrich → map to controls → rank       |
| `patchpilot report`     | Generate a security report from scan or triage output       |
| `patchpilot plan`       | Preview the secure-planning workflow; handler is not wired  |
| `patchpilot review`     | Review code changes for security issues                    |
| `patchpilot audit`      | Show triage decision history for compliance evidence        |
| `patchpilot digest`     | Produce a weekly vulnerability triage digest                |
| `patchpilot deadlines`  | Track remediation deadlines by severity                    |
| `patchpilot portfolio`  | Aggregate security posture across multiple repositories     |
| `patchpilot mappings`   | Inspect and validate compliance mappings                    |
| `patchpilot assign`     | Assign a finding to a person or team                        |
| `patchpilot close`      | Mark a finding as resolved/remediated                       |

## CI integration

Minimal example — GitHub Actions:

```yaml
- name: PatchPilot triage
  run: |
    pip install patchpilot
    patchpilot triage --path . --framework pci-dss --fail-on high
```

Exit codes:
- `0` — no findings match the configured fail threshold
- `1` — at least one finding above threshold (blocks the build)
- `2` — scanner or mapping error

## Project structure

```
patchpilot/
  cli.py                       — Click CLI entry point
  agent/
    models.py                  — canonical Finding dataclass
    scan.py                    — scan orchestration
    prioritizer.py             — scoring + ranked output
    plugins/
      scanners/trivy.py        — Trivy adapter
      enrichment/epss.py       — FIRST.org EPSS lookup
      enrichment/kev.py        — CISA KEV catalog lookup
      enrichment/compliance.py — load mappings + attach controls to findings
      scoring/default.py       — deterministic weighted scorer
  agent/mappings/
    schema.json                — JSON Schema for mapping patterns
    patterns/*.json            — public compliance control mappings
    README.md                  — mapping contribution guide
  tests/                       — pytest suite
```

## Status

Early open-source release. The core triage + compliance mapping pipeline is
stable and covered by tests. Current release: `0.7.0`; current test collection:
787 tests. Mapping coverage is deliberately narrow in v1 — contributions
welcome.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

For new compliance mappings, submit a PR adding a JSON file under
`agent/mappings/patterns/` that follows the schema. For scanner adapters or
enrichment sources, open an issue first so we can discuss scope.
