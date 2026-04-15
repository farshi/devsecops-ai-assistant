# PatchPilot

**CVE triage that speaks compliance.** Every finding is tagged with the specific
NIST 800-53, CIS Benchmark, and PCI DSS controls it affects — so developers in
regulated organisations fix what the audit actually cares about, not just what
CVSS happens to rank highest.

```
Trivy scan
    → enrich with EPSS exploitability + CISA KEV
    → map each finding to NIST / CIS / PCI controls
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

## Install

```bash
pip install patchpilot
```

Requires Python 3.9+ and [Trivy](https://aquasecurity.github.io/trivy/).

## Quick start

```bash
# Run the full triage pipeline against a repo
patchpilot triage --path ./my-project --target-name myapp

# Show only findings that break a PCI DSS 4.0 control
patchpilot triage --path ./my-project --target-name myapp --framework pci-dss

# Fail CI if any high-tier finding is present
patchpilot triage --path ./my-project --target-name myapp --fail-on high
```

The triage pipeline runs Trivy, enriches findings with EPSS exploitability
scores and CISA KEV presence, then attaches the NIST 800-53 / CIS v8 / PCI
DSS 4.0 / ISO 27001 / OWASP ASVS controls each finding impacts. The number
of frameworks a finding breaks feeds the score, so compliance-relevant
findings rank above CVSS-only noise.

Each triage action item prints a ``Compliance impact:`` block listing the
controls affected, and the data also travels with the finding through the
JSON output for downstream tooling:

```bash
patchpilot triage --path ./my-project --target-name myapp \
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

Mappings live as JSON files under `mappings/patterns/` and are editable, reviewable,
and PR-able. Each pattern links a vulnerable package, config, or vulnerability
class to the public compliance controls it affects.

Supported frameworks in v1:

| Framework                      | Source                                          |
|--------------------------------|-------------------------------------------------|
| NIST SP 800-53 Rev 5           | nist.gov                                        |
| CIS Controls v8 / Benchmarks   | cisecurity.org                                  |
| PCI DSS 4.0                    | pcisecuritystandards.org                        |
| ISO/IEC 27001:2022 Annex A     | iso.org (control IDs only — non-copyrightable)  |

See [`mappings/README.md`](mappings/README.md) for schema, examples, and how to
contribute new mappings.

## Commands

| Command              | Purpose                                                     |
|----------------------|-------------------------------------------------------------|
| `patchpilot scan`    | Run Trivy, produce normalised `summary.json`                |
| `patchpilot triage`  | Full pipeline: scan → enrich → map to controls → rank       |

## CI integration

Minimal example — GitHub Actions:

```yaml
- name: PatchPilot triage
  run: |
    pip install patchpilot
    patchpilot triage --path . --framework pci-dss --fail-on any
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
  mappings/
    schema.json                — JSON Schema for mapping patterns
    patterns/*.json            — public compliance control mappings
    README.md                  — mapping contribution guide
  tests/                       — pytest suite
```

## Status

Early open-source release. The core triage + compliance mapping pipeline is
stable and covered by tests. Mapping coverage is deliberately narrow in v1 —
contributions welcome.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) (coming soon). In short: for new compliance
mappings, submit a PR adding a JSON file under `mappings/patterns/` that follows
the schema. For scanner adapters or enrichment sources, open an issue first so
we can discuss scope.
