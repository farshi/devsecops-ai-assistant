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
patchpilot triage --path ./my-project

# Fail CI if any finding is high or above
patchpilot triage --path ./my-project --fail-on high
```

The triage pipeline runs Trivy, enriches findings with EPSS exploitability
scores, CISA KEV presence, and — new in the compliance-aware release —
attaches the NIST / CIS / PCI DSS / ISO 27001 / OWASP ASVS controls each
finding impacts. Controls travel with the finding through the JSON output so
downstream tooling can consume them.

Per-framework filtering at the CLI (`--framework`) and a dedicated
"Compliance impact" output block are on the roadmap but not yet in this
release. The controls are already present on each finding in the JSON output,
so you can post-process with `jq` today:

```bash
patchpilot triage --path ./my-project --output json \
  | jq '.findings[] | select(.compliance_controls.pci_dss_4_0) | {id, controls: .compliance_controls}'
```

## How findings are scored

Deterministic weighted model. No LLM guesswork in the scoring path.

| Signal          | What it measures                                             | Weight |
|-----------------|--------------------------------------------------------------|--------|
| CVSS severity   | How bad if exploited                                         | 20%    |
| EPSS            | Probability of exploitation in next 30 days (FIRST.org)      | 15%    |
| KEV             | Listed in CISA Known Exploited Vulnerabilities catalog       | 15%    |
| Usage signal    | Package declared in project's dependency manifest            | 25%    |
| Fix available   | Patch version exists                                         | 15%    |
| Direct dep      | Your dep vs a transitive one                                 | 10%    |

The compliance mapping is attached to each finding as data; a weighted
"compliance hit" signal in the scorer is planned for the next release.

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
