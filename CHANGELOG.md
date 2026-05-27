# Changelog

## v0.8.0 (2026-05-27)

**SonarQube / SonarCloud support** — pull Sonar findings into compliance-aware triage.

### Features
- **Sonar scanner adapter** (`agent/plugins/scanners/sonar.py`) — normalises
  SonarQube/SonarCloud `api/issues/search` issues and `api/hotspots/search`
  hotspots into canonical Findings. Maps both the legacy (BLOCKER..INFO) and
  software-quality (HIGH/MEDIUM/LOW) severity scales, issue types
  (VULNERABILITY / BUG / CODE_SMELL / SECURITY_HOTSPOT), and
  `projectKey:path` components into `path:line` locations.
- **Live Sonar REST API runner** (`devsecops/runners/run_sonar.py`) — pulls a
  project's issues and hotspots over HTTP with token auth (HTTP Basic, token
  as username), paginated to Sonar's 10k cap, tolerant of servers without the
  hotspots endpoint. Configured via the standard `SONAR_HOST_URL`,
  `SONAR_TOKEN`, and `SONAR_PROJECT_KEY` env vars so teams reuse existing CI
  settings. No new dependencies — stdlib `urllib` only.
- **Sonar in the `full` scan profile** — `patchpilot scan --profile full`
  pulls Sonar live when the env vars are set, and skips cleanly when they are
  not. A pre-fetched export can also be supplied via `PATCHPILOT_SONAR_REPORT`.

### Infrastructure
- 24 new tests (adapter + runner), full suite green at 818.

## v0.7.0 (2026-04-15)

**Compliance-aware triage pivot** — every finding now speaks NIST, CIS, PCI, ISO, and OWASP.

### Features
- **Compliance-control mapping** — every Trivy finding is tagged with the
  NIST 800-53 Rev 5, CIS Controls v8, PCI DSS 4.0, ISO 27001:2022 Annex A,
  and OWASP ASVS v4 controls it affects. Ships with 9 seed patterns covering
  Log4Shell, Spring4Shell, outdated crypto libs, Werkzeug RCE, OpenSSL / curl
  base-image CVEs, JWT algorithm-confusion, and more. Contribute new mappings
  via JSON in ``agent/mappings/patterns/`` — public-standards only.
- **`--framework` triage flag** — filter findings to only those that break a
  named framework's controls (``--framework pci-dss`` etc). Surviving
  findings are ranked against each other, not a diluted pool, so pre-audit
  triage lands on what actually matters.
- **Compliance impact in markdown output** — each action item now renders a
  ``Compliance impact:`` block listing affected controls across all five
  frameworks in a deterministic order.
- **Compliance-hit scoring signal** — weighted at 15% across all finding
  types. Findings that break mappings outrank CVSS-only peers.
- **`patchpilot mappings validate` command** — validates every pattern JSON
  against the schema. Exit 1 on any failure, suitable for CI.
- **Auto-derived `--target-name`** — target name now defaults to the path
  basename. ``patchpilot triage --path ./app`` is the full happy-path
  command; ``--target-name`` is only needed for custom output slugs.

### Packaging
- Moved optional ``anthropic`` SDK into the ``[ai]`` extra (install via
  ``pip install patchpilot[ai]``) so the lean default install stays small
  and LLM-free.
- Added ``packaging`` as a required dependency for robust version
  comparison in the compliance mapper (PEP 440 + Debian/RPM/Alpine).
- ``jsonschema`` is optional via ``[validate]`` — only needed for
  ``patchpilot mappings validate``.
- Mapping JSONs ship inside the wheel via package-data; the installed
  CLI no longer needs a source checkout to run compliance triage.

### Infrastructure
- 787 tests passing.
- Adversarial code review round completed and fully addressed (compliance
  metadata round-trip, finding-type preservation, PEP 440 version parsing,
  overclaimed NIST mappings, README/README-drift corrections, broader
  error-handling discipline, tighter schema).

---

## v0.3.0 (2026-03-31)

Remediation + PR review release. PatchPilot now tells you what to change and catches issues in PRs.

### Features
- **Context-aware fix suggestions** — upgrade commands (pip/npm/go) with confidence levels and contextual caveats from reachability, KEV, EPSS signals
- **PR security review** — `patchpilot review --diff` scans git changes for security issues with PASS/WARN/BLOCK verdicts
- **Fix suggestion guardrails** — config for major bump policy, max suggestions, unused package removal
- **Updated LLM defaults** — Claude Sonnet 4, GPT 5.4-mini

### Infrastructure
- 286 tests passing
- 30 PRs merged across 4 sprints
- Ready for PyPI publish (`pip install patchpilot`)

---

## v0.2.0 (2026-03-31)

Credibility + features release.

### Features
- **LLM narrative enhancement** — `--enhance` adds Claude-generated "why it matters" + "what to do" for each finding
- **Config and policy** — `.patchpilot/config.yaml` for severity thresholds, CVE/package ignores, enrichment toggles
- **CRA disclosure format** — `--format cra` generates EU Cyber Resilience Act compliant vulnerability disclosure
- **State and baseline tracking** — dismiss findings, accept risks, `--new-only` shows only new findings since last scan
- **LLM provider abstraction** — Claude + GPT support via config (`llm_provider: openai`), no openai SDK needed
- **GitHub Actions template** — copy-paste workflow in `examples/github-action.yml`

### Documentation
- Architecture doc with data flow diagram and module map
- Plugin development guide with examples for all 4 plugin types
- Decision log summary linking all 8 ADRs

### Infrastructure
- Project CI workflow (Python 3.9/3.11/3.12)
- 255 tests passing

---

## v0.1.0 (2026-03-31)

First public release. Smart vulnerability triage for developers.

### Features
- **Triage command** — `patchpilot triage --path . --target-name myapp` runs the full pipeline
- **Scoring model** — deterministic weighted formula ranking by reachability (25%), EPSS, KEV, CVSS, fix availability, dependency depth
- **Reachability analysis** — checks if vulnerable packages are actually imported in Python source code
- **EPSS enrichment** — fetches 30-day exploitation probability from FIRST.org
- **KEV enrichment** — checks CISA Known Exploited Vulnerabilities catalog
- **Fix availability** — assesses version bump type (patch/minor/major) and effort
- **CI gating** — `--fail-on critical|high|medium|low` returns exit code 1 for CI pipelines
- **Plugin architecture** — extensible via 4 ABCs: ScannerAdapter, EnrichmentPlugin, PrioritizationStrategy, OutputFormatter
- **Trivy adapter** — built-in scanner adapter with finding type classification (os_package vs language_dep)
- **Context builder** — repo structure detection, dependency extraction, token budgeting
- **AI-enhanced reports** — `patchpilot report --path .` sends triage data to Claude for enhanced action plans

### Infrastructure
- `pip install .` with `patchpilot` CLI entry point
- 171 tests passing
- Vulnerable sample app for demos (`vulnerable_app/`)
- Glossary and concepts documentation (`docs/concepts.md`)
- 8 ADRs documenting architectural decisions
- Spec-to-docs traceability map (`docs/MAP.md`)

### Architecture Decisions
- ADR-001: Plugin architecture for extensibility
- ADR-002: Canonical Finding schema as shared contract
- ADR-003: Reachability honesty — "unknown" over false confidence
- ADR-004: Finding type classifier — scope reachability correctly
- ADR-005: Competitive positioning — triage layer, not platform
- ADR-006: Alignment log for drift tracking
- ADR-007: Spec-to-docs traceability mapping
- ADR-008: Vision evolution — from scanner triage to security engineer assistant
