# Plan

## Sprint 1 — MVP Triage ✅ (complete)

| # | Task | Epic | Status |
|---|------|------|--------|
| 1 | 3.2 Fix availability detection | E3 | [x] |
| 2 | 3.1 Scoring model | E3 | [x] |
| 3 | 3.3a Ranked triage output | E3 | [x] |
| 4 | 3.4 Wire triage CLI command | E3 | [x] |
| 5 | 4.1 Developer action plan | E4 | [x] |
| 6 | 7.1 Glossary (lightweight) | E7 | [x] |

## Current Sprint: Sprint 2 — v0.1.0 Release (install, run, trust, demo)

Goal: `pip install patchpilot && patchpilot triage --path ./app` works end-to-end. Tagged v0.1.0 release.

| # | Task | Epic | Status |
|---|------|------|--------|
| 1 | 6.1 Packaging — pyproject.toml + entry point + version | E6 | [x] |
| 2 | 6.3 CI exit codes — --fail-on flag | E6 | [x] |
| 3 | R.1 Trivy binary error handling (graceful missing-tool error) | Release | [x] |
| 4 | 6.5 Vulnerable sample app (compelling demo) | E6 | [x] |
| 5 | R.2 End-to-end CLI test (installed patchpilot path) | Release | [x] |
| 6 | 6.4 README rewrite (PatchPilot positioning + install + demo) | E6 | [x] |
| 7 | R.3 Release metadata — CHANGELOG + LICENSE + CLAUDE.md cleanup | Release | [x] |
| 8 | R.4 Tag v0.1.0 + GitHub release | Release | [x] |

### Sprint 3 — Credibility + Features
| # | Task | Epic |
|---|------|------|
| 9 | 3.3b LLM narrative enhancement | E3 | [x] |
| 10 | 4.4 Config and policy | E4 |
| 11 | 4.2 CRA disclosure format | E4 |
| 12 | 4.3 State and baseline tracking | E4 |
| 13 | 5.1 LLM provider abstraction | E5 |
| 14 | 7.2-7.4 Remaining docs | E7 |
| 15 | 6.2 GitHub Actions template | E6 |

---

## Epic 1: Foundation (done)
- [x] Project scaffold, CLI skeleton, output conventions
- [x] README with architecture diagram
- [x] Sample FastAPI app for scanning demos
- [x] Prompts for all workflows
- [x] Implement scan command with Trivy runner
- [x] v1 summary.json schema (severity counts, top issues, findings)
- [x] Implement report command with Claude integration
- [x] Tests for report generation

## Epic 2: Context Builder — Repo Intelligence

The brain needs context before it can prioritize. This epic builds the layer that understands what a repo actually IS — not just what the scanner found.

### 2.0 Finding schema + type classifier (ADR-002, ADR-004) ✅
- **What:** Define canonical `Finding` dataclass and finding type classifier
- **Input:** Raw scanner output (any format)
- **Output:** `Finding` dataclass instances with `finding_type` set (os_package | language_dep | iac_misconfig | secret | code_pattern)
- **How:** Create `agent/models.py` with `Finding` dataclass. Update `parse_trivy.py` to return `Finding` instances. Classification by scan type: `trivy fs` on requirements.txt/package.json → `language_dep`. `trivy image` on container → `os_package` for OS-level packages, `language_dep` for app packages detected in image layers. Parse CVSS from Trivy's `CVSS.nvd.V3Score` field into `cvss_score`. Classification logic lives in scanner adapter, using Trivy's `Class` field (`os-pkgs` vs `lang-pkgs`) to distinguish.
- **File:** `agent/models.py` (new), update `devsecops/parsers/parse_trivy.py`
- **Test:** Parse Trivy output, verify Finding instances with correct `finding_type`
- **Done when:** All existing scan output flows through Finding schema with correct types

### 2.0b Plugin interface definitions (ADR-001) ✅
- **What:** Define Python ABCs for all plugin types — no implementations beyond Trivy adapter yet
- **Input:** N/A (interface design)
- **Output:** `agent/plugins/base.py` with `ScannerAdapter`, `EnrichmentPlugin`, `PrioritizationStrategy`, `OutputFormatter` ABCs
- **How:** Create ABCs matching the contracts in the spec. Refactor Trivy parser as first `ScannerAdapter` implementation.
- **File:** `agent/plugins/base.py` (new), `agent/plugins/scanners/trivy.py` (refactored from `devsecops/parsers/parse_trivy.py`)
- **Test:** Trivy adapter implements ScannerAdapter ABC, passes existing tests
- **Done when:** Plugin interfaces defined, Trivy adapter refactored as reference implementation

### 2.1 Repo structure detection ✅
- **What:** Scan the repo and detect project type, language, framework, runtime
- **Input:** Repo path
- **Output:** Structured dict: `{languages: ["python"], frameworks: ["fastapi"], runtime: "docker", has_ci: true, has_iac: false}`
- **How:** Check for marker files: `requirements.txt`/`pyproject.toml` (Python), `package.json` (Node), `Dockerfile`, `docker-compose.yml`, `.github/workflows/`, `terraform/`, `k8s/`
- **File:** `agent/context_builder.py` — new function `detect_repo_structure(path)`
- **Test:** Run on `sample_app/`, verify it detects Python + FastAPI + Docker
- **Done when:** Returns correct structure dict for sample_app

### 2.2 Dependency graph extraction ✅
- **What:** Parse dependency files and build a list of direct vs transitive deps
- **Input:** Repo path + detected languages from 2.1
- **Output:** `{direct: ["fastapi==0.104.1", "uvicorn"], transitive: [...], lockfile_exists: true}`
- **How:** Parse `requirements.txt`, `pyproject.toml`, `package.json`, `package-lock.json`. Mark direct vs transitive (if lockfile exists).
- **File:** `agent/context_builder.py` — new function `extract_dependencies(path, structure)`
- **Test:** Run on `sample_app/`, verify it finds fastapi, uvicorn etc.
- **Done when:** Returns accurate dependency list with direct/transitive distinction

### 2.3 Import reachability signal (ADR-003) ✅
- **What:** For each finding's package, check if it's actually imported in the codebase
- **Input:** Dependency list + list of Finding instances from scan
- **Output:** Each Finding gets `reachable`, `reachability_confidence` fields set
- **How:** Three-state reachability with confidence levels:
  - Maintain package→import mapping for top 50 Python/JS mismatches (PyYAML→yaml, Pillow→PIL, beautifulsoup4→bs4, etc.)
  - Use `top_level.txt` from installed packages when available
  - Simple grep/AST check — does any `.py` file `import <mapped_name>`?
  - When mapping exists and import found → `reachable: true, confidence: high`
  - When package name = import name and found → `reachable: true, confidence: medium`
  - When no mapping exists → `reachable: unknown, confidence: low`
  - OS packages, IaC, secrets → `reachable: not_applicable, confidence: none`
  - Set `reachability_evidence` with proof (e.g., "import found in app/main.py:3") for trust
  - Allow overrides in `.patchpilot/config.yaml`
  - **Scope for v1:** Python only. Node.js import mapping deferred to backlog.
- **File:** `agent/context_builder.py` — new function `check_reachability(path, findings, structure)`
- **Why this matters:** A CVE in an unused transitive dep is noise. This is the #1 signal for smart prioritization.
- **Test:** Add a dep to sample_app that's in requirements.txt but never imported. Verify it's marked `reachable: false`. Test a known mismatch (e.g., PyYAML). Test OS package → `not_applicable`.
- **Done when:** Findings have honest reachability annotation with confidence, test passes

### 2.3b EPSS + KEV enrichment ✅
- **What:** For each finding with a CVE ID, fetch EPSS score and check KEV catalog
- **Input:** List of `Finding` instances with `id` field (CVE IDs)
- **Output:** Each Finding gets `epss_score` (0.0-1.0) and `in_kev` (bool) populated
- **How:**
  - EPSS: Fetch from FIRST.org API (`https://api.first.org/data/v1/epss?cve=CVE-xxx`). Batch requests where possible. Cache responses locally for session.
  - KEV: Download CISA KEV catalog JSON (or use cached copy). Simple set lookup.
  - Both are public, free APIs — no auth required.
- **Implements:** `EnrichmentPlugin` ABC — built-in EPSS and KEV plugins
- **File:** `agent/plugins/enrichment/epss.py`, `agent/plugins/enrichment/kev.py`
- **Test:** Given a known CVE with EPSS data, verify score is populated. Given a KEV-listed CVE, verify `in_kev=True`.
- **Done when:** Findings have EPSS and KEV data populated, enrichment plugins pass tests

### 2.4 Full context bundle (with token budgeting) ✅
- **What:** Combine repo structure + deps + reachability into one context object passed to the LLM
- **Input:** All outputs from 2.1, 2.2, 2.3 + scan summary
- **Output:** A single JSON context bundle: `{repo: {...}, dependencies: {...}, findings: [Finding, ...], scan_meta: {...}}`
- **Token budgeting:** Cap file list to 50 most relevant files, collapse findings with same CVE across multiple locations, truncate context to fit within 100K token window. Large repos should degrade gracefully, not fail.
- **File:** `agent/context_builder.py` — new function `build_context(path, scan_summary_path)`
- **Test:** End-to-end: scan sample_app → build context → verify bundle is complete. Test with artificially large finding set to verify budgeting.
- **Done when:** One function call produces the full context bundle within token budget

## Epic 3: The Prioritizer — Smart Triage Engine

This is the core IP. The prioritizer takes raw findings + context and produces a ranked, actionable list. It answers: "of these 200 findings, which 3-5 should I fix this week?"

### 3.1 Scoring model design
- **What:** Define the scoring formula that ranks findings. Operates on canonical `Finding` dataclass.
- **Input:** A `Finding` with enrichment fields populated (severity, reachability, fix availability, direct/transitive, EPSS, KEV)
- **Output:** `priority_score` (0-100) + `priority_tier` (critical/high/medium/low/noise) set on each Finding
- **Factors (weighted, per finding type):**
  - **For `language_dep`:** Severity/CVSS: 20%, Reachability: 25% (biggest weight), EPSS score: 15%, Fix available: 15%, Direct vs transitive: 10%, In KEV catalog: 15%
  - **For `os_package`:** Severity/CVSS: 30%, EPSS: 20%, Fix available: 20%, In KEV: 20%, Base image age: 10%
  - **For `iac_misconfig`:** Severity: 40%, Exposure level: 30%, Fix complexity: 30%
  - Reachability weight adjusted by confidence: high confidence = full weight, low/unknown = halved
- **Implements:** `PrioritizationStrategy` ABC from plugin system
- **File:** `agent/prioritizer.py` — new module (or `agent/plugins/scoring/default.py`)
- **Test:** Given 10 findings with varying attributes across types, verify ranking matches expected order
- **Done when:** Scoring function produces sensible rankings on real scan data, different finding types weighted appropriately

### 3.2 Fix availability detection
- **What:** For each finding, determine if a fix exists and what it is
- **Input:** Finding with package name + current version
- **Output:** `{fix_available: true, fix_version: "2.1.1", breaking_change: false, notes: "minor bump"}`
- **How:** Parse Trivy's `FixedVersion` field. For Python, check if the fix version is compatible with the current pinning strategy. Flag major version bumps as potential breaking changes.
- **File:** `agent/prioritizer.py` — function `assess_fix_availability(finding)`
- **Test:** Finding with known fix → returns fix info. Finding without fix → returns `fix_available: false`.
- **Done when:** Every finding has fix availability data

### 3.3a Ranked triage output (MVP)
- **What:** Produce the ranked output — the "fix these 3-5 things this week" list
- **Input:** Scored findings from 3.1 + fix data from 3.2
- **Output:** Ranked list with: priority tier, score, finding summary, recommended action, effort estimate
- **Format:** JSON + markdown (both generated)
- **File:** `agent/prioritizer.py` — function `generate_triage(scored_findings, context, top_n=5)`
- **Key:** Ranking is algorithmic (scoring model), deterministic, explainable. No LLM dependency for core output.
- **Test:** Given scored findings, verify output has correct structure and top-N selection
- **Done when:** Running on sample_app scan produces a clear, actionable 3-5 item list

### 3.3b LLM narrative enhancement (Sprint 2)
- **What:** Add LLM-generated "why it matters" and "recommended action" sentences to triage output
- **Input:** Ranked triage from 3.3a + context bundle
- **Output:** Each finding gets a plain-English explanation and action recommendation
- **Key:** Enhancement layer on top of 3.3a. Core triage works without LLM. This adds polish.
- **File:** `agent/prioritizer.py` — function `enhance_triage_with_llm(triage, context)`
- **Done when:** Top findings have human-readable explanations

### 3.4 Wire triage CLI command
- **What:** Add `patchpilot triage` command that runs the full pipeline
- **Input:** `patchpilot triage --path . --top 5`
- **Output:** Prints ranked triage list to stdout, saves to `reports/<target>_triage_<date>.md`
- **Flow:** scan (if not already done) → build context → score → rank → output
- **File:** `cli.py` — new command `triage`
- **Test:** Full end-to-end on sample_app
- **Done when:** One command produces the smart triage output

## Epic 4: Actionable Reports + Compliance

Turn triage output into formats that serve different audiences: developers (action plan), managers (risk summary), compliance (CRA documentation).

### 4.1 Developer action plan
- **What:** Refactor existing `report` command to use prioritized triage instead of raw scan
- **Input:** Triage output from Epic 3 (list of scored `Finding` instances)
- **Output:** Markdown report with: top findings ranked, for each: what it is, why it matters, what to do, effort estimate
- **Implements:** `OutputFormatter` ABC from plugin system
- **File:** `agent/plugins/formatters/markdown.py` (refactored from `agent/security_summary.py`)
- **Key change:** Report now shows PRIORITIZED findings with context, not just a dump of everything
- **Done when:** Report reads like "fix these 3 things" not "here are 200 CVEs"

### 4.2 CRA vulnerability disclosure format
- **What:** Add `--cra` flag to report command for EU Cyber Resilience Act compliance
- **Input:** Same triage data (scored `Finding` instances + context)
- **Output:** Structured vulnerability disclosure document with: affected component, severity, exploitability assessment, remediation status, timeline, responsible contact
- **Why now:** EU CRA reporting obligations start Sept 11, 2026 — < 6 months away. Penalties up to 15M EUR. No CLI tool targets this yet — first-mover advantage.
- **Implements:** `OutputFormatter` ABC — CRA formatter plugin
- **File:** `agent/plugins/formatters/cra.py` (new)
- **Also consider:** VEX/CSAF output format for interoperability with other tools
- **Done when:** Output matches CRA disclosure requirements structure

### 4.3 State and baseline tracking
- **What:** Remember past triage decisions so PatchPilot doesn't re-alert on accepted risks
- **Input:** User actions: dismiss finding, accept risk, mark fixed
- **Output:** `.patchpilot/state.json` with triage history; `.patchpilot/baseline.json` with last scan state
- **Features:**
  - `--new-only` flag: only show findings that are NEW since last scan
  - `--ignore CVE-xxxx`: dismiss a specific finding with reason
  - State file is committed to repo — team shares triage decisions
- **File:** `agent/state.py` — new module
- **Why this matters:** Without memory, every scan is noisy again. Cumulative intelligence is a key differentiator.
- **Done when:** Second run of triage shows only new/changed findings

### 4.4 Config and policy
- **What:** Let teams configure thresholds and ignore rules
- **Input:** `.patchpilot/config.yaml`
- **Output:** Triage respects config: severity threshold, ignored packages, ignored CVEs, LLM provider choice
- **Config schema:**
  ```yaml
  severity_threshold: high        # only show high + critical
  ignore_cves: [CVE-2023-xxxx]   # accepted risks
  ignore_packages: [dev-dep]      # known safe
  llm_provider: claude            # or gpt
  top_n: 5                        # how many findings to surface
  ```
- **File:** `agent/config.py` — new module, loaded by CLI
- **Done when:** Config file changes triage output as expected

## Epic 5: LLM Orchestration + Fix Suggestions

Now that we have smart triage, add optional fix generation. This is a FEATURE of the prioritizer, not the product itself.

### 5.1 LLM provider abstraction
- **What:** Support both Claude and GPT through a single interface
- **Input:** Provider choice from config + API keys from env
- **Output:** Unified `llm_call(system, user) → response` function
- **File:** Refactor `agent/claude_client.py` → `agent/llm_client.py`
- **Done when:** Both Claude and GPT produce equivalent outputs through same interface

### 5.2 Context-aware fix suggestions
- **What:** For each triaged finding, optionally generate a fix suggestion
- **Input:** Finding + context bundle + affected files
- **Output:** Suggested change (description + diff preview), confidence level, known risks
- **Important:** This is a SUGGESTION, not an auto-patch. The developer reviews and applies.
- **File:** `agent/fix_suggester.py` — new module
- **Guardrails:** Only suggest fixes for: dependency bumps, base image updates, config changes. Never auto-modify application logic.
- **Done when:** Top findings in triage output include optional fix suggestions

### 5.3 Review command for PR changes
- **What:** `patchpilot review` scans a git diff for security issues
- **Input:** `patchpilot review --branch feature-x` or `patchpilot review --diff`
- **Output:** Security review of changes: new vulnerabilities introduced, risky patterns, recommendations
- **File:** Wire `agent/review.py` to context builder + LLM
- **Done when:** Can review a PR's diff and flag security concerns

## Epic 6: Distribution + Sales Readiness

### 6.1 Packaging and install UX
- **What:** `pip install patchpilot` works, entry point is `patchpilot`
- **File:** `pyproject.toml` or `setup.py`
- **Done when:** Clean install from PyPI (or testpypi) works in 60 seconds

### 6.2 GitHub Actions template
- **What:** Ship a ready-to-use `.github/workflows/patchpilot.yml`
- **Flow:** On push/schedule → scan → triage → comment on PR or create issue
- **File:** `examples/github-action.yml`
- **Done when:** Copy-paste into a repo and it runs

### 6.3 CI exit codes
- **What:** `patchpilot triage --fail-on critical` returns exit code 1 if critical findings exist
- **Why:** Teams can gate merges on security posture
- **File:** `cli.py` — add `--fail-on` flag to triage command
- **Done when:** CI pipeline can fail on security thresholds

### 6.4 README + demo
- **What:** Rewrite README for PatchPilot positioning, add example output, record demo
- **Done when:** A stranger understands the value in 30 seconds

### 6.5 Vulnerable sample app
- **What:** Create a sample app with intentional vulnerabilities for demo purposes
- **Why:** Clean sample_app finds nothing interesting. Need a demo that shows PatchPilot's value.
- **Done when:** `patchpilot triage --path vulnerable_app/` produces a compelling triage output

## Epic 7: Documentation

Living documentation that explains what PatchPilot is, how it works, and the concepts behind it. Lives in `docs/` — not README (that's Epic 6.4 for marketing). This is the technical reference.

### 7.1 Glossary and concepts
- **What:** Define all key terms: EPSS, KEV, CVSS, reachability, finding types, priority tiers, VEX, CRA, SBOM
- **Why:** Users and contributors need a shared vocabulary. Terms like "reachability" mean different things to different tools.
- **File:** `docs/concepts.md`
- **Done when:** Every term used in CLI output or reports is defined

### 7.2 Architecture and data flow
- **What:** Document how PatchPilot works end-to-end: scan → context → enrich → prioritize → report
- **Include:** Data flow diagram, Finding schema lifecycle, plugin pipeline, what each module does
- **File:** `docs/architecture.md`
- **Done when:** A new contributor can understand the codebase from this doc alone

### 7.3 Plugin development guide
- **What:** How to write a custom plugin (scanner adapter, enrichment, scoring, formatter)
- **Include:** ABC interfaces, example implementations, registration, testing
- **File:** `docs/plugins.md`
- **Done when:** Someone can write and register a Grype adapter from this doc

### 7.4 Decision log summary
- **What:** Human-readable summary of all ADRs and why they were made
- **File:** `docs/decisions.md`
- **Done when:** Links to all ADRs with one-line summaries and status

## Backlog

### Scanner integrations
- [ ] Checkov scanner integration (IaC scanning)
- [ ] Gitleaks scanner integration (secret detection)
- [ ] Semgrep scanner integration (SAST patterns)

### From article vision (ADR-008) — v0.2+
- [ ] Guardrail design mode — AI suggests preventive controls, not just reactive fixes
- [ ] Security metrics + trends — time-to-fix, risk per team/service, repeated mistakes
- [ ] Policy-as-code generation — convert security rules into CI/CD controls (OPA, Sentinel)
- [ ] Auto-remediation — generate patches for dependency bumps, create tickets, track to closure
- [ ] Compliance framework mapping — map findings to SOC2/ISO27001/CRA controls automatically
- [ ] Architecture risk assessment — evaluate system design for security patterns/anti-patterns

### Distribution + operations
- [ ] SBOM export (CycloneDX / SPDX format)
- [ ] Slack/email notification on new critical findings
- [ ] Done-for-you service playbook (how to run PatchPilot for clients)
- [ ] Hosted automation tier (scheduled scans, auto-PRs)
- [ ] Dependency license compliance checking
- [ ] Historical trend tracking (are we getting more or less secure over time?)
- [ ] Risk dashboards (needs UI — deferred until CLI value proven)
- [ ] Finding ownership — "who should fix this?" based on git blame/CODEOWNERS (noted from GPT strategy review)
- [ ] Ticket creation integration — create GitHub Issues / Jira tickets from triage output (noted from GPT strategy review)
