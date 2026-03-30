# Plan

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

### 2.1 Repo structure detection
- **What:** Scan the repo and detect project type, language, framework, runtime
- **Input:** Repo path
- **Output:** Structured dict: `{languages: ["python"], frameworks: ["fastapi"], runtime: "docker", has_ci: true, has_iac: false}`
- **How:** Check for marker files: `requirements.txt`/`pyproject.toml` (Python), `package.json` (Node), `Dockerfile`, `docker-compose.yml`, `.github/workflows/`, `terraform/`, `k8s/`
- **File:** `agent/context_builder.py` — new function `detect_repo_structure(path)`
- **Test:** Run on `sample_app/`, verify it detects Python + FastAPI + Docker
- **Done when:** Returns correct structure dict for sample_app

### 2.2 Dependency graph extraction
- **What:** Parse dependency files and build a list of direct vs transitive deps
- **Input:** Repo path + detected languages from 2.1
- **Output:** `{direct: ["fastapi==0.104.1", "uvicorn"], transitive: [...], lockfile_exists: true}`
- **How:** Parse `requirements.txt`, `pyproject.toml`, `package.json`, `package-lock.json`. Mark direct vs transitive (if lockfile exists).
- **File:** `agent/context_builder.py` — new function `extract_dependencies(path, structure)`
- **Test:** Run on `sample_app/`, verify it finds fastapi, uvicorn etc.
- **Done when:** Returns accurate dependency list with direct/transitive distinction

### 2.3 Import reachability signal
- **What:** For each finding's package, check if it's actually imported in the codebase
- **Input:** Dependency list + list of findings from scan
- **Output:** Each finding gets a `reachable: true/false/unknown` field
- **How:** Simple grep/AST check — does any `.py` file `import <package>`? Does any `.js` file `require('<package>')`? Not full call-graph analysis — just "is it imported anywhere?"
- **File:** `agent/context_builder.py` — new function `check_reachability(path, findings, structure)`
- **Why this matters:** A CVE in an unused transitive dep is noise. This is the #1 signal for smart prioritization.
- **Test:** Add a dep to sample_app that's in requirements.txt but never imported. Verify it's marked `reachable: false`.
- **Done when:** Findings have reachability annotation, test passes

### 2.4 Full context bundle
- **What:** Combine repo structure + deps + reachability into one context object passed to the LLM
- **Input:** All outputs from 2.1, 2.2, 2.3 + scan summary
- **Output:** A single JSON context bundle: `{repo: {...}, dependencies: {...}, findings: [{...finding, reachable, direct}], scan_meta: {...}}`
- **File:** `agent/context_builder.py` — new function `build_context(path, scan_summary_path)`
- **Test:** End-to-end: scan sample_app → build context → verify bundle is complete
- **Done when:** One function call produces the full context bundle

## Epic 3: The Prioritizer — Smart Triage Engine

This is the core IP. The prioritizer takes raw findings + context and produces a ranked, actionable list. It answers: "of these 200 findings, which 3-5 should I fix this week?"

### 3.1 Scoring model design
- **What:** Define the scoring formula that ranks findings
- **Input:** A finding with context (severity, reachability, fix availability, direct/transitive)
- **Output:** Numeric score (0-100) + human-readable priority tier (critical/high/medium/low/noise)
- **Factors (weighted):**
  - Severity (CVSS from scanner): 25%
  - Reachability (from context builder): 30% — biggest weight, this is the differentiator
  - Fix available (is there a patched version?): 20%
  - Direct vs transitive dependency: 15%
  - Exploit known in the wild (from Trivy's data): 10%
- **File:** `agent/prioritizer.py` — new module
- **Test:** Given 10 findings with varying attributes, verify ranking matches expected order
- **Done when:** Scoring function produces sensible rankings on real scan data

### 3.2 Fix availability detection
- **What:** For each finding, determine if a fix exists and what it is
- **Input:** Finding with package name + current version
- **Output:** `{fix_available: true, fix_version: "2.1.1", breaking_change: false, notes: "minor bump"}`
- **How:** Parse Trivy's `FixedVersion` field. For Python, check if the fix version is compatible with the current pinning strategy. Flag major version bumps as potential breaking changes.
- **File:** `agent/prioritizer.py` — function `assess_fix_availability(finding)`
- **Test:** Finding with known fix → returns fix info. Finding without fix → returns `fix_available: false`.
- **Done when:** Every finding has fix availability data

### 3.3 Triage output generation
- **What:** Produce the final ranked output — the "fix these 3-5 things this week" list
- **Input:** Scored findings from 3.1 + fix data from 3.2
- **Output:** Ranked list with: priority tier, finding summary, why it matters (1 sentence), recommended action, effort estimate (trivial/moderate/complex), confidence level
- **Format:** JSON + markdown (both generated)
- **File:** `agent/prioritizer.py` — function `generate_triage(scored_findings, context, top_n=5)`
- **LLM usage:** The prioritizer uses LLM to generate the "why it matters" and "recommended action" sentences — but the RANKING is algorithmic (scoring model), not LLM-dependent. This is important: ranking must be deterministic and explainable.
- **Test:** Given scored findings, verify output has correct structure and top-N selection
- **Done when:** Running on sample_app scan produces a clear, actionable 3-5 item list

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
- **Input:** Triage output from Epic 3
- **Output:** Markdown report with: top findings ranked, for each: what it is, why it matters, what to do, effort estimate
- **File:** Modify `agent/report.py` (refactored from `security_summary.py`)
- **Key change:** Report now shows PRIORITIZED findings with context, not just a dump of everything
- **Done when:** Report reads like "fix these 3 things" not "here are 200 CVEs"

### 4.2 CRA vulnerability disclosure format
- **What:** Add `--cra` flag to report command for EU Cyber Resilience Act compliance
- **Input:** Same triage data
- **Output:** Structured vulnerability disclosure document with: affected component, severity, exploitability, remediation status, timeline, responsible contact
- **Why now:** EU CRA mandatory vuln reporting starts Sept 2026 — 6 months away. Every EU-selling company will need this.
- **File:** `agent/report.py` — new function `generate_cra_report(triage, context)`
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

## Backlog
- [ ] Checkov scanner integration (IaC scanning)
- [ ] Gitleaks scanner integration (secret detection)
- [ ] Semgrep scanner integration (SAST patterns)
- [ ] SBOM export (CycloneDX / SPDX format)
- [ ] Slack/email notification on new critical findings
- [ ] Done-for-you service playbook (how to run PatchPilot for clients)
- [ ] Hosted automation tier (scheduled scans, auto-PRs)
- [ ] Dependency license compliance checking
- [ ] Historical trend tracking (are we getting more or less secure over time?)
