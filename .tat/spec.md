# PatchPilot

## The Problem (why this exists)

Security scanners produce noise. Trivy finds 200 CVEs. Checkov flags 50 misconfigs. Developers see the wall of alerts and either:
- Ignore everything (most common)
- Fix random things that look scary (wasted effort)
- Spend hours researching which CVEs actually matter for their code (expensive)

Meanwhile, AI can generate fixes — anyone can paste a CVE into Claude and get a patch. That's not the hard part anymore.

**The hard part is deciding WHAT to fix, in WHAT order, and WHY.**

That requires understanding:
- Is this vulnerability even reachable in my code?
- Does this dependency actually get called in production?
- Is there a fix available, or am I stuck?
- What's the blast radius if I upgrade this package?
- Which 3 of these 200 findings actually put me at risk?

No scanner answers these questions. And no amount of "AI remediation" helps if you're fixing the wrong things.

## What PatchPilot Does

PatchPilot is the **triage brain** between your scanner and your team. It takes raw scanner output and turns it into **a prioritized, context-aware action plan** that a developer can act on in minutes — not hours.

### Core workflow
```
Scanner output (Trivy JSON)
    ↓
PatchPilot reads your codebase context
    ↓
Prioritizes: what's reachable, fixable, and urgent
    ↓
Outputs: ranked action plan + optional fix suggestions
    ↓
Developer acts on 3 things instead of 200
```

### What makes it different from "just use Claude"
1. **Context-aware prioritization** — understands your stack, dependencies, Dockerfile, and code structure to rank what actually matters
2. **Reachability signal** — flags whether a vulnerable dependency is actually imported/used vs just sitting in requirements.txt
3. **Fix availability awareness** — knows if a patch version exists, if it's a breaking change, if there are known regressions
4. **Zero new workflow** — runs in your terminal, outputs to your PR, fits into your existing CI. Not another dashboard to check.
5. **Cumulative intelligence** — remembers what you've triaged before, doesn't re-alert on accepted risks

## What PatchPilot Is NOT

- **Not another scanner.** It consumes scanner output (Trivy, Checkov, etc.). It doesn't replace them.
- **Not an "AI remediation" tool.** Generating patches is a commodity. Knowing which patch matters is the value.
- **Not a dashboard.** No web UI. CLI + PR comments + CI output. Lives where developers already work.
- **Not another tool to learn.** If it adds friction, it fails. The bar is: faster than doing it yourself.

## Target User

**Small engineering teams (2-15 devs) without a dedicated security engineer.**

They're usually:
- Startup CTOs / senior devs who "own" security by default
- Running Python and/or Node.js services in Docker
- Using Trivy or similar because it's free
- Ignoring most findings because they don't know what matters
- Under pressure from customers, SOC2, or EU CRA to show security posture

They don't want a security platform. They want: **"Just tell me the 3 things I need to fix this week."**

## Core Principles

1. **Signal over noise** — fewer, better recommendations beats comprehensive scan dumps
2. **Context is king** — a CVE in an unused transitive dependency is not the same as a CVE in your auth module
3. **Zero friction** — if it takes more than 60 seconds to get value, redesign it
4. **No new workflow** — plug into git, CI, PRs. Don't make people go somewhere new.
5. **Honest confidence** — say "I'm not sure this is reachable" instead of pretending certainty
6. **Cumulative memory** — learn from past triage decisions, don't re-surface dismissed findings

## Technical Architecture

### What exists today
- `cli.py` — Click CLI with scan + report commands working
- `agent/scan.py` — Trivy runner, parses JSON, writes summary
- `agent/security_summary.py` — Claude-powered report generation
- `agent/claude_client.py` — Anthropic SDK wrapper
- `prompts/*.md` — System prompts for all workflows (4 written)
- `agent/analyze.py`, `plan.py`, `review.py`, `context_builder.py` — stubs (empty)
- `tests/test_report.py` — 3 passing tests
- `sample_app/` — FastAPI demo app

### Target architecture
```
patchpilot/
├── cli.py                    # Click CLI: scan, triage, report, review
├── agent/
│   ├── models.py             # Canonical Finding dataclass + shared types
│   ├── scan.py               # Scanner runners (Trivy, extensible)
│   ├── context_builder.py    # Repo intelligence: deps, imports, Dockerfile, structure
│   ├── prioritizer.py        # The brain: ranks findings by reachability + fixability + severity
│   ├── report.py             # Generates action plans and compliance docs
│   ├── review.py             # PR-level security review
│   ├── llm_client.py         # Claude + GPT support, provider-agnostic
│   ├── state.py              # Triage memory: accepted risks, dismissed findings
│   └── plugins/              # Plugin ABCs + built-in implementations
│       ├── base.py           # ScannerAdapter, EnrichmentPlugin, PrioritizationStrategy, OutputFormatter
│       ├── scanners/         # Built-in scanner adapters (Trivy, Grype)
│       ├── enrichment/       # Built-in enrichment (EPSS, KEV, fix availability)
│       ├── scoring/          # Built-in prioritization strategies
│       └── formatters/       # Built-in output formatters (markdown, JSON)
├── prompts/                   # System prompts per workflow
├── tests/                     # Unit + integration tests
├── .patchpilot/              # Per-project state (triage decisions, baselines)
│   ├── state.json            # What's been triaged, accepted, dismissed
│   ├── baseline.json         # Last known scan state (for "new findings only")
│   ├── config.yaml           # Severity thresholds, ignore rules, LLM preference
│   └── plugins/              # Project-specific plugin extensions
└── reports/                   # Generated outputs
```

### Key design decisions
- **File-based state** (`.patchpilot/`) — no database, no backend. State travels with the repo.
- **LLM-agnostic** — Claude and GPT both supported. User picks via config.
- **Scanner-agnostic** — starts with Trivy, architecture supports adding Checkov/Gitleaks/Semgrep/Grype/SARIF.
- **Prioritizer is the core IP** — this is where the intelligence lives, not in fix generation.
- **Plugin architecture** — well-defined interfaces let users and community extend every layer (see Extensibility Model below).
- **Honest confidence** — reachability says "unknown" when unsure instead of guessing wrong (see ADR-003).

### Canonical Finding Schema (ADR-002)

Every module operates on this shared contract. Scanner adapters normalize INTO it, enrichment layers ADD fields, prioritizer SCORES it, reporter FORMATS it.

```python
@dataclass
class Finding:
    # Core fields (set by scanner adapter)
    id: str                    # CVE-2023-xxxxx or advisory ID
    source_scanner: str        # trivy_fs, checkov, semgrep, grype, etc.
    finding_type: str          # os_package | language_dep | iac_misconfig | secret | code_pattern
    severity: str              # critical | high | medium | low | info
    title: str                 # Human-readable description
    package: str | None        # Package name (for dep findings)
    installed_version: str | None
    fixed_version: str | None  # None = no fix available
    location: str              # File path or "requirements.txt > package@version"

    # Normalized severity (scanner-agnostic)
    cvss_score: float | None = None  # Numeric CVSS (0.0-10.0) for deterministic scoring

    # Enrichment fields (added by context builder / enrichment plugins / prioritizer)
    reachable: str = "unknown" # true | false | unknown | not_applicable
    reachability_confidence: str = "none"  # high | medium | low | none
    reachability_evidence: str | None = None  # e.g., "import found in app/main.py:3"
    direct_dep: bool | None = None
    epss_score: float | None = None  # 30-day exploitation probability (0.0-1.0), from FIRST.org API
    in_kev: bool = False       # CISA Known Exploited Vulnerabilities catalog
    fix_available: bool = False
    fix_evidence: str | None = None  # e.g., "fixed in 1.2.3, minor bump"
    priority_score: int = 0    # 0-100, computed by prioritizer
    priority_tier: str = "unscored"  # critical | high | medium | low | noise | unscored
```

**Finding types and their analysis (ADR-004):**
| Type | Source | Reachability | Example |
|------|--------|-------------|---------|
| `os_package` | Trivy container scan | `not_applicable` | CVE in libssl, zlib |
| `language_dep` | Trivy fs, Grype, Semgrep | `true/false/unknown` | CVE in fastapi, lodash |
| `iac_misconfig` | Checkov, Trivy config | `not_applicable` | S3 bucket public |
| `secret` | Gitleaks, Semgrep | `not_applicable` | API key in source |
| `code_pattern` | Semgrep SAST | `not_applicable` | SQL injection pattern |

### Reachability Approach (ADR-003)

Reachability is the #1 signal for smart prioritization, but accuracy matters more than coverage. PatchPilot uses three-state reachability with explicit confidence:

- **`true`** — import confirmed in source code
- **`false`** — package present but not imported anywhere
- **`unknown`** — can't determine (dynamic loading, name mismatch, unsupported language)
- **`not_applicable`** — finding type doesn't support reachability (OS packages, IaC, secrets)

**Confidence levels:**
- **high**: Direct import match confirmed, or `top_level.txt` resolved
- **medium**: Package name matches import name (heuristic)
- **low**: No mapping found, best-guess
- **none**: No analysis performed

**Package→import name mapping:** Maintain a mapping of known Python/JS mismatches (top 50: PyYAML→yaml, Pillow→PIL, beautifulsoup4→bs4, opencv-python→cv2, etc.). Use `top_level.txt` from installed packages when available. Allow overrides in `.patchpilot/config.yaml`.

## Monetization

### Free (open-source CLI)
- Scan + triage + report locally
- Trivy support
- Basic prioritization
- Markdown reports

### Paid service ($299-799 per engagement)
- "Done-for-you" — we run PatchPilot on your repo, deliver a prioritized action plan
- Best for teams that want outcomes, not tools
- Can start selling immediately with current code

### Pro subscription ($49-149/mo, later)
- Hosted scheduled scans
- Auto-PR for high-confidence fixes
- CRA compliance exports
- Baseline tracking + "new findings only" mode
- Slack/email alerts

## Success Metrics

The product works when:
- A team goes from 200 findings to "fix these 3 this week" in under 5 minutes
- A developer trusts PatchPilot's ranking enough to skip reading raw scanner output
- A CTO can send PatchPilot's report to a customer asking about security posture
- Setup takes under 60 seconds
- The tool saves more time than it costs to run

## Extensibility Model (ADR-001)

PatchPilot uses a plugin architecture with well-defined interfaces. The core stays lean; everything else is extensible.

### Plugin Types
1. **Scanner Adapters** — normalize any scanner output to Finding schema
   - Built-in: Trivy, Grype
   - Community: Checkov, Semgrep, Snyk JSON, SARIF

2. **Enrichment Plugins** — add context to findings
   - Built-in: EPSS lookup, KEV catalog check, fix availability
   - Community: AWS SecurityHub, GCP SCC, VEX consumer, runtime evidence

3. **Prioritization Strategies** — custom scoring algorithms
   - Built-in: default weighted scorer (EPSS + KEV + CVSS + reachability + fix availability + direct/transitive)
   - Community: compliance-focused, risk-appetite tuned

4. **Output Formatters** — generate different report formats
   - Built-in: Markdown action plan, JSON
   - Community: CRA disclosure, SARIF, VEX/CSAF, Jira tickets, GitHub Issues

### Plugin Discovery
- Python entry points (setuptools) for pip-installable plugins
- Local plugin directory (`.patchpilot/plugins/`) for project-specific extensions
- Config-based registration in `.patchpilot/config.yaml`

### Interface Contracts (Python ABCs)
```python
class ScannerAdapter(ABC):
    def parse(self, raw_path: Path) -> list[Finding]: ...

class EnrichmentPlugin(ABC):
    def enrich(self, findings: list[Finding], context: dict) -> list[Finding]: ...

class PrioritizationStrategy(ABC):
    def score(self, findings: list[Finding]) -> list[Finding]: ...

class OutputFormatter(ABC):
    def format(self, triage_result: dict, context: dict) -> str: ...
```

## Competitive Positioning (ADR-005)

Based on competitive research (March 2026, 30+ tools analyzed):

**The gap:** No CLI-first, open-source, scanner-agnostic triage layer exists. Competitors are all SaaS dashboards at $25-105/dev/month. Closest competitor (Konvu) does "agentic triage on existing scanners" but is enterprise SaaS, closed-source.

**PatchPilot occupies a unique position:**
- Scanner-agnostic (Trivy, Grype, Semgrep, any SARIF) — not locked to one vendor
- CLI-first — lives in developer workflow, not another dashboard
- Plugin architecture — users extend triage, not just detection (unique in market)
- Honest confidence — says "unknown" instead of guessing on reachability
- CRA-ready — compliance reporting for EU deadline (Sept 11, 2026)
- Open-source core — free forever for basic triage

**NOT competing with:** Snyk (full platform), Wiz (cloud CNAPP), Oligo (runtime monitoring)
**Competing with:** developer time wasted manually triaging scanner output

**Key market facts:**
- 59K CVEs forecast for 2026, only 15-30% actually exploitable in context
- Dependabot called a "noise machine" (Feb 2026) — developer trust eroding
- EU CRA penalties up to 15M EUR / 2.5% global revenue — no CLI tool targets compliance yet

## Constraints
- Python CLI (Click framework) — keep existing foundation
- LLM APIs (Claude + GPT) — user provides their own keys
- Trivy as primary scanner — free, well-maintained, broad coverage
- CLI + file output + CI integration
- File-based state (.patchpilot/)

## DynoTrust (separate repo)
Commercial compliance dashboard built on PatchPilot. Separate brand, separate repo.
Full spec, tech stack, UX, and tasks: `.tat/dashboard-dynotrust.md`
