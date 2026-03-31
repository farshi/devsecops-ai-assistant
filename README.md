# PatchPilot

**Smart vulnerability triage for developers.** Turns 200 scanner findings into "fix these 3 things this week."

```
Scanner output (Trivy)
    → PatchPilot reads your codebase context
    → Checks reachability: is this package actually imported?
    → Checks exploitability: EPSS score + CISA KEV catalog
    → Scores and ranks by what actually matters
    → "Fix these 3 things. Here's why. Here's how."
```

## Why PatchPilot?

Security scanners find everything. Developers fix nothing — because 200 CVEs with no context is just noise.

PatchPilot sits between your scanner and your team. It answers the question every developer asks: **"Which of these actually matter for MY code?"**

| What scanners tell you | What PatchPilot tells you |
|---|---|
| 200 CVEs sorted by CVSS | 3-5 ranked by reachability + exploitability |
| "CRITICAL: CVE-2024-xxxxx" | "This is imported in your auth module, actively exploited, patch available — fix today" |
| Same list every time | Only new/changed findings (with state tracking) |

## Quick Start

```bash
# Install
pip install -e .

# Prerequisites: Trivy must be installed
# macOS: brew install trivy
# Linux: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan and triage a project
patchpilot triage --path ./vulnerable_app --target-name vuln-demo

# Triage with CI gating (exit code 1 if critical findings)
patchpilot triage --path ./app --target-name myapp --fail-on critical

# Generate AI-enhanced report (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=your-key
patchpilot report --target-name myapp --path ./app
```

## What It Does

```
patchpilot triage --path ./vulnerable_app --target-name demo --top 5

[triage]
  Total findings: 10
  Priority breakdown: 2 critical, 3 high, 4 medium, 1 low, 0 noise

  Top 5 action items:

    #1 [CRITICAL] CVE-2024-34069 (score: 87)
       Werkzeug debugger vulnerable to remote code execution
       Action: Upgrade werkzeug from 2.0.0 to >= 3.0.3
       Effort: complex

    #2 [CRITICAL] CVE-2023-30861 (score: 72)
       Flask session cookie disclosure
       Action: Upgrade flask from 2.0.0 to >= 2.3.2
       Effort: moderate

    #3 [HIGH] CVE-2023-50447 (score: 68)
       Pillow arbitrary code execution
       Action: Upgrade pillow from 8.0.0 to >= 10.2.0
       Effort: complex
    ...
```

## How It Works

PatchPilot uses a **deterministic, weighted scoring model** — not AI guesswork:

| Signal | What It Measures | Weight |
|--------|-----------------|--------|
| **Reachability** | Is the package actually imported in your code? | 25% |
| **EPSS** | Probability of exploitation in next 30 days | 15% |
| **KEV** | Is it in CISA's Known Exploited Vulnerabilities list? | 15% |
| **Severity/CVSS** | How bad is it if exploited? | 20% |
| **Fix available** | Can you actually fix it right now? | 15% |
| **Direct dependency** | Your dep or a transitive one? | 10% |

Reachability is the core differentiator: a CVSS 9.8 in an unused transitive dependency is noise. A CVSS 7.0 in your auth module is urgent.

## Commands

| Command | What It Does |
|---------|-------------|
| `patchpilot scan` | Run Trivy scanner, produce summary.json |
| `patchpilot triage` | Full pipeline: scan → context → enrich → score → rank |
| `patchpilot report` | AI-enhanced security report from triage results |
| `patchpilot analyze` | Understand repo structure and security posture (coming soon) |
| `patchpilot plan` | Secure implementation plan for a feature (coming soon) |
| `patchpilot review` | Security review of PR changes (coming soon) |

## Plugin Architecture

PatchPilot is extensible through four plugin types:

| Plugin Type | What It Does | Built-in |
|------------|-------------|----------|
| Scanner Adapter | Normalize scanner output | Trivy |
| Enrichment Plugin | Add context to findings | EPSS, KEV, fix availability |
| Prioritization Strategy | Score and rank findings | Default weighted scorer |
| Output Formatter | Format results | Markdown, JSON |

Write your own plugins for Grype, Checkov, Semgrep, AWS SecurityHub, CRA compliance, Jira tickets, and more.

## Project Structure

```
patchpilot/
├── cli.py                          # Click CLI
├── agent/
│   ├── models.py                   # Finding dataclass (canonical schema)
│   ├── context_builder.py          # Repo intelligence (structure, deps, reachability)
│   ├── prioritizer.py              # Triage engine (scoring + ranked output)
│   ├── scan.py                     # Scan orchestrator
│   ├── security_summary.py         # Report generator (Claude)
│   └── plugins/
│       ├── base.py                 # Plugin ABCs
│       ├── scanners/trivy.py       # Trivy adapter
│       ├── enrichment/epss.py      # EPSS scores
│       ├── enrichment/kev.py       # CISA KEV catalog
│       ├── enrichment/fix_availability.py  # Fix effort assessment
│       └── scoring/default.py      # Weighted scoring model
├── prompts/                        # System prompts for Claude
├── docs/                           # Concepts, architecture, glossary
├── tests/                          # 171 tests
├── sample_app/                     # Clean FastAPI demo app
└── vulnerable_app/                 # Intentionally vulnerable demo app
```

## Requirements

- Python >= 3.9
- [Trivy](https://aquasecurity.github.io/trivy/) (vulnerability scanner)
- `ANTHROPIC_API_KEY` (optional — only for AI-enhanced reports)

## Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run triage on the vulnerable demo app
patchpilot triage --path ./vulnerable_app --target-name vuln-demo --top 5
```

## License

MIT
