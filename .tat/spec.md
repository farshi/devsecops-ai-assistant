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
│   ├── scan.py               # Scanner runners (Trivy, extensible)
│   ├── context_builder.py    # Repo intelligence: deps, imports, Dockerfile, structure
│   ├── prioritizer.py        # The brain: ranks findings by reachability + fixability + severity
│   ├── report.py             # Generates action plans and compliance docs
│   ├── review.py             # PR-level security review
│   ├── llm_client.py         # Claude + GPT support, provider-agnostic
│   └── state.py              # Triage memory: accepted risks, dismissed findings
├── prompts/                   # System prompts per workflow
├── tests/                     # Unit + integration tests
├── .patchpilot/              # Per-project state (triage decisions, baselines)
│   ├── state.json            # What's been triaged, accepted, dismissed
│   ├── baseline.json         # Last known scan state (for "new findings only")
│   └── config.yaml           # Severity thresholds, ignore rules, LLM preference
└── reports/                   # Generated outputs
```

### Key design decisions
- **File-based state** (`.patchpilot/`) — no database, no backend. State travels with the repo.
- **LLM-agnostic** — Claude and GPT both supported. User picks via config.
- **Scanner-agnostic** — starts with Trivy, architecture supports adding Checkov/Gitleaks/Semgrep.
- **Prioritizer is the core IP** — this is where the intelligence lives, not in fix generation.

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

## Constraints
- Python CLI (Click framework) — keep existing foundation
- LLM APIs (Claude + GPT) — user provides their own keys
- Trivy as primary scanner — free, well-maintained, broad coverage
- No web UI — CLI + file output + CI integration only
- No database — file-based state only
