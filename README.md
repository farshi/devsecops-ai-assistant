# devsecops-ai-assistant

An AI layer on top of the DevSecOps pipeline. Instead of asking developers to read raw scanner output, this tool assembles repo context, runs security scanners, and uses Claude to produce actionable plans, reviews, and risk summaries.

---

## What It Does

```
┌─────────────────────────────────────────────────────────────┐
│                        Developer                            │
│                 writes code in  app/                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │     Context Builder     │
              │  repo tree · deps       │
              │  Dockerfile · Terraform │
              │  CI workflows · diff    │
              └────────────┬────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐
    │    Trivy    │ │   Checkov   │ │  (Semgrep  │
    │  fs · image │ │  Terraform  │ │  Gitleaks) │
    └──────┬──────┘ └──────┬──────┘ └─────┬──────┘
           │               │               │
           └───────────────▼───────────────┘
                    JSON reports
                  reports/*.json
                           │
              ┌────────────▼────────────┐
              │       AI Layer          │
              │       (Claude)          │
              │                         │
              │  prompt + context JSON  │
              └────────────┬────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────▼──────┐  ┌────────▼───────┐  ┌──────▼────────┐
│    analyze   │  │     scan       │  │    review     │
│              │  │                │  │               │
│ Understand   │  │ Triage scanner │  │ PASS/WARN/    │
│ repo posture │  │ output into    │  │ BLOCK verdict │
│ from static  │  │ prioritized    │  │ on a diff     │
│ context      │  │ risk summary   │  │ before merge  │
└──────────────┘  └────────────────┘  └───────────────┘
        │                  │                  │
        └──────────────────▼──────────────────┘
                           │
              ┌────────────▼────────────┐
              │         plan            │
              │                         │
              │  Secure implementation  │
              │  steps before code is   │
              │  written  (shift left)  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │        Output           │
              │                         │
              │  reports/               │
              │  plans/                 │
              │  reviews/               │
              └─────────────────────────┘
```

---

## Five Workflows

| Workflow | When | Input | Output |
|---|---|---|---|
| `analyze` | Onboarding a repo, quarterly review | repo path | `reports/analysis_*.md` |
| `scan` | On push, scheduled | repo path | `reports/<target>_summary_*.json` |
| `report` | After scan — generate human report | target name | `reports/<target>_security-report_*.md` |
| `plan` | Before writing a feature | change description + repo | `plans/plan_*.md` |
| `review` | Before merging a PR | git diff + repo | `reviews/review_*.md` |

---

## Project Structure

```
devsecops-ai-assistant/
├── agent/                  # Python orchestration layer
│   ├── scan.py             # scan orchestrator
│   ├── security_summary.py # report generator (Claude)
│   ├── analyze.py          # analyze workflow (stub)
│   ├── plan.py             # plan workflow (stub)
│   ├── review.py           # review workflow (stub)
│   ├── context_builder.py  # assembles repo context for Claude (stub)
│   ├── claude_client.py    # Anthropic SDK wrapper
│   └── utils.py            # slugify, timestamp
│
├── devsecops/
│   ├── runners/            # Python scanner runners (run_trivy.py)
│   ├── parsers/            # normalize raw JSON → v1 findings schema
│   └── scanners/           # legacy shell wrappers (unused)
│
├── prompts/                # system prompts loaded by agent/ code
│   ├── security_summary.md
│   ├── analyze.md
│   ├── plan.md
│   └── review.md
│
├── tests/                  # pytest test suite
├── sample_app/             # sample FastAPI app for scanner demos
├── reports/                # scan JSON + AI-generated reports
├── plans/                  # generated implementation plans
└── reviews/                # generated code reviews
```

---

## Scanners

| Tool | What it scans | Trigger |
|---|---|---|
| Trivy (fs) | Dependencies, CVEs, misconfigs | Always |
| Trivy (image) | Container base image CVEs | When Dockerfile is present |
| Checkov | Terraform, GitHub Actions | When `.tf` or `.github/` is present |
| Semgrep | SAST, custom rules | Coming soon |
| Gitleaks | Hardcoded secrets | Coming soon |

---

## Running the CLI

> Packaging is not yet configured. Until a `devsec` entry point is added, invoke the CLI directly:

```bash
pip install -r requirements.txt

python cli.py analyze  --path ./app --target-name myapp
python cli.py scan     --path ./app --target-name myapp --profile standard
python cli.py report   --target-name myapp
python cli.py plan     --path ./app --target-name myapp --task "add auth endpoint"
python cli.py review   --path ./app --target-name myapp --branch feature/auth

# See what any command would do without running it
python cli.py scan --path ./app --target-name myapp --dry-run
```

---

## The Core Idea

Security tools produce noise. Developers don't have time to read it.

This project inserts an AI reasoning layer between scanner output and the developer — assembling only the relevant context, and producing output that answers one question: **what do I fix first, and how?**
