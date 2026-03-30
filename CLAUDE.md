# DevSecOps AI Assistant — Claude Code Instructions

## What This Project Is
A Python CLI tool that runs security scanners and uses Claude to generate actionable security reports, plans, and reviews. Five commands: scan, report, analyze, plan, review.

## Development Rules
- Read `.tat/plan.md` for current task state
- One task = one branch = one PR
- Branch naming: `tat/<epic>/<task-name>`
- Conventional commits: `feat(scan):`, `fix(report):`, `test(analyze):` etc
- Python code in `agent/`, CLI in `cli.py`, prompts in `prompts/`, tests in `tests/`

## Project Structure
- `cli.py` — Click CLI with 5 commands
- `agent/` — Core logic (scan, report, analyze, plan, review, context_builder, claude_client)
- `prompts/` — System prompts for Claude (one per workflow)
- `tests/` — pytest tests
- `reports/` ��� Scanner output and generated reports
- `sample_app/` — Demo FastAPI app for scanning
- `.tat/` — TAT project state (spec, plan)

## Key Patterns
- Scanner output → `reports/<target>_<scanner>_<date>.json`
- Summary → `reports/<target>_summary_<date>.json`
- Reports → `reports/<target>_security-report_<date>.md`
- Claude client uses `claude-opus-4-6` with 4096 max tokens
