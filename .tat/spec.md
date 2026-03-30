# DevSecOps AI Assistant

## What
A CLI tool that sits on top of the DevSecOps pipeline. Instead of asking developers to read raw scanner output, it assembles repo context, runs security scanners (Trivy, Checkov, Semgrep, Gitleaks), and uses Claude to produce actionable plans, reviews, and risk summaries.

## Why
Security scanner output is noisy and hard to act on. Most developers ignore it or don't know what to prioritize. This tool translates scanner findings into developer-friendly guidance — what to fix, why it matters, and how to fix it. Demo-able as a portfolio piece for DevSecOps roles.

## What It Does (5 Workflows)
1. **scan** — Run security scanners against a repo (Trivy, Checkov, Semgrep, Gitleaks)
2. **report** — Generate human-readable security report from scan results via Claude
3. **analyze** — Understand repo structure and security posture
4. **plan** — Generate a secure implementation plan before coding a feature
5. **review** — Review code changes for security issues

## Current State
- scan + report are working (Trivy scanner, Claude integration, tests)
- analyze, plan, review are stubs (prompts written, code not wired)
- context_builder is empty (needed by analyze/plan/review)
- Only Trivy scanner implemented, Checkov/Semgrep/Gitleaks stubs exist

## Constraints
- Python CLI (Click framework)
- Claude API via Anthropic SDK
- Scanners must be installable via package managers (no custom binaries)
- Output is markdown and JSON — human-readable, git-friendly

## Non-goals
- Not a replacement for CI/CD security scanning — complementary local tool
- Not a web UI (CLI-first)
- Not trying to auto-fix vulnerabilities — advise, don't act
