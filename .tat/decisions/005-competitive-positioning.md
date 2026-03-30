# ADR-005: Competitive Positioning — Triage Layer, Not Platform

## Context
Competitive research (March 2026) analyzed 30+ tools in the vulnerability management space. The market is crowded at the top (Snyk $25-105/dev/mo, Endor Labs enterprise, Semgrep $35/dev/mo) but empty at the bottom. Key findings:

- **No CLI-first, open-source, scanner-agnostic triage layer exists**
- Closest competitor (Konvu) does "agentic triage on existing scanners" but is SaaS-only, enterprise-priced, closed-source
- Dependabot called a "noise machine" (Feb 2026) — developer trust in scanning tools is eroding
- 59K CVEs forecast for 2026, only 15-30% exploitable in context
- EU CRA reporting obligations start Sept 2026 — no CLI tool targets compliance yet
- No tool offers extensible triage/prioritization logic (only detection plugins)

## Decision
PatchPilot positions as a **thin, extensible triage layer** — not a platform.

## What PatchPilot IS
- Scanner-agnostic (consumes Trivy, Grype, Semgrep, any SARIF output)
- CLI-first (lives in terminal/CI, not another dashboard)
- Plugin architecture (users extend triage, not just detection)
- AI-powered but transparent (evidence for every decision, honest confidence)
- CRA-ready (compliance reporting as first-mover)
- Open-source core (free forever for basic triage)

## What PatchPilot is NOT
- Not a scanner (Trivy/Grype already exist and are free)
- Not a dashboard (that's where $25-105/dev/mo competitors live)
- Not a runtime monitor (Oligo/Rezilion territory)
- Not a full AppSec platform (Snyk/Endor/Semgrep territory)
- Not an "AI remediation" tool (fix generation is commodity; knowing WHAT to fix is the value)

## Strategic Moats
1. **Plugin architecture for triage** — unique in the market, enables community extensions
2. **Python/JS reachability with honest confidence** — competitors weak here
3. **Package name→import name mapping** — unique dataset opportunity
4. **CRA compliance reporting** — first-mover in CLI space, Sept 2026 deadline creates urgency
5. **Scanner-agnostic** — works with whatever scanner the team already uses

## Pricing Direction
- Free: CLI + basic prioritization (EPSS + KEV + fix availability)
- Paid service ($299-799/engagement): "done-for-you" triage report
- Pro subscription (later): hosted scans, auto-PR, CRA exports

## Risks
1. GitHub could ship Copilot-powered triage (acknowledged Dependabot noise problem)
2. Snyk/Semgrep expand reachability language coverage
3. LLM costs could make free tier unsustainable
4. Reachability false negatives destroy trust instantly

## Status
ACCEPTED
