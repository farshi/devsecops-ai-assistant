# ADR-008: Vision Evolution — From Scanner Triage to Security Engineer Assistant

## Context
GPT-reviewed article proposes AI replacing manual security review entirely. The question is: how much of this vision applies to PatchPilot NOW vs LATER, and what should we change?

## Current PatchPilot Position (ADR-005)
- Triage layer between scanner and developer
- "Fix these 3 things" — noise reduction
- CLI-first, open-source, scanner-agnostic

## Article Vision (expanded scope)
An AI Security Engineer Assistant that:
1. Reviews code and infrastructure continuously
2. Suggests fixes and generates patches
3. Maps issues to compliance frameworks (CRA, SOC2)
4. Helps write security policies and guardrails
5. Generates audit evidence
6. Provides risk dashboards and trends
7. Helps teams build secure systems by default

## Analysis: What's New vs What We Have

### Already in PatchPilot (shipped or planned)
| Capability | Status |
|-----------|--------|
| Scan + triage + prioritize | ✅ Sprint 1 done |
| Reachability analysis | ✅ Shipped |
| Fix availability + effort estimation | ✅ Shipped |
| CRA compliance reporting | 📋 Sprint 3 planned |
| CI gating (--fail-on) | ✅ Shipped |
| PR security review | 📋 Epic 5.3 planned |

### New from article (not in current plan)
| Capability | Value | Effort | When |
|-----------|-------|--------|------|
| **Guardrail design** — AI suggests preventive controls, not just reactive fixes | High | Medium | v0.2+ |
| **Security metrics/trends** — time-to-fix, risk per team/service, repeated mistakes | High | Medium | v0.3+ |
| **Policy-as-code generation** — convert security rules into CI/CD controls | High | High | v0.3+ |
| **Auto-remediation** — generate patches, create tickets, track to closure | Medium | High | v0.3+ |
| **Risk dashboards** — visual risk posture per service/team | Low for CLI | High | v0.4+ (needs UI) |
| **Architecture risk assessment** — evaluate system design for security | Medium | High | v0.4+ |

### The key strategic question from the article
> "Are we building a tool that scans for problems, or a system that helps design and operate a secure software development environment?"

**Answer for PatchPilot:** We're building BOTH, but in phases:
- **v0.1** (now): Tool that triages scanner output → "fix these 3 things"
- **v0.2**: Tool that also reviews PRs and suggests guardrails → "prevent these problems"
- **v0.3**: System that tracks risk over time and generates compliance evidence → "prove you're secure"
- **v0.4**: Platform that helps design secure architecture → "build it right from the start"

## Decision
1. **Don't change v0.1 scope** — ship the triage MVP first. Validated by research, unique position.
2. **Capture article ideas as backlog items** — they inform the product roadmap beyond v0.1.
3. **Add "security metrics" to Sprint 3** — time-to-fix tracking and repeated-issue detection are high value, moderate effort.
4. **Rename the vision** — PatchPilot is the triage product. The broader vision (security engineer assistant) could be the platform name if we go there.

## What NOT to do
- Don't pivot v0.1 to be a "security platform" — that's scope explosion
- Don't add dashboards — CLI-first is the differentiator
- Don't auto-remediate yet — trust must be earned through accurate triage first

## Status
ACCEPTED — informs roadmap, does not change Sprint 2
