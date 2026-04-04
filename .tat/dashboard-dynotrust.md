# DynoTrust Dashboard — Brainstorm & Decisions

**Date:** 2026-04-04
**Status:** Brainstormed, ready to start as separate repo
**Repo:** TBD (separate from PatchPilot — different runtime, different license)

---

## The Big Idea

**DynoTrust becomes:** "Continuous compliance for engineering teams — powered by PatchPilot."

Not a compliance *mapping* service. A compliance *automation* product.

> Your scanner finds 200 CVEs. Your auditor wants evidence you handled them.
> PatchPilot triages what matters. DynoTrust proves you did it right.

## Brand Strategy

- **PatchPilot** = open-source CLI (developer adoption engine, MIT, Python)
- **DynoTrust** = commercial brand (compliance dashboard + monetization, separate repo, TypeScript)
- Separate repos, separate licenses. Shared contract: `.patchpilot/` JSON schema.

## Decisions Made

1. **Separate brands** — PatchPilot stays OSS CLI, DynoTrust is commercial
2. **Separate repos** — different runtimes (Python vs TS), different deploy targets (PyPI vs Cloudflare), possible different licenses
3. **Tech stack** — Hono + Cloudflare Workers + R2 + Supabase + Vanilla HTML/CSS + Bun (same as oneminuta)
4. **No SPA framework** — no React, no SvelteKit. Server-rendered HTML. GPT and Opus agreed.
5. **Dashboard first** — build the product before the marketing site
6. **Manual upload first** — fastest path to demo, GitHub App later

## Tech Stack

```
Runtime:     Bun
Backend:     Hono on Cloudflare Workers
Storage:     Cloudflare R2 (raw .patchpilot/ JSON files)
Database:    Supabase (auth + repo metadata + user accounts)
Frontend:    Server-rendered HTML + vanilla CSS/JS
Charts:      Lightweight (Chart.js or inline SVG sparklines)
Deploy:      Cloudflare Pages + Workers
Domain:      dynotrust.com
```

**Why:** Same as oneminuta (proven, familiar). Read-heavy dashboard, no framework tax.

## Product Tiers

| Tier | Price | What |
|------|-------|------|
| PatchPilot CLI | Free | Open-source triage engine |
| Done-for-you | $999-2,999/engagement | We run PatchPilot, deliver report |
| DynoTrust Pro | $149-499/mo/repo | Hosted triage + dashboard + compliance export |
| Enterprise | Custom | Multi-repo + RBAC + SSO + custom frameworks |

## Dashboard UX Spec

### Audiences
1. **CTO / VP Eng** — "Are we in control?" Weekly check.
2. **Auditor / compliance officer** — "Show me proof and timestamps."

### Design principle
**Default to summary, drill down to proof.** Never dump raw JSON first.

### Pages

#### 1. Overview (landing)
- Posture score (composite 0-100)
- Findings by severity/tier (critical/high/medium/low)
- Trend sparkline (improving/degrading)
- "What changed since last scan" (new/resolved/regressions)
- Top 3-5 action items

#### 2. Findings
- Sortable/filterable table
- Columns: priority score, severity, reachability, fix available, status, age, repo
- Click → detail drawer with evidence

#### 3. Audit Trail
- Timeline of triage decisions (dismiss/accept/close/reopen)
- Timestamps, rationale
- Linked to source scan snapshot

#### 4. Compliance
- CRA / SOC2 / ISO status cards
- "Evidence available" / "gap" indicators
- Control mapping from existing PatchPilot formatters

#### 5. Trends
- Historical posture over time (from history.json)
- Open vs resolved vs accepted risk
- Mean time to triage/remediate

#### 6. Repos (later)
- Multi-repo selector
- Per-repo posture

### Data flow (phased)
1. **MVP:** Manual upload of .patchpilot/ files → parse → render
2. **v2:** GitHub App reads repo .patchpilot/ on webhook
3. **v3:** Scheduled nightly sync + trend updates

### Export
- JSON download (MVP)
- CRA evidence bundle
- SOC2 evidence pack
- PDF executive summary (later)

### Demo flow
1. Load vulnerable_app data
2. Show 200 findings triaged to 3 priority items
3. Click one finding — show why it matters
4. Open compliance page — show CRA/SOC2 status
5. Export evidence bundle

## Website (dynotrust.com)

### Pages
| Page | Purpose |
|------|---------|
| Home | Hero + 3 value props + CTA |
| How It Works | CLI demo → CI → compliance export |
| Pricing | Free CLI / Pro / Enterprise |
| Docs | Link to PatchPilot docs |
| CRA Compliance | SEO landing page for EU CRA deadline |
| Blog | "Why scanning isn't enough", "CRA compliance checklist" |

### Hero
> "Stop triaging 200 CVEs. Start shipping compliant software."

## Competitive Positioning

### The One-Liner
> **Snyk tells you what's wrong. Claude tells you how to fix it. PatchPilot tells you what to fix *first* — and proves it to your auditor.**

### vs "Just Ask Claude/ChatGPT"
- No reachability context, no memory, hallucinated fixes, no compliance trail, no trends
- PatchPilot's moat: structured judgment with memory

### vs Snyk/Endor Labs ($25-105/dev/month)
- Scanner-agnostic, CLI-first, open-source core, file-based state, compliance built in

### vs Compliance platforms (Vanta, Drata)
- Actually does vulnerability triage, developer-facing, connects decisions to evidence

## Market Context (April 2026)
- EU CRA deadline: Sept 11, 2026 — 24h/72h/14d reporting obligations
- Penalties: up to 15M EUR / 2.5% global revenue
- No CLI tool targets CRA compliance yet
- DevSecOps market: $8.91B → $29.52B by 2031 (22.1% CAGR)
- 48,000+ new CVEs in 2025
- All competitors are SaaS dashboards

## Open Questions
- Timeline for done-for-you first customer?
- Existing DynoTrust consulting clients — transition plan?
- GitHub App vs OAuth for repo access in v2?

## Tasks (for the new DynoTrust repo)

| ID | Task |
|----|------|
| 1 | Scaffold Hono app — Cloudflare Workers + R2 + Bun, wrangler.toml |
| 2 | Demo data — export vulnerable_app .patchpilot/ state as seed files |
| 3 | State parser — read state.json, history.json, baseline.json from R2 |
| 4 | Upload flow — manual .patchpilot/ file upload to R2 |
| 5 | Overview page — posture score, severity breakdown, sparkline, top actions |
| 6 | Findings table — sortable/filterable, priority score, severity, status |
| 7 | Audit trail page — decision timeline with timestamps and rationale |
| 8 | Compliance page — CRA/SOC2/ISO status cards, evidence/gap indicators |
| 9 | Trends page — historical chart from history.json snapshots |
| 10 | Export — JSON download + CRA evidence bundle |
| 11 | Supabase auth — login, repo metadata storage |
| 12 | Deploy to Cloudflare — production setup, dynotrust.com domain |
| 13 | Landing page — hero, value props, pricing tiers (marketing) |
| 14 | CRA compliance landing page — SEO for EU CRA deadline |
