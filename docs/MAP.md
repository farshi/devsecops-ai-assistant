# Spec → Docs Traceability Map

When a spec section changes, update the mapped docs. See ADR-007 for cascade rules.

## Cascade Hierarchy

```
.tat/spec.md          ← source of truth
    ↓
docs/*.md             ← user/contributor docs
    ↓
README.md             ← marketing overview (if user-facing change)
```

## Mapping

| Spec Section | → Doc File | → Doc Section | Last Synced |
|---|---|---|---|
| What PatchPilot Does (core workflow) | `concepts.md` | Overview | 2026-03-30 |
| What PatchPilot Is NOT | `concepts.md` | What PatchPilot Isn't | 2026-03-30 |
| Target User | `concepts.md` | Who It's For | — |
| Core Principles | `concepts.md` | Design Principles | — |
| Canonical Finding Schema (ADR-002) | `concepts.md` | Finding | 2026-03-30 |
| Finding Types (ADR-004) | `concepts.md` | Finding Types | 2026-03-30 |
| Reachability Approach (ADR-003) | `concepts.md` | Reachability | 2026-03-30 |
| Competitive Positioning (ADR-005) | `concepts.md` | How PatchPilot Compares | 2026-03-30 |
| Target Architecture | `architecture.md` | Project Structure | 2026-03-31 |
| Target Architecture | `architecture.md` | Data Flow | 2026-03-31 |
| Extensibility Model (ADR-001) | `architecture.md` | Plugin Pipeline | 2026-03-31 |
| Extensibility Model (ADR-001) | `plugins.md` | All | 2026-03-31 |
| Plugin Interface Contracts | `plugins.md` | ABC Reference | 2026-03-31 |
| Scoring Model (Epic 3) | `concepts.md` | Priority Scoring | 2026-03-30 |
| CRA Compliance (Epic 4.2) | `concepts.md` | EU CRA | 2026-03-30 |
| Monetization | — | — | Not in docs (internal) |
| Constraints | `architecture.md` | Constraints | 2026-03-31 |
| All ADRs | `decisions.md` | Per-entry | 2026-03-31 |

## Key Terms → Definitions Location

| Term | Defined In | Used In |
|---|---|---|
| EPSS | `concepts.md` | prioritizer, enrichment, reports |
| KEV | `concepts.md` | prioritizer, enrichment, reports |
| CVSS | `concepts.md` | Finding schema, scoring |
| Reachability | `concepts.md` | context_builder, prioritizer |
| Finding | `concepts.md` | everywhere |
| Finding Type | `concepts.md` | scanner adapters, prioritizer |
| Priority Tier | `concepts.md` | prioritizer, reports |
| VEX | `concepts.md` | future enrichment |
| CRA | `concepts.md` | report formatters |
| SBOM | `concepts.md` | future feature |
| Scanner Adapter | `plugins.md` | plugin system |
| Enrichment Plugin | `plugins.md` | plugin system |
| Prioritization Strategy | `plugins.md` | plugin system |
| Output Formatter | `plugins.md` | plugin system |

## How to Update

1. Change something in `.tat/spec.md`
2. Check this map — which docs are affected?
3. Update those docs
4. Update "Last Synced" column
5. If user-visible → check README too
