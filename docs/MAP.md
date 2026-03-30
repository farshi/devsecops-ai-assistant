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
| Target Architecture | `architecture.md` | Project Structure | — |
| Target Architecture | `architecture.md` | Data Flow | — |
| Extensibility Model (ADR-001) | `architecture.md` | Plugin Pipeline | — |
| Extensibility Model (ADR-001) | `plugins.md` | All | — |
| Plugin Interface Contracts | `plugins.md` | ABC Reference | — |
| Scoring Model (Epic 3) | `concepts.md` | Priority Scoring | — |
| CRA Compliance (Epic 4.2) | `concepts.md` | EU CRA | — |
| Monetization | — | — | Not in docs (internal) |
| Constraints | `architecture.md` | Constraints | — |
| All ADRs | `decisions.md` | Per-entry | — |

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
