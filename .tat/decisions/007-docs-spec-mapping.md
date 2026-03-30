# ADR-007: Spec→Docs Traceability Mapping

## Context
The spec (`.tat/spec.md`) is the source of truth for what PatchPilot is and how it works. Documentation (`docs/`) explains these concepts to users and contributors. When the spec changes, affected docs must update too — but without an explicit mapping, docs drift silently.

## Decision
Maintain a traceability map in `docs/MAP.md` that links every spec section to its corresponding doc section(s). Changes to a spec section trigger a review of mapped docs.

## Hierarchy and Cascade Rules

```
.tat/spec.md (source of truth)
    ↓ changes cascade to
docs/ (user-facing documentation)
    ↓ changes cascade to
README.md (marketing/overview — Epic 6.4)
```

### Cascade rules:
1. **Spec changes** → check MAP.md → update affected docs → update README if user-facing
2. **ADR changes** → update `docs/decisions.md` summary
3. **Plan changes** → no doc cascade (plan is internal workflow)
4. **Code changes** → update docs only if behavior/API changes (not refactors)

## Mapping Structure

| Spec Section | Docs File | Docs Section | Notes |
|---|---|---|---|
| What PatchPilot Does | `docs/concepts.md` | Overview | Core workflow description |
| Finding Schema (ADR-002) | `docs/concepts.md` | Finding Schema | Field definitions, types |
| Finding Types (ADR-004) | `docs/concepts.md` | Finding Types | os_package, language_dep, etc |
| Reachability (ADR-003) | `docs/concepts.md` | Reachability | Three-state model, confidence |
| Competitive Positioning (ADR-005) | `docs/concepts.md` | What PatchPilot Is/Isn't | Positioning statements |
| Target Architecture | `docs/architecture.md` | Project Structure | File tree, module roles |
| Extensibility Model (ADR-001) | `docs/architecture.md` | Plugin Pipeline | Plugin types, discovery |
| Extensibility Model (ADR-001) | `docs/plugins.md` | All sections | ABC interfaces, examples |
| Scoring Model (Epic 3.1) | `docs/concepts.md` | Priority Scoring | Weights, tiers, factors |
| CRA (Epic 4.2) | `docs/concepts.md` | EU CRA Compliance | Requirements, deadlines |
| All ADRs | `docs/decisions.md` | All entries | One-line summaries + status |

## How to Use

After any spec change:
1. Open `docs/MAP.md`
2. Find the spec section that changed
3. Check which docs are mapped to it
4. Update those docs
5. If the change affects user-visible behavior → also check README

## Status
ACCEPTED
