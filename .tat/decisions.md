# Decisions

Key decisions with rationale. Append-only.

### ADR-001: Plugin Architecture for Extensibility
Option 2: Plugin architecture with well-defined interfaces.
**Why:** - Core PatchPilot stays lean (Trivy + basic context + prioritizer)
- Community can add: new scanners (Checkov, Semgrep), evidence collectors (AWS SecurityHub, GCP SCC), report formats (CRA, SOC2), custom prioritization rules
- Uses Python entry points or a simple plugin directory — no framework overhead
- Aligns with open-source-core monetization: free plugins for community, premium plugins or hosted service for revenue

### ADR-002: Canonical Finding Schema as Shared Contract
Option 2: Canonical `Finding` dataclass.
**Why:** - Dataclass is native Python, zero dependencies, IDE-friendly (autocomplete, type checking)
- Scanner adapters normalize INTO this schema (single responsibility)
- Enrichment layers ADD fields (reachable, epss_score, etc.) — dataclass supports defaults
- Prioritizer SCORES it, Reporter FORMATS it — each knows exactly what fields exist
- Easy to serialize to/from JSON for file output and LLM context
- The schema grows with the product: new enrichment = new optional field with a default

### ADR-003: Reachability Honesty — "Unknown" Over False Confidence
Option 2: Three-state reachability with explicit confidence levels.
**Why:** - `unknown` is a valid and honest answer. Users can filter on confidence level.
- Avoids the trap of marking everything reachable (useless) or guessing wrong (dangerous).
- Allows incremental improvement: as we add better language support, confidence goes up — the schema doesn't change.
- Package→import mapping starts with top 50 known mismatches + `top_level.txt` from installed packages. When neither works → `unknown` with `confidence: low`.
- OS packages always get `reachable: not_applicable` (see ADR-004).
- Aligns with VEX standard which has explicit "UNDER INVESTIGATION" status.

### ADR-004: Finding Type Classifier — Scope Reachability Correctly
Option 2: Classify findings into types, apply appropriate analysis per type.
**Why:** - Each finding type needs different prioritization signals. OS packages care about base image update availability. Language deps care about reachability. IaC cares about exposure level.
- The prioritizer can weight factors differently per type (e.g., reachability weight = 0 for OS packages).
- Prevents the absurd outcome of a critical OS vuln being deprioritized because it's "not imported."

### ADR-005: Competitive Positioning — Triage Layer, Not Platform
PatchPilot positions as a **thin, extensible triage layer** — not a platform.

### ADR-006: Alignment Log — Plan vs Implementation Drift Tracking

### ADR-007: Spec→Docs Traceability Mapping
Maintain a traceability map in `docs/MAP.md` that links every spec section to its corresponding doc section(s). Changes to a spec section trigger a review of mapped docs.

### ADR-008: Vision Evolution — From Scanner Triage to Security Engineer Assistant
1. **Don't change v0.1 scope** — ship the triage MVP first. Validated by research, unique position.
2. **Capture article ideas as backlog items** — they inform the product roadmap beyond v0.1.
3. **Add "security metrics" to Sprint 3** — time-to-fix tracking and repeated-issue detection are high value, moderate effort.
4. **Rename the vision** — PatchPilot is the triage product. The broader vision (security engineer assistant) could be the platform name if we go there.

### ADR-009: Product Direction — AI Security Engineer in CI/CD

PatchPilot evolves from "vulnerability triage tool" to "AI security engineer in CI/CD" — the missing security reviewer for teams using AI to write code.
**Why:** 
1. Industry shifting from "securing systems" to "securing AI and AI-driven systems"
2. AI coding tools (Claude Code, Copilot, Cursor) generate code nobody security-reviews
3. Small teams (2-15 devs) have no security reviewer — PatchPilot fills that role
4. Pure triage is commodity risk — scanners are adding triage features
5. The defensible moat is **judgment** (scoring + reachability + memory), not summarization

