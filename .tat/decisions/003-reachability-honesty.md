# ADR-003: Reachability Honesty — "Unknown" Over False Confidence

## Context
Reachability analysis is PatchPilot's core differentiator — knowing whether a vulnerable dependency is actually used in the codebase. But competitive research reveals serious limitations:

- **Python package→import name mismatch:** `pip install Pillow` → `import PIL`, `pip install PyYAML` → `import yaml`. PyPI does not enforce any relationship between distribution and import names.
- **Snyk covers only Java/JS.** Semgrep covers 6 languages but admits transitive reachability is "overrated and underperforming."
- **Dynamic code loading** (reflection, importlib, Spring DI) defeats static analysis.
- **In one study, only 2% of 1,614 Dependabot alerts were actually reachable** — but marking everything "reachable" is worse than no analysis.

The spec principle says: *"say 'I'm not sure this is reachable' instead of pretending certainty."*

## Options Considered
1. **Binary reachable/unreachable** — simpler but produces false confidence. A wrong "unreachable" label hides real vulnerabilities.
2. **Three-state with confidence** — `reachable: true|false|unknown` plus `reachability_confidence: high|medium|low|none`. Honest about what we know.
3. **Skip reachability for v1** — safe but throws away the core differentiator.

## Decision
Option 2: Three-state reachability with explicit confidence levels.

## Rationale
- `unknown` is a valid and honest answer. Users can filter on confidence level.
- Avoids the trap of marking everything reachable (useless) or guessing wrong (dangerous).
- Allows incremental improvement: as we add better language support, confidence goes up — the schema doesn't change.
- Package→import mapping starts with top 50 known mismatches + `top_level.txt` from installed packages. When neither works → `unknown` with `confidence: low`.
- OS packages always get `reachable: not_applicable` (see ADR-004).
- Aligns with VEX standard which has explicit "UNDER INVESTIGATION" status.

## Confidence Levels
- **high**: Direct import match confirmed in source code, or `top_level.txt` resolved
- **medium**: Package name matches import name (heuristic, could be wrong)
- **low**: No mapping found, best-guess based on package name similarity
- **none**: No reachability analysis performed (e.g., OS package, or analysis skipped)

## Status
ACCEPTED
