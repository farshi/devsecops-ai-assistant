# ADR-006: Alignment Log — Plan vs Implementation Drift Tracking

## Purpose
Track alignment between the spec/plan and what's actually built. Updated after each milestone or GPT drift check.

---

## Check #1 — 2026-03-30 (after tasks 2.0, 2.0b, 2.1, 2.2)

**Status: ALIGNED** — no significant drift.

### What was planned vs what was built

| Task | Planned | Built | Aligned? |
|------|---------|-------|----------|
| 2.0 Finding schema | `Finding` dataclass in `agent/models.py` | ✅ Exactly as spec'd — dataclass with core + enrichment fields, `to_dict()`, constants | ✅ |
| 2.0 Type classifier | Classify findings as os_package/language_dep/etc | ✅ Trivy parser uses `Class` field (os-pkgs/lang-pkgs), sets `reachable=not_applicable` for OS | ✅ |
| 2.0b Plugin ABCs | 4 ABCs: ScannerAdapter, EnrichmentPlugin, PrioritizationStrategy, OutputFormatter | ✅ All 4 in `agent/plugins/base.py` with `name` property + core method | ✅ |
| 2.0b Trivy adapter | Refactor parse_trivy as ScannerAdapter | ✅ `TrivyScannerAdapter` in `agent/plugins/scanners/trivy.py`, thin wrapper in `devsecops/parsers/` | ✅ |
| 2.1 Repo structure | Detect languages, frameworks, runtime, CI, IaC | ✅ Marker-based detection + dep file parsing for frameworks | ✅ |
| 2.2 Dep extraction | Parse requirements.txt, pyproject.toml, package.json, go.mod | ✅ Direct deps extracted, lockfile detection, package_manager identified | ✅ |

### Known technical debt

1. **Dual location for Trivy logic** — `devsecops/parsers/parse_trivy.py` is now a thin wrapper over `agent/plugins/scanners/trivy.py`. The `devsecops/` directory has legacy runners/parsers that should be consolidated into the plugin system eventually.
2. **pyproject.toml parsing** — Only handles PEP 621 `[project.dependencies]`. Poetry format (`[tool.poetry.dependencies]`) not supported. Acceptable for v1.
3. **Transitive deps always empty** — `extract_dependencies()` returns `transitive: []`. Lockfile parsing deferred.

### GPT flags from drift check

| GPT Flag | Our Assessment | Action |
|----------|---------------|--------|
| Duplicated responsibility (plugins vs devsecops/) | Valid debt, not blocking | Clean up in Epic 6 or backlog |
| security_summary.py / review.py scope creep | Not a risk — pre-existing stubs from Epic 1 | Will refactor in Epic 4-5 |
| Missing reachability | Correct — it's the next task (2.3) | Proceeding now |
| Missing tests | 78 tests exist covering all completed tasks | No action needed |

### Architecture snapshot

```
agent/
├── models.py              ← Finding dataclass (ADR-002)
├── context_builder.py     ← detect_repo_structure() + extract_dependencies()
├── plugins/
│   ├── base.py            ← 4 ABCs (ADR-001)
│   └── scanners/trivy.py  ← TrivyScannerAdapter
├── scan.py                ← orchestrator (Epic 1)
├── security_summary.py    ← report generator (Epic 1, will refactor in Epic 4)
├── claude_client.py       ← LLM client (Epic 1, will refactor in Epic 5)
├── analyze.py             ← stub
├── plan.py                ← stub
├── review.py              ← stub
└── utils.py               ← timestamp, slugify

devsecops/
├── parsers/parse_trivy.py ← thin wrapper → plugins/scanners/trivy.py
├── parsers/summarize_findings.py ← summary builder (handles Finding + dict)
└── runners/run_trivy.py   ← shell runner

tests/ → 78 passing
```

---

## How to run a drift check

```bash
# From project root, with TAT active:
# 1. GPT alignment check (quick)
ask-gpt.sh "Compare completed tasks in .tat/plan.md vs files in agent/. Any drift?"

# 2. Full plan review (thorough)
tat-plan-review.sh
```
