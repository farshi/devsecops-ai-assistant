# PatchPilot Architecture

## Data Flow

```
patchpilot triage --path ./app --target-name myapp
                    │
                    ▼
            ┌──────────────┐
            │  CLI (cli.py) │
            └──────┬───────┘
                   │
        ┌──────────▼──────────┐
        │   Scan Orchestrator  │  agent/scan.py
        │   (runs Trivy)       │
        └──────────┬──────────┘
                   │ raw JSON
        ┌──────────▼──────────┐
        │   Scanner Adapter    │  agent/plugins/scanners/trivy.py
        │   (normalize → Finding) │
        └──────────┬──────────┘
                   │ list[Finding]
        ┌──────────▼──────────┐
        │   Context Builder    │  agent/context_builder.py
        │                      │
        │  ├─ detect_repo_structure()
        │  ├─ extract_dependencies()
        │  ├─ check_reachability()   ← Python import search
        │  └─ build_context()        ← token budgeting
        └──────────┬──────────┘
                   │ context bundle
        ┌──────────▼──────────┐
        │   Enrichment         │  agent/plugins/enrichment/
        │                      │
        │  ├─ EPSS scores      │  (FIRST.org API)
        │  ├─ KEV catalog      │  (CISA catalog)
        │  └─ Fix availability │  (version bump analysis)
        └──────────┬──────────┘
                   │ enriched findings
        ┌──────────▼──────────┐
        │   Config Filters     │  agent/config.py
        │                      │
        │  ├─ severity threshold
        │  ├─ ignore CVEs
        │  ├─ ignore packages
        │  └─ dismissed/accepted (state.py)
        └──────────┬──────────┘
                   │ filtered findings
        ┌──────────▼──────────┐
        │   Scoring Model      │  agent/plugins/scoring/default.py
        │                      │
        │  Weighted formula:   │
        │  reachability  25%   │
        │  severity      20%   │
        │  EPSS          15%   │
        │  KEV           15%   │
        │  fix available 15%   │
        │  direct dep    10%   │
        └──────────┬──────────┘
                   │ scored + ranked
        ┌──────────▼──────────┐
        │   Triage Output      │  agent/prioritizer.py
        │                      │
        │  ├─ JSON report      │
        │  ├─ Markdown report  │
        │  ├─ CRA disclosure   │  (--format cra)
        │  └─ LLM narrative    │  (--enhance, optional)
        └──────────┬──────────┘
                   │
                   ▼
            reports/*.md + *.json
```

## Module Map

| Module | Purpose | Key Functions |
|--------|---------|---------------|
| `cli.py` | Click CLI entry point | `triage`, `scan`, `report`, `dismiss` |
| `agent/models.py` | Canonical Finding dataclass | `Finding`, `fingerprint()`, `to_dict()` |
| `agent/scan.py` | Scan orchestrator | `run()` |
| `agent/context_builder.py` | Repo intelligence | `detect_repo_structure()`, `extract_dependencies()`, `check_reachability()`, `build_context()` |
| `agent/prioritizer.py` | Triage engine | `generate_triage()`, `run_triage()`, `enhance_triage_with_llm()` |
| `agent/config.py` | Config loader | `load_config()`, `apply_config_filters()` |
| `agent/state.py` | State management | `dismiss_finding()`, `filter_dismissed()`, `save_baseline()`, `filter_new_only()` |
| `agent/llm_client.py` | Unified LLM interface | `call()` → Claude or OpenAI |
| `agent/claude_client.py` | Backward-compat shim | Delegates to `llm_client` |
| `agent/security_summary.py` | Report generator | `run()`, `run_with_triage()` |

## Plugin System

Four abstract base classes in `agent/plugins/base.py`:

```
ScannerAdapter          parse(raw_path) → list[Finding]
EnrichmentPlugin        enrich(findings, context) → list[Finding]
PrioritizationStrategy  score(findings) → list[Finding]
OutputFormatter         format(findings, context) → str
```

### Built-in Plugins

| Plugin | Type | Location |
|--------|------|----------|
| `TrivyScannerAdapter` | ScannerAdapter | `agent/plugins/scanners/trivy.py` |
| `EPSSEnrichmentPlugin` | EnrichmentPlugin | `agent/plugins/enrichment/epss.py` |
| `KEVEnrichmentPlugin` | EnrichmentPlugin | `agent/plugins/enrichment/kev.py` |
| `FixAvailabilityPlugin` | EnrichmentPlugin | `agent/plugins/enrichment/fix_availability.py` |
| `DefaultScoringStrategy` | PrioritizationStrategy | `agent/plugins/scoring/default.py` |
| `CRADisclosureFormatter` | OutputFormatter | `agent/plugins/formatters/cra.py` |

## Finding Lifecycle

```
Scanner output (raw JSON)
    → ScannerAdapter.parse()          # normalize to Finding
    → check_reachability()            # set reachable + confidence
    → EPSSEnrichmentPlugin.enrich()   # set epss_score
    → KEVEnrichmentPlugin.enrich()    # set in_kev
    → FixAvailabilityPlugin.enrich()  # set fix_available + fix_evidence
    → apply_config_filters()          # remove ignored/below-threshold
    → filter_dismissed()              # remove dismissed/accepted
    → DefaultScoringStrategy.score()  # set priority_score + priority_tier
    → generate_triage()               # ranked output
```

## State Files

```
.patchpilot/
├── config.yaml       # Team config: thresholds, ignores, LLM provider
├── state.json        # Dismissed CVEs, accepted risks
└── baseline.json     # Last scan fingerprints (for --new-only)
```

All committed to repo — team shares triage decisions.

## Constraints

- Python >= 3.9
- Trivy required for scanning
- ANTHROPIC_API_KEY for Claude features (reports, --enhance)
- OPENAI_API_KEY for GPT provider
- No web UI — CLI + file output only
- No database — file-based state only
