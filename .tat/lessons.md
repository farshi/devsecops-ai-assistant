# Lessons Learned

Captured during development. These improve TAT workflow and PatchPilot quality.

## TAT Workflow Lessons

### 1. GPT review payloads must be small
**When:** Task 2.0 onwards
**Problem:** `tat-code-review.sh` sent the full spec (250+ lines) as context. Combined with large diffs, payloads broke.
**Fix:** Trimmed to spec summary (~7 lines) + current task description. Fixed in farshi/tinyaiteam#13.
**TAT improvement:** `tat-gpt.sh` now uses Python + temp files for JSON construction instead of shell interpolation.

### 2. Shell escaping breaks GPT calls silently
**When:** Every code review with special characters in diffs
**Problem:** `tat-gpt.sh` used shell string interpolation for JSON payloads. Quotes, backslashes, newlines in code diffs mangled the JSON. Script failed silently (`set -e` + no output).
**Fix:** Rewrote to write prompts to temp files, build JSON payload entirely in Python. Fixed in farshi/tinyaiteam#13.
**TAT improvement:** All GPT scripts now handle any content safely.

### 3. grep + set -e = silent death
**When:** `tat-code-review.sh` on plans without `- [ ]` checkboxes
**Problem:** `grep -F` for the current task text returns exit 1 when not found. `set -euo pipefail` kills the script with no output.
**Fix:** Added `|| true` to the grep. Fixed in farshi/tinyaiteam#13.
**TAT improvement:** Any grep in TAT scripts that might not match needs `|| true`.

### 4. Separate docs from code on branches
**When:** Task 2.0 mixed spec/plan/ADRs with code changes
**Problem:** Spec+plan changes bloated the diff, confused GPT reviews, and caused cherry-pick conflicts.
**Lesson:** When possible, commit docs changes to main directly (plan updates are allowed) and keep feature branches code-only.

### 5. Always use configured GPT model
**When:** Debugging GPT review failures
**Problem:** Temptation to hardcode a known-working model (e.g., `gpt-4o-mini`) instead of using the configured one.
**Lesson:** Always respect `~/.tinyaiteam/config.sh` model settings. If a model fails, debug why — don't silently switch.

## PatchPilot Product Lessons

### 6. Reachability honesty > reachability coverage
**When:** Task 2.3 — import reachability
**Lesson:** Competitors overstate reachability. Semgrep says transitive reachability is "overrated and underperforming." PatchPilot's advantage is saying "unknown" honestly instead of guessing. Three-state (`true/false/unknown`) with confidence levels is the right design.

### 7. Package→import name mismatch is real and unsolved
**When:** Task 2.3 design
**Problem:** PyPI does not enforce any relationship between distribution name and import name. `pip install Pillow` → `import PIL`. No tool fully solves this.
**Fix:** Maintain a mapping table (50+ entries). Use `top_level.txt` when available. Default to heuristic (replace `-` with `_`). Mark confidence accordingly.
**Opportunity:** This mapping table is a unique dataset. Keep it growing.

### 8. Guard reachability by ecosystem
**When:** GPT review of task 2.3
**Problem:** If a repo has both Python and Node deps, Python import checking would mark Node deps as "not imported" → false `reachable=false`.
**Fix:** Check `structure["languages"]` before analyzing. If Python not detected → `reachable=unknown` for all language_deps.

### 9. The market gap is real but timing matters
**When:** Competitive research (March 2026)
**Lesson:** No CLI-first, open-source, scanner-agnostic triage layer exists. Competitors are $25-105/dev/mo SaaS. But GitHub is aware of the Dependabot noise problem — they could ship something. Speed matters.
**CRA timing:** EU CRA reporting starts Sept 2026. First-mover advantage in compliance tooling.

### 10. Plugin architecture: define interfaces early, implement late
**When:** Task 2.0b
**Lesson:** Defined all 4 ABCs upfront but only implemented one (TrivyScannerAdapter). This is the right sequence — interfaces stabilize the architecture without over-building.

### 11. In auto-mode, announce what you're doing
**When:** Task 2.3b — user couldn't see what was being coded
**Source:** User feedback
**Lesson:** After creating a branch, always print 2-3 lines saying what task is being implemented and what it does. The user needs visibility even in auto-mode. Silence for minutes is bad UX.

### 12. Lessons come from everywhere — capture all of them
**When:** Task 2.3b
**Source:** User feedback
**Lesson:** Lessons can come from Opus (self-review insights), GPT (review feedback), or the user (corrections/preferences). All should be captured here. This file is a learning layer that informs both TAT workflow improvements and project decisions.
