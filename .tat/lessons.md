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

### 13. Finding fingerprint needed before state tracking
**When:** GPT plan review after task 2.3b
**Source:** GPT
**Lesson:** Epic 4.3 (state/baseline tracking) needs a stable finding identity key (CVE+package+version+location). Without it, `--new-only` and dismiss logic break across scans. Add `Finding.fingerprint()` before starting Epic 4.

### 14. Scoring model has unresolved input gaps
**When:** GPT plan review after task 2.3b
**Source:** GPT
**Lesson:** Epic 3.1 scoring weights reference "base image age" (os_package) and "exposure level" + "fix complexity" (iac_misconfig), but no enrichment task produces these. Either add enrichment tasks or simplify the scoring model for types without those inputs.

### 15. Don't build without a plan — even for docs
**When:** User requested docs/
**Source:** User
**Lesson:** Any request — including documentation — should go through the plan first. No ADR = no decision captured = no traceability. Added Epic 7 for documentation.

### 12. Lessons come from everywhere — capture all of them
**When:** Task 2.3b
**Source:** User feedback
**Lesson:** Lessons can come from Opus (self-review insights), GPT (review feedback), or the user (corrections/preferences). All should be captured here. This file is a learning layer that informs both TAT workflow improvements and project decisions.

### 16. Don't force-override hooks — fix the root cause
**When:** Post-Epic 2 sprint planning
**Source:** User correction
**Lesson:** When a TAT hook blocks a commit, don't use `TAT_FORCE=1` to bypass it. The hook is telling you something. Investigate WHY it blocked, capture the lesson, and fix the hook if it's wrong. Sweeping failures under the carpet means they'll pop up again. Learn from failures, don't mask them.
**TAT bug found:** Pre-commit hook only allows `.tat/plan.md` on main, but `.tat/lessons.md` and `.tat/decisions/` are also workflow metadata that should be allowed on main. Fix the hook whitelist.

## TAT Feature Candidates

Patterns proven in this project that should be baked into TAT as features.

### T1. Sprint-based prioritization within epics
**When:** Post-Epic 2 planning
**Source:** User + GPT
**Pattern:** Epics define WHAT to build. Sprints define WHAT ORDER. After completing an epic, reprioritize remaining tasks across all epics into sprints ordered by user value. GPT helps prioritize — ask "what's the critical path to first user value?"
**TAT feature:** `/tat sprint` — shows current sprint backlog, `/tat replan` — GPT reprioritizes remaining tasks into sprints.
**Key insight from GPT:** "Sprint 1 should be all about getting a real, usable triage loop end-to-end, not polishing reports or docs."

### T2. Docs follow context, not calendar
**When:** Post-Epic 2 planning
**Source:** GPT + Opus
**Pattern:** Don't batch all docs at the end (they'll be stale). Don't do full docs after every epic (too early, things change). Instead: do lightweight concept docs alongside work (glossary when you define a concept), full architecture docs after the shape stabilizes.
**TAT feature:** Auto-detect when a new concept is introduced (new ADR, new module) and prompt for glossary entry.

### T3. GPT as sprint planner
**When:** Post-Epic 2 planning
**Source:** This session
**Pattern:** After completing a milestone, send GPT the completed + remaining work and ask for sprint prioritization. GPT sees the forest when we're in the trees. Include: what's done, what's left, target user, deadlines, competitive context.
**TAT feature:** `/tat replan` — auto-gathers state and asks GPT for sprint reprioritization.

### T4. Split large tasks by value layer
**When:** GPT sprint planning suggestion
**Source:** GPT
**Pattern:** Task 3.3 (triage output) should split into 3.3a (ranked list — MVP) and 3.3b (LLM narrative — enhancement). The split is by value layer: core output vs enhanced output. Ship the core, iterate on enhancement.
**TAT feature:** When a task has "core + enhancement" pattern, suggest splitting during planning.

### T5. Alignment checks at milestones
**When:** After Epic 2 completion
**Source:** This session
**Pattern:** After completing an epic, run a GPT drift check (spec vs built) and update the alignment log. Catches architectural drift before it compounds.

### T6. Vision articles inform roadmap, not current sprint
**When:** Sprint 2, mid-session
**Source:** User shared GPT-reviewed article about AI replacing manual security review
**Pattern:** Strategic vision input (articles, competitor announcements, user feedback) should be captured as ADRs and backlog items, NOT injected into the current sprint. The process: (1) read/discuss, (2) capture as ADR with "what changes now vs later", (3) add new backlog items, (4) replan at next sprint boundary. Don't pivot mid-sprint.
**TAT feature:** `/tat vision <input>` — captures strategic input, creates ADR, adds backlog items, doesn't change current sprint.
**TAT feature:** Auto-run drift check after each epic completion in post-merge checkpoint.
