# Recurring Workflows

Set up PatchPilot to run automatically on a schedule — weekly digests, PR-gated triage, or both.

## Overview

PatchPilot ships with GitHub Actions workflow templates you can drop into any repo:

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| **Weekly triage** | Cron schedule | Scan → triage → digest → GitHub issue |
| **PR triage** | Pull request | Scan → triage → PR comment |

Both workflows are in `.github/workflows/` and `examples/` — copy them to your repo and configure.

## Quick Setup

### 1. Weekly Triage

Copy the weekly workflow template:

```bash
# From PatchPilot source
cp .github/workflows/patchpilot-weekly.yml <your-repo>/.github/workflows/

# Or create from the example
cp examples/github-action.yml <your-repo>/.github/workflows/patchpilot.yml
```

Add the required secret to your repo:

```
Settings → Secrets and variables → Actions → New repository secret
  Name: ANTHROPIC_API_KEY
  Value: sk-ant-...
```

> `ANTHROPIC_API_KEY` is optional — only needed for `--enhance` (AI-generated explanations). Triage works without it.

### 2. PR Triage

Copy the PR workflow template:

```bash
cp .github/workflows/patchpilot-pr.yml <your-repo>/.github/workflows/
```

No additional secrets needed — uses `GITHUB_TOKEN` for PR comments.

## Workflow Templates

### Weekly Triage (`patchpilot-weekly.yml`)

Runs every Monday at 8:00 UTC. Produces a digest and creates/updates a GitHub issue.

```yaml
on:
  schedule:
    - cron: '0 8 * * 1'    # Monday 8am UTC
  workflow_dispatch:         # Manual trigger button
```

**What it does:**
1. Installs Trivy and PatchPilot
2. Runs `patchpilot triage --profile quick --top 5 --fail-on critical`
3. Runs `patchpilot digest` to summarize trends
4. Creates a GitHub issue with the digest (or comments on an existing one)
5. Uploads full reports as artifacts (90-day retention)

**Customization:**

```yaml
# Change schedule — cron syntax: minute hour day-of-month month day-of-week
- cron: '0 8 * * 1'      # Monday 8am UTC (default)
- cron: '0 6 * * 1,4'    # Monday + Thursday 6am UTC
- cron: '0 9 1 * *'      # First of each month 9am UTC

# Change triage flags
patchpilot triage \
  --path . \
  --target-name ${{ env.TARGET_NAME }} \
  --profile deep \        # quick | default | deep
  --top 10 \              # number of findings to surface
  --fail-on high \        # critical | high | medium | low
  --enhance               # AI explanations (needs ANTHROPIC_API_KEY)

# Change digest look-back window
patchpilot digest \
  --target-name ${{ env.TARGET_NAME }} \
  --days 14               # default: 7
```

### PR Triage (`patchpilot-pr.yml`)

Runs on every pull request to `main` or `master`. Posts triage results as a PR comment.

```yaml
on:
  pull_request:
    branches: [main, master]
```

**What it does:**
1. Installs Trivy and PatchPilot
2. Runs `patchpilot triage --new-only --pr-comment --fail-on critical`
3. Posts a comment on the PR with findings

**Key flags:**
- `--new-only` — only surfaces findings that are new since the last baseline (avoids re-alerting on known issues)
- `--pr-comment` — posts results directly to the PR via GitHub API
- `--fail-on critical` — fails the check if critical findings exist (blocks merge)

### Combined Workflow (`examples/github-action.yml`)

A single workflow that handles push, PR, and scheduled triggers. Use this if you want one file instead of two.

## State and History

PatchPilot tracks state in `.patchpilot/` at your project root:

| File | Purpose | Created by |
|------|---------|-----------|
| `state.json` | Triage decisions (dismissed, accepted risk, closed) | `triage`, `dismiss`, `close` |
| `baseline.json` | Last scan snapshot (for `--new-only` diffing) | `triage` |
| `history.json` | Historical snapshots (for trends and digests) | `triage` (auto-appended) |
| `config.yaml` | Severity thresholds, ignore rules, enrichment toggles | Manual (see `examples/config.yaml`) |

**For recurring workflows to produce useful digests**, you need history. Each `patchpilot triage` run automatically appends a snapshot to `history.json`. After 2+ runs, `patchpilot digest` can show trends, new/resolved findings, and regressions.

### Committing `.patchpilot/` state

For scheduled CI workflows, state must be committed to the repo so it persists between runs:

```yaml
# Add after the triage step in your workflow
- name: Commit state updates
  run: |
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add .patchpilot/
    git diff --cached --quiet || git commit -m "chore: update patchpilot state"
    git push
```

> Without this step, each CI run starts fresh and `--new-only` / digest trends won't work.

Ensure the workflow has `contents: write` permission:

```yaml
permissions:
  contents: write
  issues: write
  pull-requests: write
```

## Cron Syntax Reference

GitHub Actions uses standard cron syntax (UTC timezone):

```
┌───────── minute (0-59)
│ ┌─────── hour (0-23)
│ │ ┌───── day of month (1-31)
│ │ │ ┌─── month (1-12)
│ │ │ │ ┌─ day of week (0-6, 0=Sunday)
│ │ │ │ │
* * * * *
```

Common schedules:

| Schedule | Cron | Notes |
|----------|------|-------|
| Weekly (Monday 8am) | `0 8 * * 1` | Default — good for most teams |
| Twice weekly | `0 8 * * 1,4` | Monday + Thursday |
| Daily | `0 6 * * *` | For high-compliance environments |
| Monthly | `0 9 1 * *` | First of each month |

> GitHub Actions cron has a minimum granularity of 5 minutes and may delay execution by several minutes during high-load periods.

## Digest Output

The `patchpilot digest` command produces a structured summary:

- **Status at a glance** — total findings, breakdown by priority tier, sparkline trend
- **What changed** — new findings, resolved, regressions since last run
- **Top priorities** — ranked action items with scores
- **Remediation velocity** — mean time to remediate, fix coverage percentage
- **Decisions** — recently dismissed or accepted-risk findings
- **Recurring packages** — dependencies that keep appearing in findings

Example digest header:

```
## Security Digest — 2026-04-04

| Metric | Value |
|--------|-------|
| Total findings | 12 |
| Critical/High | 2 / 3 |
| New this week | 1 |
| Resolved | 2 |
| Trend | ▆▅▄▃▂ (improving) |
```

## Troubleshooting

### Workflow doesn't run on schedule

- GitHub disables scheduled workflows on repos with no activity in 60 days. Push a commit or run manually via `workflow_dispatch`.
- Cron times are UTC. Convert your local time accordingly.
- Check Actions tab → select workflow → "Run workflow" button for manual trigger.

### `--new-only` always shows all findings

- `.patchpilot/baseline.json` must exist from a previous run. The first run establishes the baseline; the second run diffs against it.
- If running in CI, ensure state is committed back to the repo (see [Committing state](#committing-patchpilot-state) above).

### Digest shows no trends

- `history.json` needs 2+ snapshots. Run triage at least twice before expecting trend data.
- Check that `.patchpilot/history.json` exists and is committed.

### PR comment not appearing

- Ensure `pull-requests: write` permission is set.
- The `--pr-comment` flag requires the `gh` CLI to be available and a valid PR context (`GITHUB_REF`).
- Check the workflow logs for `[pr-comment]` output.

### Triage fails with "Trivy not found"

- The workflow templates install Trivy automatically. If using a custom runner, install it manually or use the `aquasecurity/trivy-action` GitHub Action.

## Example: Full Recurring Setup

A complete setup for a team that wants weekly digests + PR gating:

```bash
# In your project repo
mkdir -p .github/workflows

# Weekly digest → GitHub issues
curl -o .github/workflows/patchpilot-weekly.yml \
  https://raw.githubusercontent.com/<org>/patchpilot/main/.github/workflows/patchpilot-weekly.yml

# PR triage → PR comments
curl -o .github/workflows/patchpilot-pr.yml \
  https://raw.githubusercontent.com/<org>/patchpilot/main/.github/workflows/patchpilot-pr.yml

# Optional: project config
mkdir -p .patchpilot
cat > .patchpilot/config.yaml << 'EOF'
severity_threshold: medium
ignore:
  cves: []
  packages: []
enrichment:
  epss: true
  kev: true
  fix_availability: true
EOF

# Commit
git add .github/workflows/ .patchpilot/config.yaml
git commit -m "chore: add PatchPilot recurring triage workflows"
git push
```

Add `ANTHROPIC_API_KEY` to your repo secrets if you want AI-enhanced reports.
