"""
PatchPilot — smart vulnerability triage for developers.

Usage:
    patchpilot scan     --path ./app --target-name myapp
    patchpilot triage   --path ./app --target-name myapp
    patchpilot report   --target-name myapp
"""

import click
from agent.utils import timestamp, slugify, check_trivy_installed


# ---------------------------------------------------------------------------
# Output path helper
# ---------------------------------------------------------------------------

def output_path(folder: str, target_slug: str, suffix: str) -> str:
    return f"{folder}/{target_slug}_{timestamp()}{suffix}"


# ---------------------------------------------------------------------------
# Scanner profiles
#
# quick    : trivy fs only — fast local check
# standard : trivy fs + checkov (if .tf files detected at runtime)
# full     : standard + semgrep + gitleaks (future)
# ---------------------------------------------------------------------------

PROFILE_SCANNERS = {
    "quick":    ["trivy_fs"],
    "standard": ["trivy_fs", "checkov"],
    "full":     ["trivy_fs", "checkov", "semgrep", "gitleaks"],
}

PROFILE_NOTES = {
    "quick":    "trivy fs only",
    "standard": "trivy fs + checkov (checkov runs only if .tf files are found)",
    "full":     "trivy fs + checkov + semgrep + gitleaks (semgrep/gitleaks: future)",
}


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__import__("agent").__version__, prog_name="patchpilot")
def cli():
    """PatchPilot — smart vulnerability triage for developers."""
    pass


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path",        required=True, help="Path to the project directory.")
@click.option("--target-name", required=True, help="Name used for output file scoping.")
@click.option("--dry-run",     is_flag=True,  help="Show what would run without executing.")
def analyze(path, target_name, dry_run):
    """Understand a project's structure and security posture."""
    target_slug = slugify(target_name)
    out = output_path("analysis", target_slug, ".md")

    click.echo("[analyze]")
    click.echo(f"  target-name : {target_name}  (slug: {target_slug})")
    click.echo(f"  path        : {path}")
    click.echo(f"  output      : {out}")
    click.echo(f"  dry-run     : {dry_run}")

    if dry_run:
        click.echo("")
        click.echo("  Would run:")
        click.echo(f"    1. context_builder({path}) → context.json")
        click.echo(f"    2. prompts/analyze.md + context.json → Claude")
        click.echo(f"    3. Claude response → {out}")
        return

    # TODO: call agent.analyze.run(path, target_slug)
    click.echo("\n  [stub] analyze handler not implemented yet.")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path",        required=True, help="Path to the project directory.")
@click.option("--target-name", required=True, help="Name used for output file scoping.")
@click.option("--profile",
              type=click.Choice(["quick", "standard", "full"]),
              default="standard", show_default=True,
              help="Scanner depth: quick | standard | full.")
@click.option("--dry-run",     is_flag=True,  help="Show what would run without executing.")
def scan(path, target_name, profile, dry_run):
    """Run security scanners against the project."""
    target_slug = slugify(target_name)
    scanners    = PROFILE_SCANNERS[profile]
    date        = timestamp()
    out_files   = [f"reports/{target_slug}_{s}_{date}.json" for s in scanners]
    summary     = f"reports/{target_slug}_summary_{date}.json"

    click.echo("[scan]")
    click.echo(f"  target-name : {target_name}  (slug: {target_slug})")
    click.echo(f"  path        : {path}")
    click.echo(f"  profile     : {profile}  ({PROFILE_NOTES[profile]})")
    click.echo(f"  scanners    : {', '.join(scanners)}")
    click.echo(f"  dry-run     : {dry_run}")

    if dry_run:
        click.echo("")
        click.echo("  Would run:")
        for i, (scanner, out_file) in enumerate(zip(scanners, out_files), 1):
            click.echo(f"    {i}. {scanner} → {out_file}")
        click.echo(f"    {len(scanners)+1}. parsers → {summary}  (Claude reads this)")
        return

    if not check_trivy_installed():
        raise click.ClickException(
            "Trivy is not installed. PatchPilot requires Trivy for vulnerability scanning.\n\n"
            "  Install Trivy:\n"
            "    macOS:  brew install trivy\n"
            "    Linux:  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh\n"
            "    Docker: docker run aquasec/trivy\n\n"
            "  More info: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )

    from agent import scan as scan_agent
    summary_file = scan_agent.run(path, target_name, profile, scanners)
    click.echo(f"\n  summary written → {summary_file}")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target-name", required=True, help="Must match the target-name used in scan.")
@click.option("--path", default=None, help="Project path. If provided, uses triage-based report.")
@click.option("--top", default=5, show_default=True, help="Top findings to include (triage mode).")
@click.option("--dry-run",     is_flag=True,  help="Show what would run without executing.")
def report(target_name, path, top, dry_run):
    """Generate AI security report from scan results.

    \b
    With --path: uses the triage pipeline for a prioritized action plan.
    Without --path: uses raw summary for a traditional security report.
    """
    target_slug  = slugify(target_name)
    summary_glob = f"reports/{target_slug}_summary_*.json"
    out          = output_path("reports", target_slug, "_security-report.md")

    click.echo("[report]")
    click.echo(f"  target-name : {target_name}  (slug: {target_slug})")
    if path:
        click.echo(f"  path        : {path}")
        click.echo(f"  top         : {top}")
        click.echo(f"  mode        : triage-based (prioritized action plan)")
    else:
        click.echo(f"  mode        : raw summary (traditional report)")
    click.echo(f"  reads       : {summary_glob}  (latest match)")
    click.echo(f"  output      : {out}")
    click.echo(f"  dry-run     : {dry_run}")

    if dry_run:
        click.echo("")
        click.echo("  Would run:")
        click.echo(f"    1. load {summary_glob} (latest)")
        if path:
            click.echo(f"    2. run_triage({path}, summary, top={top}) → ranked findings")
            click.echo(f"    3. prompts/security_summary.md + triage → Claude")
        else:
            click.echo(f"    2. prompts/security_summary.md + summary → Claude")
        click.echo(f"    {3 if path else 3}. Claude response → {out}")
        return

    from agent import security_summary
    try:
        if path:
            report_file = security_summary.run_with_triage(target_name, target_slug, path, top)
        else:
            report_file = security_summary.run(target_name, target_slug)
        click.echo(f"\n  report written → {report_file}")
    except (FileNotFoundError, RuntimeError) as exc:
        raise click.ClickException(str(exc))


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path", required=True, help="Path to the project directory.")
@click.option("--target-name", required=True, help="Name used for output file scoping.")
@click.option("--top", default=5, show_default=True, help="Number of top findings to surface.")
@click.option("--profile",
              type=click.Choice(["quick", "standard", "full"]),
              default="quick", show_default=True,
              help="Scanner depth (used if scan needed).")
@click.option("--scan/--no-scan", default=True, show_default=True,
              help="Run scan first, or use existing summary.")
@click.option("--dry-run", is_flag=True, help="Show what would run without executing.")
@click.option("--fail-on",
              type=click.Choice(["critical", "high", "medium", "low"]),
              default=None,
              help="Exit with code 1 if findings at this tier or above exist. For CI gating.")
@click.option("--enhance/--no-enhance", default=False, show_default=True,
              help="Add AI-generated explanations (requires ANTHROPIC_API_KEY).")
@click.option("--format", "output_format",
              type=click.Choice(["default", "cra"]),
              default="default", show_default=True,
              help="Output format. 'cra' generates EU CRA disclosure document.")
@click.option("--new-only", is_flag=True, default=False,
              help="Only show findings NEW since last scan.")
def triage(path, target_name, top, profile, scan, dry_run, fail_on, enhance, output_format, new_only):
    """Smart vulnerability triage — ranked by reachability, exploitability, and fixability.

    \b
    Runs the full pipeline:
      1. Scan (unless --no-scan, or summary already exists)
      2. Build repo context (structure, deps, reachability)
      3. Enrich findings (EPSS, KEV, fix availability)
      4. Score and rank
      5. Output top-N action items

    \b
    Examples:
      python cli.py triage --path ./app --target-name myapp
      python cli.py triage --path ./app --target-name myapp --top 3
      python cli.py triage --path ./app --target-name myapp --no-scan
    """
    target_slug = slugify(target_name)

    click.echo("[triage]")
    click.echo(f"  target-name : {target_name}  (slug: {target_slug})")
    click.echo(f"  path        : {path}")
    click.echo(f"  top         : {top}")
    click.echo(f"  profile     : {profile}")
    click.echo(f"  scan        : {'yes' if scan else 'no (use existing summary)'}")
    click.echo(f"  enhance     : {'yes (LLM narratives)' if enhance else 'no'}")
    click.echo(f"  dry-run     : {dry_run}")

    if dry_run:
        click.echo("")
        click.echo("  Would run:")
        click.echo(f"    1. scan {path} with profile '{profile}'")
        click.echo(f"    2. build context (repo structure, deps, reachability)")
        click.echo(f"    3. enrich findings (EPSS, KEV, fix availability)")
        click.echo(f"    4. score and rank findings")
        click.echo(f"    5. output top {top} action items")
        if enhance:
            click.echo(f"    6. add AI-generated explanations (requires ANTHROPIC_API_KEY)")
        if fail_on:
            click.echo(f"    {'7' if enhance else '6'}. exit 1 if {fail_on}+ findings exist")
        return

    import glob
    import json
    import os

    # Check for config
    config_path = os.path.join(path, ".patchpilot", "config.yaml")
    if os.path.isfile(config_path):
        click.echo(f"  [config] Loaded .patchpilot/config.yaml")

    # Step 1: Scan if requested
    summary_path = None
    if scan:
        if not check_trivy_installed():
            raise click.ClickException(
                "Trivy is not installed. PatchPilot requires Trivy for vulnerability scanning.\n\n"
                "  Install Trivy:\n"
                "    macOS:  brew install trivy\n"
                "    Linux:  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh\n"
                "    Docker: docker run aquasec/trivy\n\n"
                "  More info: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            )
        scanners = PROFILE_SCANNERS[profile]
        click.echo(f"\n  [1/5] Scanning with profile '{profile}'...")
        from agent import scan as scan_agent
        summary_path = scan_agent.run(path, target_name, profile, scanners)
        click.echo(f"        summary → {summary_path}")
    else:
        # Find latest existing summary
        pattern = f"reports/{target_slug}_summary_*.json"
        matches = sorted(glob.glob(pattern))
        if not matches:
            raise click.ClickException(
                f"No summary found for '{target_name}'. Run with --scan first."
            )
        summary_path = matches[-1]
        click.echo(f"\n  [1/5] Using existing summary: {summary_path}")

    # Steps 2-5: Run triage pipeline
    click.echo("  [2/5] Building repo context...")
    click.echo("  [3/5] Enriching findings...")
    click.echo("  [4/5] Scoring and ranking...")

    from agent.prioritizer import run_triage
    result = run_triage(path, summary_path, top_n=top, enhance=enhance, new_only=new_only)

    # Step 5: Output
    triage_data = result["triage"]
    markdown = result["markdown"]

    # Save markdown report
    os.makedirs("reports", exist_ok=True)
    triage_ts = timestamp()
    report_file = f"reports/{target_slug}_triage_{triage_ts}.md"
    with open(report_file, "w") as f:
        f.write(markdown)

    # Save JSON triage data
    json_file = f"reports/{target_slug}_triage_{triage_ts}.json"
    with open(json_file, "w") as f:
        json.dump(result["triage"], f, indent=2)

    click.echo(f"  [5/5] Triage complete!")
    click.echo("")

    # Print summary to stdout
    click.echo(f"  Total findings: {triage_data['total_findings']}")
    summary = triage_data.get("summary", {})
    if any(summary.values()):
        click.echo(f"  Priority breakdown: {summary.get('critical', 0)} critical, "
                    f"{summary.get('high', 0)} high, {summary.get('medium', 0)} medium, "
                    f"{summary.get('low', 0)} low, {summary.get('noise', 0)} noise")
    click.echo("")

    # Print top action items
    items = triage_data.get("action_items", [])
    if items:
        click.echo(f"  Top {len(items)} action items:")
        click.echo("")
        for item in items:
            tier = item["priority_tier"].upper()
            score = item["priority_score"]
            click.echo(f"    #{item['rank']} [{tier}] {item['id']} (score: {score})")
            click.echo(f"       {item['title'][:80]}")
            click.echo(f"       Action: {item['action']}")
            click.echo(f"       Effort: {item['effort']}")
            fix = item.get("fix_suggestion", {})
            if fix.get("command"):
                click.echo(f"       Fix: {fix['command']} (confidence: {fix.get('confidence', '?')})")
            click.echo("")
    else:
        click.echo("  No actionable findings found.")

    click.echo(f"  Reports:")
    click.echo(f"    markdown → {report_file}")
    click.echo(f"    json     → {json_file}")

    # CRA disclosure generation
    if output_format == "cra":
        from agent.plugins.formatters.cra import CRADisclosureFormatter
        from agent.prioritizer import _finding_from_dict
        from agent.context_builder import build_context

        ctx = build_context(path, summary_path)
        all_findings = [_finding_from_dict(fd) for fd in ctx.get("findings", [])]

        cra_doc = CRADisclosureFormatter().format(all_findings, ctx)
        cra_file = f"reports/{target_slug}_cra-disclosure_{triage_ts}.md"
        with open(cra_file, "w") as f:
            f.write(cra_doc)
        click.echo(f"    cra      → {cra_file}")

    # CI exit code gating
    if fail_on:
        tier_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = tier_order[fail_on]

        failed = False
        for tier, count in summary.items():
            if tier in tier_order and tier_order[tier] <= threshold and count > 0:
                failed = True
                break

        if failed:
            click.echo(f"  ⚠ FAILED: findings at '{fail_on}' level or above detected")
            raise SystemExit(1)
        else:
            click.echo(f"  ✓ PASSED: no findings at '{fail_on}' level or above")


# ---------------------------------------------------------------------------
# dismiss
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path", default=".", show_default=True, help="Project path.")
@click.option("--cve", required=True, help="CVE ID to dismiss.")
@click.option("--reason", default="", help="Reason for dismissal.")
def dismiss(path, cve, reason):
    """Dismiss a finding so it won't appear in future triage.

    \b
    Example:
      patchpilot dismiss --cve CVE-2023-xxxxx --reason "mitigated by WAF"
    """
    import os
    from agent.state import dismiss_cve

    dismiss_cve(path, cve, reason)
    state_file = os.path.join(path, ".patchpilot", "state.json")
    click.echo(f"  Dismissed {cve}" + (f" — {reason}" if reason else ""))
    click.echo(f"  State saved → {state_file}")


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path",        required=True, help="Path to the project directory.")
@click.option("--task",        required=True, help="Feature or change to plan (free text).")
@click.option("--target-name", required=True, help="Name used for output file scoping.")
@click.option("--dry-run",     is_flag=True,  help="Show what would run without executing.")
def plan(path, task, target_name, dry_run):
    """Generate a secure implementation plan for a task."""
    target_slug = slugify(target_name)
    task_slug   = slugify(task)
    out         = f"plans/{target_slug}_{task_slug}_{timestamp()}.md"

    click.echo("[plan]")
    click.echo(f"  target-name : {target_name}  (slug: {target_slug})")
    click.echo(f"  path        : {path}")
    click.echo(f"  task        : {task}")
    click.echo(f"  output      : {out}")
    click.echo(f"  dry-run     : {dry_run}")

    if dry_run:
        click.echo("")
        click.echo("  Would run:")
        click.echo(f"    1. context_builder({path}) → context.json")
        click.echo(f"    2. prompts/plan.md + context.json + task → Claude")
        click.echo(f"    3. Claude response → {out}")
        return

    # TODO: call agent.plan.run(path, task, target_slug)
    click.echo("\n  [stub] plan handler not implemented yet.")


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path",        required=True,                  help="Path to the project directory.")
@click.option("--target-name", required=True,                  help="Must match the target-name used in scan.")
@click.option("--diff",        "mode", flag_value="diff",      help="Review uncommitted changes (git diff HEAD).")
@click.option("--branch",      default=None,                   help="Review diff of this branch against main.")
@click.option("--dry-run",     is_flag=True,                   help="Show what would run without executing.")
def review(path, target_name, mode, branch, dry_run):
    """Review code changes for security issues.

    \b
    Default (no flag)  : current working tree + latest summary.json for this target
    --diff             : uncommitted changes (git diff HEAD)
    --branch <name>    : diff of <name> against main
    """
    # Guard: --diff and --branch are mutually exclusive
    if mode == "diff" and branch:
        raise click.UsageError("--diff and --branch are mutually exclusive. Use one or the other.")

    if branch:
        mode = "branch"

    target_slug = slugify(target_name)
    mode_label  = {
        "diff":   "uncommitted changes (git diff HEAD)",
        "branch": f"diff of '{branch}' against main",
        None:     "current working tree + latest summary.json",
    }[mode]

    branch_slug  = slugify(branch) if branch else None
    out_suffix   = f"_{branch_slug or mode or 'workdir'}_{timestamp()}.md"
    out          = f"reviews/{target_slug}{out_suffix}"
    summary_glob = f"reports/{target_slug}_summary_*.json"

    click.echo("[review]")
    click.echo(f"  target-name : {target_name}  (slug: {target_slug})")
    click.echo(f"  path        : {path}")
    click.echo(f"  mode        : {mode_label}")
    click.echo(f"  output      : {out}")
    click.echo(f"  dry-run     : {dry_run}")

    if dry_run:
        click.echo("")
        click.echo("  Would run:")
        click.echo(f"    1. context_builder({path}) → context.json")
        click.echo(f"    2. load {summary_glob} (latest, if available)")
        click.echo(f"    3. collect diff  [{mode_label}]")
        click.echo(f"    4. prompts/review.md + context + diff + summary → Claude")
        click.echo(f"    5. Claude response → {out}")
        return

    # TODO: call agent.review.run(path, target_slug, mode, branch)
    click.echo("\n  [stub] review handler not implemented yet.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
