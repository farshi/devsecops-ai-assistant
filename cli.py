"""
devsec — DevSecOps AI Assistant CLI

Python orchestrates, scanners measure, Claude reasons.
Claude reads summarized evidence by default, not raw scan dumps.

Until packaging is added, invoke the CLI directly:
    python cli.py analyze  --path ./app --target-name myapp
    python cli.py scan     --path ./app --target-name myapp --profile standard
    python cli.py report   --target-name myapp
    python cli.py plan     --path ./app --target-name myapp --task "add auth"
    python cli.py review   --path ./app --target-name myapp [--diff | --branch feature/x]

Once installed as a package, the entrypoint becomes:
    devsec <command> ...
"""

import click
from agent.utils import timestamp, slugify


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
def cli():
    """DevSecOps AI Assistant — analyze, scan, report, plan, review."""
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

    from agent import scan as scan_agent
    summary_file = scan_agent.run(path, target_name, profile, scanners)
    click.echo(f"\n  summary written → {summary_file}")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target-name", required=True, help="Must match the target-name used in scan.")
@click.option("--dry-run",     is_flag=True,  help="Show what would run without executing.")
def report(target_name, dry_run):
    """Generate AI security report from latest scan results."""
    target_slug  = slugify(target_name)
    summary_glob = f"reports/{target_slug}_summary_*.json"
    out          = output_path("reports", target_slug, "_security-report.md")

    click.echo("[report]")
    click.echo(f"  target-name : {target_name}  (slug: {target_slug})")
    click.echo(f"  reads       : {summary_glob}  (latest match)")
    click.echo(f"  output      : {out}")
    click.echo(f"  dry-run     : {dry_run}")

    if dry_run:
        click.echo("")
        click.echo("  Would run:")
        click.echo(f"    1. load {summary_glob} (latest)")
        click.echo(f"    2. prompts/security_summary.md + summary → Claude")
        click.echo(f"    3. Claude response → {out}")
        return

    # TODO: call agent.security_summary.report(target_slug)
    click.echo("\n  [stub] report handler not implemented yet.")


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
