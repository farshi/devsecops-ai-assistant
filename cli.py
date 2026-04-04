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
    "full":     "trivy fs + checkov + semgrep + gitleaks",
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
              type=click.Choice(["default", "cra", "cyclonedx", "soc2", "iso27001"]),
              default="default", show_default=True,
              help="Output format. 'cra' generates EU CRA disclosure. 'cyclonedx' generates SBOM. 'soc2'/'iso27001' generate compliance reports.")
@click.option("--new-only", is_flag=True, default=False,
              help="Only show findings NEW since last scan.")
@click.option("--create-issues", is_flag=True, default=False,
              help="Create GitHub Issues for top findings (requires gh CLI).")
@click.option("--owners", is_flag=True, default=False,
              help="Resolve finding owners via git blame/CODEOWNERS.")
@click.option("--sarif", "sarif_path", default=None, type=click.Path(exists=True),
              help="Path to a SARIF 2.1.0 JSON file. Findings are merged into the triage pipeline.")
@click.option("--pr-comment", is_flag=True, default=False,
              help="Post triage results as PR comment (requires gh CLI & PR context).")
def triage(path, target_name, top, profile, scan, dry_run, fail_on, enhance, output_format, new_only, create_issues, owners, sarif_path, pr_comment):
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
        step = 6
        if enhance:
            click.echo(f"    {step}. add AI-generated explanations (requires ANTHROPIC_API_KEY)")
            step += 1
        if create_issues:
            click.echo(f"    {step}. create GitHub Issues for top findings (requires gh CLI)")
            step += 1
        if owners:
            click.echo(f"    {step}. resolve finding owners via git blame/CODEOWNERS")
            step += 1
        if pr_comment:
            click.echo(f"    {step}. post triage results as PR comment (requires gh CLI)")
            step += 1
        if fail_on:
            click.echo(f"    {step}. exit 1 if {fail_on}+ findings exist")
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
        if not matches and not sarif_path:
            raise click.ClickException(
                f"No summary found for '{target_name}'. Run with --scan first or provide --sarif."
            )
        if matches:
            summary_path = matches[-1]
            click.echo(f"\n  [1/5] Using existing summary: {summary_path}")
        else:
            # SARIF-only workflow: create minimal summary
            summary_path = f"reports/{target_slug}_summary_{timestamp()}.json"
            os.makedirs("reports", exist_ok=True)
            with open(summary_path, "w") as f:
                json.dump({
                    "target_name": target_name,
                    "target_slug": target_slug,
                    "path": path,
                    "profile": "sarif-only",
                    "scanners_run": [],
                    "findings": {},
                }, f, indent=2)
            click.echo(f"\n  [1/5] Created empty summary for SARIF import: {summary_path}")

    # Inject SARIF findings into summary if provided
    if sarif_path:
        from agent.plugins.scanners.sarif import SARIFScannerAdapter
        click.echo(f"  [sarif] Importing findings from {sarif_path}...")
        sarif_findings = SARIFScannerAdapter().parse(sarif_path)
        click.echo(f"  [sarif] {len(sarif_findings)} findings imported.")

        with open(summary_path) as f:
            summary_data = json.load(f)
        summary_data.setdefault("findings", {})["sarif"] = [
            {"id": sf.id, "severity": sf.severity, "title": sf.title,
             "package": sf.package, "installed_version": sf.installed_version,
             "fixed_version": sf.fixed_version, "location": sf.location,
             "cvss_score": sf.cvss_score, "source_scanner": sf.source_scanner,
             "finding_type": sf.finding_type}
            for sf in sarif_findings
        ]
        if "sarif" not in summary_data.get("scanners_run", []):
            summary_data.setdefault("scanners_run", []).append("sarif")
        with open(summary_path, "w") as f:
            json.dump(summary_data, f, indent=2)

    # Steps 2-5: Run triage pipeline
    click.echo("  [2/5] Building repo context...")
    click.echo("  [3/5] Enriching findings...")
    click.echo("  [4/5] Scoring and ranking...")

    from agent.prioritizer import run_triage
    result = run_triage(path, summary_path, top_n=top, enhance=enhance, new_only=new_only)

    # Resolve ownership if requested
    if owners:
        from agent.ownership import resolve_owners
        click.echo("  [owners] Resolving finding owners...")
        resolve_owners(result["triage"]["action_items"], path)

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
    from agent.state import get_assignments
    _assignments = get_assignments(path)

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
            owner = item.get("owner", {})
            if owner.get("name"):
                click.echo(f"       Owner: {owner['name']} (via {owner.get('source', '?')})")
            assignment = _assignments.get(item["id"], {})
            if assignment.get("assigned_to"):
                click.echo(f"       Assigned to: {assignment['assigned_to']}")
            click.echo("")
    else:
        click.echo("  No actionable findings found.")

    click.echo(f"  Reports:")
    click.echo(f"    markdown → {report_file}")
    click.echo(f"    json     → {json_file}")

    # GitHub Issues creation
    if create_issues:
        from agent.ticket_creator import create_issues_from_triage
        click.echo("")
        click.echo("  [issues] Creating GitHub Issues...")
        issue_result = create_issues_from_triage(triage_data, dry_run=dry_run)

        created_issues = issue_result["created"]
        skipped_issues = issue_result["skipped"]
        issue_errors = issue_result["errors"]

        if created_issues:
            click.echo(f"  [issues] Created {len(created_issues)} issues:")
            for c in created_issues:
                click.echo(f"    #{c['rank']} {c['id']} -> {c['issue_url']}")
        if skipped_issues:
            click.echo(f"  [issues] Skipped {len(skipped_issues)} (duplicates):")
            for s in skipped_issues:
                click.echo(f"    #{s['rank']} {s['id']} -- {s['reason']}")
        if issue_errors:
            click.echo(f"  [issues] Errors ({len(issue_errors)}):")
            for e in issue_errors:
                click.echo(f"    #{e['rank']} {e['id']} -- {e['error']}")

        if not created_issues and not skipped_issues and not issue_errors:
            click.echo("  [issues] No action items to create issues for.")

    # PR comment posting
    if pr_comment:
        from agent.pr_commenter import post_pr_comment
        click.echo("")
        click.echo("  [pr-comment] Posting triage to PR...")
        comment_result = post_pr_comment(triage_data, result["markdown"], dry_run=dry_run)
        if "error" in comment_result:
            click.echo(f"  [pr-comment] Error: {comment_result['error']}")
        else:
            action = "Updated" if comment_result.get("updated") else "Posted"
            click.echo(f"  [pr-comment] {action}: {comment_result['comment_url']}")

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

    # CycloneDX SBOM generation
    if output_format == "cyclonedx":
        from agent.plugins.formatters.cyclonedx import CycloneDXFormatter
        from agent.prioritizer import _finding_from_dict
        from agent.context_builder import build_context

        ctx = build_context(path, summary_path)
        all_findings = [_finding_from_dict(fd) for fd in ctx.get("findings", [])]

        sbom_doc = CycloneDXFormatter().format(all_findings, ctx)
        sbom_file = f"reports/{target_slug}_sbom_{triage_ts}.json"
        with open(sbom_file, "w") as f:
            f.write(sbom_doc)
        click.echo(f"    cyclonedx → {sbom_file}")

    # SOC2 compliance report
    if output_format == "soc2":
        from agent.plugins.formatters.soc2 import SOC2ComplianceFormatter
        from agent.prioritizer import _finding_from_dict
        from agent.context_builder import build_context

        ctx = build_context(path, summary_path)
        all_findings = [_finding_from_dict(fd) for fd in ctx.get("findings", [])]

        soc2_doc = SOC2ComplianceFormatter().format(all_findings, ctx)
        soc2_file = f"reports/{target_slug}_soc2_{triage_ts}.md"
        with open(soc2_file, "w") as f:
            f.write(soc2_doc)
        click.echo(f"    soc2     → {soc2_file}")

    # ISO 27001 compliance report
    if output_format == "iso27001":
        from agent.plugins.formatters.iso27001 import ISO27001ComplianceFormatter
        from agent.prioritizer import _finding_from_dict
        from agent.context_builder import build_context

        ctx = build_context(path, summary_path)
        all_findings = [_finding_from_dict(fd) for fd in ctx.get("findings", [])]

        iso_doc = ISO27001ComplianceFormatter().format(all_findings, ctx)
        iso_file = f"reports/{target_slug}_iso27001_{triage_ts}.md"
        with open(iso_file, "w") as f:
            f.write(iso_doc)
        click.echo(f"    iso27001 → {iso_file}")

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
# close
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path", default=".", show_default=True, help="Project path.")
@click.option("--cve", required=True, help="CVE ID to mark as resolved.")
@click.option("--reason", default="", help="How it was resolved (e.g. 'upgraded to 2.1.0').")
def close(path, cve, reason):
    """Mark a finding as resolved/remediated.

    \b
    Unlike dismiss (noise) or accept-risk (known risk), close means
    the vulnerability was actually fixed. Closed findings will reappear
    as regressions if the CVE shows up again in a future scan.

    \b
    Example:
      patchpilot close --cve CVE-2023-xxxxx --reason "upgraded to 2.1.0"
    """
    import os
    from agent.state import close_cve

    close_cve(path, cve, reason)
    state_file = os.path.join(path, ".patchpilot", "state.json")
    click.echo(f"  Closed {cve}" + (f" — {reason}" if reason else ""))
    click.echo(f"  State saved → {state_file}")


# ---------------------------------------------------------------------------
# assign / unassign
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path", default=".", show_default=True, help="Project path.")
@click.option("--cve", required=True, help="CVE ID to assign.")
@click.option("--to", "assigned_to", required=True, help="Person or team (e.g. alice@company.com, @security-team).")
@click.option("--reason", default="", help="Why this person/team (e.g. 'owns auth module').")
def assign(path, cve, assigned_to, reason):
    """Assign a finding to a person or team for remediation tracking.

    \b
    Example:
      patchpilot assign --cve CVE-2023-xxxxx --to alice@company.com
      patchpilot assign --cve CVE-2023-xxxxx --to @security-team --reason "owns auth module"
    """
    import os
    from agent.state import assign_cve

    assign_cve(path, cve, assigned_to, reason)
    state_file = os.path.join(path, ".patchpilot", "state.json")
    click.echo(f"  Assigned {cve} → {assigned_to}" + (f" ({reason})" if reason else ""))
    click.echo(f"  State saved → {state_file}")


@cli.command()
@click.option("--path", default=".", show_default=True, help="Project path.")
@click.option("--cve", required=True, help="CVE ID to unassign.")
def unassign(path, cve):
    """Remove assignment for a finding.

    \b
    Example:
      patchpilot unassign --cve CVE-2023-xxxxx
    """
    import os
    from agent.state import unassign_cve

    unassign_cve(path, cve)
    state_file = os.path.join(path, ".patchpilot", "state.json")
    click.echo(f"  Unassigned {cve}")
    click.echo(f"  State saved → {state_file}")


# ---------------------------------------------------------------------------
# trends
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# digest
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--path", default=".", show_default=True, help="Project path.")
@click.option("--target-name", required=True, help="Target name for report lookup.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output as JSON.")
@click.option("--days", default=7, show_default=True, help="Look-back window in days.")
@click.option("--pr-comment", is_flag=True, default=False,
              help="Post digest as PR comment (requires gh CLI & PR context).")
def digest(path, target_name, output_json, days, pr_comment):
    """Generate weekly vulnerability triage digest.

    \b
    Reads existing .patchpilot/ data (no scan needed) and produces a
    concise summary of current status, changes, trends, and top priorities.

    Example:
      patchpilot digest --path ./app --target-name myapp
      patchpilot digest --path ./app --target-name myapp --days 14
      patchpilot digest --path ./app --target-name myapp --json
    """
    import os
    from agent.digest import generate_digest, format_digest_json
    from agent.utils import slugify, timestamp as ts

    result = generate_digest(path, target_name, days=days)

    if "error" in result:
        click.echo(f"  {result['error']}")
        return

    if output_json:
        output = format_digest_json(result["data"])
        ext = "json"
    else:
        output = result["markdown"]
        ext = "md"

    click.echo(output)

    # Save report
    target_slug = slugify(target_name)
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{target_slug}_digest_{ts()}.{ext}")
    with open(report_path, "w") as f:
        f.write(output)
    click.echo(f"\n  Report saved → {report_path}")

    # PR comment
    if pr_comment:
        from agent.pr_commenter import post_pr_comment, DIGEST_MARKER
        click.echo("")
        click.echo("  [pr-comment] Posting digest to PR...")
        comment_result = post_pr_comment(
            result["data"], result["markdown"], marker=DIGEST_MARKER
        )
        if "error" in comment_result:
            click.echo(f"  [pr-comment] Error: {comment_result['error']}")
        else:
            action = "Updated" if comment_result.get("updated") else "Posted"
            click.echo(f"  [pr-comment] {action}: {comment_result['comment_url']}")


@cli.command()
@click.option("--path", default=".", show_default=True, help="Project path.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output as JSON.")
def trends(path, output_json):
    """Show vulnerability trends over time.

    \b
    Reads historical scan snapshots from .patchpilot/history.json
    (auto-captured on each triage run) and displays trend analysis.

    Example:
      patchpilot trends --path ./myapp
      patchpilot trends --path ./myapp --json
    """
    import os
    from agent.trends import (
        load_history,
        compute_trends,
        format_trend_report_markdown,
        format_trend_report_json,
    )
    from agent.utils import slugify, timestamp as ts

    history = load_history(path)
    snapshots = history.get("snapshots", [])

    if not snapshots:
        click.echo("  No trend history found. Run `patchpilot triage` at least twice to see trends.")
        return

    if len(snapshots) < 2:
        click.echo("  Only 1 snapshot in history. Run `patchpilot triage` again to start tracking trends.")
        return

    from agent.state import load_state as _load_state
    closed = _load_state(path).get("closed", {})
    trend_data = compute_trends(history, closed=closed)

    if output_json:
        output = format_trend_report_json(trend_data)
        ext = "json"
    else:
        output = format_trend_report_markdown(trend_data)
        ext = "md"

    click.echo(output)

    # Save report
    target_slug = slugify(os.path.basename(os.path.abspath(path)))
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{target_slug}_trends_{ts()}.{ext}")
    with open(report_path, "w") as f:
        f.write(output)
    click.echo(f"\n  Report saved → {report_path}")


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

    from agent import review as review_agent
    try:
        result = review_agent.run(path, target_slug, mode, branch)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    # Save review output
    import os as _os
    _os.makedirs("reviews", exist_ok=True)
    out = f"reviews/{target_slug}{out_suffix}"
    with open(out, "w") as f:
        f.write(f"# Security Review — {target_name}\n\n")
        f.write(f"**Verdict: {result['verdict']}**\n\n")
        f.write(f"Files reviewed: {', '.join(result['changed_files'][:10])}\n\n")
        f.write("---\n\n")
        f.write(result["review_text"])

    click.echo(f"\n  Verdict: {result['verdict']}")
    click.echo(f"  Files reviewed: {len(result['changed_files'])}")
    click.echo(f"  Review written → {out}")

    # Exit code for CI
    if result["verdict"] == "BLOCK":
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
