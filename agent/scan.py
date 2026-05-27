"""
Scan orchestrator — runs requested scanners, parses output, writes summary.json.
"""

import glob
import json
import os

from agent.utils import report_path, slugify, timestamp
from devsecops.parsers import parse_trivy, summarize_findings
from devsecops.runners import run_trivy


def run(path: str, target_name: str, profile: str, scanners: list[str]) -> str:
    """
    Run security scanners for *profile* against *path*.

    Returns the path of the written summary.json.
    """
    target_slug = slugify(target_name)
    date        = timestamp()

    findings_by_scanner: dict[str, list] = {}
    scanners_run:        list[str]              = []
    scanners_skipped:    list[dict]             = []
    notes:               list[str]              = []

    # --- trivy_fs ---
    if "trivy_fs" in scanners:
        raw_file = report_path(path, f"{target_slug}_trivy_fs_{date}.json")
        try:
            raw = run_trivy.run(path, raw_file)
            findings_by_scanner["trivy_fs"] = parse_trivy.parse(raw)
            scanners_run.append("trivy_fs")
        except RuntimeError as exc:
            scanners_skipped.append({"scanner": "trivy_fs", "reason": str(exc)})
            findings_by_scanner["trivy_fs"] = []
            notes.append(f"trivy_fs skipped: {exc}")

    # --- checkov ---
    if "checkov" in scanners:
        # Quick check: skip if no IaC files found (avoids slow checkov startup)
        iac_patterns = ["**/*.tf", "**/Dockerfile", "**/*.bicep",
                        "**/*.template", "**/serverless.yml",
                        "**/k8s/*.yaml", "**/kubernetes/*.yaml"]
        has_iac = any(
            glob.glob(os.path.join(path, pat), recursive=True)
            for pat in iac_patterns
        )
        if not has_iac:
            reason = f"no IaC files found under {path}"
            scanners_skipped.append({"scanner": "checkov", "reason": reason})
            findings_by_scanner["checkov"] = []
            notes.append(f"checkov skipped: {reason}")
        else:
            raw_file = report_path(path, f"{target_slug}_checkov_{date}.json")
            try:
                from devsecops.runners import run_checkov
                from agent.plugins.scanners.checkov import CheckovScannerAdapter

                raw = run_checkov.run(path, raw_file)
                adapter = CheckovScannerAdapter()
                findings_by_scanner["checkov"] = adapter.parse_list(raw)
                scanners_run.append("checkov")
            except RuntimeError as exc:
                scanners_skipped.append({"scanner": "checkov", "reason": str(exc)})
                findings_by_scanner["checkov"] = []
                notes.append(f"checkov skipped: {exc}")

    # --- gitleaks ---
    if "gitleaks" in scanners:
        raw_file = report_path(path, f"{target_slug}_gitleaks_{date}.json")
        try:
            from devsecops.runners import run_gitleaks
            from agent.plugins.scanners.gitleaks import GitleaksScannerAdapter

            raw = run_gitleaks.run(path, raw_file)
            adapter = GitleaksScannerAdapter()
            findings_by_scanner["gitleaks"] = adapter.parse_list(raw)
            scanners_run.append("gitleaks")
        except RuntimeError as exc:
            scanners_skipped.append({"scanner": "gitleaks", "reason": str(exc)})
            findings_by_scanner["gitleaks"] = []
            notes.append(f"gitleaks skipped: {exc}")

    # --- semgrep / other future scanners ---
    for scanner in scanners:
        if scanner not in ("trivy_fs", "checkov", "gitleaks", "sarif"):
            scanners_skipped.append({"scanner": scanner, "reason": "runner not yet implemented"})
            findings_by_scanner[scanner] = []
            notes.append(f"{scanner} skipped: runner not yet implemented")

    summary = summarize_findings.build(
        target_name=target_name,
        target_slug=target_slug,
        path=path,
        profile=profile,
        scanners_requested=scanners,
        scanners_run=scanners_run,
        scanners_skipped=scanners_skipped,
        findings_by_scanner=findings_by_scanner,
        notes=notes,
    )

    summary_file = report_path(path, f"{target_slug}_summary_{date}.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    return summary_file
