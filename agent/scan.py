"""
Scan orchestrator — runs requested scanners, parses output, writes summary.json.
"""

import glob
import json
import os

from agent.utils import slugify, timestamp
from devsecops.parsers import parse_trivy, summarize_findings
from devsecops.runners import run_trivy


def run(path: str, target_name: str, profile: str, scanners: list[str]) -> str:
    """
    Run security scanners for *profile* against *path*.

    Returns the path of the written summary.json.
    """
    target_slug = slugify(target_name)
    date        = timestamp()
    os.makedirs("reports", exist_ok=True)

    findings_by_scanner: dict[str, list[dict]] = {}
    scanners_run:        list[str]              = []
    scanners_skipped:    list[dict]             = []
    notes:               list[str]              = []

    # --- trivy_fs ---
    if "trivy_fs" in scanners:
        raw_file = f"reports/{target_slug}_trivy_fs_{date}.json"
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
        tf_files = glob.glob(os.path.join(path, "**", "*.tf"), recursive=True)
        if not tf_files:
            reason = f"no .tf files found under {path}"
            scanners_skipped.append({"scanner": "checkov", "reason": reason})
            findings_by_scanner["checkov"] = []
            notes.append(f"checkov skipped: {reason}")
        else:
            # TODO: implement checkov runner
            scanners_skipped.append({"scanner": "checkov", "reason": "runner not yet implemented"})
            findings_by_scanner["checkov"] = []
            notes.append("checkov skipped: runner not yet implemented")

    # --- semgrep / gitleaks (future) ---
    for scanner in scanners:
        if scanner not in ("trivy_fs", "checkov"):
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

    summary_file = f"reports/{target_slug}_summary_{date}.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    return summary_file
