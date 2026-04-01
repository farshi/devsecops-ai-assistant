"""Run gitleaks against a target path and save raw JSON output."""

import json
import os
import subprocess


def run(path: str, out_file: str) -> list:
    """Execute gitleaks detect against path, write JSON to out_file.

    Returns the parsed JSON list of findings.
    Raises RuntimeError if gitleaks is not installed or fails.
    """
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--source", path, "--report-format", "json",
             "--report-path", out_file, "--no-banner"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "gitleaks not found. Install it: https://github.com/gitleaks/gitleaks#installing"
        )

    # gitleaks exit codes: 0 = no leaks, 1 = leaks found, other = error
    if result.returncode not in (0, 1):
        raise RuntimeError(f"gitleaks error (exit {result.returncode}):\n{result.stderr.strip()}")

    if not os.path.isfile(out_file):
        # No findings = gitleaks may not create the file
        with open(out_file, "w") as f:
            json.dump([], f)
        return []

    with open(out_file) as f:
        return json.load(f)
