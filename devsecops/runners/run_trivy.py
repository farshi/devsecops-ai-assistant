"""
Run trivy fs against a target path and save raw JSON output.
"""

import json
import os
import subprocess


def run(path: str, out_file: str) -> dict:
    """
    Execute `trivy fs --format json` against *path* and write raw output to *out_file*.

    Returns the parsed raw JSON dict on success.
    Raises RuntimeError if trivy is not installed or exits non-zero.
    """
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    try:
        result = subprocess.run(
            ["trivy", "fs", "--format", "json", "--output", out_file, path],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "trivy not found. Install it: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )

    if result.returncode != 0:
        raise RuntimeError(f"trivy exited {result.returncode}:\n{result.stderr.strip()}")

    with open(out_file) as f:
        return json.load(f)
