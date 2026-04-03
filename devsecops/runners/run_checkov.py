"""Run checkov against a target path and save raw JSON output."""

import json
import os
import subprocess


def run(path: str, out_file: str) -> list:
    """Execute checkov against path, write JSON to out_file.

    Returns the parsed JSON as a list of check-type dicts.
    Raises RuntimeError if checkov is not installed or fails.

    Checkov outputs a single dict when one framework is scanned,
    or a list of dicts when multiple frameworks are detected.
    This function normalizes the output to always be a list.
    """
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    try:
        result = subprocess.run(
            ["checkov", "-d", path, "--output", "json", "--compact", "--quiet"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "checkov not found. Install it: pip install checkov"
        )

    # checkov exit codes: 0 = all passed, 1 = some failed, 2 = error
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"checkov error (exit {result.returncode}):\n{result.stderr.strip()}"
        )

    # Parse stdout — checkov outputs JSON to stdout
    stdout = result.stdout.strip()
    if not stdout:
        raw = []
    else:
        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            raise RuntimeError(
                f"checkov produced non-JSON output:\n{stdout[:500]}"
            )

    # Normalize: single dict → list
    if isinstance(raw, dict):
        raw = [raw]

    # Write to out_file for record-keeping
    with open(out_file, "w") as f:
        json.dump(raw, f, indent=2)

    return raw
