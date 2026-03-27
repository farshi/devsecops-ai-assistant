"""
Report generator — loads the latest summary.json for a target and asks Claude
to produce a human-readable security report.
"""

import glob
import json
import os

from agent import claude_client
from agent.utils import timestamp


def _load_prompt() -> str:
    prompt_path = os.path.join(os.path.dirname(__file__), "..", "prompts", "security_summary.md")
    with open(os.path.normpath(prompt_path)) as f:
        return f.read()


def _find_latest_summary(target_slug: str) -> str:
    """Return the path of the most recent summary JSON for *target_slug*."""
    pattern = f"reports/{target_slug}_summary_*.json"
    matches = sorted(glob.glob(pattern))
    if not matches:
        raise FileNotFoundError(
            f"No summary file found matching '{pattern}'. Run `scan` first."
        )
    return matches[-1]


def run(target_name: str, target_slug: str) -> str:
    """
    Load latest summary.json, call Claude, write report to reports/.

    Returns the path of the written report file.
    """
    summary_file = _find_latest_summary(target_slug)
    with open(summary_file) as f:
        summary = json.load(f)

    system_prompt = _load_prompt()
    user_message  = json.dumps(summary, indent=2)

    report_text = claude_client.call(system_prompt, user_message)

    out_file = f"reports/{target_slug}_security-report_{timestamp()}.md"
    os.makedirs("reports", exist_ok=True)
    with open(out_file, "w") as f:
        f.write(f"# Security Report — {target_name}\n\n")
        f.write(f"_Generated from: `{summary_file}`_\n\n")
        f.write("---\n\n")
        f.write(report_text)

    return out_file
