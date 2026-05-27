"""
Report generator — loads the latest summary.json for a target and asks an LLM
to produce a human-readable security report.
"""

import glob
import json
import os

from agent import llm_client
from agent.config import load_config, resolve_llm_provider
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


def _require_llm_key(provider: str) -> None:
    key_var = "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY"
    if not os.environ.get(key_var):
        raise RuntimeError(
            f"{key_var} not set. Export {key_var} or choose another provider."
        )


def run(target_name: str, target_slug: str) -> str:
    """
    Load latest summary.json, call configured LLM, write report to reports/.

    Returns the path of the written report file.
    """
    summary_file = _find_latest_summary(target_slug)
    with open(summary_file) as f:
        summary = json.load(f)

    system_prompt = _load_prompt()
    user_message  = json.dumps(summary, indent=2)

    provider = resolve_llm_provider()
    _require_llm_key(provider)
    report_text = llm_client.call(system_prompt, user_message, provider=provider)

    out_file = f"reports/{target_slug}_security-report_{timestamp()}.md"
    os.makedirs("reports", exist_ok=True)
    with open(out_file, "w") as f:
        f.write(f"# Security Report — {target_name}\n\n")
        f.write(f"_Generated from: `{summary_file}`_\n\n")
        f.write("---\n\n")
        f.write(report_text)

    return out_file


def run_with_triage(target_name: str, target_slug: str, path: str, top_n: int = 5) -> str:
    """Generate a prioritized security report using the triage pipeline.

    Unlike run(), this sends the configured LLM prioritized, context-enriched
    findings instead of raw scanner output. The report reads like an action plan.

    Returns the path of the written report file.
    """
    summary_file = _find_latest_summary(target_slug)

    from agent.prioritizer import run_triage
    triage_result = run_triage(path, summary_file, top_n=top_n)

    system_prompt = _load_prompt()

    # Give the LLM both structured data and the pre-generated markdown.
    user_message = json.dumps({
        "triage": triage_result["triage"],
        "pre_generated_report": triage_result["markdown"],
        "instructions": (
            "You are enhancing this triage report. The findings are already ranked by "
            "an algorithmic prioritizer. Your job is to:\n"
            "1. Add plain-English context for WHY each top finding matters\n"
            "2. Explain the reachability and exploitability signals in human terms\n"
            "3. Give concrete next-step recommendations\n"
            "4. Keep the ranking — do NOT re-order findings\n"
            "5. Add a brief executive summary at the top"
        ),
    }, indent=2)

    provider = resolve_llm_provider(load_config(path))
    _require_llm_key(provider)
    report_text = llm_client.call(system_prompt, user_message, provider=provider)

    out_file = f"reports/{target_slug}_security-report_{timestamp()}.md"
    os.makedirs("reports", exist_ok=True)
    with open(out_file, "w") as f:
        f.write(f"# Security Report — {target_name}\n\n")
        f.write(f"_Generated from triage of: `{summary_file}`_\n\n")
        f.write("---\n\n")
        f.write(report_text)

    return out_file
