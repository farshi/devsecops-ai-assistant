"""Security review — scans git diffs for security issues."""

import json
import os
import subprocess

from agent import llm_client
from agent.context_builder import detect_repo_structure, extract_dependencies
from agent.config import load_config, resolve_llm_provider


def run(path: str, target_slug: str, mode: str = None, branch: str = None) -> dict:
    """Run security review on code changes.

    Args:
        path: Project root path
        target_slug: Target name slug for output files
        mode: "diff" for uncommitted changes, None for default (workdir)
        branch: Branch name to diff against main

    Returns:
        {
            "verdict": "PASS" | "WARN" | "BLOCK",
            "review_text": "full LLM review output",
            "changed_files": ["file1.py", ...],
            "diff_stats": {"insertions": 10, "deletions": 5},
        }
    """
    # Get the diff
    diff_text, changed_files = _get_diff(path, mode, branch)

    if not diff_text.strip():
        return {
            "verdict": "PASS",
            "review_text": "No changes to review.",
            "changed_files": [],
            "diff_stats": {"insertions": 0, "deletions": 0},
        }

    # Build context
    structure = detect_repo_structure(path)
    dependencies = extract_dependencies(path, structure)
    config = load_config(path)

    # Load the review prompt
    prompt_path = os.path.join(os.path.dirname(__file__), "..", "prompts", "review.md")
    with open(os.path.normpath(prompt_path)) as f:
        system_prompt = f.read()

    # Build the user message
    # Read changed file contents for context
    file_contents = {}
    for cf in changed_files[:20]:  # Cap at 20 files
        full_path = os.path.join(path, cf)
        if os.path.isfile(full_path):
            try:
                with open(full_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                if len(content) < 10000:  # Cap file size
                    file_contents[cf] = content
            except OSError:
                pass

    # Count diff stats
    insertions = diff_text.count("\n+") - diff_text.count("\n+++")
    deletions = diff_text.count("\n-") - diff_text.count("\n---")

    user_message = json.dumps({
        "diff": {
            "patch": diff_text[:50000],  # Cap diff size
            "changed_files": changed_files,
            "stats": {"insertions": max(insertions, 0), "deletions": max(deletions, 0)},
        },
        "files": file_contents,
        "dependencies": {
            "direct": dependencies.get("direct", []),
            "package_manager": dependencies.get("package_manager", "unknown"),
        },
        "security": {
            "scans": None,  # Could load latest scan summary if available
        },
    }, indent=2)

    # Call LLM
    provider = resolve_llm_provider(config)

    api_key_var = "ANTHROPIC_API_KEY" if provider == "claude" else "OPENAI_API_KEY"
    if not os.environ.get(api_key_var):
        raise RuntimeError(
            f"{api_key_var} not set. The review command requires an LLM.\n"
            f"  export {api_key_var}=your-key"
        )

    review_text = llm_client.call(system_prompt, user_message, provider=provider)

    # Extract verdict from review text
    verdict = _extract_verdict(review_text)

    return {
        "verdict": verdict,
        "review_text": review_text,
        "changed_files": changed_files,
        "diff_stats": {"insertions": max(insertions, 0), "deletions": max(deletions, 0)},
    }


def _get_diff(path: str, mode: str = None, branch: str = None) -> tuple:
    """Get git diff and list of changed files.

    Returns (diff_text, changed_files_list)
    """
    try:
        if branch:
            # Diff against specific branch
            diff_cmd = ["git", "diff", f"{branch}...HEAD"]
            files_cmd = ["git", "diff", "--name-only", f"{branch}...HEAD"]
        elif mode == "diff":
            # Uncommitted changes
            diff_cmd = ["git", "diff", "HEAD"]
            files_cmd = ["git", "diff", "--name-only", "HEAD"]
        else:
            # Default: uncommitted changes + staged
            diff_cmd = ["git", "diff", "HEAD"]
            files_cmd = ["git", "diff", "--name-only", "HEAD"]

        diff_result = subprocess.run(
            diff_cmd, capture_output=True, text=True, cwd=path
        )
        files_result = subprocess.run(
            files_cmd, capture_output=True, text=True, cwd=path
        )

        diff_text = diff_result.stdout
        changed_files = [f for f in files_result.stdout.strip().split("\n") if f]

        return diff_text, changed_files
    except (subprocess.SubprocessError, OSError):
        return "", []


def _extract_verdict(review_text: str) -> str:
    """Extract PASS/WARN/BLOCK verdict from review text."""
    text_upper = review_text.upper()
    if "**BLOCK**" in text_upper or "VERDICT: BLOCK" in text_upper or "## VERDICT\nBLOCK" in text_upper:
        return "BLOCK"
    elif "**WARN**" in text_upper or "VERDICT: WARN" in text_upper:
        return "WARN"
    return "PASS"
