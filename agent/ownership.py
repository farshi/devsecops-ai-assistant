"""Finding ownership resolution via CODEOWNERS and git blame."""

from __future__ import annotations

import os
import re
import subprocess
from fnmatch import fnmatch
from typing import Optional


def resolve_owners(action_items: list[dict], repo_path: str) -> list[dict]:
    """For each action item, resolve owner and add 'owner' dict.

    Resolution order:
    1. CODEOWNERS match (highest confidence)
    2. Git blame on location file (most frequent recent author)
    3. None — no owner found

    Performance: caps at 20 unique files to avoid slow blame on large repos.

    Args:
        action_items: List of action item dicts from triage (must have 'location' key)
        repo_path: Path to the git repo root

    Returns:
        Same action_items list with 'owner' dict added to each item:
        {"name": "...", "email": "...", "source": "codeowners"|"git_blame"|"none"}
    """
    # Parse CODEOWNERS once
    codeowners = _parse_codeowners(repo_path)

    # Collect unique file paths from locations, cap at 20
    blame_cache = {}  # file_path -> owner dict
    unique_files = []
    for item in action_items:
        file_path = _extract_file_path(item.get("location", ""))
        if file_path and file_path not in blame_cache and len(unique_files) < 20:
            unique_files.append(file_path)
            blame_cache[file_path] = None  # placeholder

    # Git blame unique files
    for file_path in unique_files:
        blame_cache[file_path] = _git_blame_owner(file_path, repo_path)

    # Resolve each item
    for item in action_items:
        location = item.get("location", "")
        file_path = _extract_file_path(location)

        # Try CODEOWNERS first
        if codeowners and file_path:
            co_owner = _match_codeowners(file_path, codeowners)
            if co_owner:
                item["owner"] = {"name": co_owner, "email": None, "source": "codeowners"}
                continue

        # Try git blame
        if file_path and file_path in blame_cache and blame_cache[file_path]:
            item["owner"] = blame_cache[file_path]
            continue

        # No owner found
        item["owner"] = {"name": None, "email": None, "source": "none"}

    return action_items


def _extract_file_path(location: str) -> Optional[str]:
    """Extract a file path from a Finding location string.

    Locations can be:
    - "requirements.txt" (plain file)
    - "requirements.txt > package@version" (dep location)
    - "app/main.py:42" (file with line number)
    - "" (empty)

    Returns just the file path part, or None.
    """
    if not location:
        return None
    # Strip " > package@version" suffix
    if " > " in location:
        location = location.split(" > ")[0]
    # Strip ":line_number" suffix
    if ":" in location:
        parts = location.rsplit(":", 1)
        if parts[1].isdigit():
            location = parts[0]
    return location.strip() if location.strip() else None


def _parse_codeowners(repo_path: str) -> list[tuple[str, str]]:
    """Parse CODEOWNERS file. Returns list of (pattern, owner) tuples.

    Checks: .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS
    """
    candidates = [
        os.path.join(repo_path, ".github", "CODEOWNERS"),
        os.path.join(repo_path, "CODEOWNERS"),
        os.path.join(repo_path, "docs", "CODEOWNERS"),
    ]

    content = None
    for path in candidates:
        if os.path.isfile(path):
            with open(path) as f:
                content = f.read()
            break

    if not content:
        return []

    rules = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            pattern = parts[0]
            owner = parts[1]  # Take first owner
            rules.append((pattern, owner))

    return rules


def _match_codeowners(file_path: str, rules: list[tuple[str, str]]) -> Optional[str]:
    """Match file path against CODEOWNERS rules. Last match wins (GitHub convention)."""
    matched_owner = None
    for pattern, owner in rules:
        # Handle directory patterns like "docs/"
        if pattern.endswith("/"):
            if file_path.startswith(pattern) or file_path.startswith(pattern.lstrip("/")):
                matched_owner = owner
        # Handle glob patterns
        elif fnmatch(file_path, pattern) or fnmatch(file_path, pattern.lstrip("/")):
            matched_owner = owner
        # Handle "*.ext" patterns
        elif pattern.startswith("*") and file_path.endswith(pattern[1:]):
            matched_owner = owner
    return matched_owner


def _git_blame_owner(file_path: str, repo_path: str) -> Optional[dict]:
    """Run git blame on a file, return most frequent author from last 6 months.

    Returns: {"name": "...", "email": "...", "source": "git_blame"} or None
    """
    full_path = os.path.join(repo_path, file_path)
    if not os.path.isfile(full_path):
        return None

    try:
        result = subprocess.run(
            ["git", "blame", "--porcelain", "--since=6.months", file_path],
            capture_output=True,
            text=True,
            cwd=repo_path,
            timeout=10,
        )
        if result.returncode != 0:
            return None

        return _parse_blame_output(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _parse_blame_output(output: str) -> Optional[dict]:
    """Parse git blame --porcelain output, return most frequent author."""
    authors = {}  # "name <email>" -> count
    current_name = None
    current_email = None

    for line in output.splitlines():
        if line.startswith("author "):
            current_name = line[7:]
        elif line.startswith("author-mail "):
            current_email = line[12:].strip("<>")
            if current_name and current_email:
                key = f"{current_name} <{current_email}>"
                authors[key] = authors.get(key, 0) + 1
                current_name = None
                current_email = None

    if not authors:
        return None

    # Most frequent author
    top = max(authors, key=authors.get)
    # Parse back
    match = re.match(r"(.+) <(.+)>", top)
    if match:
        return {"name": match.group(1), "email": match.group(2), "source": "git_blame"}
    return None
