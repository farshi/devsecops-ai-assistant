"""
Shared utility helpers for the devsec agent layer.
"""

import re
import shutil
import os
import glob
from datetime import datetime, timezone


def check_trivy_installed() -> bool:
    """Check if trivy binary is available on PATH."""
    return shutil.which("trivy") is not None


def timestamp() -> str:
    """Return current UTC date as YYYY-MM-DD string for output file naming."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def slugify(text: str, max_length: int = 40) -> str:
    """Convert free text to a lowercase hyphen-separated slug.

    Examples:
        "Add user authentication endpoint" -> "add-user-authentication-endpoint"
        "Migrate DB to PostgreSQL (v14)"   -> "migrate-db-to-postgresql-v14"
    """
    text = text.lower().strip()
    text = re.sub(r"[/\\]", "-", text)       # slashes → hyphens (e.g. feature/auth)
    text = re.sub(r"[^\w\s-]", "", text)     # strip remaining special chars
    text = re.sub(r"[\s_]+", "-", text)      # spaces/underscores → hyphens
    text = re.sub(r"-+", "-", text)          # collapse consecutive hyphens
    return text[:max_length].rstrip("-")


def patchpilot_dir(path: str = ".") -> str:
    """Return the project-local .patchpilot directory."""
    return os.path.join(path, ".patchpilot")


def reports_dir(path: str = ".") -> str:
    """Return the project-local PatchPilot reports directory."""
    return os.path.join(patchpilot_dir(path), "reports")


def ensure_reports_dir(path: str = ".") -> str:
    """Create and return the project-local PatchPilot reports directory."""
    directory = reports_dir(path)
    os.makedirs(directory, exist_ok=True)
    return directory


def report_path(path: str, filename: str) -> str:
    """Return a file path inside the project-local PatchPilot reports directory."""
    return os.path.join(ensure_reports_dir(path), filename)


def report_glob(path: str, pattern: str) -> str:
    """Return a glob pattern inside the project-local PatchPilot reports directory."""
    return os.path.join(reports_dir(path), pattern)


def find_report_matches(path: str, pattern: str) -> list[str]:
    """Find reports in the project-local directory, with legacy reports/ fallback."""
    matches = sorted(glob.glob(report_glob(path, pattern)))
    if matches:
        return matches
    return sorted(glob.glob(os.path.join("reports", pattern)))
