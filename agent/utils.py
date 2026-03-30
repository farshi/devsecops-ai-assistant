"""
Shared utility helpers for the devsec agent layer.
"""

import re
import shutil
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
