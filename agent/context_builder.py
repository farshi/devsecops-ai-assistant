import glob
import json
import os
import re
from typing import Optional

from agent.models import Finding


# Marker files to check for each language/tool category
_MARKERS = [
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".github/workflows",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "terraform/",
    "*.tf",
    "k8s/",
    "kubernetes/",
]

# Language detection: marker -> language
_LANGUAGE_MARKERS = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "Pipfile": "python",
    "setup.py": "python",
    "setup.cfg": "python",
    "package.json": "javascript",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "Gemfile": "ruby",
}

# Framework keywords to search inside dependency files
_PYTHON_FRAMEWORKS = ["fastapi", "django", "flask", "starlette"]
_NODE_FRAMEWORKS = {
    "express": "express",
    "next": "nextjs",
    "react": "react",
    "vue": "vue",
    "fastify": "fastify",
}


def _check_marker(path: str, marker: str) -> bool:
    """Return True if a marker file/dir/glob exists under path."""
    if marker.endswith("/"):
        # directory check
        return os.path.isdir(os.path.join(path, marker.rstrip("/")))
    if "*" in marker:
        # glob check — limit to depth 3 to avoid slow scans
        matches = glob.glob(os.path.join(path, "**", os.path.basename(marker)), recursive=True)
        return bool(matches)
    target = os.path.join(path, marker)
    return os.path.exists(target)


def _detect_python_frameworks(path: str) -> list[str]:
    """Scan Python dependency files for known framework names."""
    frameworks = []
    for dep_file in ("requirements.txt", "pyproject.toml"):
        full_path = os.path.join(path, dep_file)
        if not os.path.isfile(full_path):
            continue
        try:
            with open(full_path) as fh:
                content = fh.read().lower()
        except OSError:
            continue
        for fw in _PYTHON_FRAMEWORKS:
            if fw in content and fw not in frameworks:
                frameworks.append(fw)
        break  # use the first file found
    return frameworks


def _detect_node_frameworks(path: str) -> list[str]:
    """Scan package.json for known framework names."""
    pkg_path = os.path.join(path, "package.json")
    if not os.path.isfile(pkg_path):
        return []
    try:
        with open(pkg_path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    all_deps: dict = {}
    for key in ("dependencies", "devDependencies"):
        all_deps.update(data.get(key, {}))

    frameworks = []
    for pkg_name, fw_name in _NODE_FRAMEWORKS.items():
        if pkg_name in all_deps and fw_name not in frameworks:
            frameworks.append(fw_name)
    return frameworks


def detect_repo_structure(path: str) -> dict:
    """Scan a repository and return a dict describing its structure.

    Args:
        path: Absolute or relative path to the root of the repository.

    Returns:
        A dict with keys: languages, frameworks, runtime, has_ci, has_iac,
        package_files, markers.
    """
    # --- Build markers map ---
    markers: dict[str, bool] = {}
    for marker in _MARKERS:
        markers[marker] = _check_marker(path, marker)

    # --- Languages ---
    languages: list[str] = []

    for marker, lang in _LANGUAGE_MARKERS.items():
        if markers.get(marker, False) and lang not in languages:
            languages.append(lang)

    # Fallback: check for *.py files in root if no other Python marker matched
    if "python" not in languages:
        py_files = glob.glob(os.path.join(path, "*.py"))
        if py_files:
            languages.append("python")

    # --- Frameworks ---
    frameworks: list[str] = []
    if "python" in languages:
        frameworks.extend(_detect_python_frameworks(path))
    if "javascript" in languages:
        frameworks.extend(_detect_node_frameworks(path))

    # --- Runtime ---
    docker_markers = ("Dockerfile", "docker-compose.yml", "docker-compose.yaml")
    runtime = "docker" if any(markers.get(m) for m in docker_markers) else "none"

    # --- CI ---
    ci_markers = (".github/workflows", ".gitlab-ci.yml", "Jenkinsfile")
    has_ci = any(markers.get(m) for m in ci_markers)
    # Also check .circleci/ separately (not in main markers list)
    if not has_ci:
        has_ci = os.path.isdir(os.path.join(path, ".circleci"))

    # --- IaC ---
    iac_markers = ("terraform/", "*.tf", "k8s/", "kubernetes/")
    has_iac = any(markers.get(m) for m in iac_markers)
    if not has_iac:
        has_iac = os.path.isdir(os.path.join(path, "cloudformation"))

    # --- Package files ---
    python_pkg_files = ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"]
    node_pkg_files = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    all_pkg_candidates = python_pkg_files + node_pkg_files + ["go.mod", "Cargo.toml", "Gemfile"]
    package_files = [f for f in all_pkg_candidates if markers.get(f, False)]

    return {
        "languages": languages,
        "frameworks": frameworks,
        "runtime": runtime,
        "has_ci": has_ci,
        "has_iac": has_iac,
        "package_files": package_files,
        "markers": markers,
    }


# ---------------------------------------------------------------------------
# Dependency extraction helpers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(filepath: str) -> list[str]:
    """Parse a requirements.txt file and return a list of dependency strings."""
    deps = []
    try:
        with open(filepath) as fh:
            for raw_line in fh:
                line = raw_line.strip()
                # Skip blank lines, comments, include references, editable installs, flags
                if not line:
                    continue
                if line.startswith("#"):
                    continue
                if line.startswith("-r ") or line.startswith("--"):
                    continue
                if line.startswith("-e "):
                    continue
                # Strip inline comment
                line = line.split(" #")[0].strip()
                if line:
                    deps.append(line)
    except OSError:
        pass
    return deps


def _parse_pyproject_toml(filepath: str) -> list[str]:
    """Parse [project.dependencies] from a pyproject.toml using simple line scanning."""
    deps = []
    try:
        with open(filepath) as fh:
            lines = fh.readlines()
    except OSError:
        return deps

    in_deps_block = False
    for line in lines:
        stripped = line.strip()
        # Enter the dependencies array
        if re.match(r"dependencies\s*=\s*\[", stripped):
            in_deps_block = True
            # Handle inline single-line case: dependencies = ["pkg"]
            inner = re.search(r"\[(.+)\]", stripped)
            if inner:
                for item in inner.group(1).split(","):
                    pkg = item.strip().strip('"\'')
                    if pkg:
                        deps.append(pkg)
                in_deps_block = False
            continue
        if in_deps_block:
            if stripped.startswith("]"):
                in_deps_block = False
                continue
            # Each line like: "fastapi>=0.110.0",
            pkg = stripped.strip(",").strip('"\'')
            if pkg and not pkg.startswith("#"):
                deps.append(pkg)
    return deps


def _parse_package_json(filepath: str) -> list[str]:
    """Parse package.json and return combined direct + dev dependency strings."""
    deps = []
    try:
        with open(filepath) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return deps

    for section in ("dependencies", "devDependencies"):
        for pkg_name, version in data.get(section, {}).items():
            deps.append(f"{pkg_name}@{version}")
    return deps


def _parse_go_mod(filepath: str) -> list[str]:
    """Parse require blocks from a go.mod file."""
    deps = []
    try:
        with open(filepath) as fh:
            lines = fh.readlines()
    except OSError:
        return deps

    in_require = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require:
            if stripped == ")":
                in_require = False
                continue
            # Format: "github.com/gin-gonic/gin v1.9.1 // indirect"
            parts = stripped.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                module, version = parts[0], parts[1]
                deps.append(f"{module}@{version}")
        elif stripped.startswith("require ") and not stripped.startswith("require ("):
            # Single-line: require github.com/foo/bar v1.0.0
            parts = stripped[len("require "):].split()
            if len(parts) >= 2:
                deps.append(f"{parts[0]}@{parts[1]}")
    return deps


def extract_dependencies(path: str, structure: dict) -> dict:
    """Extract dependencies from detected package files.

    Args:
        path: Repo root path
        structure: Output from detect_repo_structure()

    Returns:
        {
            "direct": ["fastapi==0.110.0", "uvicorn==0.29.0"],
            "transitive": [],  # populated if lockfile exists
            "lockfile_exists": False,
            "package_manager": "pip",  # pip | npm | go | cargo | bundler | unknown
            "raw": {  # raw parsed data per file
                "requirements.txt": ["fastapi==0.110.0", "uvicorn==0.29.0", ...]
            }
        }
    """
    package_files: list[str] = structure.get("package_files", [])
    markers: dict = structure.get("markers", {})

    direct: list[str] = []
    raw: dict[str, list[str]] = {}
    package_manager = "unknown"
    lockfile_exists = False

    # --- Python ---
    if "requirements.txt" in package_files:
        req_path = os.path.join(path, "requirements.txt")
        parsed = _parse_requirements_txt(req_path)
        raw["requirements.txt"] = parsed
        direct.extend(parsed)
        package_manager = "pip"

    if "pyproject.toml" in package_files:
        pyp_path = os.path.join(path, "pyproject.toml")
        parsed = _parse_pyproject_toml(pyp_path)
        if parsed:
            raw["pyproject.toml"] = parsed
            direct.extend(parsed)
            if package_manager == "unknown":
                package_manager = "pip"

    # Python lockfiles
    python_lockfiles = ("Pipfile.lock", "poetry.lock")
    for lf in python_lockfiles:
        if os.path.isfile(os.path.join(path, lf)):
            lockfile_exists = True
            break

    # --- Node ---
    if "package.json" in package_files:
        pkg_path = os.path.join(path, "package.json")
        parsed = _parse_package_json(pkg_path)
        raw["package.json"] = parsed
        direct.extend(parsed)
        if package_manager == "unknown":
            package_manager = "npm"

    node_lockfiles = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
    for lf in node_lockfiles:
        if markers.get(lf, False) or os.path.isfile(os.path.join(path, lf)):
            lockfile_exists = True
            break

    # --- Go ---
    if "go.mod" in package_files:
        go_path = os.path.join(path, "go.mod")
        parsed = _parse_go_mod(go_path)
        raw["go.mod"] = parsed
        direct.extend(parsed)
        if package_manager == "unknown":
            package_manager = "go"

    if os.path.isfile(os.path.join(path, "go.sum")):
        lockfile_exists = True

    return {
        "direct": direct,
        "transitive": [],
        "lockfile_exists": lockfile_exists,
        "package_manager": package_manager,
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# Reachability analysis
# ---------------------------------------------------------------------------

# PyPI package name → Python import name
# Only for packages where they differ from their PyPI name
PACKAGE_IMPORT_MAP = {
    "pillow": "PIL",
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "opencv-python": "cv2",
    "opencv-python-headless": "cv2",
    "scikit-learn": "sklearn",
    "scikit-image": "skimage",
    "python-dateutil": "dateutil",
    "python-dotenv": "dotenv",
    "python-jose": "jose",
    "python-multipart": "multipart",
    "attrs": "attr",
    "google-cloud-storage": "google.cloud.storage",
    "google-cloud-bigquery": "google.cloud.bigquery",
    "google-auth": "google.auth",
    "protobuf": "google.protobuf",
    "mysql-connector-python": "mysql.connector",
    "psycopg2-binary": "psycopg2",
    "psycopg2": "psycopg2",
    "pymongo": "pymongo",
    "redis": "redis",
    "celery": "celery",
    "boto3": "boto3",
    "botocore": "botocore",
    "cryptography": "cryptography",
    "paramiko": "paramiko",
    "requests": "requests",
    "urllib3": "urllib3",
    "aiohttp": "aiohttp",
    "httpx": "httpx",
    "flask": "flask",
    "django": "django",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "gunicorn": "gunicorn",
    "starlette": "starlette",
    "pydantic": "pydantic",
    "sqlalchemy": "sqlalchemy",
    "alembic": "alembic",
    "pytest": "pytest",
    "numpy": "numpy",
    "pandas": "pandas",
    "scipy": "scipy",
    "matplotlib": "matplotlib",
    "tensorflow": "tensorflow",
    "torch": "torch",
    "transformers": "transformers",
    "jinja2": "jinja2",
    "markupsafe": "markupsafe",
    "werkzeug": "werkzeug",
    "click": "click",
}

# Directories to skip when searching Python source files
_SKIP_DIRS = frozenset(
    {"__pycache__", ".git", "node_modules", ".venv", "venv", ".tox", ".eggs"}
)


def _find_import(path: str, import_name: str) -> Optional[tuple]:
    """Search for import of import_name in all .py files under path.

    Handles direct imports, from-imports, and submodule from-imports.
    Skips common non-source directories.

    Returns (filepath_relative_to_path, line_number) of first match, or None.
    """
    # Build regex: matches `import <name>` or `from <name>` (space or dot after name)
    pattern = re.compile(
        r"^\s*(import\s+" + re.escape(import_name) + r"|from\s+" + re.escape(import_name) + r"[\s.])"
    )

    for dirpath, dirnames, filenames in os.walk(path):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.endswith(".egg-info")]

        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        if pattern.match(line):
                            rel = os.path.relpath(filepath, path)
                            return rel, lineno
            except OSError:
                continue
    return None


def check_reachability(
    path: str,
    findings: list,
    structure: dict,
) -> list:
    """Check if each finding's package is actually imported in the codebase.

    Mutates findings in-place: sets reachable, reachability_confidence,
    reachability_evidence on each Finding.

    Only analyzes language_dep findings (Python only for v1). OS packages,
    IaC findings, secrets, and code_pattern findings are left unchanged.

    Args:
        path: Repo root path to search for .py files.
        findings: List of Finding objects.
        structure: Output from detect_repo_structure() (unused in v1, reserved).

    Returns:
        The same (mutated) findings list.
    """
    # Guard: only analyze if Python is detected in the repo
    languages = structure.get("languages", [])
    is_python_repo = "python" in languages

    for finding in findings:
        if finding.finding_type != "language_dep":
            # Leave as-is (scanner adapter should have set not_applicable already)
            continue

        # If not a Python repo, we can't determine reachability for Python deps
        if not is_python_repo:
            finding.reachable = "unknown"
            finding.reachability_confidence = "none"
            finding.reachability_evidence = "reachability analysis not available for this ecosystem"
            continue

        # Normalise the package name: lowercase, strip version specifiers and extras
        raw_pkg = (finding.package or "").lower().strip()
        # Strip extras like [security] before other processing
        raw_pkg = re.sub(r"\[.*?\]", "", raw_pkg)
        # Strip version specifiers like ==, >=, ~=, !=, <=, >  <
        pkg_name = re.split(r"[><=!~;@\s]", raw_pkg)[0].strip()

        if not pkg_name:
            finding.reachable = "unknown"
            finding.reachability_confidence = "none"
            finding.reachability_evidence = "package name could not be determined"
            continue

        # Determine import name and confidence
        if pkg_name in PACKAGE_IMPORT_MAP:
            import_name = PACKAGE_IMPORT_MAP[pkg_name]
            confidence = "high"
        else:
            # Heuristic: replace hyphens with underscores (PEP 8 convention)
            import_name = pkg_name.replace("-", "_")
            confidence = "medium"

        # Search source files
        match = _find_import(path, import_name)

        if match is not None:
            rel_path, lineno = match
            finding.reachable = "true"
            finding.reachability_confidence = confidence
            finding.reachability_evidence = f"import found in {rel_path}:{lineno}"
        else:
            finding.reachable = "false"
            finding.reachability_confidence = confidence
            finding.reachability_evidence = "not imported in any .py file"

    return findings


# ---------------------------------------------------------------------------
# Context bundle builder
# ---------------------------------------------------------------------------

MAX_FINDINGS = 200  # Cap to prevent LLM context overflow


def _findings_from_summary(summary: dict) -> list:
    """Convert summary.json findings dict to a list of Finding objects.

    Args:
        summary: Parsed summary.json dict.

    Returns:
        List of Finding objects with source_scanner set from the scanner key.
    """
    findings = []
    for scanner, finding_dicts in summary.get("findings", {}).items():
        for fd in finding_dicts:
            finding = Finding(
                id=fd.get("id", "UNKNOWN"),
                source_scanner=scanner,
                finding_type="language_dep",  # default for v1; summary doesn't carry this
                severity=fd.get("severity", "info"),
                title=fd.get("title", ""),
                package=fd.get("package"),
                installed_version=fd.get("installed_version"),
                fixed_version=fd.get("fixed_version") or fd.get("fix"),
                location=fd.get("location", ""),
                cvss_score=fd.get("cvss_score"),
            )
            findings.append(finding)
    return findings


def _apply_token_budget(findings: list, max_findings: int = MAX_FINDINGS) -> tuple:
    """Trim findings to fit within token budget.

    Strategy:
    - Collapse duplicate CVEs (same id across multiple locations → keep one
      with highest priority_score, noting the count).
    - Sort by severity (critical first) then by priority_score descending.
    - Keep top max_findings.

    Returns:
        (trimmed_findings, budget_info_dict)
    """
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    # --- Deduplicate by id ---
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.id not in seen:
            seen[f.id] = f
        else:
            # Keep the one with higher priority_score
            if f.priority_score > seen[f.id].priority_score:
                seen[f.id] = f

    deduplicated = list(seen.values())
    total_findings = len(findings)
    after_dedup = len(deduplicated)

    # --- Sort: severity first, then priority_score descending ---
    deduplicated.sort(
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), -f.priority_score)
    )

    # --- Apply cap ---
    trimmed = deduplicated[:max_findings]
    included = len(trimmed)
    truncated = included < after_dedup

    budget_info = {
        "total_findings": total_findings,
        "included_findings": included,
        "truncated": truncated,
        "max_findings": max_findings,
    }

    return trimmed, budget_info


def build_context(path: str, scan_summary_path: str) -> dict:
    """Build the full context bundle for LLM consumption.

    Orchestrates the entire context-building pipeline:
    1. Load scan summary from JSON
    2. Detect repo structure
    3. Extract dependencies
    4. Convert summary findings to Finding objects
    5. Run reachability analysis
    6. Run enrichment plugins (EPSS, KEV)
    7. Apply token budgeting
    8. Return the complete context bundle

    Args:
        path: Repo root path
        scan_summary_path: Path to the summary.json from a scan

    Returns:
        {
            "repo": {...},
            "dependencies": {...},
            "findings": [{...}, ...],
            "scan_meta": {...},
            "token_budget": {...},
        }
    """
    # Step 1: Load scan summary
    with open(scan_summary_path) as f:
        summary = json.load(f)

    # Step 2: Detect repo structure
    structure = detect_repo_structure(path)

    # Step 3: Extract dependencies
    dependencies = extract_dependencies(path, structure)

    # Step 4: Convert summary findings to Finding objects
    findings = _findings_from_summary(summary)

    # Step 5: Reachability analysis
    check_reachability(path, findings, structure)

    # Step 6: Enrichment (best-effort — network failures must not break pipeline)
    try:
        from agent.plugins.enrichment.epss import EPSSEnrichmentPlugin
        EPSSEnrichmentPlugin().enrich(findings, {})
    except Exception:
        pass

    try:
        from agent.plugins.enrichment.kev import KEVEnrichmentPlugin
        KEVEnrichmentPlugin().enrich(findings, {})
    except Exception:
        pass

    # Step 7: Token budgeting
    trimmed_findings, budget_info = _apply_token_budget(findings)

    # Step 8: Assemble and return
    scan = summary.get("scan", {})
    severity_counts = summary.get("severity_counts", {})

    repo = {
        "languages": structure["languages"],
        "frameworks": structure["frameworks"],
        "runtime": structure["runtime"],
        "has_ci": structure["has_ci"],
        "has_iac": structure["has_iac"],
    }

    deps = {
        "direct": dependencies["direct"],
        "transitive": dependencies["transitive"],
        "lockfile_exists": dependencies["lockfile_exists"],
        "package_manager": dependencies["package_manager"],
    }

    scan_meta = {
        "date": scan.get("date", ""),
        "profile": scan.get("profile", "standard"),
        "scanners_run": scan.get("scanners_run", []),
        "scanners_skipped": scan.get("scanners_skipped", []),
        "total_findings": budget_info["total_findings"],
        "severity_counts": severity_counts,
    }

    return {
        "repo": repo,
        "dependencies": deps,
        "findings": [f.to_dict() for f in trimmed_findings],
        "scan_meta": scan_meta,
        "token_budget": budget_info,
    }
