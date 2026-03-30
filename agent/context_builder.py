import glob
import json
import os


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
