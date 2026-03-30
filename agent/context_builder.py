import glob
import json
import os
import re


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
