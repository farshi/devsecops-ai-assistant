"""PatchPilot configuration — loads .patchpilot/config.yaml."""

import os

DEFAULT_CONFIG = {
    "severity_threshold": None,     # None = show all, or "high" = only high+critical
    "ignore_cves": [],              # List of CVE IDs to suppress
    "ignore_packages": [],          # List of package names to suppress
    "llm_provider": "claude",       # "claude" or "gpt" (future)
    "top_n": 5,                     # Number of findings to surface
    "reachability": {
        "enabled": True,
        "python_only": True,        # v1: only Python reachability
    },
    "enrichment": {
        "epss": True,
        "kev": True,
        "fix_availability": True,
    },
}


def load_config(path: str = ".") -> dict:
    """Load config from .patchpilot/config.yaml, merged with defaults.

    Args:
        path: Project root path. Looks for .patchpilot/config.yaml relative to this.

    Returns:
        Merged config dict (user values override defaults).
    """
    config = dict(DEFAULT_CONFIG)  # shallow copy of defaults

    config_path = os.path.join(path, ".patchpilot", "config.yaml")
    if not os.path.isfile(config_path):
        return config

    try:
        with open(config_path) as f:
            content = f.read()
            try:
                import yaml
                try:
                    user_config = yaml.safe_load(content) or {}
                except yaml.YAMLError:
                    return config
            except ImportError:
                # No yaml module — try to parse as simple key: value
                user_config = _parse_simple_yaml(content)
    except OSError:
        return config

    if not isinstance(user_config, dict):
        return config

    # Merge: user values override defaults (shallow for top-level, deep for nested dicts)
    for key, value in user_config.items():
        if key in config and isinstance(config[key], dict) and isinstance(value, dict):
            config[key] = {**config[key], **value}
        else:
            config[key] = value

    return config


def _parse_simple_yaml(text: str) -> dict:
    """Minimal YAML-like parser for key: value pairs when PyYAML isn't available."""
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            # Handle basic types
            if value.lower() in ("true", "yes"):
                result[key] = True
            elif value.lower() in ("false", "no"):
                result[key] = False
            elif value.isdigit():
                result[key] = int(value)
            elif value.startswith("[") and value.endswith("]"):
                # Simple list: [CVE-2023-xxx, CVE-2024-yyy]
                items = [item.strip().strip('"\'') for item in value[1:-1].split(",") if item.strip()]
                result[key] = items
            else:
                result[key] = value
    return result


def apply_config_filters(findings: list, config: dict) -> list:
    """Filter findings based on config rules.

    Applies:
    - severity_threshold: remove findings below threshold
    - ignore_cves: remove specific CVE IDs
    - ignore_packages: remove specific packages

    Args:
        findings: List of Finding objects
        config: Loaded config dict

    Returns:
        Filtered list of Finding objects
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    threshold = config.get("severity_threshold")
    ignore_cves = set(config.get("ignore_cves", []))
    ignore_packages = set(p.lower() for p in config.get("ignore_packages", []))

    filtered = []
    for finding in findings:
        # Skip ignored CVEs
        if finding.id in ignore_cves:
            continue

        # Skip ignored packages
        if finding.package and finding.package.lower() in ignore_packages:
            continue

        # Skip below severity threshold
        if threshold and threshold in severity_order:
            threshold_level = severity_order[threshold]
            finding_level = severity_order.get(finding.severity, 4)
            if finding_level > threshold_level:
                continue

        filtered.append(finding)

    return filtered
