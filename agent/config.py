"""PatchPilot configuration — loads .patchpilot/config.yaml."""

import os
from typing import Optional, Tuple

DEFAULT_CONFIG = {
    "severity_threshold": None,     # None = show all, or "high" = only high+critical
    "ignore_cves": [],              # List of CVE IDs to suppress
    "ignore_packages": [],          # List of package names to suppress
    "llm_provider": "openai",       # "openai", "claude", or "gpt"
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

ENV_FILE_NAMES = (".env", ".env.local", ".env.dev")


def load_config(path: str = ".") -> dict:
    """Load config from .patchpilot/config.yaml, merged with defaults.

    Args:
        path: Project root path. Looks for .patchpilot/config.yaml relative to this.

    Returns:
        Merged config dict (user values override defaults).
    """
    load_env_files(path)
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


def load_env_files(path: str = ".") -> list[str]:
    """Load simple KEY=VALUE entries from project env files.

    Existing process environment variables win. Among files, later files in
    ENV_FILE_NAMES override earlier files, so .env.dev wins over .env.
    """
    initially_set = set(os.environ)
    loaded_keys = set()
    loaded_files = []

    for name in ENV_FILE_NAMES:
        env_path = os.path.join(path, name)
        if not os.path.isfile(env_path):
            continue
        try:
            with open(env_path) as f:
                lines = f.readlines()
        except OSError:
            continue

        loaded_files.append(env_path)
        for line in lines:
            parsed = _parse_env_line(line)
            if not parsed:
                continue
            key, value = parsed
            if key in initially_set and key not in loaded_keys:
                continue
            os.environ[key] = value
            loaded_keys.add(key)

    return loaded_files


def _parse_env_line(line: str) -> Optional[Tuple[str, str]]:
    """Parse one dotenv-style KEY=VALUE line."""
    text = line.strip()
    if not text or text.startswith("#") or "=" not in text:
        return None
    if text.startswith("export "):
        text = text[len("export "):].strip()
    key, value = text.split("=", 1)
    key = key.strip()
    if not key:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return key, value


def normalize_llm_provider(provider: Optional[str]) -> str:
    """Return a supported LLM provider name."""
    value = (provider or DEFAULT_CONFIG["llm_provider"]).strip().lower()
    if value == "gpt":
        return "openai"
    if value in ("claude", "openai"):
        return value
    return DEFAULT_CONFIG["llm_provider"]


def resolve_llm_provider(config: Optional[dict] = None) -> str:
    """Resolve provider from env first, then config, then default."""
    env_provider = os.environ.get("PATCHPILOT_LLM_PROVIDER")
    if env_provider:
        return normalize_llm_provider(env_provider)
    return normalize_llm_provider((config or {}).get("llm_provider"))


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
