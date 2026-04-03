"""CycloneDX 1.5 SBOM formatter."""

import json
import uuid
from datetime import datetime, timezone

from agent import __version__
from agent.models import Finding
from agent.plugins.base import OutputFormatter

# Maps package manager identifiers to purl type
_PURL_TYPE = {
    "pip":     "pypi",
    "npm":     "npm",
    "go":      "golang",
    "cargo":   "cargo",
    "unknown": "generic",
}

# Maps reachability values to CycloneDX analysis state
_REACHABILITY_STATE = {
    "true":    "exploitable",
    "false":   "false_positive",
    "unknown": "in_triage",
    # "not_applicable" → omit analysis block
}


def _purl(name, version, pkg_manager):
    """Build a package URL for a component."""
    purl_type = _PURL_TYPE.get(pkg_manager, "generic")
    name_lower = name.lower()
    if version:
        return f"pkg:{purl_type}/{name_lower}@{version}"
    return f"pkg:{purl_type}/{name_lower}"


def _parse_dep_string(dep_str):
    """Parse a dependency string like 'fastapi==0.110.0' or 'uvicorn' into (name, version).

    Handles npm scoped packages like '@scope/pkg@1.2.3' by splitting on the
    last '@' only when a version separator isn't found first.
    """
    for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
        if sep in dep_str:
            parts = dep_str.split(sep, 1)
            return parts[0].strip(), parts[1].strip()
    # Handle '@' version separator (e.g., 'pkg@1.2.3', '@scope/pkg@1.2.3')
    # Use rfind to avoid splitting on npm scope prefix
    at_pos = dep_str.rfind("@")
    if at_pos > 0:  # must not be first char (that's a scope prefix)
        return dep_str[:at_pos].strip(), dep_str[at_pos + 1:].strip()
    return dep_str.strip(), ""


def _bom_ref(name, version):
    """Build a stable bom-ref for a component."""
    if version:
        return f"{name}@{version}"
    return name


class CycloneDXFormatter(OutputFormatter):
    """Generates CycloneDX 1.5 JSON SBOMs from triage findings.

    Produces a standards-compliant Software Bill of Materials that can be
    submitted to procurement, compliance, or supply-chain tooling.
    """

    @property
    def name(self) -> str:
        return "cyclonedx"

    def format(self, findings: list[Finding], context: dict) -> str:
        """Generate CycloneDX 1.5 JSON SBOM.

        Args:
            findings: Scored Finding objects (from prioritizer or scoring strategy)
            context: Context bundle from build_context()

        Returns:
            JSON string with CycloneDX 1.5 SBOM
        """
        scan_meta = context.get("scan_meta", {})
        target_name = scan_meta.get("target", context.get("target", "unknown"))
        target_version = context.get("version", scan_meta.get("version", ""))
        deps_ctx = context.get("dependencies", {})
        pkg_manager = deps_ctx.get("package_manager", "unknown")

        # ------------------------------------------------------------------
        # Build component map: unique package+version → component dict
        # ------------------------------------------------------------------
        components = {}  # bom_ref -> component dict

        # Source 1: context dependencies (direct + transitive)
        for dep_list_key in ("direct", "transitive"):
            for dep_str in deps_ctx.get(dep_list_key, []):
                name, version = _parse_dep_string(dep_str)
                if not name:
                    continue
                ref = _bom_ref(name, version)
                if ref not in components:
                    comp = {
                        "type": "library",
                        "name": name,
                        "bom-ref": ref,
                    }
                    if version:
                        comp["version"] = version
                    comp["purl"] = _purl(name, version, pkg_manager)
                    components[ref] = comp

        # Source 2: findings (deduplicated on bom-ref)
        for f in findings:
            name = f.package or ""
            version = f.installed_version or ""
            if not name:
                continue
            ref = _bom_ref(name, version)
            if ref not in components:
                comp = {
                    "type": "library",
                    "name": name,
                    "bom-ref": ref,
                }
                if version:
                    comp["version"] = version
                comp["purl"] = _purl(name, version, pkg_manager)
                components[ref] = comp

        # ------------------------------------------------------------------
        # Build vulnerabilities list (CVE findings only)
        # ------------------------------------------------------------------
        vulnerabilities = []
        for f in findings:
            if not f.id.startswith("CVE-"):
                continue

            vuln = {
                "id": f.id,
                "source": {"name": f.source_scanner},
            }

            # Ratings
            if f.cvss_score is not None:
                vuln["ratings"] = [{
                    "score": f.cvss_score,
                    "severity": f.severity.lower(),
                    "method": "CVSSv3",
                }]
            elif f.severity:
                vuln["ratings"] = [{
                    "severity": f.severity.lower(),
                    "method": "CVSSv3",
                }]

            if f.title:
                vuln["description"] = f.title

            # Link to affected component
            pkg_name = f.package or ""
            pkg_ver = f.installed_version or ""
            if pkg_name:
                ref = _bom_ref(pkg_name, pkg_ver)
                vuln["affects"] = [{"ref": ref}]

            # Reachability → analysis state
            state = _REACHABILITY_STATE.get(f.reachable)
            if state is not None:
                vuln["analysis"] = {"state": state}

            vulnerabilities.append(vuln)

        # ------------------------------------------------------------------
        # Assemble SBOM
        # ------------------------------------------------------------------
        now = datetime.now(timezone.utc).isoformat()

        metadata_component = {
            "type": "application",
            "name": target_name,
        }
        if target_version:
            metadata_component["version"] = target_version

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "metadata": {
                "timestamp": now,
                "tools": [
                    {
                        "vendor": "PatchPilot",
                        "name": "patchpilot",
                        "version": __version__,
                    }
                ],
                "component": metadata_component,
            },
            "components": list(components.values()),
            "vulnerabilities": vulnerabilities,
        }

        return json.dumps(sbom, indent=2)
