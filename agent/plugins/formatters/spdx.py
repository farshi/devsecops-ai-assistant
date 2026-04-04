"""SPDX 2.3 SBOM formatter — Software Package Data Exchange."""

import json
import uuid
from datetime import datetime, timezone

from agent import __version__
from agent.models import Finding
from agent.plugins.base import OutputFormatter


# Maps package manager to SPDX external ref type
_PURL_TYPE = {
    "pip":     "pypi",
    "npm":     "npm",
    "go":      "golang",
    "cargo":   "cargo",
    "unknown": "generic",
}


def _purl(name, version, pkg_manager):
    """Build a package URL for a component."""
    purl_type = _PURL_TYPE.get(pkg_manager, "generic")
    name_lower = name.lower()
    if version:
        return f"pkg:{purl_type}/{name_lower}@{version}"
    return f"pkg:{purl_type}/{name_lower}"


def _spdx_id(name, version):
    """Build a valid SPDX identifier for a package."""
    clean = name.replace("@", "").replace("/", "-").replace(".", "-")
    if version:
        ver_clean = version.replace(".", "-")
        return f"SPDXRef-Package-{clean}-{ver_clean}"
    return f"SPDXRef-Package-{clean}"


def _parse_dep_string(dep_str):
    """Parse a dependency string into (name, version)."""
    for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
        if sep in dep_str:
            parts = dep_str.split(sep, 1)
            return parts[0].strip(), parts[1].strip()
    at_pos = dep_str.rfind("@")
    if at_pos > 0:
        return dep_str[:at_pos].strip(), dep_str[at_pos + 1:].strip()
    return dep_str.strip(), ""


class SPDXFormatter(OutputFormatter):
    """Generates SPDX 2.3 JSON SBOMs from triage findings.

    Produces a standards-compliant SBOM in SPDX format, commonly required
    for CRA compliance and government procurement.
    """

    @property
    def name(self) -> str:
        return "spdx"

    def format(self, findings: list[Finding], context: dict) -> str:
        """Generate SPDX 2.3 JSON SBOM.

        Args:
            findings: Scored Finding objects.
            context: Context bundle from build_context().

        Returns:
            JSON string with SPDX 2.3 SBOM.
        """
        scan_meta = context.get("scan_meta", {})
        target_name = scan_meta.get("target", context.get("target", "unknown"))
        deps_ctx = context.get("dependencies", {})
        pkg_manager = deps_ctx.get("package_manager", "unknown")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        doc_namespace = f"https://patchpilot.dev/spdx/{target_name}/{uuid.uuid4()}"

        # ------------------------------------------------------------------
        # Build packages from deps + findings
        # ------------------------------------------------------------------
        packages = {}  # spdx_id -> package dict

        # Source 1: context dependencies
        for dep_list_key in ("direct", "transitive"):
            for dep_str in deps_ctx.get(dep_list_key, []):
                name, version = _parse_dep_string(dep_str)
                if not name:
                    continue
                sid = _spdx_id(name, version)
                if sid not in packages:
                    pkg = {
                        "SPDXID": sid,
                        "name": name,
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                    }
                    if version:
                        pkg["versionInfo"] = version
                    pkg["externalRefs"] = [{
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": _purl(name, version, pkg_manager),
                    }]
                    packages[sid] = pkg

        # Source 2: findings
        for f in findings:
            name = f.package or ""
            version = f.installed_version or ""
            if not name:
                continue
            sid = _spdx_id(name, version)
            if sid not in packages:
                pkg = {
                    "SPDXID": sid,
                    "name": name,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                }
                if version:
                    pkg["versionInfo"] = version
                pkg["externalRefs"] = [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": _purl(name, version, pkg_manager),
                }]
                packages[sid] = pkg

        # ------------------------------------------------------------------
        # Build relationships
        # ------------------------------------------------------------------
        relationships = [{
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-RootPackage",
        }]

        for sid in packages:
            relationships.append({
                "spdxElementId": "SPDXRef-RootPackage",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": sid,
            })

        # ------------------------------------------------------------------
        # Build vulnerability annotations (SPDX 2.3 uses annotations for vulns)
        # ------------------------------------------------------------------
        annotations = []
        for f in findings:
            if not f.id.startswith("CVE-") and not f.id.startswith("GHSA-"):
                continue
            comment_parts = [f"Vulnerability {f.id}: {f.title}"]
            if f.severity:
                comment_parts.append(f"Severity: {f.severity}")
            if f.cvss_score is not None:
                comment_parts.append(f"CVSS: {f.cvss_score}")
            if f.reachable != "unknown":
                comment_parts.append(f"Reachable: {f.reachable}")
            if f.fix_available and f.fixed_version:
                comment_parts.append(f"Fix: upgrade to >= {f.fixed_version}")

            pkg_name = f.package or ""
            pkg_ver = f.installed_version or ""
            target_sid = _spdx_id(pkg_name, pkg_ver) if pkg_name else "SPDXRef-RootPackage"

            annotations.append({
                "annotationDate": now,
                "annotationType": "REVIEW",
                "annotator": f"Tool: patchpilot-{__version__}",
                "comment": " | ".join(comment_parts),
                "subject": target_sid if target_sid in packages else "SPDXRef-RootPackage",
            })

        # ------------------------------------------------------------------
        # Assemble SPDX document
        # ------------------------------------------------------------------
        root_package = {
            "SPDXID": "SPDXRef-RootPackage",
            "name": target_name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": "APPLICATION",
        }

        all_packages = [root_package] + list(packages.values())

        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{target_name}-sbom",
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": now,
                "creators": [
                    f"Tool: patchpilot-{__version__}",
                    "Organization: PatchPilot",
                ],
                "licenseListVersion": "3.22",
            },
            "packages": all_packages,
            "relationships": relationships,
        }

        if annotations:
            sbom["annotations"] = annotations

        return json.dumps(sbom, indent=2)
