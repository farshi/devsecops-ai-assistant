"""
CheckovScannerAdapter — implements ScannerAdapter for Checkov JSON output.

Normalizes Checkov IaC findings (Terraform, CloudFormation, Kubernetes,
Dockerfile, etc.) into canonical Finding instances.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent.models import Finding
from agent.plugins.base import ScannerAdapter

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "info",
}


class CheckovScannerAdapter(ScannerAdapter):
    """Normalizes Checkov JSON output into canonical Finding instances."""

    @property
    def name(self) -> str:
        return "checkov"

    def parse(self, raw_path: Path) -> list[Finding]:
        """Read a Checkov JSON output file and return normalized Findings."""
        raw_path = Path(raw_path)
        with raw_path.open() as fh:
            raw = json.load(fh)
        # Normalize: single dict → list
        if isinstance(raw, dict):
            raw = [raw]
        return self.parse_list(raw)

    def parse_list(self, raw: list) -> list[Finding]:
        """Parse a pre-loaded Checkov JSON list into Findings.

        Checkov outputs a list of dicts, one per framework/check_type.
        Each dict has results.failed_checks, results.passed_checks, etc.
        We only process failed_checks.
        """
        findings: list[Finding] = []

        for check_type_result in raw or []:
            check_type = check_type_result.get("check_type", "unknown")
            results = check_type_result.get("results", {})

            for check in results.get("failed_checks", []):
                finding = self._parse_check(check, check_type)
                findings.append(finding)

        return findings

    @staticmethod
    def _parse_check(check: dict, check_type: str) -> Finding:
        """Convert a single Checkov failed check into a Finding."""
        check_id = check.get("check_id", "unknown")
        resource = check.get("resource", "")
        check_name = check.get("check_name", "")

        # Title: "CKV_AWS_18: Ensure S3 bucket has access logging (aws_s3_bucket.example)"
        title = f"{check_id}: {check_name}"
        if resource:
            title = f"{title} ({resource})"
        if len(title) > 120:
            title = title[:117] + "..."

        # Location: file_path + first line of file_line_range
        file_path = check.get("file_path", "unknown")
        # Strip leading slash that Checkov adds
        if file_path.startswith("/"):
            file_path = file_path[1:]
        line_range = check.get("file_line_range", [])
        if line_range:
            location = f"{file_path}:{line_range[0]}"
        else:
            location = file_path

        # Severity: Checkov may or may not include severity
        raw_severity = check.get("severity", "MEDIUM")
        severity = SEVERITY_MAP.get(
            (raw_severity or "MEDIUM").upper(), "medium"
        )

        # Guideline URL as fix evidence
        guideline = check.get("guideline", None)

        return Finding(
            id=check_id,
            source_scanner="checkov",
            finding_type="iac_misconfig",
            severity=severity,
            title=title,
            location=location,
            reachable="not_applicable",
            reachability_confidence="none",
            fix_available=True,
            fix_evidence=guideline,
        )
