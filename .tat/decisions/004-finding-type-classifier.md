# ADR-004: Finding Type Classifier — Scope Reachability Correctly

## Context
GPT review flagged that Trivy emits both OS/package-manager vulnerabilities (e.g., libssl in a Docker image) and application dependency vulnerabilities (e.g., fastapi in requirements.txt). The current reachability logic (checking Python imports) makes no sense for OS packages — you don't `import libssl` in Python.

Without classification, OS packages would be marked `reachable: false` and incorrectly deprioritized, even when they're critical (e.g., a kernel vulnerability in a container base image).

## Options Considered
1. **Ignore finding type** — apply reachability to everything. Produces nonsense results for non-code findings.
2. **Classify findings by type** — `os_package`, `language_dep`, `iac_misconfig`, `secret`, `code_pattern`. Each type gets appropriate analysis.
3. **Only analyze language deps** — skip everything else. Misses IaC and secret findings entirely.

## Decision
Option 2: Classify findings into types, apply appropriate analysis per type.

## Finding Types

| Type | Source | Reachability | Example |
|------|--------|-------------|---------|
| `os_package` | Trivy (container scan) | `not_applicable` | CVE in libssl, zlib |
| `language_dep` | Trivy (fs scan), Grype, Semgrep | `true/false/unknown` | CVE in fastapi, lodash |
| `iac_misconfig` | Checkov, Trivy (config) | `not_applicable` | S3 bucket public, no encryption |
| `secret` | Gitleaks, Semgrep | `not_applicable` | API key in source code |
| `code_pattern` | Semgrep (SAST rules) | `not_applicable` (already in code) | SQL injection pattern |

## Classification Logic
- Trivy fs scan on requirements.txt/package.json → `language_dep`
- Trivy container scan on OS packages → `os_package`
- Checkov findings → `iac_misconfig`
- Gitleaks findings → `secret`
- Semgrep SAST findings → `code_pattern`
- Scanner adapter is responsible for setting `finding_type` during normalization

## Rationale
- Each finding type needs different prioritization signals. OS packages care about base image update availability. Language deps care about reachability. IaC cares about exposure level.
- The prioritizer can weight factors differently per type (e.g., reachability weight = 0 for OS packages).
- Prevents the absurd outcome of a critical OS vuln being deprioritized because it's "not imported."

## Status
ACCEPTED
