# Compliance Mappings

This directory contains the compliance control mappings PatchPilot uses to
attach NIST, CIS, PCI, and ISO context to vulnerability findings.

Mappings are deliberately **plain JSON files** — reviewable in PRs, diffable in
git, and usable outside PatchPilot by any tool that wants them.

## Files

- `schema.json` — JSON Schema for a mapping pattern
- `patterns/*.json` — individual mapping patterns, one per file
- `sources.md` — public sources used for each framework

## How a mapping works

Each JSON file in `patterns/` represents a **pattern** — a vulnerable package,
configuration, or weakness class — linked to the public compliance controls it
breaks. When PatchPilot enriches a finding, it checks every pattern for a match
and attaches the control list.

Minimal example:

```json
{
  "pattern_id": "PP-0001",
  "name": "Outdated cryptography library (pypi)",
  "match": {
    "package": "cryptography",
    "ecosystem": "pypi",
    "version_below": "41.0.0"
  },
  "controls": {
    "nist_800_53_rev5": ["SC-8", "SC-13"],
    "pci_dss_4_0": ["4.2.1"]
  },
  "rationale": "Old cryptography versions lack enforcement of modern ciphers (TLS 1.2+). NIST SC-8 and SC-13 require protected transmission and cryptographic protection; PCI DSS 4.2.1 requires strong cryptography over open public networks.",
  "remediation_priority": "high"
}
```

## Matching rules (v1)

A finding matches a pattern if **all** specified `match` fields are satisfied.

| Field            | Behaviour                                             |
|------------------|-------------------------------------------------------|
| `package`        | Case-insensitive exact match on package name          |
| `ecosystem`      | Must match exactly                                    |
| `version_below`  | Vulnerable version must be `<` this (semver compare)  |
| `cve_ids`        | Finding's CVE must be in the list                     |
| `cwe_ids`        | Finding's CWE must be in the list                     |

If a pattern has no `match` constraints at all, it is ignored (prevents
accidental catch-all mappings).

## Contributing a mapping

1. Pick the next free `pattern_id` (sequential `PP-####`).
2. Copy an existing file in `patterns/` and edit.
3. Use **only public standard sources** for control IDs:
   - NIST SP 800-53 Rev 5 — https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
   - CIS Controls v8 — https://www.cisecurity.org/controls
   - PCI DSS 4.0 — https://www.pcisecuritystandards.org/
   - ISO/IEC 27001:2022 Annex A — ISO.org (control IDs only, never copy text)
   - OWASP ASVS v4 — https://owasp.org/www-project-application-security-verification-standard/
4. Fill in a short `rationale` that says **what the control requires** and
   **why this pattern breaks it**. Do not copy control text verbatim from
   any commercial or copyrighted source.
5. Run the schema validator (`patchpilot mappings validate`) before opening a PR.

## Licence on mappings

Mappings in this directory are original work, referencing public standard
control identifiers only. The control **text and descriptions** belong to their
respective standards bodies and are not reproduced here. Control IDs
themselves (e.g. "SC-8", "6.3.3") are factual references and not copyrightable.

Contributors must not copy mapping content from any commercial or client-owned
mapping product.

See [LICENSE](../LICENSE) for the PatchPilot project licence (MIT).
