# PatchPilot Concepts & Glossary

## What PatchPilot Does

PatchPilot is the **triage brain** between your security scanner and your team. It takes raw scanner output (200+ CVEs) and turns it into a **prioritized, context-aware action plan** — "fix these 3 things this week."

```
Scanner output (Trivy JSON)
    → PatchPilot reads your codebase context
    → Prioritizes: what's reachable, fixable, and urgent
    → Outputs: ranked action plan
    → Developer acts on 3 things instead of 200
```

## What PatchPilot Isn't

- **Not a scanner.** It consumes scanner output (Trivy, Grype, etc.). It doesn't replace them.
- **Not a dashboard.** CLI + file output + CI integration. Lives where developers work.
- **Not an auto-fix tool.** Knowing WHAT to fix is the value. Generating patches is commodity.
- **Not a platform.** Thin triage layer, not Snyk/Endor Labs.

---

## Core Concepts

### Finding

A single security issue detected by a scanner. PatchPilot normalizes all scanner output into a canonical `Finding` schema so every module speaks the same language.

Key fields:
- **id** — CVE ID or advisory identifier (e.g., `CVE-2024-12345`)
- **severity** — critical, high, medium, low, info
- **finding_type** — what kind of issue (see Finding Types below)
- **package** — affected package name
- **priority_score** — 0-100, computed by the scoring model
- **priority_tier** — critical, high, medium, low, noise

### Finding Types

Not all findings are the same. PatchPilot classifies each finding by type, because different types need different analysis.

| Type | Source | What It Is | Reachability? |
|------|--------|-----------|---------------|
| `language_dep` | Trivy fs, Grype | CVE in a Python/Node/Go dependency | Yes — is it imported? |
| `os_package` | Trivy image | CVE in an OS package (libssl, zlib) | No — always `not_applicable` |
| `iac_misconfig` | Checkov | Infrastructure misconfiguration | No |
| `secret` | Gitleaks | Hardcoded secret in source | No |
| `code_pattern` | Semgrep | Dangerous code pattern (SQLi, XSS) | No — it's in the code |

### Priority Score

A number from 0 to 100 that ranks how urgently a finding should be fixed. Computed by a **deterministic, weighted formula** — not AI guesswork.

**Signals used:**

| Signal | What It Measures |
|--------|-----------------|
| Severity / CVSS | How bad is it if exploited? |
| Reachability | Is the vulnerable code actually used? |
| EPSS | How likely is exploitation in 30 days? |
| KEV | Is it already being exploited in the wild? |
| Fix available | Can you actually fix it right now? |
| Direct dependency | Is it your dep or a transitive one? |

Weights vary by finding type. For `language_dep`, reachability gets the highest weight (25%) because it's the strongest signal for "does this matter to YOUR code?"

### Priority Tiers

| Tier | Score | Meaning |
|------|-------|---------|
| **Critical** | 80-100 | Fix immediately. Reachable, exploitable, fixable. |
| **High** | 60-79 | Fix this week. Significant risk. |
| **Medium** | 40-59 | Plan to fix. Real but not urgent. |
| **Low** | 20-39 | Track it. Low risk or low confidence. |
| **Noise** | 0-19 | Ignore safely. Unreachable, unexploitable, or informational. |

---

## Signals Explained

### CVSS (Common Vulnerability Scoring System)

Industry-standard severity score (0.0 to 10.0) assigned to each CVE. Measures how bad a vulnerability is **in theory** — not in your specific context.

- 9.0-10.0: Critical
- 7.0-8.9: High
- 4.0-6.9: Medium
- 0.1-3.9: Low

**PatchPilot's take:** CVSS is a starting point, not the answer. A CVSS 9.8 in an unused transitive dependency matters less than a CVSS 7.0 in your auth module.

### EPSS (Exploit Prediction Scoring System)

Probability (0.0 to 1.0) that a CVE will be exploited in the wild in the **next 30 days**. Maintained by FIRST.org. Updated daily.

- 0.9+ = very likely to be exploited
- 0.5 = coin flip
- 0.01 = very unlikely

**Why it matters:** EPSS answers "is anyone actually going to exploit this?" — a question CVSS can't answer. A CVSS 9.8 with EPSS 0.001 is scary on paper but nobody's targeting it.

**Source:** [FIRST.org EPSS API](https://www.first.org/epss/)

### KEV (Known Exploited Vulnerabilities)

CISA's curated catalog of CVEs that are **actively being exploited right now**. Not theoretical — attackers are using these. US federal agencies must patch KEV entries within deadlines.

- If a finding is in KEV → it's being exploited → fix it now
- Binary signal: in KEV or not

**Why it matters:** KEV is the strongest "this is real" signal. A CVE in KEV with a reachable package = drop everything.

**Source:** [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

### Reachability

Whether a vulnerable dependency is actually **imported and used** in your codebase. This is PatchPilot's core differentiator.

**Three states:**
| State | Meaning |
|-------|---------|
| `true` | Import confirmed in source code |
| `false` | Package in deps but NOT imported anywhere |
| `unknown` | Can't determine (name mismatch, dynamic loading, unsupported language) |

**Confidence levels:**
| Level | Meaning |
|-------|---------|
| `high` | Known package→import mapping confirmed (e.g., PyYAML→yaml) |
| `medium` | Heuristic match (package name = import name) |
| `low` | No mapping, best guess |
| `none` | No analysis performed |

**Why honest confidence matters:** Competitors mark everything as "reachable" or guess. PatchPilot says "unknown" when it's unsure. A wrong "unreachable" label hides real vulnerabilities — that's worse than no analysis at all.

**Current scope:** Python only (v1). Node.js planned.

### Fix Availability

Whether a patched version exists for the vulnerable package.

- **fix_available: true** — a fixed version exists, you can upgrade
- **fix_available: false** — no fix yet, assess workarounds

**Effort estimation:**
| Bump Type | Effort | Risk |
|-----------|--------|------|
| Patch (1.0.0 → 1.0.1) | Trivial | Very low |
| Minor (1.0.0 → 1.1.0) | Moderate | Low |
| Major (1.0.0 → 2.0.0) | Complex | Breaking changes possible |

---

## Architecture Concepts

### Plugin System

PatchPilot is extensible through four plugin types:

| Plugin Type | What It Does | Example |
|------------|-------------|---------|
| **Scanner Adapter** | Normalizes scanner output → Finding objects | Trivy, Grype, SARIF |
| **Enrichment Plugin** | Adds context to findings | EPSS, KEV, fix availability |
| **Prioritization Strategy** | Scores and ranks findings | Default weighted scorer |
| **Output Formatter** | Formats results for output | Markdown, JSON, CRA |

### Context Bundle

The complete picture PatchPilot builds before scoring. Includes:
- **Repo structure** — languages, frameworks, Docker, CI, IaC
- **Dependencies** — direct vs transitive, lockfile status
- **Findings** — enriched with reachability, EPSS, KEV, fix info
- **Scan metadata** — date, scanners used, coverage

### Token Budgeting

Large repos can produce thousands of findings. PatchPilot caps the context sent to LLMs:
- Deduplicates same CVE across multiple locations
- Sorts by severity and score
- Caps at 200 findings
- Reports whether truncation occurred

---

## Compliance Concepts

### EU CRA (Cyber Resilience Act)

EU regulation requiring manufacturers of products with digital elements to:
- Report actively exploited vulnerabilities within **24 hours**
- Maintain **SBOMs** across product lifecycle
- Implement continuous vulnerability monitoring
- Penalties: up to **15M EUR or 2.5% of global revenue**

**Timeline:**
- Reporting obligations: **September 11, 2026**
- Full compliance: **December 11, 2027**

PatchPilot can generate CRA-ready vulnerability disclosure reports.

### VEX (Vulnerability Exploitability eXchange)

Standard for communicating whether a vulnerability is exploitable in a specific product. Four statuses:
- **NOT AFFECTED** — vulnerability exists but doesn't impact this product
- **AFFECTED** — vulnerability impacts this product
- **FIXED** — vulnerability was present but has been remediated
- **UNDER INVESTIGATION** — status not yet determined

PatchPilot's reachability analysis is essentially automated VEX generation.

### SBOM (Software Bill of Materials)

A complete inventory of all components in a software product. Required by EU CRA and increasingly by US federal procurement. PatchPilot's dependency extraction is a foundation for SBOM generation (planned feature).

---

## How PatchPilot Compares

| | PatchPilot | Snyk/Endor | Konvu | Grype |
|---|---|---|---|---|
| Scanner | No (consumes output) | Yes (built-in) | No (consumes) | Yes (scanner only) |
| Triage/Prioritization | Core value | Feature of platform | Core value | Basic |
| Reachability | Python (honest confidence) | Java/JS only | AI-verified | None |
| CLI-first | Yes | CLI secondary | SaaS only | Yes |
| Plugin architecture | Yes | No | No | No |
| Price | Free/open-source | $25-105/dev/mo | Enterprise custom | Free |
