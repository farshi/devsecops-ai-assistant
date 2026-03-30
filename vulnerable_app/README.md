# Vulnerable Demo App

**DO NOT deploy this application.** It exists solely to demonstrate PatchPilot's vulnerability triage capabilities.

## What This Is

A deliberately vulnerable Flask app with outdated dependencies containing known CVEs. Use it to test PatchPilot:

```bash
# Scan and triage
patchpilot triage --path ./vulnerable_app --target-name vuln-demo --top 5

# Expected output: ranked list of real vulnerabilities with
# reachability analysis, EPSS scores, and fix recommendations
```

## Why These Dependencies

| Package | Version | Why |
|---------|---------|-----|
| flask | 2.0.0 | Multiple known CVEs |
| jinja2 | 3.0.0 | Template injection CVEs |
| requests | 2.25.0 | Security fixes in later versions |
| urllib3 | 1.26.5 | Multiple CVEs |
| cryptography | 3.4.0 | Multiple CVEs |
| pyyaml | 5.3.1 | Code execution CVEs |
| pillow | 8.0.0 | Multiple image processing CVEs |
| setuptools | 58.0.0 | Known vulnerabilities |

These are real CVEs that Trivy will detect. PatchPilot then:
1. Checks which packages are actually imported (reachability)
2. Looks up EPSS exploitation probability
3. Checks CISA KEV catalog
4. Assesses fix availability and effort
5. Ranks by composite score
