# Plan

## Epic 1: Foundation (done)
- [x] Project scaffold, CLI skeleton, output conventions
- [x] README with architecture diagram
- [x] Sample FastAPI app for scanning demos
- [x] Prompts for all 5 workflows

## Epic 2: Core Scanning Pipeline (done)
- [x] Implement scan command with Trivy runner
- [x] v1 summary.json schema (severity counts, top issues, findings)
- [x] Implement report command with Claude integration
- [x] Tests for report generation

## Epic 3: Context Builder (the missing piece)
- [ ] 3.1 Implement context_builder.py — assemble repo tree, deps, Dockerfile, Terraform, CI config
- [ ] 3.2 Add file-type detection (Python, Terraform, Docker, GitHub Actions)
- [ ] 3.3 Add dependency extraction (requirements.txt, package.json, go.mod)
- [ ] 3.4 Test context builder on sample_app

## Epic 4: Wire Remaining Commands
- [ ] 4.1 Implement analyze command — repo structure + security posture via Claude
- [ ] 4.2 Implement plan command — secure implementation plan for a given task
- [ ] 4.3 Implement review command — security review of code changes (diff-based)
- [ ] 4.4 Tests for analyze, plan, review

## Epic 5: Additional Scanners
- [ ] 5.1 Add Checkov scanner (IaC/Terraform scanning)
- [ ] 5.2 Add Gitleaks scanner (secret detection)
- [ ] 5.3 Add Semgrep scanner (SAST)
- [ ] 5.4 Update scan profiles: quick (trivy), standard (+checkov), full (+semgrep +gitleaks)

## Epic 6: Demo Polish
- [ ] 6.1 End-to-end demo: scan → analyze → plan → review → report on sample_app
- [ ] 6.2 Add a vulnerable sample app (intentional issues for demo)
- [ ] 6.3 Update README with demo output / screenshots
- [ ] 6.4 Record demo (asciinema or GIF)

## Backlog
