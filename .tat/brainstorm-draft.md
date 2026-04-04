# Brainstorm Draft — PatchPilot v2 Direction

**Date:** 2026-04-01
**Trigger:** RSA 2026 landscape analysis
**Decision:** ADR-009

## Future Epics (queue for Sprint 6+)

### Epic A: PR Security Bot (GitHub Action)
- [ ] GitHub Action that runs `patchpilot review` on PR diffs
- [ ] PR comment with risk score + findings + recommendations
- [ ] Status check (pass/fail based on risk threshold)
- [ ] PR label assignment (security-reviewed, needs-review, blocked)

### Epic B: Compliance Framework Mapping
- [ ] SOC2 control mapping (findings to trust criteria)
- [ ] ISO 27001 control mapping
- [ ] CRA control mapping (extend existing CRA formatter)
- [ ] Executive one-page security summary report

### Epic C: AI-Code Awareness
- [ ] AI-authored commit detection (Co-Authored-By headers, tool signatures)
- [ ] AI-code risk multiplier in PR review scoring
- [ ] Audit log: which files/functions were AI-generated
- [ ] Dashboard data: % of codebase AI-generated

### Epic D: Security Posture Dashboard (CLI-first)
- [ ] Historical trend tracking (findings over time)
- [ ] Team/service breakdown (who owns the most risk?)
- [ ] Security posture score (single number for the repo)
- [ ] Exportable report for auditors

## Risks
1. AI-code detection accuracy — start with metadata, be honest about limits
2. GitHub Action adoption — must be zero-config (<5 min setup)
3. Compliance mapping accuracy — start simple, iterate with auditor feedback
4. Monetization timing — free CLI established, paid tier needs clear value

---

## DynoTrust Commercial Layer (2026-04-04)

Full brainstorm, decisions, tech stack, UX spec, and tasks moved to:
**`.tat/dashboard-dynotrust.md`** — to be started as a separate repo.

Key decisions:
- Separate brands (PatchPilot = OSS, DynoTrust = commercial)
- Separate repos (Python vs TypeScript, different deploy targets)
- Tech: Hono + Cloudflare Workers + R2 + Supabase + Vanilla HTML + Bun
- Dashboard first, marketing site second
