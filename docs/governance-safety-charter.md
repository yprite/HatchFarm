# HatchFarm Governance & Safety Charter v1

## Purpose
This charter defines how HatchFarm makes decisions for safety, control, and transparency before growth and performance.

## Core Principles
1. **Safety-first**: No feature can reduce baseline security.
2. **Owner sovereignty**: Explicit consent is required per worker/policy version.
3. **Revoke-first control**: Owner can stop participation immediately.
4. **Transparent accounting**: Every reward/payout decision must be explainable and auditable.
5. **Least privilege by default**: Services/agents only get minimum required access.

## Team Structure
- **Security Lead**: threat model, hardening, incident response owner.
- **Consent & Policy Lead**: consent lifecycle, policy engine, revoke SLO owner.
- **Ledger & Payout Lead**: reward logic, reconciliation, payout safety owner.
- **Agent Runtime Lead**: local enforcement, update safety, worker behavior owner.
- **Platform SRE Lead**: SLOs, reliability, observability, runbooks owner.
- **Red Team Reviewer**: independent adversarial validation with release veto rights.

## Decision Model
### 2-Key Rule (Required)
The following changes require approval from **at least two owners** among Security/Policy/Ledger leads:
- Authn/Authz and identity changes
- Consent/policy enforcement logic
- Reward, fee, payout rules
- Emergency/admin controls

### Release Veto
Security Lead or Red Team Reviewer can block release if critical risks remain unresolved.

## Risk Tiers
- **P0 Critical**: exploitable now, funds/control/privacy impact. Fix before merge.
- **P1 High**: serious weakness with realistic exploit path. Time-bound mitigation required.
- **P2 Medium**: non-critical but material risk. Add to planned backlog.

## Change Management
- All security/control/ledger changes require ADR entry.
- Every PR touching critical paths must include:
  - Risk impact section
  - Rollback plan
  - Test evidence
- Canary + rollback strategy mandatory for runtime/control-plane changes.

## Required Artifacts (Always Current)
- `docs/security-threat-model-v1.md`
- `docs/PRD-v1.md`
- `docs/sprint-01-plan.md`
- `docs/release-gates-v1.md`
- `docs/incident-runbook-v1.md` (to be added)

## Weekly Operating Rhythm
- Daily 15-min risk sync
- 2x/week architecture+security review
- Weekly red-team review
- Weekly release-gate rehearsal

## Incident Governance
- SEV1/SEV2 incidents trigger immediate freeze on risky deploys.
- Mandatory postmortem with:
  - Root cause
  - Blast radius
  - Timeline
  - Preventive controls
- Action items tracked to closure before equivalent changes are re-enabled.

## Success Criteria
- Revoke-to-stop p99 target consistently met
- No unresolved P0 before release
- Payout reconciliation mismatch rate below defined threshold
- Audit evidence available for all consent/payout events
