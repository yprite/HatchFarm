# HatchFarm Sprint 01 Plan (Prod-First Foundation)

## Goal (2 weeks)
Ship a production-grade foundation for consent-safe worker orchestration.

## Scope
1. Identity bootstrap
   - machine registration endpoint
   - machine certificate issuance (short-lived)
2. Consent/policy baseline
   - create policy
   - activate policy
   - revoke consent
3. Agent heartbeat path
   - signed heartbeat payload
   - server-side policy compliance check
4. Audit baseline
   - append-only audit event writes for consent/policy/revoke/assignment
5. Ops baseline
   - structured logs, request IDs, basic metrics endpoint

## Deliverables
- `apps/api`:
  - `/v1/machines/register`
  - `/v1/policies`, `/v1/policies/{id}/activate`
  - `/v1/consents`, `/v1/consents/{id}/revoke`
  - `/v1/workers/{id}/heartbeat`
- `apps/agent`:
  - minimal daemon loop: register -> fetch policy -> heartbeat
- `docs/`:
  - API contract updates
  - runbook: revoke/stop flow

## Definition of Done
- Unit tests for all new handlers and policy checks.
- API auth middleware enabled for v1 routes.
- Revoke event blocks worker on next heartbeat (<= 30s test target).
- Audit events recorded for all consent/policy transitions.
- CI green on main.

## Risks
- Overbuilding auth and blocking feature velocity.
- Ambiguous policy schema early.

## Risk Controls
- Keep policy schema minimal but versioned.
- Timebox cryptographic hardening choices; document ADRs.

## Team Lane Split
- Codex lane: API contracts, handlers, tests.
- Claude lane: security review and threat-model delta on each PR.
- Integrator (당근): merge gate, scope control, sprint status.
