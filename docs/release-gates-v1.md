# HatchFarm Release Gates v1 (Safety / Control / Transparency)

A release can ship only if **all gates pass**.

## Gate A — Safety (Security)
### Mandatory Checks
- [ ] Authn/Authz enabled on all `/v1` non-public endpoints
- [ ] No wildcard CORS in production
- [ ] Secrets loaded from secret manager (no defaults/hardcoded creds)
- [ ] Critical dependency scan has no unaccepted blockers
- [ ] Signed build artifacts + provenance available

### Evidence
- CI security report
- Config snapshot
- Dependency/SBOM report

### Owners
- Security Lead (required)
- Red Team Reviewer (required)

---

## Gate B — Control (Consent & Policy)
### Mandatory Checks
- [ ] Default-deny behavior validated for new workers
- [ ] Consent bound to policy version and worker identity
- [ ] Revoke path tested end-to-end
- [ ] Revoke-to-stop latency p99 within target
- [ ] Policy signature verification enforced agent+server side

### Evidence
- Integration test logs
- Revoke latency dashboard snapshot
- Signed policy verification test output

### Owners
- Consent & Policy Lead (required)
- Agent Runtime Lead (required)

---

## Gate C — Transparency (Ledger & Payout)
### Mandatory Checks
- [ ] Share-to-reward mapping deterministic and documented
- [ ] Reconciliation job green for current release candidate
- [ ] Payout guardrails active (cooldown, velocity limits, step-up auth)
- [ ] Audit events emitted for reward and payout decisions
- [ ] User-facing payout explanation endpoint/report available

### Evidence
- Reconciliation report
- Payout simulation output
- Audit event sample queries

### Owners
- Ledger & Payout Lead (required)
- Security Lead or SRE Lead (required)

---

## Operational Gate — Reliability + Observability
### Mandatory Checks
- [ ] SLO dashboards healthy for pre-release window
- [ ] Alert routes tested (on-call paging)
- [ ] Rollback plan rehearsed for this release
- [ ] Error budget consumption within policy
- [ ] `/metrics` exposes fleet freshness and auth failure primitives:
  - [ ] `hatchfarm_workers_total`
  - [ ] `hatchfarm_workers_stale_total`
  - [ ] `hatchfarm_worker_auth_failures_total`
  - [ ] `hatchfarm_worker_auth_failures_recent`
- [ ] Alert primitives are wired and verified in pre-release soak:
  - [ ] `hatchfarm_alert_stale_workers` fires when stale workers > 0
  - [ ] `hatchfarm_alert_worker_auth_failures` fires when recent auth failures exceed threshold
- [ ] On-call runbook includes stale-worker and auth-failure triage links

### Owners
- Platform SRE Lead (required)
- API Runtime Lead (required)

---

## Blockers (Automatic No-Go)
- Any unresolved P0 issue
- Failed revoke-path test
- Reconciliation mismatch above threshold
- Missing signed artifact/provenance
- Red team veto not resolved
- Missing observability evidence for stale worker/auth failure alerts

---

## Go/No-Go Template
- Release ID:
- Scope summary:
- Known risks:
- Gate A result:
- Gate B result:
- Gate C result:
- Reliability gate result:
- Final decision (GO/NO-GO):
- Approvers:
- Timestamp:
