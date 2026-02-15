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

## Operational Gate — Reliability
### Mandatory Checks
- [ ] SLO dashboards healthy for pre-release window
- [ ] Alert routes tested (on-call paging)
- [ ] Rollback plan rehearsed for this release
- [ ] Error budget consumption within policy

### Owners
- Platform SRE Lead (required)

---

## Blockers (Automatic No-Go)
- Any unresolved P0 issue
- Failed revoke-path test
- Reconciliation mismatch above threshold
- Missing signed artifact/provenance
- Red team veto not resolved

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
