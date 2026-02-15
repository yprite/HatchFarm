# HatchFarm Security Threat Model v1

> Security lane seeded from Claude (sonnet) findings + consolidated review.

## Trust Boundaries
1. Owner device (untrusted execution environment)
2. Agent runtime (`agentd`) boundary
3. Public internet (Stratum/API ingress)
4. Control plane services
5. Data stores (ledger, policy, payout)
6. Wallet/payment boundary (on-chain + key custody)

## Top Threats and Mitigations
1. **Auth bypass / weak machine identity**
   - Mitigation: mTLS + per-machine certs + short-lived tokens + attestation gate.
2. **Unrestricted CORS / API abuse**
   - Mitigation: strict origin allowlist, CSRF protections, API gateway rate limits.
3. **Secrets & credential leakage**
   - Mitigation: external secret manager, no default credentials, rotation + scanning.
4. **Payout fraud / account takeover**
   - Mitigation: step-up auth, destination cooldown, withdrawal limits, anomaly detection.
5. **Telemetry tampering**
   - Mitigation: signed heartbeat payloads, monotonic counters, server-side anomaly checks.
6. **Fake share submission**
   - Mitigation: share validator service, duplicate detection, worker quarantine rules.
7. **Policy bypass on worker**
   - Mitigation: local fail-closed policy guard + heartbeat compliance checks.
8. **Malicious update / supply-chain compromise**
   - Mitigation: signed binaries, SBOM, provenance (SLSA), canary rollout, rollback.
9. **Wallet private-key compromise**
   - Mitigation: HSM/multisig, hot-cold segregation, key ceremony + audit.
10. **DDoS on gateway/API**
    - Mitigation: WAF, per-IP/per-key quotas, regional shedding and circuit breakers.
11. **Insider abuse in admin functions**
    - Mitigation: two-person approvals for critical actions, immutable audit trail.
12. **Data exfiltration via jobs/agent plugins**
    - Mitigation: strict sandboxing, syscall/network policy, minimal mounts.

## Abuse Scenarios
- **Consent replay**: old consent reused after revoke.
  - Control: versioned signed consent with revocation timestamp and nonce.
- **Reward inflation**: agent submits manipulated metrics.
  - Control: reward from validated shares only; telemetry is advisory.
- **Silent mining after revoke**
  - Control: revoke event invalidates credentials + forced stop + heartbeat SLO checks.

## Owner Consent Enforcement Model
- Consent is explicit per worker and policy version.
- Default state is DENY until active consent exists.
- Every assignment must include `policy_version` and signature proof.
- Revoke path must satisfy p99 stop latency target.

## Incident Response (IR) Baseline
- Severity matrix (SEV1-4) and on-call rotation.
- Runbooks: payout anomaly, share fraud, credential leak, revoke-path failure.
- Immediate controls: worker quarantine, payout freeze, key rotation, gateway blocklists.
- Post-incident: timeline, root cause, compensating controls, prevention ticket.

## 8-Week Prioritized Security Backlog

### P0 (Week 1-2)
- [ ] Machine identity + mTLS bootstrapping
- [ ] Policy signature verification in agent and server
- [ ] Strict API authn/authz middleware
- [ ] Remove wildcard CORS and add rate limiting
- [ ] Immutable audit event schema + write path

### P1 (Week 3-5)
- [ ] Share validator anti-fraud rules + quarantine automation
- [ ] Payout protections (step-up auth, cooldown, velocity limits)
- [ ] Signed agent release pipeline (SBOM + provenance)
- [ ] Security telemetry dashboards + alert policies

### P2 (Week 6-8)
- [ ] HSM/multisig wallet architecture pilot
- [ ] Threat-driven chaos drills (revoke fail, gateway saturation)
- [ ] Security review checklist for every service boundary
- [ ] External mini-audit for payout/consent flows
