# HatchFarm PRD v1 (Prod-First)

> Draft generated with Codex (gpt-5.3-codex), then reviewed/curated.

## Product Vision
HatchFarm is an AI-agent-orchestrated distributed Bitcoin mining pool where machine owners retain hard control over what runs, when it runs, and how revenue is handled.  
Primary outcome: increase pooled hash efficiency while enforcing explicit owner consent and policy constraints as first-class runtime controls, not UI-only settings.

## Users
- Machine Owner: contributes compute, sets consent/policy, receives payouts.
- Pool Operator: manages pool reliability, fee policy, compliance, incidents.
- Agent Developer: builds optimization/scheduling agents under policy sandbox.
- Auditor/Security Reviewer: verifies consent lineage, policy enforcement, and payout integrity.

## Core Flows
1. Owner onboarding and consent
- Owner registers machine and wallet.
- Owner signs policy profile (allowed workloads, hours, power cap, payout threshold, revocation rules).
- Control plane issues machine identity and policy version.

2. Miner enrollment
- Agent installs runtime on worker.
- Worker attests environment and fetches active policy.
- Stratum connection established only if policy + attestation pass.

3. Work orchestration
- Orchestrator assigns mining jobs by latency, hashrate profile, and owner constraints.
- Agent executes with continuous policy checks (power/time/network/command allowlist).
- Shares submitted to pool gateway.

4. Reward accounting and payout
- Shares validated and attributed per worker/owner.
- Reward engine applies fee and payout policy.
- Owner approves payout destination changes via explicit re-consent.

5. Consent/policy change and revocation
- Owner edits policy in dashboard/API.
- New policy version is signed, propagated, and enforced.
- Emergency revoke triggers immediate worker stop + key invalidation.

## Non-Goals
- Building custom ASIC firmware.
- Custodial exchange or speculative trading features.
- Anonymous, unverifiable worker participation.
- Multi-chain mining orchestration in v1.
- DAO governance in v1 pool operations.

## Functional Requirements
- Consent management
- Signed consent records with version history and immutable audit trail.
- Explicit opt-in per machine; default-deny until consent active.
- One-click revoke with max enforcement latency target.

- Policy engine
- Machine-level policy (time windows, max watts, geo/network constraints, payout rules).
- Job-class allow/deny lists and command-level restrictions.
- Policy-as-code evaluation at assignment time and runtime heartbeat time.

- Agent orchestration
- Worker discovery, health, and capability registration.
- Scheduling using policy fit + performance scoring.
- Safe rollout controls for agent updates (canary, rollback).

- Mining pool functions
- Stratum ingress/egress, share validation, stale share tracking.
- Block candidate handling and reward distribution ledger.
- Payout batching and threshold logic.

- Admin and operations
- Tenant/org support (operator vs owner roles).
- Incident controls: quarantine worker, force-stop cohort, rotate keys.
- Full audit export for consent, policy, payout decisions.

## Non-Functional Requirements
- Availability: control plane 99.9% monthly, share gateway 99.95%.
- Scalability: 100k concurrent workers target; horizontal shardable gateway.
- Latency: policy check p95 < 50ms; share submission p95 < 150ms region-local.
- Durability: consent/policy/audit data RPO 0, RTO < 1 hour.
- Security: zero-trust between services; mTLS and short-lived credentials.
- Compliance: tamper-evident logs, key lifecycle controls, least privilege IAM.

## System Architecture
- Edge/Worker Layer
- `agentd` runtime on owner machine.
- Local policy guard (hard stop if policy invalid/stale).
- Stratum client + telemetry emitter.

- Control Plane
- Identity service (owner, operator, machine identities).
- Consent & policy service (authoring, signing, versioning, distribution).
- Orchestrator service (assignment, balancing, rollout).
- Reward/payout service (accounting, settlement, payout jobs).
- Audit service (append-only event ledger).

- Data Plane
- Stratum gateway cluster (regionally distributed).
- Share validation workers.
- Block template/Bitcoin node integration.

- Platform Services
- API gateway, rate limiting, WAF.
- Message bus for state/events.
- OLTP DB + time-series metrics store + object archive for logs.

## Service Boundaries
- `identity-service`: authN/authZ, machine certificates, token minting.
- `consent-policy-service`: policy CRUD, signature verification, evaluation API.
- `orchestrator-service`: worker state, assignment decisions, rollout plans.
- `mining-gateway-service`: Stratum protocol handling and share intake.
- `share-validator-service`: validity checks, anti-fraud heuristics.
- `rewards-service`: share-to-reward conversion, fee calculation, balances.
- `payout-service`: payout requests, approvals, execution, reconciliation.
- `audit-service`: immutable events and evidence export.
- `observability-service`: metrics/traces/log pipeline + SLO alerting.

## Data Model
- `owners`: `id`, `kyc_status`, `wallet_primary`, `created_at`.
- `workers`: `id`, `owner_id`, `hardware_type`, `region`, `status`, `attestation_level`.
- `consents`: `id`, `owner_id`, `worker_id`, `policy_version`, `signed_blob_hash`, `effective_at`, `revoked_at`.
- `policies`: `id`, `owner_id`, `version`, `rules_json`, `signature`, `state`.
- `assignments`: `id`, `worker_id`, `job_id`, `policy_version`, `assigned_at`, `ended_at`, `result`.
- `shares`: `id`, `worker_id`, `job_id`, `difficulty`, `accepted`, `reason`, `timestamp`.
- `balances`: `owner_id`, `pending_sats`, `settled_sats`, `last_settlement_at`.
- `payouts`: `id`, `owner_id`, `amount_sats`, `address`, `status`, `approved_by`, `txid`.
- `audit_events`: `id`, `actor_type`, `actor_id`, `event_type`, `object_type`, `object_id`, `hash_chain_prev`, `created_at`.

## API v1
Base: `/v1`

- Auth & identity
  - `POST /auth/owner/login`
  - `POST /auth/agent/attest`
  - `POST /machines/register`

- Consent/policy
  - `POST /consents`
  - `POST /consents/{id}/revoke`
  - `GET /consents/{id}`
  - `POST /policies`
  - `GET /policies/{id}`
  - `POST /policies/{id}/activate`
  - `POST /policies/{id}/validate`

- Orchestration
  - `POST /workers/{id}/heartbeat`
  - `GET /workers/{id}/assignment`
  - `POST /assignments/{id}/complete`

- Mining/rewards
  - `POST /shares`
  - `GET /owners/{id}/rewards`
  - `GET /owners/{id}/balances`

- Payouts
  - `POST /payouts`
  - `POST /payouts/{id}/approve`
  - `GET /payouts/{id}`

- Audit/admin
  - `GET /audit/events`
  - `POST /admin/workers/{id}/quarantine`
  - `POST /admin/emergency-stop`

## Agent State Machine
States:
- `UNREGISTERED`, `REGISTERED`, `ATTESTED`, `POLICY_SYNCED`, `ELIGIBLE`, `ASSIGNED`, `MINING`, `PAUSED`, `REVOKED`, `QUARANTINED`, `TERMINATED`

Key transitions:
- `UNREGISTERED -> REGISTERED`: machine registration success.
- `REGISTERED -> ATTESTED`: attestation token issued.
- `ATTESTED -> POLICY_SYNCED`: latest active policy fetched + verified.
- `POLICY_SYNCED -> ELIGIBLE`: scheduler admission checks pass.
- `ELIGIBLE -> ASSIGNED -> MINING`: assignment received and started.
- `MINING -> PAUSED`: owner schedule/power rule violation or manual pause.
- `ANY -> REVOKED`: consent revoked; immediate stop and credential invalidation.
- `ANY -> QUARANTINED`: fraud/security signal.
- `REVOKED|QUARANTINED -> TERMINATED`: cleanup complete.

## Security Baseline
- mTLS service-to-service; workload identity.
- Hardware-backed keys where available; rotating short-lived tokens.
- Consent/policy objects signed; runtime verifies signature and freshness.
- Default-deny policy evaluation at assignment and heartbeat.
- Two-person rule for critical admin actions.
- Step-up auth for payout address updates and large withdrawals.
- Tamper-evident audit logs.
- Signed agent binaries + SBOM + provenance checks.

## Observability / SLO
SLOs:
- Share acceptance pipeline availability: 99.95%.
- Policy decision API availability: 99.9%.
- Consent revoke enforcement latency: p99 < 30s.
- Assignment decision latency: p95 < 500ms.
- Payout execution success (non-user-error): 99.5% daily.

Core metrics:
- Accepted/rejected/stale share rates.
- Policy-denied assignment count by rule.
- Revoke-to-stop latency distribution.
- Worker churn, heartbeat miss rate.
- Reward reconciliation mismatch rate.
- Payout failure reasons and retry age.

## Rollout Plan (Alpha/Beta/GA)
Alpha (50-200 workers): strict consent + revoke path validation.
Beta (1k-10k workers): multi-region, canary updates, capped payouts.
GA (100k target): redundancy, org controls, full incident readiness.

## Risks & Mitigations
- Policy bypass on compromised worker → fail-closed guard, attestation gating.
- Fraudulent share submission → validator heuristics + quarantine automation.
- Consent disputes → signed consent artifacts + immutable timeline.
- Account takeover/payout abuse → step-up auth + velocity limits.
- Control plane outage → cached signed policy + bounded offline mode.
- Bad agent rollout → staged rollout + auto rollback.
