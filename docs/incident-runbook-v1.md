# HatchFarm Incident Runbook v1

## Purpose
Define a repeatable response process for security, control, payout, and reliability incidents in HatchFarm.

## Severity Levels
- **SEV1 (Critical):** active exploit, unauthorized mining, payout compromise, major outage.
- **SEV2 (High):** significant degradation, fraud signal with potential financial impact.
- **SEV3 (Medium):** contained issue with workaround.
- **SEV4 (Low):** minor issue, no immediate risk.

## Command Structure
- **Incident Commander (IC):** coordinates response and decisions.
- **Security Lead:** threat containment and forensics.
- **SRE Lead:** infrastructure/system stabilization.
- **Policy Lead:** consent/revoke-path verification.
- **Ledger Lead:** payout/reconciliation impact analysis.
- **Comms Owner:** internal/external updates.

## Immediate Response Checklist (First 15 Minutes)
- [ ] Declare severity (SEV1-4)
- [ ] Assign IC and responders
- [ ] Freeze risky deploys
- [ ] Start incident channel + timeline log
- [ ] Capture current blast radius (services/users/workers/funds)
- [ ] Apply containment controls (see scenario playbooks)

## Universal Containment Actions
- [ ] Disable suspicious worker cohorts (quarantine)
- [ ] Pause payouts if financial integrity is uncertain
- [ ] Rotate potentially exposed credentials
- [ ] Enable stricter policy mode (default-deny where needed)
- [ ] Block abusive IPs/keys at gateway

## Scenario Playbooks

### 1) Consent/Revoke Failure
**Signals:** worker continues mining after revoke; revoke latency SLO breach.

Actions:
- [ ] Trigger `emergency-stop` for affected workers/cohort
- [ ] Invalidate machine/session credentials
- [ ] Force policy resync and heartbeat verification
- [ ] Confirm stop state on telemetry + assignment status
- [ ] Open P0 if owner-control guarantee is broken

### 2) Payout Fraud / Ledger Mismatch
**Signals:** reconciliation mismatch, suspicious withdrawals, unauthorized payout destination changes.

Actions:
- [ ] Pause payout pipeline immediately
- [ ] Enable step-up auth for all payout actions
- [ ] Lock changed payout destinations pending review
- [ ] Run reconciliation job in forensic mode
- [ ] Preserve audit logs and generate evidence snapshot

### 3) Agent Compromise / Telemetry Tampering
**Signals:** anomalous heartbeat patterns, impossible hashrate metrics, signature failures.

Actions:
- [ ] Quarantine affected worker set
- [ ] Revoke agent certs/tokens and rotate trust roots if needed
- [ ] Compare telemetry vs validated shares
- [ ] Block release channel if compromise linked to update
- [ ] Begin forensic artifact collection (binary hash, host metadata)

### 4) Gateway/API DDoS or Reliability Incident
**Signals:** high error rate, request saturation, share ingestion lag.

Actions:
- [ ] Enable traffic shedding/rate-limit escalation
- [ ] Shift traffic to healthy region(s)
- [ ] Activate circuit breakers for non-critical paths
- [ ] Protect control-plane endpoints over non-essential traffic
- [ ] Monitor SLO burn and rollback recent config changes

## Evidence Collection Requirements
- Timeline with UTC timestamps
- Affected services and versions
- Query/log snapshots (immutable store)
- Security events and auth traces
- User/financial impact estimate
- Actions taken and by whom

## Communication Cadence
- SEV1: update every 15 min
- SEV2: update every 30 min
- SEV3: update every 60 min

Internal update template:
- Incident ID:
- Severity:
- Status:
- Impact:
- Actions in progress:
- Next update ETA:

## Recovery and Closure Criteria
- [ ] Containment complete
- [ ] Core functionality restored
- [ ] No active abuse indicators
- [ ] Financial integrity verified (if applicable)
- [ ] Customer/internal comms sent

## Postmortem (Within 48 Hours)
Required sections:
1. Executive summary
2. Root cause
3. Detection and response timeline
4. Blast radius and impact
5. What worked / what failed
6. Corrective actions (owner + due date)
7. Prevention controls added

## Preventive Follow-up
- Convert findings into backlog items (P0/P1/P2)
- Update threat model + release gates
- Add/adjust alerts and tests
- Rehearse playbook in game-day drills
