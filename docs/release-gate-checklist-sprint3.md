# Sprint 3 Release Gate Checklist (Observability Focus)

Use with `docs/release-gates-v1.md` during GO/NO-GO.

## Observability Evidence Pack

- [ ] Metrics scrape from `/metrics` captured and attached
- [ ] `hatchfarm_workers_stale_total` validated in a stale-worker simulation
- [ ] `hatchfarm_worker_auth_failures_total` increments on invalid worker auth simulation
- [ ] `hatchfarm_worker_auth_failures_recent` behaves as expected within configured window
- [ ] `hatchfarm_alert_stale_workers` toggles to `1` in stale simulation and returns to `0` after recovery
- [ ] `hatchfarm_alert_worker_auth_failures` toggles to `1` when threshold is reached

## Configuration Review

- [ ] `WORKER_STATUS_STALE_SECONDS` reviewed for release environment
- [ ] `WORKER_AUTH_FAIL_ALERT_WINDOW_SECONDS` reviewed for release environment
- [ ] `WORKER_AUTH_FAIL_ALERT_THRESHOLD` reviewed for release environment
- [ ] `METRICS_PUBLIC` reviewed and approved for environment

## Alert Routing

- [ ] Alertmanager (or equivalent) rule exists for stale workers
- [ ] Alertmanager (or equivalent) rule exists for auth failure surge
- [ ] Escalation targets verified (primary + secondary)
- [ ] Runbook links included in alert annotations

## Sign-off

- Release candidate:
- Owner:
- Date:
- Decision:
