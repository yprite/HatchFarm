# HatchFarm Agent (Baseline)

`apps/agent` now includes a minimal daemon that:
1. Registers a machine (`/api/v1/machines/register`)
2. Syncs effective worker policy (`/api/v1/workers/{id}/policy`)
3. Sends periodic signed heartbeats (`/api/v1/workers/{id}/heartbeat`)

## Environment Variables

- `AGENT_API_BASE_URL` (default: `http://localhost:8080`)
- `AGENT_OWNER_TOKEN` (required)
- `AGENT_OWNER_ID` (required)
- `AGENT_POLICY_ID` (required)
- `AGENT_WORKER_NAME` (default: `agent-node`)
- `AGENT_HEARTBEAT_SECONDS` (default: `15`)
- `AGENT_STATE_FILE` (default: `.agent_state.json`)
- `AGENT_STALE_AFTER_SECONDS` (default: `120`) heartbeat staleness threshold for hook emission
- `AGENT_HOOK_COMMAND` (optional) shell command executed for resilience hooks (`cert_rotated`, `policy_refreshed`, `heartbeat_stale`)
- `AGENT_POLICY_REFRESH_MIN_SECONDS` (default: `10`) minimum interval between policy refresh retries after 403
- `AGENT_CERT_ROTATE_MIN_SECONDS` (default: `30`) minimum interval between cert rotation retries after 401

## Run

```bash
cd apps/agent
go run .
```

## Notes

- Agent uses machine token + machine certificate id for policy/heartbeat requests.
- Heartbeat signature format matches API server expectation:
  `HMAC(machine_token, worker_id|timestamp|nonce|policy_id)`
- Reliability guards included:
  - HTTP client timeout (10s)
  - machine register retry with exponential backoff
  - heartbeat retry backoff with capped consecutive failure exit
  - 401 certificate-rotation retry path with minimum retry interval guard (prevents rotate storms)
  - 403 policy refresh retry path with minimum retry interval guard (prevents fetch storms)
  - stale heartbeat detection hook (`heartbeat_stale`) for external alerting/integration
  - cert/policy rotation hooks (`cert_rotated`, `policy_refreshed`) for automation integrations
  - atomic local state persistence/reuse across restarts (`AGENT_STATE_FILE`) to avoid partial/corrupt writes
- This is an evolving Sprint 3 hardening runtime loop; attestation and update orchestration are planned next.
