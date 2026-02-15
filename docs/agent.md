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
  - on worker auth failure (401), cert rotation is attempted and heartbeat is retried once
  - local state persistence/reuse across restarts (`AGENT_STATE_FILE`)
- This is an evolving Sprint 2 runtime loop; attestation and update orchestration are planned next.
