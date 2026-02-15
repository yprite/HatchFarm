package main

import (
	"testing"
	"time"
)

func TestHeartbeatFailureBackoffCaps(t *testing.T) {
	if got := heartbeatFailureBackoff(1); got != 1*time.Second {
		t.Fatalf("expected 1s, got %s", got)
	}
	if got := heartbeatFailureBackoff(5); got != 25*time.Second {
		t.Fatalf("expected 25s, got %s", got)
	}
	if got := heartbeatFailureBackoff(20); got != heartbeatFailBackoffCap {
		t.Fatalf("expected capped %s, got %s", heartbeatFailBackoffCap, got)
	}
}

func TestEnvIntOrDefault(t *testing.T) {
	t.Setenv("AGENT_HEARTBEAT_SECONDS", "30")
	if got := envIntOrDefault("AGENT_HEARTBEAT_SECONDS", 15); got != 30 {
		t.Fatalf("expected 30, got %d", got)
	}

	t.Setenv("AGENT_HEARTBEAT_SECONDS", "bad")
	if got := envIntOrDefault("AGENT_HEARTBEAT_SECONDS", 15); got != 15 {
		t.Fatalf("expected fallback 15, got %d", got)
	}
}

func TestAgentStateRoundtrip(t *testing.T) {
	tmp := t.TempDir() + "/state.json"
	s := AgentState{
		MachineID:     "wrk_1",
		MachineToken:  "tok_1",
		MachineCertID: "mcert_1",
		PolicyID:      "pol_1",
		UpdatedAt:     time.Now().UTC(),
	}
	if err := saveState(tmp, s); err != nil {
		t.Fatalf("save state: %v", err)
	}
	loaded, ok := loadState(tmp)
	if !ok {
		t.Fatal("expected state load success")
	}
	if loaded.MachineID != s.MachineID || loaded.MachineCertID != s.MachineCertID {
		t.Fatal("state mismatch")
	}
}
