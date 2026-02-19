package main

import (
	"os"
	"path/filepath"
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

func TestShouldAttempt(t *testing.T) {
	now := time.Now().UTC()
	if !shouldAttempt(time.Time{}, 10*time.Second, now) {
		t.Fatal("zero last attempt should allow")
	}
	if shouldAttempt(now.Add(-5*time.Second), 10*time.Second, now) {
		t.Fatal("attempt should be blocked by min interval")
	}
	if !shouldAttempt(now.Add(-11*time.Second), 10*time.Second, now) {
		t.Fatal("attempt should be allowed after min interval")
	}
}

func TestMaybeRunHook(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "hook.out")
	cfg := AgentConfig{HookCommand: "printf '%s:%s' \"$AGENT_HOOK_EVENT\" \"$AGENT_HOOK_MACHINE_ID\" > \"" + outFile + "\""}
	maybeRunHook(cfg, "cert_rotated", map[string]string{"machine_id": "wrk_123"})
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("expected hook output: %v", err)
	}
	if string(b) != "cert_rotated:wrk_123" {
		t.Fatalf("unexpected hook output: %s", string(b))
	}
}
