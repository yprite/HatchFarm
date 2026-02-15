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
