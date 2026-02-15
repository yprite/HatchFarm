package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	httpTimeout                  = 10 * time.Second
	registerMaxAttempts          = 5
	registerBackoffBase          = 2 * time.Second
	heartbeatFailBackoffCap      = 60 * time.Second
	heartbeatMaxConsecutiveFails = 15
)

type AgentConfig struct {
	APIBaseURL       string
	OwnerToken       string
	OwnerID          string
	WorkerName       string
	PolicyID         string
	HeartbeatSeconds int
}

type RegisterResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Machine struct {
			ID string `json:"id"`
		} `json:"machine"`
		MachineToken string `json:"machine_token"`
	} `json:"data"`
	Error string `json:"error"`
}

type APIResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

type WorkerPolicyResponse struct {
	Success bool `json:"success"`
	Data    struct {
		WorkerID string `json:"worker_id"`
		Policy   struct {
			ID string `json:"id"`
		} `json:"policy"`
	} `json:"data"`
	Error string `json:"error"`
}

func main() {
	cfg := loadConfig()

	if cfg.OwnerToken == "" || cfg.OwnerID == "" || cfg.PolicyID == "" {
		log.Fatal("AGENT_OWNER_TOKEN, AGENT_OWNER_ID, AGENT_POLICY_ID are required")
	}

	client := &http.Client{Timeout: httpTimeout}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	machineID, machineToken, err := registerMachineWithRetry(ctx, client, cfg)
	if err != nil {
		log.Fatalf("register machine failed: %v", err)
	}
	log.Printf("registered machine_id=%s", machineID)

	resolvedPolicyID, err := fetchWorkerPolicy(ctx, client, cfg, machineID, machineToken)
	if err != nil {
		log.Fatalf("worker policy sync failed: %v", err)
	}
	if resolvedPolicyID != cfg.PolicyID {
		log.Fatalf("worker policy mismatch: expected=%s got=%s", cfg.PolicyID, resolvedPolicyID)
	}

	heartbeatInterval := time.Duration(cfg.HeartbeatSeconds) * time.Second
	if heartbeatInterval <= 0 {
		heartbeatInterval = 15 * time.Second
	}
	timer := time.NewTimer(heartbeatInterval)
	defer timer.Stop()

	consecutiveFails := 0

	for {
		select {
		case <-ctx.Done():
			log.Println("agent shutting down")
			return
		case <-timer.C:
			nextDelay := heartbeatInterval
			if err := sendHeartbeat(ctx, client, cfg, machineID, machineToken); err != nil {
				consecutiveFails++
				if consecutiveFails >= heartbeatMaxConsecutiveFails {
					log.Fatalf("heartbeat failed %d times consecutively, exiting: %v", consecutiveFails, err)
				}
				nextDelay = heartbeatFailureBackoff(consecutiveFails)
				log.Printf("heartbeat error (streak=%d): %v; next_retry=%s", consecutiveFails, err, nextDelay)
			} else {
				if consecutiveFails > 0 {
					log.Printf("heartbeat recovered after %d failures", consecutiveFails)
				}
				consecutiveFails = 0
				log.Printf("heartbeat ok machine_id=%s", machineID)
			}
			timer.Reset(nextDelay)
		}
	}
}

func loadConfig() AgentConfig {
	return AgentConfig{
		APIBaseURL:       envOrDefault("AGENT_API_BASE_URL", "http://localhost:8080"),
		OwnerToken:       os.Getenv("AGENT_OWNER_TOKEN"),
		OwnerID:          os.Getenv("AGENT_OWNER_ID"),
		WorkerName:       envOrDefault("AGENT_WORKER_NAME", "agent-node"),
		PolicyID:         os.Getenv("AGENT_POLICY_ID"),
		HeartbeatSeconds: envIntOrDefault("AGENT_HEARTBEAT_SECONDS", 15),
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func registerMachineWithRetry(ctx context.Context, client *http.Client, cfg AgentConfig) (machineID, machineToken string, err error) {
	var lastErr error
	for attempt := 1; attempt <= registerMaxAttempts; attempt++ {
		machineID, machineToken, err = registerMachine(ctx, client, cfg)
		if err == nil {
			return machineID, machineToken, nil
		}
		lastErr = err
		if attempt == registerMaxAttempts {
			break
		}
		backoff := registerBackoffBase * time.Duration(1<<(attempt-1))
		log.Printf("register attempt %d/%d failed: %v (retry in %s)", attempt, registerMaxAttempts, err, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return "", "", ctx.Err()
		}
	}
	return "", "", fmt.Errorf("register failed after retries: %w", lastErr)
}

func registerMachine(ctx context.Context, client *http.Client, cfg AgentConfig) (machineID, machineToken string, err error) {
	payload := map[string]string{"owner_id": cfg.OwnerID, "name": cfg.WorkerName}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIBaseURL+"/api/v1/machines/register", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.OwnerToken)
	req.Header.Set("X-Owner-ID", cfg.OwnerID)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var out RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	if resp.StatusCode >= 300 || !out.Success {
		return "", "", fmt.Errorf("register failed: status=%d error=%s", resp.StatusCode, out.Error)
	}
	if out.Data.Machine.ID == "" || out.Data.MachineToken == "" {
		return "", "", fmt.Errorf("register returned incomplete machine credentials")
	}
	return out.Data.Machine.ID, out.Data.MachineToken, nil
}

func fetchWorkerPolicy(ctx context.Context, client *http.Client, cfg AgentConfig, machineID, machineToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.APIBaseURL+"/api/v1/workers/"+machineID+"/policy", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Machine-Token", machineToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out WorkerPolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 || !out.Success {
		return "", fmt.Errorf("worker policy fetch failed: status=%d error=%s", resp.StatusCode, out.Error)
	}
	if out.Data.Policy.ID == "" {
		return "", fmt.Errorf("worker policy fetch returned empty policy id")
	}
	return out.Data.Policy.ID, nil
}

func sendHeartbeat(ctx context.Context, client *http.Client, cfg AgentConfig, machineID, machineToken string) error {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := randomID(12)
	sig := signHeartbeat(machineToken, machineID, timestamp, nonce, cfg.PolicyID)

	payload := map[string]interface{}{
		"timestamp": timestamp,
		"nonce":     nonce,
		"policy_id": cfg.PolicyID,
		"metrics": map[string]interface{}{
			"cpu": 10,
		},
		"signature": sig,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIBaseURL+"/api/v1/workers/"+machineID+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Machine-Token", machineToken)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var out APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if resp.StatusCode >= 300 || !out.Success {
		return fmt.Errorf("heartbeat failed: status=%d error=%s", resp.StatusCode, out.Error)
	}
	return nil
}

func heartbeatFailureBackoff(streak int) time.Duration {
	if streak < 1 {
		return 0
	}
	base := time.Duration(streak*streak) * time.Second
	if base > heartbeatFailBackoffCap {
		return heartbeatFailBackoffCap
	}
	return base
}

func signHeartbeat(secret, workerID, timestamp, nonce, policyID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(workerID + "|" + timestamp + "|" + nonce + "|" + policyID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func randomID(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
