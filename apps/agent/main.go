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

func main() {
	cfg := loadConfig()

	if cfg.OwnerToken == "" || cfg.OwnerID == "" || cfg.PolicyID == "" {
		log.Fatal("AGENT_OWNER_TOKEN, AGENT_OWNER_ID, AGENT_POLICY_ID are required")
	}

	machineID, machineToken, err := registerMachine(cfg)
	if err != nil {
		log.Fatalf("register machine failed: %v", err)
	}
	log.Printf("registered machine_id=%s", machineID)

	ticker := time.NewTicker(time.Duration(cfg.HeartbeatSeconds) * time.Second)
	defer ticker.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			if err := sendHeartbeat(cfg, machineID, machineToken); err != nil {
				log.Printf("heartbeat error: %v", err)
			} else {
				log.Printf("heartbeat ok machine_id=%s", machineID)
			}
		case <-quit:
			log.Println("agent shutting down")
			return
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

func registerMachine(cfg AgentConfig) (machineID, machineToken string, err error) {
	payload := map[string]string{"owner_id": cfg.OwnerID, "name": cfg.WorkerName}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, cfg.APIBaseURL+"/api/v1/machines/register", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.OwnerToken)
	req.Header.Set("X-Owner-ID", cfg.OwnerID)

	resp, err := http.DefaultClient.Do(req)
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
	return out.Data.Machine.ID, out.Data.MachineToken, nil
}

func sendHeartbeat(cfg AgentConfig, machineID, machineToken string) error {
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

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, cfg.APIBaseURL+"/api/v1/workers/"+machineID+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Machine-Token", machineToken)

	resp, err := http.DefaultClient.Do(req)
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
