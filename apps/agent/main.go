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
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	httpTimeout                  = 10 * time.Second
	registerMaxAttempts          = 5
	registerBackoffBase          = 2 * time.Second
	heartbeatFailBackoffCap      = 60 * time.Second
	heartbeatMaxConsecutiveFails = 15
	certRotateMinInterval        = 30 * time.Second
	policyRefreshMinInterval     = 10 * time.Second
)

type AgentConfig struct {
	APIBaseURL              string
	OwnerToken              string
	OwnerID                 string
	WorkerName              string
	PolicyID                string
	HeartbeatSeconds        int
	StateFile               string
	StaleAfterSeconds       int
	HookCommand             string
	PolicyRefreshMinSeconds int
	CertRotateMinSeconds    int
}

type AgentState struct {
	MachineID         string    `json:"machine_id"`
	MachineToken      string    `json:"machine_token"`
	MachineCertID     string    `json:"machine_certificate_id"`
	PolicyID          string    `json:"policy_id"`
	PolicySyncedAt    time.Time `json:"policy_synced_at"`
	LastHeartbeatAt   time.Time `json:"last_heartbeat_at,omitempty"`
	LastPolicyCheckAt time.Time `json:"last_policy_check_at,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type RegisterResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Machine struct {
			ID string `json:"id"`
		} `json:"machine"`
		MachineToken string `json:"machine_token"`
		MachineCert  struct {
			CertificateID string `json:"certificate_id"`
		} `json:"machine_certificate"`
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
		WorkerID           string    `json:"worker_id"`
		ConsentEffectiveAt time.Time `json:"consent_effective_at"`
		Policy             struct {
			ID string `json:"id"`
		} `json:"policy"`
	} `json:"data"`
	Error string `json:"error"`
}

type WorkerPolicySnapshot struct {
	PolicyID    string
	EffectiveAt time.Time
}

type CertificateIssueResponse struct {
	Success bool `json:"success"`
	Data    struct {
		CertificateID string `json:"certificate_id"`
		MachineID     string `json:"machine_id"`
	} `json:"data"`
	Error string `json:"error"`
}

type apiCallError struct {
	Status  int
	Message string
}

func (e *apiCallError) Error() string {
	return fmt.Sprintf("status=%d message=%s", e.Status, e.Message)
}

func main() {
	cfg := loadConfig()

	if cfg.OwnerToken == "" || cfg.OwnerID == "" || cfg.PolicyID == "" {
		log.Fatal("AGENT_OWNER_TOKEN, AGENT_OWNER_ID, AGENT_POLICY_ID are required")
	}

	client := &http.Client{Timeout: httpTimeout}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var machineID, machineToken, machineCertID string
	state, loaded := loadState(cfg.StateFile)
	if loaded {
		machineID = state.MachineID
		machineToken = state.MachineToken
		machineCertID = state.MachineCertID
		log.Printf("loaded local agent state machine_id=%s", machineID)
	}

	if machineID == "" || machineToken == "" || machineCertID == "" {
		var err error
		machineID, machineToken, machineCertID, err = registerMachineWithRetry(ctx, client, cfg)
		if err != nil {
			log.Fatalf("register machine failed: %v", err)
		}
		log.Printf("registered machine_id=%s", machineID)
	}

	policySnapshot, err := fetchWorkerPolicy(ctx, client, cfg, machineID, machineToken, machineCertID)
	if err != nil {
		if apiErr, ok := err.(*apiCallError); ok && apiErr.Status == http.StatusUnauthorized {
			log.Printf("policy sync unauthorized, rotating certificate")
			newCertID, certErr := rotateMachineCertificate(ctx, client, cfg, machineID, machineToken)
			if certErr == nil {
				machineCertID = newCertID
				policySnapshot, err = fetchWorkerPolicy(ctx, client, cfg, machineID, machineToken, machineCertID)
			}
		}
	}
	if err != nil {
		log.Printf("policy sync with saved/issued credentials failed, re-registering: %v", err)
		machineID, machineToken, machineCertID, err = registerMachineWithRetry(ctx, client, cfg)
		if err != nil {
			log.Fatalf("re-register machine failed: %v", err)
		}
		policySnapshot, err = fetchWorkerPolicy(ctx, client, cfg, machineID, machineToken, machineCertID)
		if err != nil {
			log.Fatalf("worker policy sync failed after re-register: %v", err)
		}
	}
	if policySnapshot.PolicyID != cfg.PolicyID {
		log.Printf("warning: configured policy_id=%s differs from active consent policy_id=%s; using active policy for heartbeat", cfg.PolicyID, policySnapshot.PolicyID)
	}
	currentPolicyID := policySnapshot.PolicyID
	currentPolicySyncedAt := policySnapshot.EffectiveAt
	now := time.Now().UTC()
	if currentPolicySyncedAt.IsZero() {
		currentPolicySyncedAt = now
	}
	if loaded && state.PolicySyncedAt.After(currentPolicySyncedAt) {
		currentPolicySyncedAt = state.PolicySyncedAt
	}
	lastHeartbeatAt := state.LastHeartbeatAt
	lastPolicyCheckAt := state.LastPolicyCheckAt
	persist := func() {
		if err := saveState(cfg.StateFile, AgentState{
			MachineID:         machineID,
			MachineToken:      machineToken,
			MachineCertID:     machineCertID,
			PolicyID:          currentPolicyID,
			PolicySyncedAt:    currentPolicySyncedAt,
			LastHeartbeatAt:   lastHeartbeatAt,
			LastPolicyCheckAt: lastPolicyCheckAt,
			UpdatedAt:         time.Now().UTC(),
		}); err != nil {
			log.Printf("warning: failed to persist agent state: %v", err)
		}
	}
	persist()

	heartbeatInterval := time.Duration(cfg.HeartbeatSeconds) * time.Second
	if heartbeatInterval <= 0 {
		heartbeatInterval = 15 * time.Second
	}
	staleAfter := time.Duration(cfg.StaleAfterSeconds) * time.Second
	if staleAfter <= 0 {
		staleAfter = 2 * heartbeatInterval
	}
	certRotateMin := time.Duration(cfg.CertRotateMinSeconds) * time.Second
	policyRefreshMin := time.Duration(cfg.PolicyRefreshMinSeconds) * time.Second

	timer := time.NewTimer(heartbeatInterval)
	defer timer.Stop()

	consecutiveFails := 0
	lastCertRotateAttempt := time.Time{}
	lastPolicyRefreshAttempt := time.Time{}
	staleHookFired := false

	for {
		select {
		case <-ctx.Done():
			log.Println("agent shutting down")
			return
		case <-timer.C:
			nextDelay := heartbeatInterval
			now = time.Now().UTC()
			err := sendHeartbeat(ctx, client, cfg, machineID, machineToken, machineCertID, currentPolicyID)
			if apiErr, ok := err.(*apiCallError); ok && apiErr.Status == http.StatusUnauthorized && shouldAttempt(lastCertRotateAttempt, certRotateMin, now) {
				lastCertRotateAttempt = now
				newCertID, certErr := rotateMachineCertificate(ctx, client, cfg, machineID, machineToken)
				if certErr == nil {
					machineCertID = newCertID
					maybeRunHook(cfg, "cert_rotated", map[string]string{"machine_id": machineID, "certificate_id": machineCertID})
					persist()
					err = sendHeartbeat(ctx, client, cfg, machineID, machineToken, machineCertID, currentPolicyID)
				}
			}
			if apiErr, ok := err.(*apiCallError); ok && apiErr.Status == http.StatusForbidden && shouldAttempt(lastPolicyRefreshAttempt, policyRefreshMin, now) {
				lastPolicyRefreshAttempt = now
				latestPolicy, policyErr := fetchWorkerPolicy(ctx, client, cfg, machineID, machineToken, machineCertID)
				if policyErr == nil && latestPolicy.PolicyID != "" {
					lastPolicyCheckAt = now
					if latestPolicy.EffectiveAt.After(currentPolicySyncedAt) || latestPolicy.PolicyID != currentPolicyID {
						currentPolicyID = latestPolicy.PolicyID
						if latestPolicy.EffectiveAt.IsZero() {
							currentPolicySyncedAt = now
						} else {
							currentPolicySyncedAt = latestPolicy.EffectiveAt
						}
						maybeRunHook(cfg, "policy_refreshed", map[string]string{"machine_id": machineID, "policy_id": currentPolicyID})
						persist()
					}
					err = sendHeartbeat(ctx, client, cfg, machineID, machineToken, machineCertID, currentPolicyID)
				}
			}
			if err != nil {
				consecutiveFails++
				if consecutiveFails >= heartbeatMaxConsecutiveFails {
					log.Fatalf("heartbeat failed %d times consecutively, exiting: %v", consecutiveFails, err)
				}
				nextDelay = heartbeatFailureBackoff(consecutiveFails)
				if !lastHeartbeatAt.IsZero() && now.Sub(lastHeartbeatAt) >= staleAfter && !staleHookFired {
					staleHookFired = true
					maybeRunHook(cfg, "heartbeat_stale", map[string]string{"machine_id": machineID, "age_seconds": fmt.Sprintf("%d", int(now.Sub(lastHeartbeatAt).Seconds()))})
				}
				log.Printf("heartbeat error (streak=%d): %v; next_retry=%s", consecutiveFails, err, nextDelay)
			} else {
				if consecutiveFails > 0 {
					log.Printf("heartbeat recovered after %d failures", consecutiveFails)
				}
				consecutiveFails = 0
				lastHeartbeatAt = now
				staleHookFired = false
				persist()
				log.Printf("heartbeat ok machine_id=%s", machineID)
			}
			timer.Reset(nextDelay)
		}
	}
}

func loadConfig() AgentConfig {
	return AgentConfig{
		APIBaseURL:              envOrDefault("AGENT_API_BASE_URL", "http://localhost:8080"),
		OwnerToken:              os.Getenv("AGENT_OWNER_TOKEN"),
		OwnerID:                 os.Getenv("AGENT_OWNER_ID"),
		WorkerName:              envOrDefault("AGENT_WORKER_NAME", "agent-node"),
		PolicyID:                os.Getenv("AGENT_POLICY_ID"),
		HeartbeatSeconds:        envIntOrDefault("AGENT_HEARTBEAT_SECONDS", 15),
		StateFile:               envOrDefault("AGENT_STATE_FILE", ".agent_state.json"),
		StaleAfterSeconds:       envIntOrDefault("AGENT_STALE_AFTER_SECONDS", 120),
		HookCommand:             strings.TrimSpace(os.Getenv("AGENT_HOOK_COMMAND")),
		PolicyRefreshMinSeconds: envIntOrDefault("AGENT_POLICY_REFRESH_MIN_SECONDS", int(policyRefreshMinInterval.Seconds())),
		CertRotateMinSeconds:    envIntOrDefault("AGENT_CERT_ROTATE_MIN_SECONDS", int(certRotateMinInterval.Seconds())),
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

func registerMachineWithRetry(ctx context.Context, client *http.Client, cfg AgentConfig) (machineID, machineToken, machineCertID string, err error) {
	var lastErr error
	for attempt := 1; attempt <= registerMaxAttempts; attempt++ {
		machineID, machineToken, machineCertID, err = registerMachine(ctx, client, cfg)
		if err == nil {
			return machineID, machineToken, machineCertID, nil
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
			return "", "", "", ctx.Err()
		}
	}
	return "", "", "", fmt.Errorf("register failed after retries: %w", lastErr)
}

func registerMachine(ctx context.Context, client *http.Client, cfg AgentConfig) (machineID, machineToken, machineCertID string, err error) {
	payload := map[string]string{"owner_id": cfg.OwnerID, "name": cfg.WorkerName}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIBaseURL+"/api/v1/machines/register", bytes.NewReader(body))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.OwnerToken)
	req.Header.Set("X-Owner-ID", cfg.OwnerID)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	var out RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", "", err
	}
	if resp.StatusCode >= 300 || !out.Success {
		return "", "", "", fmt.Errorf("register failed: status=%d error=%s", resp.StatusCode, out.Error)
	}
	if out.Data.Machine.ID == "" || out.Data.MachineToken == "" || out.Data.MachineCert.CertificateID == "" {
		return "", "", "", fmt.Errorf("register returned incomplete machine credentials")
	}
	return out.Data.Machine.ID, out.Data.MachineToken, out.Data.MachineCert.CertificateID, nil
}

func rotateMachineCertificate(ctx context.Context, client *http.Client, cfg AgentConfig, machineID, machineToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIBaseURL+"/api/v1/machines/"+machineID+"/certificate", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.OwnerToken)
	req.Header.Set("X-Owner-ID", cfg.OwnerID)
	req.Header.Set("X-Machine-Token", machineToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out CertificateIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 || !out.Success {
		return "", &apiCallError{Status: resp.StatusCode, Message: out.Error}
	}
	if out.Data.CertificateID == "" {
		return "", fmt.Errorf("certificate rotation returned empty certificate id")
	}
	return out.Data.CertificateID, nil
}

func fetchWorkerPolicy(ctx context.Context, client *http.Client, cfg AgentConfig, machineID, machineToken, machineCertID string) (WorkerPolicySnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.APIBaseURL+"/api/v1/workers/"+machineID+"/policy", nil)
	if err != nil {
		return WorkerPolicySnapshot{}, err
	}
	req.Header.Set("X-Machine-Token", machineToken)
	req.Header.Set("X-Machine-Certificate-Id", machineCertID)

	resp, err := client.Do(req)
	if err != nil {
		return WorkerPolicySnapshot{}, err
	}
	defer resp.Body.Close()

	var out WorkerPolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return WorkerPolicySnapshot{}, err
	}
	if resp.StatusCode >= 300 || !out.Success {
		return WorkerPolicySnapshot{}, &apiCallError{Status: resp.StatusCode, Message: out.Error}
	}
	if out.Data.Policy.ID == "" {
		return WorkerPolicySnapshot{}, fmt.Errorf("worker policy fetch returned empty policy id")
	}
	return WorkerPolicySnapshot{PolicyID: out.Data.Policy.ID, EffectiveAt: out.Data.ConsentEffectiveAt}, nil
}

func sendHeartbeat(ctx context.Context, client *http.Client, cfg AgentConfig, machineID, machineToken, machineCertID, policyID string) error {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := randomID(12)
	sig := signHeartbeat(machineToken, machineID, timestamp, nonce, policyID)

	payload := map[string]interface{}{
		"timestamp": timestamp,
		"nonce":     nonce,
		"policy_id": policyID,
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
	req.Header.Set("X-Machine-Certificate-Id", machineCertID)

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
		return &apiCallError{Status: resp.StatusCode, Message: out.Error}
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

func loadState(path string) (AgentState, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return AgentState{}, false
	}
	var s AgentState
	if err := json.Unmarshal(b, &s); err != nil {
		return AgentState{}, false
	}
	if s.MachineID == "" || s.MachineToken == "" || s.MachineCertID == "" {
		return AgentState{}, false
	}
	return s, true
}

func saveState(path string, s AgentState) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".agent-state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func shouldAttempt(last time.Time, minInterval time.Duration, now time.Time) bool {
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= minInterval
}

func maybeRunHook(cfg AgentConfig, event string, fields map[string]string) {
	if cfg.HookCommand == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", cfg.HookCommand)
	env := append(os.Environ(), "AGENT_HOOK_EVENT="+event)
	for k, v := range fields {
		if strings.TrimSpace(k) == "" {
			continue
		}
		env = append(env, "AGENT_HOOK_"+strings.ToUpper(k)+"="+v)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("warning: hook command failed event=%s err=%v output=%s", event, err, strings.TrimSpace(string(out)))
	}
}

func randomID(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
