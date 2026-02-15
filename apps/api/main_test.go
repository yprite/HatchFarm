package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer() (*App, http.Handler) {
	app := newApp()
	app.apiToken = "test-" + randomID(8)
	h := app.corsMiddleware(app.requestIDMiddleware(app.loggingMiddleware(app.tlsEnforcementMiddleware(app.bodyLimitMiddleware(app.rateLimitMiddleware(app.routes()))))))
	return app, h
}

func doJSON(t *testing.T, h http.Handler, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func authHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token, "X-Owner-ID": "own_1"}
}

func TestHealthHandler(t *testing.T) {
	_, h := newTestServer()
	w := doJSON(t, h, http.MethodGet, "/health", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed decode: %v", err)
	}
	if resp.Status != "healthy" {
		t.Fatalf("expected healthy, got %s", resp.Status)
	}
}

func TestProtectedEndpointRequiresAuth(t *testing.T) {
	_, h := newTestServer()
	w := doJSON(t, h, http.MethodPost, "/api/v1/machines/register", map[string]string{"owner_id": "own_1", "name": "mac-mini"}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestConsentLifecycleAndHeartbeat(t *testing.T) {
	app, h := newTestServer()

	// register machine
	w := doJSON(t, h, http.MethodPost, "/api/v1/machines/register", map[string]string{"owner_id": "own_1", "name": "node-a"}, authHeader(app.apiToken))
	if w.Code != http.StatusCreated {
		t.Fatalf("register expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var reg struct {
		Success bool `json:"success"`
		Data    struct {
			Machine struct {
				ID string `json:"id"`
			} `json:"machine"`
			MachineToken string `json:"machine_token"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&reg)

	// create policy
	policyRules := map[string]interface{}{"max_cpu_percent": 60}
	w = doJSON(t, h, http.MethodPost, "/api/v1/policies", map[string]interface{}{
		"owner_id":  "own_1",
		"signature": signPolicySignature(app.apiToken, "own_1", policyRules),
		"rules":     policyRules,
	}, authHeader(app.apiToken))
	if w.Code != http.StatusCreated {
		t.Fatalf("policy create expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var pol struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&pol)

	// activate policy
	w = doJSON(t, h, http.MethodPost, "/api/v1/policies/"+pol.Data.ID+"/activate", nil, authHeader(app.apiToken))
	if w.Code != http.StatusOK {
		t.Fatalf("activate expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// create consent
	w = doJSON(t, h, http.MethodPost, "/api/v1/consents", map[string]string{
		"owner_id":  "own_1",
		"worker_id": reg.Data.Machine.ID,
		"policy_id": pol.Data.ID,
		"signature": signConsentSignature(app.apiToken, "own_1", reg.Data.Machine.ID, pol.Data.ID),
	}, authHeader(app.apiToken))
	if w.Code != http.StatusCreated {
		t.Fatalf("consent expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var con struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&con)

	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := "n1"
	sig := signHeartbeat(reg.Data.MachineToken, reg.Data.Machine.ID, ts, nonce, pol.Data.ID)

	// heartbeat allowed
	w = doJSON(t, h, http.MethodPost, "/api/v1/workers/"+reg.Data.Machine.ID+"/heartbeat", map[string]interface{}{
		"timestamp": ts,
		"nonce":     nonce,
		"policy_id": pol.Data.ID,
		"metrics":   map[string]interface{}{"cpu": 35},
		"signature": sig,
	}, map[string]string{"X-Machine-Token": reg.Data.MachineToken})
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// revoke consent
	w = doJSON(t, h, http.MethodPost, "/api/v1/consents/"+con.Data.ID+"/revoke", nil, authHeader(app.apiToken))
	if w.Code != http.StatusOK {
		t.Fatalf("revoke expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// heartbeat blocked after revoke
	w = doJSON(t, h, http.MethodPost, "/api/v1/workers/"+reg.Data.Machine.ID+"/heartbeat", map[string]interface{}{
		"timestamp": ts,
		"nonce":     "n2",
		"policy_id": pol.Data.ID,
		"metrics":   map[string]interface{}{"cpu": 20},
		"signature": signHeartbeat(reg.Data.MachineToken, reg.Data.Machine.ID, ts, "n2", pol.Data.ID),
	}, map[string]string{"X-Machine-Token": reg.Data.MachineToken})
	if w.Code != http.StatusForbidden {
		t.Fatalf("heartbeat after revoke expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHeartbeatRejectsBadSignature(t *testing.T) {
	app, h := newTestServer()
	workerID, workerToken, policyID := setupWorkerConsent(t, h, app.apiToken)

	w := doJSON(t, h, http.MethodPost, "/api/v1/workers/"+workerID+"/heartbeat", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"nonce":     "x",
		"policy_id": policyID,
		"signature": "bad-signature",
	}, map[string]string{"X-Machine-Token": workerToken})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHeartbeatRejectsReplayNonce(t *testing.T) {
	app, h := newTestServer()
	workerID, workerToken, policyID := setupWorkerConsent(t, h, app.apiToken)

	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := "replay-nonce"
	sig := signHeartbeat(workerToken, workerID, ts, nonce, policyID)

	w := doJSON(t, h, http.MethodPost, "/api/v1/workers/"+workerID+"/heartbeat", map[string]interface{}{
		"timestamp": ts,
		"nonce":     nonce,
		"policy_id": policyID,
		"signature": sig,
	}, map[string]string{"X-Machine-Token": workerToken})
	if w.Code != http.StatusOK {
		t.Fatalf("first heartbeat expected 200, got %d", w.Code)
	}

	w = doJSON(t, h, http.MethodPost, "/api/v1/workers/"+workerID+"/heartbeat", map[string]interface{}{
		"timestamp": ts,
		"nonce":     nonce,
		"policy_id": policyID,
		"signature": sig,
	}, map[string]string{"X-Machine-Token": workerToken})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("replay heartbeat expected 401, got %d", w.Code)
	}
}

func TestHeartbeatRejectsStaleTimestamp(t *testing.T) {
	app, h := newTestServer()
	workerID, workerToken, policyID := setupWorkerConsent(t, h, app.apiToken)

	stale := time.Now().UTC().Add(-(heartbeatMaxSkew + 10*time.Second)).Format(time.RFC3339)
	sig := signHeartbeat(workerToken, workerID, stale, "stale-1", policyID)
	w := doJSON(t, h, http.MethodPost, "/api/v1/workers/"+workerID+"/heartbeat", map[string]interface{}{
		"timestamp": stale,
		"nonce":     "stale-1",
		"policy_id": policyID,
		"signature": sig,
	}, map[string]string{"X-Machine-Token": workerToken})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("stale heartbeat expected 401, got %d", w.Code)
	}
}

func TestRateLimitKicksIn(t *testing.T) {
	_, h := newTestServer()
	var got429 bool
	for i := 0; i < 50; i++ {
		w := doJSON(t, h, http.MethodGet, "/health", nil, nil)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected at least one 429 response from rate limiter")
	}
}

func TestPolicyValidationRejectsUnknownField(t *testing.T) {
	app, h := newTestServer()
	w := doJSON(t, h, http.MethodPost, "/api/v1/policies", map[string]interface{}{
		"owner_id":  "own_1",
		"signature": signPolicySignature(app.apiToken, "own_1", map[string]interface{}{"max_cpu_percent": 60, "evil_key": true}),
		"rules": map[string]interface{}{
			"max_cpu_percent": 60,
			"evil_key":        true,
		},
	}, authHeader(app.apiToken))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPolicyValidationRejectsInvalidAllowedHours(t *testing.T) {
	app, h := newTestServer()
	rules := map[string]interface{}{
		"max_cpu_percent": 60,
		"allowed_hours":   []interface{}{1.5, 2},
	}
	w := doJSON(t, h, http.MethodPost, "/api/v1/policies", map[string]interface{}{
		"owner_id":  "own_1",
		"signature": signPolicySignature(app.apiToken, "own_1", rules),
		"rules":     rules,
	}, authHeader(app.apiToken))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuditEventsIncludeOwnedWorkerEvents(t *testing.T) {
	app, h := newTestServer()
	workerID, workerToken, policyID := setupWorkerConsent(t, h, app.apiToken)

	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := "audit-1"
	sig := signHeartbeat(workerToken, workerID, ts, nonce, policyID)
	w := doJSON(t, h, http.MethodPost, "/api/v1/workers/"+workerID+"/heartbeat", map[string]interface{}{
		"timestamp": ts,
		"nonce":     nonce,
		"policy_id": policyID,
		"signature": sig,
	}, map[string]string{"X-Machine-Token": workerToken})
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = doJSON(t, h, http.MethodGet, "/api/v1/audit/events?limit=200", nil, authHeader(app.apiToken))
	if w.Code != http.StatusOK {
		t.Fatalf("audit list expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Events []AuditEvent `json:"events"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)

	found := false
	for _, ev := range resp.Data.Events {
		if ev.Type == "worker_heartbeat" && ev.Actor == "worker:"+workerID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected owned worker heartbeat event to be visible in owner audit list")
	}
}

func setupWorkerConsent(t *testing.T, h http.Handler, token string) (workerID, workerToken, policyID string) {
	t.Helper()
	w := doJSON(t, h, http.MethodPost, "/api/v1/machines/register", map[string]string{"owner_id": "own_1", "name": "node-a"}, authHeader(token))
	if w.Code != http.StatusCreated {
		t.Fatalf("register expected 201, got %d", w.Code)
	}
	var reg struct {
		Data struct {
			Machine struct {
				ID string `json:"id"`
			} `json:"machine"`
			MachineToken string `json:"machine_token"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&reg)

	rules := map[string]interface{}{"max_cpu_percent": 60}
	w = doJSON(t, h, http.MethodPost, "/api/v1/policies", map[string]interface{}{"owner_id": "own_1", "signature": signPolicySignature(token, "own_1", rules), "rules": rules}, authHeader(token))
	if w.Code != http.StatusCreated {
		t.Fatalf("policy create expected 201, got %d", w.Code)
	}
	var pol struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&pol)

	w = doJSON(t, h, http.MethodPost, "/api/v1/policies/"+pol.Data.ID+"/activate", nil, authHeader(token))
	if w.Code != http.StatusOK {
		t.Fatalf("policy activate expected 200, got %d", w.Code)
	}

	w = doJSON(t, h, http.MethodPost, "/api/v1/consents", map[string]string{"owner_id": "own_1", "worker_id": reg.Data.Machine.ID, "policy_id": pol.Data.ID, "signature": signConsentSignature(token, "own_1", reg.Data.Machine.ID, pol.Data.ID)}, authHeader(token))
	if w.Code != http.StatusCreated {
		t.Fatalf("consent expected 201, got %d", w.Code)
	}

	return reg.Data.Machine.ID, reg.Data.MachineToken, pol.Data.ID
}
