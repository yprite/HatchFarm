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
	app.apiToken = "test-token"
	return app, app.routes()
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

func authHeader() map[string]string {
	return map[string]string{"Authorization": "Bearer test-token"}
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
	_, h := newTestServer()

	// register machine
	w := doJSON(t, h, http.MethodPost, "/api/v1/machines/register", map[string]string{"owner_id": "own_1", "name": "node-a"}, authHeader())
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
	w = doJSON(t, h, http.MethodPost, "/api/v1/policies", map[string]interface{}{
		"owner_id":  "own_1",
		"signature": "sig_owner",
		"rules": map[string]interface{}{
			"max_cpu_percent": 60,
		},
	}, authHeader())
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
	w = doJSON(t, h, http.MethodPost, "/api/v1/policies/"+pol.Data.ID+"/activate", nil, authHeader())
	if w.Code != http.StatusOK {
		t.Fatalf("activate expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// create consent
	w = doJSON(t, h, http.MethodPost, "/api/v1/consents", map[string]string{
		"owner_id":  "own_1",
		"worker_id": reg.Data.Machine.ID,
		"policy_id": pol.Data.ID,
		"signature": "consent_sig",
	}, authHeader())
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
	w = doJSON(t, h, http.MethodPost, "/api/v1/consents/"+con.Data.ID+"/revoke", nil, authHeader())
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
	_, h := newTestServer()

	w := doJSON(t, h, http.MethodPost, "/api/v1/machines/register", map[string]string{"owner_id": "own_1", "name": "node-a"}, authHeader())
	var reg struct {
		Data struct {
			Machine struct {
				ID string `json:"id"`
			} `json:"machine"`
			MachineToken string `json:"machine_token"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&reg)

	w = doJSON(t, h, http.MethodPost, "/api/v1/policies", map[string]interface{}{"owner_id": "own_1", "signature": "sig", "rules": map[string]interface{}{}}, authHeader())
	var pol struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&pol)
	_ = doJSON(t, h, http.MethodPost, "/api/v1/policies/"+pol.Data.ID+"/activate", nil, authHeader())
	_ = doJSON(t, h, http.MethodPost, "/api/v1/consents", map[string]string{"owner_id": "own_1", "worker_id": reg.Data.Machine.ID, "policy_id": pol.Data.ID, "signature": "ok"}, authHeader())

	w = doJSON(t, h, http.MethodPost, "/api/v1/workers/"+reg.Data.Machine.ID+"/heartbeat", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"nonce":     "x",
		"policy_id": pol.Data.ID,
		"signature": "bad-signature",
	}, map[string]string{"X-Machine-Token": reg.Data.MachineToken})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
