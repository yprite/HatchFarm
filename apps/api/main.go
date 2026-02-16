package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	version                  = "0.6.0"
	maxBodyBytes             = 1 << 20 // 1MB
	heartbeatMaxSkew         = 90 * time.Second
	nonceReplayWindow        = 5 * time.Minute
	nonceCleanupInterval     = 30 * time.Second
	rateLimitRefillPerSecond = 5.0
	rateLimitBurst           = 20.0
	rateBucketTTL            = 10 * time.Minute
	maxRateBuckets           = 20000
	maxAuditEvents           = 5000
	defaultAuditPageSize     = 100
	maxAuditPageSize         = 500
	machineCertTTL           = 15 * time.Minute
)

type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type Machine struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Name      string    `json:"name"`
	Secret    string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type MachineCertificate struct {
	CertificateID string    `json:"certificate_id"`
	MachineID     string    `json:"machine_id"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Signature     string    `json:"signature"`
}

type Policy struct {
	ID        string                 `json:"id"`
	OwnerID   string                 `json:"owner_id"`
	Version   int                    `json:"version"`
	Rules     map[string]interface{} `json:"rules"`
	Signature string                 `json:"signature"`
	State     string                 `json:"state"` // draft | active
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type Consent struct {
	ID          string     `json:"id"`
	OwnerID     string     `json:"owner_id"`
	WorkerID    string     `json:"worker_id"`
	PolicyID    string     `json:"policy_id"`
	Signature   string     `json:"signature"`
	EffectiveAt time.Time  `json:"effective_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type AuditEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Actor     string                 `json:"actor"`
	ObjectID  string                 `json:"object_id"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

type nonceRecord struct {
	SeenAt time.Time
}

type tokenBucket struct {
	Tokens     float64
	LastRefill time.Time
	LastSeen   time.Time
}

type WorkerStatus struct {
	WorkerID      string    `json:"worker_id"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	PolicyID      string    `json:"policy_id"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Store struct {
	mu               sync.RWMutex
	machines         map[string]*Machine
	machineCerts     map[string]*MachineCertificate
	workerStatus     map[string]*WorkerStatus
	policies         map[string]*Policy
	consents         map[string]*Consent
	auditEvents      []*AuditEvent
	nonces           map[string]nonceRecord
	lastNonceCleanup time.Time
}

type App struct {
	store                  *Store
	apiToken               string
	allowedOrigins         map[string]struct{}
	startedAt              time.Time
	rateMu                 sync.Mutex
	rateBuckets            map[string]*tokenBucket
	redisClient            *redis.Client
	workerLocks            sync.Map
	localNonceFallback     bool
	redisRateLimitEnabled  bool
	redisRateLimitFallback bool
	redisRateLimitWindow   time.Duration
	redisRateLimitMax      int
	metricsPublic          bool
	workerStatusStateFile  string
	workerStatusStaleAfter time.Duration
}

func main() {
	app := newApp()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := app.routes()
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      app.corsMiddleware(app.requestIDMiddleware(app.loggingMiddleware(app.tlsEnforcementMiddleware(app.bodyLimitMiddleware(app.rateLimitMiddleware(mux)))))),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("HatchFarm API server starting on port %s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	if err := app.saveWorkerStatusState(); err != nil {
		log.Printf("warning: failed to save worker status state on shutdown: %v", err)
	}

	log.Println("Server exited")
}

func newApp() *App {
	apiToken := os.Getenv("HATCHFARM_API_TOKEN")
	if apiToken == "" {
		if rid := randomID(16); rid != "" {
			apiToken = "boot_" + rid
			log.Printf("warning: HATCHFARM_API_TOKEN not set; generated ephemeral token")
		} else {
			log.Fatal("failed to initialize API token")
		}
	}

	origins := map[string]struct{}{}
	for _, origin := range strings.Split(envOrDefault("ALLOWED_ORIGINS", "http://localhost:3000"), ",") {
		o := strings.TrimSpace(origin)
		if o != "" {
			origins[o] = struct{}{}
		}
	}

	app := &App{
		store: &Store{
			machines:         map[string]*Machine{},
			machineCerts:     map[string]*MachineCertificate{},
			workerStatus:     map[string]*WorkerStatus{},
			policies:         map[string]*Policy{},
			consents:         map[string]*Consent{},
			nonces:           map[string]nonceRecord{},
			lastNonceCleanup: time.Now().UTC(),
		},
		apiToken:               apiToken,
		allowedOrigins:         origins,
		startedAt:              time.Now().UTC(),
		rateBuckets:            map[string]*tokenBucket{},
		localNonceFallback:     strings.EqualFold(envOrDefault("REDIS_NONCE_FALLBACK", "false"), "true"),
		redisRateLimitEnabled:  strings.EqualFold(envOrDefault("REDIS_RATE_LIMIT_ENABLED", "false"), "true"),
		redisRateLimitFallback: strings.EqualFold(envOrDefault("REDIS_RATE_LIMIT_FALLBACK", "true"), "true"),
		redisRateLimitWindow:   time.Duration(envIntOrDefault("REDIS_RATE_LIMIT_WINDOW_SECONDS", 1)) * time.Second,
		redisRateLimitMax:      envIntOrDefault("REDIS_RATE_LIMIT_MAX_REQUESTS", int(rateLimitBurst)),
		metricsPublic:          strings.EqualFold(envOrDefault("METRICS_PUBLIC", "false"), "true"),
		workerStatusStateFile:  envOrDefault("WORKER_STATUS_STATE_FILE", ".worker_status_state.json"),
		workerStatusStaleAfter: time.Duration(envIntOrDefault("WORKER_STATUS_STALE_SECONDS", 60)) * time.Second,
	}
	app.redisClient = initRedisClient()
	if err := app.loadWorkerStatusState(); err != nil {
		log.Printf("warning: failed to load worker status state: %v", err)
	}
	return app
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func initRedisClient() *redis.Client {
	addr := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if addr == "" {
		return nil
	}
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("warning: redis disabled (ping failed): %v", err)
		_ = client.Close()
		return nil
	}
	log.Printf("redis enabled for shared nonce state")
	return client
}

func (a *App) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.healthHandler)
	mux.HandleFunc("/metrics", a.metricsHandler)
	mux.HandleFunc("/api/v1/status", a.statusHandler)
	mux.HandleFunc("/api/v1/machines/register", a.authRequired(a.registerMachineHandler))
	mux.HandleFunc("/api/v1/machines/", a.authRequired(a.machineHandler))
	mux.HandleFunc("/api/v1/policies", a.authRequired(a.createPolicyHandler))
	mux.HandleFunc("/api/v1/policies/", a.authRequired(a.activatePolicyHandler))
	mux.HandleFunc("/api/v1/consents", a.authRequired(a.createConsentHandler))
	mux.HandleFunc("/api/v1/consents/", a.authRequired(a.revokeConsentHandler))
	mux.HandleFunc("/api/v1/workers/", a.workerHandler)
	mux.HandleFunc("/api/v1/audit/events", a.authRequired(a.auditEventsHandler))
	return mux
}

func (a *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   version,
	})
}

func (a *App) statusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"service": "hatchfarm-api",
			"version": version,
			"uptime":  time.Since(a.startedAt).String(),
		},
	})
}

func (a *App) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if !a.metricsPublic {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || !hmac.Equal([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(a.apiToken)) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
	}

	uptime := time.Since(a.startedAt).Seconds()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "hatchfarm_uptime_seconds %.0f\n", uptime)
}

func (a *App) machineHandler(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/certificate") {
		a.issueMachineCertificateHandler(w, r)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (a *App) registerMachineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		OwnerID string `json:"owner_id"`
		Name    string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.OwnerID == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "owner_id and name are required")
		return
	}

	idPart := randomID(8)
	secret := randomID(24)
	if idPart == "" || secret == "" {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	id := "wrk_" + idPart
	m := &Machine{ID: id, OwnerID: req.OwnerID, Name: req.Name, Secret: secret, CreatedAt: time.Now().UTC()}

	a.store.mu.Lock()
	a.store.machines[id] = m
	cert, err := a.issueMachineCertificateLocked(id)
	if err != nil {
		a.store.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	a.appendAuditLocked("machine_registered", "owner:"+req.OwnerID, id, map[string]interface{}{"name": req.Name})
	a.store.mu.Unlock()

	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: map[string]interface{}{"machine": m, "machine_token": secret, "machine_certificate": cert}})
}

func (a *App) issueMachineCertificateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/certificate") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	machineID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/machines/"), "/certificate")
	if machineID == "" {
		writeError(w, http.StatusBadRequest, "machine id is required")
		return
	}
	ownerID := ownerIDFromHeader(r)
	if ownerID == "" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	machineToken := strings.TrimSpace(r.Header.Get("X-Machine-Token"))
	if machineToken == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	m, ok := a.store.machines[machineID]
	if !ok {
		writeError(w, http.StatusNotFound, "machine not found")
		return
	}
	if m.OwnerID != ownerID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !hmac.Equal([]byte(m.Secret), []byte(machineToken)) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	cert, err := a.issueMachineCertificateLocked(machineID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	a.appendAuditLocked("machine_certificate_issued", "owner:"+ownerID, machineID, map[string]interface{}{"certificate_id": cert.CertificateID})
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: cert})
}

func (a *App) issueMachineCertificateLocked(machineID string) (*MachineCertificate, error) {
	idPart := randomID(10)
	sigPart := randomID(24)
	if idPart == "" || sigPart == "" {
		return nil, fmt.Errorf("certificate id generation failed")
	}
	now := time.Now().UTC()
	cert := &MachineCertificate{
		CertificateID: "mcert_" + idPart,
		MachineID:     machineID,
		IssuedAt:      now,
		ExpiresAt:     now.Add(machineCertTTL),
		Signature:     sigPart,
	}
	a.store.machineCerts[machineID] = cert
	return cert, nil
}

func (a *App) isMachineCertValidLocked(machineID, certID string, now time.Time) bool {
	cert, ok := a.store.machineCerts[machineID]
	if !ok {
		return false
	}
	if cert.CertificateID != certID {
		return false
	}
	return now.Before(cert.ExpiresAt)
}

func (a *App) createPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		OwnerID   string                 `json:"owner_id"`
		Rules     map[string]interface{} `json:"rules"`
		Signature string                 `json:"signature"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.OwnerID == "" || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "owner_id and signature are required")
		return
	}
	if err := validatePolicyRules(req.Rules); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !verifyPolicySignature(a.apiToken, req.OwnerID, req.Rules, req.Signature) {
		writeError(w, http.StatusUnauthorized, "invalid policy signature")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	latest := 0
	for _, p := range a.store.policies {
		if p.OwnerID == req.OwnerID && p.Version > latest {
			latest = p.Version
		}
	}

	idPart := randomID(8)
	if idPart == "" {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	id := "pol_" + idPart
	now := time.Now().UTC()
	policy := &Policy{
		ID:        id,
		OwnerID:   req.OwnerID,
		Version:   latest + 1,
		Rules:     req.Rules,
		Signature: req.Signature,
		State:     "draft",
		CreatedAt: now,
		UpdatedAt: now,
	}
	a.store.policies[id] = policy
	a.appendAuditLocked("policy_created", "owner:"+req.OwnerID, id, map[string]interface{}{"version": policy.Version})

	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: policy})
}

func (a *App) activatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/activate") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/policies/"), "/activate")
	if id == "" {
		writeError(w, http.StatusBadRequest, "policy id is required")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	policy, ok := a.store.policies[id]
	if !ok {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	ownerID := ownerIDFromHeader(r)
	if ownerID == "" || ownerID != policy.OwnerID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if policy.Signature == "" {
		writeError(w, http.StatusBadRequest, "policy signature required")
		return
	}
	policy.State = "active"
	policy.UpdatedAt = time.Now().UTC()
	a.appendAuditLocked("policy_activated", "owner:"+policy.OwnerID, id, map[string]interface{}{"version": policy.Version})
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: policy})
}

func (a *App) createConsentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		OwnerID   string `json:"owner_id"`
		WorkerID  string `json:"worker_id"`
		PolicyID  string `json:"policy_id"`
		Signature string `json:"signature"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.OwnerID == "" || req.WorkerID == "" || req.PolicyID == "" || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "owner_id, worker_id, policy_id, signature are required")
		return
	}
	if !verifyConsentSignature(a.apiToken, req.OwnerID, req.WorkerID, req.PolicyID, req.Signature) {
		writeError(w, http.StatusUnauthorized, "invalid consent signature")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	machine, mok := a.store.machines[req.WorkerID]
	if !mok || machine.OwnerID != req.OwnerID {
		writeError(w, http.StatusBadRequest, "worker not found for owner")
		return
	}
	policy, pok := a.store.policies[req.PolicyID]
	if !pok || policy.OwnerID != req.OwnerID || policy.State != "active" {
		writeError(w, http.StatusBadRequest, "active policy not found for owner")
		return
	}

	consentIDPart := randomID(8)
	if consentIDPart == "" {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	consent := &Consent{
		ID:          "con_" + consentIDPart,
		OwnerID:     req.OwnerID,
		WorkerID:    req.WorkerID,
		PolicyID:    req.PolicyID,
		Signature:   req.Signature,
		EffectiveAt: time.Now().UTC(),
	}
	a.store.consents[consent.ID] = consent
	a.appendAuditLocked("consent_created", "owner:"+req.OwnerID, consent.ID, map[string]interface{}{"worker_id": req.WorkerID, "policy_id": req.PolicyID})
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: consent})
}

func (a *App) revokeConsentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/revoke") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/consents/"), "/revoke")
	if id == "" {
		writeError(w, http.StatusBadRequest, "consent id is required")
		return
	}

	ownerID := ownerIDFromHeader(r)
	if ownerID == "" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	a.store.mu.RLock()
	consentRef, ok := a.store.consents[id]
	if !ok {
		a.store.mu.RUnlock()
		writeError(w, http.StatusNotFound, "consent not found")
		return
	}
	if ownerID != consentRef.OwnerID {
		a.store.mu.RUnlock()
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	workerID := consentRef.WorkerID
	a.store.mu.RUnlock()

	wl := a.workerLock(workerID)
	wl.Lock()
	defer wl.Unlock()

	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	consent, ok := a.store.consents[id]
	if !ok {
		writeError(w, http.StatusNotFound, "consent not found")
		return
	}
	if ownerID != consent.OwnerID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	now := time.Now().UTC()
	consent.RevokedAt = &now
	a.appendAuditLocked("consent_revoked", "owner:"+consent.OwnerID, id, map[string]interface{}{"worker_id": consent.WorkerID})
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: consent})
}

func (a *App) workerHandler(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/heartbeat") {
		a.heartbeatHandler(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/policy") {
		a.workerPolicyHandler(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/status") {
		a.workerStatusHandler(w, r)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (a *App) heartbeatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/heartbeat") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	workerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/workers/"), "/heartbeat")
	if workerID == "" {
		writeError(w, http.StatusBadRequest, "worker id is required")
		return
	}

	var req struct {
		Timestamp string                 `json:"timestamp"`
		Nonce     string                 `json:"nonce"`
		PolicyID  string                 `json:"policy_id"`
		Metrics   map[string]interface{} `json:"metrics"`
		Signature string                 `json:"signature"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	machineToken := r.Header.Get("X-Machine-Token")
	machineCertID := strings.TrimSpace(r.Header.Get("X-Machine-Certificate-Id"))
	if machineToken == "" || machineCertID == "" || req.Timestamp == "" || req.Nonce == "" || req.PolicyID == "" || req.Signature == "" {
		a.auditWorkerAuthFailure(workerID, "missing_heartbeat_fields")
		writeError(w, http.StatusBadRequest, "missing required heartbeat fields")
		return
	}

	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid timestamp")
		return
	}
	now := time.Now().UTC()
	if ts.Before(now.Add(-heartbeatMaxSkew)) || ts.After(now.Add(heartbeatMaxSkew)) {
		writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
		return
	}

	a.store.mu.RLock()
	machine, ok := a.store.machines[workerID]
	if !ok || machine.Secret != machineToken {
		a.store.mu.RUnlock()
		a.auditWorkerAuthFailure(workerID, "invalid_machine_token")
		writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
		return
	}
	if !a.isMachineCertValidLocked(workerID, machineCertID, now) {
		a.store.mu.RUnlock()
		a.auditWorkerAuthFailure(workerID, "invalid_or_expired_machine_cert")
		writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
		return
	}

	if !verifyHeartbeatSignature(machine.Secret, workerID, req.Timestamp, req.Nonce, req.PolicyID, req.Signature) {
		a.store.mu.RUnlock()
		a.auditWorkerAuthFailure(workerID, "invalid_heartbeat_signature")
		writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
		return
	}

	consentActive := false
	for _, c := range a.store.consents {
		if c.WorkerID == workerID && c.PolicyID == req.PolicyID && c.RevokedAt == nil {
			consentActive = true
			break
		}
	}
	a.store.mu.RUnlock()
	if !consentActive {
		writeError(w, http.StatusForbidden, "no active consent for worker/policy")
		return
	}

	nonceKey := workerID + ":" + req.Nonce
	if a.redisClient != nil {
		ok, err := a.reserveNonceRedis(r.Context(), nonceKey)
		if err != nil {
			if !a.localNonceFallback {
				writeError(w, http.StatusServiceUnavailable, "nonce backend unavailable")
				return
			}
			log.Printf("warning: redis nonce reserve failed, falling back to local nonce store: %v", err)
			a.store.mu.Lock()
			if !a.reserveNonceLocalLocked(now, nonceKey) {
				a.store.mu.Unlock()
				writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
				return
			}
			a.store.mu.Unlock()
		} else if !ok {
			writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
			return
		}
	} else {
		a.store.mu.Lock()
		if !a.reserveNonceLocalLocked(now, nonceKey) {
			a.store.mu.Unlock()
			writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
			return
		}
		a.store.mu.Unlock()
	}

	// Serialize final authorization/accept path with revoke for this worker.
	wl := a.workerLock(workerID)
	wl.Lock()
	defer wl.Unlock()

	// Re-check consent after nonce reservation while worker lock is held.
	a.store.mu.RLock()
	consentStillActive := false
	for _, c := range a.store.consents {
		if c.WorkerID == workerID && c.PolicyID == req.PolicyID && c.RevokedAt == nil {
			consentStillActive = true
			break
		}
	}
	a.store.mu.RUnlock()
	if !consentStillActive {
		writeError(w, http.StatusForbidden, "no active consent for worker/policy")
		return
	}

	a.store.mu.Lock()
	a.store.workerStatus[workerID] = &WorkerStatus{
		WorkerID:      workerID,
		LastHeartbeat: now,
		PolicyID:      req.PolicyID,
		UpdatedAt:     now,
	}
	a.appendAuditLocked("worker_heartbeat", "worker:"+workerID, workerID, map[string]interface{}{"policy_id": req.PolicyID})
	a.store.mu.Unlock()
	if err := a.saveWorkerStatusState(); err != nil {
		log.Printf("warning: failed to persist worker status: %v", err)
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]interface{}{"worker_id": workerID, "accepted": true}})
}

func (a *App) workerStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/status") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	workerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/workers/"), "/status")
	if workerID == "" {
		writeError(w, http.StatusBadRequest, "worker id is required")
		return
	}

	ownerID := ownerIDFromHeader(r)
	auth := r.Header.Get("Authorization")
	if ownerID == "" || !strings.HasPrefix(auth, "Bearer ") || !hmac.Equal([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(a.apiToken)) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	m, ok := a.store.machines[workerID]
	if !ok {
		writeError(w, http.StatusNotFound, "worker not found")
		return
	}
	if m.OwnerID != ownerID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	status, ok := a.store.workerStatus[workerID]
	if !ok {
		writeError(w, http.StatusNotFound, "worker status not found")
		return
	}
	age := time.Since(status.LastHeartbeat)
	if age < 0 {
		age = 0
	}
	stale := age > a.workerStatusStaleAfter
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]interface{}{
		"worker_id":       status.WorkerID,
		"last_heartbeat":  status.LastHeartbeat,
		"policy_id":       status.PolicyID,
		"updated_at":      status.UpdatedAt,
		"stale":           stale,
		"age_seconds":     int(age.Seconds()),
		"stale_threshold": int(a.workerStatusStaleAfter.Seconds()),
	}})
}

func (a *App) workerPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/policy") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	workerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/workers/"), "/policy")
	if workerID == "" {
		writeError(w, http.StatusBadRequest, "worker id is required")
		return
	}
	machineToken := strings.TrimSpace(r.Header.Get("X-Machine-Token"))
	machineCertID := strings.TrimSpace(r.Header.Get("X-Machine-Certificate-Id"))
	if machineToken == "" || machineCertID == "" {
		a.auditWorkerAuthFailure(workerID, "missing_worker_policy_auth_headers")
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	a.store.mu.RLock()
	defer a.store.mu.RUnlock()

	machine, ok := a.store.machines[workerID]
	if !ok || machine.Secret != machineToken {
		a.auditWorkerAuthFailure(workerID, "invalid_machine_token_policy_fetch")
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !a.isMachineCertValidLocked(workerID, machineCertID, time.Now().UTC()) {
		a.auditWorkerAuthFailure(workerID, "invalid_or_expired_machine_cert_policy_fetch")
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var latestConsent *Consent
	for _, c := range a.store.consents {
		if c.WorkerID != workerID || c.RevokedAt != nil {
			continue
		}
		if latestConsent == nil || c.EffectiveAt.After(latestConsent.EffectiveAt) {
			latestConsent = c
		}
	}
	if latestConsent == nil {
		writeError(w, http.StatusForbidden, "no active consent")
		return
	}

	policy, ok := a.store.policies[latestConsent.PolicyID]
	if !ok || policy.State != "active" {
		writeError(w, http.StatusForbidden, "no active policy")
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]interface{}{
		"worker_id":            workerID,
		"policy":               policy,
		"consent_effective_at": latestConsent.EffectiveAt,
	}})
}

func (a *App) auditEventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := defaultAuditPageSize
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		if v > maxAuditPageSize {
			v = maxAuditPageSize
		}
		limit = v
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			writeError(w, http.StatusBadRequest, "invalid offset")
			return
		}
		offset = v
	}

	ownerID := ownerIDFromHeader(r)
	if ownerID == "" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	filtered := make([]*AuditEvent, 0, len(a.store.auditEvents))
	for _, ev := range a.store.auditEvents {
		if ev.Actor == "owner:"+ownerID {
			filtered = append(filtered, ev)
			continue
		}
		if strings.HasPrefix(ev.Actor, "worker:") {
			workerID := strings.TrimPrefix(ev.Actor, "worker:")
			if m, ok := a.store.machines[workerID]; ok && m.OwnerID == ownerID {
				filtered = append(filtered, ev)
			}
		}
	}
	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	events := filtered[offset:end]
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]interface{}{"events": events, "total": total, "limit": limit, "offset": offset}})
}

func (a *App) appendAuditLocked(eventType, actor, objectID string, metadata map[string]interface{}) {
	auditIDPart := randomID(8)
	if auditIDPart == "" {
		return
	}
	a.store.auditEvents = append(a.store.auditEvents, &AuditEvent{
		ID:        "aud_" + auditIDPart,
		Type:      eventType,
		Actor:     actor,
		ObjectID:  objectID,
		Metadata:  metadata,
		CreatedAt: time.Now().UTC(),
	})
	if len(a.store.auditEvents) > maxAuditEvents {
		a.store.auditEvents = append([]*AuditEvent(nil), a.store.auditEvents[len(a.store.auditEvents)-maxAuditEvents:]...)
	}
}

func (a *App) auditWorkerAuthFailure(workerID, reason string) {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.appendAuditLocked("worker_auth_failed", "worker:"+workerID, workerID, map[string]interface{}{"reason": reason})
}

func (a *App) saveWorkerStatusState() error {
	if strings.TrimSpace(a.workerStatusStateFile) == "" {
		return nil
	}
	a.store.mu.RLock()
	snapshot := make(map[string]*WorkerStatus, len(a.store.workerStatus))
	for k, v := range a.store.workerStatus {
		if v == nil {
			continue
		}
		c := *v
		snapshot[k] = &c
	}
	a.store.mu.RUnlock()
	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.workerStatusStateFile, b, 0o600)
}

func (a *App) loadWorkerStatusState() error {
	path := strings.TrimSpace(a.workerStatusStateFile)
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytesTrimSpace(b)) == 0 {
		return nil
	}
	var state map[string]*WorkerStatus
	if err := json.Unmarshal(b, &state); err != nil {
		return err
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	for k, v := range state {
		if k == "" || v == nil || v.WorkerID == "" {
			continue
		}
		c := *v
		a.store.workerStatus[k] = &c
	}
	return nil
}

func bytesTrimSpace(in []byte) []byte {
	return []byte(strings.TrimSpace(string(in)))
}

func randomID(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func signHeartbeat(secret, workerID, timestamp, nonce, policyID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(workerID + "|" + timestamp + "|" + nonce + "|" + policyID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func signPolicySignature(secret, ownerID string, rules map[string]interface{}) string {
	payload, _ := json.Marshal(rules)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ownerID + "|" + string(payload)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func signConsentSignature(secret, ownerID, workerID, policyID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ownerID + "|" + workerID + "|" + policyID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func verifyPolicySignature(secret, ownerID string, rules map[string]interface{}, signature string) bool {
	expected := signPolicySignature(secret, ownerID, rules)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func verifyConsentSignature(secret, ownerID, workerID, policyID, signature string) bool {
	expected := signConsentSignature(secret, ownerID, workerID, policyID)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func verifyHeartbeatSignature(secret, workerID, timestamp, nonce, policyID, signature string) bool {
	expected := signHeartbeat(secret, workerID, timestamp, nonce, policyID)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func validatePolicyRules(rules map[string]interface{}) error {
	if rules == nil {
		return fmt.Errorf("rules are required")
	}

	allowed := map[string]struct{}{
		"max_cpu_percent":    {},
		"max_memory_percent": {},
		"max_gpu_percent":    {},
		"timezone":           {},
		"allowed_hours":      {},
	}
	for k := range rules {
		if _, ok := allowed[k]; !ok {
			return fmt.Errorf("unsupported policy field: %s", k)
		}
	}

	if v, ok := rules["max_cpu_percent"]; ok {
		n, ok := asFloat(v)
		if !ok || n < 1 || n > 100 {
			return fmt.Errorf("max_cpu_percent must be between 1 and 100")
		}
	} else {
		return fmt.Errorf("max_cpu_percent is required")
	}

	if v, ok := rules["max_memory_percent"]; ok {
		n, ok := asFloat(v)
		if !ok || n < 1 || n > 100 {
			return fmt.Errorf("max_memory_percent must be between 1 and 100")
		}
	}

	if v, ok := rules["max_gpu_percent"]; ok {
		n, ok := asFloat(v)
		if !ok || n < 1 || n > 100 {
			return fmt.Errorf("max_gpu_percent must be between 1 and 100")
		}
	}

	if v, ok := rules["timezone"]; ok {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return fmt.Errorf("timezone must be a non-empty string")
		}
	}

	if v, ok := rules["allowed_hours"]; ok {
		arr, ok := v.([]interface{})
		if !ok || len(arr) == 0 || len(arr) > 24 {
			return fmt.Errorf("allowed_hours must be a non-empty array")
		}
		for _, raw := range arr {
			hour, ok := asFloat(raw)
			if !ok || int(hour) < 0 || int(hour) > 23 || hour != float64(int(hour)) {
				return fmt.Errorf("allowed_hours values must be integers between 0 and 23")
			}
		}
	}

	return nil
}

func asFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}

func (a *App) maybeCleanupNoncesLocked(now time.Time) {
	if now.Sub(a.store.lastNonceCleanup) < nonceCleanupInterval {
		return
	}
	for k, rec := range a.store.nonces {
		if now.Sub(rec.SeenAt) > nonceReplayWindow {
			delete(a.store.nonces, k)
		}
	}
	a.store.lastNonceCleanup = now
}

func (a *App) reserveNonceLocalLocked(now time.Time, nonceKey string) bool {
	a.maybeCleanupNoncesLocked(now)
	if _, exists := a.store.nonces[nonceKey]; exists {
		return false
	}
	a.store.nonces[nonceKey] = nonceRecord{SeenAt: now}
	return true
}

func (a *App) reserveNonceRedis(ctx context.Context, nonceKey string) (bool, error) {
	if a.redisClient == nil {
		return false, nil
	}
	key := "hf:nonce:" + nonceKey
	ok, err := a.redisClient.SetNX(ctx, key, "1", nonceReplayWindow).Result()
	return ok, err
}

func decodeJSON(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("unexpected trailing json")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, APIResponse{Success: false, Error: msg})
}

func (a *App) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := randomID(8)
		r.Header.Set("X-Request-ID", rid)
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r)
	})
}

func requestIDFromHeader(r *http.Request) string {
	if rid := r.Header.Get("X-Request-ID"); rid != "" {
		return rid
	}
	return "-"
}

func ownerIDFromHeader(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Owner-ID"))
}

func (a *App) workerLock(workerID string) *sync.Mutex {
	v, _ := a.workerLocks.LoadOrStore(workerID, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (a *App) authRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		provided := strings.TrimPrefix(auth, "Bearer ")
		if !hmac.Equal([]byte(provided), []byte(a.apiToken)) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func (a *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("request_id=%s method=%s path=%s duration=%s", requestIDFromHeader(r), r.Method, r.URL.Path, time.Since(start))
	})
}

func (a *App) bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) tlsEnforcementMiddleware(next http.Handler) http.Handler {
	requireHTTPS := strings.EqualFold(envOrDefault("REQUIRE_HTTPS", "false"), "true")
	trustProxy := strings.EqualFold(envOrDefault("TRUST_PROXY_HEADERS", "false"), "true")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireHTTPS {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}
		if trustProxy {
			proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
			if proto == "https" {
				next.ServeHTTP(w, r)
				return
			}
		}
		writeError(w, http.StatusUpgradeRequired, "https required")
	})
}

func (a *App) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		key := clientIP(r.RemoteAddr)
		if key == "" {
			key = "unknown"
		}
		allowed, denyStatus := a.allowRequest(r.Context(), key)
		if !allowed {
			status := denyStatus
			if status == 0 {
				status = http.StatusTooManyRequests
			}
			writeError(w, status, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) allowRequest(ctx context.Context, key string) (bool, int) {
	if a.redisRateLimitEnabled && a.redisClient != nil {
		ok, err := a.allowRequestRedis(ctx, key)
		if err == nil {
			if !ok {
				return false, http.StatusTooManyRequests
			}
			return true, 0
		}
		if !a.redisRateLimitFallback {
			log.Printf("warning: redis rate limit backend unavailable: %v", err)
			return false, http.StatusServiceUnavailable
		}
		log.Printf("warning: redis rate limit failed, falling back local: %v", err)
	}

	ok := a.allowRequestLocal(key)
	if !ok {
		return false, http.StatusTooManyRequests
	}
	return true, 0
}

func (a *App) allowRequestRedis(ctx context.Context, key string) (bool, error) {
	windowSec := int(a.redisRateLimitWindow.Seconds())
	if windowSec < 1 {
		windowSec = 1
	}
	nowSec := time.Now().Unix()
	redisKey := fmt.Sprintf("hf:rl:%s:%d", key, nowSec)

	pipe := a.redisClient.TxPipeline()
	incr := pipe.Incr(ctx, redisKey)
	pipe.Expire(ctx, redisKey, time.Duration(windowSec)*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}
	return int(incr.Val()) <= a.redisRateLimitMax, nil
}

func (a *App) allowRequestLocal(key string) bool {
	now := time.Now()
	a.rateMu.Lock()
	defer a.rateMu.Unlock()

	a.cleanupRateBucketsLocked(now)

	bucket, ok := a.rateBuckets[key]
	if !ok {
		if len(a.rateBuckets) >= maxRateBuckets {
			key = "_overflow_shared"
			bucket, ok = a.rateBuckets[key]
		}
		if !ok {
			a.rateBuckets[key] = &tokenBucket{Tokens: rateLimitBurst - 1, LastRefill: now, LastSeen: now}
			return true
		}
	}

	elapsed := now.Sub(bucket.LastRefill).Seconds()
	bucket.Tokens = minFloat(rateLimitBurst, bucket.Tokens+(elapsed*rateLimitRefillPerSecond))
	bucket.LastRefill = now
	bucket.LastSeen = now
	if bucket.Tokens < 1 {
		return false
	}
	bucket.Tokens -= 1
	return true
}

func (a *App) cleanupRateBucketsLocked(now time.Time) {
	for k, b := range a.rateBuckets {
		if now.Sub(b.LastSeen) > rateBucketTTL {
			delete(a.rateBuckets, k)
		}
	}
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func (a *App) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if _, ok := a.allowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Machine-Token, X-Machine-Certificate-Id")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
