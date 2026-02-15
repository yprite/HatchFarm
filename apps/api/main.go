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
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	version                  = "0.3.0"
	maxBodyBytes             = 1 << 20 // 1MB
	heartbeatMaxSkew         = 90 * time.Second
	nonceReplayWindow        = 5 * time.Minute
	rateLimitRefillPerSecond = 5.0
	rateLimitBurst           = 20.0
	rateBucketTTL            = 10 * time.Minute
	maxRateBuckets           = 20000
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

type Store struct {
	mu          sync.RWMutex
	machines    map[string]*Machine
	policies    map[string]*Policy
	consents    map[string]*Consent
	auditEvents []*AuditEvent
	nonces      map[string]nonceRecord
}

type App struct {
	store          *Store
	apiToken       string
	allowedOrigins map[string]struct{}
	startedAt      time.Time
	rateMu         sync.Mutex
	rateBuckets    map[string]*tokenBucket
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
		Handler:      app.corsMiddleware(app.loggingMiddleware(app.bodyLimitMiddleware(app.rateLimitMiddleware(mux)))),
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

	log.Println("Server exited")
}

func newApp() *App {
	apiToken := os.Getenv("HATCHFARM_API_TOKEN")
	if apiToken == "" {
		apiToken = "boot_" + randomID(16)
		log.Printf("warning: HATCHFARM_API_TOKEN not set; generated ephemeral token")
	}

	origins := map[string]struct{}{}
	for _, origin := range strings.Split(envOrDefault("ALLOWED_ORIGINS", "http://localhost:3000"), ",") {
		o := strings.TrimSpace(origin)
		if o != "" {
			origins[o] = struct{}{}
		}
	}

	return &App{
		store: &Store{
			machines: map[string]*Machine{},
			policies: map[string]*Policy{},
			consents: map[string]*Consent{},
			nonces:   map[string]nonceRecord{},
		},
		apiToken:       apiToken,
		allowedOrigins: origins,
		startedAt:      time.Now().UTC(),
		rateBuckets:    map[string]*tokenBucket{},
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (a *App) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.healthHandler)
	mux.HandleFunc("/api/v1/status", a.statusHandler)
	mux.HandleFunc("/api/v1/machines/register", a.authRequired(a.registerMachineHandler))
	mux.HandleFunc("/api/v1/policies", a.authRequired(a.createPolicyHandler))
	mux.HandleFunc("/api/v1/policies/", a.authRequired(a.activatePolicyHandler))
	mux.HandleFunc("/api/v1/consents", a.authRequired(a.createConsentHandler))
	mux.HandleFunc("/api/v1/consents/", a.authRequired(a.revokeConsentHandler))
	mux.HandleFunc("/api/v1/workers/", a.heartbeatHandler)
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

	id := "wrk_" + randomID(8)
	secret := randomID(24)
	m := &Machine{ID: id, OwnerID: req.OwnerID, Name: req.Name, Secret: secret, CreatedAt: time.Now().UTC()}

	a.store.mu.Lock()
	a.store.machines[id] = m
	a.appendAuditLocked("machine_registered", "owner:"+req.OwnerID, id, map[string]interface{}{"name": req.Name})
	a.store.mu.Unlock()

	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: map[string]interface{}{"machine": m, "machine_token": secret}})
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

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	latest := 0
	for _, p := range a.store.policies {
		if p.OwnerID == req.OwnerID && p.Version > latest {
			latest = p.Version
		}
	}

	id := "pol_" + randomID(8)
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

	consent := &Consent{
		ID:          "con_" + randomID(8),
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

	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	consent, ok := a.store.consents[id]
	if !ok {
		writeError(w, http.StatusNotFound, "consent not found")
		return
	}
	now := time.Now().UTC()
	consent.RevokedAt = &now
	a.appendAuditLocked("consent_revoked", "owner:"+consent.OwnerID, id, map[string]interface{}{"worker_id": consent.WorkerID})
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: consent})
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
	if machineToken == "" || req.Timestamp == "" || req.Nonce == "" || req.PolicyID == "" || req.Signature == "" {
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

	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	machine, ok := a.store.machines[workerID]
	if !ok || machine.Secret != machineToken {
		writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
		return
	}

	if !verifyHeartbeatSignature(machine.Secret, workerID, req.Timestamp, req.Nonce, req.PolicyID, req.Signature) {
		writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
		return
	}

	a.cleanupNoncesLocked(now)
	nonceKey := workerID + ":" + req.Nonce
	if _, exists := a.store.nonces[nonceKey]; exists {
		writeError(w, http.StatusUnauthorized, "invalid heartbeat auth")
		return
	}
	a.store.nonces[nonceKey] = nonceRecord{SeenAt: now}

	consentActive := false
	for _, c := range a.store.consents {
		if c.WorkerID == workerID && c.PolicyID == req.PolicyID && c.RevokedAt == nil {
			consentActive = true
			break
		}
	}
	if !consentActive {
		writeError(w, http.StatusForbidden, "no active consent for worker/policy")
		return
	}

	a.appendAuditLocked("worker_heartbeat", "worker:"+workerID, workerID, map[string]interface{}{"policy_id": req.PolicyID})
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]interface{}{"worker_id": workerID, "accepted": true}})
}

func (a *App) auditEventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]interface{}{"events": a.store.auditEvents}})
}

func (a *App) appendAuditLocked(eventType, actor, objectID string, metadata map[string]interface{}) {
	a.store.auditEvents = append(a.store.auditEvents, &AuditEvent{
		ID:        "aud_" + randomID(8),
		Type:      eventType,
		Actor:     actor,
		ObjectID:  objectID,
		Metadata:  metadata,
		CreatedAt: time.Now().UTC(),
	})
}

func randomID(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func signHeartbeat(secret, workerID, timestamp, nonce, policyID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(workerID + "|" + timestamp + "|" + nonce + "|" + policyID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func verifyHeartbeatSignature(secret, workerID, timestamp, nonce, policyID, signature string) bool {
	expected := signHeartbeat(secret, workerID, timestamp, nonce, policyID)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func (a *App) cleanupNoncesLocked(now time.Time) {
	for k, rec := range a.store.nonces {
		if now.Sub(rec.SeenAt) > nonceReplayWindow {
			delete(a.store.nonces, k)
		}
	}
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
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
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
		if !a.allowRequest(key) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) allowRequest(key string) bool {
	now := time.Now()
	a.rateMu.Lock()
	defer a.rateMu.Unlock()

	a.cleanupRateBucketsLocked(now)

	bucket, ok := a.rateBuckets[key]
	if !ok {
		if len(a.rateBuckets) >= maxRateBuckets {
			return false
		}
		a.rateBuckets[key] = &tokenBucket{Tokens: rateLimitBurst - 1, LastRefill: now, LastSeen: now}
		return true
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Machine-Token")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
