package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const stateSchemaVersion = 1

type persistedMachine struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
}

type persistedState struct {
	SchemaVersion int                            `json:"schema_version"`
	SavedAt       time.Time                      `json:"saved_at"`
	Machines      map[string]*persistedMachine   `json:"machines"`
	MachineCerts  map[string]*MachineCertificate `json:"machine_certs"`
	WorkerStatus  map[string]*WorkerStatus       `json:"worker_status"`
	Policies      map[string]*Policy             `json:"policies"`
	Consents      map[string]*Consent            `json:"consents"`
	AuditEvents   []*AuditEvent                  `json:"audit_events"`
}

func (a *App) loadPersistentState() error {
	if strings.TrimSpace(a.stateFile) != "" {
		if err := a.loadStateFile(a.stateFile); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		} else {
			return nil
		}
	}
	return a.loadWorkerStatusState()
}

func (a *App) savePersistentState() error {
	if strings.TrimSpace(a.stateFile) != "" {
		if err := a.saveStateFile(a.stateFile); err != nil {
			return err
		}
	}
	return a.saveWorkerStatusState()
}

func (a *App) saveStateFile(path string) error {
	state := a.snapshotState()
	state.SchemaVersion = stateSchemaVersion
	state.SavedAt = time.Now().UTC()

	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *App) loadStateFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(bytesTrimSpace(b)) == 0 {
		return nil
	}
	var state persistedState
	if err := json.Unmarshal(b, &state); err != nil {
		return err
	}
	if state.SchemaVersion != 0 && state.SchemaVersion != stateSchemaVersion {
		return fmt.Errorf("unsupported state schema version: %d", state.SchemaVersion)
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.machines = map[string]*Machine{}
	for k, v := range state.Machines {
		if v == nil || k == "" {
			continue
		}
		a.store.machines[k] = &Machine{ID: v.ID, OwnerID: v.OwnerID, Name: v.Name, Secret: v.Secret, CreatedAt: v.CreatedAt}
	}
	a.store.machineCerts = copyMachineCerts(state.MachineCerts)
	a.store.workerStatus = copyWorkerStatus(state.WorkerStatus)
	a.store.policies = copyPolicies(state.Policies)
	a.store.consents = copyConsents(state.Consents)
	a.store.auditEvents = copyAuditEvents(state.AuditEvents)
	return nil
}

func (a *App) snapshotState() *persistedState {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	state := &persistedState{
		Machines:     map[string]*persistedMachine{},
		MachineCerts: copyMachineCerts(a.store.machineCerts),
		WorkerStatus: copyWorkerStatus(a.store.workerStatus),
		Policies:     copyPolicies(a.store.policies),
		Consents:     copyConsents(a.store.consents),
		AuditEvents:  copyAuditEvents(a.store.auditEvents),
	}
	for k, v := range a.store.machines {
		if v == nil {
			continue
		}
		c := *v
		state.Machines[k] = &persistedMachine{ID: c.ID, OwnerID: c.OwnerID, Name: c.Name, Secret: c.Secret, CreatedAt: c.CreatedAt}
	}
	return state
}

func copyMachineCerts(in map[string]*MachineCertificate) map[string]*MachineCertificate {
	out := make(map[string]*MachineCertificate, len(in))
	for k, v := range in {
		if v == nil {
			continue
		}
		c := *v
		out[k] = &c
	}
	return out
}

func copyWorkerStatus(in map[string]*WorkerStatus) map[string]*WorkerStatus {
	out := make(map[string]*WorkerStatus, len(in))
	for k, v := range in {
		if v == nil {
			continue
		}
		c := *v
		out[k] = &c
	}
	return out
}

func copyPolicies(in map[string]*Policy) map[string]*Policy {
	out := make(map[string]*Policy, len(in))
	for k, v := range in {
		if v == nil {
			continue
		}
		c := *v
		if v.Rules != nil {
			rules := make(map[string]interface{}, len(v.Rules))
			for rk, rv := range v.Rules {
				rules[rk] = rv
			}
			c.Rules = rules
		}
		out[k] = &c
	}
	return out
}

func copyConsents(in map[string]*Consent) map[string]*Consent {
	out := make(map[string]*Consent, len(in))
	for k, v := range in {
		if v == nil {
			continue
		}
		c := *v
		if v.RevokedAt != nil {
			r := *v.RevokedAt
			c.RevokedAt = &r
		}
		out[k] = &c
	}
	return out
}

func copyAuditEvents(in []*AuditEvent) []*AuditEvent {
	out := make([]*AuditEvent, 0, len(in))
	for _, v := range in {
		if v == nil {
			continue
		}
		c := *v
		if v.Metadata != nil {
			m := make(map[string]interface{}, len(v.Metadata))
			for mk, mv := range v.Metadata {
				m[mk] = mv
			}
			c.Metadata = m
		}
		out = append(out, &c)
	}
	return out
}
