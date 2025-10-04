package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/singleflight"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

var ErrNoManager = errors.New("session manager not initialised")

const (
	DefaultSafetyWindow      = time.Minute
	defaultSafetyWindow      = DefaultSafetyWindow
	invalidReasonFingerprint = "fingerprint"
	invalidReasonManual      = "manual"
	invalidReasonError       = "error"
)

type CleanupFunc func(context.Context, util.Client) error

type Request struct {
	Key         string
	Fingerprint string
	Scope       string
	BuildClient func() (util.Client, error)
	Cleanup     CleanupFunc
}

type Manager struct {
	mu           sync.RWMutex
	entries      map[string]*entry
	maxEntries   int
	safetyWindow time.Duration
	logger       logr.Logger
	flight       singleflight.Group
}

type entry struct {
	mu          sync.Mutex
	key         string
	fingerprint string
	client      util.Client
	lease       *Lease
	refs        int
	lastUsed    time.Time
	cleanup     CleanupFunc
	manager     *Manager
	invalid     bool
	scope       string
}

type Handle struct {
	entry *entry
	mgr   *Manager
}

func NewManager(maxEntries int, logger logr.Logger) *Manager {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	mgr := &Manager{
		entries:      make(map[string]*entry, maxEntries),
		maxEntries:   maxEntries,
		safetyWindow: defaultSafetyWindow,
		logger:       logger,
	}
	setCacheEntries(0)
	return mgr
}

func (m *Manager) SafetyWindow() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.safetyWindow
}

func (m *Manager) SetSafetyWindow(d time.Duration) {
	if d <= 0 {
		return
	}
	m.mu.Lock()
	m.safetyWindow = d
	m.mu.Unlock()
}

func (m *Manager) Acquire(ctx context.Context, req Request) (*Handle, error) {
	if req.BuildClient == nil {
		return nil, fmt.Errorf("nil BuildClient")
	}
	if handle := m.tryReuse(req); handle != nil {
		return handle, nil
	}

	result, err, _ := m.flight.Do(req.Key, func() (any, error) {
		return m.ensureEntry(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	ent := result.(*entry)
	handle, attachErr := m.attachHandle(ent)
	if attachErr != nil {
		return nil, attachErr
	}
	return handle, nil
}

func (m *Manager) tryReuse(req Request) *Handle {
	m.mu.RLock()
	e, ok := m.entries[req.Key]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.invalid || e.fingerprint != req.Fingerprint {
		return nil
	}
	if !e.shouldReuse(now, m.safetyWindow) {
		return nil
	}
	e.refs++
	e.lastUsed = now
	observeCacheHit(e.scope)
	m.logger.V(1).Info("vault session cache hit", "key", req.Key, "scope", e.scope)
	return &Handle{entry: e, mgr: m}
}

func (m *Manager) ensureEntry(ctx context.Context, req Request) (*entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.entries[req.Key]; ok {
		existing.mu.Lock()
		sameFingerprint := existing.fingerprint == req.Fingerprint && !existing.invalid
		scope := existing.scope
		existing.mu.Unlock()
		if sameFingerprint {
			observeCacheHit(scope)
			m.logger.V(1).Info("vault session cache reused after singleflight", "key", req.Key, "scope", scope)
			return existing, nil
		}
		m.removeEntry(ctx, req.Key, existing, invalidReasonFingerprint)
	}

	client, err := req.BuildClient()
	if err != nil {
		return nil, err
	}
	entry := &entry{
		key:         req.Key,
		fingerprint: req.Fingerprint,
		client:      client,
		lastUsed:    time.Now(),
		cleanup:     req.Cleanup,
		manager:     m,
		scope:       normalizeScope(req.Scope),
	}
	m.entries[req.Key] = entry
	m.evictIfNeeded(ctx)
	observeCacheMiss(entry.scope)
	m.logger.V(1).Info("vault session cache miss", "key", req.Key, "scope", entry.scope)
	setCacheEntries(float64(len(m.entries)))
	return entry, nil
}

// removeEntry assumes the caller already holds m.mu for writing.
func (m *Manager) removeEntry(ctx context.Context, key string, e *entry, reason string) {
	delete(m.entries, key)
	e.mu.Lock()
	if !e.invalid {
		e.invalid = true
	}
	e.mu.Unlock()
	go e.cleanupContext(ctx)
	observeCacheInvalidation(e.scope, reason)
	setCacheEntries(float64(len(m.entries)))
	m.logger.V(1).Info("vault session cache invalidated", "key", key, "scope", e.scope, "reason", reason)
}

func (m *Manager) attachHandle(e *entry) (*Handle, error) {
	now := time.Now()
	e.mu.Lock()
	if e.invalid || e.client == nil {
		e.mu.Unlock()
		return nil, fmt.Errorf("invalid entry state")
	}
	e.refs++
	e.lastUsed = now
	e.mu.Unlock()
	return &Handle{entry: e, mgr: m}, nil
}

// shouldReuse reports whether the cached lease is still considered safe for reuse.
// Caller must hold e.mu.
func (e *entry) shouldReuse(now time.Time, safetyWindow time.Duration) bool {
	if e == nil {
		return false
	}
	if e.client == nil {
		return false
	}
	if e.lease == nil {
		return false
	}
	return e.lease.IsUsable(now, safetyWindow)
}

func (e *entry) cleanupContext(ctx context.Context) {
	e.mu.Lock()
	cleanup := e.cleanup
	client := e.client
	e.mu.Unlock()
	if cleanup != nil {
		if err := cleanup(ctx, client); err != nil {
			e.manager.logger.Error(err, "cleanup failed", "key", e.key)
		}
	}
}

// evictIfNeeded presumes the caller holds m.mu for writing.
func (m *Manager) evictIfNeeded(ctx context.Context) {
	if m.maxEntries <= 0 {
		return
	}
	if len(m.entries) <= m.maxEntries {
		return
	}
	var oldest *entry
	for _, e := range m.entries {
		e.mu.Lock()
		if e.refs == 0 && !e.invalid {
			if oldest == nil || e.lastUsed.Before(oldest.lastUsed) {
				if oldest != nil {
					oldest.mu.Unlock()
				}
				oldest = e
				continue
			}
		}
		e.mu.Unlock()
	}
	if oldest != nil {
		key := oldest.key
		scope := oldest.scope
		oldest.invalid = true
		oldest.mu.Unlock()
		delete(m.entries, key)
		observeCacheEviction(scope)
		setCacheEntries(float64(len(m.entries)))
		m.logger.V(1).Info("vault session cache eviction", "key", key, "scope", scope)
		go oldest.cleanupContext(ctx)
	}
}

func (h *Handle) Client() util.Client {
	if h == nil || h.entry == nil {
		return nil
	}
	return h.entry.client
}

func (h *Handle) Lease() *Lease {
	if h == nil || h.entry == nil {
		return nil
	}
	h.entry.mu.Lock()
	defer h.entry.mu.Unlock()
	return h.entry.lease
}

func (h *Handle) UpdateLease(lease *Lease) {
	if h == nil || h.entry == nil {
		return
	}
	h.entry.mu.Lock()
	h.entry.lease = lease
	h.entry.lastUsed = time.Now()
	h.entry.mu.Unlock()
}

func (h *Handle) RefreshLease(ctx context.Context) (*Lease, error) {
	if h == nil || h.entry == nil {
		return nil, fmt.Errorf("nil handle")
	}
	lease, err := LookupLease(ctx, h.entry.client)
	if err != nil {
		return nil, err
	}
	h.UpdateLease(lease)
	return lease, nil
}

func (h *Handle) Invalidate(ctx context.Context) {
	if h == nil || h.entry == nil {
		return
	}
	h.entry.mu.Lock()
	if h.entry.invalid {
		h.entry.mu.Unlock()
		return
	}
	h.entry.invalid = true
	h.entry.mu.Unlock()

	h.mgr.mu.Lock()
	if existing, ok := h.mgr.entries[h.entry.key]; ok && existing == h.entry {
		h.mgr.removeEntry(ctx, h.entry.key, h.entry, invalidReasonManual)
	}
	h.mgr.mu.Unlock()
}

func (h *Handle) Release(ctx context.Context) {
	if h == nil || h.entry == nil {
		return
	}
	h.entry.mu.Lock()
	if h.entry.refs > 0 {
		h.entry.refs--
		h.entry.lastUsed = time.Now()
	}
	refs := h.entry.refs
	invalid := h.entry.invalid
	h.entry.mu.Unlock()

	if refs == 0 && invalid {
		h.mgr.mu.Lock()
		if existing, ok := h.mgr.entries[h.entry.key]; ok && existing == h.entry {
			h.mgr.removeEntry(ctx, h.entry.key, h.entry, invalidReasonError)
		}
		h.mgr.mu.Unlock()
	} else if refs == 0 {
		h.mgr.mu.Lock()
		h.mgr.evictIfNeeded(ctx)
		h.mgr.mu.Unlock()
	}
}
