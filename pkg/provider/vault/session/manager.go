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
	// Fast path: Check if we can reuse an existing, valid entry
	if handle := m.tryReuse(req); handle != nil {
		return handle, nil
	}

	// Slow path: Use singleflight to ensure only one goroutine creates the entry
	// for a given key, even if multiple goroutines request it simultaneously.
	// This prevents thundering herd on cache misses.
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
	// Don't reuse if entry is marked invalid or fingerprint changed
	if e.invalid || e.fingerprint != req.Fingerprint {
		return nil
	}
	// Don't reuse if token is expired or near expiration (within safety window)
	if !e.shouldReuse(now, m.safetyWindow) {
		return nil
	}
	// Entry is valid and safe to reuse - increment ref count
	e.refs++
	e.lastUsed = now
	observeCacheHit(e.scope)
	m.logger.V(1).Info("vault session cache hit", "key", req.Key, "scope", e.scope)
	return &Handle{entry: e, mgr: m}
}

func (m *Manager) ensureEntry(ctx context.Context, req Request) (*entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if another goroutine in the singleflight group already created this entry
	if existing, ok := m.entries[req.Key]; ok {
		existing.mu.Lock()
		sameFingerprint := existing.fingerprint == req.Fingerprint && !existing.invalid
		scope := existing.scope
		existing.mu.Unlock()
		if sameFingerprint {
			// Fingerprint matches - safe to reuse this entry
			observeCacheHit(scope)
			m.logger.V(1).Info("vault session cache reused after singleflight", "key", req.Key, "scope", scope)
			return existing, nil
		}
		// Fingerprint changed - config/version changed, invalidate and recreate
		m.removeEntry(ctx, req.Key, existing, invalidReasonFingerprint)
	}

	// No existing entry or fingerprint mismatch - create new client
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
	if e == nil || e.client == nil || e.lease == nil {
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
//
// Lock ordering: We iterate entries while holding m.mu (manager lock), then lock
// each entry individually. This is safe because:
//   - Callers always acquire m.mu before calling evictIfNeeded
//   - Other code paths that lock entries first (e.g., tryReuse) also acquire m.mu
//     before modifying m.entries
//
// The algorithm uses a "lock handoff" pattern:
//   - Lock each entry to inspect refs/lastUsed
//   - If this entry is older than our current oldest candidate, unlock the previous
//     oldest and keep this one locked (handoff)
//   - Otherwise unlock immediately
//   - At loop end, exactly one entry remains locked (the oldest eligible victim)
//   - We mark it invalid, unlock it, remove from map, and trigger async cleanup
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
		// Only consider entries with no active references and not already invalid
		if e.refs == 0 && !e.invalid {
			if oldest == nil || e.lastUsed.Before(oldest.lastUsed) {
				// This entry is older than our current candidate.
				// Unlock the previous oldest (if any) and transfer the lock to this one.
				if oldest != nil {
					oldest.mu.Unlock()
				}
				oldest = e
				continue // Keep 'e' locked as the new oldest candidate
			}
		}
		// Not a candidate or not older than current oldest - unlock immediately
		e.mu.Unlock()
	}
	if oldest != nil {
		// Extract metadata while still holding the entry lock
		key := oldest.key
		scope := oldest.scope
		oldest.invalid = true
		oldest.mu.Unlock()
		// Now safe to modify m.entries while holding m.mu
		delete(m.entries, key)
		observeCacheEviction(scope)
		setCacheEntries(float64(len(m.entries)))
		m.logger.V(1).Info("vault session cache eviction", "key", key, "scope", scope)
		// Cleanup (token revocation) happens asynchronously to avoid blocking
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

	// If this was the last reference and the entry was marked invalid (e.g., by
	// auth error), clean it up immediately. Otherwise, let it stay in cache.
	if refs == 0 && invalid {
		h.mgr.mu.Lock()
		if existing, ok := h.mgr.entries[h.entry.key]; ok && existing == h.entry {
			h.mgr.removeEntry(ctx, h.entry.key, h.entry, invalidReasonError)
		}
		h.mgr.mu.Unlock()
	} else if refs == 0 {
		// Entry now has zero refs but is still valid - check if we need to evict
		// something to stay within cache size limits
		h.mgr.mu.Lock()
		h.mgr.evictIfNeeded(ctx)
		h.mgr.mu.Unlock()
	}
}

// Shutdown revokes all cached Vault tokens and clears the cache.
// This should be called during controller shutdown to ensure tokens are properly
// cleaned up. The actual token revocation happens asynchronously.
//
// Note: This method should only be called once during shutdown. Concurrent
// operations (Acquire/Release) should not be performed during shutdown.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	entries := make([]*entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
	}
	// Clear the map to prevent new acquisitions during shutdown
	m.entries = make(map[string]*entry)
	setCacheEntries(0)
	m.mu.Unlock()

	m.logger.Info("shutting down vault session cache", "entries", len(entries))

	// Trigger cleanup for all entries asynchronously
	// We don't wait for completion to avoid blocking shutdown indefinitely
	for _, e := range entries {
		go e.cleanupContext(ctx)
	}
}
