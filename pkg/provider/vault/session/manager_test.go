package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/fake"
	vaultutil "github.com/external-secrets/external-secrets/pkg/provider/vault/util"
	vault "github.com/hashicorp/vault/api"
)

func newClientBuilder(t *testing.T, calls *atomic.Int32) func() (vaultutil.Client, error) {
	return func() (vaultutil.Client, error) {
		calls.Add(1)
		client, err := fake.ClientWithLoginMock(nil)
		if err != nil {
			t.Fatalf("build client: %v", err)
		}
		return client, nil
	}
}

func TestManagerCacheHitsAndMisses(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	var cleanups atomic.Int32

	build := newClientBuilder(t, &builds)
	cleanup := func(_ context.Context, _ vaultutil.Client) error {
		cleanups.Add(1)
		return nil
	}

	req := Request{Key: "store|default|s1", Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: cleanup}
	reqEdge := req
	h1, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	h1.Release(ctx)

	if got := testutil.ToFloat64(cacheMisses.WithLabelValues("store")); got != 1 {
		t.Fatalf("expected 1 miss, got %.0f", got)
	}
	if builds.Load() != 1 {
		t.Fatalf("expected 1 build call, got %d", builds.Load())
	}
	if entries := testutil.ToFloat64(cacheEntries); entries != 1 {
		t.Fatalf("expected entries gauge 1, got %.0f", entries)
	}

	h2, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	h2.Release(ctx)

	if got := testutil.ToFloat64(cacheHits.WithLabelValues("store")); got != 1 {
		t.Fatalf("expected 1 hit, got %.0f", got)
	}
	if builds.Load() != 1 {
		t.Fatalf("expected no additional build calls, got %d", builds.Load())
	}
	if cleanups.Load() != 0 {
		t.Fatalf("expected no cleanup calls, got %d", cleanups.Load())
	}

	reqRev2 := req
	reqRev2.Fingerprint = "rev2"
	h3, err := mgr.Acquire(ctx, reqRev2)
	if err != nil {
		t.Fatalf("third acquire: %v", err)
	}
	h3.Release(ctx)
	missesBefore := testutil.ToFloat64(cacheMisses.WithLabelValues("store"))
	if missesBefore != 2 {
		t.Fatalf("expected 2 misses, got %.0f", missesBefore)
	}
	if got := testutil.ToFloat64(cacheInvalidations.WithLabelValues("store", invalidReasonFingerprint)); got != 1 {
		t.Fatalf("expected 1 fingerprint invalidation, got %.0f", got)
	}
	waitForAtomic(t, &cleanups, 1)
	if entries := testutil.ToFloat64(cacheEntries); entries != 1 {
		t.Fatalf("expected entries gauge 1 after invalidation, got %.0f", entries)
	}

	// Near-expiry lease should trigger an additional miss even with same fingerprint.
	mgr.SetSafetyWindow(2 * time.Minute)
	h4, err := mgr.Acquire(ctx, reqEdge)
	if err != nil {
		t.Fatalf("fourth acquire: %v", err)
	}
	lease := &Lease{Token: "tok", ExpiresAt: time.Now().Add(30 * time.Second)}
	h4.UpdateLease(lease)
	h4.Release(ctx)

	if got := testutil.ToFloat64(cacheMisses.WithLabelValues("store")); got != missesBefore+1 {
		t.Fatalf("expected additional miss for near-expiry lease, got %.0f", got)
	}
}

func TestManagerEvictionMetrics(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(1, logger)

	var builds atomic.Int32
	var cleanups atomic.Int32

	build := newClientBuilder(t, &builds)
	cleanup := func(_ context.Context, _ vaultutil.Client) error {
		cleanups.Add(1)
		return nil
	}

	req := Request{Key: "store|default|a", Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: cleanup}
	h1, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	h1.Release(ctx)

	reqB := Request{Key: "store|default|b", Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: cleanup}
	h2, err := mgr.Acquire(ctx, reqB)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	h2.Release(ctx)

	if got := testutil.ToFloat64(cacheMisses.WithLabelValues("store")); got != 2 {
		t.Fatalf("expected 2 misses after different keys, got %.0f", got)
	}
	if got := testutil.ToFloat64(cacheEvictions.WithLabelValues("store")); got != 1 {
		t.Fatalf("expected 1 eviction, got %.0f", got)
	}
	if entries := testutil.ToFloat64(cacheEntries); entries != 1 {
		t.Fatalf("expected entries gauge 1 after eviction, got %.0f", entries)
	}
	waitForAtomic(t, &cleanups, 1)
	if builds.Load() != 2 {
		t.Fatalf("expected 2 build calls, got %d", builds.Load())
	}
}

func TestHandleInvalidateMetrics(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(5, logger)

	var builds atomic.Int32
	var cleanups atomic.Int32

	build := newClientBuilder(t, &builds)
	cleanup := func(_ context.Context, _ vaultutil.Client) error {
		cleanups.Add(1)
		return nil
	}

	req := Request{Key: "store|default|invalidate", Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: cleanup}
	h, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	h.Invalidate(ctx)
	waitForAtomic(t, &cleanups, 1)

	if got := testutil.ToFloat64(cacheInvalidations.WithLabelValues("store", invalidReasonManual)); got != 1 {
		t.Fatalf("expected 1 manual invalidation, got %.0f", got)
	}
	if entries := testutil.ToFloat64(cacheEntries); entries != 0 {
		t.Fatalf("expected entries gauge 0 after invalidate, got %.0f", entries)
	}
	if builds.Load() != 1 {
		t.Fatalf("expected single build call, got %d", builds.Load())
	}

	// release should be a no-op
	h.Release(ctx)

	// Mark entry invalid then release to exercise invalidReasonError path.
	reqErr := Request{Key: "store|default|release", Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: func(context.Context, vaultutil.Client) error { return nil }}
	hErr, err := mgr.Acquire(ctx, reqErr)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	hErr.entry.mu.Lock()
	hErr.entry.invalid = true
	hErr.entry.mu.Unlock()
	hErr.Release(ctx)
	if got := testutil.ToFloat64(cacheInvalidations.WithLabelValues("store", invalidReasonError)); got < 1 {
		t.Fatalf("expected error invalidation after release, got %.0f", got)
	}
}

func TestSafetyWindowSetter(t *testing.T) {
	logger := testr.New(t)
	mgr := NewManager(5, logger)
	if got := mgr.SafetyWindow(); got != defaultSafetyWindow {
		t.Fatalf("expected default safety window %s, got %s", defaultSafetyWindow, got)
	}
	dur := 2 * time.Minute
	mgr.SetSafetyWindow(dur)
	if got := mgr.SafetyWindow(); got != dur {
		t.Fatalf("expected safety window %s, got %s", dur, got)
	}
}

func TestHandleAccessors(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(5, logger)

	build := func() (vaultutil.Client, error) {
		secret := &vault.Secret{Data: map[string]any{
			"ttl":         json.Number("300"),
			"expire_time": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			"type":        "service",
		}}
		buildFn := fake.ModifiableClientWithLoginMock(func(cl *fake.VaultClient) {
			cl.MockAuthToken = fake.Token{
				LookupSelfWithContextFn: func(context.Context) (*vault.Secret, error) {
					return secret, nil
				},
			}
			cl.MockToken = fake.NewTokenFn("tok")
		})
		return buildFn(nil)
	}

	req := Request{Key: "store|default|access", Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: func(context.Context, vaultutil.Client) error { return nil }}
	h, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if h.Client() == nil {
		t.Fatalf("expected non-nil client")
	}
	if h.Lease() != nil {
		t.Fatalf("expected initial lease to be nil")
	}

	lease := &Lease{Token: "tok", NonExpiring: true}
	h.UpdateLease(lease)
	if got := h.Lease(); got != lease {
		t.Fatalf("expected updated lease reference")
	}

	refreshed, err := h.RefreshLease(ctx)
	if err != nil {
		t.Fatalf("refresh lease: %v", err)
	}
	if refreshed == nil || refreshed.Token != "tok" {
		t.Fatalf("expected refreshed lease with token, got %#v", refreshed)
	}

	h.Release(ctx)
}

func TestAcquireBuildError(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(5, logger)

	req := Request{
		Key:         "store|default|fail",
		Fingerprint: "rev1",
		Scope:       "store",
		BuildClient: func() (vaultutil.Client, error) { return nil, errors.New("boom") },
	}
	if _, err := mgr.Acquire(ctx, req); err == nil {
		t.Fatalf("expected build error")
	}
	if entries := testutil.ToFloat64(cacheEntries); entries != 0 {
		t.Fatalf("expected no entries after build failure, got %.0f", entries)
	}
}

func TestShouldReuseLocked(t *testing.T) {
	now := time.Now()
	leaseFresh := &Lease{Token: "tok", ExpiresAt: now.Add(5 * time.Minute)}
	e := &entry{client: &vaultutil.VaultClient{}, lease: leaseFresh}
	if !e.shouldReuse(now, time.Minute) {
		t.Fatalf("expected reusable lease")
	}

	e = &entry{client: &vaultutil.VaultClient{}, lease: &Lease{Token: "tok", ExpiresAt: now.Add(30 * time.Second)}}
	if e.shouldReuse(now, time.Minute) {
		t.Fatalf("expected lease to be considered stale")
	}

	e = &entry{client: nil, lease: leaseFresh}
	if e.shouldReuse(now, time.Minute) {
		t.Fatalf("expected false when client missing")
	}

	e = &entry{client: &vaultutil.VaultClient{}, lease: nil}
	if e.shouldReuse(now, time.Minute) {
		t.Fatalf("expected false when lease missing")
	}
}

func TestNormalizeScope(t *testing.T) {
	if got := normalizeScope(""); got != "unknown" {
		t.Fatalf("expected unknown, got %s", got)
	}
	if got := normalizeScope("store"); got != "store" {
		t.Fatalf("expected same scope, got %s", got)
	}
}

func TestConcurrentAcquireSameKey(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	var cleanups atomic.Int32

	build := newClientBuilder(t, &builds)
	cleanup := func(_ context.Context, _ vaultutil.Client) error {
		cleanups.Add(1)
		return nil
	}

	const numGoroutines = 10
	req := Request{Key: "store|default|concurrent", Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: cleanup}

	// Launch multiple goroutines trying to acquire the same key simultaneously
	start := make(chan struct{})
	var wg sync.WaitGroup
	handles := make([]*Handle, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for signal to start
			h, err := mgr.Acquire(ctx, req)
			handles[idx] = h
			errors[idx] = err
		}(i)
	}

	// Release all goroutines at once to maximize concurrency
	close(start)
	wg.Wait()

	// Verify all succeeded
	for i, err := range errors {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", i, err)
		}
	}

	// Verify BuildClient was called exactly once due to singleflight
	if builds.Load() != 1 {
		t.Fatalf("expected 1 build call, got %d (singleflight failed)", builds.Load())
	}

	// All handles should reference the same entry
	firstEntry := handles[0].entry
	for i, h := range handles {
		if h.entry != firstEntry {
			t.Fatalf("handle %d has different entry pointer (expected shared entry)", i)
		}
	}

	// Release all handles
	for _, h := range handles {
		h.Release(ctx)
	}

	// No cleanups should happen yet since all releases should decrement refs to 0
	// but entry remains valid
	if cleanups.Load() != 0 {
		t.Fatalf("expected no cleanup calls after releases, got %d", cleanups.Load())
	}
}

func TestAuthErrorInvalidatesCache(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	build := newClientBuilder(t, &builds)
	cleanup := func(_ context.Context, _ vaultutil.Client) error { return nil }

	req := Request{Key: "store|default|autherr", Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: cleanup}
	h, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Verify initial cache miss
	if got := testutil.ToFloat64(cacheMisses.WithLabelValues("store")); got != 1 {
		t.Fatalf("expected 1 miss, got %.0f", got)
	}

	// Simulate the entry being acquired and used successfully initially
	lease := &Lease{Token: "tok", ExpiresAt: time.Now().Add(5 * time.Minute)}
	h.UpdateLease(lease)
	h.Release(ctx)

	// Acquire again - should hit cache
	h2, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if got := testutil.ToFloat64(cacheHits.WithLabelValues("store")); got != 1 {
		t.Fatalf("expected 1 hit, got %.0f", got)
	}

	// Now manually invalidate as if auth error occurred
	h2.Invalidate(ctx)

	if got := testutil.ToFloat64(cacheInvalidations.WithLabelValues("store", invalidReasonManual)); got != 1 {
		t.Fatalf("expected 1 manual invalidation, got %.0f", got)
	}

	// Next acquire should miss cache and create new entry
	h3, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("third acquire: %v", err)
	}
	h3.Release(ctx)

	if got := testutil.ToFloat64(cacheMisses.WithLabelValues("store")); got != 2 {
		t.Fatalf("expected 2 misses after invalidation, got %.0f", got)
	}

	// Verify BuildClient was called twice: once for initial, once after invalidation
	if builds.Load() != 2 {
		t.Fatalf("expected 2 build calls, got %d", builds.Load())
	}
}

func TestShutdown(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	var cleanups atomic.Int32

	build := newClientBuilder(t, &builds)
	cleanup := func(_ context.Context, _ vaultutil.Client) error {
		cleanups.Add(1)
		return nil
	}

	// Create several cache entries
	keys := []string{"store|ns1|s1", "store|ns2|s2", "store|ns3|s3"}
	for _, key := range keys {
		req := Request{Key: key, Fingerprint: "rev1", Scope: "store", BuildClient: build, Cleanup: cleanup}
		h, err := mgr.Acquire(ctx, req)
		if err != nil {
			t.Fatalf("acquire %s: %v", key, err)
		}
		h.Release(ctx)
	}

	if builds.Load() != 3 {
		t.Fatalf("expected 3 builds, got %d", builds.Load())
	}

	if entries := testutil.ToFloat64(cacheEntries); entries != 3 {
		t.Fatalf("expected 3 cache entries, got %.0f", entries)
	}

	// Shutdown should clear all entries and trigger cleanup
	mgr.Shutdown(ctx)

	// Verify cache is now empty
	if entries := testutil.ToFloat64(cacheEntries); entries != 0 {
		t.Fatalf("expected 0 entries after shutdown, got %.0f", entries)
	}

	// Wait for async cleanups to complete
	waitForAtomic(t, &cleanups, 3)

	// Verify all 3 entries were cleaned up
	if cleanups.Load() != 3 {
		t.Fatalf("expected 3 cleanup calls, got %d", cleanups.Load())
	}
}

func waitForAtomic(t *testing.T, v *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if v.Load() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected atomic value %d, got %d", want, v.Load())
}

// TestNewManagerDefaults tests edge cases in NewManager
func TestNewManagerDefaults(t *testing.T) {
	logger := testr.New(t)

	t.Run("negative maxEntries defaults to 4096", func(t *testing.T) {
		mgr := NewManager(-1, logger)
		if mgr.maxEntries != 4096 {
			t.Fatalf("expected maxEntries=4096, got %d", mgr.maxEntries)
		}
	})

	t.Run("zero maxEntries defaults to 4096", func(t *testing.T) {
		mgr := NewManager(0, logger)
		if mgr.maxEntries != 4096 {
			t.Fatalf("expected maxEntries=4096, got %d", mgr.maxEntries)
		}
	})
}

// TestSetSafetyWindowInvalid tests that invalid safety windows are rejected
func TestSetSafetyWindowInvalid(t *testing.T) {
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	original := mgr.SafetyWindow()

	mgr.SetSafetyWindow(-1 * time.Minute)
	if mgr.SafetyWindow() != original {
		t.Fatal("expected safety window to remain unchanged for negative duration")
	}

	mgr.SetSafetyWindow(0)
	if mgr.SafetyWindow() != original {
		t.Fatal("expected safety window to remain unchanged for zero duration")
	}

	mgr.SetSafetyWindow(5 * time.Minute)
	if mgr.SafetyWindow() != 5*time.Minute {
		t.Fatal("expected safety window to be updated")
	}
}

// TestHandleGettersEdgeCases covers edge cases in Handle getter methods
func TestHandleGettersEdgeCases(t *testing.T) {
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	build := newClientBuilder(t, &builds)

	req := Request{
		Key:         "key1",
		Fingerprint: "fp1",
		Scope:       "store",
		BuildClient: build,
	}

	h, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer h.Release(ctx)

	// Test Client() when entry has nil client
	h.entry.mu.Lock()
	h.entry.client = nil
	h.entry.mu.Unlock()

	if h.Client() != nil {
		t.Fatal("expected nil client")
	}

	// Test Lease() when entry has nil lease
	h.entry.mu.Lock()
	h.entry.lease = nil
	h.entry.mu.Unlock()

	if h.Lease() != nil {
		t.Fatal("expected nil lease")
	}
}

// TestRefreshLeaseErrorHandling tests error paths in RefreshLease
func TestRefreshLeaseErrorHandling(t *testing.T) {
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	build := func() (vaultutil.Client, error) {
		builds.Add(1)
		return nil, errors.New("build failed")
	}

	req := Request{
		Key:         "key1",
		Fingerprint: "fp1",
		Scope:       "store",
		BuildClient: build,
	}

	_, err := mgr.Acquire(ctx, req)
	if err == nil {
		t.Fatal("expected error from failed build")
	}
}

// TestInvalidateRaceCondition tests invalidation under concurrent access
func TestInvalidateRaceCondition(t *testing.T) {
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	build := newClientBuilder(t, &builds)

	req := Request{
		Key:         "key1",
		Fingerprint: "fp1",
		Scope:       "store",
		BuildClient: build,
	}

	h, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Concurrent invalidation while holding handle
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Invalidate(ctx)
		}()
	}
	wg.Wait()

	h.Release(ctx)

	// Verify invalidation worked
	h.entry.mu.Lock()
	isInvalid := h.entry.invalid
	h.entry.mu.Unlock()
	if !isInvalid {
		t.Fatal("expected entry to be invalid after concurrent invalidation")
	}
}

// TestUpdateLeaseEdgeCases tests edge cases in UpdateLease
func TestUpdateLeaseEdgeCases(t *testing.T) {
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	build := newClientBuilder(t, &builds)

	req := Request{
		Key:         "key1",
		Fingerprint: "fp1",
		Scope:       "store",
		BuildClient: build,
	}

	h, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer h.Release(ctx)

	// Test updating with nil lease (should not panic)
	h.UpdateLease(nil)

	// Test updating with valid lease
	newLease := &Lease{
		Token:       "new-token",
		NonExpiring: true,
	}
	h.UpdateLease(newLease)

	if h.Lease().Token != "new-token" {
		t.Fatal("expected lease to be updated")
	}
}

// TestAcquireWithFingerprintChange tests cache invalidation when fingerprint changes
func TestAcquireWithFingerprintChange(t *testing.T) {
	ResetMetricsForTest()
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(10, logger)

	var builds atomic.Int32
	build := newClientBuilder(t, &builds)

	req := Request{
		Key:         "key1",
		Fingerprint: "fp1",
		Scope:       "store",
		BuildClient: build,
	}

	h1, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	h1.Release(ctx)

	// Acquire with different fingerprint - should invalidate and rebuild
	req.Fingerprint = "fp2"
	h2, err := mgr.Acquire(ctx, req)
	if err != nil {
		t.Fatalf("acquire with new fingerprint: %v", err)
	}
	defer h2.Release(ctx)

	// Should have built twice (once per fingerprint)
	if builds.Load() != 2 {
		t.Fatalf("expected 2 builds for fingerprint change, got %d", builds.Load())
	}

	// Verify invalidation was recorded
	if got := testutil.ToFloat64(cacheInvalidations.WithLabelValues("store", invalidReasonFingerprint)); got != 1 {
		t.Fatalf("expected 1 fingerprint invalidation, got %.0f", got)
	}
}

// TestHandleNilCases covers nil handle edge cases
func TestHandleNilCases(t *testing.T) {
	var h *Handle

	// All methods should safely handle nil handle
	if h.Client() != nil {
		t.Fatal("expected nil client from nil handle")
	}
	if h.Lease() != nil {
		t.Fatal("expected nil lease from nil handle")
	}
	h.UpdateLease(&Lease{Token: "test"}) // Should not panic
	h.Invalidate(context.Background())    // Should not panic
	h.Release(context.Background())       // Should not panic

	_, err := h.RefreshLease(context.Background())
	if err == nil {
		t.Fatal("expected error from RefreshLease on nil handle")
	}
}

// TestCleanupErrorHandling tests cleanup function error handling
func TestCleanupErrorHandling(t *testing.T) {
	ctx := context.Background()
	logger := testr.New(t)
	mgr := NewManager(2, logger) // Small cache to force eviction

	var builds atomic.Int32
	var cleanupErr error = fmt.Errorf("cleanup failed")

	build := newClientBuilder(t, &builds)
	cleanup := func(_ context.Context, _ vaultutil.Client) error {
		return cleanupErr
	}

	// Create entries that will trigger cleanup
	for i := 0; i < 3; i++ {
		req := Request{
			Key:         fmt.Sprintf("key%d", i),
			Fingerprint: "fp1",
			Scope:       "store",
			BuildClient: build,
			Cleanup:     cleanup,
		}
		h, err := mgr.Acquire(ctx, req)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		h.Release(ctx)
	}

	// Wait for async cleanup
	time.Sleep(100 * time.Millisecond)

	// Should have evicted despite cleanup errors
	if got := testutil.ToFloat64(cacheEvictions.WithLabelValues("store")); got < 1 {
		t.Fatalf("expected at least 1 eviction, got %.0f", got)
	}
}
