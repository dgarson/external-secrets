package session

import (
	"context"
	"encoding/json"
	"errors"
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
