/*
Copyright © 2025 ESO Maintainer Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

const (
	minRenewalCheckInterval      = 100 * time.Millisecond
	defaultTokenOperationTimeout = 5 * time.Second
	renewalFailureThreshold      = 3
)

// ManagedClientCallbacks provides hooks for the ManagedClient to coordinate
// with the pool without tight coupling. These callbacks allow the pool to
// respond to events without the ManagedClient knowing about pool internals.
type ManagedClientCallbacks struct {
	// OnEvictionNeeded is called when the ManagedClient determines it should
	// be evicted from the pool (e.g., due to repeated renewal failures).
	// The pool should remove this client from the cache.
	OnEvictionNeeded func(key VaultClientCacheKey)
}

func clampRenewalInterval(d time.Duration) time.Duration {
	if d < minRenewalCheckInterval {
		return minRenewalCheckInterval
	}
	return d
}

func jsonNumberToInt64(raw interface{}) (int64, error) {
	switch v := raw.(type) {
	case json.Number:
		return v.Int64()
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("unexpected numeric type %T", raw)
	}
}

// ManagedClient wraps a Vault client with automatic token renewal and re-authentication backoff.
// This is a self-contained object that manages its own lifecycle, including running a renewal
// goroutine if enabled. It uses callbacks to coordinate with the pool without tight coupling.
type ManagedClient struct {
	client    util.Client
	config    AcquireClientConfig
	cacheKey  VaultClientCacheKey
	callbacks ManagedClientCallbacks

	// Token renewal
	stopRenewal     chan struct{}
	stopRenewalOnce sync.Once
	renewalEnabled  bool
	lastRenewed     time.Time
	renewalMu       sync.RWMutex

	// Renewal configuration
	renewalThresholdPercent int
	renewalCheckInterval    time.Duration

	// Re-authentication backoff
	reauthAttempts    int32
	lastReauthAttempt time.Time
	reauthAttemptMu   sync.RWMutex
	reauthBackoffBase time.Duration
	reauthBackoffMax  time.Duration

	// Token operation timeout
	tokenOperationTimeout time.Duration

	// Reference counting for safe eviction
	activeUsers     int32
	renewalFailures int32
	evicted         int32
	finalizeOnce    sync.Once
}

// ManagedClientConfig configures a ManagedClient instance.
type ManagedClientConfig struct {
	Client                  util.Client
	Config                  AcquireClientConfig
	CacheKey                VaultClientCacheKey
	Callbacks               ManagedClientCallbacks
	EnableRenewal           bool
	RenewalThresholdPercent int
	RenewalCheckInterval    time.Duration
	ReauthBackoffBase       time.Duration
	ReauthBackoffMax        time.Duration
	TokenOperationTimeout   time.Duration
}

// NewManagedClient creates a new managed Vault client.
// If EnableRenewal is true, this will start a background goroutine to manage token renewal.
// The goroutine is owned by the ManagedClient and will be stopped when Close() is called.
func NewManagedClient(cfg ManagedClientConfig) *ManagedClient {
	timeout := cfg.TokenOperationTimeout
	if timeout == 0 {
		timeout = defaultTokenOperationTimeout
	}
	mc := &ManagedClient{
		client:                  cfg.Client,
		config:                  cfg.Config,
		cacheKey:                cfg.CacheKey,
		callbacks:               cfg.Callbacks,
		renewalEnabled:          cfg.EnableRenewal,
		renewalThresholdPercent: cfg.RenewalThresholdPercent,
		renewalCheckInterval:    cfg.RenewalCheckInterval,
		reauthBackoffBase:       cfg.ReauthBackoffBase,
		reauthBackoffMax:        cfg.ReauthBackoffMax,
		tokenOperationTimeout:   timeout,
		stopRenewal:             make(chan struct{}),
	}

	// Start renewal goroutine if enabled - ManagedClient owns its lifecycle
	if cfg.EnableRenewal {
		go mc.renewalLoop()
	}

	return mc
}

// Client returns the underlying Vault client.
func (m *ManagedClient) Client() util.Client {
	return m.client
}

// CacheKey returns the cache key for this client.
func (m *ManagedClient) CacheKey() VaultClientCacheKey {
	return m.cacheKey
}

// Acquire increments the active users count.
// This is called when a client is acquired from the pool.
func (m *ManagedClient) Acquire() {
	atomic.AddInt32(&m.activeUsers, 1)
}

// Release decrements the active users count.
// Returns true if the client should be finalized (refcount is 0 and evicted).
// This is called when a client is released back to the pool.
func (m *ManagedClient) Release() bool {
	remaining := atomic.AddInt32(&m.activeUsers, -1)
	isEvicted := atomic.LoadInt32(&m.evicted) == 1
	return remaining == 0 && isEvicted
}

// activeCount returns the current number of active users (internal use).
func (m *ManagedClient) activeCount() int32 {
	return atomic.LoadInt32(&m.activeUsers)
}

// markEvicted marks this client as evicted from the cache.
// This is called internally when eviction is needed.
func (m *ManagedClient) markEvicted() {
	atomic.StoreInt32(&m.evicted, 1)
}

// isEvicted returns true if this client has been evicted (internal use).
func (m *ManagedClient) isEvicted() bool {
	return atomic.LoadInt32(&m.evicted) == 1
}

// ShouldAttemptReauth checks if re-authentication should be attempted based on exponential backoff.
// Returns (shouldAttempt, backoffRemaining).
func (m *ManagedClient) ShouldAttemptReauth() (bool, time.Duration) {
	attempts := atomic.LoadInt32(&m.reauthAttempts)
	if attempts == 0 {
		return true, 0
	}

	// Calculate exponential backoff: base * 2^attempts
	backoff := m.reauthBackoffBase * (1 << attempts)
	if backoff > m.reauthBackoffMax {
		backoff = m.reauthBackoffMax
	}

	m.reauthAttemptMu.RLock()
	lastAttempt := m.lastReauthAttempt
	m.reauthAttemptMu.RUnlock()

	if lastAttempt.IsZero() {
		return true, 0
	}

	elapsed := time.Since(lastAttempt)
	if elapsed >= backoff {
		return true, 0
	}

	return false, backoff - elapsed
}

// RecordReauthAttempt records a re-authentication attempt timestamp.
func (m *ManagedClient) RecordReauthAttempt() {
	m.reauthAttemptMu.Lock()
	defer m.reauthAttemptMu.Unlock()
	m.lastReauthAttempt = time.Now()
}

// IncrementReauthAttempts increments the consecutive re-auth failure count.
func (m *ManagedClient) IncrementReauthAttempts() int32 {
	return atomic.AddInt32(&m.reauthAttempts, 1)
}

// ResetReauthAttempts resets the re-auth attempt counter.
func (m *ManagedClient) ResetReauthAttempts() {
	atomic.StoreInt32(&m.reauthAttempts, 0)
}

// GetReauthAttempts returns the current re-auth attempt count.
func (m *ManagedClient) GetReauthAttempts() int32 {
	return atomic.LoadInt32(&m.reauthAttempts)
}

// incrementRenewalFailure increments the renewal failure counter (internal use).
func (m *ManagedClient) incrementRenewalFailure() int32 {
	return atomic.AddInt32(&m.renewalFailures, 1)
}

// resetRenewalFailures resets the renewal failure counter (internal use).
func (m *ManagedClient) resetRenewalFailures() {
	atomic.StoreInt32(&m.renewalFailures, 0)
}

// UpdateConfig updates the cached configuration (used after successful re-auth).
func (m *ManagedClient) UpdateConfig(config AcquireClientConfig) {
	m.renewalMu.Lock()
	defer m.renewalMu.Unlock()
	m.config = config
	m.lastRenewed = time.Now()
}

// stopRenewalGoroutine stops the token renewal goroutine (internal use).
func (m *ManagedClient) stopRenewalGoroutine() {
	m.stopRenewalOnce.Do(func() {
		close(m.stopRenewal)
	})
}

// computeRenewalThresholdSeconds calculates the renewal threshold in seconds.
func (m *ManagedClient) computeRenewalThresholdSeconds(creationTTL int64) (int64, bool) {
	if m.renewalThresholdPercent <= 0 || creationTTL <= 0 {
		return 0, false
	}
	threshold := (creationTTL * int64(m.renewalThresholdPercent)) / 100
	if threshold <= 0 {
		threshold = 1
	}
	return threshold, true
}

// calculateCheckInterval computes the next renewal check interval based on token TTL (internal use).
func (m *ManagedClient) calculateCheckInterval(ctx context.Context) time.Duration {
	if m.renewalThresholdPercent <= 0 {
		return clampRenewalInterval(m.renewalCheckInterval)
	}

	resp, err := m.client.AuthToken().LookupSelfWithContext(ctx)
	if err != nil {
		logger.V(1).Info("failed to lookup token for dynamic interval calculation", "err", err)
		return clampRenewalInterval(m.renewalCheckInterval)
	}

	if resp == nil || resp.Data == nil {
		return clampRenewalInterval(m.renewalCheckInterval)
	}

	ttlRaw, ok := resp.Data["ttl"]
	if !ok {
		return clampRenewalInterval(m.renewalCheckInterval)
	}
	ttlSeconds, err := jsonNumberToInt64(ttlRaw)
	if err != nil {
		return clampRenewalInterval(m.renewalCheckInterval)
	}

	creationTTLRaw, ok := resp.Data["creation_ttl"]
	if !ok {
		return clampRenewalInterval(m.renewalCheckInterval)
	}
	creationTTL, err := jsonNumberToInt64(creationTTLRaw)
	if err != nil {
		return clampRenewalInterval(m.renewalCheckInterval)
	}

	thresholdSeconds, ok := m.computeRenewalThresholdSeconds(creationTTL)
	if !ok {
		return clampRenewalInterval(m.renewalCheckInterval)
	}

	intervalSeconds := ttlSeconds - thresholdSeconds
	if intervalSeconds <= 0 {
		return minRenewalCheckInterval
	}

	interval := time.Duration(intervalSeconds) * time.Second
	return clampRenewalInterval(interval)
}

// checkAndRenew checks if the token needs renewal and renews it if necessary (internal use).
func (m *ManagedClient) checkAndRenew(ctx context.Context) error {
	m.renewalMu.Lock()
	defer m.renewalMu.Unlock()

	resp, err := m.client.AuthToken().LookupSelfWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to lookup token: %w", err)
	}

	if resp == nil || resp.Data == nil {
		return fmt.Errorf("invalid token lookup response")
	}

	renewableRaw, ok := resp.Data["renewable"]
	if !ok {
		m.resetRenewalFailures()
		return nil
	}
	renewable, ok := renewableRaw.(bool)
	if !ok || !renewable {
		m.resetRenewalFailures()
		return nil
	}

	ttlRaw, ok := resp.Data["ttl"]
	if !ok {
		return fmt.Errorf("no TTL in token response")
	}
	ttlSeconds, err := jsonNumberToInt64(ttlRaw)
	if err != nil {
		return fmt.Errorf("invalid TTL: %w", err)
	}

	creationTTLRaw, ok := resp.Data["creation_ttl"]
	if !ok {
		return fmt.Errorf("no creation_ttl in token response")
	}
	creationTTL, err := jsonNumberToInt64(creationTTLRaw)
	if err != nil {
		return fmt.Errorf("invalid creation_ttl: %w", err)
	}

	thresholdSeconds, ok := m.computeRenewalThresholdSeconds(creationTTL)
	if !ok {
		fallbackThreshold := clampRenewalInterval(m.renewalCheckInterval)
		thresholdSeconds = int64(fallbackThreshold / time.Second)
		if thresholdSeconds <= 0 {
			thresholdSeconds = 1
		}
	}

	if ttlSeconds > thresholdSeconds {
		m.resetRenewalFailures()
		return nil
	}

	logger.V(1).Info("renewing token", "key", m.cacheKey.String(), "ttl", ttlSeconds, "threshold", thresholdSeconds)

	_, err = m.client.AuthToken().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}

	m.lastRenewed = time.Now()
	m.resetRenewalFailures()
	logger.V(1).Info("token renewed successfully", "key", m.cacheKey.String())
	return nil
}

// ValidateToken checks if the current token is valid.
func (m *ManagedClient) ValidateToken(ctx context.Context) (bool, error) {
	return checkToken(ctx, m.client.AuthToken())
}

// Reauthenticate attempts to re-authenticate the client using fresh credentials.
// This is used when a cached client's token becomes invalid, ensuring that if credentials
// have been rotated in Kubernetes (e.g., AppRole secret, ServiceAccount token), we use
// the latest values.
func (m *ManagedClient) Reauthenticate(ctx context.Context, currentConfig AcquireClientConfig) error {
	// Record the re-auth attempt timestamp
	m.RecordReauthAttempt()

	// Use current config (with fresh credentials from K8s) instead of cached config
	c := &client{
		kube:      currentConfig.Kube,
		corev1:    currentConfig.CoreV1,
		store:     currentConfig.VaultProvider,
		namespace: currentConfig.Namespace,
		storeKind: currentConfig.StoreKind,
		client:    m.client,
		auth:      m.client.Auth(),
		logical:   m.client.Logical(),
		token:     m.client.AuthToken(),
		log:       logger,
	}

	reauthCtx, cancel := context.WithTimeout(ctx, m.tokenOperationTimeout)
	defer cancel()

	if err := c.setAuth(reauthCtx, currentConfig.VaultConfig); err != nil {
		// Increment failure count for backoff calculation
		m.IncrementReauthAttempts()
		return fmt.Errorf("failed to re-authenticate: %w", err)
	}

	// Update the cached config with fresh credentials for future renewals
	m.UpdateConfig(currentConfig)

	// Reset re-auth attempts on success
	m.ResetReauthAttempts()

	return nil
}

// renewalLoop runs in a goroutine to periodically check and renew tokens.
// This is owned by the ManagedClient and runs independently of the pool.
func (m *ManagedClient) renewalLoop() {
	// Calculate initial check interval
	ctx, cancel := context.WithTimeout(context.Background(), m.tokenOperationTimeout)
	checkInterval := m.calculateCheckInterval(ctx)
	cancel()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopRenewal:
			// Renewal goroutine stopped
			return
		case <-ticker.C:
			// Perform renewal check
			ctx, cancel := context.WithTimeout(context.Background(), m.tokenOperationTimeout)
			if err := m.checkAndRenew(ctx); err != nil {
				count := m.incrementRenewalFailure()
				logger.Error(err, "token renewal failed", "key", m.cacheKey.String())

				if count >= renewalFailureThreshold {
					logger.Error(err, "evicting client after repeated renewal failures", "key", m.cacheKey.String())

					// Mark as evicted and request eviction from pool
					m.markEvicted()
					if m.callbacks.OnEvictionNeeded != nil {
						m.callbacks.OnEvictionNeeded(m.cacheKey)
					}

					cancel()
					return
				}
			} else {
				m.resetRenewalFailures()
			}
			cancel()

			// Recalculate interval after renewal
			ctx, cancel = context.WithTimeout(context.Background(), m.tokenOperationTimeout)
			newInterval := m.calculateCheckInterval(ctx)
			cancel()

			if newInterval != checkInterval {
				ticker.Reset(newInterval)
				checkInterval = newInterval
			}
		}
	}
}

// Close performs cleanup operations for this client.
// This stops the renewal goroutine, revokes the token (if not a static token),
// and performs any other cleanup. This is called when the client is finalized.
func (m *ManagedClient) Close(ctx context.Context) error {
	var finalizeErr error
	m.finalizeOnce.Do(func() {
		// Stop renewal goroutine first
		m.stopRenewalGoroutine()

		// Only revoke if this is not a static token (TokenSecretRef)
		if m.config.VaultProvider.Auth == nil || m.config.VaultProvider.Auth.TokenSecretRef == nil {
			revokeCtx, cancel := context.WithTimeout(ctx, m.tokenOperationTimeout)
			defer cancel()

			if err := revokeTokenIfValid(revokeCtx, m.client); err != nil {
				logger.V(1).Info("failed to revoke token during finalization", "key", m.cacheKey.String(), "err", err)
				finalizeErr = fmt.Errorf("failed to revoke token: %w", err)
			} else {
				logger.V(1).Info("token revoked during finalization", "key", m.cacheKey.String())
			}
		} else {
			logger.V(1).Info("skipping token revocation for static token", "key", m.cacheKey.String())
		}
	})
	return finalizeErr
}
