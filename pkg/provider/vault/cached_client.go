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
	"strings"
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

// CachedClientDeps provides dependencies for the CachedClient to coordinate
// with the pool without tight coupling. These functions allow the CachedClient
// to perform actions without knowing about pool internals.
type CachedClientDeps struct {
	// onEvicted is called when the CachedClient determines it should be
	// evicted from the pool (e.g., due to repeated renewal failures).
	// The pool should remove this client from the cache.
	onEvicted func(key string)
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

// isPermanentAuthError checks if an error is a permanent authentication failure
// that should not be retried (e.g., permission denied, invalid credentials).
func isPermanentAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	// Check for permanent error indicators
	permanentPatterns := []string{
		"permission denied",
		"invalid credentials",
		"unauthorized",
		"authentication failed",
		"invalid token",
		"forbidden",
		"access denied",
	}
	for _, pattern := range permanentPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

// tokenMetadata contains parsed token information from a Vault token lookup response.
type tokenMetadata struct {
	ttl         int64
	creationTTL int64
	renewable   bool
}

// parseTokenMetadata extracts token metadata from a Vault token lookup response.
// This centralizes TTL parsing logic that was previously duplicated across multiple methods.
func parseTokenMetadata(data map[string]interface{}) (*tokenMetadata, error) {
	if data == nil {
		return nil, fmt.Errorf("nil token data")
	}

	meta := &tokenMetadata{}

	// Parse TTL (current time-to-live)
	if ttlRaw, ok := data["ttl"]; ok {
		ttl, err := jsonNumberToInt64(ttlRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl: %w", err)
		}
		meta.ttl = ttl
	}

	// Parse creation TTL (original TTL when token was created)
	if creationTTLRaw, ok := data["creation_ttl"]; ok {
		creationTTL, err := jsonNumberToInt64(creationTTLRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid creation_ttl: %w", err)
		}
		meta.creationTTL = creationTTL
	}

	// Parse renewable flag
	if renewableRaw, ok := data["renewable"]; ok {
		if renewable, ok := renewableRaw.(bool); ok {
			meta.renewable = renewable
		}
	}

	return meta, nil
}

// CachedClient wraps a Vault client with automatic token renewal and re-authentication.
// This is a self-contained object that manages its own lifecycle, including running a renewal
// goroutine if enabled. It uses dependency injection to coordinate with the pool without tight coupling.
type CachedClient struct {
	client   util.Client
	config   AcquireClientConfig
	cacheKey string
	deps     CachedClientDeps

	// Token renewal
	stopRenewal     chan struct{}
	stopRenewalOnce sync.Once
	renewalEnabled  bool
	nextRenewal     time.Time // When the next renewal should occur
	renewalMu       sync.RWMutex

	// Renewal configuration
	renewalThresholdPercent int
	renewalCheckInterval    time.Duration

	// Re-authentication coordination
	reauthMu sync.Mutex // Prevents concurrent re-authentication attempts

	// Token operation timeout
	tokenOperationTimeout time.Duration

	// Reference counting for safe eviction
	activeUsers     int32
	renewalFailures int32
	evicted         int32
	finalizeOnce    sync.Once
}

// CachedClientConfig configures a CachedClient instance.
type CachedClientConfig struct {
	Client                  util.Client
	Config                  AcquireClientConfig
	CacheKey                string
	Deps                    CachedClientDeps
	EnableRenewal           bool
	RenewalThresholdPercent int
	RenewalCheckInterval    time.Duration
	TokenOperationTimeout   time.Duration
}

// NewCachedClient creates a new cached Vault client.
// If EnableRenewal is true, this will start a background goroutine to manage token renewal.
// The goroutine is owned by the CachedClient and will be stopped when Close() is called.
func NewCachedClient(cfg CachedClientConfig) *CachedClient {
	timeout := cfg.TokenOperationTimeout
	if timeout == 0 {
		timeout = defaultTokenOperationTimeout
	}
	mc := &CachedClient{
		client:                  cfg.Client,
		config:                  cfg.Config,
		cacheKey:                cfg.CacheKey,
		deps:                    cfg.Deps,
		renewalEnabled:          cfg.EnableRenewal,
		renewalThresholdPercent: cfg.RenewalThresholdPercent,
		renewalCheckInterval:    cfg.RenewalCheckInterval,
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
func (c *CachedClient) Client() util.Client {
	return c.client
}

// CacheKey returns the cache key for this client.
func (c *CachedClient) CacheKey() string {
	return c.cacheKey
}

// Acquire increments the active users count.
// This is called when a client is acquired from the pool.
func (c *CachedClient) Acquire() {
	atomic.AddInt32(&c.activeUsers, 1)
}

// Release decrements the active users count.
// Returns true if the client should be finalized (refcount is 0 and evicted).
// This is called when a client is released back to the pool.
func (c *CachedClient) Release() bool {
	remaining := atomic.AddInt32(&c.activeUsers, -1)
	isEvicted := atomic.LoadInt32(&c.evicted) == 1
	return remaining == 0 && isEvicted
}

// updateConfig updates the cached configuration (used after successful re-auth).
func (c *CachedClient) updateConfig(config AcquireClientConfig) {
	c.renewalMu.Lock()
	defer c.renewalMu.Unlock()
	c.config = config
}

// stopRenewalGoroutine stops the token renewal goroutine (internal use).
func (c *CachedClient) stopRenewalGoroutine() {
	c.stopRenewalOnce.Do(func() {
		close(c.stopRenewal)
	})
}

// calculateAndSetNextRenewal computes when the next renewal should occur
// based on the token's creation TTL and renewal threshold percentage.
// This should only be called after successful authentication or renewal.
func (c *CachedClient) calculateAndSetNextRenewal(ctx context.Context) {
	if c.renewalThresholdPercent <= 0 {
		return // Renewal timing not configured
	}

	// Don't hold lock during API call
	resp, err := c.client.AuthToken().LookupSelfWithContext(ctx)
	if err != nil {
		logger.V(1).Info("failed to lookup token for next renewal calculation", "err", err)
		return
	}

	if resp == nil || resp.Data == nil {
		return
	}

	meta, err := parseTokenMetadata(resp.Data)
	if err != nil {
		logger.V(1).Info("failed to parse token metadata for next renewal", "err", err)
		return
	}

	if !meta.renewable {
		logger.V(1).Info("token is not renewable, skipping next renewal calculation", "key", c.cacheKey)
		return
	}

	// Calculate renewal threshold (the TTL value at which we should renew)
	thresholdSeconds := (meta.creationTTL * int64(c.renewalThresholdPercent)) / 100
	if thresholdSeconds <= 0 {
		thresholdSeconds = 1
	}

	// Calculate when to renew based on current TTL
	// If TTL is already below threshold, renew immediately (set nextRenewal to past)
	// Otherwise, renew when TTL drops to threshold
	var timeUntilRenewal int64
	if meta.ttl <= thresholdSeconds {
		// Token already needs renewal
		timeUntilRenewal = 0
	} else {
		// Token doesn't need renewal yet - calculate when it will
		timeUntilRenewal = meta.ttl - thresholdSeconds
	}

	// Lock only for the update
	c.renewalMu.Lock()
	c.nextRenewal = time.Now().Add(time.Duration(timeUntilRenewal) * time.Second)
	c.renewalMu.Unlock()

	logger.V(1).Info("next renewal scheduled", "key", c.cacheKey, "nextRenewal", c.nextRenewal, "ttl", meta.ttl, "threshold", thresholdSeconds, "timeUntilRenewal", timeUntilRenewal)
}

// checkAndRenew attempts to renew the token and schedules the next renewal (internal use).
func (c *CachedClient) checkAndRenew(ctx context.Context) error {
	logger.V(1).Info("renewing token", "key", c.cacheKey)

	// Attempt renewal (no lock needed for Vault API call)
	_, err := c.client.AuthToken().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}

	// Success - reset failure counter and calculate next renewal
	atomic.StoreInt32(&c.renewalFailures, 0)
	logger.V(1).Info("token renewed successfully", "key", c.cacheKey)

	c.calculateAndSetNextRenewal(ctx)

	return nil
}

// validateToken checks if the current token is valid.
func (c *CachedClient) validateToken(ctx context.Context) (bool, error) {
	return checkToken(ctx, c.client.AuthToken())
}

// reauthenticate attempts to re-authenticate the client using fresh credentials.
// This is used when a cached client's token becomes invalid, ensuring that if credentials
// have been rotated in Kubernetes (e.g., AppRole secret, ServiceAccount token), we use
// the latest values.
func (c *CachedClient) reauthenticate(ctx context.Context, currentConfig AcquireClientConfig) error {
	// Use current config (with fresh credentials from K8s) instead of cached config
	authClient := &client{
		kube:      currentConfig.Kube,
		corev1:    currentConfig.CoreV1,
		store:     currentConfig.VaultProvider,
		namespace: currentConfig.CredentialNamespace,
		storeKind: currentConfig.Metadata.StoreKind,
		client:    c.client,
		auth:      c.client.Auth(),
		logical:   c.client.Logical(),
		token:     c.client.AuthToken(),
		log:       logger,
	}

	reauthCtx, cancel := context.WithTimeout(ctx, c.tokenOperationTimeout)
	defer cancel()

	if err := authClient.setAuth(reauthCtx, currentConfig.VaultConfig); err != nil {
		return fmt.Errorf("failed to re-authenticate: %w", err)
	}

	// Update the cached config with fresh credentials for future renewals
	c.updateConfig(currentConfig)

	// Calculate next renewal time after successful re-authentication
	c.calculateAndSetNextRenewal(ctx)

	logger.V(1).Info("re-authentication succeeded", "key", c.cacheKey)

	return nil
}

// GetValidClient returns a valid Vault client, re-authenticating if necessary.
// This method consolidates token validation and re-authentication logic.
// Uses a simple mutex to prevent concurrent re-authentication attempts.
// Returns the client on success, or an error if re-authentication fails.
func (c *CachedClient) GetValidClient(ctx context.Context, freshConfig AcquireClientConfig) (util.Client, error) {
	// First, check if the current token is valid
	valid, err := c.validateToken(ctx)
	if err == nil && valid {
		// Token is valid, return client immediately (fast path)
		return c.client, nil
	}

	// Token is invalid - acquire lock to prevent concurrent re-authentication
	c.reauthMu.Lock()
	defer c.reauthMu.Unlock()

	// Re-check validity after acquiring lock (another goroutine may have re-authed)
	valid, err = c.validateToken(ctx)
	if err == nil && valid {
		return c.client, nil
	}

	// Perform re-authentication
	logger.V(1).Info("cached vault client token invalid, re-authenticating with fresh credentials", "key", c.cacheKey)

	// Clear the old token before re-authenticating
	c.client.ClearToken()

	// Attempt re-authentication once (fail fast, let reconciliation loop retry)
	if err := c.reauthenticate(ctx, freshConfig); err != nil {
		return nil, fmt.Errorf("re-authentication failed: %w", err)
	}

	return c.client, nil
}

// renewalLoop runs in a goroutine to periodically check and renew tokens.
// This is owned by the ManagedClient and runs independently of the pool.
func (c *CachedClient) renewalLoop() {
	// Use fixed polling interval for checking if it's time to renew
	ticker := time.NewTicker(c.renewalCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopRenewal:
			// Renewal goroutine stopped
			return
		case <-ticker.C:
			// Check if it's time to renew
			c.renewalMu.RLock()
			nextRenewal := c.nextRenewal
			c.renewalMu.RUnlock()

			// Skip if nextRenewal not initialized or not time yet
			if nextRenewal.IsZero() || time.Now().Before(nextRenewal) {
				continue
			}

			// Perform renewal
			ctx, cancel := context.WithTimeout(context.Background(), c.tokenOperationTimeout)
			if err := c.checkAndRenew(ctx); err != nil {
				count := atomic.AddInt32(&c.renewalFailures, 1)
				logger.Error(err, "token renewal failed", "key", c.cacheKey, "failures", count)

				if count >= renewalFailureThreshold {
					logger.Error(err, "evicting client after repeated renewal failures", "key", c.cacheKey)

					// Mark as evicted and request eviction from pool
					atomic.StoreInt32(&c.evicted, 1)
					if c.deps.onEvicted != nil {
						c.deps.onEvicted(c.cacheKey)
					}

					cancel()
					return
				}
			}
			cancel()
		}
	}
}

// Close performs cleanup operations for this client.
// This stops the renewal goroutine, revokes the token (if not a static token),
// and performs any other cleanup. This is called when the client is finalized.
func (c *CachedClient) Close(ctx context.Context) error {
	var finalizeErr error
	c.finalizeOnce.Do(func() {
		// Stop renewal goroutine first
		c.stopRenewalGoroutine()

		// Only revoke if this is not a static token (TokenSecretRef)
		if c.config.VaultProvider.Auth == nil || c.config.VaultProvider.Auth.TokenSecretRef == nil {
			revokeCtx, cancel := context.WithTimeout(ctx, c.tokenOperationTimeout)
			defer cancel()

			if err := revokeTokenIfValid(revokeCtx, c.client); err != nil {
				logger.V(1).Info("failed to revoke token during finalization", "key", c.cacheKey, "err", err)
				finalizeErr = fmt.Errorf("failed to revoke token: %w", err)
			} else {
				logger.V(1).Info("token revoked during finalization", "key", c.cacheKey)
			}
		} else {
			logger.V(1).Info("skipping token revocation for static token", "key", c.cacheKey)
		}
	})
	return finalizeErr
}
