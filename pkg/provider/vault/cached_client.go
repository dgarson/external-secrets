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
	defaultTokenOperationTimeout = 5 * time.Second
	defaultRotationThreshold     = 50 // Rotate when TTL < 50% of creation TTL
)

// CachedClientDeps provides dependencies for the CachedClient to coordinate
// with the pool without tight coupling.
type CachedClientDeps struct {
	// onEvicted is called when the CachedClient should be evicted from the cache.
	onEvicted func(key string)
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

// isPermanentAuthError checks if an error is a permanent authentication failure.
func isPermanentAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
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
func parseTokenMetadata(data map[string]interface{}) (*tokenMetadata, error) {
	if data == nil {
		return nil, fmt.Errorf("nil token data")
	}

	meta := &tokenMetadata{}

	if ttlRaw, ok := data["ttl"]; ok {
		ttl, err := jsonNumberToInt64(ttlRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl: %w", err)
		}
		meta.ttl = ttl
	}

	if creationTTLRaw, ok := data["creation_ttl"]; ok {
		creationTTL, err := jsonNumberToInt64(creationTTLRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid creation_ttl: %w", err)
		}
		meta.creationTTL = creationTTL
	}

	if renewableRaw, ok := data["renewable"]; ok {
		if renewable, ok := renewableRaw.(bool); ok {
			meta.renewable = renewable
		}
	}

	return meta, nil
}

// CachedClient wraps a Vault client with on-demand rotation when the token approaches expiry.
// No background goroutines are used, keeping the implementation simple and predictable.
type CachedClient struct {
	client   util.Client
	config   AcquireClientConfig
	cacheKey string
	deps     CachedClientDeps

	// Rotation configuration
	rotationThresholdPercent int

	// Rotation coordination
	rotationMu sync.Mutex

	// Token operation timeout
	tokenOperationTimeout time.Duration

	// Reference counting for safe eviction
	activeUsers  int32
	evicted      int32
	finalizeOnce sync.Once
}

// CachedClientConfig configures a CachedClient instance.
type CachedClientConfig struct {
	Client                   util.Client
	Config                   AcquireClientConfig
	CacheKey                 string
	Deps                     CachedClientDeps
	RotationThresholdPercent int
	TokenOperationTimeout    time.Duration
}

// NewCachedClient creates a new cached Vault client.
func NewCachedClient(cfg CachedClientConfig) *CachedClient {
	timeout := cfg.TokenOperationTimeout
	if timeout == 0 {
		timeout = defaultTokenOperationTimeout
	}

	rotationThreshold := cfg.RotationThresholdPercent
	if rotationThreshold == 0 {
		rotationThreshold = defaultRotationThreshold
	}

	return &CachedClient{
		client:                   cfg.Client,
		config:                   cfg.Config,
		cacheKey:                 cfg.CacheKey,
		deps:                     cfg.Deps,
		rotationThresholdPercent: rotationThreshold,
		tokenOperationTimeout:    timeout,
	}
}

// Client returns the underlying Vault client.
func (c *CachedClient) Client() util.Client {
	return c.client
}

// CacheKey returns the cache key.
func (c *CachedClient) CacheKey() string {
	return c.cacheKey
}

// Acquire increments the active user count.
func (c *CachedClient) Acquire() {
	atomic.AddInt32(&c.activeUsers, 1)
}

// Release decrements the active user count and returns true if the client should be finalized.
func (c *CachedClient) Release() bool {
	newCount := atomic.AddInt32(&c.activeUsers, -1)
	isEvicted := atomic.LoadInt32(&c.evicted) == 1
	return isEvicted && newCount == 0
}

// validateToken checks if the current token is valid.
func (c *CachedClient) validateToken(ctx context.Context) (bool, error) {
	return checkToken(ctx, c.client.AuthToken())
}

// needsRotation checks if the token TTL is below the rotation threshold.
func (c *CachedClient) needsRotation(ctx context.Context) bool {
	resp, err := c.client.AuthToken().LookupSelfWithContext(ctx)
	if err != nil {
		logger.V(1).Info("failed to lookup token for rotation check", "err", err, "key", c.cacheKey)
		return false
	}

	if resp == nil || resp.Data == nil {
		return false
	}

	meta, err := parseTokenMetadata(resp.Data)
	if err != nil {
		logger.V(1).Info("failed to parse token metadata for rotation check", "err", err, "key", c.cacheKey)
		return false
	}

	// Calculate rotation threshold
	thresholdSeconds := (meta.creationTTL * int64(c.rotationThresholdPercent)) / 100
	if thresholdSeconds <= 0 {
		return false
	}

	// Rotate if current TTL is below threshold
	shouldRotate := meta.ttl <= thresholdSeconds
	if shouldRotate {
		logger.V(1).Info("token TTL below rotation threshold", "key", c.cacheKey, "ttl", meta.ttl, "threshold", thresholdSeconds)
	}

	return shouldRotate
}

// GetValidClient returns a valid Vault client, re-authenticating if needed.
// On-demand approach: no background goroutines.
func (c *CachedClient) GetValidClient(ctx context.Context, freshConfig AcquireClientConfig) (util.Client, error) {
	// Check if token is valid
	valid, err := c.validateToken(ctx)
	if err != nil || !valid {
		// Token is invalid - need to re-authenticate immediately
		return c.rotateClient(ctx, freshConfig)
	}

	// Token is valid - check if it needs pro-active rotation
	// This is best-effort: if rotation fails, we continue with existing client
	if c.needsRotation(ctx) {
		logger.V(1).Info("token TTL low, should rotate soon", "key", c.cacheKey)
		// We could trigger eviction here to force a new client on next acquire
		// For now, just log and continue - the pool will handle rotation on next acquire
	}

	return c.client, nil
}

// rotateClient performs immediate re-authentication when token is invalid.
func (c *CachedClient) rotateClient(ctx context.Context, freshConfig AcquireClientConfig) (util.Client, error) {
	c.rotationMu.Lock()
	defer c.rotationMu.Unlock()

	// Double-check after acquiring lock
	valid, err := c.validateToken(ctx)
	if err == nil && valid {
		return c.client, nil
	}

	logger.V(1).Info("re-authenticating vault client with fresh credentials", "key", c.cacheKey)

	// Clear old token
	c.client.ClearToken()

	// Re-authenticate using fresh credentials
	authClient := &client{
		kube:      freshConfig.Kube,
		corev1:    freshConfig.CoreV1,
		store:     freshConfig.VaultProvider,
		namespace: freshConfig.CredentialNamespace,
		storeKind: freshConfig.Metadata.StoreKind,
		client:    c.client,
		auth:      c.client.Auth(),
		logical:   c.client.Logical(),
		token:     c.client.AuthToken(),
		log:       logger,
	}

	authCtx, cancel := context.WithTimeout(ctx, c.tokenOperationTimeout)
	defer cancel()

	if err := authClient.setAuth(authCtx, freshConfig.VaultConfig); err != nil {
		return nil, fmt.Errorf("re-authentication failed: %w", err)
	}

	// Update cached config
	c.config = freshConfig

	logger.V(1).Info("re-authentication succeeded", "key", c.cacheKey)

	return c.client, nil
}

// Close performs cleanup operations for this client.
func (c *CachedClient) Close(ctx context.Context) error {
	var finalizeErr error
	c.finalizeOnce.Do(func() {
		// Only revoke if not a static token
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
