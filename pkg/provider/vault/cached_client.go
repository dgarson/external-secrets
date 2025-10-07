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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

const (
	defaultTokenOperationTimeout = 5 * time.Second
)

// CachedClientDeps provides dependencies for the CachedClient to coordinate
// with the pool without tight coupling.
type CachedClientDeps struct {
	// onEvicted is called when the CachedClient should be evicted from the cache.
	onEvicted func(key string)
}

// CachedClient wraps a Vault client with simple reference counting and re-authentication support.
// This is the absolute minimum wrapper needed for caching - no validation, no background work.
type CachedClient struct {
	client   util.Client
	config   AcquireClientConfig
	cacheKey string
	deps     CachedClientDeps

	// Re-authentication coordination
	reauthMu sync.Mutex

	// Token operation timeout
	tokenOperationTimeout time.Duration

	// Reference counting for safe eviction
	activeUsers  int32
	evicted      int32
	finalizeOnce sync.Once
}

// CachedClientConfig configures a CachedClient instance.
type CachedClientConfig struct {
	Client                util.Client
	Config                AcquireClientConfig
	CacheKey              string
	Deps                  CachedClientDeps
	TokenOperationTimeout time.Duration
}

// NewCachedClient creates a new cached Vault client.
func NewCachedClient(cfg CachedClientConfig) *CachedClient {
	timeout := cfg.TokenOperationTimeout
	if timeout == 0 {
		timeout = defaultTokenOperationTimeout
	}

	return &CachedClient{
		client:                cfg.Client,
		config:                cfg.Config,
		cacheKey:              cfg.CacheKey,
		deps:                  cfg.Deps,
		tokenOperationTimeout: timeout,
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

// GetValidClient returns the cached Vault client with zero overhead.
// No validation is performed - the client is returned instantly.
// If the token is expired, the caller will receive a 403/401 from Vault operations
// and can trigger re-authentication via Reauthenticate().
func (c *CachedClient) GetValidClient(ctx context.Context, freshConfig AcquireClientConfig) (util.Client, error) {
	// Zero overhead: just return the cached client
	// Re-authentication only happens when caller gets auth errors from actual Vault operations
	return c.client, nil
}

// Reauthenticate performs re-authentication using fresh credentials.
// This should be called when a Vault operation returns a 401/403 error.
// Uses a mutex to prevent concurrent re-authentication attempts.
func (c *CachedClient) Reauthenticate(ctx context.Context, freshConfig AcquireClientConfig) error {
	c.reauthMu.Lock()
	defer c.reauthMu.Unlock()

	logger.V(1).Info("re-authenticating vault client with fresh credentials", "key", c.cacheKey)

	// Clear old token
	c.client.ClearToken()

	// Re-authenticate using fresh credentials from Kubernetes
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
		return fmt.Errorf("re-authentication failed: %w", err)
	}

	// Update cached config with fresh credentials
	c.config = freshConfig

	logger.V(1).Info("re-authentication succeeded", "key", c.cacheKey)

	return nil
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
