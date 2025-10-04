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
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	lru "github.com/hashicorp/golang-lru/v2"
	vault "github.com/hashicorp/vault/api"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// CachingClientPool is a ClientPool implementation that caches ManagedClient instances using an LRU cache.
// The pool is intentionally simple - ManagedClient instances handle their own lifecycle (renewal, eviction).
// The pool just maintains the cache and responds to eviction requests via callbacks.
type CachingClientPool struct {
	mu             sync.RWMutex
	cache          *lru.Cache[string, *ManagedClient]
	newVaultClient func(config *vault.Config) (util.Client, error)

	// Configuration for ManagedClient creation
	enableRenewal           bool
	renewalThresholdPercent int
	renewalCheckInterval    time.Duration
	reauthBackoffBase       time.Duration
	reauthBackoffMax        time.Duration
	maxReauthAttempts       uint
	tokenOperationTimeout   time.Duration

	// Client index for reverse lookup (client -> ManagedClient)
	indexMu     sync.RWMutex
	clientIndex map[util.Client]*ManagedClient

	// Optional callback for eviction events
	onClientEvicted func(address string)
}

// CachingClientPoolConfig configures the caching client pool.
type CachingClientPoolConfig struct {
	NewVaultClient func(config *vault.Config) (util.Client, error)

	EnableRenewal           bool
	RenewalThresholdPercent int
	RenewalCheckInterval    time.Duration

	TokenOperationTimeout time.Duration
	MaxCacheSize          int

	ReauthBackoffBase time.Duration
	ReauthBackoffMax  time.Duration
	MaxReauthAttempts uint

	// Optional callback invoked when a client is evicted from the cache.
	// This is called with the Vault server address of the evicted client.
	OnClientEvicted func(address string)
}

// NewCachingClientPool creates a new caching client pool.
func NewCachingClientPool(config CachingClientPoolConfig) *CachingClientPool {
	if config.NewVaultClient == nil {
		config.NewVaultClient = NewVaultClient
	}
	if config.RenewalCheckInterval == 0 {
		config.RenewalCheckInterval = 30 * time.Minute
	}
	config.RenewalCheckInterval = clampRenewalInterval(config.RenewalCheckInterval)
	if config.RenewalThresholdPercent == 0 {
		config.RenewalThresholdPercent = 50
	}
	if config.MaxCacheSize == 0 {
		config.MaxCacheSize = 1000
	}
	if config.TokenOperationTimeout == 0 {
		config.TokenOperationTimeout = defaultTokenOperationTimeout
	}
	if config.ReauthBackoffBase == 0 {
		config.ReauthBackoffBase = 1 * time.Second
	}
	if config.ReauthBackoffMax == 0 {
		config.ReauthBackoffMax = 5 * time.Minute
	}
	if config.MaxReauthAttempts == 0 {
		config.MaxReauthAttempts = 3
	}

	pool := &CachingClientPool{
		newVaultClient:          config.NewVaultClient,
		enableRenewal:           config.EnableRenewal,
		renewalThresholdPercent: config.RenewalThresholdPercent,
		renewalCheckInterval:    config.RenewalCheckInterval,
		reauthBackoffBase:       config.ReauthBackoffBase,
		reauthBackoffMax:        config.ReauthBackoffMax,
		maxReauthAttempts:       config.MaxReauthAttempts,
		tokenOperationTimeout:   config.TokenOperationTimeout,
		onClientEvicted:         config.OnClientEvicted,
		clientIndex:             make(map[util.Client]*ManagedClient),
	}

	cache, err := lru.NewWithEvict(config.MaxCacheSize, func(key string, managed *ManagedClient) {
		pool.handleEvictedClient(key, managed)
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create LRU cache: %v", err))
	}

	pool.cache = cache
	return pool
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

// reauthenticateWithBackoff attempts to re-authenticate a ManagedClient with exponential backoff.
// It uses the cenkalti/backoff library to handle retry logic and respects MaxReauthAttempts.
// Returns a permanent error (via backoff.Permanent) for auth failures that should not be retried.
func (p *CachingClientPool) reauthenticateWithBackoff(ctx context.Context, managed *ManagedClient, config AcquireClientConfig, keyStr string) error {
	// Create exponential backoff strategy
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = p.reauthBackoffBase
	b.MaxInterval = p.reauthBackoffMax

	// Retry function - returns struct{} as a placeholder since we only care about errors
	operation := func() (struct{}, error) {
		logger.V(1).Info("attempting re-authentication", "key", keyStr)
		err := managed.Reauthenticate(ctx, config)
		if err != nil {
			// Check if this is a permanent error
			if isPermanentAuthError(err) {
				logger.Error(err, "permanent authentication error, stopping retries", "key", keyStr)
				return struct{}{}, backoff.Permanent(err)
			}
			logger.V(1).Info("re-authentication attempt failed, will retry", "key", keyStr, "err", err)
			return struct{}{}, err
		}
		logger.V(1).Info("re-authentication succeeded", "key", keyStr)
		return struct{}{}, nil
	}

	// Execute with backoff, respecting max attempts and context
	_, err := backoff.Retry(
		ctx,
		operation,
		backoff.WithBackOff(b),
		backoff.WithMaxTries(uint(p.maxReauthAttempts)),
	)
	if err != nil {
		return fmt.Errorf("re-authentication failed after retries: %w", err)
	}
	return nil
}

// AcquireClient returns a cached ManagedClient or creates a new one.
func (p *CachingClientPool) AcquireClient(ctx context.Context, config AcquireClientConfig) (util.Client, error) {
	// Compute cache key
	cacheKey, err := ComputeCacheKey(config)
	if err != nil {
		return nil, fmt.Errorf("failed to compute cache key: %w", err)
	}
	keyStr := cacheKey.String()

	// Check if we have a cached client
	p.mu.RLock()
	managed, exists := p.cache.Get(keyStr)
	p.mu.RUnlock()

	if exists {
		// Validate the cached client's token via ManagedClient
		valid, err := managed.ValidateToken(ctx)
		if err == nil && valid {
			// Token is still valid, use cached client
			logger.V(1).Info("reusing cached vault client", "key", keyStr)
			managed.Acquire()
			return managed.Client(), nil
		}

		// Token is invalid, check if we should attempt re-auth (respects backoff)
		shouldAttempt, backoffRemaining := managed.ShouldAttemptReauth()
		if !shouldAttempt {
			// Still in backoff period, remove from cache and create new client
			logger.V(1).Info("skipping re-auth due to backoff", "key", keyStr, "backoff_remaining", backoffRemaining)
			p.mu.Lock()
			p.cache.Remove(keyStr)
			p.mu.Unlock()
			// Fall through to create new client
		} else {
			// Try to re-authenticate using backoff logic
			logger.V(1).Info("cached vault client token invalid, re-authenticating with fresh credentials", "key", keyStr)
			reauthErr := p.reauthenticateWithBackoff(ctx, managed, config, keyStr)
			if reauthErr != nil {
				// Re-authentication failed after all retries, remove from cache and create new
				logger.Error(reauthErr, "failed to re-authenticate cached client after retries", "key", keyStr)
				p.mu.Lock()
				p.cache.Remove(keyStr)  // This triggers handleEvictedClient which stops renewal
				p.mu.Unlock()
				// Fall through to create new client
			} else {
				// Re-authentication succeeded
				logger.V(1).Info("re-authentication succeeded", "key", keyStr)
				managed.Acquire()
				return managed.Client(), nil
			}
		}
	}

	// Use write lock to prevent concurrent creation
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check: another goroutine may have created it
	if managed, exists := p.cache.Get(keyStr); exists {
		managed.Acquire()
		return managed.Client(), nil
	}

	// Create new Vault client
	vaultClient, err := createClient(&config, p.newVaultClient)
	if err != nil {
		return nil, err
	}

	// Create ManagedClient wrapper with callbacks
	managed = NewManagedClient(ManagedClientConfig{
		Client:  vaultClient,
		Config:  config,
		CacheKey: cacheKey,
		Callbacks: ManagedClientCallbacks{
			OnEvictionNeeded: func(key VaultClientCacheKey) {
				// ManagedClient is requesting eviction due to renewal failures
				p.mu.Lock()
				p.cache.Remove(key.String())
				p.mu.Unlock()
			},
		},
		EnableRenewal:           p.enableRenewal,
		RenewalThresholdPercent: p.renewalThresholdPercent,
		RenewalCheckInterval:    p.renewalCheckInterval,
		ReauthBackoffBase:       p.reauthBackoffBase,
		ReauthBackoffMax:        p.reauthBackoffMax,
		TokenOperationTimeout:   p.tokenOperationTimeout,
	})

	// Register in client index for reverse lookup
	p.registerClient(managed)

	// Add to cache
	p.cache.Add(keyStr, managed)

	// Acquire and return - ManagedClient has already started its renewal goroutine
	managed.Acquire()
	return managed.Client(), nil
}

// ReleaseClient decrements the usage count for the provided client.
func (p *CachingClientPool) ReleaseClient(ctx context.Context, client util.Client) error {
	if client == nil {
		return nil
	}

	p.indexMu.RLock()
	managed, ok := p.clientIndex[client]
	p.indexMu.RUnlock()

	if !ok {
		return nil
	}

	// Release returns true if the client should be finalized
	if shouldFinalize := managed.Release(); shouldFinalize {
		return managed.Close(ctx)
	}

	return nil
}

// Close closes all cached clients and stops renewal goroutines.
func (p *CachingClientPool) Close(ctx context.Context) error {
	// Clear cache (Purge() removes all items and calls eviction callback)
	// The eviction callback will mark each client as evicted
	p.mu.Lock()
	p.cache.Purge()
	p.mu.Unlock()

	// Finalize any remaining clients
	// (clients with active users will finalize when their refcount reaches 0)
	p.finalizeAllClients(ctx)

	return nil
}

// handleEvictedClient is called when a client is evicted from the LRU cache.
func (p *CachingClientPool) handleEvictedClient(key string, managed *ManagedClient) {
	if managed == nil {
		return
	}

	// Mark as evicted so Release() knows to finalize when refcount reaches 0
	managed.markEvicted()

	// If no active users, close immediately
	if managed.activeCount() == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), p.tokenOperationTimeout)
		defer cancel()

		if err := managed.Close(ctx); err != nil {
			logger.Error(err, "failed to close evicted client", "key", key)
		}

		p.unregisterClient(managed)

		// Notify listener if configured
		if p.onClientEvicted != nil {
			p.onClientEvicted(managed.Client().GetAddress())
		}
	}

	logger.V(1).Info("evicted client from cache", "key", key, "active_users", managed.activeCount())
}


// finalizeAllClients closes all clients in the index.
func (p *CachingClientPool) finalizeAllClients(ctx context.Context) {
	p.indexMu.RLock()
	managedClients := make([]*ManagedClient, 0, len(p.clientIndex))
	for _, managed := range p.clientIndex {
		managedClients = append(managedClients, managed)
	}
	p.indexMu.RUnlock()

	for _, managed := range managedClients {
		if managed == nil {
			continue
		}
		managed.markEvicted()

		if err := managed.Close(ctx); err != nil {
			logger.Error(err, "failed to close client during shutdown", "key", managed.CacheKey().String())
		}

		p.unregisterClient(managed)

		// Notify listener if configured
		if p.onClientEvicted != nil {
			p.onClientEvicted(managed.Client().GetAddress())
		}
	}
}

// registerClient registers a ManagedClient in the index for reverse lookup.
func (p *CachingClientPool) registerClient(managed *ManagedClient) {
	if managed == nil || managed.Client() == nil {
		return
	}

	p.indexMu.Lock()
	p.clientIndex[managed.Client()] = managed
	p.indexMu.Unlock()
}

// unregisterClient removes a ManagedClient from the index.
func (p *CachingClientPool) unregisterClient(managed *ManagedClient) {
	if managed == nil || managed.Client() == nil {
		return
	}

	p.indexMu.Lock()
	delete(p.clientIndex, managed.Client())
	p.indexMu.Unlock()
}

// createClient creates and authenticates a new Vault client.
func createClient(config *AcquireClientConfig, newVaultClient func(*vault.Config) (util.Client, error)) (util.Client, error) {
	vaultClient, err := newVaultClient(config.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set namespace and headers
	if config.VaultProvider.Namespace != nil {
		vaultClient.SetNamespace(*config.VaultProvider.Namespace)
	}
	if config.VaultProvider.Headers != nil {
		for key, value := range config.VaultProvider.Headers {
			vaultClient.AddHeader(key, value)
		}
	}
	if config.VaultProvider.ReadYourWrites && config.VaultProvider.ForwardInconsistent {
		vaultClient.AddHeader("X-Vault-Inconsistent", "forward-active-node")
	}

	// Authenticate
	c := &client{
		kube:      config.Kube,
		corev1:    config.CoreV1,
		store:     config.VaultProvider,
		namespace: config.Namespace,
		storeKind: config.StoreKind,
		client:    vaultClient,
		auth:      vaultClient.Auth(),
		logical:   vaultClient.Logical(),
		token:     vaultClient.AuthToken(),
		log:       logger,
	}

	skipAuth := config.StoreKind == esv1.ClusterSecretStoreKind &&
		config.Namespace == "" &&
		isReferentSpec(config.VaultProvider)

	if !skipAuth {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTokenOperationTimeout)
		defer cancel()
		if err := c.setAuth(ctx, config.VaultConfig); err != nil {
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	return vaultClient, nil
}

// Verify CachingClientPool implements ClientPool interface.
var _ ClientPool = &CachingClientPool{}
