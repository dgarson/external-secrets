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

	"golang.org/x/sync/singleflight"
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
	createGroup    singleflight.Group // Deduplicates concurrent createClient calls
	newVaultClient func(config *vault.Config) (util.Client, error)

	// Configuration for ManagedClient creation
	enableRenewal           bool
	renewalThresholdPercent int
	renewalCheckInterval    time.Duration
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

	// Optional callback invoked when a client is evicted from the cache.
	// This is called with the Vault server address of the evicted client.
	OnClientEvicted func(address string)
}

// NewCachingClientPool creates a new caching client pool.
// Returns an error if the LRU cache cannot be created (e.g., invalid MaxCacheSize).
func NewCachingClientPool(config CachingClientPoolConfig) (*CachingClientPool, error) {
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

	pool := &CachingClientPool{
		newVaultClient:          config.NewVaultClient,
		enableRenewal:           config.EnableRenewal,
		renewalThresholdPercent: config.RenewalThresholdPercent,
		renewalCheckInterval:    config.RenewalCheckInterval,
		tokenOperationTimeout:   config.TokenOperationTimeout,
		onClientEvicted:         config.OnClientEvicted,
		clientIndex:             make(map[util.Client]*ManagedClient),
	}

	cache, err := lru.NewWithEvict(config.MaxCacheSize, func(key string, managed *ManagedClient) {
		pool.handleEvictedClient(key, managed)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %w", err)
	}

	pool.cache = cache
	return pool, nil
}

// hasDynamicTLS returns true if the provider uses TLS certificates from Kubernetes secrets.
// TLS configuration is set when creating the HTTP client and cannot be updated via re-authentication
// (unlike auth tokens). Therefore, clients with dynamic TLS should not be cached to ensure
// certificate rotations are picked up immediately.
func hasDynamicTLS(provider *esv1.VaultProvider) bool {
	if provider == nil {
		return false
	}
	// TLS certs/keys from K8s secrets can be rotated - these clients should not be cached
	return provider.ClientTLS.CertSecretRef != nil || provider.ClientTLS.KeySecretRef != nil
}

// AcquireClient returns a cached ManagedClient or creates a new one.
func (p *CachingClientPool) AcquireClient(ctx context.Context, config AcquireClientConfig) (util.Client, error) {
	// Validate config
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Don't cache clients with TLS certificates from secrets
	// TLS config is set at HTTP client creation and cannot be updated via reauth (unlike tokens)
	// This ensures certificate rotations are picked up immediately
	if hasDynamicTLS(config.VaultProvider) {
		logger.V(1).Info("creating non-cached vault client due to dynamic TLS configuration")
		return createClient(&config, p.newVaultClient)
	}

	// Compute cache key
	cacheKey, err := ComputeCacheKey(config)
	if err != nil {
		return nil, fmt.Errorf("failed to compute cache key: %w", err)
	}
	keyStr := cacheKey.String()

	// Fast path: check cache with read lock
	p.mu.RLock()
	managed, exists := p.cache.Get(keyStr)
	p.mu.RUnlock()

	if exists {
		// Get a valid client (will reauth if needed using its own singleflight)
		client, err := managed.GetValidClient(ctx, config)
		if err != nil {
			// Re-authentication failed - return error instead of creating new client
			// (creating new client with same credentials would fail the same way)
			return nil, fmt.Errorf("cached client reauth failed: %w", err)
		}

		// Successfully got valid client (either was valid or successfully reauthed)
		logger.V(1).Info("using cached vault client", "key", keyStr)
		managed.Acquire()
		return client, nil
	}

	// Slow path: use singleflight to ensure only ONE goroutine creates the client.
	// Multiple goroutines requesting the same uncached key will wait here and all
	// receive the same result when the first goroutine completes.
	result, err, _ := p.createGroup.Do(keyStr, func() (interface{}, error) {
		// Double-check cache inside singleflight (another goroutine may have won)
		p.mu.RLock()
		if existing, ok := p.cache.Get(keyStr); ok {
			p.mu.RUnlock()
			return existing, nil
		}
		p.mu.RUnlock()

		// Actually create new client (expensive I/O operation)
		vaultClient, err := createClient(&config, p.newVaultClient)
		if err != nil {
			return nil, err
		}

		// Create ManagedClient wrapper
		managed := NewManagedClient(ManagedClientConfig{
			Client:                  vaultClient,
			Config:                  config,
			CacheKey:                keyStr,
			Deps: ManagedClientDeps{
				onEvicted: func(key string) {
					// ManagedClient is requesting eviction due to renewal failures
					p.mu.Lock()
					p.cache.Remove(key)
					p.mu.Unlock()
				},
			},
			EnableRenewal:           p.enableRenewal,
			RenewalThresholdPercent: p.renewalThresholdPercent,
			RenewalCheckInterval:    p.renewalCheckInterval,
			TokenOperationTimeout:   p.tokenOperationTimeout,
		})

		// Calculate initial renewal time after successful authentication
		if p.enableRenewal {
			reauthCtx, cancel := context.WithTimeout(ctx, p.tokenOperationTimeout)
			managed.calculateAndSetNextRenewal(reauthCtx)
			cancel()
		}

		// Add to cache and register for reverse lookup under write lock
		p.mu.Lock()
		p.cache.Add(keyStr, managed)
		p.registerClient(managed)
		p.mu.Unlock()

		return managed, nil
	})

	if err != nil {
		return nil, err
	}

	managed = result.(*ManagedClient)
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
	atomic.StoreInt32(&managed.evicted, 1)

	// If no active users, close immediately
	activeUsers := atomic.LoadInt32(&managed.activeUsers)
	if activeUsers == 0 {
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

	logger.V(1).Info("evicted client from cache", "key", key, "active_users", activeUsers)
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
		atomic.StoreInt32(&managed.evicted, 1)

		if err := managed.Close(ctx); err != nil {
			logger.Error(err, "failed to close client during shutdown", "key", managed.CacheKey())
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
		namespace: config.CredentialNamespace,
		storeKind: config.Metadata.StoreKind,
		client:    vaultClient,
		auth:      vaultClient.Auth(),
		logical:   vaultClient.Logical(),
		token:     vaultClient.AuthToken(),
		log:       logger,
	}

	skipAuth := config.Metadata.StoreKind == esv1.ClusterSecretStoreKind &&
		config.CredentialNamespace == "" &&
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
