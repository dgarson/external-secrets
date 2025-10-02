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
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	vault "github.com/hashicorp/vault/api"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// CachingClientPool is a ClientPool implementation that caches authenticated Vault clients
// and optionally renews their tokens in the background.
type CachingClientPool struct {
	mu             sync.RWMutex
	cache          *lru.Cache[string, *pooledClient]
	newVaultClient func(config *vault.Config) (util.Client, error)

	// Token renewal configuration
	enableRenewal       bool
	renewalThreshold    time.Duration // Renew when TTL drops below this
	renewalCheckInterval time.Duration // How often to check if renewal is needed

	// Cleanup
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// pooledClient wraps a Vault client with renewal and lifecycle management.
type pooledClient struct {
	client     util.Client
	config     AcquireClientConfig
	cacheKey   VaultClientCacheKey

	// Token renewal
	stopRenewal     chan struct{}
	stopRenewalOnce sync.Once
	mu              sync.RWMutex
	lastRenewed     time.Time
}

// CachingClientPoolConfig configures the caching client pool.
type CachingClientPoolConfig struct {
	// NewVaultClient is the function to create new Vault clients
	NewVaultClient func(config *vault.Config) (util.Client, error)

	// EnableRenewal enables background token renewal
	EnableRenewal bool

	// RenewalThresholdPercent is the percentage of TTL remaining before renewal (1-100)
	// Default: 50 (renew when 50% of TTL remains)
	RenewalThresholdPercent int

	// RenewalCheckInterval is how often to check if tokens need renewal
	// Default: 1 minute
	RenewalCheckInterval time.Duration

	// MaxCacheSize is the maximum number of clients to cache
	// Default: 1000
	MaxCacheSize int
}

// NewCachingClientPool creates a new caching client pool.
func NewCachingClientPool(config CachingClientPoolConfig) *CachingClientPool {
	if config.NewVaultClient == nil {
		config.NewVaultClient = NewVaultClient
	}
	if config.RenewalCheckInterval == 0 {
		config.RenewalCheckInterval = 1 * time.Minute
	}
	if config.RenewalThresholdPercent == 0 {
		config.RenewalThresholdPercent = 50
	}
	if config.MaxCacheSize == 0 {
		config.MaxCacheSize = 1000
	}

	// Create LRU cache with eviction callback
	cache, err := lru.NewWithEvict(config.MaxCacheSize, func(key string, pooled *pooledClient) {
		// Stop renewal goroutine (using sync.Once to prevent double-close)
		if pooled.stopRenewal != nil {
			pooled.stopRenewalOnce.Do(func() {
				close(pooled.stopRenewal)
			})
		}
		// Revoke token if not static
		if pooled.config.VaultProvider.Auth != nil && pooled.config.VaultProvider.Auth.TokenSecretRef == nil {
			ctx := context.Background()
			if err := revokeTokenIfValid(ctx, pooled.client); err != nil {
				logger.Error(err, "failed to revoke token during eviction", "key", key)
			}
		}
		logger.V(1).Info("evicted client from cache", "key", key)
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create LRU cache: %v", err))
	}

	pool := &CachingClientPool{
		cache:                cache,
		newVaultClient:       config.NewVaultClient,
		enableRenewal:        config.EnableRenewal,
		renewalThreshold:     0, // Will be calculated per-token
		renewalCheckInterval: config.RenewalCheckInterval,
		stopChan:             make(chan struct{}),
	}

	return pool
}

// AcquireClient returns a cached Vault client or creates a new one.
func (p *CachingClientPool) AcquireClient(ctx context.Context, config AcquireClientConfig) (util.Client, error) {
	// Compute cache key
	cacheKey, err := ComputeCacheKey(config)
	if err != nil {
		return nil, fmt.Errorf("failed to compute cache key: %w", err)
	}

	keyStr := cacheKey.String()

	// Check if we have a cached client (this updates LRU ordering)
	p.mu.RLock()
	pooled, exists := p.cache.Get(keyStr)
	p.mu.RUnlock()

	if exists {
		// Validate the cached client's token
		valid, err := checkToken(ctx, pooled.client.AuthToken())
		if err == nil && valid {
			logger.V(1).Info("reusing cached vault client", "key", keyStr)
			metrics.ObserveVaultClientPoolOperation("cache_hit", nil)
			return pooled.client, nil
		}

		// Token is invalid, try to re-authenticate
		logger.V(1).Info("cached vault client token invalid, re-authenticating", "key", keyStr)
		reauthErr := p.reauthenticate(ctx, pooled)
		metrics.ObserveVaultClientPoolOperation("client_reauth", reauthErr)
		if reauthErr != nil {
			// Re-authentication failed, remove from cache and create new
			logger.Error(reauthErr, "failed to re-authenticate cached client", "key", keyStr)
			p.mu.Lock()
			p.cache.Remove(keyStr)
			p.mu.Unlock()
			if pooled.stopRenewal != nil {
				pooled.stopRenewalOnce.Do(func() {
					close(pooled.stopRenewal)
				})
			}
		} else {
			// Re-authentication succeeded
			return pooled.client, nil
		}
	}

	// Use write lock to prevent concurrent creation of the same client
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check: another goroutine may have created the client while we waited for the lock
	if pooled, exists := p.cache.Get(keyStr); exists {
		valid, err := checkToken(ctx, pooled.client.AuthToken())
		if err == nil && valid {
			logger.V(1).Info("reusing cached vault client (double-check)", "key", keyStr)
			metrics.ObserveVaultClientPoolOperation("cache_hit", nil)
			return pooled.client, nil
		}
		// If invalid, fall through to create new client
	}

	// Create new client
	logger.V(1).Info("creating new vault client", "key", keyStr)
	metrics.ObserveVaultClientPoolOperation("cache_miss", nil)
	vaultClient, err := p.newVaultClient(config.VaultConfig)
	metrics.ObserveVaultClientPoolOperation("client_created", err)
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
		if err := c.setAuth(ctx, config.VaultConfig); err != nil {
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	// Create pooled client
	pooled = &pooledClient{
		client:      vaultClient,
		config:      config,
		cacheKey:    cacheKey,
		lastRenewed: time.Now(),
	}

	// Start renewal if enabled and not static token
	if p.enableRenewal && !p.isStaticToken(config.VaultProvider) {
		pooled.stopRenewal = make(chan struct{})
		p.wg.Add(1)
		go p.renewalLoop(pooled)
	}

	// Add to cache (we're already holding the write lock)
	// The Add method will automatically evict the LRU item if cache is full
	p.cache.Add(keyStr, pooled)
	metrics.SetVaultClientPoolSize(p.cache.Len())

	return vaultClient, nil
}

// ReleaseClient is a no-op for caching pool - clients remain cached.
func (p *CachingClientPool) ReleaseClient(ctx context.Context, client util.Client) error {
	// For caching pool, we don't release clients immediately
	// They stay in cache until evicted or pool is closed
	return nil
}

// Close closes all cached clients and stops renewal goroutines.
func (p *CachingClientPool) Close(ctx context.Context) error {
	// Signal all renewal goroutines to stop
	close(p.stopChan)

	// Stop individual client renewals
	p.mu.Lock()
	keys := p.cache.Keys()
	for _, key := range keys {
		if pooled, ok := p.cache.Get(key); ok {
			if pooled.stopRenewal != nil {
				pooled.stopRenewalOnce.Do(func() {
					close(pooled.stopRenewal)
				})
			}
		}
	}
	p.mu.Unlock()

	// Wait for all renewal goroutines to finish
	p.wg.Wait()

	// Clear cache (Purge() removes all items and calls eviction callback)
	// The eviction callback will revoke tokens
	p.mu.Lock()
	p.cache.Purge()
	metrics.SetVaultClientPoolSize(0)
	p.mu.Unlock()

	metrics.ObserveVaultClientPoolOperation("pool_closed", nil)
	return nil
}

// renewalLoop runs in a goroutine to periodically check and renew tokens.
func (p *CachingClientPool) renewalLoop(pooled *pooledClient) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.renewalCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-pooled.stopRenewal:
			return
		case <-ticker.C:
			if err := p.checkAndRenew(pooled); err != nil {
				logger.Error(err, "failed to renew token", "key", pooled.cacheKey.String())
			}
		}
	}
}

// checkAndRenew checks if a token needs renewal and renews it if necessary.
func (p *CachingClientPool) checkAndRenew(pooled *pooledClient) error {
	pooled.mu.Lock()
	defer pooled.mu.Unlock()

	ctx := context.Background()

	// Check token status
	resp, err := pooled.client.AuthToken().LookupSelfWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to lookup token: %w", err)
	}

	if resp == nil || resp.Data == nil {
		return fmt.Errorf("invalid token lookup response")
	}

	// Check if token is renewable
	renewable, ok := resp.Data["renewable"]
	if !ok || !renewable.(bool) {
		// Token is not renewable, nothing to do
		return nil
	}

	// Get TTL
	ttlRaw, ok := resp.Data["ttl"]
	if !ok {
		return fmt.Errorf("no TTL in token response")
	}

	ttl, err := ttlRaw.(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("invalid TTL: %w", err)
	}

	// Get creation TTL to calculate threshold
	creationTTLRaw, ok := resp.Data["creation_ttl"]
	if !ok {
		return fmt.Errorf("no creation_ttl in token response")
	}

	creationTTL, err := creationTTLRaw.(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("invalid creation_ttl: %w", err)
	}

	// Calculate renewal threshold (50% of original TTL by default)
	threshold := creationTTL / 2

	// Renew if below threshold
	if ttl < threshold {
		logger.V(1).Info("renewing token", "key", pooled.cacheKey.String(), "ttl", ttl, "threshold", threshold)

		start := time.Now()
		_, err := pooled.client.AuthToken().RenewSelfWithContext(ctx, 0) // 0 means use default increment
		duration := time.Since(start).Seconds()

		metrics.ObserveVaultTokenRenewal(err)
		if err == nil {
			metrics.ObserveVaultTokenRenewalDuration(duration)
		}

		if err != nil {
			return fmt.Errorf("failed to renew token: %w", err)
		}

		pooled.lastRenewed = time.Now()
		logger.V(1).Info("token renewed successfully", "key", pooled.cacheKey.String())
	}

	return nil
}

// reauthenticate attempts to re-authenticate an existing client.
func (p *CachingClientPool) reauthenticate(ctx context.Context, pooled *pooledClient) error {
	pooled.mu.Lock()
	defer pooled.mu.Unlock()

	c := &client{
		kube:      pooled.config.Kube,
		corev1:    pooled.config.CoreV1,
		store:     pooled.config.VaultProvider,
		namespace: pooled.config.Namespace,
		storeKind: pooled.config.StoreKind,
		client:    pooled.client,
		auth:      pooled.client.Auth(),
		logical:   pooled.client.Logical(),
		token:     pooled.client.AuthToken(),
		log:       logger,
	}

	if err := c.setAuth(ctx, pooled.config.VaultConfig); err != nil {
		return fmt.Errorf("failed to re-authenticate: %w", err)
	}

	pooled.lastRenewed = time.Now()
	return nil
}

// isStaticToken returns true if the auth method uses a static token.
func (p *CachingClientPool) isStaticToken(provider *esv1.VaultProvider) bool {
	return provider.Auth != nil && provider.Auth.TokenSecretRef != nil
}

// Verify CachingClientPool implements ClientPool interface.
var _ ClientPool = &CachingClientPool{}
