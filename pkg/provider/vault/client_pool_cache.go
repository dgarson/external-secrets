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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/singleflight"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

var _ ClientPool = &cachingPool{}

// cachingPool implements ClientPool with LRU caching and deduplication.
type cachingPool struct {
	// cache stores cached clients with LRU eviction
	cache *lru.Cache[string, *cachedClient]

	// mu protects the cache and acquisition operations
	mu sync.RWMutex

	// acquireGroup deduplicates concurrent client acquisitions
	acquireGroup singleflight.Group

	// config is the pool configuration
	config PoolConfig

	// breaker is the circuit breaker for preventing auth storms (optional)
	breaker *circuitBreaker

	// metrics provides Prometheus metrics
	metrics *poolMetrics

	// shutdownCh signals the cleanup goroutine to stop
	shutdownCh chan struct{}

	// cleanupTicker triggers periodic cleanup
	cleanupTicker *time.Ticker

	// shutdownOnce ensures shutdown is only called once
	shutdownOnce sync.Once
}

// newCachingPool creates a new caching pool.
func newCachingPool(cfg PoolConfig) *cachingPool {
	// Set defaults if not configured
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 100
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	if cfg.EnableBreaker && cfg.BreakerConfig.Threshold <= 0 {
		cfg.BreakerConfig.Threshold = 5
	}
	if cfg.EnableBreaker && cfg.BreakerConfig.OpenDuration <= 0 {
		cfg.BreakerConfig.OpenDuration = 30 * time.Second
	}

	// Create LRU cache with eviction callback
	cache, err := lru.NewWithEvict(cfg.MaxSize, func(key string, value *cachedClient) {
		// Mark the client as evicted so it will be cleaned up when the last reference is released
		value.markEvicted()
		cfg.Logger.V(1).Info("client evicted from cache", "key", key)
	})
	if err != nil {
		// This should never happen with valid MaxSize
		panic(fmt.Sprintf("failed to create LRU cache: %v", err))
	}

	p := &cachingPool{
		cache:      cache,
		config:     cfg,
		metrics:    newPoolMetrics(),
		shutdownCh: make(chan struct{}),
	}

	// Initialize circuit breaker if enabled
	if cfg.EnableBreaker {
		p.breaker = newCircuitBreaker(cfg.BreakerConfig)
		cfg.Logger.V(1).Info("circuit breaker enabled", "threshold", cfg.BreakerConfig.Threshold, "openDuration", cfg.BreakerConfig.OpenDuration)
	}

	// Start background cleanup goroutine
	p.cleanupTicker = time.NewTicker(cfg.CleanupInterval)
	go p.cleanupLoop()
	cfg.Logger.V(1).Info("background cleanup started", "interval", cfg.CleanupInterval)

	return p
}

// Acquire obtains a client from the pool or creates a new one.
func (p *cachingPool) Acquire(ctx context.Context, config VaultClientConfig) (ClientLease, error) {
	// Generate cache key
	key := computeCacheKey(config)

	// Check circuit breaker if enabled
	if p.breaker != nil {
		breakerKey := getBreakerKey(config.VaultSpec.Server, getAuthMethod(config.VaultSpec))
		if err := p.breaker.Check(breakerKey); err != nil {
			p.metrics.incrementBreakerBlocks()
			p.config.Logger.V(1).Info("circuit breaker blocked request", "key", breakerKey, "error", err)
			return nil, err
		}
	}

	// Try to get from cache first
	p.mu.RLock()
	if cached, ok := p.cache.Get(key); ok {
		p.mu.RUnlock()
		p.metrics.incrementCacheHits()
		client := cached.acquire()
		p.config.Logger.V(2).Info("reusing cached client", "key", key)

		// Create authentication function for re-auth
		authFunc := p.createAuthFunc(config, client)

		return newPooledLease(cached, authFunc, p.breaker, p.metrics), nil
	}
	p.mu.RUnlock()

	p.metrics.incrementCacheMisses()

	// Use singleflight to deduplicate concurrent acquisitions
	result, err, _ := p.acquireGroup.Do(key, func() (interface{}, error) {
		// Double-check cache after acquiring singleflight lock
		p.mu.RLock()
		if cached, ok := p.cache.Get(key); ok {
			p.mu.RUnlock()
			p.config.Logger.V(2).Info("reusing cached client from singleflight", "key", key)
			return cached, nil
		}
		p.mu.RUnlock()

		// Create new client
		p.config.Logger.V(1).Info("creating new vault client", "key", key)
		client, err := p.createClient(ctx, config)
		if err != nil {
			// Record failure in circuit breaker
			if p.breaker != nil {
				breakerKey := getBreakerKey(config.VaultSpec.Server, getAuthMethod(config.VaultSpec))
				p.breaker.RecordFailure(breakerKey)
			}
			p.metrics.incrementAuthErrors()
			return nil, err
		}

		// Record success in circuit breaker
		if p.breaker != nil {
			breakerKey := getBreakerKey(config.VaultSpec.Server, getAuthMethod(config.VaultSpec))
			p.breaker.RecordSuccess(breakerKey)
		}

		// Add to cache
		cached := newCachedClient(client, config, p.config.Logger, p.config.EnableRenewal, p.metrics)
		p.mu.Lock()
		p.cache.Add(key, cached)
		p.metrics.setPoolSize(p.cache.Len())
		p.mu.Unlock()

		return cached, nil
	})

	if err != nil {
		return nil, err
	}

	cached := result.(*cachedClient)
	client := cached.acquire()

	// Create authentication function for re-auth
	authFunc := p.createAuthFunc(config, client)

	return newPooledLease(cached, authFunc, p.breaker, p.metrics), nil
}

// Shutdown gracefully shuts down the pool.
func (p *cachingPool) Shutdown(ctx context.Context) error {
	var shutdownErr error

	p.shutdownOnce.Do(func() {
		// Stop background tasks
		close(p.shutdownCh)
		p.cleanupTicker.Stop()

		// Wait for cleanup with timeout
		done := make(chan struct{})
		go func() {
			p.mu.Lock()
			defer p.mu.Unlock()

			// Cancel all renewals and cleanup
			for _, key := range p.cache.Keys() {
				if cached, ok := p.cache.Peek(key); ok {
					cached.cancelRenewal()
					if cached.refCount.Load() == 0 {
						cached.cleanup(context.Background())
					} else {
						cached.markEvicted()
					}
				}
			}
			p.cache.Purge()
			p.metrics.setPoolSize(0)
			close(done)
		}()

		select {
		case <-done:
			p.config.Logger.Info("client pool shutdown complete")
			shutdownErr = nil
		case <-ctx.Done():
			p.config.Logger.Error(ctx.Err(), "client pool shutdown timeout")
			shutdownErr = ctx.Err()
		}
	})

	return shutdownErr
}

// cleanupLoop runs the background cleanup goroutine.
func (p *cachingPool) cleanupLoop() {
	for {
		select {
		case <-p.cleanupTicker.C:
			p.performCleanup()
		case <-p.shutdownCh:
			return
		}
	}
}

// performCleanup removes stale clients from the pool.
func (p *cachingPool) performCleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	keysToRemove := []string{}

	// Iterate through cached clients
	for _, key := range p.cache.Keys() {
		cached, ok := p.cache.Peek(key)
		if !ok {
			continue
		}

		// Remove evicted clients with no references
		if cached.evicted.Load() && cached.refCount.Load() == 0 {
			keysToRemove = append(keysToRemove, key)
			cached.cleanup(context.Background())
			p.config.Logger.V(2).Info("removing evicted client with no references", "key", key)
			continue
		}

		// Check max age if configured
		if p.config.MaxAge > 0 {
			age := now.Sub(cached.createdAt)
			if age > p.config.MaxAge {
				// Mark as evicted and cleanup if no references
				cached.markEvicted()
				if cached.refCount.Load() == 0 {
					keysToRemove = append(keysToRemove, key)
					cached.cleanup(context.Background())
					p.config.Logger.V(2).Info("removing aged client", "key", key, "age", age)
				} else {
					p.config.Logger.V(2).Info("marked aged client for eviction", "key", key, "age", age, "refCount", cached.refCount.Load())
				}
			}
		}
	}

	// Remove keys outside the iteration
	for _, key := range keysToRemove {
		p.cache.Remove(key)
	}

	if len(keysToRemove) > 0 {
		p.metrics.setPoolSize(p.cache.Len())
		p.config.Logger.V(1).Info("cleanup complete", "removed", len(keysToRemove), "poolSize", p.cache.Len())
	}
}

// createClient creates and authenticates a new Vault client.
func (p *cachingPool) createClient(ctx context.Context, config VaultClientConfig) (util.Client, error) {
	// Create a new Vault client
	vaultClient, err := NewVaultClient(config.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set namespace if specified
	if config.VaultSpec.Namespace != nil {
		vaultClient.SetNamespace(*config.VaultSpec.Namespace)
	}

	// Set custom headers if specified
	if config.VaultSpec.Headers != nil {
		for key, value := range config.VaultSpec.Headers {
			vaultClient.AddHeader(key, value)
		}
	}

	// Set read-your-writes header if needed
	if config.VaultSpec.ReadYourWrites && config.VaultSpec.ForwardInconsistent {
		vaultClient.AddHeader("X-Vault-Inconsistent", "forward-active-node")
	}

	// Create a temporary client wrapper to reuse setAuth
	tempClient := &client{
		kube:      config.Kubernetes,
		corev1:    config.CoreV1,
		store:     config.VaultSpec,
		log:       p.config.Logger,
		namespace: config.CredentialNS,
		storeKind: config.StoreKind,
		client:    vaultClient,
		auth:      vaultClient.Auth(),
		logical:   vaultClient.Logical(),
		token:     vaultClient.AuthToken(),
	}

	// Authenticate the client
	if err := tempClient.setAuth(ctx, config.VaultConfig); err != nil {
		return nil, fmt.Errorf("failed to authenticate vault client: %w", err)
	}

	return vaultClient, nil
}

// createAuthFunc creates an authentication function for re-authentication.
func (p *cachingPool) createAuthFunc(config VaultClientConfig, vaultClient util.Client) func(context.Context) error {
	return func(ctx context.Context) error {
		// Create a temporary client wrapper to reuse setAuth
		tempClient := &client{
			kube:      config.Kubernetes,
			corev1:    config.CoreV1,
			store:     config.VaultSpec,
			log:       p.config.Logger,
			namespace: config.CredentialNS,
			storeKind: config.StoreKind,
			client:    vaultClient,
			auth:      vaultClient.Auth(),
			logical:   vaultClient.Logical(),
			token:     vaultClient.AuthToken(),
		}

		// Re-authenticate
		return tempClient.setAuth(ctx, config.VaultConfig)
	}
}

// computeCacheKey generates a deterministic cache key from the config.
func computeCacheKey(config VaultClientConfig) string {
	h := sha256.New()

	// Include server URL
	h.Write([]byte(config.VaultSpec.Server))

	// Include auth method
	h.Write([]byte(getAuthMethod(config.VaultSpec)))

	// Include auth configuration
	if config.VaultSpec.Auth != nil {
		authData, _ := json.Marshal(config.VaultSpec.Auth)
		h.Write(authData)
	}

	// Include CA bundle if present
	if config.VaultSpec.CABundle != nil {
		h.Write(config.VaultSpec.CABundle)
	}

	// Include namespace if present
	if config.VaultSpec.Namespace != nil {
		h.Write([]byte(*config.VaultSpec.Namespace))
	}

	// Include store information for multi-tenant scenarios
	h.Write([]byte(config.StoreKind))
	h.Write([]byte(config.StoreName))
	h.Write([]byte(config.StoreNamespace))

	return fmt.Sprintf("%x", h.Sum(nil))
}

// getAuthMethod returns the authentication method name.
func getAuthMethod(spec *esv1.VaultProvider) string {
	if spec.Auth == nil {
		return "none"
	}
	if spec.Auth.AppRole != nil {
		return "approle"
	}
	if spec.Auth.Kubernetes != nil {
		return "kubernetes"
	}
	if spec.Auth.Ldap != nil {
		return "ldap"
	}
	if spec.Auth.Jwt != nil {
		return "jwt"
	}
	if spec.Auth.Cert != nil {
		return "cert"
	}
	if spec.Auth.TokenSecretRef != nil {
		return "token"
	}
	if spec.Auth.Iam != nil {
		return "iam"
	}
	if spec.Auth.UserPass != nil {
		return "userpass"
	}
	return "unknown"
}

// isStaticToken checks if the auth method is a static token.
func isStaticToken(spec *esv1.VaultProvider) bool {
	return spec.Auth != nil && spec.Auth.TokenSecretRef != nil
}
