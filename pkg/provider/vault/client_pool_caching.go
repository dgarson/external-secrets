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

	lru "github.com/hashicorp/golang-lru/v2"
	vault "github.com/hashicorp/vault/api"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

const (
	minRenewalCheckInterval      = 100 * time.Millisecond
	defaultTokenOperationTimeout = 5 * time.Second
	renewalFailureThreshold      = 3
)

// CachingClientPool is a ClientPool implementation that caches authenticated Vault clients
// and optionally renews their tokens in the background.
type CachingClientPool struct {
	mu             sync.RWMutex
	cache          *lru.Cache[string, *pooledClient]
	newVaultClient func(config *vault.Config) (util.Client, error)

	// Token renewal configuration
	enableRenewal           bool
	renewalThresholdPercent int           // Percentage of TTL to use as renewal threshold
	renewalCheckInterval    time.Duration // Static check interval (used if threshold percent is 0)

	// Cleanup
	stopChan chan struct{}
	wg       sync.WaitGroup

	countsMu              sync.Mutex
	addressCounts         map[string]int
	tokenOperationTimeout time.Duration

	indexMu     sync.RWMutex
	clientIndex map[util.Client]*pooledClient
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

func (p *CachingClientPool) computeRenewalThresholdSeconds(creationTTL int64) (int64, bool) {
	if p.renewalThresholdPercent <= 0 || creationTTL <= 0 {
		return 0, false
	}
	threshold := (creationTTL * int64(p.renewalThresholdPercent)) / 100
	if threshold <= 0 {
		threshold = 1
	}
	return threshold, true
}

func (p *CachingClientPool) trackClientAdded(address string) {
	if address == "" {
		return
	}

	p.countsMu.Lock()
	defer p.countsMu.Unlock()

	next := p.addressCounts[address] + 1
	p.addressCounts[address] = next
	metrics.SetVaultClientPoolSize(address, next)
}

func (p *CachingClientPool) checkoutClient(pooled *pooledClient) util.Client {
	if pooled == nil {
		return nil
	}
	pooled.incrementActive()
	return pooled.client
}

func (p *CachingClientPool) trackClientRemoved(address string) {
	if address == "" {
		return
	}

	p.countsMu.Lock()
	defer p.countsMu.Unlock()

	count, ok := p.addressCounts[address]
	if !ok {
		return
	}

	count--
	if count <= 0 {
		delete(p.addressCounts, address)
		metrics.SetVaultClientPoolSize(address, 0)
		return
	}

	p.addressCounts[address] = count
	metrics.SetVaultClientPoolSize(address, count)
}

func (p *CachingClientPool) registerClient(pooled *pooledClient) {
	if pooled == nil || pooled.client == nil {
		return
	}

	p.indexMu.Lock()
	p.clientIndex[pooled.client] = pooled
	p.indexMu.Unlock()
}

func (p *CachingClientPool) unregisterClient(pooled *pooledClient) {
	if pooled == nil || pooled.client == nil {
		return
	}

	p.indexMu.Lock()
	delete(p.clientIndex, pooled.client)
	p.indexMu.Unlock()
}

func (p *CachingClientPool) operationContext() (context.Context, context.CancelFunc) {
	timeout := p.tokenOperationTimeout
	if timeout <= 0 {
		timeout = defaultTokenOperationTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (p *CachingClientPool) handleEvictedClient(key string, pooled *pooledClient) {
	if pooled == nil {
		return
	}

	pooled.markEvicted()
	pooled.resetRenewalFailures()

	if pooled.stopRenewal != nil {
		pooled.stopRenewalOnce.Do(func() {
			close(pooled.stopRenewal)
		})
	}

	address := ""
	if pooled.client != nil {
		address = pooled.client.GetAddress()
	}
	if address != "" {
		p.trackClientRemoved(address)
	}

	remaining := pooled.activeCount()
	if remaining == 0 {
		p.finalizePooledClient(pooled)
	}

	logger.V(1).Info("evicted client from cache", "key", key, "address", address, "active_users", remaining)
}

func (p *CachingClientPool) finalizePooledClient(pooled *pooledClient) {
	if pooled == nil {
		return
	}

	pooled.finalizeOnce.Do(func() {
		if pooled.config.VaultProvider != nil && pooled.config.VaultProvider.Auth != nil && pooled.config.VaultProvider.Auth.TokenSecretRef == nil {
			ctx, cancel := p.operationContext()
			defer cancel()
			if err := revokeTokenIfValid(ctx, pooled.client); err != nil {
				logger.Error(err, "failed to revoke token during finalization", "key", pooled.cacheKey.String())
			}
		}

		p.unregisterClient(pooled)
	})
}

func (p *CachingClientPool) finalizeAllClients() {
	p.indexMu.RLock()
	pooledClients := make([]*pooledClient, 0, len(p.clientIndex))
	for _, pooled := range p.clientIndex {
		pooledClients = append(pooledClients, pooled)
	}
	p.indexMu.RUnlock()

	for _, pooled := range pooledClients {
		if pooled == nil {
			continue
		}
		pooled.markEvicted()
		p.finalizePooledClient(pooled)
	}
}

func (p *CachingClientPool) evictPooledClient(pooled *pooledClient) {
	if pooled == nil {
		return
	}

	key := pooled.cacheKey.String()
	p.mu.Lock()
	p.cache.Remove(key)
	p.mu.Unlock()
}

// pooledClient wraps a Vault client with renewal and lifecycle management.
type pooledClient struct {
	client   util.Client
	config   AcquireClientConfig
	cacheKey VaultClientCacheKey

	// Token renewal
	stopRenewal     chan struct{}
	stopRenewalOnce sync.Once
	mu              sync.RWMutex
	lastRenewed     time.Time

	activeUsers         int32
	renewalFailureCount int32
	evicted             int32
	finalizeOnce        sync.Once
}

func (p *pooledClient) incrementActive() {
	atomic.AddInt32(&p.activeUsers, 1)
}

func (p *pooledClient) decrementActive() int32 {
	newVal := atomic.AddInt32(&p.activeUsers, -1)
	if newVal < 0 {
		atomic.StoreInt32(&p.activeUsers, 0)
		return 0
	}
	return newVal
}

func (p *pooledClient) activeCount() int32 {
	return atomic.LoadInt32(&p.activeUsers)
}

func (p *pooledClient) markEvicted() {
	atomic.StoreInt32(&p.evicted, 1)
}

func (p *pooledClient) isEvicted() bool {
	return atomic.LoadInt32(&p.evicted) == 1
}

func (p *pooledClient) incrementRenewalFailure() int32 {
	return atomic.AddInt32(&p.renewalFailureCount, 1)
}

func (p *pooledClient) resetRenewalFailures() {
	atomic.StoreInt32(&p.renewalFailureCount, 0)
}

// CachingClientPoolConfig configures the caching client pool.
type CachingClientPoolConfig struct {
	// NewVaultClient is the function to create new Vault clients
	NewVaultClient func(config *vault.Config) (util.Client, error)

	// EnableRenewal enables background token renewal
	EnableRenewal bool

	// RenewalThresholdPercent is the percentage of TTL remaining before renewal (1-100)
	// Default: 50 (renew when 50% of TTL remains)
	// When set, RenewalCheckInterval is overridden with a dynamic interval based on token TTL
	RenewalThresholdPercent int

	// RenewalCheckInterval is how often to check if tokens need renewal
	// Default: 30 minutes
	// Ignored if RenewalThresholdPercent is set, as the check interval will be dynamically calculated
	RenewalCheckInterval time.Duration

	// TokenOperationTimeout bounds Vault token lookup/renew/revoke operations
	// Default: 5 seconds
	TokenOperationTimeout time.Duration

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
		stopChan:                make(chan struct{}),
		addressCounts:           make(map[string]int),
		tokenOperationTimeout:   config.TokenOperationTimeout,
		clientIndex:             make(map[util.Client]*pooledClient),
	}

	cache, err := lru.NewWithEvict(config.MaxCacheSize, func(key string, pooled *pooledClient) {
		pool.handleEvictedClient(key, pooled)
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create LRU cache: %v", err))
	}

	pool.cache = cache

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
			metrics.ObserveVaultClientPoolOperation("cache_hit", pooled.client.GetAddress(), nil)
			return p.checkoutClient(pooled), nil
		}

		// Token is invalid, try to re-authenticate with fresh credentials from current config
		logger.V(1).Info("cached vault client token invalid, re-authenticating with fresh credentials", "key", keyStr)
		reauthErr := p.reauthenticate(ctx, pooled, config)
		metrics.ObserveVaultClientPoolOperation("client_reauth", pooled.client.GetAddress(), reauthErr)
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
			return p.checkoutClient(pooled), nil
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
			metrics.ObserveVaultClientPoolOperation("cache_hit", pooled.client.GetAddress(), nil)
			return p.checkoutClient(pooled), nil
		}
		// If invalid, fall through to create new client
	}

	// Create new client
	logger.V(1).Info("creating new vault client", "key", keyStr)
	vaultClient, err := p.newVaultClient(config.VaultConfig)
	address := config.VaultProvider.Server
	if vaultClient != nil {
		address = vaultClient.GetAddress()
	}
	metrics.ObserveVaultClientPoolOperation("cache_miss", address, nil)
	metrics.ObserveVaultClientPoolOperation("client_created", address, err)
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
	p.registerClient(pooled)
	p.trackClientAdded(address)

	return p.checkoutClient(pooled), nil
}

// ReleaseClient decrements the usage count for the provided client.
func (p *CachingClientPool) ReleaseClient(ctx context.Context, client util.Client) error {
	if client == nil {
		return nil
	}

	p.indexMu.RLock()
	pooled, ok := p.clientIndex[client]
	p.indexMu.RUnlock()
	if !ok {
		return nil
	}

	remaining := pooled.decrementActive()
	if remaining == 0 && pooled.isEvicted() {
		p.finalizePooledClient(pooled)
	}

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
	p.mu.Unlock()

	p.finalizeAllClients()

	metrics.ObserveVaultClientPoolOperation("pool_closed", "", nil)
	return nil
}

// renewalLoop runs in a goroutine to periodically check and renew tokens.
func (p *CachingClientPool) renewalLoop(pooled *pooledClient) {
	defer p.wg.Done()

	// Calculate initial check interval
	checkInterval := p.calculateCheckInterval(pooled)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-pooled.stopRenewal:
			return
		case <-ticker.C:
			if err := p.checkAndRenew(pooled); err != nil {
				count := pooled.incrementRenewalFailure()
				logger.Error(err, "failed to renew token", "key", pooled.cacheKey.String(), "attempt", count)
				if count >= renewalFailureThreshold {
					logger.Error(err, "evicting pooled client after repeated renewal failures", "key", pooled.cacheKey.String())
					p.evictPooledClient(pooled)
					return
				}
			} else {
				pooled.resetRenewalFailures()
			}
			// Recalculate check interval after renewal (token TTL may have changed)
			newInterval := p.calculateCheckInterval(pooled)
			if newInterval != checkInterval {
				checkInterval = newInterval
				ticker.Reset(checkInterval)
			}
		}
	}
}

// calculateCheckInterval computes the renewal check interval for a pooled client.
// If renewalThresholdPercent is set AND is not the default 50%, it calculates the interval dynamically based on token TTL.
// Otherwise, it uses the static renewalCheckInterval.
func (p *CachingClientPool) calculateCheckInterval(pooled *pooledClient) time.Duration {
	// If threshold-based scheduling is disabled, fall back to the static interval.
	if p.renewalThresholdPercent <= 0 {
		return clampRenewalInterval(p.renewalCheckInterval)
	}

	ctx, cancel := p.operationContext()
	defer cancel()
	resp, err := pooled.client.AuthToken().LookupSelfWithContext(ctx)
	if err != nil {
		logger.V(1).Info("failed to lookup token for dynamic interval calculation, using static interval", "err", err)
		return clampRenewalInterval(p.renewalCheckInterval)
	}

	if resp == nil || resp.Data == nil {
		return clampRenewalInterval(p.renewalCheckInterval)
	}

	ttlRaw, ok := resp.Data["ttl"]
	if !ok {
		return clampRenewalInterval(p.renewalCheckInterval)
	}
	ttlSeconds, err := jsonNumberToInt64(ttlRaw)
	if err != nil {
		logger.V(1).Info("failed to parse ttl for dynamic interval calculation, using static interval", "err", err)
		return clampRenewalInterval(p.renewalCheckInterval)
	}

	creationTTLRaw, ok := resp.Data["creation_ttl"]
	if !ok {
		return clampRenewalInterval(p.renewalCheckInterval)
	}
	creationTTL, err := jsonNumberToInt64(creationTTLRaw)
	if err != nil {
		logger.V(1).Info("failed to parse creation_ttl for dynamic interval calculation, using static interval", "err", err)
		return clampRenewalInterval(p.renewalCheckInterval)
	}

	thresholdSeconds, ok := p.computeRenewalThresholdSeconds(creationTTL)
	if !ok {
		return clampRenewalInterval(p.renewalCheckInterval)
	}

	intervalSeconds := ttlSeconds - thresholdSeconds
	if intervalSeconds <= 0 {
		return minRenewalCheckInterval
	}

	interval := time.Duration(intervalSeconds) * time.Second
	interval = clampRenewalInterval(interval)

	logger.V(1).Info("calculated dynamic renewal check interval",
		"key", pooled.cacheKey.String(),
		"creation_ttl", creationTTL,
		"current_ttl", ttlSeconds,
		"threshold_percent", p.renewalThresholdPercent,
		"interval", interval)

	return interval
}

// checkAndRenew checks if a token needs renewal and renews it if necessary.
func (p *CachingClientPool) checkAndRenew(pooled *pooledClient) error {
	pooled.mu.Lock()
	defer pooled.mu.Unlock()

	ctx, cancel := p.operationContext()
	defer cancel()

	resp, err := pooled.client.AuthToken().LookupSelfWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to lookup token: %w", err)
	}

	if resp == nil || resp.Data == nil {
		return fmt.Errorf("invalid token lookup response")
	}

	renewableRaw, ok := resp.Data["renewable"]
	if !ok {
		pooled.resetRenewalFailures()
		return nil
	}
	renewable, ok := renewableRaw.(bool)
	if !ok || !renewable {
		pooled.resetRenewalFailures()
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

	thresholdSeconds, ok := p.computeRenewalThresholdSeconds(creationTTL)
	if !ok {
		fallbackThreshold := clampRenewalInterval(p.renewalCheckInterval)
		thresholdSeconds = int64(fallbackThreshold / time.Second)
		if thresholdSeconds <= 0 {
			thresholdSeconds = 1
		}
	}

	if ttlSeconds > thresholdSeconds {
		pooled.resetRenewalFailures()
		return nil
	}

	logger.V(1).Info("renewing token", "key", pooled.cacheKey.String(), "ttl", ttlSeconds, "threshold", thresholdSeconds)

	start := time.Now()
	_, err = pooled.client.AuthToken().RenewSelfWithContext(ctx, 0)
	duration := time.Since(start).Seconds()

	address := pooled.client.GetAddress()
	metrics.ObserveVaultTokenRenewal(address, err)
	if err == nil {
		metrics.ObserveVaultTokenRenewalDuration(address, duration)
	}

	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}

	pooled.lastRenewed = time.Now()
	pooled.resetRenewalFailures()
	logger.V(1).Info("token renewed successfully", "key", pooled.cacheKey.String())
	return nil
}

// reauthenticate attempts to re-authenticate an existing client using fresh credentials.
// This uses the current config (from the AcquireClient call) rather than cached config,
// ensuring that if credentials have been rotated in Kubernetes (e.g., AppRole secret,
// ServiceAccount token), we use the latest values.
func (p *CachingClientPool) reauthenticate(ctx context.Context, pooled *pooledClient, currentConfig AcquireClientConfig) error {
	pooled.mu.Lock()
	defer pooled.mu.Unlock()

	// Use current config (with fresh credentials from K8s) instead of cached config
	c := &client{
		kube:      currentConfig.Kube,
		corev1:    currentConfig.CoreV1,
		store:     currentConfig.VaultProvider,
		namespace: currentConfig.Namespace,
		storeKind: currentConfig.StoreKind,
		client:    pooled.client,
		auth:      pooled.client.Auth(),
		logical:   pooled.client.Logical(),
		token:     pooled.client.AuthToken(),
		log:       logger,
	}

	timeout := p.tokenOperationTimeout
	if timeout <= 0 {
		timeout = defaultTokenOperationTimeout
	}
	reauthCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := c.setAuth(reauthCtx, currentConfig.VaultConfig); err != nil {
		return fmt.Errorf("failed to re-authenticate: %w", err)
	}

	// Update the cached config with fresh credentials for future renewals
	pooled.config = currentConfig
	pooled.lastRenewed = time.Now()
	return nil
}

// isStaticToken returns true if the auth method uses a static token.
func (p *CachingClientPool) isStaticToken(provider *esv1.VaultProvider) bool {
	return provider.Auth != nil && provider.Auth.TokenSecretRef != nil
}

// Verify CachingClientPool implements ClientPool interface.
var _ ClientPool = &CachingClientPool{}
