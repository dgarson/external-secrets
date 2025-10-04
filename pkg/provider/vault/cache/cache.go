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

package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// ClientManager provides a managed, cached source of Vault clients.
// It handles client creation, caching, token renewal, and invalidation.
type ClientManager struct {
	entries sync.Map // string (cacheKey) -> *CacheEntry
	sf      singleflight.Group
	config  CacheConfig
	metrics MetricsRecorder
	mu      sync.RWMutex // For iteration operations only
}

// NewClientManager creates a new ClientManager with the given configuration.
func NewClientManager(config CacheConfig) *ClientManager {
	// Set default renewal window if not specified
	if config.RenewalWindow == 0 {
		config.RenewalWindow = 5 * time.Minute
	}

	// Initialize metrics recorder
	var metrics MetricsRecorder
	if config.EnableMetrics {
		metrics = NewPrometheusMetrics()
	} else {
		metrics = &NoopMetrics{}
	}

	return &ClientManager{
		entries: sync.Map{},
		sf:      singleflight.Group{},
		config:  config,
		metrics: metrics,
	}
}

// GetClient retrieves or creates a Vault client from the cache.
// Uses singleflight to prevent duplicate concurrent creation for the same key.
func (c *ClientManager) GetClient(
	ctx context.Context,
	config ClientConfig,
	createFn func() (util.Client, time.Time, bool, error),
) (util.Client, error) {
	// Compute cache key
	key := config.ComputeCacheKey()

	// Use singleflight to prevent duplicate concurrent creation
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		// Check cache first
		if cached, ok := c.entries.Load(key); ok {
			entry := cached.(*CacheEntry)
			c.metrics.RecordCacheHit()

			// Check if token needs renewal
			if err := c.renewTokenIfNeeded(ctx, entry); err != nil {
				// Renewal failed, fall through to create new client
				c.entries.Delete(key)
			} else {
				// Return cached client
				return entry.Client, nil
			}
		}

		// Cache miss - create new client
		c.metrics.RecordCacheMiss()

		client, expiry, renewable, err := createFn()
		if err != nil {
			return nil, fmt.Errorf("failed to create vault client: %w", err)
		}

		// Store in cache
		entry := &CacheEntry{
			Client:      client,
			TokenExpiry: expiry,
			Renewable:   renewable,
			CreatedAt:   time.Now(),
			CacheKey:    key,
			AuthContext: config.AuthContext,
		}
		c.entries.Store(key, entry)

		// Update cache size metric
		c.updateCacheSize()

		return client, nil
	})

	if err != nil {
		return nil, err
	}

	return v.(util.Client), nil
}

// renewTokenIfNeeded checks if a token needs renewal and renews it if necessary.
func (c *ClientManager) renewTokenIfNeeded(
	ctx context.Context,
	entry *CacheEntry,
) error {
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Check time until expiry
	timeUntilExpiry := time.Until(entry.TokenExpiry)
	if timeUntilExpiry > c.config.RenewalWindow {
		// No renewal needed yet
		return nil
	}

	// Check if token is renewable
	if !entry.Renewable {
		return fmt.Errorf("token is not renewable and expires in %v", timeUntilExpiry)
	}

	// Attempt to renew the token (increment=0 means use default TTL)
	secret, err := entry.Client.AuthToken().RenewSelfWithContext(ctx, 0)
	if err != nil {
		c.metrics.RecordRenewal("failure")
		return fmt.Errorf("failed to renew vault token: %w", err)
	}

	// Extract new lease duration from response
	if secret != nil && secret.Auth != nil && secret.Auth.LeaseDuration > 0 {
		newExpiry := time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
		entry.TokenExpiry = newExpiry
	}

	c.metrics.RecordRenewal("success")
	return nil
}

// Invalidate removes a specific cache entry by key.
func (c *ClientManager) Invalidate(ctx context.Context, key string) error {
	c.entries.Delete(key)
	c.metrics.RecordInvalidation("manual")
	c.updateCacheSize()
	return nil
}

// InvalidateBySecret invalidates all cache entries that depend on a specific secret.
func (c *ClientManager) InvalidateBySecret(ctx context.Context, namespace, name string) int {
	count := 0

	c.entries.Range(func(key, value interface{}) bool {
		entry := value.(*CacheEntry)

		// Check if entry has auth context
		if entry.AuthContext == nil {
			return true // continue iteration
		}

		// Check if any secret reference matches
		for _, ref := range entry.AuthContext.SecretRefs {
			if ref.Namespace == namespace && ref.Name == name {
				c.entries.Delete(key)
				c.metrics.RecordInvalidation("secret_change")
				count++
				return true // continue iteration
			}
		}

		return true // continue iteration
	})

	if count > 0 {
		c.updateCacheSize()
	}

	return count
}

// InvalidateByServiceAccount invalidates all cache entries that depend on a specific service account.
func (c *ClientManager) InvalidateByServiceAccount(ctx context.Context, namespace, name string) int {
	count := 0

	c.entries.Range(func(key, value interface{}) bool {
		entry := value.(*CacheEntry)

		// Check if entry has auth context with service account reference
		if entry.AuthContext == nil || entry.AuthContext.ServiceAccountRef == nil {
			return true // continue iteration
		}

		// Check if service account reference matches
		if entry.AuthContext.ServiceAccountRef.Namespace == namespace &&
			entry.AuthContext.ServiceAccountRef.Name == name {
			c.entries.Delete(key)
			c.metrics.RecordInvalidation("serviceaccount_change")
			count++
		}

		return true // continue iteration
	})

	if count > 0 {
		c.updateCacheSize()
	}

	return count
}

// Shutdown gracefully shuts down the cache, revoking all cached tokens.
func (c *ClientManager) Shutdown(ctx context.Context) error {
	// Iterate all entries and revoke tokens
	c.entries.Range(func(key, value interface{}) bool {
		entry := value.(*CacheEntry)

		// Only revoke valid, non-expired tokens
		if entry.Client.Token() != "" && time.Now().Before(entry.TokenExpiry) {
			if err := revokeToken(ctx, entry.Client); err != nil {
				// Log error but continue shutdown
				// In a production system, you might want to use a proper logger here
				_ = err
			}
		}

		return true // continue iteration
	})

	// Clear the cache
	c.entries = sync.Map{}
	c.updateCacheSize()

	return nil
}

// revokeToken revokes a Vault token and clears it from the client.
func revokeToken(ctx context.Context, client util.Client) error {
	token := client.Token()
	if token == "" {
		return nil
	}

	// Attempt to revoke the token
	if err := client.AuthToken().RevokeSelfWithContext(ctx, token); err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	// Clear the token from the client
	client.ClearToken()

	return nil
}

// updateCacheSize updates the cache size metric.
func (c *ClientManager) updateCacheSize() {
	size := 0
	c.entries.Range(func(key, value interface{}) bool {
		size++
		return true
	})
	c.metrics.SetCacheSize(size)
}
