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
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// cachedClient wraps a Vault client with reference counting and eviction tracking.
type cachedClient struct {
	// client is the underlying Vault client
	client util.Client

	// config stores the client configuration for re-authentication
	config VaultClientConfig

	// refCount tracks the number of active leases on this client
	refCount atomic.Int32

	// evicted indicates whether this client has been evicted from the cache
	evicted atomic.Bool

	// logger for logging client operations
	logger logr.Logger

	// renewMu protects renewal operations
	renewMu sync.Mutex

	// renewTimer schedules token renewal
	renewTimer *time.Timer

	// renewalEnabled indicates if token renewal is enabled
	renewalEnabled bool

	// createdAt tracks when this client was created (for max age tracking)
	createdAt time.Time

	// metrics for tracking renewal errors
	metrics *poolMetrics
}

// newCachedClient creates a new cached client wrapper.
func newCachedClient(client util.Client, config VaultClientConfig, logger logr.Logger, renewalEnabled bool, metrics *poolMetrics) *cachedClient {
	c := &cachedClient{
		client:         client,
		config:         config,
		logger:         logger,
		renewalEnabled: renewalEnabled,
		createdAt:      time.Now(),
		metrics:        metrics,
	}
	c.refCount.Store(0)
	c.evicted.Store(false)

	// Schedule renewal if enabled and token is renewable
	if renewalEnabled && isRenewable(client) {
		c.scheduleRenewal()
	}

	return c
}

// acquire increments the reference count and returns the client.
func (c *cachedClient) acquire() util.Client {
	c.refCount.Add(1)
	c.logger.V(2).Info("acquired client lease", "refCount", c.refCount.Load())
	return c.client
}

// release decrements the reference count and performs cleanup if necessary.
func (c *cachedClient) release(ctx context.Context) error {
	newCount := c.refCount.Add(-1)
	c.logger.V(2).Info("released client lease", "refCount", newCount)

	// If this was the last reference and the client has been evicted,
	// perform cleanup (revoke token if not static)
	if newCount == 0 && c.evicted.Load() {
		return c.cleanup(ctx)
	}
	return nil
}

// markEvicted marks this client as evicted from the cache.
// Cleanup will be performed when the last reference is released.
func (c *cachedClient) markEvicted() {
	c.evicted.Store(true)
	c.logger.V(1).Info("client marked as evicted")
}

// cleanup revokes the token if it's not a static token.
func (c *cachedClient) cleanup(ctx context.Context) error {
	// Cancel any pending renewal
	c.cancelRenewal()

	// Only revoke tokens that are not static (i.e., not from TokenSecretRef)
	if !isStaticToken(c.config.VaultSpec) {
		c.logger.V(1).Info("cleaning up client, revoking token")
		return revokeTokenIfValid(ctx, c.client)
	}
	c.logger.V(1).Info("skipping token revocation for static token")
	return nil
}

// scheduleRenewal schedules the next token renewal.
func (c *cachedClient) scheduleRenewal() {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()

	// Get token TTL
	secret, err := c.client.AuthToken().LookupSelfWithContext(context.Background())
	if err != nil {
		c.logger.Error(err, "failed to lookup token for renewal scheduling")
		return
	}

	ttl, err := secret.TokenTTL()
	if err != nil || ttl == 0 {
		c.logger.V(2).Info("token has no TTL, skipping renewal")
		return
	}

	// Schedule renewal at 80% of TTL
	renewAt := time.Duration(float64(ttl) * 0.8)
	c.logger.V(1).Info("scheduling token renewal", "ttl", ttl, "renewAt", renewAt)

	c.renewTimer = time.AfterFunc(renewAt, func() {
		if err := c.renew(); err != nil {
			c.logger.Error(err, "token renewal failed")
		}
	})
}

// renew attempts to renew the token with exponential backoff.
func (c *cachedClient) renew() error {
	const maxAttempts = 3
	backoff := 1 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		secret, err := c.client.AuthToken().LookupSelfWithContext(context.Background())
		if err != nil {
			c.metrics.incrementRenewalErrors()
			c.logger.Error(err, "renewal attempt failed", "attempt", attempt)

			if attempt < maxAttempts {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}

			// After max failures, mark client as evicted
			c.logger.Error(err, "max renewal attempts reached, marking client as evicted")
			c.markEvicted()
			return err
		}

		// Check if token is still renewable
		renewable, _ := secret.Data["renewable"].(bool)
		if !renewable {
			c.logger.V(2).Info("token is no longer renewable")
			return nil
		}

		// Renew the token using the client's AuthToken interface
		_, err = c.client.AuthToken().RenewSelfWithContext(context.Background(), 0) // renew for the default increment
		if err != nil {
			c.metrics.incrementRenewalErrors()
			c.logger.Error(err, "token renew failed", "attempt", attempt)

			if attempt < maxAttempts {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}

			// After max failures, mark client as evicted
			c.logger.Error(err, "max renewal attempts reached, marking client as evicted")
			c.markEvicted()
			return err
		}

		c.logger.V(1).Info("token renewed successfully")

		// Schedule next renewal
		c.scheduleRenewal()
		return nil
	}

	return nil
}

// cancelRenewal cancels any pending renewal timer.
func (c *cachedClient) cancelRenewal() {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()

	if c.renewTimer != nil {
		c.renewTimer.Stop()
		c.renewTimer = nil
		c.logger.V(2).Info("renewal timer cancelled")
	}
}

// isRenewable checks if the token is renewable.
func isRenewable(client util.Client) bool {
	secret, err := client.AuthToken().LookupSelfWithContext(context.Background())
	if err != nil {
		return false
	}
	renewable, _ := secret.Data["renewable"].(bool)
	return renewable
}
