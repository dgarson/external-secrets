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
	"time"

	"github.com/go-logr/logr"
)

// PoolConfig contains configuration for the client pool.
//
// Use DefaultPoolConfig() to get sensible defaults, then customize as needed.
type PoolConfig struct {
	// MaxSize is the maximum number of cached clients in the pool.
	// When the pool reaches this size, the least recently used client will
	// be evicted to make room for new clients.
	// Default: 100
	// Recommended range: 10-1000 depending on cluster size
	MaxSize int

	// MaxAge is the maximum age of a client before it's marked for eviction.
	// Clients older than this duration will be removed during cleanup cycles.
	// Set to 0 to disable age-based eviction.
	// Default: 0 (disabled)
	// Recommended: 1-24 hours if token rotation is desired
	MaxAge time.Duration

	// CleanupInterval is how often to run background cleanup.
	// The cleanup routine removes evicted clients with no references and
	// enforces max age limits.
	// Default: 5 minutes
	// Recommended range: 1-30 minutes
	CleanupInterval time.Duration

	// EnableRenewal enables automatic token renewal for renewable tokens.
	// When enabled, tokens are renewed at 80% of their TTL to prevent expiration.
	// Tokens that fail renewal after max retries are marked for eviction.
	// Default: false
	// Recommended: Enable for long-running pools with renewable auth methods
	EnableRenewal bool

	// EnableBreaker enables the circuit breaker to prevent auth storms.
	// When enabled, repeated authentication failures will open the circuit
	// and temporarily block new authentication attempts.
	// Default: true
	// Recommended: Always enabled in production
	EnableBreaker bool

	// BreakerConfig contains circuit breaker configuration.
	// Only used if EnableBreaker is true.
	BreakerConfig BreakerConfig

	// Logger is used for logging pool operations.
	// Required field - use ctrl.Log.WithName("vault-pool") or similar.
	Logger logr.Logger
}

// DefaultPoolConfig returns a PoolConfig with sensible defaults.
func DefaultPoolConfig(logger logr.Logger) PoolConfig {
	return PoolConfig{
		MaxSize:         100,
		MaxAge:          0, // disabled
		CleanupInterval: 5 * time.Minute,
		EnableRenewal:   false,
		EnableBreaker:   true,
		BreakerConfig: BreakerConfig{
			Threshold:    5,
			OpenDuration: 30 * time.Second,
		},
		Logger: logger,
	}
}

// NewCachingPool creates a new caching client pool with the given configuration.
func NewCachingPool(cfg PoolConfig) ClientPool {
	return newCachingPool(cfg)
}

// NewNoOpPool creates a new no-op client pool that doesn't cache clients.
// This maintains backward compatibility when caching is disabled.
func NewNoOpPool() ClientPool {
	return newNoOpPool()
}
