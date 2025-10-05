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

// Package vault provides HashiCorp Vault integration for External Secrets Operator.
//
// The client pooling system caches authenticated Vault clients to reduce authentication
// overhead and prevent token revocation on every operation. It includes:
//   - Automatic re-authentication on 401/403 errors
//   - Circuit breaking to prevent auth storms during outages
//   - Optional token renewal for renewable tokens
//   - Reference counting to prevent cleanup of in-use clients
//   - LRU eviction for cache management
//   - Comprehensive Prometheus metrics
//
// # Basic Usage
//
//	pool := vault.NewCachingPool(vault.PoolConfig{
//	    MaxSize: 100,
//	    EnableBreaker: true,
//	    Logger: logger,
//	})
//	defer pool.Shutdown(context.Background())
//
//	lease, err := pool.Acquire(ctx, config)
//	if err != nil {
//	    return err
//	}
//	defer lease.Release()
//
//	err = lease.WithRetry(ctx, func(client util.Client) error {
//	    // Use client for Vault operations
//	    secret, err := client.Logical().ReadWithDataWithContext(ctx, "secret/data/myapp", nil)
//	    return err
//	})
//
// # Thread Safety
//
// All pool operations are thread-safe and designed for concurrent use.
// The pool uses fine-grained locking and singleflight deduplication to
// minimize contention during concurrent acquisitions.
//
// # Performance
//
// Cache key generation: ~320 ns/op
// Circuit breaker check: ~3.5 ns/op
// Concurrent acquisition: ~816 ns/op
//
// # Backward Compatibility
//
// For environments where pooling is not desired, use NewNoOpPool() which
// provides the same interface but creates a new client for each acquisition.
package vault

import (
	"context"

	vault "github.com/hashicorp/vault/api"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// ClientPool manages a pool of Vault clients with automatic lifecycle management.
//
// The pool caches authenticated clients using an LRU cache with configurable size.
// Clients are deduplicated using singleflight to prevent authentication storms
// when multiple goroutines request the same client concurrently.
//
// Thread-safe for concurrent use.
type ClientPool interface {
	// Acquire obtains a client from the pool or creates a new one.
	//
	// If a cached client exists for the given configuration, it will be reused
	// (cache hit). Otherwise, a new client is created and authenticated (cache miss).
	// Concurrent acquisitions for the same configuration are deduplicated using
	// singleflight to prevent redundant authentication attempts.
	//
	// The returned lease must be released when done to properly manage reference
	// counts and enable cleanup. Always use defer lease.Release() after acquisition.
	//
	// Returns an error if:
	//   - The circuit breaker is open (too many recent failures)
	//   - Client creation fails
	//   - Authentication fails
	//   - Context is cancelled
	Acquire(ctx context.Context, config VaultClientConfig) (ClientLease, error)

	// Shutdown gracefully shuts down the pool and releases all resources.
	//
	// This stops the background cleanup goroutine, cancels all renewal timers,
	// and revokes tokens for clients that are no longer in use. Clients with
	// active leases are marked for eviction and will be cleaned up when released.
	//
	// The shutdown respects the provided context timeout. If cleanup cannot
	// complete within the timeout, an error is returned but the pool is still
	// in a shutdown state.
	//
	// Multiple calls to Shutdown are safe and will only execute once.
	Shutdown(ctx context.Context) error
}

// ClientLease represents a lease on a Vault client from the pool.
//
// A lease provides access to a pooled Vault client and must be explicitly
// released when done to maintain accurate reference counts. Leases support
// automatic re-authentication on auth errors via the WithRetry method.
//
// Thread-safe for concurrent use by a single lessee.
type ClientLease interface {
	// Client returns the underlying Vault client.
	//
	// The client should only be used for the duration of the lease.
	// Do not retain references to the client after calling Release().
	Client() util.Client

	// WithRetry executes an operation with automatic retry on authentication errors.
	//
	// If the operation returns a 401, 403, or other authentication error,
	// WithRetry will automatically re-authenticate the client and retry the
	// operation once. This provides transparent recovery from token expiration.
	//
	// Re-authentication attempts are deduplicated using singleflight to prevent
	// concurrent re-auth attempts from the same lease.
	//
	// Example:
	//   err := lease.WithRetry(ctx, func(client util.Client) error {
	//       secret, err := client.Logical().ReadWithDataWithContext(ctx, path, nil)
	//       if err != nil {
	//           return err
	//       }
	//       // Process secret...
	//       return nil
	//   })
	//
	// Returns the error from the operation if it succeeds on first attempt or
	// after retry. If re-authentication fails, returns the re-auth error.
	WithRetry(ctx context.Context, op func(util.Client) error) error

	// Release returns the client to the pool.
	//
	// This decrements the reference count on the underlying cached client.
	// If the reference count reaches zero and the client has been evicted
	// from the cache, the client's token will be revoked (unless it's a
	// static token).
	//
	// Must be called exactly once per acquired lease. Calling Release()
	// multiple times may lead to undefined behavior.
	//
	// Always use defer lease.Release() immediately after acquisition:
	//   lease, err := pool.Acquire(ctx, config)
	//   if err != nil {
	//       return err
	//   }
	//   defer lease.Release()
	Release() error
}

// VaultClientConfig contains all configuration needed to create a Vault client.
type VaultClientConfig struct {
	// VaultConfig is the Vault client configuration
	VaultConfig *vault.Config

	// VaultSpec is the VaultProvider spec from the SecretStore
	VaultSpec *esv1.VaultProvider

	// Kubernetes is the Kubernetes client
	Kubernetes kclient.Client

	// CoreV1 is the CoreV1 interface for Kubernetes API
	CoreV1 typedcorev1.CoreV1Interface

	// CredentialNS is the namespace to use for credential lookups
	CredentialNS string

	// StoreKind is the kind of the SecretStore (SecretStore or ClusterSecretStore)
	StoreKind string

	// StoreName is the name of the SecretStore
	StoreName string

	// StoreNamespace is the namespace of the SecretStore
	StoreNamespace string
}
