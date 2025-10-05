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
	"errors"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"golang.org/x/sync/singleflight"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

var _ ClientLease = &pooledLease{}

// pooledLease implements ClientLease for cached clients.
type pooledLease struct {
	// cached is the cached client wrapper
	cached *cachedClient

	// reauth is a singleflight group for deduplicating re-authentication attempts
	reauth singleflight.Group

	// authFunc is the function used to authenticate the client
	authFunc func(context.Context) error

	// breaker is the circuit breaker (optional)
	breaker *circuitBreaker

	// metrics provides Prometheus metrics
	metrics *poolMetrics
}

// newPooledLease creates a new pooled lease.
func newPooledLease(cached *cachedClient, authFunc func(context.Context) error, breaker *circuitBreaker, metrics *poolMetrics) *pooledLease {
	return &pooledLease{
		cached:   cached,
		authFunc: authFunc,
		breaker:  breaker,
		metrics:  metrics,
	}
}

// Client returns the underlying Vault client.
func (l *pooledLease) Client() util.Client {
	return l.cached.client
}

// WithRetry executes an operation with automatic retry on authentication errors.
func (l *pooledLease) WithRetry(ctx context.Context, op func(util.Client) error) error {
	// First attempt
	err := op(l.cached.client)
	if err == nil {
		return nil
	}

	// Check if this is an authentication error
	if !isAuthError(err) {
		return err
	}

	l.cached.logger.V(1).Info("authentication error detected, attempting re-authentication")
	l.metrics.incrementReauthAttempts()

	// Re-authenticate using singleflight to deduplicate concurrent re-auth attempts
	_, authErr, _ := l.reauth.Do("reauth", func() (interface{}, error) {
		return nil, l.authFunc(ctx)
	})

	// CRITICAL: Forget the key to prevent memory leaks
	// This ensures the singleflight group doesn't hold onto the result indefinitely
	l.reauth.Forget("reauth")

	if authErr != nil {
		l.cached.logger.Error(authErr, "failed to re-authenticate")
		l.metrics.incrementAuthErrors()

		// Record failure in circuit breaker
		if l.breaker != nil {
			breakerKey := getBreakerKey(l.cached.config.VaultSpec.Server, getAuthMethod(l.cached.config.VaultSpec))
			l.breaker.RecordFailure(breakerKey)
		}

		return authErr
	}

	// Record success in circuit breaker
	if l.breaker != nil {
		breakerKey := getBreakerKey(l.cached.config.VaultSpec.Server, getAuthMethod(l.cached.config.VaultSpec))
		l.breaker.RecordSuccess(breakerKey)
	}

	l.cached.logger.V(1).Info("re-authentication successful, retrying operation")

	// Retry the operation with the new token
	return op(l.cached.client)
}

// Release returns the client to the pool.
func (l *pooledLease) Release() error {
	return l.cached.release(context.Background())
}

// isAuthError checks if an error is an authentication/authorization error.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check for Vault ResponseError with 401 or 403 status code
	var respErr *vault.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == 401 || respErr.StatusCode == 403
	}

	// Check error message for common authentication error patterns
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "permission denied") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "forbidden")
}
