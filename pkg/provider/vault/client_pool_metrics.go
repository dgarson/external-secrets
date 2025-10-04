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

	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// MetricsClientPool is a decorator that wraps a ClientPool and emits metrics.
// It has no business logic - only observability concerns.
type MetricsClientPool struct {
	inner ClientPool

	// Per-address client count tracking for metrics
	countsMu      sync.Mutex
	addressCounts map[string]int

	// Client index for reverse lookup (client -> address) for ReleaseClient
	indexMu     sync.RWMutex
	clientIndex map[util.Client]string
}

// NewMetricsClientPool creates a new MetricsClientPool that wraps an inner ClientPool.
func NewMetricsClientPool(inner ClientPool) *MetricsClientPool {
	return &MetricsClientPool{
		inner:         inner,
		addressCounts: make(map[string]int),
		clientIndex:   make(map[util.Client]string),
	}
}

// AcquireClient delegates to the inner pool and emits metrics.
func (m *MetricsClientPool) AcquireClient(ctx context.Context, config AcquireClientConfig) (util.Client, error) {
	client, err := m.inner.AcquireClient(ctx, config)

	if err != nil {
		// Failed to acquire client
		address := ""
		if config.VaultProvider != nil {
			address = config.VaultProvider.Server
		}
		metrics.ObserveVaultClientPoolOperation("acquire_failed", address, err)
		return nil, err
	}

	// Successfully acquired client
	address := client.GetAddress()

	// Track client for reverse lookup in ReleaseClient
	m.indexMu.Lock()
	m.clientIndex[client] = address
	m.indexMu.Unlock()

	// Track address count
	m.trackClientAdded(address)

	// Emit acquisition success metric
	metrics.ObserveVaultClientPoolOperation("acquire_success", address, nil)

	return client, nil
}

// ReleaseClient delegates to the inner pool and emits metrics.
func (m *MetricsClientPool) ReleaseClient(ctx context.Context, client util.Client) error {
	if client == nil {
		return nil
	}

	// Get address before releasing
	m.indexMu.RLock()
	address, exists := m.clientIndex[client]
	m.indexMu.RUnlock()

	if !exists {
		// Client not tracked, just delegate
		return m.inner.ReleaseClient(ctx, client)
	}

	// Delegate to inner pool
	err := m.inner.ReleaseClient(ctx, client)

	// Note: We don't decrement address counts here because clients can be reused.
	// The count represents active cached clients, not active borrows.
	// Counts are decremented when clients are finalized/evicted.

	if err != nil {
		metrics.ObserveVaultClientPoolOperation("release_failed", address, err)
	}

	return err
}

// Close delegates to the inner pool and emits metrics.
func (m *MetricsClientPool) Close(ctx context.Context) error {
	err := m.inner.Close(ctx)

	metrics.ObserveVaultClientPoolOperation("pool_closed", "", err)

	// Clear tracking maps
	m.indexMu.Lock()
	m.clientIndex = make(map[util.Client]string)
	m.indexMu.Unlock()

	m.countsMu.Lock()
	// Reset all address counts to 0
	for address := range m.addressCounts {
		metrics.SetVaultClientPoolSize(address, 0)
	}
	m.addressCounts = make(map[string]int)
	m.countsMu.Unlock()

	return err
}

// trackClientAdded increments the count for an address and emits a metric.
func (m *MetricsClientPool) trackClientAdded(address string) {
	m.countsMu.Lock()
	defer m.countsMu.Unlock()

	next := m.addressCounts[address] + 1
	m.addressCounts[address] = next
	metrics.SetVaultClientPoolSize(address, next)
}

// TrackClientRemoved decrements the count for an address and emits a metric.
// This is called by the inner pool when a client is finalized/evicted.
func (m *MetricsClientPool) TrackClientRemoved(address string) {
	m.countsMu.Lock()
	defer m.countsMu.Unlock()

	count := m.addressCounts[address] - 1
	if count <= 0 {
		delete(m.addressCounts, address)
		metrics.SetVaultClientPoolSize(address, 0)
		return
	}
	m.addressCounts[address] = count
	metrics.SetVaultClientPoolSize(address, count)
}

// Verify MetricsClientPool implements ClientPool interface.
var _ ClientPool = &MetricsClientPool{}
