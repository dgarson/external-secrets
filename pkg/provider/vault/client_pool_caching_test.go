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
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/fake"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// createTestAcquireConfig creates a test AcquireClientConfig with static token auth
func createTestAcquireConfig(server, namespace string) AcquireClientConfig {
	kube := clientfake.NewClientBuilder().WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-token",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"token": []byte("test-token"),
		},
	}).Build()

	return AcquireClientConfig{
		VaultConfig: &vault.Config{},
		VaultProvider: &esv1.VaultProvider{
			Server: server,
			Auth: &esv1.VaultAuth{
				TokenSecretRef: &esmeta.SecretKeySelector{
					Name:      "vault-token",
					Namespace: &namespace,
					Key:       "token",
				},
			},
		},
		Kube:      kube,
		Namespace: namespace,
		StoreKind: esv1.SecretStoreKind,
	}
}

// createAppRoleAcquireConfig creates a test AcquireClientConfig for AppRole auth
func createAppRoleAcquireConfig(server, namespace string) AcquireClientConfig {
	kube := clientfake.NewClientBuilder().WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"id": []byte("test-secret-id"),
		},
	}).Build()

	return AcquireClientConfig{
		VaultConfig: &vault.Config{},
		VaultProvider: &esv1.VaultProvider{
			Server: server,
			Auth: &esv1.VaultAuth{
				AppRole: &esv1.VaultAppRole{
					Path:   "approle",
					RoleID: "test-role",
					SecretRef: esmeta.SecretKeySelector{
						Name:      "secret",
						Namespace: &namespace,
						Key:       "id",
					},
				},
			},
		},
		Kube:      kube,
		Namespace: namespace,
		StoreKind: esv1.SecretStoreKind,
	}
}

func TestCachingClientPool_BasicCaching(t *testing.T) {
	var clientCreationCount atomic.Int32

	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: func(config *vault.Config) (util.Client, error) {
			clientCreationCount.Add(1)
			return fake.ClientWithLoginMock(config)
		},
		EnableRenewal: false,
	})
	defer pool.Close(context.Background())

	ctx := context.Background()
	config1 := createTestAcquireConfig("https://vault.example.com", "default")

	// First acquire - should create new client
	client1, err := pool.AcquireClient(ctx, config1)
	require.NoError(t, err)
	require.NotNil(t, client1)
	assert.Equal(t, int32(1), clientCreationCount.Load(), "should create one client")

	// Second acquire with same config - should return cached client
	client2, err := pool.AcquireClient(ctx, config1)
	require.NoError(t, err)
	require.NotNil(t, client2)
	assert.Equal(t, int32(1), clientCreationCount.Load(), "should not create another client")
	assert.Equal(t, client1, client2, "should return the same client instance")

	// Acquire with different server - should create new client
	config2 := config1
	config2.VaultProvider = &esv1.VaultProvider{
		Server: "https://vault2.example.com",
		Auth: &esv1.VaultAuth{
			TokenSecretRef: &esmeta.SecretKeySelector{
				Name: "vault-token",
				Key:  "token",
			},
		},
	}
	client3, err := pool.AcquireClient(ctx, config2)
	require.NoError(t, err)
	require.NotNil(t, client3)
	assert.Equal(t, int32(2), clientCreationCount.Load(), "should create second client for different server")
	assert.NotEqual(t, client1, client3, "should be different client instances")

	// Verify ReleaseClient is a no-op for caching pool
	err = pool.ReleaseClient(ctx, client2)
	require.NoError(t, err, "ReleaseClient should not error")

	// Should still be able to acquire the same client after release
	client4, err := pool.AcquireClient(ctx, config1)
	require.NoError(t, err)
	assert.Equal(t, client1, client4, "should return same cached client after release")
	assert.Equal(t, int32(2), clientCreationCount.Load(), "should not create new client after release")
}

func TestCachingClientPool_DifferentCacheKeys(t *testing.T) {
	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: fake.ClientWithLoginMock,
		EnableRenewal:  false,
	})
	defer pool.Close(context.Background())

	ctx := context.Background()
	baseConfig := createTestAcquireConfig("https://vault.example.com", "default")

	tests := []struct {
		name         string
		modifyConfig func(*AcquireClientConfig)
		shouldReuse  bool
	}{
		{
			name:         "same config should reuse",
			modifyConfig: func(c *AcquireClientConfig) {},
			shouldReuse:  true,
		},
		{
			name: "different server should not reuse",
			modifyConfig: func(c *AcquireClientConfig) {
				c.VaultProvider.Server = "https://vault2.example.com"
			},
			shouldReuse: false,
		},
		{
			name: "different vault namespace should not reuse",
			modifyConfig: func(c *AcquireClientConfig) {
				ns := "different-vault-ns"
				c.VaultProvider.Namespace = &ns
			},
			shouldReuse: false,
		},
	}

	// Get baseline client
	baseClient, err := pool.AcquireClient(ctx, baseConfig)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := baseConfig
			tt.modifyConfig(&config)

			client, err := pool.AcquireClient(ctx, config)
			require.NoError(t, err)
			require.NotNil(t, client)

			if tt.shouldReuse {
				assert.Equal(t, baseClient, client, "should reuse cached client")
			} else {
				assert.NotEqual(t, baseClient, client, "should create new client")
			}
		})
	}
}

func TestCachingClientPool_StaticTokenHandling(t *testing.T) {
	var renewalCallCount atomic.Int32

	// Create a client with custom renewal tracking
	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: func(config *vault.Config) (util.Client, error) {
			client, err := fake.ClientWithLoginMock(config)
			if err != nil {
				return nil, err
			}

			// Wrap the token to track renewals
			vc := client.(*util.VaultClient)
			origToken := vc.AuthTokenField
			vc.AuthTokenField = &util.VaultToken{
				LookupSelfFunc: origToken.LookupSelfWithContext,
				RevokeSelfFunc: origToken.RevokeSelfWithContext,
				RenewSelfFunc: func(ctx context.Context, increment int) (*vault.Secret, error) {
					renewalCallCount.Add(1)
					return &vault.Secret{}, nil
				},
			}

			return client, nil
		},
		EnableRenewal:        true,
		RenewalCheckInterval: 50 * time.Millisecond,
	})
	defer pool.Close(context.Background())

	ctx := context.Background()
	config := createTestAcquireConfig("https://vault.example.com", "default")

	client, err := pool.AcquireClient(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Wait to see if renewal happens (it shouldn't for static tokens)
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int32(0), renewalCallCount.Load(), "static tokens should not be renewed")
}

func TestCachingClientPool_TokenRenewal(t *testing.T) {
	var renewalCallCount atomic.Int32

	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: func(config *vault.Config) (util.Client, error) {
			client, err := fake.ClientWithLoginMock(config)
			if err != nil {
				return nil, err
			}

			// Wrap to track renewals and return low TTL
			vc := client.(*util.VaultClient)
			vc.AuthTokenField = &util.VaultToken{
				LookupSelfFunc: func(ctx context.Context) (*vault.Secret, error) {
					return &vault.Secret{
						Data: map[string]interface{}{
							"ttl":          json.Number("100"),  // Low TTL to trigger renewal
							"creation_ttl": json.Number("3600"), // creation_ttl
							"renewable":    true,
							"type":         "service",
						},
					}, nil
				},
				RenewSelfFunc: func(ctx context.Context, increment int) (*vault.Secret, error) {
					renewalCallCount.Add(1)
					return &vault.Secret{}, nil
				},
				RevokeSelfFunc: func(ctx context.Context, token string) error {
					return nil
				},
			}

			return client, nil
		},
		EnableRenewal:           true,
		RenewalThresholdPercent: 50, // Since we provide explicit RenewalCheckInterval, dynamic calculation is skipped
		RenewalCheckInterval:    50 * time.Millisecond,
	})
	defer pool.Close(context.Background())

	ctx := context.Background()

	// Create test config with AppRole auth to trigger renewal
	namespace := "default"
	kube := clientfake.NewClientBuilder().WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"id": []byte("test-secret-id"),
		},
	}).Build()

	config := AcquireClientConfig{
		VaultConfig: &vault.Config{},
		VaultProvider: &esv1.VaultProvider{
			Server: "https://vault.example.com",
			Auth: &esv1.VaultAuth{
				AppRole: &esv1.VaultAppRole{
					Path:   "approle",
					RoleID: "test-role",
					SecretRef: esmeta.SecretKeySelector{
						Name:      "secret",
						Namespace: &namespace,
						Key:       "id",
					},
				},
			},
		},
		Kube:      kube,
		Namespace: namespace,
		StoreKind: esv1.SecretStoreKind,
	}

	client, err := pool.AcquireClient(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Wait for renewal to happen
	// Using static check interval of 50ms since we provided explicit RenewalCheckInterval
	// TTL is 100, threshold is 50% of creation_ttl (3600) = 1800, and 100 < 1800, so renewal should happen
	time.Sleep(250 * time.Millisecond)

	count := renewalCallCount.Load()
	assert.Greater(t, count, int32(0), "token should be renewed at least once, got %d", count)
}

func TestCachingClientPool_Close(t *testing.T) {
	var revokeCallCount atomic.Int32

	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: func(config *vault.Config) (util.Client, error) {
			client, err := fake.ClientWithLoginMock(config)
			if err != nil {
				return nil, err
			}

			// Wrap to track revocations
			vc := client.(*util.VaultClient)
			origToken := vc.AuthTokenField
			vc.AuthTokenField = &util.VaultToken{
				LookupSelfFunc: origToken.LookupSelfWithContext,
				RenewSelfFunc:  origToken.RenewSelfWithContext,
				RevokeSelfFunc: func(ctx context.Context, token string) error {
					revokeCallCount.Add(1)
					return nil
				},
			}

			return client, nil
		},
		EnableRenewal:        true,
		RenewalCheckInterval: 100 * time.Millisecond,
	})

	ctx := context.Background()

	// Create test config with AppRole auth
	namespace := "default"
	kube := clientfake.NewClientBuilder().WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"id": []byte("test-secret-id"),
		},
	}).Build()

	config := AcquireClientConfig{
		VaultConfig: &vault.Config{},
		VaultProvider: &esv1.VaultProvider{
			Server: "https://vault.example.com",
			Auth: &esv1.VaultAuth{
				AppRole: &esv1.VaultAppRole{
					Path:   "approle",
					RoleID: "test-role",
					SecretRef: esmeta.SecretKeySelector{
						Name:      "secret",
						Namespace: &namespace,
						Key:       "id",
					},
				},
			},
		},
		Kube:      kube,
		Namespace: namespace,
		StoreKind: esv1.SecretStoreKind,
	}

	// Acquire a client
	client, err := pool.AcquireClient(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Close the pool
	err = pool.Close(context.Background())
	require.NoError(t, err)

	// Verify token was revoked
	assert.Equal(t, int32(1), revokeCallCount.Load(), "token should be revoked on close")
}

func TestCachingClientPool_RenewalFailureEvictsClient(t *testing.T) {
	var renewAttempts atomic.Int32
	var clientCreationCount atomic.Int32

	base := fake.ModifiableClientWithLoginMock(func(cl *fake.VaultClient) {
		cl.MockAuthToken = fake.Token{
			RevokeSelfWithContextFn: func(ctx context.Context, token string) error { return nil },
			LookupSelfWithContextFn: func(ctx context.Context) (*vault.Secret, error) {
				return &vault.Secret{
					Data: map[string]interface{}{
						"type":         "service",
						"ttl":          json.Number("10"),
						"creation_ttl": json.Number("100"),
						"renewable":    true,
						"expire_time":  "2099-01-01T00:00:00Z",
					},
				}, nil
			},
			RenewSelfWithContextFn: func(ctx context.Context, increment int) (*vault.Secret, error) {
				renewAttempts.Add(1)
				return nil, errors.New("renewal failed")
			},
		}
	})

	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: func(config *vault.Config) (util.Client, error) {
			clientCreationCount.Add(1)
			return base(config)
		},
		EnableRenewal:           true,
		RenewalCheckInterval:    50 * time.Millisecond,
		RenewalThresholdPercent: 50,
		TokenOperationTimeout:   200 * time.Millisecond,
		MaxCacheSize:            1,
	})
	ctx := context.Background()

	config := createAppRoleAcquireConfig("https://vault-renewal.example.com", "renewal-ns")
	client, err := pool.AcquireClient(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, client)

	require.Eventually(t, func() bool {
		return renewAttempts.Load() >= renewalFailureThreshold
	}, 2*time.Second, 50*time.Millisecond)

	// Allow eviction to process
	time.Sleep(100 * time.Millisecond)

	newClient, err := pool.AcquireClient(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, newClient)
	assert.NotEqual(t, client, newClient, "client should be evicted and recreated")
	assert.GreaterOrEqual(t, clientCreationCount.Load(), int32(2), "new client should be constructed after eviction")

	require.NoError(t, pool.ReleaseClient(ctx, client))
	require.NoError(t, pool.ReleaseClient(ctx, newClient))
	require.NoError(t, pool.Close(ctx))
}

func TestCachingClientPool_EvictionWaitsForRelease(t *testing.T) {
	var revokeCallCount atomic.Int32
	address := "https://vault-eviction.example.com"

	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: func(config *vault.Config) (util.Client, error) {
			client, err := fake.ClientWithLoginMock(config)
			if err != nil {
				return nil, err
			}

			vc := client.(*util.VaultClient)
			origToken := vc.AuthTokenField
			vc.AuthTokenField = &util.VaultToken{
				RevokeSelfFunc: func(ctx context.Context, token string) error {
					revokeCallCount.Add(1)
					return nil
				},
				LookupSelfFunc: origToken.LookupSelfWithContext,
				RenewSelfFunc:  origToken.RenewSelfWithContext,
			}

			return client, nil
		},
		EnableRenewal: false,
		MaxCacheSize:  1,
	})
	ctx := context.Background()

	config1 := createAppRoleAcquireConfig(address, "evict-ns1")
	client1, err := pool.AcquireClient(ctx, config1)
	require.NoError(t, err)
	require.NotNil(t, client1)

	config2 := createAppRoleAcquireConfig(address, "evict-ns2")
	client2, err := pool.AcquireClient(ctx, config2)
	require.NoError(t, err)
	require.NotNil(t, client2)

	assert.Equal(t, int32(0), revokeCallCount.Load(), "revocation should be deferred while client is in use")

	require.NoError(t, pool.ReleaseClient(ctx, client1))
	assert.Equal(t, int32(1), revokeCallCount.Load(), "revocation should occur after final release")

	require.NoError(t, pool.ReleaseClient(ctx, client2))
	require.NoError(t, pool.Close(ctx))
}

func TestCachingClientPool_Concurrency(t *testing.T) {
	var clientCreationCount atomic.Int32

	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: func(config *vault.Config) (util.Client, error) {
			clientCreationCount.Add(1)
			// Small delay to increase chance of race conditions
			time.Sleep(10 * time.Millisecond)
			return fake.ClientWithLoginMock(config)
		},
		EnableRenewal: false,
	})
	defer pool.Close(context.Background())

	ctx := context.Background()
	config := createTestAcquireConfig("https://vault.example.com", "default")

	// Acquire same client concurrently
	const numGoroutines = 20
	var wg sync.WaitGroup
	clients := make([]util.Client, numGoroutines)
	errs := make([]error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			clients[idx], errs[idx] = pool.AcquireClient(ctx, config)
		}(i)
	}
	wg.Wait()

	// Verify all goroutines succeeded
	for i := 0; i < numGoroutines; i++ {
		require.NoError(t, errs[i], "goroutine %d should not error", i)
		require.NotNil(t, clients[i], "goroutine %d should have received a client", i)
	}

	// Verify all clients are the same instance
	for i := 1; i < numGoroutines; i++ {
		assert.Equal(t, clients[0], clients[i], "all clients should be the same instance")
	}

	// Should have created only one client despite concurrent requests
	assert.Equal(t, int32(1), clientCreationCount.Load(), "should create only one client despite concurrent access")
}

func TestCachingClientPool_PoolSizeMetrics(t *testing.T) {
	address := "https://vault-metrics.example.com"
	metrics.SetVaultClientPoolSize(address, 0)

	pool := NewCachingClientPool(CachingClientPoolConfig{
		NewVaultClient: fake.ModifiableClientWithLoginMock(func(cl *fake.VaultClient) {
			cl.MockGetAddress = func() string { return address }
		}),
		EnableRenewal: false,
		MaxCacheSize:  1,
	})
	ctx := context.Background()

	config1 := createTestAcquireConfig(address, "metrics-ns1")
	client1, err := pool.AcquireClient(ctx, config1)
	require.NoError(t, err)
	require.NotNil(t, client1)
	assert.Equal(t, 1.0, getPoolGaugeValue(t, address), "gauge should reflect single client")

	config2 := createTestAcquireConfig(address, "metrics-ns2")
	client2, err := pool.AcquireClient(ctx, config2)
	require.NoError(t, err)
	require.NotNil(t, client2)
	assert.Equal(t, 1.0, getPoolGaugeValue(t, address), "gauge should stay at size 1 after eviction")

	require.NoError(t, pool.Close(ctx))
	assert.Equal(t, 0.0, getPoolGaugeValue(t, address), "gauge should reset to zero after close")
}

func getPoolGaugeValue(t *testing.T, address string) float64 {
	t.Helper()

	metricFamilies, err := ctrmetrics.Registry.Gather()
	require.NoError(t, err)

	for _, mf := range metricFamilies {
		if mf.GetName() != "externalsecret_vault_client_pool_size" {
			continue
		}
		for _, m := range mf.Metric {
			if m == nil {
				continue
			}
			var addr string
			for _, l := range m.GetLabel() {
				if l.GetName() == "address" {
					addr = l.GetValue()
					break
				}
			}
			if addr != address {
				continue
			}
			g := m.GetGauge()
			if g == nil {
				return 0
			}
			return g.GetValue()
		}
	}

	return 0
}
