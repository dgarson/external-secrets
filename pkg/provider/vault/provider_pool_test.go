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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// mockLogical implements util.Logical for testing
type mockLogical struct {
	readFunc   func(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error)
	writeFunc  func(ctx context.Context, path string, data map[string]interface{}) (*vault.Secret, error)
	listFunc   func(ctx context.Context, path string) (*vault.Secret, error)
	deleteFunc func(ctx context.Context, path string) (*vault.Secret, error)
}

func (m *mockLogical) ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
	if m.readFunc != nil {
		return m.readFunc(ctx, path, data)
	}
	return &vault.Secret{}, nil
}

func (m *mockLogical) WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*vault.Secret, error) {
	if m.writeFunc != nil {
		return m.writeFunc(ctx, path, data)
	}
	return &vault.Secret{}, nil
}

func (m *mockLogical) ListWithContext(ctx context.Context, path string) (*vault.Secret, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, path)
	}
	return &vault.Secret{}, nil
}

func (m *mockLogical) DeleteWithContext(ctx context.Context, path string) (*vault.Secret, error) {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, path)
	}
	return &vault.Secret{}, nil
}

// mockAuth implements util.Auth for testing
type mockAuth struct{}

func (m *mockAuth) Login(ctx context.Context, authMethod vault.AuthMethod) (*vault.Secret, error) {
	return &vault.Secret{}, nil
}

// mockToken implements util.Token for testing
type mockToken struct {
	lookupFunc func(ctx context.Context) (*vault.Secret, error)
}

func (m *mockToken) RevokeSelfWithContext(ctx context.Context, token string) error {
	return nil
}

func (m *mockToken) LookupSelfWithContext(ctx context.Context) (*vault.Secret, error) {
	if m.lookupFunc != nil {
		return m.lookupFunc(ctx)
	}
	return &vault.Secret{}, nil
}

// createTestVaultClient creates a mock VaultClient for testing
func createTestVaultClient() *util.VaultClient {
	return &util.VaultClient{
		SetTokenFunc:     func(v string) {},
		TokenFunc:        func() string { return "test-token" },
		ClearTokenFunc:   func() {},
		AuthField:        &mockAuth{},
		LogicalField:     &mockLogical{},
		AuthTokenField:   &mockToken{},
		NamespaceFunc:    func() string { return "" },
		SetNamespaceFunc: func(namespace string) {},
		AddHeaderFunc:    func(key, value string) {},
	}
}

// createTestPool creates an LRU cache for testing (mimics vaultClientPool)
func createTestPool(maxSize int, ttl time.Duration) *expirable.LRU[string, *pooledVaultClient] {
	onEvict := func(key string, value *pooledVaultClient) {
		// Eviction callback for testing
	}
	return expirable.NewLRU[string, *pooledVaultClient](maxSize, onEvict, ttl)
}

func TestClientPoolGetPut(t *testing.T) {
	pool := createTestPool(100, 15*time.Minute)

	vaultClient := createTestVaultClient()
	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth:  func(ctx context.Context, cfg *vault.Config) error { return nil },
		lastAuth: time.Now(),
	}

	// Test Put
	pool.Add("test-key", pooledClient)
	assert.Equal(t, 1, pool.Len())

	// Test Get - should return the same client
	retrieved, ok := pool.Get("test-key")
	assert.True(t, ok)
	assert.NotNil(t, retrieved)
	assert.Equal(t, pooledClient, retrieved)

	// Test Get non-existent key
	_, ok = pool.Get("non-existent")
	assert.False(t, ok)
}

func TestClientPoolEviction(t *testing.T) {
	pool := createTestPool(100, 100*time.Millisecond)

	vaultClient := createTestVaultClient()
	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth:  func(ctx context.Context, cfg *vault.Config) error { return nil },
		lastAuth: time.Now(),
	}

	pool.Add("test-key", pooledClient)

	// Client should be retrievable immediately
	retrieved, ok := pool.Get("test-key")
	assert.True(t, ok)
	assert.NotNil(t, retrieved)

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// After TTL expires, Get should return false (expirable.LRU handles this automatically)
	_, ok = pool.Get("test-key")
	assert.False(t, ok)
}

// TestClientPoolEvictStale removed - TTL-based eviction is now handled automatically by expirable.LRU

func TestClientPoolMaxSize(t *testing.T) {
	pool := createTestPool(3, 15*time.Minute)

	vaultClient := createTestVaultClient()

	// Add 4 clients (exceeds max size of 3)
	for i := 0; i < 4; i++ {
		key := fmt.Sprintf("client-%d", i)
		client := &pooledVaultClient{
			client:   vaultClient,
			cacheKey: key,
			setAuth:  func(ctx context.Context, cfg *vault.Config) error { return nil },
			lastAuth: time.Now(),
		}
		time.Sleep(10 * time.Millisecond) // Ensure different add times
		pool.Add(key, client)
	}

	// Should only have 3 clients (LRU evicted one)
	assert.Equal(t, 3, pool.Len())

	// First client should be evicted (least recently used)
	_, ok := pool.Get("client-0")
	assert.False(t, ok)

	// Others should exist
	_, ok = pool.Get("client-1")
	assert.True(t, ok)
	_, ok = pool.Get("client-2")
	assert.True(t, ok)
	_, ok = pool.Get("client-3")
	assert.True(t, ok)
}

func TestClientPoolRemove(t *testing.T) {
	pool := createTestPool(100, 15*time.Minute)

	vaultClient := createTestVaultClient()
	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth:  func(ctx context.Context, cfg *vault.Config) error { return nil },
		lastAuth: time.Now(),
	}

	pool.Add("test-key", pooledClient)
	assert.Equal(t, 1, pool.Len())

	pool.Remove("test-key")
	assert.Equal(t, 0, pool.Len())

	// Removing non-existent key should not panic
	pool.Remove("non-existent")
	assert.Equal(t, 0, pool.Len())
}

func TestPooledClientReAuthentication(t *testing.T) {
	authCalls := 0
	vaultClient := createTestVaultClient()

	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth: func(ctx context.Context, cfg *vault.Config) error {
			authCalls++
			return nil
		},
		lastAuth: time.Now(),
	}

	// Test successful re-authentication
	err := pooledClient.reAuthenticate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, authCalls)
}

func TestPooledClientReAuthenticationFailure(t *testing.T) {
	// This test verifies that re-authentication failure removes the client from the pool.
	// However, there's a design issue: reAuthenticate() calls GetGlobalClientPool().Remove(),
	// but if the global pool has already been initialized by another test or code path,
	// we can't easily substitute our test pool.

	// Instead, we'll test that the auth function is called and returns an error,
	// and we'll manually verify the removal logic in a different way.

	vaultClient := createTestVaultClient()
	expectedErr := errors.New("auth failed")
	authCallCount := 0

	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key-auth-fail",
		setAuth: func(ctx context.Context, cfg *vault.Config) error {
			authCallCount++
			return expectedErr
		},
		lastAuth: time.Now(),
	}

	// Re-authentication should fail
	err := pooledClient.reAuthenticate(context.Background())
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, 1, authCallCount)

	// The client would be removed from the global pool (if it was there)
	// We can't easily test the removal without interfering with the global state
}

func TestShouldRetryWithReauth(t *testing.T) {
	tests := []struct {
		name                string
		err                 error
		lookupResp          *vault.Secret
		lookupErr           error
		expectedShouldRetry bool
	}{
		{
			name:                "nil error",
			err:                 nil,
			expectedShouldRetry: false,
		},
		{
			name:                "unambiguous - invalid token",
			err:                 errors.New("invalid token"),
			expectedShouldRetry: true,
		},
		{
			name:                "unambiguous - token is expired",
			err:                 errors.New("token is expired"),
			expectedShouldRetry: true,
		},
		{
			name:                "unambiguous - token has been revoked",
			err:                 errors.New("token has been revoked"),
			expectedShouldRetry: true,
		},
		{
			name:                "permission denied - lookup fails (token invalid)",
			err:                 errors.New("permission denied"),
			lookupErr:           errors.New("lookup failed"),
			expectedShouldRetry: true,
		},
		{
			name: "permission denied - lookup succeeds (policy denial)",
			err:  errors.New("permission denied"),
			lookupResp: &vault.Secret{
				Data: map[string]interface{}{
					"ttl": int64(3600),
				},
			},
			expectedShouldRetry: false,
		},
		{
			name:                "unrelated error",
			err:                 errors.New("something else"),
			expectedShouldRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockToken := &mockToken{}
			if tt.lookupResp != nil || tt.lookupErr != nil {
				// Override the mock to return specific values
				mockToken.lookupFunc = func(ctx context.Context) (*vault.Secret, error) {
					return tt.lookupResp, tt.lookupErr
				}
			}

			vaultClient := createTestVaultClient()
			vaultClient.AuthTokenField = mockToken

			pooledClient := &pooledVaultClient{
				client:   vaultClient,
				cacheKey: "test-key",
				setAuth:  func(ctx context.Context, cfg *vault.Config) error { return nil },
				lastAuth: time.Now(),
			}

			result := pooledClient.shouldRetryWithReauth(context.Background(), tt.err)
			assert.Equal(t, tt.expectedShouldRetry, result)
		})
	}
}

func TestIsVaultTokenInvalidOrExpired(t *testing.T) {
	tests := []struct {
		name                string
		err                 error
		expectedShouldRetry bool
	}{
		{
			name:                "nil error",
			err:                 nil,
			expectedShouldRetry: false,
		},
		{
			name:                "invalid token",
			err:                 errors.New("invalid token"),
			expectedShouldRetry: true,
		},
		{
			name:                "token is expired",
			err:                 errors.New("token is expired"),
			expectedShouldRetry: true,
		},
		{
			name:                "token has been revoked",
			err:                 errors.New("token has been revoked"),
			expectedShouldRetry: true,
		},
		{
			name:                "permission denied",
			err:                 errors.New("permission denied"),
			expectedShouldRetry: true,
		},
		{
			name:                "unrelated error",
			err:                 errors.New("something else"),
			expectedShouldRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isVaultTokenInvalidOrExpired(tt.err)
			assert.Equal(t, tt.expectedShouldRetry, result)
		})
	}
}

func TestPooledLogicalReadWithRetry(t *testing.T) {
	callCount := 0
	tokenExpiredErr := errors.New("permission denied")

	mockLog := &mockLogical{
		readFunc: func(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
			callCount++
			if callCount == 1 {
				return nil, tokenExpiredErr
			}
			return &vault.Secret{Data: map[string]interface{}{"key": "value"}}, nil
		},
	}

	// Mock token lookup to fail, indicating token is invalid
	mockToken := &mockToken{
		lookupFunc: func(ctx context.Context) (*vault.Secret, error) {
			return nil, errors.New("token lookup failed")
		},
	}

	vaultClient := createTestVaultClient()
	vaultClient.LogicalField = mockLog
	vaultClient.AuthTokenField = mockToken

	authCalls := 0
	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth: func(ctx context.Context, cfg *vault.Config) error {
			authCalls++
			return nil
		},
		lastAuth: time.Now(),
	}

	logical := pooledClient.Logical()
	secret, err := logical.ReadWithDataWithContext(context.Background(), "secret/test", nil)

	require.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Equal(t, 2, callCount) // First call failed, second succeeded
	assert.Equal(t, 1, authCalls) // Re-authentication happened once
}

func TestPooledLogicalWriteWithRetry(t *testing.T) {
	callCount := 0
	tokenExpiredErr := errors.New("invalid token")

	mockLog := &mockLogical{
		writeFunc: func(ctx context.Context, path string, data map[string]interface{}) (*vault.Secret, error) {
			callCount++
			if callCount == 1 {
				return nil, tokenExpiredErr
			}
			return &vault.Secret{Data: map[string]interface{}{"updated": "true"}}, nil
		},
	}

	vaultClient := createTestVaultClient()
	vaultClient.LogicalField = mockLog

	authCalls := 0
	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth: func(ctx context.Context, cfg *vault.Config) error {
			authCalls++
			return nil
		},
		lastAuth: time.Now(),
	}

	logical := pooledClient.Logical()
	secret, err := logical.WriteWithContext(context.Background(), "secret/test", map[string]interface{}{"key": "value"})

	require.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Equal(t, 2, callCount)
	assert.Equal(t, 1, authCalls)
}

func TestPooledLogicalListWithRetry(t *testing.T) {
	callCount := 0
	tokenExpiredErr := errors.New("token is expired")

	mockLog := &mockLogical{
		listFunc: func(ctx context.Context, path string) (*vault.Secret, error) {
			callCount++
			if callCount == 1 {
				return nil, tokenExpiredErr
			}
			return &vault.Secret{Data: map[string]interface{}{"keys": []string{"key1", "key2"}}}, nil
		},
	}

	vaultClient := createTestVaultClient()
	vaultClient.LogicalField = mockLog

	authCalls := 0
	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth: func(ctx context.Context, cfg *vault.Config) error {
			authCalls++
			return nil
		},
		lastAuth: time.Now(),
	}

	logical := pooledClient.Logical()
	secret, err := logical.ListWithContext(context.Background(), "secret/")

	require.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Equal(t, 2, callCount)
	assert.Equal(t, 1, authCalls)
}

func TestPooledLogicalDeleteWithRetry(t *testing.T) {
	callCount := 0
	tokenExpiredErr := errors.New("token has been revoked")

	mockLog := &mockLogical{
		deleteFunc: func(ctx context.Context, path string) (*vault.Secret, error) {
			callCount++
			if callCount == 1 {
				return nil, tokenExpiredErr
			}
			return &vault.Secret{}, nil
		},
	}

	vaultClient := createTestVaultClient()
	vaultClient.LogicalField = mockLog

	authCalls := 0
	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth: func(ctx context.Context, cfg *vault.Config) error {
			authCalls++
			return nil
		},
		lastAuth: time.Now(),
	}

	logical := pooledClient.Logical()
	secret, err := logical.DeleteWithContext(context.Background(), "secret/test")

	require.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Equal(t, 2, callCount)
	assert.Equal(t, 1, authCalls)
}

func TestPooledVaultClientDelegatedMethods(t *testing.T) {
	vaultClient := createTestVaultClient()

	pooledClient := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "test-key",
		setAuth:  func(ctx context.Context, cfg *vault.Config) error { return nil },
		lastAuth: time.Now(),
	}

	// Test Auth()
	assert.NotNil(t, pooledClient.Auth())

	// Test AuthToken()
	assert.NotNil(t, pooledClient.AuthToken())

	// Test SetToken/Token
	pooledClient.SetToken("new-token")
	assert.Equal(t, "test-token", pooledClient.Token())

	// Test ClearToken
	pooledClient.ClearToken()

	// Test SetNamespace/Namespace
	pooledClient.SetNamespace("test-namespace")
	assert.Equal(t, "", pooledClient.Namespace())

	// Test AddHeader
	pooledClient.AddHeader("X-Test", "value")
}

func TestConcurrentAccess(t *testing.T) {
	pool := createTestPool(100, 15*time.Minute)

	vaultClient := createTestVaultClient()

	var wg sync.WaitGroup
	concurrency := 50

	// Concurrent puts
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", idx%10) // 10 unique keys, lots of contention
			client := &pooledVaultClient{
				client:   vaultClient,
				cacheKey: key,
				setAuth:  func(ctx context.Context, cfg *vault.Config) error { return nil },
				lastAuth: time.Now(),
			}
			pool.Add(key, client)
		}(i)
	}

	// Concurrent gets
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", idx%10)
			pool.Get(key)
		}(i)
	}

	wg.Wait()

	// Should have at most 10 clients (expirable.LRU is thread-safe)
	assert.LessOrEqual(t, pool.Len(), 10)
}

func TestAcquireVaultClientInvalidatesStaleConfig(t *testing.T) {
	t.Cleanup(func() {
		enableVaultClientPooling = false
		vaultClientPool = nil
	})

	enableVaultClientPooling = true
	vaultClientPool = expirable.NewLRU[string, *pooledVaultClient](10, func(string, *pooledVaultClient) {}, time.Minute)

	vaultSpec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
	}

	cacheKey := buildCacheKey(vaultSpec, "no-auth")
	vaultClientPool.Add(cacheKey, &pooledVaultClient{
		client:       createTestVaultClient(),
		cacheKey:     cacheKey,
		cfg:          &vault.Config{},
		setAuth:      func(ctx context.Context, cfg *vault.Config) error { return nil },
		configDigest: "stale",
	})

	p := &Provider{
		NewVaultClient: func(config *vault.Config) (util.Client, error) {
			return createTestVaultClient(), nil
		},
	}

	kube := fake.NewClientBuilder().Build()
	c, cfg, err := p.prepareConfig(context.Background(), kube, nil, vaultSpec, nil, "default", esv1.SecretStoreKind)
	require.NoError(t, err)

	fullyInitialized, err := acquireVaultClient(context.Background(), p, c, cfg, nil)
	require.NoError(t, err)
	require.False(t, fullyInitialized)

	_, ok := vaultClientPool.Get(cacheKey)
	assert.False(t, ok, "stale pooled client should have been removed")
}

func TestVaultClientPool(t *testing.T) {
	// Note: We can't safely reset the global pool in tests because:
	// 1. It would cause metric re-registration conflicts
	// 2. Other tests might be using the global pool
	// 3. init() may or may not have been called depending on flag state

	// If pooling has been initialized, verify the pool exists
	if vaultClientPool != nil {
		require.NotNil(t, vaultClientPool, "vaultClientPool should be initialized when pooling is enabled")
		// Basic sanity check - can add and retrieve
		testClient := createTestVaultClient()
		testPooled := &pooledVaultClient{
			client:   testClient,
			cacheKey: "test-global-pool",
			setAuth:  func(ctx context.Context, cfg *vault.Config) error { return nil },
			lastAuth: time.Now(),
		}
		vaultClientPool.Add("test-global-pool", testPooled)
		retrieved, ok := vaultClientPool.Get("test-global-pool")
		assert.True(t, ok)
		assert.NotNil(t, retrieved)
		removePooledClient("test-global-pool") // Clean up
	}
}
