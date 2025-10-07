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
	"sync"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// Mock implementations for testing

type MockVaultClient struct {
	token       string
	tokenValid  bool
	authToken   *MockToken
	authField   util.Auth
	logicalField util.Logical
}

func (m *MockVaultClient) Token() string {
	return m.token
}

func (m *MockVaultClient) SetToken(token string) {
	m.token = token
}

func (m *MockVaultClient) ClearToken() {
	m.token = ""
}

func (m *MockVaultClient) Auth() util.Auth {
	return m.authField
}

func (m *MockVaultClient) AuthToken() util.Token {
	return m.authToken
}

func (m *MockVaultClient) Logical() util.Logical {
	return m.logicalField
}

func (m *MockVaultClient) Namespace() string {
	return ""
}

func (m *MockVaultClient) SetNamespace(namespace string) {}

func (m *MockVaultClient) AddHeader(key, value string) {}

type MockToken struct {
	valid bool
}

func (m *MockToken) LookupSelfWithContext(ctx context.Context) (*vault.Secret, error) {
	if !m.valid {
		return nil, errors.New("invalid token")
	}
	return &vault.Secret{
		Data: map[string]interface{}{
			"ttl": 3600,
		},
	}, nil
}

func (m *MockToken) RevokeSelfWithContext(ctx context.Context, token string) error {
	return nil
}

// Test: Pool key determinism
func TestPoolKey_String_Deterministic(t *testing.T) {
	key1 := PoolKey{
		ServerURL:          "https://vault.example.com",
		VaultNamespace:     "admin",
		AuthMethod:         "kubernetes",
		K8sNamespace:       "default",
		CredentialIdentity: "k8s-sa:default/vault-sa",
	}

	key2 := PoolKey{
		ServerURL:          "https://vault.example.com",
		VaultNamespace:     "admin",
		AuthMethod:         "kubernetes",
		K8sNamespace:       "default",
		CredentialIdentity: "k8s-sa:default/vault-sa",
	}

	assert.Equal(t, key1.String(), key2.String(), "identical keys should produce identical strings")

	// Test multiple times to ensure determinism
	for i := 0; i < 100; i++ {
		assert.Equal(t, key1.String(), key2.String())
	}
}

// Test: Pool key uniqueness
func TestPoolKey_String_UniqueForDifferentCredentials(t *testing.T) {
	key1 := PoolKey{
		ServerURL:          "https://vault.example.com",
		AuthMethod:         "kubernetes",
		K8sNamespace:       "default",
		CredentialIdentity: "k8s-sa:default/sa1",
	}

	key2 := PoolKey{
		ServerURL:          "https://vault.example.com",
		AuthMethod:         "kubernetes",
		K8sNamespace:       "default",
		CredentialIdentity: "k8s-sa:default/sa2",
	}

	assert.NotEqual(t, key1.String(), key2.String(), "different SAs should produce different keys")
}

// Test: Pool key uniqueness for different configurations
func TestPoolKey_String_UniqueForDifferentConfigs(t *testing.T) {
	tests := []struct {
		name string
		key1 PoolKey
		key2 PoolKey
	}{
		{
			name: "different server URLs",
			key1: PoolKey{ServerURL: "https://vault1.com", AuthMethod: "token"},
			key2: PoolKey{ServerURL: "https://vault2.com", AuthMethod: "token"},
		},
		{
			name: "different namespaces",
			key1: PoolKey{ServerURL: "https://vault.com", VaultNamespace: "ns1"},
			key2: PoolKey{ServerURL: "https://vault.com", VaultNamespace: "ns2"},
		},
		{
			name: "different auth methods",
			key1: PoolKey{ServerURL: "https://vault.com", AuthMethod: "kubernetes"},
			key2: PoolKey{ServerURL: "https://vault.com", AuthMethod: "approle"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEqual(t, tt.key1.String(), tt.key2.String())
		})
	}
}

// Test: Store and retrieve
func TestClientPool_StoreAndRetrieve(t *testing.T) {
	pool := NewClientPool(10, 15*time.Minute)

	mockClient := &MockVaultClient{
		token:      "test-token",
		tokenValid: true,
		authToken:  &MockToken{valid: true},
	}
	poolKey := "test-key"

	pool.StoreAuthenticated(poolKey, mockClient, &AuthConfig{})

	retrieved := pool.GetAuthenticated(poolKey)
	require.NotNil(t, retrieved)
	assert.Equal(t, mockClient, retrieved.client)
	assert.Equal(t, poolKey, retrieved.poolKey)
}

// Test: Cache miss returns nil
func TestClientPool_CacheMiss(t *testing.T) {
	pool := NewClientPool(10, 15*time.Minute)

	retrieved := pool.GetAuthenticated("nonexistent-key")
	assert.Nil(t, retrieved)
}

// Test: Invalid token returns nil
func TestClientPool_InvalidTokenReturnsNil(t *testing.T) {
	pool := NewClientPool(10, 15*time.Minute)

	mockClient := &MockVaultClient{
		token:      "invalid-token",
		tokenValid: false,
		authToken:  &MockToken{valid: false},
	}
	poolKey := "test-key"

	pool.StoreAuthenticated(poolKey, mockClient, &AuthConfig{})

	// Should return nil because token validation fails
	retrieved := pool.GetAuthenticated(poolKey)
	assert.Nil(t, retrieved, "invalid token should result in cache miss")
}

// Test: TTL eviction
func TestClientPool_TTLEviction(t *testing.T) {
	pool := NewClientPool(10, 50*time.Millisecond)

	mockClient := &MockVaultClient{
		token:     "test-token",
		authToken: &MockToken{valid: true},
	}
	pool.StoreAuthenticated("key1", mockClient, &AuthConfig{})

	// Wait for TTL to expire (LRU cache handles eviction automatically)
	time.Sleep(100 * time.Millisecond)

	// Should be evicted by LRU cache TTL
	retrieved := pool.GetAuthenticated("key1")
	assert.Nil(t, retrieved, "client should be evicted after TTL")

	// Verify pool is empty
	metrics := pool.GetMetrics()
	assert.Equal(t, int64(0), metrics.size)
}

// Test: Max size eviction (LRU)
func TestClientPool_MaxSizeEviction(t *testing.T) {
	pool := NewClientPool(2, 15*time.Minute)

	mockClient1 := &MockVaultClient{token: "token1", authToken: &MockToken{valid: true}}
	mockClient2 := &MockVaultClient{token: "token2", authToken: &MockToken{valid: true}}
	mockClient3 := &MockVaultClient{token: "token3", authToken: &MockToken{valid: true}}

	pool.StoreAuthenticated("key1", mockClient1, &AuthConfig{})
	pool.StoreAuthenticated("key2", mockClient2, &AuthConfig{})
	pool.StoreAuthenticated("key3", mockClient3, &AuthConfig{})

	// key1 should be evicted (LRU cache automatically evicts least recently used)
	assert.Nil(t, pool.GetAuthenticated("key1"), "oldest client should be evicted")
	assert.NotNil(t, pool.GetAuthenticated("key2"), "newer client should remain")
	assert.NotNil(t, pool.GetAuthenticated("key3"), "newest client should remain")

	// Verify pool size
	metrics := pool.GetMetrics()
	assert.Equal(t, int64(2), metrics.size)
}

// Test: Concurrent access
func TestClientPool_ConcurrentAccess(t *testing.T) {
	pool := NewClientPool(100, 15*time.Minute)

	mockClient := &MockVaultClient{
		token:     "test-token",
		authToken: &MockToken{valid: true},
	}
	poolKey := "concurrent-key"
	pool.StoreAuthenticated(poolKey, mockClient, &AuthConfig{})

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := pool.GetAuthenticated(poolKey)
			assert.NotNil(t, client)
		}()
	}

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := poolKey + string(rune(id))
			mockClient := &MockVaultClient{
				token:     "token-" + string(rune(id)),
				authToken: &MockToken{valid: true},
			}
			pool.StoreAuthenticated(key, mockClient, &AuthConfig{})
		}(i)
	}

	wg.Wait()

	// Verify no panics occurred and pool is still functional
	metrics := pool.GetMetrics()
	assert.True(t, metrics.size > 0)
}

// Test: Auth identity for Kubernetes auth
func TestGetAuthIdentity_Kubernetes(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	auth := &esv1.VaultAuth{
		Kubernetes: &esv1.VaultKubernetesAuth{
			Path: "kubernetes",
			Role: "my-role",
			ServiceAccountRef: &esmeta.ServiceAccountSelector{
				Name: "vault-sa",
			},
		},
	}

	identity, method, path, role, err := getAuthIdentity(
		context.Background(), auth, "default", kubeClient, nil, "")

	require.NoError(t, err)
	assert.Equal(t, "k8s-sa:default/vault-sa", identity)
	assert.Equal(t, "kubernetes", method)
	assert.Equal(t, "kubernetes", path)
	assert.Equal(t, "my-role", role)
}

// Test: Auth identity for TokenAuth
func TestGetAuthIdentity_TokenAuth(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "vault-token",
			Namespace:       "default",
			ResourceVersion: "12345",
		},
		Data: map[string][]byte{
			"token": []byte("my-token"),
		},
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	auth := &esv1.VaultAuth{
		TokenSecretRef: &esmeta.SecretKeySelector{
			Name: "vault-token",
			Key:  "token",
		},
	}

	identity, method, _, _, err := getAuthIdentity(
		context.Background(), auth, "default", kubeClient, nil, "")

	require.NoError(t, err)
	assert.Equal(t, "token:rv:12345", identity)
	assert.Equal(t, "token", method)
}

// Test: Auth identity for AppRole
func TestGetAuthIdentity_AppRole(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "approle-secret",
			Namespace:       "default",
			ResourceVersion: "67890",
		},
		Data: map[string][]byte{
			"secret-id": []byte("my-secret-id"),
		},
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	auth := &esv1.VaultAuth{
		AppRole: &esv1.VaultAppRole{
			Path:   "approle",
			RoleID: "my-role-id",
			SecretRef: esmeta.SecretKeySelector{
				Name: "approle-secret",
				Key:  "secret-id",
			},
		},
	}

	identity, method, path, role, err := getAuthIdentity(
		context.Background(), auth, "default", kubeClient, nil, "")

	require.NoError(t, err)
	assert.Equal(t, "approle:role:my-role-id:rv:67890", identity)
	assert.Equal(t, "approle", method)
	assert.Equal(t, "approle", path)
	assert.Equal(t, "my-role-id", role)
}

// Test: Metrics tracking
func TestClientPool_Metrics(t *testing.T) {
	pool := NewClientPool(10, 15*time.Minute)

	mockClient := &MockVaultClient{
		token:     "test-token",
		authToken: &MockToken{valid: true},
	}

	// Cache miss
	pool.GetAuthenticated("nonexistent")
	metrics := pool.GetMetrics()
	assert.Equal(t, int64(0), metrics.size)

	// Store and verify size
	pool.StoreAuthenticated("key1", mockClient, &AuthConfig{})
	pool.GetAuthenticated("key1")
	metrics = pool.GetMetrics()
	assert.Equal(t, int64(1), metrics.size)

	// Note: hits/misses/evictions are tracked via Prometheus metrics, not in PoolMetrics struct
}

// Test: getSecretResourceVersion
func TestGetSecretResourceVersion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-secret",
			Namespace:       "default",
			ResourceVersion: "99999",
		},
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	rv, err := getSecretResourceVersion(
		context.Background(),
		kubeClient,
		"",
		"default",
		&esmeta.SecretKeySelector{Name: "test-secret", Key: "test"},
	)

	require.NoError(t, err)
	assert.Equal(t, "99999", rv)
}

// Test: getSecretResourceVersion with ClusterSecretStore cross-namespace
func TestGetSecretResourceVersion_ClusterStore(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-secret",
			Namespace:       "other-namespace",
			ResourceVersion: "11111",
		},
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	otherNS := "other-namespace"
	rv, err := getSecretResourceVersion(
		context.Background(),
		kubeClient,
		esv1.ClusterSecretStoreKind,
		"default",
		&esmeta.SecretKeySelector{
			Name:      "test-secret",
			Key:       "test",
			Namespace: &otherNS,
		},
	)

	require.NoError(t, err)
	assert.Equal(t, "11111", rv)
}

// Test: Pool key collision prevention
func TestPoolKey_NoCollisions(t *testing.T) {
	// Test cases that could potentially collide if separator was missing
	key1 := PoolKey{
		ServerURL:  "https://vault.com",
		AuthMethod: "kubernetes",
		AuthRole:   "roleA",
	}

	key2 := PoolKey{
		ServerURL:  "https://vault.co",
		AuthMethod: "mkubernetes",
		AuthRole:   "roleA",
	}

	// Should be different even though concatenation without separator could collide
	assert.NotEqual(t, key1.String(), key2.String())
}
