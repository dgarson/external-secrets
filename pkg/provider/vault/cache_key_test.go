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
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

func TestComputeCacheKey(t *testing.T) {
	tests := []struct {
		name      string
		config1   AcquireClientConfig
		config2   AcquireClientConfig
		shouldMatch bool
		reason    string
	}{
		{
			name: "identical kubernetes auth should match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
							ServiceAccountRef: &esmeta.ServiceAccountSelector{
								Name: "my-sa",
							},
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
							ServiceAccountRef: &esmeta.ServiceAccountSelector{
								Name: "my-sa",
							},
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: true,
			reason:      "identical configurations should produce identical cache keys",
		},
		{
			name: "different server should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault1.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault2.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: false,
			reason:      "different Vault servers should have different cache keys",
		},
		{
			name: "different auth method should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						AppRole: &esv1.VaultAppRole{
							Path:   "approle",
							RoleID: "my-role-id",
							SecretRef: esmeta.SecretKeySelector{
								Name: "my-secret",
								Key:  "secret-id",
							},
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: false,
			reason:      "different auth methods should have different cache keys",
		},
		{
			name: "different vault namespace should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server:    "https://vault.example.com",
					Namespace: stringPtr("tenant-a"),
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server:    "https://vault.example.com",
					Namespace: stringPtr("tenant-b"),
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: false,
			reason:      "different Vault namespaces should have different cache keys",
		},
		{
			name: "different auth namespace should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Namespace: stringPtr("auth-ns-a"),
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Namespace: stringPtr("auth-ns-b"),
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: false,
			reason:      "different auth namespaces should have different cache keys",
		},
		{
			name: "ClusterSecretStore with referent spec and different k8s namespace should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
							ServiceAccountRef: &esmeta.ServiceAccountSelector{
								Name: "my-sa",
								// No namespace - this is referent
							},
						},
					},
				},
				Namespace: "namespace-a",
				StoreKind: esv1.ClusterSecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
							ServiceAccountRef: &esmeta.ServiceAccountSelector{
								Name: "my-sa",
								// No namespace - this is referent
							},
						},
					},
				},
				Namespace: "namespace-b",
				StoreKind: esv1.ClusterSecretStoreKind,
			},
			shouldMatch: false,
			reason:      "ClusterSecretStore with referent spec should use different cache keys for different k8s namespaces",
		},
		{
			name: "ClusterSecretStore with explicit namespace should match across k8s namespaces",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
							ServiceAccountRef: &esmeta.ServiceAccountSelector{
								Name:      "my-sa",
								Namespace: stringPtr("explicit-ns"),
							},
						},
					},
				},
				Namespace: "namespace-a",
				StoreKind: esv1.ClusterSecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
							ServiceAccountRef: &esmeta.ServiceAccountSelector{
								Name:      "my-sa",
								Namespace: stringPtr("explicit-ns"),
							},
						},
					},
				},
				Namespace: "namespace-b",
				StoreKind: esv1.ClusterSecretStoreKind,
			},
			shouldMatch: true,
			reason:      "ClusterSecretStore with explicit namespace should share cache across k8s namespaces",
		},
		{
			name: "different kubernetes role should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "role-a",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "role-b",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: false,
			reason:      "different Kubernetes roles should have different cache keys",
		},
		{
			name: "different TLS config should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					ClientTLS: esv1.VaultClientTLS{
						CertSecretRef: &esmeta.SecretKeySelector{
							Name: "cert-a",
							Key:  "tls.crt",
						},
						KeySecretRef: &esmeta.SecretKeySelector{
							Name: "cert-a",
							Key:  "tls.key",
						},
					},
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					ClientTLS: esv1.VaultClientTLS{
						CertSecretRef: &esmeta.SecretKeySelector{
							Name: "cert-b",
							Key:  "tls.crt",
						},
						KeySecretRef: &esmeta.SecretKeySelector{
							Name: "cert-b",
							Key:  "tls.key",
						},
					},
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: false,
			reason:      "different TLS configurations should have different cache keys",
		},
		{
			name: "different vault secrets namespace should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server:    "https://vault.example.com",
					Namespace: stringPtr("secrets-ns-a"),
					Auth: &esv1.VaultAuth{
						Namespace: stringPtr("auth-ns"),
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server:    "https://vault.example.com",
					Namespace: stringPtr("secrets-ns-b"),
					Auth: &esv1.VaultAuth{
						Namespace: stringPtr("auth-ns"),
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: false,
			reason:      "different Vault secrets namespaces (provider.Namespace) should have different cache keys even with same auth namespace",
		},
		{
			name: "different custom headers should not match",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Headers: map[string]string{
						"X-Custom-Header": "value-a",
					},
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Headers: map[string]string{
						"X-Custom-Header": "value-b",
					},
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: false,
			reason:      "different custom headers should have different cache keys",
		},
		{
			name: "auth-related headers should not affect cache key",
			config1: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Headers: map[string]string{
						"Authorization":     "Bearer token-a",
						"X-Vault-Token":     "token-a",
						"X-Vault-Namespace": "ns-a",
					},
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			config2: AcquireClientConfig{
				VaultConfig: &vault.Config{},
				VaultProvider: &esv1.VaultProvider{
					Server: "https://vault.example.com",
					Headers: map[string]string{
						"Authorization":     "Bearer token-b",
						"X-Vault-Token":     "token-b",
						"X-Vault-Namespace": "ns-b",
					},
					Auth: &esv1.VaultAuth{
						Kubernetes: &esv1.VaultKubernetesAuth{
							Path: "kubernetes",
							Role: "my-role",
						},
					},
				},
				Namespace: "default",
				StoreKind: esv1.SecretStoreKind,
			},
			shouldMatch: true,
			reason:      "auth-related headers (Authorization, X-Vault-Token, X-Vault-Namespace) should be excluded from cache key hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1, err := ComputeCacheKey(tt.config1)
			require.NoError(t, err, "failed to compute cache key for config1")

			key2, err := ComputeCacheKey(tt.config2)
			require.NoError(t, err, "failed to compute cache key for config2")

			if tt.shouldMatch {
				assert.Equal(t, key1, key2, "cache keys should match: %s", tt.reason)
			} else {
				assert.NotEqual(t, key1, key2, "cache keys should not match: %s", tt.reason)
			}
		})
	}
}

func TestComputeAuthHash(t *testing.T) {
	tests := []struct {
		name           string
		auth           *esv1.VaultAuth
		credentialNS   string
		storeKind      string
		expectedMethod string
		shouldError    bool
	}{
		{
			name:           "no auth returns none",
			auth:           nil,
			expectedMethod: "none",
			shouldError:    false,
		},
		{
			name: "token auth",
			auth: &esv1.VaultAuth{
				TokenSecretRef: &esmeta.SecretKeySelector{
					Name: "my-token",
					Key:  "token",
				},
			},
			expectedMethod: "token",
			shouldError:    false,
		},
		{
			name: "kubernetes auth",
			auth: &esv1.VaultAuth{
				Kubernetes: &esv1.VaultKubernetesAuth{
					Path: "kubernetes",
					Role: "my-role",
				},
			},
			expectedMethod: "kubernetes",
			shouldError:    false,
		},
		{
			name: "approle auth",
			auth: &esv1.VaultAuth{
				AppRole: &esv1.VaultAppRole{
					Path:   "approle",
					RoleID: "my-role-id",
					SecretRef: esmeta.SecretKeySelector{
						Name: "my-secret",
						Key:  "secret-id",
					},
				},
			},
			expectedMethod: "approle",
			shouldError:    false,
		},
		{
			name: "jwt auth",
			auth: &esv1.VaultAuth{
				Jwt: &esv1.VaultJwtAuth{
					Path: "jwt",
					Role: "my-role",
				},
			},
			expectedMethod: "jwt",
			shouldError:    false,
		},
		{
			name: "ldap auth",
			auth: &esv1.VaultAuth{
				Ldap: &esv1.VaultLdapAuth{
					Path:     "ldap",
					Username: "user",
					SecretRef: esmeta.SecretKeySelector{
						Name: "my-secret",
						Key:  "password",
					},
				},
			},
			expectedMethod: "ldap",
			shouldError:    false,
		},
		{
			name: "userpass auth",
			auth: &esv1.VaultAuth{
				UserPass: &esv1.VaultUserPassAuth{
					Path:     "userpass",
					Username: "user",
					SecretRef: esmeta.SecretKeySelector{
						Name: "my-secret",
						Key:  "password",
					},
				},
			},
			expectedMethod: "userpass",
			shouldError:    false,
		},
		{
			name: "cert auth",
			auth: &esv1.VaultAuth{
				Cert: &esv1.VaultCertAuth{
					ClientCert: esmeta.SecretKeySelector{
						Name: "my-cert",
						Key:  "tls.crt",
					},
					SecretRef: esmeta.SecretKeySelector{
						Name: "my-cert",
						Key:  "tls.key",
					},
				},
			},
			expectedMethod: "cert",
			shouldError:    false,
		},
		{
			name: "iam auth",
			auth: &esv1.VaultAuth{
				Iam: &esv1.VaultIamAuth{
					Path:   "aws",
					Region: "us-east-1",
					Role:   "my-vault-role",
				},
			},
			expectedMethod: "iam",
			shouldError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, hash, err := computeAuthHash(tt.auth, tt.credentialNS, tt.storeKind)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMethod, method)
				assert.NotEmpty(t, hash, "hash should not be empty")
			}
		})
	}
}

func TestCacheKeyDeterministic(t *testing.T) {
	config := AcquireClientConfig{
		VaultConfig: &vault.Config{},
		VaultProvider: &esv1.VaultProvider{
			Server: "https://vault.example.com",
			Auth: &esv1.VaultAuth{
				Kubernetes: &esv1.VaultKubernetesAuth{
					Path: "kubernetes",
					Role: "my-role",
					ServiceAccountRef: &esmeta.ServiceAccountSelector{
						Name: "my-sa",
					},
				},
			},
		},
		Namespace: "default",
		StoreKind: esv1.SecretStoreKind,
	}

	// Compute the cache key multiple times
	key1, err := ComputeCacheKey(config)
	require.NoError(t, err)

	key2, err := ComputeCacheKey(config)
	require.NoError(t, err)

	key3, err := ComputeCacheKey(config)
	require.NoError(t, err)

	// All keys should be identical
	assert.Equal(t, key1, key2, "cache keys should be deterministic")
	assert.Equal(t, key2, key3, "cache keys should be deterministic")
	assert.Equal(t, key1, key3, "cache keys should be deterministic")
}

func stringPtr(s string) *string {
	return &s
}
