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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// ClientPool manages pooled Vault clients using an LRU cache with TTL.
type ClientPool struct {
	cache *lru.LRU[string, *PooledClient]
}

// PooledClient wraps a Vault client with metadata.
type PooledClient struct {
	client    util.Client
	createdAt time.Time
	poolKey   string
}

// AuthConfig stores information needed for potential re-authentication.
type AuthConfig struct {
	vaultSpec *esv1.VaultProvider
	namespace string
	kube      kclient.Client
	corev1    typedcorev1.CoreV1Interface
	storeKind string
}

// PoolKey represents a cache key for client pooling.
type PoolKey struct {
	ServerURL          string
	VaultNamespace     string
	CABundle           string
	TLSServerName      string
	AuthMethod         string
	AuthMountPath      string
	AuthRole           string
	K8sNamespace       string
	CredentialIdentity string
}

// String returns a deterministic string representation.
func (k PoolKey) String() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		k.ServerURL,
		k.VaultNamespace,
		k.CABundle,
		k.TLSServerName,
		k.AuthMethod,
		k.AuthMountPath,
		k.AuthRole,
		k.K8sNamespace,
		k.CredentialIdentity,
	)
}

// NewClientPool creates a new client pool with LRU eviction and TTL.
func NewClientPool(maxSize int, ttl time.Duration) *ClientPool {
	// Create LRU cache with eviction callback for metrics
	cache := lru.NewLRU[string, *PooledClient](maxSize, func(key string, value *PooledClient) {
		// Track evictions in metrics
		metrics.VaultClientPoolEvictions.WithLabelValues("lru").Inc()
		logger.V(1).Info("Evicted client from pool", "poolKey", key)
	}, ttl)

	return &ClientPool{
		cache: cache,
	}
}

// GetAuthenticated retrieves an authenticated client from the pool.
func (p *ClientPool) GetAuthenticated(poolKey string) *PooledClient {
	client, ok := p.cache.Get(poolKey)
	if !ok {
		metrics.VaultClientPoolMisses.Inc()
		return nil
	}

	// Check if token is still valid
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.client.AuthToken().LookupSelfWithContext(ctx)
	if err != nil {
		// Token expired or invalid - remove from cache
		logger.V(1).Info("Cached client has invalid token, removing from pool", "poolKey", poolKey, "error", err)
		p.cache.Remove(poolKey)
		metrics.VaultClientPoolMisses.Inc()
		return nil
	}

	metrics.VaultClientPoolHits.Inc()
	logger.V(1).Info("Pool hit", "poolKey", poolKey, "age", time.Since(client.createdAt))
	return client
}

// StoreAuthenticated stores an authenticated client in the pool.
func (p *ClientPool) StoreAuthenticated(poolKey string, client util.Client, authConfig *AuthConfig) {
	pooledClient := &PooledClient{
		client:    client,
		createdAt: time.Now(),
		poolKey:   poolKey,
	}

	p.cache.Add(poolKey, pooledClient)

	// Update size metric
	metrics.VaultClientPoolSize.Set(float64(p.cache.Len()))
	logger.V(1).Info("Stored client in pool", "poolKey", poolKey, "poolSize", p.cache.Len())
}

// StartEviction is a no-op since the LRU cache handles eviction automatically.
// Kept for API compatibility.
func (p *ClientPool) StartEviction(ctx context.Context) {
	// LRU cache handles eviction automatically, nothing to do
}

// GetMetrics returns current pool metrics.
func (p *ClientPool) GetMetrics() PoolMetrics {
	return PoolMetrics{
		size: int64(p.cache.Len()),
		// hits, misses, evictions are tracked via Prometheus metrics
	}
}

// PoolMetrics tracks pool performance.
type PoolMetrics struct {
	hits      int64
	misses    int64
	evictions int64
	size      int64
}

// generatePoolKey generates a pool key for the given configuration.
func generatePoolKey(ctx context.Context, vaultSpec *esv1.VaultProvider,
	namespace string, kube kclient.Client, corev1 typedcorev1.CoreV1Interface,
	storeKind string) (string, error) {

	key := PoolKey{
		ServerURL:      vaultSpec.Server,
		VaultNamespace: safeString(vaultSpec.Namespace),
	}

	// Hash CA bundle if present
	if len(vaultSpec.CABundle) > 0 {
		hash := sha256.Sum256(vaultSpec.CABundle)
		key.CABundle = hex.EncodeToString(hash[:])
	}

	// Get credential identity based on auth method
	credentialIdentity, authMethod, authPath, authRole, err := getAuthIdentity(
		ctx, vaultSpec.Auth, namespace, kube, corev1, storeKind)
	if err != nil {
		return "", fmt.Errorf("failed to get auth identity: %w", err)
	}

	key.AuthMethod = authMethod
	key.AuthMountPath = authPath
	key.AuthRole = authRole
	key.K8sNamespace = namespace
	key.CredentialIdentity = credentialIdentity

	return key.String(), nil
}

// getAuthIdentity returns the credential identity for the auth method.
// This function extracts credential identity (ResourceVersion for Secret-based auth,
// or ServiceAccount/Role identity for dynamic auth) to generate pool keys.
//
// It reuses the same Secret-fetching logic as the existing auth_*.go files
// (via getSecretResourceVersion), ensuring consistency with how credentials are
// read during authentication. The key difference is:
// - auth_*.go files: use resolvers.SecretKeyRef() to get the secret VALUE and authenticate
// - getAuthIdentity(): uses getSecretResourceVersion() to get the RESOURCEVERSION for pool keys
//
// This approach ensures that:
// 1. We detect credential rotation immediately (ResourceVersion changes)
// 2. We follow the same namespace resolution logic as authentication
// 3. We don't duplicate Secret-fetching logic - we reuse the same k8s client patterns
func getAuthIdentity(ctx context.Context, auth *esv1.VaultAuth, namespace string,
	kube kclient.Client, corev1 typedcorev1.CoreV1Interface, storeKind string) (
	credentialIdentity, authMethod, authPath, authRole string, err error) {

	if auth == nil {
		return "no-auth", "none", "", "", nil
	}

	switch {
	case auth.TokenSecretRef != nil:
		// Static token - read Secret for ResourceVersion
		// Reuses the same Secret-fetching logic as auth_token.go:setSecretKeyToken
		rv, err := getSecretResourceVersion(ctx, kube, storeKind, namespace, auth.TokenSecretRef)
		if err != nil {
			return "", "", "", "", err
		}
		return fmt.Sprintf("token:rv:%s", rv),
			"token", "", "", nil

	case auth.Kubernetes != nil:
		// Dynamic SA token - identity-based
		saRef := auth.Kubernetes.ServiceAccountRef
		saNamespace := namespace
		if saRef != nil && saRef.Namespace != nil {
			saNamespace = *saRef.Namespace
		}
		saName := ""
		if saRef != nil {
			saName = saRef.Name
		}
		return fmt.Sprintf("k8s-sa:%s/%s", saNamespace, saName),
			"kubernetes",
			auth.Kubernetes.Path,
			auth.Kubernetes.Role,
			nil

	case auth.AppRole != nil:
		// AppRole - RoleID + SecretID Secret ResourceVersion
		// Reuses the same Secret-fetching logic as auth_approle.go:requestTokenWithAppRoleRef
		roleID := auth.AppRole.RoleID
		// SecretRef is not a pointer, it's required
		rv, err := getSecretResourceVersion(ctx, kube, storeKind, namespace, &auth.AppRole.SecretRef)
		if err != nil {
			return "", "", "", "", err
		}
		return fmt.Sprintf("approle:role:%s:rv:%s", roleID, rv),
			"approle",
			auth.AppRole.Path,
			roleID,
			nil

	case auth.Jwt != nil:
		if auth.Jwt.SecretRef != nil {
			// JWT from Secret - reuses logic from auth_jwt.go:requestTokenWithJwtAuth
			rv, err := getSecretResourceVersion(ctx, kube, storeKind, namespace, auth.Jwt.SecretRef)
			if err != nil {
				return "", "", "", "", err
			}
			return fmt.Sprintf("jwt:role:%s:rv:%s", auth.Jwt.Role, rv),
				"jwt",
				auth.Jwt.Path,
				auth.Jwt.Role,
				nil
		} else if auth.Jwt.KubernetesServiceAccountToken != nil {
			// JWT from SA token - identity-based (similar to auth_kubernetes.go)
			saRef := &auth.Jwt.KubernetesServiceAccountToken.ServiceAccountRef
			saNamespace := namespace
			if saRef.Namespace != nil {
				saNamespace = *saRef.Namespace
			}
			return fmt.Sprintf("jwt-sa:%s/%s:role:%s", saNamespace, saRef.Name, auth.Jwt.Role),
				"jwt",
				auth.Jwt.Path,
				auth.Jwt.Role,
				nil
		}

	case auth.Ldap != nil:
		// LDAP - credentials from Secret (reuses logic from auth_ldap.go)
		rv, err := getSecretResourceVersion(ctx, kube, storeKind, namespace, &auth.Ldap.SecretRef)
		if err != nil {
			return "", "", "", "", err
		}
		return fmt.Sprintf("ldap:user:%s:rv:%s", auth.Ldap.Username, rv),
			"ldap",
			auth.Ldap.Path,
			"",
			nil

	case auth.UserPass != nil:
		// UserPass - credentials from Secret (reuses logic from auth_userpass.go)
		rv, err := getSecretResourceVersion(ctx, kube, storeKind, namespace, &auth.UserPass.SecretRef)
		if err != nil {
			return "", "", "", "", err
		}
		return fmt.Sprintf("userpass:user:%s:rv:%s", auth.UserPass.Username, rv),
			"userpass",
			auth.UserPass.Path,
			"",
			nil

	case auth.Cert != nil:
		// Certificate auth - cert and key Secrets (reuses logic from auth_cert.go)
		certRV, err := getSecretResourceVersion(ctx, kube, storeKind, namespace, &auth.Cert.ClientCert)
		if err != nil {
			return "", "", "", "", err
		}
		keyRV, err := getSecretResourceVersion(ctx, kube, storeKind, namespace, &auth.Cert.SecretRef)
		if err != nil {
			return "", "", "", "", err
		}
		return fmt.Sprintf("cert:rv:%s:%s", certRV, keyRV),
			"cert",
			"", // Cert auth doesn't have a mount path in the struct
			"",
			nil

	case auth.Iam != nil:
		// AWS IAM auth (reuses logic from auth_iam.go)
		if auth.Iam.SecretRef != nil {
			// Static credentials from Secret
			rv, err := getSecretResourceVersion(ctx, kube, storeKind, namespace, &auth.Iam.SecretRef.AccessKeyID)
			if err != nil {
				return "", "", "", "", err
			}
			return fmt.Sprintf("iam:static:rv:%s", rv),
				"iam",
				auth.Iam.Path,
				auth.Iam.Role,
				nil
		}
		// IRSA or instance profile - identity-based
		return fmt.Sprintf("iam:role:%s:region:%s", auth.Iam.Role, auth.Iam.Region),
			"iam",
			auth.Iam.Path,
			auth.Iam.Role,
			nil
	}

	return "unknown", "unknown", "", "", nil
}

// safeString returns the string value or empty string if nil.
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// getSecretResourceVersion retrieves a Secret's ResourceVersion for pool key generation.
// This is similar to resolvers.SecretKeyRef but returns the ResourceVersion instead of the value.
// We reuse the same namespace resolution logic as resolvers.SecretKeyRef to ensure consistency.
func getSecretResourceVersion(ctx context.Context, kube kclient.Client, storeKind, namespace string, ref *esmeta.SecretKeySelector) (string, error) {
	// Use the same namespace resolution logic as resolvers.SecretKeyRef
	key := types.NamespacedName{
		Namespace: namespace,
		Name:      ref.Name,
	}
	if storeKind == esv1.ClusterSecretStoreKind && ref.Namespace != nil {
		key.Namespace = *ref.Namespace
	}

	secret := &corev1.Secret{}
	err := kube.Get(ctx, key, secret)
	if err != nil {
		return "", fmt.Errorf("cannot get Kubernetes secret %q from namespace %q: %w", ref.Name, key.Namespace, err)
	}
	return secret.ResourceVersion, nil
}
