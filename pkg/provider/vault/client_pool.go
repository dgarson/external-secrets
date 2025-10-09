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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	vault "github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// ============================================================================
// Client Pooling Infrastructure
// ============================================================================
//
// The pooling system reduces Vault authentication overhead by reusing
// authenticated clients across ExternalSecrets with identical credentials.
//
// Key concepts:
//   - Clients are cached using composite keys (server, namespace, auth mount, auth identity)
//   - Cache keys include Kubernetes ResourceVersion for automatic invalidation on credential changes
//   - Clients automatically re-authenticate on token expiration
//   - LRU eviction prevents unbounded memory growth
//
// See design/013-vault-client-pooling.md for complete documentation.

var (
	// vaultClientPool is the global LRU cache for pooled Vault clients
	vaultClientPool *expirable.LRU[string, *pooledVaultClient]

	// Pool metrics
	poolCacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vault_client_pool_hits_total",
		Help: "Total number of cache hits",
	})
	poolCacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vault_client_pool_misses_total",
		Help: "Total number of cache misses",
	})
	poolCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vault_client_pool_size",
		Help: "Current number of clients in pool",
	})
	poolEvictions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vault_client_pool_evictions_total",
			Help: "Total number of client evictions",
		},
		[]string{"reason"}, // lru, manual
	)
)

var manualPoolRemovals sync.Map

// pooledVaultClient wraps a Vault client with automatic re-authentication capability.
//
// This client can be safely reused across multiple ExternalSecrets with identical
// credentials. It automatically re-authenticates when Vault tokens expire.
type pooledVaultClient struct {
	client          *util.VaultClient
	cacheKey        string
	cfg             *vault.Config
	setAuth         func(context.Context, *vault.Config) error
	mu              sync.Mutex
	lastAuth        time.Time
	configDigest    string
	skipTokenRevoke bool
}

// Auth returns the Auth interface from the underlying client.
func (pvc *pooledVaultClient) Auth() util.Auth {
	return pvc.client.Auth()
}

// AuthToken returns the Token interface from the underlying client.
func (pvc *pooledVaultClient) AuthToken() util.Token {
	return pvc.client.AuthToken()
}

// Logical returns a wrapped Logical interface with automatic retry on token expiration.
func (pvc *pooledVaultClient) Logical() util.Logical {
	return &logicalWithRetry{
		Logical:      pvc.client.Logical(),
		pooledClient: pvc,
		cacheKey:     pvc.cacheKey,
		shouldRetry:  pvc.shouldRetryWithReauth,
	}
}

// SetToken sets the token on the underlying client.
func (pvc *pooledVaultClient) SetToken(token string) {
	pvc.client.SetToken(token)
}

// Token returns the current token.
func (pvc *pooledVaultClient) Token() string {
	return pvc.client.Token()
}

// ClearToken clears the token on the underlying client.
func (pvc *pooledVaultClient) ClearToken() {
	pvc.client.ClearToken()
}

// SetNamespace sets the namespace on the underlying client.
func (pvc *pooledVaultClient) SetNamespace(namespace string) {
	pvc.client.SetNamespace(namespace)
}

// Namespace returns the current namespace.
func (pvc *pooledVaultClient) Namespace() string {
	return pvc.client.Namespace()
}

// AddHeader adds a header to the underlying client.
func (pvc *pooledVaultClient) AddHeader(key, value string) {
	pvc.client.AddHeader(key, value)
}

// reAuthenticate re-authenticates the client with current credentials from Kubernetes.
// This is called automatically when token expiration is detected.
func (pvc *pooledVaultClient) reAuthenticate(ctx context.Context) error {
	pvc.mu.Lock()
	defer pvc.mu.Unlock()

	// Call the auth function (fetches current credentials from K8s and authenticates)
	if err := pvc.setAuth(ctx, pvc.cfg); err != nil {
		// Remove from pool on auth failure
		removePooledClient(pvc.cacheKey)
		return err
	}

	pvc.lastAuth = time.Now()
	return nil
}

// shouldRetryWithReauth determines if an error indicates token expiration/invalidity
// and whether we should retry with re-authentication.
//
// For unambiguous errors (invalid token, expired, revoked), returns true immediately.
// For "permission denied", performs a token lookup to distinguish between:
//   - Token invalid/expired (lookup fails) - returns true (should retry)
//   - Valid token with insufficient permissions (lookup succeeds) - returns false (policy issue, don't retry)
func (pvc *pooledVaultClient) shouldRetryWithReauth(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Unambiguous token errors - always retry
	if strings.Contains(errStr, "invalid token") ||
		strings.Contains(errStr, "token is expired") ||
		strings.Contains(errStr, "token has been revoked") {
		return true
	}

	// Ambiguous "permission denied" - need to check if it's token expiration or policy denial
	if strings.Contains(errStr, "permission denied") {
		// Try to look up the token to see if it's still valid
		_, lookupErr := pvc.client.AuthToken().LookupSelfWithContext(ctx)

		// If lookup fails, token is invalid - should retry
		// If lookup succeeds, token is valid but insufficient permissions - should NOT retry (policy denial)
		return lookupErr != nil
	}

	// Other errors - don't retry
	return false
}

// logicalWithRetry wraps util.Logical with automatic retry on token expiration.
type logicalWithRetry struct {
	util.Logical
	pooledClient *pooledVaultClient
	cacheKey     string
	shouldRetry  func(context.Context, error) bool
}

// ReadWithDataWithContext implements Logical interface with retry on token expiration.
func (l *logicalWithRetry) ReadWithDataWithContext(ctx context.Context,
	path string, data map[string][]string) (*vault.Secret, error) {

	secret, err := l.Logical.ReadWithDataWithContext(ctx, path, data)

	if err != nil && l.shouldRetry(ctx, err) {
		if reAuthErr := l.pooledClient.reAuthenticate(ctx); reAuthErr != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", reAuthErr)
		}
		secret, err = l.Logical.ReadWithDataWithContext(ctx, path, data)
	}

	return secret, err
}

// WriteWithContext implements Logical interface with retry on token expiration.
func (l *logicalWithRetry) WriteWithContext(ctx context.Context,
	path string, data map[string]interface{}) (*vault.Secret, error) {

	secret, err := l.Logical.WriteWithContext(ctx, path, data)

	if err != nil && l.shouldRetry(ctx, err) {
		if reAuthErr := l.pooledClient.reAuthenticate(ctx); reAuthErr != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", reAuthErr)
		}
		secret, err = l.Logical.WriteWithContext(ctx, path, data)
	}

	return secret, err
}

// ListWithContext implements Logical interface with retry on token expiration.
func (l *logicalWithRetry) ListWithContext(ctx context.Context,
	path string) (*vault.Secret, error) {

	secret, err := l.Logical.ListWithContext(ctx, path)

	if err != nil && l.shouldRetry(ctx, err) {
		if reAuthErr := l.pooledClient.reAuthenticate(ctx); reAuthErr != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", reAuthErr)
		}
		secret, err = l.Logical.ListWithContext(ctx, path)
	}

	return secret, err
}

// DeleteWithContext implements Logical interface with retry on token expiration.
func (l *logicalWithRetry) DeleteWithContext(ctx context.Context,
	path string) (*vault.Secret, error) {

	secret, err := l.Logical.DeleteWithContext(ctx, path)

	if err != nil && l.shouldRetry(ctx, err) {
		if reAuthErr := l.pooledClient.reAuthenticate(ctx); reAuthErr != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", reAuthErr)
		}
		secret, err = l.Logical.DeleteWithContext(ctx, path)
	}

	return secret, err
}

// isVaultTokenInvalidOrExpired checks if error indicates token expiration.
func isVaultTokenInvalidOrExpired(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "permission denied") ||
		strings.Contains(errStr, "invalid token") ||
		strings.Contains(errStr, "token is expired") ||
		strings.Contains(errStr, "token has been revoked")
}

// initPooling initializes the client pool and registers metrics.
func initPooling() {
	onEvict := func(key string, value *pooledVaultClient) {
		isManual := false
		if _, ok := manualPoolRemovals.Load(key); ok {
			isManual = true
			manualPoolRemovals.Delete(key)
		}

		if !isManual {
			poolEvictions.WithLabelValues("lru").Inc()
		}

		if value != nil && !value.skipTokenRevoke {
			if err := revokeTokenIfValid(context.Background(), value); err != nil {
				logger.Error(err, "failed to revoke token on pool eviction", "cacheKey", key)
			}
		}
		poolCacheSize.Set(float64(vaultClientPool.Len()))
	}

	vaultClientPool = expirable.NewLRU[string, *pooledVaultClient](
		defaultPoolMaxSize, onEvict, defaultPoolTTL)

	metrics.Registry.MustRegister(poolCacheHits, poolCacheMisses, poolCacheSize, poolEvictions)
}

// ============================================================================
// Cache Key Generation
// ============================================================================

// buildCacheKey generates a cache key from Vault configuration.
// The cache key does NOT include the ExternalSecret's namespace because clients
// should be shared across namespaces when using the same credentials.
// See POOL.md for complete cache key design documentation.
func buildCacheKey(vaultSpec *esv1.VaultProvider, authIdentity string) string {
	parts := []string{
		vaultSpec.Server,
	}

	if vaultSpec.Namespace != nil {
		parts = append(parts, *vaultSpec.Namespace)
	} else {
		parts = append(parts, "")
	}

	// Add auth mount path if customized
	authPath := "auth"
	if vaultSpec.Auth != nil {
		if vaultSpec.Auth.Kubernetes != nil && vaultSpec.Auth.Kubernetes.Path != "" {
			authPath = vaultSpec.Auth.Kubernetes.Path
		} else if vaultSpec.Auth.AppRole != nil && vaultSpec.Auth.AppRole.Path != "" {
			authPath = vaultSpec.Auth.AppRole.Path
		}
		// Add other auth paths as needed
	}
	parts = append(parts, authPath)

	parts = append(parts, authIdentity)

	return strings.Join(parts, "|")
}

func removePooledClient(cacheKey string) {
	if vaultClientPool == nil {
		return
	}

	manualPoolRemovals.Store(cacheKey, struct{}{})
	vaultClientPool.Remove(cacheKey)
	manualPoolRemovals.Delete(cacheKey)
	poolCacheSize.Set(float64(vaultClientPool.Len()))
}

// getAuthIdentity extracts the authentication identity from Vault auth configuration.
// It fetches the necessary Kubernetes resources (Secrets/ServiceAccounts) and includes
// their ResourceVersion in the identity string for automatic cache invalidation.
func getAuthIdentity(ctx context.Context, auth *esv1.VaultAuth,
	kube kclient.Client, namespace string) (string, error) {

	if auth == nil {
		return "no-auth", nil
	}

	switch {
	// Kubernetes ServiceAccount authentication
	case auth.Kubernetes != nil && auth.Kubernetes.ServiceAccountRef != nil:
		k8sAuth := auth.Kubernetes
		sa := &corev1.ServiceAccount{}
		saNs := namespace
		if k8sAuth.ServiceAccountRef.Namespace != nil {
			saNs = *k8sAuth.ServiceAccountRef.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: saNs,
			Name:      k8sAuth.ServiceAccountRef.Name,
		}, sa)
		if err != nil {
			return "", fmt.Errorf("failed to get ServiceAccount: %w", err)
		}

		return fmt.Sprintf("k8s-sa:%s:%s:%s:v%s",
			saNs,
			k8sAuth.ServiceAccountRef.Name,
			k8sAuth.Role,
			sa.ResourceVersion), nil

	// Kubernetes auth with SecretRef (JWT from Secret)
	case auth.Kubernetes != nil && auth.Kubernetes.SecretRef != nil:
		k8sAuth := auth.Kubernetes
		secret := &corev1.Secret{}
		secretNs := namespace
		if k8sAuth.SecretRef.Namespace != nil {
			secretNs = *k8sAuth.SecretRef.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: secretNs,
			Name:      k8sAuth.SecretRef.Name,
		}, secret)
		if err != nil {
			return "", fmt.Errorf("failed to get Kubernetes secret: %w", err)
		}

		return fmt.Sprintf("k8s-secret:%s:%s:v%s",
			secretNs,
			k8sAuth.SecretRef.Name,
			secret.ResourceVersion), nil

	// AWS IAM authentication with ServiceAccount (IRSA/EKS Pod Identity)
	case auth.Iam != nil && auth.Iam.JWTAuth != nil && auth.Iam.JWTAuth.ServiceAccountRef != nil:
		iamAuth := auth.Iam
		sa := &corev1.ServiceAccount{}
		saNs := namespace
		if iamAuth.JWTAuth.ServiceAccountRef.Namespace != nil {
			saNs = *iamAuth.JWTAuth.ServiceAccountRef.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: saNs,
			Name:      iamAuth.JWTAuth.ServiceAccountRef.Name,
		}, sa)
		if err != nil {
			return "", fmt.Errorf("failed to get ServiceAccount for IAM auth: %w", err)
		}

		return fmt.Sprintf("iam:%s:%s:sa:%s:%s:v%s",
			iamAuth.Region,
			iamAuth.Role,
			saNs,
			iamAuth.JWTAuth.ServiceAccountRef.Name,
			sa.ResourceVersion), nil

	// AWS IAM authentication with static credentials from Secrets
	case auth.Iam != nil && auth.Iam.SecretRef != nil:
		iamAuth := auth.Iam

		// Get AccessKeyID Secret
		akSecret := &corev1.Secret{}
		akNs := namespace
		if iamAuth.SecretRef.AccessKeyID.Namespace != nil {
			akNs = *iamAuth.SecretRef.AccessKeyID.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: akNs,
			Name:      iamAuth.SecretRef.AccessKeyID.Name,
		}, akSecret)
		if err != nil {
			return "", fmt.Errorf("failed to get IAM AccessKeyID secret: %w", err)
		}

		// Get SecretAccessKey Secret
		skSecret := &corev1.Secret{}
		skNs := namespace
		if iamAuth.SecretRef.SecretAccessKey.Namespace != nil {
			skNs = *iamAuth.SecretRef.SecretAccessKey.Namespace
		}

		err = kube.Get(ctx, kclient.ObjectKey{
			Namespace: skNs,
			Name:      iamAuth.SecretRef.SecretAccessKey.Name,
		}, skSecret)
		if err != nil {
			return "", fmt.Errorf("failed to get IAM SecretAccessKey secret: %w", err)
		}

		// Build base identity string
		identity := fmt.Sprintf("iam:%s:%s:ak:%s:%s:v%s:sk:%s:%s:v%s",
			iamAuth.Region,
			iamAuth.Role,
			akNs,
			iamAuth.SecretRef.AccessKeyID.Name,
			akSecret.ResourceVersion,
			skNs,
			iamAuth.SecretRef.SecretAccessKey.Name,
			skSecret.ResourceVersion)

		// Add SessionToken if present
		if iamAuth.SecretRef.SessionToken != nil {
			stSecret := &corev1.Secret{}
			stNs := namespace
			if iamAuth.SecretRef.SessionToken.Namespace != nil {
				stNs = *iamAuth.SecretRef.SessionToken.Namespace
			}

			err = kube.Get(ctx, kclient.ObjectKey{
				Namespace: stNs,
				Name:      iamAuth.SecretRef.SessionToken.Name,
			}, stSecret)
			if err != nil {
				return "", fmt.Errorf("failed to get IAM SessionToken secret: %w", err)
			}

			identity = fmt.Sprintf("%s:st:%s:%s:v%s",
				identity,
				stNs,
				iamAuth.SecretRef.SessionToken.Name,
				stSecret.ResourceVersion)
		}

		return identity, nil

	// AWS IAM authentication using controller's ServiceAccount (implicit IRSA)
	case auth.Iam != nil:
		// No explicit credentials - using controller's own ServiceAccount
		// This is implicit IRSA/EKS Pod Identity (credentials from pod's SA)
		iamAuth := auth.Iam
		return fmt.Sprintf("iam:%s:%s:controller-sa",
			iamAuth.Region,
			iamAuth.Role), nil

	// STATIC AUTH: Include Secret ResourceVersion for immediate rotation detection

	case auth.AppRole != nil:
		// AppRole with SecretID in K8s Secret
		secret := &corev1.Secret{}
		secretRef := auth.AppRole.SecretRef
		secretNs := namespace
		if secretRef.Namespace != nil {
			secretNs = *secretRef.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: secretNs,
			Name:      secretRef.Name,
		}, secret)
		if err != nil {
			return "", fmt.Errorf("failed to get AppRole secret: %w", err)
		}

		roleID := auth.AppRole.RoleID
		if roleID == "" && auth.AppRole.RoleRef != nil {
			roleID = "roleRef"
		}

		return fmt.Sprintf("approle:%s:secret:%s:%s:v%s",
			roleID,
			secretNs,
			secretRef.Name,
			secret.ResourceVersion), nil

	case auth.TokenSecretRef != nil:
		// Token from K8s Secret
		secret := &corev1.Secret{}
		tokenRef := auth.TokenSecretRef
		tokenNs := namespace
		if tokenRef.Namespace != nil {
			tokenNs = *tokenRef.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: tokenNs,
			Name:      tokenRef.Name,
		}, secret)
		if err != nil {
			return "", fmt.Errorf("failed to get token secret: %w", err)
		}

		return fmt.Sprintf("token:%s:%s:v%s",
			tokenNs,
			tokenRef.Name,
			secret.ResourceVersion), nil

	case auth.Jwt != nil:
		jwtAuth := auth.Jwt

		if jwtAuth.SecretRef != nil {
			// JWT from K8s Secret
			secret := &corev1.Secret{}
			jwtRef := jwtAuth.SecretRef
			jwtNs := namespace
			if jwtRef.Namespace != nil {
				jwtNs = *jwtRef.Namespace
			}

			err := kube.Get(ctx, kclient.ObjectKey{
				Namespace: jwtNs,
				Name:      jwtRef.Name,
			}, secret)
			if err != nil {
				return "", fmt.Errorf("failed to get JWT secret: %w", err)
			}

			return fmt.Sprintf("jwt:%s:secret:%s:%s:v%s",
				jwtAuth.Role,
				jwtNs,
				jwtRef.Name,
				secret.ResourceVersion), nil
		}

		if jwtAuth.KubernetesServiceAccountToken != nil {
			// JWT from Kubernetes ServiceAccount token (dynamic)
			sa := &corev1.ServiceAccount{}
			saRef := jwtAuth.KubernetesServiceAccountToken.ServiceAccountRef
			saNs := namespace
			if saRef.Namespace != nil {
				saNs = *saRef.Namespace
			}

			err := kube.Get(ctx, kclient.ObjectKey{
				Namespace: saNs,
				Name:      saRef.Name,
			}, sa)
			if err != nil {
				return "", fmt.Errorf("failed to get ServiceAccount for JWT auth: %w", err)
			}

			return fmt.Sprintf("jwt-sa:%s:%s:%s:v%s",
				saNs,
				saRef.Name,
				jwtAuth.Role,
				sa.ResourceVersion), nil
		}

	case auth.Cert != nil:
		// Certificate authentication
		certAuth := auth.Cert

		certSecret := &corev1.Secret{}
		certNs := namespace
		if certAuth.ClientCert.Namespace != nil {
			certNs = *certAuth.ClientCert.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: certNs,
			Name:      certAuth.ClientCert.Name,
		}, certSecret)
		if err != nil {
			return "", fmt.Errorf("failed to get cert secret: %w", err)
		}

		keySecret := &corev1.Secret{}
		keyNs := namespace
		if certAuth.SecretRef.Namespace != nil {
			keyNs = *certAuth.SecretRef.Namespace
		}

		err = kube.Get(ctx, kclient.ObjectKey{
			Namespace: keyNs,
			Name:      certAuth.SecretRef.Name,
		}, keySecret)
		if err != nil {
			return "", fmt.Errorf("failed to get key secret: %w", err)
		}

		return fmt.Sprintf("cert:cert:%s:%s:v%s:key:%s:%s:v%s",
			certNs,
			certAuth.ClientCert.Name,
			certSecret.ResourceVersion,
			keyNs,
			certAuth.SecretRef.Name,
			keySecret.ResourceVersion), nil

	case auth.Ldap != nil:
		// LDAP authentication
		ldapAuth := auth.Ldap

		secret := &corev1.Secret{}
		ldapRef := ldapAuth.SecretRef
		ldapNs := namespace
		if ldapRef.Namespace != nil {
			ldapNs = *ldapRef.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: ldapNs,
			Name:      ldapRef.Name,
		}, secret)
		if err != nil {
			return "", fmt.Errorf("failed to get LDAP secret: %w", err)
		}

		return fmt.Sprintf("ldap:%s:secret:%s:%s:v%s",
			ldapAuth.Username,
			ldapNs,
			ldapRef.Name,
			secret.ResourceVersion), nil

	case auth.UserPass != nil:
		// UserPass authentication
		userPassAuth := auth.UserPass

		secret := &corev1.Secret{}
		upRef := userPassAuth.SecretRef
		upNs := namespace
		if upRef.Namespace != nil {
			upNs = *upRef.Namespace
		}

		err := kube.Get(ctx, kclient.ObjectKey{
			Namespace: upNs,
			Name:      upRef.Name,
		}, secret)
		if err != nil {
			return "", fmt.Errorf("failed to get UserPass secret: %w", err)
		}

		return fmt.Sprintf("userpass:%s:secret:%s:%s:v%s",
			userPassAuth.Username,
			upNs,
			upRef.Name,
			secret.ResourceVersion), nil
	}

	return "unknown-auth", nil
}
