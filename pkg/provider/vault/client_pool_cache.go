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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
	lru "github.com/hashicorp/golang-lru/v2"
	vault "github.com/hashicorp/vault/api"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// CachingClientPool is a ClientPool implementation that caches ManagedClient instances using an LRU cache.
// The pool is intentionally simple - ManagedClient instances handle their own lifecycle (renewal, eviction).
// The pool just maintains the cache and responds to eviction requests via callbacks.
type CachingClientPool struct {
	mu             sync.RWMutex
	cache          *lru.Cache[string, *CachedClient]
	authGroup      singleflight.Group // Deduplicates concurrent client creation and authentication
	newVaultClient func(config *vault.Config) (util.Client, error)

	// Configuration for ManagedClient creation
	enableRenewal           bool
	renewalThresholdPercent int
	renewalCheckInterval    time.Duration
	tokenOperationTimeout   time.Duration

	// Client index for reverse lookup (client -> ManagedClient)
	indexMu     sync.RWMutex
	clientIndex map[util.Client]*CachedClient

	// Optional callback for eviction events
	onClientEvicted func(address string)
}

// CachingClientPoolConfig configures the caching client pool.
type CachingClientPoolConfig struct {
	NewVaultClient func(config *vault.Config) (util.Client, error)

	EnableRenewal           bool
	RenewalThresholdPercent int
	RenewalCheckInterval    time.Duration

	TokenOperationTimeout time.Duration
	MaxCacheSize          int

	// Optional callback invoked when a client is evicted from the cache.
	// This is called with the Vault server address of the evicted client.
	OnClientEvicted func(address string)
}

// NewCachingClientPool creates a new caching client pool.
// Returns an error if the LRU cache cannot be created (e.g., invalid MaxCacheSize).
func NewCachingClientPool(config CachingClientPoolConfig) (*CachingClientPool, error) {
	if config.NewVaultClient == nil {
		config.NewVaultClient = NewVaultClient
	}
	if config.RenewalCheckInterval == 0 {
		config.RenewalCheckInterval = 30 * time.Minute
	}
	config.RenewalCheckInterval = clampRenewalInterval(config.RenewalCheckInterval)
	if config.RenewalThresholdPercent == 0 {
		config.RenewalThresholdPercent = 50
	}
	if config.MaxCacheSize == 0 {
		config.MaxCacheSize = 1000
	}
	if config.TokenOperationTimeout == 0 {
		config.TokenOperationTimeout = defaultTokenOperationTimeout
	}

	pool := &CachingClientPool{
		newVaultClient:          config.NewVaultClient,
		enableRenewal:           config.EnableRenewal,
		renewalThresholdPercent: config.RenewalThresholdPercent,
		renewalCheckInterval:    config.RenewalCheckInterval,
		tokenOperationTimeout:   config.TokenOperationTimeout,
		onClientEvicted:         config.OnClientEvicted,
		clientIndex:             make(map[util.Client]*CachedClient),
	}

	cache, err := lru.NewWithEvict(config.MaxCacheSize, func(key string, managed *CachedClient) {
		pool.handleEvictedClient(key, managed)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %w", err)
	}

	pool.cache = cache
	return pool, nil
}

// hasDynamicTLS returns true if the provider uses TLS certificates from Kubernetes secrets.
// TLS configuration is set when creating the HTTP client and cannot be updated via re-authentication
// (unlike auth tokens). Therefore, clients with dynamic TLS should not be cached to ensure
// certificate rotations are picked up immediately.
func hasDynamicTLS(provider *esv1.VaultProvider) bool {
	if provider == nil {
		return false
	}
	// TLS certs/keys from K8s secrets can be rotated - these clients should not be cached
	return provider.ClientTLS.CertSecretRef != nil || provider.ClientTLS.KeySecretRef != nil
}

// AcquireClient returns a cached ManagedClient or creates a new one.
func (p *CachingClientPool) AcquireClient(ctx context.Context, config AcquireClientConfig) (util.Client, error) {
	// Validate config
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Don't cache clients with TLS certificates from secrets
	// TLS config is set at HTTP client creation and cannot be updated via reauth (unlike tokens)
	// This ensures certificate rotations are picked up immediately
	if hasDynamicTLS(config.VaultProvider) {
		logger.V(1).Info("creating non-cached vault client due to dynamic TLS configuration")
		return createClient(&config, p.newVaultClient)
	}

	// Compute cache key
	cacheKey, err := ComputeCacheKey(config)
	if err != nil {
		return nil, fmt.Errorf("failed to compute cache key: %w", err)
	}
	keyStr := cacheKey.String()

	// Fast path: check cache with read lock
	p.mu.RLock()
	managed, exists := p.cache.Get(keyStr)
	p.mu.RUnlock()

	if exists {
		// Get a valid client (will reauth if needed using its own singleflight)
		client, err := managed.GetValidClient(ctx, config)
		if err != nil {
			// Re-authentication failed - return error instead of creating new client
			// (creating new client with same credentials would fail the same way)
			return nil, fmt.Errorf("cached client reauth failed: %w", err)
		}

		// Successfully got valid client (either was valid or successfully reauthed)
		logger.V(1).Info("using cached vault client", "key", keyStr)
		managed.Acquire()
		return client, nil
	}

	// Slow path: use singleflight to ensure only ONE goroutine creates the client.
	// Multiple goroutines requesting the same uncached key will wait here and all
	// receive the same result when the first goroutine completes.
	result, err, _ := p.authGroup.Do(keyStr, func() (interface{}, error) {
		// Double-check cache inside singleflight (another goroutine may have won)
		p.mu.RLock()
		if existing, ok := p.cache.Get(keyStr); ok {
			p.mu.RUnlock()
			return existing, nil
		}
		p.mu.RUnlock()

		// Actually create new client (expensive I/O operation)
		vaultClient, err := createClient(&config, p.newVaultClient)
		if err != nil {
			return nil, err
		}

		// Create ManagedClient wrapper
		managed := NewCachedClient(CachedClientConfig{
			Client:                  vaultClient,
			Config:                  config,
			CacheKey:                keyStr,
			Deps: CachedClientDeps{
				onEvicted: func(key string) {
					// CachedClient is requesting eviction due to renewal failures
					p.mu.Lock()
					p.cache.Remove(key)
					p.mu.Unlock()
				},
			},
			EnableRenewal:           p.enableRenewal,
			RenewalThresholdPercent: p.renewalThresholdPercent,
			RenewalCheckInterval:    p.renewalCheckInterval,
			TokenOperationTimeout:   p.tokenOperationTimeout,
		})

		// Calculate initial renewal time after successful authentication
		if p.enableRenewal {
			reauthCtx, cancel := context.WithTimeout(ctx, p.tokenOperationTimeout)
			managed.calculateAndSetNextRenewal(reauthCtx)
			cancel()
		}

		// Add to cache and register for reverse lookup under write lock
		p.mu.Lock()
		p.cache.Add(keyStr, managed)
		p.registerClient(managed)
		p.mu.Unlock()

		return managed, nil
	})

	if err != nil {
		return nil, err
	}

	managed = result.(*CachedClient)
	managed.Acquire()
	return managed.Client(), nil
}

// ReleaseClient decrements the usage count for the provided client.
func (p *CachingClientPool) ReleaseClient(ctx context.Context, client util.Client) error {
	if client == nil {
		return nil
	}

	p.indexMu.RLock()
	managed, ok := p.clientIndex[client]
	p.indexMu.RUnlock()

	if !ok {
		return nil
	}

	// Release returns true if the client should be finalized
	if shouldFinalize := managed.Release(); shouldFinalize {
		return managed.Close(ctx)
	}

	return nil
}

// Close closes all cached clients and stops renewal goroutines.
func (p *CachingClientPool) Close(ctx context.Context) error {
	// Clear cache (Purge() removes all items and calls eviction callback)
	// The eviction callback will mark each client as evicted
	p.mu.Lock()
	p.cache.Purge()
	p.mu.Unlock()

	// Finalize any remaining clients
	// (clients with active users will finalize when their refcount reaches 0)
	p.finalizeAllClients(ctx)

	return nil
}

// handleEvictedClient is called when a client is evicted from the LRU cache.
func (p *CachingClientPool) handleEvictedClient(key string, managed *CachedClient) {
	if managed == nil {
		return
	}

	// Mark as evicted so Release() knows to finalize when refcount reaches 0
	atomic.StoreInt32(&managed.evicted, 1)

	// If no active users, close immediately
	activeUsers := atomic.LoadInt32(&managed.activeUsers)
	if activeUsers == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), p.tokenOperationTimeout)
		defer cancel()

		if err := managed.Close(ctx); err != nil {
			logger.Error(err, "failed to close evicted client", "key", key)
		}

		p.unregisterClient(managed)

		// Notify listener if configured
		if p.onClientEvicted != nil {
			p.onClientEvicted(managed.Client().GetAddress())
		}
	}

	logger.V(1).Info("evicted client from cache", "key", key, "active_users", activeUsers)
}


// finalizeAllClients closes all clients in the index.
func (p *CachingClientPool) finalizeAllClients(ctx context.Context) {
	p.indexMu.RLock()
	managedClients := make([]*CachedClient, 0, len(p.clientIndex))
	for _, managed := range p.clientIndex {
		managedClients = append(managedClients, managed)
	}
	p.indexMu.RUnlock()

	for _, managed := range managedClients {
		if managed == nil {
			continue
		}
		atomic.StoreInt32(&managed.evicted, 1)

		if err := managed.Close(ctx); err != nil {
			logger.Error(err, "failed to close client during shutdown", "key", managed.CacheKey())
		}

		p.unregisterClient(managed)

		// Notify listener if configured
		if p.onClientEvicted != nil {
			p.onClientEvicted(managed.Client().GetAddress())
		}
	}
}

// registerClient registers a ManagedClient in the index for reverse lookup.
func (p *CachingClientPool) registerClient(managed *CachedClient) {
	if managed == nil || managed.Client() == nil {
		return
	}

	p.indexMu.Lock()
	p.clientIndex[managed.Client()] = managed
	p.indexMu.Unlock()
}

// unregisterClient removes a ManagedClient from the index.
func (p *CachingClientPool) unregisterClient(managed *CachedClient) {
	if managed == nil || managed.Client() == nil {
		return
	}

	p.indexMu.Lock()
	delete(p.clientIndex, managed.Client())
	p.indexMu.Unlock()
}

// createClient creates and authenticates a new Vault client.
func createClient(config *AcquireClientConfig, newVaultClient func(*vault.Config) (util.Client, error)) (util.Client, error) {
	vaultClient, err := newVaultClient(config.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set namespace and headers
	if config.VaultProvider.Namespace != nil {
		vaultClient.SetNamespace(*config.VaultProvider.Namespace)
	}
	if config.VaultProvider.Headers != nil {
		for key, value := range config.VaultProvider.Headers {
			vaultClient.AddHeader(key, value)
		}
	}
	if config.VaultProvider.ReadYourWrites && config.VaultProvider.ForwardInconsistent {
		vaultClient.AddHeader("X-Vault-Inconsistent", "forward-active-node")
	}

	// Authenticate
	c := &client{
		kube:      config.Kube,
		corev1:    config.CoreV1,
		store:     config.VaultProvider,
		namespace: config.CredentialNamespace,
		storeKind: config.Metadata.StoreKind,
		client:    vaultClient,
		auth:      vaultClient.Auth(),
		logical:   vaultClient.Logical(),
		token:     vaultClient.AuthToken(),
		log:       logger,
	}

	skipAuth := config.Metadata.StoreKind == esv1.ClusterSecretStoreKind &&
		config.CredentialNamespace == "" &&
		isReferentSpec(config.VaultProvider)

	if !skipAuth {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTokenOperationTimeout)
		defer cancel()
		if err := c.setAuth(ctx, config.VaultConfig); err != nil {
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	return vaultClient, nil
}

// Verify CachingClientPool implements ClientPool interface.
var _ ClientPool = &CachingClientPool{}

// VaultClientCacheKey uniquely identifies a Vault client based on its
// connection properties and authentication identity.
// Two configurations that would produce the same authenticated Vault token
// should have the same cache key.
type VaultClientCacheKey struct {
	// Server is the Vault server URL
	Server string `json:"server"`

	// VaultAuthNamespace is the Vault namespace where authentication occurs.
	// This is auth.Namespace if set, otherwise provider.Namespace.
	VaultAuthNamespace string `json:"vaultAuthNamespace"`

	// AuthMethod identifies the authentication method being used.
	// Examples: "kubernetes", "approle", "jwt", "ldap", "userpass", "cert", "iam", "token"
	AuthMethod string `json:"authMethod"`

	// AuthConfigHash is a SHA256 hash of the authentication configuration
	// specific to the AuthMethod. This includes paths, roles, and credential
	// references, but excludes the actual credential values.
	AuthConfigHash string `json:"authConfigHash"`

	// CredentialNamespace is the Kubernetes namespace used for resolving
	// credential references (secrets, service accounts). This is only set
	// for referent specs where credentials are namespace-dependent.
	CredentialNamespace string `json:"credentialNamespace,omitempty"`

	// TLSConfigHash is a SHA256 hash of the client TLS configuration.
	// This includes certificate and key references but not the actual certs.
	TLSConfigHash string `json:"tlsConfigHash"`

	// VaultSecretsNamespace is the Vault namespace for reading/writing secrets.
	// This is provider.Namespace and can differ from VaultAuthNamespace when
	// authenticating in one namespace but accessing secrets in another.
	VaultSecretsNamespace string `json:"vaultSecretsNamespace,omitempty"`

	// HeadersHash is a SHA256 hash of custom headers (excluding auth-related headers).
	// Headers are sorted for deterministic output.
	HeadersHash string `json:"headersHash"`
}

// String returns a string representation of the cache key for debugging.
func (k VaultClientCacheKey) String() string {
	return fmt.Sprintf("server=%s,authNS=%s,method=%s,authHash=%s,credNS=%s,tlsHash=%s,secretsNS=%s,headersHash=%s",
		k.Server, k.VaultAuthNamespace, k.AuthMethod, k.AuthConfigHash[:8],
		k.CredentialNamespace, k.TLSConfigHash[:8], k.VaultSecretsNamespace, k.HeadersHash[:8])
}

// ComputeCacheKey computes the cache key for a Vault client configuration.
func ComputeCacheKey(config AcquireClientConfig) (VaultClientCacheKey, error) {
	key := VaultClientCacheKey{
		Server: config.VaultProvider.Server,
	}

	// Compute effective auth namespace (where authentication happens)
	if config.VaultProvider.Auth != nil && config.VaultProvider.Auth.Namespace != nil {
		key.VaultAuthNamespace = *config.VaultProvider.Auth.Namespace
	} else if config.VaultProvider.Namespace != nil {
		key.VaultAuthNamespace = *config.VaultProvider.Namespace
	}

	// Determine auth method and compute auth config hash
	authMethod, authHash, err := computeAuthHash(config.VaultProvider.Auth, config.CredentialNamespace, config.Metadata.StoreKind)
	if err != nil {
		return key, fmt.Errorf("failed to compute auth hash: %w", err)
	}
	key.AuthMethod = authMethod
	key.AuthConfigHash = authHash

	// Set credential namespace for referent specs
	// This ensures different K8s namespaces get separate cache entries when
	// using ClusterSecretStore with namespace-relative credential references
	if config.Metadata.StoreKind == esv1.ClusterSecretStoreKind &&
		config.CredentialNamespace != "" &&
		isReferentSpec(config.VaultProvider) {
		key.CredentialNamespace = config.CredentialNamespace
	}

	// Compute TLS config hash
	tlsHash, err := computeTLSHash(&config.VaultProvider.ClientTLS)
	if err != nil {
		return key, fmt.Errorf("failed to compute TLS hash: %w", err)
	}
	key.TLSConfigHash = tlsHash

	// Set secrets namespace (where secrets are read/written)
	if config.VaultProvider.Namespace != nil {
		key.VaultSecretsNamespace = *config.VaultProvider.Namespace
	}

	// Compute headers hash (excluding auth-related headers)
	headersHash, err := computeHeadersHash(config.VaultProvider.Headers)
	if err != nil {
		return key, fmt.Errorf("failed to compute headers hash: %w", err)
	}
	key.HeadersHash = headersHash

	return key, nil
}

// computeAuthHash returns the auth method name and a hash of the auth configuration.
func computeAuthHash(auth *esv1.VaultAuth, credentialNS, storeKind string) (string, string, error) {
	if auth == nil {
		return "none", hashString(""), nil
	}

	// Determine which auth method is configured and compute its hash
	// We use a normalized structure for each method to ensure deterministic hashing

	if auth.TokenSecretRef != nil {
		hash, err := hashObject(map[string]interface{}{
			"secretRef": normalizeSecretKeySelector(auth.TokenSecretRef, credentialNS, storeKind),
		})
		return "token", hash, err
	}

	if auth.AppRole != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":      auth.AppRole.Path,
			"roleId":    auth.AppRole.RoleID,
			"roleRef":   normalizeSecretKeySelector(auth.AppRole.RoleRef, credentialNS, storeKind),
			"secretRef": normalizeSecretKeySelector(&auth.AppRole.SecretRef, credentialNS, storeKind),
		})
		return "approle", hash, err
	}

	if auth.Kubernetes != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":              auth.Kubernetes.Path,
			"role":              auth.Kubernetes.Role,
			"serviceAccountRef": normalizeServiceAccountSelector(auth.Kubernetes.ServiceAccountRef, credentialNS, storeKind),
			"secretRef":         normalizeSecretKeySelector(auth.Kubernetes.SecretRef, credentialNS, storeKind),
		})
		return "kubernetes", hash, err
	}

	if auth.Ldap != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":      auth.Ldap.Path,
			"username":  auth.Ldap.Username,
			"secretRef": normalizeSecretKeySelector(&auth.Ldap.SecretRef, credentialNS, storeKind),
		})
		return "ldap", hash, err
	}

	if auth.UserPass != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":      auth.UserPass.Path,
			"username":  auth.UserPass.Username,
			"secretRef": normalizeSecretKeySelector(&auth.UserPass.SecretRef, credentialNS, storeKind),
		})
		return "userpass", hash, err
	}

	if auth.Jwt != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":                       auth.Jwt.Path,
			"role":                       auth.Jwt.Role,
			"secretRef":                  normalizeSecretKeySelector(auth.Jwt.SecretRef, credentialNS, storeKind),
			"kubernetesServiceAccountToken": normalizeKubernetesServiceAccountToken(auth.Jwt.KubernetesServiceAccountToken, credentialNS, storeKind),
		})
		return "jwt", hash, err
	}

	if auth.Cert != nil {
		hash, err := hashObject(map[string]interface{}{
			"clientCert": normalizeSecretKeySelector(&auth.Cert.ClientCert, credentialNS, storeKind),
			"secretRef":  normalizeSecretKeySelector(&auth.Cert.SecretRef, credentialNS, storeKind),
		})
		return "cert", hash, err
	}

	if auth.Iam != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":                auth.Iam.Path,
			"region":              auth.Iam.Region,
			"awsIAMRole":          auth.Iam.AWSIAMRole,
			"vaultRole":           auth.Iam.Role,
			"externalID":          auth.Iam.ExternalID,
			"vaultAwsIamServerID": auth.Iam.VaultAWSIAMServerID,
			"secretRef":           normalizeVaultAwsAuthSecretRef(auth.Iam.SecretRef, credentialNS, storeKind),
			"jwtAuth":             normalizeVaultAwsJWTAuth(auth.Iam.JWTAuth, credentialNS, storeKind),
		})
		return "iam", hash, err
	}

	return "unknown", hashString(""), nil
}

// computeTLSHash computes a hash of the TLS configuration.
func computeTLSHash(tls *esv1.VaultClientTLS) (string, error) {
	if tls == nil {
		return hashString(""), nil
	}

	// We hash the references to the cert/key, not the actual values
	// This is because the actual cert/key values might change but if the
	// reference is the same, we assume it's the same identity
	return hashObject(map[string]interface{}{
		"certSecretRef": normalizeSecretKeySelector(tls.CertSecretRef, "", ""),
		"keySecretRef":  normalizeSecretKeySelector(tls.KeySecretRef, "", ""),
	})
}

// computeHeadersHash computes a hash of custom headers, excluding auth-related headers.
// Headers are sorted for deterministic output.
func computeHeadersHash(headers map[string]string) (string, error) {
	if len(headers) == 0 {
		return hashString(""), nil
	}

	// Exclude auth-related headers that we manage ourselves
	excludedHeaders := map[string]bool{
		"authorization":      true,
		"x-vault-token":      true,
		"x-vault-namespace":  true,
	}

	// Filter and collect non-auth headers
	filtered := make(map[string]string)
	for k, v := range headers {
		if !excludedHeaders[strings.ToLower(k)] {
			filtered[k] = v
		}
	}

	// Sort keys for deterministic hashing
	keys := make([]string, 0, len(filtered))
	for k := range filtered {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build sorted map for hashing
	sortedHeaders := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		sortedHeaders = append(sortedHeaders, map[string]string{
			"key":   k,
			"value": filtered[k],
		})
	}

	return hashObject(sortedHeaders)
}

// normalizeSecretKeySelector converts a SecretKeySelector to a normalized form
// for hashing, resolving namespace based on store kind and credential namespace.
func normalizeSecretKeySelector(sel interface{}, credentialNS, storeKind string) interface{} {
	if sel == nil {
		return nil
	}

	// Type assertion to get the actual selector
	switch s := sel.(type) {
	case *esmeta.SecretKeySelector:
		if s == nil {
			return nil
		}
		ns := ""
		if s.Namespace != nil {
			ns = *s.Namespace
		} else if storeKind == esv1.ClusterSecretStoreKind {
			ns = credentialNS
		}
		return map[string]interface{}{
			"name":      s.Name,
			"namespace": ns,
			"key":       s.Key,
		}
	default:
		return sel
	}
}

// normalizeServiceAccountSelector normalizes a ServiceAccountSelector.
func normalizeServiceAccountSelector(sel interface{}, credentialNS, storeKind string) interface{} {
	if sel == nil {
		return nil
	}

	switch s := sel.(type) {
	case *esmeta.ServiceAccountSelector:
		if s == nil {
			return nil
		}
		ns := ""
		if s.Namespace != nil {
			ns = *s.Namespace
		} else if storeKind == esv1.ClusterSecretStoreKind {
			ns = credentialNS
		}
		return map[string]interface{}{
			"name":      s.Name,
			"namespace": ns,
			"audiences": s.Audiences,
		}
	default:
		return sel
	}
}

// normalizeKubernetesServiceAccountToken normalizes VaultKubernetesServiceAccountTokenAuth.
func normalizeKubernetesServiceAccountToken(token interface{}, credentialNS, storeKind string) interface{} {
	if token == nil {
		return nil
	}

	switch t := token.(type) {
	case *esv1.VaultKubernetesServiceAccountTokenAuth:
		if t == nil {
			return nil
		}
		return map[string]interface{}{
			"serviceAccountRef": normalizeServiceAccountSelector(&t.ServiceAccountRef, credentialNS, storeKind),
			"audiences":         t.Audiences,
			"expirationSeconds": t.ExpirationSeconds,
		}
	default:
		return token
	}
}

// normalizeVaultAwsAuthSecretRef normalizes VaultAwsAuthSecretRef.
func normalizeVaultAwsAuthSecretRef(ref *esv1.VaultAwsAuthSecretRef, credentialNS, storeKind string) interface{} {
	if ref == nil {
		return nil
	}
	return map[string]interface{}{
		"accessKeyID":     normalizeSecretKeySelector(&ref.AccessKeyID, credentialNS, storeKind),
		"secretAccessKey": normalizeSecretKeySelector(&ref.SecretAccessKey, credentialNS, storeKind),
		"sessionToken":    normalizeSecretKeySelector(ref.SessionToken, credentialNS, storeKind),
	}
}

// normalizeVaultAwsJWTAuth normalizes VaultAwsJWTAuth.
func normalizeVaultAwsJWTAuth(auth *esv1.VaultAwsJWTAuth, credentialNS, storeKind string) interface{} {
	if auth == nil {
		return nil
	}
	return map[string]interface{}{
		"serviceAccountRef": normalizeServiceAccountSelector(auth.ServiceAccountRef, credentialNS, storeKind),
	}
}

// hashObject creates a deterministic hash of an object by marshaling to JSON.
func hashObject(obj interface{}) (string, error) {
	// Marshal to JSON for deterministic ordering
	data, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal object: %w", err)
	}
	return hashString(string(data)), nil
}

// hashString creates a SHA256 hash of a string.
func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash)
}
