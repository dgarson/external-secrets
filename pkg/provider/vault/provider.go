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
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcfg "sigs.k8s.io/controller-runtime/pkg/client/config"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/cache"
	"github.com/external-secrets/external-secrets/pkg/feature"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

var (
	_                        esv1.Provider = &Provider{}
	enableCache              bool
	logger                   = ctrl.Log.WithName("provider").WithName("vault")
	clientCache              *cache.Cache[util.Client]
	enableVaultClientPooling bool
)

const (
	errVaultStore    = "received invalid Vault SecretStore resource: %w"
	errVaultClient   = "cannot setup new vault client: %w"
	errVaultCert     = "cannot set Vault CA certificate: %w"
	errClientTLSAuth = "error from Client TLS Auth: %q"
	errCANamespace   = "missing namespace on caProvider secret"
)

const (
	defaultCacheSize   = 2 << 17
	defaultPoolMaxSize = 1000
	defaultPoolTTL     = 15 * time.Minute
)

type Provider struct {
	// NewVaultClient is a function that returns a new Vault client.
	// This is used for testing to inject a fake client.
	NewVaultClient func(config *vault.Config) (util.Client, error)
}

// NewVaultClient returns a new Vault client.
func NewVaultClient(config *vault.Config) (util.Client, error) {
	vaultClient, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &util.VaultClient{
		SetTokenFunc:     vaultClient.SetToken,
		TokenFunc:        vaultClient.Token,
		ClearTokenFunc:   vaultClient.ClearToken,
		AuthField:        vaultClient.Auth(),
		AuthTokenField:   vaultClient.Auth().Token(),
		LogicalField:     vaultClient.Logical(),
		NamespaceFunc:    vaultClient.Namespace,
		SetNamespaceFunc: vaultClient.SetNamespace,
		AddHeaderFunc:    vaultClient.AddHeader,
	}, nil
}

// Capabilities return the provider supported capabilities (ReadOnly, WriteOnly, ReadWrite).
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

// NewClient implements the Client interface.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {
	// controller-runtime/client does not support TokenRequest or other subresource APIs
	// so we need to construct our own client and use it to fetch tokens
	// (for Kubernetes service account token auth)
	restCfg, err := ctrlcfg.GetConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	return p.newClient(ctx, store, kube, clientset.CoreV1(), namespace)
}

func (p *Provider) NewGeneratorClient(ctx context.Context, kube kclient.Client, corev1 typedcorev1.CoreV1Interface, vaultSpec *esv1.VaultProvider, namespace string, retrySettings *esv1.SecretStoreRetrySettings) (util.Client, error) {
	vStore, cfg, err := p.prepareConfig(ctx, kube, corev1, vaultSpec, retrySettings, namespace, resolvers.EmptyStoreKind)
	if err != nil {
		return nil, err
	}

	// Use unified kernel method to acquire client (pass nil for store in generator path)
	initialized, err := acquireVaultClient(ctx, p, vStore, cfg, nil)
	if err != nil {
		return nil, err
	}

	// If pool hit, client is fully initialized - return immediately
	if initialized {
		return vStore.client, nil
	}

	// Pool miss or non-pooled - needs initialization
	_, err = p.initClient(ctx, vStore, vStore.client, cfg, vaultSpec)
	if err != nil {
		return nil, err
	}

	// Return the potentially pooled client from vStore
	return vStore.client, nil
}

func (p *Provider) newClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, corev1 typedcorev1.CoreV1Interface, namespace string) (esv1.SecretsClient, error) {
	storeSpec := store.GetSpec()
	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.Vault == nil {
		return nil, errors.New(errVaultStore)
	}
	vaultSpec := storeSpec.Provider.Vault

	vStore, cfg, err := p.prepareConfig(
		ctx,
		kube,
		corev1,
		vaultSpec,
		storeSpec.RetrySettings,
		namespace,
		store.GetObjectKind().GroupVersionKind().Kind)
	if err != nil {
		return nil, err
	}

	// Use unified kernel method to acquire client
	initialized, err := acquireVaultClient(ctx, p, vStore, cfg, store)
	if err != nil {
		return nil, fmt.Errorf(errVaultClient, err)
	}

	// If pool hit, client is fully initialized - return immediately
	if initialized {
		return vStore, nil
	}

	// Pool miss or non-pooled - needs initialization
	return p.initClient(ctx, vStore, vStore.client, cfg, vaultSpec)
}

func (p *Provider) initClient(ctx context.Context, c *client, client util.Client, cfg *vault.Config, vaultSpec *esv1.VaultProvider) (esv1.SecretsClient, error) {
	// Check if pooling is enabled
	if enableVaultClientPooling {
		return p.authenticateAndPoolClient(ctx, c, client, cfg, vaultSpec)
	}

	// Existing non-pooled behavior
	return p.initClientNonPooled(ctx, c, client, cfg, vaultSpec)
}

// initClientNonPooled handles non-pooled client initialization (existing logic)
func (p *Provider) initClientNonPooled(ctx context.Context, c *client, client util.Client, cfg *vault.Config, vaultSpec *esv1.VaultProvider) (esv1.SecretsClient, error) {
	// Configure client with common settings
	configureVaultClient(client, vaultSpec)

	c.client = client
	c.auth = client.Auth()
	c.logical = client.Logical()
	c.token = client.AuthToken()

	// allow SecretStore controller validation to pass
	// when using referent namespace.
	if c.storeKind == esv1.ClusterSecretStoreKind && c.namespace == "" && isReferentSpec(vaultSpec) {
		return c, nil
	}
	if err := c.setAuth(ctx, cfg); err != nil {
		return nil, err
	}

	return c, nil
}

// authenticateAndPoolClient handles pooled client initialization.
//
// This function implements a double-checked locking optimization for concurrent requests:
//
//  1. First check in acquireVaultClient() (fast path for existing pooled clients)
//  2. Second check here (catches clients added by concurrent requests)
//
// The second check is intentional and beneficial for concurrency:
//   - Between first check (miss) and second check, another goroutine may authenticate
//   - Second check allows us to use that authentication instead of duplicating work
//   - Race window is narrow (only during client creation and config)
//   - Duplicate authentication is wasteful but not incorrect (last-write-wins)
func (p *Provider) authenticateAndPoolClient(ctx context.Context, c *client, client util.Client, cfg *vault.Config, vaultSpec *esv1.VaultProvider) (esv1.SecretsClient, error) {
	// Generate identity-based cache key
	authIdentity, err := getAuthIdentity(ctx, vaultSpec.Auth, c.kube, c.namespace)
	if err != nil {
		c.log.Error(err, "Failed to get auth identity, falling back to non-pooled")
		return p.initClientNonPooled(ctx, c, client, cfg, vaultSpec)
	}

	cacheKey := buildCacheKey(vaultSpec, authIdentity)

	// SECOND POOL CHECK (concurrent request optimization)
	// If another goroutine authenticated while we were creating the client, use theirs
	if pooledClient, ok := vaultClientPool.Get(cacheKey); ok {
		if pooledClient.configDigest != c.configDigest {
			c.log.V(1).Info("Invalidated pooled client due to configuration change on second check", "cacheKey", cacheKey)
			removePooledClient(cacheKey)
		} else {
			poolCacheHits.Inc()
			c.log.V(1).Info("Pool hit on second check, using existing authenticated client", "cacheKey", cacheKey)

			c.client = pooledClient
			c.auth = pooledClient.Auth()
			c.logical = pooledClient.Logical() // Returns logicalWithRetry wrapper
			c.token = pooledClient.AuthToken()

			return c, nil
		}
	}

	// Pool miss - authenticate and store
	poolCacheMisses.Inc()
	c.log.V(1).Info("Pool miss, authenticating and caching client", "cacheKey", cacheKey)

	// Configure client with common settings
	configureVaultClient(client, vaultSpec)

	c.client = client
	c.auth = client.Auth()
	c.logical = client.Logical()
	c.token = client.AuthToken()

	// allow SecretStore controller validation to pass
	// when using referent namespace.
	if c.storeKind == esv1.ClusterSecretStoreKind && c.namespace == "" && isReferentSpec(vaultSpec) {
		return c, nil
	}

	// Authenticate
	if err := c.setAuth(ctx, cfg); err != nil {
		return nil, err
	}

	// Wrap and store in pool
	vaultClient, ok := client.(*util.VaultClient)
	if !ok {
		c.log.Error(fmt.Errorf("unexpected client type"), "Cannot pool client")
		return c, nil
	}

	pooledClient := &pooledVaultClient{
		client:          vaultClient,
		cacheKey:        cacheKey,
		cfg:             cfg,
		setAuth:         c.setAuth,
		lastAuth:        time.Now(),
		configDigest:    c.configDigest,
		skipTokenRevoke: vaultSpec.Auth == nil || vaultSpec.Auth.TokenSecretRef != nil,
	}

	vaultClientPool.Add(cacheKey, pooledClient)
	poolCacheSize.Set(float64(vaultClientPool.Len()))

	// Update client references to use pooled version
	c.client = pooledClient
	c.logical = pooledClient.Logical() // Returns logicalWithRetry wrapper

	c.log.V(1).Info("Stored client in pool", "cacheKey", cacheKey)

	return c, nil
}

func (p *Provider) prepareConfig(ctx context.Context, kube kclient.Client, corev1 typedcorev1.CoreV1Interface, vaultSpec *esv1.VaultProvider, retrySettings *esv1.SecretStoreRetrySettings, namespace, storeKind string) (*client, *vault.Config, error) {
	c := &client{
		kube:      kube,
		corev1:    corev1,
		store:     vaultSpec,
		log:       logger,
		namespace: namespace,
		storeKind: storeKind,
	}

	cfg, err := c.newConfig(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Setup retry options if present
	if retrySettings != nil {
		if retrySettings.MaxRetries != nil {
			cfg.MaxRetries = int(*retrySettings.MaxRetries)
		} else {
			// By default we rely only on the reconciliation process for retrying
			cfg.MaxRetries = 0
		}

		if retrySettings.RetryInterval != nil {
			retryWait, err := time.ParseDuration(*retrySettings.RetryInterval)
			if err != nil {
				return nil, nil, err
			}
			cfg.MinRetryWait = retryWait
			cfg.MaxRetryWait = retryWait
		}
	}

	return c, cfg, nil
}

// configureVaultClient applies common configuration to a Vault client.
// This includes namespace, headers, and read-your-writes settings.
func configureVaultClient(client util.Client, vaultSpec *esv1.VaultProvider) {
	if vaultSpec.Namespace != nil {
		client.SetNamespace(*vaultSpec.Namespace)
	}

	if vaultSpec.Headers != nil {
		for hKey, hValue := range vaultSpec.Headers {
			client.AddHeader(hKey, hValue)
		}
	}

	if vaultSpec.ReadYourWrites && vaultSpec.ForwardInconsistent {
		client.AddHeader("X-Vault-Inconsistent", "forward-active-node")
	}
}

// acquireVaultClient is the unified kernel method for obtaining Vault clients.
// It handles pool lookups (when pooling enabled), old cache lookups (when pooling disabled),
// and fresh client creation. Returns (fullyInitialized bool, error).
//
// When fullyInitialized=true, the client in c.client is ready to use (skip initClient).
// When fullyInitialized=false, the client needs initialization via initClient.
//
// Parameters:
//   - ctx: Context for Kubernetes API calls
//   - p: Provider instance
//   - c: Client wrapper struct (from prepareConfig) containing kube, namespace, etc.
//   - cfg: Vault configuration
//   - store: GenericStore (nil for generator path)
func acquireVaultClient(ctx context.Context, p *Provider, c *client, cfg *vault.Config, store esv1.GenericStore) (bool, error) {
	vaultSpec := c.store

	// POOLING PATH: Check pool first when pooling is enabled
	if enableVaultClientPooling {
		configDigest, err := c.computeConfigDigest(ctx, store)
		if err != nil {
			return false, err
		}
		c.configDigest = configDigest

		authIdentity, err := getAuthIdentity(ctx, vaultSpec.Auth, c.kube, c.namespace)
		if err != nil {
			c.log.V(1).Info("Failed to get auth identity for pooling, falling back to non-pooled path")
			// Fall through to non-pooled logic
		} else {
			cacheKey := buildCacheKey(vaultSpec, authIdentity)

			// FIRST POOL CHECK (fast path for existing pooled clients)
			if pooledClient, ok := vaultClientPool.Get(cacheKey); ok {
				if pooledClient.configDigest != c.configDigest {
					c.log.V(1).Info("Invalidated pooled client due to configuration change", "cacheKey", cacheKey)
					removePooledClient(cacheKey)
				} else {
					poolCacheHits.Inc()
					c.log.V(1).Info("Pool hit in acquireVaultClient, using existing authenticated client", "cacheKey", cacheKey)

					// Configure wrapper struct with pooled client
					c.client = pooledClient
					c.auth = pooledClient.Auth()
					c.logical = pooledClient.Logical() // Returns logicalWithRetry wrapper
					c.token = pooledClient.AuthToken()

					return true, nil // Skip initClient - already fully initialized
				}
			}

			c.log.V(1).Info("Pool miss in acquireVaultClient, will create and authenticate new client", "cacheKey", cacheKey)
			// Fall through to create new client (will be pooled in authenticateAndPoolClient)
		}
	}

	// NON-POOLED PATH / POOL MISS: Use old cache or create fresh client
	// Old cache is only used when pooling is disabled AND store is provided
	if !enableVaultClientPooling && store != nil {
		vaultProvider := store.GetSpec().Provider.Vault
		auth := vaultProvider.Auth
		isStaticToken := auth != nil && auth.TokenSecretRef != nil
		useCache := enableCache && !isStaticToken

		if useCache {
			keyNamespace := store.GetObjectMeta().Namespace
			// A single ClusterSecretStore may need to spawn separate vault clients for each namespace
			if store.GetTypeMeta().Kind == esv1.ClusterSecretStoreKind && c.namespace != "" && isReferentSpec(vaultProvider) {
				keyNamespace = c.namespace
			}

			key := cache.Key{
				Name:      store.GetObjectMeta().Name,
				Namespace: keyNamespace,
				Kind:      store.GetTypeMeta().Kind,
			}

			if client, ok := clientCache.Get(store.GetObjectMeta().ResourceVersion, key); ok {
				c.log.V(1).Info("Old cache hit")
				c.client = client
				c.auth = client.Auth()
				c.logical = client.Logical()
				c.token = client.AuthToken()
				return false, nil // Needs initClient for authentication
			}
		}
	}

	// Create fresh client (for pool miss, non-pooled, or generator path)
	client, err := p.NewVaultClient(cfg)
	if err != nil {
		return false, fmt.Errorf(errVaultClient, err)
	}

	// Set wrapper fields
	c.client = client
	c.auth = client.Auth()
	c.logical = client.Logical()
	c.token = client.AuthToken()

	// Add to old cache if applicable (non-pooled path with store)
	if !enableVaultClientPooling && store != nil && enableCache {
		vaultProvider := store.GetSpec().Provider.Vault
		auth := vaultProvider.Auth
		isStaticToken := auth != nil && auth.TokenSecretRef != nil

		if !isStaticToken {
			keyNamespace := store.GetObjectMeta().Namespace
			if store.GetTypeMeta().Kind == esv1.ClusterSecretStoreKind && c.namespace != "" && isReferentSpec(vaultProvider) {
				keyNamespace = c.namespace
			}

			key := cache.Key{
				Name:      store.GetObjectMeta().Name,
				Namespace: keyNamespace,
				Kind:      store.GetTypeMeta().Kind,
			}

			if !clientCache.Contains(key) {
				clientCache.Add(store.GetObjectMeta().ResourceVersion, key, client)
			}
		}
	}

	return false, nil // Needs initClient for configuration and authentication
}

func isReferentSpec(prov *esv1.VaultProvider) bool {
	if prov.Auth == nil {
		return false
	}

	if prov.Auth.TokenSecretRef != nil && prov.Auth.TokenSecretRef.Namespace == nil {
		return true
	}
	if prov.Auth.AppRole != nil && prov.Auth.AppRole.SecretRef.Namespace == nil {
		return true
	}
	if prov.Auth.Kubernetes != nil && prov.Auth.Kubernetes.SecretRef != nil && prov.Auth.Kubernetes.SecretRef.Namespace == nil {
		return true
	}
	if prov.Auth.Kubernetes != nil && prov.Auth.Kubernetes.ServiceAccountRef != nil && prov.Auth.Kubernetes.ServiceAccountRef.Namespace == nil {
		return true
	}
	if prov.Auth.Ldap != nil && prov.Auth.Ldap.SecretRef.Namespace == nil {
		return true
	}
	if prov.Auth.UserPass != nil && prov.Auth.UserPass.SecretRef.Namespace == nil {
		return true
	}
	if prov.Auth.Jwt != nil && prov.Auth.Jwt.SecretRef != nil && prov.Auth.Jwt.SecretRef.Namespace == nil {
		return true
	}
	if prov.Auth.Jwt != nil && prov.Auth.Jwt.KubernetesServiceAccountToken != nil && prov.Auth.Jwt.KubernetesServiceAccountToken.ServiceAccountRef.Namespace == nil {
		return true
	}
	if prov.Auth.Cert != nil && prov.Auth.Cert.SecretRef.Namespace == nil {
		return true
	}
	if prov.Auth.Iam != nil && prov.Auth.Iam.JWTAuth != nil && prov.Auth.Iam.JWTAuth.ServiceAccountRef != nil && prov.Auth.Iam.JWTAuth.ServiceAccountRef.Namespace == nil {
		return true
	}
	if prov.Auth.Iam != nil && prov.Auth.Iam.SecretRef != nil &&
		(prov.Auth.Iam.SecretRef.AccessKeyID.Namespace == nil ||
			prov.Auth.Iam.SecretRef.SecretAccessKey.Namespace == nil ||
			(prov.Auth.Iam.SecretRef.SessionToken != nil && prov.Auth.Iam.SecretRef.SessionToken.Namespace == nil)) {
		return true
	}
	return false
}

func initCache(size int) {
	logger.Info("initializing vault cache", "size", size)
	clientCache = cache.Must(size, func(client util.Client) {
		err := revokeTokenIfValid(context.Background(), client)
		if err != nil {
			logger.Error(err, "unable to revoke cached token on eviction")
		}
	})
}

func init() {
	var vaultTokenCacheSize int
	fs := pflag.NewFlagSet("vault", pflag.ExitOnError)
	fs.BoolVar(&enableCache, "experimental-enable-vault-token-cache", false, "Enable experimental Vault token cache. External secrets will reuse the Vault token without creating a new one on each request. Mutually exclusive with --enable-vault-client-pooling.")
	// max. 265k vault leases with 30bytes each ~= 7MB
	fs.IntVar(&vaultTokenCacheSize, "experimental-vault-token-cache-size", defaultCacheSize, "Maximum size of Vault token cache. When more tokens than Only used if --experimental-enable-vault-token-cache is set.")
	fs.BoolVar(&enableVaultClientPooling, "enable-vault-client-pooling", false, "Enable Vault client pooling to reduce authentication API calls. Mutually exclusive with --experimental-enable-vault-token-cache.")
	feature.Register(feature.Feature{
		Flags: fs,
		Initialize: func() {
			// Enforce mutual exclusivity between token caching and client pooling
			if enableCache && enableVaultClientPooling {
				logger.Error(
					fmt.Errorf("invalid configuration"),
					"Vault token caching and client pooling are mutually exclusive. Disabling token cache in favor of client pooling.",
				)
				enableCache = false
			}

			if enableCache {
				initCache(vaultTokenCacheSize)
			}
			if enableVaultClientPooling {
				initPooling()
			}
		},
	})

	esv1.Register(&Provider{
		NewVaultClient: NewVaultClient,
	}, &esv1.SecretStoreProvider{
		Vault: &esv1.VaultProvider{},
	}, esv1.MaintenanceStatusMaintained)
}
