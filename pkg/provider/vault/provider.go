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
	// Build auth context
	authCtx := newAuthContext(
		vaultSpec,
		kube,
		corev1,
		namespace,
		resolvers.EmptyStoreKind,
	)

	// Build config
	cfg, err := buildVaultConfigFromContext(ctx, authCtx, retrySettings)
	if err != nil {
		return nil, err
	}

	// Acquire fully-ready client (pass nil for store in generator path)
	vaultClient, err := p.acquireVaultClient(ctx, authCtx, cfg, nil)
	if err != nil {
		return nil, err
	}

	return vaultClient, nil // Ready to use!
}

func (p *Provider) newClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, corev1 typedcorev1.CoreV1Interface, namespace string) (esv1.SecretsClient, error) {
	storeSpec := store.GetSpec()
	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.Vault == nil {
		return nil, errors.New(errVaultStore)
	}
	vaultSpec := storeSpec.Provider.Vault

	// Build auth context
	authCtx := newAuthContext(
		vaultSpec,
		kube,
		corev1,
		namespace,
		store.GetObjectKind().GroupVersionKind().Kind,
	)

	// Build Vault config
	cfg, err := buildVaultConfigFromContext(ctx, authCtx, storeSpec.RetrySettings)
	if err != nil {
		return nil, err
	}

	// Acquire fully-ready Vault client (always returns ready client!)
	vaultClient, err := p.acquireVaultClient(ctx, authCtx, cfg, store)
	if err != nil {
		return nil, fmt.Errorf(errVaultClient, err)
	}

	// Wrap in secretsClient struct (ESO business logic)
	sc := &secretsClient{
		client:    vaultClient, // Already fully initialized!
		kube:      kube,
		corev1:    corev1,
		store:     vaultSpec,
		namespace: namespace,
		storeKind: authCtx.storeKind,
		log:       logger,
	}

	// Set helper fields
	sc.auth = vaultClient.Auth()
	sc.logical = vaultClient.Logical()
	sc.token = vaultClient.AuthToken()

	return sc, nil
}

// tryPooledClient checks the pool and returns a cached client if valid.
// Returns (client, nil) on hit, (nil, nil) on miss, (nil, err) on error.
func tryPooledClient(
	ctx context.Context,
	authCtx *authContext,
	store esv1.GenericStore,
) (*pooledVaultClient, error) {
	if !enableVaultClientPooling {
		return nil, nil
	}

	// Compute cache key
	authIdentity, err := getAuthIdentity(ctx, authCtx.spec.Auth, authCtx.kube, authCtx.namespace)
	if err != nil {
		logger.V(1).Info("Failed to get auth identity for pooling", "error", err)
		return nil, nil // Not an error, just skip pooling
	}

	cacheKey := buildCacheKey(authCtx.spec, authIdentity)

	// Compute config digest for invalidation check (even with nil store)
	configDigest, err := computeVaultConfigDigest(ctx, authCtx, store)
	if err != nil {
		return nil, err
	}

	// Check pool
	if pooled, ok := vaultClientPool.Get(cacheKey); ok {
		if pooled.configDigest != configDigest {
			logger.V(1).Info("Invalidated pooled client due to config change", "cacheKey", cacheKey)
			removePooledClient(cacheKey)
			return nil, nil // Cache invalidated
		}

		poolCacheHits.Inc()
		logger.V(1).Info("Pool hit, using existing client", "cacheKey", cacheKey)
		return pooled, nil // Hit!
	}

	// Miss
	return nil, nil
}

// createPooledClient creates a NEW pooled client, authenticates it, and caches it.
// Returns a FULLY INITIALIZED client ready to use.
func createPooledClient(
	ctx context.Context,
	p *Provider,
	authCtx *authContext,
	cfg *vault.Config,
	store esv1.GenericStore,
) (*pooledVaultClient, error) {
	// Compute cache key and config digest
	authIdentity, err := getAuthIdentity(ctx, authCtx.spec.Auth, authCtx.kube, authCtx.namespace)
	if err != nil {
		return nil, err
	}
	cacheKey := buildCacheKey(authCtx.spec, authIdentity)

	configDigest, err := computeVaultConfigDigest(ctx, authCtx, store)
	if err != nil {
		return nil, err
	}

	poolCacheMisses.Inc()
	logger.V(1).Info("Pool miss, creating and caching client", "cacheKey", cacheKey)

	// 1. Create Vault SDK client
	vaultSDK, err := p.NewVaultClient(cfg)
	if err != nil {
		return nil, err
	}

	// 2. Configure (namespace, headers, read-your-writes)
	configureVaultClient(vaultSDK, authCtx.spec)

	// 3. Allow ClusterSecretStore validation with referent namespace
	if authCtx.storeKind == esv1.ClusterSecretStoreKind && authCtx.namespace == "" && isReferentSpec(authCtx.spec) {
		// For ClusterSecretStore with referent spec, don't authenticate yet
		// This allows validation to pass
		vaultClient := vaultSDK.(*util.VaultClient)
		pooled := &pooledVaultClient{
			vault:           vaultClient,
			authContext:     authCtx,
			cfg:             cfg,
			cacheKey:        cacheKey,
			lastAuth:        time.Now(),
			configDigest:    configDigest,
			skipTokenRevoke: authCtx.spec.Auth == nil || authCtx.spec.Auth.TokenSecretRef != nil,
		}
		vaultClientPool.Add(cacheKey, pooled)
		poolCacheSize.Set(float64(vaultClientPool.Len()))
		return pooled, nil
	}

	// 4. Authenticate (standalone function)
	if err := authenticateVault(ctx, vaultSDK, authCtx, cfg); err != nil {
		return nil, err
	}

	// 5. Wrap in pooled client
	vaultClient := vaultSDK.(*util.VaultClient)
	pooled := &pooledVaultClient{
		vault:           vaultClient,
		authContext:     authCtx,
		cfg:             cfg,
		cacheKey:        cacheKey,
		lastAuth:        time.Now(),
		configDigest:    configDigest,
		skipTokenRevoke: authCtx.spec.Auth == nil || authCtx.spec.Auth.TokenSecretRef != nil,
	}

	// 6. Cache
	vaultClientPool.Add(cacheKey, pooled)
	poolCacheSize.Set(float64(vaultClientPool.Len()))

	logger.V(1).Info("Stored client in pool", "cacheKey", cacheKey)
	return pooled, nil
}

// createStandaloneClient creates a non-pooled client.
// Returns a FULLY INITIALIZED client ready to use.
func createStandaloneClient(
	ctx context.Context,
	p *Provider,
	authCtx *authContext,
	cfg *vault.Config,
	store esv1.GenericStore,
) (util.Client, error) {
	// 1. Create Vault SDK client
	vaultSDK, err := p.NewVaultClient(cfg)
	if err != nil {
		return nil, err
	}

	// 2. Configure
	configureVaultClient(vaultSDK, authCtx.spec)

	// 3. Allow ClusterSecretStore validation with referent namespace
	if authCtx.storeKind == esv1.ClusterSecretStoreKind && authCtx.namespace == "" && isReferentSpec(authCtx.spec) {
		return vaultSDK, nil
	}

	// 4. Authenticate
	if err := authenticateVault(ctx, vaultSDK, authCtx, cfg); err != nil {
		return nil, err
	}

	// 5. Add to old cache if applicable
	if !enableVaultClientPooling && store != nil && enableCache {
		addToOldCache(store, authCtx, vaultSDK)
	}

	return vaultSDK, nil
}

// addToOldCache adds a client to the old cache system (when pooling disabled).
func addToOldCache(store esv1.GenericStore, authCtx *authContext, vaultClient util.Client) {
	if authCtx.spec.Auth != nil && authCtx.spec.Auth.TokenSecretRef != nil {
		// Don't cache static tokens
		return
	}

	keyNamespace := store.GetObjectMeta().Namespace
	if store.GetTypeMeta().Kind == esv1.ClusterSecretStoreKind && authCtx.namespace != "" && isReferentSpec(authCtx.spec) {
		keyNamespace = authCtx.namespace
	}

	key := cache.Key{
		Name:      store.GetObjectMeta().Name,
		Namespace: keyNamespace,
		Kind:      store.GetTypeMeta().Kind,
	}

	if !clientCache.Contains(key) {
		clientCache.Add(store.GetObjectMeta().ResourceVersion, key, vaultClient)
	}
}

// tryOldCache checks the old cache system and returns client if found.
func tryOldCache(store esv1.GenericStore, authCtx *authContext) (util.Client, bool) {
	if !enableCache {
		return nil, false
	}

	// Don't cache static tokens
	if authCtx.spec.Auth != nil && authCtx.spec.Auth.TokenSecretRef != nil {
		return nil, false
	}

	keyNamespace := store.GetObjectMeta().Namespace
	if store.GetTypeMeta().Kind == esv1.ClusterSecretStoreKind && authCtx.namespace != "" && isReferentSpec(authCtx.spec) {
		keyNamespace = authCtx.namespace
	}

	key := cache.Key{
		Name:      store.GetObjectMeta().Name,
		Namespace: keyNamespace,
		Kind:      store.GetTypeMeta().Kind,
	}

	if client, ok := clientCache.Get(store.GetObjectMeta().ResourceVersion, key); ok {
		return client, true
	}

	return nil, false
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

// buildVaultConfigFromContext builds Vault configuration from authContext.
func buildVaultConfigFromContext(
	ctx context.Context,
	authCtx *authContext,
	retrySettings *esv1.SecretStoreRetrySettings,
) (*vault.Config, error) {
	cfg, err := buildVaultConfig(ctx, authCtx)
	if err != nil {
		return nil, err
	}

	// Setup retry options
	if retrySettings != nil {
		if retrySettings.MaxRetries != nil {
			cfg.MaxRetries = int(*retrySettings.MaxRetries)
		} else {
			cfg.MaxRetries = 0
		}

		if retrySettings.RetryInterval != nil {
			retryWait, err := time.ParseDuration(*retrySettings.RetryInterval)
			if err != nil {
				return nil, err
			}
			cfg.MinRetryWait = retryWait
			cfg.MaxRetryWait = retryWait
		}
	}

	return cfg, nil
}

// acquireVaultClient returns a FULLY INITIALIZED Vault client.
// The returned client is always ready to use - no additional initialization needed.
//
// The function:
// 1. Checks the pool for an existing client (if pooling enabled)
// 2. Checks the old cache (if old cache enabled and pooling disabled)
// 3. Creates a new client (pooled or standalone)
//
// In all cases, the returned client is fully configured and authenticated.
func (p *Provider) acquireVaultClient(
	ctx context.Context,
	authCtx *authContext,
	cfg *vault.Config,
	store esv1.GenericStore,
) (util.Client, error) {

	// Try pool first (if enabled)
	pooled, err := tryPooledClient(ctx, authCtx, store)
	if err != nil {
		return nil, err
	}
	if pooled != nil {
		return pooled, nil // Pool hit - fully initialized!
	}

	// Try old cache (if pooling disabled and store provided)
	if !enableVaultClientPooling && store != nil {
		cached, hit := tryOldCache(store, authCtx)
		if hit {
			logger.V(1).Info("Old cache hit")
			return cached, nil
		}
	}

	// Create new client (pooled or standalone)
	if enableVaultClientPooling && store != nil {
		return createPooledClient(ctx, p, authCtx, cfg, store)
	}
	return createStandaloneClient(ctx, p, authCtx, cfg, store)
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
