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
	_           esv1.Provider = &Provider{}
	enableCache bool
	logger      = ctrl.Log.WithName("provider").WithName("vault")
	clientCache *cache.Cache[util.Client]
	clientPool  ClientPool // Global client pool instance
)

const (
	errVaultStore    = "received invalid Vault SecretStore resource: %w"
	errVaultClient   = "cannot setup new vault client: %w"
	errVaultCert     = "cannot set Vault CA certificate: %w"
	errClientTLSAuth = "error from Client TLS Auth: %q"
	errCANamespace   = "missing namespace on caProvider secret"
)

const (
	defaultCacheSize = 2 << 17
)

type Provider struct {
	// NewVaultClient is a function that returns a new Vault client.
	// This is used for testing to inject a fake client.
	NewVaultClient func(config *vault.Config) (util.Client, error)

	// ClientPool manages Vault client instances. If nil, a default pool will be used.
	ClientPool ClientPool
}

// NewVaultClient returns a new Vault client.
func NewVaultClient(config *vault.Config) (util.Client, error) {
	vaultClient, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	tokenAPI := vaultClient.Auth().Token()
	return &util.VaultClient{
		SetTokenFunc:     vaultClient.SetToken,
		TokenFunc:        vaultClient.Token,
		ClearTokenFunc:   vaultClient.ClearToken,
		AuthField:        vaultClient.Auth(),
		AuthTokenField: &util.VaultToken{
			RevokeSelfFunc: tokenAPI.RevokeSelfWithContext,
			LookupSelfFunc: tokenAPI.LookupSelfWithContext,
			RenewSelfFunc:  tokenAPI.RenewSelfWithContext,
		},
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
	_, cfg, err := p.prepareConfig(ctx, kube, corev1, vaultSpec, retrySettings, namespace, resolvers.EmptyStoreKind)
	if err != nil {
		return nil, err
	}

	// Get or create client pool
	pool := p.getClientPool()

	// Build acquire config
	acquireConfig := AcquireClientConfig{
		VaultConfig:   cfg,
		VaultProvider: vaultSpec,
		Kube:          kube,
		CoreV1:        corev1,
		Namespace:     namespace,
		StoreKind:     resolvers.EmptyStoreKind,
		StoreName:     "generator",
		StoreNamespace: namespace,
	}

	// Acquire client from pool
	client, err := pool.AcquireClient(ctx, acquireConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
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

	// Get or create client pool
	pool := p.getClientPool()

	// Build acquire config
	acquireConfig := AcquireClientConfig{
		VaultConfig:    cfg,
		VaultProvider:  vaultSpec,
		Kube:           kube,
		CoreV1:         corev1,
		Namespace:      namespace,
		StoreKind:      store.GetObjectKind().GroupVersionKind().Kind,
		StoreName:      store.GetObjectMeta().Name,
		StoreNamespace: store.GetObjectMeta().Namespace,
	}

	// Acquire client from pool
	vaultClient, err := pool.AcquireClient(ctx, acquireConfig)
	if err != nil {
		return nil, err
	}

	return p.initClient(ctx, vStore, vaultClient, cfg, vaultSpec)
}

func (p *Provider) initClient(ctx context.Context, c *client, client util.Client, cfg *vault.Config, vaultSpec *esv1.VaultProvider) (esv1.SecretsClient, error) {
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

// getClientPool returns the ClientPool to use for this provider.
// If the provider has a ClientPool set, it uses that. Otherwise, it uses the global clientPool.
// If neither is set, it creates a default NoOpClientPool.
func (p *Provider) getClientPool() ClientPool {
	if p.ClientPool != nil {
		return p.ClientPool
	}
	if clientPool != nil {
		return clientPool
	}
	// Fallback for tests or when feature flags haven't been initialized
	newClientFunc := p.NewVaultClient
	if newClientFunc == nil {
		newClientFunc = NewVaultClient
	}
	return NewNoOpClientPool(newClientFunc)
}

// getVaultClient is a legacy helper for tests. Use getClientPool() instead.
// DEPRECATED: This function is kept for backward compatibility with existing tests.
func getVaultClient(p *Provider, store esv1.GenericStore, cfg *vault.Config, namespace string) (util.Client, error) {
	vaultProvider := store.GetSpec().Provider.Vault
	auth := vaultProvider.Auth
	isStaticToken := auth != nil && auth.TokenSecretRef != nil
	useCache := enableCache && !isStaticToken

	keyNamespace := store.GetObjectMeta().Namespace
	// A single ClusterSecretStore may need to spawn separate vault clients for each namespace.
	if store.GetTypeMeta().Kind == esv1.ClusterSecretStoreKind && namespace != "" && isReferentSpec(vaultProvider) {
		keyNamespace = namespace
	}

	key := cache.Key{
		Name:      store.GetObjectMeta().Name,
		Namespace: keyNamespace,
		Kind:      store.GetTypeMeta().Kind,
	}
	if useCache {
		client, ok := clientCache.Get(store.GetObjectMeta().ResourceVersion, key)
		if ok {
			return client, nil
		}
	}

	client, err := p.NewVaultClient(cfg)
	if err != nil {
		return nil, fmt.Errorf(errVaultClient, err)
	}

	if useCache && !clientCache.Contains(key) {
		clientCache.Add(store.GetObjectMeta().ResourceVersion, key, client)
	}
	return client, nil
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

func initClientPool(enablePooling, enableRenewal bool, renewalThreshold int, renewalInterval time.Duration) {
	if enablePooling {
		logger.Info("initializing vault client pool with caching",
			"enableRenewal", enableRenewal,
			"renewalThreshold", renewalThreshold,
			"renewalInterval", renewalInterval)
		clientPool = NewCachingClientPool(CachingClientPoolConfig{
			NewVaultClient:          NewVaultClient,
			EnableRenewal:           enableRenewal,
			RenewalThresholdPercent: renewalThreshold,
			RenewalCheckInterval:    renewalInterval,
		})
	} else {
		logger.Info("initializing vault client pool without caching (legacy mode)")
		clientPool = NewNoOpClientPool(NewVaultClient)
	}
}

func init() {
	var (
		vaultTokenCacheSize            int
		enableClientPool               bool
		enableTokenRenewal             bool
		tokenRenewalThresholdPercent   int
		tokenRenewalCheckIntervalStr   string
	)

	fs := pflag.NewFlagSet("vault", pflag.ExitOnError)

	// Legacy cache flags (deprecated, kept for backward compatibility)
	fs.BoolVar(&enableCache, "experimental-enable-vault-token-cache", false,
		"DEPRECATED: Use --vault-client-pool instead. Enable experimental Vault token cache.")
	fs.IntVar(&vaultTokenCacheSize, "experimental-vault-token-cache-size", defaultCacheSize,
		"DEPRECATED: Maximum size of Vault token cache. Only used if --experimental-enable-vault-token-cache is set.")

	// New client pool flags
	fs.BoolVar(&enableClientPool, "vault-client-pool", false,
		"Enable Vault client pooling with identity-based caching and optional token renewal.")
	fs.BoolVar(&enableTokenRenewal, "vault-token-renewal", false,
		"Enable automatic Vault token renewal for pooled clients. Only used if --vault-client-pool is set.")
	fs.IntVar(&tokenRenewalThresholdPercent, "vault-token-renewal-threshold-percent", 50,
		"Percentage of token TTL remaining before renewal (1-100). Only used if --vault-token-renewal is set.")
	fs.StringVar(&tokenRenewalCheckIntervalStr, "vault-token-renewal-check-interval", "1m",
		"How often to check if tokens need renewal (e.g., '1m', '30s'). Only used if --vault-token-renewal is set.")

	feature.Register(feature.Feature{
		Flags: fs,
		Initialize: func() {
			// Parse renewal check interval
			renewalInterval, err := time.ParseDuration(tokenRenewalCheckIntervalStr)
			if err != nil {
				logger.Error(err, "invalid vault-token-renewal-check-interval, using default 1m")
				renewalInterval = 1 * time.Minute
			}

			// Initialize the appropriate client pool
			usePooling := enableClientPool || enableCache
			initClientPool(usePooling, enableTokenRenewal, tokenRenewalThresholdPercent, renewalInterval)

			// Initialize legacy cache if old flag is used (for backward compatibility)
			if enableCache && !enableClientPool {
				initCache(vaultTokenCacheSize)
			}
		},
	})

	esv1.Register(&Provider{
		NewVaultClient: NewVaultClient,
	}, &esv1.SecretStoreProvider{
		Vault: &esv1.VaultProvider{},
	}, esv1.MaintenanceStatusMaintained)
}
