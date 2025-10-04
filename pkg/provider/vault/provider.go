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
	"github.com/external-secrets/external-secrets/pkg/feature"
	vaultcache "github.com/external-secrets/external-secrets/pkg/provider/vault/cache"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

var (
	_             esv1.Provider = &Provider{}
	enableCache   bool
	logger        = ctrl.Log.WithName("provider").WithName("vault")
	clientManager *vaultcache.ClientManager
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

	// Check if we should use cache
	auth := vaultSpec.Auth
	isStaticToken := auth != nil && auth.TokenSecretRef != nil

	// Static tokens or cache disabled - create client directly
	if isStaticToken || clientManager == nil {
		client, err := p.NewVaultClient(cfg)
		if err != nil {
			return nil, err
		}

		_, err = p.initClient(ctx, vStore, client, cfg, vaultSpec)
		if err != nil {
			return nil, err
		}

		return client, nil
	}

	// Build cache configuration for generators
	clientConfig := &vaultcache.ClientConfig{
		VaultAddr:  vaultSpec.Server,
		AuthMethod: determineAuthMethod(vaultSpec.Auth),
		AuthParams: extractAuthParams(vaultSpec.Auth),
		Headers:    make(map[string]string),
	}

	// Namespace
	if vaultSpec.Namespace != nil {
		clientConfig.Namespace = *vaultSpec.Namespace
	}

	// Headers
	if vaultSpec.Headers != nil {
		for k, v := range vaultSpec.Headers {
			clientConfig.Headers[k] = v
		}
	}

	// Read-your-writes headers
	clientConfig.ReadYourWrites = vaultSpec.ReadYourWrites
	clientConfig.ForwardInconsistent = vaultSpec.ForwardInconsistent

	// Auth context for invalidation
	clientConfig.AuthContext = buildAuthContext(vaultSpec, namespace, resolvers.EmptyStoreKind)

	// TLS config hashes
	if len(vaultSpec.CABundle) > 0 {
		clientConfig.TLSConfig = &vaultcache.TLSConfig{
			CABundle:   vaultSpec.CABundle,
			CACertHash: computeHash(vaultSpec.CABundle),
		}
	}

	// Create client via cache
	return clientManager.GetClient(ctx, *clientConfig, func() (util.Client, time.Time, bool, error) {
		// This function is only called on cache miss
		vaultClient, err := p.NewVaultClient(cfg)
		if err != nil {
			return nil, time.Time{}, false, fmt.Errorf("failed to create vault client: %w", err)
		}

		// Set up the client struct for auth
		vStore.client = vaultClient
		vStore.auth = vaultClient.Auth()
		vStore.logical = vaultClient.Logical()
		vStore.token = vaultClient.AuthToken()

		// Apply namespace if specified
		if vaultSpec.Namespace != nil {
			vaultClient.SetNamespace(*vaultSpec.Namespace)
		}

		// Apply headers if specified
		if vaultSpec.Headers != nil {
			for hKey, hValue := range vaultSpec.Headers {
				vaultClient.AddHeader(hKey, hValue)
			}
		}

		// Apply read-your-writes header if needed
		if vaultSpec.ReadYourWrites && vaultSpec.ForwardInconsistent {
			vaultClient.AddHeader("X-Vault-Inconsistent", "forward-active-node")
		}

		// Perform authentication
		metadata, err := vStore.setAuth(ctx, cfg)
		if err != nil {
			return nil, time.Time{}, false, fmt.Errorf("authentication failed: %w", err)
		}

		// Return client with metadata
		if metadata != nil {
			return vaultClient, metadata.Expiry, metadata.Renewable, nil
		}

		// Default metadata if not available (e.g., for token reuse)
		return vaultClient, time.Now().Add(1 * time.Hour), false, nil
	})
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

	client, err := getVaultClient(ctx, p, vStore, store, cfg, namespace)
	if err != nil {
		return nil, fmt.Errorf(errVaultClient, err)
	}

	return p.initClient(ctx, vStore, client, cfg, vaultSpec)
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
	metadata, err := c.setAuth(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// metadata will be used in Phase 3 for cache integration
	_ = metadata

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

// buildClientConfig constructs a ClientConfig from store specifications for caching.
func buildClientConfig(
	ctx context.Context,
	store esv1.GenericStore,
	vaultSpec *esv1.VaultProvider,
	namespace string,
) (*vaultcache.ClientConfig, error) {
	config := &vaultcache.ClientConfig{
		VaultAddr:  vaultSpec.Server,
		AuthMethod: determineAuthMethod(vaultSpec.Auth),
		AuthParams: make(map[string]interface{}),
		Headers:    make(map[string]string),
	}

	// Namespace
	if vaultSpec.Namespace != nil {
		config.Namespace = *vaultSpec.Namespace
	}

	// Headers
	if vaultSpec.Headers != nil {
		for k, v := range vaultSpec.Headers {
			config.Headers[k] = v
		}
	}

	// Read-your-writes headers
	config.ReadYourWrites = vaultSpec.ReadYourWrites
	config.ForwardInconsistent = vaultSpec.ForwardInconsistent

	// Auth context for invalidation
	config.AuthContext = buildAuthContext(vaultSpec, namespace, store.GetTypeMeta().Kind)

	// Auth params (method-specific, extract from vaultSpec.Auth)
	config.AuthParams = extractAuthParams(vaultSpec.Auth)

	// TLS config hashes
	if len(vaultSpec.CABundle) > 0 {
		config.TLSConfig = &vaultcache.TLSConfig{
			CABundle:   vaultSpec.CABundle,
			CACertHash: computeHash(vaultSpec.CABundle),
		}
	}

	// Note: Client TLS cert/key hashing would require fetching secrets here,
	// which is not ideal. For now, we rely on other cache key components.
	// In a future enhancement, we could add cert fingerprints to the auth context.

	return config, nil
}

// determineAuthMethod returns the auth method type from auth spec.
func determineAuthMethod(auth *esv1.VaultAuth) string {
	if auth == nil {
		return "none"
	}
	if auth.TokenSecretRef != nil {
		return "token"
	}
	if auth.AppRole != nil {
		return "approle"
	}
	if auth.Kubernetes != nil {
		return "kubernetes"
	}
	if auth.Ldap != nil {
		return "ldap"
	}
	if auth.UserPass != nil {
		return "userpass"
	}
	if auth.Jwt != nil {
		return "jwt"
	}
	if auth.Cert != nil {
		return "cert"
	}
	if auth.Iam != nil {
		return "iam"
	}
	return "unknown"
}

// buildAuthContext creates AuthContext for cache invalidation.
func buildAuthContext(vaultSpec *esv1.VaultProvider, namespace, storeKind string) *vaultcache.AuthContext {
	ctx := &vaultcache.AuthContext{
		AuthMethod: determineAuthMethod(vaultSpec.Auth),
		SecretRefs: []vaultcache.SecretReference{},
	}

	if vaultSpec.Auth == nil {
		return ctx
	}

	// Extract secret references based on auth method
	auth := vaultSpec.Auth

	if auth.TokenSecretRef != nil {
		ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
			Namespace: resolveNamespace(auth.TokenSecretRef.Namespace, namespace, storeKind),
			Name:      auth.TokenSecretRef.Name,
		})
	}

	if auth.AppRole != nil && auth.AppRole.SecretRef.Namespace != nil {
		ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
			Namespace: *auth.AppRole.SecretRef.Namespace,
			Name:      auth.AppRole.SecretRef.Name,
		})
	}

	if auth.Kubernetes != nil {
		if auth.Kubernetes.SecretRef != nil {
			ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
				Namespace: resolveNamespace(auth.Kubernetes.SecretRef.Namespace, namespace, storeKind),
				Name:      auth.Kubernetes.SecretRef.Name,
			})
		}
		if auth.Kubernetes.ServiceAccountRef != nil {
			ctx.ServiceAccountRef = &vaultcache.ServiceAccountReference{
				Namespace: resolveNamespace(auth.Kubernetes.ServiceAccountRef.Namespace, namespace, storeKind),
				Name:      auth.Kubernetes.ServiceAccountRef.Name,
			}
		}
	}

	if auth.Ldap != nil && auth.Ldap.SecretRef.Namespace != nil {
		ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
			Namespace: *auth.Ldap.SecretRef.Namespace,
			Name:      auth.Ldap.SecretRef.Name,
		})
	}

	if auth.UserPass != nil && auth.UserPass.SecretRef.Namespace != nil {
		ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
			Namespace: *auth.UserPass.SecretRef.Namespace,
			Name:      auth.UserPass.SecretRef.Name,
		})
	}

	if auth.Jwt != nil && auth.Jwt.SecretRef != nil && auth.Jwt.SecretRef.Namespace != nil {
		ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
			Namespace: *auth.Jwt.SecretRef.Namespace,
			Name:      auth.Jwt.SecretRef.Name,
		})
	}

	if auth.Jwt != nil && auth.Jwt.KubernetesServiceAccountToken != nil {
		saRef := auth.Jwt.KubernetesServiceAccountToken.ServiceAccountRef
		ctx.ServiceAccountRef = &vaultcache.ServiceAccountReference{
			Namespace: resolveNamespace(saRef.Namespace, namespace, storeKind),
			Name:      saRef.Name,
		}
	}

	if auth.Cert != nil && auth.Cert.SecretRef.Namespace != nil {
		ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
			Namespace: *auth.Cert.SecretRef.Namespace,
			Name:      auth.Cert.SecretRef.Name,
		})
	}

	if auth.Iam != nil {
		if auth.Iam.JWTAuth != nil && auth.Iam.JWTAuth.ServiceAccountRef != nil {
			ctx.ServiceAccountRef = &vaultcache.ServiceAccountReference{
				Namespace: resolveNamespace(auth.Iam.JWTAuth.ServiceAccountRef.Namespace, namespace, storeKind),
				Name:      auth.Iam.JWTAuth.ServiceAccountRef.Name,
			}
		}
		if auth.Iam.SecretRef != nil {
			if auth.Iam.SecretRef.AccessKeyID.Namespace != nil {
				ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
					Namespace: *auth.Iam.SecretRef.AccessKeyID.Namespace,
					Name:      auth.Iam.SecretRef.AccessKeyID.Name,
				})
			}
			if auth.Iam.SecretRef.SecretAccessKey.Namespace != nil {
				ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
					Namespace: *auth.Iam.SecretRef.SecretAccessKey.Namespace,
					Name:      auth.Iam.SecretRef.SecretAccessKey.Name,
				})
			}
			if auth.Iam.SecretRef.SessionToken != nil && auth.Iam.SecretRef.SessionToken.Namespace != nil {
				ctx.SecretRefs = append(ctx.SecretRefs, vaultcache.SecretReference{
					Namespace: *auth.Iam.SecretRef.SessionToken.Namespace,
					Name:      auth.Iam.SecretRef.SessionToken.Name,
				})
			}
		}
	}

	return ctx
}

// extractAuthParams extracts auth-specific parameters for cache key generation.
func extractAuthParams(auth *esv1.VaultAuth) map[string]interface{} {
	params := make(map[string]interface{})
	if auth == nil {
		return params
	}

	// Add relevant auth params that affect authentication
	if auth.Kubernetes != nil {
		params["role"] = auth.Kubernetes.Role
		params["path"] = auth.Kubernetes.Path
	}
	if auth.AppRole != nil {
		params["path"] = auth.AppRole.Path
		if auth.AppRole.RoleID != "" {
			params["roleId"] = auth.AppRole.RoleID
		}
	}
	if auth.Ldap != nil {
		params["path"] = auth.Ldap.Path
		params["username"] = auth.Ldap.Username
	}
	if auth.UserPass != nil {
		params["path"] = auth.UserPass.Path
		params["username"] = auth.UserPass.Username
	}
	if auth.Jwt != nil {
		params["path"] = auth.Jwt.Path
		params["role"] = auth.Jwt.Role
	}
	if auth.Cert != nil {
		// Cert auth doesn't have path or role fields in the API
		params["auth_method"] = "cert"
	}
	if auth.Iam != nil {
		params["path"] = auth.Iam.Path
		params["role"] = auth.Iam.Role
		if auth.Iam.Region != "" {
			params["region"] = auth.Iam.Region
		}
	}

	return params
}

// resolveNamespace resolves namespace for secret refs.
func resolveNamespace(ref *string, defaultNS, storeKind string) string {
	if ref != nil {
		return *ref
	}
	// For ClusterSecretStore, use the provided namespace
	// For SecretStore, use the store's namespace
	return defaultNS
}

// computeHash computes SHA256 hash of data.
func computeHash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// getVaultClient retrieves or creates an authenticated Vault client using the ClientManager.
func getVaultClient(
	ctx context.Context,
	p *Provider,
	vStore *client,
	store esv1.GenericStore,
	cfg *vault.Config,
	namespace string,
) (util.Client, error) {
	vaultSpec := store.GetSpec().Provider.Vault
	auth := vaultSpec.Auth
	isStaticToken := auth != nil && auth.TokenSecretRef != nil

	// Static tokens bypass cache - create client directly
	if isStaticToken || clientManager == nil {
		client, err := p.NewVaultClient(cfg)
		if err != nil {
			return nil, fmt.Errorf(errVaultClient, err)
		}
		return client, nil
	}

	// Build cache configuration
	clientConfig, err := buildClientConfig(ctx, store, vaultSpec, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to build client config: %w", err)
	}

	// Create client via cache (with singleflight + renewal)
	return clientManager.GetClient(ctx, *clientConfig, func() (util.Client, time.Time, bool, error) {
		// This function is only called on cache miss
		// Create new client
		vaultClient, err := p.NewVaultClient(cfg)
		if err != nil {
			return nil, time.Time{}, false, fmt.Errorf("failed to create vault client: %w", err)
		}

		// Set up the client struct for auth
		vStore.client = vaultClient
		vStore.auth = vaultClient.Auth()
		vStore.logical = vaultClient.Logical()
		vStore.token = vaultClient.AuthToken()

		// Apply namespace if specified
		if vaultSpec.Namespace != nil {
			vaultClient.SetNamespace(*vaultSpec.Namespace)
		}

		// Apply headers if specified
		if vaultSpec.Headers != nil {
			for hKey, hValue := range vaultSpec.Headers {
				vaultClient.AddHeader(hKey, hValue)
			}
		}

		// Apply read-your-writes header if needed
		if vaultSpec.ReadYourWrites && vaultSpec.ForwardInconsistent {
			vaultClient.AddHeader("X-Vault-Inconsistent", "forward-active-node")
		}

		// Perform authentication
		metadata, err := vStore.setAuth(ctx, cfg)
		if err != nil {
			return nil, time.Time{}, false, fmt.Errorf("authentication failed: %w", err)
		}

		// Return client with metadata
		if metadata != nil {
			return vaultClient, metadata.Expiry, metadata.Renewable, nil
		}

		// Default metadata if not available (e.g., for token reuse)
		return vaultClient, time.Now().Add(1 * time.Hour), false, nil
	})
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

func initClientManager(size int) {
	logger.Info("initializing vault client manager", "size", size, "renewal_window", "5m")
	clientManager = vaultcache.NewClientManager(vaultcache.CacheConfig{
		Size:          size,
		RenewalWindow: 5 * time.Minute,
		EnableMetrics: true,
	})
}

func init() {
	var vaultTokenCacheSize int
	fs := pflag.NewFlagSet("vault", pflag.ExitOnError)
	fs.BoolVar(&enableCache, "experimental-enable-vault-token-cache", false, "Enable experimental Vault token cache. External secrets will reuse the Vault token without creating a new one on each request.")
	// max. 265k vault leases with 30bytes each ~= 7MB
	fs.IntVar(&vaultTokenCacheSize, "experimental-vault-token-cache-size", defaultCacheSize, "Maximum size of Vault token cache. When more tokens than Only used if --experimental-enable-vault-token-cache is set.")
	feature.Register(feature.Feature{
		Flags: fs,
		Initialize: func() {
			if enableCache {
				initClientManager(vaultTokenCacheSize)
			}
		},
	})

	esv1.Register(&Provider{
		NewVaultClient: NewVaultClient,
	}, &esv1.SecretStoreProvider{
		Vault: &esv1.VaultProvider{},
	}, esv1.MaintenanceStatusMaintained)
}
