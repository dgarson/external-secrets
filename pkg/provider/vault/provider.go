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
	"strings"
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
	"github.com/external-secrets/external-secrets/pkg/provider/vault/session"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

var (
	_                              esv1.Provider = &Provider{}
	enableCache                    bool
	enableRevokeOnShutdown         bool
	vaultTokenCacheShutdownTimeout time.Duration
	logger                         = ctrl.Log.WithName("provider").WithName("vault")
	sessionMgr                     *session.Manager
	vaultTokenCacheSafetyWindow    = session.DefaultSafetyWindow
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

	client, handle, err := getGeneratorVaultClient(ctx, p, cfg, vaultSpec, namespace)
	if err != nil {
		return nil, err
	}

	vStore.sessionHandle = handle
	if handle != nil {
		vStore.sessionLease = handle.Lease()
		if vStore.sessionLease != nil {
			vStore.sessionLease.Apply(client)
		}
	}

	_, err = p.initClient(ctx, vStore, client, cfg, vaultSpec)
	if err != nil {
		if handle != nil {
			handle.Invalidate(ctx)
			handle.Release(ctx)
		}
		return nil, err
	}

	if handle != nil {
		handle.Release(ctx)
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

	client, handle, err := getVaultClient(ctx, p, store, cfg, namespace)
	if err != nil {
		return nil, fmt.Errorf(errVaultClient, err)
	}

	vStore.sessionHandle = handle
	if handle != nil {
		vStore.sessionLease = handle.Lease()
		if vStore.sessionLease != nil {
			vStore.sessionLease.Apply(client)
		}
	}

	cl, err := p.initClient(ctx, vStore, client, cfg, vaultSpec)
	if err != nil {
		if handle != nil {
			handle.Invalidate(ctx)
			handle.Release(ctx)
		}
		return nil, err
	}
	return cl, nil
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
	if c.sessionLease != nil {
		c.sessionLease.Apply(c.client)
	}

	reuse := false
	if enableCache && c.sessionLease != nil {
		window := session.DefaultSafetyWindow
		if sessionMgr != nil {
			window = sessionMgr.SafetyWindow()
		}
		reuse = c.sessionLease.IsUsable(time.Now(), window)
	}

	// allow SecretStore controller validation to pass
	// when using referent namespace.
	if c.storeKind == esv1.ClusterSecretStoreKind && c.namespace == "" && isReferentSpec(vaultSpec) {
		return c, nil
	}
	if !reuse {
		if err := c.setAuth(ctx, cfg); err != nil {
			if c.sessionHandle != nil {
				c.sessionHandle.Invalidate(ctx)
			}
			return nil, err
		}
		if c.sessionHandle != nil {
			lease, err := c.sessionHandle.RefreshLease(ctx)
			if err != nil {
				c.log.Error(err, "unable to refresh cached lease")
			} else {
				c.sessionLease = lease
			}
		}
	} else {
		c.log.V(1).Info("re-using cached vault token")
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

func getVaultClient(ctx context.Context, p *Provider, store esv1.GenericStore, cfg *vault.Config, namespace string) (util.Client, *session.Handle, error) {
	vaultProvider := store.GetSpec().Provider.Vault
	auth := vaultProvider.Auth
	isStaticToken := auth != nil && auth.TokenSecretRef != nil

	if !enableCache || isStaticToken {
		client, err := p.NewVaultClient(cfg)
		if err != nil {
			return nil, nil, fmt.Errorf(errVaultClient, err)
		}
		return client, nil, nil
	}

	if sessionMgr == nil {
		return nil, nil, fmt.Errorf("vault session cache not initialised")
	}

	keyNamespace := store.GetObjectMeta().Namespace
	if store.GetTypeMeta().Kind == esv1.ClusterSecretStoreKind && namespace != "" && isReferentSpec(vaultProvider) {
		keyNamespace = namespace
	}

	// Cache key layout:
	//   - qualifier prefix (store vs generator) to avoid collisions with other cache users.
	//   - store kind, namespace, and name to scope entries uniquely per Store/ClusterSecretStore.
	// Fingerprint inputs:
	//   - Vault provider spec (TLS/auth settings) to detect semantic changes.
	//   - Vault address to separate clusters.
	//   - Effective namespace the store resolves tokens in.
	//   - Store resource version and kind to invalidate when the CR is updated.
	//   - Referent namespace (for ClusterSecretStores) because auth material may vary per target namespace.
	key := fmt.Sprintf("store|%s|%s|%s", store.GetTypeMeta().Kind, keyNamespace, store.GetObjectMeta().Name)
	extras := []string{cfg.Address, keyNamespace, store.GetObjectMeta().ResourceVersion, store.GetTypeMeta().Kind}
	if store.GetTypeMeta().Kind == esv1.ClusterSecretStoreKind && namespace != "" && isReferentSpec(vaultProvider) {
		extras = append(extras, namespace)
	}
	fingerprint := session.Fingerprint(vaultProvider, extras...)

	scope := strings.ToLower(store.GetTypeMeta().Kind)
	if scope == "" {
		scope = "store"
	}

	handle, err := sessionMgr.Acquire(ctx, session.Request{
		Key:         key,
		Fingerprint: fingerprint,
		Scope:       scope,
		BuildClient: func() (util.Client, error) {
			return p.NewVaultClient(cfg)
		},
		Cleanup: func(cleanupCtx context.Context, client util.Client) error {
			return revokeTokenIfValid(cleanupCtx, client)
		},
	})
	if err != nil {
		return nil, nil, err
	}
	client := handle.Client()
	if client == nil {
		handle.Release(ctx)
		return nil, nil, fmt.Errorf("vault session returned nil client")
	}
	return client, handle, nil
}

func getGeneratorVaultClient(ctx context.Context, p *Provider, cfg *vault.Config, vaultSpec *esv1.VaultProvider, namespace string) (util.Client, *session.Handle, error) {
	auth := vaultSpec.Auth
	isStaticToken := auth != nil && auth.TokenSecretRef != nil

	if !enableCache || isStaticToken {
		client, err := p.NewVaultClient(cfg)
		if err != nil {
			return nil, nil, err
		}
		return client, nil, nil
	}
	if sessionMgr == nil {
		return nil, nil, fmt.Errorf("vault session cache not initialised")
	}

	// Generator cache key combines the namespace in which the generator runs with a hash of the
	// Vault specification. Fingerprint also considers the Vault address so separate Vault clusters
	// do not share sessions even if specs are identical.
	specHash := session.Fingerprint(vaultSpec)
	key := fmt.Sprintf("generator|%s|%s", namespace, specHash)
	fingerprint := session.Fingerprint(vaultSpec, namespace, cfg.Address)

	handle, err := sessionMgr.Acquire(ctx, session.Request{
		Key:         key,
		Fingerprint: fingerprint,
		Scope:       "generator",
		BuildClient: func() (util.Client, error) {
			return p.NewVaultClient(cfg)
		},
		Cleanup: func(cleanupCtx context.Context, client util.Client) error {
			return revokeTokenIfValid(cleanupCtx, client)
		},
	})
	if err != nil {
		return nil, nil, err
	}
	client := handle.Client()
	if client == nil {
		handle.Release(ctx)
		return nil, nil, fmt.Errorf("vault session returned nil client")
	}
	return client, handle, nil
}

func isReferentSpec(prov *esv1.VaultProvider) bool {
	if prov.Auth == nil {
		return false
	}

	if (prov.Auth.TokenSecretRef != nil && prov.Auth.TokenSecretRef.Namespace == nil) ||
		(prov.Auth.AppRole != nil && prov.Auth.AppRole.SecretRef.Namespace == nil) {
		return true
	}
	if prov.Auth.Kubernetes != nil &&
		((prov.Auth.Kubernetes.SecretRef != nil && prov.Auth.Kubernetes.SecretRef.Namespace == nil) ||
			(prov.Auth.Kubernetes.ServiceAccountRef != nil && prov.Auth.Kubernetes.ServiceAccountRef.Namespace == nil)) {
		return true
	}
	if (prov.Auth.Ldap != nil && prov.Auth.Ldap.SecretRef.Namespace == nil) ||
		(prov.Auth.UserPass != nil && prov.Auth.UserPass.SecretRef.Namespace == nil) {
		return true
	}
	if prov.Auth.Jwt != nil &&
		((prov.Auth.Jwt.SecretRef != nil && prov.Auth.Jwt.SecretRef.Namespace == nil) ||
			(prov.Auth.Jwt.KubernetesServiceAccountToken != nil && prov.Auth.Jwt.KubernetesServiceAccountToken.ServiceAccountRef.Namespace == nil)) {
		return true
	}
	if (prov.Auth.Cert != nil && prov.Auth.Cert.SecretRef.Namespace == nil) ||
		(prov.Auth.Iam != nil && prov.Auth.Iam.JWTAuth != nil && prov.Auth.Iam.JWTAuth.ServiceAccountRef != nil && prov.Auth.Iam.JWTAuth.ServiceAccountRef.Namespace == nil) {
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

func initCache(size int, safetyWindow time.Duration) {
	logger.V(1).Info("initializing vault cache", "size", size, "safetyWindow", safetyWindow)
	sessionMgr = session.NewManager(size, logger.WithName("session"))
	sessionMgr.SetSafetyWindow(safetyWindow)
}

// GetSessionManager returns the global Vault session manager for shutdown purposes.
// Returns nil if cache is not enabled or not initialized.
func GetSessionManager() *session.Manager {
	return sessionMgr
}

// IsRevokeOnShutdownEnabled returns whether token revocation on shutdown is enabled.
func IsRevokeOnShutdownEnabled() bool {
	return enableCache && enableRevokeOnShutdown
}

// GetShutdownTimeout returns the configured timeout for shutdown token revocation.
func GetShutdownTimeout() time.Duration {
	return vaultTokenCacheShutdownTimeout
}

func init() {
	var vaultTokenCacheSize int
	fs := pflag.NewFlagSet("vault", pflag.ExitOnError)
	fs.BoolVar(&enableCache, "experimental-enable-vault-token-cache", false, "Enable experimental Vault token cache. External secrets will reuse the Vault token without creating a new one on each request.")
	// max. 265k vault leases with 30bytes each ~= 7MB
	fs.IntVar(&vaultTokenCacheSize, "experimental-vault-token-cache-size", defaultCacheSize, "Maximum size of Vault token cache. When more tokens than Only used if --experimental-enable-vault-token-cache is set.")
	fs.DurationVar(&vaultTokenCacheSafetyWindow, "experimental-vault-token-cache-safety-window", session.DefaultSafetyWindow, "Safety window before token expiry that triggers re-authentication for cached Vault sessions.")
	fs.BoolVar(&enableRevokeOnShutdown, "experimental-vault-token-cache-revoke-on-shutdown", false, "Revoke all cached Vault tokens on controller shutdown. Only used if --experimental-enable-vault-token-cache is set.")
	fs.DurationVar(&vaultTokenCacheShutdownTimeout, "experimental-vault-token-cache-shutdown-timeout", 10*time.Second, "Maximum time to wait for token revocation during shutdown. Only used if --experimental-vault-token-cache-revoke-on-shutdown is set.")
	feature.Register(feature.Feature{
		Flags:      fs,
		Initialize: func() { initCache(vaultTokenCacheSize, vaultTokenCacheSafetyWindow) },
	})

	esv1.Register(&Provider{
		NewVaultClient: NewVaultClient,
	}, &esv1.SecretStoreProvider{
		Vault: &esv1.VaultProvider{},
	}, esv1.MaintenanceStatusMaintained)
}
