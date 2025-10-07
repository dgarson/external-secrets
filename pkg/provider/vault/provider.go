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
	"sort"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/pflag"
	"golang.org/x/sync/singleflight"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
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
	_                   esv1.Provider = &Provider{}
	enableCache         bool
	enableClientPooling bool
	logger              = ctrl.Log.WithName("provider").WithName("vault")
	clientCache         *cache.Cache[util.Client]
	pooledClientCache   *cache.Cache[util.Client]
	createGroup         singleflight.Group
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

// ClientPoolKey represents a functional cache key based on Vault configuration + credential identity.
// This key is used to deduplicate Vault clients across multiple resources that share the same
// vault configuration and credential identity.
// The CredentialIdentity is based on identifying information + ResourceVersion (not actual credential values).
type ClientPoolKey struct {
	Server              string
	Namespace           *string
	AuthMethod          string
	AuthPath            string
	CredentialIdentity  string // Credential identity + ResourceVersion (concatenated, not hashed)
	CABundle            []byte
	ClientCertHash      *[32]byte // Hash of client cert ResourceVersion if used
	ClientKeyHash       *[32]byte // Hash of client key ResourceVersion if used
	ReadYourWrites      bool
	ForwardInconsistent bool
	Headers             map[string]string
}

// String returns a deterministic string representation for singleflight and cache keys.
// Uses string concatenation for non-sensitive configuration values and hex encoding for
// already-hashed credential fields, making cache keys more readable and debuggable.
func (k ClientPoolKey) String() string {
	var parts []string

	// Non-sensitive configuration values - use plain strings
	parts = append(parts, k.Server)

	if k.Namespace != nil {
		parts = append(parts, *k.Namespace)
	} else {
		parts = append(parts, "")
	}

	parts = append(parts, k.AuthMethod)
	parts = append(parts, k.AuthPath)
	parts = append(parts, fmt.Sprintf("%t", k.ReadYourWrites))
	parts = append(parts, fmt.Sprintf("%t", k.ForwardInconsistent))

	// Headers - serialize deterministically
	if len(k.Headers) > 0 {
		keys := make([]string, 0, len(k.Headers))
		for key := range k.Headers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		headerPairs := make([]string, 0, len(keys))
		for _, key := range keys {
			headerPairs = append(headerPairs, fmt.Sprintf("%s=%s", key, k.Headers[key]))
		}
		parts = append(parts, strings.Join(headerPairs, ","))
	} else {
		parts = append(parts, "")
	}

	// CABundle - hex encode if present (not secret but could be large)
	if len(k.CABundle) > 0 {
		parts = append(parts, fmt.Sprintf("%x", sha256.Sum256(k.CABundle)))
	} else {
		parts = append(parts, "")
	}

	// Credential identity (ResourceVersions + identifiers - not sensitive)
	parts = append(parts, k.CredentialIdentity)

	if k.ClientCertHash != nil {
		parts = append(parts, fmt.Sprintf("%x", *k.ClientCertHash))
	} else {
		parts = append(parts, "")
	}

	if k.ClientKeyHash != nil {
		parts = append(parts, fmt.Sprintf("%x", *k.ClientKeyHash))
	} else {
		parts = append(parts, "")
	}

	return strings.Join(parts, "|")
}

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
	return wrapVaultClient(vaultClient), nil
}

// wrapVaultClient wraps a Vault SDK client in our util.Client interface.
func wrapVaultClient(vaultClient *vault.Client) util.Client {
	wrapper := &util.VaultClient{
		SetTokenFunc:     vaultClient.SetToken,
		TokenFunc:        vaultClient.Token,
		ClearTokenFunc:   vaultClient.ClearToken,
		AuthField:        vaultClient.Auth(),
		AuthTokenField:   vaultClient.Auth().Token(),
		LogicalField:     vaultClient.Logical(),
		NamespaceFunc:    vaultClient.Namespace,
		SetNamespaceFunc: vaultClient.SetNamespace,
		AddHeaderFunc:    vaultClient.AddHeader,
	}

	// Set CloneFunc to call the Vault SDK's Clone() method and wrap the result
	wrapper.CloneFunc = func() (util.Client, error) {
		cloned, err := vaultClient.Clone()
		if err != nil {
			return nil, err
		}
		return wrapVaultClient(cloned), nil
	}

	return wrapper
}

// cloneClientForMutation clones a Vault client to prevent shared state mutations.
// This is critical when using pooled clients - we need to clone before calling
// AddHeader or SetNamespace to avoid affecting other resources sharing the client.
// The cloned client will have a copy of the token but fresh (empty) headers and namespace.
func cloneClientForMutation(client util.Client) (util.Client, error) {
	return client.Clone()
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

	// Use pooling if enabled, otherwise create client directly
	var client util.Client
	if enableClientPooling {
		client, err = getOrCreatePooledClient(
			p,
			ctx,
			vaultSpec,
			cfg,
			kube,
			corev1,
			resolvers.EmptyStoreKind,
			namespace,
		)

	} else {
		client, err = p.NewVaultClient(cfg)
	}
	if err != nil {
		return nil, err
	}

	_, err = p.initClient(ctx, vStore, client, cfg, vaultSpec)
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

	client, err := getVaultClient(p, store, cfg, namespace)
	if err != nil {
		return nil, fmt.Errorf(errVaultClient, err)
	}

	return p.initClient(ctx, vStore, client, cfg, vaultSpec)
}

func (p *Provider) initClient(ctx context.Context, c *client, client util.Client, cfg *vault.Config, vaultSpec *esv1.VaultProvider) (esv1.SecretsClient, error) {
	// If using pooled clients, clone before mutation to prevent shared state contamination
	if enableClientPooling {
		auth := vaultSpec.Auth
		isStaticToken := auth != nil && auth.TokenSecretRef != nil
		if !isStaticToken {
			// Clone the client to avoid mutating the shared cached client
			cloned, err := cloneClientForMutation(client)
			if err != nil {
				return nil, fmt.Errorf("failed to clone client: %w", err)
			}
			client = cloned
		}
	}

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

	// Wrap client with PooledClient for automatic retry on token expiration
	if enableClientPooling {
		auth := vaultSpec.Auth
		isStaticToken := auth != nil && auth.TokenSecretRef != nil
		if !isStaticToken {
			// Create re-auth function that calls setAuth
			reAuthFunc := func(ctx context.Context) error {
				return c.setAuth(ctx, cfg)
			}
			client = NewPooledClient(client, reAuthFunc)
		}
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

// buildClientPoolKey builds a cache key by reading credential metadata (ResourceVersion) from Kubernetes.
// This function enables immediate detection of credential rotation by hashing identifying info + ResourceVersion
// (not actual credential VALUES). It does NOT read credential data. On cache miss, credentials are read via setAuth().
func buildClientPoolKey(
	ctx context.Context,
	corev1 typedcorev1.CoreV1Interface,
	vaultSpec *esv1.VaultProvider,
	kube kclient.Client,
	storeKind string,
	namespace string,
) (ClientPoolKey, error) {
	// Build base cache key from VaultProvider spec
	key := ClientPoolKey{
		Server:              vaultSpec.Server,
		Namespace:           vaultSpec.Namespace,
		ReadYourWrites:      vaultSpec.ReadYourWrites,
		ForwardInconsistent: vaultSpec.ForwardInconsistent,
		Headers:             vaultSpec.Headers,
		CABundle:            vaultSpec.CABundle,
	}

	// Extract credential identity + ResourceVersion based on auth method
	if vaultSpec.Auth != nil {
		auth := vaultSpec.Auth
		var credParts []string

		// AppRole Auth - Concatenate roleID (or roleRef identity) + Secret ResourceVersion
		if auth.AppRole != nil {
			key.AuthMethod = "approle"
			key.AuthPath = auth.AppRole.Path

			// Add roleID or roleRef identity
			if auth.AppRole.RoleID != "" {
				credParts = append(credParts, "roleID:"+strings.TrimSpace(auth.AppRole.RoleID))
			} else if auth.AppRole.RoleRef != nil {
				roleRefID := fmt.Sprintf("roleRef:%s|%s", auth.AppRole.RoleRef.Name, auth.AppRole.RoleRef.Key)
				if auth.AppRole.RoleRef.Namespace != nil {
					roleRefID += "|" + *auth.AppRole.RoleRef.Namespace
				}
				credParts = append(credParts, roleRefID)
			}

			// Get SecretID Secret's ResourceVersion
			secretName := auth.AppRole.SecretRef.Name
			secretNamespace := namespace
			if auth.AppRole.SecretRef.Namespace != nil {
				secretNamespace = *auth.AppRole.SecretRef.Namespace
			}
			secret := &v1.Secret{}
			err := kube.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get approle secret metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+secret.ResourceVersion)
			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// Kubernetes Auth with ServiceAccountRef - Concatenate SA identity + ResourceVersion
		if auth.Kubernetes != nil && auth.Kubernetes.ServiceAccountRef != nil {
			key.AuthMethod = "kubernetes"
			key.AuthPath = auth.Kubernetes.Path

			// Determine namespace
			saNamespace := namespace
			if auth.Kubernetes.ServiceAccountRef.Namespace != nil {
				saNamespace = *auth.Kubernetes.ServiceAccountRef.Namespace
			}
			saName := auth.Kubernetes.ServiceAccountRef.Name
			audiences := auth.Kubernetes.ServiceAccountRef.Audiences

			// Concatenate: namespace|name|audiences|ResourceVersion
			credParts = append(credParts, saNamespace)
			credParts = append(credParts, saName)
			credParts = append(credParts, strings.Join(audiences, ","))

			// Get ServiceAccount ResourceVersion
			sa := &v1.ServiceAccount{}
			err := kube.Get(ctx, types.NamespacedName{Name: saName, Namespace: saNamespace}, sa)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get service account metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+sa.ResourceVersion)
			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// Kubernetes Auth with SecretRef - Concatenate Secret identity + ResourceVersion
		if auth.Kubernetes != nil && auth.Kubernetes.SecretRef != nil {
			key.AuthMethod = "kubernetes"
			key.AuthPath = auth.Kubernetes.Path

			secretName := auth.Kubernetes.SecretRef.Name
			secretKey := auth.Kubernetes.SecretRef.Key
			if secretKey == "" {
				secretKey = "token"
			}
			secretNamespace := namespace
			if auth.Kubernetes.SecretRef.Namespace != nil {
				secretNamespace = *auth.Kubernetes.SecretRef.Namespace
			}

			// Concatenate: name|key|namespace|ResourceVersion
			credParts = append(credParts, secretName)
			credParts = append(credParts, secretKey)
			credParts = append(credParts, secretNamespace)

			// Get Secret ResourceVersion
			secret := &v1.Secret{}
			err := kube.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get kubernetes secret metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+secret.ResourceVersion)
			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// LDAP Auth - Concatenate username + Secret ResourceVersion
		if auth.Ldap != nil {
			key.AuthMethod = "ldap"
			key.AuthPath = auth.Ldap.Path

			username := strings.TrimSpace(auth.Ldap.Username)
			secretName := auth.Ldap.SecretRef.Name
			secretKey := auth.Ldap.SecretRef.Key
			secretNamespace := namespace
			if auth.Ldap.SecretRef.Namespace != nil {
				secretNamespace = *auth.Ldap.SecretRef.Namespace
			}

			// Concatenate: username|name|key|namespace|ResourceVersion
			credParts = append(credParts, username)
			credParts = append(credParts, secretName)
			credParts = append(credParts, secretKey)
			credParts = append(credParts, secretNamespace)

			// Get Secret ResourceVersion
			secret := &v1.Secret{}
			err := kube.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get ldap secret metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+secret.ResourceVersion)
			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// UserPass Auth - Concatenate username + Secret ResourceVersion
		if auth.UserPass != nil {
			key.AuthMethod = "userpass"
			key.AuthPath = auth.UserPass.Path

			username := strings.TrimSpace(auth.UserPass.Username)
			secretName := auth.UserPass.SecretRef.Name
			secretKey := auth.UserPass.SecretRef.Key
			secretNamespace := namespace
			if auth.UserPass.SecretRef.Namespace != nil {
				secretNamespace = *auth.UserPass.SecretRef.Namespace
			}

			// Concatenate: username|name|key|namespace|ResourceVersion
			credParts = append(credParts, username)
			credParts = append(credParts, secretName)
			credParts = append(credParts, secretKey)
			credParts = append(credParts, secretNamespace)

			// Get Secret ResourceVersion
			secret := &v1.Secret{}
			err := kube.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get userpass secret metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+secret.ResourceVersion)
			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// JWT Auth with SecretRef - Concatenate Secret identity + ResourceVersion
		if auth.Jwt != nil && auth.Jwt.SecretRef != nil {
			key.AuthMethod = "jwt"
			key.AuthPath = auth.Jwt.Path

			secretName := auth.Jwt.SecretRef.Name
			secretKey := auth.Jwt.SecretRef.Key
			secretNamespace := namespace
			if auth.Jwt.SecretRef.Namespace != nil {
				secretNamespace = *auth.Jwt.SecretRef.Namespace
			}

			// Concatenate: role|name|key|namespace|ResourceVersion
			credParts = append(credParts, strings.TrimSpace(auth.Jwt.Role))
			credParts = append(credParts, secretName)
			credParts = append(credParts, secretKey)
			credParts = append(credParts, secretNamespace)

			// Get Secret ResourceVersion
			secret := &v1.Secret{}
			err := kube.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get jwt secret metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+secret.ResourceVersion)
			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// JWT Auth with KubernetesServiceAccountToken - Concatenate SA identity + ResourceVersion
		if auth.Jwt != nil && auth.Jwt.KubernetesServiceAccountToken != nil {
			key.AuthMethod = "jwt"
			key.AuthPath = auth.Jwt.Path

			saRef := auth.Jwt.KubernetesServiceAccountToken.ServiceAccountRef
			saNamespace := namespace
			if saRef.Namespace != nil {
				saNamespace = *saRef.Namespace
			}
			saName := saRef.Name
			audiences := auth.Jwt.KubernetesServiceAccountToken.Audiences
			if audiences == nil {
				audiences = &[]string{"vault"}
			}

			// Concatenate: role|namespace|name|audiences|ResourceVersion
			credParts = append(credParts, strings.TrimSpace(auth.Jwt.Role))
			credParts = append(credParts, saNamespace)
			credParts = append(credParts, saName)
			credParts = append(credParts, strings.Join(*audiences, ","))

			// Get ServiceAccount ResourceVersion
			sa := &v1.ServiceAccount{}
			err := kube.Get(ctx, types.NamespacedName{Name: saName, Namespace: saNamespace}, sa)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get jwt service account metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+sa.ResourceVersion)
			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// Certificate Auth - Concatenate Secret identity + ResourceVersion
		if auth.Cert != nil {
			key.AuthMethod = "cert"

			// Get client cert Secret ResourceVersion
			certSecretName := auth.Cert.ClientCert.Name
			certSecretKey := auth.Cert.ClientCert.Key
			certSecretNamespace := namespace
			if auth.Cert.ClientCert.Namespace != nil {
				certSecretNamespace = *auth.Cert.ClientCert.Namespace
			}

			credParts = append(credParts, certSecretName)
			credParts = append(credParts, certSecretKey)
			credParts = append(credParts, certSecretNamespace)

			certSecret := &v1.Secret{}
			err := kube.Get(ctx, types.NamespacedName{Name: certSecretName, Namespace: certSecretNamespace}, certSecret)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get cert secret metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+certSecret.ResourceVersion)

			// Get client key Secret ResourceVersion
			keySecretName := auth.Cert.SecretRef.Name
			keySecretKey := auth.Cert.SecretRef.Key
			keySecretNamespace := namespace
			if auth.Cert.SecretRef.Namespace != nil {
				keySecretNamespace = *auth.Cert.SecretRef.Namespace
			}

			credParts = append(credParts, keySecretName)
			credParts = append(credParts, keySecretKey)
			credParts = append(credParts, keySecretNamespace)

			keySecret := &v1.Secret{}
			err = kube.Get(ctx, types.NamespacedName{Name: keySecretName, Namespace: keySecretNamespace}, keySecret)
			if err != nil {
				return ClientPoolKey{}, fmt.Errorf("failed to get cert key secret metadata: %w", err)
			}

			credParts = append(credParts, "rv:"+keySecret.ResourceVersion)
			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// IAM Auth - Multiple credential sources (IRSA, Pod Identity, SecretRef)
		if auth.Iam != nil {
			key.AuthMethod = "aws"
			key.AuthPath = auth.Iam.Path

			// Concatenate common IAM auth properties
			credParts = append(credParts, auth.Iam.Region)
			credParts = append(credParts, auth.Iam.Role)
			credParts = append(credParts, auth.Iam.AWSIAMRole)
			credParts = append(credParts, auth.Iam.ExternalID)
			credParts = append(credParts, auth.Iam.VaultAWSIAMServerID)

			// Case 1: ServiceAccount-based (IRSA/Pod Identity) - Concatenate SA identity + ResourceVersion
			if auth.Iam.JWTAuth != nil && auth.Iam.JWTAuth.ServiceAccountRef != nil {
				saRef := auth.Iam.JWTAuth.ServiceAccountRef
				saNamespace := namespace
				if saRef.Namespace != nil {
					saNamespace = *saRef.Namespace
				}
				saName := saRef.Name

				credParts = append(credParts, "jwt-sa")
				credParts = append(credParts, saNamespace)
				credParts = append(credParts, saName)

				// Get ServiceAccount ResourceVersion
				sa := &v1.ServiceAccount{}
				err := kube.Get(ctx, types.NamespacedName{Name: saName, Namespace: saNamespace}, sa)
				if err != nil {
					return ClientPoolKey{}, fmt.Errorf("failed to get iam jwt service account metadata: %w", err)
				}

				credParts = append(credParts, "rv:"+sa.ResourceVersion)
			} else if auth.Iam.SecretRef != nil {
				// Case 2: SecretRef-based credentials - Concatenate Secret identities + ResourceVersions
				credParts = append(credParts, "secret-ref")

				// AccessKeyID Secret
				accessKeyName := auth.Iam.SecretRef.AccessKeyID.Name
				accessKeyKey := auth.Iam.SecretRef.AccessKeyID.Key
				accessKeyNamespace := namespace
				if auth.Iam.SecretRef.AccessKeyID.Namespace != nil {
					accessKeyNamespace = *auth.Iam.SecretRef.AccessKeyID.Namespace
				}

				credParts = append(credParts, accessKeyName)
				credParts = append(credParts, accessKeyKey)
				credParts = append(credParts, accessKeyNamespace)

				accessKeySecret := &v1.Secret{}
				err := kube.Get(ctx, types.NamespacedName{Name: accessKeyName, Namespace: accessKeyNamespace}, accessKeySecret)
				if err != nil {
					return ClientPoolKey{}, fmt.Errorf("failed to get iam access key secret metadata: %w", err)
				}

				credParts = append(credParts, "rv:"+accessKeySecret.ResourceVersion)

				// SecretAccessKey Secret
				secretKeyName := auth.Iam.SecretRef.SecretAccessKey.Name
				secretKeyKey := auth.Iam.SecretRef.SecretAccessKey.Key
				secretKeyNamespace := namespace
				if auth.Iam.SecretRef.SecretAccessKey.Namespace != nil {
					secretKeyNamespace = *auth.Iam.SecretRef.SecretAccessKey.Namespace
				}

				credParts = append(credParts, secretKeyName)
				credParts = append(credParts, secretKeyKey)
				credParts = append(credParts, secretKeyNamespace)

				secretKeySecret := &v1.Secret{}
				err = kube.Get(ctx, types.NamespacedName{Name: secretKeyName, Namespace: secretKeyNamespace}, secretKeySecret)
				if err != nil {
					return ClientPoolKey{}, fmt.Errorf("failed to get iam secret access key secret metadata: %w", err)
				}

				credParts = append(credParts, "rv:"+secretKeySecret.ResourceVersion)

				// Optional SessionToken Secret
				if auth.Iam.SecretRef.SessionToken != nil {
					sessionTokenName := auth.Iam.SecretRef.SessionToken.Name
					sessionTokenKey := auth.Iam.SecretRef.SessionToken.Key
					sessionTokenNamespace := namespace
					if auth.Iam.SecretRef.SessionToken.Namespace != nil {
						sessionTokenNamespace = *auth.Iam.SecretRef.SessionToken.Namespace
					}

					credParts = append(credParts, sessionTokenName)
					credParts = append(credParts, sessionTokenKey)
					credParts = append(credParts, sessionTokenNamespace)

					sessionTokenSecret := &v1.Secret{}
					err = kube.Get(ctx, types.NamespacedName{Name: sessionTokenName, Namespace: sessionTokenNamespace}, sessionTokenSecret)
					if err != nil {
						return ClientPoolKey{}, fmt.Errorf("failed to get iam session token secret metadata: %w", err)
					}

					credParts = append(credParts, "rv:"+sessionTokenSecret.ResourceVersion)
				}
			} else {
				// Case 3: Pod identity (controller's own service account) - use static identifier
				// No credentials to track - cache based on role/region only
				credParts = append(credParts, "pod-identity")
			}

			key.CredentialIdentity = strings.Join(credParts, "|")
		}

		// Token Auth - Static tokens should not be cached
		if auth.TokenSecretRef != nil {
			// Static tokens are handled separately - not cached
			key.AuthMethod = "token"
		}
	}

	// Hash client cert/key Secret ResourceVersion if present for mTLS
	if vaultSpec.ClientTLS.CertSecretRef != nil {
		certSecretName := vaultSpec.ClientTLS.CertSecretRef.Name
		certSecretNamespace := namespace
		if vaultSpec.ClientTLS.CertSecretRef.Namespace != nil {
			certSecretNamespace = *vaultSpec.ClientTLS.CertSecretRef.Namespace
		}

		certSecret := &v1.Secret{}
		err := kube.Get(ctx, types.NamespacedName{Name: certSecretName, Namespace: certSecretNamespace}, certSecret)
		if err == nil {
			certHash := sha256.Sum256([]byte(certSecret.ResourceVersion))
			key.ClientCertHash = &certHash
		}
	}
	if vaultSpec.ClientTLS.KeySecretRef != nil {
		keySecretName := vaultSpec.ClientTLS.KeySecretRef.Name
		keySecretNamespace := namespace
		if vaultSpec.ClientTLS.KeySecretRef.Namespace != nil {
			keySecretNamespace = *vaultSpec.ClientTLS.KeySecretRef.Namespace
		}

		keySecret := &v1.Secret{}
		err := kube.Get(ctx, types.NamespacedName{Name: keySecretName, Namespace: keySecretNamespace}, keySecret)
		if err == nil {
			keyHash := sha256.Sum256([]byte(keySecret.ResourceVersion))
			key.ClientKeyHash = &keyHash
		}
	}

	return key, nil
}

func getVaultClient(p *Provider, store esv1.GenericStore, cfg *vault.Config, namespace string) (util.Client, error) {
	vaultProvider := store.GetSpec().Provider.Vault
	auth := vaultProvider.Auth
	isStaticToken := auth != nil && auth.TokenSecretRef != nil

	// Credential-based pooling (new approach)
	if enableClientPooling && !isStaticToken {
		return getPooledVaultClient(p, store, cfg, namespace)
	}

	// Legacy caching based on SecretStore ResourceVersion (old approach)
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

// getOrCreatePooledClient is a shared helper for credential-based client pooling with singleflight pattern.
// Clients are cached based on functional equivalence (configuration + credentials) rather than
// resource version. This enables sharing clients across multiple resources that use the same
// Vault configuration and credentials.
// This function is used by both SecretStore/ClusterSecretStore and VaultDynamicSecret resources.
func getOrCreatePooledClient(
	p *Provider,
	ctx context.Context,
	vaultSpec *esv1.VaultProvider,
	cfg *vault.Config,
	kube kclient.Client,
	corev1 typedcorev1.CoreV1Interface,
	storeKind string,
	namespace string,
) (util.Client, error) {
	// Skip pooling for static tokens
	auth := vaultSpec.Auth
	isStaticToken := auth != nil && auth.TokenSecretRef != nil
	if isStaticToken {
		return p.NewVaultClient(cfg)
	}

	// Build credential-based cache key
	poolKey, err := buildClientPoolKey(
		ctx,
		corev1,
		vaultSpec,
		kube,
		storeKind,
		namespace,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build pool key: %w", err)
	}

	cacheKey := poolKey.String()

	// Check cache first
	if client, ok := pooledClientCache.Get("", cache.Key{Name: cacheKey}); ok {
		return client, nil
	}

	// Use singleflight to prevent duplicate client creation for the same credentials
	result, err, _ := createGroup.Do(cacheKey, func() (interface{}, error) {
		// Double-check cache after acquiring singleflight lock
		if client, ok := pooledClientCache.Get("", cache.Key{Name: cacheKey}); ok {
			return client, nil
		}

		// Create new Vault client
		client, err := p.NewVaultClient(cfg)
		if err != nil {
			return nil, fmt.Errorf(errVaultClient, err)
		}

		// Add to cache
		if !pooledClientCache.Contains(cache.Key{Name: cacheKey}) {
			pooledClientCache.Add("", cache.Key{Name: cacheKey}, client)
		}

		return client, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(util.Client), nil
}

// getPooledVaultClient implements credential-based client pooling for SecretStore/ClusterSecretStore resources.
func getPooledVaultClient(p *Provider, store esv1.GenericStore, cfg *vault.Config, namespace string) (util.Client, error) {
	// controller-runtime/client does not support TokenRequest or other subresource APIs
	// so we need to construct our own client and use it to fetch tokens
	restCfg, err := ctrlcfg.GetConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	corev1Client := clientset.CoreV1()

	// Create controller-runtime client for reading Secrets/ServiceAccounts
	kubeClient, err := kclient.New(restCfg, kclient.Options{})
	if err != nil {
		return nil, err
	}

	vaultProvider := store.GetSpec().Provider.Vault
	storeKind := store.GetTypeMeta().Kind

	return getOrCreatePooledClient(
		p,
		context.Background(),
		vaultProvider,
		cfg,
		kubeClient,
		corev1Client,
		storeKind,
		namespace,
	)
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

func initPooledCache(size int) {
	logger.Info("initializing vault client pool", "size", size)
	pooledClientCache = cache.Must(size, func(client util.Client) {
		err := revokeTokenIfValid(context.Background(), client)
		if err != nil {
			logger.Error(err, "unable to revoke pooled client token on eviction")
		}
	})
}

func init() {
	var vaultTokenCacheSize int
	var vaultClientPoolSize int
	fs := pflag.NewFlagSet("vault", pflag.ExitOnError)
	fs.BoolVar(&enableCache, "experimental-enable-vault-token-cache", false, "Enable experimental Vault token cache. External secrets will reuse the Vault token without creating a new one on each request.")
	// max. 265k vault leases with 30bytes each ~= 7MB
	fs.IntVar(&vaultTokenCacheSize, "experimental-vault-token-cache-size", defaultCacheSize, "Maximum size of Vault token cache. When more tokens than Only used if --experimental-enable-vault-token-cache is set.")
	fs.BoolVar(&enableClientPooling, "experimental-enable-vault-client-pooling", false, "Enable experimental Vault client pooling. Vault clients are cached based on credentials and shared across multiple resources, reducing authentication overhead by 10-100x.")
	fs.IntVar(&vaultClientPoolSize, "experimental-vault-client-pool-size", defaultCacheSize, "Maximum size of Vault client pool. Only used if --experimental-enable-vault-client-pooling is set.")
	feature.Register(feature.Feature{
		Flags: fs,
		Initialize: func() {
			initCache(vaultTokenCacheSize)
			initPooledCache(vaultClientPoolSize)
		},
	})

	esv1.Register(&Provider{
		NewVaultClient: NewVaultClient,
	}, &esv1.SecretStoreProvider{
		Vault: &esv1.VaultProvider{},
	}, esv1.MaintenanceStatusMaintained)
}
