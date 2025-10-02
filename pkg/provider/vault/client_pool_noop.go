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

	vault "github.com/hashicorp/vault/api"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// NoOpClientPool is a ClientPool implementation that provides the current/legacy behavior:
// - Creates a new Vault client on every AcquireClient call
// - Performs authentication on every client creation
// - ReleaseClient is a no-op (token revocation is handled by client.Close())
// - No caching or connection pooling
//
// This implementation ensures backward compatibility and identical behavior to the
// existing code without the client pool abstraction.
//
// IMPORTANT: Static tokens (from auth.tokenSecretRef) are NEVER revoked by this pool.
// Token revocation is handled by client.Close() which has access to the VaultProvider
// configuration and can properly check if the token is static.
type NoOpClientPool struct {
	newVaultClient func(config *vault.Config) (util.Client, error)
}

// NewNoOpClientPool creates a new NoOpClientPool.
func NewNoOpClientPool(newVaultClient func(config *vault.Config) (util.Client, error)) *NoOpClientPool {
	if newVaultClient == nil {
		newVaultClient = NewVaultClient
	}
	return &NoOpClientPool{
		newVaultClient: newVaultClient,
	}
}

// AcquireClient creates a new Vault client and authenticates it.
// This matches the current behavior where each operation gets a fresh client.
func (p *NoOpClientPool) AcquireClient(ctx context.Context, config AcquireClientConfig) (util.Client, error) {
	// Create new Vault client
	vaultClient, err := p.newVaultClient(config.VaultConfig)
	if err != nil {
		return nil, err
	}

	// Set namespace if configured
	if config.VaultProvider.Namespace != nil {
		vaultClient.SetNamespace(*config.VaultProvider.Namespace)
	}

	// Set custom headers if configured
	if config.VaultProvider.Headers != nil {
		for key, value := range config.VaultProvider.Headers {
			vaultClient.AddHeader(key, value)
		}
	}

	// Set read-your-writes headers if configured
	if config.VaultProvider.ReadYourWrites && config.VaultProvider.ForwardInconsistent {
		vaultClient.AddHeader("X-Vault-Inconsistent", "forward-active-node")
	}

	// Perform authentication
	// We create a client struct to reuse the existing setAuth logic
	c := &client{
		kube:      config.Kube,
		corev1:    config.CoreV1,
		store:     config.VaultProvider,
		namespace: config.Namespace,
		storeKind: config.StoreKind,
		client:    vaultClient,
		auth:      vaultClient.Auth(),
		logical:   vaultClient.Logical(),
		token:     vaultClient.AuthToken(),
		log:       logger,
	}

	// allow SecretStore controller validation to pass when using referent namespace
	skipAuth := config.StoreKind == esv1.ClusterSecretStoreKind &&
		config.Namespace == "" &&
		isReferentSpec(config.VaultProvider)
	if !skipAuth {
		if err := c.setAuth(ctx, config.VaultConfig); err != nil {
			return nil, err
		}
	}

	return vaultClient, nil
}

// ReleaseClient is a no-op for NoOpClientPool.
// Token revocation is handled by the client.Close() method, which has access to the
// VaultProvider configuration and can properly check if the token is static (from TokenSecretRef).
// We intentionally do NOT revoke tokens here to avoid accidentally revoking static tokens,
// which are managed externally to ESO.
func (p *NoOpClientPool) ReleaseClient(ctx context.Context, vaultClient util.Client) error {
	// No-op: client cleanup is handled by client.Close() which has proper TokenSecretRef checking
	return nil
}

// Close is a no-op for NoOpClientPool since it doesn't maintain any state.
func (p *NoOpClientPool) Close(ctx context.Context) error {
	return nil
}

// Verify NoOpClientPool implements ClientPool interface.
var _ ClientPool = &NoOpClientPool{}
