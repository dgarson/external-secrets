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

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

var _ ClientPool = &noOpPool{}
var _ ClientLease = &noOpLease{}

// noOpPool is a no-op implementation that doesn't cache clients.
// It maintains backward compatibility when caching is disabled.
type noOpPool struct{}

// newNoOpPool creates a new no-op pool.
func newNoOpPool() *noOpPool {
	return &noOpPool{}
}

// Acquire creates a new client without caching.
func (p *noOpPool) Acquire(ctx context.Context, config VaultClientConfig) (ClientLease, error) {
	// Create a new Vault client
	vaultClient, err := NewVaultClient(config.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set namespace if specified
	if config.VaultSpec.Namespace != nil {
		vaultClient.SetNamespace(*config.VaultSpec.Namespace)
	}

	// Set custom headers if specified
	if config.VaultSpec.Headers != nil {
		for key, value := range config.VaultSpec.Headers {
			vaultClient.AddHeader(key, value)
		}
	}

	// Set read-your-writes header if needed
	if config.VaultSpec.ReadYourWrites && config.VaultSpec.ForwardInconsistent {
		vaultClient.AddHeader("X-Vault-Inconsistent", "forward-active-node")
	}

	// Create a temporary client wrapper to reuse setAuth
	tempClient := &client{
		kube:      config.Kubernetes,
		corev1:    config.CoreV1,
		store:     config.VaultSpec,
		log:       logger,
		namespace: config.CredentialNS,
		storeKind: config.StoreKind,
		client:    vaultClient,
		auth:      vaultClient.Auth(),
		logical:   vaultClient.Logical(),
		token:     vaultClient.AuthToken(),
	}

	// Authenticate the client
	if err := tempClient.setAuth(ctx, config.VaultConfig); err != nil {
		return nil, fmt.Errorf("failed to authenticate vault client: %w", err)
	}

	return &noOpLease{
		client: vaultClient,
		spec:   config.VaultSpec,
	}, nil
}

// Shutdown is a no-op for the no-op pool.
func (p *noOpPool) Shutdown(ctx context.Context) error {
	return nil
}

// noOpLease is a no-op implementation of ClientLease.
type noOpLease struct {
	client util.Client
	spec   *esv1.VaultProvider
}

// Client returns the underlying Vault client.
func (l *noOpLease) Client() util.Client {
	return l.client
}

// WithRetry executes the operation without retry logic (backward compatible behavior).
func (l *noOpLease) WithRetry(ctx context.Context, op func(util.Client) error) error {
	return op(l.client)
}

// Release revokes the token (backward compatible behavior).
func (l *noOpLease) Release() error {
	// Revoke the token if it's not a static token
	if !isStaticToken(l.spec) {
		return revokeTokenIfValid(context.Background(), l.client)
	}
	return nil
}
