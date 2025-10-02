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
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// ClientPool is an interface for managing Vault client instances.
// It provides a mechanism to acquire and release Vault clients, with optional
// connection pooling and token renewal capabilities.
type ClientPool interface {
	// AcquireClient returns a Vault client based on the provided configuration.
	// The implementation may return a cached client or create a new one.
	AcquireClient(ctx context.Context, config AcquireClientConfig) (util.Client, error)

	// ReleaseClient signals that the client is no longer in use for the current operation.
	// For pooled implementations, this may keep the client alive for reuse.
	// For non-pooled implementations, this may close/revoke the client.
	ReleaseClient(ctx context.Context, client util.Client) error

	// Close closes all managed clients and cleans up resources.
	Close(ctx context.Context) error
}

// AcquireClientConfig contains all configuration needed to acquire a Vault client.
// This includes both the Vault-specific configuration and the Kubernetes context
// needed for authentication.
type AcquireClientConfig struct {
	// VaultConfig is the Hashicorp Vault API client configuration
	VaultConfig *vault.Config

	// VaultProvider contains the ESO Vault provider configuration
	VaultProvider *esv1.VaultProvider

	// Kube is the Kubernetes client for reading secrets/service accounts
	Kube kclient.Client

	// CoreV1 is the Kubernetes typed client for TokenRequest API
	CoreV1 typedcorev1.CoreV1Interface

	// Namespace is the Kubernetes namespace context for credential resolution
	// For SecretStore: this is the store's namespace
	// For ClusterSecretStore with referent auth: this is the ExternalSecret's namespace
	Namespace string

	// StoreKind is the kind of store (SecretStore or ClusterSecretStore)
	StoreKind string

	// StoreName is the name of the store (for logging/metrics)
	StoreName string

	// StoreNamespace is the namespace of the store (empty for ClusterSecretStore)
	StoreNamespace string
}
