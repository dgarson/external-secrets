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
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// authContext bundles all state needed for Vault authentication.
// This eliminates circular dependencies by allowing pooledVaultClient
// to re-authenticate without depending on the client/secretsClient struct.
//
// The authContext contains:
// - spec: Vault provider configuration (auth methods, server config, etc.)
// - kube: Kubernetes client for reading Secrets/ServiceAccounts
// - corev1: Kubernetes API for ServiceAccount token operations
// - namespace: The namespace context for authentication
// - storeKind: Type of store (SecretStore vs ClusterSecretStore)
//
// This struct is immutable after creation and can be safely shared
// across re-authentication attempts.
type authContext struct {
	spec      *esv1.VaultProvider
	kube      kclient.Client
	corev1    typedcorev1.CoreV1Interface
	namespace string
	storeKind string
}

// newAuthContext creates an authentication context from the provided components.
// All parameters are required for proper authentication.
func newAuthContext(
	spec *esv1.VaultProvider,
	kube kclient.Client,
	corev1 typedcorev1.CoreV1Interface,
	namespace string,
	storeKind string,
) *authContext {
	return &authContext{
		spec:      spec,
		kube:      kube,
		corev1:    corev1,
		namespace: namespace,
		storeKind: storeKind,
	}
}
