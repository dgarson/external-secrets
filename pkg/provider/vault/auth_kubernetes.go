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
	"os"

	authkubernetes "github.com/hashicorp/vault/api/auth/kubernetes"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

const (
	serviceAccTokenPath       = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	errServiceAccount         = "cannot read Kubernetes service account token from file system: %w"
	errGetKubeSA              = "cannot get Kubernetes service account %q: %w"
	errGetKubeSASecrets       = "cannot find secrets bound to service account: %q"
	errGetKubeSANoToken       = "cannot find token in secrets bound to service account: %q"
	errServiceAccountNotFound = "serviceaccounts %q not found"
)

// extractKubernetesCredentials extracts Kubernetes auth credentials (JWT token) from various sources.
// This function is used by the client pooling feature to extract credentials before caching.
// It supports ServiceAccountRef (with TokenRequest API), SecretRef, and in-cluster service account token file.
func extractKubernetesCredentials(
	ctx context.Context,
	corev1 typedcorev1.CoreV1Interface,
	kube kclient.Client,
	storeKind string,
	namespace string,
	kubernetesAuth *esv1.VaultKubernetesAuth,
) (jwt string, err error) {
	if kubernetesAuth.ServiceAccountRef != nil {
		// Kubernetes >=v1.24: fetch token via TokenRequest API
		jwt, err = createServiceAccountToken(
			ctx,
			corev1,
			storeKind,
			namespace,
			*kubernetesAuth.ServiceAccountRef,
			nil,
			600)
		if jwt != "" && err == nil {
			return jwt, nil
		}

		// Kubernetes <v1.24 fetch token via ServiceAccount.Secrets[]
		// This is a fallback for older clusters
		jwt, err = getSecretKeyRefForServiceAccount(ctx, kube, storeKind, namespace, kubernetesAuth.ServiceAccountRef)
		if err != nil {
			return "", fmt.Errorf(errGetKubeSATokenRequest, kubernetesAuth.ServiceAccountRef.Name, err)
		}
		return jwt, nil
	} else if kubernetesAuth.SecretRef != nil {
		tokenRef := kubernetesAuth.SecretRef
		if tokenRef.Key == "" {
			tokenRef = kubernetesAuth.SecretRef.DeepCopy()
			tokenRef.Key = "token"
		}
		jwt, err = resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, tokenRef)
		if err != nil {
			return "", err
		}
		return jwt, nil
	} else {
		// In-cluster service account token file
		if _, err := os.Stat(serviceAccTokenPath); err != nil {
			return "", fmt.Errorf(errServiceAccount, err)
		}
		jwtByte, err := os.ReadFile(serviceAccTokenPath)
		if err != nil {
			return "", fmt.Errorf(errServiceAccount, err)
		}
		return string(jwtByte), nil
	}
}

// getSecretKeyRefForServiceAccount is a helper function that fetches JWT from ServiceAccount.Secrets[]
// This is used for Kubernetes <v1.24 compatibility.
func getSecretKeyRefForServiceAccount(
	ctx context.Context,
	kube kclient.Client,
	storeKind string,
	namespace string,
	serviceAccountRef *esmeta.ServiceAccountSelector,
) (string, error) {
	serviceAccount := &corev1.ServiceAccount{}
	ref := types.NamespacedName{
		Namespace: namespace,
		Name:      serviceAccountRef.Name,
	}
	if (storeKind == esv1.ClusterSecretStoreKind) && (serviceAccountRef.Namespace != nil) {
		ref.Namespace = *serviceAccountRef.Namespace
	}

	err := kube.Get(ctx, ref, serviceAccount)
	if err != nil {
		return "", fmt.Errorf(errGetKubeSA, ref.Name, err)
	}
	if len(serviceAccount.Secrets) == 0 {
		return "", fmt.Errorf(errGetKubeSASecrets, ref.Name)
	}

	for _, tokenRef := range serviceAccount.Secrets {
		token, err := resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &esmeta.SecretKeySelector{
			Name:      tokenRef.Name,
			Namespace: &ref.Namespace,
			Key:       "token",
		})
		if err != nil {
			continue
		}
		return token, nil
	}
	return "", fmt.Errorf(errGetKubeSANoToken, ref.Name)
}

// authenticateWithKubernetes authenticates to Vault using Kubernetes auth with pre-extracted JWT.
// This function is used by the client pooling feature to avoid re-reading credentials from Kubernetes.
func authenticateWithKubernetes(
	ctx context.Context,
	auth util.Auth,
	kubernetesAuth *esv1.VaultKubernetesAuth,
	jwt string,
) error {
	k, err := authkubernetes.NewKubernetesAuth(
		kubernetesAuth.Role,
		authkubernetes.WithServiceAccountToken(jwt),
		authkubernetes.WithMountPath(kubernetesAuth.Path))
	if err != nil {
		return err
	}
	_, err = auth.Login(ctx, k)
	metrics.ObserveAPICall(constants.ProviderHCVault, constants.CallHCVaultLogin, err)
	if err != nil {
		return err
	}
	return nil
}

func setKubernetesAuthToken(ctx context.Context, v *client) (bool, error) {
	kubernetesAuth := v.store.Auth.Kubernetes
	if kubernetesAuth != nil {
		err := v.requestTokenWithKubernetesAuth(ctx, kubernetesAuth)
		if err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

func (c *client) requestTokenWithKubernetesAuth(ctx context.Context, kubernetesAuth *esv1.VaultKubernetesAuth) error {
	// Extract credentials
	jwt, err := extractKubernetesCredentials(ctx, c.corev1, c.kube, c.storeKind, c.namespace, kubernetesAuth)
	if err != nil {
		return err
	}

	// Authenticate with extracted credentials
	return authenticateWithKubernetes(ctx, c.auth, kubernetesAuth, jwt)
}
