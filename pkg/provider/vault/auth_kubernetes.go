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

func setKubernetesAuthToken(
	ctx context.Context,
	vaultClient util.Client,
	authCtx *authContext,
) (bool, error) {
	kubernetesAuth := authCtx.spec.Auth.Kubernetes
	if kubernetesAuth != nil {
		err := requestTokenWithKubernetesAuth(ctx, vaultClient, authCtx, kubernetesAuth)
		if err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

func requestTokenWithKubernetesAuth(
	ctx context.Context,
	vaultClient util.Client,
	authCtx *authContext,
	kubernetesAuth *esv1.VaultKubernetesAuth,
) error {
	jwtString, err := getJwtString(ctx, authCtx, kubernetesAuth)
	if err != nil {
		return err
	}
	k, err := authkubernetes.NewKubernetesAuth(kubernetesAuth.Role, authkubernetes.WithServiceAccountToken(jwtString), authkubernetes.WithMountPath(kubernetesAuth.Path))
	if err != nil {
		return err
	}
	_, err = vaultClient.Auth().Login(ctx, k)
	metrics.ObserveAPICall(constants.ProviderHCVault, constants.CallHCVaultLogin, err)
	if err != nil {
		return err
	}
	return nil
}

func getJwtString(
	ctx context.Context,
	authCtx *authContext,
	kubernetesAuth *esv1.VaultKubernetesAuth,
) (string, error) {
	if kubernetesAuth.ServiceAccountRef != nil {
		// Kubernetes >=v1.24: fetch token via TokenRequest API
		// note: this is a massive change from vault perspective: the `iss` claim will very likely change.
		// Vault 1.9 deprecated issuer validation by default, and authentication with Vault clusters <1.9 will likely fail.
		jwt, err := createServiceAccountToken(
			ctx,
			authCtx.corev1,
			authCtx.storeKind,
			authCtx.namespace,
			*kubernetesAuth.ServiceAccountRef,
			nil,
			600)
		if jwt != "" && err == nil {
			return jwt, nil
		}
		logger.V(1).Info("unable to create service account token, trying to fetch jwt from service account secret next")
		// Kubernetes <v1.24 fetch token via ServiceAccount.Secrets[]
		// this behavior was removed in v1.24 and we must use TokenRequest API (see below)
		jwt, err = secretKeyRefForServiceAccount(ctx, authCtx, kubernetesAuth.ServiceAccountRef)
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
		jwt, err := resolvers.SecretKeyRef(ctx, authCtx.kube, authCtx.storeKind, authCtx.namespace, tokenRef)
		if err != nil {
			return "", err
		}
		return jwt, nil
	} else {
		// Kubernetes authentication is specified, but without a referenced
		// Kubernetes secret. We check if the file path for in-cluster service account
		// exists and attempt to use the token for Vault Kubernetes auth.
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

func secretKeyRefForServiceAccount(
	ctx context.Context,
	authCtx *authContext,
	serviceAccountRef *esmeta.ServiceAccountSelector,
) (string, error) {
	serviceAccount := &corev1.ServiceAccount{}
	ref := types.NamespacedName{
		Namespace: authCtx.namespace,
		Name:      serviceAccountRef.Name,
	}
	if (authCtx.storeKind == esv1.ClusterSecretStoreKind) &&
		(serviceAccountRef.Namespace != nil) {
		ref.Namespace = *serviceAccountRef.Namespace
	}
	err := authCtx.kube.Get(ctx, ref, serviceAccount)
	if err != nil {
		return "", fmt.Errorf(errGetKubeSA, ref.Name, err)
	}
	if len(serviceAccount.Secrets) == 0 {
		return "", fmt.Errorf(errGetKubeSASecrets, ref.Name)
	}
	for _, tokenRef := range serviceAccount.Secrets {
		token, err := resolvers.SecretKeyRef(ctx, authCtx.kube, authCtx.storeKind, authCtx.namespace, &esmeta.SecretKeySelector{
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
