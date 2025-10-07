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
	"strings"

	authuserpass "github.com/hashicorp/vault/api/auth/userpass"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

// extractUserPassCredentials extracts UserPass credentials (username and password) from Kubernetes secrets.
// This function is used by the client pooling feature to extract credentials before caching.
func extractUserPassCredentials(
	ctx context.Context,
	kube kclient.Client,
	storeKind string,
	namespace string,
	userPassAuth *esv1.VaultUserPassAuth,
) (username string, password string, err error) {
	username = strings.TrimSpace(userPassAuth.Username)
	password, err = resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &userPassAuth.SecretRef)
	if err != nil {
		return "", "", err
	}
	return username, password, nil
}

// authenticateWithUserPass authenticates to Vault using UserPass with pre-extracted credentials.
// This function is used by the client pooling feature to avoid re-reading credentials from Kubernetes.
func authenticateWithUserPass(
	ctx context.Context,
	auth util.Auth,
	userPassAuth *esv1.VaultUserPassAuth,
	username string,
	password string,
) error {
	pass := authuserpass.Password{FromString: password}
	l, err := authuserpass.NewUserpassAuth(username, &pass, authuserpass.WithMountPath(userPassAuth.Path))
	if err != nil {
		return err
	}
	_, err = auth.Login(ctx, l)
	metrics.ObserveAPICall(constants.ProviderHCVault, constants.CallHCVaultLogin, err)
	if err != nil {
		return err
	}
	return nil
}

func setUserPassAuthToken(ctx context.Context, v *client) (bool, error) {
	userPassAuth := v.store.Auth.UserPass
	if userPassAuth != nil {
		err := v.requestTokenWithUserPassAuth(ctx, userPassAuth)
		if err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

func (c *client) requestTokenWithUserPassAuth(ctx context.Context, userPassAuth *esv1.VaultUserPassAuth) error {
	// Extract credentials
	username, password, err := extractUserPassCredentials(ctx, c.kube, c.storeKind, c.namespace, userPassAuth)
	if err != nil {
		return err
	}

	// Authenticate with extracted credentials
	return authenticateWithUserPass(ctx, c.auth, userPassAuth, username, password)
}
