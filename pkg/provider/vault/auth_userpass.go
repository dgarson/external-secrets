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

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

func setUserPassAuthToken(ctx context.Context, v *client) (bool, *TokenMetadata, error) {
	userPassAuth := v.store.Auth.UserPass
	if userPassAuth != nil {
		metadata, err := v.requestTokenWithUserPassAuth(ctx, userPassAuth)
		if err != nil {
			return true, nil, err
		}
		return true, metadata, nil
	}
	return false, nil, nil
}

func (c *client) requestTokenWithUserPassAuth(ctx context.Context, userPassAuth *esv1.VaultUserPassAuth) (*TokenMetadata, error) {
	username := strings.TrimSpace(userPassAuth.Username)
	password, err := resolvers.SecretKeyRef(ctx, c.kube, c.storeKind, c.namespace, &userPassAuth.SecretRef)
	if err != nil {
		return nil, err
	}
	pass := authuserpass.Password{FromString: password}
	l, err := authuserpass.NewUserpassAuth(username, &pass, authuserpass.WithMountPath(userPassAuth.Path))
	if err != nil {
		return nil, err
	}
	secret, err := c.auth.Login(ctx, l)
	metrics.ObserveAPICall(constants.ProviderHCVault, constants.CallHCVaultLogin, err)
	if err != nil {
		return nil, err
	}

	// Extract and return metadata
	return extractTokenMetadata(secret), nil
}
