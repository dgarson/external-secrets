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
	"strings"

	"github.com/hashicorp/vault/api/auth/approle"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

const (
	errInvalidAppRoleID = "invalid Auth.AppRole: neither `roleId` nor `roleRef` was supplied"
)

// extractAppRoleCredentials extracts AppRole credentials (roleID and secretID) from Kubernetes secrets.
// This function is used by the client pooling feature to extract credentials before caching.
func extractAppRoleCredentials(
	ctx context.Context,
	kube kclient.Client,
	storeKind string,
	namespace string,
	appRole *esv1.VaultAppRole,
) (roleID string, secretID string, err error) {
	// prefer .auth.appRole.roleId, fallback to .auth.appRole.roleRef, give up after that.
	if appRole.RoleID != "" { // use roleId from CRD, if configured
		roleID = strings.TrimSpace(appRole.RoleID)
	} else if appRole.RoleRef != nil { // use RoleID from Secret, if configured
		roleID, err = resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, appRole.RoleRef)
		if err != nil {
			return "", "", err
		}
	} else { // we ran out of ways to get RoleID. return an appropriate error
		return "", "", errors.New(errInvalidAppRoleID)
	}

	secretID, err = resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &appRole.SecretRef)
	if err != nil {
		return "", "", err
	}

	return roleID, secretID, nil
}

// authenticateWithAppRole authenticates to Vault using AppRole with pre-extracted credentials.
// This function is used by the client pooling feature to avoid re-reading credentials from Kubernetes.
func authenticateWithAppRole(
	ctx context.Context,
	auth util.Auth,
	appRole *esv1.VaultAppRole,
	roleID string,
	secretID string,
) error {
	secret := approle.SecretID{FromString: secretID}
	appRoleClient, err := approle.NewAppRoleAuth(roleID, &secret, approle.WithMountPath(appRole.Path))
	if err != nil {
		return err
	}
	_, err = auth.Login(ctx, appRoleClient)
	metrics.ObserveAPICall(constants.ProviderHCVault, constants.CallHCVaultLogin, err)
	if err != nil {
		return err
	}
	return nil
}

func setAppRoleToken(ctx context.Context, v *client) (bool, error) {
	appRole := v.store.Auth.AppRole
	if appRole != nil {
		err := v.requestTokenWithAppRoleRef(ctx, appRole)
		if err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

func (c *client) requestTokenWithAppRoleRef(ctx context.Context, appRole *esv1.VaultAppRole) error {
	// Extract credentials
	roleID, secretID, err := extractAppRoleCredentials(ctx, c.kube, c.storeKind, c.namespace, appRole)
	if err != nil {
		return err
	}

	// Authenticate with extracted credentials
	return authenticateWithAppRole(ctx, c.auth, appRole, roleID, secretID)
}
