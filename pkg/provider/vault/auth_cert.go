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
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	vault "github.com/hashicorp/vault/api"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

const (
	errVaultRequest = "error from Vault request: %w"
)

func setCertAuthToken(ctx context.Context, v *client, cfg *vault.Config) (bool, *TokenMetadata, error) {
	certAuth := v.store.Auth.Cert
	if certAuth != nil {
		metadata, err := v.requestTokenWithCertAuth(ctx, certAuth, cfg)
		if err != nil {
			return true, nil, err
		}
		return true, metadata, nil
	}
	return false, nil, nil
}

func (c *client) requestTokenWithCertAuth(ctx context.Context, certAuth *esv1.VaultCertAuth, cfg *vault.Config) (*TokenMetadata, error) {
	clientKey, err := resolvers.SecretKeyRef(ctx, c.kube, c.storeKind, c.namespace, &certAuth.SecretRef)
	if err != nil {
		return nil, err
	}

	clientCert, err := resolvers.SecretKeyRef(ctx, c.kube, c.storeKind, c.namespace, &certAuth.ClientCert)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
	if err != nil {
		return nil, fmt.Errorf(errClientTLSAuth, err)
	}

	if transport, ok := cfg.HttpClient.Transport.(*http.Transport); ok {
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	url := strings.Join([]string{"auth", "cert", "login"}, "/")
	vaultResult, err := c.logical.WriteWithContext(ctx, url, nil)
	metrics.ObserveAPICall(constants.ProviderHCVault, constants.CallHCVaultWriteSecretData, err)
	if err != nil {
		return nil, fmt.Errorf(errVaultRequest, err)
	}
	token, err := vaultResult.TokenID()
	if err != nil {
		return nil, fmt.Errorf(errVaultToken, err)
	}
	c.client.SetToken(token)

	// Extract and return metadata
	return extractTokenMetadata(vaultResult), nil
}
