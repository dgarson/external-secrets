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

	vault "github.com/hashicorp/vault/api"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// PooledClient wraps a Vault client with automatic retry logic for token expiration.
// When a 403 error is detected, it attempts to re-authenticate once and retry the operation.
type PooledClient struct {
	client       util.Client
	reAuthFunc   func(context.Context) error
	tokenRevoked bool
}

// NewPooledClient creates a new PooledClient wrapper around a Vault client.
// The reAuthFunc is called when token expiration is detected to re-authenticate.
func NewPooledClient(client util.Client, reAuthFunc func(context.Context) error) *PooledClient {
	return &PooledClient{
		client:     client,
		reAuthFunc: reAuthFunc,
	}
}

// SetToken sets the Vault token.
func (p *PooledClient) SetToken(token string) {
	p.client.SetToken(token)
}

// Token returns the current Vault token.
func (p *PooledClient) Token() string {
	return p.client.Token()
}

// ClearToken clears the Vault token.
func (p *PooledClient) ClearToken() {
	p.client.ClearToken()
}

// Auth returns the Auth interface.
func (p *PooledClient) Auth() util.Auth {
	return p.client.Auth()
}

// AuthToken returns the Token interface.
func (p *PooledClient) AuthToken() util.Token {
	return p.client.AuthToken()
}

// Logical returns the Logical interface with retry wrapper.
func (p *PooledClient) Logical() util.Logical {
	return &pooledLogical{
		logical:    p.client.Logical(),
		poolClient: p,
	}
}

// Namespace returns the current namespace.
func (p *PooledClient) Namespace() string {
	return p.client.Namespace()
}

// SetNamespace sets the namespace.
func (p *PooledClient) SetNamespace(namespace string) {
	p.client.SetNamespace(namespace)
}

// AddHeader adds a header to the client.
func (p *PooledClient) AddHeader(key, value string) {
	p.client.AddHeader(key, value)
}

// Clone creates a new PooledClient with a cloned underlying client.
func (p *PooledClient) Clone() (util.Client, error) {
	clonedClient, err := p.client.Clone()
	if err != nil {
		return nil, err
	}
	return &PooledClient{
		client:       clonedClient,
		reAuthFunc:   p.reAuthFunc,
		tokenRevoked: p.tokenRevoked,
	}, nil
}

// pooledLogical wraps the Logical interface with retry logic for token expiration.
type pooledLogical struct {
	logical    util.Logical
	poolClient *PooledClient
}

// ReadWithDataWithContext reads a secret with data and context, with automatic retry on 403 errors.
func (p *pooledLogical) ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
	secret, err := p.logical.ReadWithDataWithContext(ctx, path, data)
	if err != nil && is403Error(err) && !p.poolClient.tokenRevoked {
		// Token may have expired, try re-authenticating once
		if reAuthErr := p.poolClient.reAuthFunc(ctx); reAuthErr != nil {
			return nil, fmt.Errorf("failed to re-authenticate after 403 error: %w", reAuthErr)
		}
		// Retry the operation with fresh token
		secret, err = p.logical.ReadWithDataWithContext(ctx, path, data)
	}
	return secret, err
}

// WriteWithContext writes a secret with context and automatic retry on 403 errors.
func (p *pooledLogical) WriteWithContext(ctx context.Context, path string, data map[string]any) (*vault.Secret, error) {
	secret, err := p.logical.WriteWithContext(ctx, path, data)
	if err != nil && is403Error(err) && !p.poolClient.tokenRevoked {
		// Token may have expired, try re-authenticating once
		if reAuthErr := p.poolClient.reAuthFunc(ctx); reAuthErr != nil {
			return nil, fmt.Errorf("failed to re-authenticate after 403 error: %w", reAuthErr)
		}
		// Retry the operation with fresh token
		secret, err = p.logical.WriteWithContext(ctx, path, data)
	}
	return secret, err
}

// ListWithContext lists secrets with context and automatic retry on 403 errors.
func (p *pooledLogical) ListWithContext(ctx context.Context, path string) (*vault.Secret, error) {
	secret, err := p.logical.ListWithContext(ctx, path)
	if err != nil && is403Error(err) && !p.poolClient.tokenRevoked {
		// Token may have expired, try re-authenticating once
		if reAuthErr := p.poolClient.reAuthFunc(ctx); reAuthErr != nil {
			return nil, fmt.Errorf("failed to re-authenticate after 403 error: %w", reAuthErr)
		}
		// Retry the operation with fresh token
		secret, err = p.logical.ListWithContext(ctx, path)
	}
	return secret, err
}

// DeleteWithContext deletes a secret with context and automatic retry on 403 errors.
func (p *pooledLogical) DeleteWithContext(ctx context.Context, path string) (*vault.Secret, error) {
	secret, err := p.logical.DeleteWithContext(ctx, path)
	if err != nil && is403Error(err) && !p.poolClient.tokenRevoked {
		// Token may have expired, try re-authenticating once
		if reAuthErr := p.poolClient.reAuthFunc(ctx); reAuthErr != nil {
			return nil, fmt.Errorf("failed to re-authenticate after 403 error: %w", reAuthErr)
		}
		// Retry the operation with fresh token
		secret, err = p.logical.DeleteWithContext(ctx, path)
	}
	return secret, err
}

// is403Error checks if the error is a 403 Forbidden error indicating token expiration.
func is403Error(err error) bool {
	if err == nil {
		return false
	}
	// Check if it's a Vault ResponseError with 403 status code
	if respErr, ok := err.(*vault.ResponseError); ok {
		return respErr.StatusCode == 403
	}
	return false
}
