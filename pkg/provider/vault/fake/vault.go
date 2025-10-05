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

package fake

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	vault "github.com/hashicorp/vault/api"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

type LoginFn func(ctx context.Context, authMethod vault.AuthMethod) (*vault.Secret, error)
type Auth struct {
	LoginFn LoginFn
}

func (f Auth) Login(ctx context.Context, authMethod vault.AuthMethod) (*vault.Secret, error) {
	return f.LoginFn(ctx, authMethod)
}

type ReadWithDataWithContextFn func(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error)
type ListWithContextFn func(ctx context.Context, path string) (*vault.Secret, error)
type WriteWithContextFn func(ctx context.Context, path string, data map[string]any) (*vault.Secret, error)
type DeleteWithContextFn func(ctx context.Context, path string) (*vault.Secret, error)
type Logical struct {
	ReadWithDataWithContextFn ReadWithDataWithContextFn
	ListWithContextFn         ListWithContextFn
	WriteWithContextFn        WriteWithContextFn
	DeleteWithContextFn       DeleteWithContextFn
}

func (f Logical) DeleteWithContext(ctx context.Context, path string) (*vault.Secret, error) {
	return f.DeleteWithContextFn(ctx, path)
}
func NewDeleteWithContextFn(secret map[string]any, err error) DeleteWithContextFn {
	return func(ctx context.Context, path string) (*vault.Secret, error) {
		vault := &vault.Secret{
			Data: secret,
		}
		return vault, err
	}
}

func buildDataResponse(secret map[string]any, err error) (*vault.Secret, error) {
	if secret == nil {
		return nil, err
	}
	return &vault.Secret{Data: secret}, err
}

func buildMetadataResponse(secret map[string]any, err error) (*vault.Secret, error) {
	if secret == nil {
		return nil, err
	}
	// If the secret already has the expected metadata structure, return as-is
	if _, hasCustomMetadata := secret["custom_metadata"]; hasCustomMetadata {
		return &vault.Secret{Data: secret}, err
	}
	// Otherwise, wrap in custom_metadata for backwards compatibility
	metadata := make(map[string]any)
	metadata["custom_metadata"] = secret
	return &vault.Secret{Data: metadata}, err
}

func NewReadWithContextFn(secret map[string]any, err error) ReadWithDataWithContextFn {
	return func(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
		return buildDataResponse(secret, err)
	}
}

func NewReadMetadataWithContextFn(secret map[string]any, err error) ReadWithDataWithContextFn {
	return func(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
		return buildMetadataResponse(secret, err)
	}
}

func NewReadWithDataAndMetadataFn(dataSecret, metadataSecret map[string]any, dataErr, metadataErr error) ReadWithDataWithContextFn {
	return func(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
		// Check if this is a metadata path request
		if strings.Contains(path, "/metadata/") {
			return buildMetadataResponse(metadataSecret, metadataErr)
		}

		// This is a data path request
		return buildDataResponse(dataSecret, dataErr)
	}
}

func NewWriteWithContextFn(secret map[string]any, err error) WriteWithContextFn {
	return func(ctx context.Context, path string, data map[string]any) (*vault.Secret, error) {
		return &vault.Secret{Data: secret}, err
	}
}

func ExpectWriteWithContextValue(expected map[string]any) WriteWithContextFn {
	return func(ctx context.Context, path string, data map[string]any) (*vault.Secret, error) {
		if strings.Contains(path, "metadata") {
			return &vault.Secret{Data: data}, nil
		}
		if !reflect.DeepEqual(expected, data) {
			return nil, fmt.Errorf("expected: %v, got: %v", expected, data)
		}
		return &vault.Secret{Data: data}, nil
	}
}

func ExpectWriteWithContextNoCall() WriteWithContextFn {
	return func(_ context.Context, path string, data map[string]any) (*vault.Secret, error) {
		return nil, errors.New("fail")
	}
}

func ExpectDeleteWithContextNoCall() DeleteWithContextFn {
	return func(ctx context.Context, path string) (*vault.Secret, error) {
		return nil, errors.New("fail")
	}
}
func WriteChangingReadContext(secret map[string]any, l Logical) WriteWithContextFn {
	v := &vault.Secret{
		Data: secret,
	}
	return func(ctx context.Context, path string, data map[string]any) (*vault.Secret, error) {
		l.ReadWithDataWithContextFn = func(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
			return v, nil
		}
		return v, nil
	}
}

func (f Logical) ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
	return f.ReadWithDataWithContextFn(ctx, path, data)
}
func (f Logical) ListWithContext(ctx context.Context, path string) (*vault.Secret, error) {
	return f.ListWithContextFn(ctx, path)
}
func (f Logical) WriteWithContext(ctx context.Context, path string, data map[string]any) (*vault.Secret, error) {
	return f.WriteWithContextFn(ctx, path, data)
}

type RevokeSelfWithContextFn func(ctx context.Context, token string) error
type LookupSelfWithContextFn func(ctx context.Context) (*vault.Secret, error)
type RenewSelfWithContextFn func(ctx context.Context, increment int) (*vault.Secret, error)

type Token struct {
	RevokeSelfWithContextFn RevokeSelfWithContextFn
	LookupSelfWithContextFn LookupSelfWithContextFn
	RenewSelfWithContextFn  RenewSelfWithContextFn

	// Test tracking fields
	mu            sync.Mutex
	revokeCalls   int
	renewCalls    int
	revokedTokens map[string]bool
	tokenValid    bool
}

func (f *Token) RevokeSelfWithContext(ctx context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls++
	if f.revokedTokens == nil {
		f.revokedTokens = make(map[string]bool)
	}
	f.revokedTokens[token] = true
	f.tokenValid = false

	if f.RevokeSelfWithContextFn != nil {
		return f.RevokeSelfWithContextFn(ctx, token)
	}
	return nil
}

func (f *Token) LookupSelfWithContext(ctx context.Context) (*vault.Secret, error) {
	if f.LookupSelfWithContextFn != nil {
		return f.LookupSelfWithContextFn(ctx)
	}
	return &vault.Secret{}, nil
}

func (f *Token) RenewSelfWithContext(ctx context.Context, increment int) (*vault.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewCalls++

	if f.RenewSelfWithContextFn != nil {
		return f.RenewSelfWithContextFn(ctx, increment)
	}
	return &vault.Secret{}, nil
}

// GetRevokeCalls returns the number of token revocation calls made
func (f *Token) GetRevokeCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revokeCalls
}

// GetRenewCalls returns the number of token renewal calls made
func (f *Token) GetRenewCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.renewCalls
}

// IsTokenRevoked checks if a specific token was revoked
func (f *Token) IsTokenRevoked(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokedTokens == nil {
		return false
	}
	return f.revokedTokens[token]
}

// IsTokenValid returns whether the token is currently valid
func (f *Token) IsTokenValid() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenValid
}

// ResetCalls resets all call counters
func (f *Token) ResetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls = 0
	f.renewCalls = 0
	f.revokedTokens = make(map[string]bool)
}

type MockSetTokenFn func(v string)

type MockTokenFn func() string

type MockClearTokenFn func()

type MockNamespaceFn func() string

type MockSetNamespaceFn func(namespace string)

type MockAddHeaderFn func(key, value string)

type VaultListResponse struct {
	Metadata *vault.Response
	Data     *vault.Response
}

func NewAuthTokenFn() *Token {
	t := &Token{
		RevokeSelfWithContextFn: nil,
		LookupSelfWithContextFn: func(ctx context.Context) (*vault.Secret, error) {
			return &(vault.Secret{}), nil
		},
		RenewSelfWithContextFn: nil,
		tokenValid:             true,
	}
	return t
}

// NewAuthTokenFnWithTTL creates a Token with configurable TTL and renewability
func NewAuthTokenFnWithTTL(ttl int, renewable bool) *Token {
	t := &Token{
		RevokeSelfWithContextFn: nil,
		LookupSelfWithContextFn: func(ctx context.Context) (*vault.Secret, error) {
			return &vault.Secret{
				Auth: &vault.SecretAuth{
					LeaseDuration: ttl,
					Renewable:     renewable,
				},
				Data: map[string]interface{}{
					"ttl":       ttl,
					"renewable": renewable,
				},
			}, nil
		},
		RenewSelfWithContextFn: func(ctx context.Context, increment int) (*vault.Secret, error) {
			return &vault.Secret{
				Auth: &vault.SecretAuth{
					LeaseDuration: ttl,
					Renewable:     renewable,
				},
			}, nil
		},
		tokenValid: true,
	}
	return t
}

func NewSetTokenFn(ofn ...func(v string)) MockSetTokenFn {
	return func(v string) {
		for _, fn := range ofn {
			fn(v)
		}
	}
}

func NewTokenFn(v string) MockTokenFn {
	return func() string {
		return v
	}
}

func NewClearTokenFn() MockClearTokenFn {
	return func() {
		// no-op
	}
}

func NewAddHeaderFn() MockAddHeaderFn {
	return func(key, value string) {
		// no header
	}
}

type VaultClient struct {
	MockLogical      Logical
	MockAuth         Auth
	MockAuthToken    *Token
	MockSetToken     MockSetTokenFn
	MockToken        MockTokenFn
	MockClearToken   MockClearTokenFn
	MockNamespace    MockNamespaceFn
	MockSetNamespace MockSetNamespaceFn
	MockAddHeader    MockAddHeaderFn

	namespace       string
	lock            sync.RWMutex
	authAttempts    int
	authAttemptsMu  sync.Mutex
	simulateUnavail bool
	unavailMu       sync.Mutex
	currentToken    string
	tokenMu         sync.Mutex
}

// GetAuthAttempts returns the number of authentication attempts
func (c *VaultClient) GetAuthAttempts() int {
	c.authAttemptsMu.Lock()
	defer c.authAttemptsMu.Unlock()
	return c.authAttempts
}

// IncrementAuthAttempts increments the authentication attempt counter
func (c *VaultClient) IncrementAuthAttempts() {
	c.authAttemptsMu.Lock()
	defer c.authAttemptsMu.Unlock()
	c.authAttempts++
}

// ResetAuthAttempts resets the authentication attempt counter
func (c *VaultClient) ResetAuthAttempts() {
	c.authAttemptsMu.Lock()
	defer c.authAttemptsMu.Unlock()
	c.authAttempts = 0
}

// SetSimulateUnavailable simulates Vault being unavailable
func (c *VaultClient) SetSimulateUnavailable(unavail bool) {
	c.unavailMu.Lock()
	defer c.unavailMu.Unlock()
	c.simulateUnavail = unavail
}

// IsSimulatingUnavailable returns whether Vault unavailability is being simulated
func (c *VaultClient) IsSimulatingUnavailable() bool {
	c.unavailMu.Lock()
	defer c.unavailMu.Unlock()
	return c.simulateUnavail
}

// GetCurrentToken returns the currently set token
func (c *VaultClient) GetCurrentToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.currentToken
}

// SetCurrentToken sets the current token
func (c *VaultClient) SetCurrentToken(token string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.currentToken = token
}

func (c *VaultClient) Logical() Logical {
	return c.MockLogical
}

func NewVaultLogical() Logical {
	logical := Logical{
		ReadWithDataWithContextFn: func(ctx context.Context, path string, data map[string][]string) (*vault.Secret, error) {
			return nil, nil
		},
		ListWithContextFn: func(ctx context.Context, path string) (*vault.Secret, error) {
			return nil, nil
		},
		WriteWithContextFn: func(ctx context.Context, path string, data map[string]any) (*vault.Secret, error) {
			return nil, nil
		},
	}
	return logical
}
func (c *VaultClient) Auth() Auth {
	return c.MockAuth
}

func NewVaultAuth() Auth {
	auth := Auth{
		LoginFn: func(ctx context.Context, authMethod vault.AuthMethod) (*vault.Secret, error) {
			return nil, nil
		},
	}
	return auth
}
func (c *VaultClient) AuthToken() *Token {
	return c.MockAuthToken
}

func (c *VaultClient) SetToken(v string) {
	c.MockSetToken(v)
}

func (c *VaultClient) Token() string {
	return c.MockToken()
}

func (c *VaultClient) ClearToken() {
	c.MockClearToken()
}

func (c *VaultClient) Namespace() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	ns := c.namespace
	return ns
}

func (c *VaultClient) SetNamespace(namespace string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.namespace = namespace
}

func (c *VaultClient) AddHeader(key, value string) {
	c.MockAddHeader(key, value)
}

func ClientWithLoginMock(config *vault.Config) (util.Client, error) {
	return clientWithLoginMockOptions(config)
}

func ModifiableClientWithLoginMock(opts ...func(cl *VaultClient)) func(config *vault.Config) (util.Client, error) {
	return func(config *vault.Config) (util.Client, error) {
		return clientWithLoginMockOptions(config, opts...)
	}
}

func clientWithLoginMockOptions(_ *vault.Config, opts ...func(cl *VaultClient)) (util.Client, error) {
	cl := &VaultClient{
		MockAuthToken: NewAuthTokenFn(),
		MockSetToken:  NewSetTokenFn(),
		MockToken:     NewTokenFn(""),
		MockAuth:      NewVaultAuth(),
		MockLogical:   NewVaultLogical(),
	}

	for _, opt := range opts {
		opt(cl)
	}

	return &util.VaultClient{
		SetTokenFunc:     cl.SetToken,
		TokenFunc:        cl.Token,
		ClearTokenFunc:   cl.ClearToken,
		AuthField:        cl.Auth(),
		AuthTokenField:   cl.AuthToken(),
		LogicalField:     cl.Logical(),
		NamespaceFunc:    cl.Namespace,
		SetNamespaceFunc: cl.SetNamespace,
		AddHeaderFunc:    cl.AddHeader,
	}, nil
}
