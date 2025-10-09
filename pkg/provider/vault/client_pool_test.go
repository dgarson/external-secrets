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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	vault "github.com/hashicorp/vault/api"
)

func TestBuildCacheKey(t *testing.T) {
	tests := []struct {
		name         string
		vaultSpec    *esv1.VaultProvider
		authIdentity string
		expected     string
	}{
		{
			name: "basic configuration",
			vaultSpec: &esv1.VaultProvider{
				Server: "https://vault.example.com",
			},
			authIdentity: "k8s-sa:default:vault-client:reader:v12345",
			expected:     "https://vault.example.com||auth|k8s-sa:default:vault-client:reader:v12345",
		},
		{
			name: "with vault namespace",
			vaultSpec: &esv1.VaultProvider{
				Server:    "https://vault.example.com",
				Namespace: stringPtr("my-vault-ns"),
			},
			authIdentity: "k8s-sa:default:vault-client:reader:v12345",
			expected:     "https://vault.example.com|my-vault-ns|auth|k8s-sa:default:vault-client:reader:v12345",
		},
		{
			name: "with custom k8s auth path",
			vaultSpec: &esv1.VaultProvider{
				Server: "https://vault.example.com",
				Auth: &esv1.VaultAuth{
					Kubernetes: &esv1.VaultKubernetesAuth{
						Path: "custom-k8s",
						ServiceAccountRef: &esmeta.ServiceAccountSelector{
							Name: "vault-client",
						},
						Role: "reader",
					},
				},
			},
			authIdentity: "k8s-sa:default:vault-client:reader:v12345",
			expected:     "https://vault.example.com||custom-k8s|k8s-sa:default:vault-client:reader:v12345",
		},
		{
			name: "same credentials from different namespaces share client",
			vaultSpec: &esv1.VaultProvider{
				Server: "https://vault.example.com",
			},
			authIdentity: "token:vault-system:vault-token:v100",
			expected:     "https://vault.example.com||auth|token:vault-system:vault-token:v100",
		},
		{
			name: "different credentials produce different keys",
			vaultSpec: &esv1.VaultProvider{
				Server: "https://vault.example.com",
			},
			authIdentity: "k8s-sa:other-ns:other-client:writer:v67890",
			expected:     "https://vault.example.com||auth|k8s-sa:other-ns:other-client:writer:v67890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCacheKey(tt.vaultSpec, tt.authIdentity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAuthIdentity_KubernetesSA(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "vault-client",
			Namespace:       "default",
			ResourceVersion: "98765",
		},
	}
	fakeClient := fake.NewClientBuilder().WithObjects(sa).Build()

	auth := &esv1.VaultAuth{
		Kubernetes: &esv1.VaultKubernetesAuth{
			ServiceAccountRef: &esmeta.ServiceAccountSelector{
				Name: "vault-client",
			},
			Role: "reader",
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "k8s-sa:default:vault-client:reader:v98765", identity)
}

func TestGetAuthIdentity_IAM(t *testing.T) {
	auth := &esv1.VaultAuth{
		Iam: &esv1.VaultIamAuth{
			Region: "us-east-1",
			Role:   "my-vault-role",
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, nil, "default")
	require.NoError(t, err)
	assert.Equal(t, "iam:us-east-1:my-vault-role:controller-sa", identity)
}

func TestGetAuthIdentity_IAMWithServiceAccount(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "irsa-vault",
			Namespace:       "apps",
			ResourceVersion: "77777",
		},
	}
	fakeClient := fake.NewClientBuilder().WithObjects(sa).Build()

	auth := &esv1.VaultAuth{
		Iam: &esv1.VaultIamAuth{
			Region: "us-east-1",
			Role:   "my-vault-role",
			JWTAuth: &esv1.VaultAwsJWTAuth{
				ServiceAccountRef: &esmeta.ServiceAccountSelector{
					Name: "irsa-vault",
				},
			},
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "apps")
	require.NoError(t, err)
	assert.Equal(t, "iam:us-east-1:my-vault-role:sa:apps:irsa-vault:v77777", identity)
}

func TestGetAuthIdentity_IAMWithStaticCreds(t *testing.T) {
	credsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "aws-creds",
			Namespace:       "vault-system",
			ResourceVersion: "11111",
		},
		Data: map[string][]byte{
			"access-key": []byte("AKIAIOSFODNN7EXAMPLE"),
			"secret-key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}
	fakeClient := fake.NewClientBuilder().WithObjects(credsSecret).Build()

	vaultSystemNs := "vault-system"
	auth := &esv1.VaultAuth{
		Iam: &esv1.VaultIamAuth{
			Region: "us-west-2",
			Role:   "vault-role",
			SecretRef: &esv1.VaultAwsAuthSecretRef{
				AccessKeyID: esmeta.SecretKeySelector{
					Name:      "aws-creds",
					Key:       "access-key",
					Namespace: &vaultSystemNs,
				},
				SecretAccessKey: esmeta.SecretKeySelector{
					Name:      "aws-creds",
					Key:       "secret-key",
					Namespace: &vaultSystemNs,
				},
			},
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "iam:us-west-2:vault-role:ak:vault-system:aws-creds:v11111:sk:vault-system:aws-creds:v11111", identity)
}

func TestGetAuthIdentity_AppRole(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "approle-secret",
			Namespace:       "default",
			ResourceVersion: "12345",
		},
		Data: map[string][]byte{
			"secretId": []byte("my-secret-id"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithObjects(secret).Build()

	auth := &esv1.VaultAuth{
		AppRole: &esv1.VaultAppRole{
			RoleID: "my-role-id",
			SecretRef: esmeta.SecretKeySelector{
				Name: "approle-secret",
				Key:  "secretId",
			},
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "approle:my-role-id:secret:default:approle-secret:v12345", identity)
}

func TestGetAuthIdentity_Token(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "vault-token",
			Namespace:       "default",
			ResourceVersion: "67890",
		},
		Data: map[string][]byte{
			"token": []byte("my-vault-token"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithObjects(secret).Build()

	auth := &esv1.VaultAuth{
		TokenSecretRef: &esmeta.SecretKeySelector{
			Name: "vault-token",
			Key:  "token",
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "token:default:vault-token:v67890", identity)
}

func TestGetAuthIdentity_JWTFromSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "jwt-secret",
			Namespace:       "default",
			ResourceVersion: "11111",
		},
		Data: map[string][]byte{
			"jwt": []byte("my-jwt-token"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithObjects(secret).Build()

	auth := &esv1.VaultAuth{
		Jwt: &esv1.VaultJwtAuth{
			Role: "my-role",
			SecretRef: &esmeta.SecretKeySelector{
				Name: "jwt-secret",
				Key:  "jwt",
			},
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "jwt:my-role:secret:default:jwt-secret:v11111", identity)
}

func TestGetAuthIdentity_JWTFromServiceAccount(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "vault-sa",
			Namespace:       "default",
			ResourceVersion: "88888",
		},
	}
	fakeClient := fake.NewClientBuilder().WithObjects(sa).Build()

	auth := &esv1.VaultAuth{
		Jwt: &esv1.VaultJwtAuth{
			Role: "my-role",
			KubernetesServiceAccountToken: &esv1.VaultKubernetesServiceAccountTokenAuth{
				ServiceAccountRef: esmeta.ServiceAccountSelector{
					Name: "vault-sa",
				},
			},
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "jwt-sa:default:vault-sa:my-role:v88888", identity)
}

func TestGetAuthIdentity_Cert(t *testing.T) {
	certSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cert-secret",
			Namespace:       "default",
			ResourceVersion: "22222",
		},
		Data: map[string][]byte{
			"cert": []byte("cert-data"),
		},
	}

	keySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "key-secret",
			Namespace:       "default",
			ResourceVersion: "33333",
		},
		Data: map[string][]byte{
			"key": []byte("key-data"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithObjects(certSecret, keySecret).Build()

	auth := &esv1.VaultAuth{
		Cert: &esv1.VaultCertAuth{
			ClientCert: esmeta.SecretKeySelector{
				Name: "cert-secret",
				Key:  "cert",
			},
			SecretRef: esmeta.SecretKeySelector{
				Name: "key-secret",
				Key:  "key",
			},
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "cert:cert:default:cert-secret:v22222:key:default:key-secret:v33333", identity)
}

func TestGetAuthIdentity_LDAP(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "ldap-secret",
			Namespace:       "default",
			ResourceVersion: "44444",
		},
		Data: map[string][]byte{
			"password": []byte("my-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithObjects(secret).Build()

	auth := &esv1.VaultAuth{
		Ldap: &esv1.VaultLdapAuth{
			Username: "myuser",
			SecretRef: esmeta.SecretKeySelector{
				Name: "ldap-secret",
				Key:  "password",
			},
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "ldap:myuser:secret:default:ldap-secret:v44444", identity)
}

func TestGetAuthIdentity_UserPass(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "userpass-secret",
			Namespace:       "default",
			ResourceVersion: "55555",
		},
		Data: map[string][]byte{
			"password": []byte("my-password"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithObjects(secret).Build()

	auth := &esv1.VaultAuth{
		UserPass: &esv1.VaultUserPassAuth{
			Username: "myuser",
			SecretRef: esmeta.SecretKeySelector{
				Name: "userpass-secret",
				Key:  "password",
			},
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "userpass:myuser:secret:default:userpass-secret:v55555", identity)
}

func TestGetAuthIdentity_NoAuth(t *testing.T) {
	identity, err := getAuthIdentity(context.Background(), nil, nil, "default")
	require.NoError(t, err)
	assert.Equal(t, "no-auth", identity)
}

func TestGetAuthIdentity_UnknownAuth(t *testing.T) {
	auth := &esv1.VaultAuth{
		// Empty auth struct - no method specified
	}

	identity, err := getAuthIdentity(context.Background(), auth, nil, "default")
	require.NoError(t, err)
	assert.Equal(t, "unknown-auth", identity)
}

func TestGetAuthIdentity_SecretNotFound(t *testing.T) {
	fakeClient := fake.NewClientBuilder().Build()

	auth := &esv1.VaultAuth{
		TokenSecretRef: &esmeta.SecretKeySelector{
			Name: "non-existent-secret",
			Key:  "token",
		},
	}

	_, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get token secret")
}

func TestGetAuthIdentity_CrossNamespace(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "vault-token",
			Namespace:       "other-namespace",
			ResourceVersion: "99999",
		},
		Data: map[string][]byte{
			"token": []byte("my-vault-token"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithObjects(secret).Build()

	otherNs := "other-namespace"
	auth := &esv1.VaultAuth{
		TokenSecretRef: &esmeta.SecretKeySelector{
			Name:      "vault-token",
			Key:       "token",
			Namespace: &otherNs,
		},
	}

	identity, err := getAuthIdentity(context.Background(), auth, fakeClient, "default")
	require.NoError(t, err)
	assert.Equal(t, "token:other-namespace:vault-token:v99999", identity)
}

func TestComputeConfigDigest_InlineCABundleChange(t *testing.T) {
	spec1 := &esv1.VaultProvider{
		Server:   "https://vault.example.com",
		CABundle: []byte("bundle-a"),
	}
	spec2 := &esv1.VaultProvider{
		Server:   spec1.Server,
		CABundle: []byte("bundle-b"),
	}

	kube := fake.NewClientBuilder().Build()

	digest1, err := newDigestClient(t, kube, spec1).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)

	digest2, err := newDigestClient(t, kube, spec2).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)

	require.NotEqual(t, digest1, digest2)
}

func TestComputeConfigDigest_CAProviderResourceVersionChange(t *testing.T) {
	ns := "vault-system"
	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		CAProvider: &esv1.CAProvider{
			Type:      esv1.CAProviderTypeSecret,
			Name:      "ca-secret",
			Namespace: &ns,
		},
	}

	secretV1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "ca-secret",
			Namespace:       ns,
			ResourceVersion: "1",
		},
	}
	secretV2 := secretV1.DeepCopy()
	secretV2.ResourceVersion = "2"

	digest1, err := newDigestClient(t,
		fake.NewClientBuilder().WithObjects(secretV1).Build(),
		spec).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)

	digest2, err := newDigestClient(t,
		fake.NewClientBuilder().WithObjects(secretV2).Build(),
		spec).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)

	require.NotEqual(t, digest1, digest2)
}

func TestComputeConfigDigest_ClientTLSSecretChange(t *testing.T) {
	ns := "default"
	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		ClientTLS: esv1.VaultClientTLS{
			CertSecretRef: &esmeta.SecretKeySelector{
				Name:      "tls-cert",
				Namespace: &ns,
			},
			KeySecretRef: &esmeta.SecretKeySelector{
				Name:      "tls-key",
				Namespace: &ns,
			},
		},
	}

	certV1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "tls-cert",
			Namespace:       ns,
			ResourceVersion: "1",
		},
	}
	keyV1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "tls-key",
			Namespace:       ns,
			ResourceVersion: "1",
		},
	}
	certV2 := certV1.DeepCopy()
	certV2.ResourceVersion = "2"

	kube1 := fake.NewClientBuilder().WithObjects(certV1, keyV1).Build()
	digest1, err := newDigestClient(t, kube1, spec).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)

	kube2 := fake.NewClientBuilder().WithObjects(certV2, keyV1).Build()
	digest2, err := newDigestClient(t, kube2, spec).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)

	require.NotEqual(t, digest1, digest2)
}

func TestComputeConfigDigest_HeaderChange(t *testing.T) {
	spec1 := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		Headers: map[string]string{
			"X-Test": "one",
		},
	}
	spec2 := &esv1.VaultProvider{
		Server: spec1.Server,
		Headers: map[string]string{
			"X-Test": "two",
		},
	}

	kube := fake.NewClientBuilder().Build()

	digest1, err := newDigestClient(t, kube, spec1).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)
	digest2, err := newDigestClient(t, kube, spec2).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)

	require.NotEqual(t, digest1, digest2)
}

func TestComputeConfigDigest_HeaderOrderStable(t *testing.T) {
	spec1 := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		Headers: map[string]string{
			"A": "1",
			"B": "2",
		},
	}
	spec2 := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		Headers: map[string]string{
			"B": "2",
			"A": "1",
		},
	}

	kube := fake.NewClientBuilder().Build()

	digest1, err := newDigestClient(t, kube, spec1).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)
	digest2, err := newDigestClient(t, kube, spec2).computeConfigDigest(context.Background(), nil)
	require.NoError(t, err)

	require.Equal(t, digest1, digest2)
}

func TestComputeConfigDigest_StoreGenerationChange(t *testing.T) {
	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
	}
	storeV1 := &esv1.SecretStore{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "vault-store",
			Namespace:  "default",
			Generation: 1,
		},
	}
	storeV2 := storeV1.DeepCopy()
	storeV2.Generation = 2

	kube := fake.NewClientBuilder().Build()

	digest1, err := newDigestClient(t, kube, spec).computeConfigDigest(context.Background(), storeV1)
	require.NoError(t, err)

	digest2, err := newDigestClient(t, kube, spec).computeConfigDigest(context.Background(), storeV2)
	require.NoError(t, err)

	require.NotEqual(t, digest1, digest2)
}

func TestClientCloseSkipsRevokeForPooledClient(t *testing.T) {
	origPooling := enableVaultClientPooling
	origCache := enableCache
	t.Cleanup(func() {
		enableVaultClientPooling = origPooling
		enableCache = origCache
	})

	enableVaultClientPooling = true
	enableCache = false

	tokenCalled := false
	lookupCalled := false

	vaultClient := createTestVaultClient()
	origTokenFunc := vaultClient.TokenFunc
	vaultClient.TokenFunc = func() string {
		tokenCalled = true
		return origTokenFunc()
	}
	vaultClient.AuthTokenField = &mockToken{
		lookupFunc: func(ctx context.Context) (*vault.Secret, error) {
			lookupCalled = true
			return &vault.Secret{}, nil
		},
	}

	pooled := &pooledVaultClient{
		client:   vaultClient,
		cacheKey: "pooled-key",
		setAuth:  func(context.Context, *vault.Config) error { return nil },
	}

	c := &client{
		client: pooled,
		store: &esv1.VaultProvider{
			Auth: &esv1.VaultAuth{},
		},
		log: logger,
	}

	err := c.Close(context.Background())
	require.NoError(t, err)
	assert.False(t, tokenCalled, "pooled client should not inspect token on Close")
	assert.False(t, lookupCalled, "pooled client should not lookup token on Close")
}

// Helper function
func stringPtr(s string) *string {
	return &s
}

func newDigestClient(t *testing.T, kube ctrlclient.Client, spec *esv1.VaultProvider) *client {
	t.Helper()
	return &client{
		kube:      kube,
		store:     spec,
		log:       logger,
		namespace: "default",
		storeKind: esv1.SecretStoreKind,
	}
}

func TestRevokeTokenIfValidSkipsLookupWhenTokenEmpty(t *testing.T) {
	client := createTestVaultClient()
	client.TokenFunc = func() string { return "" }
	lookupCalled := false
	client.AuthTokenField = &mockToken{
		lookupFunc: func(ctx context.Context) (*vault.Secret, error) {
			lookupCalled = true
			return &vault.Secret{}, nil
		},
	}

	err := revokeTokenIfValid(context.Background(), client)
	require.NoError(t, err)
	assert.False(t, lookupCalled, "LookupSelf should not be called when token is empty")
}
