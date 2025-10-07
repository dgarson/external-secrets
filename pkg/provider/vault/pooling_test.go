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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// TestExtractCredentialsAndBuildKey verifies that the cache key generation works correctly
// and detects credential changes via ResourceVersion.
func TestExtractCredentialsAndBuildKey(t *testing.T) {
	// Create test secret with credentials
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "vault-secret",
			Namespace:       "default",
			ResourceVersion: "12345",
		},
		Data: map[string][]byte{
			"role-id":   []byte("test-role-id"),
			"secret-id": []byte("test-secret-id"),
		},
	}

	kubeClient := clientfake.NewClientBuilder().
		WithObjects(secret).
		Build()

	vaultSpec := &esv1.VaultProvider{
		Server:  "https://vault.example.com",
		Path:    ptr.To("secret"),
		Version: esv1.VaultKVStoreV2,
		Auth: &esv1.VaultAuth{
			AppRole: &esv1.VaultAppRole{
				Path: "approle",
				RoleRef: &esmeta.SecretKeySelector{
					Name: "vault-secret",
					Key:  "role-id",
				},
				SecretRef: esmeta.SecretKeySelector{
					Name: "vault-secret",
					Key:  "secret-id",
				},
			},
		},
	}

	// Build cache key with initial ResourceVersion
	key1, err := buildClientPoolKey(
		context.Background(),
		nil, // typedcorev1 not needed for this test
		vaultSpec,
		kubeClient,
		"SecretStore",
		"default",
	)
	if err != nil {
		t.Fatalf("Failed to build cache key: %v", err)
	}

	// Verify key fields
	if key1.Server != "https://vault.example.com" {
		t.Errorf("Expected server 'https://vault.example.com', got '%s'", key1.Server)
	}
	if key1.AuthMethod != "approle" {
		t.Errorf("Expected auth method 'approle', got '%s'", key1.AuthMethod)
	}
	if key1.AuthPath != "approle" {
		t.Errorf("Expected auth path 'approle', got '%s'", key1.AuthPath)
	}

	// Build same key again - should be identical
	key2, err := buildClientPoolKey(
		context.Background(),
		nil,
		vaultSpec,
		kubeClient,
		"SecretStore",
		"default",
	)
	if err != nil {
		t.Fatalf("Failed to build cache key second time: %v", err)
	}

	if key1.String() != key2.String() {
		t.Errorf("Expected identical cache keys for same credentials, got different keys")
	}

	// Create new client with updated secret that has different ResourceVersion
	secret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "vault-secret",
			Namespace:       "default",
			ResourceVersion: "99999", // Different ResourceVersion
		},
		Data: map[string][]byte{
			"role-id":   []byte("test-role-id"),
			"secret-id": []byte("test-secret-id"),
		},
	}

	kubeClient2 := clientfake.NewClientBuilder().
		WithObjects(secret2).
		Build()

	// Build cache key with new ResourceVersion - should be different
	key3, err := buildClientPoolKey(
		context.Background(),
		nil,
		vaultSpec,
		kubeClient2,
		"SecretStore",
		"default",
	)
	if err != nil {
		t.Fatalf("Failed to build cache key after update: %v", err)
	}

	if key1.String() == key3.String() {
		t.Errorf("Expected different cache keys after ResourceVersion change, got same key")
	}
}

// TestExtractCredentialsServiceAccount verifies cache key generation for ServiceAccount-based auth.
func TestExtractCredentialsServiceAccount(t *testing.T) {
	// Create ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-sa",
			Namespace:       "default",
			ResourceVersion: "67890",
		},
	}

	kubeClient := clientfake.NewClientBuilder().
		WithObjects(sa).
		Build()

	vaultSpec := &esv1.VaultProvider{
		Server:  "https://vault.example.com",
		Path:    ptr.To("secret"),
		Version: esv1.VaultKVStoreV2,
		Auth: &esv1.VaultAuth{
			Kubernetes: &esv1.VaultKubernetesAuth{
				Path: "kubernetes",
				Role: "test-role",
				ServiceAccountRef: &esmeta.ServiceAccountSelector{
					Name:      "test-sa",
					Audiences: []string{"vault"},
				},
			},
		},
	}

	// Build cache key with initial ResourceVersion
	key1, err := buildClientPoolKey(
		context.Background(),
		nil,
		vaultSpec,
		kubeClient,
		"SecretStore",
		"default",
	)
	if err != nil {
		t.Fatalf("Failed to build cache key: %v", err)
	}

	if key1.AuthMethod != "kubernetes" {
		t.Errorf("Expected auth method 'kubernetes', got '%s'", key1.AuthMethod)
	}

	// Create new client with updated SA that has different ResourceVersion
	sa2 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-sa",
			Namespace:       "default",
			ResourceVersion: "88888", // Different ResourceVersion
		},
	}

	kubeClient2 := clientfake.NewClientBuilder().
		WithObjects(sa2).
		Build()

	// Build cache key with new ResourceVersion - should be different
	key2, err := buildClientPoolKey(
		context.Background(),
		nil,
		vaultSpec,
		kubeClient2,
		"SecretStore",
		"default",
	)
	if err != nil {
		t.Fatalf("Failed to build cache key after update: %v", err)
	}

	if key1.String() == key2.String() {
		t.Errorf("Expected different cache keys after ServiceAccount ResourceVersion change, got same key")
	}
}

// TestClientPoolKeyString verifies that the String() method produces stable, deterministic output.
func TestClientPoolKeyString(t *testing.T) {
	key := ClientPoolKey{
		Server:              "https://vault.example.com",
		Namespace:           ptr.To("test-ns"),
		AuthMethod:          "approle",
		AuthPath:            "approle",
		CredentialIdentity:  "roleID:test-role|rv:12345",
		ReadYourWrites:      true,
		ForwardInconsistent: false,
		Headers: map[string]string{
			"X-Custom": "value",
		},
	}

	// Get string representation twice
	str1 := key.String()
	str2 := key.String()

	// Should be identical (deterministic)
	if str1 != str2 {
		t.Errorf("Expected stable String() output, got different values")
	}

	// Should contain the server URL
	if !strings.Contains(str1, "https://vault.example.com") {
		t.Errorf("Expected cache key to contain server URL, got: %s", str1)
	}

	// Should contain pipe separators
	if !strings.Contains(str1, "|") {
		t.Errorf("Expected cache key to use pipe separators, got: %s", str1)
	}

	// Should contain credential identity with ResourceVersion
	if !strings.Contains(str1, "roleID:test-role|rv:12345") {
		t.Errorf("Expected cache key to contain credential identity, got: %s", str1)
	}
}
