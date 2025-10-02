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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// VaultClientCacheKey uniquely identifies a Vault client based on its
// connection properties and authentication identity.
// Two configurations that would produce the same authenticated Vault token
// should have the same cache key.
type VaultClientCacheKey struct {
	// Server is the Vault server URL
	Server string `json:"server"`

	// VaultAuthNamespace is the Vault namespace where authentication occurs.
	// This is auth.Namespace if set, otherwise provider.Namespace.
	VaultAuthNamespace string `json:"vaultAuthNamespace"`

	// AuthMethod identifies the authentication method being used.
	// Examples: "kubernetes", "approle", "jwt", "ldap", "userpass", "cert", "iam", "token"
	AuthMethod string `json:"authMethod"`

	// AuthConfigHash is a SHA256 hash of the authentication configuration
	// specific to the AuthMethod. This includes paths, roles, and credential
	// references, but excludes the actual credential values.
	AuthConfigHash string `json:"authConfigHash"`

	// CredentialNamespace is the Kubernetes namespace used for resolving
	// credential references (secrets, service accounts). This is only set
	// for referent specs where credentials are namespace-dependent.
	CredentialNamespace string `json:"credentialNamespace,omitempty"`

	// TLSConfigHash is a SHA256 hash of the client TLS configuration.
	// This includes certificate and key references but not the actual certs.
	TLSConfigHash string `json:"tlsConfigHash"`

	// VaultSecretsNamespace is the Vault namespace for reading/writing secrets.
	// This is provider.Namespace and can differ from VaultAuthNamespace when
	// authenticating in one namespace but accessing secrets in another.
	VaultSecretsNamespace string `json:"vaultSecretsNamespace,omitempty"`

	// HeadersHash is a SHA256 hash of custom headers (excluding auth-related headers).
	// Headers are sorted for deterministic output.
	HeadersHash string `json:"headersHash"`
}

// String returns a string representation of the cache key for debugging.
func (k VaultClientCacheKey) String() string {
	return fmt.Sprintf("server=%s,authNS=%s,method=%s,authHash=%s,credNS=%s,tlsHash=%s,secretsNS=%s,headersHash=%s",
		k.Server, k.VaultAuthNamespace, k.AuthMethod, k.AuthConfigHash[:8],
		k.CredentialNamespace, k.TLSConfigHash[:8], k.VaultSecretsNamespace, k.HeadersHash[:8])
}

// ComputeCacheKey computes the cache key for a Vault client configuration.
func ComputeCacheKey(config AcquireClientConfig) (VaultClientCacheKey, error) {
	key := VaultClientCacheKey{
		Server: config.VaultProvider.Server,
	}

	// Compute effective auth namespace (where authentication happens)
	if config.VaultProvider.Auth != nil && config.VaultProvider.Auth.Namespace != nil {
		key.VaultAuthNamespace = *config.VaultProvider.Auth.Namespace
	} else if config.VaultProvider.Namespace != nil {
		key.VaultAuthNamespace = *config.VaultProvider.Namespace
	}

	// Determine auth method and compute auth config hash
	authMethod, authHash, err := computeAuthHash(config.VaultProvider.Auth, config.Namespace, config.StoreKind)
	if err != nil {
		return key, fmt.Errorf("failed to compute auth hash: %w", err)
	}
	key.AuthMethod = authMethod
	key.AuthConfigHash = authHash

	// Set credential namespace for referent specs
	// This ensures different K8s namespaces get separate cache entries when
	// using ClusterSecretStore with namespace-relative credential references
	if config.StoreKind == esv1.ClusterSecretStoreKind &&
		config.Namespace != "" &&
		isReferentSpec(config.VaultProvider) {
		key.CredentialNamespace = config.Namespace
	}

	// Compute TLS config hash
	tlsHash, err := computeTLSHash(&config.VaultProvider.ClientTLS)
	if err != nil {
		return key, fmt.Errorf("failed to compute TLS hash: %w", err)
	}
	key.TLSConfigHash = tlsHash

	// Set secrets namespace (where secrets are read/written)
	if config.VaultProvider.Namespace != nil {
		key.VaultSecretsNamespace = *config.VaultProvider.Namespace
	}

	// Compute headers hash (excluding auth-related headers)
	headersHash, err := computeHeadersHash(config.VaultProvider.Headers)
	if err != nil {
		return key, fmt.Errorf("failed to compute headers hash: %w", err)
	}
	key.HeadersHash = headersHash

	return key, nil
}

// computeAuthHash returns the auth method name and a hash of the auth configuration.
func computeAuthHash(auth *esv1.VaultAuth, credentialNS, storeKind string) (string, string, error) {
	if auth == nil {
		return "none", hashString(""), nil
	}

	// Determine which auth method is configured and compute its hash
	// We use a normalized structure for each method to ensure deterministic hashing

	if auth.TokenSecretRef != nil {
		hash, err := hashObject(map[string]interface{}{
			"secretRef": normalizeSecretKeySelector(auth.TokenSecretRef, credentialNS, storeKind),
		})
		return "token", hash, err
	}

	if auth.AppRole != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":      auth.AppRole.Path,
			"roleId":    auth.AppRole.RoleID,
			"roleRef":   normalizeSecretKeySelector(auth.AppRole.RoleRef, credentialNS, storeKind),
			"secretRef": normalizeSecretKeySelector(&auth.AppRole.SecretRef, credentialNS, storeKind),
		})
		return "approle", hash, err
	}

	if auth.Kubernetes != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":              auth.Kubernetes.Path,
			"role":              auth.Kubernetes.Role,
			"serviceAccountRef": normalizeServiceAccountSelector(auth.Kubernetes.ServiceAccountRef, credentialNS, storeKind),
			"secretRef":         normalizeSecretKeySelector(auth.Kubernetes.SecretRef, credentialNS, storeKind),
		})
		return "kubernetes", hash, err
	}

	if auth.Ldap != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":      auth.Ldap.Path,
			"username":  auth.Ldap.Username,
			"secretRef": normalizeSecretKeySelector(&auth.Ldap.SecretRef, credentialNS, storeKind),
		})
		return "ldap", hash, err
	}

	if auth.UserPass != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":      auth.UserPass.Path,
			"username":  auth.UserPass.Username,
			"secretRef": normalizeSecretKeySelector(&auth.UserPass.SecretRef, credentialNS, storeKind),
		})
		return "userpass", hash, err
	}

	if auth.Jwt != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":                       auth.Jwt.Path,
			"role":                       auth.Jwt.Role,
			"secretRef":                  normalizeSecretKeySelector(auth.Jwt.SecretRef, credentialNS, storeKind),
			"kubernetesServiceAccountToken": normalizeKubernetesServiceAccountToken(auth.Jwt.KubernetesServiceAccountToken, credentialNS, storeKind),
		})
		return "jwt", hash, err
	}

	if auth.Cert != nil {
		hash, err := hashObject(map[string]interface{}{
			"clientCert": normalizeSecretKeySelector(&auth.Cert.ClientCert, credentialNS, storeKind),
			"secretRef":  normalizeSecretKeySelector(&auth.Cert.SecretRef, credentialNS, storeKind),
		})
		return "cert", hash, err
	}

	if auth.Iam != nil {
		hash, err := hashObject(map[string]interface{}{
			"path":                auth.Iam.Path,
			"region":              auth.Iam.Region,
			"awsIAMRole":          auth.Iam.AWSIAMRole,
			"vaultRole":           auth.Iam.Role,
			"externalID":          auth.Iam.ExternalID,
			"vaultAwsIamServerID": auth.Iam.VaultAWSIAMServerID,
			"secretRef":           normalizeVaultAwsAuthSecretRef(auth.Iam.SecretRef, credentialNS, storeKind),
			"jwtAuth":             normalizeVaultAwsJWTAuth(auth.Iam.JWTAuth, credentialNS, storeKind),
		})
		return "iam", hash, err
	}

	return "unknown", hashString(""), nil
}

// computeTLSHash computes a hash of the TLS configuration.
func computeTLSHash(tls *esv1.VaultClientTLS) (string, error) {
	if tls == nil {
		return hashString(""), nil
	}

	// We hash the references to the cert/key, not the actual values
	// This is because the actual cert/key values might change but if the
	// reference is the same, we assume it's the same identity
	return hashObject(map[string]interface{}{
		"certSecretRef": normalizeSecretKeySelector(tls.CertSecretRef, "", ""),
		"keySecretRef":  normalizeSecretKeySelector(tls.KeySecretRef, "", ""),
	})
}

// computeHeadersHash computes a hash of custom headers, excluding auth-related headers.
// Headers are sorted for deterministic output.
func computeHeadersHash(headers map[string]string) (string, error) {
	if len(headers) == 0 {
		return hashString(""), nil
	}

	// Exclude auth-related headers that we manage ourselves
	excludedHeaders := map[string]bool{
		"authorization":      true,
		"x-vault-token":      true,
		"x-vault-namespace":  true,
	}

	// Filter and collect non-auth headers
	filtered := make(map[string]string)
	for k, v := range headers {
		if !excludedHeaders[strings.ToLower(k)] {
			filtered[k] = v
		}
	}

	// Sort keys for deterministic hashing
	keys := make([]string, 0, len(filtered))
	for k := range filtered {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build sorted map for hashing
	sortedHeaders := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		sortedHeaders = append(sortedHeaders, map[string]string{
			"key":   k,
			"value": filtered[k],
		})
	}

	return hashObject(sortedHeaders)
}

// normalizeSecretKeySelector converts a SecretKeySelector to a normalized form
// for hashing, resolving namespace based on store kind and credential namespace.
func normalizeSecretKeySelector(sel interface{}, credentialNS, storeKind string) interface{} {
	if sel == nil {
		return nil
	}

	// Type assertion to get the actual selector
	switch s := sel.(type) {
	case *esmeta.SecretKeySelector:
		if s == nil {
			return nil
		}
		ns := ""
		if s.Namespace != nil {
			ns = *s.Namespace
		} else if storeKind == esv1.ClusterSecretStoreKind {
			ns = credentialNS
		}
		return map[string]interface{}{
			"name":      s.Name,
			"namespace": ns,
			"key":       s.Key,
		}
	default:
		return sel
	}
}

// normalizeServiceAccountSelector normalizes a ServiceAccountSelector.
func normalizeServiceAccountSelector(sel interface{}, credentialNS, storeKind string) interface{} {
	if sel == nil {
		return nil
	}

	switch s := sel.(type) {
	case *esmeta.ServiceAccountSelector:
		if s == nil {
			return nil
		}
		ns := ""
		if s.Namespace != nil {
			ns = *s.Namespace
		} else if storeKind == esv1.ClusterSecretStoreKind {
			ns = credentialNS
		}
		return map[string]interface{}{
			"name":      s.Name,
			"namespace": ns,
			"audiences": s.Audiences,
		}
	default:
		return sel
	}
}

// normalizeKubernetesServiceAccountToken normalizes VaultKubernetesServiceAccountTokenAuth.
func normalizeKubernetesServiceAccountToken(token interface{}, credentialNS, storeKind string) interface{} {
	if token == nil {
		return nil
	}

	switch t := token.(type) {
	case *esv1.VaultKubernetesServiceAccountTokenAuth:
		if t == nil {
			return nil
		}
		return map[string]interface{}{
			"serviceAccountRef": normalizeServiceAccountSelector(&t.ServiceAccountRef, credentialNS, storeKind),
			"audiences":         t.Audiences,
			"expirationSeconds": t.ExpirationSeconds,
		}
	default:
		return token
	}
}

// normalizeVaultAwsAuthSecretRef normalizes VaultAwsAuthSecretRef.
func normalizeVaultAwsAuthSecretRef(ref *esv1.VaultAwsAuthSecretRef, credentialNS, storeKind string) interface{} {
	if ref == nil {
		return nil
	}
	return map[string]interface{}{
		"accessKeyID":     normalizeSecretKeySelector(&ref.AccessKeyID, credentialNS, storeKind),
		"secretAccessKey": normalizeSecretKeySelector(&ref.SecretAccessKey, credentialNS, storeKind),
		"sessionToken":    normalizeSecretKeySelector(ref.SessionToken, credentialNS, storeKind),
	}
}

// normalizeVaultAwsJWTAuth normalizes VaultAwsJWTAuth.
func normalizeVaultAwsJWTAuth(auth *esv1.VaultAwsJWTAuth, credentialNS, storeKind string) interface{} {
	if auth == nil {
		return nil
	}
	return map[string]interface{}{
		"serviceAccountRef": normalizeServiceAccountSelector(auth.ServiceAccountRef, credentialNS, storeKind),
	}
}

// hashObject creates a deterministic hash of an object by marshaling to JSON.
func hashObject(obj interface{}) (string, error) {
	// Marshal to JSON for deterministic ordering
	data, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal object: %w", err)
	}
	return hashString(string(data)), nil
}

// hashString creates a SHA256 hash of a string.
func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash)
}
