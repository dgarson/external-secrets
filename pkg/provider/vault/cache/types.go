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

package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

// CacheEntry holds a cached Vault client with token metadata.
// Used by ClientManager to store client instances.
type CacheEntry struct {
	Client      util.Client
	TokenExpiry time.Time
	Renewable   bool
	CreatedAt   time.Time
	CacheKey    string // For logging/debugging

	// Auth context for invalidation matching
	AuthContext *AuthContext

	mu sync.Mutex
}

// AuthContext stores auth-related info for cache invalidation.
type AuthContext struct {
	AuthMethod        string // "kubernetes", "approle", "jwt", etc.
	SecretRefs        []SecretReference
	ServiceAccountRef *ServiceAccountReference
}

// SecretReference identifies a Kubernetes Secret.
type SecretReference struct {
	Namespace string
	Name      string
}

// ServiceAccountReference identifies a Kubernetes ServiceAccount.
type ServiceAccountReference struct {
	Namespace string
	Name      string
}

// CacheConfig holds cache configuration.
type CacheConfig struct {
	Size          int
	RenewalWindow time.Duration // Time before expiry to trigger renewal (default: 5 minutes)
	EnableMetrics bool
}

// ClientConfig captures all inputs needed for client creation.
type ClientConfig struct {
	VaultAddr           string
	AuthMethod          string
	AuthParams          map[string]interface{} // Auth-specific params
	Namespace           string
	Headers             map[string]string
	TLSConfig           *TLSConfig
	RetrySettings       *RetrySettings
	ReadYourWrites      bool
	ForwardInconsistent bool

	// Auth context for tracking dependencies
	AuthContext *AuthContext
}

// TLSConfig holds TLS-related configuration.
type TLSConfig struct {
	CABundle       []byte
	CACertHash     string
	ClientCertHash string
	ClientKeyHash  string
}

// RetrySettings holds retry configuration.
type RetrySettings struct {
	MaxRetries    int
	RetryInterval time.Duration
}

// CacheStats holds cache statistics.
type CacheStats struct {
	Size          int
	Hits          int64
	Misses        int64
	Renewals      int64
	Invalidations int64
	Evictions     int64
}

// ComputeCacheKey creates a deterministic key from the config.
func (c *ClientConfig) ComputeCacheKey() string {
	h := sha256.New()

	// Core components in deterministic order
	h.Write([]byte(c.VaultAddr))
	h.Write([]byte(c.AuthMethod))
	h.Write([]byte(c.Namespace))

	// Auth params (sorted keys for determinism)
	if len(c.AuthParams) > 0 {
		authJSON, _ := json.Marshal(sortedMap(c.AuthParams))
		h.Write(authJSON)
	}

	// Headers (sorted keys)
	if len(c.Headers) > 0 {
		headersJSON, _ := json.Marshal(sortedStringMap(c.Headers))
		h.Write(headersJSON)
	}

	// TLS config
	if c.TLSConfig != nil {
		h.Write([]byte(c.TLSConfig.CACertHash))
		h.Write([]byte(c.TLSConfig.ClientCertHash))
		h.Write([]byte(c.TLSConfig.ClientKeyHash))
	}

	// Retry settings
	if c.RetrySettings != nil {
		h.Write([]byte(fmt.Sprintf("%d:%d", c.RetrySettings.MaxRetries, c.RetrySettings.RetryInterval)))
	}

	// Read-your-writes flags
	if c.ReadYourWrites {
		h.Write([]byte("ryw"))
	}
	if c.ForwardInconsistent {
		h.Write([]byte("fwd"))
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// sortedMap converts a map to a sorted representation for deterministic hashing.
func sortedMap(m map[string]interface{}) map[string]interface{} {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make(map[string]interface{}, len(m))
	for _, k := range keys {
		result[k] = m[k]
	}
	return result
}

// sortedStringMap converts a string map to a sorted representation for deterministic hashing.
func sortedStringMap(m map[string]string) map[string]string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make(map[string]string, len(m))
	for _, k := range keys {
		result[k] = m[k]
	}
	return result
}
