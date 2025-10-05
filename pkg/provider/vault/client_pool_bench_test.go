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
	"testing"

	vault "github.com/hashicorp/vault/api"
	ctrl "sigs.k8s.io/controller-runtime"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// BenchmarkCacheKeyGeneration benchmarks cache key generation performance
func BenchmarkCacheKeyGeneration(b *testing.B) {
	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		Auth: &esv1.VaultAuth{
			AppRole: &esv1.VaultAppRole{
				Path: "approle",
			},
		},
	}

	config := VaultClientConfig{
		VaultConfig:    &vault.Config{},
		VaultSpec:      spec,
		StoreKind:      "SecretStore",
		StoreName:      "test",
		StoreNamespace: "default",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = computeCacheKey(config)
	}
}

// BenchmarkCircuitBreakerCheck benchmarks breaker check latency
func BenchmarkCircuitBreakerCheck(b *testing.B) {
	cb := newCircuitBreaker(BreakerConfig{
		Threshold:    5,
		OpenDuration: 30,
	})

	key := "test-key"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Check(key)
	}
}

// BenchmarkCircuitBreakerRecordSuccess benchmarks recording successes
func BenchmarkCircuitBreakerRecordSuccess(b *testing.B) {
	cb := newCircuitBreaker(BreakerConfig{
		Threshold:    5,
		OpenDuration: 30,
	})

	key := "test-key"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.RecordSuccess(key)
	}
}

// BenchmarkCircuitBreakerRecordFailure benchmarks recording failures
func BenchmarkCircuitBreakerRecordFailure(b *testing.B) {
	cb := newCircuitBreaker(BreakerConfig{
		Threshold:    1000000, // High threshold to avoid opening circuit
		OpenDuration: 30,
	})

	key := "test-key"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.RecordFailure(key)
	}
}

// BenchmarkMetricsIncrement benchmarks metrics increment operations
func BenchmarkMetricsIncrement(b *testing.B) {
	m := newPoolMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.incrementCacheHits()
	}
}

// BenchmarkPoolAcquireFailure benchmarks failed acquisition attempts
func BenchmarkPoolAcquireFailure(b *testing.B) {
	pool := NewCachingPool(PoolConfig{
		MaxSize: 100,
		Logger:  ctrl.Log.WithName("bench"),
	})
	defer func() {
		ctx := context.Background()
		pool.Shutdown(ctx)
	}()

	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		Auth: &esv1.VaultAuth{
			AppRole: &esv1.VaultAppRole{
				Path: "approle",
			},
		},
	}

	config := VaultClientConfig{
		VaultConfig:    &vault.Config{},
		VaultSpec:      spec,
		StoreKind:      "SecretStore",
		StoreName:      "test",
		StoreNamespace: "default",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pool.Acquire(context.Background(), config)
	}
}

// BenchmarkPoolConcurrentAcquireFailure benchmarks concurrent failed acquisitions
func BenchmarkPoolConcurrentAcquireFailure(b *testing.B) {
	pool := NewCachingPool(PoolConfig{
		MaxSize: 100,
		Logger:  ctrl.Log.WithName("bench-concurrent"),
	})
	defer func() {
		ctx := context.Background()
		pool.Shutdown(ctx)
	}()

	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		Auth: &esv1.VaultAuth{
			AppRole: &esv1.VaultAppRole{
				Path: "approle",
			},
		},
	}

	config := VaultClientConfig{
		VaultConfig:    &vault.Config{},
		VaultSpec:      spec,
		StoreKind:      "SecretStore",
		StoreName:      "test",
		StoreNamespace: "default",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = pool.Acquire(context.Background(), config)
		}
	})
}

// BenchmarkAuthMethodDetection benchmarks auth method detection
func BenchmarkAuthMethodDetection(b *testing.B) {
	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		Auth: &esv1.VaultAuth{
			AppRole: &esv1.VaultAppRole{
				Path: "approle",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getAuthMethod(spec)
	}
}

// BenchmarkIsAuthError benchmarks auth error detection
func BenchmarkIsAuthError(b *testing.B) {
	err := &vault.ResponseError{StatusCode: 401}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isAuthError(err)
	}
}

// BenchmarkDifferentCacheKeys benchmarks key generation with different configs
func BenchmarkDifferentCacheKeys(b *testing.B) {
	configs := make([]VaultClientConfig, 100)
	for i := 0; i < 100; i++ {
		configs[i] = VaultClientConfig{
			VaultConfig: &vault.Config{},
			VaultSpec: &esv1.VaultProvider{
				Server: fmt.Sprintf("https://vault-%d.example.com", i),
				Auth: &esv1.VaultAuth{
					AppRole: &esv1.VaultAppRole{
						Path: "approle",
					},
				},
			},
			StoreKind:      "SecretStore",
			StoreName:      fmt.Sprintf("store-%d", i),
			StoreNamespace: "default",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = computeCacheKey(configs[i%100])
	}
}

// BenchmarkPoolShutdown benchmarks shutdown performance
func BenchmarkPoolShutdown(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pool := NewCachingPool(PoolConfig{
			MaxSize: 10,
			Logger:  ctrl.Log.WithName("bench-shutdown"),
		})
		b.StartTimer()

		ctx := context.Background()
		pool.Shutdown(ctx)
	}
}

// BenchmarkIsStaticToken benchmarks static token detection
func BenchmarkIsStaticToken(b *testing.B) {
	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
		Auth: &esv1.VaultAuth{
			AppRole: &esv1.VaultAppRole{
				Path: "approle",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isStaticToken(spec)
	}
}
