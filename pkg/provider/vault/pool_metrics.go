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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// poolMetrics provides Prometheus metrics for the client pool.
type poolMetrics struct {
	cacheHits      prometheus.Counter
	cacheMisses    prometheus.Counter
	poolSize       prometheus.Gauge
	authErrors     prometheus.Counter
	renewalErrors  prometheus.Counter
	reauthAttempts prometheus.Counter
	breakerBlocks  prometheus.Counter
}

var (
	metricsOnce    sync.Once
	globalMetrics  *poolMetrics
	metricsInitErr error
)

// newPoolMetrics creates and registers Prometheus metrics for the pool.
// Uses sync.Once to ensure metrics are only registered once.
func newPoolMetrics() *poolMetrics {
	metricsOnce.Do(func() {
		m := &poolMetrics{
			cacheHits: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "vault_client_pool_cache_hits_total",
				Help: "Total number of cache hits when acquiring clients",
			}),
			cacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "vault_client_pool_cache_misses_total",
				Help: "Total number of cache misses when acquiring clients",
			}),
			poolSize: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: "vault_client_pool_size",
				Help: "Current number of clients in the pool",
			}),
			authErrors: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "vault_client_pool_auth_errors_total",
				Help: "Total number of authentication errors",
			}),
			renewalErrors: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "vault_client_pool_renewal_errors_total",
				Help: "Total number of token renewal errors",
			}),
			reauthAttempts: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "vault_client_pool_reauth_attempts_total",
				Help: "Total number of re-authentication attempts",
			}),
			breakerBlocks: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "vault_client_pool_breaker_blocks_total",
				Help: "Total number of requests blocked by circuit breaker",
			}),
		}

		// Register all metrics
		prometheus.MustRegister(m.cacheHits)
		prometheus.MustRegister(m.cacheMisses)
		prometheus.MustRegister(m.poolSize)
		prometheus.MustRegister(m.authErrors)
		prometheus.MustRegister(m.renewalErrors)
		prometheus.MustRegister(m.reauthAttempts)
		prometheus.MustRegister(m.breakerBlocks)

		globalMetrics = m
	})

	return globalMetrics
}

// incrementCacheHits increments the cache hits counter.
func (m *poolMetrics) incrementCacheHits() {
	m.cacheHits.Inc()
}

// incrementCacheMisses increments the cache misses counter.
func (m *poolMetrics) incrementCacheMisses() {
	m.cacheMisses.Inc()
}

// setPoolSize sets the current pool size.
func (m *poolMetrics) setPoolSize(size int) {
	m.poolSize.Set(float64(size))
}

// incrementAuthErrors increments the authentication errors counter.
func (m *poolMetrics) incrementAuthErrors() {
	m.authErrors.Inc()
}

// incrementRenewalErrors increments the renewal errors counter.
func (m *poolMetrics) incrementRenewalErrors() {
	m.renewalErrors.Inc()
}

// incrementReauthAttempts increments the re-authentication attempts counter.
func (m *poolMetrics) incrementReauthAttempts() {
	m.reauthAttempts.Inc()
}

// incrementBreakerBlocks increments the circuit breaker blocks counter.
func (m *poolMetrics) incrementBreakerBlocks() {
	m.breakerBlocks.Inc()
}
