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
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// MetricsRecorder defines the interface for recording cache metrics.
type MetricsRecorder interface {
	RecordCacheHit()
	RecordCacheMiss()
	RecordRenewal(status string) // "success" or "failure"
	RecordLogin(authMethod string, duration time.Duration)
	RecordInvalidation(reason string)
	RecordRevocation()
	SetCacheSize(size int)
	GetStats() *CacheStats
}

// NoopMetrics is a no-op implementation of MetricsRecorder.
type NoopMetrics struct{}

func (n *NoopMetrics) RecordCacheHit()                                 {}
func (n *NoopMetrics) RecordCacheMiss()                                {}
func (n *NoopMetrics) RecordRenewal(status string)                     {}
func (n *NoopMetrics) RecordLogin(authMethod string, duration time.Duration) {}
func (n *NoopMetrics) RecordInvalidation(reason string)                {}
func (n *NoopMetrics) RecordRevocation()                               {}
func (n *NoopMetrics) SetCacheSize(size int)                           {}
func (n *NoopMetrics) GetStats() *CacheStats                           { return &CacheStats{} }

// PrometheusMetrics implements MetricsRecorder using Prometheus.
type PrometheusMetrics struct {
	cacheHits       prometheus.Counter
	cacheMisses     prometheus.Counter
	renewals        *prometheus.CounterVec
	logins          *prometheus.HistogramVec
	invalidations   *prometheus.CounterVec
	revocations     prometheus.Counter
	cacheSize       prometheus.Gauge

	// Stats for GetStats()
	hits          atomic.Int64
	misses        atomic.Int64
	renewalCount  atomic.Int64
	invalidCount  atomic.Int64
	revocationCount atomic.Int64
}

// NewPrometheusMetrics creates a new Prometheus metrics recorder.
func NewPrometheusMetrics() *PrometheusMetrics {
	pm := &PrometheusMetrics{
		cacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "externalsecrets_vault_client_cache_hits_total",
			Help: "Total number of Vault client cache hits",
		}),
		cacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "externalsecrets_vault_client_cache_misses_total",
			Help: "Total number of Vault client cache misses",
		}),
		renewals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "externalsecrets_vault_client_renewals_total",
			Help: "Total number of Vault token renewals",
		}, []string{"status"}),
		logins: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "externalsecrets_vault_client_login_duration_seconds",
			Help:    "Duration of Vault login operations",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
		}, []string{"auth_method"}),
		invalidations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "externalsecrets_vault_client_invalidations_total",
			Help: "Total number of cache invalidations",
		}, []string{"reason"}),
		revocations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "externalsecrets_vault_client_revocations_total",
			Help: "Total number of token revocations",
		}),
		cacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "externalsecrets_vault_client_cache_entries",
			Help: "Current number of entries in the Vault client cache",
		}),
	}

	// Register metrics
	metrics.Registry.MustRegister(
		pm.cacheHits,
		pm.cacheMisses,
		pm.renewals,
		pm.logins,
		pm.invalidations,
		pm.revocations,
		pm.cacheSize,
	)

	return pm
}

func (pm *PrometheusMetrics) RecordCacheHit() {
	pm.cacheHits.Inc()
	pm.hits.Add(1)
}

func (pm *PrometheusMetrics) RecordCacheMiss() {
	pm.cacheMisses.Inc()
	pm.misses.Add(1)
}

func (pm *PrometheusMetrics) RecordRenewal(status string) {
	pm.renewals.WithLabelValues(status).Inc()
	pm.renewalCount.Add(1)
}

func (pm *PrometheusMetrics) RecordLogin(authMethod string, duration time.Duration) {
	pm.logins.WithLabelValues(authMethod).Observe(duration.Seconds())
}

func (pm *PrometheusMetrics) RecordInvalidation(reason string) {
	pm.invalidations.WithLabelValues(reason).Inc()
	pm.invalidCount.Add(1)
}

func (pm *PrometheusMetrics) RecordRevocation() {
	pm.revocations.Inc()
	pm.revocationCount.Add(1)
}

func (pm *PrometheusMetrics) SetCacheSize(size int) {
	pm.cacheSize.Set(float64(size))
}

func (pm *PrometheusMetrics) GetStats() *CacheStats {
	return &CacheStats{
		Hits:          pm.hits.Load(),
		Misses:        pm.misses.Load(),
		Renewals:      pm.renewalCount.Load(),
		Invalidations: pm.invalidCount.Load(),
		Evictions:     pm.revocationCount.Load(),
	}
}
