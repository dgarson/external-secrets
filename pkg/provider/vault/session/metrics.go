package session

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	metricsSubsystem = "vault_token_cache"
	labelScope       = "scope"
	labelReason      = "reason"
)

var (
	cacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: metricsSubsystem,
		Name:      "hits_total",
		Help:      "Number of times a cached Vault client was reused without re-authentication.",
	}, []string{labelScope})

	cacheMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: metricsSubsystem,
		Name:      "misses_total",
		Help:      "Number of times a new Vault client/token had to be created.",
	}, []string{labelScope})

	cacheInvalidations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: metricsSubsystem,
		Name:      "invalidations_total",
		Help:      "Number of cached Vault clients invalidated due to fingerprint or auth issues.",
	}, []string{labelScope, labelReason})

	cacheEvictions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: metricsSubsystem,
		Name:      "evictions_total",
		Help:      "Number of cached Vault clients evicted due to capacity limits.",
	}, []string{labelScope})

	cacheEntries = prometheus.NewGauge(prometheus.GaugeOpts{
		Subsystem: metricsSubsystem,
		Name:      "entries",
		Help:      "Current number of active Vault client cache entries.",
	})
)

func init() {
	metrics.Registry.MustRegister(cacheHits, cacheMisses, cacheInvalidations, cacheEvictions, cacheEntries)
}

func observeCacheHit(scope string) {
	cacheHits.WithLabelValues(normalizeScope(scope)).Inc()
}

func observeCacheMiss(scope string) {
	cacheMisses.WithLabelValues(normalizeScope(scope)).Inc()
}

func observeCacheInvalidation(scope, reason string) {
	cacheInvalidations.WithLabelValues(normalizeScope(scope), reason).Inc()
}

func observeCacheEviction(scope string) {
	cacheEvictions.WithLabelValues(normalizeScope(scope)).Inc()
}

func setCacheEntries(count float64) {
	cacheEntries.Set(count)
}

func normalizeScope(scope string) string {
	if scope == "" {
		return "unknown"
	}
	return scope
}

// ResetMetricsForTest clears metric state for unit tests.
func ResetMetricsForTest() {
	cacheHits.Reset()
	cacheMisses.Reset()
	cacheInvalidations.Reset()
	cacheEvictions.Reset()
	cacheEntries.Set(0)
}
