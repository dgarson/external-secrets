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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/external-secrets/external-secrets/pkg/constants"
)

const (
	ExternalSecretSubsystem = "externalsecret"
	providerAPICalls        = "provider_api_calls_count"
)

var (
	syncCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      providerAPICalls,
		Help:      "Number of API calls towards the secret provider",
	}, []string{"provider", "call", "status"})

	// Vault client pool metrics
	VaultClientPoolHits = prometheus.NewCounter(prometheus.CounterOpts{
		Subsystem: "vault",
		Name:      "client_pool_hits_total",
		Help:      "Total number of Vault client pool cache hits",
	})

	VaultClientPoolMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Subsystem: "vault",
		Name:      "client_pool_misses_total",
		Help:      "Total number of Vault client pool cache misses",
	})

	VaultClientPoolEvictions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: "vault",
		Name:      "client_pool_evictions_total",
		Help:      "Total number of Vault client pool evictions",
	}, []string{"reason"}) // reason: "ttl", "size"

	VaultClientPoolSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Subsystem: "vault",
		Name:      "client_pool_size",
		Help:      "Current number of clients in the Vault client pool",
	})

	VaultClientPoolAuthTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Subsystem: "vault",
		Name:      "client_pool_auth_duration_seconds",
		Help:      "Time spent authenticating to Vault",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	})
)

func ObserveAPICall(provider, call string, err error) {
	syncCallsTotal.WithLabelValues(provider, call, deriveStatus(err)).Inc()
}

func deriveStatus(err error) string {
	if err != nil {
		return constants.StatusError
	}
	return constants.StatusSuccess
}

func init() {
	metrics.Registry.MustRegister(
		syncCallsTotal,
		VaultClientPoolHits,
		VaultClientPoolMisses,
		VaultClientPoolEvictions,
		VaultClientPoolSize,
		VaultClientPoolAuthTime,
	)
}
