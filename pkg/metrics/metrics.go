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
	ExternalSecretSubsystem      = "externalsecret"
	providerAPICalls             = "provider_api_calls_count"
	vaultClientPoolOperations    = "vault_client_pool_operations_total"
	vaultClientPoolSize          = "vault_client_pool_size"
	vaultClientTokenRenewals     = "vault_client_token_renewals_total"
	vaultClientTokenRenewalTimer = "vault_client_token_renewal_duration_seconds"
)

var (
	syncCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      providerAPICalls,
		Help:      "Number of API calls towards the secret provider",
	}, []string{"provider", "call", "status"})

	vaultClientPoolOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientPoolOperations,
		Help:      "Number of Vault client pool operations",
	}, []string{"operation", "status"})

	vaultClientPoolGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientPoolSize,
		Help:      "Current number of clients in the Vault client pool",
	})

	vaultTokenRenewals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientTokenRenewals,
		Help:      "Number of Vault token renewal attempts",
	}, []string{"status"})

	vaultTokenRenewalDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientTokenRenewalTimer,
		Help:      "Duration of Vault token renewal operations in seconds",
		Buckets:   prometheus.DefBuckets,
	})
)

func ObserveAPICall(provider, call string, err error) {
	syncCallsTotal.WithLabelValues(provider, call, deriveStatus(err)).Inc()
}

// ObserveVaultClientPoolOperation records a Vault client pool operation.
// operation can be: "cache_hit", "cache_miss", "client_created", "client_reauth", "pool_closed"
func ObserveVaultClientPoolOperation(operation string, err error) {
	vaultClientPoolOps.WithLabelValues(operation, deriveStatus(err)).Inc()
}

// SetVaultClientPoolSize sets the current size of the Vault client pool.
func SetVaultClientPoolSize(size int) {
	vaultClientPoolGauge.Set(float64(size))
}

// ObserveVaultTokenRenewal records a Vault token renewal attempt.
func ObserveVaultTokenRenewal(err error) {
	vaultTokenRenewals.WithLabelValues(deriveStatus(err)).Inc()
}

// ObserveVaultTokenRenewalDuration records the duration of a token renewal operation.
func ObserveVaultTokenRenewalDuration(seconds float64) {
	vaultTokenRenewalDuration.Observe(seconds)
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
		vaultClientPoolOps,
		vaultClientPoolGauge,
		vaultTokenRenewals,
		vaultTokenRenewalDuration,
	)
}
