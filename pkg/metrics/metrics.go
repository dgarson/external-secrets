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
	ExternalSecretSubsystem           = "externalsecret"
	providerAPICalls                  = "provider_api_calls_count"
	vaultClientPoolOperations         = "vault_client_pool_operations_total"
	vaultClientPoolSize               = "vault_client_pool_size"
	vaultClientTokenRenewals          = "vault_client_token_renewals_total"
	vaultClientTokenRenewalTimer      = "vault_client_token_renewal_duration_seconds"
	vaultClientReauthBackoffSeconds   = "vault_client_reauth_backoff_seconds"
	vaultClientReauthAttempts         = "vault_client_reauth_attempts"
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
	}, []string{"operation", "status", "address"})

	vaultClientPoolGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientPoolSize,
		Help:      "Current number of clients in the Vault client pool",
	}, []string{"address"})

	vaultTokenRenewals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientTokenRenewals,
		Help:      "Number of Vault token renewal attempts",
	}, []string{"status", "address"})

	vaultTokenRenewalDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientTokenRenewalTimer,
		Help:      "Duration of Vault token renewal operations in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"address"})

	vaultReauthBackoffGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientReauthBackoffSeconds,
		Help:      "Current re-authentication backoff duration in seconds for Vault clients",
	}, []string{"address"})

	vaultReauthAttemptsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      vaultClientReauthAttempts,
		Help:      "Current consecutive re-authentication attempt count for Vault clients",
	}, []string{"address"})
)

func ObserveAPICall(provider, call string, err error) {
	syncCallsTotal.WithLabelValues(provider, call, deriveStatus(err)).Inc()
}

// ObserveVaultClientPoolOperation records a Vault client pool operation.
// operation can be: "cache_hit", "cache_miss", "client_created", "client_reauth", "pool_closed"
func ObserveVaultClientPoolOperation(operation, address string, err error) {
	vaultClientPoolOps.WithLabelValues(operation, deriveStatus(err), address).Inc()
}

// SetVaultClientPoolSize sets the current size of the Vault client pool.
func SetVaultClientPoolSize(address string, size int) {
	vaultClientPoolGauge.WithLabelValues(address).Set(float64(size))
}

// ObserveVaultTokenRenewal records a Vault token renewal attempt.
func ObserveVaultTokenRenewal(address string, err error) {
	vaultTokenRenewals.WithLabelValues(deriveStatus(err), address).Inc()
}

// ObserveVaultTokenRenewalDuration records the duration of a token renewal operation.
func ObserveVaultTokenRenewalDuration(address string, seconds float64) {
	vaultTokenRenewalDuration.WithLabelValues(address).Observe(seconds)
}

// SetVaultReauthBackoff sets the current re-authentication backoff duration.
func SetVaultReauthBackoff(address string, seconds float64) {
	vaultReauthBackoffGauge.WithLabelValues(address).Set(seconds)
}

// SetVaultReauthAttempts sets the current consecutive re-authentication attempt count.
func SetVaultReauthAttempts(address string, attempts int32) {
	vaultReauthAttemptsGauge.WithLabelValues(address).Set(float64(attempts))
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
		vaultReauthBackoffGauge,
		vaultReauthAttemptsGauge,
	)
}
