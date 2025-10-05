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
	ctrlmetrics "github.com/external-secrets/external-secrets/pkg/controllers/metrics"
)

const (
	ExternalSecretSubsystem = "externalsecret"
	providerAPICalls        = "provider_api_calls_count"
	storeAPICalls           = "store_api_calls_count"
)

var (
	syncCallsTotal     *prometheus.CounterVec
	storeAPICallsTotal *prometheus.CounterVec
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

func SetUpMetrics() {
	labels := []string{"provider", "call", "status"}

	syncCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      providerAPICalls,
		Help:      "Number of API calls towards the secret provider",
	}, labels)

	metrics.Registry.MustRegister(syncCallsTotal)

	// Store API calls metric with optional granular labels
	storeLabels := ctrlmetrics.WithGranularLabels(
		[]string{"provider", "call", "status"},
		"secretstore_kind", "secretstore_name", "secretstore_namespace",
	)

	storeAPICallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      storeAPICalls,
		Help:      "Number of controller-initiated API calls to secret providers, aggregated by SecretStore (requires --enable-granular-metrics). Does not include internal provider operations like auth retries.",
	}, storeLabels)

	metrics.Registry.MustRegister(storeAPICallsTotal)

	// Wire up the callback for StoreMetricsRecorder
	ctrlmetrics.SetObserveStoreAPICallFunc(ObserveStoreAPICall)
}

// ObserveStoreAPICall records a provider API call for a specific SecretStore.
// This metric is only recorded when --enable-granular-metrics is enabled.
// It aggregates API calls by SecretStore dimension, regardless of which resource triggered them.
func ObserveStoreAPICall(storeName, storeKind, storeNamespace, provider, call string, err error) {
	if !ctrlmetrics.EnableGranularMetrics {
		return
	}

	labels := prometheus.Labels{
		"provider":              provider,
		"call":                  call,
		"status":                deriveStatus(err),
		"secretstore_kind":      storeKind,
		"secretstore_name":      storeName,
		"secretstore_namespace": storeNamespace,
	}

	storeAPICallsTotal.With(labels).Inc()
}
