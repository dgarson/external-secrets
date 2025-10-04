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
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	NonConditionMetricLabelNames = make([]string, 0)

	ConditionMetricLabelNames = make([]string, 0)

	NonConditionMetricLabels = make(map[string]string)

	ConditionMetricLabels = make(map[string]string)

	// EnableGranularMetrics controls whether granular labels (SecretStore refs, provider types, error categories) are added to metrics
	EnableGranularMetrics = false
)

var nonAlphanumericRegex *regexp.Regexp

func init() {
	nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)
}

// SetUpLabelNames initializes both non-conditional and conditional metric labels and label names.
func SetUpLabelNames(addKubeStandardLabels bool) {
	NonConditionMetricLabelNames = []string{"name", "namespace"}
	ConditionMetricLabelNames = []string{"name", "namespace", "condition", "status"}

	// Figure out what the labels for the metrics are
	if addKubeStandardLabels {
		NonConditionMetricLabelNames = append(
			NonConditionMetricLabelNames,
			"app_kubernetes_io_name", "app_kubernetes_io_instance",
			"app_kubernetes_io_version", "app_kubernetes_io_component",
			"app_kubernetes_io_part_of", "app_kubernetes_io_managed_by",
		)

		ConditionMetricLabelNames = append(
			ConditionMetricLabelNames,
			"app_kubernetes_io_name", "app_kubernetes_io_instance",
			"app_kubernetes_io_version", "app_kubernetes_io_component",
			"app_kubernetes_io_part_of", "app_kubernetes_io_managed_by",
		)
	}

	// Set default values for each label
	for _, k := range NonConditionMetricLabelNames {
		NonConditionMetricLabels[k] = ""
	}

	for _, k := range ConditionMetricLabelNames {
		ConditionMetricLabels[k] = ""
	}
}

// RefineLabels refines the given Prometheus Labels with values from a map `newLabels`
// Only overwrite a value if the corresponding key is present in the
// Prometheus' Labels already to avoid adding label names which are
// not defined in a metric's description. Note that non-alphanumeric
// characters from keys of `newLabels` are replaced by an underscore
// because Prometheus does not accept non-alphanumeric, non-underscore
// characters in label names.
func RefineLabels(promLabels prometheus.Labels, newLabels map[string]string) prometheus.Labels {
	var refinement = prometheus.Labels{}

	for k, v := range promLabels {
		refinement[k] = v
	}

	for k, v := range newLabels {
		cleanKey := nonAlphanumericRegex.ReplaceAllString(k, "_")
		if _, ok := refinement[cleanKey]; ok {
			refinement[cleanKey] = v
		}
	}

	return refinement
}

func RefineNonConditionMetricLabels(labels map[string]string) prometheus.Labels {
	return RefineLabels(NonConditionMetricLabels, labels)
}

func RefineConditionMetricLabels(labels map[string]string) prometheus.Labels {
	return RefineLabels(ConditionMetricLabels, labels)
}

// WithGranularLabels returns a new slice with base labels plus optional granular labels.
// Only adds granular labels if EnableGranularMetrics is true.
// Always returns a copy to prevent accidental mutation of the base slice.
func WithGranularLabels(baseLabels []string, granularLabels ...string) []string {
	if !EnableGranularMetrics || len(granularLabels) == 0 {
		// Return copy to avoid accidental mutation
		result := make([]string, len(baseLabels))
		copy(result, baseLabels)
		return result
	}

	result := make([]string, len(baseLabels), len(baseLabels)+len(granularLabels))
	copy(result, baseLabels)
	return append(result, granularLabels...)
}

// AddStoreRefLabels adds SecretStore reference labels if granular metrics is enabled.
// For ClusterSecretStore (kind=="ClusterSecretStore"), namespace is set to empty string.
func AddStoreRefLabels(labels prometheus.Labels, storeName, storeKind, namespace string) prometheus.Labels {
	if !EnableGranularMetrics {
		return labels
	}

	storeNamespace := namespace
	if storeKind == "ClusterSecretStore" {
		storeNamespace = ""
	}

	return RefineLabels(labels, map[string]string{
		"secretstore_name":      storeName,
		"secretstore_namespace": storeNamespace,
	})
}

// AddProviderTypeLabel adds provider type label if granular metrics is enabled.
func AddProviderTypeLabel(labels prometheus.Labels, providerType string) prometheus.Labels {
	if !EnableGranularMetrics || providerType == "" {
		return labels
	}

	return RefineLabels(labels, map[string]string{
		"provider_type": providerType,
	})
}

// Provider operation constants for store API call metrics.
// These ensure consistent operation names across controllers.
const (
	OperationGetSecret     = "GetSecret"
	OperationGetSecretMap  = "GetSecretMap"
	OperationGetAllSecrets = "GetAllSecrets"
	OperationPushSecret    = "PushSecret"
	OperationDeleteSecret  = "DeleteSecret"
	OperationSecretExists  = "SecretExists"
	OperationValidate      = "Validate"
)

// NewStoreMetricsObserver creates an observer function for recording provider API calls
// for the given SecretStore or ClusterSecretStore.
// Returns a no-op function when EnableGranularMetrics is false.
func NewStoreMetricsObserver(storeName, storeKind, storeNamespace, providerType string) func(operation string, err error) {
	if !EnableGranularMetrics {
		return func(string, error) {} // no-op
	}

	return func(operation string, err error) {
		if observeStoreAPICallFunc != nil {
			observeStoreAPICallFunc(storeName, storeKind, storeNamespace, providerType, operation, err)
		}
	}
}

// observeStoreAPICallFunc is a callback to record store API calls.
// This is set by the metrics package to avoid import cycles.
var observeStoreAPICallFunc func(storeName, storeKind, storeNamespace, provider, call string, err error)

// SetObserveStoreAPICallFunc sets the callback for recording store API calls.
func SetObserveStoreAPICallFunc(fn func(storeName, storeKind, storeNamespace, provider, call string, err error)) {
	observeStoreAPICallFunc = fn
}
