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
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	ctrlmetrics "github.com/external-secrets/external-secrets/pkg/controllers/metrics"
)

func TestObserveStoreAPICall_GranularMetricsDisabled(t *testing.T) {
	// Save original state
	origEnabled := ctrlmetrics.EnableGranularMetrics
	defer func() {
		ctrlmetrics.EnableGranularMetrics = origEnabled
	}()

	// Disable granular metrics
	ctrlmetrics.EnableGranularMetrics = false

	// Create a new registry for isolated testing
	registry := prometheus.NewRegistry()

	// Create metric with granular labels (as SetUpMetrics does)
	storeLabels := ctrlmetrics.WithGranularLabels(
		[]string{"provider", "call", "status"},
		"secretstore_kind", "secretstore_name", "secretstore_namespace",
	)

	testMetric := prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      "test_store_api_calls_count",
		Help:      "Test metric",
	}, storeLabels)

	registry.MustRegister(testMetric)

	// Replace global metric temporarily
	origMetric := storeAPICallsTotal
	storeAPICallsTotal = testMetric
	defer func() {
		storeAPICallsTotal = origMetric
	}()

	// Call ObserveStoreAPICall
	ObserveStoreAPICall("test-store", "SecretStore", "default", "vault", "GetSecret", nil)

	// Verify metric was NOT recorded (granular metrics disabled)
	count := testutil.CollectAndCount(testMetric)
	if count != 0 {
		t.Errorf("Expected 0 metrics when granular metrics disabled, got %d", count)
	}
}

func TestObserveStoreAPICall_GranularMetricsEnabled(t *testing.T) {
	// Save original state
	origEnabled := ctrlmetrics.EnableGranularMetrics
	defer func() {
		ctrlmetrics.EnableGranularMetrics = origEnabled
	}()

	// Enable granular metrics
	ctrlmetrics.EnableGranularMetrics = true

	testCases := []struct {
		name              string
		storeName         string
		storeKind         string
		storeNamespace    string
		provider          string
		call              string
		err               error
		expectedLabels    prometheus.Labels
		expectedIncrement float64
	}{
		{
			name:           "SecretStore success",
			storeName:      "prod-vault",
			storeKind:      "SecretStore",
			storeNamespace: "production",
			provider:       "vault",
			call:           "GetSecret",
			err:            nil,
			expectedLabels: prometheus.Labels{
				"provider":              "vault",
				"call":                  "GetSecret",
				"status":                "success",
				"secretstore_kind":      "SecretStore",
				"secretstore_name":      "prod-vault",
				"secretstore_namespace": "production",
			},
			expectedIncrement: 1,
		},
		{
			name:           "ClusterSecretStore error",
			storeName:      "cluster-vault",
			storeKind:      "ClusterSecretStore",
			storeNamespace: "",
			provider:       "aws",
			call:           "PushSecret",
			err:            errors.New("test error"),
			expectedLabels: prometheus.Labels{
				"provider":              "aws",
				"call":                  "PushSecret",
				"status":                "error",
				"secretstore_kind":      "ClusterSecretStore",
				"secretstore_name":      "cluster-vault",
				"secretstore_namespace": "",
			},
			expectedIncrement: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new registry for isolated testing
			registry := prometheus.NewRegistry()

			// Create metric with granular labels
			storeLabels := ctrlmetrics.WithGranularLabels(
				[]string{"provider", "call", "status"},
				"secretstore_kind", "secretstore_name", "secretstore_namespace",
			)

			testMetric := prometheus.NewCounterVec(prometheus.CounterOpts{
				Subsystem: ExternalSecretSubsystem,
				Name:      "test_store_api_calls_count_" + tc.name,
				Help:      "Test metric",
			}, storeLabels)

			registry.MustRegister(testMetric)

			// Replace global metric temporarily
			origMetric := storeAPICallsTotal
			storeAPICallsTotal = testMetric
			defer func() {
				storeAPICallsTotal = origMetric
			}()

			// Get initial value
			initialValue := testutil.ToFloat64(testMetric.With(tc.expectedLabels))

			// Call ObserveStoreAPICall
			ObserveStoreAPICall(tc.storeName, tc.storeKind, tc.storeNamespace, tc.provider, tc.call, tc.err)

			// Verify metric was incremented
			finalValue := testutil.ToFloat64(testMetric.With(tc.expectedLabels))
			actualIncrement := finalValue - initialValue

			if actualIncrement != tc.expectedIncrement {
				t.Errorf("Expected increment of %f, got %f", tc.expectedIncrement, actualIncrement)
			}
		})
	}
}

func TestObserveStoreAPICall_MultipleIncrements(t *testing.T) {
	// Save original state
	origEnabled := ctrlmetrics.EnableGranularMetrics
	defer func() {
		ctrlmetrics.EnableGranularMetrics = origEnabled
	}()

	// Enable granular metrics
	ctrlmetrics.EnableGranularMetrics = true

	// Create a new registry for isolated testing
	registry := prometheus.NewRegistry()

	storeLabels := ctrlmetrics.WithGranularLabels(
		[]string{"provider", "call", "status"},
		"secretstore_kind", "secretstore_name", "secretstore_namespace",
	)

	testMetric := prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem,
		Name:      "test_multiple_increments",
		Help:      "Test metric",
	}, storeLabels)

	registry.MustRegister(testMetric)

	// Replace global metric temporarily
	origMetric := storeAPICallsTotal
	storeAPICallsTotal = testMetric
	defer func() {
		storeAPICallsTotal = origMetric
	}()

	labels := prometheus.Labels{
		"provider":              "vault",
		"call":                  "GetSecret",
		"status":                "success",
		"secretstore_kind":      "SecretStore",
		"secretstore_name":      "test-store",
		"secretstore_namespace": "default",
	}

	// Call multiple times
	for i := 0; i < 5; i++ {
		ObserveStoreAPICall("test-store", "SecretStore", "default", "vault", "GetSecret", nil)
	}

	// Verify counter incremented 5 times
	value := testutil.ToFloat64(testMetric.With(labels))
	if value != 5 {
		t.Errorf("Expected counter value of 5, got %f", value)
	}
}

func TestObserveAPICall_BeforeMetricsInitialized(t *testing.T) {
	// Save original state
	origMetric := syncCallsTotal
	defer func() {
		syncCallsTotal = origMetric
	}()

	// Set to nil to simulate metrics not being initialized
	syncCallsTotal = nil

	// Should not panic when metrics are not initialized
	ObserveAPICall("vault", "GetSecret", nil)
	ObserveAPICall("aws", "PushSecret", errors.New("test error"))

	// Test passes if we get here without panicking
}

func TestObserveStoreAPICall_BeforeMetricsInitialized(t *testing.T) {
	// Save original state
	origEnabled := ctrlmetrics.EnableGranularMetrics
	origMetric := storeAPICallsTotal
	defer func() {
		ctrlmetrics.EnableGranularMetrics = origEnabled
		storeAPICallsTotal = origMetric
	}()

	// Enable granular metrics but set metric to nil
	ctrlmetrics.EnableGranularMetrics = true
	storeAPICallsTotal = nil

	// Should not panic when metrics are not initialized
	ObserveStoreAPICall("test-store", "SecretStore", "default", "vault", "GetSecret", nil)
	ObserveStoreAPICall("cluster-store", "ClusterSecretStore", "", "aws", "PushSecret", errors.New("test error"))

	// Test passes if we get here without panicking
}

func TestSetUpMetrics_LabelConfiguration(t *testing.T) {
	testCases := []struct {
		name           string
		enableGranular bool
		expectedLabels []string
	}{
		{
			name:           "Granular metrics disabled",
			enableGranular: false,
			expectedLabels: []string{"provider", "call", "status"},
		},
		{
			name:           "Granular metrics enabled",
			enableGranular: true,
			expectedLabels: []string{"provider", "call", "status", "secretstore_kind", "secretstore_name", "secretstore_namespace"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Save original state
			origEnabled := ctrlmetrics.EnableGranularMetrics
			defer func() {
				ctrlmetrics.EnableGranularMetrics = origEnabled
			}()

			ctrlmetrics.EnableGranularMetrics = tc.enableGranular

			// Get labels using the same logic as SetUpMetrics
			storeLabels := ctrlmetrics.WithGranularLabels(
				[]string{"provider", "call", "status"},
				"secretstore_kind", "secretstore_name", "secretstore_namespace",
			)

			// Verify label count matches expected
			if len(storeLabels) != len(tc.expectedLabels) {
				t.Errorf("Expected %d labels, got %d", len(tc.expectedLabels), len(storeLabels))
			}

			// Verify each expected label is present
			labelMap := make(map[string]bool)
			for _, label := range storeLabels {
				labelMap[label] = true
			}

			for _, expectedLabel := range tc.expectedLabels {
				if !labelMap[expectedLabel] {
					t.Errorf("Expected label %q not found in %v", expectedLabel, storeLabels)
				}
			}
		})
	}
}
