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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
)

func TestSetUpLabelNames(t *testing.T) {
	testCases := []struct {
		description                          string
		addKubeStandardLabels                bool
		expectedNonConditionMetricLabelNames []string
		expectedConditionMetricLabelNames    []string
		expectedNonConditionMetricLabels     map[string]string
		expectedConditionMetricLabels        map[string]string
	}{
		{
			description:           "Add standard labels disabled",
			addKubeStandardLabels: false,
			expectedNonConditionMetricLabelNames: []string{
				"name",
				"namespace",
			},
			expectedConditionMetricLabelNames: []string{
				"name",
				"namespace",
				"condition",
				"status",
			},
			expectedNonConditionMetricLabels: map[string]string{
				"name":      "",
				"namespace": "",
			},
			expectedConditionMetricLabels: map[string]string{
				"name":      "",
				"namespace": "",
				"condition": "",
				"status":    "",
			},
		},
		{
			description:           "Add standard labels enabled",
			addKubeStandardLabels: true,
			expectedNonConditionMetricLabelNames: []string{
				"name",
				"namespace",
				"app_kubernetes_io_name",
				"app_kubernetes_io_instance",
				"app_kubernetes_io_version",
				"app_kubernetes_io_component",
				"app_kubernetes_io_part_of",
				"app_kubernetes_io_managed_by",
			},
			expectedConditionMetricLabelNames: []string{
				"name",
				"namespace",
				"condition",
				"status",
				"app_kubernetes_io_name",
				"app_kubernetes_io_instance",
				"app_kubernetes_io_version",
				"app_kubernetes_io_component",
				"app_kubernetes_io_part_of",
				"app_kubernetes_io_managed_by",
			},
			expectedNonConditionMetricLabels: map[string]string{
				"name":                         "",
				"namespace":                    "",
				"app_kubernetes_io_name":       "",
				"app_kubernetes_io_instance":   "",
				"app_kubernetes_io_version":    "",
				"app_kubernetes_io_component":  "",
				"app_kubernetes_io_part_of":    "",
				"app_kubernetes_io_managed_by": "",
			},
			expectedConditionMetricLabels: map[string]string{
				"name":                         "",
				"namespace":                    "",
				"condition":                    "",
				"status":                       "",
				"app_kubernetes_io_name":       "",
				"app_kubernetes_io_instance":   "",
				"app_kubernetes_io_version":    "",
				"app_kubernetes_io_component":  "",
				"app_kubernetes_io_part_of":    "",
				"app_kubernetes_io_managed_by": "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			SetUpLabelNames(tc.addKubeStandardLabels)

			if diff := cmp.Diff(NonConditionMetricLabelNames, tc.expectedNonConditionMetricLabelNames); diff != "" {
				t.Errorf("NonConditionMetricLabelNames does not match the expected value. (-got +want)\n%s", diff)
			}

			if diff := cmp.Diff(ConditionMetricLabelNames, tc.expectedConditionMetricLabelNames); diff != "" {
				t.Errorf("ConditionMetricLabelNames does not match the expected value. (-got +want)\n%s", diff)
			}

			if diff := cmp.Diff(NonConditionMetricLabels, tc.expectedNonConditionMetricLabels); diff != "" {
				t.Errorf("NonConditionMetricLabels are not initialized with empty strings. (-got +want)\n%s", diff)
			}

			if diff := cmp.Diff(ConditionMetricLabels, tc.expectedConditionMetricLabels); diff != "" {
				t.Errorf("ConditionMetricLabels are not initialized with empty strings. (-got +want)\n%s", diff)
			}
		})
	}
}

func TestRefineLabels(t *testing.T) {
	testCases := []struct {
		description        string
		promLabels         prometheus.Labels
		newLabels          map[string]string
		expectedRefinement prometheus.Labels
	}{
		{
			description: "No new labels",
			promLabels: prometheus.Labels{
				"label1": "value1",
				"label2": "value2",
			},
			newLabels:          map[string]string{},
			expectedRefinement: prometheus.Labels{"label1": "value1", "label2": "value2"},
		},
		{
			description: "Add unregistered labels",
			promLabels: prometheus.Labels{
				"label1": "value1",
				"label2": "value2",
			},
			newLabels: map[string]string{
				"new_label1": "new_value1",
				"new_label2": "new_value2",
			},
			expectedRefinement: prometheus.Labels{
				"label1": "value1",
				"label2": "value2",
			},
		},
		{
			description: "Overwrite existing labels",
			promLabels: prometheus.Labels{
				"label1": "value1",
				"label2": "value2",
			},
			newLabels: map[string]string{
				"label1": "new_value1",
				"label2": "new_value2",
			},
			expectedRefinement: prometheus.Labels{
				"label1": "new_value1",
				"label2": "new_value2",
			},
		},
		{
			description: "Clean non-alphanumeric characters in new labels",
			promLabels: prometheus.Labels{
				"label_1": "value1",
			},
			newLabels: map[string]string{
				"label@1": "new_value",
			},
			expectedRefinement: prometheus.Labels{
				"label_1": "new_value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			refinement := RefineLabels(tc.promLabels, tc.newLabels)

			if diff := cmp.Diff(refinement, tc.expectedRefinement); diff != "" {
				t.Errorf("Refinement does not match the expected value. (-got +want)\n%s", diff)
			}
		})
	}
}

func TestStoreMetricsObserver(t *testing.T) {
	// Save original state
	origEnabled := EnableGranularMetrics
	origCallback := observeStoreAPICallFunc
	defer func() {
		EnableGranularMetrics = origEnabled
		observeStoreAPICallFunc = origCallback
	}()

	testCases := []struct {
		description         string
		enableGranular      bool
		storeName           string
		storeKind           string
		storeNamespace      string
		providerType        string
		operation           string
		err                 error
		setupCallback       bool
		expectedCallbackRun bool
	}{
		{
			description:         "Granular metrics disabled - returns no-op function",
			enableGranular:      false,
			storeName:           "test-store",
			storeKind:           "SecretStore",
			storeNamespace:      "default",
			providerType:        "vault",
			operation:           OperationGetSecret,
			err:                 nil,
			setupCallback:       true,
			expectedCallbackRun: false,
		},
		{
			description:         "Granular metrics enabled - SecretStore",
			enableGranular:      true,
			storeName:           "test-store",
			storeKind:           "SecretStore",
			storeNamespace:      "default",
			providerType:        "vault",
			operation:           OperationGetSecret,
			err:                 nil,
			setupCallback:       true,
			expectedCallbackRun: true,
		},
		{
			description:         "Granular metrics enabled - ClusterSecretStore",
			enableGranular:      true,
			storeName:           "cluster-store",
			storeKind:           "ClusterSecretStore",
			storeNamespace:      "",
			providerType:        "aws",
			operation:           OperationPushSecret,
			err:                 nil,
			setupCallback:       true,
			expectedCallbackRun: true,
		},
		{
			description:         "No callback set - function doesn't panic",
			enableGranular:      true,
			storeName:           "test-store",
			storeKind:           "SecretStore",
			storeNamespace:      "default",
			providerType:        "vault",
			operation:           OperationValidate,
			err:                 nil,
			setupCallback:       false,
			expectedCallbackRun: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			EnableGranularMetrics = tc.enableGranular

			callbackRun := false
			var capturedStoreName, capturedStoreKind, capturedNamespace, capturedProvider, capturedOperation string
			var capturedErr error

			if tc.setupCallback {
				observeStoreAPICallFunc = func(storeName, storeKind, storeNamespace, provider, call string, err error) {
					callbackRun = true
					capturedStoreName = storeName
					capturedStoreKind = storeKind
					capturedNamespace = storeNamespace
					capturedProvider = provider
					capturedOperation = call
					capturedErr = err
				}
			} else {
				observeStoreAPICallFunc = nil
			}

			// Create observer and execute
			observe := NewStoreMetricsObserver(tc.storeName, tc.storeKind, tc.storeNamespace, tc.providerType)
			observe(tc.operation, tc.err)

			// Verify
			if callbackRun != tc.expectedCallbackRun {
				t.Errorf("Expected callback run=%v, got=%v", tc.expectedCallbackRun, callbackRun)
			}

			if tc.expectedCallbackRun {
				if capturedStoreName != tc.storeName {
					t.Errorf("Expected storeName=%q, got=%q", tc.storeName, capturedStoreName)
				}
				if capturedStoreKind != tc.storeKind {
					t.Errorf("Expected storeKind=%q, got=%q", tc.storeKind, capturedStoreKind)
				}
				if capturedNamespace != tc.storeNamespace {
					t.Errorf("Expected namespace=%q, got=%q", tc.storeNamespace, capturedNamespace)
				}
				if capturedProvider != tc.providerType {
					t.Errorf("Expected provider=%q, got=%q", tc.providerType, capturedProvider)
				}
				if capturedOperation != tc.operation {
					t.Errorf("Expected operation=%q, got=%q", tc.operation, capturedOperation)
				}
				if capturedErr != tc.err {
					t.Errorf("Expected err=%v, got=%v", tc.err, capturedErr)
				}
			}
		})
	}
}

func TestNewStoreMetricsObserver(t *testing.T) {
	// Save original state
	origEnabled := EnableGranularMetrics
	defer func() {
		EnableGranularMetrics = origEnabled
	}()

	t.Run("Returns non-nil function when granular metrics enabled", func(t *testing.T) {
		EnableGranularMetrics = true
		observe := NewStoreMetricsObserver("my-store", "SecretStore", "default", "vault")

		if observe == nil {
			t.Fatal("Expected non-nil observer function")
		}
	})

	t.Run("Returns non-nil no-op function when granular metrics disabled", func(t *testing.T) {
		EnableGranularMetrics = false
		observe := NewStoreMetricsObserver("my-store", "SecretStore", "default", "vault")

		if observe == nil {
			t.Fatal("Expected non-nil observer function (no-op)")
		}

		// Should not panic when called
		observe(OperationGetSecret, nil)
	})
}

func TestWithGranularLabels(t *testing.T) {
	// Save original state
	origEnabled := EnableGranularMetrics
	defer func() {
		EnableGranularMetrics = origEnabled
	}()

	baseLabels := []string{"provider", "call", "status"}

	t.Run("Granular metrics disabled - returns only base labels", func(t *testing.T) {
		EnableGranularMetrics = false
		result := WithGranularLabels(baseLabels, "extra1", "extra2")

		expectedLabels := []string{"provider", "call", "status"}
		if diff := cmp.Diff(result, expectedLabels); diff != "" {
			t.Errorf("Labels don't match (-got +want)\n%s", diff)
		}
	})

	t.Run("Granular metrics enabled - returns base + granular labels", func(t *testing.T) {
		EnableGranularMetrics = true
		result := WithGranularLabels(baseLabels, "extra1", "extra2")

		expectedLabels := []string{"provider", "call", "status", "extra1", "extra2"}
		if diff := cmp.Diff(result, expectedLabels); diff != "" {
			t.Errorf("Labels don't match (-got +want)\n%s", diff)
		}
	})

	t.Run("Returns copy to prevent mutation", func(t *testing.T) {
		EnableGranularMetrics = true
		result1 := WithGranularLabels(baseLabels, "extra1")
		result2 := WithGranularLabels(baseLabels, "extra2")

		// Modify result1
		result1[0] = "modified"

		// result2 should not be affected
		if result2[0] == "modified" {
			t.Error("Modifying one result affected another - slice was not copied properly")
		}

		// baseLabels should not be affected
		if baseLabels[0] == "modified" {
			t.Error("Modifying result affected base labels - slice was not copied properly")
		}
	})
}
