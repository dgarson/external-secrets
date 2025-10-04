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

func TestStoreMetricsRecorder_Observe(t *testing.T) {
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
		recorder            *StoreMetricsRecorder
		operation           string
		err                 error
		setupCallback       bool
		expectedCallbackRun bool
		expectedStoreName   string
		expectedStoreKind   string
		expectedNamespace   string
		expectedProvider    string
		expectedOperation   string
	}{
		{
			description:    "Granular metrics disabled - callback not run",
			enableGranular: false,
			recorder: &StoreMetricsRecorder{
				storeName:      "test-store",
				storeKind:      "SecretStore",
				storeNamespace: "default",
				providerType:   "vault",
			},
			operation:           OperationGetSecret,
			err:                 nil,
			setupCallback:       true,
			expectedCallbackRun: false,
		},
		{
			description:    "Granular metrics enabled - SecretStore",
			enableGranular: true,
			recorder: &StoreMetricsRecorder{
				storeName:      "test-store",
				storeKind:      "SecretStore",
				storeNamespace: "default",
				providerType:   "vault",
			},
			operation:           OperationGetSecret,
			err:                 nil,
			setupCallback:       true,
			expectedCallbackRun: true,
			expectedStoreName:   "test-store",
			expectedStoreKind:   "SecretStore",
			expectedNamespace:   "default",
			expectedProvider:    "vault",
			expectedOperation:   OperationGetSecret,
		},
		{
			description:    "Granular metrics enabled - ClusterSecretStore",
			enableGranular: true,
			recorder: &StoreMetricsRecorder{
				storeName:      "cluster-store",
				storeKind:      "ClusterSecretStore",
				storeNamespace: "",
				providerType:   "aws",
			},
			operation:           OperationPushSecret,
			err:                 nil,
			setupCallback:       true,
			expectedCallbackRun: true,
			expectedStoreName:   "cluster-store",
			expectedStoreKind:   "ClusterSecretStore",
			expectedNamespace:   "",
			expectedProvider:    "aws",
			expectedOperation:   OperationPushSecret,
		},
		{
			description:         "Nil recorder - no panic",
			enableGranular:      true,
			recorder:            nil,
			operation:           OperationValidate,
			err:                 nil,
			setupCallback:       true,
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

			// Execute
			tc.recorder.Observe(tc.operation, tc.err)

			// Verify
			if callbackRun != tc.expectedCallbackRun {
				t.Errorf("Expected callback run=%v, got=%v", tc.expectedCallbackRun, callbackRun)
			}

			if tc.expectedCallbackRun {
				if capturedStoreName != tc.expectedStoreName {
					t.Errorf("Expected storeName=%q, got=%q", tc.expectedStoreName, capturedStoreName)
				}
				if capturedStoreKind != tc.expectedStoreKind {
					t.Errorf("Expected storeKind=%q, got=%q", tc.expectedStoreKind, capturedStoreKind)
				}
				if capturedNamespace != tc.expectedNamespace {
					t.Errorf("Expected namespace=%q, got=%q", tc.expectedNamespace, capturedNamespace)
				}
				if capturedProvider != tc.expectedProvider {
					t.Errorf("Expected provider=%q, got=%q", tc.expectedProvider, capturedProvider)
				}
				if capturedOperation != tc.expectedOperation {
					t.Errorf("Expected operation=%q, got=%q", tc.expectedOperation, capturedOperation)
				}
				if capturedErr != tc.err {
					t.Errorf("Expected err=%v, got=%v", tc.err, capturedErr)
				}
			}
		})
	}
}

func TestNewStoreMetricsRecorder(t *testing.T) {
	recorder := NewStoreMetricsRecorder("my-store", "SecretStore", "default", "vault")

	if recorder == nil {
		t.Fatal("Expected non-nil recorder")
	}
	if recorder.storeName != "my-store" {
		t.Errorf("Expected storeName=my-store, got=%s", recorder.storeName)
	}
	if recorder.storeKind != "SecretStore" {
		t.Errorf("Expected storeKind=SecretStore, got=%s", recorder.storeKind)
	}
	if recorder.storeNamespace != "default" {
		t.Errorf("Expected storeNamespace=default, got=%s", recorder.storeNamespace)
	}
	if recorder.providerType != "vault" {
		t.Errorf("Expected providerType=vault, got=%s", recorder.providerType)
	}
}
