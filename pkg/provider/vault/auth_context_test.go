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

package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestNewAuthContext(t *testing.T) {
	spec := &esv1.VaultProvider{
		Server: "https://vault.example.com",
	}

	fakeKube := fake.NewClientBuilder().Build()

	authCtx := newAuthContext(
		spec,
		fakeKube,
		nil, // corev1 can be nil for this test
		"default",
		esv1.SecretStoreKind,
	)

	assert.NotNil(t, authCtx)
	assert.Equal(t, spec, authCtx.spec)
	assert.Equal(t, fakeKube, authCtx.kube)
	assert.Equal(t, "default", authCtx.namespace)
	assert.Equal(t, esv1.SecretStoreKind, authCtx.storeKind)
}
