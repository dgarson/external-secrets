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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsPermanentAuthError tests the permanent error detection logic.
// This function is critical for ensuring that GetValidClient doesn't retry
// on errors that will never succeed (like permission denied).
func TestIsPermanentAuthError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		isPermanent bool
	}{
		{
			name:       "nil error",
			err:        nil,
			isPermanent: false,
		},
		{
			name:       "permission denied",
			err:        errors.New("permission denied"),
			isPermanent: true,
		},
		{
			name:       "invalid credentials",
			err:        errors.New("invalid credentials"),
			isPermanent: true,
		},
		{
			name:       "unauthorized",
			err:        errors.New("unauthorized access"),
			isPermanent: true,
		},
		{
			name:       "authentication failed",
			err:        errors.New("authentication failed"),
			isPermanent: true,
		},
		{
			name:       "invalid token",
			err:        errors.New("invalid token"),
			isPermanent: true,
		},
		{
			name:       "forbidden",
			err:        errors.New("403 forbidden"),
			isPermanent: true,
		},
		{
			name:       "access denied",
			err:        errors.New("access denied"),
			isPermanent: true,
		},
		{
			name:       "transient network error",
			err:        errors.New("connection timeout"),
			isPermanent: false,
		},
		{
			name:       "transient server error",
			err:        errors.New("500 internal server error"),
			isPermanent: false,
		},
		{
			name:       "case insensitive matching",
			err:        errors.New("PERMISSION DENIED"),
			isPermanent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPermanentAuthError(tt.err)
			assert.Equal(t, tt.isPermanent, result, "isPermanentAuthError mismatch")
		})
	}
}
