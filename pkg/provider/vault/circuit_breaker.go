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
	"fmt"
	"sync"
	"time"
)

// BreakerConfig contains configuration for the circuit breaker.
//
// The circuit breaker prevents authentication storms by temporarily blocking
// requests after repeated failures. It operates per-server and auth-method pair.
type BreakerConfig struct {
	// Threshold is the number of consecutive failures before opening the circuit.
	// After this many failures, the circuit opens and blocks subsequent requests.
	// Default: 5
	// Recommended range: 3-10
	Threshold int

	// OpenDuration is how long to keep the circuit open before attempting to close it.
	// After this duration, the circuit automatically closes and allows requests again.
	// A successful request will also close the circuit.
	// Default: 30 seconds
	// Recommended range: 10-60 seconds
	OpenDuration time.Duration
}

// circuitBreaker implements a simple circuit breaker to prevent auth storms during Vault outages.
// It tracks consecutive failures per key and opens the circuit after reaching the threshold.
type circuitBreaker struct {
	mu           sync.RWMutex
	failures     map[string]int
	lastFailTime map[string]time.Time
	openUntil    map[string]time.Time
	threshold    int
	openDuration time.Duration
}

// newCircuitBreaker creates a new circuit breaker with the given configuration.
func newCircuitBreaker(cfg BreakerConfig) *circuitBreaker {
	return &circuitBreaker{
		failures:     make(map[string]int),
		lastFailTime: make(map[string]time.Time),
		openUntil:    make(map[string]time.Time),
		threshold:    cfg.Threshold,
		openDuration: cfg.OpenDuration,
	}
}

// Check returns an error if the circuit is open for the given key.
// It automatically closes the circuit if the open duration has elapsed.
func (cb *circuitBreaker) Check(key string) error {
	cb.mu.RLock()
	openUntil, isOpen := cb.openUntil[key]
	cb.mu.RUnlock()

	if !isOpen {
		return nil
	}

	// Check if we should close the circuit
	if time.Now().After(openUntil) {
		cb.mu.Lock()
		delete(cb.openUntil, key)
		delete(cb.failures, key)
		delete(cb.lastFailTime, key)
		cb.mu.Unlock()
		return nil
	}

	return fmt.Errorf("circuit breaker open for key %s until %s", key, openUntil.Format(time.RFC3339))
}

// RecordSuccess records a successful operation and resets the failure count.
func (cb *circuitBreaker) RecordSuccess(key string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	delete(cb.failures, key)
	delete(cb.lastFailTime, key)
	delete(cb.openUntil, key)
}

// RecordFailure records a failed operation and potentially opens the circuit.
func (cb *circuitBreaker) RecordFailure(key string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	cb.failures[key]++
	cb.lastFailTime[key] = now

	// Open the circuit if we've reached the threshold
	if cb.failures[key] >= cb.threshold {
		cb.openUntil[key] = now.Add(cb.openDuration)
	}
}

// getBreakerKey generates a circuit breaker key from server and auth method.
// Format: {server}:{authMethod}
func getBreakerKey(server, authMethod string) string {
	return fmt.Sprintf("%s:%s", server, authMethod)
}
