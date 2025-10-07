# External Secrets Operator - Vault Client Pooling Deep Review & Alternative Design

## Part 1: Comprehensive Review of Current Design

### Summary
- **Verdict**: Design is architecturally sound but has **CRITICAL implementation gaps** that render pooling non-functional
- **Pool Bypass Bug**: Client revokes tokens on Close() instead of releasing to pool - **pooling is completely ineffective**
- **Lease Abstraction**: Excellent design pattern that properly encapsulates retry and release semantics
- **Concurrency**: Multiple race conditions need addressing, but the configMu/lease pattern is correct
- **Circuit Breaker**: Well-designed and essential for production resilience

### Critical Findings (Severity: CRITICAL)

#### 1. Pool Completely Bypassed Due to Token Revocation
**Severity**: CRITICAL
**Location**: `pkg/provider/vault/client.go:122` (per current-vault-client-pool-gemini.md:14-19)
**Description**: The `client.Close()` method directly revokes tokens instead of calling `pool.ReleaseClient()`. Since controllers always call `defer mgr.Close(ctx)`, every reconciliation revokes the token, making pooling completely ineffective.
**Remediation**: Implement the lease pattern from GEMINI-POOLING-PLAN.md §4.3-4.4. The client must store a `ClientLease` and delegate Close() to `lease.Close()`.

#### 2. Missing Release Contract in Provider
**Severity**: CRITICAL
**Location**: `pkg/provider/vault/provider.go:112` (per current-vault-client-pool-gemini.md:26)
**Description**: Generator path returns raw `util.Client` with no release hook. The `secretstore.Manager` has no way to notify the pool when done.
**Remediation**: Follow VAULT_CLIENT_POOL_ACTION_PLAN.md Task 1 - inject pool and lease into client struct.

### High-Priority Findings

#### 3. Proactive Token Validation Defeats Caching
**Severity**: HIGH
**Location**: `pkg/provider/vault/managed_client.go:320` (per current-vault-client-pool-gemini.md:33-35)
**Description**: `validateToken()` calls `LookupSelf` on every borrow, adding constant API calls and defeating the purpose of caching.
**Remediation**: Implement lazy validation via WithRetry pattern (VAULT_CLIENT_POOL_ACTION_PLAN.md Task 2).

#### 4. Cache Key Missing TLS Trust Roots
**Severity**: HIGH
**Location**: `pkg/provider/vault/cache_key.go` - `computeTLSHash`
**Description**: Only hashes client cert/key, ignoring CABundle, CAProvider, InsecureSkipVerify, ServerName. CA rotations reuse stale HTTP transport.
**Remediation**: Include all TLS config in hash as specified in GEMINI-POOLING-PLAN.md §5.1.

#### 5. Config Synchronization Race Conditions
**Severity**: HIGH
**Location**: `pkg/provider/vault/managed_client.go:236,460`
**Description**: `updateConfig` writes under `renewalMu` but `Close` reads without lock. Data race when reauth updates config during eviction.
**Remediation**: Use consistent `configMu` for all config access (VAULT_CLIENT_POOL_ACTION_PLAN.md Task 5).

### Medium-Priority Findings

#### 6. Circuit Breaker Completely Missing
**Severity**: MEDIUM
**Location**: Not implemented
**Description**: No throttling of auth failures. During Vault outages, thousands of ExternalSecrets hammer the API.
**Remediation**: Implement circuit breaker per VAULT_CLIENT_POOL_ACTION_PLAN.md Task 3.

#### 7. Renewal Uses Inefficient Polling
**Severity**: MEDIUM
**Location**: `ManagedClient.renewalLoop`
**Description**: Fixed-interval ticker wastes CPU. Should use one-shot timers computed at auth time.
**Remediation**: Implement timer-based scheduling (GEMINI-POOLING-PLAN.md §9.1).

#### 8. No Background Cleanup for Expired Entries
**Severity**: MEDIUM
**Location**: `pkg/provider/vault/client_pool_cache.go`
**Description**: Expired entries linger until next cache hit. No proactive cleanup.
**Remediation**: Add background ticker per VAULT_CLIENT_POOL_ACTION_PLAN.md Task 7.

### Low-Priority Findings

#### 9. Unnecessary Token Validation Before Revocation
**Severity**: LOW
**Location**: `revokeTokenIfValid` function
**Description**: Calls `checkToken` before revoking. Vault handles expired tokens gracefully.
**Remediation**: Remove validation, just attempt revocation and log errors.

#### 10. Missing Singleflight Key Cleanup
**Severity**: LOW
**Location**: `WithRetry` implementations
**Description**: Must call `reauthGroup.Forget(cacheKey)` after each attempt to prevent memory growth.
**Remediation**: Add Forget() call as shown in GEMINI-POOLING-PLAN.md §8.1.

### Positive Observations
- **ClientLease abstraction** (GEMINI-POOLING-PLAN.md §4.3) is excellent - hides complexity from controllers
- **VaultClientConfig** structure properly encapsulates all inputs for client creation
- **Parallel execution strategy** in ACTION_PLAN is well-organized for implementation
- **Comprehensive testing strategy** covers unit, integration, and race detection

### Open Questions & Assumptions
1. **Dynamic TLS Flag Default**: Should `--vault-client-pool-allow-dynamic-tls-cache` default to false (safe) or true (performance)?
2. **Non-idempotent Operations**: How to handle PushSecret/DeleteSecret retry? Feature flag or document at-least-once semantics?
3. **Metrics Registration**: How to handle prometheus.AlreadyRegisteredError when controller reinitializes?
4. **Token Timeout Configuration**: Should timeout be per-pool or per-client configurable?

### Recommended Next Steps
1. **IMMEDIATE**: Fix pool bypass bug (Task 1 from ACTION_PLAN) - without this, pooling is non-functional
2. **IMMEDIATE**: Implement WithRetry lazy validation (Task 2) to eliminate unnecessary API calls
3. **HIGH**: Add circuit breaker (Task 3) before production deployment
4. **HIGH**: Fix cache key to include all TLS config
5. **MEDIUM**: Replace polling with timer-based renewal
6. **MEDIUM**: Add background cleanup ticker

---

## Part 2: Alternative Design Document - opus-client-pooling.md

# Vault Client Pooling for External Secrets Operator - Opus Design

## 1. Executive Summary

This document presents a production-ready Vault client pooling system for the External Secrets Operator (ESO) that reduces authentication overhead, handles token lifecycle properly, and integrates seamlessly with Kubernetes controller patterns.

### Key Design Principles
- **Correctness over Performance**: Never compromise security or data integrity for speed
- **Fail Fast, Recover Gracefully**: Use circuit breakers and leverage controller-runtime's backoff
- **Explicit Lifecycle Management**: Clear acquire/release semantics with automatic cleanup
- **Zero Trust on Rotation**: Assume credentials and TLS material rotate frequently

## 2. Goals & Requirements

### Functional Requirements
1. **FR1**: Reduce Vault authentication calls from O(reconciliations) to O(token_expiry)
2. **FR2**: Support concurrent reconciliations sharing the same identity safely
3. **FR3**: Handle token expiration transparently within a single reconciliation
4. **FR4**: Prevent token revocation while operations are in-flight
5. **FR5**: Support dynamic credential and TLS rotation without restart
6. **FR6**: Provide circuit breaking for auth failures

### Non-Functional Requirements
1. **NFR1**: Zero data races (pass `go test -race`)
2. **NFR2**: Bounded memory growth (proactive cleanup of expired entries)
3. **NFR3**: Observable via Prometheus metrics
4. **NFR4**: Configurable via flags/environment variables
5. **NFR5**: Backward compatible (feature flag for gradual rollout)
6. **NFR6**: Comprehensive test coverage (>80% for critical paths)

### Assumptions
- Controller-runtime provides exponential backoff (5ms → 1000s) per resource
- Vault clients are mostly stateless (safe to share after auth)
- Token renewal is optional (many deployments use short-lived tokens)
- Most operations are read-only (GetSecret, GetSecretMap)

## 3. Architecture Overview

```
┌─────────────────────────────────┐
│   Controller (Reconciliation)    │
└─────────────┬────────────────────┘
              │ borrows
┌─────────────▼────────────────────┐
│     secretstore.Manager          │
│   (holds ClientLease reference)  │
└─────────────┬────────────────────┘
              │ acquires
┌─────────────▼────────────────────┐       ┌──────────────────┐
│      Provider.NewClient          │       │   ClientLease    │
│  (returns SecretsClient with     │───────│ - WithRetry()    │
│   embedded lease for release)    │       │ - Close()        │
└─────────────┬────────────────────┘       └──────────────────┘
              │ uses
┌─────────────▼────────────────────┐       ┌──────────────────┐
│         ClientPool               │       │ CachedVaultClient│
│  - Acquire() → ClientLease       │◀─────▶│ - lease counting │
│  - Shutdown()                    │       │ - re-auth logic  │
│  - Circuit Breaker               │       │ - renewal timer  │
└──────────────────────────────────┘       └──────────────────┘
```

### Component Responsibilities

1. **ClientPool**: Manages cache of authenticated clients, enforces circuit breaker, handles eviction
2. **ClientLease**: Opaque handle that encapsulates retry logic and ensures proper release
3. **CachedVaultClient**: Manages token lifecycle, renewal scheduling, and re-authentication
4. **SecretsClient**: ESO interface implementation that delegates to pool via lease
5. **CircuitBreaker**: Prevents auth storms during Vault outages

## 4. Detailed Design

### 4.1 Client Lifecycle Management

#### The Critical Fix: Lease-Based Release
```go
// Current BROKEN implementation
func (c *client) Close(ctx context.Context) error {
    // This revokes the token, making pooling useless!
    if c.client.Token() != "" {
        revokeTokenIfValid(ctx, c.client)
    }
}

// CORRECT implementation
type vaultSecretsClient struct {
    // ... existing fields ...
    poolLease ClientLease  // NEW: holds lease for release
}

func (c *vaultSecretsClient) Close(ctx context.Context) error {
    if c.poolLease != nil {
        return c.poolLease.Close(ctx)  // Delegate to pool
    }
    return nil
}
```

#### Lease Interface
```go
type ClientLease interface {
    Client() util.Client                                    // Get underlying client
    WithRetry(ctx context.Context, op func(util.Client) error) error  // Auto-retry on auth error
    Close(ctx context.Context) error                       // Release back to pool
}

type clientLease struct {
    pool   *CachingClientPool
    client *CachedVaultClient
    closed bool
    mu     sync.Mutex
}

func (l *clientLease) Close(ctx context.Context) error {
    l.mu.Lock()
    defer l.mu.Unlock()
    if l.closed {
        return nil  // Idempotent
    }
    l.closed = true
    l.pool.releaseLease(l.client)
    return nil
}
```

### 4.2 Cache Key Strategy

#### Comprehensive Identity Hashing
```go
func ComputeCacheKey(cfg VaultClientConfig) string {
    h := sha256.New()

    // Core identity
    h.Write([]byte(cfg.VaultSpec.Server))
    h.Write([]byte(cfg.VaultSpec.Namespace))
    h.Write([]byte(determineAuthMethod(cfg.VaultSpec.Auth)))

    // Auth configuration (with secret resolution)
    authData := resolveAuthSecrets(cfg)
    h.Write(authData)

    // TLS configuration - MUST include CA!
    h.Write([]byte(fmt.Sprintf("%v", cfg.VaultSpec.InsecureSkipVerify)))
    h.Write([]byte(cfg.VaultSpec.ServerName))
    if cfg.VaultSpec.CABundle != nil {
        h.Write(cfg.VaultSpec.CABundle)
    }
    if cfg.VaultSpec.CAProvider != nil {
        h.Write([]byte(cfg.VaultSpec.CAProvider.Type))
        h.Write([]byte(cfg.VaultSpec.CAProvider.Name))
        h.Write([]byte(cfg.VaultSpec.CAProvider.Namespace))
        h.Write([]byte(cfg.VaultSpec.CAProvider.Key))
    }

    // Store identity
    h.Write([]byte(cfg.Metadata.StoreKind))
    h.Write([]byte(cfg.Metadata.StoreName))
    h.Write([]byte(cfg.Metadata.StoreNamespace))

    // Headers if present
    for k, v := range cfg.VaultSpec.Headers {
        h.Write([]byte(k))
        h.Write([]byte(v))
    }

    return hex.EncodeToString(h.Sum(nil))
}
```

### 4.3 Re-Authentication Strategy

#### WithRetry Pattern (No Proactive Validation)
```go
func (c *CachedVaultClient) WithRetry(ctx context.Context, op func(util.Client) error) error {
    // Try operation first - no proactive validation
    err := op(c.vaultClient)

    // Success or non-auth error - return immediately
    if !isAuthError(err) {
        c.recordBreakerResult(err)
        return err
    }

    // Auth error - attempt re-authentication ONCE
    _, reauthErr, _ := c.reauthGroup.Do(c.cacheKey, func() (interface{}, error) {
        c.vaultClient.ClearToken()
        return nil, c.reauthenticate(ctx)
    })
    c.reauthGroup.Forget(c.cacheKey)  // CRITICAL: prevent memory leak

    if reauthErr != nil {
        c.recordBreakerResult(reauthErr)
        return fmt.Errorf("vault re-auth failed: %w", reauthErr)
    }

    // Retry operation with new token
    err = op(c.vaultClient)
    c.recordBreakerResult(err)
    return err
}

func isAuthError(err error) bool {
    if err == nil {
        return false
    }
    // Check for Vault auth errors (403, 401)
    var respErr *vault.ResponseError
    if errors.As(err, &respErr) {
        return respErr.StatusCode == 401 || respErr.StatusCode == 403
    }
    return false
}
```

### 4.4 Circuit Breaker Implementation

```go
type CircuitBreaker struct {
    mu       sync.RWMutex
    circuits map[string]*circuit

    failureThreshold int           // Open after N failures (default: 5)
    failureWindow    time.Duration // Within this window (default: 30s)
    cooldownPeriod   time.Duration // Stay open this long (default: 30s)
}

type circuit struct {
    failures      []time.Time
    state         CircuitState
    openUntil     time.Time
}

func (cb *CircuitBreaker) Check(key CircuitBreakerKey) error {
    cb.mu.RLock()
    c := cb.circuits[key.String()]
    cb.mu.RUnlock()

    if c == nil {
        return nil  // No failures yet
    }

    if c.state == CircuitOpen && time.Now().After(c.openUntil) {
        // Transition to half-open
        cb.mu.Lock()
        c.state = CircuitHalfOpen
        cb.mu.Unlock()
        return nil  // Allow one probe
    }

    if c.state == CircuitOpen {
        return ErrCircuitOpen
    }

    return nil
}
```

### 4.5 Token Renewal Strategy

#### One-Shot Timer Approach
```go
func (c *CachedVaultClient) scheduleRenewal(tokenTTL time.Duration) {
    if !c.renewalEnabled || tokenTTL <= 0 {
        return
    }

    // Cancel previous timer if exists
    if c.renewalTimer != nil {
        c.renewalTimer.Stop()
    }

    // Calculate next renewal (80% of TTL)
    renewIn := time.Duration(float64(tokenTTL) * 0.8)
    c.nextRenewal = time.Now().Add(renewIn)

    // Schedule one-shot timer
    c.renewalTimer = time.AfterFunc(renewIn, func() {
        if err := c.renewToken(); err != nil {
            c.onEvict(c.cacheKey)  // Mark for eviction
        } else {
            // Success - schedule next renewal
            c.scheduleRenewal(c.tokenTTL)
        }
    })
}
```

### 4.6 Dynamic TLS Handling

```go
func shouldCacheTLSClient(spec *esv1.VaultProvider) bool {
    // Never cache if using dynamic TLS materials
    if hasDynamicTLS(spec) {
        // Unless explicitly opted in via flag
        return viper.GetBool("vault-client-pool-allow-dynamic-tls-cache")
    }
    return true
}

func hasDynamicTLS(spec *esv1.VaultProvider) bool {
    tls := spec.ClientTLS

    // Client cert/key from secrets
    if tls.CertSecretRef != nil || tls.KeySecretRef != nil {
        return true
    }

    // CA from ConfigMap or Secret
    if spec.CAProvider != nil {
        switch spec.CAProvider.Type {
        case "Secret", "ConfigMap":
            return true
        }
    }

    return false
}
```

## 5. Implementation Roadmap

### Phase 1: Foundation (Week 1)
1. **Fix pool bypass** - Update client.Close() to use lease.Close()
2. **Implement ClientLease** abstraction with proper release semantics
3. **Add WithRetry** pattern for lazy validation
4. **Wire pool into Provider.NewClient**

### Phase 2: Resilience (Week 2)
1. **Circuit breaker** implementation with metrics
2. **Comprehensive cache key** including all TLS config
3. **Config synchronization** with proper locking
4. **Timer-based renewal** replacing polling

### Phase 3: Production Readiness (Week 3)
1. **Dynamic TLS handling** with feature flag
2. **Background cleanup** ticker for expired entries
3. **Comprehensive metrics** and logging
4. **Race condition testing** and fixes

### Phase 4: Documentation & Testing (Week 4)
1. **Unit tests** with >80% coverage
2. **Integration tests** with mock Vault
3. **Documentation** updates
4. **Performance benchmarks**

## 6. Testing Strategy

### Unit Tests
```go
// Critical test cases
func TestClientLease_ReleaseCalledOnClose(t *testing.T)
func TestWithRetry_ReauthenticatesOn403(t *testing.T)
func TestCircuitBreaker_OpensAfterThreshold(t *testing.T)
func TestCacheKey_ChangesOnCARotation(t *testing.T)
func TestRenewal_UsesOneShot Timer(t *testing.T)
func TestEviction_WaitsForActiveLeases(t *testing.T)
```

### Integration Tests
- Expired token recovery within single reconcile
- Concurrent reconciliations sharing client
- CA rotation triggers cache miss
- Circuit breaker prevents auth storms

### Race Detection
```bash
go test -race -count=10 ./pkg/provider/vault/...
```

## 7. Operational Considerations

### Configuration
```yaml
# Feature flags
--enable-vault-client-pooling=true
--vault-client-pool-size=1000
--vault-client-pool-ttl=1h
--vault-client-pool-allow-dynamic-tls-cache=false

# Circuit breaker
--vault-circuit-breaker-threshold=5
--vault-circuit-breaker-window=30s
--vault-circuit-breaker-cooldown=30s

# Renewal
--vault-token-renewal-enabled=true
--vault-token-renewal-threshold=0.8
```

### Metrics
```prometheus
# Pool effectiveness
vault_client_pool_hits_total
vault_client_pool_misses_total
vault_client_pool_active_clients

# Auth operations
vault_client_auth_success_total
vault_client_auth_failure_total
vault_client_reauth_attempts_total

# Circuit breaker
vault_circuit_breaker_state{state="open|closed|half_open"}
vault_circuit_breaker_trips_total

# Token lifecycle
vault_token_renewals_total
vault_token_revocations_total
```

### Failure Modes
1. **Vault Unavailable**: Circuit breaker opens, controllers back off exponentially
2. **Token Expired**: Automatic re-auth within reconciliation
3. **CA Rotation**: Cache miss forces new client creation
4. **Memory Pressure**: LRU eviction + background cleanup

## 8. Migration Plan

### Rollout Strategy
1. Deploy with pooling disabled (default)
2. Enable for non-critical namespaces
3. Monitor metrics for 24-48 hours
4. Gradual rollout to production namespaces
5. Enable globally after validation

### Rollback Plan
- Feature flag allows instant disable
- Pool cleanup happens automatically
- No persistent state to clean up

## 9. Security Considerations

1. **Token Isolation**: Each unique identity gets separate client
2. **Token Revocation**: On graceful shutdown only (not per-reconcile)
3. **TLS Validation**: Full TLS config in cache key prevents reuse
4. **Secret Rotation**: Automatic detection via cache key changes
5. **Audit Logging**: All auth operations logged at appropriate levels

## 10. Conclusion

This design addresses all critical issues identified in the review while maintaining simplicity and correctness. The lease abstraction provides clean separation of concerns, the circuit breaker prevents auth storms, and proper cache key computation ensures security.

The implementation is incremental, testable, and observable - suitable for production deployment in a critical operator like ESO.