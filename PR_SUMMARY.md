# Add Per-SecretStore Provider API Call Metrics

## Problem Statement

Currently, the `externalsecret_provider_api_calls_count` metric tracks all provider API calls but cannot answer questions like:
- "Which SecretStore is experiencing the most API call failures?"
- "Is the production Vault SecretStore healthy compared to the dev one?"
- "Which tenant's SecretStore is causing rate limiting?"

In multi-tenant deployments or large-scale operations, the ability to attribute provider API calls to specific SecretStores is valuable for troubleshooting and capacity planning.

## Implemented Solution

This PR adds a **new opt-in metric** `externalsecret_store_api_calls_count` that tracks controller-initiated provider API calls with SecretStore attribution, enabled via the existing `--enable-granular-metrics` flag.

### Metric Comparison

| Metric | Scope | Cardinality | Use Case |
|--------|-------|-------------|----------|
| `externalsecret_provider_api_calls_count` (existing) | **All API calls** including internal provider operations (auth, retries, token refresh) | Low (always enabled) | Overall provider health, total API usage |
| `externalsecret_store_api_calls_count` (new) | **Controller-initiated operations only** (GetSecret, PushSecret, Validate, etc.) | High (requires flag) | Per-SecretStore troubleshooting, tenant attribution |

### Labels Added

When `--enable-granular-metrics=true`:
```
externalsecret_store_api_calls_count{
  provider="vault",
  call="GetSecret",
  status="success",
  secretstore_kind="SecretStore",
  secretstore_name="prod-vault",
  secretstore_namespace="default"
}
```

### Operations Tracked

- **ExternalSecret**: GetSecret, GetSecretMap, GetAllSecrets
- **PushSecret**: PushSecret, SecretExists, DeleteSecret
- **SecretStore/ClusterSecretStore**: Validate

## Implementation Details

### Architecture: Controller-Layer Recording

Metrics are recorded at the **controller layer** (where SecretStore context is available) rather than deep in provider code. This design choice:
- ✅ Requires **zero changes to provider implementations** (30+ files untouched)
- ✅ Minimizes PR scope (7 files changed)
- ✅ Preserves backward compatibility
- ⚠️ Only captures controller-initiated operations (not internal provider auth/retries)

### Key Components

1. **`StoreMetricsRecorder`** (pkg/controllers/metrics/labels.go)
   - Helper struct encapsulating SecretStore context
   - Provides type-safe `Observe(operation, err)` method
   - Uses operation constants (e.g., `OperationGetSecret`) to prevent typos

2. **Manager.Get() Enhancement** (pkg/controllers/secretstore/client_manager.go)
   - Now returns `(client, recorder, error)` instead of `(client, error)`
   - Automatically creates recorder from SecretStore metadata
   - All controllers get recorder "for free" when fetching client

3. **ObserveStoreAPICall()** (pkg/metrics/metrics.go)
   - Records metric with store labels when granular metrics enabled
   - Callback pattern avoids import cycles
   - Metric help text clearly states "controller-initiated operations only"

### Files Changed (7 total)

```
pkg/controllers/metrics/labels.go          (+98 lines)  - Recorder + constants + tests
pkg/metrics/metrics.go                     (+31 lines)  - New metric + callback
pkg/controllers/secretstore/client_manager.go (+16 lines)  - Get() returns recorder
pkg/controllers/externalsecret/externalsecret_controller_secret.go (+4 lines)   - Use recorder
pkg/controllers/pushsecret/pushsecret_controller.go (+6 lines)   - Use recorder
pkg/controllers/secretstore/common.go      (+12 lines)  - Use recorder
docs/api/metrics.md                        (+28 lines)  - Documentation
```

**Provider files changed: 0**

## Testing

Added comprehensive unit tests covering the entire metric recording pipeline:

### StoreMetricsRecorder Tests (pkg/controllers/metrics/labels_test.go)
- ✅ `TestStoreMetricsRecorder_Observe`: Tests callback invocation, granular metrics flag, nil safety
- ✅ `TestNewStoreMetricsRecorder`: Tests recorder construction
- ✅ Covers SecretStore vs ClusterSecretStore distinction
- ✅ Tests enabled/disabled granular metrics behavior

### Metric Publication Tests (pkg/metrics/metrics_test.go)
- ✅ `TestObserveStoreAPICall_GranularMetricsDisabled`: Verifies no metrics recorded when flag disabled
- ✅ `TestObserveStoreAPICall_GranularMetricsEnabled`: Verifies correct label values for SecretStore and ClusterSecretStore
- ✅ `TestObserveStoreAPICall_MultipleIncrements`: Verifies counter accumulates correctly
- ✅ `TestSetUpMetrics_LabelConfiguration`: Verifies metric registered with correct labels based on flag state

**Test Coverage:**
- ✅ Flag-based conditional behavior
- ✅ Label value correctness
- ✅ Counter increment behavior
- ✅ SecretStore vs ClusterSecretStore (including empty namespace)
- ✅ Success vs error status
- ✅ Multiple providers and operations

All tests pass (11 test cases total):
```
=== RUN   TestStoreMetricsRecorder_Observe
    --- PASS: TestStoreMetricsRecorder_Observe/Granular_metrics_disabled (0.00s)
    --- PASS: TestStoreMetricsRecorder_Observe/Granular_metrics_enabled_-_SecretStore (0.00s)
    --- PASS: TestStoreMetricsRecorder_Observe/Granular_metrics_enabled_-_ClusterSecretStore (0.00s)
    --- PASS: TestStoreMetricsRecorder_Observe/Nil_recorder (0.00s)
--- PASS: TestStoreMetricsRecorder_Observe (0.00s)

=== RUN   TestObserveStoreAPICall_GranularMetricsDisabled
--- PASS: TestObserveStoreAPICall_GranularMetricsDisabled (0.00s)

=== RUN   TestObserveStoreAPICall_GranularMetricsEnabled
    --- PASS: TestObserveStoreAPICall_GranularMetricsEnabled/SecretStore_success (0.00s)
    --- PASS: TestObserveStoreAPICall_GranularMetricsEnabled/ClusterSecretStore_error (0.00s)
--- PASS: TestObserveStoreAPICall_GranularMetricsEnabled (0.00s)

=== RUN   TestObserveStoreAPICall_MultipleIncrements
--- PASS: TestObserveStoreAPICall_MultipleIncrements (0.00s)

=== RUN   TestSetUpMetrics_LabelConfiguration
    --- PASS: TestSetUpMetrics_LabelConfiguration/Granular_metrics_disabled (0.00s)
    --- PASS: TestSetUpMetrics_LabelConfiguration/Granular_metrics_enabled (0.00s)
--- PASS: TestSetUpMetrics_LabelConfiguration (0.00s)
```

## Documentation

### Metric Help Text
Clearly states incomplete coverage:
```
"Number of controller-initiated API calls to secret providers, aggregated by SecretStore
(requires --enable-granular-metrics). Does not include internal provider operations like auth retries."
```

### User Documentation (docs/api/metrics.md)
Added comprehensive section explaining:
- ✅ Comparison table of both metrics
- ✅ What operations are NOT captured (auth, retries, multi-step ops)
- ✅ When to use each metric
- ✅ Cardinality impact warning with formulas
- ✅ Example PromQL queries
- ✅ `secretstore_kind` label for distinguishing SecretStore vs ClusterSecretStore

## Cardinality Impact

**Formula**: `Base × Number of SecretStores`
- Base: 10 providers × 8 operations × 2 statuses × 2 kinds = **320 series**
- 100 stores: **32,000 series**
- 500 stores: **160,000 series**
- 1000 stores: **320,000 series**

**Mitigation**:
- Opt-in via flag (default: false)
- Clear warnings in docs and flag help text
- Only recorded when granular metrics explicitly enabled

## Trade-off Analysis: Two Metrics vs Enhanced Existing Metric

### Current Approach: Separate Metric (This PR)

**Pros:**
- ✅ Minimal PR scope (7 files vs 35+ files)
- ✅ Zero provider code changes
- ✅ Backward compatible (existing metric unchanged)
- ✅ Low review burden
- ✅ Low risk of bugs

**Cons:**
- ❌ Metric duplication (two similar metrics)
- ❌ Incomplete coverage (controller ops only, misses auth/retries)
- ❌ User confusion potential ("why don't these match?")
- ❌ Two parallel systems to maintain

### Alternative: Context-Based Enhanced Metric

**What it would look like:**
```go
// Add store ref to context in controllers
ctx = ctrlmetrics.WithStoreRef(ctx, storeName, storeKind, namespace)

// Change ObserveAPICall signature (breaking change)
func ObserveAPICall(ctx context.Context, provider, call string, err error) {
    storeRef := GetStoreRef(ctx) // extract from context
    // Record with store labels if present + granular metrics enabled
}

// Update ALL provider callsites (~100+)
metrics.ObserveAPICall(ctx, "vault", "GetSecret", err)
```

**Pros:**
- ✅ Complete coverage (captures ALL provider operations)
- ✅ No metric duplication (single source of truth)
- ✅ Accurate counts (includes auth, retries, multi-step ops)
- ✅ Idiomatic Go (context propagation standard pattern)
- ✅ Future-proof (context can carry tracing, request IDs, etc.)

**Cons:**
- ❌ Large PR scope (35+ files changed)
- ❌ ~100+ callsites across all providers need updating
- ❌ Breaking API change (`ObserveAPICall` signature)
- ❌ High review burden for maintainers
- ❌ Risk of missing callsites during migration

**Comparison:**

| Aspect | Separate Metric (This PR) | Context-Based |
|--------|---------------------------|---------------|
| Files changed | 7 | 35+ |
| Provider files touched | 0 | ~30 |
| Callsites updated | 8 | 108+ |
| Breaking changes | No | Yes |
| Coverage completeness | Partial | Complete |
| Review burden | Low | Very High |
| Maintenance burden | Higher (2 systems) | Lower (1 system) |

## Questions for Maintainers

I've implemented the **minimal-change approach** (separate metric, controller-layer recording) to reduce PR scope and review burden. However, I recognize this comes with trade-offs.

**Which approach would you prefer?**

1. **Accept this PR as-is** (separate metric, controller-layer only)
   - Quick to review and merge
   - Provides immediate value for per-store troubleshooting
   - Can be enhanced later if needed

2. **Request context-based implementation** (enhanced existing metric)
   - I can implement this if you prefer the more complete solution
   - Larger PR but cleaner long-term architecture
   - Better coverage but higher review burden

3. **Phased migration approach**
   - Phase 1: This PR (separate metric)
   - Phase 2: Add optional context parameter to ObserveAPICall
   - Phase 3: Gradually migrate provider callsites
   - Phase 4: Deprecate separate metric

I'm happy to implement whichever approach aligns with your vision for ESO metrics architecture.

## Example Queries

```promql
# Which SecretStore has the most API call errors?
topk(5, sum by (secretstore_name, secretstore_namespace) (
  rate(externalsecret_store_api_calls_count{status="error"}[5m])
))

# Compare API call rate between SecretStores
sum by (secretstore_name) (
  rate(externalsecret_store_api_calls_count{provider="vault"}[5m])
)

# Per-tenant attribution (assuming namespaces = tenants)
sum by (secretstore_namespace) (
  rate(externalsecret_store_api_calls_count[5m])
)

# Are there many unattributed calls? (auth/retries)
sum(rate(externalsecret_provider_api_calls_count{provider="vault"}[5m]))
-
sum(rate(externalsecret_store_api_calls_count{provider="vault"}[5m]))
```

## Checklist

- [x] Code builds successfully
- [x] Unit tests added and passing
- [x] Documentation updated (metrics.md)
- [x] Flag help text includes cardinality warning
- [x] Metric help text explains incomplete coverage
- [x] Operation constants defined (type-safe)
- [x] ClusterSecretStore properly distinguished (secretstore_kind label)
- [x] Backward compatible (no breaking changes)
- [ ] Maintainer feedback on preferred approach
