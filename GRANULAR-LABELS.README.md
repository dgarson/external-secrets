# Granular Labels Patch

This patch file contains changes that add granular SecretStore labels to ALL existing controller metrics when `--enable-granular-metrics` is enabled.

## What This Patch Does

Adds optional labels to existing metrics:
- ExternalSecret metrics: `secretstore_name`, `secretstore_namespace`
- PushSecret metrics: `secretstore_name`, `secretstore_namespace`
- ClusterExternalSecret metrics: `secretstore_name` (no namespace for cluster-scoped stores)
- ClusterPushSecret metrics: `secretstore_name` (no namespace for cluster-scoped stores)
- SecretStore/ClusterSecretStore metrics: `provider_type`

## Affected Metrics (12 total)

1. `externalsecret_sync_calls_total`
2. `externalsecret_sync_calls_error`
3. `externalsecret_status_condition`
4. `externalsecret_reconcile_duration`
5. `pushsecret_status_condition`
6. `pushsecret_reconcile_duration`
7. `clusterexternalsecret_status_condition`
8. `clusterexternalsecret_reconcile_duration`
9. `clusterpushsecret_status_condition`
10. `clusterpushsecret_reconcile_duration`
11. `secretstore_status_condition`
12. `secretstore_reconcile_duration`
13. `clustersecretstore_status_condition`
14. `clustersecretstore_reconcile_duration`

## Files Modified

- `pkg/controllers/externalsecret/esmetrics/esmetrics.go`
- `pkg/controllers/pushsecret/psmetrics/psmetrics.go`
- `pkg/controllers/clusterexternalsecret/cesmetrics/cesmetrics.go`
- `pkg/controllers/clusterpushsecret/cpsmetrics/cpsmetrics.go`
- `pkg/controllers/secretstore/ssmetrics/ssmetrics.go`
- `pkg/controllers/secretstore/cssmetrics/cssmetrics.go`

## Cardinality Impact

When `--enable-granular-metrics=true`, each metric's cardinality multiplies by:
- Number of SecretStores (for ES/PS metrics)
- Number of provider types (for SS/CSS metrics)

Example: With 100 SecretStores, `externalsecret_status_condition` goes from ~10 series to ~1000 series.

## How to Apply

```bash
# Apply the patch
git apply GRANULAR-LABELS.patch

# Or use patch command
patch -p1 < GRANULAR-LABELS.patch
```

## How to Revert

```bash
# Revert using git
git apply -R GRANULAR-LABELS.patch

# Or using patch command
patch -R -p1 < GRANULAR-LABELS.patch
```

## Testing

After applying, ensure:
1. All tests pass: `make test`
2. Metrics are properly labeled when flag is enabled
3. Metrics work normally when flag is disabled (default)

## Rationale

This change enables consistent SecretStore attribution across ALL metrics, not just API calls.
This allows correlating:
- API call failures with reconcile failures for the same store
- Store validation status with resource sync status
- Provider-level issues across all metric dimensions

## Concerns

This is a **broader scope change** than just adding the new `externalsecret_store_api_calls_count` metric.
Consider whether this should be:
1. A separate PR (metrics labels overhaul)
2. Documented as intentional scope expansion
3. Removed if not essential to core feature
