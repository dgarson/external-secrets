---
hide:
  - toc
---

# Metrics

The External Secrets Operator exposes its Prometheus metrics in the `/metrics` path. To enable it, set the `serviceMonitor.enabled` Helm flag to `true`.

If you are using a different monitoring tool that also needs a `/metrics` endpoint, you can set the `metrics.service.enabled` Helm flag to `true`. In addition you can also set `webhook.metrics.service.enabled` and `certController.metrics.service.enabled` to scrape the other components.

The Operator has [the controller-runtime metrics inherited from kubebuilder](https://book.kubebuilder.io/reference/metrics-reference.html) plus some custom metrics with a resource name prefix, such as `externalsecret_`.

## Granular Metrics

By default, metrics include basic labels like `name` and `namespace`. The `--enable-granular-metrics` flag adds additional labels to help identify performance bottlenecks and failures at a more granular level:

**Added Labels:**
- `secretstore_name` / `secretstore_namespace`: Identifies which SecretStore/ClusterSecretStore is associated with the resource
- `provider_type`: Identifies the provider type (e.g., "vault", "aws", "gcpsm") for SecretStore metrics

**Affected Metrics:**
- All ExternalSecret metrics (including `externalsecret_store_api_calls_count` for per-store provider API tracking)
- All PushSecret metrics
- All ClusterExternalSecret metrics (secretstore_name only)
- All ClusterPushSecret metrics (secretstore_name only)
- All SecretStore/ClusterSecretStore metrics

**Provider API Call Metrics:**

ESO provides two complementary metrics for tracking provider API calls:

| Metric | Scope | Cardinality | Use Case |
|--------|-------|-------------|----------|
| `externalsecret_provider_api_calls_count` | **All API calls** including internal provider operations (auth, retries, token refresh) | Low (always enabled) | Overall provider health, total API usage |
| `externalsecret_store_api_calls_count` | **Controller-initiated operations only** (GetSecret, PushSecret, Validate, etc.) | High (requires `--enable-granular-metrics`) | Per-SecretStore troubleshooting, tenant attribution |

**Important:** `store_api_calls_count` intentionally undercounts vs `provider_api_calls_count` because it only tracks operations initiated by controllers. It does NOT include:
- Provider authentication/token refresh calls
- Internal retries within provider code
- Multi-step operations (e.g., Vault metadata fetch + secret fetch counted as 1)

**When to use each:**
- **Debugging total API usage**: Use `provider_api_calls_count`
- **Identifying which SecretStore is causing issues**: Use `store_api_calls_count` (when granular metrics enabled)

**⚠️ Cardinality Warning:**
Enabling granular metrics increases metric cardinality. In large deployments, this can significantly impact Prometheus performance and storage:
- **Cardinality multiplier**: ~(number of resources × number of SecretStores) for ExternalSecret/PushSecret metrics
- **Cardinality multiplier**: ~(number of SecretStores × number of provider types) for SecretStore metrics

**When to enable:**
- ✅ Debugging specific SecretStore performance issues
- ✅ Multi-tenant deployments needing per-store observability
- ✅ Environments with <100 SecretStores and adequate Prometheus capacity
- ❌ Very large deployments (1000+ ExternalSecrets/SecretStores)
- ❌ Prometheus clusters with limited capacity

## Cluster External Secret Metrics
| Name                                       | Type  | Description                                                | Granular Labels¹              |
|--------------------------------------------|-------|------------------------------------------------------------|-----------------------------|
| `clusterexternalsecret_status_condition`   | Gauge | The status condition of a specific Cluster External Secret | `secretstore_name`          |
| `clusterexternalsecret_reconcile_duration` | Gauge | The duration time to reconcile the Cluster External Secret | `secretstore_name`          |

## External Secret Metrics
| Name                                           | Type      | Description                                                                                                                                                                                                             | Granular Labels¹                              |
|------------------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| `externalsecret_provider_api_calls_count`      | Counter   | Number of API calls made to an upstream secret provider API. The metric provides a `provider`, `call` and `status` labels.                                                                                              | -                                           |
| `externalsecret_store_api_calls_count`         | Counter   | Number of controller-initiated API calls to secret providers, aggregated by SecretStore. Provides `provider`, `call`, and `status` labels.                                                                             | `secretstore_kind`, `secretstore_name`, `secretstore_namespace` |
| `externalsecret_sync_calls_total`              | Counter   | Total number of the External Secret sync calls                                                                                                                                                                          | `secretstore_name`, `secretstore_namespace` |
| `externalsecret_sync_calls_error`              | Counter   | Total number of the External Secret sync errors                                                                                                                                                                         | `secretstore_name`, `secretstore_namespace` |
| `externalsecret_status_condition`              | Gauge     | The status condition of a specific External Secret                                                                                                                                                                      | `secretstore_name`, `secretstore_namespace` |
| `externalsecret_reconcile_duration`            | Gauge     | The duration time to reconcile the External Secret                                                                                                                                                                      | `secretstore_name`, `secretstore_namespace` |

## Push Secret Metrics
| Name                                    | Type  | Description                                             | Granular Labels¹                              |
|-----------------------------------------|-------|--------------------------------------------------------|---------------------------------------------|
| `pushsecret_status_condition`   | Gauge | The status condition of a specific Push Secret | `secretstore_name`, `secretstore_namespace` |
| `pushsecret_reconcile_duration` | Gauge | The duration time to reconcile the Push Secret | `secretstore_name`, `secretstore_namespace` |

## Cluster Push Secret Metrics
| Name                                          | Type  | Description                                                   | Granular Labels¹       |
|-----------------------------------------------|-------|---------------------------------------------------------------|----------------------|
| `clusterpushsecret_status_condition`          | Gauge | The status condition of a specific Cluster Push Secret       | `secretstore_name`   |
| `clusterpushsecret_reconcile_duration`        | Gauge | The duration time to reconcile the Cluster Push Secret       | `secretstore_name`   |

## Cluster Secret Store Metrics
| Name                                    | Type  | Description                                             | Granular Labels¹  |
|-----------------------------------------|-------|---------------------------------------------------------|-----------------|
| `clustersecretstore_status_condition`   | Gauge | The status condition of a specific Cluster Secret Store | `provider_type` |
| `clustersecretstore_reconcile_duration` | Gauge | The duration time to reconcile the Cluster Secret Store | `provider_type` |

## Secret Store Metrics
| Name                             | Type  | Description                                     | Granular Labels¹  |
|----------------------------------|-------|-------------------------------------------------|-----------------|
| `secretstore_status_condition`   | Gauge | The status condition of a specific Secret Store | `provider_type` |
| `secretstore_reconcile_duration` | Gauge | The duration time to reconcile the Secret Store | `provider_type` |

¹ These additional labels are only present when `--enable-granular-metrics=true`

## Controller Runtime Metrics
See [the kubebuilder documentation](https://book.kubebuilder.io/reference/metrics-reference.html) on the default exported metrics by controller-runtime.

## Dashboard

We provide a [Grafana Dashboard](https://raw.githubusercontent.com/external-secrets/external-secrets/main/docs/snippets/dashboard.json) that gives you an overview of External Secrets Operator:

![ESO Dashboard](../pictures/eso-dashboard-1.png)
![ESO Dashboard](../pictures/eso-dashboard-2.png)


## Service Level Indicators and Alerts

We find the following Service Level Indicators (SLIs) useful when operating ESO. They should give you a good starting point and hints to develop your own Service Level Objectives (SLOs).

#### Webhook HTTP Status Codes
The webhook HTTP status code indicates that a HTTP Request was answered successfully or not.
If the Webhook pod is not able to serve the requests properly then that failure may cascade down to the controller or any other user of `kube-apiserver`.

SLI Example: request error percentage.
```
sum(increase(controller_runtime_webhook_requests_total{service=~"external-secrets.*",code="500"}[1m]))
/
sum(increase(controller_runtime_webhook_requests_total{service=~"external-secrets.*"}[1m]))
```

#### Webhook HTTP Request Latency
If the webhook server is not able to respond in time then that may cause a timeout at the client.
This failure may cascade down to the controller or any other user of `kube-apiserver`.

SLI Example: p99 across all webhook requests.
```
histogram_quantile(0.99,
  sum(rate(controller_runtime_webhook_latency_seconds_bucket{service=~"external-secrets.*"}[5m])) by (le)
)
```

#### Controller Workqueue Depth
If the workqueue depth is > 0 for a longer period of time then this is an indicator for the controller not being able to reconcile resources in time. I.e. delivery of secret updates is delayed.

Note: when a controller is restarted, then `queue length = total number of resources`. Make sure to measure the time it takes for the controller to fully reconcile all secrets after a restart. In large clusters this may take a while, make sure to define an acceptable timeframe to fully reconcile all resources.

```
sum(
  workqueue_depth{service=~"external-secrets.*"}
) by (name)
```

#### Controller Reconcile Latency
The controller should be able to reconcile resources within a reasonable timeframe. When latency is high secret delivery may impacted.

SLI Example: p99 across all controllers.
```
histogram_quantile(0.99,
  sum(rate(controller_runtime_reconcile_time_seconds_bucket{service=~"external-secrets.*"}[5m])) by (le)
)
```

#### Controller Reconcile Error
The controller should be able to reconcile resources without errors. When errors occur secret delivery may be impacted which could cascade down to the secret consuming applications.

```
sum(increase(
  controller_runtime_reconcile_total{service=~"external-secrets.*",controller=~"$controller",result="error"}[1m])
) by (result)
```
