# Sonnet Vault Client Pooling Design

## 1. Purpose & Goals

The External Secrets Operator (ESO) must minimise Vault authentication traffic, tolerate high concurrency, and remain safe under credential rotation or Vault outage.  This design introduces a first-class **Vault Client Pool** that supplies short-lived *leases* over cached clients.  The goals are:

1. **Reuse connections & tokens** across reconciliations.
2. **Guarantee correctness per identity** – no credential leakage or token revocation races.
3. **Fail fast & heal fast** – circuit break repeated auth failures while allowing quick recovery.
4. **Be Kubernetes-controller friendly** – integrate with controller-runtime back-off & informers.
5. **Offer clear observability & configuration knobs** so operators understand behaviour.

---

## 2. Non-Functional Requirements

* Support ≥5 000 ExternalSecrets at 1 rps each without exhausting Vault rate limits.
* No goroutine or memory leaks under continuous churn tests (24 h soak, `go test -race`).
* Mean additional latency per read ≤ 2 ms P95.
* Disabled by default; single flag enables pooling.
* Zero breaking API change to provider interface.

---

## 3. Assumptions & Scope

* ESO controllers already re-queue failed reconciles with exponential back-off.
* Vault API client (`util.Client`) is safe for concurrent use after token is set.
* Only read operations (*Get*, *List*, *Exists*) are retried automatically; write/delete are single-attempt unless `--vault-retry-mutations` is set.
* Static tokens are identified by presence of `spec.auth.tokenSecretRef`.
* Dynamic TLS assets reside in Secrets/ConfigMaps and can change at runtime.

---

## 4. Architecture Overview

```text
┌─────────────────────────────────────┐
│ ESO controller reconcile goroutine │
└──────────────┬──────────────────────┘
               │ Acquire(…)
┌──────────────▼───────────────┐   Lease.Close()   ┌───────────────────┐
│  CachingClientPool (LRU)     │◀──────────────────▶│ CachedVaultClient │
│  - mutex & LRU cache         │                   │  (token, timers) │
│  - circuit breaker           │                   └───────────────────┘
│  - background cleanup        │ WithRetry(op) ▲
└──────────────┬───────────────┘                 │
               │ new on miss                     │ Vault API calls
               ▼                                 ▼
        Vault HTTP / mTLS / KV
```

### Key Types

| Type | Responsibility |
|------|----------------|
| `ClientPool` | Global entry – acquires `ClientLease`, owns cache & cleanup |
| `ClientLease` | Per-borrow wrapper exposing `Client()` and `WithRetry()`; tracks ref-count |
| `CachedVaultClient` | Holds `util.Client`, renewal timer, breaker key, eviction flag |
| `CircuitBreaker` | Per-identity failure tracker shared by pool & cached client |
| `VaultClientID` | Canonical cache-key struct (Vault URL + auth + TLS hash + store metadata) |

---

## 5. Detailed Design

### 5.1 Cache Key (`VaultClientID`)

```go
type VaultClientID struct {
    Address        string // https://vault.example:8200
    AuthMethod     string // kubernetes|approle|…
    AuthHash       string // SHA256 over auth-specific config + SA/role refs + headers
    TLSHash        string // SHA256 over CA, client cert/key refs, flags
    StoreNamespace string // namespace of SecretStore; "" for ClusterSecretStore
    StoreName      string
}
```

`ID.String()` concatenates the fields with `\0` separators to prevent accidental collisions.
If **dynamic TLS** is detected (`CertSecretRef`, `KeySecretRef`, or CA from Secret/ConfigMap) **and** the `--allow-dynamic-tls-cache` flag is *not* set, the pool degenerates to a *no-op pool* (one client per acquire).

### 5.2 Acquire / Release Flow

```
Acquire(ctx, req) {
    if dynamicTLS && !flag { return newNoOpLease() }

    id := BuildID(req)
    cbKey := CircuitKey(id.Address, id.AuthMethod)
    if breaker.Check(cbKey) != nil { return error }

    if cached := lru.Get(id); cached != nil && !cached.evicted {
        return cached.NewLease()
    }

    cli := newVaultClient(req.VaultConfig) // creates HTTP transport with TLS
    if err := setAuth(ctx, cli, req); err != nil { breaker.Fail(cbKey); return err }

    cached := &CachedVaultClient{cli,…}
    lru.Add(id, cached)
    breaker.Success(cbKey)
    return cached.NewLease()
}

Lease.Close() → cached.release()
Cached.release() { atomic.Dec(&leaseCount); if leaseCount==0 && evicted { finalize() } }
```

Finalization revokes the token (unless static), stops renewal timer, removes from reverse index, and emits metrics.

### 5.3 `WithRetry`

```go
func (l *clientLease) WithRetry(ctx context.Context, op func(util.Client) error) error {
    err := op(l.cli)
    if !isAuthErr(err) { record(err); return err }

    _, raErr, _ := l.cached.reauthGroup.Do(l.cached.id.String(), func() (any, error) {
        l.cli.ClearToken(); return nil, setAuth(ctx, l.cli, l.cached.req)
    })
    l.cached.reauthGroup.Forget(l.cached.id.String())
    if raErr != nil { breaker.Fail(l.cached.cbKey); return raErr }
    breaker.Success(l.cached.cbKey)
    return op(l.cli)
}
```

### 5.4 Renewal Scheduling

* After successful auth, if `auth.IsRenewable` and `--vault-renew-tokens` is true, compute `next = now + ttl*0.8`.
* Schedule `time.AfterFunc(next.Sub(now), renew)`.
* `renew` calls `AuthToken().RenewSelfWithContext`; on failure increment counter, evict after N failures.
* Timer reset happens inside `renew` on success.

### 5.5 Circuit Breaker

* Configurable thresholds (env or flag): `--vault-breaker-failures`, `--vault-breaker-window`, `--vault-breaker-open`.
* Breaker shared by pool and cached clients. Failures recorded on:
  * auth failure during `Acquire` or re-auth;
  * Vault returns network errors (connection refused/timeouts).
* Success resets state.
* Metrics: `vault_client_breaker_state{state="open"|"half"|"closed"}` gauge (0/1 labels for each state).

### 5.6 Background Cleanup

* `pool` starts a goroutine: `ticker := time.NewTicker(flagCleanup)`, default 5 m.
* On tick iterate over cache snapshot; for any entry with `leaseCount==0` **and** (`evicted` **or** `nextRenewal.Before(now)`), call `finalize()`.
* Also invoked on `Shutdown(ctx)` for graceful operator termination.

### 5.7 Concurrency & Data Races

* `CachedVaultClient` guards mutable state (`evicted`, `nextRenewal`, `req`) with `sync.RWMutex cfgMu`.
* `leaseCount` is `int32` updated with `atomic` ops.
* `singleflight.Group` ensures one re-auth at a time per cache key.
* Design is race-detector clean – validated via `go test -race ./...` in CI.

### 5.8 Metrics & Logging

| Metric | Type | Description |
|--------|------|-------------|
| `vault_client_pool_cache_hits` | counter | successful cache hits |
| `vault_client_pool_cache_misses` | counter | new clients created |
| `vault_client_pool_reauth_total{result}` | counter | label `result="success"|"failure"` |
| `vault_client_pool_active_clients` | gauge | LRU size |
| `vault_client_pool_cleanup_total` | counter | number of finalised clients |
| `vault_client_breaker_state` | gauge | 1=open,0=closed per key |

Registration uses `prometheus.Register`, swallowing `AlreadyRegisteredError`.

### 5.9 Feature Flags & Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-vault-client-pooling` | **false** | master switch |
| `--vault-client-pool-size` | `512` | LRU capacity |
| `--vault-renew-tokens` | **false** | enable token auto-renew |
| `--vault-client-token-timeout` | `8h` | hard cap for token age |
| `--vault-breaker-failures` | `5` | open after consecutive failures |
| `--vault-breaker-open` | `30s` | open state duration |
| `--vault-client-cleanup` | `5m` | cleanup ticker period |
| `--allow-dynamic-tls-cache` | **false** | cache clients with Secret-based TLS |

All have env var equivalents (upper-snake).

---

## 6. Failure Modes & Recovery

| Failure | Behaviour | Operator Action |
|---------|-----------|-----------------|
| Vault returns 403 (expired token) | `WithRetry` triggers singleflight re-auth & retries once | none |
| Re-auth fails repeatedly | breaker opens; controllers fail fast & back-off | investigate Vault |
| Renewal fails N times | client marked evicted; next `Acquire` builds fresh client | none |
| CA bundle rotated | cache miss due to hash change **or** eviction via informer when flag enabled | none |
| Pool at capacity | LRU evicts least-used client (must have `leaseCount==0`) | may adjust size |

---

## 7. Operational Considerations

* **Shutdown** – on SIGTERM ESO calls `ClientPool.Shutdown(ctx)`; tokens are revoked (non-static) before process exit.
* **Multi-controller scaling** – each controller instance has its own pool; use cluster IP-based breaker key to avoid cross-pod chatter.
* **Metrics** – expose on existing Prometheus port; dashboards updated.
* **Upgrade path** – enabled via feature flag; disable to revert to legacy behaviour.

---

## 8. Testing Strategy

### Unit
* Cache hit/miss, key equality, singleflight re-auth, lease ref-count, circuit breaker state transitions, renewal timer scheduling.

### Integration (kind cluster + dev Vault)
1. **Expired token** – inject TTL=30 s, wait expiry, read secret → expect automatic re-auth.
2. **CA rotation** – change Secret data, ensure informer evicts & new TLS handshake succeeds.
3. **Breaker** – point at non-existent Vault, expect failures then open circuit.
4. **High concurrency** – 1 000 goroutines calling *GetSecret* concurrently; expect ≤1 re-auth.

### Chaos & Race
* `go test -race ./pkg/provider/vault/...` every PR.
* `litmuschaos.io/pod-network-loss` – ensure breaker opens & controllers recover.

---

## 9. Implementation Roadmap

1. **Scaffold interfaces & No-Op pool** (PR 1, behind flag).
2. **LRU cache + lease plumbing** (PR 2) – include unit tests.
3. **WithRetry & singleflight** (PR 3) – remove proactive `LookupSelf`.
4. **Renewal & background cleanup** (PR 4).
5. **Circuit breaker + metrics** (PR 5).
6. **Dynamic TLS guard & informer hooks** (PR 6).
7. **Docs & examples** (PR 7).
8. **Soak & chaos tests** (PR 8, non-blocking).

Each PR merges behind flag until soak passes.

---

## 10. Glossary

* **Lease** – lightweight handle that gives a reconciliation goroutine temporary ownership of a cached client; releasing decrements ref-count.
* **Eviction** – marking a cached client invalid; it remains usable by current leasers but will be finalised after the last release.
* **Breaker** – failure-rate guard that temporarily halts expensive authentication traffic.
