# Vault Client Caching Design Considerations (PRELIMINARY - OUTDATED)

> **⚠️ WARNING: This document is preliminary and outdated.**
>
> **Please refer to [DESIGN.md](./DESIGN.md) as the authoritative source of truth for the Vault Client Pooling implementation.**
>
> This document contains early design considerations and trade-off analysis that led to the final design.

---

## Executive Summary

This document captures all design considerations, trade-offs, and decisions made for implementing Vault client caching in the External Secrets Operator. The primary goal is to reduce Vault API calls while maintaining security, correctness, and operational simplicity.

## Performance Analysis

### Current Baseline (No Caching)

Every reconciliation performs:
1. **K8s Resource Reads** (~15ms total)
   - Secret reads: 2-5ms each
   - ConfigMap reads: 2-5ms each
   - ServiceAccount token requests: 8-15ms each

2. **Vault Operations** (~85-200ms total)
   - Client creation: 0.1ms
   - TCP connection: 5-20ms
   - TLS handshake: 10-30ms
   - Authentication: 30-150ms
   - Secret operations: 10-30ms

### Relative Performance Costs

| Operation | Latency | Relative Cost | Network | CPU Impact |
|-----------|---------|---------------|---------|------------|
| K8s Secret Read | 2-5ms | 1x baseline | Local | Minimal |
| K8s SA Token Request | 8-15ms | 3x | Local | Signing overhead |
| Vault Auth (Kubernetes) | 87ms avg | 17x | Remote | High (crypto) |
| Vault Auth (AppRole) | 64ms avg | 13x | Remote | High (crypto) |
| Vault Auth (IAM) | 156ms avg | 31x | Remote + AWS | Very High |

### Key Finding
**Vault authentication is 4-10x more expensive than all K8s reads combined**, making it the primary optimization target.

## Design Decisions

### 1. Credential Reading Strategy

**Decision: Read and hash credentials on every reconciliation for change detection**

**Alternatives Considered:**

#### Option A: Cache Everything (Credentials + Client)
```go
// Don't read credentials if client is cached
if cachedClient := cache.Get(key); cachedClient != nil {
    return cachedClient
}
```
- ✅ Pros: Maximum performance, zero K8s reads on cache hit
- ❌ Cons: Cannot detect credential rotation, security risk
- **Rejected**: Unacceptable security implications

#### Option B: Cache with Periodic Refresh
```go
// Force refresh every N minutes
if time.Since(cached.created) > refreshInterval {
    // Re-read credentials and re-authenticate
}
```
- ✅ Pros: Eventual consistency, reduced K8s reads
- ❌ Cons: Delayed rotation detection, complex timing logic
- **Rejected**: Complexity without significant benefit

#### Option C: Always Read Credentials (CHOSEN)
```go
// Always read fresh credentials
credentials, version := readCredentials() // ~15ms

// Use version in cache key
cacheKey := buildKey(config, version)

// Check for cached authenticated client
if client := cache.Get(cacheKey); client != nil {
    return client // Skip only Vault auth
}
```
- ✅ Pros:
  - Immediate rotation detection
  - Simple, predictable behavior
  - Credentials always fresh
  - Version metadata is free
- ✅ Cons that are acceptable:
  - K8s reads on every reconcile (only 15ms)
- **Selected**: Best balance of security and performance

**Rationale:**
- K8s reads are fast (15ms) and unavoidable for authentication
- We get ResourceVersion/Generation for free from these reads
- Avoiding Vault auth (85ms) is the real performance win
- 70% latency reduction even with K8s reads

### 2. Cache Key Design

**Decision: Include credential metadata but not SecretStore ResourceVersion**

**Key Components:**
```go
type CacheKey struct {
    // Vault configuration
    ServerURL       string
    VaultNamespace  string
    AuthMethod      string
    AuthMountPath   string
    Role            string

    // K8s context
    K8sNamespace    string

    // Credential identifier (universal for all auth types)
    CredentialIdentifier string  // Hash or version that changes on rotation

    // NOT included:
    // - SecretStore ResourceVersion (prevents sharing)
    // - Actual credential values (security)
    // - Arbitrary timestamps (use credential-based detection)
}
```

**Alternatives Considered:**

#### Option A: Include SecretStore ResourceVersion
- ❌ **Critical Flaw**: Prevents sharing between resources
- Different SecretStores would have different cache keys
- Defeats the primary goal of client pooling
- **Rejected**: Fundamental design flaw

#### Option B: Include Credential Digest
```go
credentialHash := sha256(secretData)
```
- ✅ Pros: Precise change detection
- ❌ Cons: Extra computation, timing issues
- **Rejected**: ResourceVersion provides same benefit for free

#### Option C: Time-based Epochs
```go
epoch := time.Now().Unix() / 300 // 5-minute epochs
```
- ✅ Pros: Forced refresh, handles external rotation
- ❌ Cons: Unnecessary client recreation, complexity
- **Rejected**: Not needed with fresh credential reads

### 3. Resource Sharing Strategy

**Decision: Maximum sharing across all resource types**

**Sharing Matrix:**

| Resource Type | Shares With | Condition |
|--------------|-------------|-----------|
| SecretStore A | SecretStore B | Same namespace, same Vault config, same credential version |
| SecretStore | VaultDynamicSecret | Same namespace, same Vault config, same credential version |
| ClusterSecretStore | Any resource | Same Vault config, same credential version |
| ClusterSecretStore (referent) | Per-namespace resources | Namespace-specific clients when using referent auth |

**Implementation:**
```go
// All resources use same cache key generation
func getCacheKey(vaultSpec *esv1.VaultProvider,
                 credentialVersion string,
                 namespace string) string {
    // Identical logic for all resource types
    return fmt.Sprintf("%s|%s|%s|%s",
        vaultConfig,
        namespace,
        credentialRef,
        credentialVersion)
}
```

### 4. Token Expiration Handling

**Decision: Lazy invalidation with automatic retry**

**Alternatives Considered:**

#### Option A: Proactive Token Refresh
```go
if token.ExpiresIn(5*time.Minute) {
    refreshToken()
}
```
- ❌ Cons: Complex timing, unnecessary refreshes
- **Rejected**: Over-engineering

#### Option B: Token Watching
```go
go watchTokenExpiry(client, onExpiry)
```
- ❌ Cons: Goroutine management, complexity
- **Rejected**: Unnecessary complexity

#### Option C: Lazy Invalidation (CHOSEN)
```go
err := client.VaultOperation()
if isTokenExpired(err) {
    cache.Remove(key)
    client = createNewClient()
    retry()
}
```
- ✅ Pros: Simple, no background tasks, self-healing
- **Selected**: Simplest correct solution

### 5. Thread Safety Design

**Decision: Simple mutex-based locking without singleflight**

**Rationale:**
- KISS principle: Start simple, optimize if needed
- Mutex per cache entry prevents concurrent re-auth
- Global cache mutex protects map operations
- Singleflight adds complexity without proven need

```go
type ClientCache struct {
    mu      sync.RWMutex          // Protects map
    clients map[string]*CachedClient
}

type CachedClient struct {
    client  *vault.Client
    mu      sync.Mutex            // Protects re-auth
}
```

### 6. Credential Rotation Detection

**Decision: Generate unique identifier for each auth method's credentials**

**Per Auth Method Strategy:**

| Auth Method | Credential Source | Identifier Strategy | Rotation Detection |
|-------------|------------------|--------------------|--------------------|
| **Kubernetes SA** | Dynamic token | Hash of token | Immediate (new token each time) |
| **AppRole** | K8s Secret | Secret ResourceVersion | Immediate (Secret update) |
| **IAM** | AWS credentials | Hash of session token or access key | Immediate (STS rotation) |
| **JWT** | K8s Secret or SA token | Secret version or token hash | Immediate |
| **Certificate** | K8s Secret | Secret ResourceVersion | Immediate (cert renewal) |
| **Token** | K8s Secret | Secret ResourceVersion | Immediate (token rotation) |
| **LDAP/UserPass** | K8s Secret | Secret ResourceVersion | Immediate (password change) |

**Detection Flow:**
1. Every reconciliation obtains credentials (required for auth anyway)
2. Generate identifier based on credential type:
   - K8s Secrets: Use ResourceVersion (metadata)
   - Dynamic tokens: Hash the token
   - AWS credentials: Hash session token or use access key ID
3. Include identifier in cache key
4. Different identifier = cache miss = new client

**Implementation Example:**
```go
// For IAM credentials with automatic rotation
func getIAMCredentialID(iamAuth *VaultIAMAuth) string {
    creds := aws.GetCredentials() // Uses same chain as actual auth

    if creds.SessionToken != "" {
        // Temporary credentials - hash for privacy
        hash := sha256.Sum256([]byte(creds.SessionToken))
        return fmt.Sprintf("sts:%x", hash[:8])
    }

    // Long-lived credentials - access key is not sensitive
    return fmt.Sprintf("akid:%s", creds.AccessKeyID)
}
```

**Edge Cases Handled:**

| Scenario | Detection | Recovery |
|----------|-----------|----------|
| K8s Secret updated | Immediate (ResourceVersion change) | Automatic re-auth |
| External rotation | On token expiry | Auth error triggers re-auth |
| Partial update (SecretID only) | Immediate (Secret ResourceVersion) | Automatic re-auth |
| Config change (non-credential) | No cache invalidation | Correct (config unchanged) |

### 7. Cache Eviction Strategy

**Decision: Simple TTL-based eviction**

**Alternatives Considered:**

#### Option A: LRU Eviction
- ❌ Cons: Complexity, may evict active clients
- **Rejected**: Over-engineering

#### Option B: Reference Counting
- ❌ Cons: Complex lifecycle management
- **Rejected**: Unnecessary

#### Option C: TTL-based (CHOSEN)
```go
if time.Since(client.lastUsed) > 15*time.Minute {
    evict(client)
}
```
- ✅ Pros: Simple, predictable, no active client eviction
- **Selected**: Simplest effective approach

### 8. Feature Flag Strategy

**Decision: Alpha feature flag, disabled by default**

```go
if !feature.Gates.Enabled(feature.VaultClientPooling) {
    // Use existing non-cached behavior
    return createNewClient()
}
```

**Rollout Plan:**
1. Alpha: Opt-in via feature flag
2. Beta: Enabled by default, opt-out available
3. GA: Always enabled, flag removed

## Implementation Complexity Analysis

### Complexity We're Adding
- Cache map with TTL eviction (~100 lines)
- Cache key generation (~50 lines)
- Error detection and retry (~50 lines)
- Feature flag integration (~20 lines)

### Complexity We're Avoiding
- No singleflight patterns
- No background goroutines
- No complex state machines
- No credential watching
- No proactive refresh
- No reference counting

## Risk Analysis

### Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Memory leak from unbounded cache | Medium | TTL eviction, max size limit |
| Credential rotation not detected | High | Fresh credential reads, ResourceVersion tracking |
| Token expires mid-operation | Low | Retry with new client |
| Cache key collisions | Low | Comprehensive key components |
| Thread safety issues | Medium | Simple mutex design, extensive testing |

## Operational Considerations

### Monitoring and Metrics

```go
metrics.CacheHits.Inc()          // Cache effectiveness
metrics.CacheMisses.Inc()         // Cache misses
metrics.AuthenticationTime.Set() // Auth latency
metrics.TokenExpiries.Inc()      // Token expiration rate
metrics.CacheSize.Set()           // Current cache size
```

### Debugging Support

```yaml
# Enable debug logging
env:
  - name: VAULT_CLIENT_CACHE_DEBUG
    value: "true"

# Adjust cache parameters
  - name: VAULT_CLIENT_CACHE_TTL
    value: "15m"
  - name: VAULT_CLIENT_CACHE_MAX_SIZE
    value: "1000"
```

## Decision Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Read credentials every time | Yes | Already required, enables rotation detection |
| Cache authenticated clients | Yes | 70% latency reduction |
| Include SecretStore ResourceVersion | No | Prevents resource sharing |
| Include credential ResourceVersion | Yes | Free rotation detection |
| Use singleflight | No | Unnecessary complexity |
| Proactive token refresh | No | Lazy invalidation simpler |
| Background workers | No | Lazy operations simpler |
| Feature flag | Yes | Safe rollout |

## Expected Outcomes

### Performance Improvements
- **70-85% reduction** in reconciliation latency (varies by auth method)
- **99% reduction** in Vault authentication calls
- **50% reduction** in network traffic to Vault
- **Minimal** impact on K8s API server
- **Small overhead** for credential hashing (~1-2ms)

### Operational Benefits
- Fewer Vault audit log entries
- Reduced Vault CPU usage
- Better behavior under Vault rate limits
- Improved reconciliation throughput

### Security Posture
- ✅ No credential storage in cache
- ✅ Immediate K8s-managed rotation detection
- ✅ Automatic recovery from auth failures
- ⚠️ Delayed detection of external rotation (acceptable)

## Trade-off: Credential Hashing Overhead

**Additional Work per Reconciliation:**
- Obtain credentials for hashing: +2-5ms
- SHA-256 computation: +0.1ms
- Total overhead: ~3-5ms

**Why It's Worth It:**
- Accurate rotation detection for ALL auth methods
- No time-based epochs causing unnecessary cache misses
- Works with dynamic credentials (IAM, K8s SA)
- Security: Only hash/identifier stored, never actual credentials

**Net Benefit:**
- Cost: 3-5ms credential processing
- Savings: 85ms Vault authentication
- **Net gain: 80ms (94% improvement)**

## Conclusion

The design prioritizes:
1. **Correctness** over minimal overhead (credential hashing for accurate detection)
2. **Security** through fresh credential reads and hashing
3. **Performance** by caching expensive Vault auth operations
4. **Universality** through support for all auth methods

By obtaining and hashing credentials (small overhead) and caching authenticated clients (large savings), we achieve significant performance gains while maintaining security and accurate rotation detection for all Vault auth methods.