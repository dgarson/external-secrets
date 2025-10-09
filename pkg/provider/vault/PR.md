## Problem Statement

The Vault provider currently creates a new authenticated Vault client for every ExternalSecret reconciliation, even when multiple ExternalSecrets use identical credentials. This leads to:

1. **Performance overhead**: Repeated authentication API calls to Vault (50-200ms each)
2. **Resource waste**: Multiple clients holding identical tokens
3. **Vault load**: Unnecessary authentication traffic, especially in clusters with hundreds of ExternalSecrets
4. **Scaling limits**: Authentication rate limits can be hit in large deployments

## Related Issue

Fixes #XXXX

## Proposed Changes

This PR introduces **Vault Client Pooling** to reuse authenticated Vault clients across ExternalSecrets that share the same credentials. The implementation focuses on correctness, security, and automatic cache invalidation.

### High-Level Design

**Client Pooling with Identity-Based Cache Keys**

Instead of creating a new client for each ExternalSecret, we:
1. Generate a cache key based on Vault server, auth method, and credential identity
2. Reuse existing authenticated clients when credentials match
3. Automatically invalidate cache when credentials change (via Kubernetes ResourceVersion tracking)

**Why Cache Clients Instead of Tokens?**

We cache entire authenticated Vault clients rather than just tokens because:
- **Automatic re-authentication**: Pooled clients can detect token expiration and re-authenticate transparently
- **Connection reuse**: HTTP connection pooling reduces network overhead
- **State preservation**: Vault namespace, headers, and client configuration remain consistent
- **Token lifecycle**: Clients can handle token renewal/rotation without manual intervention

### Key Components

#### 1. ClientPool with LRU Cache (`pool.go`)
- **LRU eviction**: Size-limited cache (default 1000 clients) with TTL-based expiration (15min)
- **Mutex protection**: Thread-safe access for concurrent ExternalSecret reconciliations
- **Metrics**: Prometheus metrics for cache hits, misses, size, and evictions
- **PooledClient wrapper**: Embeds VaultClient with automatic re-authentication on token expiration

#### 2. Identity-Based Cache Keys (`pool_key.go`)
- **Format**: `{vaultServer}|{vaultNamespace}|{authPath}|{authIdentity}`
- **Security**: Uses Kubernetes ResourceVersion instead of hashing credentials
- **Automatic invalidation**: Cache key changes when Secret/ServiceAccount ResourceVersion changes
- **Namespace resolution**: Handles both explicit namespace references and referent specs

**Auth Identity Formats** (all include `namespace:name:v{resourceVersion}`):
- Kubernetes SA: `k8s-sa:{ns}:{sa}:{role}:v{rv}`
- Token: `token:{ns}:{secret}:v{rv}`
- AppRole: `approle:{roleID}:secret:{ns}:{secret}:v{rv}`
- JWT: `jwt:{role}:secret:{ns}:{secret}:v{rv}` or `jwt-sa:{ns}:{sa}:{role}:v{rv}`
- IAM: `iam:{region}:{role}:sa:{ns}:{sa}:v{rv}` or `iam:{region}:{role}:ak:{ns}:{secret}:v{rv}:sk:{ns}:{secret}:v{rv}`
- Cert: `cert:cert:{ns}:{secret}:v{rv}:key:{ns}:{secret}:v{rv}`
- LDAP: `ldap:{user}:secret:{ns}:{secret}:v{rv}`
- UserPass: `userpass:{user}:secret:{ns}:{secret}:v{rv}`

#### 3. Auto-Retry on Token Expiration (`pooledLogical`)
- Wraps Vault's Logical interface to detect token expiration errors
- Automatically re-authenticates using stored credentials
- Retries failed operation with fresh token
- Removes client from pool if re-authentication fails

#### 4. Singleflight for Authentication
- **Why needed**: Multiple ExternalSecrets may race to authenticate with same credentials
- **Implementation**: First request authenticates, subsequent requests wait and reuse result
- **Benefit**: Prevents authentication storms during controller startup or cache eviction

### Client Sharing Behavior

**Scenario 1: Same Credentials, Same Namespace**
- 5 ExternalSecrets in namespace `apps` using SecretStore `vault`
- SecretStore references Secret `apps/vault-token:v100`
- **Result**: All 5 share ONE client (cache key: `https://vault||auth|token:apps:vault-token:v100`)

**Scenario 2: Same Credentials, Cross-Namespace (ClusterSecretStore)**
- 5 ExternalSecrets in different namespaces using ClusterSecretStore `vault-global`
- ClusterSecretStore references Secret `vault-system/vault-token:v200`
- **Result**: All 5 share ONE client (cache key: `https://vault||auth|token:vault-system:vault-token:v200`)

**Scenario 3: Different Credentials (Referent Spec)**
- ClusterSecretStore references Secret `vault-token` (no namespace)
- ExternalSecret in `ns-1` → resolves to `ns-1/vault-token:v100`
- ExternalSecret in `ns-2` → resolves to `ns-2/vault-token:v200`
- **Result**: Two separate clients (different cache keys)

### Cache Invalidation

**Automatic invalidation** when credentials change:
- Secret data rotated → ResourceVersion changes → new cache key → cache miss → new client
- ServiceAccount annotations changed (e.g., IRSA role) → ResourceVersion changes → new cache key
- Secret/SA deleted and recreated → new ResourceVersion → new client

**No invalidation** for external changes:
- AWS IAM policy changes (doesn't modify K8s resources)
- Vault policy changes
- Network issues
- **Mitigation**: Token TTLs, error handling, and auto-retry handle these cases

### Security Considerations

**Why ResourceVersion instead of hashed credentials?**

We explicitly avoid hashing credentials in cache keys because:
1. **Correlation attacks**: Same hash reveals credential reuse across systems
2. **Compliance violations**: Many security policies prohibit any derivative of credentials in logs
3. **Side channels**: Cache access patterns could leak credential usage information
4. **No credential access needed**: ResourceVersion is provided by Kubernetes metadata

**What's safe to log?**
Cache keys contain only:
- Vault server URL (configuration, not secret)
- Namespace and Secret/SA names (metadata, not secret)
- ResourceVersions (opaque identifiers, not secret)

### Performance Impact

**Expected improvements:**
- >95% cache hit ratio in steady state
- Reduced Vault authentication calls (50-200ms saved per cached request)
- Lower Vault server load
- Faster ExternalSecret reconciliation

**Overhead:**
- Initial cache miss: 1-10ms to fetch Secret/SA for ResourceVersion
- Subsequent hits: No additional overhead (client already authenticated)

### Migration & Rollout

**Breaking changes:**
- Cache key format changed (removed ExternalSecret namespace from key)
- All existing cache entries invalidated on upgrade

**Impact:**
- One-time authentication spike during upgrade (all clients re-authenticate)
- No configuration changes required
- No data loss or service disruption

**Feature flag:**
- Controlled by `enableVaultClientPooling` flag (disabled by default initially)
- Fallback to non-pooled behavior if cache key generation fails

### Documentation

This PR includes comprehensive documentation distributed across three locations to serve different audiences:

#### 1. Design Document: `design/013-vault-client-pooling.md`
- **Audience**: Developers, contributors, maintainers
- **Content**: Complete technical design document following project template
  - Motivation, goals, and non-goals
  - Detailed cache key structure and all 11 auth identity formats
  - Security rationale (why ResourceVersion vs hashing credentials)
  - Client sharing behavior and cache invalidation mechanics
  - Performance analysis, drawbacks, and alternatives considered
  - Edge case handling, error behavior, and graceful degradation
  - Migration notes and future enhancements

#### 2. User Documentation: `docs/provider/hashicorp-vault.md`
- **Audience**: End users configuring Vault provider
- **Content**: New "Client Pooling & Performance" section
  - High-level explanation of how pooling works
  - Three practical scenarios showing when clients are/aren't shared
  - Cache invalidation behavior for credential rotation
  - Performance impact examples (~10x improvement)
  - Reference link to design document for technical details

#### 3. Inline Code Documentation: `pkg/provider/vault/pool.go`
- **Audience**: Developers reading implementation code
- **Content**: Enhanced package and type-level documentation
  - Package overview explaining client pooling concepts
  - Cache key structure and format
  - Detailed comments on `ClientPool`, `PooledClient`, and `AuthFunc` types
  - Clear references to design/013-vault-client-pooling.md for comprehensive details

## Format

```
perf(vault): implement client pooling for credential-based reuse
```

## Checklist

- [ ] I have read the [contribution guidelines](https://external-secrets.io/latest/contributing/process/#submitting-a-pull-request)
- [ ] All commits are signed with `git commit --signoff`
- [ ] My changes have reasonable test coverage
- [ ] All tests pass with `make test`
- [ ] I ensured my PR is ready for review with `make reviewable`
