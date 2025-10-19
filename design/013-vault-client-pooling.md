```yaml
---
title: Vault Client Pooling
version: v1beta1
authors: davidgarson
creation-date: 2025-01-08
status: implemented
---
```

# Vault Client Pooling

## Table of Contents

<!-- toc -->
// autogen please
<!-- /toc -->

## Summary

The Vault provider implements client pooling to reduce authentication overhead by reusing authenticated Vault clients across multiple ExternalSecrets that share the same credentials. This design ensures correctness (different credentials never share clients), efficiency (identical credentials always share clients), security (cache keys contain no credential data), and proper cache invalidation when credentials change.

## Motivation

Without client pooling, the Vault provider creates a new authenticated client for every ExternalSecret reconciliation, even when multiple ExternalSecrets use identical credentials. This results in:

1. **Excessive authentication overhead**: Each Vault authentication takes 50-200ms
2. **Increased load on Vault**: Unnecessary authentication requests
3. **Slower reconciliation**: ExternalSecrets take longer to sync
4. **Resource waste**: Multiple identical authenticated clients in memory

### Goals

- Reduce Vault authentication overhead by reusing clients with identical credentials
- Ensure different credentials never share a client (correctness)
- Ensure identical credentials always share a client (efficiency)
- Never include credentials in cache keys, even hashed (security)
- Automatically invalidate cache when credentials change
- Support all Vault authentication methods
- Gracefully degrade when client pooling fails

### Non-Goals

- Caching secrets fetched from Vault (already handled by controller reconciliation)
- Managing Vault token lifecycle beyond re-authentication on expiration
- Implementing connection pooling at the HTTP level (handled by Vault SDK)
- Tracking or invalidating based on Vault server-side policy changes
- Tracking or invalidating based on AWS IAM policy changes (external to Kubernetes)

## Proposal

Implement an LRU cache (using hashicorp/golang-lru) that stores authenticated Vault clients keyed by a composite cache key. The cache key is constructed from:

1. Vault server URL
2. Vault namespace (Enterprise)
3. Auth method mount path
4. Auth identity (credential metadata, not credentials themselves)

### User Stories

1. **As a platform operator**, I want to deploy 50 ExternalSecrets in the same namespace that all use the same Vault token, and I want them to share a single authenticated Vault client to reduce authentication overhead and improve performance.

2. **As a security engineer**, I want to ensure that when I rotate credentials in a Kubernetes Secret, all ExternalSecrets using those credentials automatically get new Vault clients without manual intervention.

3. **As a multi-tenant cluster administrator**, I want to use a ClusterSecretStore with referent authentication where each namespace has its own credentials, and I want to ensure each namespace gets its own Vault client (not shared across tenants).

4. **As a developer**, I want client pooling to work transparently without requiring any configuration changes to my ExternalSecret or SecretStore definitions.

### Implementation Design

#### Cache Key Structure

**Format:**
```
{vaultServer}|{vaultNamespace}|{authMountPath}|{authIdentity}
```

**Components:**

1. **vaultServer** (string)
   - Vault server URL (e.g., `https://vault.example.com:8200`)
   - Ensures clients connecting to different Vault servers are separate

2. **vaultNamespace** (string)
   - Vault Enterprise namespace (or empty string if not used)
   - Ensures clients in different Vault namespaces are separate

3. **authMountPath** (string)
   - Vault auth method mount path (e.g., `kubernetes`, `approle`, `jwt`)
   - Defaults to standard mount path but can be customized per auth method
   - Ensures clients using different auth mounts are separate

4. **authIdentity** (string)
   - Credential-specific identity string (format varies by auth method)
   - Contains namespace, name, and ResourceVersion of credential sources
   - **Never contains actual credentials** (only Kubernetes resource metadata)

#### Why ResourceVersion Instead of Hashed Credentials?

**Critical Security Principle: Never include credentials in cache keys, even hashed.**

We use Kubernetes ResourceVersion instead of hashing credential values for several reasons:

1. **No Credential Exposure**: ResourceVersion is a Kubernetes-provided opaque identifier that contains no credential data
2. **Automatic Invalidation**: ResourceVersion changes whenever a Secret/ServiceAccount is modified
3. **Correlation Attack Prevention**: Even SHA-256 of a token could be used to correlate cache accesses or identify credential reuse across systems
4. **Compliance**: Many security policies prohibit storing any derivative of credentials in logs/metrics
5. **Simplicity**: No need to extract and hash credential values from various sources
6. **Safe to Log**: Cache keys can be safely logged for debugging without exposing credential information

#### Auth Identity Formats

Each authentication method has a specific format for `authIdentity`. All formats include the **resolved namespace and name** of credential sources to ensure uniqueness.

##### 1. Kubernetes Auth (ServiceAccountRef)

**Format:**
```
k8s-sa:{serviceAccountNamespace}:{serviceAccountName}:{vaultRole}:v{serviceAccountResourceVersion}
```

**Example:**
```
k8s-sa:apps:vault-client:reader:v98765
```

**Components:**
- `serviceAccountNamespace`: Namespace where ServiceAccount exists
- `serviceAccountName`: ServiceAccount name
- `vaultRole`: Vault role for authentication
- `serviceAccountResourceVersion`: K8s ResourceVersion of ServiceAccount

**Invalidation**: Cache invalidates when ServiceAccount changes (annotations like IRSA role ARN, deletion/recreation, etc.)

##### 2. Kubernetes Auth (SecretRef - JWT from Secret)

**Format:**
```
k8s-secret:{secretNamespace}:{secretName}:v{secretResourceVersion}
```

**Example:**
```
k8s-secret:apps:k8s-jwt-token:v54321
```

##### 3. IAM Auth (JWTAuth with ServiceAccountRef)

**Format:**
```
iam:{region}:{vaultRole}:sa:{serviceAccountNamespace}:{serviceAccountName}:v{serviceAccountResourceVersion}
```

**Example:**
```
iam:us-east-1:vault-role:sa:apps:irsa-vault:v11111
```

**Components:**
- `region`: AWS region
- `vaultRole`: Vault role for authentication
- `serviceAccountNamespace`: Namespace where ServiceAccount exists
- `serviceAccountName`: ServiceAccount name
- `serviceAccountResourceVersion`: K8s ResourceVersion of ServiceAccount

**Invalidation**: Cache invalidates when ServiceAccount changes, including when IRSA/EKS Pod Identity role annotations change.

##### 4. IAM Auth (SecretRef - Static AWS Credentials)

**Format:**
```
iam:{region}:{vaultRole}:ak:{accessKeySecretNs}:{accessKeySecretName}:v{accessKeyRV}:sk:{secretKeySecretNs}:{secretKeySecretName}:v{secretKeyRV}[:st:{sessionTokenSecretNs}:{sessionTokenSecretName}:v{sessionTokenRV}]
```

**Example (without session token):**
```
iam:us-east-1:vault-role:ak:vault-system:aws-creds:v100:sk:vault-system:aws-creds:v100
```

**Example (with session token):**
```
iam:us-east-1:vault-role:ak:vault-system:aws-creds:v100:sk:vault-system:aws-creds:v100:st:vault-system:aws-session:v200
```

**Note**: Session token part is optional and only included when configured.

##### 5. AppRole (SecretRef)

**Format:**
```
approle:{roleID}:secret:{secretNamespace}:{secretName}:v{secretResourceVersion}
```

**Example:**
```
approle:my-role-id:secret:apps:approle-secret:v12345
```

**Components:**
- `roleID`: AppRole role ID (or "roleRef" if using RoleRef)
- `secretNamespace`: Namespace where Secret with SecretID exists
- `secretName`: Secret name containing SecretID
- `secretResourceVersion`: K8s ResourceVersion of Secret

##### 6. Token (TokenSecretRef)

**Format:**
```
token:{secretNamespace}:{secretName}:v{secretResourceVersion}
```

**Example:**
```
token:vault-system:vault-token:v67890
```

**Components:**
- `secretNamespace`: Namespace where token Secret exists
- `secretName`: Secret name containing token
- `secretResourceVersion`: K8s ResourceVersion of Secret

##### 7. JWT from Secret

**Format:**
```
jwt:{vaultRole}:secret:{secretNamespace}:{secretName}:v{secretResourceVersion}
```

**Example:**
```
jwt:my-jwt-role:secret:apps:jwt-secret:v11111
```

**Components:**
- `vaultRole`: Vault role for JWT authentication
- `secretNamespace`: Namespace where JWT Secret exists
- `secretName`: Secret name containing JWT
- `secretResourceVersion`: K8s ResourceVersion of Secret

##### 8. JWT from KubernetesServiceAccountToken

**Format:**
```
jwt-sa:{serviceAccountNamespace}:{serviceAccountName}:{vaultRole}:v{serviceAccountResourceVersion}
```

**Example:**
```
jwt-sa:apps:vault-sa:my-jwt-role:v22222
```

**Components:**
- `serviceAccountNamespace`: Namespace where ServiceAccount exists
- `serviceAccountName`: ServiceAccount name
- `vaultRole`: Vault role for JWT authentication
- `serviceAccountResourceVersion`: K8s ResourceVersion of ServiceAccount

##### 9. Cert (ClientCert + SecretRef for key)

**Format:**
```
cert:cert:{certSecretNamespace}:{certSecretName}:v{certSecretResourceVersion}:key:{keySecretNamespace}:{keySecretName}:v{keySecretResourceVersion}
```

**Example:**
```
cert:cert:apps:client-cert:v33333:key:apps:client-key:v33333
```

**Components:**
- `certSecretNamespace`: Namespace where client certificate Secret exists
- `certSecretName`: Secret name containing client certificate
- `certSecretResourceVersion`: K8s ResourceVersion of certificate Secret
- `keySecretNamespace`: Namespace where private key Secret exists
- `keySecretName`: Secret name containing private key
- `keySecretResourceVersion`: K8s ResourceVersion of key Secret

**Note**: Certificate and key can be in different Secrets and namespaces.

##### 10. LDAP

**Format:**
```
ldap:{username}:secret:{secretNamespace}:{secretName}:v{secretResourceVersion}
```

**Example:**
```
ldap:myuser:secret:apps:ldap-password:v44444
```

**Components:**
- `username`: LDAP username
- `secretNamespace`: Namespace where password Secret exists
- `secretName`: Secret name containing password
- `secretResourceVersion`: K8s ResourceVersion of Secret

##### 11. UserPass

**Format:**
```
userpass:{username}:secret:{secretNamespace}:{secretName}:v{secretResourceVersion}
```

**Example:**
```
userpass:myuser:secret:apps:userpass-password:v55555
```

**Components:**
- `username`: UserPass username
- `secretNamespace`: Namespace where password Secret exists
- `secretName`: Secret name containing password
- `secretResourceVersion`: K8s ResourceVersion of Secret

### Behavior

#### Client Sharing Scenarios

##### Scenario 1: Multiple ExternalSecrets in Same Namespace, Same SecretStore

```yaml
# 5 ExternalSecrets in namespace "apps"
# All reference SecretStore "vault" in namespace "apps"
# SecretStore references Secret "apps/vault-token"
```

**Expected Behavior**: All 5 ExternalSecrets share ONE client

**Cache Key**: `https://vault||auth|token:apps:vault-token:v12345`

**Rationale**: Identical credentials (same Secret) should reuse the same authenticated Vault client.

##### Scenario 2: Multiple ExternalSecrets Across Namespaces, Shared ClusterSecretStore

```yaml
# 5 ExternalSecrets in namespaces [ns-1, ns-2, ns-3, ns-4, ns-5]
# All use ClusterSecretStore "vault-global"
# ClusterSecretStore references Secret "vault-system/vault-token" (explicit namespace)
```

**Expected Behavior**: All 5 ExternalSecrets share ONE client

**Cache Key**: `https://vault||auth|token:vault-system:vault-token:v12345`

**Rationale**: Same credentials (same Secret in vault-system) should reuse the same client regardless of which namespace's ExternalSecret is using it.

##### Scenario 3: ClusterSecretStore with Referent Spec (Namespace-less References)

```yaml
# ClusterSecretStore references Secret "vault-token" (no namespace)
# ExternalSecret "es1" in "ns-1" → resolves to Secret "ns-1/vault-token"
# ExternalSecret "es2" in "ns-2" → resolves to Secret "ns-2/vault-token"
```

**Expected Behavior**: Different clients (different credentials)

**Cache Keys**:
- es1: `https://vault||auth|token:ns-1:vault-token:v100`
- es2: `https://vault||auth|token:ns-2:vault-token:v200`

**Rationale**: Different Secrets (in different namespaces) should use separate clients.

#### Cache Invalidation

##### Automatic Invalidation

Cache invalidation happens automatically when credential sources change because we include **ResourceVersion** in cache keys:

1. **Secret Updated**: ResourceVersion changes → cache key changes → cache miss → new client created
2. **Secret Deleted/Recreated**: New ResourceVersion → cache key changes → cache miss → new client created
3. **ServiceAccount Updated**: ResourceVersion changes (e.g., IRSA annotation change) → cache key changes → cache miss → new client created
4. **ServiceAccount Deleted/Recreated**: New ResourceVersion → cache key changes → cache miss → new client created

##### What Changes Trigger Invalidation

**For Secrets:**
- Data changes (credentials rotated)
- Annotations/labels changed
- Secret deleted and recreated
- Any other metadata change

**For ServiceAccounts:**
- Annotations changed (e.g., `eks.amazonaws.com/role-arn` for IRSA)
- Labels changed
- ServiceAccount secrets list changed (Kubernetes <1.24)
- ServiceAccount deleted and recreated
- Any other metadata change

##### What Doesn't Trigger Invalidation

**External changes that don't modify K8s resources:**
- AWS IAM policy changes (doesn't modify ServiceAccount)
- Vault policy changes
- Network/connectivity changes
- Vault server configuration changes

**Mitigation**: These scenarios are handled by:
- Vault token TTLs (eventual expiration forces re-authentication)
- Error handling and retry logic
- Re-authentication on token expiration

#### Namespace Resolution

When building `authIdentity`, namespaces are resolved using this logic:

1. **Explicit namespace in reference**: Use as-is
   - Example: ClusterSecretStore references `vault-system/vault-token` → namespace is `vault-system`

2. **No namespace in reference (referent spec)**: Use caller's namespace
   - Example: SecretStore in namespace `apps` references `vault-token` → namespace is `apps`
   - Example: ClusterSecretStore references `vault-token`, called from ExternalSecret in `team-a` → namespace is `team-a`

This resolution happens in `getAuthIdentity()` before building the cache key.

#### Error Handling

If fetching a Secret or ServiceAccount fails during cache key generation:
1. `getAuthIdentity()` returns an error
2. `initClientPooled()` catches the error (provider.go:200-201)
3. System falls back to non-pooled behavior for that request
4. Logs error for visibility
5. Next reconciliation retries

This ensures graceful degradation when K8s API is unavailable or permissions are incorrect.

### Drawbacks

1. **Additional K8s API calls**: Cache key generation requires fetching Secrets/ServiceAccounts to get ResourceVersion. However:
   - This only happens on cache miss, not every reconciliation
   - controller-runtime client has built-in caching
   - Cost is ~1-10ms per GET operation vs 50-200ms for Vault auth

2. **Memory overhead**: LRU cache stores authenticated clients in memory. However:
   - Cache size is configurable (default: reasonable limit)
   - LRU eviction prevents unbounded growth
   - Memory savings from not creating duplicate clients outweighs cache overhead

3. **Not tracking ClientTLS changes**: We don't include ClientTLS certificate/key Secret ResourceVersions in cache keys. This is acceptable because:
   - ClientTLS is transport layer, not authentication
   - TLS certificate changes are rare
   - Incorrect TLS will cause connection errors and trigger re-authentication

4. **Not tracking CAProvider changes**: We don't include CA bundle Secret/ConfigMap ResourceVersions in cache keys. This is acceptable because:
   - CA changes are rare
   - Incorrect CA will cause validation errors
   - Lower priority than authentication credentials

### Acceptance Criteria

#### Rollout
- [x] Feature is enabled by default in Vault provider
- [x] No configuration changes required for existing ExternalSecrets
- [x] Cache automatically invalidates on upgrade (one-time authentication spike)

#### Testing
- [x] Unit tests verify cache key format for all auth methods
- [x] Unit tests verify namespace resolution (explicit vs referent spec)
- [x] Unit tests verify ResourceVersion inclusion
- [x] Unit tests verify uniqueness (different credentials → different keys)
- [x] Unit tests verify sharing (same credentials → same keys)
- [x] Unit tests verify error handling (missing resources)
- [x] Integration tests verify client reuse across multiple ExternalSecrets
- [x] Integration tests verify cache invalidation on Secret update

#### Observability
- [ ] (Future) Metrics for cache hit/miss rate
- [ ] (Future) Metrics for authentication API call reduction
> Note: only automatic LRU/TTL evictions are currently exported in metrics; manual removals for config drift or auth failures are intentionally suppressed to keep the eviction counter focused on cache pressure.
- [x] Log messages when creating pooled clients (debug level)
- [x] Log messages on cache key generation errors

#### Monitoring
- Cache behavior is transparent to users
- No new failure modes introduced (graceful degradation on errors)
- Existing Vault authentication metrics still apply

#### Troubleshooting
- Debug logs show cache keys being used (safe to log, no credential data)
- Cache key generation errors are logged with context
- Fallback to non-pooled behavior on errors prevents complete failure

## Alternatives

### Alternative 1: Hash Credential Values in Cache Key

**Approach**: Include SHA-256 hash of credential values in cache key instead of ResourceVersion.

**Pros**:
- No need to fetch Secrets/ServiceAccounts for ResourceVersion
- Faster cache key generation

**Cons**:
- Security risk: Even hashed credentials can enable correlation attacks
- Compliance issues: Many policies prohibit any derivative of credentials
- Requires extracting credential data (more complex)
- No automatic invalidation on metadata-only changes
- Cannot be safely logged

**Decision**: Rejected due to security concerns.

### Alternative 2: No Client Pooling

**Approach**: Create a new client for every reconciliation.

**Pros**:
- Simpler implementation
- No cache invalidation concerns

**Cons**:
- Excessive authentication overhead (50-200ms per reconciliation)
- Increased load on Vault
- Slower reconciliation times
- Wasteful resource usage

**Decision**: Rejected due to performance impact.

### Alternative 3: Session-Level Caching (One Client Per SecretStore)

**Approach**: Cache one client per SecretStore instance, ignoring credential differences.

**Pros**:
- Simple cache key (just SecretStore name)
- Fast cache lookups

**Cons**:
- Incorrect behavior with referent auth (different namespaces share credentials)
- Security risk in multi-tenant scenarios
- No cache invalidation on credential rotation

**Decision**: Rejected due to correctness and security concerns.

### Alternative 4: Time-Based Cache Invalidation

**Approach**: Invalidate cache entries after a fixed TTL instead of tracking ResourceVersion.

**Pros**:
- No need to fetch ResourceVersion
- Simple implementation

**Cons**:
- Delayed invalidation after credential rotation (security risk)
- Unnecessary invalidation before credentials change (performance loss)
- Difficult to choose appropriate TTL

**Decision**: Rejected in favor of event-driven invalidation via ResourceVersion.

## Performance Considerations

### API Call Overhead

**Cost:**
- Each cache key generation requires fetching Secrets/ServiceAccounts
- Cost: ~1-10ms per GET operation
- **Only happens on cache miss**, not on every reconciliation
- controller-runtime client has built-in caching
- Multiple ExternalSecrets using same credentials benefit from K8s client cache

### Cache Hit Ratio

**Expected**: >95% in steady state

**Cache misses only occur on:**
- First access to new credentials
- Credential rotation (ResourceVersion changes)
- Cache eviction (LRU, size limits)

### Network Cost

**Reduced Vault authentication API calls** (primary benefit):
- Vault auth typically takes 50-200ms
- K8s API GET typically takes 1-10ms
- **Net savings: Significant** (especially for frequently accessed secrets)

**Example**: 50 ExternalSecrets using same credentials:
- Without pooling: 50 Vault auths = 2,500-10,000ms
- With pooling: 1 Vault auth + 50 K8s GETs = 50-200ms + 50-500ms = 100-700ms
- **Improvement**: ~4-14x faster

## Migration Notes

### Breaking Changes

This implementation changes the cache key format from:

**Old format:**
```
{vaultServer}|{vaultNamespace}|{authMountPath}|{externalSecretNamespace}|{authIdentity}
```

**New format:**
```
{vaultServer}|{vaultNamespace}|{authMountPath}|{authIdentity}
```

**Impact:**
- All existing cache entries will be invalidated when upgrading
- Clients will need to re-authenticate to Vault
- This is a one-time event during upgrade

### Rollout Recommendations

1. **Expect authentication spike**: All cached clients will be evicted on upgrade
2. **Monitor Vault load**: Authentication requests will spike temporarily
3. **No data loss**: ExternalSecrets will continue working, just with new clients
4. **No configuration changes needed**: Cache key changes are internal

## Future Enhancements

### Potential Improvements

1. **ClientTLS ResourceVersion Tracking**
   - Include ClientTLS certificate/key Secret ResourceVersions
   - Currently not tracked (lower priority, transport layer not auth)

2. **CAProvider ResourceVersion Tracking**
   - Include CA bundle Secret/ConfigMap ResourceVersions
   - Currently not tracked (lower priority, validation not auth)

3. **Metrics**
   - Cache hit/miss rate
   - Authentication API call reduction
   - Cache eviction reasons (currently only automatic LRU/TTL evictions are counted; manual removals are intentionally ignored so the metric reflects cache pressure)

4. **Adaptive TTL**
   - Adjust cache TTL based on token lifetime
   - Could further reduce authentication overhead

5. **Configurable Cache Size**
   - Allow users to tune LRU cache size
   - Current default is reasonable for most deployments

## References

- Kubernetes ResourceVersion: https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions
- Vault Authentication: https://developer.hashicorp.com/vault/docs/auth
- External Secrets Operator: https://external-secrets.io/
- LRU Cache Implementation: https://github.com/hashicorp/golang-lru
