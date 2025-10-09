# Vault Client Pooling - Cache Key Design

## Overview

The Vault provider implements client pooling to reduce authentication overhead by reusing authenticated Vault clients across multiple ExternalSecrets. The cache key design is critical to ensure:

1. **Correctness**: Different credentials must never share a client
2. **Efficiency**: Identical credentials should always share a client
3. **Security**: Cache keys must never contain sensitive data (even hashed)
4. **Invalidation**: Cache must invalidate when credentials change

## Cache Key Structure

### Format

```
{vaultServer}|{vaultNamespace}|{authMountPath}|{authIdentity}
```

### Components

1. **vaultServer** (string)
   - Vault server URL (e.g., `https://vault.example.com:8200`)
   - Ensures clients connecting to different Vault servers are separate

2. **vaultNamespace** (string)
   - Vault Enterprise namespace (or empty string if not used)
   - Ensures clients in different Vault namespaces are separate

3. **authMountPath** (string)
   - Vault auth method mount path (e.g., `kubernetes`, `approle`, `jwt`)
   - Defaults to `auth` but can be customized per auth method
   - Ensures clients using different auth mounts are separate

4. **authIdentity** (string)
   - Credential-specific identity string (see below)
   - Contains namespace, name, and ResourceVersion of credential sources
   - **Never contains actual credentials** (only metadata)

### Why ResourceVersion Instead of Hashed Credentials?

**Critical Security Principle: Never include credentials in cache keys, even hashed.**

Reasons we use Kubernetes ResourceVersion instead of hashing credential values:

1. **No Credential Exposure**: ResourceVersion is a Kubernetes-provided opaque identifier that contains no credential data
2. **Automatic Invalidation**: ResourceVersion changes whenever a Secret/ServiceAccount is modified
3. **Correlation Attack Prevention**: Even SHA-256 of a token could be used to correlate cache accesses or identify credential reuse
4. **Compliance**: Many security policies prohibit storing any derivative of credentials in logs/metrics
5. **Simplicity**: No need to extract and hash credential values

## Client Sharing Behavior

### Scenario 1: Multiple ExternalSecrets in Same Namespace, Same SecretStore

```yaml
# 5 ExternalSecrets in namespace "apps"
# All reference SecretStore "vault" in namespace "apps"
# SecretStore references Secret "apps/vault-token"
```

**Expected Behavior**: All 5 ExternalSecrets share ONE client

**Cache Key**: `https://vault||auth|token:apps:vault-token:v12345`

**Rationale**: Identical credentials (same Secret) should reuse the same authenticated Vault client.

### Scenario 2: Multiple ExternalSecrets Across Namespaces, Shared ClusterSecretStore

```yaml
# 5 ExternalSecrets in namespaces [ns-1, ns-2, ns-3, ns-4, ns-5]
# All use ClusterSecretStore "vault-global"
# ClusterSecretStore references Secret "vault-system/vault-token" (explicit namespace)
```

**Expected Behavior**: All 5 ExternalSecrets share ONE client

**Cache Key**: `https://vault||auth|token:vault-system:vault-token:v12345`

**Rationale**: Same credentials (same Secret in vault-system) should reuse the same client regardless of which namespace's ExternalSecret is using it.

### Scenario 3: ClusterSecretStore with Referent Spec (Namespace-less References)

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

## Auth Identity Formats

Each authentication method has a specific format for `authIdentity`. All formats include the **resolved namespace and name** of credential sources to ensure uniqueness.

### 1. Kubernetes Auth (ServiceAccountRef)

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

### 2. Kubernetes Auth (SecretRef - JWT from Secret)

**Format:**
```
k8s-secret:{secretNamespace}:{secretName}:v{secretResourceVersion}
```

**Example:**
```
k8s-secret:apps:k8s-jwt-token:v54321
```

### 3. IAM Auth (JWTAuth with ServiceAccountRef)

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

### 4. IAM Auth (SecretRef - Static AWS Credentials)

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

### 5. AppRole (SecretRef)

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

### 6. Token (TokenSecretRef)

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

### 7. JWT from Secret

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

### 8. JWT from KubernetesServiceAccountToken

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

### 9. Cert (ClientCert + SecretRef for key)

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

### 10. LDAP

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

### 11. UserPass

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

## Cache Invalidation

### Automatic Invalidation

Cache invalidation happens automatically when credential sources change because we include **ResourceVersion** in cache keys:

1. **Secret Updated**: ResourceVersion changes → cache key changes → cache miss → new client created
2. **Secret Deleted/Recreated**: New ResourceVersion → cache key changes → cache miss → new client created
3. **ServiceAccount Updated**: ResourceVersion changes (e.g., IRSA annotation change) → cache key changes → cache miss → new client created
4. **ServiceAccount Deleted/Recreated**: New ResourceVersion → cache key changes → cache miss → new client created

### What Changes Trigger Invalidation

#### For Secrets:
- Data changes (credentials rotated)
- Annotations/labels changed
- Secret deleted and recreated
- Any other metadata change

#### For ServiceAccounts:
- Annotations changed (e.g., `eks.amazonaws.com/role-arn` for IRSA)
- Labels changed
- ServiceAccount secrets list changed (Kubernetes <1.24)
- ServiceAccount deleted and recreated
- Any other metadata change

### What Doesn't Trigger Invalidation

**External changes that don't modify K8s resources:**
- AWS IAM policy changes (doesn't modify ServiceAccount)
- Vault policy changes
- Network/connectivity changes
- Vault server configuration changes

**Mitigation**: These scenarios are handled by:
- Vault token TTLs (eventual expiration forces re-authentication)
- Error handling and retry logic
- Re-authentication on token expiration

## Implementation Details

### Namespace Resolution

When building `authIdentity`, namespaces are resolved using this logic:

1. **Explicit namespace in reference**: Use as-is
   - Example: ClusterSecretStore references `vault-system/vault-token` → namespace is `vault-system`

2. **No namespace in reference (referent spec)**: Use caller's namespace
   - Example: SecretStore in namespace `apps` references `vault-token` → namespace is `apps`
   - Example: ClusterSecretStore references `vault-token`, called from ExternalSecret in `team-a` → namespace is `team-a`

This resolution happens in `getAuthIdentity()` before building the cache key.

### Error Handling

If fetching a Secret or ServiceAccount fails during cache key generation:
1. `getAuthIdentity()` returns an error
2. `initClientPooled()` catches the error (provider.go:200-201)
3. System falls back to non-pooled behavior for that request
4. Logs error for visibility
5. Next reconciliation retries

This ensures graceful degradation when K8s API is unavailable or permissions are incorrect.

### Performance Considerations

**API Call Overhead:**
- Each cache key generation requires fetching Secrets/ServiceAccounts
- Cost: ~1-10ms per GET operation
- **Only happens on cache miss**, not on every reconciliation
- controller-runtime client has built-in caching
- Multiple ExternalSecrets using same credentials benefit from K8s client cache

**Cache Hit Ratio:**
- Expected: >95% in steady state
- Cache misses only occur on:
  - First access to new credentials
  - Credential rotation (ResourceVersion changes)
  - Cache eviction (LRU, size limits)

**Network Cost:**
- Reduced Vault authentication API calls (primary benefit)
- Vault auth typically takes 50-200ms
- K8s API GET typically takes 1-10ms
- Net savings: Significant (especially for frequently accessed secrets)

## Security Considerations

### Why Not Hash Credentials?

**Problem with hashing**: Even cryptographic hashes of credentials can be security risks:

1. **Correlation Attacks**: Same credential hash appears in logs/metrics across systems
2. **Credential Lifetime Tracking**: Observers can track when credentials are rotated
3. **Compliance Issues**: Many security frameworks prohibit any derivative of credentials in non-encrypted storage
4. **Rainbow Tables**: For low-entropy credentials (common in tests), hashes may be reversible
5. **Side Channels**: Cache key access patterns could leak information about credential usage

**Solution**: Use Kubernetes ResourceVersion, which is:
- Provided by Kubernetes (no access to credential data needed)
- Opaque (contains no credential information)
- Changes on any resource update (perfect invalidation signal)
- Safe to log, monitor, and store

### Cache Key in Logs

Cache keys may appear in debug logs. Since they contain only:
- Vault server URLs (not secrets)
- Namespace and resource names (not secrets)
- ResourceVersions (opaque identifiers, not secrets)

They are safe to log and monitor.

**Example log entry:**
```
Using pooled Vault client: vault-server=https://vault:8200 cacheKey=https://vault||auth|token:apps:vault-token:v12345
```

This reveals:
- Vault is at https://vault:8200
- Using a Secret named "vault-token" in namespace "apps"
- Secret's ResourceVersion is "12345"

This reveals **no credential data**.

## Testing

### Test Coverage

Tests in `pool_key_test.go` verify:

1. **Cache key format**: Correct structure for each auth method
2. **Namespace resolution**: Explicit vs referent spec
3. **ResourceVersion inclusion**: All auth methods include ResourceVersion
4. **Uniqueness**: Different credentials produce different keys
5. **Sharing**: Same credentials produce same keys
6. **Error handling**: Missing resources return errors

### Example Test Cases

```go
// Same credentials → same cache key
func TestSharedClient_SameCredentials(t *testing.T)

// Different namespaces → different cache keys (referent spec)
func TestSeparateClients_DifferentNamespaces(t *testing.T)

// Different ResourceVersions → different cache keys
func TestInvalidation_ResourceVersionChange(t *testing.T)

// Missing Secret → error returned
func TestError_SecretNotFound(t *testing.T)
```

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
   - Cache eviction reasons

4. **Adaptive TTL**
   - Adjust cache TTL based on token lifetime
   - Could further reduce authentication overhead

## References

- Kubernetes ResourceVersion: https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions
- Vault Authentication: https://developer.hashicorp.com/vault/docs/auth
- External Secrets Operator: https://external-secrets.io/