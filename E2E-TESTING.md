# Vault Client Pooling E2E Testing Guide

This guide provides scripts and instructions for testing the Vault client pooling feature with end-to-end tests.

## Scripts Overview

### 1. `run-vault-e2e-with-metrics.sh` - Full E2E Test Runner

**Purpose**: Sets up a complete testing environment with Kind cluster, runs Vault e2e tests, and establishes port-forwarding for metrics inspection.

**Usage**:
```bash
./run-vault-e2e-with-metrics.sh
```

**What it does**:
- ✅ Creates a Kind cluster named `external-secrets`
- ✅ Builds controller and e2e Docker images
- ✅ Loads images into Kind cluster
- ✅ Runs Vault e2e tests in the background (with pooling enabled)
- ✅ Starts port-forwarding to ESO controller on localhost:8080
- ✅ Tails test logs in real-time

**Output**:
- Test logs: `/tmp/vault-e2e-tests.log`
- Port-forward logs: `/tmp/port-forward.log`

---

### 2. `check-vault-metrics.sh` - Metrics Inspector

**Purpose**: Fetches and pretty-prints Vault client pool metrics from the ESO controller.

**Usage**:
```bash
# Pretty-printed output (default)
./check-vault-metrics.sh

# JSON output
./check-vault-metrics.sh --json

# Raw Prometheus metrics
./check-vault-metrics.sh --raw

# Custom metrics URL
./check-vault-metrics.sh --url http://localhost:9090/metrics
```

**Metrics displayed**:
- **Cache Performance**:
  - Cache hits
  - Cache misses
  - Hit rate
- **Pool Status**:
  - Current pool size
  - Pool utilization
- **Evictions**:
  - TTL-based evictions
  - Size-based evictions (LRU)
- **Health Indicators**:
  - Hit rate assessment
  - Eviction rate assessment
  - Recommendations

**Example output**:
```
╔════════════════════════════════════════════════════════════╗
║       Vault Client Pool Metrics - 2025-01-08 14:30:22     ║
╚════════════════════════════════════════════════════════════╝

┌─ Cache Performance
│
│  Cache Hits:                   245
│  Cache Misses:                 12
│  Total Requests:               257
│  Hit Rate:                     95.33%
└

┌─ Pool Status
│
│  Current Pool Size:            12
│  Max Pool Size:                1000 (default)
│  Pool Utilization:             1.2%
└
```

---

### 3. `verify-vault-pooling-logs.sh` - Log Verifier

**Purpose**: Analyzes ESO controller logs to verify vault client pooling is working correctly.

**Usage**:
```bash
# Pretty-printed analysis (default)
./verify-vault-pooling-logs.sh

# JSON output
./verify-vault-pooling-logs.sh --json

# Analyze more log lines
./verify-vault-pooling-logs.sh --lines 5000

# Different namespace
./verify-vault-pooling-logs.sh --namespace eso-system
```

**What it checks**:
- ✅ Feature flag is enabled (`--enable-vault-client-pooling`)
- ✅ Cache hit messages in logs
- ✅ Cache miss messages in logs
- ✅ Unique cache keys being used
- ✅ Sample log entries

**Expected log messages**:
- `Using pooled Vault client: cacheKey=...`
- `Cache miss, creating new Vault client: cacheKey=...`

**Example output**:
```
╔════════════════════════════════════════════════════════════╗
║     Vault Client Pool Log Verification - 2025-01-08 14:30:22 ║
╚════════════════════════════════════════════════════════════╝

┌─ Feature Status
│
│  Vault Client Pooling:         ✓ Enabled
└

┌─ Pooling Activity
│
│  Cache Hits:                   48
│  Cache Misses:                 6
│  Cache Key References:         54
│  Hit Rate:                     88.89%
└

┌─ Verification Results
│
│  ✓ Feature flag detected in logs
│  ✓ Cache activity detected (54 operations)
│  ✓ Cache hits detected - pooling is working
│  ✓ Cache keys found (6 unique configurations)
└

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Vault Client Pooling is WORKING CORRECTLY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### 4. `verify-vault-pooling.sh` - Comprehensive Verifier

**Purpose**: Runs both metrics and log verification in a single command.

**Usage**:
```bash
# Pretty-printed combined output
./verify-vault-pooling.sh

# JSON output with both metrics and logs
./verify-vault-pooling.sh --json
```

**What it does**:
1. Verifies logs for pooling activity
2. Checks metrics endpoint for pool statistics
3. Provides comprehensive verification results

---

## Quick Start

### Step 1: Run E2E Tests

```bash
# This will set up everything and start tests
./run-vault-e2e-with-metrics.sh
```

Keep this terminal open - it will tail the test logs.

### Step 2: Verify Pooling (in a new terminal)

```bash
# Run comprehensive verification
./verify-vault-pooling.sh
```

Or check individual components:

```bash
# Check metrics only
./check-vault-metrics.sh

# Check logs only
./verify-vault-pooling-logs.sh
```

### Step 3: Monitor in Real-Time

```bash
# Watch metrics update every 5 seconds
watch -n 5 './check-vault-metrics.sh'

# Or watch the combined verification
watch -n 5 './verify-vault-pooling.sh'
```

---

## Manual Setup (Alternative)

If you prefer manual control:

### 1. Create Kind Cluster
```bash
make -C e2e start-kind
```

### 2. Build and Run Tests
```bash
cd e2e
export VERSION=$(git describe --dirty --always --tags --exclude 'helm*' | sed 's/-/./2' | sed 's/-/./2')
export TEST_SUITES=provider
export GINKGO_LABELS=vault
make test
```

### 3. Port-Forward to ESO
```bash
kubectl port-forward -n default deployment/eso-external-secrets 8080:8080
```

### 4. Check Metrics
```bash
./check-vault-metrics.sh
```

### 5. Verify Logs
```bash
./verify-vault-pooling-logs.sh
```

---

## Expected Behavior

### When Pooling is Working Correctly

**Metrics**:
- Hit rate: **>90%** after warm-up period
- Pool size: Grows to accommodate unique credential combinations
- Evictions: Minimal (mostly TTL-based, not size-based)

**Logs**:
- Feature flag `enable-vault-client-pooling` detected
- "Using pooled Vault client" messages for cache hits
- "Cache miss, creating new Vault client" for first-time credentials
- Unique cache keys following the format: `{SERVER}|{VAULT_NS}|{AUTH_PATH}|{K8S_NS}|{AUTH_IDENTITY}`

### Example Cache Keys

```
# Kubernetes ServiceAccount (dynamic caching)
https://vault:8200||auth/kubernetes|default|k8s-sa:default:reader

# AppRole (static caching with ResourceVersion)
https://vault:8200||auth/approle|default|approle:my-role:v12345

# Token auth (static caching)
https://vault:8200||auth/token|default|token:v98765
```

---

## Troubleshooting

### No metrics found

**Problem**: `check-vault-metrics.sh` reports "No vault_client_pool metrics found"

**Solutions**:
1. Verify feature flag is enabled:
   ```bash
   kubectl get deployment eso-external-secrets -n default -o yaml | grep enable-vault-client-pooling
   ```
2. Check if any Vault operations have occurred:
   ```bash
   kubectl get externalsecrets -A
   ```
3. Wait for tests to start (they may take a few minutes to initialize)

### Port-forward not working

**Problem**: Cannot connect to localhost:8080

**Solutions**:
1. Check if port-forward is running:
   ```bash
   ps aux | grep "port-forward"
   ```
2. Restart port-forward:
   ```bash
   kubectl port-forward -n default deployment/eso-external-secrets 8080:8080
   ```
3. Check if ESO pod is running:
   ```bash
   kubectl get pods -n default -l app.kubernetes.io/name=external-secrets
   ```

### Low cache hit rate

**Problem**: Hit rate is below 70%

**Possible causes**:
1. **Credentials are changing frequently** - Check if SecretStore resources are being recreated
2. **Multiple unique credential configurations** - Normal if you have many different Vault auth setups
3. **Tests are still warming up** - Give it a few minutes for cache to populate

### No log activity

**Problem**: `verify-vault-pooling-logs.sh` shows no cache activity

**Solutions**:
1. Increase the number of log lines analyzed:
   ```bash
   ./verify-vault-pooling-logs.sh --lines 5000
   ```
2. Check if tests have started:
   ```bash
   tail -f /tmp/vault-e2e-tests.log
   ```
3. Verify ESO pod is running:
   ```bash
   kubectl logs -n default -l app.kubernetes.io/name=external-secrets --tail=100
   ```

---

## Cleanup

```bash
# Stop port-forward (if running manually)
pkill -f "port-forward.*eso-external-secrets"

# Delete Kind cluster
make -C e2e stop-kind

# Clean up log files
rm -f /tmp/vault-e2e-tests.log /tmp/port-forward.log
```

---

## Advanced Usage

### Export Verification Data

```bash
# Export metrics as JSON
./check-vault-metrics.sh --json > metrics-$(date +%Y%m%d-%H%M%S).json

# Export log analysis as JSON
./verify-vault-pooling-logs.sh --json > logs-$(date +%Y%m%d-%H%M%S).json

# Export combined verification
./verify-vault-pooling.sh --json > verification-$(date +%Y%m%d-%H%M%S).json
```

### Continuous Monitoring

```bash
# Monitor and log metrics every 30 seconds
while true; do
    echo "=== $(date) ===" >> metrics-history.log
    ./check-vault-metrics.sh >> metrics-history.log
    sleep 30
done
```

### Compare Metrics Over Time

```bash
# Capture initial state
./check-vault-metrics.sh --json > metrics-before.json

# Wait for some time or run operations
sleep 300

# Capture final state
./check-vault-metrics.sh --json > metrics-after.json

# Compare (requires jq)
diff <(jq . metrics-before.json) <(jq . metrics-after.json)
```

---

## CI/CD Integration

These scripts can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions snippet
- name: Run Vault E2E Tests with Pooling
  run: |
    ./run-vault-e2e-with-metrics.sh &
    RUNNER_PID=$!
    sleep 300  # Wait for tests to run

    # Verify pooling is working
    ./verify-vault-pooling.sh --json > verification.json

    # Check results
    if jq -e '.logs.verification.working_correctly == true' verification.json; then
      echo "✓ Vault client pooling verified"
    else
      echo "✗ Vault client pooling verification failed"
      exit 1
    fi
```

---

## Additional Resources

- **Implementation Summary**: See `IMPLEMENTATION-SUMMARY.md` for technical details
- **Design Document**: See `DESIGN.md` for architecture and design decisions
- **Pool Documentation**: See `pkg/provider/vault/POOL.md` for cache key design
- **Unit Tests**: See `pkg/provider/vault/pool_test.go` and `pool_key_test.go`

---

## Support

If you encounter issues:

1. Check this guide's Troubleshooting section
2. Review test logs: `/tmp/vault-e2e-tests.log`
3. Inspect ESO pod logs: `kubectl logs -n default -l app.kubernetes.io/name=external-secrets`
4. Verify Kind cluster health: `kubectl get nodes`