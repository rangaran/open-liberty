# PQC LTPA Production Testing Guide

## Overview
This guide provides step-by-step instructions for testing the Post-Quantum Cryptography (PQC) LTPA implementation in a production-like environment.

## Prerequisites

### Required Software
- ✅ Java 26 (IBM Semeru Runtime Open Edition 26+35)
- ✅ Java 21 (for Liberty build compatibility)
- ✅ Open Liberty development environment
- ✅ Git repository on `bob-pqc-ltpa` branch

### Environment Setup
```bash
export JAVA_HOME=/Users/utle/Java/semeru/jdk-17.0.12+7/Contents/Home
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home
export JAVA_26_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home
```

## Testing Phases

### Phase 1: Build Verification ✅ COMPLETE
**Status:** All tests passed
- ✅ Code compiles with Java 17
- ✅ 90/90 unit tests passing
- ✅ Module builds successfully
- ✅ Java 26 ML-KEM verified functional

### Phase 2: Server Build & Startup (CURRENT)
**Objective:** Build and start Liberty server with PQC configuration

#### Step 1: Build Liberty with PQC Module
```bash
cd /Users/utle/libertyGit/open-liberty/dev
export JAVA_HOME=/Users/utle/Java/semeru/jdk-17.0.12+7/Contents/Home
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home

# Build LTPA module
./gradlew com.ibm.ws.security.token.ltpa:build

# Build complete Liberty runtime (takes 10-15 minutes)
./gradlew assemble
```

#### Step 2: Create Local Release
```bash
# Create a local Liberty release with PQC support
./gradlew releaseNeeded

# Release will be in:
# open-liberty/dev/cnf/release/dev/openliberty/<version>/openliberty-<version>.zip
```

#### Step 3: Extract and Configure Server
```bash
# Extract Liberty
cd /tmp
unzip /Users/utle/libertyGit/open-liberty/dev/cnf/release/dev/openliberty/*/openliberty-*.zip

# Create PQC test server
cd wlp/bin
./server create pqcTestServer

# Copy PQC configuration
cp /Users/utle/libertyGit/open-liberty/dev/com.ibm.ws.security.token.ltpa_fat/publish/servers/com.ibm.ws.security.token.ltpa.fat.pqcTestServer/server.xml \
   ../usr/servers/pqcTestServer/

cp /Users/utle/libertyGit/open-liberty/dev/com.ibm.ws.security.token.ltpa_fat/publish/servers/com.ibm.ws.security.token.ltpa.fat.pqcTestServer/bootstrap.properties \
   ../usr/servers/pqcTestServer/
```

#### Step 4: Start Server with Java 26
```bash
# Set Java 26 for runtime
export JAVA_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home

# Start server
./server start pqcTestServer

# Monitor startup
tail -f ../usr/servers/pqcTestServer/logs/messages.log
```

### Phase 3: Verification Tests

#### Test 1: Server Startup
**Expected Results:**
```
CWWKF0011I: The pqcTestServer server is ready to run a smarter planet.
CWWKS4105I: LTPA configuration is ready after X seconds.
```

**Verification:**
```bash
# Check server status
./server status pqcTestServer

# Should show: Server pqcTestServer is running
```

#### Test 2: PQC Keystore Creation
**Expected Results:**
- Traditional LTPA keys: `ltpa.keys`
- PQC keystore: `ltpa-pqc.p12`

**Verification:**
```bash
ls -la ../usr/servers/pqcTestServer/resources/security/

# Should see:
# -rw------- ltpa.keys
# -rw------- ltpa-pqc.p12
```

#### Test 3: PQC Runtime Detection
**Expected in messages.log:**
```
[PQCRuntimeSupport] Java 26+ detected, ML-KEM support available
[LTPAPQCKeyGenerator] Generating ML-KEM-768 key pair...
[LTPAPQCKeystoreManager] PQC keystore created: ltpa-pqc.p12
```

**Verification:**
```bash
grep -i "pqc\|ml-kem" ../usr/servers/pqcTestServer/logs/messages.log
```

#### Test 4: Trace Log Analysis
**Enable detailed tracing:**
```xml
<logging 
    traceSpecification="*=info:com.ibm.ws.security.token.ltpa*=all:com.ibm.ws.security.token.ltpa.pqc*=all"/>
```

**Expected in trace.log:**
```
[PQCRuntimeSupport] isPQCSupported() = true
[LTPAPQCCrypto] Encrypting token with ML-KEM + AES-GCM
[LTPAPQCCrypto] Encapsulation successful, shared secret: 32 bytes
```

**Verification:**
```bash
grep -i "pqc\|ml-kem" ../usr/servers/pqcTestServer/logs/trace.log | head -50
```

### Phase 4: Functional Testing

#### Test 5: LTPA Token Generation
**Create test application:**
```java
@WebServlet("/test")
public class LTPATestServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        // Access authenticated - LTPA token should be created
        response.getWriter().println("User: " + request.getRemoteUser());
        response.getWriter().println("Auth Type: " + request.getAuthType());
    }
}
```

**Test:**
```bash
curl -u testuser:testpwd http://localhost:9080/test

# Check Set-Cookie header for LtpaToken2
curl -v -u testuser:testpwd http://localhost:9080/test 2>&1 | grep -i "set-cookie"
```

#### Test 6: Token Validation
**Test token reuse:**
```bash
# Get token from first request
TOKEN=$(curl -c cookies.txt -u testuser:testpwd http://localhost:9080/test 2>&1 | grep LtpaToken2 | cut -d'=' -f2)

# Use token for second request (should work without credentials)
curl -b "LtpaToken2=$TOKEN" http://localhost:9080/test
```

### Phase 5: Performance Testing

#### Test 7: Token Generation Performance
**Measure token creation time:**
```bash
# Run 100 token generations
for i in {1..100}; do
    time curl -s -u testuser:testpwd http://localhost:9080/test > /dev/null
done
```

**Compare:**
- LTPA v2 (RSA-only): ~5-10ms per token
- LTPA v3 (PQC): ~15-25ms per token (expected overhead)

#### Test 8: Memory Usage
**Monitor server memory:**
```bash
# Before load test
ps aux | grep pqcTestServer

# Run load test (1000 requests)
ab -n 1000 -c 10 -A testuser:testpwd http://localhost:9080/test

# After load test
ps aux | grep pqcTestServer
```

### Phase 6: Failure Scenarios

#### Test 9: Java 17 Fallback
**Test with Java 17:**
```bash
export JAVA_HOME=/Users/utle/Java/semeru/jdk-17.0.12+7/Contents/Home
./server start pqcTestServer
```

**Expected:**
```
[PQCRuntimeSupport] Java 26 not detected, PQC unavailable
[LTPA] Falling back to LTPA v2 (RSA-only)
```

#### Test 10: Invalid Configuration
**Test with invalid ML-KEM algorithm:**
```xml
<ltpa mlkemAlgorithm="ML-KEM-999"/>
```

**Expected:**
```
CWWKS4xxx: Invalid ML-KEM algorithm: ML-KEM-999
CWWKS4xxx: Valid algorithms: ML-KEM-512, ML-KEM-768, ML-KEM-1024
```

## Success Criteria

### Must Pass
- ✅ Server starts successfully with Java 26
- ✅ PQC keystore created (ltpa-pqc.p12)
- ✅ ML-KEM runtime detection works
- ✅ LTPA tokens generated successfully
- ✅ Token validation works correctly
- ✅ Graceful fallback to Java 17

### Should Pass
- ✅ Performance within acceptable range (<50ms per token)
- ✅ Memory usage stable under load
- ✅ Trace logs show PQC operations
- ✅ Error handling works correctly

## Troubleshooting

### Issue: Server won't start
**Cause:** Missing dependencies or configuration errors
**Solution:**
```bash
# Check messages.log for errors
tail -100 ../usr/servers/pqcTestServer/logs/messages.log

# Check console.log
tail -100 ../usr/servers/pqcTestServer/logs/console.log
```

### Issue: PQC keystore not created
**Cause:** Java 26 not detected or insufficient permissions
**Solution:**
```bash
# Verify Java version
$JAVA_HOME/bin/java --version

# Check file permissions
ls -la ../usr/servers/pqcTestServer/resources/security/
```

### Issue: Token generation fails
**Cause:** Configuration error or missing features
**Solution:**
```bash
# Verify LTPA configuration
grep -A 10 "<ltpa" ../usr/servers/pqcTestServer/server.xml

# Check feature manager
grep -A 5 "<featureManager" ../usr/servers/pqcTestServer/server.xml
```

## Estimated Time

| Phase | Duration | Status |
|-------|----------|--------|
| Build Verification | 5 min | ✅ Complete |
| Server Build | 15 min | ⏳ Pending |
| Server Startup | 2 min | ⏳ Pending |
| Verification Tests | 10 min | ⏳ Pending |
| Functional Testing | 15 min | ⏳ Pending |
| Performance Testing | 20 min | ⏳ Pending |
| Failure Scenarios | 10 min | ⏳ Pending |
| **Total** | **~77 min** | **In Progress** |

## Next Steps

1. **Build Liberty Runtime** (15 minutes)
   ```bash
   ./gradlew assemble
   ```

2. **Create Local Release** (5 minutes)
   ```bash
   ./gradlew releaseNeeded
   ```

3. **Start PQC Test Server** (2 minutes)
   ```bash
   ./server start pqcTestServer
   ```

4. **Run Verification Tests** (10 minutes)
   - Check keystore creation
   - Verify PQC detection
   - Analyze trace logs

5. **Functional Testing** (15 minutes)
   - Generate LTPA tokens
   - Validate token reuse
   - Test authentication flow

## Conclusion

This guide provides a comprehensive testing plan for the PQC LTPA implementation. The tests cover build verification, server startup, functional testing, performance analysis, and failure scenarios.

**Current Status:** Ready to begin Phase 2 (Server Build & Startup)

**Recommendation:** Start with building the Liberty runtime and creating a local release, then proceed with server startup and verification tests.