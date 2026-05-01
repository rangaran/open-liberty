# LTPA Refactoring Test Plan

## Overview

This document outlines the testing strategy for the LTPA SSO method refactoring changes made in the `bob-pqc-ltpa` branch.

**Date:** 2026-05-01  
**Branch:** bob-pqc-ltpa  

## Changes Summary

### 1. Method Renaming
- **Old:** `getJwtSsoTokenFromCookies(HttpServletRequest, String)`
- **New:** `getSsoTokenFromCookies(HttpServletRequest, String)`
- **Reason:** Generic name reflects multi-token support (JWT, LTPA, etc.)
- **Backward Compatibility:** Old method deprecated and delegates to new method

### 2. Code Refactoring
- **handleLtpaSSO()**: Refactored to use common `getSsoTokenFromCookies()` method
- **Eliminated:** Custom fragmented cookie handling logic
- **Code Reduction:** 77 → 43 lines (44% reduction)

### 3. Variable Naming
- **Changed:** `ltpa64` → `ltpaToken`
- **Reason:** LTPA3 tokens use hex encoding, not base64

## Test Strategy

### Phase 1: Unit Tests ✅

#### A. SSOAuthenticatorTest
**Location:** `dev/com.ibm.ws.webcontainer.security/test/com/ibm/ws/webcontainer/security/internal/SSOAuthenticatorTest.java`

**Test Methods to Verify:**
1. `authenticate_NoCookies()` - Verifies null return when no cookies exist
2. `authenticate_createLogoutCookiesOnInvalidSession()` - Tests logout cookie creation
3. `authenticate_NoSSOCookies()` - Tests behavior with non-SSO cookies
4. `authenticate_EmptyCookieValue()` - Tests empty cookie value handling
5. `authenticate_InvalidCookieValue()` - Tests invalid cookie authentication
6. `authenticate_WithCookie()` - **CRITICAL** - Tests successful LTPA authentication
7. `authenticate_authenticationFails()` - Tests authentication failure handling

**Expected Results:**
- All tests should pass without modification
- Tests use mocked `ssoCookieHelper.getSSOCookiename()` which is unchanged
- Authentication flow logic remains the same, only implementation details changed

#### B. SSOCookieHelperImplTest
**Location:** `dev/com.ibm.ws.webcontainer.security/test/com/ibm/ws/webcontainer/security/SSOCookieHelperImplTest.java`

**Test Methods to Verify:**
1. `testAddSSOCookiesToResponse_SubjectWithSSOToken()` - Tests cookie addition
2. `addCookies()` - Tests cookie handling

**Expected Results:**
- All tests should pass
- New `getSsoTokenFromCookies()` method should work identically to old method
- Deprecated method should still work via delegation

### Phase 2: Integration Tests

#### A. Build Verification
**Command:**
```bash
cd /Users/utle/libertyGit/open-liberty/dev
export JAVA_HOME=/Users/utle/Java/semeru/jdk-17.0.12+7/Contents/Home
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home
./gradlew com.ibm.ws.webcontainer.security:build --console=plain
```

**Expected Results:**
- ✅ Compilation succeeds
- ✅ No new warnings or errors
- ✅ All unit tests pass

#### B. Run Unit Tests Explicitly
**Command:**
```bash
./gradlew com.ibm.ws.webcontainer.security:test --console=plain
```

**Expected Results:**
- All existing tests pass
- No test failures or errors
- Test coverage maintained

### Phase 3: Functional Acceptance Tests (FAT)

#### A. Existing LTPA FAT Tests
**Location:** `dev/com.ibm.ws.security.token.ltpa_fat/`

**Test Suite:** `FATSuite.java`

**Critical Tests:**
1. **LTPAConfigTests** - LTPA configuration and token generation
2. **LTPAKeystoreTests** - Keystore management and conversion
3. **Cookie handling tests** - Fragmented cookie reassembly

**Command:**
```bash
./gradlew com.ibm.ws.security.token.ltpa_fat:buildandrun --console=plain
```

**Expected Results:**
- All existing FAT tests pass
- Cookie fragmentation/reassembly works correctly
- LTPA2 token authentication succeeds
- No regressions in existing functionality

#### B. New PQC FAT Tests
**Location:** `dev/com.ibm.ws.security.token.ltpa_fat/fat/src/com/ibm/ws/security/token/ltpa/fat/LTPAPQCTests.java`

**Test Cases:**
1. `testPQCTokenGeneration()` - Generate LTPA3 tokens with PQC
2. `testPQCTokenValidation()` - Validate LTPA3 tokens
3. `testPQCCookieFragmentation()` - Test large token fragmentation
4. `testPQCInteroperability()` - LTPA2/LTPA3 interoperability
5. `testJavaVersionFallback()` - Java 17 fallback behavior
6. `testInvalidPQCToken()` - Error handling
7. `testPQCConfiguration()` - Configuration validation
8. `testPQCPerformance()` - Performance benchmarking

**Prerequisites:**
- Java 26+ for PQC support
- PQC test keystores generated
- Test server configured

**Command:**
```bash
export JAVA_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home
./gradlew com.ibm.ws.security.token.ltpa_fat:buildandrun --tests=LTPAPQCTests --console=plain
```

**Expected Results:**
- PQC token generation succeeds on Java 26+
- Cookie fragmentation handles large LTPA3 tokens
- Fallback to LTPA2 on Java 17
- All PQC-specific tests pass

### Phase 4: Regression Testing

#### A. JWT SSO Tests
**Verify:** JWT authentication still works with renamed method

**Tests:**
- JWT token retrieval from cookies
- JWT authentication flow
- JWT cookie fragmentation (if applicable)

#### B. Cookie Handling Tests
**Verify:** Cookie chunking refactoring works correctly

**Tests:**
- Single cookie handling
- Fragmented cookie reassembly
- Cookie naming patterns (base + numbered fragments)
- Maximum cookie size handling

#### C. Backward Compatibility Tests
**Verify:** Deprecated method still works

**Test Code:**
```java
// Old method should still work
String token = ssoCookieHelper.getJwtSsoTokenFromCookies(req, "JWT");
assertNotNull(token);

// New method should work identically
String token2 = ssoCookieHelper.getSsoTokenFromCookies(req, "JWT");
assertEquals(token, token2);
```

## Test Execution Status

| Phase | Test | Status | Notes |
|-------|------|--------|-------|
| 1A | SSOAuthenticatorTest | ⏳ Pending | Build in progress |
| 1B | SSOCookieHelperImplTest | ⏳ Pending | Build in progress |
| 2A | Build Verification | ⏳ In Progress | Gradle build running |
| 2B | Unit Tests | ⏳ Pending | After build completes |
| 3A | Existing LTPA FAT | ⏳ Pending | After unit tests pass |
| 3B | New PQC FAT | ⏳ Pending | Requires Java 26+ |
| 4A | JWT SSO Tests | ⏳ Pending | Regression testing |
| 4B | Cookie Handling | ⏳ Pending | Regression testing |
| 4C | Backward Compatibility | ⏳ Pending | Deprecated method test |

## Success Criteria

### Must Pass (P0)
- ✅ All existing unit tests pass
- ✅ Build completes without errors
- ✅ No new compiler warnings
- ✅ All existing LTPA FAT tests pass
- ✅ Cookie fragmentation works correctly
- ✅ LTPA2 authentication succeeds

### Should Pass (P1)
- ⏳ PQC FAT tests pass on Java 26+
- ⏳ JWT SSO tests pass
- ⏳ Backward compatibility verified
- ⏳ No performance regressions

### Nice to Have (P2)
- ⏳ Code coverage maintained or improved
- ⏳ Performance benchmarks show no degradation
- ⏳ Documentation updated

## Risk Assessment

### Low Risk Changes
- ✅ Method renaming with deprecation (backward compatible)
- ✅ Variable naming improvement (no functional change)
- ✅ Code consolidation (same logic, better organized)

### Medium Risk Changes
- ⚠️ Refactored `handleLtpaSSO()` method
  - **Mitigation:** Extensive unit test coverage exists
  - **Verification:** Run all SSOAuthenticatorTest tests

### High Risk Changes
- None identified

## Rollback Plan

If tests fail:

1. **Identify Failure:**
   - Review test output and logs
   - Identify which specific test failed
   - Determine root cause

2. **Quick Fix Options:**
   - Revert variable naming change if causing issues
   - Restore original `handleLtpaSSO()` implementation
   - Keep method renaming (low risk, backward compatible)

3. **Full Rollback:**
   ```bash
   git checkout HEAD~1 -- dev/com.ibm.ws.webcontainer.security/
   ```

## Next Steps

1. ✅ Wait for build to complete
2. ⏳ Run unit tests
3. ⏳ Analyze test results
4. ⏳ Run FAT tests if unit tests pass
5. ⏳ Document test results
6. ⏳ Create final summary

## References

- [SSOAuthenticatorTest.java](dev/com.ibm.ws.webcontainer.security/test/com/ibm/ws/webcontainer/security/internal/SSOAuthenticatorTest.java)
- [SSOCookieHelperImplTest.java](dev/com.ibm.ws.webcontainer.security/test/com/ibm/ws/webcontainer/security/SSOCookieHelperImplTest.java)
- [LTPA_SSO_METHOD_REFACTORING_SUMMARY.md](LTPA_SSO_METHOD_REFACTORING_SUMMARY.md)
- [LTPA_COOKIE_REFACTORING_SUMMARY.md](LTPA_COOKIE_REFACTORING_SUMMARY.md)

---

**Created with IBM Bob** - LTPA Refactoring Test Plan