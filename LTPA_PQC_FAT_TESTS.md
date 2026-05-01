# LTPA PQC FAT Tests Documentation

## Overview

This document describes the Functional Acceptance Tests (FAT) for LTPA Hybrid Post-Quantum Cryptography (PQC) support in Open Liberty.

## Test Suite: LTPAPQCTests

**Location:** `dev/com.ibm.ws.security.token.ltpa_fat/fat/src/com/ibm/ws/security/token/ltpa/fat/LTPAPQCTests.java`

**Test Server:** `com.ibm.ws.security.token.ltpa.fat.pqcTestServer`

### Purpose

These tests verify the implementation of LTPA Token Version 3 with triple-layer hybrid cryptography:
- **RSA-2048** for classical digital signatures (backward compatibility)
- **ML-DSA-65** for quantum-resistant digital signatures (NIST FIPS 204)
- **ML-KEM-768** for quantum-resistant key encapsulation (NIST FIPS 203)

## Prerequisites

### Java Version Requirements

- **Java 26+**: Required for full PQC support (ML-DSA and ML-KEM)
- **Java 17**: Tests will run but fall back to RSA-only mode

### Environment Setup

```bash
# For full PQC testing (Java 26)
export JAVA_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home

# For fallback testing (Java 17)
export JAVA_HOME=/Users/utle/Java/semeru/jdk-17.0.12+7/Contents/Home
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home
```

## Test Cases

### 1. testPQC_BasicTokenCreationAndValidation

**Mode:** LITE  
**Java Requirement:** Java 26+

**Purpose:** Verify basic PQC LTPA token creation and validation.

**Test Steps:**
1. Start server with hybrid PQC configuration
2. Verify LTPA configuration is ready (CWWKS4105I)
3. Verify hybrid keystore is created (`ltpa-hybrid.p12`)
4. Verify PQC support is enabled
5. Perform form login with user1/user1pwd
6. Verify LTPA token is created
7. Reuse token to access protected resource

**Expected Results:**
- Server starts successfully
- Hybrid keystore created with RSA + ML-DSA + ML-KEM keys
- LTPA tokens can be created and validated
- Form login works with PQC-enabled tokens
- Token can be reused for subsequent requests

**Verification:**
```
CWWKS4105I: LTPA configuration is ready after X seconds.
CWWKS4104A: LTPA keys created in X seconds.
[INFO] Hybrid keystore created: ltpa-hybrid.p12
[INFO] Generated RSA-2048 + ML-DSA-65 + ML-KEM-768 hybrid keys
```

---

### 2. testPQC_FallbackToRSAOnly

**Mode:** FULL  
**Java Requirement:** Java 17 (not Java 26+)

**Purpose:** Verify graceful fallback to RSA-only mode when Java 26 is not available.

**Test Steps:**
1. Start server with Java 17
2. Verify LTPA configuration is ready
3. Verify PQC fallback warnings are logged
4. Perform form login
5. Verify token works with RSA-only mode

**Expected Results:**
- Server starts successfully even without Java 26
- Falls back to RSA-only mode (LTPA Token Version 2)
- Logs appropriate warnings about PQC unavailability
- Form login still works with RSA-only tokens

**Verification:**
```
[WARN] ML-DSA not available, falling back to RSA-only mode
[WARN] ML-KEM not available, using AES-GCM encryption
CWWKS4105I: LTPA configuration is ready after X seconds.
```

---

### 3. testPQC_MLDSAAlgorithms

**Mode:** FULL  
**Java Requirement:** Java 26+

**Purpose:** Verify ML-DSA signature algorithms work correctly.

**Test Steps:**
1. Start server with ML-DSA-65 configuration (default)
2. Verify ML-DSA-65 algorithm is initialized
3. Perform form login
4. Verify token creation and validation

**Expected Results:**
- ML-DSA-65 algorithm is properly initialized
- Tokens are signed with both RSA and ML-DSA-65
- Token validation succeeds

**Supported Algorithms:**
- `ML-DSA-44`: NIST Level 2 (128-bit quantum security)
- `ML-DSA-65`: NIST Level 3 (192-bit quantum security) ⭐ **Default**
- `ML-DSA-87`: NIST Level 5 (256-bit quantum security)

---

### 4. testPQC_MLKEMAlgorithms

**Mode:** FULL  
**Java Requirement:** Java 26+

**Purpose:** Verify ML-KEM key encapsulation algorithms work correctly.

**Test Steps:**
1. Start server with ML-KEM-768 configuration (default)
2. Verify ML-KEM-768 algorithm is initialized
3. Perform form login
4. Verify token encryption and decryption

**Expected Results:**
- ML-KEM-768 algorithm is properly initialized
- Tokens are encrypted with ML-KEM + AES-GCM
- Token decryption succeeds

**Supported Algorithms:**
- `ML-KEM-512`: NIST Level 1 (128-bit quantum security)
- `ML-KEM-768`: NIST Level 3 (192-bit quantum security) ⭐ **Default**
- `ML-KEM-1024`: NIST Level 5 (256-bit quantum security)

---

### 5. testPQC_HybridSignatureVerification

**Mode:** FULL  
**Java Requirement:** Java 26+

**Purpose:** Verify defense-in-depth approach where both RSA and ML-DSA signatures must be valid.

**Test Steps:**
1. Start server with hybrid PQC enabled
2. Create token with hybrid signatures
3. Verify both RSA and ML-DSA signatures are checked
4. Verify token is valid

**Expected Results:**
- Token contains both RSA and ML-DSA signatures
- Both signatures are verified during validation
- Token validation succeeds only if both signatures are valid

**Security Note:** This defense-in-depth approach ensures security even if one cryptographic system is compromised.

---

### 6. testPQC_TokenExpiration

**Mode:** FULL  
**Java Requirement:** Java 26+

**Purpose:** Verify token expiration works correctly with PQC-enabled tokens.

**Test Steps:**
1. Start server (configured with 30m expiration)
2. Create token
3. Verify token is valid immediately
4. (Note: Full expiration testing requires waiting 30+ minutes)

**Expected Results:**
- Token is created with correct expiration time
- Token is valid within expiration window
- Token validation respects expiration settings

---

### 7. testPQC_HybridKeystorePasswordProtection

**Mode:** FULL  
**Java Requirement:** Java 26+

**Purpose:** Verify hybrid keystore is properly password-protected.

**Test Steps:**
1. Start server
2. Verify hybrid keystore is created
3. Verify keystore has appropriate file permissions

**Expected Results:**
- Hybrid keystore is created
- Keystore is password-protected
- Keystore has secure file permissions (600)

**Expected FFDC:**
- `java.io.IOException` (if password is incorrect)
- `java.security.UnrecoverableKeyException` (if password is incorrect)

---

### 8. testPQC_BackwardCompatibility

**Mode:** FULL  
**Java Requirement:** Java 26+

**Purpose:** Verify PQC tokens maintain backward compatibility with RSA-only validation.

**Test Steps:**
1. Start server with hybrid PQC enabled
2. Create token with hybrid PQC
3. Verify RSA signature is present and valid
4. Verify token can be validated using only RSA signature

**Expected Results:**
- Token contains valid RSA signature
- Token can be validated by RSA-only systems
- Backward compatibility is maintained

**Use Case:** Allows gradual migration from RSA-only to hybrid PQC systems.

---

## Running the Tests

### Run All LTPA FAT Tests

```bash
cd /Users/utle/libertyGit/open-liberty/dev
export JAVA_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home && \
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home && \
./gradlew com.ibm.ws.security.token.ltpa_fat:buildandrun
```

### Run Only PQC Tests

```bash
cd /Users/utle/libertyGit/open-liberty/dev
export JAVA_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home && \
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home && \
./gradlew com.ibm.ws.security.token.ltpa_fat:buildandrun --tests LTPAPQCTests
```

### Run Specific Test

```bash
cd /Users/utle/libertyGit/open-liberty/dev
export JAVA_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home && \
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home && \
./gradlew com.ibm.ws.security.token.ltpa_fat:buildandrun --tests LTPAPQCTests.testPQC_BasicTokenCreationAndValidation
```

### Run with Java 17 (Fallback Testing)

```bash
cd /Users/utle/libertyGit/open-liberty/dev
export JAVA_HOME=/Users/utle/Java/semeru/jdk-17.0.12+7/Contents/Home && \
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home && \
./gradlew com.ibm.ws.security.token.ltpa_fat:buildandrun --tests LTPAPQCTests.testPQC_FallbackToRSAOnly
```

## Test Server Configuration

**Server:** `com.ibm.ws.security.token.ltpa.fat.pqcTestServer`

**Location:** `dev/com.ibm.ws.security.token.ltpa_fat/publish/servers/com.ibm.ws.security.token.ltpa.fat.pqcTestServer/`

### Key Configuration (server.xml)

```xml
<ltpa
    keysFileName="${server.output.dir}/resources/security/ltpa.keys"
    keysPassword="{xor}Lz4sLCgwLTs="
    expiration="30m"
    tokenVersion="3"
    hybridPqcEnabled="true"
    hybridKeystoreFile="${server.output.dir}/resources/security/ltpa-hybrid.p12"
    hybridKeystorePassword="{xor}Lz4sLCgwLTs="
    mldsaAlgorithm="ML-DSA-65"
    mlkemAlgorithm="ML-KEM-768"/>
```

### Test Users

| Username | Password | Role |
|----------|----------|------|
| testuser | testpwd  | User |
| user1    | user1pwd | User |
| user2    | user2pwd | User |

### Passwords

- LTPA Keys Password: `ltpapwd` (XOR encoded: `{xor}Lz4sLCgwLTs=`)
- Hybrid Keystore Password: `ltpapwd` (XOR encoded: `{xor}Lz4sLCgwLTs=`)

## Test Artifacts

### Generated Files

During test execution, the following files are created:

1. **ltpa.keys** - Traditional RSA keys (backward compatibility)
   - Location: `${server.output.dir}/resources/security/ltpa.keys`
   - Format: Encrypted properties file
   - Contains: RSA-2048 private/public keys

2. **ltpa-hybrid.p12** - Hybrid keystore with PQC keys
   - Location: `${server.output.dir}/resources/security/ltpa-hybrid.p12`
   - Format: PKCS12 keystore
   - Contains: RSA-2048 + ML-DSA-65 + ML-KEM-768 keys

### Cleanup

All generated files are automatically cleaned up after each test in the `@After` method:
- `ltpa.keys` is deleted
- `ltpa-hybrid.p12` is deleted

## Troubleshooting

### Issue: Tests Skip with "Assumption Failed"

**Cause:** Running Java 26-required tests with Java 17

**Solution:** Use Java 26 for full PQC testing:
```bash
export JAVA_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home
```

### Issue: "ML-DSA not available" Warning

**Cause:** Running with Java 17 or earlier

**Solution:** This is expected behavior. The test `testPQC_FallbackToRSAOnly` specifically tests this scenario.

### Issue: Hybrid Keystore Not Created

**Cause:** Insufficient permissions or invalid path

**Solution:** 
- Check server has write access to `${server.output.dir}/resources/security/`
- Verify directory exists and has correct permissions

### Issue: Token Validation Fails

**Cause:** Clock skew, expired tokens, or signature verification failure

**Solution:**
- Check system time synchronization
- Verify both RSA and ML-DSA signatures are valid
- Check trace logs for specific signature verification errors
- Enable detailed tracing: `*=info:com.ibm.ws.security.token.ltpa*=all`

## Log Messages

### Success Messages

```
CWWKS4105I: LTPA configuration is ready after X seconds.
CWWKS4104A: LTPA keys created in X seconds. LTPA key file: ltpa.keys
[INFO] PQC Runtime Support: Java 26+ detected
[INFO] ML-DSA support available: true
[INFO] ML-KEM support available: true
[INFO] Hybrid keystore created: ltpa-hybrid.p12
[INFO] Generated RSA-2048 + ML-DSA-65 + ML-KEM-768 hybrid keys
```

### Fallback Messages (Java 17)

```
[WARN] ML-DSA not available, falling back to RSA-only mode
[WARN] ML-KEM not available, using AES-GCM encryption
[INFO] PQC Runtime Support: Java 17 detected, using RSA-only mode
```

### Error Messages

```
CWWKS4106E: Unable to create or read LTPA keys
CWWKS4118E: LTPA password not set
LTPA_TOKEN3_FACTORY_NO_HYBRID_KEYS: Hybrid keys not initialized
```

## Security Considerations

1. **Defense-in-Depth:** Both RSA and ML-DSA signatures must be valid for token acceptance
2. **Quantum Readiness:** Implementation is quantum-safe and future-proof
3. **Backward Compatibility:** PQC tokens maintain RSA signatures for legacy systems
4. **Key Protection:** Hybrid keystore is password-protected with secure file permissions
5. **Algorithm Selection:** ML-DSA-65 + ML-KEM-768 provides NIST Level 3 security (192-bit quantum security)

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [JEP 478: Key Encapsulation Mechanism API](https://openjdk.org/jeps/478)
- [Open Liberty LTPA Documentation](https://openliberty.io/docs/latest/reference/config/ltpa.html)

## Test Coverage Summary

| Test Case | Java 26 | Java 17 | Mode | Coverage |
|-----------|---------|---------|------|----------|
| Basic Token Creation | ✅ | ⏭️ | LITE | Core functionality |
| RSA Fallback | ⏭️ | ✅ | FULL | Backward compatibility |
| ML-DSA Algorithms | ✅ | ⏭️ | FULL | Signature algorithms |
| ML-KEM Algorithms | ✅ | ⏭️ | FULL | Key encapsulation |
| Hybrid Signatures | ✅ | ⏭️ | FULL | Defense-in-depth |
| Token Expiration | ✅ | ⏭️ | FULL | Token lifecycle |
| Keystore Protection | ✅ | ⏭️ | FULL | Security |
| Backward Compatibility | ✅ | ⏭️ | FULL | Migration support |

**Legend:**
- ✅ Test runs
- ⏭️ Test skipped (Assumption failed)

---

**Created with IBM Bob** - PQC LTPA FAT Tests Implementation