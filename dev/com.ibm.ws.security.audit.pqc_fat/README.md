# PQC Audit FAT Module

## Overview

This FAT (Feature Acceptance Test) module provides comprehensive integration testing for Post-Quantum Cryptography (PQC) support in Liberty Audit encryption using ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism).

## Purpose

The FAT tests verify:
1. **PQC Support Detection** - Runtime detection of Java 26+ with PQC capabilities
2. **ML-KEM Key Generation** - Generation of ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key pairs
3. **PQC Encryption/Decryption** - Hybrid encryption using ML-KEM + AES-256
4. **Forward Secrecy** - Multiple encryptions produce different ciphertexts
5. **Backward Compatibility** - Classical AES-256 mode still works
6. **Security** - Wrong keys fail decryption

## Module Structure

```
com.ibm.ws.security.audit.pqc_fat/
├── bnd.bnd                          # Build configuration
├── build.gradle                     # Gradle build script
├── .project                         # Eclipse project file
├── fat/src/                         # FAT test sources
│   └── com/ibm/ws/security/audit/pqc/fat/
│       ├── FATSuite.java           # Test suite
│       └── PQCAuditTests.java      # Main test class
├── test-applications/               # Test web applications
│   └── pqcAuditTest/
│       ├── src/                    # Servlet sources
│       │   └── com/ibm/ws/security/audit/pqc/servlet/
│       │       └── PQCAuditTestServlet.java
│       └── resources/              # Web resources
│           └── WEB-INF/
│               └── web.xml
└── publish/servers/                # Test server configurations
    └── com.ibm.ws.security.audit.pqc.fat/
        ├── server.xml              # Liberty server config
        ├── bootstrap.properties    # Bootstrap properties
        └── .gitignore             # Git ignore rules
```

## Test Cases

### 1. testPQCSupport
- **Purpose**: Verify PQC runtime support detection
- **Expected**: Returns PQC_SUPPORTED on Java 26+, PQC_NOT_SUPPORTED otherwise

### 2. testMLKEM512KeyGeneration
- **Purpose**: Test ML-KEM-512 key pair generation
- **Expected**: Successfully generates 512-bit security level keys

### 3. testMLKEM768KeyGeneration
- **Purpose**: Test ML-KEM-768 key pair generation (recommended)
- **Expected**: Successfully generates 768-bit security level keys

### 4. testMLKEM1024KeyGeneration
- **Purpose**: Test ML-KEM-1024 key pair generation (highest security)
- **Expected**: Successfully generates 1024-bit security level keys

### 5. testPQCEncryptDecrypt
- **Purpose**: Verify end-to-end PQC encryption and decryption
- **Expected**: Data encrypts and decrypts correctly, matching original

### 6. testForwardSecrecy
- **Purpose**: Verify forward secrecy property
- **Expected**: Same plaintext produces different ciphertexts, both decrypt correctly

### 7. testClassicalMode
- **Purpose**: Verify backward compatibility with classical AES-256
- **Expected**: Classical mode encryption/decryption works without PQC

### 8. testWrongKeyFailsDecryption
- **Purpose**: Verify security - wrong key cannot decrypt
- **Expected**: Decryption fails or produces corrupted data

## Running the Tests

### Prerequisites
- Java 26+ for PQC tests to execute (tests skip gracefully on Java < 26)
- Gradle build system
- Liberty test framework

### Build and Run
```bash
cd dev
./gradlew com.ibm.ws.security.audit.pqc_fat:buildandrun
```

### Run Specific Test
```bash
cd dev
./gradlew com.ibm.ws.security.audit.pqc_fat:test --tests PQCAuditTests.testPQCEncryptDecrypt
```

## Test Servlet Endpoints

The `PQCAuditTestServlet` provides the following test endpoints:

- `?test=pqcSupport` - Check PQC support
- `?test=generateKeys&algorithm=ML_KEM_768` - Generate ML-KEM keys
- `?test=encryptDecrypt&algorithm=ML_KEM_768` - Test encryption/decryption
- `?test=forwardSecrecy&algorithm=ML_KEM_768` - Test forward secrecy
- `?test=classicalMode` - Test classical AES-256 mode
- `?test=wrongKey&algorithm=ML_KEM_768` - Test wrong key failure

## Implementation Details

### Hybrid Encryption Process
1. **ML-KEM Encapsulation**: Generate random shared secret using recipient's public key
2. **AES-256 Encryption**: Encrypt data using shared secret
3. **Packaging**: Combine encapsulation + encrypted data with length prefix

### Key Algorithms
- **ML-KEM-512**: NIST security level 1 (128-bit equivalent)
- **ML-KEM-768**: NIST security level 3 (192-bit equivalent) - **Recommended**
- **ML-KEM-1024**: NIST security level 5 (256-bit equivalent)

## Dependencies

- `com.ibm.ws.security.audit.source` - Audit encryption implementation
- `com.ibm.ws.security.token.ltpa` - PQC runtime support utilities
- `com.ibm.ws.security.fat.common` - FAT test framework

## Notes

- Tests automatically skip on Java < 26 with informative messages
- PQC functionality requires Java 26+ runtime
- Classical mode works on all Java versions (backward compatible)
- FAT tests run in full Liberty server environment (unlike unit tests)

## Related Documentation

- [AuditKeyEncryptor Implementation](../com.ibm.ws.security.audit.source/src/com/ibm/ws/security/audit/encryption/AuditKeyEncryptor.java)
- [LTPA PQC FAT Tests](../com.ibm.ws.security.token.ltpa.pqc_fat/) - Similar test pattern
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Standard

---
*Created with IBM Bob - AI-assisted development*