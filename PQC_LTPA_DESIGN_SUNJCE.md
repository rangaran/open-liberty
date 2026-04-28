# Post-Quantum Cryptography (PQC) LTPA Token Design
## Using Java 26 SunJCE Provider

## Executive Summary

This document specifies the design for implementing Post-Quantum Cryptography (PQC) support in IBM Open Liberty's LTPA tokens using **Java 26's native SunJCE provider** with ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) support.

**Status**: Design Phase  
**Target**: Open Liberty 26.0.0.x+  
**Branch**: bob-pqc-ltpa  
**Java Version**: Java 26 (JEP 478: Quantum-Resistant Module-Lattice-Based Key Encapsulation Mechanism)  
**Crypto Provider**: SunJCE (built-in, no external dependencies)

---

## 1. Java 26 PQC Support Overview

### 1.1 JEP 478: ML-KEM Support

Java 26 introduces **ML-KEM** (FIPS 203) support in the SunJCE provider:

| Algorithm | Security Level | Key Size | Ciphertext Size | Use Case |
|-----------|----------------|----------|-----------------|----------|
| **ML-KEM-512** | NIST Level 1 (≈AES-128) | ~800 bytes | ~768 bytes | Low security, faster |
| **ML-KEM-768** | NIST Level 3 (≈AES-192) | ~1184 bytes | ~1088 bytes | **Recommended** |
| **ML-KEM-1024** | NIST Level 5 (≈AES-256) | ~1568 bytes | ~1568 bytes | High security, slower |

### 1.2 Available Java APIs

```java
// Key Generation
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "SunJCE");
kpg.initialize(MLKEMParameterSpec.ml_kem_768);
KeyPair keyPair = kpg.generateKeyPair();

// Key Encapsulation (Encryption side)
KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "SunJCE");
kg.init(new KEMGenerateSpec(publicKey, "AES"));
SecretKeyWithEncapsulation skwe = (SecretKeyWithEncapsulation) kg.generateKey();
byte[] encapsulation = skwe.getEncapsulation();
SecretKey sharedSecret = skwe.getSecretKey();

// Key Decapsulation (Decryption side)
KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "SunJCE");
kg.init(new KEMExtractSpec(privateKey, encapsulation, "AES"));
SecretKey sharedSecret = kg.generateKey();
```

### 1.3 Limitations

**Note**: Java 26 currently provides **ML-KEM only** (key encapsulation for encryption). For digital signatures, we have two options:

1. **Continue using RSA-2048** for signatures (hybrid approach)
2. **Wait for ML-DSA** (Dilithium) support in future Java versions
3. **Use external library** for ML-DSA (contradicts "no Bouncy Castle" requirement)

**Recommendation**: Use **hybrid approach** - RSA-2048 for signatures + ML-KEM-768 for encryption.

---

## 2. Threat Model & Requirements

### 2.1 Quantum Computing Threat

**Harvest Now, Decrypt Later (HNDL) Attack**:
- Adversaries capture encrypted LTPA tokens today
- Store them until quantum computers become available  
- Decrypt historical tokens using Shor's algorithm

**Current Vulnerabilities**:
1. **3DES Encryption** (168-bit): Grover's algorithm reduces to 84-bit security
2. **RSA-2048 Signatures**: Shor's algorithm can forge signatures (but less critical for HNDL)

### 2.2 Security Requirements

| Requirement | Description | Priority | Status |
|-------------|-------------|----------|--------|
| **PQC Encryption** | Use ML-KEM for token encryption | P0 | ✅ Java 26 |
| **Hybrid Mode** | Support classical + PQC (transition) | P0 | Design |
| **Backward Compatibility** | Existing tokens must work | P0 | Design |
| **Performance** | Token operations < 100ms overhead | P1 | TBD |
| **Key Management** | Secure PQC key generation/storage | P0 | Design |
| **No External Deps** | Use only Java built-in crypto | P0 | ✅ SunJCE |

---

## 3. LTPA Token Architecture

### 3.1 Current LTPA2 Token Structure

```
Token = AES-CBC(userData % expiration % RSA-Signature, 3DES-Key)
```

**Components**:
1. **userData**: User attributes (username, realm, groups)
2. **expiration**: Token expiration timestamp
3. **RSA-Signature**: ISO9796-2 signature over userData
4. **3DES-Key**: Shared secret for encryption (168-bit)

### 3.2 Proposed PQC-LTPA Token Structure (Hybrid)

```
Token = AES-256-GCM(
    userData % expiration % RSA-Signature % TokenVersion,
    DerivedKey
)

DerivedKey = HKDF(SharedSecret-from-ML-KEM)
Encapsulation = ML-KEM-768.Encapsulate(RecipientPublicKey)

Final Token = Encapsulation || Encrypted-Token
```

**Key Changes**:
1. **Encryption**: ML-KEM-768 key encapsulation → AES-256-GCM (replaces 3DES)
2. **Signature**: Keep RSA-2048 (quantum-vulnerable but acceptable for now)
3. **Token Version**: Add version field (3 = hybrid)
4. **Format**: Prepend ML-KEM encapsulation to encrypted token

### 3.3 Token Format Versioning

| Version | Format | Signature | Encryption | Quantum-Safe | Status |
|---------|--------|-----------|------------|--------------|--------|
| **1** | LTPA | RSA-1024 | 3DES | ❌ No | Deprecated |
| **2** | LTPA2 | RSA-2048 | 3DES/AES-CBC | ❌ No | Current |
| **3** | LTPA-PQC | RSA-2048 | ML-KEM-768 + AES-256-GCM | ✅ Encryption only | **New** |
| **4** | LTPA-Full-PQC | ML-DSA-65 | ML-KEM-768 + AES-256-GCM | ✅ Full | Future |

---

## 4. Key Management

### 4.1 PQC Key Structure

```java
public class LTPAPQCKeys {
    // Classical keys (existing - for signatures)
    private byte[] rsaPrivateKey;       // RSA-2048 private key
    private byte[] rsaPublicKey;        // RSA-2048 public key
    
    // PQC keys (new - for encryption)
    private PrivateKey mlkemPrivateKey; // ML-KEM-768 private key (~1.2KB)
    private PublicKey mlkemPublicKey;   // ML-KEM-768 public key (~1.2KB)
    
    // Metadata
    private MLKEMParameterSpec mlkemParams; // ML_KEM_512, ML_KEM_768, ML_KEM_1024
    private int tokenVersion;                // 3 = hybrid PQC
    private boolean pqcEnabled;              // true = use PQC encryption
}
```

### 4.2 Keystore Storage

**PKCS12 Keystore Structure** (ltpa_pqc.p12):

| Alias | Type | Content | Size |
|-------|------|---------|------|
| `ltpaRsaPrivateKey` | PrivateKey | RSA-2048 private | ~1.2 KB |
| `ltpaRsaPublicKey` | Certificate | RSA-2048 public | ~1 KB |
| `ltpaMlkemPrivateKey` | PrivateKey | ML-KEM-768 private | ~1.2 KB |
| `ltpaMlkemPublicKey` | Certificate (self-signed) | ML-KEM-768 public | ~1.2 KB |

**Note**: Java 26 KeyStore supports ML-KEM keys natively - no custom encoding needed!

### 4.3 Key Generation

```java
public class LTPAPQCKeyGenerator {
    
    public static LTPAPQCKeys generateHybridKeys() throws Exception {
        // 1. Generate RSA keys (existing - for signatures)
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();
        
        // 2. Generate ML-KEM keys (new - for encryption)
        KeyPairGenerator kemGen = KeyPairGenerator.getInstance("ML-KEM", "SunJCE");
        kemGen.initialize(MLKEMParameterSpec.ml_kem_768);
        KeyPair kemKeyPair = kemGen.generateKeyPair();
        
        return new LTPAPQCKeys(
            rsaKeyPair.getPrivate(),
            rsaKeyPair.getPublic(),
            kemKeyPair.getPrivate(),
            kemKeyPair.getPublic(),
            MLKEMParameterSpec.ml_kem_768
        );
    }
}
```

---

## 5. Cryptographic Operations

### 5.1 Signature Generation (RSA - Unchanged)

```java
public byte[] signToken(byte[] userData) throws Exception {
    // Use existing RSA signature (ISO9796-2)
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initSign(rsaPrivateKey);
    sig.update(userData);
    return sig.sign();
}
```

### 5.2 Signature Verification (RSA - Unchanged)

```java
public boolean verifyToken(byte[] userData, byte[] signature) throws Exception {
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initVerify(rsaPublicKey);
    sig.update(userData);
    return sig.verify(signature);
}
```

### 5.3 PQC Encryption (ML-KEM + AES-256-GCM)

```java
public byte[] encryptTokenPQC(byte[] tokenData, PublicKey recipientMlkemPublicKey) 
        throws Exception {
    
    // 1. Generate shared secret using ML-KEM encapsulation
    KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "SunJCE");
    kg.init(new KEMGenerateSpec(recipientMlkemPublicKey, "AES"));
    SecretKeyWithEncapsulation skwe = (SecretKeyWithEncapsulation) kg.generateKey();
    
    byte[] encapsulation = skwe.getEncapsulation();  // ~1088 bytes for ML-KEM-768
    SecretKey sharedSecret = skwe.getSecretKey();    // AES key derived from KEM
    
    // 2. Derive AES-256 key using HKDF
    SecretKey aesKey = deriveAESKey(sharedSecret);
    
    // 3. Encrypt token data with AES-256-GCM
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, generateIV());
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
    byte[] encryptedData = cipher.doFinal(tokenData);
    
    // 4. Combine: encapsulation || IV || encrypted data
    return concatenate(encapsulation, gcmSpec.getIV(), encryptedData);
}

private SecretKey deriveAESKey(SecretKey sharedSecret) throws Exception {
    // Use HKDF to derive AES-256 key from shared secret
    Mac hkdf = Mac.getInstance("HmacSHA256");
    hkdf.init(sharedSecret);
    byte[] derivedKey = hkdf.doFinal("LTPA-PQC-v3".getBytes());
    return new SecretKeySpec(derivedKey, 0, 32, "AES");
}
```

### 5.4 PQC Decryption (ML-KEM + AES-256-GCM)

```java
public byte[] decryptTokenPQC(byte[] encryptedToken, PrivateKey mlkemPrivateKey) 
        throws Exception {
    
    // 1. Extract components
    int encapSize = 1088; // ML-KEM-768 encapsulation size
    int ivSize = 12;      // GCM IV size
    
    byte[] encapsulation = Arrays.copyOfRange(encryptedToken, 0, encapSize);
    byte[] iv = Arrays.copyOfRange(encryptedToken, encapSize, encapSize + ivSize);
    byte[] encryptedData = Arrays.copyOfRange(encryptedToken, encapSize + ivSize, 
                                               encryptedToken.length);
    
    // 2. Decapsulate shared secret using ML-KEM
    KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "SunJCE");
    kg.init(new KEMExtractSpec(mlkemPrivateKey, encapsulation, "AES"));
    SecretKey sharedSecret = kg.generateKey();
    
    // 3. Derive AES-256 key
    SecretKey aesKey = deriveAESKey(sharedSecret);
    
    // 4. Decrypt with AES-256-GCM
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
    return cipher.doFinal(encryptedData);
}
```

---

## 6. Configuration

### 6.1 Server Configuration

```xml
<ltpa keysFileName="ltpaPQCKeyStore"
      expiration="120m"
      pqcEnabled="true"
      pqcEncryptionAlgorithm="ML-KEM-768"
      pqcTransitionPeriod="90d">
    
    <!-- Validation keys can be classical or PQC -->
    <validationKeys fileName="ltpaValidationKeyStore" />
</ltpa>

<keyStore id="ltpaPQCKeyStore"
          location="${server.output.dir}/resources/security/ltpa_pqc.p12"
          type="PKCS12"
          password="{xor}Lz4sLCgwLTs=" />
```

### 6.2 Configuration Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `pqcEnabled` | boolean | false | Enable PQC encryption (ML-KEM) |
| `pqcEncryptionAlgorithm` | enum | ML-KEM-768 | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` |
| `pqcTransitionPeriod` | duration | 90d | Accept both classical and PQC tokens |
| `pqcFallbackToClassical` | boolean | true | Fallback to 3DES if PQC fails |

---

## 7. Migration Strategy

### 7.1 Phase 1: Preparation (Week 1)

**Goal**: Infrastructure ready, no behavior change

1. Update environment rules to require Java 26
2. Add PQC key generation utilities
3. Extend keystore manager for ML-KEM keys
4. Add configuration schema
5. **No token format changes yet**

### 7.2 Phase 2: PQC Encryption (Weeks 2-4)

**Goal**: Generate PQC-encrypted tokens, accept classical tokens

1. Generate LTPA tokens with ML-KEM encryption (version 3)
2. Accept both classical (v2) and PQC (v3) tokens
3. Gradual rollout across cluster
4. Monitor performance impact

**Configuration**:
```xml
<ltpa pqcEnabled="true" pqcTransitionPeriod="90d" />
```

### 7.3 Phase 3: PQC-Only Mode (Future)

**Goal**: Reject classical tokens

1. After transition period, reject version 2 tokens
2. Only accept PQC-encrypted tokens (version 3)
3. Remove 3DES encryption code

**Configuration**:
```xml
<ltpa pqcEnabled="true" pqcTransitionPeriod="0d" />
```

---

## 8. Performance Considerations

### 8.1 Expected Performance Impact

| Operation | Classical (RSA+3DES) | PQC (RSA+ML-KEM-768) | Overhead |
|-----------|----------------------|----------------------|----------|
| **Key Generation** | ~500ms | ~600ms | +20% |
| **Sign** | ~5ms | ~5ms | 0% (unchanged) |
| **Verify** | ~1ms | ~1ms | 0% (unchanged) |
| **Encrypt** | ~2ms | ~4ms | +100% |
| **Decrypt** | ~2ms | ~4ms | +100% |
| **Token Size** | ~500 bytes | ~2KB | +300% |

**Note**: ML-KEM operations are faster than Bouncy Castle implementations due to native Java optimization.

### 8.2 Optimization Strategies

1. **Key Caching**: Cache ML-KEM keys in memory (already done for RSA keys)
2. **Connection Pooling**: Reuse cipher instances
3. **Hardware Acceleration**: Java 26 uses AVX2/AVX-512 when available
4. **Token Compression**: Compress userData before encryption

---

## 9. Security Analysis

### 9.1 Security Levels

| Component | Classical | PQC (Hybrid) | Quantum Resistance |
|-----------|-----------|--------------|-------------------|
| **Signature** | RSA-2048 | RSA-2048 | ❌ No (but acceptable) |
| **Encryption** | 3DES | ML-KEM-768 + AES-256-GCM | ✅ Yes |
| **Overall** | ❌ Vulnerable | ⚠️ Partial | Encryption protected |

### 9.2 Attack Scenarios

| Attack | Classical | PQC (Hybrid) | Mitigation |
|--------|-----------|--------------|------------|
| **Quantum Decryption (HNDL)** | ❌ Vulnerable | ✅ Protected | ML-KEM-768 encryption |
| **Quantum Signature Forgery** | ❌ Vulnerable | ❌ Vulnerable | Wait for ML-DSA in Java |
| **Classical Attacks** | ✅ Protected | ✅ Protected | Both classical and PQC secure |
| **Downgrade Attack** | N/A | ✅ Protected | Token version enforced |

**Risk Assessment**: 
- **High Priority**: Protect encryption (HNDL attack) ✅ **Solved with ML-KEM**
- **Medium Priority**: Protect signatures (less critical for HNDL) ⏳ **Wait for Java ML-DSA support**

---

## 10. Implementation Plan

### 10.1 File Structure

```
dev/com.ibm.ws.security.token.ltpa/
├── src/com/ibm/ws/security/token/ltpa/
│   ├── pqc/
│   │   ├── LTPAPQCKeys.java              (NEW)
│   │   ├── LTPAPQCKeyGenerator.java      (NEW)
│   │   ├── LTPAPQCCrypto.java            (NEW)
│   │   ├── LTPAPQCKeystoreManager.java   (NEW)
│   │   └── MLKEMAlgorithmType.java       (NEW)
│   ├── internal/
│   │   ├── LTPAToken3.java               (NEW - PQC hybrid token)
│   │   └── LTPATokenFactory.java         (MODIFIED - version routing)
│   └── LTPAConfiguration.java            (MODIFIED - PQC config)
└── test/com/ibm/ws/security/token/ltpa/
    └── pqc/
        ├── LTPAPQCKeyGeneratorTest.java  (NEW)
        ├── LTPAPQCCryptoTest.java        (NEW)
        └── LTPAToken3Test.java           (NEW)
```

### 10.2 Dependencies

**Update bnd.bnd** (NO external dependencies needed!):
```properties
# No changes needed - Java 26 SunJCE provider is built-in
```

**Update environment rules**:
```markdown
# .bob/rules/environment.md

## Java Environment

### Required Java Installations

Bob MUST use Java 26 for PQC LTPA development:

```bash
export JAVA_HOME=/Users/utle/java/OpenJDK/jdk-26+35/Contents/Home
export JAVA_21_HOME=/Users/utle/java/OpenJDK/jdk-21.0.4+7/Contents/Home
```
```

---

## 11. Testing Strategy

### 11.1 Unit Tests

1. **PQC Key Generation**
   - Generate ML-KEM-768 key pairs
   - Validate key sizes and formats
   - Test KeyStore storage/retrieval

2. **Encryption Operations**
   - Encrypt with ML-KEM-768
   - Decrypt with ML-KEM-768
   - Test encapsulation/decapsulation

3. **Token Operations**
   - Create PQC LTPA tokens (version 3)
   - Validate PQC tokens
   - Version compatibility (v2 vs v3)

### 11.2 FAT Tests

1. **End-to-End Authentication**
   - User login with PQC tokens
   - Token propagation across servers
   - Token validation

2. **Migration Scenarios**
   - Classical → PQC migration
   - Rollback scenarios
   - Mixed cluster (some PQC, some classical)

3. **Performance Tests**
   - Token generation throughput
   - Token validation latency
   - Memory usage

---

## 12. Risks & Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Java 26 not production-ready** | High | Medium | Use Java 26 EA, plan for GA release |
| **Performance degradation** | Medium | Low | Optimize hot paths, cache keys |
| **Token size increase** | Medium | High | Compression, monitor network impact |
| **ML-DSA not available** | Medium | High | Accept RSA signatures for now |
| **Key management complexity** | Medium | Medium | Clear documentation, automated tools |

---

## 13. Success Criteria

✅ **Functional**:
- Generate and validate PQC LTPA tokens (version 3)
- Backward compatible with classical tokens (version 2)
- Support ML-KEM-512, ML-KEM-768, ML-KEM-1024

✅ **Performance**:
- Token operations < 100ms overhead
- No memory leaks
- Throughput > 1000 tokens/sec

✅ **Security**:
- Quantum-resistant encryption (ML-KEM-768)
- No external crypto dependencies
- Pass security review

✅ **Quality**:
- >80% test coverage
- All FAT tests passing
- Documentation complete

---

## 14. Timeline

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| **Phase 1: Design** | 1 week | Design document, security review |
| **Phase 2: Core Implementation** | 2 weeks | PQC key generation, crypto operations |
| **Phase 3: Token Integration** | 2 weeks | LTPAToken3, configuration, keystore |
| **Phase 4: Testing** | 2 weeks | Unit tests, FAT tests, performance tests |
| **Phase 5: Review & Documentation** | 2 weeks | Code review, user documentation |
| **Total** | **9 weeks** | Production-ready PQC LTPA |

---

## 15. References

1. **Java Enhancement Proposals**:
   - JEP 478: Quantum-Resistant Module-Lattice-Based Key Encapsulation Mechanism
   - https://openjdk.org/jeps/478

2. **NIST PQC Standards**:
   - FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
   - https://csrc.nist.gov/pubs/fips/203/final

3. **Java Cryptography Architecture**:
   - Java Security Standard Algorithm Names
   - https://docs.oracle.com/en/java/javase/26/docs/specs/security/standard-names.html

---

**Document Version**: 1.0  
**Last Updated**: 2026-04-28  
**Author**: IBM Bob (AI Assistant)  
**Status**: Design Phase - Ready for Implementation  
**Crypto Provider**: Java 26 SunJCE (built-in, no external dependencies)