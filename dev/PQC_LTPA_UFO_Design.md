# Upcoming Feature Overview (UFO): PQC Support for LTPA Tokens

**Feature Name**: Post-Quantum Cryptography (PQC) Support for LTPA  
**Issue**: [#35556](https://github.ibm.com/websphere/WS-CD-Open/issues/35556)  
**Feature Owner**: [To be assigned]  
**Target Release**: TBD  
**Feature Size**: 2XL (16-20 person weeks)

---

## 1. Executive Summary

### 1.1 Business Value
Post-Quantum Cryptography (PQC) support in LTPA tokens protects IBM WebSphere Liberty customers against future quantum computing threats. This feature enables:
- **Future-proof security**: Protection against quantum attacks on RSA signatures
- **Compliance readiness**: Meet emerging PQC regulatory requirements
- **Competitive advantage**: Early adoption of NIST-standardized PQC algorithms
- **Customer confidence**: Demonstrate IBM's commitment to long-term security

### 1.2 Technical Summary
Add ML-DSA (FIPS 204) digital signature support to Liberty's LTPA token implementation while maintaining backward compatibility with existing RSA-based tokens. Support hybrid mode for smooth migration.

---

## 2. Feature Description

### 2.1 Current State
Liberty's LTPA tokens currently use:
- **RSA signatures** (2048-bit) with ISO9796 padding
- **AES-CBC** encryption for token data
- **SHA-256** hashing

These classical algorithms are vulnerable to Shor's algorithm on quantum computers.

### 2.2 Proposed Solution
Implement PQC support with three operational modes:

| Mode | Description | Use Case |
|------|-------------|----------|
| **Classical** | RSA only (current behavior) | Default, existing deployments |
| **PQC** | ML-DSA only | Pure PQC environments |
| **Hybrid** | Both RSA + ML-DSA | Migration period, defense-in-depth |

### 2.3 Key Features
1. **ML-DSA Digital Signatures** (FIPS 204)
   - ML-DSA-44 (128-bit security)
   - ML-DSA-65 (192-bit security) - **Recommended**
   - ML-DSA-87 (256-bit security)

2. **Hybrid Cryptography**
   - Dual signatures in tokens
   - Validates with either signature
   - Smooth migration path

3. **Backward Compatibility**
   - Existing LTPA v2.0 tokens remain valid
   - New servers validate old tokens
   - Configurable per-server

4. **Enhanced Encryption**
   - Upgrade from AES-CBC to AES-256-GCM
   - Authenticated encryption
   - Better performance

---

## 3. Architecture & Design

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LTPA Token v3.0                          │
├─────────────────────────────────────────────────────────────┤
│  Header: version=3, mode=hybrid                             │
├─────────────────────────────────────────────────────────────┤
│  Encrypted Payload (AES-256-GCM):                           │
│    - User Data (unique ID, attributes)                      │
│    - Expiration timestamp                                   │
│    - RSA Signature (2048-bit)                               │
│    - ML-DSA Signature (ML-DSA-65)                           │
├─────────────────────────────────────────────────────────────┤
│  Authentication Tag (GCM)                                   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Component Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   LTPAConfiguration                          │
│  - cryptoMode: classical|pqc|hybrid                          │
│  - pqcAlgorithm: ML-DSA-44|ML-DSA-65|ML-DSA-87              │
│  - enablePQC: boolean                                        │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│              LTPAKeyInfoManager                              │
│  - Load RSA keys (existing)                                  │
│  - Load ML-DSA keys (new)                                    │
│  - Manage validation keys                                    │
│  - Handle key rotation                                       │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│              LTPAToken2Factory                               │
│  - createToken() - with PQC support                          │
│  - validateTokenBytes() - hybrid validation                  │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│                 LTPAToken2                                   │
│  Token Creation:                                             │
│    - sign() - RSA signature                                  │
│    - signPQC() - ML-DSA signature (new)                      │
│    - encrypt() - AES-256-GCM (upgraded)                      │
│                                                              │
│  Token Validation:                                           │
│    - verify() - RSA verification                             │
│    - verifyPQC() - ML-DSA verification (new)                 │
│    - decrypt() - AES-256-GCM (upgraded)                      │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Key File Format (v3.0)

```properties
# IBM WebSphere Application Server LTPA key file v3.0
com.ibm.websphere.ltpa.version=3.0
com.ibm.websphere.ltpa.cryptoMode=hybrid
com.ibm.websphere.CreationDate=2026-04-22T01:00:00Z
com.ibm.websphere.CreationHost=liberty-server
com.ibm.websphere.ltpa.Realm=DefaultRealm

# Classical RSA Keys (existing)
com.ibm.websphere.ltpa.3DESKey=<base64-encoded-aes-key>
com.ibm.websphere.ltpa.PrivateKey=<base64-encoded-rsa-private>
com.ibm.websphere.ltpa.PublicKey=<base64-encoded-rsa-public>

# PQC ML-DSA Keys (new)
com.ibm.websphere.ltpa.MLDSAPrivateKey=<base64-encoded-mldsa-private>
com.ibm.websphere.ltpa.MLDSAPublicKey=<base64-encoded-mldsa-public>
com.ibm.websphere.ltpa.MLDSAAlgorithm=ML-DSA-65
```

### 3.4 Configuration (server.xml)

```xml
<server>
    <featureManager>
        <feature>appSecurity-5.0</feature>
        <feature>transportSecurity-1.0</feature>
    </featureManager>
    
    <!-- PQC-enabled LTPA Configuration -->
    <ltpa 
        keysFileName="${server.config.dir}/resources/security/ltpa.keys"
        keysPassword="{xor}Lz4sLCgwLTs="
        expiration="120"
        cryptoMode="hybrid"
        pqcAlgorithm="ML-DSA-65"
        enablePQC="true"
        monitorInterval="5m"
        updateTrigger="polled">
        
        <!-- Optional: Validation keys for key rotation -->
        <validationKeys 
            fileName="${server.config.dir}/resources/security/ltpa-old.keys"
            password="{xor}Lz4sLCgwLTs="
            validUntilDate="2027-01-01T00:00:00Z"/>
    </ltpa>
</server>
```

---

## 4. User Experience

### 4.1 Administrator Experience

**Scenario 1: Enable PQC on New Server**
```bash
# 1. Update server.xml
<ltpa enablePQC="true" cryptoMode="hybrid" pqcAlgorithm="ML-DSA-65"/>

# 2. Restart server (generates new PQC keys automatically)
./server start myServer

# 3. Verify in logs
CWWKS4105I: LTPA configuration is ready after 2.5 seconds.
CWWKS4110I: PQC support enabled with ML-DSA-65 algorithm.
```

**Scenario 2: Migrate Existing Server to PQC**
```bash
# 1. Backup existing keys
cp ltpa.keys ltpa.keys.backup

# 2. Update configuration to hybrid mode
<ltpa cryptoMode="hybrid" enablePQC="true"/>

# 3. Add old keys as validation keys
<validationKeys fileName="ltpa.keys.backup" .../>

# 4. Restart - new tokens use PQC, old tokens still valid
```

### 4.2 Developer Experience

**No code changes required** - PQC is transparent to applications:
```java
// Existing code continues to work
Subject subject = WSSubject.getRunAsSubject();
Set<SingleSignonToken> tokens = subject.getPrivateCredentials(SingleSignonToken.class);
// Token now contains PQC signatures (if enabled)
```

---

## 5. Dependencies

### 5.1 IBM Java/Semeru Requirements

| Platform | Java Version | Provider | Availability |
|----------|--------------|----------|--------------|
| Distributed | Java 17+ | OpenJCEPlus | July 2025 |
| Distributed | Java 8 | IBMJCEPlus | July 2025 |
| z/OS | Java 17+ | IBMJCECCA | June 2025 |
| z/OS | Java 8 | IBMJCEPlus | Q4 2025 |

### 5.2 Liberty Feature Dependencies
- `appSecurity-5.0` or higher
- `transportSecurity-1.0` (for TLS 1.3)
- Updated `com.ibm.ws.crypto.ltpakeyutil` bundle

### 5.3 External Dependencies
- FIPS 140-3 certified cryptographic modules
- ML-DSA implementation (FIPS 204)

---

## 6. Performance Impact

### 6.1 Expected Performance Characteristics

| Operation | Classical (RSA) | PQC (ML-DSA-65) | Hybrid | Impact |
|-----------|-----------------|-----------------|--------|--------|
| Key Generation | ~500ms | ~50ms | ~550ms | +10% |
| Token Creation | ~2ms | ~3ms | ~5ms | +150% |
| Token Validation | ~1ms | ~2ms | ~3ms | +200% |
| Token Size | 512 bytes | 768 bytes | 1024 bytes | +100% |

### 6.2 Mitigation Strategies
- **Caching**: Cache validated tokens to reduce verification overhead
- **Async Key Generation**: Generate keys asynchronously during startup
- **Optimized Algorithms**: Use ML-DSA-65 (balanced security/performance)
- **Connection Pooling**: Reuse authenticated connections

### 6.3 Performance Testing Plan
- Benchmark token operations (create, validate, encrypt, decrypt)
- Load testing with 1000+ concurrent users
- Memory profiling for token caching
- Network bandwidth impact analysis

---

## 7. Security Considerations

### 7.1 Threat Model

| Threat | Classical | PQC | Hybrid | Mitigation |
|--------|-----------|-----|--------|------------|
| Quantum Attack | ❌ Vulnerable | ✅ Protected | ✅ Protected | Use PQC mode |
| Classical Attack | ✅ Protected | ✅ Protected | ✅ Protected | Both secure |
| Implementation Bug | ⚠️ Single point | ⚠️ Single point | ✅ Redundant | Hybrid mode |
| Key Compromise | ❌ Total failure | ❌ Total failure | ⚠️ Partial | Key rotation |

### 7.2 Security Requirements (MUST)
1. ✅ Use TLS 1.3 for all PQC token transmission
2. ✅ Validate all PQC keys meet FIPS 204 requirements
3. ✅ Implement constant-time operations (prevent timing attacks)
4. ✅ Use secure random number generation (IBM Java providers)
5. ✅ Never log or expose PQC private keys
6. ✅ Implement proper key rotation mechanisms
7. ✅ Encrypt keys at rest with AES-256
8. ✅ Use authenticated encryption (AES-GCM)

### 7.3 Compliance
- **FIPS 140-3**: Use certified cryptographic modules
- **NIST PQC**: Follow FIPS 204 (ML-DSA) standard
- **IBM Security Standards**: Meet all IBM security policies

---

## 8. Testing Strategy

### 8.1 Unit Tests
- PQC key generation and loading
- Token creation with ML-DSA signatures
- Token validation (classical, PQC, hybrid)
- Encryption/decryption with AES-GCM
- Configuration parsing and validation

### 8.2 FAT Tests
- **Interoperability**: Token exchange between servers
- **Migration**: Classical → Hybrid → PQC transition
- **Key Rotation**: Validation keys with PQC
- **Performance**: Benchmark token operations
- **Security**: Invalid signature detection
- **FIPS Mode**: Compatibility testing

### 8.3 Security Testing
- Vulnerability scanning (Mend)
- Penetration testing
- Cryptographic validation
- Side-channel attack resistance

---

## 9. Migration & Rollout

### 9.1 Migration Path

```
Phase 1: Preparation (Week 1-2)
├── Backup existing LTPA keys
├── Update to Liberty version with PQC support
├── Verify IBM Java PQC provider availability
└── Test in non-production environment

Phase 2: Hybrid Mode (Week 3-4)
├── Enable hybrid mode on servers
├── Monitor token validation success rate
├── Verify old tokens still work
└── Generate new PQC-enabled tokens

Phase 3: PQC Only (Week 5+)
├── Switch to PQC-only mode
├── Remove RSA validation keys
├── Monitor for any issues
└── Complete migration
```

### 9.2 Rollback Plan
1. Switch back to classical mode in server.xml
2. Restart servers
3. Old RSA tokens immediately valid again
4. No data loss or service interruption

---

## 10. Documentation Requirements

### 10.1 User Documentation
- [ ] Configuration guide for PQC LTPA
- [ ] Migration guide (Classical → PQC)
- [ ] Troubleshooting guide
- [ ] Performance tuning guide
- [ ] Security best practices

### 10.2 Developer Documentation
- [ ] API documentation (if any new APIs)
- [ ] Architecture documentation
- [ ] Code examples
- [ ] Integration guide

### 10.3 Operations Documentation
- [ ] Monitoring and alerting guide
- [ ] Key rotation procedures
- [ ] Backup and recovery procedures
- [ ] Incident response playbook

---

## 11. Risks & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| PQC provider unavailable | Medium | High | Graceful fallback, clear error messages |
| Performance degradation | High | Medium | Benchmark early, optimize, document |
| Interoperability issues | Medium | High | Extensive testing with tWAS |
| Key size too large | Low | Low | Use ML-DSA-65 (balanced) |
| Implementation bugs | Medium | High | Code review, security audit, extensive testing |
| Customer adoption slow | Medium | Low | Clear documentation, migration tools |

---

## 12. Success Criteria

### 12.1 Functional
- ✅ PQC tokens can be created and validated
- ✅ Hybrid mode works correctly
- ✅ Backward compatibility maintained
- ✅ Key rotation works with PQC
- ✅ All configuration options functional

### 12.2 Non-Functional
- ✅ Performance impact < 20% for token operations
- ✅ Token size increase < 100%
- ✅ Zero critical security vulnerabilities
- ✅ All FAT tests pass
- ✅ Documentation complete

### 12.3 Process
- ✅ All focal point approvals obtained
- ✅ Legal clearance for dependencies
- ✅ Translation complete
- ✅ UFO approved by Chief Architect

---

## 13. Timeline & Milestones

| Milestone | Week | Deliverable |
|-----------|------|-------------|
| UFO Approval | 3 | This document approved |
| Design Complete | 3 | Technical specs finalized |
| Phase 1 Complete | 6 | Key generation implemented |
| Phase 2 Complete | 10 | Token creation/validation done |
| Phase 3 Complete | 14 | All testing complete |
| Documentation Complete | 16 | All docs published |
| Focal Approvals | 17 | All approvals obtained |
| **Feature Complete** | **17** | **Ready for GA** |

---

## 14. Open Questions

1. **Q**: Should we support ML-KEM for key encapsulation?  
   **A**: Not in initial release; focus on ML-DSA for signatures

2. **Q**: What's the default crypto mode?  
   **A**: Classical (no breaking changes)

3. **Q**: Support for other PQC algorithms (e.g., Falcon)?  
   **A**: No; ML-DSA is NIST-standardized and IBM-supported

4. **Q**: Interoperability with tWAS?  
   **A**: Yes, must be tested extensively

5. **Q**: FIPS mode compatibility?  
   **A**: Yes, must work in FIPS 140-3 mode

---

## 15. Approvals

| Role | Name | Status | Date |
|------|------|--------|------|
| Feature Owner | TBD | ⏳ Pending | - |
| Chief Architect | TBD | ⏳ Pending | - |
| Security Architect | TBD | ⏳ Pending | - |
| Performance Lead | TBD | ⏳ Pending | - |
| ID Lead | TBD | ⏳ Pending | - |

---

*End of UFO Document*
