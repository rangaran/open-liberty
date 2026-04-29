# PQC (Post-Quantum Cryptography) Support for LTPA in Liberty - Implementation Plan

**Issue**: [#35556 - PQC support in Liberty - Update LTPA code](https://github.ibm.com/websphere/WS-CD-Open/issues/35556)  
**Date**: April 22, 2026  
**Estimated Effort**: 2XL (16-20 person weeks)  
**Timeline**: 17 weeks (4+ months)

---

## Executive Summary

This plan outlines the approach to add Post-Quantum Cryptography (PQC) support to Liberty's LTPA (Lightweight Third Party Authentication) token implementation. The implementation will support ML-DSA (FIPS 204) digital signatures while maintaining backward compatibility with existing RSA-based LTPA tokens.

## Background

### Industry Context

Post-Quantum Cryptography (PQC) is critical for protecting against future quantum computing threats. IBM Java/Semeru has begun rolling out PQC support:

- **ML-KEM** (key encapsulation) and **ML-DSA** (digital signatures) available in IBM Java 17+ (July 2025)
- Support across distributed platforms and z/OS
- Java 24 includes PQC in OpenJDK via SunJCE provider

### Current State

Liberty's LTPA implementation currently uses:
- **RSA signatures** with ISO9796 padding for token authentication
- **AES-CBC** for symmetric encryption
- **SHA-256** for hashing

These classical algorithms are vulnerable to quantum computing attacks and need PQC alternatives.

---

## Current LTPA Architecture

### Core Components

1. **LTPAToken2.java** - Token representation with RSA signatures
2. **LTPAToken2Factory.java** - Token creation and validation factory
3. **LTPAKeyInfoManager.java** - Key management and loading
4. **LTPAConfiguration.java** - Configuration interface

### Current Cryptographic Operations

| Operation | Algorithm | Location |
|-----------|-----------|----------|
| Token Encryption | AES-CBC | LTPAToken2.encrypt() |
| Token Decryption | AES-CBC | LTPAToken2.decrypt() |
| Token Signing | RSA + ISO9796 | LTPAToken2.sign() |
| Token Verification | RSA + ISO9796 | LTPAToken2.verify() |
| Hashing | SHA-256 | MessageDigest |

---

## Implementation Plan

### Phase 1: Research & Design (Weeks 1-3)

#### 1.1 PQC Algorithm Selection

**Selected Algorithms:**
- **ML-DSA (FIPS 204)** - Digital signatures (replaces RSA)
  - ML-DSA-44: 128-bit security level
  - ML-DSA-65: 192-bit security level (recommended)
  - ML-DSA-87: 256-bit security level
- **AES-256-GCM** - Symmetric encryption (upgrade from AES-CBC)

**Provider Verification:**
- OpenJCEPlus (distributed platforms)
- IBMJCEPlus (IBM Java 8)
- IBMJCECCA (z/OS)

#### 1.2 Design Approach

**Key Design Decisions:**

1. **Hybrid Cryptography Mode** - Support both RSA and ML-DSA signatures
2. **Backward Compatibility** - Existing LTPA v2.0 tokens remain valid
3. **Configuration-Driven** - Administrators choose crypto mode
4. **Version Management** - LTPA version 3.0 for PQC tokens

---

### Phase 2: Core Implementation (Weeks 4-10)

#### 2.1 Update Key Generation
- Add ML-DSA key pair generation
- Support hybrid key storage (RSA + ML-DSA)
- Update key file format to version 3.0
- Add properties: MLDSAPrivateKey, MLDSAPublicKey

#### 2.2 Modify Token Creation
- Add PQC signature method using ML-DSA
- Implement hybrid signing (both RSA and ML-DSA)
- Update encrypt() to use AES-GCM
- Add version field to distinguish PQC tokens

#### 2.3 Update Token Validation
- Add PQC signature verification using ML-DSA
- Support hybrid verification (try PQC first, fallback to RSA)
- Update decrypt() to handle AES-GCM

#### 2.4 Update Key Management
- Load PQC keys from key files
- Support validation keys with PQC
- Handle key migration scenarios

#### 2.5 Configuration Updates
- Add cryptoMode property: "classical", "pqc", "hybrid"
- Add pqcAlgorithm property: "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
- Add enablePQC boolean flag
- Update schema files (server.xsd)

---

### Phase 3: Testing (Weeks 11-14)

#### 3.1 Unit Tests
- Test PQC key generation
- Test PQC token creation and validation
- Test hybrid mode operations
- Test backward compatibility with RSA tokens

#### 3.2 FAT Tests
- Create new FAT project: com.ibm.ws.security.token.ltpa.pqc_fat
- Test token interoperability between servers
- Test key rotation scenarios
- Test performance impact
- Test FIPS mode compatibility

#### 3.3 Security Testing
- Vulnerability scanning with Mend
- Penetration testing for PQC implementation
- Verify no information leakage
- Test against known PQC attack vectors

---

### Phase 4: Documentation & Compliance (Weeks 15-16)

#### 4.1 Documentation
- Update Liberty documentation for PQC configuration
- Create migration guide from RSA to PQC
- Document performance characteristics
- Add troubleshooting guide

#### 4.2 Compliance Requirements
- **Legal**: Clear all new dependencies
- **Translation**: Update all error messages
- **Serviceability**: Add trace points for PQC operations
- **Performance**: Benchmark and document performance impact

---

### Phase 5: Focal Point Approvals (Week 17)

Complete all required approvals:
- [ ] APIs/Externals approval
- [ ] Demo scheduled
- [ ] FAT approval
- [ ] ID (documentation) approval
- [ ] InstantOn compatibility
- [ ] Performance testing approval
- [ ] Serviceability approval
- [ ] STE (Skills Transfer) approval
- [ ] SVT approval

---

## Key Technical Decisions

### 1. Hybrid Cryptography Approach
**Decision**: Implement hybrid mode where tokens contain both RSA and ML-DSA signatures  
**Rationale**: Provides defense-in-depth and smooth migration path

### 2. Backward Compatibility
**Decision**: Version 2.0 tokens (RSA) remain valid indefinitely  
**Rationale**: Prevents breaking existing deployments

### 3. Configuration Strategy
**Decision**: PQC disabled by default, opt-in via configuration  
**Rationale**: Allows customers to adopt PQC when ready

### 4. Key File Format
**Decision**: Extend existing format with new properties  
**Rationale**: Minimizes configuration changes

---

## Security Considerations

1. **MUST** use TLS 1.3 for all PQC token transmission
2. **MUST** validate all PQC keys meet FIPS 204 requirements
3. **MUST** implement constant-time operations to prevent timing attacks
4. **MUST** use secure random number generation from IBM Java providers
5. **NEVER** log or expose PQC private keys
6. **MUST** implement proper key rotation mechanisms

---

## Dependencies

- IBM Java 17+ with OpenJCEPlus provider (ML-DSA support)
- IBM Java 8 with IBMJCEPlus provider (z/OS)
- FIPS 140-3 certified cryptographic modules
- Updated com.ibm.ws.crypto.ltpakeyutil bundle

---

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| PQC provider not available | High | Graceful fallback to RSA, clear error messages |
| Performance degradation | Medium | Benchmark early, optimize hot paths |
| Key size increase | Low | Update buffer sizes, test with large tokens |
| Interoperability issues | High | Extensive testing with tWAS |

---

## Success Criteria

1. ✅ PQC tokens can be created and validated
2. ✅ Hybrid mode works with both RSA and PQC
3. ✅ Backward compatibility maintained
4. ✅ Performance impact < 20% for token operations
5. ✅ All focal point approvals obtained
6. ✅ Zero critical security vulnerabilities
7. ✅ Documentation complete and reviewed

---

## Estimated Effort

- **Size**: 2XL (16-20 person weeks)
- **Timeline**: 17 weeks (4+ months)
- **Team**: 2-3 developers + 1 security expert

---

## Next Steps

1. Schedule POC/UFO design review
2. Create detailed technical design document
3. Set up development environment with PQC providers
4. Begin Phase 1 research and prototyping

---

## Appendix: File Locations

### Files to Modify

1. **com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAToken2.java**
   - Add PQC signing and verification methods
   - Update encrypt/decrypt for AES-GCM

2. **com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAToken2Factory.java**
   - Update token creation and validation logic

3. **com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java**
   - Add PQC key loading and management

4. **com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAConfiguration.java**
   - Add PQC configuration properties

5. **com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAKeyFileCreatorImpl.java**
   - Add PQC key generation

### New Files to Create

1. **com.ibm.ws.security.token.ltpa.pqc_fat/** - FAT test project
2. **PQC migration guide** - Documentation
3. **PQC configuration examples** - Sample server.xml files

---

*End of Implementation Plan*
