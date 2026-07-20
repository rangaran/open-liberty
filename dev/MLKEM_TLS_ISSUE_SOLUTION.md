# ML-KEM TLS Integration Issue - Complete Analysis and Solution

## Issue Summary

**Error**: `java.lang.IllegalArgumentException: System property jdk.tls.namedGroups(X25519MLKEM768) contains no supported named groups`

## Root Cause Analysis

Your IBM Semeru Runtime 26.0.1 has **partial ML-KEM support**:

### ✅ What IS Available:
- **KEM API** (`javax.crypto.KEM`) - Present
- **ML-KEM Algorithms** - Available from two providers:
  - **SunJCE**: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  - **OpenJCEPlus**: ML-KEM-512, ML-KEM-768, ML-KEM-1024

### ❌ What is NOT Available:
- **TLS Hybrid Named Groups** - X25519MLKEM768, X448MLKEM1024, etc.
- The TLS layer only supports traditional named groups:
  - Elliptic curves: X25519, X448, SECP256_R1, SECP384_R1, SECP521_R1
  - Finite field groups: FFDHE_2048, FFDHE_3072, etc.

## Why This Happens

The ML-KEM algorithms are available for **direct cryptographic operations** (key encapsulation), but the **TLS 1.3 protocol integration** for hybrid post-quantum key exchange is not yet implemented in this Java version.

Hybrid named groups like `X25519MLKEM768` combine:
- Traditional ECDH (X25519) for proven security
- ML-KEM-768 for quantum resistance

This requires TLS protocol changes that are still in development.

## Solutions

### Solution 1: Remove PQC Configuration (Immediate Fix)

**Recommended for production use right now.**

Edit `dev/build.image/wlp/usr/servers/defaultServer/jvm.options`:

```properties
-Djavax.net.debug=all
# ML-KEM TLS integration not yet available in Java 26.0.1
# The KEM algorithms exist but TLS hybrid named groups are not implemented
# Uncomment when using a Java build with full TLS ML-KEM support:
# -Djdk.tls.namedGroups=X25519MLKEM768
# -Dcom.ibm.ws.security.pqc.enabled=true
```

Your server will use standard TLS 1.3 with X25519, which is secure and widely supported.

### Solution 2: Use ML-KEM for Application-Level Encryption

Since ML-KEM algorithms ARE available, you can use them for application-level encryption (not TLS):

```java
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulator;
import javax.crypto.KEM.Decapsulator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

// Generate ML-KEM key pair
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768");
KeyPair keyPair = kpg.generateKeyPair();

// Encapsulation (sender side)
KEM kem = KEM.getInstance("ML-KEM-768");
Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());
KEM.Encapsulated encapsulated = encapsulator.encapsulate();
byte[] sharedSecret = encapsulated.key().getEncoded();
byte[] ciphertext = encapsulated.encapsulation();

// Decapsulation (receiver side)
Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivate());
byte[] recoveredSecret = decapsulator.decapsulate(ciphertext).getEncoded();
```

This is useful for:
- LTPA token encryption (your PQC work)
- Audit log encryption
- Application data encryption
- Key exchange in custom protocols

### Solution 3: Wait for TLS Integration

Monitor these sources for TLS ML-KEM support:

1. **IBM Semeru Releases**
   - https://developer.ibm.com/languages/java/semeru-runtimes/
   - Watch for announcements about TLS 1.3 PQC support

2. **OpenJDK JEPs**
   - Watch for JEP proposals for TLS ML-KEM integration
   - Expected timeline: Late 2026 or 2027

3. **IETF Standards**
   - RFC for hybrid key exchange in TLS 1.3
   - Draft: draft-ietf-tls-hybrid-design

### Solution 4: Custom TLS Integration (Advanced)

If you need TLS ML-KEM support now, you could:

1. **Use BouncyCastle TLS**
   - BouncyCastle has experimental PQC TLS support
   - Requires replacing Java's TLS implementation
   - Complex and not recommended for production

2. **Implement Custom SSLContext**
   - Create a custom SSLContext that uses ML-KEM
   - Very complex, requires deep TLS knowledge
   - Not recommended

## Recommended Action Plan

### For Your Current Work:

1. **Comment out TLS PQC configuration** (Solution 1)
2. **Keep using ML-KEM for application-level crypto** (Solution 2)
   - Your LTPA PQC work can still use ML-KEM-768
   - Audit encryption can use ML-KEM
3. **Use standard TLS 1.3 for transport security**
   - X25519 is secure and quantum-resistant against current threats
   - When quantum computers become a real threat, TLS ML-KEM will be available

### Configuration Changes:

**File: `dev/build.image/wlp/usr/servers/defaultServer/jvm.options`**
```properties
-Djavax.net.debug=all
# Note: ML-KEM algorithms (ML-KEM-512, ML-KEM-768, ML-KEM-1024) are available
# for application-level encryption via javax.crypto.KEM API.
# However, TLS hybrid named groups (X25519MLKEM768) are not yet implemented.
# 
# Uncomment these when using a Java build with TLS ML-KEM support:
# -Djdk.tls.namedGroups=X25519MLKEM768
# -Dcom.ibm.ws.security.pqc.enabled=true
```

**File: `dev/build.image/wlp/usr/servers/defaultServer/server.xml`**
```xml
<!-- Keep TLS 1.3 enabled - it will use X25519 for key exchange -->
<ssl id="defaultSSLConfig" trustDefaultCerts="true" sslProtocol="TLSv1.3" />
```

## Testing Your Setup

Run the diagnostic tools:

```bash
cd dev

# Test KEM availability
java TestKEMAndTLS

# Test TLS named groups
java --add-opens java.base/sun.security.ssl=ALL-UNNAMED TestTLSNamedGroups
```

## Timeline Expectations

- **Q3 2026**: Possible preview builds with TLS ML-KEM
- **Q4 2026 - Q1 2027**: Expected stable release with TLS ML-KEM support
- **2027+**: Widespread adoption

## Summary

Your Java build is **ahead of the curve** with ML-KEM algorithm support, but the TLS protocol integration is still in development. You can:

1. ✅ Use ML-KEM for application-level encryption (LTPA, audit logs, etc.)
2. ✅ Use standard TLS 1.3 for transport security
3. ❌ Cannot use ML-KEM for TLS key exchange yet

This is actually a good position - you can develop and test your PQC features now, and when TLS integration arrives, you'll be ready to enable it with a simple configuration change.

---

**Created**: 2026-07-18  
**Java Version Tested**: IBM Semeru Runtime 26.0.1  
**Status**: ML-KEM algorithms available, TLS integration pending