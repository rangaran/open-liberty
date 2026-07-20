# Post-Quantum Cryptography (ML-KEM) Setup Guide for Open Liberty

## Problem Summary

You're encountering this error:
```
java.lang.IllegalArgumentException: System property jdk.tls.namedGroups(X25519MLKEM768) 
contains no supported named groups
```

This occurs because your JVM configuration specifies the ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) named group `X25519MLKEM768`, but your current Java installation doesn't have built-in support for this post-quantum cryptography algorithm.

## Current Environment

- **Java Version**: IBM Semeru Runtime Open Edition 26.0.1
- **Java Vendor**: IBM Corporation  
- **JVM**: Eclipse OpenJ9 VM 26.0.1.0
- **Java Home**: `/Users/niyathar/Downloads/javak/Contents/Home`

## Understanding ML-KEM Support

ML-KEM (formerly known as CRYSTALS-Kyber) is a post-quantum key encapsulation mechanism standardized by NIST. The named groups like `X25519MLKEM768` combine traditional elliptic curve cryptography (X25519) with post-quantum algorithms (ML-KEM-768) for hybrid security.

### Current Status in Java

As of Java 26 (April 2026), ML-KEM support is:
- **Not yet in standard OpenJDK/IBM Semeru releases** - Still in development
- **Available in experimental builds** - Some vendors provide preview builds
- **Expected in future Java versions** - Likely Java 27+ (late 2026 or 2027)

## Solutions

### Option 1: Use Standard TLS 1.3 (Recommended for Production)

Remove the PQC configuration and use standard TLS 1.3 with proven algorithms:

**Edit `dev/build.image/wlp/usr/servers/defaultServer/jvm.options`:**
```properties
-Djavax.net.debug=all
# PQC/ML-KEM support requires a Java build with ML-KEM support
# Uncomment these lines when using a PQC-enabled Java build:
# -Djdk.tls.namedGroups=X25519MLKEM768
# -Dcom.ibm.ws.security.pqc.enabled=true
```

**Keep your `server.xml` SSL configuration:**
```xml
<ssl id="defaultSSLConfig" trustDefaultCerts="true" sslProtocol="TLSv1.3" />
```

This will use standard TLS 1.3 with algorithms like X25519, secp256r1, etc.

### Option 2: Obtain a PQC-Enabled Java Build

To use ML-KEM, you need a Java build with PQC support. Here are your options:

#### A. Wait for Official Support
- **IBM Semeru**: Monitor IBM's releases for PQC support announcements
- **OpenJDK**: Watch for JEP (Java Enhancement Proposal) for ML-KEM integration
- **Timeline**: Likely Q3-Q4 2026 or early 2027

#### B. Use Experimental/Preview Builds

Some vendors provide experimental builds with PQC support:

1. **Oracle Java with PQC Preview** (if available)
   - Check Oracle's Early Access builds: https://jdk.java.net/
   - Look for builds with "PQC" or "ML-KEM" in release notes

2. **Azul Zulu with PQC** (if available)
   - Check Azul's downloads: https://www.azul.com/downloads/
   - Look for builds with cryptography enhancements

3. **Custom OpenJDK Build with BouncyCastle**
   - Build OpenJDK with BouncyCastle PQC provider
   - More complex, requires compilation

#### C. Use BouncyCastle Security Provider

Add BouncyCastle as a security provider for PQC support:

1. **Download BouncyCastle JARs:**
   - bcprov-jdk18on (core provider)
   - bcpkix-jdk18on (PKI/X.509 support)
   - bcpqc-jdk18on (post-quantum cryptography)
   
   From: https://www.bouncycastle.org/latest_releases.html

2. **Add to Liberty:**
   ```bash
   # Copy JARs to Liberty's lib directory
   cp bcprov-jdk18on-*.jar dev/build.image/wlp/lib/
   cp bcpkix-jdk18on-*.jar dev/build.image/wlp/lib/
   cp bcpqc-jdk18on-*.jar dev/build.image/wlp/lib/
   ```

3. **Register BouncyCastle Provider:**
   
   Edit `jvm.options`:
   ```properties
   -Djava.security.properties=/path/to/custom-security.properties
   ```
   
   Create `custom-security.properties`:
   ```properties
   security.provider.1=org.bouncycastle.jce.provider.BouncyCastleProvider
   security.provider.2=org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
   # Keep existing providers with incremented numbers
   ```

**Note**: This approach may require additional configuration and testing.

### Option 3: Use Hybrid Configuration (Fallback Support)

Configure your server to support both PQC and traditional algorithms:

**In `jvm.options`:**
```properties
-Djavax.net.debug=all
# Hybrid: Try PQC first, fall back to traditional
-Djdk.tls.namedGroups=X25519MLKEM768,X25519,secp256r1,secp384r1
-Dcom.ibm.ws.security.pqc.enabled=true
```

This requires a PQC-enabled Java build but allows connections from non-PQC clients.

## Verification Steps

After obtaining a PQC-enabled Java build:

1. **Test ML-KEM Support:**
   ```bash
   cd dev
   java TestMLKEMSupport
   ```
   
   Look for `X25519MLKEM768` in the supported named groups list.

2. **Start Liberty Server:**
   ```bash
   cd dev/build.image/wlp/bin
   ./server start defaultServer
   ```

3. **Check Logs:**
   ```bash
   tail -f dev/build.image/wlp/usr/servers/defaultServer/logs/messages.log
   ```
   
   Should see successful SSL initialization without errors.

4. **Test HTTPS Connection:**
   ```bash
   curl -v https://localhost:9443/
   ```
   
   With `-Djavax.net.debug=all`, check trace logs for ML-KEM negotiation.

## Testing Without PQC

To test your current setup without PQC:

1. **Comment out PQC settings in `jvm.options`**
2. **Restart the server**
3. **Verify HTTPS works with standard TLS 1.3**

## References

- **NIST PQC Standardization**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **ML-KEM Specification**: FIPS 203
- **BouncyCastle PQC**: https://www.bouncycastle.org/
- **OpenJDK Security**: https://openjdk.org/groups/security/

## Recommendation

**For immediate use**: Choose **Option 1** (remove PQC configuration) and use standard TLS 1.3. This provides excellent security with proven algorithms.

**For future PQC support**: Monitor IBM Semeru releases and update when official PQC support is available (likely late 2026).

**For experimental/development**: Use **Option 2C** (BouncyCastle) if you need to test PQC functionality now, but be aware this is not production-ready.

## Next Steps

1. Decide which option fits your needs
2. Update configuration accordingly
3. Test thoroughly
4. Document any changes for your team

---

**Created**: 2026-07-18  
**Last Updated**: 2026-07-18