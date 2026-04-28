# LTPA PQC Test Server

This test server is configured to test Post-Quantum Cryptography (PQC) support in LTPA tokens.

## Overview

This server demonstrates the use of LTPA Token Version 3 with hybrid Post-Quantum Cryptography:
- **RSA-2048** for backward compatibility
- **ML-KEM-768** for quantum-resistant key encapsulation
- **AES-256-GCM** for symmetric encryption

## Prerequisites

### Java 26 Required for Full PQC Support
To test the full PQC functionality, you must run this server with **Java 26 or later**, which includes:
- ML-KEM (FIPS 203) support via JEP 478
- Native quantum-resistant key encapsulation

### Fallback Behavior with Java 17
If you run with Java 17, the server will:
- Compile successfully (uses reflection-based compatibility layer)
- Detect that Java 26 is not available at runtime
- Fall back to RSA-only mode (LTPA Token Version 2)
- Log a warning about PQC unavailability

## Configuration

### LTPA Configuration (server.xml)
```xml
<ltpa 
    keysFileName="${server.output.dir}/resources/security/ltpa.keys"
    keysPassword="{xor}Lz4sLCgwLTs="
    expiration="30m"
    tokenVersion="3"
    pqcEnabled="true"
    pqcKeystoreFile="${server.output.dir}/resources/security/ltpa-pqc.p12"
    pqcKeystorePassword="{xor}Lz4sLCgwLTs="
    mlkemAlgorithm="ML-KEM-768"/>
```

### Key Configuration Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `tokenVersion` | `3` | Enables LTPA Token Version 3 (PQC) |
| `pqcEnabled` | `true` | Activates Post-Quantum Cryptography |
| `mlkemAlgorithm` | `ML-KEM-768` | Quantum-resistant algorithm (512/768/1024) |
| `pqcKeystoreFile` | Path to PKCS12 | Stores PQC keys securely |

### Passwords
- LTPA Keys Password: `ltpapwd` (XOR encoded: `{xor}Lz4sLCgwLTs=`)
- PQC Keystore Password: `ltpapwd` (XOR encoded: `{xor}Lz4sLCgwLTs=`)

## Running the Server

### With Java 26 (Full PQC Support)
```bash
export JAVA_HOME=/path/to/java-26
cd /Users/utle/libertyGit/open-liberty/dev
./gradlew :com.ibm.ws.security.token.ltpa_fat:buildandrun
```

### With Java 17 (RSA Fallback)
```bash
export JAVA_HOME=/path/to/java-17
cd /Users/utle/libertyGit/open-liberty/dev
./gradlew :com.ibm.ws.security.token.ltpa_fat:buildandrun
```

## Testing PQC Functionality

### 1. Check Server Logs
Look for these messages in `logs/messages.log`:
```
CWWKS4105I: LTPA configuration is ready after X seconds.
CWWKS4106I: LTPA keys created in X seconds. LTPA key file: ltpa.keys
```

With Java 26, you should also see:
```
[INFO] PQC Runtime Support: Java 26+ detected, ML-KEM support available
[INFO] PQC keystore created: ltpa-pqc.p12
```

### 2. Verify PQC Keys Generated
Check that the PQC keystore was created:
```bash
ls -la wlp/usr/servers/com.ibm.ws.security.token.ltpa.fat.pqcTestServer/resources/security/
```

You should see:
- `ltpa.keys` (traditional RSA keys)
- `ltpa-pqc.p12` (PQC keystore with ML-KEM keys)

### 3. Test Token Creation
Access a protected resource to trigger LTPA token creation:
```bash
curl -u testuser:testpwd http://localhost:9080/protected-resource
```

Check the `Set-Cookie` header for the LTPA token.

### 4. Inspect Trace Logs
Enable detailed tracing in `server.xml`:
```xml
<logging 
    traceSpecification="*=info:com.ibm.ws.security.token.ltpa*=all:com.ibm.ws.security.token.ltpa.pqc*=all"/>
```

Look for PQC-specific trace in `logs/trace.log`:
```
[PQCRuntimeSupport] Checking Java version for PQC support...
[PQCRuntimeSupport] Java 26 detected, ML-KEM available
[LTPAPQCKeyGenerator] Generating ML-KEM-768 key pair...
[LTPAPQCCrypto] Encrypting token with ML-KEM + AES-GCM...
```

## Troubleshooting

### Issue: "PQC not available" warning
**Cause:** Running with Java 17 or earlier  
**Solution:** Use Java 26 or later for full PQC support

### Issue: Keystore not created
**Cause:** Insufficient permissions or invalid path  
**Solution:** Check server has write access to `${server.output.dir}/resources/security/`

### Issue: Token validation fails
**Cause:** Clock skew or expired tokens  
**Solution:** Check system time synchronization, adjust `expiration` setting

## Security Notes

1. **Passwords:** Change default passwords in production
2. **Keystore Protection:** Secure the PQC keystore file with appropriate file permissions
3. **Key Rotation:** Implement regular key rotation for both RSA and PQC keys
4. **Algorithm Selection:** ML-KEM-768 provides good balance of security and performance
   - ML-KEM-512: Faster, lower security margin
   - ML-KEM-1024: Slower, higher security margin

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [JEP 478: Key Encapsulation Mechanism API](https://openjdk.org/jeps/478)
- [Open Liberty LTPA Documentation](https://openliberty.io/docs/latest/reference/config/ltpa.html)

## Test Users

| Username | Password | Role |
|----------|----------|------|
| testuser | testpwd  | User |
| user1    | user1pwd | User |
| user2    | user2pwd | User |

---
**Created with IBM Bob** - PQC LTPA Implementation