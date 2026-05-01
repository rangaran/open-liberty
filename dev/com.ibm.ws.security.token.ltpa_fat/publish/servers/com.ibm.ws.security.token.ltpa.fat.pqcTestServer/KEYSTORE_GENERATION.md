# PQC LTPA Test Keystore Generation Guide

## Overview

This guide explains how to generate test keystores with Post-Quantum Cryptography (PQC) keys for LTPA FAT testing.

## Automatic Generation (Recommended)

The LTPA PQC implementation automatically generates hybrid keystores when the server starts with `hybridPqcEnabled="true"`. This is the recommended approach for testing.

### How It Works

1. Server starts with PQC configuration in `server.xml`
2. LTPA configuration detects `hybridPqcEnabled="true"`
3. If hybrid keystore doesn't exist, it's automatically created
4. Keystore contains:
   - RSA-2048 key pair (alias: `ltpa-rsa`)
   - ML-DSA-65 key pair (alias: `ltpa-mldsa`)
   - ML-KEM-768 key pair (alias: `ltpa-mlkem`)

### Configuration

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

### Generated Files

After server startup, you'll find:

```
wlp/usr/servers/com.ibm.ws.security.token.ltpa.fat.pqcTestServer/
└── resources/
    └── security/
        ├── ltpa.keys              # Traditional RSA keys (backward compatibility)
        └── ltpa-hybrid.p12        # Hybrid keystore (RSA + ML-DSA + ML-KEM)
```

## Manual Generation (Advanced)

If you need to pre-generate keystores for testing, follow these steps.

### Prerequisites

- Java 26+ (for ML-DSA and ML-KEM support)
- OpenSSL (optional, for inspection)

### Step 1: Generate RSA Key Pair

```bash
# Using Java keytool
keytool -genkeypair \
  -alias ltpa-rsa \
  -keyalg RSA \
  -keysize 2048 \
  -keystore ltpa-hybrid.p12 \
  -storetype PKCS12 \
  -storepass ltpapwd \
  -keypass ltpapwd \
  -dname "CN=LTPA RSA Key, OU=Liberty, O=IBM, C=US" \
  -validity 3650
```

### Step 2: Generate ML-DSA Key Pair

```bash
# Using Java 26+ keytool with ML-DSA support
keytool -genkeypair \
  -alias ltpa-mldsa \
  -keyalg ML-DSA-65 \
  -keystore ltpa-hybrid.p12 \
  -storetype PKCS12 \
  -storepass ltpapwd \
  -keypass ltpapwd \
  -dname "CN=LTPA ML-DSA Key, OU=Liberty, O=IBM, C=US" \
  -validity 3650
```

### Step 3: Generate ML-KEM Key Pair

```bash
# Using Java 26+ keytool with ML-KEM support
keytool -genkeypair \
  -alias ltpa-mlkem \
  -keyalg ML-KEM-768 \
  -keystore ltpa-hybrid.p12 \
  -storetype PKCS12 \
  -storepass ltpapwd \
  -keypass ltpapwd \
  -dname "CN=LTPA ML-KEM Key, OU=Liberty, O=IBM, C=US" \
  -validity 3650
```

### Step 4: Verify Keystore Contents

```bash
# List all entries in the keystore
keytool -list -v \
  -keystore ltpa-hybrid.p12 \
  -storetype PKCS12 \
  -storepass ltpapwd
```

Expected output:
```
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 3 entries

Alias name: ltpa-rsa
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=LTPA RSA Key, OU=Liberty, O=IBM, C=US
Issuer: CN=LTPA RSA Key, OU=Liberty, O=IBM, C=US
Serial number: ...
Valid from: ... until: ...
Certificate fingerprints:
         SHA1: ...
         SHA256: ...
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key

Alias name: ltpa-mldsa
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=LTPA ML-DSA Key, OU=Liberty, O=IBM, C=US
Issuer: CN=LTPA ML-DSA Key, OU=Liberty, O=IBM, C=US
Serial number: ...
Valid from: ... until: ...
Certificate fingerprints:
         SHA1: ...
         SHA256: ...
Signature algorithm name: ML-DSA-65
Subject Public Key Algorithm: ML-DSA-65 key

Alias name: ltpa-mlkem
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=LTPA ML-KEM Key, OU=Liberty, O=IBM, C=US
Issuer: CN=LTPA ML-KEM Key, OU=Liberty, O=IBM, C=US
Serial number: ...
Valid from: ... until: ...
Certificate fingerprints:
         SHA1: ...
         SHA256: ...
Signature algorithm name: ML-KEM-768
Subject Public Key Algorithm: ML-KEM-768 key
```

## Algorithm Options

### ML-DSA (Digital Signatures)

| Algorithm | NIST Level | Quantum Security | Public Key Size | Signature Size |
|-----------|------------|------------------|-----------------|----------------|
| ML-DSA-44 | 2 | 128-bit | 1,312 bytes | 2,420 bytes |
| ML-DSA-65 | 3 | 192-bit | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | 5 | 256-bit | 2,592 bytes | 4,627 bytes |

**Recommended:** ML-DSA-65 (good balance of security and performance)

### ML-KEM (Key Encapsulation)

| Algorithm | NIST Level | Quantum Security | Public Key Size | Ciphertext Size |
|-----------|------------|------------------|-----------------|-----------------|
| ML-KEM-512 | 1 | 128-bit | 800 bytes | 768 bytes |
| ML-KEM-768 | 3 | 192-bit | 1,184 bytes | 1,088 bytes |
| ML-KEM-1024 | 5 | 256-bit | 1,568 bytes | 1,568 bytes |

**Recommended:** ML-KEM-768 (good balance of security and performance)

## Testing Different Algorithms

To test different PQC algorithms, modify the `server.xml` configuration:

### High Security (NIST Level 5)

```xml
<ltpa
    mldsaAlgorithm="ML-DSA-87"
    mlkemAlgorithm="ML-KEM-1024"
    .../>
```

### Balanced Security (NIST Level 3) - Default

```xml
<ltpa
    mldsaAlgorithm="ML-DSA-65"
    mlkemAlgorithm="ML-KEM-768"
    .../>
```

### Fast Performance (NIST Level 1-2)

```xml
<ltpa
    mldsaAlgorithm="ML-DSA-44"
    mlkemAlgorithm="ML-KEM-512"
    .../>
```

## Keystore Security

### File Permissions

Ensure the keystore has restrictive permissions:

```bash
chmod 600 ltpa-hybrid.p12
chown liberty:liberty ltpa-hybrid.p12
```

### Password Protection

- **Test Password:** `ltpapwd` (XOR encoded: `{xor}Lz4sLCgwLTs=`)
- **Production:** Use strong, unique passwords and secure password management

### Key Rotation

For production environments, implement regular key rotation:

1. Generate new hybrid keystore
2. Update server configuration
3. Restart server
4. Verify new keys are in use
5. Archive old keystore securely

## Troubleshooting

### Issue: "Algorithm ML-DSA-65 not available"

**Cause:** Running with Java 17 or earlier

**Solution:** Use Java 26+ for PQC support:
```bash
export JAVA_HOME=/path/to/java-26
```

### Issue: "Invalid keystore format"

**Cause:** Keystore was created with incompatible tool or format

**Solution:** Ensure keystore is PKCS12 format:
```bash
keytool -list -keystore ltpa-hybrid.p12 -storetype PKCS12
```

### Issue: "Cannot recover key"

**Cause:** Incorrect password or corrupted keystore

**Solution:** 
- Verify password is correct
- Regenerate keystore if corrupted
- Check file permissions

## FAT Test Integration

The FAT tests automatically handle keystore generation:

1. Test starts server with PQC configuration
2. Server detects missing hybrid keystore
3. Server generates keystore with all required keys
4. Test verifies keystore was created
5. Test cleans up keystore after completion

No manual keystore generation is required for FAT testing.

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [JEP 478: Key Encapsulation Mechanism API](https://openjdk.org/jeps/478)
- [Java Keytool Documentation](https://docs.oracle.com/en/java/javase/26/docs/specs/man/keytool.html)

---

**Created with IBM Bob** - PQC LTPA Keystore Generation Guide