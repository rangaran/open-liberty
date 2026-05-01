# LTPA Token Version Detection

## Overview

This document describes the token version detection mechanism in LTPA tokens, which allows quick identification of token versions without expensive cryptographic operations.

## Token Version Header

### LTPAToken3 (Version 3) - PQC Hybrid Token

**Status:** ✅ **IMPLEMENTED**

LTPAToken3 includes an **unencrypted version byte** at the beginning of the token that can be checked before any decryption or signature verification.

#### Token Structure

```
[version:1 byte] + [rsaSignature:256 bytes] + [mldsaSignatureSize:2 bytes] + [mldsaSignature:variable] + [encrypted data]
```

#### Version Byte Details

- **Position:** First byte of the token (index 0)
- **Value:** `0x03` (decimal 3)
- **Encoding:** Single byte, not encrypted, not signed
- **Purpose:** Quick version detection without cryptographic operations

#### Implementation

**File:** `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAToken3.java`

**Encryption Method (lines 220, 247):**
```java
ByteBuffer tokenBuffer = ByteBuffer.allocate(...);
tokenBuffer.put((byte) VERSION);  // VERSION = 3
tokenBuffer.put(rsaSignature);
tokenBuffer.putShort((short) mldsaSignatureSize);
tokenBuffer.put(mldsaSignature);
tokenBuffer.put(encryptedData);
```

**Decryption Method:**
```java
private void decrypt() throws InvalidTokenException {
    ByteBuffer buffer = ByteBuffer.wrap(encryptedBytes);
    
    // Read version byte (unencrypted)
    byte version = buffer.get();
    if (version != VERSION) {
        throw new InvalidTokenException("Invalid token version: " + version);
    }
    
    // Continue with signature verification and decryption...
}
```

#### Benefits

1. **Performance:** No decryption needed to check version
2. **Early Detection:** Reject incompatible tokens immediately
3. **Routing:** Route tokens to appropriate handlers based on version
4. **Backward Compatibility:** Detect legacy tokens quickly

### LTPAToken2 (Version 2) - Classical Token

**Status:** ❌ **NOT IMPLEMENTED**

LTPAToken2 does **NOT** have an unencrypted version header. The entire token is encrypted, including any version information.

#### Token Structure

```
[encrypted data containing: userData + expiration + signature]
```

#### Detection Method

LTPAToken2 must be detected by:
1. Attempting to decrypt with shared key
2. Parsing the decrypted content
3. Checking for version field in userData (if present)

#### Limitation

- Requires full decryption to determine version
- Cannot quickly reject incompatible tokens
- Higher performance cost for version detection

## Version Detection Algorithm

### Recommended Approach

```java
public static int detectTokenVersion(byte[] tokenBytes) {
    if (tokenBytes == null || tokenBytes.length == 0) {
        throw new InvalidTokenException("Empty token");
    }
    
    // Check first byte for LTPAToken3 version header
    byte firstByte = tokenBytes[0];
    
    if (firstByte == 0x03) {
        // LTPAToken3 with unencrypted version header
        return 3;
    } else if (firstByte == 0x02) {
        // Future: LTPAToken2 with version header (if implemented)
        return 2;
    } else {
        // Legacy LTPAToken2 without version header
        // Must decrypt to determine version
        return detectLegacyTokenVersion(tokenBytes);
    }
}

private static int detectLegacyTokenVersion(byte[] tokenBytes) {
    // Attempt to decrypt and parse as LTPAToken2
    // This is expensive but necessary for legacy tokens
    try {
        // Decrypt with shared key
        // Parse token structure
        // Return version based on structure
        return 2; // Assume LTPAToken2 for legacy tokens
    } catch (Exception e) {
        throw new InvalidTokenException("Unable to determine token version", e);
    }
}
```

### Performance Comparison

| Token Version | Version Detection | Performance |
|---------------|-------------------|-------------|
| LTPAToken3 | Read first byte | O(1) - Instant |
| LTPAToken2 (legacy) | Decrypt + parse | O(n) - Expensive |

## Future Enhancement: Add Version Header to LTPAToken2

### Proposal

Add an unencrypted version byte to LTPAToken2 for consistency and performance.

#### Proposed Token Structure

```
[version:1 byte] + [encrypted data containing: userData + expiration + signature]
```

#### Implementation Steps

1. **Modify LTPAToken2.encrypt():**
   ```java
   private final void encrypt() throws Exception {
       // Existing encryption logic...
       byte[] encryptedData = LTPAKeyUtil.encrypt(toBeEnc, sharedKey, cipher);
       
       // Prepend version byte
       byte[] tokenWithVersion = new byte[1 + encryptedData.length];
       tokenWithVersion[0] = (byte) version; // version = 2
       System.arraycopy(encryptedData, 0, tokenWithVersion, 1, encryptedData.length);
       
       encryptedBytes = tokenWithVersion;
   }
   ```

2. **Modify LTPAToken2.decrypt():**
   ```java
   private final void decrypt() throws InvalidTokenException {
       // Check if token has version header
       if (encryptedBytes[0] == (byte) version) {
           // New format with version header
           byte[] encryptedData = new byte[encryptedBytes.length - 1];
           System.arraycopy(encryptedBytes, 1, encryptedData, 0, encryptedData.length);
           // Continue with decryption...
       } else {
           // Legacy format without version header
           // Decrypt entire encryptedBytes...
       }
   }
   ```

3. **Backward Compatibility:**
   - Detect legacy tokens (no version header)
   - Support both formats during transition period
   - Gradually migrate to new format

#### Benefits

- Consistent version detection across all token types
- Improved performance for LTPAToken2 version checks
- Better routing and error handling
- Easier debugging and monitoring

#### Risks

- Backward compatibility complexity
- Requires careful testing with legacy tokens
- May require configuration flag for gradual rollout

## Token Version Registry

| Version | Token Type | Version Header | Cryptography | Status |
|---------|------------|----------------|--------------|--------|
| 1 | LTPAToken (legacy) | ❌ No | 3DES | Deprecated |
| 2 | LTPAToken2 | ❌ No | RSA-2048 + AES | Current |
| 3 | LTPAToken3 | ✅ Yes | RSA + ML-DSA + ML-KEM | PQC Hybrid |

## Testing

### Test Case: Version Detection

**File:** `dev/com.ibm.ws.security.token.ltpa_fat/fat/src/com/ibm/ws/security/token/ltpa/fat/LTPAPQCTests.java`

```java
@Test
public void testPQC_TokenVersionDetection() throws Exception {
    Assume.assumeTrue("This test requires Java 26+ for PQC support", isJava26OrLater);
    
    server.startServer(true);
    verifyLtpaConfigurationReadyMessageFound();
    
    // Create PQC token
    String cookie = verifySuccessfulFormLogin(USER1, USER1PWD);
    
    // Extract token bytes from cookie
    byte[] tokenBytes = extractTokenBytesFromCookie(cookie);
    
    // Verify version byte is present and correct
    assertNotNull("Token bytes should not be null", tokenBytes);
    assertTrue("Token should have at least 1 byte", tokenBytes.length > 0);
    
    // Check version byte (first byte should be 0x03)
    byte versionByte = tokenBytes[0];
    assertEquals("Version byte should be 3 for LTPAToken3", 3, versionByte);
    
    Log.info(thisClass, "testPQC_TokenVersionDetection", 
             "Successfully detected token version: " + versionByte);
}
```

### Test Case: Version Header Not Encrypted

```java
@Test
public void testPQC_VersionHeaderNotEncrypted() throws Exception {
    Assume.assumeTrue("This test requires Java 26+ for PQC support", isJava26OrLater);
    
    server.startServer(true);
    verifyLtpaConfigurationReadyMessageFound();
    
    // Create two tokens with same user
    String cookie1 = verifySuccessfulFormLogin(USER1, USER1PWD);
    formLoginClient.resetClientState();
    String cookie2 = verifySuccessfulFormLogin(USER1, USER1PWD);
    
    // Extract token bytes
    byte[] token1 = extractTokenBytesFromCookie(cookie1);
    byte[] token2 = extractTokenBytesFromCookie(cookie2);
    
    // Version bytes should be identical (not encrypted)
    assertEquals("Version bytes should match", token1[0], token2[0]);
    assertEquals("Version should be 3", 3, token1[0]);
    
    // Rest of token should differ (encrypted with different IVs)
    boolean restDiffers = false;
    for (int i = 1; i < Math.min(token1.length, token2.length); i++) {
        if (token1[i] != token2[i]) {
            restDiffers = true;
            break;
        }
    }
    assertTrue("Encrypted portions should differ", restDiffers);
    
    Log.info(thisClass, "testPQC_VersionHeaderNotEncrypted", 
             "Verified version header is not encrypted");
}
```

## References

- [LTPA Token Version 3 Implementation](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAToken3.java)
- [LTPA Token Version 2 Implementation](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAToken2.java)
- [LTPA PQC FAT Tests](dev/com.ibm.ws.security.token.ltpa_fat/fat/src/com/ibm/ws/security/token/ltpa/fat/LTPAPQCTests.java)

---

**Created with IBM Bob** - LTPA Token Version Detection Documentation