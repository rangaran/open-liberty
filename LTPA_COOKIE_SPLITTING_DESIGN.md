# LTPA Cookie Splitting Design

## Problem Statement

LTPA3 tokens with Post-Quantum Cryptography (PQC) are significantly larger than traditional LTPA2 tokens:
- **LTPA2 Token**: ~200-400 bytes
- **LTPA3 Token (ML-KEM-512)**: 3,530 bytes raw, ~4,707 bytes Base64-encoded
- **Browser Cookie Limit**: 4,096 bytes per cookie

After Base64 encoding, LTPA3 tokens exceed the standard HTTP cookie size limit, requiring cookie splitting.

## Current Token Size Breakdown

From trace analysis:
```
Total Token Size: 3,530 bytes (raw)
├── RSA Signature: ~256 bytes
├── ML-DSA-44 Signature: 2,420 bytes
└── Encrypted Payload: 851 bytes
    ├── ML-KEM Encapsulation: 768 bytes
    └── AES-GCM Ciphertext: 83 bytes
```

After Base64 encoding: **~4,707 bytes** (exceeds 4KB limit)

## Design Goals

1. **Transparent Splitting**: Split large tokens across multiple cookies automatically
2. **Backward Compatibility**: LTPA2 tokens continue to use single cookie
3. **Reassembly**: Reconstruct original token from cookie fragments
4. **Security**: Maintain cryptographic integrity across fragments
5. **Browser Compatibility**: Stay within cookie size limits (3KB per fragment recommended)

## Proposed Solution

### Cookie Naming Convention

```
LtpaToken3       - Main cookie (contains metadata + first fragment)
LtpaToken3_1     - Fragment 1
LtpaToken3_2     - Fragment 2
LtpaToken3_N     - Fragment N
```

### Fragment Structure

**Main Cookie (LtpaToken3)**:
```
[Version:1][FragmentCount:1][TotalSize:4][Fragment0Data]
```

**Fragment Cookies (LtpaToken3_N)**:
```
[FragmentData]
```

### Fragment Size Calculation

```java
// Conservative fragment size to account for cookie overhead
private static final int MAX_FRAGMENT_SIZE = 3000; // 3KB per fragment
private static final int METADATA_SIZE = 6; // Version(1) + Count(1) + Size(4)

// Calculate number of fragments needed
int fragmentCount = (tokenBytes.length + METADATA_SIZE + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE;
```

### Implementation Components

#### 1. LTPACookieSplitter (New Class)

```java
package com.ibm.ws.security.token.ltpa.internal;

public class LTPACookieSplitter {
    
    private static final int MAX_FRAGMENT_SIZE = 3000;
    private static final byte VERSION = 1;
    
    /**
     * Split token bytes into multiple cookie-sized fragments
     */
    public static Map<String, byte[]> splitToken(byte[] tokenBytes, String cookieName);
    
    /**
     * Reassemble token from cookie fragments
     */
    public static byte[] reassembleToken(Map<String, String> cookies, String cookieName);
    
    /**
     * Check if token requires splitting
     */
    public static boolean requiresSplitting(byte[] tokenBytes);
}
```

#### 2. Cookie Creation (LTPAToken3)

Modify token serialization to support splitting:

```java
public Map<String, String> getCookies() {
    byte[] tokenBytes = getBytes();
    
    if (LTPACookieSplitter.requiresSplitting(tokenBytes)) {
        // Split into multiple cookies
        Map<String, byte[]> fragments = LTPACookieSplitter.splitToken(tokenBytes, "LtpaToken3");
        
        // Base64 encode each fragment
        Map<String, String> cookies = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : fragments.entrySet()) {
            cookies.put(entry.getKey(), Base64Coder.base64EncodeToString(entry.getValue()));
        }
        return cookies;
    } else {
        // Single cookie (backward compatible)
        return Collections.singletonMap("LtpaToken3", toString());
    }
}
```

#### 3. Cookie Parsing (Token Reconstruction)

Modify token deserialization to support reassembly:

```java
public static LTPAToken3 fromCookies(Map<String, String> cookies, LTPAHybridKeys keys) {
    String mainCookie = cookies.get("LtpaToken3");
    
    if (mainCookie == null) {
        throw new InvalidTokenException("LtpaToken3 cookie not found");
    }
    
    byte[] tokenBytes;
    
    // Check if this is a fragmented token
    if (cookies.containsKey("LtpaToken3_1")) {
        // Reassemble from fragments
        tokenBytes = LTPACookieSplitter.reassembleToken(cookies, "LtpaToken3");
    } else {
        // Single cookie (backward compatible)
        tokenBytes = Base64Coder.base64Decode(mainCookie);
    }
    
    return new LTPAToken3(tokenBytes, keys);
}
```

#### 4. HTTP Cookie Handler Integration

Update the web container integration to handle multiple cookies:

```java
// In LTPAAuthenticationMechanism or similar
public void setCookies(HttpServletResponse response, LTPAToken3 token) {
    Map<String, String> cookies = token.getCookies();
    
    for (Map.Entry<String, String> entry : cookies.entrySet()) {
        Cookie cookie = new Cookie(entry.getKey(), entry.getValue());
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(tokenExpiration);
        response.addCookie(cookie);
    }
}

public LTPAToken3 getTokenFromCookies(HttpServletRequest request) {
    Map<String, String> cookies = new HashMap<>();
    
    for (Cookie cookie : request.getCookies()) {
        if (cookie.getName().startsWith("LtpaToken3")) {
            cookies.put(cookie.getName(), cookie.getValue());
        }
    }
    
    return LTPAToken3.fromCookies(cookies, hybridKeys);
}
```

## Fragment Format Specification

### Main Cookie Format (LtpaToken3)

```
Byte Offset | Size | Description
------------|------|-------------
0           | 1    | Version (0x01)
1           | 1    | Fragment Count (1-255)
2-5         | 4    | Total Token Size (big-endian)
6-N         | Var  | First Fragment Data
```

### Fragment Cookie Format (LtpaToken3_N)

```
Byte Offset | Size | Description
------------|------|-------------
0-N         | Var  | Fragment Data
```

## Example Scenarios

### Scenario 1: Small Token (No Splitting)

```
Token Size: 2,000 bytes (Base64: 2,667 bytes)
Cookies:
  - LtpaToken3: [full token]
```

### Scenario 2: Large Token (Splitting Required)

```
Token Size: 3,530 bytes (Base64: 4,707 bytes)
Cookies:
  - LtpaToken3: [Version|Count:2|Size:3530|Fragment0:2994 bytes]
  - LtpaToken3_1: [Fragment1:536 bytes]
```

### Scenario 3: Very Large Token (ML-KEM-1024)

```
Token Size: 5,000 bytes (Base64: 6,667 bytes)
Cookies:
  - LtpaToken3: [Version|Count:3|Size:5000|Fragment0:2994 bytes]
  - LtpaToken3_1: [Fragment1:3000 bytes]
  - LtpaToken3_2: [Fragment2:1006 bytes]
```

## Security Considerations

1. **Fragment Integrity**: All fragments must be present for token validation
2. **Fragment Order**: Fragments must be reassembled in correct order
3. **Atomic Operations**: All fragments should be set/cleared together
4. **Replay Protection**: Existing token expiration and signature validation applies
5. **Fragment Tampering**: Any modification to fragments invalidates the entire token

## Performance Impact

- **Cookie Overhead**: Additional HTTP header size (~50 bytes per fragment)
- **Processing Time**: Minimal (<1ms for split/reassemble operations)
- **Network Impact**: Slightly larger HTTP headers (acceptable trade-off)

## Configuration Options

Add server.xml configuration for cookie splitting:

```xml
<ltpa 
    keysFileName="ltpa.keys"
    expiration="120m"
    cookieSplitting="auto|always|never"
    maxFragmentSize="3000" />
```

- **auto** (default): Split only when necessary
- **always**: Always split (for testing)
- **never**: Fail if token exceeds single cookie limit

## Testing Strategy

1. **Unit Tests**: Test split/reassemble logic with various token sizes
2. **Integration Tests**: Test cookie handling in web container
3. **Browser Tests**: Verify cookie limits across browsers
4. **Performance Tests**: Measure overhead of splitting
5. **Security Tests**: Verify fragment tampering detection

## Migration Path

1. **Phase 1**: Implement splitting logic (backward compatible)
2. **Phase 2**: Update web container integration
3. **Phase 3**: Add configuration options
4. **Phase 4**: Update documentation

## Browser Compatibility

| Browser | Cookie Size Limit | Fragment Support |
|---------|------------------|------------------|
| Chrome  | 4KB              | ✓ Yes            |
| Firefox | 4KB              | ✓ Yes            |
| Safari  | 4KB              | ✓ Yes            |
| Edge    | 4KB              | ✓ Yes            |
| IE11    | 4KB              | ✓ Yes            |

## Alternative Approaches Considered

### 1. Session Storage (Rejected)
- **Pros**: No cookie size limits
- **Cons**: Requires server-side state, breaks stateless design

### 2. URL Parameters (Rejected)
- **Pros**: No cookie limits
- **Cons**: Security risk (tokens in URLs), URL length limits

### 3. Custom Headers (Rejected)
- **Pros**: Larger size limits
- **Cons**: Not supported by all clients, breaks standard LTPA flow

### 4. Token Compression (Considered)
- **Pros**: Reduces token size
- **Cons**: Minimal benefit (PQC signatures are already compact), adds complexity

## Implementation Priority

1. **High Priority**: Core splitting/reassembly logic
2. **High Priority**: Web container integration
3. **Medium Priority**: Configuration options
4. **Low Priority**: Advanced features (compression, custom fragment sizes)

## Success Criteria

- ✓ LTPA3 tokens work across all major browsers
- ✓ No breaking changes to LTPA2 token handling
- ✓ Performance overhead < 5ms per request
- ✓ All security properties maintained
- ✓ Comprehensive test coverage

## Next Steps

1. Implement `LTPACookieSplitter` class
2. Update `LTPAToken3` to support cookie splitting
3. Modify web container integration
4. Add unit and integration tests
5. Update documentation