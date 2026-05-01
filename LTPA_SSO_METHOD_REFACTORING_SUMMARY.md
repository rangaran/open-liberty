# LTPA SSO Method Refactoring Summary

## Overview

Comprehensive refactoring of SSO cookie handling methods to eliminate code duplication and improve maintainability across JWT and LTPA token processing.

**Date:** 2026-04-30  
**Branch:** bob-pqc-ltpa  

## Changes Made

### 1. Renamed Method: `getJwtSsoTokenFromCookies` → `getSsoTokenFromCookies`

**Rationale:** The method is generic and works for any SSO token type (JWT, LTPA, etc.), not just JWT tokens. The new name better reflects its purpose.

**Files Modified:**
- `SSOCookieHelper.java` (interface)
- `SSOCookieHelperImpl.java` (implementation)
- `SSOAuthenticator.java` (usage)

#### Interface Changes (`SSOCookieHelper.java`)

**Added:**
```java
/**
 * Retrieves and reassembles an SSO token from cookies.
 * Handles both single cookies and fragmented cookies for large tokens (e.g., LTPA3 with PQC).
 * 
 * @param req The HTTP servlet request
 * @param cookieName The base cookie name (e.g., "LtpaToken2", "JWT")
 * @return The reassembled token string, or null if no cookies found
 */
String getSsoTokenFromCookies(HttpServletRequest req, String cookieName);
```

**Deprecated (for backward compatibility):**
```java
/**
 * @deprecated Use {@link #getSsoTokenFromCookies(HttpServletRequest, String)} instead.
 */
@Deprecated
String getJwtSsoTokenFromCookies(HttpServletRequest req, String jwtCookieName);
```

#### Implementation Changes (`SSOCookieHelperImpl.java`)

**New Method with Enhanced Documentation:**
```java
/**
 * Retrieves and reassembles an SSO token from cookies.
 * This method handles both single cookies and fragmented cookies (e.g., for large tokens).
 * 
 * Fragmented cookies follow the naming pattern:
 * - Base cookie: {baseName} (e.g., "LtpaToken2" or "JWT")
 * - Fragment 2: {baseName}02 (e.g., "LtpaToken202" or "JWT02")
 * - Fragment 3: {baseName}03 (e.g., "LtpaToken203" or "JWT03")
 * - ...
 * - Fragment 99: {baseName}99 (e.g., "LtpaToken299" or "JWT99")
 * 
 * This is particularly important for LTPA Token Version 3 with Post-Quantum Cryptography,
 * which can exceed single cookie size limits (4KB).
 * 
 * @param req The HTTP servlet request containing the cookies
 * @param baseName The base name of the cookie (e.g., "LtpaToken2", "JWT")
 * @return The reassembled token string, or null if no cookies found
 */
@Override
public String getSsoTokenFromCookies(HttpServletRequest req, String baseName) {
    // Implementation (unchanged logic, just renamed)
}
```

**Deprecated Method (delegates to new method):**
```java
/**
 * @deprecated Use {@link #getSsoTokenFromCookies(HttpServletRequest, String)} instead.
 * This method is retained for backward compatibility.
 */
@Deprecated
@Override
public String getJwtSsoTokenFromCookies(HttpServletRequest req, String baseName) {
    return getSsoTokenFromCookies(req, baseName);
}
```

**Updated Internal References:**
- Line 91: `getSsoTokenFromCookies(req, getJwtCookieName())`
- Line 307: `getSsoTokenFromCookies(req, jwtCookieName)`

### 2. Refactored `handleLtpaSSO` Method

**File:** `SSOAuthenticator.java`

**Before (77 lines):**
```java
private AuthenticationResult handleLtpaSSO(HttpServletRequest req, HttpServletResponse res, Cookie[] cookies) {
    // Custom fragmented cookie handling using CookieHelper.getFragmentedCookies()
    java.util.Map<String, String> fragmentedCookies = CookieHelper.getFragmentedCookies(cookies, cookieName);
    if (fragmentedCookies != null && fragmentedCookies.size() > 1) {
        // Manual reassembly logic
        StringBuilder reassembledToken = new StringBuilder();
        for (String fragmentValue : fragmentedCookies.values()) {
            reassembledToken.append(fragmentValue);
        }
        // ... authentication logic
    }
    
    // Fall back to standard cookie handling
    String[] hdrVals = CookieHelper.getCookieValues(cookies, cookieName);
    // ... more logic
}
```

**After (43 lines - 44% reduction):**
```java
private AuthenticationResult handleLtpaSSO(HttpServletRequest req, HttpServletResponse res, Cookie[] cookies) {
    String cookieName = ssoCookieHelper.getSSOCookiename();
    
    // Use the common method to retrieve and reassemble LTPA token from cookies
    // This handles both single cookies and fragmented LTPA3 tokens (Post-Quantum Cryptography)
    // Note: Token format varies by version:
    //   - LTPA2: Base64-encoded
    //   - LTPA3: Hex-encoded binary (PQC)
    String ltpaToken = ssoCookieHelper.getSsoTokenFromCookies(req, cookieName);
    
    // Fall back to default cookie name if custom cookie name yields no results
    boolean useOnlyCustomCookieName = webAppSecurityConfig != null && webAppSecurityConfig.isUseOnlyCustomCookieName();
    if (ltpaToken == null && !DEFAULT_SSO_COOKIE_NAME.equalsIgnoreCase(cookieName) && !useOnlyCustomCookieName) {
        ltpaToken = ssoCookieHelper.getSsoTokenFromCookies(req, DEFAULT_SSO_COOKIE_NAME);
    }
    
    if (ltpaToken != null && ltpaToken.length() > 0) {
        // ... authentication logic (unchanged)
    }
    
    return authResult;
}
```

**Variable Naming Improvement:**
- Changed `ltpa64` → `ltpaToken` to accurately reflect that LTPA3 tokens are hex-encoded (not base64)
- Added comment clarifying encoding differences between LTPA2 and LTPA3

**Updated `handleJwtSSO` Method:**
- Line 248: Changed from `getJwtSsoTokenFromCookies` to `getSsoTokenFromCookies`

### 3. Cookie Chunking Refactoring (Previous Change)

**File:** `SSOCookieHelperImpl.java`

Created common method `addSsoCookiesWithChunking()` to eliminate duplication between:
- `addJwtCookies()` - 59% code reduction
- `addLtpaSsoCookiesToResponse()` - 51% code reduction

## Benefits

### 1. Consistent Naming
- Method name now accurately reflects its generic purpose
- Works for JWT, LTPA, and any future SSO token types

### 2. Code Reusability
- Single implementation for cookie reassembly logic
- Used by both JWT and LTPA authentication flows

### 3. Maintainability
- Bug fixes and enhancements in one place
- Consistent behavior across all token types

### 4. Reduced Code Duplication
- **handleLtpaSSO:** 77 → 43 lines (44% reduction)
- Eliminated custom fragmented cookie handling
- Eliminated manual reassembly logic

### 5. Improved Readability
- Clear separation of concerns
- Well-documented methods with comprehensive JavaDoc
- Simplified authentication flow

### 6. PQC Support
- Seamlessly handles large LTPA3 tokens with Post-Quantum Cryptography
- Automatic fragmentation and reassembly
- No special handling required in authentication code

## Backward Compatibility

✅ **Fully backward compatible:**
- Old method `getJwtSsoTokenFromCookies()` marked as `@Deprecated`
- Old method delegates to new method
- No breaking changes to external APIs
- Existing code continues to work

## Migration Path

### For New Code
Use the new generic method:
```java
String token = ssoCookieHelper.getSsoTokenFromCookies(req, cookieName);
```

### For Existing Code
No immediate changes required. The deprecated method will continue to work:
```java
String token = ssoCookieHelper.getJwtSsoTokenFromCookies(req, jwtCookieName);
```

### Future Deprecation
In a future release, consider:
1. Adding compiler warnings for deprecated method usage
2. Updating all internal references to use new method
3. Eventually removing the deprecated method

## Testing Recommendations

### Unit Tests

1. **Test getSsoTokenFromCookies with various token types:**
   - JWT tokens
   - LTPA2 tokens
   - LTPA3 tokens (PQC)

2. **Test cookie reassembly:**
   - Single cookie (< 3900 bytes)
   - Multiple cookies (fragmented)
   - Missing fragments (error handling)

3. **Test backward compatibility:**
   - Verify deprecated method still works
   - Verify it delegates to new method

### Integration Tests

1. **Test LTPA authentication with fragmented cookies**
2. **Test JWT authentication with fragmented cookies**
3. **Test fallback to default cookie name**
4. **Test logged-out token tracking**

## Performance Impact

**Positive Impact:**
- Reduced code duplication improves maintainability
- Single implementation reduces potential for bugs
- No performance degradation (same logic, better organized)

## Files Modified

| File | Lines Changed | Description |
|------|---------------|-------------|
| `SSOCookieHelper.java` | +14, -1 | Added new method, deprecated old |
| `SSOCookieHelperImpl.java` | +35, -3 | Implemented new method, updated references |
| `SSOAuthenticator.java` | +43, -77 | Refactored handleLtpaSSO, updated handleJwtSSO |

**Net Change:** +92 lines added, -81 lines removed = +11 lines (mostly documentation)

## Related Refactorings

This refactoring builds on the previous cookie-chunking refactoring:
- `addSsoCookiesWithChunking()` - Common method for adding fragmented cookies
- `getSsoTokenFromCookies()` - Common method for retrieving fragmented cookies

Together, these provide a complete, consistent API for handling large SSO tokens.

## Commit Message

```
Refactor: Rename getJwtSsoTokenFromCookies to getSsoTokenFromCookies

- Renamed method to reflect its generic purpose (works for JWT, LTPA, etc.)
- Deprecated old method for backward compatibility
- Refactored handleLtpaSSO to use common cookie retrieval method
- Eliminated custom fragmented cookie handling (44% code reduction)
- Updated handleJwtSSO to use new method name
- Added comprehensive JavaDoc documentation
- No functional changes - fully backward compatible

This refactoring improves code reusability and makes it easier to support
large tokens such as LTPA Token Version 3 with Post-Quantum Cryptography.

Related to previous refactoring of addSsoCookiesWithChunking method.

Co-authored-by-AI: IBM Bob 1.0.0 (Claude Sonnet 4.6)
```

## References

- [SSOCookieHelper.java](dev/com.ibm.ws.webcontainer.security/src/com/ibm/ws/webcontainer/security/SSOCookieHelper.java)
- [SSOCookieHelperImpl.java](dev/com.ibm.ws.webcontainer.security/src/com/ibm/ws/webcontainer/security/SSOCookieHelperImpl.java)
- [SSOAuthenticator.java](dev/com.ibm.ws.webcontainer.security/src/com/ibm/ws/webcontainer/security/internal/SSOAuthenticator.java)
- [LTPA Cookie Refactoring Summary](LTPA_COOKIE_REFACTORING_SUMMARY.md)

---

**Created with IBM Bob** - SSO Method Refactoring for LTPA PQC Support