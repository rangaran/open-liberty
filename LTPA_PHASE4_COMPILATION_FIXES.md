# Phase 4 Compilation Error Fixes

## Summary

Multiple compilation errors found across test files:
- **LTPAToken3Test.java**: Wrong constructor usage and API mismatches
- **Phase 3 test files**: Type mismatches (byte[] vs Key objects)
- **Missing methods**: In MLDSAAlgorithmType and PQCRuntimeSupport

## Error Categories

### 1. LTPAToken3Test.java Errors (35+ errors)

**Root Cause**: Test file uses wrong API - LTPAToken3 doesn't have a constructor that takes `(Map<String, Object>, long, LTPAHybridKeys)`.

**Actual LTPAToken3 Constructors**:
```java
// For validation
public LTPAToken3(byte[] tokenBytes, LTPAHybridKeys hybridKeys)

// For validation with attribute removal
public LTPAToken3(byte[] tokenBytes, LTPAHybridKeys hybridKeys, String... attributes)

// For creation (protected)
protected LTPAToken3(String accessID, long expirationInMinutes, LTPAHybridKeys hybridKeys)

// For cloning (protected)
protected LTPAToken3(long expirationInMinutes, LTPAHybridKeys hybridKeys, UserData userdata)
```

**Actual LTPAToken3 Methods**:
```java
// Get single attribute
String[] getAttributes(String name)

// Add attribute
String[] addAttribute(String name, String value)

// Get all attribute names
Enumeration<String> getAttributeNames()
```

**Fix Strategy**: Rewrite LTPAToken3Test.java to use LTPAToken3Factory for token creation and correct API for attribute access.

### 2. Phase 3 Test Files - Type Mismatch Errors

**Files Affected**:
- LTPAHybridKeysTest.java (20 errors)
- LTPAPQCSignatureTest.java (30+ errors)

**Root Cause**: Tests pass `keyPair.getPrivate().getEncoded()` (byte[]) but methods expect Key objects.

**Example Error**:
```java
// WRONG
LTPAPQCSignature.sign(data, keyPair.getPrivate().getEncoded(), algo);

// CORRECT
LTPAPQCSignature.sign(data, keyPair.getPrivate(), algo);
```

**Fix Strategy**: Remove `.getEncoded()` calls - pass Key objects directly.

### 3. Missing Methods in MLDSAAlgorithmType

**Errors**:
```
error: cannot find symbol: method getNistSecurityLevel()
error: cannot find symbol: method fromSecurityLevel(int)
```

**Fix Strategy**: Add these methods to MLDSAAlgorithmType enum.

### 4. Missing Method in PQCRuntimeSupport

**Error**:
```
error: cannot find symbol: method isPQCAvailable()
```

**Fix Strategy**: Add `isPQCAvailable()` method to PQCRuntimeSupport.

### 5. LTPAToken3 API Issues

**Error**:
```
error: setExpiration(long) has private access in LTPAToken3
```

**Fix Strategy**: Change `setExpiration()` visibility or remove test that calls it.

## Detailed Fix Plan

### Step 1: Fix LTPAHybridKeys Constructor Calls

**File**: `dev/com.ibm.ws.security.token.ltpa/test/com/ibm/ws/security/token/ltpa/pqc/LTPAHybridKeysTest.java`

**Changes**: Replace all instances of:
```java
rsaKeyPair.getPrivate()  // Remove .getEncoded()
rsaKeyPair.getPublic()   // Remove .getEncoded()
```

### Step 2: Fix LTPAPQCSignature Method Calls

**File**: `dev/com.ibm.ws.security.token.ltpa/test/com/ibm/ws/security/token/ltpa/pqc/LTPAPQCSignatureTest.java`

**Changes**: Replace all instances of:
```java
keyPair.getPrivate().getEncoded()  → keyPair.getPrivate()
keyPair.getPublic().getEncoded()   → keyPair.getPublic()
```

### Step 3: Add Missing Methods to MLDSAAlgorithmType

**File**: `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/pqc/MLDSAAlgorithmType.java`

**Add**:
```java
public int getNistSecurityLevel() {
    return this.securityLevel;
}

public static MLDSAAlgorithmType fromSecurityLevel(int level) {
    for (MLDSAAlgorithmType type : values()) {
        if (type.securityLevel == level) {
            return type;
        }
    }
    throw new IllegalArgumentException("No ML-DSA algorithm for security level: " + level);
}
```

### Step 4: Add isPQCAvailable() to PQCRuntimeSupport

**File**: `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/pqc/PQCRuntimeSupport.java`

**Add**:
```java
public static boolean isPQCAvailable() {
    return isMLKEMAvailable() && isMLDSAAvailable();
}
```

### Step 5: Completely Rewrite LTPAToken3Test.java

**File**: `dev/com.ibm.ws.security.token.ltpa/test/com/ibm/ws/security/token/ltpa/internal/LTPAToken3Test.java`

**Strategy**:
1. Use LTPAToken3Factory to create tokens (not direct constructor)
2. Use `getAttributes(String name)` to get individual attributes
3. Use `addAttribute(String name, String value)` to add attributes
4. Test token serialization/deserialization via `getBytes()` and constructor
5. Remove tests that access private methods

## Execution Order

1. Fix MLDSAAlgorithmType (add missing methods)
2. Fix PQCRuntimeSupport (add isPQCAvailable)
3. Fix LTPAHybridKeysTest (remove .getEncoded() calls)
4. Fix LTPAPQCSignatureTest (remove .getEncoded() calls)
5. Completely rewrite LTPAToken3Test.java

## Expected Outcome

After all fixes:
- All Phase 3 tests compile successfully
- LTPAToken3Test.java uses correct API
- All test files follow Liberty coding standards
- Ready to run unit tests

## Next Steps After Compilation

1. Run unit tests: `./gradlew com.ibm.ws.security.token.ltpa:test`
2. Fix any runtime failures
3. Create remaining Phase 4 tests (Factory, integration, performance)
4. Commit all Phase 4 test files