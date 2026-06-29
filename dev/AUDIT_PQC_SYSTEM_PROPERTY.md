# Audit PQC System Property Configuration

## Overview
The Audit PQC implementation uses a system property to enable/disable Post-Quantum Cryptography support. This provides a simple way to control PQC usage without code changes.

## System Property

**Property Name:** `com.ibm.ws.security.audit.pqc.enabled`

**Values:**
- `true` - Enable PQC encryption and signing (requires Java 26+ and PQC keys)
- `false` - Use classical encryption and signing (default)

## Usage

### Enable PQC

Add to `jvm.options`:
```
-Dcom.ibm.ws.security.audit.pqc.enabled=true
```

Or set as environment variable:
```bash
export JAVA_OPTS="-Dcom.ibm.ws.security.audit.pqc.enabled=true"
```

### Disable PQC (Default)

No configuration needed - PQC is disabled by default.

Or explicitly disable:
```
-Dcom.ibm.ws.security.audit.pqc.enabled=false
```

## Behavior

### When PQC is Enabled (`true`)

The system checks three conditions:
1. ✅ System property is `true`
2. ✅ PQC keys are configured
3. ✅ Java 26+ runtime with ML-KEM support

**All three must be true** for PQC to be used.

If any condition fails:
- Logs a debug/warning message
- Falls back to classical encryption/signing
- Continues working normally

### When PQC is Disabled (`false` or not set)

- Uses classical RSA/AES encryption (existing behavior)
- No PQC code is executed
- Works on any Java version

## Examples

### Example 1: Enable PQC with All Requirements Met

```bash
# jvm.options
-Dcom.ibm.ws.security.audit.pqc.enabled=true
```

**Result:**
- ✅ System property: true
- ✅ Java 26+: available
- ✅ PQC keys: configured
- **Uses PQC encryption/signing**

### Example 2: Enable PQC but Java 17 Runtime

```bash
# jvm.options
-Dcom.ibm.ws.security.audit.pqc.enabled=true
```

**Result:**
- ✅ System property: true
- ❌ Java 26+: not available (running Java 17)
- ✅ PQC keys: configured
- **Falls back to classical encryption** (logs warning)

### Example 3: PQC Not Configured (Default)

```bash
# No system property set
```

**Result:**
- ❌ System property: false (default)
- **Uses classical encryption** (existing behavior)

## Code Usage

### Check if PQC is Enabled

```java
// In encryption implementation
AuditPQCEncryptionImpl encryption = new AuditPQCEncryptionImpl(...);
encryption.setPQCKeys(keys);

if (encryption.isPqcEnabled()) {
    // PQC is active
    byte[] encrypted = encryption.encryptPQC(data);
} else {
    // Classical encryption
    byte[] encrypted = encryption.encrypt(data);
}
```

### Check System Property Directly

```java
// Static check
boolean pqcProperty = AuditPQCEncryptionImpl.isPqcEnabledByProperty();
if (pqcProperty) {
    System.out.println("PQC is enabled via system property");
}
```

## Integration with AuditPQCManager

The `AuditPQCManager` automatically checks the system property:

```java
AuditPQCManager manager = new AuditPQCManager(...);
manager.configurePQC(keys);

// Automatically uses PQC if property is true, classical if false
byte[] encrypted = manager.encrypt(data);
```

## Logging

### Debug Logging

When `tc.isDebugEnabled()` is true, the implementation logs:

```
PQC disabled via system property: com.ibm.ws.security.audit.pqc.enabled=false
```

```
PQC system property enabled but keys not configured
```

```
PQC system property enabled but runtime not supported (Java 26+ required)
```

### Info Logging

When PQC is successfully enabled:
```
Audit PQC encryption enabled with ML-KEM-768
```

## Migration Path

### Phase 1: Testing (PQC Disabled)
```
# No system property - uses classical encryption
```

### Phase 2: Pilot (PQC Enabled for Testing)
```
-Dcom.ibm.ws.security.audit.pqc.enabled=true
# Test with PQC on Java 26+ environments
```

### Phase 3: Production (PQC Enabled)
```
-Dcom.ibm.ws.security.audit.pqc.enabled=true
# Roll out to production with Java 26+
```

### Phase 4: Rollback (If Needed)
```
-Dcom.ibm.ws.security.audit.pqc.enabled=false
# Immediately falls back to classical encryption
```

## Requirements

For PQC to be active, you need:

1. **System Property:** `-Dcom.ibm.ws.security.audit.pqc.enabled=true`
2. **Java Runtime:** Java 26 or later (JEP 478: Key Encapsulation Mechanism API)
3. **PQC Keys:** Generated and configured via `AuditPQCKeyGenerator`

## Troubleshooting

### PQC Not Working

**Check 1: System Property**
```bash
# Verify property is set
echo $JAVA_OPTS | grep "audit.pqc.enabled"
```

**Check 2: Java Version**
```bash
java -version
# Should show Java 26 or later
```

**Check 3: PQC Keys**
```java
// Verify keys are configured
if (pqcKeys != null && pqcKeys.hasMlkemKeys()) {
    System.out.println("PQC keys are configured");
}
```

**Check 4: Runtime Support**
```java
// Check if ML-KEM is available
if (PQCRuntimeSupport.isPQCSupported()) {
    System.out.println("ML-KEM support available");
}
```

### Logs Show "PQC disabled"

This is normal when:
- System property is not set (default behavior)
- System property is explicitly set to `false`
- Running on Java < 26
- PQC keys are not configured

## Summary

The system property provides a simple on/off switch for PQC:
- **Set to `true`**: Attempts to use PQC (requires Java 26+ and keys)
- **Set to `false` or not set**: Uses classical encryption (default)
- **Graceful fallback**: If PQC can't be used, falls back to classical automatically

This allows easy testing, rollout, and rollback of PQC functionality.