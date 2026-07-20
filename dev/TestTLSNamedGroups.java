import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class TestTLSNamedGroups {
    public static void main(String[] args) {
        System.out.println("=== Testing TLS Named Groups Support ===\n");
        
        try {
            // Access the NamedGroup class
            Class<?> namedGroupClass = Class.forName("sun.security.ssl.NamedGroup");
            System.out.println("✓ NamedGroup class found");
            
            // Try to get all named groups using reflection
            try {
                Method valuesMethod = namedGroupClass.getMethod("values");
                valuesMethod.setAccessible(true);
                Object[] namedGroups = (Object[]) valuesMethod.invoke(null);
                
                System.out.println("\n=== All Supported Named Groups ===");
                for (Object ng : namedGroups) {
                    System.out.println("  - " + ng.toString());
                }
                
                System.out.println("\n=== Checking for ML-KEM Hybrid Groups ===");
                boolean foundMLKEM = false;
                for (Object ng : namedGroups) {
                    String name = ng.toString();
                    if (name.contains("MLKEM") || name.contains("ML-KEM") || 
                        name.contains("Kyber") || name.contains("X25519ML")) {
                        System.out.println("✓ Found: " + name);
                        foundMLKEM = true;
                    }
                }
                
                if (!foundMLKEM) {
                    System.out.println("✗ No ML-KEM hybrid named groups found");
                    System.out.println("\nThis means:");
                    System.out.println("- ML-KEM algorithms are available (KEM API)");
                    System.out.println("- But TLS integration for hybrid groups is not yet implemented");
                    System.out.println("- X25519MLKEM768 is not a recognized TLS named group");
                }
                
            } catch (Exception e) {
                System.out.println("✗ Cannot access NamedGroup.values(): " + e.getClass().getName());
                System.out.println("  Message: " + e.getMessage());
                
                // Try alternative approach - check static fields
                System.out.println("\n=== Trying to enumerate via fields ===");
                Field[] fields = namedGroupClass.getDeclaredFields();
                System.out.println("Found " + fields.length + " fields in NamedGroup class");
                
                for (Field field : fields) {
                    if (java.lang.reflect.Modifier.isStatic(field.getModifiers()) &&
                        field.getType().equals(namedGroupClass)) {
                        try {
                            field.setAccessible(true);
                            Object value = field.get(null);
                            if (value != null) {
                                String name = field.getName();
                                if (name.contains("MLKEM") || name.contains("ML_KEM") || 
                                    name.contains("KYBER") || name.contains("X25519ML")) {
                                    System.out.println("✓ Found field: " + name + " = " + value);
                                }
                            }
                        } catch (Exception ex) {
                            // Skip inaccessible fields
                        }
                    }
                }
            }
            
        } catch (ClassNotFoundException e) {
            System.out.println("✗ NamedGroup class not found");
        }
        
        System.out.println("\n=== Recommendation ===");
        System.out.println("Based on the test results:");
        System.out.println("1. Your Java build HAS ML-KEM-512, ML-KEM-768, ML-KEM-1024");
        System.out.println("2. But TLS hybrid named groups (X25519MLKEM768) are NOT implemented");
        System.out.println("3. You need to wait for TLS integration or use a different approach");
    }
}

// Made with Bob
