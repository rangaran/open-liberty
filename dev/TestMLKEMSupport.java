import javax.net.ssl.SSLContext;
import java.security.Security;
import java.util.Arrays;

public class TestMLKEMSupport {
    public static void main(String[] args) {
        System.out.println("Testing ML-KEM/PQC Support in Java");
        System.out.println("Java Version: " + System.getProperty("java.version"));
        System.out.println("Java Vendor: " + System.getProperty("java.vendor"));
        System.out.println();
        
        // Check security providers
        System.out.println("Security Providers:");
        Arrays.stream(Security.getProviders())
            .forEach(p -> System.out.println("  - " + p.getName() + " v" + p.getVersion()));
        System.out.println();
        
        // Try to check for ML-KEM support
        try {
            Class<?> namedGroupClass = Class.forName("sun.security.ssl.NamedGroup");
            System.out.println("NamedGroup class found: " + namedGroupClass.getName());
            
            // Try to get supported groups
            try {
                Object[] values = (Object[]) namedGroupClass.getMethod("values").invoke(null);
                System.out.println("\nSupported Named Groups:");
                for (Object ng : values) {
                    System.out.println("  - " + ng.toString());
                }
            } catch (Exception e) {
                System.out.println("Could not enumerate named groups: " + e.getMessage());
            }
        } catch (ClassNotFoundException e) {
            System.out.println("NamedGroup class not found (internal API)");
        }
        
        // Check if X25519MLKEM768 is mentioned anywhere
        System.out.println("\nChecking for ML-KEM support...");
        String testProperty = System.getProperty("jdk.tls.namedGroups", "");
        System.out.println("Current jdk.tls.namedGroups: " + (testProperty.isEmpty() ? "(not set)" : testProperty));
    }
}

// Made with Bob
