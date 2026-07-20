import javax.crypto.KEM;
import java.security.Security;
import java.security.Provider;
import java.util.Set;

public class TestKEMAndTLS {
    public static void main(String[] args) {
        System.out.println("=== Testing KEM and TLS ML-KEM Support ===\n");
        System.out.println("Java Version: " + System.getProperty("java.version"));
        System.out.println("Java Vendor: " + System.getProperty("java.vendor"));
        System.out.println();
        
        // Test 1: Check if KEM class exists
        try {
            Class<?> kemClass = Class.forName("javax.crypto.KEM");
            System.out.println("✓ javax.crypto.KEM class is available");
            System.out.println("  Class: " + kemClass.getName());
        } catch (ClassNotFoundException e) {
            System.out.println("✗ javax.crypto.KEM class NOT found");
        }
        System.out.println();
        
        // Test 2: List all KEM algorithms from all providers
        System.out.println("=== Available KEM Algorithms ===");
        boolean foundKEM = false;
        for (Provider provider : Security.getProviders()) {
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                if ("KEM".equals(service.getType())) {
                    System.out.println("Provider: " + provider.getName());
                    System.out.println("  Algorithm: " + service.getAlgorithm());
                    System.out.println("  Class: " + service.getClassName());
                    foundKEM = true;
                }
            }
        }
        if (!foundKEM) {
            System.out.println("No KEM algorithms found in any provider");
        }
        System.out.println();
        
        // Test 3: Check for ML-KEM specific algorithms
        System.out.println("=== Checking for ML-KEM Algorithms ===");
        String[] mlkemAlgorithms = {
            "ML-KEM-512", "MLKEM512", "ML-KEM512",
            "ML-KEM-768", "MLKEM768", "ML-KEM768",
            "ML-KEM-1024", "MLKEM1024", "ML-KEM1024",
            "Kyber512", "Kyber768", "Kyber1024"
        };
        
        for (String algo : mlkemAlgorithms) {
            try {
                KEM kem = KEM.getInstance(algo);
                System.out.println("✓ " + algo + " is available");
            } catch (Exception e) {
                System.out.println("✗ " + algo + " not available: " + e.getMessage());
            }
        }
        System.out.println();
        
        // Test 4: Check TLS-related properties
        System.out.println("=== TLS Configuration ===");
        String namedGroups = System.getProperty("jdk.tls.namedGroups", "(not set)");
        System.out.println("jdk.tls.namedGroups: " + namedGroups);
        
        // Test 5: Try to access NamedGroup with module access
        System.out.println();
        System.out.println("=== Checking TLS NamedGroup Support ===");
        try {
            // This will fail due to module restrictions, but we can try
            Class<?> namedGroupClass = Class.forName("sun.security.ssl.NamedGroup");
            System.out.println("NamedGroup class found (but may not be accessible)");
        } catch (Exception e) {
            System.out.println("Cannot access NamedGroup: " + e.getMessage());
        }
        
        System.out.println();
        System.out.println("=== Analysis ===");
        System.out.println("If KEM API exists but no ML-KEM algorithms are available,");
        System.out.println("it means the KEM API framework is present but ML-KEM");
        System.out.println("implementations are not included in this Java build.");
        System.out.println();
        System.out.println("For TLS to use ML-KEM, you need:");
        System.out.println("1. KEM API (javax.crypto.KEM) - Present");
        System.out.println("2. ML-KEM algorithm implementations - Check above");
        System.out.println("3. TLS integration (NamedGroup support) - Check above");
    }
}

// Made with Bob
