import java.security.*;
import javax.crypto.*;

public class TestMLKEM {
    public static void main(String[] args) {
        System.out.println("Java Version: " + System.getProperty("java.version"));
        
        // Test 1: Check if KEM class exists
        try {
            Class<?> kemClass = Class.forName("javax.crypto.KEM");
            System.out.println("✓ javax.crypto.KEM found");
        } catch (ClassNotFoundException e) {
            System.out.println("✗ javax.crypto.KEM not found: " + e.getMessage());
        }
        
        // Test 2: Check if MLKEMParameterSpec exists
        try {
            Class<?> paramSpec = Class.forName("java.security.spec.MLKEMParameterSpec");
            System.out.println("✓ java.security.spec.MLKEMParameterSpec found");
        } catch (ClassNotFoundException e) {
            System.out.println("✗ java.security.spec.MLKEMParameterSpec not found: " + e.getMessage());
        }
        
        // Test 3: Check if SecretKeyWithEncapsulation exists
        try {
            Class<?> secretKey = Class.forName("javax.crypto.SecretKeyWithEncapsulation");
            System.out.println("✓ javax.crypto.SecretKeyWithEncapsulation found");
        } catch (ClassNotFoundException e) {
            System.out.println("✗ javax.crypto.SecretKeyWithEncapsulation not found: " + e.getMessage());
        }
        
        // Test 4: Try to generate ML-KEM key pair
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
            System.out.println("✓ ML-KEM KeyPairGenerator available");
            System.out.println("  Provider: " + kpg.getProvider().getName());
        } catch (Exception e) {
            System.out.println("✗ ML-KEM KeyPairGenerator not available: " + e.getMessage());
        }
        
        // Test 5: Try to get KEM instance
        try {
            Class<?> kemClass = Class.forName("javax.crypto.KEM");
            java.lang.reflect.Method getInstance = kemClass.getMethod("getInstance", String.class);
            Object kem = getInstance.invoke(null, "ML-KEM");
            System.out.println("✓ KEM.getInstance(\"ML-KEM\") successful");
        } catch (Exception e) {
            System.out.println("✗ KEM.getInstance(\"ML-KEM\") failed: " + e.getMessage());
        }
    }
}

// Made with Bob
