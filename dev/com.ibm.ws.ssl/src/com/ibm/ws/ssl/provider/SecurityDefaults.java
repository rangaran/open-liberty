package com.ibm.ws.ssl.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Security defaults for kernel boot.
 * Ensures a secure baseline before JSSE initializes.
 */
public final class SecurityDefaults {

    private static final String PROPERTY = "jdk.tls.ephemeralDHKeySize";
    private static final int MIN_SIZE = 2048;

    static {
        // Ensure this executes only once per JVM via static initialization
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            try {
                String value = System.getProperty(PROPERTY);

                // User explicitly configured the property
                if (value != null && !value.trim().isEmpty()) {
                    String v = value.trim();
                    try {
                        int configured = Integer.parseInt(v);
                        if (configured < MIN_SIZE) {
                            System.out.println(
                                "WARNING: " + PROPERTY + " is set to " + configured +
                                ", which is below the required minimum of " + MIN_SIZE
                            );
                        } else {
                            System.out.println(PROPERTY + " = " + configured);
                        }
                    } catch (NumberFormatException e) {
                        System.out.println(
                            "WARNING: " + PROPERTY + " has a non-numeric value: '" + v + "'"
                        );
                    }
                    return null;
                }

                // Property not set - enforce secure default
                System.setProperty(PROPERTY, String.valueOf(MIN_SIZE));
                System.out.println(
                    PROPERTY + " not set; defaulting to secure minimum of " + MIN_SIZE
                );
            } catch (Throwable t) {
                // Diagnostics only — do not fail kernel startup
                t.printStackTrace();
            }
            return null;
        });
    }

    private SecurityDefaults() { /* utility */ }

    /**
     * Trigger class initialization to ensure DH key size is set.
     * The actual work is done in the static initializer.
     */
    public static void ensureDhKeySize() {
        // Method body intentionally empty - static initializer does the work
    }
}
