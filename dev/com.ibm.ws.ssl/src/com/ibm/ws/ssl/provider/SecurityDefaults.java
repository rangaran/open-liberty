package com.ibm.ws.ssl.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Security defaults for kernel boot.
 * Ensures a secure baseline before JSSE initializes.
 */
public final class SecurityDefaults {

    private static final String PROPERTY = "jdk.tls.ephemeralDHKeySize";
    private static final int MIN_SIZE = 2048;

    // Ensure this executes only once per JVM
    private static final AtomicBoolean executed = new AtomicBoolean(false);

    static {
        try {
            ensureDhKeySize();
        } catch (Throwable t) {
            // Diagnostics only — do not fail kernel startup
            t.printStackTrace();
        }
    }

    private SecurityDefaults() { /* utility */ }

    public static void ensureDhKeySize() {
        if (!executed.compareAndSet(false, true)) {
            return;
        }

        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {

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

            return null;
        });
    }
}
