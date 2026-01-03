package com.ibm.ws.ssl.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lightweight security defaults for kernel boot. These defaults are applied
 * very early in the JVM startup to ensure a secure baseline before JSSE
 * providers and SSL contexts are initialized.
 */
public final class SecurityDefaults {

    private static final String PROPERTY = "jdk.tls.ephemeralDHKeySize";
    private static final int MIN_SIZE = 2048;
    // Ensure the check runs only once per JVM to avoid duplicate diagnostics
    private static final AtomicBoolean executed = new AtomicBoolean(false);

    /*
     * Ensure this logic always executes once the class is loaded,
     * independent of SSLSocketFactoryProxy usage.
     */
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
        // Run the body only once; subsequent invocations are no-ops
        if (!executed.compareAndSet(false, true)) {
            return;
        }

        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {

                String sysValue = System.getProperty(PROPERTY);
                String secValue = Security.getProperty(PROPERTY);

                if (sysValue != null && !sysValue.trim().isEmpty()) {
                    String v = sysValue.trim();

                    // Mirror JVM option into java.security for consistency
                    Security.setProperty(PROPERTY, v);

                    try {
                        int configured = Integer.parseInt(v);
                        if (configured < MIN_SIZE) {
                            System.out.println(PROPERTY + " (from JVM -D) is set to " + configured +
                                    ", which is below the recommended minimum of " + MIN_SIZE);
                        } else {
                            System.out.println(PROPERTY + " (from JVM -D) = " + configured);
                        }
                    } catch (NumberFormatException e) {
                        System.out.println(PROPERTY + " (from JVM -D) has a non-numeric value: '" + v + "'");
                    }

                } else if (secValue != null && !secValue.trim().isEmpty()) {
                    String v = secValue.trim();

                    try {
                        int configured = Integer.parseInt(v);
                        if (configured < MIN_SIZE) {
                            System.out.println(PROPERTY + " (from java.security) is set to " + configured +
                                    ", which is below the recommended minimum of " + MIN_SIZE);
                        } else {
                            System.out.println(PROPERTY + " (from java.security) = " + configured);
                        }
                    } catch (NumberFormatException e) {
                        System.out.println(PROPERTY + " (from java.security) has a non-numeric value: '" + v + "'");
                    }

                } else {
                    Security.setProperty(PROPERTY, String.valueOf(MIN_SIZE));
                    System.out.println(PROPERTY + " not found; setting secure default = " + MIN_SIZE);
                }

                return null;
            }
        });
    }
}
