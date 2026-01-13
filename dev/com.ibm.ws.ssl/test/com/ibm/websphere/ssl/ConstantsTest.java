/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.websphere.ssl;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.Test;

/**
 *
 */
public class ConstantsTest {
    /**
     * Array of cipher suites that contain patterns from DISALLOWED_CIPHER_SUITES.
     * These cipher suites are considered insecure and should not be used in production.
     * Organized by disallowed pattern type for reference.
     */
    private static String[] CIPHER_SUITES_NOT_ALLOWED = {
                                                          // _NULL_
                                                          "SSL_NULL_WITH_NULL_NULL",
                                                          "SSL_RSA_WITH_NULL_MD5",
                                                          "SSL_RSA_WITH_NULL_SHA",
                                                          "TLS_ECDH_ECDSA_WITH_NULL_SHA",
                                                          "TLS_ECDH_RSA_WITH_NULL_SHA",

                                                          // _RC4
                                                          "SSL_CK_RC4_128_WITH_MD5",
                                                          "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
                                                          "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
                                                          "SSL_RSA_WITH_RC4_128_MD5",
                                                          "SSL_RSA_WITH_RC4_128_SHA",
                                                          "SSL_DHE_DSS_WITH_RC4_128_SHA",
                                                          "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
                                                          "SSL_DH_anon_WITH_RC4_128_MD5",
                                                          "TLS_KRB5_WITH_RC4_128_SHA",
                                                          "TLS_KRB5_WITH_RC4_128_MD5",
                                                          "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
                                                          "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",

                                                          // _EXPORT_
                                                          "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
                                                          "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
                                                          "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
                                                          "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
                                                          "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
                                                          "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
                                                          "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",

                                                          // _3DES_
                                                          "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
                                                          "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                                                          "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA",
                                                          "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA",
                                                          "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                                                          "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                                                          "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
                                                          "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
                                                          "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
                                                          "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
                                                          "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",

                                                          // _FIPS_
                                                          "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",

                                                          // _KRB5_
                                                          "TLS_KRB5_WITH_DES_CBC_SHA",
                                                          "TLS_KRB5_WITH_DES_CBC_MD5",

                                                          // _ECDH_
                                                          "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
                                                          "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
                                                          "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
                                                          "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
                                                          "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
                                                          "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
                                                          "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
                                                          "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",

                                                          // _anon_
                                                          "SSL_DH_anon_WITH_DES_CBC_SHA",
                                                          "SSL_DH_anon_WITH_AES_128_CBC_SHA",
                                                          "SSL_DH_anon_WITH_AES_256_CBC_SHA"
    };
    private static String[] CIPHER_SUITES_ALLOWED = new String[] { "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
                                                                   "SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                                                   "SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                                   "SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                                                   "SSL_DHE_RSA_WITH_AES_256_GCM_SHA384", "SSL_DHE_DSS_WITH_AES_256_GCM_SHA384",
                                                                   "SSL_DHE_RSA_WITH_AES_128_GCM_SHA256",
                                                                   "SSL_DHE_DSS_WITH_AES_128_GCM_SHA256", "SSL_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                                                                   "SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                                                                   "SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                                                   "SSL_DHE_RSA_WITH_AES_256_CBC_SHA256",
                                                                   "SSL_DHE_DSS_WITH_AES_256_CBC_SHA256", "SSL_DHE_RSA_WITH_AES_128_CBC_SHA256",
                                                                   "SSL_DHE_DSS_WITH_AES_128_CBC_SHA256",
                                                                   "SSL_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                                                                   "SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                                                                   "SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA", "SSL_DHE_RSA_WITH_AES_256_CBC_SHA", "SSL_DHE_DSS_WITH_AES_256_CBC_SHA",
                                                                   "SSL_DHE_RSA_WITH_AES_128_CBC_SHA", "SSL_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                                   "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                                                                   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                                                                   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" }; // ECDHE for key exchange, RSA for authentication.

    private static String[] CIPHER_SUITES_NOT_ALLOWED_AND_ALLOWED = Stream.concat(Stream.of(CIPHER_SUITES_NOT_ALLOWED), Stream.of(CIPHER_SUITES_ALLOWED)).toArray(String[]::new);

    /**
     * Test method for {@link com.ibm.websphere.ssl.Constants#adjustSupportedCiphersToSecurityLevel(java.lang.String[], java.lang.String)}.
     *
     * This test ensures that the output from {@link Constants#SECURITY_LEVEL_LOW} invocations match any other level since the concept of securityLevels is being removed.
     * A default list is returned with ciphers considered safe and modern ciphers.
     */
    @Test
    public void testAdjustSupportedCiphersToSecurityLevel() {
        for (String[] ciphers : Arrays.asList(CIPHER_SUITES_ALLOWED, CIPHER_SUITES_NOT_ALLOWED, CIPHER_SUITES_NOT_ALLOWED_AND_ALLOWED)) {
            for (String level : Arrays.asList(Constants.SECURITY_LEVEL_MEDIUM, Constants.SECURITY_LEVEL_HIGH, Constants.SECURITY_LEVEL_CUSTOM)) {
                assertEquals("All security levels should return the same value",
                             adjustSupportedCiphersToSecurityLevelHelper(ciphers, Constants.SECURITY_LEVEL_LOW),
                             adjustSupportedCiphersToSecurityLevelHelper(ciphers, level));
            }
        }
    }

    /**
     * Test method for {@link com.ibm.websphere.ssl.Constants#adjustSupportedCiphers(java.lang.String[])}.
     * Test logic ensures all not allowed ciphers are filtered, all allowed ciphers are not filtered and a
     * mix of the two results in a list with only allowed ciphers.
     */
    @Test
    public void testAdjustSupportedCiphers() {

        assertEquals("No Ciphers should be returned", Arrays.asList(),
                     Arrays.asList(Constants.adjustSupportedCiphers(CIPHER_SUITES_NOT_ALLOWED)));

        assertEquals("All allowed ciphers should be returned", Arrays.asList(CIPHER_SUITES_ALLOWED),
                     Arrays.asList(Constants.adjustSupportedCiphers(CIPHER_SUITES_ALLOWED)));

        assertEquals("Only allowed ciphers should be returned", Arrays.asList(CIPHER_SUITES_ALLOWED),
                     Arrays.asList(Constants.adjustSupportedCiphers(CIPHER_SUITES_NOT_ALLOWED_AND_ALLOWED)));
    }

    private List<String> adjustSupportedCiphersToSecurityLevelHelper(String[] ciphers, String securityLevel) {
        return Arrays.asList(Constants.adjustSupportedCiphersToSecurityLevel(ciphers, securityLevel));
    }

}
