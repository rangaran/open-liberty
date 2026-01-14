/*******************************************************************************
 * Copyright (c) 2011, 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.ssl.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.ws.ssl.config.SSLConfigManager;

import test.common.SharedOutputManager;

/**
 * Test for ensureDhKeySize() and runtime DH cipher suite detection
 */
public class SSLConfigManagerTest {

    private static SharedOutputManager outputMgr;
    private static final String DHKEYSIZE_PROP = "jdk.tls.ephemeralDHKeySize";

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr = SharedOutputManager.getInstance();
        outputMgr.captureStreams();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        outputMgr.restoreStreams();
    }

    @After
    public void tearDown() {
        // Clear the property after each test
        System.clearProperty(DHKEYSIZE_PROP);
        outputMgr.resetStreams();
        // Reset the DH key size flags so each test starts fresh
        SSLConfigManager.getInstance().resetDhKeySizeFlags();
    }

    @Test
    public void testPropertyNotSetEnablesRuntimeMonitoring() {
        // Clear any existing property
        System.clearProperty(DHKEYSIZE_PROP);
        
        // Call the method
        SSLConfigManager mgr = SSLConfigManager.getInstance();
        mgr.ensureDhKeySize();
        
        // Verify the property was NOT set (we don't default it)
        String dhKeySize = System.getProperty(DHKEYSIZE_PROP);
        assertTrue("DH key size property should NOT be set when not configured",
                   dhKeySize == null || dhKeySize.isEmpty());
        
        // Verify runtime monitoring is enabled
        assertFalse("Runtime monitoring should be enabled when property not set",
                    mgr.isDhKeySizePropertySet());
    }

    /**
     * KEY TEST: Runtime detection of weak DH cipher suite when property is NOT set
     * This tests the scenario where no property is configured and a legacy system
     * negotiates a weak DH cipher suite (< 2048 bits like 1024-bit DES).
     */
    @Test
    public void testRuntimeDetectionOfWeakDHCipherSuiteWhenPropertyNotSet() {
        // Clear property to simulate it not being set
        System.clearProperty(DHKEYSIZE_PROP);
        
        SSLConfigManager mgr = SSLConfigManager.getInstance();
        mgr.ensureDhKeySize();
        
        // Verify property was NOT set (we don't default it)
        String dhKeySize = System.getProperty(DHKEYSIZE_PROP);
        assertTrue("DH key size property should NOT be set",
                   dhKeySize == null || dhKeySize.isEmpty());
        
        // Verify that runtime monitoring is enabled (property was not set by user)
        assertFalse("Runtime monitoring should be enabled when property not set",
                    mgr.isDhKeySizePropertySet());
        
        // Simulate a weak DH cipher suite being negotiated (1024-bit DES)
        outputMgr.resetStreams();
        mgr.checkDHCipherSuite("TLS_DHE_RSA_WITH_DES_CBC_SHA");
        
        // Verify warning was logged for weak DH cipher suite
        assertTrue("Should log warning for weak DH cipher suite",
                   outputMgr.checkForMessages("Weak DH cipher suite detected"));
    }

    @Test
    public void testRuntimeDetectionOfVariousWeakDHCipherSuites() {
        // Clear property
        System.clearProperty(DHKEYSIZE_PROP);
        
        SSLConfigManager mgr = SSLConfigManager.getInstance();
        mgr.ensureDhKeySize();
        
        // Test various weak cipher suites that use DH < 2048
        String[] weakCiphers = {
            "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",  // EXPORT (512-bit)
            "TLS_DH_anon_WITH_AES_128_CBC_SHA",        // anon (weak)
            "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",       // 3DES (1024-bit)
            "TLS_DH_RSA_WITH_DES_CBC_SHA",             // DES (1024-bit)
            "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA"         // Legacy SSL_DH_ (weak)
        };
        
        // Warning should only be logged once (for the first weak cipher detected)
        outputMgr.resetStreams();
        for (int i = 0; i < weakCiphers.length; i++) {
            mgr.checkDHCipherSuite(weakCiphers[i]);
            if (i == 0) {
                // First weak cipher should trigger warning
                assertTrue("Should log warning for first weak cipher: " + weakCiphers[i],
                           outputMgr.checkForMessages("Weak DH cipher suite detected"));
            }
        }
        
        // Verify warning was only logged once (not for subsequent weak ciphers)
        outputMgr.resetStreams();
        mgr.checkDHCipherSuite("TLS_DHE_RSA_WITH_DES_CBC_SHA");
        assertFalse("Should NOT log warning again for subsequent weak cipher",
                    outputMgr.checkForMessages("Weak DH cipher suite detected"));
    }

    @Test
    public void testNoRuntimeDetectionWhenPropertyExplicitlySet() {
        // Set property explicitly (even to a weak value)
        System.setProperty(DHKEYSIZE_PROP, "1024");
        
        SSLConfigManager mgr = SSLConfigManager.getInstance();
        mgr.ensureDhKeySize();
        
        // Verify runtime monitoring is NOT enabled (property was set by user)
        assertTrue("Runtime monitoring should NOT be enabled when property is set",
                   mgr.isDhKeySizePropertySet());
        
        // Simulate a weak DH cipher suite being negotiated
        outputMgr.resetStreams();
        mgr.checkDHCipherSuite("TLS_DHE_RSA_WITH_DES_CBC_SHA");
        
        // Verify NO warning from runtime detection (user explicitly set property)
        assertFalse("Should NOT perform runtime detection when property is set",
                    outputMgr.checkForMessages("Weak DH cipher suite detected"));
    }

}

