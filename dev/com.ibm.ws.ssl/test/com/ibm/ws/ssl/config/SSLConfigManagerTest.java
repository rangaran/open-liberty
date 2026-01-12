/*******************************************************************************
 * Copyright (c) 2011 IBM Corporation and others.
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
import static org.junit.Assert.assertNotNull;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.ws.ssl.config.SSLConfigManager;

import test.common.SharedOutputManager;

/**
 * Test for ensureDhKeySize()
 */
public class SSLConfigManagerTest {

    private static SharedOutputManager outputMgr;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr = SharedOutputManager.getInstance();
        outputMgr.captureStreams();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        outputMgr.restoreStreams();
    }

    @Test
    public void defaultDHKeySizeSetByEnsureDhKeySize() {
        // Call the method to ensure DH key size is set
        SSLConfigManager mgr = SSLConfigManager.getInstance();
        mgr.ensureDhKeySize();
        
        // Verify the property was set to the secure default
        String dhKeySize = System.getProperty("jdk.tls.ephemeralDHKeySize");
        assertNotNull("DH key size should be set", dhKeySize);
        assertEquals("DH key size should be 2048", "2048", dhKeySize);
    }

}

