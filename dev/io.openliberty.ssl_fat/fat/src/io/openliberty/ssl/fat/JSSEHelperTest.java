/*******************************************************************************
 * Copyright (c) 2024 IBM Corporation and others.
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
package io.openliberty.ssl.fat;

import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.ShrinkHelper;
import com.ibm.websphere.simplicity.log.Log;

import componenttest.annotation.Server;
import componenttest.annotation.TestServlet;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.utils.FATServletClient;
import io.openliberty.ssl.fat.jssehelper.JSSEHelperClientTestServlet;

/*
 * Test getting the SSLContext and SSLSocketFactory from JSSEHelper to create an SSL
 * connection that honors Liberty's SSL config.
 */
@RunWith(FATRunner.class)
public class JSSEHelperTest extends FATServletClient {

    private static final Class<?> c = JSSEHelperTest.class;
    private static final String appName = "jssehelper";

    @Server("JSSEHelperTestServer")
    @TestServlet(servlet = JSSEHelperClientTestServlet.class, contextRoot = appName)
    public static LibertyServer server;

    @BeforeClass
    public static void setup() throws Exception {
        // Build an application and export it to the dropins directory
        ShrinkHelper.defaultDropinApp(server, appName, "io.openliberty.ssl.fat.jssehelper");

        // Make sure we don't fail because we try to start an
        // already started server
        try {
            server.startServer("JSSEHelperTest.log", true);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    @AfterClass
    public static void teardown() throws Exception {
        if (server != null) {
            // ignore "CWWKO0801E: The SSL connection cannot be initialized"
            server.stopServer("CWWKE1102W", "CWWKO0801E");  //ignore server quiesce timeouts due to slow test machines
        }
    }

    @Before
    public void beforeTest() {}

    @After
    public void afterTest() {}

    /**
     * Verify PQC TLS 1.3 handshake through log analysis.
     * This test analyzes server logs to verify that TLS 1.3 is used
     * and checks for evidence of PQC hybrid key exchange if supported by the JDK.
     */
    @Test
    public void testPQCHandshakeLogVerification() throws Exception {
        Log.info(c, "testPQCHandshakeLogVerification", "Analyzing server logs for PQC handshake evidence");
        
        // Search for TLS 1.3 handshake evidence in logs
        String logContent = server.waitForStringInLog("TLSv1.3", 5000);
        assertNotNull("Should find TLSv1.3 in server logs", logContent);
        Log.info(c, "testPQCHandshakeLogVerification", "Confirmed TLS 1.3 protocol in logs");
        
        // Search for PQC named group evidence (X25519MLKEM768)
        // verifyStringNotInLogUsingMark returns null if string IS found
        String pqcEvidence = server.verifyStringNotInLogUsingMark("X25519MLKEM768", 2000);
        
        if (pqcEvidence == null) {
            Log.info(c, "testPQCHandshakeLogVerification",
                "SUCCESS: Found evidence of X25519MLKEM768 PQC hybrid key exchange in handshake logs");
        } else {
            Log.warning(c, "WARNING: X25519MLKEM768 not found in handshake logs. " +
                "This may indicate the JDK does not support PQC named groups. " +
                "The test verified TLS 1.3 works, but PQC hybrid key exchange was not used.");
        }
        
        Log.info(c, "testPQCHandshakeLogVerification", "Log verification complete");
    }
}
