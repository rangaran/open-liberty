/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
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
package com.ibm.ws.logstash.collector.tests;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Arrays;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.testcontainers.containers.GenericContainer;

import com.ibm.websphere.simplicity.ShrinkHelper;
import com.ibm.websphere.simplicity.log.Log;

import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.impl.LibertyServerFactory;

/**
 *
 */
@RunWith(FATRunner.class)
public class LogStashShutdownTest extends LogstashCollectorTest {
    private static LibertyServer server = LibertyServerFactory.getLibertyServer("LogstashServer");
    private static Class<?> c = LogStashShutdownTest.class;
    public final String WEBAPP_REMOVAL_MESSAGE_ID = "CWWKT0017I";

    @ClassRule
    public static GenericContainer<?> logstashContainer = createExpLogstashContainer();

    private static GenericContainer<?> createExpLogstashContainer() {
        try {
            return prepareServerSSLAndConstructContainer(server);
        } catch (Exception e) {
            throw new RuntimeException("Failed to setup server and/or container", e);
        }
    }

    @Before
    public void setUpTest() throws Exception {
        server.addIgnoredErrors(Arrays.asList("CWPKI0063W"));

        clearContainerOutput();
        String host = logstashContainer.getHost();
        String port = String.valueOf(logstashContainer.getMappedPort(5043));
        Log.info(c, "setUp", "Logstash container: host=" + host + "  port=" + port);

        clearContainerOutput();

        // Use the host and port set in @BeforeClass
        server.addEnvVar("LOGSTASH_HOST", host);
        server.addEnvVar("LOGSTASH_PORT", port);

        ShrinkHelper.defaultDropinApp(server, "LogstashApp", "com.ibm.logs");

        if (!server.isStarted()) {
            serverStart();
        }
    }

    /*
     * Verify that the server stops immediately when shutdown is triggered.
     * This is done by verifying that the server quiesce message does not appear: CWWKE1102W
     */
    @Test
    @Mode(TestMode.LITE)
    public void testLogstashForQuickShutdown() throws Exception {
        clearContainerOutput();

        try {
            if (server.isStarted()) {
                Log.info(c, "testingShutdown", "---> Stopping server..");
                server.stopServer();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        //Verify the web app removed message appears in the logstash collector, meaning all required messages were collected.
        assertNotNull(waitForStringInContainerOutput(WEBAPP_REMOVAL_MESSAGE_ID));
        //Verify that the following message does not appear: CWWKE1102W: The quiesce operation did not complete. The server will now stop.
        //If this message appears, it means Logstash took too long to shut down.
        assertNull("Found CWWKE1102W from messages.log", getServer().waitForStringInLogUsingMark("CWWKE1102W", 31000));

    }

    /*
     * Verify that the server stops immediately when shutdown is triggered while an application sends
     * a large number of messages.
     */
    @Test
    @Mode(TestMode.FULL)
    public void testLogstashForQuickShutdownDuringMessageSpam() throws Exception {
        clearContainerOutput();
        String testName = "testLogstashForQuickShutdownDuringMessageSpam";

        createMessageLogEvents(testName);

        try {
            Thread.sleep(1000);
        } catch (Exception e) {
            e.printStackTrace();

        }

        try {
            if (server.isStarted()) {
                Log.info(c, "testingShutdown", "---> Stopping server..");
                server.stopServer();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        //Verify the web app removed message appears in the logstash collector, meaning all required messages were collected.
        assertNotNull(waitForStringInContainerOutput(WEBAPP_REMOVAL_MESSAGE_ID));
        //Verify that the following message does not appear: CWWKE1102W: The quiesce operation did not complete. The server will now stop.
        //If this message appears, it means Logstash took too long to shut down.
        assertNull("Found CWWKE1102W from messages.log", getServer().waitForStringInLogUsingMark("CWWKE1102W", 31000));

    }

    @AfterClass
    public static void completeTest() throws Exception {
        try {
            if (server.isStarted()) {
                Log.info(c, "completeTest", "---> Stopping server..");
                server.stopServer();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void serverStart() throws Exception {
        Log.info(c, "serverStart", "--->  Starting Server.. ");
        server.startServer();

        Log.info(c, "serverStart", "---> Wait for feature to start ");
        assertNotNull("Cannot find CWWKZ0001I from messages.log", server.waitForStringInLogUsingMark("CWWKZ0001I", 15000));
        waitForStringInContainerOutput("CWWKT0016I");
    }

    /*
     * Override the setConfig is required as binary logging does not have messages.log
     */
    @Override
    protected void setConfig(String conf) throws Exception {
        clearContainerOutput();
        server.setServerConfigurationFile(conf);
        assertNotNull(waitForStringInContainerOutput("CWWKG0017I|CWWKG0018I"));
    }

    /** {@inheritDoc} */
    @Override
    protected LibertyServer getServer() {
        return server;
    }

}
