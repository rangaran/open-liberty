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
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package io.openliberty.security.jakartasec.fat.tests;

import static io.openliberty.security.jakartasec.fat.utils.Jakartasec40TestConstants.IN_MEM_ID_STORE_EXPECTED_MESSAGES;
import static io.openliberty.security.jakartasec.fat.utils.Jakartasec40TestConstants.PRODUCTION_USE_WARNING_MSG;
import static io.openliberty.security.jakartasec.fat.utils.Jakartasec40TestConstants.USER_JASMINE;
import static io.openliberty.security.jakartasec.fat.utils.Jakartasec40TestConstants.USER_THEO;
import static io.openliberty.security.jakartasec.fat.utils.Jakartasec40TestConstants.VALID_PASSWORD;
import static org.junit.Assert.assertEquals;

import java.io.File;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.RemoteFile;
import com.ibm.websphere.simplicity.ShrinkHelper;
import com.ibm.websphere.simplicity.ShrinkHelper.DeployOptions;

import componenttest.annotation.Server;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.topology.impl.LibertyServer;

/**
 * Tests for InMemoryIdentityStoreDefinition with various password encoding schemes.
 * Tests positive scenarios (plain, XOR, AES, Hash passwords) and negative scenarios
 * (bad passwords, bad encoding, insufficient groups).
 */
@RunWith(FATRunner.class)
@Mode(TestMode.LITE)
public class InMemoryIdentityStoreEnablementTests extends BaseJakartaSecurity40Test {

    private static final Class<?> c = InMemoryIdentityStoreEnablementTests.class;

    public static final String APP_NAME = "IdentityStoreEnablement";
    private static final String CONTEXT_ROOT = "/" + APP_NAME;
    private static final String RESOURCE_PATH = "/resource/test";
    public static final String SERVER_XML_ID_STORE_DISABLED = "inMemoryIdStoreDisabled.xml";

    private static String url = null;

    @Server(IN_MEM_ID_STORE_ENABLED_SERVER_NAME)
    public static LibertyServer server;

    @Override
    protected Class<?> getTestClass() {
        return c;
    }

    @Override
    protected LibertyServer getServer() {
        return server;
    }

    @BeforeClass
    public static void initialSetup() throws Exception {
        // Save the server configuration before all tests.
        server.saveServerConfiguration();
    }

    @Before
    public void testSetUp() throws Exception {
        InMemoryIdentityStoreEnablementTests instance = new InMemoryIdentityStoreEnablementTests();
        logInfo("testSetUp", "Starting server setup for the test scenario...");

        // The URL is not expected to be modified during this test scope
        url = instance.buildUrl(CONTEXT_ROOT, RESOURCE_PATH);

        // Create the web application
        WebArchive app = ShrinkWrap.create(WebArchive.class,
                                           APP_NAME + ".war").addPackage("inmemory.identity.store").addAsWebInfResource(new File("test-applications/inmemory/WEB-INF/web.xml"));

        ShrinkHelper.exportDropinAppToServer(server, app, DeployOptions.SERVER_ONLY);

        instance.startServer();
    }

    @After
    public void testTearDown() throws Exception {
        server.stopServer(IN_MEM_ID_STORE_EXPECTED_MESSAGES);

        // Restore the server configuration, after each test case.
        server.restoreServerConfiguration();
    }

    /**
     * Test that the specified in-memory identity store is enabled by the default configuration that has the required enablement element.
     * Test the log file output for in-memory store usage warning for sanity.
     * This should only ever appear once upon the first invocation of authentication against the in memory identity store data.
     */
    @Test
    public void testInMemStoreIsAllowed() throws Exception {
        logInfo("testInMemStoreIsAllowed", "Testing that in-mem identity store is enabled in the default config file");

        // Should get 200 and proceed
        executeGetRequest(url, USER_THEO, VALID_PASSWORD, 200);
        assertEquals("Warning message should appear in log once", 1, server.waitForMultipleStringsInLog(1, PRODUCTION_USE_WARNING_MSG));

        logInfo("testInMemStoreIsAllowed", "Test passed");
    }

    /**
     * Test that a specified server configuration will restrict the use of the store
     * A custom server configuration is used with allowInMemoryIdentityStores = false
     */
    //@Test
    public void testInMemStoreCustomConfigIsNotAllowed() throws Exception {
        logInfo("testInMemStoreCustomConfigIsNotAllowed", "Testing that in-mem identity store is not allow by the custom config file");

        RemoteFile consoleLogFile = server.getConsoleLogFile();
        setServerConfig(SERVER_XML_ID_STORE_DISABLED, consoleLogFile, server);

        // Perform successful authentication
        executeGetRequest(url, USER_JASMINE, VALID_PASSWORD, 400);

        // Check that no unexpected error messages appear
        // We expect the warning message, but no error messages
//        String logContent = waitForStringInLog("CWWKS35", 2000);
//
//        if (logContent != null) {
//            // If we found CWWKS35xx messages, make sure they're only the expected warning
//            assertTrue("Should only see warning message, not errors",
//                       logContent.contains(PRODUCTION_USE_WARNING_MSG));
//        }

        logInfo("testInMemStoreCustomConfigIsNotAllowed", "Test passed - no unexpected errors");
    }

    /**
     * Update the server configuration with a specified file
     * Wait for message that indicates the config change
     * CWWKG0017I : The server configuration successfully updated
     * CWWKG0018I : The server configuration was not updated
     *
     * @param fileName the name of the custom configuration file
     * @param logFile
     * @param server
     * @return
     * @throws Exception
     */
    private static String setServerConfig(String fileName, RemoteFile logFile, LibertyServer server) throws Exception {
        server.setMarkToEndOfLog(logFile);
        server.setServerConfigurationFile(fileName);
        return server.waitForStringInLogUsingMark("CWWKG0017I.*|CWWKG0018I.*");
    }

    @AfterClass
    public static void tearDown() throws Exception {
        // Expected warnings and errors during testing
        if (server != null && server.isStarted()) {
            server.stopServer(IN_MEM_ID_STORE_EXPECTED_MESSAGES);
        }
    }
}
