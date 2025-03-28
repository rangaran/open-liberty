/*******************************************************************************
 * Copyright (c) 2023, 2025 IBM Corporation and others.
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

package com.ibm.ws.security.token.ltpa.fat;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.config.ConfigElementList;
import com.ibm.websphere.simplicity.config.LTPA;
import com.ibm.websphere.simplicity.config.ServerConfiguration;
import com.ibm.websphere.simplicity.config.ValidationKeys;
import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.webcontainer.security.test.servlets.FormLoginClient;

import componenttest.annotation.AllowedFFDC;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.topology.impl.LibertyFileManager;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.impl.LibertyServerFactory;
import componenttest.vulnerability.LeakedPasswordChecker;

@SuppressWarnings("restriction")
@RunWith(FATRunner.class)
@Mode(TestMode.FULL)
public class LTPAInitializationVectorTests {

    // Initialize needed strings for the tests
    protected static String METHODS = null;
    protected static final String APP_NAME = "ltpaInitializationVectorTestServer";
    protected static final String PROGRAMMATIC_API_SERVLET = "ProgrammaticAPIServlet";
    protected static final String authTypeForm = "FORM";
    protected static final String cookieName = "LtpaToken2";

    // Initialize two liberty servers for form login
    private static LibertyServer server1 = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.initializationVectorTestServer1");
    private static LibertyServer server2 = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.initializationVectorTestServer2");

    private static final Class<?> thisClass = LTPAInitializationVectorTests.class;

    // Initialize the user
    private static final String validUser = "user1";
    private static final String validPassword = "user1pwd";

    private static final String[] serverShutdownMessages = { "CWWKS4102E", "CWWKG0058E", "CWWKG0083W", "CWWKS4106E", "CWWKS4109W", "CWWKS4110E", "CWWKS4111E", "CWWKS4112E",
                                                             "CWWKS4113W",
                                                             "CWWKS4114W", "CWWKS4115W", "CWWKS1859E" };

    // Initialize the FormLogin Clients
    private static FormLoginClient server1FlClient1;
    private static FormLoginClient server2FlClient1;

    // Define server.xml files
    private static final String DEFAULT_SERVER_XML = "server.xml";
    private static String DEFAULT_FIPS_SERVER1_XML = "server1FIPS.xml";
    private static String DEFAULT_FIPS_SERVER2_XML = "server2FIPS.xml";
    private static String BACKUP_SERVERXML_IV_SERVER_1 = "iv_server1_server.xml";
    private static String BACKUP_SERVERXML_IV_SERVER_2 = "iv_server2_server.xml";

    // Define the paths to the key files
    private static final String DEFAULT_KEY_PATH = "resources/security/ltpa.keys";
    private static final String VALIDATION_KEY1_PATH = "resources/security/validation1.keys";
    private static final String VALIDATION_KEY2_PATH = "resources/security/validation2.keys";
    private static final String VALIDATION_KEY3_PATH = "resources/security/validation3.keys";
    private static final String BAD_SHARED_VALIDATION_KEY2_PATH = "resources/security/validation4.keys";
    private static final String DIFFERENT_PW_VALIDATION_KEY_PATH = "resources/security/validation9.keys";
    private static final String VALIDATION_KEY1 = "validation1.keys";
    private static final String VALIDATION_KEY4 = "validation4.keys";
    private static final String VALIDATION_KEY9 = "validation9.keys";
    private static final String LTPA_LIBERTY_PASSWORD = "{xor}EzY9Oi0rJg==";
    private static String LTPA_DEFAULT_PASSWORD = "{xor}Lz4sLCgwLTs=";
    private static String LTPA_FIPS_DEFAULT_PASSWORD = "{xor}CDo9Hgw=";

    List<String> PREBUILT_KEYS = Arrays.asList(DEFAULT_KEY_PATH, DIFFERENT_PW_VALIDATION_KEY_PATH, BAD_SHARED_VALIDATION_KEY2_PATH,
                                               VALIDATION_KEY3_PATH,
                                               VALIDATION_KEY2_PATH, VALIDATION_KEY1_PATH);

    /**  */

    // Define the paths to the alternate key files
    private static String ALT_VALIDATION_KEY1_PATH = "alternate/validation1.keys";
    private static String ALT_VALIDATION_KEY2_PATH = "alternate/validation2.keys";
    private static String ALT_VALIDATION_KEY3_PATH = "alternate/validation3.keys";
    private static String ALT_VALIDATION_KEY4_PATH = "alternate/validation4.keys";
    private static String ALT_VALIDATION_KEY9_PATH = "alternate/validation9.keys";

    // Define the paths to the alternate key files
    private static String ALT_FIPS_VALIDATION_KEY1_PATH = "alternateFIPS/validation1.keys";
    private static String ALT_FIPS_VALIDATION_KEY2_PATH = "alternateFIPS/validation2.keys";
    private static String ALT_FIPS_VALIDATION_KEY3_PATH = "alternateFIPS/validation3.keys";
    private static String ALT_FIPS_VALIDATION_KEY4_PATH = "alternateFIPS/validation4.keys";
    private static String ALT_FIPS_VALIDATION_KEY9_PATH = "alternateFIPS/validation9.keys";

    // Define fipsEnabled
    private static final boolean fipsEnabled;

    static {
        boolean isFipsEnabled = false;
        try {
            isFipsEnabled = server1.isFIPS140_3EnabledAndSupported() && server2.isFIPS140_3EnabledAndSupported();
        } catch (Exception e) {
            e.printStackTrace();
        }
        fipsEnabled = isFipsEnabled;

        if (fipsEnabled) {
            BACKUP_SERVERXML_IV_SERVER_1 = DEFAULT_FIPS_SERVER1_XML;
            BACKUP_SERVERXML_IV_SERVER_2 = DEFAULT_FIPS_SERVER2_XML;
            ALT_VALIDATION_KEY1_PATH = ALT_FIPS_VALIDATION_KEY1_PATH;
            ALT_VALIDATION_KEY2_PATH = ALT_FIPS_VALIDATION_KEY2_PATH;
            ALT_VALIDATION_KEY3_PATH = ALT_FIPS_VALIDATION_KEY3_PATH;
            ALT_VALIDATION_KEY4_PATH = ALT_FIPS_VALIDATION_KEY4_PATH;
            ALT_VALIDATION_KEY9_PATH = ALT_FIPS_VALIDATION_KEY9_PATH;
            LTPA_DEFAULT_PASSWORD = LTPA_FIPS_DEFAULT_PASSWORD;
        }
    }

    @Rule
    public TestRule passwordChecker1 = new LeakedPasswordChecker(server1);
    public TestRule passwordChecker2 = new LeakedPasswordChecker(server2);

    @Rule
    public final TestWatcher logger = new TestWatcher() {
        @Override
        // Function to make it easier to see when each test starts and ends
        public void starting(Description description) {
            Log.info(thisClass, description.getMethodName(), "\n@@@@@@@@@@@@@@@@@\nEntering test " + description.getMethodName() + "\n@@@@@@@@@@@@@@@@@");
        }

        @Override
        public void finished(Description description) {
            Log.info(thisClass, description.getMethodName(), "\n@@@@@@@@@@@@@@@@@\nExiting test " + description.getMethodName() + "\n@@@@@@@@@@@@@@@@@");
        }
    };

    @BeforeClass
    public static void setUpClass() throws Exception {

        // Copy validation key file (validation1.keys) to the server
        server2.useSecondaryHTTPPort();

        LibertyServer[] servers = { server1, server2 };

        for (LibertyServer server : servers) {

            server.setupForRestConnectorAccess();
            server.startServer(true);

            assertNotNull("Featurevalid did not report update was complete",
                          server.waitForStringInLogUsingMark("CWWKF0008I"));
            assertNotNull("Security service did not report it was ready",
                          server.waitForStringInLogUsingMark("CWWKS0008I"));
            assertNotNull("The application did not report is was started",
                          server.waitForStringInLogUsingMark("CWWKZ0001I"));
            // Wait for the LTPA configuration to be ready
            assertNotNull("Expected LTPA configuration ready message not found in the log.",
                          server.waitForStringInLogUsingMark("CWWKS4105I"));

        }

        server1FlClient1 = new FormLoginClient(server1, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin1");
        server2FlClient1 = new FormLoginClient(server2, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin1");

    }

    @Before
    public void setUp() throws Exception {
        LibertyServer[] servers = { server1, server2 };

        for (LibertyServer server : servers) {
            if (!server.isStarted()) {
                // Delete on setUp so that old keys are saved when the server is backed up by the framework
                for (String path : PREBUILT_KEYS) {
                    deleteFileIfExists(path, true, server);
                }
                server.startServer(true);
            }
        }

        //Copy over server.xml on set up to restore the server.xml between tests
        server1.copyFileToLibertyServerRoot(BACKUP_SERVERXML_IV_SERVER_1);
        renameKeyAndWaitForMessage(BACKUP_SERVERXML_IV_SERVER_1, DEFAULT_SERVER_XML, server1, "CWWKG001[7-8]I");

        server2.copyFileToLibertyServerRoot(BACKUP_SERVERXML_IV_SERVER_2);
        renameKeyAndWaitForMessage(BACKUP_SERVERXML_IV_SERVER_2, DEFAULT_SERVER_XML, server2, "CWWKG001[7-8]I");

        for (LibertyServer server : servers) {
            moveLogMarkForServer(server);
        }

    }

    @After
    public void after() throws Exception {
        server1FlClient1.resetClientState();
        server2FlClient1.resetClientState();

        resetServer(server1);
        resetServer(server2);
    }

    public void resetConnection() {

    }

    @AfterClass
    public static void tearDown() throws Exception {
        server1FlClient1.releaseClient();
        server2FlClient1.releaseClient();
    }

    /**
     * Verify that an SSO cookie retrieved from authentication on one server can be used on a second server using a validation key and derived IV where both
     * servers use the same keysPassword.
     *
     * Steps:
     * <OL>
     * <LI> Configure Server #1 and Server #2 to contain different primary LTPA Keys with the same LTPA keys passwords and with monitorValidationKeysDir set to True
     * <LI> Access a simple servlet with form login using valid credentials on Server #1 and retrieve the SSO cookie
     * <LI> Copy the LTPA primary key from Server #1 and place it in Server #2
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI> Successful authentication to simple servlet application on server #1 using valid credentials
     * <LI> Successful retrieval of SSO cookie from server #1
     * <LI> Successful copy and rename of ltpa.keys file to server #2 to be used as validation keys
     * <LI> Successful authentication to simple servlet application on server #2 using the SSO cookie
     * </OL>
     */
    @Mode(TestMode.LITE)
    @Test
    public void testLTPAValidationKeyUsage_twoServers_samePW_monitorValidationKeysDir_true() throws Exception {

        // Configure the servers
        configureServer("true", "10", true, server1);
        configureServer("true", "10", true, server2);

        // Copy valid ltpa keys to each server, the ltpa keys are configured using the same keysPassword
        server1.setMarkToEndOfLog();
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLogUsingMark("CWWKS4105I"));

        server2.setMarkToEndOfLog();
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLogUsingMark("CWWKS4105I"));

        // Replace the randomly generated LTPA keys with the known valid ltpa keys and assert the change occurs
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, server2);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Retrieve the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        server2.setMarkToEndOfLog();
        // Copy the ltpa.keys file from server #1 to server #2 (server #2 now contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);

        // Wait for the LTPA configuration to be ready after the change
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLogUsingMark("CWWKS4105I"));

        // Attempt to login to the simple servlet on server #2 and assert that the login is successful
        server2FlClient1.accessProtectedServletWithAuthorizedCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);
    }

    /**
     * Verify that an SSO cookie retrieved from authentication on one server can be used on a second server using a validation key and derived IV where both servers use the same
     * keysPassword and with the server monitorValidationKeysDir variable set to false.
     *
     * Steps:
     * <OL>
     * <LI> Configure Server #1 and Server #2 to contain different primary LTPA Keys with the same LTPA keys passwords with monitorValidationKeysDir set to False
     * <LI> Access a simple servlet with form login using valid credentials on Server #1 and retrieve the SSO cookie
     * <LI> Copy the LTPA primary key from Server #1 and place it in Server #2
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * <LI> Configure the previously added validation key and password in Server #2 server.xml
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI> Successful authentication to simple servlet application on server #1 using valid credentials
     * <LI> Successful retrieval of SSO cookie from server #1
     * <LI> Successful copy of ltpa.keys file to server #2 to be used as validation keys (Server #2 contains the primary key of server #1 as a validation key)
     * <LI> Unsuccessful authentication to simple servlet application on server #2 using SSO cookie due to monitorKeysValidationDir not recognizing unspecified keys
     * <LI> Successful configuration of validation key
     * <LI> Successful authentication to simple servlet application on server #2 using SSO cookie
     * </OL>
     */
    @Mode(TestMode.FULL)
    @Test
    public void testLTPAValidationKeyUsage_twoServers_samePW_monitorValidationKeysDir_false() throws Exception {

        // Configure the servers
        configureServer("false", "10", false, server1);
        configureServer("false", "10", false, server2);

        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        // Configuration message is not recognized because directory is not being monitored for changes
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);

        // Replace the randomly generated LTPA keys with the known valid ltpa keys and assert the change occurs
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);

        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, server2);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        server2.setMarkToEndOfLog();

        // Copy the ltpa.keys file to server #2 (server #2 contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails because with monitorValidationKeysDir means the server does not recognize unspecified keys file
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));

        // Dynamically add a configured validation key element into the server2 configuration
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAValidationKey(ltpa2, VALIDATION_KEY1, LTPA_DEFAULT_PASSWORD);

        // Update the server configuration to recognize the changes
        updateConfigDynamically(server2, server2Config);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLogUsingMark("CWWKS4105I"));

        // Attempt to login to the simple servlet on server #2 and assert that the login is successful (uses validation key)
        server2FlClient1.accessProtectedServletWithAuthorizedCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);
    }

    /**
     * Verify that an SSO cookie retrieved from authentication on one server can be used on a second server using a validation key and derived IV where both servers use different
     * keysPassword.
     *
     * Steps:
     * <OL>
     * <LI> Configure Server #1 and Server #2 to contain different primary LTPA Keys with different LTPA keys passwords with monitorValidationKeysDir set to True
     * <LI> Configure Server #1 with the correct password of the key to-be added (Server #1 will be configured with a different password than server #2)
     * <LI> Access a simple servlet with form login using valid credentials on Server #1 and retrieve the SSO cookie
     * <LI> Copy the LTPA primary key from Server #1 and place it in Server #2
     * <LI> Configure the previously added validation key and password in Server #2 server.xml
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI> Successful authentication to simple servlet application on server #1 using valid credentials
     * <LI> Successful retrieval of SSO cookie from server #1
     * <LI> Successful copy of ltpa.keys file to server #2 to be used as validation keys
     * <LI> Successful authentication to simple servlet application on server #2 using SSO cookie
     * </OL>
     */
    @Mode(TestMode.LITE)
    @Test
    public void testLTPAValidationKeyUsage_twoServers_differentPW_monitorValidationKeysDir_true() throws Exception {

        // Configure the servers
        configureServer("true", "10", true, server1);
        configureServer("true", "10", true, server2);

        // Change the default keysPassword configured in server.xml to that of the added ltpa keys file (Liberty)
        ServerConfiguration serverConfig = server1.getServerConfiguration();
        LTPA ltpa = serverConfig.getLTPA();
        setLTPAKeyPasswordElement(ltpa, LTPA_LIBERTY_PASSWORD);
        updateConfigDynamically(server1, serverConfig);

        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server1);

        // Replace the randomly generated LTPA keys with the known valid ltpa keys and assert the change occurs
        renameKeyAndWaitForLtpaConfigReady(DIFFERENT_PW_VALIDATION_KEY_PATH, DEFAULT_KEY_PATH, server1);

        server2.setMarkToEndOfLog();
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLogUsingMark("CWWKS4105I"));

        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, server2);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Dynamically add the validation key element into the server2 configuration
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAValidationKey(ltpa2, VALIDATION_KEY9, LTPA_LIBERTY_PASSWORD);
        updateConfigDynamically(server2, server2Config);

        // Copy the ltpa.keys file to server #2 and test authentication should be successful because monitorValidationkeysDir monitors unlisted keys files
        server2.setMarkToEndOfLog();
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLogUsingMark("CWWKS4105I"));

        // Attempt to login to the simple servlet on server #2 and assert that the login is successful (uses validation key)
        server2FlClient1.accessProtectedServletWithAuthorizedCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);
    }

    /**
     * Verify that an SSO cookie retrieved from authentication on one server can be used on a second server using a validation key and derived IV where both servers use different
     * keysPassword and with the server monitorValidationKeysDir variable set to false.
     *
     * Steps:
     * <OL>
     * <LI> Configure Server #1 and Server #2 to contain different primary LTPA Keys with different LTPA keys passwords with monitorValidationKeysDir set to False
     * <LI> Configure Server #1 with the correct password of the key to-be added (Server #1 will be configured with a different password than server #2)
     * <LI> Access a simple servlet with form login using valid credentials on Server #1 and retrieve the SSO cookie
     * <LI> Copy the LTPA primary key from Server #1 and place it in Server #2
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * <LI> Configure the previously added validation key and password in Server #2 server.xml
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI> Successful authentication to simple servlet application on server #1 using valid credentials
     * <LI> Successful retrieval of SSO cookie from server #1
     * <LI> Successful copy of ltpa.keys file to server #2 to be used as validation keys
     * <LI> Unsuccessful authentication to simple servlet application on server #2 using SSO cookie due to monitorKeysValidationDir not recognizing unspecified keys
     * <LI> Successful rename of the validation keys file to that specified in server.xml
     * <LI> Successful authentication to simple servlet application on server #2 using SSO cookie
     * </OL>
     */
    @Mode(TestMode.FULL)
    @Test
    public void testLTPAValidationKeyUsage_twoServers_differentPW_monitorValidationKeysDir_false() throws Exception {

        // Configure the servers
        configureServer("false", "10", false, server1);
        configureServer("false", "10", false, server2);

        // Change the default keysPassword configured in server.xml to that of the added ltpa keys file (Liberty)
        ServerConfiguration serverConfig = server1.getServerConfiguration();
        LTPA ltpa = serverConfig.getLTPA();
        setLTPAKeyPasswordElement(ltpa, "{xor}EzY9Oi0rJg==");
        updateConfigDynamically(server1, serverConfig);

        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server1);
        renameKeyAndWaitForLtpaConfigReady(DIFFERENT_PW_VALIDATION_KEY_PATH, DEFAULT_KEY_PATH, server1);

        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, server2);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Copy the ltpa.keys file to server #2 as validation9.keys (server #2 contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server2);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails because with monitorValidationKeysDir means the server does not recognize unspecified keys file
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));

        // Dynamically add the validation key element into the server2 configuration
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAValidationKey(ltpa2, VALIDATION_KEY9, LTPA_LIBERTY_PASSWORD);
        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login is successful
        server2FlClient1.accessProtectedServletWithAuthorizedCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);
    }

    /**
     * Negative Test Case:
     * Verify that the cookie obtained from server 1 fails on server 2 if the primary key values with are different (keypassword is the same) on both servers and validate that the
     * IV for server2
     * is different from server 1.
     *
     *
     * Steps:
     * <OL>
     * <LI> Server #1 and Server #2 contain different primary LTPA keys
     * <LI> Replace LTPA keys with validation keys from respective servers to ensure no validation keys exist in either server.
     * <LI> Access a simple servlet with form login using valid credentials on Server #1
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI> Succesful rename to respective ltpa.keys per server of validation keys copied over
     * <LI> Authentication should be successful on server 1 and succesful retrieval the SSO cookie
     * <LI> Authentication fails because the SSO token cannot be decrypted by the primary key of server 2
     * </OL>
     *
     */

    @Mode(TestMode.FULL)
    @Test
    public void testLTPAValidationKeyUsage_no_validation_keys() throws Exception {

        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);

        // Configure the server, and replace the generated LTPA keys with the known valid ltpa key in server 1
        configureServer("true", "10", true, server1);
        configureServer("true", "10", true, server2);

        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);

        // Configure the server, and replace the generated LTPA keys with the known valid ltpa key in server 2
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, server2);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails
        // IV for server 1 is validation1.keys but IV for server 2 is validation2.keys
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }

    /**
     * Negative Test Case:
     * Verify that the SSO cookie from a server with a valid key fails on a server with an invalid key. Even though an FFDC will be created for server 2
     * because an invalid key (badly formatted) can not be decrypted, we can allow it to validate the SSO failure on server 2.
     * This will result in an invalid IV value for server 2.
     *
     * Steps:
     *
     * <OL>
     * <LI> Server #1 and Server #2 contain different primary LTPA keys with different LTPA keys passwords and corrupted keys in server 2
     * <LI> Place an invalid primary key into Server #2 (different than primary key of Server #1
     * <LI> Access a simple servlet with form login using valid credentials on Server #1
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI>
     * <LI> Authentication should be successful and retrieve the SSO cookie on server 1
     * <LI> Authentication fails on server 2 because the SSO token cannot be decrypted by the primary and validation key does not exist in server 2 to override the ltpa key
     * </OL>
     */

    @Mode(TestMode.FULL)
    @Test
    @AllowedFFDC({ "java.lang.IllegalArgumentException" })
    //Have to allow FFDC as the 3des key length with the word 'garbage' is not divisible by 4 and can not be decrypted properly
    public void testLTPAValidationKeyUsage_no_validation_keys_and_bad_keys() throws Exception {

        // Copy valid ltpa keys to server 1 and an invalid one to server 2
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY3_PATH, server2);

        // Configure both servers, and replace the randomly generated LTPA keys with the known valid ltpa keys
        configureServer("true", "10", true, server1);
        configureServer("true", "10", true, server2);

        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);

        renameKeyAndWaitForMessage(VALIDATION_KEY3_PATH, DEFAULT_KEY_PATH, server2, "CWWKS4106E");

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // // Attempt to login to the simple servlet on server #2 and assert that the login fails as only bad key is in the IV of server 2
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }

    /**
     * Negative Test Case:
     * Verify that the SSO cookie from a server with a valid key fails on a server with an invalid key. Even though an FFDC will be created for server 2
     * because an invalid key (badly formatted) can not be decrypted, we can allow it to validate the SSO failure on server 2. Even though we have validation4.keys,
     * the FFDC will still be created as all of server 2's validation keys will be monitored.
     * This will as result in an invalid IV value for server 2 because both the primary and validation keys are invalid.
     *
     * Steps:
     * <OL>
     * <LI> Server #1 and Server #2 contain different primary LTPA keys with same LTPA keys passwords
     * <LI> Place an invalid primary and validation key into Server #2 (different than primary key of Server #1)
     * <LI> Access a simple servlet with form login using valid credentials on Server #1
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI> Successful copy and rename to ltpa.keys in server 1
     * <LI> Successful copy and rename of files to ltpa.keys and validation4.keys in server 2
     * <LI> Authentication should be successful and retrieve the SSO cookie
     * <LI> Authentication fails because the SSO token cannot be decrypted by the primary and validation key (keys are bad and IV based on the keys is invalid)
     * </OL>
     *
     */

    @Mode(TestMode.LITE)
    @Test
    @AllowedFFDC({ "java.lang.IllegalArgumentException" })
    //FFDC because validation4.keys is an incorrectly formatted corrupted key which will cause an Illegal Argument exceptions
    public void testLTPAValidationKeyUsage_bad_keys() throws Exception {

        // Copy valid ltpa keys to server1 and invalid primary and valid key to server 2
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY3_PATH, server2);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY4_PATH, server2);

        // Configure both servers

        //replace the randomly generated LTPA key with a known valid ltpa key
        configureServer("true", "10", true, server1);
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);

        configureServer("true", "10", true, server2);
        renameKeyAndWaitForMessage(VALIDATION_KEY3_PATH, DEFAULT_KEY_PATH, server2, "CWWKS4106E");

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Change the default keysPassword to that of the added ltpa keys file (Liberty)
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAValidationKey(ltpa2, VALIDATION_KEY4, LTPA_DEFAULT_PASSWORD);

        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login  fails as expected
        // The IV is set to an invalid  key for server 2
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }

    /**
     * Negative Test Case:
     * Verify that copying a fips key in a non fips environment (and vice versa) will result in an Argument exception as the key can not be decrypted
     * The IV for the server will be set to an invalid key.
     *
     * Steps:
     * <OL>
     * <LI> Server #1 contains primary fips LTPA keys(in non fips) and non fips LTPA key(in fips)
     * <LI> Place a fips validation key (in non fips) and non fips validation key(in fips)
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI> non-fips: com.ibm.websphere.ltpa.3DESKey property is missing exception
     * <LI> fips: com.ibm.websphere.ltpa.sharedKey property is missing exception
     * </OL>
     */

    @Mode(TestMode.LITE)
    @Test
    @AllowedFFDC({ "java.lang.IllegalArgumentException" })
    public void testLTPA_fipskey_in_nonfips_and_vice_versa() throws Exception {

        if (!fipsEnabled) {

            // Copy valid fips primary and validation keys into server 1
            copyFileToServerResourcesSecurityDir(ALT_FIPS_VALIDATION_KEY1_PATH, server1);
            copyFileToServerResourcesSecurityDir(ALT_FIPS_VALIDATION_KEY2_PATH, server1);

            // Configure the server, and replace the generated LTPA key with the fips key
            configureServer("true", "10", true, server1);
            renameKeyAndWaitForMessage(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1, "CWWKS4102E");
        }

        else {
            // Copy valid non fips primary and validation keys into server 1
            //Have to use the full path as keys get overriden on the top
            copyFileToServerResourcesSecurityDir("alternate/validation1.keys", server1);
            copyFileToServerResourcesSecurityDir("alternate/validation2.keys", server1);

            // Configure the server, and replace the generated LTPA key with the non fips key
            configureServer("true", "10", true, server1);
            renameKeyAndWaitForMessage(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1, "CWWKS4102E");

        }

    }

    /**
     * Negative Test Case:
     *
     * Verify that the SSO cookie from a server with valid keys fails in a server with the same key but with a different password (bad password).
     * The IV for server 2 will be different from server 1 as the keyPassword for server 2 is not the same as server 1.
     *
     * Steps:
     * <OL>
     * <LI> Server #1 and Server #2 contain the same primary LTPA keys and validation key respectively with different keys passwords
     * <LI> Access a simple servlet with form login using valid credentials on server #1
     * <LI> Replace the `password` property of the validation key with 'garbage' values on server #2
     * <LI> Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * </OL>
     *
     *
     * Expected Results:
     * <OL>
     * <LI> Succesful file copy and file rename to ltpa.keys and to validation1.keys in server 1 and server 2 respectively.
     * <LI> Authentication should be successful and retrieve the SSO cookie on server 1
     * <LI> Authentication fails on server 2, the keypassword is different
     * </OL>
     */

    @Mode(TestMode.FULL)
    @Test
    @AllowedFFDC({ "javax.crypto.BadPaddingException" })
    public void testLTPAValidationKeyUsage_invalid_passwords() throws Exception {
        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);

        // Configure both servers, and replace the randomly generated LTPA keys with the known valid ltpa keys
        configureServer("true", "10", true, server1);
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);

        configureServer("true", "10", true, server2);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Change the default password  to an invalid value
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAValidationKey(ltpa2, "validation1.keys", "garbage");
        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }

    /**
     * Negative Test Case:
     *
     * Verify that the SSO cookie works in server 2 when the IV is set to be the same dynamically. Furthermore, validate that it fails
     * when the IV is set to a different value dynamically.
     *
     * Steps:
     * <OL>
     * <LI> Server #1 and Server #2 contain different primary LTPA keys with different LTPA keys passwords.
     * <LI> Copy a valid key into server1 as a primary key
     * <LI> Copy an invalid key into server2 as a primary key
     * <LI> Access a simple servlet with form login using valid credentials on server #1
     * <LI> Copy the LTPA Primary key from Server #1 and place it in Server #2, renamed as validation1.key
     * <LI> Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * <LI> Delete existing valid validation1.keys on server 2
     * <LI> Copy an invalid validation key into Server #2, validation4.keys on server 2
     * <LI> Access a simple servlet with form login using the same server 1 cookie on server #2
     * </OL>
     *
     * Expected results:
     * <OL>
     * <LI> Succesful rename of ltpa.key containing a valid and invalid key in server 1 and server 2 respectively
     * <LI> Authentication should be successful and retrieve the SSO cookie on server 1
     * <LI> Successful validation1.keys copy created on server2
     * <LI> Authentication should be successful on server 2 using the SSO cookie on server 1
     * <LI> Successful deletion of validation1.keys on server 2
     * <LI> Successful validation4.keys copy created on server2
     * <LI> Authentication fails because although IV and keys file are invalid on server 2
     * </OL>
     */

    @Mode(TestMode.FULL)
    @Test
    public void testLTPAValidationKeyUsage_set_passing_validation_key_to_failing_validation_key() throws Exception {
        // Copy valid ltpa keys to server1. Copy invalid keys to server 2.
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY4_PATH, server2);

        // Configure both servers, and replace the randomly generated LTPA keys with the known validation keys
        configureServer("true", "10", true, server1);
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);

        // Wait for the LTPA configuration to be ready after the change
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLogUsingMark("CWWKS4105I"));

        configureServer("true", "10", true, server2);
        renameKeyAndWaitForLtpaConfigReady(BAD_SHARED_VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, server2);

        // Change the default keysPassword to that of the added ltpa keys file
        ServerConfiguration serverConfig = server1.getServerConfiguration();
        LTPA ltpa = serverConfig.getLTPA();
        setLTPAKeyPasswordElement(ltpa, LTPA_DEFAULT_PASSWORD);
        updateConfigDynamically(server1, serverConfig);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();

        //Copy over validation1.keys
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);

        // Change the default keysPassword to that of the added ltpa keys file
        setLTPAValidationKey(ltpa2, VALIDATION_KEY1, LTPA_DEFAULT_PASSWORD);

        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login is successful (uses validation key)
        server2FlClient1.accessProtectedServletWithAuthorizedCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);

        //Delete validation1.keys
        deleteFileIfExists(VALIDATION_KEY1_PATH, true, server2);

        //Copy over validation4.keys
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY4_PATH, server2);
        setLTPAValidationKey(ltpa2, VALIDATION_KEY4, LTPA_DEFAULT_PASSWORD);

        updateConfigDynamically(server2, server2Config);

        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));

    }

    /**
     * Negative Test Case:
     *
     * Since MonitorValidationKeysDir is false, verify that a server 2 continues to fail authentication using a cookie from server 1
     * even if a valid validation keys file is copied over to server 2. This is because the IV can only be set to validation files set in
     * the server.xml as the feature to monitor all existing validation keys file is disabled.
     *
     * Steps:
     * <OL>
     * <LI> Server #1 and Server #2 contain different primary LTPA keys
     * <LI> Access a simple servlet with form login using valid credentials on server #1
     * <LI> Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * <LI> Copy over validation9.keys
     * <LI> Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * <LI> Copy the LTPA Primary key as in Server #1 and place it in Server #2, renamed as validation1.keys
     * <LI> Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * </OL>
     *
     * Expected Results:
     * <OL>
     * <LI> Succesful file copy and rename to ltpa.keys in server 1 and server 2
     * <LI> Authentication should be successful and retrieve the SSO cookie on server 1
     * <LI> Succesful copy of validation9.keys created in server 2
     * <LI> Authentication should fail on server 2
     * <LI> Succesful copy of validation1.keys created in server 2
     * <LI> Authentication should fail on server 2
     * </OL>
     *
     *
     **/

    @Mode(TestMode.FULL)
    @Test
    public void testLTPAValidationKeyUsage_set_MonitorValidationKeysDir_to_false_with_failing_validation_key() throws Exception {
        // Configure the servers
        configureServer("false", "10", false, server1);
        configureServer("false", "10", false, server2);

        // // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);

        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, server2);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Copy the ltpa.keys file to server #2 as validation9.keys
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server2);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails because with monitorValidationKeysDir means the server does not recognize unspecified keys file
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));

        // Copy the ltpa.keys file to server #2 as validation1.keys (server #2 contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails because with monitorValidationKeysDir means the server does not recognize unspecified keys file
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));

    }

    /**
     * Negative Test Case:
     *
     * Verify that an SSO cookie from server 1 fails auth in server 2 because the IV is set to an invalid key with a swapped 3DES value
     *
     * Steps:
     *
     * <OL>
     * <LI> Server #1 and Server #2 contain different primary LTPA keys with same LTPA keys passwords
     * <LI> Access a simple servlet with form login using valid credentials on server #1
     * <LI> Copy over validation4.keys to server2
     * <LI> Replace the `password` property of the validation key to that of server 1's keypassword
     * <LI> Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * </OL>
     *
     * Expected results:
     * <OL>
     * <LI> Successful file copy and rename to ltpa.keys in server 1 and server 2
     * <LI> Succesful file copy of validation4.keys in server 2
     * <LI> Authentication should be successful and retrieve the SSO cookie on server 1
     * <LI> Authentication fails because although IV and keys file is valid, the 3des key is incorrect
     * </OL>
     */

    @Mode(TestMode.LITE)
    @Test
    public void testLTPAValidationKeyUsage_swapped_3DESkey_or_shared_value() throws Exception {
        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        //copy over invalid key
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY4_PATH, server2);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);

        // Configure both servers, and replace the randomly generated LTPA keys  with valid keys
        configureServer("true", "10", true, server1);
        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, server1);

        configureServer("true", "10", true, server2);

        renameKeyAndWaitForLtpaConfigReady(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, server2);

        // Initial login to simple servlet for form login1
        server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Change the default password of the validation key to that of the added ltpa keys file
        // set the key file element as the failing key
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAValidationKey(ltpa2, VALIDATION_KEY4, LTPA_DEFAULT_PASSWORD);

        updateConfigDynamically(server2, server2Config);

        // Attempt should fail as the IV is set to an invalid validation key
        assertTrue("An invalid cookie should result in an authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }

    public void moveLogMarkForServer(LibertyServer server) throws Exception {
        server.setMarkToEndOfLog();
    }

    // Function to do the server configuration for all the tests.
    public void configureServer(String monitorValidationKeysDir, String monitorInterval, Boolean waitForLTPAConfigReadyMessage, LibertyServer server) throws Exception {
        configureServer(monitorValidationKeysDir, monitorInterval, waitForLTPAConfigReadyMessage, true, server);
    }

    public void configureServer(String monitorValidationKeysDir, String monitorInterval, Boolean waitForLTPAConfigReadyMessage, boolean setLogMarkToEnd,
                                LibertyServer server) throws Exception {
        configureServer("polled", monitorValidationKeysDir, monitorInterval, waitForLTPAConfigReadyMessage, true, server);
    }

    /**
     * Function to do the server configuration for all the tests.
     * Assert that the server has with a default ltpa.keys file.
     *
     * @param updateTrigger
     * @param monitorValidationKeysDir
     * @param monitorInterval
     * @param waitForLTPAConfigReadyMessage
     * @param setLogMarkToEnd
     *
     * @throws Exception
     */
    public void configureServer(String updateTrigger, String monitorValidationKeysDir, String monitorInterval, Boolean waitForLTPAConfigReadyMessage,
                                boolean setLogMarkToEnd, LibertyServer server) throws Exception {
        moveLogMarkForServer(server);
        // Get the server configuration
        ServerConfiguration serverConfiguration = server.getServerConfiguration();
        LTPA ltpa = serverConfiguration.getLTPA();

        // Check if the configuration needs to be updated
        boolean configurationUpdateNeeded = false;

        configurationUpdateNeeded = setLTPAupdateTriggerElement(ltpa, updateTrigger)
                                    | setLTPAmonitorValidationKeysDirElement(ltpa, monitorValidationKeysDir)
                                    | setLTPAmonitorIntervalElement(ltpa, monitorInterval);

        // Apply server configuration update if needed
        if (configurationUpdateNeeded) {
            updateConfigDynamically(server, serverConfiguration);

            if (updateTrigger.equals("polled") && monitorValidationKeysDir.equals("true") && monitorInterval.equals("0")) {
                // Wait for a warning message message to be logged
                assertNotNull("Expected LTPA configuration warning message not found in the log.",
                              server.waitForStringInLogUsingMark("CWWKS4113W"));
            }

            if (waitForLTPAConfigReadyMessage) {
                // Wait for the LTPA configuration to be ready after the change
                assertNotNull("Expected LTPA configuration ready message not found in the log.",
                              server.waitForStringInLogUsingMark("CWWKS4105I"));
            }
        }

        // Assert that a default ltpa.keys file is generated
        assertFileWasCreated(DEFAULT_KEY_PATH, server);
        server.setKeysAndJVMOptsForFips();
        if (setLogMarkToEnd)
            server.setMarkToEndOfLog();
        server.setMarkToEndOfLog();
    }

    // Function to configure the password for validation keys
    public boolean setLTPAvalidationKeyPasswordElement(LTPA ltpa, String value) {
        ConfigElementList<ValidationKeys> validationKeys = ltpa.getValidationKeys();
        ValidationKeys validationKey = validationKeys.get(0);

        // Check if null
        if (validationKey.password == null) {
            validationKey.password = value;
            return true; // Config update is needed
        }

        if (!validationKey.password.equals(value)) {
            validationKey.password = value;
            return true; // Config update is needed
        }
        return false; // Config update is not needed;
    }

    // Function to configure the fileName for validation keys
    public boolean setLTPAValidationKey(LTPA ltpa, String keyName, String password) {
        ConfigElementList<ValidationKeys> validationKeys = ltpa.getValidationKeys();

        ValidationKeys newValidationKey = new ValidationKeys();
        newValidationKey.fileName = keyName;
        newValidationKey.password = password;
        newValidationKey.validUntilDate = "2099-01-01T00:00:00Z";

        validationKeys.add(newValidationKey);

        return true;

    }

    // Function to configure the password for LTPA primary keys
    public boolean setLTPAKeyPasswordElement(LTPA ltpa, String value) {
        // Check if null
        if (ltpa.keysPassword == null) {
            ltpa.keysPassword = value;
            return true; // Config update is needed
        }

        if (!ltpa.keysPassword.equals(value)) {
            ltpa.keysPassword = value;
            return true; // Config update is needed
        }
        return false; // Config update is not needed;

    }

    // Function to configure the fileName for validation keys
    public boolean setLTPAvalidationKeyFileNameElement(LTPA ltpa, String value) {
        ConfigElementList<ValidationKeys> validationKeys = ltpa.getValidationKeys();
        ValidationKeys validationKey = validationKeys.get(0);

        // Check if null
        if (validationKey.fileName == null) {
            validationKey.fileName = value;
            return true; // Config update is needed
        }

        if (!validationKey.fileName.equals(value)) {
            validationKey.fileName = value;
            return true; // Config update is needed
        }
        return false; // Config update is not needed;
    }

    // Function to set the monitorValidationKeysDir to true or false
    public boolean setLTPAmonitorValidationKeysDirElement(LTPA ltpa, String value) {
        if (!ltpa.monitorValidationKeysDir.equals(value)) {
            ltpa.monitorValidationKeysDir = value;
            return true; // Config update is needed
        }
        return false; // Config update is not needed;
    }

    // Function to configure monitorInterval to a specific value
    public boolean setLTPAmonitorIntervalElement(LTPA ltpa, String value) {
        if (!ltpa.monitorInterval.equals(value)) {
            ltpa.monitorInterval = value;
            return true; // Config update is needed
        }
        return false; // Config update is not needed;
    }

    // Function to configure the expiration time for the LTPA token to a specific value
    public boolean setLTPAexpiryElement(LTPA ltpa, String value) {
        if (!ltpa.expiration.equals(value)) {
            ltpa.expiration = value;
            return true; // Config update is needed
        }
        return false; // Config update is not needed;
    }

    // Function to configure the updateTrigger to a specific value
    public boolean setLTPAupdateTriggerElement(LTPA ltpa, String value) {
        if (!ltpa.updateTrigger.equals(value)) {
            ltpa.updateTrigger = value;
            return true; // Config update is needed
        }
        return false; // Config update is not needed;
    }

    // Function to update the server configuration dynamically
    public static void updateConfigDynamically(LibertyServer server, ServerConfiguration config) throws Exception {
        server.setMarkToEndOfLog(server.getDefaultLogFile());
        server.setMarkToEndOfLog(server.getMostRecentTraceFile());

        server.updateServerConfiguration(config);
        //CWWKG0017I: The server configuration was successfully updated in {0} seconds.
        //CWWKG0018I: The server configuration was not updated. No functional changes were detected.
        server.waitForStringInLogUsingMark("CWWKG001[7-8]I");

        // Wait for feature update to be completed or LTPA configuration to get ready
        Thread.sleep(2000);
    }

    /**
     * Delete the file if it exists. If we can't delete it, then
     * throw an exception as we need to be able to delete these files.
     *
     * @param filePath
     *
     * @throws Exception
     */
    private static void deleteFileIfExists(String filePath, boolean checkFileIsGone, LibertyServer server) throws Exception {
        Log.info(thisClass, "deleteFileIfExists", "filepath: " + filePath);
        if (fileExists(filePath, 1, server)) {
            Log.info(thisClass, "deleteFileIfExists", "file exists, deleting...");
            server.deleteFileFromLibertyServerRoot(filePath);

            // Double check to make sure the file is gone
            if (checkFileIsGone && fileExists(filePath, 1, server))
                throw new Exception("Unable to delete file: " + filePath);
        }
    }

    /**
     * Assert that file was created otherwise print a message saying it's an intermittent failure.
     *
     * @param filePath
     *
     * @throws Exception
     */
    private void assertFileWasCreated(String filePath, LibertyServer server) throws Exception {
        assertTrue("The file was not created as expected. If this is an intermittent failure, then increase the wait time.",
                   fileExists(filePath, server));
    }

    /**
     * Check to see if the file exists. We will wait a bit to ensure
     * that the system was not slow to flush the file.
     *
     * @param filePath
     *
     * @throws Exception
     */
    private static boolean fileExists(String filePath, LibertyServer server) throws Exception {
        return fileExists(filePath, 5, server);
    }

    /**
     * Check to see if the file exists. We will retry a few times to ensure
     * that the system was not slow to flush the file.
     *
     * @param filePath
     * @param numberOfTries
     *
     * @throws Exception
     */
    private static boolean fileExists(String filePath, int numberOfTries, LibertyServer server) throws Exception {
        boolean exists = false;
        boolean exceptionHasBeenPrinted = false;
        int count = 0;
        do {
            // Sleep 2 seconds
            if (count != 0) {
                Thread.sleep(3000);
                Log.info(thisClass, "fileExists", "waiting 2s...");
            }
            try {
                exists = server.getFileFromLibertyServerRoot(filePath).exists();
            } catch (Exception e) {
                // The file does not exist if there's an exception
                Log.info(thisClass, "fileExists", "The file does not exist");
                exists = false;
                // We don't want to print the same exception over and over again... so we'll only print it one time.
                if (!exceptionHasBeenPrinted) {
                    e.printStackTrace();
                    exceptionHasBeenPrinted = true;
                }
            }
            count++;
        }
        // Wait up to 10 seconds for the key file to appear
        while ((!exists) && count < numberOfTries);

        return exists;
    }

    /**
     * Copies a file to the "server/resources/security/" directory
     *
     * @param sourceFile
     *
     * @throws Exception
     */
    private static void copyFileToServerResourcesSecurityDir(String sourceFile, LibertyServer server) throws Exception {
        Log.info(thisClass, "copyFileToServerResourcesSecurityDir", "sourceFile: " + sourceFile);
        String serverRoot = server.getServerRoot();
        String securityResources = serverRoot + "/resources/security";
        server.setServerRoot(securityResources);
        server.copyFileToLibertyServerRoot(sourceFile);
        server.setServerRoot(serverRoot);
    }

    /**
     * Rename the file if it exists. If we can't rename it, then
     * throw an exception as we need to be able to rename these files.
     * If checkFileIsGone is true, then we will double check to make
     * sure the file is gone.
     *
     * @param filePath
     * @param newFilePath
     * @param checkFileIsGone
     *
     * @throws Exception
     */
    private static void renameServerFileInLibertyRoot(String filePath, String newFilePath, boolean checkFileIsGone, LibertyServer server) throws Exception {
        Log.info(thisClass, "renameFileIfExists", "\nfilepath: " + filePath + "\nnewFilePath: " + newFilePath);

        if (fileExists(newFilePath, 1, server)) {
            LibertyFileManager.moveLibertyFile(server.getFileFromLibertyServerRoot(filePath), server.getFileFromLibertyServerRoot(newFilePath));
        } else {
            server.renameLibertyServerRootFile(filePath, newFilePath);
        }

        // Double check to make sure the file is gone
        if (checkFileIsGone && fileExists(filePath, 1, server))
            throw new Exception("Unable to rename file: " + filePath);
    }

    /**
     * Reset the server to the default configuration
     *
     * @throws Exception
     */
    private void resetServer(LibertyServer server) throws Exception {
        Log.info(thisClass, "resetServer", "entering");

        ServerConfiguration serverConfig = server.getServerConfiguration();
        LTPA ltpa = serverConfig.getLTPA();
        if (fipsEnabled) {
            setLTPAKeyPasswordElement(ltpa, "{xor}CDo9Hgw=");
        } else {
            setLTPAKeyPasswordElement(ltpa, "{xor}Lz4sLCgwLTs=");
        }
        updateConfigDynamically(server, serverConfig);

        server.stopServer(serverShutdownMessages);
        Log.info(thisClass, "resetServer", "exiting");
    }

    private void renameKeyAndWaitForLtpaConfigReady(String oldName, String newName, LibertyServer serv) throws Exception {
        renameKeyAndWaitForMessage(oldName, newName, serv, "CWWKS4105I");
    }

    private void renameKeyAndWaitForMessage(String oldName, String newName, LibertyServer serv, String messageRegex) throws Exception {
        if (fileExists(oldName, 1, serv)) {
            serv.setMarkToEndOfLog();
            renameServerFileInLibertyRoot(oldName, newName, true, serv);
            assertNotNull("Expected message '" + messageRegex + "' was not found in log.",
                          serv.waitForStringInLogUsingMark(messageRegex));
        } else {
            fail("File '" + oldName + "' cannot be renamed because it does not exist");
        }
    }
}