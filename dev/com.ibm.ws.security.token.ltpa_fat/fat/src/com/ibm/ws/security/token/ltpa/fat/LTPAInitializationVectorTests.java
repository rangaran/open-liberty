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

import com.ibm.websphere.simplicity.RemoteFile;
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
    protected static final String APP_NAME = "ltpaKeyRotationTestServer";
    protected static final String PROGRAMMATIC_API_SERVLET = "ProgrammaticAPIServlet";
    protected static final String authTypeForm = "FORM";
    protected static final String cookieName = "LtpaToken2";

    // Initialize two liberty servers for form login
    private static LibertyServer server1 = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.initializationVectorTestServer1");
    private static LibertyServer server2 = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.initializationVectorTestServer2");

    private static final Class<?> thisClass = LTPAKeyRotationTests.class;

    // Initialize the user
    private static final String validUser = "user1";
    private static final String validPassword = "user1pwd";

    private static final String[] serverShutdownMessages = { "CWWKS4102E", "CWWKG0058E", "CWWKG0083W", "CWWKS4106E", "CWWKS4109W", "CWWKS4110E", "CWWKS4111E", "CWWKS4112E", "CWWKS4113W",
                                                             "CWWKS4114W", "CWWKS4115W", "CWWKS1859E" };

    private static String validationKeyPassword = "{xor}Lz4sLCgwLTs=";
    private static String validationKeyFIPSPassword = "{xor}CDo9Hgw=";

    // Initialize the FormLogin Clients
    private static FormLoginClient server1FlClient1;
    private static FormLoginClient server1FlClient2;
    private static FormLoginClient server2FlClient1;
    private static FormLoginClient server2FlClient2;

    // Define server.xml files
    private static final String DEFAULT_SERVER_XML = "server.xml";
    private static final String DEFAULT_FIPS_SERVER1_XML = "serverFIPS.xml";
    private static final String DEFAULT_FIPS_SERVER2_XML = "server2FIPS.xml";

    // Define the paths to the key files
    private static final String DEFAULT_KEY_PATH = "resources/security/ltpa.keys";
    private static final String CONFIGURED_VALIDATION_KEY1_PATH = "resources/security/configuredValidation1.keys";
    private static final String FIPS_VALIDATION_KEY1_PATH = "resources/security/validation1.keys";
    private static final String FIPS_VALIDATION_KEY2_PATH = "resources/security/validation2.keys";
    private static final String VALIDATION_KEYS_PATH = "resources/security/";
    private static final String VALIDATION_KEY1_PATH = "resources/security/validation1.keys";
    private static final String VALIDATION_KEY2_PATH = "resources/security/validation2.keys";
    private static final String VALIDATION_KEY3_PATH = "resources/security/validation3.keys";
    private static final String BAD_SHARED_VALIDATION_KEY1_PATH = "resources/security/validation3.keys";
    private static final String BAD_SHARED_VALIDATION_KEY2_PATH = "resources/security/validation4.keys";
    private static final String BAD_PRIVATE_VALIDATION_KEY1_PATH = "resources/security/validation5.keys";
    private static final String BAD_PRIVATE_VALIDATION_KEY2_PATH = "resources/security/validation6.keys";
    private static final String BAD_PUBLIC_VALIDATION_KEY1_PATH = "resources/security/validation7.keys";
    private static final String BAD_PUBLIC_VALIDATION_KEY2_PATH = "resources/security/validation8.keys";
    private static final String DIFFERENT_PW_VALIDATION_KEY_PATH = "resources/security/validation9.keys";

    // Define the paths to the alternate key files
    private static String ALT_VALIDATION_KEY1_PATH = "alternate/validation1.keys";
    private static String ALT_VALIDATION_KEY2_PATH = "alternate/validation2.keys";
    private static String ALT_VALIDATION_KEY3_PATH = "alternate/validation3.keys";
    private static String ALT_VALIDATION_KEY4_PATH = "alternate/validation4.keys";
    private static String ALT_VALIDATION_KEY5_PATH = "alternate/validation5.keys";
    private static String ALT_VALIDATION_KEY6_PATH = "alternate/validation6.keys";
    private static String ALT_VALIDATION_KEY7_PATH = "alternate/validation7.keys";
    private static String ALT_VALIDATION_KEY8_PATH = "alternate/validation8.keys";
    private static String ALT_VALIDATION_KEY9_PATH = "alternate/validation9.keys";
    private static String ALT_CONFIGVALIDATION_KEY1_PATH = "alternate/configuredValidation1.keys";
    
    private static String SERVER_XML_PATH = "server.xml";

    // Define the paths to the alternate key files
    private static String ALT_FIPS_VALIDATION_KEY1_PATH = "alternateFIPS/validation1.keys";
    private static String ALT_FIPS_VALIDATION_KEY2_PATH = "alternateFIPS/validation2.keys";
    private static String ALT_FIPS_VALIDATION_KEY3_PATH = "alternateFIPS/validation3.keys";
    private static String ALT_FIPS_VALIDATION_KEY4_PATH = "alternateFIPS/validation4.keys";
    private static String ALT_FIPS_VALIDATION_KEY5_PATH = "alternateFIPS/validation5.keys";
    private static String ALT_FIPS_VALIDATION_KEY6_PATH = "alternateFIPS/validation6.keys";
    private static String ALT_FIPS_VALIDATION_KEY7_PATH = "alternateFIPS/validation7.keys";
    private static String ALT_FIPS_VALIDATION_KEY8_PATH = "alternateFIPS/validation8.keys";
    private static String ALT_FIPS_VALIDATION_KEY9_PATH = "alternateFIPS/validation9.keys";
    private static String ALT_FIPS_CONFIGVALIDATION_KEY1_PATH = "alternateFIPS/configuredValidation1.keys";
    private static String FIPS_SERVER1_XML_PATH = "serverFIPS.xml";
    private static String FIPS_SERVER2_XML_PATH = "server2FIPS.xml";

    // Define the paths to the server.xml files
    private static final String relativeDirectory1 = server1.getServerRoot();
    private static final String wlpDirectory1 = server1.getInstallRoot();
    private static final String baseDirectory1 = server1.getInstallRootParent();

    private static final String relativeDirectory2 = server2.getServerRoot();
    private static final String wlpDirectory2 = server2.getInstallRoot();
    private static final String baseDirectory2 = server2.getInstallRootParent();

    // Define the remote message log file
    private static RemoteFile messagesLogFile1 = null;
    private static RemoteFile messagesLogFile2 = null;

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
            ALT_VALIDATION_KEY1_PATH = ALT_FIPS_VALIDATION_KEY1_PATH;
            ALT_VALIDATION_KEY2_PATH = ALT_FIPS_VALIDATION_KEY2_PATH;
            ALT_VALIDATION_KEY3_PATH = ALT_FIPS_VALIDATION_KEY3_PATH;
            ALT_VALIDATION_KEY4_PATH = ALT_FIPS_VALIDATION_KEY4_PATH;
            ALT_VALIDATION_KEY5_PATH = ALT_FIPS_VALIDATION_KEY5_PATH;
            ALT_VALIDATION_KEY6_PATH = ALT_FIPS_VALIDATION_KEY6_PATH;
            ALT_VALIDATION_KEY7_PATH = ALT_FIPS_VALIDATION_KEY7_PATH;
            ALT_VALIDATION_KEY8_PATH = ALT_FIPS_VALIDATION_KEY8_PATH;
            ALT_VALIDATION_KEY9_PATH = ALT_FIPS_VALIDATION_KEY9_PATH;
            ALT_CONFIGVALIDATION_KEY1_PATH = ALT_FIPS_CONFIGVALIDATION_KEY1_PATH;
            validationKeyPassword = validationKeyFIPSPassword;
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
    public static void setUp() throws Exception {

        // Copy validation key file (validation1.keys) to the server
        server2.useSecondaryHTTPPort();

        LibertyServer[] servers = { server1, server2 };

        for (LibertyServer server : servers) {

            server.setupForRestConnectorAccess();

//            if (fipsEnabled) {
//                File fipsServerXml;
//                if (server == server1) {
//                    fipsServerXml = new File(server.pathToAutoFVTTestFiles + DEFAULT_FIPS_SERVER1_XML);
//                } else {
//                    fipsServerXml = new File(server.pathToAutoFVTTestFiles + DEFAULT_FIPS_SERVER2_XML);
//
//                }
//                File serverXml = new File(server.pathToAutoFVTTestFiles + DEFAULT_SERVER_XML);
//                Files.move(fipsServerXml.toPath(), serverXml.toPath(), StandardCopyOption.REPLACE_EXISTING);
//                server.copyFileToLibertyServerRoot(DEFAULT_SERVER_XML);
//            }

            server.startServer(true);

            assertNotNull("Featurevalid did not report update was complete",
                          server.waitForStringInLog("CWWKF0008I"));
            assertNotNull("Security service did not report it was ready",
                          server.waitForStringInLog("CWWKS0008I"));
            assertNotNull("The application did not report is was started",
                          server.waitForStringInLog("CWWKZ0001I"));
            // Wait for the LTPA configuration to be ready
            assertNotNull("Expected LTPA configuration ready message not found in the log.",
                          server.waitForStringInLog("CWWKS4105I"));

        }

        messagesLogFile1 = server1.getDefaultLogFile();
        messagesLogFile2 = server2.getDefaultLogFile();

        server1FlClient1 = new FormLoginClient(server1, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin1");
        server1FlClient2 = new FormLoginClient(server1, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin2");
        server2FlClient1 = new FormLoginClient(server2, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin1");
        server2FlClient2 = new FormLoginClient(server2, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin2");

    }

    @Before
    public void moveLogMark() throws Exception {
        moveLogMarkForServer(server1);
        moveLogMarkForServer(server2);

    }

    @After
    public void after() throws Exception {
        resetConnection();
        resetServer(server1);
        resetServer(server2);
    }

    public void resetConnection() {
        server1FlClient1.resetClientState();
        server1FlClient2.resetClientState();

        server2FlClient1.resetClientState();
        server2FlClient2.resetClientState();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        try {
            server1.stopServer(serverShutdownMessages);
            server2.stopServer(serverShutdownMessages);
        } finally {
            server1FlClient1.resetClientState();
            server1FlClient2.resetClientState();

            server2FlClient1.resetClientState();
            server2FlClient2.resetClientState();
        }
    }

    /**
     * Verify that an SSO cookie retrieved from authentication on one server can be used on a second server using a validation key and derived IV where both
     * servers use the same keysPassword.
     *
     * Steps:
     * <OL>
     * <LI> Configure Server #1 and Server #2 to contain different primary LTPA Keys with the same LTPA keys passwords with monitorValidationKeysDir set to True
     * <LI> Access a simple servlet with form login using valid credentials on Server #1 and retrieve the SSO cookie
     * <LI> Copy the LTPA primary key from Server #1 and place it in Server #2
     * <LI> Rename the copied key to the name specified for the validation key in server.xml (configuredValidationKey1.keys)
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
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLog("CWWKS4105I", 5000));

        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4105I", 5000));

        // Replace the randomly generated LTPA keys with the known valid ltpa keys and assert the change occurs
        renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLog("CWWKS4107A", 5000));

        renameFileIfExists(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, true, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Initial login to simple servlet for form login1
        String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Retrieve the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Copy the ltpa.keys file from server #1 to server #2 and rename it as configuredValidation1.key (server #2 now contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);
        renameFileIfExists(VALIDATION_KEY1_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);

        // Wait for the LTPA configuration to be ready after the change
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Refresh the server configuration to allow recognition of the configured validation key
        ServerConfiguration server2Config = server2.getServerConfiguration();
        updateConfigDynamically(server2, server2Config);

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
     * <LI> Rename the copied key to the name specified for the validation key in server.xml (configuredValidationKey1.keys)
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
    @Mode(TestMode.LITE)
    @Test
    public void testLTPAValidationKeyUsage_twoServers_samePW_monitorValidationKeysDir_false() throws Exception {

        // Configure the servers
        configureServer("false", "10", false, server1);
        configureServer("false", "10", false, server2);

        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLog("CWWKS4107A", 5000));

        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Replace the randomly generated LTPA keys with the known valid ltpa keys and assert the change occurs
        renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLog("CWWKS4107A", 5000));

        renameFileIfExists(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, true, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Initial login to simple servlet for form login1
        String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Copy the ltpa.keys file to server #2 and rename it as configuredValidation1.key (server #2 contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);
        ServerConfiguration server2Config = server2.getServerConfiguration();
        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails because with monitorValidationKeysDir means the server does not recognize unspecified keys file
        assertTrue("An invalid cookie should result in authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));

        // Rename the validation keys file to ConfgiuredValidation1.keys as specified in the server configuration
        renameFileIfExists(VALIDATION_KEY1_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);

        // Refresh the server configuration to allow recognition of the renamed validation key
        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login is successful
        server2FlClient1.accessProtectedServletWithAuthorizedCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);
    }

    /**
     * Verify that an SSO cookie retrieved from authentication on one server can be used on a second server using a validation key and derived IV where both servers use different
     * keysPassword.
     *
     * Steps:
     * <OL>
     * <LI> Configure Server #1 and Server #2 to contain different primary LTPA Keys with different LTPA keys passwords with monitorValidationKeysDir set to True
     * <LI> Configure the different passwords in the servers
     * <LI> Access a simple servlet with form login using valid credentials on Server #1 and retrieve the SSO cookie
     * <LI> Copy the LTPA primary key from Server #1 and place it in Server #2
     * <LI> Rename the copied key to the name specified for the validation key in server.xml (configuredValidationKey1.keys)
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
    @AllowedFFDC({ "javax.crypto.BadPaddingException" })
    public void testLTPAValidationKeyUsage_twoServers_differentPW_monitorValidationKeysDir_true() throws Exception {

        // Configure the servers
        configureServer("true", "10", true, server1);
        configureServer("true", "10", true, server2);

        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLog("CWWKS4107A", 5000));

        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Replace the randomly generated LTPA keys with the known valid ltpa keys and assert the change occurs
        renameFileIfExists(DIFFERENT_PW_VALIDATION_KEY_PATH, DEFAULT_KEY_PATH, true, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLog("CWWKS4107A", 5000));

        renameFileIfExists(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, true, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Change the default keysPassword configured in server.xml to that of the added ltpa keys file (Liberty)
        ServerConfiguration serverConfig = server1.getServerConfiguration();
        LTPA ltpa = serverConfig.getLTPA();
        setLTPAKeyPasswordElement(ltpa, "{xor}EzY9Oi0rJg==");
        updateConfigDynamically(server1, serverConfig);

        // Change the default password of the validation key to that of the added ltpa keys file from Server #1 (Liberty)
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAvalidationKeyPasswordElement(ltpa2, "{xor}EzY9Oi0rJg==");
        updateConfigDynamically(server2, server2Config);

        // Initial login to simple servlet for form login1
        String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Copy the ltpa.keys file to server #2 and rename it as configuredValidation1.key (server #2 contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server2);
        renameFileIfExists(DIFFERENT_PW_VALIDATION_KEY_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);

        // Wait for the LTPA configuration to be ready after the change
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Attempt to login to the simple servlet on server #2 and assert that the login is successful (uses validation key)
        server2FlClient1.accessProtectedServletWithAuthorizedCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);
    }
        
        
        
 /**
     * Negative Test Case:
     * 1. Server #1 and Server #2 contain different primary LTPA keys with different LTPA keys passwords
     * 2. Access a simple servlet with form login using valid credentials on server #1
     * 3. authentication should be successful and retrieve the cookie
     * 4. Access a simple servlet with form login on server #2 using the cookie (token) from server #1
     * 5. authentication should fail because no validation keys and primary key are different, and since the keys are different, the IV derived is also different
     */
    @Mode(TestMode.LITE)
    @Test
    @AllowedFFDC({ "javax.crypto.BadPaddingException"})
    public void testLTPAValidationKeyUsage_twoServers_different_KeyPW() throws Exception {
        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server1);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        

        // Configure both servers, and replace the generated LTPA keys of each server using the values from the validation keys
        configureServer("true", "10", true, server1);
        renameFileIfExists(DIFFERENT_PW_VALIDATION_KEY_PATH, DEFAULT_KEY_PATH, true, server1);

        configureServer("true", "10", true, server2);
        renameFileIfExists(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, true, server2);

        // Change the default keysPassword to that of the added ltpa keys file (encrypted "Liberty")
        ServerConfiguration serverConfig = server1.getServerConfiguration();
        LTPA ltpa = serverConfig.getLTPA();
        setLTPAKeyPasswordElement(ltpa, "{xor}EzY9Oi0rJg==");
        updateConfigDynamically(server1, serverConfig);

        // Initial login to simple servlet for form login1
        String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Copy the ltpa.keys file to server #2 and rename it as configuredValidation1.key (server #2 contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server2);
        renameFileIfExists(DIFFERENT_PW_VALIDATION_KEY_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);

        // // Change the default password of the validation key to another password (encrypted "mypassword")
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAvalidationKeyPasswordElement(ltpa2, "{xor}MiYvPiwsKDAtOw==");
        setLTPAKeyPasswordElement(ltpa2, "{xor}MiYvPiwsKDAtOw==");
        

        // // Attempt to login to the simple servlet on server #2 and assert that the login is a failure as expected
        assertTrue("An invalid cookie should result in authorization challenge",server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }


/**
     * Negative Test Case:
     * 1. Server #1 and Server #2 contain different primary LTPA keys with different LTPA keys passwords
     * 2. Access a simple servlet with form login using valid credentials on Server #1
     * 3. authentication should be successful and retrieve the SSO cookie
     * 4. Replace LTPA keys with validation keys from respective servers to ensure no validation keys exist in either server.
     * 5. Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * 6. Authentication fails because the SSO token cannot be decrypted by the primary key of server 2 
     * (passwords might be the same but since the primary key values are different and there are no validation keys containing ltpa1, it fails). IV is set to
     * different valid ltpa keys
     */

     @Mode(TestMode.LITE)
     @Test
     @AllowedFFDC({ "javax.crypto.BadPaddingException","java.lang.IllegalArgumentException" })
     public void testLTPAValidationKeyUsage_no_validation_keys() throws Exception {
         // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
         copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
         copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);

 
         // Configure both servers, and replace the generated LTPA keys with the known valid ltpa key in server 1
         configureServer("true", "10", true, server1);
         renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
       
 
         configureServer("true", "10", true, server2);
          // Configure both servers, and replace the generated LTPA keys with the known valid ltpa key in server 2
         renameFileIfExists(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, true, server2);
         // Wait for the LTPA configuration to be ready after the change
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
        server2.waitForStringInLog("CWWKS4105I", 5000));

         
 
         // Change the default keysPassword to that of the added ltpa keys file (Liberty)
         ServerConfiguration serverConfig = server1.getServerConfiguration();
         LTPA ltpa = serverConfig.getLTPA();
         setLTPAKeyPasswordElement(ltpa, "{xor}Lz4sLCgwLTs=");
         updateConfigDynamically(server1, serverConfig);
 
         // Initial login to simple servlet for form login1
         String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);
 
         // Get the SSO cookie from the login
         String server1Cookie = server1FlClient1.getCookieFromLastLogin();
         assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

 
         /// Change the default keysPassword to that of the added ltpa keys file (Liberty)
         ServerConfiguration server2Config = server2.getServerConfiguration();
         LTPA ltpa2 = server2Config.getLTPA();
         setLTPAKeyPasswordElement(ltpa2, "{xor}Lz4sLCgwLTs=");
         updateConfigDynamically(server2, server2Config);
         
 
         // // Attempt to login to the simple servlet on server #2 and assert that the login fails 
         assertTrue("An invalid cookie should result in authorization challenge",server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
     }


 /**
     * Negative Test Case:
     * 1. Server #1 and Server #2 contain different primary LTPA keys with different LTPA keys passwords and corrupted keys in server 2
     * 2. Access a simple servlet with form login using valid credentials on Server #1
     * 3. authentication should be successful and retrieve the SSO cookie
     * 4. Place an invalid primary key into Server #2 (different than primary key of Server #1)
     * 5. Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * 6. Authentication fails because the SSO token cannot be decrypted by the primary and validation key does not exist in server 2 to override the ltpa key
     */

     @Mode(TestMode.LITE)
     @Test
     @AllowedFFDC({ "javax.crypto.BadPaddingException","java.lang.IllegalArgumentException" })
     public void testLTPAValidationKeyUsage_no_validation_keys_and_bad_keys() throws Exception {
         // Copy valid ltpa keys to server 1 and an invalid one to server 2
         copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
         copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY3_PATH, server2);

 
         // Configure both servers, and replace the randomly generated LTPA keys with the known valid ltpa keys
         configureServer("true", "10", true, server1);
         renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
 
         configureServer("true", "10", true, server2);
         renameFileIfExists(VALIDATION_KEY3_PATH, DEFAULT_KEY_PATH, true, server2);

         // Wait for the LTPA configuration error message (ltpa contains garbage value)
         assertNotNull("Expected LTPA configuration error message not found in the log.",
                       server2.waitForStringInLog("CWWKS4106E", 5000));
         
 
         // Change the default keysPassword to that of the added ltpa keys file (Liberty)
         ServerConfiguration serverConfig = server1.getServerConfiguration();
         LTPA ltpa = serverConfig.getLTPA();
         setLTPAKeyPasswordElement(ltpa, "{xor}Lz4sLCgwLTs=");
         updateConfigDynamically(server1, serverConfig);
 
         // Initial login to simple servlet for form login1
         String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);
 
         // Get the SSO cookie from the login
         String server1Cookie = server1FlClient1.getCookieFromLastLogin();
         assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

 
         // Change the default keysPassword to that of the added ltpa keys file (Liberty)
         ServerConfiguration server2Config = server2.getServerConfiguration();
         LTPA ltpa2 = server2Config.getLTPA();
         setLTPAKeyPasswordElement(ltpa2, "{xor}Lz4sLCgwLTs=");
         
 
         // // Attempt to login to the simple servlet on server #2 and assert that the login fails as only bad key is in the IV of server 2
         assertTrue("An invalid cookie should result in authorization challenge",server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
     }

     /**
     * Negative Test Case:
     * 1. Server #1 and Server #2 contain different primary LTPA keys with same LTPA keys passwords
     * 2. Access a simple servlet with form login using valid credentials on Server #1
     * 3. authentication should be successful and retrieve the SSO cookie
     * 4. Place an invalid primary and validation key into Server #2 (different than primary key of Server #1)
     * 5. Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * 6. Authentication fails because the SSO token cannot be decrypted by the primary and validation key (keys are bad and IV based on the keys is invalid)
     */

    @Mode(TestMode.LITE)
    @Test
    @AllowedFFDC({ "javax.crypto.BadPaddingException","java.lang.IllegalArgumentException" })
    public void testLTPAValidationKeyUsage_bad_keys() throws Exception {
        // Copy valid ltpa keys to server1 and invalid primary and valid key to server 2
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY3_PATH, server2);
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY4_PATH, server2);

        // Configure both servers, and replace the randomly generated LTPA keys with the known valid ltpa keys
        configureServer("true", "10", true, server1);
        renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
      

        configureServer("true", "10", true, server2);
        renameFileIfExists(VALIDATION_KEY3_PATH, DEFAULT_KEY_PATH, true, server2);
        // Wait for the LTPA configuration to be an error after the change
        assertNotNull("Expected LTPA configuration error message not found in the log.",
                      server2.waitForStringInLog("CWWKS4106E", 5000));

        renameFileIfExists(BAD_SHARED_VALIDATION_KEY2_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);
     
        

        // Change the default keysPassword to that of the added ltpa keys file (Liberty)
        ServerConfiguration serverConfig = server1.getServerConfiguration();
        LTPA ltpa = serverConfig.getLTPA();
        setLTPAKeyPasswordElement(ltpa, "{xor}Lz4sLCgwLTs=");
        updateConfigDynamically(server1, serverConfig);

        // Initial login to simple servlet for form login1
        String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

       // Change the default keysPassword to that of the added ltpa keys file (Liberty)
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAvalidationKeyPasswordElement(ltpa2, "{xor}Lz4sLCgwLTs=");
        setLTPAKeyPasswordElement(ltpa2, "{xor}Lz4sLCgwLTs=");
        

        // // Attempt to login to the simple servlet on server #2 and assert that the login  fails as expected
        assertTrue("An invalid cookie should result in authorization challenge",server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }

 /**
     * Negative Test Case:
     * 1. Server #1 contains primary fips LTPA keys(in non fips) and non fips LTPA key(in fips)
     * 4. Place a fips validation key (in non fips) and non fips validation key(in fips)
     * 5. IV would be set to an invalid key as fips keys only work in a fips environment(same for non fips)
     */

     @Mode(TestMode.LITE)
     @Test
     @AllowedFFDC({ "javax.crypto.BadPaddingException","java.lang.IllegalArgumentException" })
     public void testLTPA_fipskey_in_nonfips_and_vice_versa() throws Exception {
        


         if (!fipsEnabled){
        
     // Copy valid fips primary and validation keys into server 1
         copyFileToServerResourcesSecurityDir(ALT_FIPS_VALIDATION_KEY1_PATH, server1);
         copyFileToServerResourcesSecurityDir(ALT_FIPS_VALIDATION_KEY2_PATH, server1);
         
         ServerConfiguration serverConfig = server1.getServerConfiguration();
 
         // Configure the server, and replace the generated LTPA key with the fips key
         configureServer("true", "10", true, server1);

         renameFileIfExists(FIPS_VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
         renameFileIfExists(FIPS_VALIDATION_KEY2_PATH,CONFIGURED_VALIDATION_KEY1_PATH, true, server1);

         updateConfigDynamically(server1, serverConfig);

         //assert ltpa token creation fails
         assertNotNull("The system cannot create the LTPA token because the required com.ibm.websphere.ltpa.3DESKey property is missing",
        server1.waitForStringInLog("CWWKS4102E", 5000));

         
        
         }

         else{
            // Copy valid non fips primary and validation keys into server 1
            copyFileToServerResourcesSecurityDir("alternate/validation1.keys", server1);
            copyFileToServerResourcesSecurityDir("alternate/validation2.keys", server1);
            
            ServerConfiguration serverConfig = server1.getServerConfiguration();
    
            // Configure the server, and replace the generated LTPA key with the non fips key
            configureServer("true", "10", true, server1);
            //configureServer("true", "10", true, server2);
            renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
            renameFileIfExists(VALIDATION_KEY2_PATH,CONFIGURED_VALIDATION_KEY1_PATH, true, server1);
   
            updateConfigDynamically(server1, serverConfig);
   
            //assert ltpa token creation fails
            assertNotNull("The system cannot create the LTPA token because the required com.ibm.websphere.ltpa.sharedKey property is missing",
           server1.waitForStringInLog("CWWKS4102E", 5000));
         }
     
        }


    /**
     * Negative Test Case:
     * 1. Server #1 and Server #2 contain different primary LTPA keys with different invalid LTPA keys passwords for server 2
     * 2. Access a simple servlet with form login using valid credentials on server #1
     * 3. Authentication should be successful and retrieve the SSO cookie
     * 4. Replace the `password` property of the validation key with ‘garbage’ values
     * 5. Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * 6. Authentication fails because although IV and keys file is valid
     */

     @Mode(TestMode.LITE)
     @Test
     @AllowedFFDC({ "javax.crypto.BadPaddingException","java.lang.IllegalArgumentException" })
    public void testLTPAValidationKeyUsage_invalid_passwords() throws Exception {
          // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);
  
          // Configure both servers, and replace the randomly generated LTPA keys with the known valid ltpa keys
          configureServer("true", "10", true, server1);
          renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
  
          // Wait for the LTPA configuration to be ready after the change
        
  
          configureServer("true", "10", true, server2);
   

          renameFileIfExists(VALIDATION_KEY1_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);
  
          // Change the default keysPassword to that of the added ltpa keys file (Liberty)
          ServerConfiguration serverConfig = server1.getServerConfiguration();
          LTPA ltpa = serverConfig.getLTPA();
          setLTPAKeyPasswordElement(ltpa, "{xor}EzY9Oi0rJg==");
          updateConfigDynamically(server1, serverConfig);
  
          // Initial login to simple servlet for form login1
          String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);
  
          // Get the SSO cookie from the login
          String server1Cookie = server1FlClient1.getCookieFromLastLogin();
          assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);
  
  
          // // Change the default password  to an invalid value
          ServerConfiguration server2Config = server2.getServerConfiguration();
          LTPA ltpa2 = server2Config.getLTPA();
          setLTPAvalidationKeyPasswordElement(ltpa2, "garbage");
          setLTPAKeyPasswordElement(ltpa2, "garbage");
          
  
          // // Attempt to login to the simple servlet on server #2 and assert that the login fails 
          assertTrue("An invalid cookie should result in authorization challenge",server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }


     /**
     * Negative Test Case:
     * 1. Server #1 and Server #2 contain different primary LTPA keys with different LTPA keys passwords
     * 2. Access a simple servlet with form login using valid credentials on server #1
     * 3. Authentication should be successful and retrieve the SSO cookie
     * 4. Copy the LTPA Primary key from Server #1 and place it in Server #2, renamed as validation1.key
     * 5. Replace the `password` property of the validation key with ‘garbage’ values
     * 6. Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * 7. Authentication fails because although IV and keys file are invalid
     */

     @Mode(TestMode.LITE)
     @Test
     @AllowedFFDC({ "javax.crypto.BadPaddingException","java.lang.IllegalArgumentException" })
    public void testLTPAValidationKeyUsage_set_passing_validation_key_to_failing_validation_key() throws Exception {
          // Copy valid ltpa keys to server1. Copy invalid keys to server 2.
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY3_PATH, server2);
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY4_PATH, server2);
          
  
          // Configure both servers, and replace the randomly generated LTPA keys with the ltpa keys
          configureServer("true", "10", true, server1);
          renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
  
          // Wait for the LTPA configuration to be ready after the change
        
  
          configureServer("true", "10", true, server2);
          renameFileIfExists(VALIDATION_KEY3_PATH, DEFAULT_KEY_PATH, true, server2);
          // Wait for the LTPA configuration error after the change (garbage value)

          assertNotNull("Expected LTPA configuration error message not found in the log.",
                        server2.waitForStringInLog("CWWKS4106E", 5000));

          renameFileIfExists(BAD_SHARED_VALIDATION_KEY2_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);

  
          // Change the default keysPassword to that of the added ltpa keys file (Liberty)
          ServerConfiguration serverConfig = server1.getServerConfiguration();
          LTPA ltpa = serverConfig.getLTPA();
          setLTPAKeyPasswordElement(ltpa, "{xor}EzY9Oi0rJg==");
          updateConfigDynamically(server1, serverConfig);
  
          // Initial login to simple servlet for form login1
          String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);
  
          // Get the SSO cookie from the login
          String server1Cookie = server1FlClient1.getCookieFromLastLogin();
          assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);
  
          ServerConfiguration server2Config = server2.getServerConfiguration();
          LTPA ltpa2 = server2Config.getLTPA();


          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);

          // Change the default keysPassword to that of the added ltpa keys file (Liberty)
          setLTPAvalidationKeyFileNameElement(ltpa2, "validation1.keys");
          setLTPAvalidationKeyPasswordElement(ltpa2, "{xor}EzY9Oi0rJg==");
          setLTPAKeyPasswordElement(ltpa2, "{xor}EzY9Oi0rJg==");
          
  
          // // Attempt to login to the simple servlet on server #2 and assert that the login is successful (uses validation key)
          server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);
        
          
          setLTPAvalidationKeyFileNameElement(ltpa2, "validation4.keys");
          setLTPAvalidationKeyPasswordElement(ltpa2, "garbage");
          setLTPAKeyPasswordElement(ltpa2, "garbage");
          
  
          // // Attempt to login to the simple servlet on server #2 and assert that the login fails
          assertTrue("An invalid cookie should result in authorization challenge",server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));


          
    
        }



        /**
     * Negative Test Case:
     * 1. Server #1 and Server #2 contain different primary LTPA keys 
     * 2. Access a simple servlet with form login using valid credentials on server #1
     * 3. Authentication should be successful and retrieve the SSO cookie
     * 4. Copy the LTPA Primary key as in Server #1 and place it in Server #2, renamed as validation1.key
     * 5. Replace the `password` property to the same as that of server 1. 
     * 6. Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * 7. Authentication fails because although IV and keys are invalid as MonitorValidationKeysDir was false so any changes to the validation key
     * will not be registered. Even though validation1.keys should result in a success on server 2, it does not as the IV was still set to ltpa2.keys.
     */

     @Mode(TestMode.LITE)
     @Test
     @AllowedFFDC({ "javax.crypto.BadPaddingException","java.lang.IllegalArgumentException" })
    public void testLTPAValidationKeyUsage_set_MonitorValidationKeysDir_to_false_with_failing_validation_key() throws Exception {
          // Copy valid ltpa keys to each server
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server2);
          
         
          
  
          // Configure both servers, and replace the generated LTPA keys with the known valid key for server 1 and invalid one for server 2
          configureServer("true", "10", true, server1);
          renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
  
          configureServer("false", "0", true, server2);


     
          // Change the default keysPassword to that of the added ltpa keys file (Liberty)
          ServerConfiguration serverConfig = server1.getServerConfiguration();
          LTPA ltpa = serverConfig.getLTPA();
          setLTPAKeyPasswordElement(ltpa, "{xor}EzY9Oi0rJg==");
          updateConfigDynamically(server1, serverConfig);
  
          // Initial login to simple servlet for form login1
          String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);
  
          // Get the SSO cookie from the login
          String server1Cookie = server1FlClient1.getCookieFromLastLogin();
          assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);
  
          

          ServerConfiguration server2Config = server2.getServerConfiguration();
          LTPA ltpa2 = server2Config.getLTPA();
        
        // Change the default keysPassword to that of the added ltpa keys file (Liberty)
          setLTPAvalidationKeyFileNameElement(ltpa2, "validation1.keys");
          setLTPAvalidationKeyPasswordElement(ltpa2, "{xor}EzY9Oi0rJg==");
          setLTPAKeyPasswordElement(ltpa2, "{xor}EzY9Oi0rJg==");
    

          // login should fail as the updates to validation keys to enable a successful login do not happen as MonitorValidationKeysDir is false (the IV is still invalid)
          assertTrue("An invalid cookie should result in authorization challenge",server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));

          
    
        }

     /**
     * Negative Test Case:
     * 1. Server #1 and Server #2 contain different primary LTPA keys with different LTPA keys passwords
     * 2. Access a simple servlet with form login using valid credentials on server #1
     * 3. Authentication should be successful and retrieve the SSO cookie
     * 4. Copy the LTPA Primary key from Server #1 and place it in Server #2, renamed as validation1.key
     * 5. Replace the `password` property of the validation key with swapped 3DES values
     * 6. Attempt to access the SimpleServlet with form login on server #2 using the same cookie token from Server #1
     * 7. Authentication fails because although IV and keys file is valid, the shared key is incorrect
     */

     @Mode(TestMode.LITE)
     @Test
     @AllowedFFDC({ "javax.crypto.BadPaddingException","java.lang.IllegalArgumentException" })
    public void testLTPAValidationKeyUsage_swapped_3DESkey() throws Exception {
          // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY1_PATH, server1);
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY4_PATH, server2);
          copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
  
          // Configure both servers, and replace the randomly generated LTPA keys  with valid keys in server 1 and invalid ones in server 2
          configureServer("true", "10", true, server1);
          renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH, true, server1);
  
        
          configureServer("true", "10", true, server2);
          renameFileIfExists(BAD_SHARED_VALIDATION_KEY2_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);
          renameFileIfExists(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, true, server2);

          // Change the default keysPassword to that of the added ltpa keys file (Liberty)
          ServerConfiguration serverConfig = server1.getServerConfiguration();
          LTPA ltpa = serverConfig.getLTPA();
          setLTPAKeyPasswordElement(ltpa, "{xor}Lz4sLCgwLTs=");
          setLTPAvalidationKeyPasswordElement(ltpa, "{xor}Lz4sLCgwLTs=");

          updateConfigDynamically(server1, serverConfig);
  
          // Initial login to simple servlet for form login1
          String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);
  
          // Get the SSO cookie from the login
          String server1Cookie = server1FlClient1.getCookieFromLastLogin();
          assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);
  
  
          // Change the default password of the validation key to that of the added ltpa keys file
          // set the key file element as the failing key
          ServerConfiguration server2Config = server2.getServerConfiguration();
          LTPA ltpa2 = server2Config.getLTPA();
          setLTPAvalidationKeyFileNameElement(ltpa2, "validation4.keys");
          setLTPAvalidationKeyPasswordElement(ltpa2, "{xor}Lz4sLCgwLTs=");
          setLTPAKeyPasswordElement(ltpa2, "{xor}Lz4sLCgwLTs=");
          
  
          // // Attempt should fail as the IV is set to an invalid validation key
          assertTrue("An invalid cookie should result in authorization challenge",server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));
    }



    /**
     * Verify that an SSO cookie retrieved from authentication on one server can be used on a second server using a validation key and derived IV where both servers use different
     * keysPassword and with the server monitorValidationKeysDir variable set to false.
     *
     * Steps:
     * <OL>
     * <LI> Configure Server #1 and Server #2 to contain different primary LTPA Keys with different LTPA keys passwords with monitorValidationKeysDir set to False
     * <LI> Access a simple servlet with form login using valid credentials on Server #1 and retrieve the SSO cookie
     * <LI> Copy the LTPA primary key from Server #1 and place it in Server #2
     * <LI> Attempt to access the simple servlet with form login on Server #2 using the SSO cookie from Server #1
     * <LI> Rename the copied key to the name specified for the validation key in server.xml (configuredValidationKey1.keys)
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
    @Mode(TestMode.LITE)
    @Test
    @AllowedFFDC({ "javax.crypto.BadPaddingException" })
    public void testLTPAValidationKeyUsage_twoServers_differentPW_monitorValidationKeysDir_false() throws Exception {

        // Configure the servers
        configureServer("false", "10", false, server1);
        configureServer("false", "10", false, server2);

        // Copy valid ltpa keys to each server, the ltpa keys are configured using different keysPassword
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLog("CWWKS4107A", 5000));

        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY2_PATH, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Replace the randomly generated LTPA keys with the known valid ltpa keys and assert the change occurs
        renameFileIfExists(DIFFERENT_PW_VALIDATION_KEY_PATH, DEFAULT_KEY_PATH, true, server1);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server1.waitForStringInLog("CWWKS4107A", 5000));

        renameFileIfExists(VALIDATION_KEY2_PATH, DEFAULT_KEY_PATH, true, server2);
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server2.waitForStringInLog("CWWKS4107A", 5000));

        // Change the default keysPassword configured in server.xml to that of the added ltpa keys file (Liberty)
        ServerConfiguration serverConfig = server1.getServerConfiguration();
        LTPA ltpa = serverConfig.getLTPA();
        setLTPAKeyPasswordElement(ltpa, "{xor}EzY9Oi0rJg==");
        updateConfigDynamically(server1, serverConfig);

        // Change the default password of the validation key to that of the added ltpa keys file from Server #1 (Liberty)
        ServerConfiguration server2Config = server2.getServerConfiguration();
        LTPA ltpa2 = server2Config.getLTPA();
        setLTPAvalidationKeyPasswordElement(ltpa2, "{xor}EzY9Oi0rJg==");
        updateConfigDynamically(server2, server2Config);

        // Initial login to simple servlet for form login1
        String response1 = server1FlClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookie from the login
        String server1Cookie = server1FlClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", server1Cookie);

        // Copy the ltpa.keys file to server #2 and rename it as configuredValidation1.key (server #2 contains the ltpa.keys file from server #1 as a validation key)
        copyFileToServerResourcesSecurityDir(ALT_VALIDATION_KEY9_PATH, server2);
        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login fails because with monitorValidationKeysDir means the server does not recognize unspecified keys file
        assertTrue("An invalid cookie should result in authorization challenge",
                   server2FlClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie));

        // Rename the validation keys file to ConfgiuredValidation1.keys as specified in the server configuration
        renameFileIfExists(DIFFERENT_PW_VALIDATION_KEY_PATH, CONFIGURED_VALIDATION_KEY1_PATH, true, server2);

        // Refresh the server configuration to allow recognition of the renamed validation key
        updateConfigDynamically(server2, server2Config);

        // Attempt to login to the simple servlet on server #2 and assert that the login is successful
        server2FlClient1.accessProtectedServletWithAuthorizedCookie(FormLoginClient.PROTECTED_SIMPLE, server1Cookie);
    }

    public void moveLogMarkForServer(LibertyServer server) throws Exception {
        server.setMarkToEndOfLog(messagesLogFile1);
        server.setMarkToEndOfLog(messagesLogFile2);
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
                              server.waitForStringInLog("CWWKS4113W", 5000));
            }

            if (waitForLTPAConfigReadyMessage) {
                // Wait for the LTPA configuration to be ready after the change
                assertNotNull("Expected LTPA configuration ready message not found in the log.",
                              server.waitForStringInLog("CWWKS4105I", 5000));
            }
        }

        // Assert that a default ltpa.keys file is generated
        assertFileWasCreated(DEFAULT_KEY_PATH, server);
        server.setKeysAndJVMOptsForFips();
        if (setLogMarkToEnd)
            server.setMarkToEndOfLog(messagesLogFile1);
        server.setMarkToEndOfLog(messagesLogFile2);
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
        String logLine = server.waitForStringInLogUsingMark("CWWKG001[7-8]I");

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
    private static void renameFileIfExists(String filePath, String newFilePath, boolean checkFileIsGone, LibertyServer server) throws Exception {
        Log.info(thisClass, "renameFileIfExists", "\nfilepath: " + filePath + "\nnewFilePath: " + newFilePath);
        server.setMarkToEndOfLog(server.getDefaultLogFile());

        if (fileExists(filePath, 1, server)) {
            if (fileExists(newFilePath, 1, server)) {
                LibertyFileManager.moveLibertyFile(server.getFileFromLibertyServerRoot(filePath), server.getFileFromLibertyServerRoot(newFilePath));
            } else {
                Log.info(thisClass, "renameFileIfExists", "Calling server.renameLibertyServerRootFile");
                server.renameLibertyServerRootFile(filePath, newFilePath);
            }
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

        // Make sure the mark is at the end of the log, so we don't use earlier messages.
        moveLogMarkForServer(server);

        // We need to put the base config back, otherwise the waits below will timeout on some tests
        configureServer("true", "10", true, server);

        // Delete all ltpa keys files in the security directory
        deleteFileIfExists(DEFAULT_KEY_PATH, false, server);
        deleteFileIfExists(VALIDATION_KEY1_PATH, true, server);
        deleteFileIfExists(VALIDATION_KEY2_PATH, true, server);
        deleteFileIfExists(CONFIGURED_VALIDATION_KEY1_PATH, true, server);

        // Wait for the LTPA configuration to be ready after the change
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server.waitForStringInLog("CWWKS4105I", 10000));

        // Assert that a default ltpa.keys file exists prior to next test case
        assertFileWasCreated(DEFAULT_KEY_PATH, server);
        Log.info(thisClass, "resetServer", "exiting");
    }
}