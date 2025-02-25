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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;

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
import com.ibm.websphere.simplicity.config.Authentication;
import com.ibm.websphere.simplicity.config.ConfigElementList;
import com.ibm.websphere.simplicity.config.LTPA;
import com.ibm.websphere.simplicity.config.ServerConfiguration;
import com.ibm.websphere.simplicity.config.ValidationKeys;
import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.webcontainer.security.test.servlets.FormLoginClient;

import componenttest.annotation.AllowedFFDC;
import componenttest.annotation.CheckForLeakedPasswords;
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
public class IVChangesTests {
    
 // Initialize needed strings for the tests
 protected static String METHODS = null;
 protected static final String APP_NAME = "IVChangesTestServer";
 protected static final String PROGRAMMATIC_API_SERVLET = "ProgrammaticAPIServlet";
 protected static final String authTypeForm = "FORM";
 protected static final String authTypeBasic = "BASIC";
 protected static final String cookieName = "LtpaToken2";

 private static final String CONFIGURED_VALIDATION_KEY1_PATH = "resources/security/ltpa.keys";

 // Keys to help readability of the test
 protected static final boolean IS_MANAGER_ROLE = true;
 protected static final boolean NOT_MANAGER_ROLE = false;
 protected static final boolean IS_EMPLOYEE_ROLE = true;
 protected static final boolean NOT_EMPLOYEE_ROLE = false;

 // Initialize a liberty server for form login
 private static LibertyServer server = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.IVChangesTestServer1");

 //Initialize second server for form login
 //private static LibertyServer server2 = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.IVChangesTestServer2");

 private static final Class<?> thisClass = IVChangesTests.class;

 // Initialize the user
 private static final String validUser = "user1";
 private static final String validPassword = "user1pwd";

 private static final String[] serverShutdownMessages = { "CWWKG0058E", "CWWKG0083W", "CWWKS4106E", "CWWKS4109W", "CWWKS4110E", "CWWKS4111E", "CWWKS4112E", "CWWKS4113W",
                                                          "CWWKS4114W", "CWWKS4115W", "CWWKS1859E" };

 private static String validationKeyPassword = "{xor}Lz4sLCgwLTs=";
 private static String validationKeyFIPSPassword = "{xor}CDo9Hgw=";

 // Initialize the FormLogin Clients
 private static final FormLoginClient flClient1 = new FormLoginClient(server, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin1");
 private static final FormLoginClient flClient2 = new FormLoginClient(server, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin2");


//   // Initialize the FormLogin Clients
//   private static final FormLoginClient flClient1_2 = new FormLoginClient(server2, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin1");
//   private static final FormLoginClient flClient2_2 = new FormLoginClient(server2, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin2");

 private static final String DEFAULT_SERVER_XML = "server.xml";
 private static final String DEFAULT_FIPS_SERVER_XML = "serverFIPS.xml";
 // Define the paths to the key files
 private static final String KEY_PATH_SERVER1 = "alternate/ltpa.keys";
 private static final String DEFAULT_KEY_PATH_SERVER1 = "resources/security/ltpa.keys";
 private static final String DEFAULT_KEY_PATH_SERVER2 = "resources/security/ltpa.keys";
 private static final String VALIDATION_KEY1_PATH = "resources/security/validation1.keys";




 // Define the paths to the server.xml files
 private static final String relativeDirectory = server.getServerRoot();
 private static final String wlpDirectory = server.getInstallRoot();
 private static final String baseDirectory = server.getInstallRootParent();


//  // Define the paths to the server.xml files
//  private static final String relativeDirectory_2 = server2.getServerRoot();
//  private static final String wlpDirectory_2 = server2.getInstallRoot();
//  private static final String baseDirectory_2 = server2.getInstallRootParent();

 // Define the remote message log file
 private static RemoteFile messagesLogFile = null;

 // Define fipsEnabled
 private static final boolean fipsEnabled;
//  private static final boolean fipsEnabled_2;


 static {
     boolean isFipsEnabled = false;
     try {
         isFipsEnabled = server.isFIPS140_3EnabledAndSupported();
     } catch (Exception e) {
         e.printStackTrace();
     }
     fipsEnabled = isFipsEnabled;
 }

//  static {
//     boolean isFipsEnabled = false;
//     try {
//         isFipsEnabled = server2.isFIPS140_3EnabledAndSupported();
//     } catch (Exception e) {
//         e.printStackTrace();
//     }
//     fipsEnabled_2 = isFipsEnabled;
// }


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
        // // Copy validation key file primary key to the server 2
        // copyFileToServerResourcesSecurityDir(DEFAULT_KEY_PATH_SERVER1);
        // copyFileToServerResourcesSecurityDir(DEFAULT_KEY_PATH_SERVER2);
        //copyFileToTempDir("resources/security/key.p12", "key.p12");
        copyFileToServerResourcesSecurityDir(server, KEY_PATH_SERVER1);

        server.setupForRestConnectorAccess();
        if (fipsEnabled) {
            File fipsServerXml = new File(server.pathToAutoFVTTestFiles + DEFAULT_FIPS_SERVER_XML);
            File serverXml = new File(server.pathToAutoFVTTestFiles + DEFAULT_SERVER_XML);
            Files.move(fipsServerXml.toPath(), serverXml.toPath(), StandardCopyOption.REPLACE_EXISTING);
            server.copyFileToLibertyServerRoot(DEFAULT_SERVER_XML);
        }

        server.startServer(true);

        assertNotNull("Featurevalid did not report update was complete",
                      server.waitForStringInLog("CWWKF0008I"));
        // assertNotNull("Security service did not report it was ready",
        //               server.waitForStringInLog("CWWKS0008I"));
        // assertNotNull("The application did not report is was started",
        //               server.waitForStringInLog("CWWKZ0001I"));
        // Wait for the LTPA configuration to be ready
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server.waitForStringInLog("CWWKS4105I"));

        messagesLogFile = server.getDefaultLogFile();



        // server2.setupForRestConnectorAccess();
        // if (fipsEnabled) {
        //     File fipsServerXml = new File(server2.pathToAutoFVTTestFiles + DEFAULT_FIPS_SERVER_XML);
        //     File serverXml = new File(server2.pathToAutoFVTTestFiles + DEFAULT_SERVER_XML);
        //     Files.move(fipsServerXml.toPath(), serverXml.toPath(), StandardCopyOption.REPLACE_EXISTING);
        //     server2.copyFileToLibertyServerRoot(DEFAULT_SERVER_XML);
        // }

        // server2.startServer(true);

        // assertNotNull("Featurevalid did not report update was complete",
        //               server2.waitForStringInLog("CWWKF0008I"));
        // assertNotNull("Security service did not report it was ready",
        //               server2.waitForStringInLog("CWWKS0008I"));
        // assertNotNull("The application did not report is was started",
        //               server2.waitForStringInLog("CWWKZ0001I"));
        // // Wait for the LTPA configuration to be ready
        // assertNotNull("Expected LTPA configuration ready message not found in the log.",
        //               server2.waitForStringInLog("CWWKS4105I"));

        // messagesLogFile = server2.getDefaultLogFile();

    }

    @Mode(TestMode.LITE)
    @Test
    @CheckForLeakedPasswords({ validPassword })
    @AllowedFFDC({ "java.lang.IllegalArgumentException" })
    public void testReplacingValidationKeyWithLTPAKeyFromServer1() throws Exception {
        // Configure the server
        configureServer(server, "true", "10", true);

        // Copy validation key file (validation2.keys) to the server
        copyFileToServerResourcesSecurityDir(server,DEFAULT_KEY_PATH_SERVER1);


        // // Configure the server
        // configureServer(server2, "true", "10", true);

        // // Copy validation key file (validation2.keys) to the server
        // copyFileToServerResourcesSecurityDir(server2, DEFAULT_KEY_PATH_SERVER2);
        
        



        // Wait for the LTPA configuration to be ready after the change
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server.waitForStringInLog("CWWKS4105I", 5000));

        // Initial login to simple servlet for form login1
        String response1 = flClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // Get the SSO cookies back from the login
        String cookie1 = flClient1.getCookieFromLastLogin();
        assertNotNull("Expected SSO Cookie 1 is missing.", cookie1);


        copyFileToServerResourcesTmpdir(server, DEFAULT_KEY_PATH_SERVER1 );

        // renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH_SERVER1, false);

        // copyFileToServerResourcesSecurityDir(server2, VALIDATION_KEY1_PATH);

        

        // // Wait for the LTPA configuration to be ready after the change
        // assertNotNull("Expected LTPA configuration ready message not found in the log.",
        //               server2.waitForStringInLog("CWWKS4105I", 5000));


        // // Initial login to simple servlet for form login1
        // String response2 = flClient1.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);

        // // Get the SSO cookies back from the login
        // String cookie2 = flClient1.getCookieFromLastLogin();
        // assertNotNull("Expected SSO Cookie 1 is missing.", cookie2);


        // // Replace the primary key with a different valid key
        // //renameFileIfExists(VALIDATION_KEY1_PATH, DEFAULT_KEY_PATH_SERVER1, false);

        


        // assertTrue("The new cookie is the same as the old cookie. Cookie1 = " + cookie1 + ". Cookie2 = " + cookie2 + ".",
        //             cookie1.equals(cookie2));


        // Attempt to access the simple servlet again with the same cookie and assert it fails and the server needs to login again
        //assertTrue("An invalid cookie should result in authorization challenge",
                   //flClient1.accessProtectedServletWithInvalidCookie(FormLoginClient.PROTECTED_SIMPLE, cookie1));

        // New login to simple servlet for form login2
        //String response2 = flClient2.accessProtectedServletWithAuthorizedCredentials(FormLoginClient.PROTECTED_SIMPLE, validUser, validPassword);
        // String cookie2 = flClient2.getCookieFromLastLogin();

        // // Assert that the new cookie is different from the old cookie
        // assertNotNull("Expected SSO Cookie 2 is missing.", cookie2);
        // assertFalse("The new cookie is the same as the old cookie. Cookie1 = " + cookie1 + ". Cookie2 = " + cookie2 + ".",
        //             cookie1.equals(cookie2));
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
    private static void renameFileIfExists(String filePath, String newFilePath, boolean checkFileIsGone) throws Exception {
        Log.info(thisClass, "renameFileIfExists", "\nfilepath: " + filePath + "\nnewFilePath: " + newFilePath);
        server.setMarkToEndOfLog(server.getDefaultLogFile());

        if (fileExists(filePath, 1)) {
            if (fileExists(newFilePath, 1)) {
                LibertyFileManager.moveLibertyFile(server.getFileFromLibertyServerRoot(filePath), server.getFileFromLibertyServerRoot(newFilePath));
            } else {
                Log.info(thisClass, "renameFileIfExists", "Calling server.renameLibertyServerRootFile");
                server.renameLibertyServerRootFile(filePath, newFilePath);
            }
        }

        // Double check to make sure the file is gone
        if (checkFileIsGone && fileExists(filePath, 1))
            throw new Exception("Unable to rename file: " + filePath);
    }


  // Function to do the server configuration for all the tests.
  public void configureServer(LibertyServer server, String monitorValidationKeysDir, String monitorInterval, Boolean waitForLTPAConfigReadyMessage) throws Exception {
    configureServer(server, monitorValidationKeysDir, monitorInterval, waitForLTPAConfigReadyMessage, true);
}

public void configureServer(LibertyServer server, String monitorValidationKeysDir, String monitorInterval, Boolean waitForLTPAConfigReadyMessage, boolean setLogMarkToEnd) throws Exception {
    configureServer(server, "polled", monitorValidationKeysDir, monitorInterval, waitForLTPAConfigReadyMessage, true);
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
    public void configureServer(LibertyServer server_conf, String updateTrigger, String monitorValidationKeysDir, String monitorInterval, Boolean waitForLTPAConfigReadyMessage,
                                boolean setLogMarkToEnd) throws Exception {
        moveLogMark();
        // Get the server configuration
        ServerConfiguration serverConfiguration = server_conf.getServerConfiguration();
        LTPA ltpa = serverConfiguration.getLTPA();

        // Check if the configuration needs to be updathttps://ibm.enterprise.slack.com/files/U0882KRDNRK/F08F45W70U9/output.txt?origin_team=E27SFGS2W&origin_channel=D08B6L8D869ed
        boolean configurationUpdateNeeded = false;

        configurationUpdateNeeded = setLTPAupdateTriggerElement(ltpa, updateTrigger)
                                    | setLTPAmonitorValidationKeysDirElement(ltpa, monitorValidationKeysDir)
                                    | setLTPAmonitorIntervalElement(ltpa, monitorInterval);

        // Apply server configuration update if needed
        if (configurationUpdateNeeded) {
            updateConfigDynamically(server_conf, serverConfiguration);

            if (updateTrigger.equals("polled") && monitorValidationKeysDir.equals("true") && monitorInterval.equals("0")) {
                // Wait for a warning message message to be logged
                assertNotNull("Expected LTPA configuration warning message not found in the log.",
                              server_conf.waitForStringInLog("CWWKS4113W", 5000));
            }

            if (waitForLTPAConfigReadyMessage) {
                // Wait for the LTPA configuration to be ready after the change
                assertNotNull("Expected LTPA configuration ready message not found in the log.",
                              server_conf.waitForStringInLog("CWWKS4105I", 5000));
            }
        }

        // Assert that a default ltpa.keys file is generated
        assertFileWasCreated(DEFAULT_KEY_PATH_SERVER1);
        server_conf.setKeysAndJVMOptsForFips();
        if (setLogMarkToEnd)
            server_conf.setMarkToEndOfLog(messagesLogFile);
    }
    /**
     * Check to see if the file exists. We will wait a bit to ensure
     * that the system was not slow to flush the file.
     *
     * @param filePath
     *
     * @throws Exception
     */
    private static boolean fileExists(String filePath) throws Exception {
        return fileExists(filePath, 5);
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
    private static boolean fileExists(String filePath, int numberOfTries) throws Exception {
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
     * Copies a file to the "server/resources/tmp/" directory
     *
     * @param sourceFile
     *
     * @throws Exception
     */
    private static void copyFileToServerResourcesTmpdir(LibertyServer server_conf, String sourceFile) throws Exception {
        Log.info(thisClass, "copyFileToServerResourcesSecurityDir", "sourceFile: " + sourceFile);
        String serverRoot = server_conf.getServerRoot();
        String securityResources = "/temp";
        server_conf.setServerRoot(securityResources);
        server_conf.copyFileToLibertyServerRoot(sourceFile);
        server_conf.setServerRoot(serverRoot);
    }

 /**
     * Copies a file to the "server/resources/security/" directory
     *
     * @param sourceFile
     *
     * @throws Exception
     */
    private static void copyFileToServerResourcesSecurityDir(LibertyServer server_conf, String sourceFile) throws Exception {
        Log.info(thisClass, "copyFileToServerResourcesSecurityDir", "sourceFile: " + sourceFile);
        String serverRoot = server_conf.getServerRoot();
        String securityResources = serverRoot + "/resources/security";
        server_conf.setServerRoot(securityResources);
        server_conf.copyFileToLibertyServerRoot(sourceFile);
        server_conf.setServerRoot(serverRoot);
    }
    
    @Before
    public void moveLogMark() throws Exception {
        server.setMarkToEndOfLog(messagesLogFile);
    }

    @After
    public void after() throws Exception {
        resetConnection();
        resetServer();
    }

    public void resetConnection() {
        flClient1.resetClientState();
        flClient2.resetClientState();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        try {
            server.stopServer(serverShutdownMessages);
        } finally {
            flClient1.releaseClient();
            flClient2.releaseClient();
        }
    }
   // Function to configure the updateTrigger to a specific value
   public boolean setLTPAupdateTriggerElement(LTPA ltpa, String value) {
    if (!ltpa.updateTrigger.equals(value)) {
        ltpa.updateTrigger = value;
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



    private void resetServer() throws Exception {
        Log.info(thisClass, "resetServer", "entering");

        // Make sure the mark is at the end of the log, so we don't use earlier messages.
        moveLogMark();

        // We need to put the base config back, otherwise the waits below will timeout on some tests
        configureServer(server,"true", "10", true);

        
        // We need to put the base config back, otherwise the waits below will timeout on some tests
      //  configureServer(server2,"true", "10", true);

        
        // Delete all ltpa keys files in the security directory
        deleteFileIfExists(DEFAULT_KEY_PATH_SERVER1, false);
        deleteFileIfExists(VALIDATION_KEY1_PATH, true);
        //deleteFileIfExists(CONFIGURED_VALIDATION_KEY1_PATH, true);

        // Wait for the LTPA configuration to be ready after the change
        assertNotNull("Expected LTPA configuration ready message not found in the log.",
                      server.waitForStringInLog("CWWKS4105I", 5000));

        // Assert that a default ltpa.keys file exists prior to next test case
        assertFileWasCreated(DEFAULT_KEY_PATH_SERVER1);
        assertFileWasCreated(DEFAULT_KEY_PATH_SERVER2);
        
        Log.info(thisClass, "resetServer", "exiting");
    }

        /**
     * Delete the file if it exists. If we can't delete it, then
     * throw an exception as we need to be able to delete these files.
     *
     * @param filePath
     *
     * @throws Exception
     */
    private static void deleteFileIfExists(String filePath, boolean checkFileIsGone) throws Exception {
        Log.info(thisClass, "deleteFileIfExists", "filepath: " + filePath);
        if (fileExists(filePath, 1)) {
            Log.info(thisClass, "deleteFileIfExists", "file exists, deleting...");
            server.deleteFileFromLibertyServerRoot(filePath);

            // Double check to make sure the file is gone
            if (checkFileIsGone && fileExists(filePath, 1))
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
    private void assertFileWasCreated(String filePath) throws Exception {
        assertTrue("The file was not created as expected. If this is an intermittent failure, then increase the wait time.",
                   fileExists(filePath));
    }


}

