/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.audit.pqc.fat;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.log.Log;

import componenttest.annotation.Server;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.utils.HttpUtils;

/**
 * FAT tests for PQC Audit infrastructure.
 * 
 * Tests basic server configuration and Java environment
 * to verify PQC audit feature can be deployed and tested.
 */
@RunWith(FATRunner.class)
public class PQCAuditTests {
    
    private static final Class<?> c = PQCAuditTests.class;
    
    @Server("com.ibm.ws.security.audit.pqc.fat")
    public static LibertyServer server;
    
    private static final String APP_NAME = "pqcAuditTest";
    private static final String SERVLET_PATH = "/" + APP_NAME + "/PQCAuditTestServlet";
    private static final String SUCCESS_PREFIX = "SUCCESS:";
    
    @BeforeClass
    public static void setUp() throws Exception {
        Log.info(c, "setUp", "Starting server...");
        server.startServer();
        server.waitForStringInLog("CWWKF0011I"); // Server ready
        Log.info(c, "setUp", "Server started successfully");
    }
    
    @AfterClass
    public static void tearDown() throws Exception {
        Log.info(c, "tearDown", "Stopping server...");
        if (server != null && server.isStarted()) {
            // Ignore Java 2 Security warnings - they're informational only
            server.stopServer("CWWKE0921W", "CWWKE0912W");
        }
    }
    
    private String invokeServlet(String testName) throws Exception {
        String response = HttpUtils.getHttpResponseAsString(server, SERVLET_PATH + "?test=" + testName);
        Log.info(c, "invokeServlet", "Test [" + testName + "] response: " + response);
        assertNotNull("Response should not be null for test " + testName, response);
        assertFalse("Response should not contain an error for test " + testName, response.contains("ERROR:"));
        return response;
    }

    /**
     * Test Java version detection
     */
    @Test
    public void testJavaVersion() throws Exception {
        Log.info(c, "testJavaVersion", "Testing Java version detection");
        
        String response = invokeServlet("javaVersion");
        assertTrue("Should detect Java version",
            response.contains("Java Version:"));
        assertTrue("Should indicate PQC capability",
            response.contains("PQC_CAPABLE") || response.contains("PQC_NOT_CAPABLE"));
    }
    
    /**
     * Test Java version response includes vendor details and success marker.
     */
    @Test
    public void testJavaVersionIncludesVendorAndSuccess() throws Exception {
        Log.info(c, "testJavaVersionIncludesVendorAndSuccess", "Testing Java version response details");

        String response = invokeServlet("javaVersion");

        assertTrue("Should include success marker", response.contains(SUCCESS_PREFIX));
        assertTrue("Should include Java vendor", response.contains("Java Vendor:"));
    }

    /**
     * Test server information
     */
    @Test
    public void testServerInfo() throws Exception {
        Log.info(c, "testServerInfo", "Testing server information");
        
        String response = invokeServlet("serverInfo");
        assertTrue("Should get server info",
            response.contains("SERVER_RUNNING"));
    }
    
    /**
     * Test server information response includes server details and success marker.
     */
    @Test
    public void testServerInfoIncludesDetailsAndSuccess() throws Exception {
        Log.info(c, "testServerInfoIncludesDetailsAndSuccess", "Testing server info response details");

        String response = invokeServlet("serverInfo");

        assertTrue("Should include success marker", response.contains(SUCCESS_PREFIX));
        assertTrue("Should include server info details", response.contains("Server Info:"));
    }

    /**
     * Test audit feature check
     */
    @Test
    public void testAuditFeature() throws Exception {
        Log.info(c, "testAuditFeature", "Testing audit feature");
        
        String response = invokeServlet("auditFeature");
        assertTrue("Should complete audit check",
            response.contains("AUDIT_CHECK_COMPLETE"));
    }

    /**
     * Test audit feature response includes success marker.
     */
    @Test
    public void testAuditFeatureIncludesSuccess() throws Exception {
        Log.info(c, "testAuditFeatureIncludesSuccess", "Testing audit feature response details");

        String response = invokeServlet("auditFeature");

        assertTrue("Should include success marker", response.contains(SUCCESS_PREFIX));
    }

    /**
     * Test unknown servlet endpoint handling.
     */
    @Test
    public void testUnknownEndpointReturnsError() throws Exception {
        Log.info(c, "testUnknownEndpointReturnsError", "Testing unknown endpoint handling");

        String response = HttpUtils.getHttpResponseAsString(server, SERVLET_PATH + "?test=unknownScenario");

        Log.info(c, "testUnknownEndpointReturnsError", "Response: " + response);
        assertNotNull("Response should not be null", response);
        assertTrue("Should report unknown test error", response.contains("ERROR: Unknown test: unknownScenario"));
    }

    // ========================================
    // PQC Encryption/Decryption Tests
    // ========================================

    /**
     * Test PQC encryption and decryption with ML-KEM-512.
     * Verifies that data encrypted with ML-KEM-512 can be successfully decrypted.
     */
    @Test
    public void testPQCEncryptDecrypt_MLKEM512() throws Exception {
        Log.info(c, "testPQCEncryptDecrypt_MLKEM512", "Testing PQC encrypt/decrypt with ML-KEM-512");
        
        String response = invokeServlet("pqcEncryptDecrypt_MLKEM512");
        assertTrue("Should successfully encrypt and decrypt with ML-KEM-512",
            response.contains("ENCRYPT_DECRYPT_SUCCESS"));
        assertTrue("Should use ML-KEM-512 algorithm",
            response.contains("ML-KEM-512"));
    }

    /**
     * Test PQC encryption and decryption with ML-KEM-768.
     * Verifies that data encrypted with ML-KEM-768 can be successfully decrypted.
     */
    @Test
    public void testPQCEncryptDecrypt_MLKEM768() throws Exception {
        Log.info(c, "testPQCEncryptDecrypt_MLKEM768", "Testing PQC encrypt/decrypt with ML-KEM-768");
        
        String response = invokeServlet("pqcEncryptDecrypt_MLKEM768");
        assertTrue("Should successfully encrypt and decrypt with ML-KEM-768",
            response.contains("ENCRYPT_DECRYPT_SUCCESS"));
        assertTrue("Should use ML-KEM-768 algorithm",
            response.contains("ML-KEM-768"));
    }

    /**
     * Test PQC encryption and decryption with ML-KEM-1024.
     * Verifies that data encrypted with ML-KEM-1024 can be successfully decrypted.
     */
    @Test
    public void testPQCEncryptDecrypt_MLKEM1024() throws Exception {
        Log.info(c, "testPQCEncryptDecrypt_MLKEM1024", "Testing PQC encrypt/decrypt with ML-KEM-1024");
        
        String response = invokeServlet("pqcEncryptDecrypt_MLKEM1024");
        assertTrue("Should successfully encrypt and decrypt with ML-KEM-1024",
            response.contains("ENCRYPT_DECRYPT_SUCCESS"));
        assertTrue("Should use ML-KEM-1024 algorithm",
            response.contains("ML-KEM-1024"));
    }

    /**
     * Test classical (non-PQC) encryption and decryption.
     * Verifies backward compatibility with AES-256 encryption.
     */
    @Test
    public void testClassicalEncryptDecrypt() throws Exception {
        Log.info(c, "testClassicalEncryptDecrypt", "Testing classical encrypt/decrypt");
        
        String response = invokeServlet("classicalEncryptDecrypt");
        assertTrue("Should successfully encrypt and decrypt with classical mode",
            response.contains("ENCRYPT_DECRYPT_SUCCESS"));
        assertTrue("Should use classical mode",
            response.contains("CLASSICAL_MODE"));
    }

    /**
     * Test that PQC encrypted data cannot be decrypted with wrong private key.
     */
    @Test
    public void testPQCDecryptWithWrongKey() throws Exception {
        Log.info(c, "testPQCDecryptWithWrongKey", "Testing PQC decrypt with wrong key");
        
        String response = invokeServlet("pqcDecryptWrongKey");
        assertTrue("Should fail to decrypt with wrong key",
            response.contains("DECRYPT_FAILED") || response.contains("WRONG_KEY_DETECTED"));
    }

    /**
     * Test PQC encryption with different data sizes.
     * Verifies that PQC encryption works correctly for small, medium, and large data.
     */
    @Test
    public void testPQCEncryptDifferentSizes() throws Exception {
        Log.info(c, "testPQCEncryptDifferentSizes", "Testing PQC encrypt with different data sizes");
        
        String response = invokeServlet("pqcEncryptDifferentSizes");
        assertTrue("Should successfully encrypt different data sizes",
            response.contains("ALL_SIZES_SUCCESS"));
        assertTrue("Should test small data",
            response.contains("SMALL_DATA_OK"));
        assertTrue("Should test medium data",
            response.contains("MEDIUM_DATA_OK"));
        assertTrue("Should test large data",
            response.contains("LARGE_DATA_OK"));
    }

    /**
     * Test that tampered encrypted data fails decryption.
     */
    @Test
    public void testPQCDecryptTamperedData() throws Exception {
        Log.info(c, "testPQCDecryptTamperedData", "Testing PQC decrypt with tampered data");
        
        String response = invokeServlet("pqcDecryptTampered");
        assertTrue("Should detect tampered data",
            response.contains("TAMPERED_DETECTED") || response.contains("DECRYPT_FAILED"));
    }

    /**
     * Test PQC mode detection and validation.
     */
    @Test
    public void testPQCModeDetection() throws Exception {
        Log.info(c, "testPQCModeDetection", "Testing PQC mode detection");
        
        String response = invokeServlet("pqcModeDetection");
        assertTrue("Should detect PQC mode correctly",
            response.contains("MODE_DETECTION_SUCCESS"));
    }

    /**
     * Test ML-KEM key pair generation for all algorithm types.
     */
    @Test
    public void testMLKEMKeyGeneration() throws Exception {
        Log.info(c, "testMLKEMKeyGeneration", "Testing ML-KEM key generation");
        
        String response = invokeServlet("mlkemKeyGeneration");
        assertTrue("Should generate ML-KEM keys successfully",
            response.contains("KEY_GENERATION_SUCCESS"));
        assertTrue("Should generate ML-KEM-512 keys",
            response.contains("ML-KEM-512_OK"));
        assertTrue("Should generate ML-KEM-768 keys",
            response.contains("ML-KEM-768_OK"));
        assertTrue("Should generate ML-KEM-1024 keys",
            response.contains("ML-KEM-1024_OK"));
    }

    /**
     * Test encapsulation size validation for different ML-KEM algorithms.
     */
    @Test
    public void testEncapsulationSizes() throws Exception {
        Log.info(c, "testEncapsulationSizes", "Testing encapsulation sizes");
        
        String response = invokeServlet("encapsulationSizes");
        assertTrue("Should validate encapsulation sizes",
            response.contains("ENCAPSULATION_SIZES_OK"));
        assertTrue("ML-KEM-512 encapsulation should be correct size",
            response.contains("ML-KEM-512: 768 bytes"));
        assertTrue("ML-KEM-768 encapsulation should be correct size",
            response.contains("ML-KEM-768: 1088 bytes"));
        assertTrue("ML-KEM-1024 encapsulation should be correct size",
            response.contains("ML-KEM-1024: 1568 bytes"));
    }

    /**
     * Test multiple encrypt/decrypt operations with same key pair.
     */
    @Test
    public void testMultipleEncryptDecryptOperations() throws Exception {
        Log.info(c, "testMultipleEncryptDecryptOperations", "Testing multiple encrypt/decrypt operations");
        
        String response = invokeServlet("multipleEncryptDecrypt");
        assertTrue("Should handle multiple operations successfully",
            response.contains("MULTIPLE_OPERATIONS_SUCCESS"));
        assertTrue("Should complete all iterations",
            response.contains("ITERATIONS_COMPLETE"));
    }

    /**
     * Test PQC encryption format validation.
     * Verifies the format: [4-byte length][encapsulation][encrypted_data]
     */
    @Test
    public void testPQCEncryptionFormat() throws Exception {
        Log.info(c, "testPQCEncryptionFormat", "Testing PQC encryption format");
        
        String response = invokeServlet("pqcEncryptionFormat");
        assertTrue("Should validate encryption format",
            response.contains("FORMAT_VALIDATION_SUCCESS"));
        assertTrue("Should have correct header",
            response.contains("HEADER_OK"));
        assertTrue("Should have correct encapsulation",
            response.contains("ENCAPSULATION_OK"));
        assertTrue("Should have correct encrypted data",
            response.contains("ENCRYPTED_DATA_OK"));
    }

    /**
     * Test error handling for invalid PQC parameters.
     */
    @Test
    public void testPQCErrorHandling() throws Exception {
        Log.info(c, "testPQCErrorHandling", "Testing PQC error handling");
        
        String response = invokeServlet("pqcErrorHandling");
        assertTrue("Should handle errors gracefully",
            response.contains("ERROR_HANDLING_SUCCESS"));
        assertTrue("Should handle null keys",
            response.contains("NULL_KEY_HANDLED"));
        assertTrue("Should handle invalid algorithm",
            response.contains("INVALID_ALGORITHM_HANDLED"));
    }

    /**
     * Test PQC vs Classical mode comparison.
     * Verifies that both modes work correctly and produce different results.
     */
    @Test
    public void testPQCvsClassicalComparison() throws Exception {
        Log.info(c, "testPQCvsClassicalComparison", "Testing PQC vs Classical comparison");
        
        String response = invokeServlet("pqcVsClassical");
        assertTrue("Should compare modes successfully",
            response.contains("COMPARISON_SUCCESS"));
        assertTrue("Should show different encrypted outputs",
            response.contains("OUTPUTS_DIFFERENT"));
        assertTrue("Both modes should decrypt correctly",
            response.contains("BOTH_DECRYPT_OK"));
    }

    /**
     * Test shared secret generation and usage.
     */
    @Test
    public void testSharedSecretGeneration() throws Exception {
        Log.info(c, "testSharedSecretGeneration", "Testing shared secret generation");
        
        String response = invokeServlet("sharedSecretGeneration");
        assertTrue("Should generate shared secret successfully",
            response.contains("SHARED_SECRET_SUCCESS"));
        assertTrue("Shared secret should be 32 bytes",
            response.contains("SECRET_SIZE: 32"));
    }

    /**
     * Test AuditKeyEncryptor isPqcMode() method.
     */
    @Test
    public void testIsPqcMode() throws Exception {
        Log.info(c, "testIsPqcMode", "Testing isPqcMode() method");
        
        String response = invokeServlet("isPqcMode");
        assertTrue("Should detect PQC mode correctly",
            response.contains("PQC_MODE_DETECTION_OK"));
    }

    /**
     * Test AuditKeyEncryptor getMlkemAlgorithm() method.
     */
    @Test
    public void testGetMlkemAlgorithm() throws Exception {
        Log.info(c, "testGetMlkemAlgorithm", "Testing getMlkemAlgorithm() method");
        
        String response = invokeServlet("getMlkemAlgorithm");
        assertTrue("Should get ML-KEM algorithm correctly",
            response.contains("ALGORITHM_RETRIEVAL_OK"));
    }

    /**
     * Test concurrent PQC encryption operations.
     * Verifies thread safety of PQC encryption.
     */
    @Test
    public void testConcurrentPQCOperations() throws Exception {
        Log.info(c, "testConcurrentPQCOperations", "Testing concurrent PQC operations");
        
        String response = invokeServlet("concurrentPQC");
        assertTrue("Should handle concurrent operations",
            response.contains("CONCURRENT_SUCCESS"));
        assertTrue("All threads should complete",
            response.contains("ALL_THREADS_COMPLETE"));
    }
}

// Made with Bob