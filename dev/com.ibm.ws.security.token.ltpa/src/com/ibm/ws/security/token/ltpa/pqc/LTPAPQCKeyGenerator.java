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
package com.ibm.ws.security.token.ltpa.pqc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.MLKEMParameterSpec;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.crypto.ltpakeyutil.LTPADigSignature;
import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyPair;

/**
 * Generator for LTPA Post-Quantum Cryptography (PQC) keys.
 * 
 * This class generates both classical cryptographic keys (RSA for signatures) and
 * post-quantum cryptographic keys (ML-KEM for encryption) using Java 26's native
 * SunJCE provider.
 * 
 * <p>Key Generation Process:
 * <ol>
 *   <li>Generate RSA-2048 key pair for digital signatures (existing)</li>
 *   <li>Generate ML-KEM key pair for key encapsulation (new)</li>
 *   <li>Combine into LTPAPQCKeys object</li>
 * </ol>
 * 
 * <p>Security:
 * <ul>
 *   <li>Uses SecureRandom for cryptographically secure randomness</li>
 *   <li>RSA-2048: 112-bit classical security</li>
 *   <li>ML-KEM-768: 192-bit quantum security (NIST Level 3)</li>
 * </ul>
 */
public class LTPAPQCKeyGenerator {
    
    private static final TraceComponent tc = Tr.register(LTPAPQCKeyGenerator.class);
    
    private static final String ML_KEM_ALGORITHM = "ML-KEM";
    private static final String SUNJCE_PROVIDER = "SunJCE";
    
    /**
     * Generate hybrid LTPA PQC keys with default ML-KEM-768 algorithm.
     * 
     * @return LTPAPQCKeys containing both RSA and ML-KEM keys
     * @throws Exception if key generation fails
     */
    public static LTPAPQCKeys generateHybridKeys() throws Exception {
        return generateHybridKeys(MLKEMAlgorithmType.getDefault());
    }
    
    /**
     * Generate hybrid LTPA PQC keys with specified ML-KEM algorithm.
     * 
     * @param mlkemAlgorithm The ML-KEM algorithm type to use
     * @return LTPAPQCKeys containing both RSA and ML-KEM keys
     * @throws Exception if key generation fails
     */
    public static LTPAPQCKeys generateHybridKeys(MLKEMAlgorithmType mlkemAlgorithm) throws Exception {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "generateHybridKeys", mlkemAlgorithm);
        }
        
        long startTime = System.currentTimeMillis();
        
        try {
            // 1. Generate RSA keys (existing - for signatures)
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Generating RSA-2048 key pair for signatures");
            }
            LTPAKeyPair rsaKeyPair = LTPADigSignature.generateLTPAKeyPair();
            byte[] rsaPrivateKeyBytes = rsaKeyPair.getPrivateKey().getRawKey()[0];
            byte[] rsaPublicKeyBytes = rsaKeyPair.getPublicKey().getRawKey()[0];
            
            // 2. Generate ML-KEM keys (new - for encryption)
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Generating " + mlkemAlgorithm + " key pair for encryption");
            }
            KeyPair mlkemKeyPair = generateMLKEMKeyPair(mlkemAlgorithm);
            
            // 3. Create LTPAPQCKeys object
            LTPAPQCKeys pqcKeys = new LTPAPQCKeys(
                rsaPrivateKeyBytes,
                rsaPublicKeyBytes,
                mlkemKeyPair.getPrivate(),
                mlkemKeyPair.getPublic(),
                mlkemAlgorithm
            );
            
            long elapsedTime = System.currentTimeMillis() - startTime;
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Generated hybrid PQC keys in " + elapsedTime + "ms");
            }
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "generateHybridKeys", pqcKeys);
            }
            
            return pqcKeys;
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(tc, "Error generating hybrid PQC keys", e);
            }
            throw e;
        }
    }
    
    /**
     * Generate an ML-KEM key pair using Java 26's SunJCE provider.
     * 
     * @param mlkemAlgorithm The ML-KEM algorithm type
     * @return KeyPair containing ML-KEM private and public keys
     * @throws NoSuchAlgorithmException if ML-KEM algorithm is not available
     * @throws NoSuchProviderException if SunJCE provider is not available
     * @throws Exception if key generation fails
     */
    private static KeyPair generateMLKEMKeyPair(MLKEMAlgorithmType mlkemAlgorithm) 
            throws NoSuchAlgorithmException, NoSuchProviderException, Exception {
        
        // Get KeyPairGenerator for ML-KEM from SunJCE provider
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ML_KEM_ALGORITHM, SUNJCE_PROVIDER);
        
        // Get the appropriate MLKEMParameterSpec for the algorithm type
        AlgorithmParameterSpec paramSpec = getMLKEMParameterSpec(mlkemAlgorithm);
        
        // Initialize with parameter spec and secure random
        SecureRandom secureRandom = new SecureRandom();
        kpg.initialize(paramSpec, secureRandom);
        
        // Generate and return the key pair
        return kpg.generateKeyPair();
    }
    
    /**
     * Get the MLKEMParameterSpec for the specified algorithm type.
     * 
     * @param mlkemAlgorithm The ML-KEM algorithm type
     * @return The corresponding MLKEMParameterSpec
     */
    private static AlgorithmParameterSpec getMLKEMParameterSpec(MLKEMAlgorithmType mlkemAlgorithm) {
        switch (mlkemAlgorithm) {
            case ML_KEM_512:
                return MLKEMParameterSpec.ml_kem_512;
            case ML_KEM_768:
                return MLKEMParameterSpec.ml_kem_768;
            case ML_KEM_1024:
                return MLKEMParameterSpec.ml_kem_1024;
            default:
                // Should never happen due to enum
                throw new IllegalArgumentException("Unknown ML-KEM algorithm: " + mlkemAlgorithm);
        }
    }
    
    /**
     * Check if ML-KEM support is available in the current Java runtime.
     * 
     * @return true if ML-KEM is supported, false otherwise
     */
    public static boolean isMLKEMSupported() {
        try {
            KeyPairGenerator.getInstance(ML_KEM_ALGORITHM, SUNJCE_PROVIDER);
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-KEM not supported in current Java runtime", e);
            }
            return false;
        }
    }
    
    /**
     * Get the Java version string.
     * 
     * @return The Java version (e.g., "26")
     */
    public static String getJavaVersion() {
        return System.getProperty("java.version");
    }
    
    /**
     * Check if the current Java version supports ML-KEM (Java 26+).
     * 
     * @return true if Java 26 or higher, false otherwise
     */
    public static boolean isJava26OrHigher() {
        try {
            String version = getJavaVersion();
            // Parse major version (e.g., "26" from "26.0.1" or "26-ea")
            String majorVersion = version.split("[.-]")[0];
            int major = Integer.parseInt(majorVersion);
            return major >= 26;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Could not parse Java version", e);
            }
            return false;
        }
    }
    
    /**
     * Validate that the runtime environment supports PQC LTPA.
     * 
     * @throws UnsupportedOperationException if PQC is not supported
     */
    public static void validatePQCSupport() {
        if (!isJava26OrHigher()) {
            String msg = "PQC LTPA requires Java 26 or higher. Current version: " + getJavaVersion();
            Tr.error(tc, "LTPA_PQC_UNSUPPORTED_JAVA_VERSION", getJavaVersion());
            throw new UnsupportedOperationException(msg);
        }
        
        if (!isMLKEMSupported()) {
            String msg = "ML-KEM algorithm not available in SunJCE provider";
            Tr.error(tc, "LTPA_PQC_MLKEM_NOT_AVAILABLE");
            throw new UnsupportedOperationException(msg);
        }
    }
}

// Made with Bob
