/*******************************************************************************
 * Copyright (c) 2018, 2026 IBM Corporation and others.
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
package com.ibm.ws.security.audit.encryption;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.ws.security.audit.source.utils.ByteArray;
import com.ibm.ws.security.token.ltpa.pqc.MLKEMAlgorithmType;
import com.ibm.ws.security.token.ltpa.pqc.PQCRuntimeSupport;

/**
 * A package local class for performing encryption and decryption of keys based on a key.
 *
 * Supports two modes:
 * <ul>
 *   <li><b>Classical Mode:</b> AES-256 encryption with password-based key derivation</li>
 *   <li><b>PQC Mode:</b> ML-KEM (Post-Quantum) key encapsulation for quantum-resistant encryption</li>
 * </ul>
 */
public class AuditKeyEncryptor {
    private static final TraceComponent tc = Tr.register(AuditKeyEncryptor.class);
    
    private final String algorithm = CryptoUtils.MESSAGE_DIGEST_ALGORITHM_SHA_256; // Semerun 1.8 does not support string SHA256
    @Sensitive
    byte[] password;
    @Sensitive
    byte[] passwordDigestBytes;
    AuditCrypto des;
    
    // PQC mode fields
    private final boolean pqcMode;
    @Sensitive
    private PrivateKey mlkemPrivateKey;
    private PublicKey mlkemPublicKey;
    private MLKEMAlgorithmType mlkemAlgorithm;

    /**
     * Constructor for classical (non-PQC) mode using password-based encryption.
     *
     * @param password The password used for key derivation
     */
    public AuditKeyEncryptor(byte[] password) {
        this(password, false, null, null, null);
    }

    /**
     * Constructor with PQC mode support.
     *
     * @param password The password used for key derivation (used in classical mode)
     * @param pqcMode Whether to enable PQC mode
     * @param mlkemPrivateKey The ML-KEM private key (required if pqcMode is true)
     * @param mlkemPublicKey The ML-KEM public key (required if pqcMode is true)
     * @param mlkemAlgorithm The ML-KEM algorithm type (required if pqcMode is true)
     */
    public AuditKeyEncryptor(@Sensitive byte[] password, boolean pqcMode,
                            @Sensitive PrivateKey mlkemPrivateKey,
                            PublicKey mlkemPublicKey,
                            MLKEMAlgorithmType mlkemAlgorithm) {
        this.password = password;
        this.pqcMode = pqcMode;
        this.mlkemPrivateKey = mlkemPrivateKey;
        this.mlkemPublicKey = mlkemPublicKey;
        this.mlkemAlgorithm = mlkemAlgorithm != null ? mlkemAlgorithm : MLKEMAlgorithmType.getDefault();
        
        // Validate PQC mode requirements
        if (pqcMode) {
            if (!PQCRuntimeSupport.isPQCSupported()) {
                throw new UnsupportedOperationException(
                    "PQC mode requires Java 26 or later. Current version: " +
                    PQCRuntimeSupport.getJavaVersion());
            }
            if (mlkemPrivateKey == null || mlkemPublicKey == null) {
                throw new IllegalArgumentException(
                    "ML-KEM keys are required when PQC mode is enabled");
            }
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "AuditKeyEncryptor initialized in PQC mode with " + this.mlkemAlgorithm);
            }
        } else {
            // Initialize classical mode
            java.security.MessageDigest md = null;
            try {
                md = java.security.MessageDigest.getInstance(algorithm);
                passwordDigestBytes = new byte[CryptoUtils.AES_256_KEY_LENGTH_BYTES];
                byte[] digest = md.digest(this.password);
                ByteArray.copy(digest, 0, digest.length, passwordDigestBytes, 0);

            } catch (java.security.NoSuchAlgorithmException e) {
                com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.encryption.AuditKeyEncryptor", "21", this);
            }
            des = new AuditCrypto();
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "AuditKeyEncryptor initialized in classical mode");
            }
        }
    }

    /**
     * Decrypt an encrypted key.
     *
     * @param encrKey The encrypted key bytes
     * @return The decrypted key bytes
     */
    public byte[] decrypt(byte[] encrKey) {
        if (pqcMode) {
            return decryptPQC(encrKey);
        } else {
            return des.decrypt(encrKey, passwordDigestBytes);
        }
    }

    /**
     * Encrypt a key.
     *
     * @param key The key bytes to encrypt
     * @return The encrypted key bytes
     */
    public byte[] encrypt(byte[] key) {
        if (pqcMode) {
            return encryptPQC(key);
        } else {
            return des.encrypt(key, passwordDigestBytes);
        }
    }
    
    /**
     * Encrypt a key using ML-KEM (Post-Quantum Cryptography).
     *
     * <p><b>How PQC Encryption Works:</b></p>
     *
     * <p>ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) is a quantum-resistant
     * algorithm standardized by NIST in FIPS 203. Unlike traditional RSA/ECC encryption,
     * ML-KEM uses lattice-based cryptography that is believed to be secure against both
     * classical and quantum computer attacks.</p>
     *
     * <p><b>Encryption Process (3 Steps):</b></p>
     *
     * <ol>
     * <li><b>ML-KEM Encapsulation:</b>
     *     <ul>
     *       <li>Input: ML-KEM public key (from recipient)</li>
     *       <li>Process: Generate a random shared secret and encapsulate it using the public key</li>
     *       <li>Output:
     *           <ul>
     *             <li>Shared Secret: A symmetric key (32 bytes for AES-256)</li>
     *             <li>Encapsulation: Ciphertext that can only be decrypted with the private key</li>
     *           </ul>
     *       </li>
     *       <li>Security: The shared secret is never transmitted; only the encapsulation is sent</li>
     *     </ul>
     * </li>
     *
     * <li><b>AES-256 Encryption:</b>
     *     <ul>
     *       <li>Input: Original key data + shared secret from step 1</li>
     *       <li>Process: Encrypt the key data using AES-256-CBC with the shared secret</li>
     *       <li>Output: Encrypted key data</li>
     *       <li>Why: ML-KEM is for key exchange only; we use AES for actual data encryption</li>
     *     </ul>
     * </li>
     *
     * <li><b>Combine Results:</b>
     *     <ul>
     *       <li>Format: [4-byte length][encapsulation][encrypted data]</li>
     *       <li>The 4-byte length prefix allows the decryptor to split the data correctly</li>
     *       <li>This combined format is what gets stored/transmitted</li>
     *     </ul>
     * </li>
     * </ol>
     *
     * <p><b>Example Flow:</b></p>
     * <pre>
     * Original Key: "my-secret-audit-key" (19 bytes)
     *     ↓
     * Step 1: ML-KEM Encapsulation
     *   - Generate shared secret: [32 random bytes]
     *   - Create encapsulation: [1088 bytes for ML-KEM-768]
     *     ↓
     * Step 2: AES-256 Encryption
     *   - Encrypt key with shared secret: [32 bytes encrypted]
     *     ↓
     * Step 3: Combine
     *   - Result: [4][1088 bytes encapsulation][32 bytes encrypted data]
     *   - Total: 1124 bytes
     * </pre>
     *
     * <p><b>Security Properties:</b></p>
     * <ul>
     *   <li>Quantum-resistant: Safe against Shor's algorithm and other quantum attacks</li>
     *   <li>Forward secrecy: Each encryption uses a fresh shared secret</li>
     *   <li>Hybrid security: Combines lattice-based (ML-KEM) + symmetric (AES-256) cryptography</li>
     * </ul>
     *
     * @param key The key bytes to encrypt
     * @return The encrypted key bytes in format: [length(4)][encapsulation][encrypted_data]
     * @throws RuntimeException if encryption fails (wraps underlying exceptions)
     */
    @Sensitive
    private byte[] encryptPQC(byte[] key) {
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "Encrypting key using PQC mode with " + mlkemAlgorithm);
        }
        
        try {
            // Step 1: Perform ML-KEM encapsulation to generate shared secret
            Object secretKeyWithEncap = PQCRuntimeSupport.encapsulate(mlkemPublicKey);
            SecretKey sharedSecret = PQCRuntimeSupport.extractSharedSecret(secretKeyWithEncap);
            byte[] encapsulation = PQCRuntimeSupport.extractEncapsulation(secretKeyWithEncap);
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-KEM encapsulation successful, encapsulation size: " + encapsulation.length);
            }
            
            // Step 2: Use shared secret to encrypt the key with AES-256
            byte[] sharedSecretBytes = sharedSecret.getEncoded();
            byte[] encryptedKey = AuditCrypto.encrypt(key, sharedSecretBytes);
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Key encrypted with shared secret, encrypted size: " + encryptedKey.length);
            }
            
            // Step 3: Combine encapsulation + encrypted data
            // Format: [encapsulation_length (4 bytes)][encapsulation][encrypted_data]
            byte[] result = new byte[4 + encapsulation.length + encryptedKey.length];
            
            // Write encapsulation length
            result[0] = (byte) (encapsulation.length >> 24);
            result[1] = (byte) (encapsulation.length >> 16);
            result[2] = (byte) (encapsulation.length >> 8);
            result[3] = (byte) encapsulation.length;
            
            // Write encapsulation
            System.arraycopy(encapsulation, 0, result, 4, encapsulation.length);
            
            // Write encrypted data
            System.arraycopy(encryptedKey, 0, result, 4 + encapsulation.length, encryptedKey.length);
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "PQC encryption complete, total size: " + result.length);
            }
            
            return result;
            
        } catch (Exception e) {
            Tr.error(tc, "Error encrypting key with PQC: " + e.getMessage());
            com.ibm.ws.ffdc.FFDCFilter.processException(e,
                "com.ibm.ws.security.audit.encryption.AuditKeyEncryptor.encryptPQC", "200", this);
            throw new RuntimeException("Failed to encrypt key using PQC", e);
        }
    }
    
    /**
     * Decrypt a key using ML-KEM (Post-Quantum Cryptography).
     *
     * This method:
     * 1. Extracts the encapsulation from the encrypted data
     * 2. Performs ML-KEM decapsulation with the private key to recover the shared secret
     * 3. Uses the shared secret to decrypt the actual key data with AES-256
     *
     * @param encrKey The encrypted key bytes (encapsulation || encrypted data)
     * @return The decrypted key bytes
     */
    @Sensitive
    private byte[] decryptPQC(byte[] encrKey) {
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "Decrypting key using PQC mode with " + mlkemAlgorithm);
        }
        
        try {
            // Step 1: Extract encapsulation length
            int encapsulationLength = ((encrKey[0] & 0xFF) << 24) |
                                     ((encrKey[1] & 0xFF) << 16) |
                                     ((encrKey[2] & 0xFF) << 8) |
                                     (encrKey[3] & 0xFF);
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Extracted encapsulation length: " + encapsulationLength);
            }
            
            // Step 2: Extract encapsulation
            byte[] encapsulation = new byte[encapsulationLength];
            System.arraycopy(encrKey, 4, encapsulation, 0, encapsulationLength);
            
            // Step 3: Extract encrypted data
            int encryptedDataLength = encrKey.length - 4 - encapsulationLength;
            byte[] encryptedData = new byte[encryptedDataLength];
            System.arraycopy(encrKey, 4 + encapsulationLength, encryptedData, 0, encryptedDataLength);
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Extracted encrypted data length: " + encryptedDataLength);
            }
            
            // Step 4: Perform ML-KEM decapsulation to recover shared secret
            SecretKey sharedSecret = PQCRuntimeSupport.decapsulate(mlkemPrivateKey, encapsulation);
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-KEM decapsulation successful");
            }
            
            // Step 5: Use shared secret to decrypt the key with AES-256
            byte[] sharedSecretBytes = sharedSecret.getEncoded();
            byte[] decryptedKey = AuditCrypto.decrypt(encryptedData, sharedSecretBytes);
            
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Key decrypted successfully, size: " +
                    (decryptedKey != null ? decryptedKey.length : 0));
            }
            
            return decryptedKey;
            
        } catch (Exception e) {
            Tr.error(tc, "Error decrypting key with PQC: " + e.getMessage());
            com.ibm.ws.ffdc.FFDCFilter.processException(e,
                "com.ibm.ws.security.audit.encryption.AuditKeyEncryptor.decryptPQC", "260", this);
            throw new RuntimeException("Failed to decrypt key using PQC", e);
        }
    }
    
    /**
     * Check if this encryptor is in PQC mode.
     *
     * @return true if PQC mode is enabled, false otherwise
     */
    public boolean isPqcMode() {
        return true;
    }
    
    /**
     * Get the ML-KEM algorithm type (only valid in PQC mode).
     *
     * @return The ML-KEM algorithm type, or null if not in PQC mode
     */
    public MLKEMAlgorithmType getMlkemAlgorithm() {
        return mlkemAlgorithm;
    }
    
    /**
     * Generate a new ML-KEM key pair for PQC mode.
     *
     * @param algorithm The ML-KEM algorithm type
     * @return A new KeyPair containing ML-KEM public and private keys
     * @throws Exception if key generation fails
     */
    public static KeyPair generateMLKEMKeyPair(MLKEMAlgorithmType algorithm) throws Exception {
        return PQCRuntimeSupport.generateMLKEMKeyPair(algorithm);
    }
}
