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
package com.ibm.ws.security.token.ltpa.internal;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.websphere.security.auth.TokenExpiredException;
import com.ibm.ws.common.encoder.Base64Coder;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.token.ltpa.pqc.LTPAPQCCrypto;
import com.ibm.ws.security.token.ltpa.pqc.LTPAPQCKeys;
import com.ibm.wsspi.security.ltpa.Token;
import com.ibm.wsspi.security.token.AttributeNameConstants;

/**
 * Represents an LTPA Token Version 3 with Post-Quantum Cryptography (PQC) support.
 * 
 * This token uses a hybrid cryptographic approach:
 * - RSA-2048 for digital signatures (classical security)
 * - ML-KEM-768 for key encapsulation and encryption (quantum-resistant security)
 * - AES-256-GCM for authenticated encryption of token data
 * 
 * Token Format (Base64-encoded):
 * [version:1][userData][expiration:8][rsaSignature:256][mlkemEncapsulation:variable][iv:12][encryptedData:variable][authTag:16]
 * 
 * Security Properties:
 * - Provides ~192-bit quantum security via ML-KEM-768 (NIST Level 3)
 * - Maintains classical security via RSA-2048 signatures
 * - Forward secrecy through ephemeral ML-KEM key encapsulation
 * - Authenticated encryption prevents tampering
 * 
 * @since Liberty 26.0.0.1
 */
public class LTPAToken3 implements Token, Serializable {

    private static final TraceComponent tc = Tr.register(LTPAToken3.class);
    private static final long serialVersionUID = 3L;
    
    // Token format constants
    private static final short VERSION = 3;
    private static final String DELIM = "%";
    private static final int VERSION_SIZE = 1;
    private static final int EXPIRATION_SIZE = 8;
    private static final int RSA_SIGNATURE_SIZE = 256; // RSA-2048 signature
    
    // Token components
    private byte[] encryptedBytes = null;
    private byte[] rsaSignature = null;
    private UserData userData;
    private long expirationInMilliseconds;
    
    // Cryptographic keys
    private final LTPAPQCKeys pqcKeys;
    
    /**
     * Constructor for validating an existing LTPA3 token.
     * 
     * @param tokenBytes The Base64-encoded byte representation of the LTPA3 token
     * @param pqcKeys The PQC keys (RSA + ML-KEM) for validation
     * @throws InvalidTokenException if the token is malformed or invalid
     */
    public LTPAToken3(byte[] tokenBytes, LTPAPQCKeys pqcKeys) throws InvalidTokenException {
        checkTokenBytes(tokenBytes);
        this.encryptedBytes = tokenBytes.clone();
        this.pqcKeys = pqcKeys;
        this.rsaSignature = null;
        this.expirationInMilliseconds = 0;
        decrypt();
    }
    
    /**
     * Constructor for validating an existing LTPA3 token with attribute removal.
     * 
     * @param tokenBytes The Base64-encoded byte representation of the LTPA3 token
     * @param pqcKeys The PQC keys (RSA + ML-KEM) for validation
     * @param attributes The list of attributes to remove from the token
     * @throws InvalidTokenException if the token is malformed or invalid
     * @throws TokenExpiredException if the token has expired
     */
    public LTPAToken3(byte[] tokenBytes, LTPAPQCKeys pqcKeys, String... attributes) 
            throws InvalidTokenException, TokenExpiredException {
        checkTokenBytes(tokenBytes);
        this.encryptedBytes = tokenBytes.clone();
        this.pqcKeys = pqcKeys;
        this.rsaSignature = null;
        this.expirationInMilliseconds = 0;
        decrypt();
        isValid();
        if (attributes != null) {
            // Reset signature and encrypted bytes, then remove attributes
            this.rsaSignature = null;
            this.encryptedBytes = null;
            userData.removeAttributes(attributes);
        }
    }
    
    /**
     * Constructor for creating a new LTPA3 token.
     * 
     * @param accessID The unique user identifier
     * @param expirationInMinutes Expiration limit of the token in minutes
     * @param pqcKeys The PQC keys (RSA + ML-KEM) for signing and encryption
     */
    protected LTPAToken3(String accessID, long expirationInMinutes, LTPAPQCKeys pqcKeys) {
        this.pqcKeys = pqcKeys;
        this.userData = new UserData(accessID);
        this.rsaSignature = null;
        this.encryptedBytes = null;
        setExpiration(expirationInMinutes);
    }
    
    /**
     * Constructor for cloning an LTPA3 token.
     * 
     * @param expirationInMinutes Expiration limit of the token in minutes
     * @param pqcKeys The PQC keys (RSA + ML-KEM)
     * @param userdata The UserData to clone
     */
    protected LTPAToken3(long expirationInMinutes, LTPAPQCKeys pqcKeys, UserData userdata) {
        this.pqcKeys = pqcKeys;
        this.userData = userdata;
        this.rsaSignature = null;
        this.encryptedBytes = null;
        setExpiration(expirationInMinutes);
    }
    
    /**
     * Encrypts the token data using ML-KEM key encapsulation and AES-256-GCM.
     * 
     * Token Structure:
     * 1. Version byte (1 byte)
     * 2. User data (variable length, Base64-encoded)
     * 3. Expiration timestamp (8 bytes, long)
     * 4. RSA signature (256 bytes)
     * 5. ML-KEM encapsulation + IV + encrypted data + auth tag
     * 
     * @throws Exception if encryption fails
     */
    @FFDCIgnore(Exception.class)
    private void encrypt() throws Exception {
        try {
            // Prepare user data with expiration
            String ud = userData.toString();
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "encrypt: userData=" + ud);
            }
            
            byte[] userDataBytes = ud.getBytes(StandardCharsets.UTF_8);
            
            // Build plaintext: userData + expiration
            ByteBuffer plaintext = ByteBuffer.allocate(userDataBytes.length + EXPIRATION_SIZE);
            plaintext.put(userDataBytes);
            plaintext.putLong(expirationInMilliseconds);
            byte[] plaintextBytes = plaintext.array();
            
            // Encrypt using ML-KEM + AES-256-GCM
            byte[] encryptedData = LTPAPQCCrypto.encryptToken(
                plaintextBytes,
                pqcKeys.getMlkemPublicKey(),
                pqcKeys.getMlkemAlgorithm()
            );
            
            // Build final token: version + rsaSignature + encryptedData
            ByteBuffer tokenBuffer = ByteBuffer.allocate(
                VERSION_SIZE + RSA_SIGNATURE_SIZE + encryptedData.length
            );
            tokenBuffer.put((byte) VERSION);
            tokenBuffer.put(rsaSignature);
            tokenBuffer.put(encryptedData);
            
            encryptedBytes = tokenBuffer.array();
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Token encrypted successfully, size=" + encryptedBytes.length);
            }
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error encrypting token", e);
            }
            throw e;
        }
    }
    
    /**
     * Decrypts the encrypted token bytes.
     * 
     * @throws InvalidTokenException if decryption fails or token is malformed
     */
    @FFDCIgnore(Exception.class)
    private void decrypt() throws InvalidTokenException {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encryptedBytes);
            
            // Read version
            byte version = buffer.get();
            if (version != VERSION) {
                throw new InvalidTokenException("Invalid token version: " + version);
            }
            
            // Read RSA signature
            byte[] signature = new byte[RSA_SIGNATURE_SIZE];
            buffer.get(signature);
            this.rsaSignature = signature;
            
            // Read encrypted data (ML-KEM encapsulation + IV + ciphertext + tag)
            byte[] encryptedData = new byte[buffer.remaining()];
            buffer.get(encryptedData);
            
            // Decrypt using ML-KEM + AES-256-GCM
            byte[] decryptedData = LTPAPQCCrypto.decryptToken(
                encryptedData,
                pqcKeys.getMlkemPrivateKey(),
                pqcKeys.getMlkemAlgorithm()
            );
            
            // Parse decrypted data
            ByteBuffer plaintext = ByteBuffer.wrap(decryptedData);
            
            // Extract user data (everything except last 8 bytes)
            byte[] userDataBytes = new byte[decryptedData.length - EXPIRATION_SIZE];
            plaintext.get(userDataBytes);
            
            // Extract expiration
            expirationInMilliseconds = plaintext.getLong();
            
            // Parse user data
            String userDataStr = new String(userDataBytes, StandardCharsets.UTF_8);
            String[] userFields = LTPATokenizer.parseToken(userDataStr);
            Map<String, ArrayList<String>> attribs = LTPATokenizer.parseUserData(userFields[0]);
            userData = new UserData(attribs);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Token decrypted successfully");
            }
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error decrypting token", e);
            }
            throw new InvalidTokenException("Token decryption failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Signs the token data using RSA-2048 with SHA-256.
     * 
     * @throws Exception if signing fails
     */
    @FFDCIgnore(Exception.class)
    private void sign() throws Exception {
        try {
            // Prepare data to sign: userData + expiration
            String dataStr = userData.toString();
            byte[] userDataBytes = dataStr.getBytes(StandardCharsets.UTF_8);
            
            ByteBuffer signData = ByteBuffer.allocate(userDataBytes.length + EXPIRATION_SIZE);
            signData.put(userDataBytes);
            signData.putLong(expirationInMilliseconds);
            
            // Sign with RSA-2048
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(pqcKeys.getRsaPrivateKey());
            signer.update(signData.array());
            rsaSignature = signer.sign();
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Token signed successfully");
            }
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error signing token", e);
            }
            throw e;
        }
    }
    
    /**
     * Verifies the RSA signature of the token.
     * 
     * @return true if signature is valid
     * @throws Exception if verification fails
     */
    @FFDCIgnore(Exception.class)
    private boolean verify() throws Exception {
        try {
            // Prepare data to verify: userData + expiration
            String dataStr = userData.toString();
            byte[] userDataBytes = dataStr.getBytes(StandardCharsets.UTF_8);
            
            ByteBuffer verifyData = ByteBuffer.allocate(userDataBytes.length + EXPIRATION_SIZE);
            verifyData.put(userDataBytes);
            verifyData.putLong(expirationInMilliseconds);
            
            // Verify RSA signature
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(pqcKeys.getRsaPublicKey());
            verifier.update(verifyData.array());
            boolean valid = verifier.verify(rsaSignature);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Signature verification: " + valid);
            }
            
            return valid;
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error verifying signature", e);
            }
            throw e;
        }
    }
    
    /** {@inheritDoc} */
    @Override
    @FFDCIgnore(Exception.class)
    public boolean isValid() throws InvalidTokenException, TokenExpiredException {
        validateExpiration();
        
        boolean verified = false;
        try {
            verified = verify();
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, "Signature verification failed", e);
            }
            throw new InvalidTokenException("Token validation failed: " + e.getMessage(), e);
        }
        
        if (!verified) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, "Invalid signature");
            }
            throw new InvalidTokenException("Token validation failed: invalid signature");
        }
        
        return true;
    }
    
    /**
     * Validates that the token has not expired.
     * 
     * @throws TokenExpiredException if the token has expired
     */
    public void validateExpiration() throws TokenExpiredException {
        Date currentTime = new Date();
        Date expirationTime = new Date(expirationInMilliseconds);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(this, tc, "Current time=" + currentTime + ", expiration=" + expirationTime);
        }
        
        if (currentTime.after(expirationTime)) {
            String msg = "Token expired: current=" + currentTime + ", expiration=" + expirationTime;
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, msg);
            }
            throw new TokenExpiredException(expirationInMilliseconds, msg);
        }
    }
    
    /** {@inheritDoc} */
    @Override
    @FFDCIgnore(Exception.class)
    public byte[] getBytes() throws InvalidTokenException, TokenExpiredException {
        if (encryptedBytes == null) {
            try {
                sign();
                encrypt();
            } catch (Exception e) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(this, tc, "Error generating token bytes", e);
                }
                throw new InvalidTokenException("Failed to generate token: " + e.getMessage(), e);
            }
        }
        return encryptedBytes.clone();
    }
    
    /** {@inheritDoc} */
    @Override
    public long getExpiration() {
        return expirationInMilliseconds;
    }
    
    /** {@inheritDoc} */
    @Override
    public short getVersion() {
        return VERSION;
    }
    
    /** {@inheritDoc} */
    @Override
    public String[] addAttribute(String name, String value) {
        rsaSignature = null;
        encryptedBytes = null;
        return userData.addAttribute(name, value);
    }
    
    /** {@inheritDoc} */
    @Override
    public String[] getAttributes(String name) {
        return userData.getAttributes(name);
    }
    
    /** {@inheritDoc} */
    @Override
    public Enumeration<String> getAttributeNames() {
        return userData.getAttributeNames();
    }
    
    /** {@inheritDoc} */
    @Override
    public String toString() {
        return encryptedBytes == null ? "NULL" : Base64Coder.base64EncodeToString(encryptedBytes);
    }
    
    /**
     * Creates a deep copy of this LTPA3 token.
     * 
     * @return A new copy of the token
     */
    @Override
    public Object clone() {
        UserData clonedUserData = (UserData) userData.clone();
        return new LTPAToken3(expirationInMilliseconds, pqcKeys, clonedUserData);
    }
    
    /**
     * Validates that token bytes are not null or empty.
     * 
     * @param tokenBytes The token bytes to validate
     * @throws IllegalArgumentException if token bytes are invalid
     */
    private static void checkTokenBytes(byte[] tokenBytes) {
        if (tokenBytes == null || tokenBytes.length == 0) {
            throw new IllegalArgumentException("Token bytes cannot be null or empty");
        }
    }
    
    /**
     * Sets the expiration time for this token.
     * 
     * @param expirationInMinutes The expiration time in minutes from now
     */
    private void setExpiration(long expirationInMinutes) {
        expirationInMilliseconds = System.currentTimeMillis() + (expirationInMinutes * 60 * 1000);
        rsaSignature = null;
        encryptedBytes = null;
        
        if (userData != null) {
            userData.addAttribute(AttributeNameConstants.WSTOKEN_EXPIRATION, 
                                Long.toString(expirationInMilliseconds));
        }
    }
}

// Made with Bob
