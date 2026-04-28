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

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.websphere.security.auth.TokenCreationFailedException;
import com.ibm.websphere.security.auth.TokenExpiredException;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.token.ltpa.LTPAValidationKeysInfo;
import com.ibm.ws.security.token.ltpa.pqc.LTPAPQCKeys;
import com.ibm.wsspi.security.ltpa.Token;
import com.ibm.wsspi.security.ltpa.TokenFactory;

/**
 * Factory for creating and validating LTPA Token Version 3 with Post-Quantum Cryptography (PQC) support.
 * 
 * This factory creates tokens using hybrid cryptography:
 * - RSA-2048 for digital signatures (classical security)
 * - ML-KEM-768 for key encapsulation and encryption (quantum-resistant security)
 * 
 * The factory supports:
 * - Creating new LTPA3 tokens with PQC keys
 * - Validating existing LTPA3 tokens
 * - Using primary PQC keys for token creation
 * - Using validation PQC keys for backward compatibility
 * 
 * @since Liberty 26.0.0.1
 */
public class LTPAToken3Factory implements TokenFactory {
    
    private static final TraceComponent tc = Tr.register(LTPAToken3Factory.class);
    
    // Token configuration
    private long expirationInMinutes;
    
    // Primary PQC keys (for creating new tokens)
    private LTPAPQCKeys primaryPQCKeys;
    
    // Validation PQC keys (for validating tokens from other servers)
    private CopyOnWriteArrayList<LTPAValidationKeysInfo> validationKeys;
    
    /**
     * Initializes the factory with PQC keys and configuration.
     * 
     * @param tokenFactoryMap Map containing:
     *   - LTPAConstants.EXPIRATION: Token expiration in minutes
     *   - LTPAConstants.PRIMARY_PQC_KEYS: Primary PQC keys for token creation
     *   - LTPAConstants.VALIDATION_KEYS: List of validation keys
     */
    @SuppressWarnings("unchecked")
    @Override
    public void initialize(@Sensitive Map tokenFactoryMap) {
        expirationInMinutes = (Long) tokenFactoryMap.get(LTPAConstants.EXPIRATION);
        primaryPQCKeys = (LTPAPQCKeys) tokenFactoryMap.get(LTPAConstants.PRIMARY_PQC_KEYS);
        validationKeys = (CopyOnWriteArrayList<LTPAValidationKeysInfo>) tokenFactoryMap.get(LTPAConstants.VALIDATION_KEYS);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "LTPAToken3Factory initialized");
            Tr.debug(tc, "Expiration: " + expirationInMinutes + " minutes");
            Tr.debug(tc, "Primary PQC keys: " + (primaryPQCKeys != null ? "present" : "null"));
            Tr.debug(tc, "Validation keys: " + (validationKeys != null ? validationKeys.size() : 0));
        }
    }
    
    /**
     * Creates a new LTPA3 token with the specified user data.
     * 
     * @param tokenData Map containing user data, must include LTPAConstants.UNIQUE_ID
     * @return A new LTPA3 token
     * @throws TokenCreationFailedException if token creation fails
     */
    @Override
    public Token createToken(Map tokenData) throws TokenCreationFailedException {
        String userUniqueId = getUniqueId(tokenData);
        
        if (primaryPQCKeys == null) {
            Tr.error(tc, "LTPA_TOKEN3_FACTORY_NO_PQC_KEYS");
            String formattedMessage = Tr.formatMessage(tc, "LTPA_TOKEN3_FACTORY_NO_PQC_KEYS");
            throw new TokenCreationFailedException(formattedMessage);
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Creating LTPA3 token for user: " + userUniqueId);
        }
        
        return new LTPAToken3(userUniqueId, expirationInMinutes, primaryPQCKeys);
    }
    
    /**
     * Extracts the unique user ID from token data.
     * 
     * @param tokenData Map containing user data
     * @return The unique user ID
     * @throws TokenCreationFailedException if unique ID is missing or empty
     */
    private String getUniqueId(Map tokenData) throws TokenCreationFailedException {
        String userUniqueId = (String) tokenData.get(LTPAConstants.UNIQUE_ID);
        if (userUniqueId == null || userUniqueId.length() == 0) {
            Tr.error(tc, "LTPA_TOKEN_SERVICE_INVALID_UNIQUE_ID");
            String formattedMessage = Tr.formatMessage(tc, "LTPA_TOKEN_SERVICE_INVALID_UNIQUE_ID");
            throw new TokenCreationFailedException(formattedMessage);
        }
        return userUniqueId;
    }
    
    /**
     * Validates token bytes and returns a validated token.
     * 
     * @param tokenBytes The Base64-encoded token bytes
     * @return A validated LTPA3 token
     * @throws InvalidTokenException if the token is invalid
     * @throws TokenExpiredException if the token has expired
     */
    @Override
    public Token validateTokenBytes(byte[] tokenBytes) throws InvalidTokenException, TokenExpiredException {
        return validateTokenBytes(tokenBytes, (String[]) null);
    }
    
    /**
     * Validates token bytes and returns a validated token with specified attributes removed.
     * 
     * This method attempts validation in the following order:
     * 1. Primary PQC keys (for tokens created by this server)
     * 2. Validation PQC keys (for tokens created by other servers in the cluster)
     * 
     * @param tokenBytes The Base64-encoded token bytes
     * @param removeAttributes Attributes to remove from the validated token
     * @return A validated LTPA3 token
     * @throws InvalidTokenException if the token is invalid
     * @throws TokenExpiredException if the token has expired
     */
    @FFDCIgnore(Exception.class)
    @Override
    public Token validateTokenBytes(byte[] tokenBytes, String... removeAttributes) 
            throws InvalidTokenException, TokenExpiredException {
        
        Token validatedToken = null;
        
        // Try primary PQC keys first
        if (primaryPQCKeys != null) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Validating token with primary PQC keys");
            }
            
            try {
                validatedToken = new LTPAToken3(tokenBytes, primaryPQCKeys, removeAttributes);
                if (validatedToken != null) {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "Token validated successfully with primary PQC keys");
                    }
                    return validatedToken;
                }
            } catch (Exception e) {
                // If token is expired, don't try validation keys
                if (e instanceof TokenExpiredException) {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "Token expired");
                    }
                    throw (TokenExpiredException) e;
                }
                // For invalid tokens, continue to validation keys
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Primary key validation failed, trying validation keys", e);
                }
            }
        }
        
        // Try validation PQC keys
        if (validationKeys != null && !validationKeys.isEmpty()) {
            Exception lastException = null;
            Iterator<LTPAValidationKeysInfo> validationKeysIterator = validationKeys.iterator();
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Trying " + validationKeys.size() + " validation keys");
            }
            
            while (validationKeysIterator.hasNext()) {
                LTPAValidationKeysInfo ltpaKeyInfo = validationKeysIterator.next();
                
                // Remove expired validation keys
                if (ltpaKeyInfo.isValidUntilDateExpired()) {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "Removing expired validation key: " + ltpaKeyInfo);
                    }
                    validationKeys.remove(ltpaKeyInfo);
                    continue;
                }
                
                // Get PQC keys from validation key info
                LTPAPQCKeys validationPQCKeys = ltpaKeyInfo.getPQCKeys();
                if (validationPQCKeys == null) {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "Validation key has no PQC keys, skipping");
                    }
                    continue;
                }
                
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Validating with validation key: " + ltpaKeyInfo);
                }
                
                try {
                    validatedToken = new LTPAToken3(tokenBytes, validationPQCKeys, removeAttributes);
                    if (validatedToken != null) {
                        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                            Tr.debug(tc, "Token validated successfully with validation key");
                        }
                        return validatedToken;
                    }
                } catch (Exception e) {
                    // If token is expired, stop trying
                    if (e instanceof TokenExpiredException) {
                        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                            Tr.debug(tc, "Token expired");
                        }
                        throw (TokenExpiredException) e;
                    }
                    
                    lastException = e;
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "Validation key failed: " + e.getMessage());
                    }
                }
            }
            
            // All validation keys failed
            if (lastException != null) {
                if (lastException instanceof InvalidTokenException) {
                    throw (InvalidTokenException) lastException;
                } else {
                    throw new InvalidTokenException("Token validation failed: " + lastException.getMessage(), lastException);
                }
            }
        }
        
        // No keys available or all failed
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Token validation failed: no valid keys");
        }
        throw new InvalidTokenException("Token factory not properly initialized or token is invalid");
    }
}

// Made with Bob
