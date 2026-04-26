/*******************************************************************************
 * Copyright (c) 2012, 2026 IBM Corporation and others.
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
package com.ibm.ws.security.token.ltpa;

import java.util.List;
import java.util.Properties;

import com.ibm.wsspi.security.ltpa.TokenFactory;

/**
 * Service class to indicate the LTPA configuration is available and
 * ready for use.
 */
public interface LTPAConfiguration {

    /**
     * The token keys file.
     */
    public static final String CFG_KEY_IMPORT_FILE = "keysFileName";

    /**
     * The token keys file password.
     */
    public static final String CFG_KEY_PASSWORD = "keysPassword"; // pragma: allowlist secret

    /**
     * The token expiration.
     */
    public static final String CFG_KEY_TOKEN_EXPIRATION = "expiration";

    /**
     * The token keys file's monitor interval.
     */
    public static final String CFG_KEY_MONITOR_INTERVAL = "monitorInterval";

    /**
     * The Boolean to monitor the token keys file's directory.
     */
    public static final String CFG_KEY_MONITOR_VALIDATION_KEYS_DIR = "monitorValidationKeysDir";

    /**
     * The token keys file's update method or trigger.
     */
    public static final String CFG_KEY_UPDATE_TRIGGER = "updateTrigger";

    /**
     * The token validation keys.
     */
    static final String CFG_KEY_VALIDATION_KEYS = "validationKeys";

    /**
     * The token validation keys file(s).
     */
    static final String CFG_KEY_VALIDATION_FILE_NAME = "fileName";

    /**
     * The token validation keys file password.
     */
    static final String CFG_KEY_VALIDATION_PASSWORD = "password";

    /**
     * The the date-time to stop using the token validation keys.
     */
    static final String CFG_KEY_VALIDATION_VALID_UNTIL_DATE = "validUntilDate";

    // ========== PQC Configuration Properties (Issue #35556) ==========
    
    /**
     * The cryptographic mode for LTPA tokens.
     * Valid values: "classical" (RSA only), "pqc" (ML-DSA only), "hybrid" (both RSA and ML-DSA)
     */
    public static final String CFG_KEY_CRYPTO_MODE = "cryptoMode";
    
    /**
     * The PQC algorithm to use for digital signatures.
     * Valid values: "ML-DSA-44" (128-bit security), "ML-DSA-65" (192-bit security), "ML-DSA-87" (256-bit security)
     */
    public static final String CFG_KEY_PQC_ALGORITHM = "pqcAlgorithm";
    
    /**
     * Enable or disable Post-Quantum Cryptography support.
     */
    public static final String CFG_KEY_ENABLE_PQC = "enablePQC";

    /**
     * Internal property used to distinguish configured validation keys from non-configured validation keys.
     * Configured validation keys are explicitly defined in the server.xml using <validationKeys /> and require a password.
     * Non-configured validation keys are picked up when <ltpa monitorValidationKeysDir="true" /> is set and uses the same password as the primary ltpa key.
     *
     * Currently only used to determine if we should re-encrypt the validation key when the primary ltpa key is re-encrypted and it is a non-configured validation key.
     */
    static final String INTERNAL_KEY_IS_CONFIGURED_VALIDATION_KEY = "isConfiguredValidationKey";

    /**
     * @return TokenFactory instance corresponding to this LTPA configuration
     */
    TokenFactory getTokenFactory();

    /**
     * @return LTPAKeyInfoManager instance corresponding to this LTPA configuration
     */
    LTPAKeyInfoManager getLTPAKeyInfoManager();

    /**
     * @return LTPA key file
     */
    String getPrimaryKeyFile();

    /**
     * @return LTPA key password
     */
    String getPrimaryKeyPassword();

    /**
     * @return boolean for try to re-encrypt ltpa keys
     */
    boolean getTryToReEncryptLtpaKeys();

    /**
     * @return LTPA expiration
     */
    long getTokenExpiration();

    /**
     * @return authFiler reference
     */
    String getAuthFilterRef();

    /**
     * @return Maximum expiration difference allowed
     */
    long getExpirationDifferenceAllowed();

    
    // ========== PQC Configuration Getters (Issue #35556) ==========
    
    /**
     * Get the cryptographic mode for LTPA tokens.
     * 
     * @return The crypto mode: "classical" (RSA only), "pqc" (ML-DSA only), or "hybrid" (both)
     */
    String getCryptoMode();
    
    /**
     * Get the PQC algorithm to use for digital signatures.
     * 
     * @return The PQC algorithm: "ML-DSA-44", "ML-DSA-65", or "ML-DSA-87"
     */
    String getPQCAlgorithm();
    
    /**
     * Check if Post-Quantum Cryptography support is enabled.
     * 
     * @return true if PQC is enabled, false otherwise
     */
    boolean isEnablePQC();

    /**
     * @return monitor interval
     */
    long getMonitorInterval();

    /**
     * @return boolean for monitoring validation keys dir
     */
    boolean getMonitorValidationKeysDir();

    /**
     * @return update trigger
     */
    String getUpdateTrigger();

    /**
     * @return validation Keys
     */
    List<Properties> getValidationKeys();
    
}
