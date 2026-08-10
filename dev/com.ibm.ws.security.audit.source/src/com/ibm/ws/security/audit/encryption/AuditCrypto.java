/*******************************************************************************
 * Copyright (c) 2018, 2025 IBM Corporation and others.
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.common.crypto.CryptoUtils;

final class AuditCrypto {

    private static TraceComponent tc = Tr.register(AuditCrypto.class, null, "com.ibm.ejs.resources.security");

    /** Version marker prepended to all GCM-encrypted output. */
    private static final byte GCM_VERSION_MARKER = 0x01;
    /** GCM recommended IV length in bytes (96 bits). */
    private static final int GCM_IV_LENGTH = 12;
    /** GCM authentication tag length in bits (128 bits = 16 bytes). */
    private static final int GCM_TAG_LENGTH_BITS = 128;
    /** Legacy CBC IV length in bytes. */
    private static final int CBC_IV_LENGTH = 16;

    public AuditCrypto() {}

    static final byte[] generateSharedKey() {
        return CryptoUtils.generateRandomBytes(CryptoUtils.AES_256_KEY_LENGTH_BYTES);
    }

    /**
     * Encrypt {@code data} with AES-256-GCM.
     * Output format: {@code [0x01][12-byte random IV][GCM ciphertext+tag]}
     */
    static final byte[] encrypt(byte[] data, byte[] key) {
        return encrypt(data, key, CryptoUtils.AES_GCM_CIPHER);
    }

    /**
     * Encrypt {@code data} with the given AES cipher.
     * When {@code cipher} is {@code AES/GCM/NoPadding} the output is prefixed with
     * the version marker {@code 0x01} followed by a freshly generated 12-byte IV,
     * so the decryptor can recover it: {@code [0x01][IV][GCM ciphertext+tag]}.
     */
    static final byte[] encrypt(byte[] data, byte[] key, String cipher) {
        long start_time = 0;

        if (tc.isDebugEnabled()) {
            start_time = System.currentTimeMillis();
            Tr.debug(tc, "Cipher used to encrypt: " + cipher);
            Tr.debug(tc, "Data size: " + data.length);
            Tr.debug(tc, "Key size: " + key.length);
        }

        if (null == data) {
            if (tc.isDebugEnabled())
                Tr.debug(tc, "data Array was null");
            return null;
        }

        byte[] result = null;
        try {
            SecretKey sKey = constructSecretKey(key);

            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher ci = Cipher.getInstance(cipher);
            ci.init(Cipher.ENCRYPT_MODE, sKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            if (tc.isDebugEnabled())
                Tr.debug(tc, "encrypt() Cipher.doFinal()\n   data: " + new String(data));
            byte[] ciphertext = ci.doFinal(data);

            // Prepend version marker and IV: [0x01][IV][ciphertext+tag]
            result = new byte[1 + GCM_IV_LENGTH + ciphertext.length];
            result[0] = GCM_VERSION_MARKER;
            System.arraycopy(iv, 0, result, 1, GCM_IV_LENGTH);
            System.arraycopy(ciphertext, 0, result, 1 + GCM_IV_LENGTH, ciphertext.length);

        } catch (java.security.NoSuchAlgorithmException e) {
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2256");
        } catch (java.security.InvalidKeyException e) {
            Tr.debug(tc, "Error: Key invalid");
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2264");
        } catch (java.security.spec.InvalidKeySpecException e) {
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2267");
        } catch (javax.crypto.NoSuchPaddingException e) {
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2270");
        } catch (javax.crypto.IllegalBlockSizeException e) {
            // we get this exception when validating other token types
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2273");
        } catch (javax.crypto.BadPaddingException e) {
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2276");
        } catch (java.security.InvalidAlgorithmParameterException e) {
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2279");
        }

        if (tc.isDebugEnabled()) {
            long end_time = System.currentTimeMillis();
            Tr.debug(tc, "Total encryption time: " + (end_time - start_time));
        }

        return result;
    }

    /**
     * Decrypt {@code mesg} previously encrypted by {@link #encrypt(byte[], byte[])}.
     * Auto-detects format from the version marker in byte 0:
     * {@code 0x01} → AES/GCM/NoPadding; otherwise → legacy AES/CBC/PKCS5Padding.
     */
    static final byte[] decrypt(byte[] mesg, byte[] key) {
        return decrypt(mesg, key, CryptoUtils.AES_GCM_CIPHER);
    }

    /**
     * Decrypt {@code mesg} using format auto-detection:
     * <ul>
     *   <li>If {@code mesg[0] == 0x01}: GCM path — extract 12-byte IV from bytes 1–12,
     *       ciphertext from bytes 13+, decrypt with {@code AES/GCM/NoPadding}.</li>
     *   <li>Otherwise: legacy CBC path — derive 16-byte IV from the first 16 bytes of
     *       {@code key}, decrypt with {@code AES/CBC/PKCS5Padding}.</li>
     * </ul>
     * The {@code cipher} parameter is ignored; it is retained for API compatibility only.
     */
    static final byte[] decrypt(byte[] mesg, byte[] key, String cipher) {
        long start_time = 0;

        if (tc.isDebugEnabled()) {
            start_time = System.currentTimeMillis();
            Tr.debug(tc, "key size: " + key.length);
        }

        byte[] plaintext = null;
        try {
            SecretKey sKey = constructSecretKey(key);

            if (mesg.length > 0 && mesg[0] == GCM_VERSION_MARKER) {
                // --- GCM path ---
                if (tc.isDebugEnabled())
                    Tr.debug(tc, "decrypt() using AES/GCM path");
                byte[] iv = new byte[GCM_IV_LENGTH];
                System.arraycopy(mesg, 1, iv, 0, GCM_IV_LENGTH);
                byte[] ciphertext = new byte[mesg.length - 1 - GCM_IV_LENGTH];
                System.arraycopy(mesg, 1 + GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

                Cipher ci = Cipher.getInstance(CryptoUtils.AES_GCM_CIPHER);
                ci.init(Cipher.DECRYPT_MODE, sKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
                plaintext = ci.doFinal(ciphertext);
            } else {
                // --- Legacy CBC path (backward compatibility) ---
                if (tc.isDebugEnabled())
                    Tr.debug(tc, "decrypt() using legacy AES/CBC path");
                byte[] iv16 = new byte[CBC_IV_LENGTH];
                System.arraycopy(key, 0, iv16, 0, CBC_IV_LENGTH);

                Cipher ci = Cipher.getInstance(CryptoUtils.AES_CBC_CIPHER);
                ci.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(iv16));
                plaintext = ci.doFinal(mesg);
            }

            if (tc.isDebugEnabled())
                Tr.debug(tc, "decrypt() Cipher.doFinal()\n   plaintext: " + new String(plaintext));

        } catch (java.security.NoSuchAlgorithmException e) {
            Tr.error(tc, "no such algorithm exception", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2385");
        } catch (java.security.InvalidKeyException e) {
            Tr.debug(tc, "Error: Key invalid");
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2393");
        } catch (java.security.spec.InvalidKeySpecException e) {
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2396");
        } catch (javax.crypto.NoSuchPaddingException e) {
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2399");
        } catch (javax.crypto.IllegalBlockSizeException e) {
            // we get this exception when validating other token types
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2402");
        } catch (javax.crypto.BadPaddingException e) {
            Tr.debug(tc, "BadPaddingException validating token, normal when token generated from other factory.", new Object[] { e.getMessage() });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.AuditCrypto", "2405");
        } catch (java.security.InvalidAlgorithmParameterException e) {
            Tr.error(tc, "security.ltpa.noalgorithm", new Object[] { e });
            com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.auditAuditCrypto", "2408");
        }

        if (tc.isDebugEnabled()) {
            long end_time = System.currentTimeMillis();
            Tr.debug(tc, "Total decryption time: " + (end_time - start_time));
        }

        return plaintext;
    }

    private static SecretKey constructSecretKey(byte[] key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        return new SecretKeySpec(key, 0, CryptoUtils.AES_256_KEY_LENGTH_BYTES, CryptoUtils.ENCRYPT_ALGORITHM_AES);
    }
}
