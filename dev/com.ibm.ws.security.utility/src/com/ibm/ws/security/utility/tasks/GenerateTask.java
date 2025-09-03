/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.utility.tasks;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.ws.crypto.util.AESKeyManager;
import com.ibm.ws.crypto.util.AESKeyManager.KeyVersion;
import com.ibm.ws.security.utility.SecurityUtilityReturnCodes;
import com.ibm.ws.security.utility.utils.ConsoleWrapper;

/**
 * GenerateTask handles the generation of encryption keys for Liberty server configuration.
 * It can create either a random AES-256 key or use a provided passphrase to derive a key, and then writes
 * the result to an XML configuration file.
 */
public class GenerateTask extends BaseCommandTask {

    // Command line argument constants
    private static final String ARG_FILE = "--file";
    private static final String ARG_KEY = "--key";
    private static final List<String> VALID_ARGUMENTS = Collections.unmodifiableList(
                                                                                     Arrays.asList(ARG_KEY, ARG_FILE));

    private static final String TASK_NAME = "generate";

    /**
     * Constructs a new GenerateTask with the specified script name.
     *
     * @param scriptName The name of the script executing this task
     */
    public GenerateTask(String scriptName) {
        super(scriptName);
    }

    @Override
    void checkRequiredArguments(String[] args) throws IllegalArgumentException {
        boolean fileFound = false;

        for (String arg : args) {
            String key = arg.split("=")[0];

            if (ARG_FILE.equals(key)) {
                fileFound = true;
            }
        }

        if (!fileFound) {
            throw new IllegalArgumentException(getMessage("missingArg", ARG_FILE));
        }

    }

    @Override
    public String getTaskDescription() {
        return getOption("generate.desc", true);
    }

    @Override
    public String getTaskHelp() {
        return getTaskHelp("generate.desc", "generate.usage.options",
                           "generate.required-key.", "generate.required-desc.",
                           "generate.option-key.", "generate.option-desc.",
                           null, null,
                           scriptName);
    }

    @Override
    public String getTaskName() {
        return TASK_NAME;
    }

    @Override
    public SecurityUtilityReturnCodes handleTask(ConsoleWrapper stdin, PrintStream stdout, PrintStream stderr, String[] args) throws Exception {

        // Parse command line arguments
        CommandArguments parsedArgs = parseArgs(args);

        // Create XML builder and generate the key file
        PasswordEncryptionConfigXMLBuilder builder = new PasswordEncryptionConfigXMLBuilder(parsedArgs.keyPhrase, parsedArgs.filePath);

        builder.generateXML();
        stdout.println(getMessage("generate.success", new File(builder.getFilePath()).getAbsolutePath()));
        return SecurityUtilityReturnCodes.OK;

    }

    @Override
    boolean isKnownArgument(String arg) {
        return arg != null && VALID_ARGUMENTS.contains(arg);
    }

    /**
     * Data class to hold parsed command arguments
     */
    private static class CommandArguments {
        final String keyPhrase;
        final String filePath;

        CommandArguments(String keyPhrase, String filePath) {
            this.keyPhrase = keyPhrase;
            this.filePath = filePath;
        }
    }

    /**
     * Parses command line arguments and returns a CommandArguments object.
     *
     * @param args Command line arguments to parse
     * @return CommandArguments object containing the parsed values
     * @throws IllegalArgumentException if invalid arguments are provided
     */
    private CommandArguments parseArgs(String[] args) {
        String keyPhrase = null;
        String filePath = null;

        for (String arg : args) {
            if (!arg.startsWith("--")) {
                continue;
            }

            int index = arg.indexOf('=');
            if (index == -1) {
                // Options must have values
                throw new IllegalArgumentException(getMessage("invalidArg", arg));
            }

            String value = (index + 1 < arg.length()) ? arg.substring(index + 1) : null;
            String option = arg.substring(0, index);

            if (!isKnownArgument(option)) {
                throw new IllegalArgumentException(getMessage("invalidArg", option));
            }

            if (ARG_KEY.equals(option)) {
                keyPhrase = value;
            } else if (ARG_FILE.equals(option)) {
                if (new File(value).isDirectory()) {
                    throw new IllegalArgumentException(getMessage("generate.failFileIsDirectory", value));
                } else if (new File(value).exists()) {
                    throw new IllegalArgumentException(getMessage("generate.failFileExists", value));
                }
                filePath = value;

            }
        }
        if (filePath == null) {
            throw new IllegalArgumentException(getMessage("missingArg", ARG_FILE));
        }

        return new CommandArguments(keyPhrase, filePath);
    }

    /**
     * Builder class for generating XML configuration with encryption keys.
     * This class handles the creation of properly formatted XML configuration
     * for Liberty server encryption keys.
     */
    public static class PasswordEncryptionConfigXMLBuilder {
        private final String filePath;
        private final String passphrase;

        /**
         * Creates a new builder with the specified passphrase and file path.
         *
         * @param keyPhrase The passphrase to use for encryption, or null to generate a random key
         * @param filePath  The path where the XML file should be written, or null to use the default
         */
        public PasswordEncryptionConfigXMLBuilder(String keyPhrase, String filePath) {
            this.passphrase = keyPhrase;
            this.filePath = filePath;
        }

        /**
         * @return the filePath
         */
        public String getFilePath() {
            return filePath;
        }

        /**
         * Formats the property name and value as an XML server configuration.
         *
         * @param name  The property name, not null
         * @param value The property value, not null
         * @return Formatted XML string
         */
        private String formatXml(String name, String value) {
            StringBuilder xml = new StringBuilder();
            xml.append("<server>\n");
            xml.append("    <variable name=\"").append(name).append("\" value=\"").append(value).append("\" />\n");
            xml.append("</server>");
            return xml.toString();
        }

        /**
         * Generates a cryptographically secure random AES-256 key.
         *
         * @return Base64-encoded random AES-256 key
         */
        private String generateRandomAes256Key() {
            byte[] keyBytes;
            SecureRandom secureRandom = new SecureRandom();

            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoUtils.ENCRYPT_ALGORITHM_AES);
                keyGenerator.init(CryptoUtils.AES_256_KEY_LENGTH_BITS, secureRandom);
                SecretKey secretKey = keyGenerator.generateKey();
                keyBytes = secretKey.getEncoded();
            } catch (NoSuchAlgorithmException e) {
                // Fallback to SecureRandom if KeyGenerator is not available
                keyBytes = new byte[CryptoUtils.AES_256_KEY_LENGTH_BYTES];
                secureRandom.nextBytes(keyBytes);
            }

            return Base64.getEncoder().encodeToString(keyBytes);
        }

        private String generateAes256KeyWithPBKDF2(String phrase) throws NoSuchAlgorithmException, InvalidKeySpecException {
            byte[] data = KeyVersion.AES_V1.buildAesKeyWithPbkdf2(phrase.toCharArray());
            return Base64.getEncoder().encodeToString(data);
        }

        /**
         * Writes the generated key configuration to the specified file.
         *
         * @throws IOException              If an I/O error occurs
         * @throws InvalidKeySpecException
         * @throws NoSuchAlgorithmException
         *
         */
        public void generateXML() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            generateXML(this.passphrase, this.filePath);
        }

        /**
         * Generates an XML configuration file with encryption key information.
         *
         * @param keyPhrase The passphrase to use for encryption, or null to generate a random key
         * @param filePath  The path where the XML file should be written, cannot be null.
         * @throws IOException              If an I/O error occurs during file creation or writing
         * @throws InvalidKeySpecException
         * @throws NoSuchAlgorithmException
         */
        private void generateXML(String keyPhrase, String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            String propertyName = AESKeyManager.NAME_WLP_BASE64_AES_ENCRYPTION_KEY;
            String keyValue;
            if (keyPhrase == null) {
                keyValue = generateRandomAes256Key();
            } else {
                keyValue = generateAes256KeyWithPBKDF2(keyPhrase);
            }

            // Generate XML content
            String xmlContent = formatXml(propertyName, keyValue);
            Path path = Paths.get(filePath);

            try {
                // Create parent directories if they don't exist
                Path parent = path.getParent();
                if (parent != null && !Files.exists(parent)) {
                    Files.createDirectories(parent);
                }

                // Write the file with proper character encoding
                Files.write(
                            path,
                            xmlContent.getBytes(StandardCharsets.UTF_8),
                            StandardOpenOption.CREATE,
                            StandardOpenOption.WRITE);
            } catch (IOException e) {
                throw new IOException("Failed to write encryption key to file: " + filePath, e);
            }
        }
    }
}
