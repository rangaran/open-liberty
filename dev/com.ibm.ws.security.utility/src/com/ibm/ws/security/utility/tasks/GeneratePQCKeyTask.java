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
package com.ibm.ws.security.utility.tasks;

import java.io.File;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.ibm.ws.security.audit.crypto.AuditPQCKeyLoader;
import com.ibm.ws.security.utility.IFileUtility;
import com.ibm.ws.security.utility.SecurityUtilityReturnCodes;
import com.ibm.ws.security.utility.utils.ConsoleWrapper;

/**
 * GeneratePQCKeyTask handles native generation and storage of Post-Quantum Cryptography (PQC)
 * key pairs (ML-KEM and ML-DSA) for Open Liberty without requiring external 3rd-party tools.
 */
public class GeneratePQCKeyTask extends BaseCommandTask {

    public static final String ARG_TYPE = "--type";
    public static final String ARG_FILE = "--createConfigFile";
    public static final String ARG_OUT = "--out";

    public static final String TYPE_ML_KEM = "ML-KEM";
    public static final String TYPE_ML_DSA = "ML-DSA";

    public static final String DEFAULT_TYPE = TYPE_ML_KEM;
    public static final String DEFAULT_KEM_ALG = "ML-KEM-768";
    public static final String DEFAULT_DSA_ALG = "ML-DSA-65";

    private static final List<String> VALID_ARGUMENTS = Collections.unmodifiableList(
                                                                                     Arrays.asList(ARG_TYPE, ARG_FILE, ARG_OUT));

    protected static final String TASK_NAME = "generatePQCKey";
    private final IFileUtility fileUtil;

    public GeneratePQCKeyTask(IFileUtility fileUtil, String scriptName) {
        super(scriptName);
        this.fileUtil = fileUtil;
    }

    @Override
    void checkRequiredArguments(String[] args) throws IllegalArgumentException {
        // Defaults are provided for minimal operator input
    }

    @Override
    public String getTaskDescription() {
        return getOption("generatepqckey.desc", true);
    }

    @Override
    public String getTaskHelp() {
        return getTaskHelp("generatepqckey.desc", "generatepqckey.usage.options",
                           "generatepqckey.required-key.", "generatepqckey.required-desc.",
                           "generatepqckey.option-key.", "generatepqckey.option-desc.",
                           null, null,
                           scriptName);
    }

    @Override
    public String getTaskName() {
        return TASK_NAME;
    }

    @Override
    public SecurityUtilityReturnCodes handleTask(ConsoleWrapper stdin, PrintStream stdout, PrintStream stderr, String[] args) throws Exception {
        CommandArguments parsedArgs = parseArgs(args, this.fileUtil);

        String type = parsedArgs.type != null ? parsedArgs.type.toUpperCase() : DEFAULT_TYPE;
        String outputPath = parsedArgs.outputPath;
        if (outputPath == null) {
            outputPath = (TYPE_ML_DSA.equals(type) ? "mldsa_key.pem" : "mlkem_key.pem");
        }

        File outFile = new File(outputPath);
        if (fileUtil.isDirectory(outFile)) {
            stderr.println(getMessage("invalidArg", outputPath));
            return SecurityUtilityReturnCodes.ERR_GENERIC;
        }

        try {
            if (TYPE_ML_DSA.equals(type) || type.startsWith("ML-DSA")) {
                AuditPQCKeyLoader.generateAndSaveMLDSA(outFile.getAbsolutePath());
                stdout.println("Successfully generated ML-DSA key pair: " + outFile.getAbsolutePath());
            } else if (TYPE_ML_KEM.equals(type) || type.startsWith("ML-KEM")) {
                AuditPQCKeyLoader.generateAndSave(outFile.getAbsolutePath());
                stdout.println("Successfully generated ML-KEM key pair: " + outFile.getAbsolutePath());
            } else {
                stderr.println("Unsupported key type: " + type + ". Supported types are ML-KEM and ML-DSA.");
                return SecurityUtilityReturnCodes.ERR_GENERIC;
            }
        } catch (Exception e) {
            stderr.println("Failed to generate PQC key pair: " + e.getMessage());
            return SecurityUtilityReturnCodes.ERR_GENERIC;
        }

        if (parsedArgs.configFile != null) {
            PQCConfigBuilder builder = new PQCConfigBuilder(type, outFile.getAbsolutePath(), parsedArgs.configFile, fileUtil);
            if (builder.generateXML()) {
                stdout.println("Successfully generated server configuration: " + new File(parsedArgs.configFile).getAbsolutePath());
            } else {
                return SecurityUtilityReturnCodes.ERR_GENERIC;
            }
        }

        return SecurityUtilityReturnCodes.OK;
    }

    @Override
    boolean isKnownArgument(String arg) {
        return arg != null && VALID_ARGUMENTS.contains(arg);
    }

    private CommandArguments parseArgs(String[] args, IFileUtility fileUtil) {
        String type = null;
        String configFile = null;
        String outputPath = null;

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                throw new IllegalArgumentException(getMessage("invalidArg", arg));
            }

            int index = arg.indexOf('=');
            String option;
            String value = null;
            if (index != -1) {
                option = arg.substring(0, index);
                value = (index + 1 < arg.length()) ? arg.substring(index + 1) : null;
            } else {
                option = arg;
            }

            if (!isKnownArgument(option)) {
                throw new IllegalArgumentException(getMessage("invalidArg", option));
            }

            if (ARG_TYPE.equals(option)) {
                if (value == null) {
                    throw new IllegalArgumentException(getMessage("missingValue", option));
                }
                type = value;
            } else if (ARG_FILE.equals(option)) {
                if (value == null) {
                    throw new IllegalArgumentException(getMessage("missingValue", option));
                }
                configFile = value;
            } else if (ARG_OUT.equals(option)) {
                if (value == null) {
                    throw new IllegalArgumentException(getMessage("missingValue", option));
                }
                outputPath = value;
            }
        }

        return new CommandArguments(type, configFile, outputPath);
    }

    private static class CommandArguments {
        final String type;
        final String configFile;
        final String outputPath;

        CommandArguments(String type, String configFile, String outputPath) {
            this.type = type;
            this.configFile = configFile;
            this.outputPath = outputPath;
        }
    }

    public static class PQCConfigBuilder {
        private final String type;
        private final String keyLocation;
        private final String configFile;
        private final IFileUtility fileUtil;

        public PQCConfigBuilder(String type, String keyLocation, String configFile, IFileUtility fileUtil) {
            this.type = type;
            this.keyLocation = keyLocation;
            this.configFile = configFile;
            this.fileUtil = fileUtil;
        }

        public boolean generateXML() throws Exception {
            StringBuilder xml = new StringBuilder();
            xml.append("<server>\n");
            xml.append("    <!-- Generated PQC Key Configuration -->\n");
            if (TYPE_ML_DSA.equalsIgnoreCase(type)) {
                xml.append("    <auditFileHandler id=\"defaultAuditHandler\" sign=\"true\" signingAlgorithm=\"ML-DSA-65\" signKeyStoreLocation=\"").append(keyLocation).append("\" />\n");
            } else {
                xml.append("    <auditFileHandler id=\"defaultAuditHandler\" encrypt=\"true\" encryptAlgorithm=\"AES-256\" kemAlgorithm=\"ML-KEM-768\" encryptKeyStoreLocation=\"").append(keyLocation).append("\" />\n");
            }
            xml.append("</server>\n");
            return fileUtil.writeToFile(null, xml.toString(), new File(configFile));
        }
    }
}
