/*******************************************************************************
 * Copyright (c) 2025, 2025 IBM Corporation and others.
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
package componenttest.rules.repeater;

import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.Map.Entry;
import java.util.Map;
import java.util.HashMap;
import java.security.Security;
import java.util.Properties;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

import com.ibm.websphere.simplicity.log.Log;
import componenttest.common.apiservices.Bootstrap;
import com.ibm.ws.ssl.JSSEProviderFactory;
import componenttest.topology.utils.FileUtils;
import componenttest.topology.impl.LibertyClientFactory;
import componenttest.topology.impl.LibertyServerFactory;

public class KeyManagerFactoryReplacementAction implements RepeatTestAction {
    private static final Class<?> c = KeyManagerFactoryReplacementAction.class;
    private String currentID = null;
    private final Set<File> optionFilesCreated = new HashSet<File>();
    private final Map<File, File> optionsFileBackupMapping = new HashMap<File, File>();
    private static final String pathToAutoFVTTestServers = "publish/servers/";
    private static final String pathToAutoFVTTestClients = "publish/clients/";

    public KeyManagerFactoryReplacementAction() {
    }

    public static KeyManagerFactoryReplacementAction setPKIX() {
        return new SetPKIXKeyManagerFactory();
    }

    @Override
    /**
     * Used to identify the RepeatTestAction and used in conjunction
     * with @SkipForRepat
     */
    public String getID() {
        if (currentID != null) {
            return currentID;
        }
        return "KEY_MANAGER_FACTORY";
    }

    @Override
    /**
     * Invoked by the FAT framework to test if the PKIX should be set or not.
     */
    public boolean isEnabled() {
        if (isPKIXEnabledInConfig()) {
            Log.info(c, "isEnabled", "PKIX KeyManager Factory will be used in the test");
            return true;
        }
        Log.info(c, "isEnabled", "Will not set PKIX KeyManager Factory algorithm");
        return false;
    }

    @Override
    public void setup() throws Exception {
        Log.info(c, "setup", "setting up pkix");
        setJvmOptions("PKIX");
        Properties envVars = new Properties();
        String JVM_ARGS = "-Djava.security.properties=" + getkeymanagerFactoryPKIX();
        envVars.setProperty("JVM_ARGS", JVM_ARGS);
    }

    @Override
    /**
     * Invoked by the FAT framework to perform cleanup steps before ending test
     * repetition.
     * If clean up is needed to undo the setup changes after running the action then
     * override this method.
     */
    public void cleanup() {
        if (optionsFileBackupMapping.isEmpty()) // Nothing to clean up
            return;
        // Undo changes done to jvm.options
        for (Entry<File, File> mapping : optionsFileBackupMapping.entrySet()) {
            File original = mapping.getKey();
            File backup = mapping.getValue();
            Log.info(c, "cleanup", "Restoring " + original + " from " + backup);
            try {
                FileUtils.recursiveDelete(original);
                FileUtils.copyDirectory(backup, original);
            } catch (Exception e) {
                throw new RuntimeException("Exception restoring backup for file " + original, e);
            }
        }
        optionsFileBackupMapping.clear();
        // Clean up backup folder
        Path backupsDir = Paths.get("publish/backups");
        try {
            Log.info(c, "cleanup", "Deleting backups directory.");
            FileUtils.recursiveDelete(backupsDir.toFile());
        } catch (IOException e) {
            Log.error(c, "Problems deleting backup directory", e);
        }
    }

    public KeyManagerFactoryReplacementAction withID(String id) {
        currentID = id;
        return this;
    }

    protected static boolean isPKIXEnabledInConfig() {
        return Security.getProperty("ssl.KeyManagerFactory.algorithm") == "PKIX";
    }

    protected static boolean isSunX509EnabledInConfig() {
        return Security.getProperty("ssl.KeyManagerFactory.algorithm") == "SunX509";
    }

    private String getkeymanagerFactoryPKIX() throws Exception {
        Properties localProperties = getLocalProperties();
        String basedir = localProperties.getProperty("basedir");
        String location = basedir + "/keymanagerFactoryPKIX.properties";

        byte[] fileContents = Files.readAllBytes(Paths.get(location));
        Log.info(c, "getkeymanagerFactoryPKIX",
                "keymanagerFactoryPKIX.properties contents:\n"
                        + new String(fileContents, StandardCharsets.UTF_8));

        return location;
    }

    public Properties getLocalProperties() throws Exception {
        String localPropertiesLocation = System.getProperty("local.properties");
        Properties localProperties = new Properties();
        FileInputStream in = new FileInputStream(localPropertiesLocation);
        localProperties.load(in);
        in.close();
        return localProperties;
    }

    /*
     * /
     **
     * Goes through all the servers and clients setting the specified JVM options
     */
    private void setJvmOptions(String provider) throws IOException {
        final String m = "setJvmOptions";

        Path publishDir = Paths.get("publish");
        Path backupsDir = Paths.get("publish/backups");

        Set<File> serverOptions = new HashSet<>();
        Set<File> locationsChecked = new HashSet<>(); // Directories we checked for client/server options files.
        Set<String> servers = new HashSet<>(); // All Servers found
        Log.info(c, m, "Checking all servers for jvm.options files");
        File serverFolder = new File(pathToAutoFVTTestServers);

        // Find all of the server jvm.options to add options
        if (serverFolder.exists()) {
            for (File f : serverFolder.listFiles()) {
                if (f.isDirectory()) {
                    servers.add(f.getName());
                }
            }
        }
        locationsChecked.add(serverFolder);

        // Go through all the servers
        for (String serverName : servers) {
            Set<File> optionsFound = findFile(new File(pathToAutoFVTTestServers + serverName), "jvm.options");
            // If options file doesn't exist
            if (optionsFound.isEmpty()) {
                // Create it
                File jvmOptionsCreated = new File(pathToAutoFVTTestServers + serverName + "/jvm.options");
                if (jvmOptionsCreated.createNewFile()) {
                    Log.info(c, m, "Successfully created jvm.options in: " + serverName);
                    optionFilesCreated.add(jvmOptionsCreated);
                } else
                    Log.info(c, m, "Failed to create jvm.options in: " + serverName);
                optionsFound.add(jvmOptionsCreated);
            }
            serverOptions.addAll(optionsFound);
        }

        Set<File> clientOptions = new HashSet<>();
        Set<String> clients = new HashSet<>(); // All clients found
        File clientFolder = new File(pathToAutoFVTTestClients);
        // Find all jvm.options in the clients
        clientOptions.addAll(findFile(clientFolder, "jvm.options"));
        if (clientFolder.exists()) {
            for (File f : clientFolder.listFiles()) {
                if (f.isDirectory()) {
                    clients.add(f.getName());
                }
            }
        }

        // Go through all the clients
        for (String clientName : clients) {
            Set<File> optionsFound = findFile(new File(pathToAutoFVTTestClients + clientName), "jvm.options");
            // If options file doesn't exist
            if (optionsFound.isEmpty()) {
                // Create it
                File jvmOptionsCreated = new File(pathToAutoFVTTestClients + clientName + "/jvm.options");
                if (jvmOptionsCreated.createNewFile()) {
                    Log.info(c, m, "Successfully created jvm.options in: " + clientName);
                    optionFilesCreated.add(jvmOptionsCreated);
                } else
                    Log.info(c, m, "Failed to create jvm.options in: " + clientName);
                optionsFound.add(jvmOptionsCreated);
            }
            clientOptions.addAll(optionsFound);
        }
        locationsChecked.add(clientFolder);

        Log.info(c, m, "Adding options in files: " + serverOptions.toString() + "  and  " + clientOptions.toString());

        // change all the jvm.options files
        assertTrue("There were no servers/clients found in the following folders."
                + ". To use a BetaOptionsAction, there must be 1 or more servers/clients in any of the following locations: "
                + locationsChecked,
                (serverOptions.size() > 0 || clientOptions.size() > 0));

        Set<File> optionFilesOriginal = new HashSet<>();
        optionFilesOriginal.addAll(clientOptions);
        optionFilesOriginal.addAll(serverOptions);
        for (File optionsFile : optionFilesOriginal) {
            Log.info(c, m, "Modifying options file: " + optionsFile.getAbsolutePath());
            if (!optionsFile.exists() || !optionsFile.canRead() || !optionsFile.canWrite()) {
                Log.info(c, m, "File did not exist or was not readable: " + optionsFile.getAbsolutePath());
                continue;
            }

            try (FileWriter optionsWriter = new FileWriter(optionsFile, true);
                    BufferedWriter bw = new BufferedWriter(optionsWriter);) {
                Path backupFile = backupsDir.resolve(publishDir.relativize(optionsFile.toPath()));
                Files.createDirectories(backupFile.getParent());
                FileUtils.copyDirectory(optionsFile, backupFile.toFile());
                optionsFileBackupMapping.put(optionsFile, backupFile.toFile());

                // Add new line if file already has content
                if (optionsFile.length() != 0)
                    bw.newLine();

                bw.write("-Dssl.KeyManagerFactory.algorithm=" + provider);
                bw.newLine();
            }
        }
        // Make sure options updates are pushed to the liberty install's copy of the
        // servers & clients
        for (String serverName : servers)
            LibertyServerFactory.getLibertyServer(serverName);
        for (String clientName : clients)
            LibertyClientFactory.getLibertyClient(clientName);
    }

    private static Set<File> findFile(File dir, String suffix) {
        HashSet<File> set = new HashSet<File>();
        File[] list = dir.listFiles();
        if (list != null) {
            for (File file : list) {
                if (file.isDirectory()) {
                    set.addAll(findFile(file, suffix));
                } else if (file.getName().endsWith(suffix)) {
                    set.add(file);
                }
            }
        }
        return set;
    }

}
