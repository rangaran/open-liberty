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
package componenttest.topology.database.container;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.utility.DockerImageName;

import com.ibm.websphere.simplicity.log.Log;

/**
 * This is a H2 database test container that is returned
 * when attempting to test against H2.
 *
 * This test container overrides the start and stop methods
 * to prevent the creation of a docker container.
 *
 */
public class H2Container extends JdbcDatabaseContainer<H2Container> {

    //Logging Constants
    private static final Class<H2Container> c = H2Container.class;

    //Embedding constants
    private static final Path IN_FILE_PATH = Paths.get("results", "h2", "test").toAbsolutePath().normalize();
    private static final String IN_MEMORY = "mem:test";
    private static final String IN_FILE = "file:" + IN_FILE_PATH.toString();

    //Counter
    private static final AtomicInteger counter = new AtomicInteger();

    //Default auth data - what we expect is in server.xml
    private static final String USER = "dbuser1";
    private static final String PASS = "{xor}Oz0vKDtu";

    // Configurations
    private final Map<String, String> users = new HashMap<>();
    private final List<String> options = new ArrayList<>();

    public H2Container(DockerImageName image) {
        // Calling super constructor like this since super("") doesn't compile with
        // Java 25 due to stricter annotation checking rules
        super(DockerImageName.parse(""));
    }

    public H2Container(String image) {
        // Calling super constructor like this since super("") doesn't compile with
        // Java 25 due to stricter annotation checking rules
        super(DockerImageName.parse(""));
    }

    public H2Container() {
        // Calling super constructor like this since super("") doesn't compile with
        // Java 25 due to stricter annotation checking rules
        super(DockerImageName.parse(""));
    }

    /**
     * When the H2 container "starts" it will execute create user queries to add these
     * users to the database and allow them to connect.
     *
     * @param  username
     * @param  password
     * @return          this
     */
    public H2Container withUser(String username, String password) {
        users.put(username, password);
        return this;
    }

    /**
     * Add options to append to the URL, for example to enable tracing add option:
     * TRACE_LEVEL_SYSTEM_OUT=3
     *
     * @param  option
     * @return        this
     */
    public H2Container withOption(String option) {
        options.add(option);
        return this;
    }

    @Override
    public String getDockerImageName() {
        return "";
    }

    @Override
    public void start() {
        if (users.size() == 0) {
            return;
        }

        // If we want to test against multiple users then we'll need to use
        // a file-based embedded database so that users can be created by the client
        // jvm and be available to the server jvm.

        Log.info(c, "start", "Adding the following users to the database " + users);
        Log.info(c, "start", "Using the admin auth data " + this.getUsername() + ":" + this.getPassword());

        Properties properties = new Properties();
        properties.put("user", getUsername());
        properties.put("password", "dbpwd1");
        Driver driver = getJdbcDriverInstance();

        try (Connection con = driver.connect(getJdbcUrl(), properties); //
                        Statement stmt = con.createStatement()) {
            for (Map.Entry<String, String> e : users.entrySet()) {
                stmt.executeUpdate("create user if not exists " + e.getKey() + " password '" + e.getValue() + "' admin;");
            }
        } catch (SQLException e) {
            throw new RuntimeException("Could not create new users", e);
        }
    }

    @Override
    protected void doStart() {
        //DO NOTHING
    }

    @Override
    public void stop() {
        if (users.size() == 0) {
            return;
        }

        // If a file-based embedded database was used during the start()
        // method, then we need to clean it up in the stop() method
        // so the database is gone when executing repeats.

        Path currentDir = IN_FILE_PATH.getParent();
        Path backupDir = currentDir.resolve("backup" + counter.getAndIncrement());

        Log.info(c, "stop", "Backing up database from " + currentDir + " to " + backupDir);

        try {
            Files.createDirectories(backupDir);
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(currentDir)) {
                for (Path file : stream) {
                    Path targetFile = backupDir.resolve(file.getFileName());
                    Files.move(file, targetFile, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        } catch (IOException e) {
            Log.info(c, "stop", "Failed to move files:" + e.getMessage());
        }

    }

    @Override
    public void close() {
        //DO NOTHING
    }

    @Override
    public String getJdbcUrl() {
        // Shared options between in memory and in file embedded modes
        String opts = options.size() > 0 ? ";" + String.join(";", options) : "";

        // If we need to add shared users then do so in file so that both the client
        // and server can share the same h2 database.
        return users.size() == 0 ? //
                        "jdbc:h2:" + IN_MEMORY + ";DB_CLOSE_DELAY=-1" + opts : // use in-memory mode
                        "jdbc:h2:" + IN_FILE + ";AUTO_SERVER=TRUE" + opts; // use automatic mixed mode
    }

    @Override
    public String getUsername() {
        return USER;
    }

    @Override
    public String getPassword() {
        return PASS;
    }

    @Override
    public Integer getFirstMappedPort() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getHost() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getDriverClassName() {
        return "org.h2.Driver";
    }

    @Override
    protected String getTestQueryString() {
        return "SELECT 1";
    }
}
