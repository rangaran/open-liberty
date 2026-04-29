/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.jsp23.fat.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.logging.Logger;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.ShrinkHelper;
import com.ibm.ws.jsp23.fat.JSPUtils;
import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;

import componenttest.annotation.Server;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.topology.impl.LibertyServer;

/**
 * Test to verify that tag files packaged in a JAR under WEB-INF/lib
 * can be loaded from META-INF/resources/WEB-INF/tags/
 * 
 * This test addresses the bug where Liberty fails to load tag files from JARs,
 * throwing error: JSPG0046E: Unable to locate tagfile
 * 
 * The test verifies that tag files in a JAR are properly discovered and used
 * by JSP pages, matching the behavior of Apache Tomcat.
 */
@RunWith(FATRunner.class)
public class JSPTagFilesInJarTest {
    private static final Logger LOG = Logger.getLogger(JSPTagFilesInJarTest.class.getName());
    private static final String APP_NAME = "TestTagFilesInJar";

    @Server("tagFilesInJarServer")
    public static LibertyServer server;

    @BeforeClass
    public static void setup() throws Exception {
        // Create a JAR with tag files in META-INF/resources/WEB-INF/tags/
        JavaArchive tagLibJar = ShrinkWrap.create(JavaArchive.class, "test-taglib.jar")
                        .addAsResource(new File("test-applications/TestTagFilesInJar.war/test-taglib/META-INF/resources/WEB-INF/tags/myTag.tag"),
                                       "META-INF/resources/WEB-INF/tags/myTag.tag")
                        .addAsResource(new File("test-applications/TestTagFilesInJar.war/test-taglib/META-INF/resources/WEB-INF/tags/anotherTag.tag"),
                                       "META-INF/resources/WEB-INF/tags/anotherTag.tag");

        // Create the WAR and add the JAR to WEB-INF/lib
        WebArchive app = ShrinkWrap.create(WebArchive.class, APP_NAME + ".war")
                        .addAsWebInfResource(new File("test-applications/TestTagFilesInJar.war/resources/WEB-INF/web.xml"))
                        .addAsWebResource(new File("test-applications/TestTagFilesInJar.war/resources/tag-test.jsp"))
                        .addAsWebResource(new File("test-applications/TestTagFilesInJar.war/resources/multiple-tags-test.jsp"))
                        .addAsLibrary(tagLibJar);

        ShrinkHelper.exportDropinAppToServer(server, app);

        server.startServer(JSPTagFilesInJarTest.class.getSimpleName() + ".log");
    }

    @AfterClass
    public static void testCleanup() throws Exception {
        if (server != null && server.isStarted()) {
            server.stopServer();
        }
    }

    /**
     * Test that a JSP can successfully use a tag file packaged in a JAR
     * located in WEB-INF/lib with the tag file at META-INF/resources/WEB-INF/tags/
     * 
     * @throws Exception if the test fails
     */
    @Test
    public void testTagFileFromJar() throws Exception {
        WebConversation wc = new WebConversation();
        wc.setExceptionsThrownOnErrorStatus(false);

        String url = JSPUtils.createHttpUrlString(server, APP_NAME, "tag-test.jsp");
        LOG.info("url: " + url);

        WebRequest request = new GetMethodWebRequest(url);
        WebResponse response = wc.getResponse(request);
        LOG.info("JSP response: " + response.getText());

        assertEquals("Expected 200 status code was not returned!",
                     200, response.getResponseCode());
        
        // Verify the tag was successfully invoked and rendered
        assertTrue("The response did not contain expected output from tag file",
                   response.getText().contains("Hello from myTag!"));
        assertTrue("The response did not contain the message parameter",
                   response.getText().contains("Test message from JSP"));
    }

    /**
     * Test that a JSP can use multiple tag files from the same JAR
     * 
     * @throws Exception if the test fails
     */
    @Test
    public void testMultipleTagFilesFromJar() throws Exception {
        WebConversation wc = new WebConversation();
        wc.setExceptionsThrownOnErrorStatus(false);

        String url = JSPUtils.createHttpUrlString(server, APP_NAME, "multiple-tags-test.jsp");
        LOG.info("url: " + url);

        WebRequest request = new GetMethodWebRequest(url);
        WebResponse response = wc.getResponse(request);
        LOG.info("JSP response: " + response.getText());

        assertEquals("Expected 200 status code was not returned!",
                     200, response.getResponseCode());
        
        // Verify both tags were successfully invoked
        assertTrue("The response did not contain output from myTag",
                   response.getText().contains("Hello from myTag!"));
        assertTrue("The response did not contain output from anotherTag",
                   response.getText().contains("Another tag output"));
    }
}
