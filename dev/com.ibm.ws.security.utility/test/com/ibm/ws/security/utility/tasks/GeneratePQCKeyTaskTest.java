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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.util.Base64;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.ibm.ws.security.utility.IFileUtility;
import com.ibm.ws.security.utility.SecurityUtilityReturnCodes;
import com.ibm.ws.security.utility.utils.ConsoleWrapper;

public class GeneratePQCKeyTaskTest {

    private final Mockery mockContext = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };

    private IFileUtility fileUtil;
    private ConsoleWrapper stdin;
    private PrintStream stdout;
    private PrintStream stderr;
    private ByteArrayOutputStream stdoutBytes;
    private ByteArrayOutputStream stderrBytes;

    private GeneratePQCKeyTask task;

    @Before
    public void setUp() {
        fileUtil = mockContext.mock(IFileUtility.class);
        stdin = mockContext.mock(ConsoleWrapper.class);

        stdoutBytes = new ByteArrayOutputStream();
        stderrBytes = new ByteArrayOutputStream();
        stdout = new PrintStream(stdoutBytes);
        stderr = new PrintStream(stderrBytes);

        task = new GeneratePQCKeyTask(fileUtil, "securityUtility");
    }

    @After
    public void tearDown() {
        stdoutBytes = null;
        stderrBytes = null;
    }

    @Test
    public void testTaskName() {
        assertEquals("generatePQCKey", task.getTaskName());
    }

    @Test
    public void testTaskDescription() {
        assertNotNull(task.getTaskDescription());
    }

    @Test
    public void testIsKnownArgument() {
        assertTrue(task.isKnownArgument("--type"));
        assertTrue(task.isKnownArgument("--out"));
        assertTrue(task.isKnownArgument("--createConfigFile"));
    }
}
