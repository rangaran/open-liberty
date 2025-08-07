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
package com.ibm.ws.springboot.support.fat;

import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import componenttest.annotation.MinimumJavaLevel;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.rules.repeater.RepeatTests;

@RunWith(FATRunner.class)
@MinimumJavaLevel(javaLevel = 17)
public class CommonWebServerTests40 extends CommonWebServerTests {

    @ClassRule
    public static RepeatTests r = FATSuite.defaultRepeat(SERVER_NAME);

    @After
    public void stopTestServer() throws Exception {
        String methodName = testName.getMethodName();
        if ((methodName != null) && methodName.contains(DEFAULT_HOST_WITH_APP_PORT)) {
            super.stopServer(true, "CWWKT0015W");
        } else {
            super.stopServer();
        }
    }

    @Override
    public String getApplication() {
        return SPRING_BOOT_40_APP_BASE;
    }

    @Test
    public void testBasicSpringBootApplication40() throws Exception {
        testBasicSpringBootApplication();
    }

    @Test
    public void testDefaultHostWithAppPort() throws Exception {
        // A variation of 'testBasicSpringBootApplication40'.
        // The different behavior is triggered by the test name.
        testBasicSpringBootApplication();
    }
}
