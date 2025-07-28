/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
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

package componenttest.rules;

import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Assume;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.ssl.JSSEProviderFactory;

public class SkipKeymanagerFactoryPKIXEnabled implements TestRule {

    // All tests that must be skipped with this rule must be annotated with the following tag
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.METHOD, ElementType.TYPE })
    public @interface SkipKeymanagerFactoryPKIXEnabledRule {}

    @Override
    public Statement apply(Statement statement, Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                AtomicBoolean isPkixEnabled = new AtomicBoolean(JSSEProviderFactory.getKeyManagerFactoryAlgorithm().equalsIgnoreCase("PKIX"));
                if (description.getAnnotation(SkipKeymanagerFactoryPKIXEnabledRule.class) != null) {
                    if (isPkixEnabled.get()) {
                         Log.info(description.getTestClass(), description.getMethodName(),
                                    "Test class or method is skipped because environment is ssl.KeyManagerFactory PKIX");
                        ;
                        Assume.assumeTrue(false);
                    } else {
                       Log.info(description.getTestClass(), description.getMethodName(),
                                    "Running test case: " + isPkixEnabled.get());
                       statement.evaluate();
                    }
                } else{
                    statement.evaluate();
                }
            }
        };
    }
}