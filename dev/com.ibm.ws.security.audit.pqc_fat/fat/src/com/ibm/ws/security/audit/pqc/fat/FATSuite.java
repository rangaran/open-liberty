/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.audit.pqc.fat;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Collection of all PQC Audit FAT tests.
 * 
 * This suite runs comprehensive tests for Post-Quantum Cryptography (PQC)
 * support in Liberty Audit encryption, including:
 * - ML-KEM key generation and management
 * - PQC audit data encryption and decryption
 * - Hybrid mode (AES-256 + ML-KEM) operations
 * - Backward compatibility with classical audit encryption
 */
@RunWith(Suite.class)
@SuiteClasses({
    PQCAuditTests.class
})
public class FATSuite {
    // Test suite - no implementation needed
}

// Made with Bob
