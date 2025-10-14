package com.ibm.ws.security.utility.test;

/*
 * IBM Confidential
 *
 * OCO Source Materials
 *
 * Copyright IBM Corp. 2016, 2025
 *
 * The source code for this program is not published or other-
 * wise divested of its trade secrets, irrespective of what has
 * been deposited with the U.S. Copyright Office.
 */
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({
    SecurityUtilityEncodeTest.class,
    SecurityUtilityGenerateAesKeyTest.class,
    SecurityUtilityCreateSSLCertificateTest.class,
    SecurityUtilityCreateLTPAKeysTest.class
})
/**
 * Purpose: This suite collects and runs all known good test suites.
 */
public class FATSuite {

}