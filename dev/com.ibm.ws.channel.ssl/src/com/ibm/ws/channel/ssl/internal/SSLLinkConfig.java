/*******************************************************************************
 * Copyright (c) 2004, 2026 IBM Corporation and others.
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
package com.ibm.ws.channel.ssl.internal;

import java.util.Properties;

import javax.net.ssl.SSLEngine;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ssl.Constants;
import com.ibm.websphere.ssl.Constants;
import com.ibm.ws.kernel.productinfo.ProductInfo;

/**
 * Configuration used on the individual SSL connections. This may or may not
 * match the owning channel configuration as the configuration can come from
 * that, from a repertoire, or even from on-thread programmatic properties.
 */
public class SSLLinkConfig {

    /** Trace component for WAS */
    private static final TraceComponent tc = Tr.register(SSLLinkConfig.class,
                                                         SSLChannelConstants.SSL_TRACE_NAME,
                                                         SSLChannelConstants.SSL_BUNDLE);

    /** Configuration reference */
    private Properties myConfig = null;

    /**
     * Constructor.
     *
     * @param config
     */
    public SSLLinkConfig(Properties config) {
        this.myConfig = config;
    }

    /**
     * Access a boolean property.
     *
     * @param key
     * @return boolean - false if the property does not exist
     */
    public boolean getBooleanProperty(String key) {
        return "true".equalsIgnoreCase(this.myConfig.getProperty(key));
    }

    /**
     * Access a property.
     *
     * @param key
     * @return String
     */
    public String getProperty(String key) {
        return this.myConfig.getProperty(key);
    }

    /**
     * Access the set of properties.
     *
     * @return Properties
     */
    public Properties getProperties() {
        return this.myConfig;
    }

    /**
     * Query the list of enabled cipher suites for this connection.
     *
     * @param sslEngine
     * @return String[]
     */
   public String[] getEnabledCipherSuites(SSLEngine sslEngine) {

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "getEnabledCipherSuites");
        }

        Object ciphersObject = this.myConfig.get(Constants.SSLPROP_ENABLED_CIPHERS);
        String cipherString = null;
        String[] ciphers = null;

        // Normalize input to string
        if (ciphersObject instanceof String) {
            cipherString = (String) ciphersObject;
        } else if (ciphersObject instanceof String[]) {
            cipherString = String.join(" ", (String[]) ciphersObject);
        }

        if (ProductInfo.getBetaEdition()) {
            // Beta: always go through adjustSupportedCiphers
            ciphers = Constants.adjustSupportedCiphers(
                sslEngine.getSupportedCipherSuites(),
                cipherString
            );
        } else {
            if (cipherString != null) {
                // Non-beta: user provided value
                ciphers = cipherString.split("[,\\s]+");
            } else {
                // No custom ciphers - fallback to security level
                String securityLevel = this.myConfig.getProperty(Constants.SSLPROP_SECURITY_LEVEL);
                if (securityLevel == null) {
                    Tr.debug(tc, "Defaulting to HIGH security level");
                    securityLevel = Constants.SECURITY_LEVEL_HIGH;
                }

                ciphers = Constants.adjustSupportedCiphersToSecurityLevel(
                    sslEngine.getSupportedCipherSuites(),
                    securityLevel
                );
            }
        }

        if (ciphers == null || ciphers.length == 0) {

            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(tc, "Unable to find any enabled ciphers");
            }
        }

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "getEnabledCipherSuites");
        }
        
        return ciphers;
    }
    /**
     * Get the SSL protocol for this connection and check to see it correct for setting on a SSLEngine
     * and put the protocol in the correct format.
     *
     * @return String
     */
    public String[] getSSLProtocol() {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "getSSLProtocol");
        }

        // get the configured protocol
        String protocol = (String) this.myConfig.get(Constants.SSLPROP_PROTOCOL);

        // protocol(s) need to be in an array
        String[] protocols = protocol.split(",");

        // we only want to set the protocol on the engine if it a specific protocol name
        // don't set to TLS or SSL
        if (protocols.length == 1) {
            if (protocols[0].equals(Constants.PROTOCOL_TLS) || protocols[0].equals(Constants.PROTOCOL_SSL)) {
                protocols = null;
            }
        }

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "getSSLProtocol " + protocols);
        }
        return protocols;
    }

}
