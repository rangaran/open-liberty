/*******************************************************************************
 * Copyright (c) 2017, 2024 IBM Corporation and others.
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
package com.ibm.ws.jaxrs20.appsecurity.security;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ssl.Constants;
import com.ibm.websphere.ssl.JSSEHelper;
import com.ibm.websphere.ssl.SSLConfigurationNotAvailableException;
import com.ibm.websphere.ssl.SSLException;

public class JaxRsSSLManager {
    private static final TraceComponent tc = Tr.register(JaxRsSSLManager.class);

    private static final Map<String, SSLSocketFactory> socketFactories = new HashMap<>();
    private static final Map<String, SSLContext> sslContexts = new HashMap<>();
    private static final JSSEHelper jsseHelper = JSSEHelper.getInstance();

    /**
     * Get the SSLSocketFactory by sslRef, if could not get the configuration, try use the server's default
     * ssl configuration when fallbackOnDefault = true
     *
     * @param sslRef
     * @param host   - used to get the SSLSocketFactory from JSSEHelper
     * @param port   - used to get the SSLSocketFactory from JSSEHelper
     * @return
     */
    public static SSLSocketFactory getSSLSocketFactoryBySSLRef(String sslRef, String host, String port) {
        SSLSocketFactory sslSocketFactory = null;

        try {
            Map<String, Object> connectionInfo = getConnectionInfo(host, port);
            String cacheKey = getCacheKey(sslRef, host, port);
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "JaxRsSSLManager.getSSLSocketFactoryBySSLRef entry"
                             + ", inputSslRef=" + sslRef
                             + ", host=" + host
                             + ", port=" + port
                             + ", cacheKey=" + cacheKey
                             + ", connectionInfo=" + connectionInfo,
                         new Throwable("JaxRsSSLManager.getSSLSocketFactoryBySSLRef entry stack"));
            }

            SSLContext sslContext = getSSLContext(sslRef, connectionInfo);

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "JaxRsSSLManager.getSSLSocketFactoryBySSLRef after getSSLContext"
                             + ", inputSslRef=" + sslRef
                             + ", host=" + host
                             + ", port=" + port
                             + ", cacheKey=" + cacheKey
                             + ", sslContextIdentity=" + (sslContext == null ? "null" : Integer.toHexString(System.identityHashCode(sslContext)))
                             + ", sslContextClass=" + (sslContext == null ? "null" : sslContext.getClass().getName()));
            }

            if (sslContext == null) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "JaxRsSSLManager.getSSLSocketFactoryBySSLRef returning null because sslContext is null"
                                 + ", inputSslRef=" + sslRef
                                 + ", host=" + host
                                 + ", port=" + port
                                 + ", cacheKey=" + cacheKey);
                }
                return null;
            }

            boolean recache = false;
            synchronized (sslContexts) {
                SSLContext cachedSslContext = sslContexts.get(cacheKey);
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "JaxRsSSLManager.sslContexts lookup"
                                 + ", cacheKey=" + cacheKey
                                 + ", host=" + host
                                 + ", port=" + port
                                 + ", requestedSslContextIdentity=" + Integer.toHexString(System.identityHashCode(sslContext))
                                 + ", cachedSslContextIdentity=" + (cachedSslContext == null ? "null" : Integer.toHexString(System.identityHashCode(cachedSslContext)))
                                 + ", cacheHit=" + (cachedSslContext != null));
                }
                if (sslContext == null || !sslContext.equals(cachedSslContext)) {
                    // first request or SSL config has changed, re-cache the SSLContext and SSLSocketFactory
                    sslContexts.put(cacheKey, sslContext);
                    recache = true;
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "JaxRsSSLManager.sslContexts put"
                                     + ", cacheKey=" + cacheKey
                                     + ", host=" + host
                                     + ", port=" + port
                                     + ", storedSslContextIdentity=" + Integer.toHexString(System.identityHashCode(sslContext))
                                     + ", recache=true");
                    }
                }
            }

            synchronized (socketFactories) {
                sslSocketFactory = socketFactories.get(cacheKey);
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "JaxRsSSLManager.socketFactories lookup"
                                 + ", cacheKey=" + cacheKey
                                 + ", host=" + host
                                 + ", port=" + port
                                 + ", cachedSocketFactoryIdentity=" + (sslSocketFactory == null ? "null" : Integer.toHexString(System.identityHashCode(sslSocketFactory)))
                                 + ", cacheHit=" + (sslSocketFactory != null)
                                 + ", recache=" + recache);
                }
                if (sslSocketFactory == null || recache) {
                    sslSocketFactory = sslContext.getSocketFactory();
                    socketFactories.put(cacheKey, sslSocketFactory);
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "JaxRsSSLManager.socketFactories put"
                                     + ", cacheKey=" + cacheKey
                                     + ", host=" + host
                                     + ", port=" + port
                                     + ", storedSocketFactoryIdentity=" + Integer.toHexString(System.identityHashCode(sslSocketFactory))
                                     + ", sslContextIdentity=" + Integer.toHexString(System.identityHashCode(sslContext)));
                    }
                }
            }
        } catch (com.ibm.websphere.ssl.SSLException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "configClientSSL failed to get the SSLSocketFactory with exception: " + e.toString());
            }
            return null;
        }
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "JaxRsSSLManager.getSSLSocketFactoryBySSLRef return"
                         + ", inputSslRef=" + sslRef
                         + ", host=" + host
                         + ", port=" + port
                         + ", cacheKey=" + getCacheKey(sslRef, host, port)
                         + ", returnedSocketFactoryIdentity=" + (sslSocketFactory == null ? "null" : Integer.toHexString(System.identityHashCode(sslSocketFactory)))
                         + ", returnedSocketFactoryClass=" + (sslSocketFactory == null ? "null" : sslSocketFactory.getClass().getName()));
        }
        return sslSocketFactory;
    }

    private static String getCacheKey(String sslRef, String host, String port) {
        if (sslRef != null) {
            return sslRef;
        }
        return "dynamic:" + host + ":" + port;
    }

    private static Map<String, Object> getConnectionInfo(String host, String port) {
        Map<String, Object> connectionInfo = new HashMap<String, Object>();
        connectionInfo.put(Constants.CONNECTION_INFO_DIRECTION, Constants.DIRECTION_OUTBOUND);
        connectionInfo.put(Constants.CONNECTION_INFO_REMOTE_HOST, host);
        connectionInfo.put(Constants.CONNECTION_INFO_REMOTE_PORT, port); // String expected by OutboundSSLSelections
        return connectionInfo;
    }

    private static Properties getSSLProperties(String sslRef, Map<String, Object> connectionInfo) throws SSLException {
        Properties sslProps;
        try {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "JaxRsSSLManager.getSSLProperties before jsseHelper.getProperties"
                             + ", inputSslRef=" + sslRef
                             + ", connectionInfo=" + connectionInfo,
                         new Throwable("JaxRsSSLManager.getSSLProperties before stack"));
            }
            sslProps = AccessController.doPrivileged(new PrivilegedExceptionAction<Properties>() {
                @Override
                public Properties run() throws SSLException {
                    return jsseHelper.getProperties(sslRef, connectionInfo, null);
                }
            });

        } catch (PrivilegedActionException pae) {
            Throwable cause = pae.getCause();
            throw (SSLException) cause;
        }

        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "JaxRsSSLManager.getSSLProperties after jsseHelper.getProperties"
                         + ", inputSslRef=" + sslRef
                         + ", connectionInfo=" + connectionInfo
                         + ", resolvedAlias=" + (sslProps == null ? "null" : sslProps.getProperty(Constants.SSLPROP_ALIAS))
                         + ", resolvedTrustStore=" + (sslProps == null ? "null" : sslProps.getProperty(Constants.SSLPROP_TRUST_STORE))
                         + ", propertiesIdentity=" + (sslProps == null ? "null" : Integer.toHexString(System.identityHashCode(sslProps))),
                     new Throwable("JaxRsSSLManager.getSSLProperties after stack"));
        }

        return sslProps;
    }

    private static SSLContext getSSLContext(String sslRef, Map<String, Object> connectionInfo) throws SSLException {
        Boolean sslCfgExists = null;
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "JaxRsSSLManager.getSSLContext entry"
                         + ", inputSslRef=" + sslRef
                         + ", connectionInfo=" + connectionInfo,
                     new Throwable("JaxRsSSLManager.getSSLContext entry stack"));
        }
        if (sslRef != null) {
            try {
                sslCfgExists = AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                    @Override
                    public Boolean run() throws SSLException {
                        return Boolean.valueOf(jsseHelper.doesSSLConfigExist(sslRef));
                    }
                });

            } catch (PrivilegedActionException pae) {
                Throwable cause = pae.getCause();
                throw (SSLException) cause;
            }

            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "JaxRsSSLManager.getSSLContext explicit sslRef existence check"
                             + ", inputSslRef=" + sslRef
                             + ", sslCfgExists=" + sslCfgExists);
            }

            if (!sslCfgExists.booleanValue())
                return null;
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<SSLContext>() {
                @Override
                public SSLContext run() throws SSLConfigurationNotAvailableException, SSLException {
                    if (sslRef != null) {
                        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                            Tr.debug(tc, "JaxRsSSLManager.getSSLContext using explicit sslRef path"
                                         + ", inputSslRef=" + sslRef
                                         + ", connectionInfo=" + connectionInfo);
                        }
                        SSLContext sslContext = jsseHelper.getSSLContext(sslRef, connectionInfo, null, false);
                        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                            Tr.debug(tc, "JaxRsSSLManager.getSSLContext explicit sslRef path result"
                                         + ", inputSslRef=" + sslRef
                                         + ", sslContextIdentity=" + (sslContext == null ? "null" : Integer.toHexString(System.identityHashCode(sslContext)))
                                         + ", sslContextClass=" + (sslContext == null ? "null" : sslContext.getClass().getName()));
                        }
                        return sslContext;
                    } else {
                        // get the default ssl context with possible dynamic outbound mapping
                        Properties resolvedProps = getSSLProperties(sslRef, connectionInfo);
                        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                            Tr.debug(tc, "JaxRsSSLManager.getSSLContext dynamic path resolved properties"
                                         + ", inputSslRef=" + sslRef
                                         + ", connectionInfo=" + connectionInfo
                                         + ", resolvedAlias=" + (resolvedProps == null ? "null" : resolvedProps.getProperty(Constants.SSLPROP_ALIAS))
                                         + ", resolvedTrustStore=" + (resolvedProps == null ? "null" : resolvedProps.getProperty(Constants.SSLPROP_TRUST_STORE))
                                         + ", propertiesIdentity=" + (resolvedProps == null ? "null" : Integer.toHexString(System.identityHashCode(resolvedProps))));
                        }
                        SSLContext sslContext = jsseHelper.getSSLContext(connectionInfo, resolvedProps);
                        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                            Tr.debug(tc, "JaxRsSSLManager.getSSLContext dynamic path result"
                                         + ", inputSslRef=" + sslRef
                                         + ", connectionInfo=" + connectionInfo
                                         + ", resolvedAlias=" + (resolvedProps == null ? "null" : resolvedProps.getProperty(Constants.SSLPROP_ALIAS))
                                         + ", sslContextIdentity=" + (sslContext == null ? "null" : Integer.toHexString(System.identityHashCode(sslContext)))
                                         + ", sslContextClass=" + (sslContext == null ? "null" : sslContext.getClass().getName()));
                        }
                        return sslContext;
                    }
                }
            });
        } catch (PrivilegedActionException pae) {
            assert SSLException.class.isAssignableFrom(SSLConfigurationNotAvailableException.class);
            throw (SSLException) pae.getCause();
        }
    }
}
