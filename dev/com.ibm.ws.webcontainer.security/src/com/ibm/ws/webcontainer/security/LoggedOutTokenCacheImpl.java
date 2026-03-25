/*******************************************************************************
 * Copyright (c) 2014, 2026 IBM Corporation and others.
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
package com.ibm.ws.webcontainer.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Properties;

import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.ws.webcontainer.security.internal.StringUtil;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;

import com.ibm.websphere.cache.DistributedMap;
import com.ibm.websphere.cache.EntryInfo;
import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Trivial;
import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.websphere.security.auth.TokenExpiredException;
import com.ibm.ws.common.encoder.Base64Coder;
import com.ibm.ws.security.jaas.common.callback.AuthenticationHelper;
import com.ibm.ws.security.token.TokenManager;
import com.ibm.wsspi.cache.DistributedObjectCacheFactory;
import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;
import com.ibm.wsspi.security.ltpa.Token;

/**
 * Methods to create, add, and get logged out tokens from the LoggedOutTokenMap DistributedMap
 */
public class LoggedOutTokenCacheImpl implements LoggedOutTokenCache {
    private static final TraceComponent tc = Tr.register(LoggedOutTokenCacheImpl.class);

    private static final AtomicServiceReference<TokenManager> tokenManager = new AtomicServiceReference<TokenManager>("tokenManager");
    
    private static MessageDigest messageDigest = null;

    private static final String LOGOUT_KEY_PREFIX = "LOGOUT:";

    private final InMemoryLoggedOutTokenCache inMemoryCookieCache = new InMemoryLoggedOutTokenCache();

    protected void setTokenManager(ServiceReference<TokenManager> ref) {
        tokenManager.setReference(ref);
    }

    protected void unsetTokenManager(ServiceReference<TokenManager> ref) {
        tokenManager.setReference(ref);
    }

    protected void activate(ComponentContext cc, Map<String, Object> properties) {
        tokenManager.activate(cc);
    }

    protected void deactivate(ComponentContext cc) {
        tokenManager.deactivate(cc);
    }

    static final class Singleton {
        private static final LoggedOutTokenCache instance = new LoggedOutTokenCacheImpl();
    }

    @Trivial
    public static LoggedOutTokenCache getInstance() {
        return Singleton.instance;
    }

    @Override
    public boolean contains(Object key) {
        String keyStr = (String) key;

        LoggedOutCookieCache jCacheCookieCache = LoggedOutCookieCacheHelper.getLoggedOutCookieCacheService();
        String hashedKeyStr = generateTokenHashKey(keyStr);
        if (jCacheCookieCache != null) {
            return jCacheCookieCache.contains(hashedKeyStr);
        } else {
            return inMemoryCookieCache.contains(hashedKeyStr);
        }
    }

    @Override
    public void put(Object key, Object value) {
        String keyStr = (String) key;

        /*
         * Determine if the token is still valid. If it is not, don't cache it.
         */
        TokenManager tm = LoggedOutTokenCacheImpl.tokenManager.getService();
        int timeOut = -1;
        try {
            byte[] tokenBytes = AuthenticationHelper.copyCredToken(Base64Coder.base64DecodeString(keyStr));
            Token token = tm.recreateTokenFromBytes(tokenBytes);
            if (token != null) {
                long tokenExp = token.getExpiration();
                long calcTimeOut = tokenExp - System.currentTimeMillis();
                timeOut = (int) calcTimeOut / 1000;
                String userName = token.getAttributes("u")[0];
                if (userName != null)
                    value = userName;
            }

        } catch (InvalidTokenException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Token is not valid so do not cache it " + e.getMessage());
            }
            return;
        } catch (TokenExpiredException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Token is expired so do not cache it " + e.getMessage());
            }
            return;
        }

        /*
         * Choose between using the in-memory logged out cookie cache, or the JCache logged out cookie cache.
         */
        LoggedOutCookieCache jCacheCookieCache = LoggedOutCookieCacheHelper.getLoggedOutCookieCacheService();
        String hashedKeyStr = generateTokenHashKey(keyStr);
        if (jCacheCookieCache != null) {
            jCacheCookieCache.put(hashedKeyStr, value);
        } else {
            inMemoryCookieCache.put(hashedKeyStr, value, timeOut);
        }
    }

    @Override
    public boolean shouldTrackTokens() {
        /*
         * Indicate we should always track tokens if LoggedOutCookieCacheService is available.
         */
        return LoggedOutCookieCacheHelper.getLoggedOutCookieCacheService() != null;
    }

    /**
     * Generate a hash key from the token bytes for cache storage.
     *
     * @param tokenString The LTPA token bytes
     * @return Hash string with LOGOUT: prefix, or null if error
     */
    private String generateTokenHashKey(String tokenString) {
        if (tc.isEntryEnabled()) Tr.entry(tc, "generateTokenHashKey()", tokenString);

        if (tokenString == null || tokenString.isEmpty()) {
            if (tc.isEntryEnabled()) Tr.exit(tc, "generateTokenHashKey()", "null or empty token");
            return null;
        }

        if (messageDigest == null) {
            try {
                messageDigest = CryptoUtils.getMessageDigest();
            } catch (NoSuchAlgorithmException e) {

            }
        }

        String hashKey = null;
        if (messageDigest != null) {
            messageDigest.reset();
            messageDigest.update(StringUtil.getBytes(tokenString));
            byte[] hash = messageDigest.digest();

            hashKey = LOGOUT_KEY_PREFIX + Base64Coder.base64Encode(StringUtil.toString(hash));
        } else {
            if (tc.isDebugEnabled()) Tr.debug(tc, "MessageDigest unavailable; token hash cannot be generated. Logout tracking is disabled.");
        }

        if (tc.isEntryEnabled()) Tr.exit(tc, "generateTokenHashKey()", hashKey);
        return hashKey;
    }

    /**
     * In-memory cache to store logged out tokens.
     */
    private class InMemoryLoggedOutTokenCache {
        private DistributedMap dmns = null;

        /*
         * Look up the key from the DistributedMap if it exists
         */
        public boolean contains(Object key) {
            //check to see if the token is in the distributed map
            if (dmns != null) {
                return dmns.containsKey(key);
            }

            // if dmns does not exist there are no entries in the DistributedMap
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "The LoggedOutTokenMap DistributedMap does not exist.");
            }
            return false;
        }

        /*
         * Add the token to the DistributedMap
         *
         * key is the token string
         * value is the subject
         * timeToLive is the about of time left before the token expires, to become the expiring time of the distributed map entry
         */
        public Object put(Object key, Object value, int timeToLive) {

            DistributedMap map = getDMLoggedOutTokenMap();

            if (map != null) {
                Object dist_object = map.put(key, value, 1, timeToLive, EntryInfo.SHARED_PUSH, null);
                return dist_object;
            }
            return null;
        }

        /*
         * Get the LoggedOutTokenMap
         */
        private DistributedMap getDMLoggedOutTokenMap() {

            if (dmns == null) {
                dmns = getDistributedMap("LoggedOutTokenMap");
            }

            return dmns;

        }

        /*
         * Creates the LoggedOutTokeMap if it does not exist.
         */
        private DistributedMap getDistributedMap(String mapName) {
            DistributedMap dm = null;

            dm = DistributedObjectCacheFactory.getMap(mapName, new Properties());

            return dm;
        }
    }
}
