/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.microprofile.health.file.healthcheck.endpoints.fat.utils;

import java.io.File;

import com.ibm.websphere.simplicity.log.Log;

/**
 *
 */
public class HealthFileUtils {
    private static void log(String method, String msg) {
        Log.info(HealthFileUtils.class, method, msg);
    }

    public static File getHealthDirFile(File serverRootDirFile) {

        File healthDirFile = new File(serverRootDirFile, "health");

        return healthDirFile;
    }

    public static File getStartFile(File serverRootDirFile) {

        File startedFile = new File(getHealthDirFile(serverRootDirFile), HealthCheckFileName.STARTED_FILE.getFileName());

        return startedFile;
    }

    public static File getReadyFile(File serverRootDirFile) {

        File readyFile = new File(getHealthDirFile(serverRootDirFile), HealthCheckFileName.READY_FILE.getFileName());

        return readyFile;
    }

    public static File getLiveFile(File serverRootDirFile) {

        File liveFile = new File(getHealthDirFile(serverRootDirFile), HealthCheckFileName.LIVE_FILE.getFileName());

        return liveFile;
    }

    enum HealthCheckFileName {
        STARTED_FILE("started"),
        READY_FILE("ready"),
        LIVE_FILE("live");

        private final String fileName;

        HealthCheckFileName(String fileName) {
            this.fileName = fileName;
        }

        String getFileName() {
            return fileName;
        }
    }
}
