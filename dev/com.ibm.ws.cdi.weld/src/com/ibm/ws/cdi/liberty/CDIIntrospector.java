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
 package com.ibm.ws.cdi.liberty;

import java.io.PrintWriter;
import java.util.Collection;
import java.util.Optional;

import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;

import com.ibm.ws.cdi.CDIService;
import com.ibm.ws.cdi.impl.weld.WebSphereCDIDeploymentImpl;
import com.ibm.ws.cdi.internal.archive.liberty.RuntimeFactory;
import com.ibm.ws.cdi.internal.interfaces.Application;
import com.ibm.ws.cdi.internal.interfaces.WebSphereBeanDeploymentArchive;
import com.ibm.ws.cdi.internal.interfaces.WebSphereCDIDeployment;
import com.ibm.ws.runtime.metadata.ApplicationMetaData;
import com.ibm.ws.runtime.metadata.MetaDataSlot;
import com.ibm.wsspi.logging.Introspector;

@Component(immediate = true, configurationPolicy = ConfigurationPolicy.IGNORE, property = {
                                                                                            Constants.SERVICE_VENDOR + "=" + "IBM" })
public class CDIIntrospector implements Introspector {

    @Reference
    CDIService cdiService;

    @Override
    public String getIntrospectorDescription() {
        return "An introspector for CDI's internel represenation of running CDI enabled apps";
    }

    @Override
    public String getIntrospectorName() {
        return "CDIIntrospector";
    }

    @Override
    public void introspect(PrintWriter out) throws Exception {
        try {
            if (!(cdiService instanceof CDIRuntimeImpl)) {
                out.println("cdiService was not an instance of CDIRuntimeImpl");
                return;
            }

            CDIRuntimeImpl cdiRuntimeImpl = (CDIRuntimeImpl) cdiService;
            RuntimeFactory runtimeFactory = cdiRuntimeImpl.getRuntimeFactory();
            Collection<Application> applications = runtimeFactory.getApplications();

            for (Application application : applications) {
                out.println("************** Beginning introspection of Application: " + application.getName() + " *******************");

                Optional<WebSphereCDIDeployment> deploymentOptional = getWebSphereCDIDeploymentFromApplication(application, cdiRuntimeImpl);
                if (deploymentOptional.isPresent()) {
                    WebSphereCDIDeployment deployment = deploymentOptional.get();
                    deployment.getApplicationBDAs();

                    Collection<WebSphereBeanDeploymentArchive> BDAs = deployment.getWebSphereBeanDeploymentArchives();

                    for (WebSphereBeanDeploymentArchive BDA : BDAs) {
                        BDA.introspect(out);
                    }

                    if (deployment instanceof WebSphereCDIDeploymentImpl) {
                        WebSphereCDIDeploymentImpl deploymentImpl = (WebSphereCDIDeploymentImpl) deployment;
                        for (WebSphereBeanDeploymentArchive BDA : deploymentImpl.getExtensionBDAs()) {
                            BDA.introspect(out);
                        }
                    }
                }

                out.println("************** End introspection of Application: " + application.getName() + " *******************");
            }
        } finally {
            out.flush();
            out.close();
        }

    }

    private Optional<WebSphereCDIDeployment> getWebSphereCDIDeploymentFromApplication(Application application, CDIRuntimeImpl cdiRuntime) {
        ApplicationMetaData applicationMetaData = application.getApplicationMetaData();
        MetaDataSlot slot = cdiRuntime.getApplicationSlot();
        Object maybeDeployment = applicationMetaData.getMetaData(slot);

        if (maybeDeployment instanceof WebSphereCDIDeployment) {
            return Optional.of((WebSphereCDIDeployment) maybeDeployment);
        } else {
            return Optional.empty();
        }
    }

}
