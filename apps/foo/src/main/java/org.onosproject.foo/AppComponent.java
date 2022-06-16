/*
 * Copyright 2022-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.foo;

import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import static org.slf4j.LoggerFactory.getLogger;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;

/**
 * Skeletal ONOS application component.
 */
@Component
        (
                immediate = true,
                service = AppComponent.class,
                property = {}
        )

public class AppComponent {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    private final Logger log = getLogger(getClass());
    private ApplicationId appId;

    @Activate
    protected void activate()
    {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("org.onosproject.foo");
        log.info("Started", appId.id());
    }

    @Deactivate
    protected void deactivate()
    {
        cfgService.unregisterProperties(getClass(), false);

        log.info("Stopped");
    }

}
