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
//author: Desmond Kang
package org.onosproject.switchportlookup;

import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.util.HashMap;
import java.util.Map;

import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true)
public class SwitchportLookup {
    private static final Logger log = getLogger(SwitchportLookup.class);

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    private ApplicationId appId; // to constructor

    private static Map<MacAddress, ConnectPoint> MacToConnectPoint = new HashMap<>();

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.switchportlookup");
        log.info("{} Started", appId.id());
    }

    @Deactivate
    public void deactivate() {
        log.info("{} Stopped", appId.id());
    }

    public static boolean addEntry(MacAddress macAddress, ConnectPoint connectPoint) {
        if (MacToConnectPoint.containsKey(macAddress)) {
            log.info("[MacToConnectPoint] replaced ConnectPoint {} with {} " +
                             "at key: {}", MacToConnectPoint.get(macAddress), connectPoint, macAddress);
            MacToConnectPoint.replace(macAddress, connectPoint);
            return true;
        } else if (MacToConnectPoint.containsValue(connectPoint)) {
            log.warn("connectPoint is existed, cannot be inserted into MacToConnectPoint.");
            return false;
        } else // MacToConnectPoint does not have the entry
        {
            log.info("[MacToConnectPoint] entry registered successfully. {}, {}", macAddress, connectPoint);
            MacToConnectPoint.put(macAddress, connectPoint);
            return true;
        }
    }

    public static ConnectPoint getConnectPoint(MacAddress macAddress) {
        if (MacToConnectPoint.containsKey(macAddress)) {
            return MacToConnectPoint.get(macAddress);
        } else {
            log.info("Retrieval of ConnectPoint using Mac Address: {} failed", macAddress);
            return null;
        }
    }

    public static Map<MacAddress, ConnectPoint> getMacToConnectPoint() {
        return MacToConnectPoint;
    }
}
