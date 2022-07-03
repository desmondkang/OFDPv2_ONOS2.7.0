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
import org.onosproject.net.Device;
import org.onosproject.openflow.controller.Dpid;
import org.onosproject.openflow.controller.OpenFlowController;
import org.onosproject.openflow.controller.OpenFlowEventListener;
import org.onosproject.openflow.controller.OpenFlowSwitchListener;
import org.onosproject.openflow.controller.RoleState;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPortStatus;
import org.slf4j.Logger;

import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.projectfloodlight.openflow.protocol.OFType.ERROR;
import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true)
public class SwitchportLookup {
    private static final Logger log = getLogger(SwitchportLookup.class);

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected OpenFlowController controller;

    private final InternalDeviceProvider listener = new InternalDeviceProvider();

    private ApplicationId appId; // to constructor

    // To store whether the MacAddress existed here before or not
    private static Map<MacAddress, Dpid> MacAddressToDpid = new HashMap<>();
    // Mapping of dpid to a List of MAC Addresses
    private static Map<Dpid, HashSet<MacAddress>> DpidToMacAddresses = new HashMap<>();
    // The one-to-one mapping of MAC Address to Connect Point
    private static Map<MacAddress, ConnectPoint> MacToConnectPoint = new HashMap<>();

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.switchportlookup");

        controller.addListener(listener);
        controller.addEventListener(listener);

        log.info("{} Started", appId.id());
    }

    @Deactivate
    public void deactivate() {
        log.info("{} Stopped", appId.id());
    }

    public static boolean addEntry(Dpid dpid, MacAddress macAddress, ConnectPoint connectPoint) {
        if (MacToConnectPoint.containsKey(macAddress)) {
            log.info("[MacToConnectPoint] replaced ConnectPoint {} with {} " +
                             "at key: {}", MacToConnectPoint.get(macAddress), connectPoint, macAddress);
            MacToConnectPoint.replace(macAddress, connectPoint);
            initDpidtoMacAddresses(dpid, macAddress);
            return true;
        } else if (MacToConnectPoint.containsValue(connectPoint)) {
            log.warn("connectPoint is existed, cannot be inserted into MacToConnectPoint.");
            return false;
        } else // MacToConnectPoint does not have the entry
        {
            log.info("[MacToConnectPoint] entry registered successfully. {}, {}", macAddress, connectPoint);
            MacToConnectPoint.put(macAddress, connectPoint);
            initDpidtoMacAddresses(dpid, macAddress);
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

    public static Map<Dpid, HashSet<MacAddress>> getDpidToMacAddresses() {
        return DpidToMacAddresses;
    }

    public static Map<MacAddress, Dpid> getMacAddressToDpid() {
        return MacAddressToDpid;
    }

    private static void initDpidtoMacAddresses(Dpid dpid, MacAddress macAddress)
    {
        //if the map does not have the dpid
        if(!DpidToMacAddresses.containsKey(dpid))
        {
            // register an entry for the dpid
            DpidToMacAddresses.put(dpid, new HashSet<>());
        }
        // check if mac addresses is duplicated
        if(macAddressExisted(macAddress))
        {
            removeMACfromDpidToMacAddresses(MacAddressToDpid.get(macAddress), macAddress);
        }
        addDpidToMacAddresses(dpid, macAddress);
    }

    private static void addDpidToMacAddresses(Dpid dpid, MacAddress macAddress)
    {
        DpidToMacAddresses.get(dpid).add(macAddress);
        log.info("macAddress: {} added to dpid: {}", macAddress, dpid);
        MacAddressToDpid.put(macAddress, dpid);
    }

    private static void removeMACfromDpidToMacAddresses(Dpid dpid, MacAddress macAddress)
    {
        DpidToMacAddresses.get(dpid).remove(macAddress);
        log.info("macAddress: {} removed from dpid: {}", macAddress, dpid);
        MacAddressToDpid.remove(macAddress);
    }

    private static boolean macAddressExisted(MacAddress macAddress)
    {
        return MacAddressToDpid.containsKey(macAddress);
    }

    private static boolean dpidExisted(Dpid dpid)
    {
        return DpidToMacAddresses.containsKey(dpid);
    }

    private static void eraseDpidfromDatabase(Dpid dpid)
    {
        DpidToMacAddresses.get(dpid).forEach(mac -> {
            MacAddressToDpid.remove(mac);
            MacToConnectPoint.remove(mac);
        });
        DpidToMacAddresses.remove(dpid);
    }

    // Internal Class starts here
    private class InternalDeviceProvider implements OpenFlowSwitchListener, OpenFlowEventListener
    {

        @Override
        public void switchAdded(Dpid dpid)
        {
            log.info("SWITCH ADDED!!!");
            if(!dpidExisted(dpid))
            {
                DpidToMacAddresses.put(dpid, new HashSet<>());
            }
            else // replace the old dpid
            {
                eraseDpidfromDatabase(dpid);
                DpidToMacAddresses.put(dpid, new HashSet<>());
            }
        }

        @Override
        public void switchRemoved(Dpid dpid)
        {
            log.info("SWITCH REMOVED!!!");
            eraseDpidfromDatabase(dpid);
        }

        @Override
        public void switchChanged(Dpid dpid) {

        }

        @Override
        public void portChanged(Dpid dpid, OFPortStatus status) {

        }

        @Override
        public void receivedRoleReply(Dpid dpid, RoleState requested, RoleState response) {

        }

        @Override
        public void handleMessage(Dpid dpid, OFMessage msg) {
            log.info("Message DETECTED: {}", msg);
//            try
//            {
//                if(msg.getType() == ERROR)
//            }catch ()
//            {
//
//            }
        }
    }
}
