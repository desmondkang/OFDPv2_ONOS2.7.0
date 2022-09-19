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
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true)
public class SwitchportLookup {
    private static final Logger log = getLogger(SwitchportLookup.class);

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    private final DeviceListener listener = new InternalDeviceListener();

    private ApplicationId appId; // to constructor

    // To store whether the MacAddress existed here before or not
    private static Map<MacAddress, DeviceId> MacAddressToDeviceId = new HashMap<>();
    // Mapping of device id to a List of MAC Addresses
    private static Map<DeviceId, HashSet<MacAddress>> DeviceIdToMacAddresses = new HashMap<>();

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.switchportlookup");
        deviceService.addListener(listener);
        activationInitialization();
        log.info("{} Started", appId.id());
    }

    private void cleanup(){
        deviceService.removeListener(listener);
    }

    @Deactivate
    public void deactivate() {
        cleanup();
        log.info("{} Stopped", appId.id());
    }

    private void activationInitialization(){
        deviceService.getDevices().forEach(this::deviceAddedHandler);
    }

    private static void registerNewDeviceID(DeviceId deviceId){
        DeviceIdToMacAddresses.put(deviceId, new HashSet<>());
    }

    public static Map<DeviceId, HashSet<MacAddress>> getDeviceIdToMacAddresses() {
        return DeviceIdToMacAddresses;
    }
    public static Map<MacAddress, DeviceId> getMacAddressToDeviceId() {
        return MacAddressToDeviceId;
    }

    private static void insertMacSetIntoDeviceIdtoMacAddresses(DeviceId deviceId, HashSet<MacAddress> MacSet) {
        for(MacAddress macAddress : MacSet)
        {
            initDeviceIdtoMacAddresses(deviceId, macAddress);
        }
    }
    private static void initDeviceIdtoMacAddresses(DeviceId deviceId, MacAddress macAddress) {
        //if the map does not have the deviceId
        if(deviceId != null && !DeviceIdToMacAddresses.containsKey(deviceId))
        {
            // register an entry for the deviceId
            registerNewDeviceID(deviceId);
        }
        // check if mac addresses is duplicated
        if(macAddressExisted(macAddress))
        {
            if(!existInWhereItShouldBe(deviceId, macAddress))
                removeMACfromDeviceIdToMacAddresses(MacAddressToDeviceId.get(macAddress), macAddress);
        }
        addDeviceIdToMacAddresses(deviceId, macAddress);
    }
    private static void addDeviceIdToMacAddresses(DeviceId deviceId, MacAddress macAddress) {
        if(deviceId != null && !existInWhereItShouldBe(deviceId, macAddress))
        {
            DeviceIdToMacAddresses.get(deviceId).add(macAddress);
            MacAddressToDeviceId.put(macAddress, deviceId);
        }
    }
    private static void removeMACfromDeviceIdToMacAddresses(DeviceId deviceId, MacAddress macAddress) {
        DeviceIdToMacAddresses.get(deviceId).remove(macAddress);
        MacAddressToDeviceId.remove(macAddress);
    }

    private static boolean existInWhereItShouldBe(DeviceId deviceId, MacAddress macAddress) {
        return DeviceIdToMacAddresses.get(deviceId).contains(macAddress);
    }
    private static boolean macAddressExisted(MacAddress macAddress) {
        return MacAddressToDeviceId.containsKey(macAddress);
    }
    private static boolean deviceIdExisted(DeviceId deviceId) {
        return DeviceIdToMacAddresses.containsKey(deviceId);
    }
    private static boolean isNotLocalPort(Port port){
        return !port.number().equals(PortNumber.LOCAL);
    }

    private static void removeDeviceIdfromDatabase(DeviceId deviceId) {
        DeviceIdToMacAddresses.get(deviceId).forEach(mac ->
            MacAddressToDeviceId.remove(mac)
        );
        DeviceIdToMacAddresses.remove(deviceId);
    }
    private static void removeMacAddressfromDatabase(MacAddress macAddress) {
        DeviceId deviceId = MacAddressToDeviceId.get(macAddress);
        DeviceIdToMacAddresses.get(deviceId).remove(macAddress);
        MacAddressToDeviceId.remove(macAddress);
    }

    private synchronized void deviceAddedHandler(Device device){
        if (deviceIdExisted(device.id()))
            removeDeviceIdfromDatabase(device.id());
        HashSet<MacAddress> MacSet = new HashSet<>();
        deviceService.getPorts(device.id()).forEach( port -> {
            if(isNotLocalPort(port))
                MacSet.add(MacAddress.valueOf(port.annotations().value(AnnotationKeys.PORT_MAC)));
        });
        insertMacSetIntoDeviceIdtoMacAddresses(device.id(), MacSet);
    }
    private synchronized void deviceRemovedHandler(Device device){
        removeDeviceIdfromDatabase(device.id());
    }
    private synchronized void portAddedHandler(DeviceEvent event){
        if(isNotLocalPort(event.port()))
            initDeviceIdtoMacAddresses(event.subject().id(),
                                       MacAddress.valueOf(event.port()
                                                                  .annotations()
                                                                  .value(AnnotationKeys.PORT_MAC)));
    }
    private synchronized void portRemovedHandler(DeviceEvent event) {
        MacAddress removedMac = MacAddress.valueOf(event.port().annotations().value(AnnotationKeys.PORT_MAC));
        removeMacAddressfromDatabase(removedMac);
    }
    // Internal Class starts here
    private class InternalDeviceListener implements DeviceListener
    {
        DeviceId deviceId;
        @Override
        public void event(DeviceEvent event) {
            deviceId = event.subject().id();
            switch (event.type())
            {
                case DEVICE_ADDED:
                    deviceAddedHandler(event.subject());
                    break;

                case DEVICE_REMOVED:
                    deviceRemovedHandler(event.subject());
                    break;

                case PORT_ADDED:
                    portAddedHandler(event);
                    break;

                case PORT_REMOVED:
                    portRemovedHandler(event);
                    break;
            }
        }
    }
}
