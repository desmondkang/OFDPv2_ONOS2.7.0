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
package org.onosproject.provider.ofdpv2.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.Device;
import org.onosproject.net.device.DeviceService;
import org.onosproject.openflow.controller.OpenFlowController;
import org.onosproject.openflow.controller.OpenFlowSwitch;

/**
 * "Display Dpid and DeviceId"
 */
@Service
@Command(scope = "onos", name = "displaydpidanddeviceid",
         description = "Display Dpid and DeviceId")
public class displayDpidandDeviceId extends AbstractShellCommand
{
    @Override
    protected void doExecute() {
        DeviceService service = get(DeviceService.class);
        Iterable<Device> devices = service.getAvailableDevices();
        print("Printing all deviceID: ");
        for(Device device : devices)
        {
            print("Chassis ID: %s, Device ID: %s, Serial Number: %s",device.chassisId().value(), device.id(), device.serialNumber());
        }

        OpenFlowController controller = get(OpenFlowController.class);
        Iterable<OpenFlowSwitch> dpids = controller.getSwitches();
        print("Printing all Dpids: ");
        dpids.forEach(
                sw -> print("Dpid: %s, ID: %s, StringID: %s, Serial Number: %s",
                            sw.getDpid(), sw.getId(), sw.getStringId(), sw.serialNumber())
        );
    }

}
