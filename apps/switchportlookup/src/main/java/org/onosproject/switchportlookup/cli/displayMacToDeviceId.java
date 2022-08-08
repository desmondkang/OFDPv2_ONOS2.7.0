package org.onosproject.switchportlookup.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.switchportlookup.SwitchportLookup;

/**
 * Print out the mapping of Mac Address to Device ID
 */
@Service
@Command(scope = "onos", name = "showmactodeviceid",
        description = "Sample Apache Karaf CLI command")
public class displayMacToDeviceId extends AbstractShellCommand {

    @Override
    protected void doExecute()
    {
        print("Printing All entries in MacAddressToDeviceid...");
        SwitchportLookup.getMacAddressToDeviceId().forEach((macAddress, deviceId) -> {
            print("MAC: %s --- DeviceID: %s", macAddress, deviceId);
        });
    }

}
