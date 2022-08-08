package org.onosproject.switchportlookup.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.switchportlookup.SwitchportLookup;

/**
 * Print out the mapping of Device ID to Mac Address
 */
@Service
@Command(scope = "onos", name = "showdeviceidtomacaddress",
        description = "Sample Apache Karaf CLI command")
public class displayDeviceIdToMacAddresses extends AbstractShellCommand {

    @Override
    protected void doExecute()
    {
        print("Printing All entries in DeviceIdToMacAddresses...");
        SwitchportLookup.getDeviceIdToMacAddresses().forEach((deviceId, hashset) -> {
            print("DeviceID: %s --- MACs: %s", deviceId, hashset);
        });
    }

}
