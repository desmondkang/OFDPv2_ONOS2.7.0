package org.onosproject.switchportlookup.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.switchportlookup.SwitchportLookup;

/**
 * Sample Apache Karaf CLI command
 */
@Service
@Command(scope = "onos", name = "displaymactoconnectpoint",
        description = "Sample Apache Karaf CLI command")
public class displayMacToConnectPoint extends AbstractShellCommand {

    @Override
    protected void doExecute()
    {
        print("Printing All entries in MacToConnectPoint...");
        SwitchportLookup.getMacToConnectPoint().forEach((macAddress, connectPoint) -> {
            print("MAC: {} --- ConnectPoint: {}", macAddress, connectPoint);
        });
    }

}
