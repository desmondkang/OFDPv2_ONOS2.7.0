package org.onosproject.switchportlookup.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.switchportlookup.SwitchportLookup;

/**
 * Print out the mapping of Mac Address to Connect Point
 */
@Service
@Command(scope = "onos", name = "showmactoconnectpoint",
        description = "Sample Apache Karaf CLI command")
public class displayMacToConnectPoint extends AbstractShellCommand {

    @Override
    protected void doExecute()
    {
        print("Printing All entries in MacToConnectPoint...");
        SwitchportLookup.getMacToConnectPoint().forEach((macAddress, connectPoint) -> {
            print("MAC: %s --- ConnectPoint: %s", macAddress, connectPoint);
        });
    }

}
