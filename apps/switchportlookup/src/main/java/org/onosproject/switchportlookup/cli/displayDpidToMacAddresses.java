package org.onosproject.switchportlookup.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.switchportlookup.SwitchportLookup;

/**
 * Sample Apache Karaf CLI command
 */
@Service
@Command(scope = "onos", name = "displaydpidtomacaddresses",
        description = "Sample Apache Karaf CLI command")
public class displayDpidToMacAddresses extends AbstractShellCommand {

    @Override
    protected void doExecute()
    {
        print("Printing All entries in DpidToMacAddresses...");
        SwitchportLookup.getDpidToMacAddresses().forEach((dpid, hashset) -> {
            print("DPID: %s --- MACs: %s", dpid, hashset);
        });
    }

}
