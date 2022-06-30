package org.onosproject.provider.ofdpv2.storage;

import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;
import org.slf4j.Logger;

import java.util.Map;

import static org.slf4j.LoggerFactory.getLogger;

public class SwitchportLookup
{
    private static final Logger log = getLogger(SwitchportLookup.class);
    private static Map<MacAddress, ConnectPoint> MacToConnectPoint;

    public SwitchportLookup(MacAddress macAddress, ConnectPoint connectPoint)
    {
        MacToConnectPoint.put(macAddress, connectPoint);
    }

    public static ConnectPoint getConnectPoint(MacAddress macAddress)
    {
        if(MacToConnectPoint.containsKey(macAddress))
            return MacToConnectPoint.get(macAddress);
        else
        {
            log.info("Retrieval of ConnectPoint using Mac Address: {} failed", macAddress);
            return null;
        }
    }
}
