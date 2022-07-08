/*
 * Copyright 2016-present Open Networking Foundation
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
package org.onosproject.provider.ofdpv2.lldpcommon_ofdpv2;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import io.netty.util.Timeout;
import io.netty.util.TimerTask;
import io.netty.util.internal.StringUtil;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
//import org.onlab.packet.ONOSLLDP_ofdpv2;
import org.onosproject.openflow.controller.Dpid;
import org.onosproject.openflow.controller.OpenFlowController;
import org.onosproject.provider.ofdpv2.packet.ONOSLLDP_ofdpv2;
import org.onlab.util.Timer;
import org.onlab.util.Tools;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DefaultAnnotations;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Link.Type;
import org.onosproject.net.LinkKey;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.link.DefaultLinkDescription;
import org.onosproject.net.link.LinkDescription;
import org.onosproject.net.link.ProbedLinkProvider;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.provider.ofdpv2.storage.Switch;
import org.onosproject.switchportlookup.SwitchportLookup;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.onosproject.net.AnnotationKeys.PORT_NAME;
import static org.onosproject.net.PortNumber.portNumber;
import static org.onosproject.net.flow.DefaultTrafficTreatment.builder;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Run discovery process from a physical switch. Ports are initially labeled as
 * slow ports. When an LLDP is successfully received, label the remote port as
 * fast. Every probeRate milliseconds, loop over all fast ports and send an
 * LLDP, send an LLDP for a single slow port. Based on FlowVisor topology
 * discovery implementation.
 */
public class LinkDiscovery implements TimerTask {

    private static final String SCHEME_NAME = "linkdiscovery";
    private static final String ETHERNET = "ETHERNET";

    private final Logger log = getLogger(getClass());

    private final DeviceId deviceId;
    private final LinkDiscoveryContext context;

    private final Ethernet lldpEth;
    private final Ethernet bddpEth;

    private Timeout timeout;
    private volatile boolean isStopped;

    // Set of ports to be probed
    private final Map<Long, String> portMap = Maps.newConcurrentMap();

    /**
     * Instantiates discovery manager for the given physical switch. Creates a
     * generic LLDP packet that will be customized for the port it is sent out on.
     * Starts the the timer for the discovery process.
     *
     * @param deviceId  the physical switch
     * @param context discovery context
     */
    public LinkDiscovery(DeviceId deviceId, LinkDiscoveryContext context) {
        this.deviceId = deviceId;
        this.context = context;

        //Creating a Generic Ethernet LLDP and BDDP
        lldpEth = new Ethernet();
        lldpEth.setEtherType(Ethernet.TYPE_LLDP);
        lldpEth.setDestinationMACAddress(MacAddress.ONOS_LLDP);
        lldpEth.setPad(true); //pad this packet to 60bytes minimum, filling with zeroes?

        bddpEth = new Ethernet();
        bddpEth.setEtherType(Ethernet.TYPE_BSN);
        bddpEth.setDestinationMACAddress(MacAddress.BROADCAST);
        bddpEth.setPad(true); //pad this packet to 60bytes minimum, filling with zeroes?

        isStopped = true;
        start();
        log.debug("Started discovery manager for switch {}", deviceId);
    }

    public synchronized void stop() {
        if (!isStopped) {
            isStopped = true;
            timeout.cancel();
        } else {
            log.warn("LinkDiscovery stopped multiple times?");
        }
    }

    public synchronized void start() {
        if (isStopped) {
            isStopped = false;
            timeout = Timer.newTimeout(this, 0, MILLISECONDS);
        } else {
            log.warn("LinkDiscovery started multiple times?");
        }
    }

    public synchronized boolean isStopped() {
        return isStopped || timeout.isCancelled();
    }

    /**
     * Add physical port to discovery process.
     * Send out initial LLDP and label it as slow port.
     *
     * @param port the port
     */
    public void addPort(Port port) {
        Long portNum = port.number().toLong();
        String portName = port.annotations().value(PORT_NAME);
        if (portName == null) {
            portName = StringUtil.EMPTY_STRING;
        }

        boolean newPort = !containsPort(portNum);
        portMap.put(portNum, portName);

        boolean isMaster = context.mastershipService().isLocalMaster(deviceId);
        if (newPort && isMaster) {
            log.debug("Sending initial probe to port {}@{}", port.number().toLong(), deviceId);
            sendProbes(portNum, portName);
        }
    }

    /**
     * removed physical port from discovery process.
     * @param port the port number
     */
    public void removePort(PortNumber port) {
        portMap.remove(port.toLong());
    }

    /**
     * Handles an incoming LLDP packet.
     * Creates link in topology and
     * Adds the link for staleness tracking.
     *
     * @param packetContext packet context
     * @return true if handled
     */
    public boolean handleLldp(PacketContext packetContext) {
        Ethernet eth = packetContext.inPacket().parsed();
        if (eth == null) {
            return false;
        }

        // commenting out this
        if (processOnosLldp(packetContext, eth)) {
            return true;
        }

        if (processLldp(packetContext, eth)) {
            return true;
        }

        ONOSLLDP_ofdpv2 lldp = ONOSLLDP_ofdpv2.parseLLDP(eth);

        if (lldp == null) {
            log.debug("Cannot parse the packet. It seems that it is not the lldp or bsn packet.");
        } else {
            log.debug("LLDP packet is dropped due to there are no handlers that properly handle this packet: {}",
                    lldp.toString());
        }

        return false;
    }

    //Needs hard-work, ONOS is using src mac to verify its own fingerprint
    private boolean processOnosLldp(PacketContext packetContext, Ethernet eth)
    {
        DeviceService deviceService = context.deviceService();
        ONOSLLDP_ofdpv2 onoslldp = ONOSLLDP_ofdpv2.parseONOSLLDP(eth);
        if (onoslldp != null) {
            Type lt;
            // Need to find another way for ONOS to deal with mastership
            if (notMy(eth.getSourceMAC().toString())) {
                lt = Type.EDGE;
            } else {
                lt = eth.getEtherType() == Ethernet.TYPE_LLDP ? // If LLDP then p2p links, else BDDP means indirect links
                        Type.DIRECT : Type.INDIRECT;

                /* Verify MAC in LLDP packets */
                if (!ONOSLLDP_ofdpv2.verify(onoslldp, context.lldpSecret(), context.maxDiscoveryDelay())) {
                    log.warn("LLDP Packet failed to validate!");
                    return true;
                }
            }

            //srcPort is redundant
            //need to configure it to verify srcPort through MAC Address
            MacAddress srcMac = eth.getSourceMAC();
            // Need to find a way to convert srcMac to PortNumber
            // Using one-to-one mapping
            //log.info("Processing ONOS LLDP...");
            PortNumber srcPort = portNumber(onoslldp.getPort());
            PortNumber dstPort = packetContext.inPacket().receivedFrom().port();

            String idString = onoslldp.getDeviceString();
            if (!isNullOrEmpty(idString)) {
                try {
                    DeviceId srcDeviceId = DeviceId.deviceId(idString);
                    DeviceId dstDeviceId = packetContext.inPacket().receivedFrom().deviceId();
//                    log.info("SrcMAC: {}, SrcDeviceID: {}, SrcPort: {} | dstPort: {}", srcMac, srcDeviceId, srcPort, dstPort);

                    MacAddress srcMacAddress = MacAddress.valueOf(
                            deviceService.getPort(srcDeviceId, srcPort).annotations().value(AnnotationKeys.PORT_MAC)
                    );
                    MacAddress dstMacAddress = MacAddress.valueOf(
                            deviceService.getPort(dstDeviceId, dstPort).annotations().value(AnnotationKeys.PORT_MAC)
                    );

                    ConnectPoint src = translateSwitchPort(srcDeviceId, srcPort);
                    SwitchportLookup.addEntry(SwitchportLookup.getMacAddressToDpid().get(srcMacAddress), srcMacAddress, src);
                    ConnectPoint dst = new ConnectPoint(dstDeviceId, dstPort);
                    SwitchportLookup.addEntry(SwitchportLookup.getMacAddressToDpid().get(dstMacAddress), dstMacAddress, dst);
                    LinkDescription ld = new DefaultLinkDescription(src, dst, lt);
                    context.providerService().linkDetected(ld); // This is where links truly gets registered
                    context.touchLink(LinkKey.linkKey(src, dst)); // Dont see the point of this yet
                } catch (IllegalStateException | IllegalArgumentException e) {
                    log.warn("There is an exception during link creation: {}", e.getMessage());
                    return true;
                }
                return true;
            }
        }
        return false;
    }

    // This one is better to modify, src MAC is free
    private boolean processLldp(PacketContext packetContext, Ethernet eth) {
        ONOSLLDP_ofdpv2 onoslldp = ONOSLLDP_ofdpv2.parseLLDP(eth);
        if (onoslldp != null) {
            Type lt = eth.getEtherType() == Ethernet.TYPE_LLDP ?
                    Type.DIRECT : Type.INDIRECT;

            DeviceService deviceService = context.deviceService();
            MacAddress srcMacAddress = eth.getSourceMAC();
            String srcPortName = onoslldp.getPortNameString(); //need to change
            String srcPortDesc = onoslldp.getPortDescString();

            log.debug("srcMacAddress:{}, srcPortName:{}, srcPortDesc:{}", srcMacAddress, srcPortName, srcPortDesc);

            if (srcMacAddress == null && srcPortDesc == null) {
                log.warn("there are no valid port id");
                return false;
            }

            Optional<Device> srcDevice = findSourceDeviceByChassisIdorMacAddress(deviceService, srcMacAddress);
            //Optional<Device> srcDevice = findSourceDeviceByMacAddress(deviceService, srcMacAddress);

            if (srcDevice.isEmpty()) {
                log.debug("source device not found. srcChassisId value: {}", srcMacAddress);
                return false;
            }
//            Optional<Port> sourcePort = findSourcePortByName(
//                    srcPortName == null ? srcPortDesc : srcPortName,
//                    deviceService,
//                    srcDevice.get());
            Optional<Port> sourcePort = findSourcePortByMacAddress(
                    srcMacAddress,
                    deviceService,
                    srcDevice.get());

            if (sourcePort.isEmpty()) {
                log.debug("source port not found. sourcePort value: {}", sourcePort);
                return false;
            }

            PortNumber srcPort = sourcePort.get().number();
            PortNumber dstPort = packetContext.inPacket().receivedFrom().port(); // ok

            DeviceId srcDeviceId = srcDevice.get().id();
            DeviceId dstDeviceId = packetContext.inPacket().receivedFrom().deviceId(); // ok

            if (!sourcePort.get().isEnabled()) {
                log.debug("Ports are disabled. Cannot create a link between {}/{} and {}/{}",
                        srcDeviceId, sourcePort.get(), dstDeviceId, dstPort);
                return false;
            }

            MacAddress dstMacAddress = MacAddress.valueOf(
                    deviceService.getPort(dstDeviceId, dstPort).annotations().value(AnnotationKeys.PORT_MAC)
            );

            try {
                ConnectPoint src = new ConnectPoint(srcDeviceId, srcPort);
                SwitchportLookup.addEntry(SwitchportLookup.getMacAddressToDpid().get(srcMacAddress), srcMacAddress, src);
                ConnectPoint dst = new ConnectPoint(dstDeviceId, dstPort);
                SwitchportLookup.addEntry(SwitchportLookup.getMacAddressToDpid().get(dstMacAddress), dstMacAddress, dst);

                DefaultAnnotations annotations = DefaultAnnotations.builder()
                        .set(AnnotationKeys.PROTOCOL, SCHEME_NAME.toUpperCase())
                        .set(AnnotationKeys.LAYER, ETHERNET)
                        .build();

                LinkDescription ld = new DefaultLinkDescription(src, dst, lt, true, annotations);
                try {
                    context.providerService().linkDetected(ld);
                    context.setTtl(LinkKey.linkKey(src, dst), onoslldp.getTtlBySeconds());
                } catch (IllegalStateException e) {
                    log.debug("There is a exception during link creation: {}", e.toString()); //added toString()
                    return true;
                }
            } catch (Exception e) {
                log.warn(e.getMessage());
            }
            return true;
        }
        return false;
    }

    private Optional<Device> findSourceDeviceByChassisIdorMacAddress(DeviceService deviceService, MacAddress srcChassisIdorsrcMacAddress) {
        Supplier<Stream<Device>> deviceStream = () ->
                StreamSupport.stream(deviceService.getAvailableDevices().spliterator(), false);
        Optional<Device> remoteDeviceOptional = deviceStream.get()
                .filter(device -> device.chassisId() != null
                        && MacAddress.valueOf(device.chassisId().value()).equals(srcChassisIdorsrcMacAddress))
                .findAny();

        if (remoteDeviceOptional.isPresent()) {
            log.debug("sourceDevice found by chassis id: {}", srcChassisIdorsrcMacAddress);
            return remoteDeviceOptional;
        } else {
            remoteDeviceOptional = deviceStream.get().filter(device ->
                    Tools.stream(deviceService.getPorts(device.id()))
                            .anyMatch(port -> port.annotations().keys().contains(AnnotationKeys.PORT_MAC)
                                    && MacAddress.valueOf(port.annotations().value(AnnotationKeys.PORT_MAC))
                                    .equals(srcChassisIdorsrcMacAddress)))
                    .findAny();
            if (remoteDeviceOptional.isPresent()) {
                log.debug("sourceDevice found by port mac: {}", srcChassisIdorsrcMacAddress);
                return remoteDeviceOptional;
            } else {
                return Optional.empty();
            }
        }
    }

//    private Optional<Device> findSourceDeviceByMacAddress(DeviceService deviceService, MacAddress macAddress)
//    {
//        log.info("Find SourceDevice by MacAddress: {}", macAddress);
//        long chassisId = convertDpidIDtoChassisIDLong(SwitchportLookup.getMacAddressToDpid().get(macAddress));
//        log.info("Source Device ChassisID Found: {}", chassisId);
//        Supplier<Stream<Device>> deviceStream = () ->
//                StreamSupport.stream(deviceService.getAvailableDevices().spliterator(), false);
//        Optional<Device> remoteDeviceOptional = deviceStream.get()
//                .filter(device -> device.chassisId() != null
//                        && MacAddress.valueOf(device.chassisId().value()).equals(chassisId))
//                .findAny();
//
//        if (remoteDeviceOptional.isPresent()) {
//            log.info("sourceDevice found by Mac Address: {}", macAddress);
//            log.info("sourceDevice: {}, MacAddress: {}",remoteDeviceOptional.get(), macAddress);
//            return remoteDeviceOptional;
//        } else {
//            remoteDeviceOptional = deviceStream.get().filter(device ->
//                 Tools.stream(deviceService.getPorts(device.id()))
//                         .anyMatch(port -> port.annotations().keys().contains(AnnotationKeys.PORT_MAC)
//                                 && MacAddress.valueOf(port.annotations().value(AnnotationKeys.PORT_MAC))
//                                 .equals(macAddress)))
//                    .findAny();
//            if (remoteDeviceOptional.isPresent()) {
//                log.info("sourceDevice found: {}, MacAddress: {}",remoteDeviceOptional.get(), macAddress);
//                return remoteDeviceOptional;
//            } else {
//                return Optional.empty();
//            }
//        }
//    }

//    private long convertDpidIDtoChassisIDLong(Dpid dpid){
//        log.info("converting dpid {} to chassisID", dpid);
//        return controller.getSwitch(dpid).getId();
//    }

    private Optional<Port> findSourcePortByName(String remotePortName,
                                                DeviceService deviceService,
                                                Device remoteDevice) {
        if (remotePortName == null) {
            return Optional.empty();
        }
        Optional<Port> remotePort = deviceService.getPorts(remoteDevice.id())
                .stream().filter(port -> Objects.equals(remotePortName,
                                                        port.annotations().value(AnnotationKeys.PORT_NAME)))
                .findAny();

        if (remotePort.isPresent()) {
            log.info("RemotePortName: {}, Type: {}",remotePortName, remotePortName.getClass());
            return remotePort;
        } else {
            return Optional.empty();
        }
    }

    private Optional<Port> findSourcePortByMacAddress(MacAddress srcMacAddress,
                                                DeviceService deviceService,
                                                Device remoteDevice) {
        if (srcMacAddress == null) {
            return Optional.empty();
        }
        Optional<Port> remotePort = deviceService.getPorts(remoteDevice.id())
                .stream().filter(port -> Objects.equals(srcMacAddress,
                                                        MacAddress.valueOf(
                                                                port.annotations().value(AnnotationKeys.PORT_MAC))
                )).findAny();

        if (remotePort.isPresent()) {
            log.info("Port Found: {}",remotePort.get());
            return remotePort;
        } else {
            return Optional.empty();
        }
    }

    // true if *NOT* this cluster's own probe.
    private boolean notMy(String mac) {
        // if we are using DEFAULT_MAC, clustering hadn't initialized, so conservative 'yes'
        String ourMac = context.fingerprint();
        if (ProbedLinkProvider.defaultMac().equalsIgnoreCase(ourMac)) {
            // DEFAULT_MAC
            return true;
        }
        return !mac.equalsIgnoreCase(ourMac);
    }

    /**
     * Execute this method every t milliseconds. Loops over all ports
     * labeled as fast and sends out an LLDP. Send out an LLDP on a single slow
     * port.
     *
     * @param t timeout
     */
    @Override
    public void run(Timeout t) {
        try {
            // Check first if it has been stopped
            if (isStopped()) {
                return;
            }
            // Verify if we are still the master
            if (context.mastershipService().isLocalMaster(deviceId)) {
                log.trace("Sending probes from {}", deviceId);
                ImmutableMap.copyOf(portMap).forEach(this::sendProbes);
            }
        } catch (Exception e) {
            // Catch all exceptions to avoid timer task being cancelled
            if (!isStopped()) {
                // Error condition
                log.error("Exception thrown during link discovery process", e);
            } else {
                // Provider is shutting down, the error can be ignored
                log.trace("Shutting down, ignoring error", e);
            }
        } finally {
            // if it has not been stopped - re-schedule itself
            if (!isStopped()) {
                timeout = t.timer().newTimeout(this, context.probeRate(), MILLISECONDS);
            }
        }
    }

//    /**
//     * Creates packet_out LLDP for specified output port.
//     *
//     * @param portNumber the port
//     * @param portDesc the port description
//     * @return Packet_out message with LLDP data
//     */
//    private OutboundPacket createOutBoundLldp(Long portNumber, String portDesc) {
//        if (portNumber == null) {
//            return null;
//        }
//        ONOSLLDP_ofdpv2 lldp = getLinkProbe(portNumber, portDesc);
//        if (lldp == null) {
//            log.warn("Cannot get link probe with portNumber {} and portDesc {} for {} at LLDP packet creation.",
//                    portNumber, portDesc, deviceId);
//            return null;
//        }
//        lldpEth.setSourceMACAddress(context.fingerprint()).setPayload(lldp);
//        return new DefaultOutboundPacket(deviceId,
//                                         builder().setOutput(portNumber(portNumber)).build(),
//                                         ByteBuffer.wrap(lldpEth.serialize()));
//    }

    /**
     * Creates packet_out LLDP for specified output port.
     *
     * @param portNumber the port
     * @param portDesc the port description
     * @return Packet_out message with LLDP data
     */
    private OutboundPacket createOutBoundLldp(Long portNumber, String portDesc) {
        if (portNumber == null)
        {
            return null;
        }
        ONOSLLDP_ofdpv2 lldp = getLinkProbe(portNumber, portDesc);
        if (lldp == null) {
            log.warn("Cannot get link probe with portNumber {} and portDesc {} for {} at LLDP packet creation.",
                     portNumber, portDesc, deviceId);
            return null;
        }
        // "02:eb:96:7F:68:ED"
        lldpEth.setSourceMACAddress(context.fingerprint()).setPayload(lldp);
        return new DefaultOutboundPacket(deviceId,
                                         builder().setOutput(portNumber(portNumber)).build(),
                                         ByteBuffer.wrap(lldpEth.serialize()));
    }

    /**
     * Creates packet_out BDDP for specified output port.
     *
     * @param portNumber the port
     * @param portDesc the port description
     * @return Packet_out message with LLDP data
     */
    private OutboundPacket createOutBoundBddp(Long portNumber, String portDesc) {
        if (portNumber == null) {
            return null;
        }
        ONOSLLDP_ofdpv2 lldp = getLinkProbe(portNumber, portDesc);
        if (lldp == null) {
            log.warn("Cannot get link probe with portNumber {} and portDesc {} for {} at BDDP packet creation.",
                    portNumber, portDesc, deviceId);
            return null;
        }
        bddpEth.setSourceMACAddress(context.fingerprint()).setPayload(lldp);
        return new DefaultOutboundPacket(deviceId,
                                         builder().setOutput(portNumber(portNumber)).build(),
                                         ByteBuffer.wrap(bddpEth.serialize()));
    }

    private ONOSLLDP_ofdpv2 getLinkProbe(Long portNumber, String portDesc) {
        Device device = context.deviceService().getDevice(deviceId);
        if (device == null) {
            log.warn("Cannot find the device {}", deviceId);
            return null;
        }
        return ONOSLLDP_ofdpv2.onosSecureLLDP(deviceId.toString(), device.chassisId(), portNumber.intValue(), portDesc,
                                       context.lldpSecret());
    }

//    private void sendProbes(Long portNumber, String portDesc) {
//        if (context.packetService() == null) {
//            return;
//        }
//        log.trace("Sending probes out of {}@{}", portNumber, deviceId);
//        OutboundPacket pkt = createOutBoundLldp(portNumber, portDesc);
//        if (pkt != null)
//        {
//            context.packetService().emit(pkt);
//        }
//        else
//        {
//            log.warn("Cannot send lldp packet due to packet is null {}", deviceId);
//        }
//        if (context.useBddp())
//        {
//            OutboundPacket bpkt = createOutBoundBddp(portNumber, portDesc);
//            if (bpkt != null)
//            {
//                context.packetService().emit(bpkt);
//            }
//            else
//            {
//                log.warn("Cannot send bddp packet due to packet is null {}", deviceId);
//            }
//        }
//    }

    //OFDPv2
    private void sendProbes(Long portNumber, String portDesc)
    {
        if (context.packetService() == null) {
            return;
        }
        log.trace("Sending probes out of {}@{}", portNumber, deviceId);
        OutboundPacket pkt = createOutBoundLldp(portNumber, portDesc);
        if (pkt != null)
        {
            context.packetService().emit(pkt);
        }
        else
        {
            log.warn("Cannot send lldp packet due to packet is null {}", deviceId);
        }
        if (context.useBddp())
        {
            OutboundPacket bpkt = createOutBoundBddp(portNumber, portDesc);
            if (bpkt != null)
            {
                context.packetService().emit(bpkt);
            }
            else
            {
                log.warn("Cannot send bddp packet due to packet is null {}", deviceId);
            }
        }
    }

    public boolean containsPort(long portNumber) {
        return portMap.containsKey(portNumber);
    }

    /* Port number created from ONOS lldp does not have port name
       we use the device service as translation service */
    private ConnectPoint translateSwitchPort(DeviceId deviceId, PortNumber portNumber) {
        Port devicePort = this.context.deviceService().getPort(deviceId, portNumber);
        if (devicePort != null) {
            return new ConnectPoint(deviceId, devicePort.number());
        }
        return new ConnectPoint(deviceId, portNumber);
    }
}
