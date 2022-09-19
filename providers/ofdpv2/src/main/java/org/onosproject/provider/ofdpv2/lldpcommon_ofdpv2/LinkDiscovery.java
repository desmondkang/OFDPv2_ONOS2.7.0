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

import com.google.common.collect.Maps;
import io.netty.util.Timeout;
import io.netty.util.TimerTask;
import io.netty.util.internal.StringUtil;
import org.onlab.packet.Ethernet;
import org.onlab.packet.LLDPTLV;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
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
import static org.onosproject.net.AnnotationKeys.PORT_MAC;
import static org.onosproject.net.AnnotationKeys.PORT_NAME;
import static org.onosproject.net.PortNumber.*;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Run discovery process from a physical switch. Ports are initially labeled as
 * slow ports. When an LLDP is successfully received, label the remote port as
 * fast. Every probeRate milliseconds, loop over all fast ports and send an
 * LLDP, send an LLDP for a single slow port. Based on FlowVisor topology
 * discovery implementation.
 */
// Each object of LinkDiscovery (discoverer) represents a unique device,
// a device has multiple ports which only one LinkDiscovery (discoverer) will be responsible to look after.
public class LinkDiscovery implements TimerTask {

    private ApplicationId appId;
    private static final String SCHEME_NAME = "linkdiscovery";
    private static final String ETHERNET = "ETHERNET";

    private final Logger log = getLogger(getClass());

    private final DeviceId deviceId;
    private final LinkDiscoveryContext context;

    private final DeviceService deviceService;

    private final Ethernet lldpEth;
    private final Ethernet bddpEth;
    private TrafficTreatment actionList;

    private Timeout timeout;
    private volatile boolean isStopped;

    private FlowRule lldpFlowRule;
    private FlowRule bddpFlowRule;
    private final int OFDPv2_A_PRIORITY = 45000;

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
    public LinkDiscovery(DeviceId deviceId, ApplicationId appId, LinkDiscoveryContext context) {
        this.deviceId = deviceId;
        this.appId = appId;
        this.context = context;
        this.deviceService = context.deviceService();
        this.lldpFlowRule = null;
        this.bddpFlowRule = null;
        this.actionList = generateOFDPv2APacketOutActionList();

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
            removeFlowEntry(this.lldpFlowRule);
            removeFlowEntry(this.bddpFlowRule);
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

        // checks if the port is a new port, if yes, initialize LLDP Probing.
        boolean newPort = !containsPort(portNum);
        boolean isMaster = context.mastershipService().isLocalMaster(deviceId);
        if (newPort && isMaster) {
            portMap.put(portNum, portName);
            log.trace("portMap updated/replaced: portNum {} and portName {}", portNum, portName);
            updateOFDPv2AFlowRule();
        }
    }

    /**
     * removed physical port from discovery process.
     * @param port the port number
     */
    public void removePort(PortNumber port) {
        portMap.remove(port.toLong());
        updateOFDPv2AFlowRule();
    }

    /**
     * check if the port is being found before
     * @param portNumber the port number
     */
    public boolean containsPort(long portNumber) {
        return portMap.containsKey(portNumber);
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

    private boolean processOnosLldp(PacketContext packetContext, Ethernet eth) {
        ONOSLLDP_ofdpv2 onoslldp = ONOSLLDP_ofdpv2.parseONOSLLDP(eth);
        if (onoslldp != null) {
            Type lt;
            Optional<String> fingerprint = extractMastershipFingerprint(onoslldp);
            if(fingerprint.isEmpty()){
                log.error("Unable to retrieve fingerprint, not ONOSLLDP_OFDPv2 {}", deviceId);
                return false;
            }
            if (notMy(fingerprint.get())) {
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

            MacAddress srcMacAddress = eth.getSourceMAC();
            Optional<Device> srcDevice = findSourceDeviceByMacAddress(srcMacAddress);
            if (srcDevice.isEmpty()) {
                log.error("source device not found. srcChassisId value: {}", srcMacAddress);
                return false;
            }

            Optional<Port> sourcePort = findSourcePortByMacAddress(srcMacAddress, srcDevice.get());

            if (sourcePort.isEmpty()) {
                log.error("source port not found. sourcePort value: {}", sourcePort);
                return false;
            }

            PortNumber srcPort = sourcePort.get().number();
            PortNumber dstPort = packetContext.inPacket().receivedFrom().port();

            String idString = onoslldp.getDeviceString();
            if (!isNullOrEmpty(idString)) {
                try {
                    DeviceId srcDeviceId = srcDevice.get().id();
                    DeviceId dstDeviceId = packetContext.inPacket().receivedFrom().deviceId();

                    ConnectPoint src = translateSwitchPort(srcDeviceId, srcPort);
                    ConnectPoint dst = new ConnectPoint(dstDeviceId, dstPort);

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

            MacAddress srcMacAddress = eth.getSourceMAC();
            String srcPortDesc = onoslldp.getPortDescString();

            if (srcMacAddress == null && srcPortDesc == null) {
                log.error("there are no valid port id");
                return false;
            }

            Optional<Device> srcDevice = findSourceDeviceByMacAddress(srcMacAddress);

            if (srcDevice.isEmpty()) {
                log.error("source device not found. srcChassisId value: {}", srcMacAddress);
                return false;
            }
            Optional<Port> sourcePort = findSourcePortByMacAddress(srcMacAddress, srcDevice.get());

            if (sourcePort.isEmpty()) {
                log.error("source port not found. sourcePort value: {}", sourcePort);
                return false;
            }

            PortNumber srcPort = sourcePort.get().number();
            PortNumber dstPort = packetContext.inPacket().receivedFrom().port(); // ok

            DeviceId srcDeviceId = srcDevice.get().id();
            DeviceId dstDeviceId = packetContext.inPacket().receivedFrom().deviceId(); // ok

            if (!sourcePort.get().isEnabled()) {
                log.error("Ports are disabled. Cannot create a link between {}/{} and {}/{}",
                        srcDeviceId, sourcePort.get(), dstDeviceId, dstPort);
                return false;
            }

            ConnectPoint src = new ConnectPoint(srcDeviceId, srcPort);
            ConnectPoint dst = new ConnectPoint(dstDeviceId, dstPort);

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
            return true;
        }
        return false;
    }

    private Optional<String> extractMastershipFingerprint(ONOSLLDP_ofdpv2 onoslldp) {
        Supplier<Stream<LLDPTLV>> opttlvStream = () ->
                onoslldp.getOptionalTLVList().stream();
        Optional<LLDPTLV> fingerprint = opttlvStream.get()
                .filter(lldptlv -> lldptlv.getType() == ONOSLLDP_ofdpv2.FINGERPRINT_TLV_TYPE).findAny();

        if (fingerprint.isPresent()){
            byte[] bytes = fingerprint.get().getValue();
            byte[] macByte = new byte[bytes.length-1];
            System.arraycopy(bytes, 1, macByte, 0, macByte.length);
            return Optional.of(new MacAddress(macByte).toString());
        }
        else {
            log.error("Fingerprint not found");
            return Optional.empty();
        }
    }

    private Optional<Device> findSourceDeviceByMacAddress(MacAddress macAddress) {
        if(macAddress.equals(MacAddress.valueOf(context.fingerprint())))
        {
            log.error("Expecting a Switchport Mac Addr but found context fingerprint");
            return Optional.empty();
        }

        Supplier<Stream<Device>> deviceStream = () ->
                StreamSupport.stream(deviceService.getAvailableDevices().spliterator(), false);

        Optional<Device> remoteDeviceOptional = deviceStream.get().filter(device ->
                 Tools.stream(deviceService.getPorts(device.id()))
                         .anyMatch(port -> port.annotations().keys().contains(AnnotationKeys.PORT_MAC)
                                 && MacAddress.valueOf(port.annotations().value(AnnotationKeys.PORT_MAC))
                                 .equals(macAddress)))
                .findAny();

        if (remoteDeviceOptional.isPresent()) {
            return remoteDeviceOptional;
        } else {
            log.error("Unable to find SourceDevice using Mac: {}", macAddress);
            return Optional.empty();
        }
    }

    private Optional<Port> findSourcePortByMacAddress(MacAddress srcMacAddress,
                                                Device remoteDevice) {
        if (srcMacAddress == null) {
            log.error("srcMacAddress is null");
            return Optional.empty();
        }
        Optional<Port> remotePort = deviceService.getPorts(remoteDevice.id())
                .stream().filter(port -> Objects.equals(srcMacAddress,
                                                        MacAddress.valueOf(
                                                                port.annotations().value(AnnotationKeys.PORT_MAC))
                )).findAny();

        if (remotePort.isPresent()) {
            return remotePort;
        } else {
            log.error("Port does not found using Mac: {}",srcMacAddress);
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
     * Link Discovery Mechanism using OFDPv2A
     * Execute this method every t milliseconds.
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
                sendOFDPv2AProbes(); // O(n)
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

    // LLDP Outbound Packet
    private OutboundPacket createOFDPv2AOutBoundLldp() {
        if (portMap.isEmpty())
        {
            log.warn("portMap is empty, quitting OFDPv2OutBoundLLDP Creation."); // this line should never run
            return null;
        }
        ONOSLLDP_ofdpv2 lldp = getOFDPv2LinkProbe();
        if (lldp == null) {
            log.warn("Cannot get link probe for device {} at LLDP packet creation.", deviceId);
            return null;
        }
        lldpEth.setSourceMACAddress(context.fingerprint())
                .setPayload(lldp);

        return new DefaultOutboundPacket(deviceId, // DeviceId
                                         this.actionList, // Blank Treatment
                                         ByteBuffer.wrap(lldpEth.serialize())); // ByteBuffer
    }

    // BDDP Outbound Packet
    private OutboundPacket createOFDPv2AOutBoundBddp() {
        if (portMap.isEmpty())
        {
            log.warn("portMap is empty, quitting OFDPv2OutBoundBBDP Creation."); // this line should never run
            return null;
        }
        ONOSLLDP_ofdpv2 bddp = getOFDPv2LinkProbe();
        if (bddp == null) {
            log.warn("Cannot get link probe for device {} at BDDP packet creation.", deviceId);
            return null;
        }
        bddpEth.setSourceMACAddress(context.fingerprint())
                .setPayload(bddp);
        return new DefaultOutboundPacket(deviceId, // DeviceId
                                         this.actionList, // Blank Treatment
                                         ByteBuffer.wrap(bddpEth.serialize())); // ByteBuffer
    }

    private ONOSLLDP_ofdpv2 getOFDPv2LinkProbe() {
        Device device = context.deviceService().getDevice(deviceId);
        if (device == null) {
            log.warn("Cannot find the device {}", deviceId);
            return null;
        }
        return ONOSLLDP_ofdpv2.onosSecureLLDP(deviceId.toString(),
                                              device.chassisId(),
                                              context.fingerprint(),
                                              0,
                                              context.lldpSecret());
    }

    private void sendOFDPv2AProbes() {
        if(portMap.isEmpty()) {
            log.warn("portMap is empty, unable to send OFDPv2 Probes");
            return;
        }
        OutboundPacket pkt = createOFDPv2AOutBoundLldp();
        if (pkt != null)
        {
            context.packetService().emit(pkt);
        }
        else
        {
            log.warn("Cannot send lldp packet due to packet is null {}", deviceId);
        }

        // BDDP
        if (context.useBddp())
        {
            OutboundPacket bpkt = createOFDPv2AOutBoundBddp();
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

    /* Port number created from ONOS lldp does not have port name
       we use the device service as translation service */
    private ConnectPoint translateSwitchPort(DeviceId deviceId, PortNumber portNumber) {
        Port devicePort = this.context.deviceService().getPort(deviceId, portNumber);
        if (devicePort != null) {
            return new ConnectPoint(deviceId, devicePort.number());
        }
        return new ConnectPoint(deviceId, portNumber);
    }

    /**
     * Creates an ActionList for OFDPv2A Packet Out
     *
     * @return Instruction: Output through OFPMP Table
     */
    private TrafficTreatment generateOFDPv2APacketOutActionList() {
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setOutput(TABLE); // to be decided by flow TABLE
        return treatment.build();
    }

    // OFDPv2A FlowRule
    private synchronized boolean updateOFDPv2AFlowRule() {
        boolean updateSuccess = false;

        // LLDP
        FlowRule newLldpRule = generateLldpFlowRule();
        if(checkFlowEntryInequality(newLldpRule, this.lldpFlowRule))
        {
            if(removeFlowEntry(this.lldpFlowRule))
            {
                if(installFlowEntry(newLldpRule))
                {
                    this.lldpFlowRule = newLldpRule;
                }
            }
        }
        if(newLldpRule.exactMatch(this.lldpFlowRule) && this.lldpFlowRule!=null)
            updateSuccess = true;

        // BDDP
        if(context.useBddp())
        {
            FlowRule newBddpRule = generateBddpFlowRule();
            if(checkFlowEntryInequality(newBddpRule, this.bddpFlowRule))
            {
                if(removeFlowEntry(this.bddpFlowRule))
                {
                    if(installFlowEntry(newBddpRule))
                    {
                        this.bddpFlowRule = newBddpRule;
                    } else updateSuccess = false;
                } else updateSuccess = false;
            }
        }

        // Return Statement
        if(updateSuccess) return true;
        else {
            log.error("Update OFDPv2-A FlowRule {} failed.", newLldpRule);
            return false;
        }
    }
    private FlowRule generateLldpFlowRule(){
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_LLDP)
                .matchInPort(CONTROLLER);

        TrafficTreatment.Builder treatment = generateOFDPv2ATrafficTreatment();

        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .fromApp(appId)
                .makePermanent()
                .withSelector(selector.build())
                .withTreatment(treatment.build())
                .withPriority(OFDPv2_A_PRIORITY)
                .build();
    }
    private FlowRule generateBddpFlowRule(){
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_BSN)
                .matchInPort(CONTROLLER);

        TrafficTreatment.Builder treatment = generateOFDPv2ATrafficTreatment();

        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .fromApp(appId)
                .makePermanent()
                .withSelector(selector.build())
                .withTreatment(treatment.build())
                .withPriority(OFDPv2_A_PRIORITY)
                .build();
    }
    private TrafficTreatment.Builder generateOFDPv2ATrafficTreatment(){
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();

        for (Port port : deviceService.getPorts(deviceId))
        {
            if(port.number().equals(LOCAL) && !portMap.containsKey(port.number().toLong())) {
                continue; // Intentionally skip the local port and disabled port
            }

            treatment.setEthSrc(MacAddress.valueOf(port.annotations().value(PORT_MAC)))
                    .setOutput(port.number());
        }
        return treatment;
    }

    /***
     *
     * @param newRule New Rule that is replacing the Old Rule
     * @param oldRule Old Rule that is to be Replaced.
     * @return TRUE if oldRule and newRule are not equal else FALSE.
     * if FALSE, it could mean that there is no need to update FlowRule from Switch
     */
    private boolean checkFlowEntryInequality(FlowRule newRule, FlowRule oldRule){
        if(oldRule == null){
            return true;
        }
        if(newRule == null){
            return false;
        }
        return !newRule.exactMatch(oldRule);
    }
    private synchronized boolean installFlowEntry(FlowRule newRule) {
        if(newRule == null){
            log.warn("New Rule is Null, no rules are installed.");
            return false;
        }
        try {
            context.flowRuleService().applyFlowRules(newRule);
            return true;
        } catch(Exception e)
        {
            log.error("Unknown exception occurred when installing flow entry: {}", e.getMessage());
            return false;
        }
    }
    private synchronized boolean removeFlowEntry(FlowRule oldRule) {
        if(oldRule == null) {
            log.debug("Flow Rule in device {} is null, nothing is removed", deviceId);
            return true;
        }
        try {
            context.flowRuleService().removeFlowRules(oldRule);
            return true;
        } catch(Exception e)
        {
            log.error("Unknown exception occurred when removing flow entry: {}", e.getMessage());
            return false;
        }
    }
}
