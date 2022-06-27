/*
 * Copyright 2015 Open Networking Foundation
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
package org.onosproject.packetsniffer;

import com.google.common.collect.HashMultimap;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;

import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_REMOVED;
import static org.onosproject.net.flow.criteria.Criterion.Type.ETH_SRC;

/**
 * Sample application that intercepts all inbound traffic.
 */
@Component(immediate = true)
public class PacketSniffer {

    private static Logger log = LoggerFactory.getLogger(PacketSniffer.class);

    private static final String MSG_RECEIVED =
            "{} Packet received!!!";

    private static final int PRIORITY = 128;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new PingPacketProcessor();

    // Selector for LLDP traffic that is to be intercepted
    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_LLDP)
            .build();

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.packetsniffer",
                                                () -> log.info("Periscope down."));
        packetService.addProcessor(packetProcessor, PRIORITY);
        packetService.requestPackets(intercept, PacketPriority.CONTROL, appId,
                                     Optional.empty());
        log.info("Packet Sniffer Service Started");
    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flowRuleService.removeFlowRulesById(appId);
        log.info("Packet Sniffer Service Stopped");
    }

    // Intercepts packets, but filter LLDP type to pass through
    private class PingPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (isLldp(eth)) {
                processLldp(context, eth);
            }
        }
    }

    private void processLldp(PacketContext context, Ethernet eth)
    {
        log.info(MSG_RECEIVED, eth.getEtherType());
        log.info(eth.getSourceMAC().toString());
    }

    // Indicates whether the specified packet corresponds to LLDP
    private boolean isLldp(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_LLDP;
    }
}
