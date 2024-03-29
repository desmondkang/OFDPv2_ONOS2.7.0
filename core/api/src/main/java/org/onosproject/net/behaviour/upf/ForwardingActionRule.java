/*
 * Copyright 2021-present Open Networking Foundation
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

package org.onosproject.net.behaviour.upf;

import org.onlab.packet.Ip4Address;
import org.onlab.util.ImmutableByteSequence;

import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A single Forwarding Action Rule (FAR), an entity described in the 3GPP
 * specifications (although that does not mean that this class is 3GPP
 * compliant). An instance of this class will be generated by a logical switch
 * write request to the database-style FAR P4 table, and the resulting instance
 * should contain all the information needed to reproduce that logical switch
 * FAR in the event of a client read request. The instance should also contain
 * sufficient information (or expose the means to retrieve such information) to
 * generate the corresponding dataplane forwarding state that implements the FAR.
 */
public final class ForwardingActionRule {
    // Match Keys
    private final ImmutableByteSequence sessionId;  // The PFCP session identifier that created this FAR
    private final int farId;  // PFCP session-local identifier for this FAR
    // Action parameters
    private final boolean notifyFlag;  // Should this FAR notify the control plane when it sees a packet?
    private final boolean dropFlag;
    private final boolean bufferFlag;
    private final GtpTunnel tunnel;  // The GTP tunnel that this FAR should encapsulate packets with (if downlink)

    private static final int SESSION_ID_BITWIDTH = 96;

    private ForwardingActionRule(ImmutableByteSequence sessionId, Integer farId,
                                 boolean notifyFlag, GtpTunnel tunnel, boolean dropFlag, boolean bufferFlag) {
        this.sessionId = sessionId;
        this.farId = farId;
        this.notifyFlag = notifyFlag;
        this.tunnel = tunnel;
        this.dropFlag = dropFlag;
        this.bufferFlag = bufferFlag;
    }

    /**
     * Return a new instance of this FAR with the action parameters stripped, leaving only the match keys.
     *
     * @return a new FAR with only match keys
     */
    public ForwardingActionRule withoutActionParams() {
        return ForwardingActionRule.builder()
                .setFarId(farId)
                .withSessionId(sessionId)
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Return a string representing the dataplane action applied by this FAR.
     *
     * @return a string representing the FAR action
     */
    public String actionString() {
        String actionName;
        String actionParams = "";
        if (dropFlag) {
            actionName = "Drop";
        } else if (bufferFlag) {
            actionName = "Buffer";
        } else if (tunnel != null) {
            actionName = "Encap";
            actionParams = String.format("Src=%s, SPort=%d, TEID=%s, Dst=%s",
                                         tunnel.src().toString(), tunnel.srcPort(),
                                         tunnel.teid().toString(), tunnel.dst().toString());
        } else {
            actionName = "Forward";
        }
        if (notifyFlag) {
            actionName += "+NotifyCP";
        }

        return String.format("%s(%s)", actionName, actionParams);
    }

    @Override
    public String toString() {
        String matchKeys = String.format("ID=%d, SEID=%s", farId, sessionId.toString());
        String actionString = actionString();

        return String.format("FAR{Match(%s) -> %s}", matchKeys, actionString);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ForwardingActionRule that = (ForwardingActionRule) obj;

        // Safe comparisons between potentially null objects
        return (this.dropFlag == that.dropFlag &&
                this.bufferFlag == that.bufferFlag &&
                this.notifyFlag == that.notifyFlag &&
                this.farId == that.farId &&
                Objects.equals(this.tunnel, that.tunnel) &&
                Objects.equals(this.sessionId, that.sessionId));
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionId, farId, notifyFlag, tunnel, dropFlag, bufferFlag);
    }

    /**
     * Get the ID of the PFCP Session that produced this FAR.
     *
     * @return PFCP session ID
     */
    public ImmutableByteSequence sessionId() {
        return sessionId;
    }

    /**
     * Get the PFCP session-local ID of the FAR that should apply to packets that match this PDR.
     *
     * @return PFCP session-local FAR ID
     */
    public int farId() {
        return farId;
    }

    /**
     * True if this FAR does not drop packets.
     *
     * @return true if FAR is forwards
     */
    public boolean forwards() {
        return !dropFlag;
    }

    /**
     * True if this FAR encapsulates packets in a GTP tunnel, and false otherwise.
     *
     * @return true is FAR encapsulates
     */
    public boolean encaps() {
        return tunnel != null;
    }

    /**
     * Returns true if this FAR drops packets, and false otherwise.
     *
     * @return true if this FAR drops
     */
    public boolean drops() {
        return dropFlag;
    }

    /**
     * Returns true if this FAR notifies the control plane on receiving a packet, and false otherwise.
     *
     * @return true if this FAR notifies the cp
     */
    public boolean notifies() {
        return notifyFlag;
    }


    /**
     * Returns true if this FAR buffers incoming packets, and false otherwise.
     *
     * @return true if this FAR buffers
     */
    public boolean buffers() {
        return bufferFlag;
    }

    /**
     * A description of the tunnel that this FAR will encapsulate packets with, if it is a downlink FAR. If the FAR
     * is uplink, there will be no such tunnel and this method wil return null.
     *
     * @return A GtpTunnel instance containing a tunnel sourceIP, destIP, and GTPU TEID, or null if the FAR is uplink.
     */
    public GtpTunnel tunnel() {
        return tunnel;
    }

    /**
     * Get the source UDP port of the GTP tunnel that this FAR will encapsulate packets with.
     *
     * @return GTP tunnel source UDP port
     */
    public Short tunnelSrcPort() {
        return tunnel != null ? tunnel.srcPort() : null;
    }

    /**
     * Get the source IP of the GTP tunnel that this FAR will encapsulate packets with.
     *
     * @return GTP tunnel source IP
     */
    public Ip4Address tunnelSrc() {
        if (tunnel == null) {
            return null;
        }
        return tunnel.src();
    }

    /**
     * Get the destination IP of the GTP tunnel that this FAR will encapsulate packets with.
     *
     * @return GTP tunnel destination IP
     */
    public Ip4Address tunnelDst() {
        if (tunnel == null) {
            return null;
        }
        return tunnel.dst();
    }

    /**
     * Get the identifier of the GTP tunnel that this FAR will encapsulate packets with.
     *
     * @return GTP tunnel ID
     */
    public ImmutableByteSequence teid() {
        if (tunnel == null) {
            return null;
        }
        return tunnel.teid();
    }

    public static class Builder {
        private ImmutableByteSequence sessionId = null;
        private Integer farId = null;
        private GtpTunnel tunnel = null;
        private boolean dropFlag = false;
        private boolean bufferFlag = false;
        private boolean notifyCp = false;

        public Builder() {
        }

        /**
         * Set the ID of the PFCP session that created this FAR.
         *
         * @param sessionId PFC session ID
         * @return This builder object
         */
        public Builder withSessionId(ImmutableByteSequence sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        /**
         * Set the ID of the PFCP session that created this FAR.
         *
         * @param sessionId PFC session ID
         * @return This builder object
         */
        public Builder withSessionId(long sessionId) {
            try {
                this.sessionId = ImmutableByteSequence.copyFrom(sessionId).fit(SESSION_ID_BITWIDTH);
            } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
                // This error is literally impossible
            }
            return this;
        }

        /**
         * Set the PFCP Session-local ID of this FAR.
         *
         * @param farId PFCP session-local FAR ID
         * @return This builder object
         */
        public Builder setFarId(int farId) {
            this.farId = farId;
            return this;
        }

        /**
         * Make this FAR forward incoming packets.
         *
         * @param flag the flag value to set
         * @return This builder object
         */
        public Builder setForwardFlag(boolean flag) {
            this.dropFlag = !flag;
            return this;
        }

        /**
         * Make this FAR drop incoming packets.
         *
         * @param flag the flag value to set
         * @return This builder object
         */
        public Builder setDropFlag(boolean flag) {
            this.dropFlag = flag;
            return this;
        }

        /**
         * Make this FAR buffer incoming packets.
         *
         * @param flag the flag value to set
         * @return This builder object
         */
        public Builder setBufferFlag(boolean flag) {
            this.bufferFlag = flag;
            return this;
        }

        /**
         * Set a flag specifying if the control plane should be notified when this FAR is hit.
         *
         * @param notifyCp true if FAR notifies control plane
         * @return This builder object
         */
        public Builder setNotifyFlag(boolean notifyCp) {
            this.notifyCp = notifyCp;
            return this;
        }

        /**
         * Set the GTP tunnel that this FAR should encapsulate packets with.
         *
         * @param tunnel GTP tunnel
         * @return This builder object
         */
        public Builder setTunnel(GtpTunnel tunnel) {
            this.tunnel = tunnel;
            return this;
        }

        /**
         * Set the unidirectional GTP tunnel that this FAR should encapsulate packets with.
         *
         * @param src  GTP tunnel source IP
         * @param dst  GTP tunnel destination IP
         * @param teid GTP tunnel ID
         * @return This builder object
         */
        public Builder setTunnel(Ip4Address src, Ip4Address dst, ImmutableByteSequence teid) {
            return this.setTunnel(GtpTunnel.builder()
                    .setSrc(src)
                    .setDst(dst)
                    .setTeid(teid)
                    .build());
        }

        /**
         * Set the unidirectional GTP tunnel that this FAR should encapsulate packets with.
         *
         * @param src     GTP tunnel source IP
         * @param dst     GTP tunnel destination IP
         * @param teid    GTP tunnel ID
         * @param srcPort GTP tunnel UDP source port (destination port is hardcoded as 2152)
         * @return This builder object
         */
        public Builder setTunnel(Ip4Address src, Ip4Address dst, ImmutableByteSequence teid, short srcPort) {
            return this.setTunnel(GtpTunnel.builder()
                    .setSrc(src)
                    .setDst(dst)
                    .setTeid(teid)
                    .setSrcPort(srcPort)
                    .build());
        }

        public ForwardingActionRule build() {
            // All match keys are required
            checkNotNull(sessionId, "Session ID is required");
            checkNotNull(farId, "FAR ID is required");
            return new ForwardingActionRule(sessionId, farId, notifyCp, tunnel, dropFlag, bufferFlag);
        }
    }
}
