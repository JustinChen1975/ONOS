/*
 * Copyright 2018-present Open Networking Foundation
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
//package org.onosproject.pipelines.basic;
//package com.cxc.ngsdn.pipeconf;
package com.cxc.ngsdn;

import com.cxc.ngsdn.api.IntConstants;
import com.google.common.collect.Sets;
import org.onlab.packet.Ip6Prefix;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.*;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import com.cxc.ngsdn.api.IntConfig;
import com.cxc.ngsdn.api.IntObjective;
import com.cxc.ngsdn.api.IntIntent;


import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.onlab.util.ImmutableByteSequence;

import static com.cxc.ngsdn.AppConstants.INITIAL_SETUP_DELAY;
import static org.slf4j.LoggerFactory.getLogger;


//public class IntProcess extends AbstractHandlerBehaviour implements IntProgrammable {
@Component(
        immediate = true,
        // set to true when ready
        enabled = true,
        // service会在别的java文件中调用
        service = IntDevice.class
)

public class IntDevice  {

    // TODO: change this value to the value of diameter of a network.
    private static final int MAXHOP = 64;
    private static final int PORTMASK = 0xffff;
    private static final int IDLE_TIMEOUT = 10000;
    // Application name of the pipeline which adds this implementation to the pipeconf
//    private static final String PIPELINE_APP_NAME = "com.cxc.ngsdn";
    private final Logger log = getLogger(getClass());
    private ApplicationId appId;

    private static final Set<Criterion.Type> SUPPORTED_CRITERION = Sets.newHashSet(
            Criterion.Type.IPV6_DST,
            Criterion.Type.IPV6_SRC,
            Criterion.Type.IPV4_DST,
            Criterion.Type.IPV4_SRC,
            Criterion.Type.UDP_SRC,
            Criterion.Type.UDP_DST,
            Criterion.Type.TCP_SRC,
            Criterion.Type.TCP_DST,
            Criterion.Type.IP_PROTO);

    private static final Set<PiTableId> TABLES_TO_CLEANUP = Sets.newHashSet(
            IntConstants.INGRESS_SET_INT_SOURCE_PORT_TABLE,
            IntConstants.INGRESS_SET_INT_HEADER_AT_SOURCE_TABLE,
            IntConstants.INGRESS_SET_INT_SINK_PORT_TABLE,
            IntConstants.EGRESS_PROCESS_INT_TRANSIT_TB_INT_INSERT,
            IntConstants.EGRESS_TB_GENERATE_REPORT_TABLE);

    enum IntFunctionality {
        /**
         * Source functionality.
         */
        SOURCE,
        /**
         * Sink functionality.
         */
        SINK,
        /**
         * Transit functionality.
         */
        TRANSIT
    }

//    IntFunctionality intFunctionality;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

//    private DeviceId deviceId;
    private static final int DEFAULT_PRIORITY = 10000;

//    public IntDevice(DeviceId deviceIda, ApplicationId appId){
//        this.deviceId = deviceIda;
//        this.appId = appId;
////        this.flowRuleService = flowRuleService;
//    }

    // 好像没有在提供service ?
    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        // Schedule set up for all devices.
//        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);
        log.info("INT devices Started");
    }

    @Deactivate
    protected void deactivate() {

        log.info("INT devices Stopped");
    }

// 在simpleIntManager.java中会调用init().在IDEA里可以用call hierarchy查看调用路径。
// init()后，P4交换机(充当INT transit)如果遇到带有int option报头的报文，才会插入INT的metadata
// 这里的init其实就是添加了一个flowrule，也就是在table tb_int_insert里面添加了一条entry
//    @Override
    public boolean init(DeviceId deviceId) {

        PiActionParam transitIdParam = new PiActionParam(
                IntConstants.SWITCH_ID,
                ImmutableByteSequence.copyFrom(
                        deviceId.hashCode()));
//                        Integer.parseInt(deviceId.toString().substring(deviceId.toString().length() - 2))));
        PiAction transitAction = PiAction.builder()
                .withId(IntConstants.EGRESS_PROCESS_INT_TRANSIT_INIT_METADATA)
                .withParameter(transitIdParam)
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(transitAction)
                .build();

        // int_transit.p4的table tb_int_insert里面
        // key = {
        //     hdr.int_opt_header.isValid(): exact @name("int_is_valid");
        // }
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder().matchExact(
                        IntConstants.HDR_INT_IS_VALID, (byte) 0x01)
                         .build())
                .build();        

        FlowRule transitFlowRule = DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(IntConstants.EGRESS_PROCESS_INT_TRANSIT_TB_INT_INSERT)
                .build();

//        log.info(" {} " ,transitFlowRule.toString());

        flowRuleService.applyFlowRules(transitFlowRule);

//        return  transitFlowRule;
        return true;
    }


//    @Override
    public boolean setSourcePort(DeviceId deviceId,PortNumber port) {
//        if (!setupBehaviour()) {
//            return false;
//        }

        // 这几个函数都差不多，应该考虑简化下。
        // process_int_source_sink.tb_set_source for each host-facing port
        PiCriterion ingressCriterion = PiCriterion.builder()
                .matchExact(IntConstants.HDR_STANDARD_METADATA_INGRESS_PORT, port.toLong())
                .build();
        TrafficSelector srcSelector = DefaultTrafficSelector.builder()
                .matchPi(ingressCriterion)
                .build();
        PiAction setSourceAct = PiAction.builder()
                .withId(IntConstants.INGRESS_PROCESS_INT_SOURCE_PORT_SET_SOURCE_PORT)
                .build();
        TrafficTreatment srcTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(setSourceAct)
                .build();
        FlowRule srcFlowRule = DefaultFlowRule.builder()
                .withSelector(srcSelector)
                .withTreatment(srcTreatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(IntConstants.INGRESS_SET_INT_SOURCE_PORT_TABLE)
                .build();
        flowRuleService.applyFlowRules(srcFlowRule);
        return true;
    }

//    @Override
    public boolean setSinkPort(DeviceId deviceId,PortNumber port) {
//        if (!setupBehaviour()) {
//            return false;
//        }

        // process_set_source_sink.tb_set_sink
        PiCriterion egressCriterion = PiCriterion.builder()
                .matchExact(IntConstants.HDR_STANDARD_METADATA_EGRESS_SPEC, port.toLong())
                .build();
        TrafficSelector sinkSelector = DefaultTrafficSelector.builder()
                .matchPi(egressCriterion)
                .build();
        PiAction setSinkAct = PiAction.builder()
                .withId(IntConstants.INGRESS_PROCESS_INT_SINK_PORT_SET_SINK_PORT)
                .build();
        TrafficTreatment sinkTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(setSinkAct)
                .build();
        FlowRule sinkFlowRule = DefaultFlowRule.builder()
                .withSelector(sinkSelector)
                .withTreatment(sinkTreatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(IntConstants.INGRESS_SET_INT_SINK_PORT_TABLE)
                .build();
        flowRuleService.applyFlowRules(sinkFlowRule);
        return true;
    }

//    @Override
    public boolean addIntObjective(DeviceId deviceId, IntObjective obj) {
        // TODO: support different types of watchlist other than flow watchlist

        return processIntObjective(deviceId,obj, true);
    }

//    @Override
    public boolean removeIntObjective(DeviceId deviceId,IntObjective obj) {
        return processIntObjective(deviceId,obj, false);
    }

//    @Override
    public boolean setupIntConfig(DeviceId deviceId,IntConfig config) {
        return setupIntReportInternal(deviceId,config);
    }

//    @Override
    public void cleanup(DeviceId deviceId) {
//        if (!setupBehaviour()) {
//            return;
//        }

        // 删除与INT相关table的flowRules .
//        StreamSupport.stream(flowRuleService.getFlowEntries(
//                data().deviceId()).spliterator(), false)
//                .filter(f -> f.table().type() == TableId.Type.PIPELINE_INDEPENDENT)
//                .filter(f -> TABLES_TO_CLEANUP.contains((PiTableId) f.table()))
//                .forEach(flowRuleService::removeFlowRules);

        // TABLES_TO_CLEANUP里面定义了和INT相关的tables
        StreamSupport.stream(flowRuleService.getFlowEntries(
                deviceId).spliterator(), false)
                .filter(f -> f.table().type() == TableId.Type.PIPELINE_INDEPENDENT)
                .filter(f -> TABLES_TO_CLEANUP.contains((PiTableId) f.table()))
                .forEach(flowRuleService::removeFlowRules);
    }

//    @Override
    public boolean supportsFunctionality(IntFunctionality functionality) {
        switch (functionality) {
            case SOURCE:
            case SINK:
            case TRANSIT:
                return true;
            default:
                log.warn("Unknown functionality {}", functionality);
                return false;
        }
    }

    // 这个应该是个通用的flowRule的应用架构。
    private void populateInstTableEntry(DeviceId deviceId,PiTableId tableId, PiMatchFieldId matchFieldId,
                                        int matchValue, PiActionId actionId, ApplicationId appId) {
        PiCriterion instCriterion = PiCriterion.builder()
                .matchExact(matchFieldId, matchValue)
                .build();
        TrafficSelector instSelector = DefaultTrafficSelector.builder()
                .matchPi(instCriterion)
                .build();
        PiAction instAction = PiAction.builder()
                .withId(actionId)
                .build();
        TrafficTreatment instTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(instAction)
                .build();

        FlowRule instFlowRule = DefaultFlowRule.builder()
                .withSelector(instSelector)
                .withTreatment(instTreatment)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(tableId)
                .fromApp(appId)
                .build();

        flowRuleService.applyFlowRules(instFlowRule);
    }

    // TODO:要关注下怎么构建一个INT object(for IPv6)
    private FlowRule buildWatchlistEntry(DeviceId deviceId,IntObjective obj) {
        int instructionBitmap = buildInstructionBitmap(deviceId,obj.metadataTypes());
        // PiActionParam hopMetaLenParam = new PiActionParam(
        //         IntConstants.HOP_METADATA_LEN,
        //         ImmutableByteSequence.copyFrom(Integer.bitCount(instructionBitmap)));
        PiActionParam hopCntParam = new PiActionParam(
                IntConstants.REMAINING_HOP_CNT,
                ImmutableByteSequence.copyFrom(MAXHOP));
        PiActionParam inst0003Param = new PiActionParam(
                IntConstants.INS_MASK0003,
                ImmutableByteSequence.copyFrom((instructionBitmap >> 12) & 0xF));
        PiActionParam inst0407Param = new PiActionParam(
                IntConstants.INS_MASK0407,
                ImmutableByteSequence.copyFrom((instructionBitmap >> 8) & 0xF));

        PiAction intSourceAction = PiAction.builder()
                .withId(IntConstants.INGRESS_PROCESS_INT_SOURCE_CREATE_INT_OPTION)
                // .withParameter(hopMetaLenParam)
                .withParameter(hopCntParam)
                .withParameter(inst0003Param)
                .withParameter(inst0407Param)
                .build();

        TrafficTreatment instTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(intSourceAction)
                .build();

        TrafficSelector.Builder sBuilder = DefaultTrafficSelector.builder();

        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder();

        for (Criterion criterion : obj.selector().criteria()) {
            switch (criterion.type()) {
                case IPV6_SRC:
                    log.info("I am here now. IPv6_SRC");
                    Ip6Prefix ip6Prefix = ((IPCriterion) criterion).ip().getIp6Prefix();
                            piCriterionBuilder.matchTernary(
                                    IntConstants.HDR_HDR_IPV6_SRC_ADDR,
                                    ip6Prefix.address().toOctets(),
                                    ImmutableByteSequence.ofOnes(ip6Prefix.prefixLength()/8).asArray()
//                                    ImmutableByteSequence.ofOnes(a).asArray()
//                                    ByteBuffer.allocate(16).putInt(ip6Prefix.prefixLength()).array()
                            );
                    break;
                case IPV6_DST:
//                    sBuilder.matchIPv6Dst(((IPCriterion) criterion).ip());
                    log.info("I am here now. IPv6_DST");
                    Ip6Prefix ip6dstPrefix = ((IPCriterion) criterion).ip().getIp6Prefix();
//                    log.info("th ipv6 mask is  {} " , ip6dstPrefix.prefixLength());
                    piCriterionBuilder.matchTernary(
                            IntConstants.HDR_HDR_IPV6_DST_ADDR,
                            ip6dstPrefix.address().toOctets(),
                            ImmutableByteSequence.ofOnes(ip6dstPrefix.prefixLength()/8).asArray()
                    );
                    break;
                case IPV4_SRC:
                    sBuilder.matchIPSrc(((IPCriterion) criterion).ip());
                    break;
                case IPV4_DST:
                    sBuilder.matchIPDst(((IPCriterion) criterion).ip());
                    break;
                case TCP_SRC:
                    sBuilder.matchPi(
                            PiCriterion.builder().matchTernary(
                                    IntConstants.HDR_LOCAL_METADATA_L4_SRC_PORT,
                                    ((TcpPortCriterion) criterion).tcpPort().toInt(), PORTMASK)
                                    .build());
                    break;
                case UDP_SRC:
                    sBuilder.matchPi(
                            PiCriterion.builder().matchTernary(
                                    IntConstants.HDR_LOCAL_METADATA_L4_SRC_PORT,
                                    ((UdpPortCriterion) criterion).udpPort().toInt(), PORTMASK)
                                    .build());
                    break;
                case TCP_DST:
                    sBuilder.matchPi(
                            PiCriterion.builder().matchTernary(
                                    IntConstants.HDR_LOCAL_METADATA_L4_DST_PORT,
                                    ((TcpPortCriterion) criterion).tcpPort().toInt(), PORTMASK)
                                    .build());
                    break;
                case UDP_DST:
                    sBuilder.matchPi(
                            PiCriterion.builder().matchTernary(
                                    IntConstants.HDR_LOCAL_METADATA_L4_DST_PORT,
                                    ((UdpPortCriterion) criterion).udpPort().toInt(), PORTMASK)
                                    .build());
                    break;
                default:
                    log.warn("Unsupported criterion type: {}", criterion.type());
            }
        }

        sBuilder.matchPi(piCriterionBuilder.build());
        log.info("selector  is  {}",sBuilder.build());

        return DefaultFlowRule.builder()
//                .forDevice(this.data().deviceId())
                .forDevice(deviceId)
                .withSelector(sBuilder.build())
                .withTreatment(instTreatment)
                .withPriority(DEFAULT_PRIORITY)
                .forTable(IntConstants.INGRESS_SET_INT_HEADER_AT_SOURCE_TABLE)
                .fromApp(appId)
                .withIdleTimeout(IDLE_TIMEOUT)
                .build();
    }

//    ImmutableByteSequence.ofOnes

    private int buildInstructionBitmap(DeviceId deviceId,Set<IntIntent.IntMetadataType> metadataTypes) {
        int instBitmap = 0;
        for (IntIntent.IntMetadataType metadataType : metadataTypes) {
            switch (metadataType) {
                case SWITCH_ID:
                    instBitmap |= (1 << 15);
                    break;
                case L1_PORT_ID:
                    instBitmap |= (1 << 14);
                    break;
                case HOP_LATENCY:
                    instBitmap |= (1 << 13);
                    break;
                case QUEUE_OCCUPANCY:
                    instBitmap |= (1 << 12);
                    break;
                case INGRESS_TIMESTAMP:
                    instBitmap |= (1 << 11);
                    break;
                case EGRESS_TIMESTAMP:
                    instBitmap |= (1 << 10);
                    break;
                case L2_PORT_ID:
                    instBitmap |= (1 << 9);
                    break;
                case EGRESS_TX_UTIL:
                    instBitmap |= (1 << 8);
                    break;
                default:
                    log.info("Unsupported metadata type {}. Ignoring...", metadataType);
                    break;
            }
        }
        return instBitmap;
    }

    /**
     * Returns a subset of Criterion from given selector, which is unsupported
     * by this INT pipeline.
     *
     * @param selector a traffic selector
     * @return a subset of Criterion from given selector, unsupported by this
     * INT pipeline, empty if all criteria are supported.
     */
    private Set<Criterion> unsupportedSelectors(TrafficSelector selector) {
        return selector.criteria().stream()
                .filter(criterion -> !SUPPORTED_CRITERION.contains(criterion.type()))
                .collect(Collectors.toSet());
    }

    private boolean processIntObjective(DeviceId deviceId,IntObjective obj, boolean install) {
//        if (!setupBehaviour()) {
//            return false;
//        }
        if (install && !unsupportedSelectors(obj.selector()).isEmpty()) {
            log.warn("Device {} does not support criteria {} for INT.",
                     deviceId, unsupportedSelectors(obj.selector()));
            return false;
        }

        FlowRule flowRule = buildWatchlistEntry(deviceId,obj);
        if (flowRule != null) {
            if (install) {
                flowRuleService.applyFlowRules(flowRule);
            } else {
                flowRuleService.removeFlowRules(flowRule);
            }
            log.debug("IntObjective {} has been {} {}",
                      obj, install ? "installed to" : "removed from", deviceId);
            return true;
        } else {
            log.warn("Failed to {} IntObjective {} on {}",
                     install ? "install" : "remove", obj, deviceId);
            return false;
        }
    }

    private boolean setupIntReportInternal(DeviceId deviceId,IntConfig cfg) {
//        if (!setupBehaviour()) {
//            return false;
//        }

        FlowRule reportRule = buildReportEntry(deviceId,cfg);
        if (reportRule != null) {
            flowRuleService.applyFlowRules(reportRule);
            log.info("Report entry {} has been added to {}", reportRule, deviceId);
            return true;
        } else {
            log.warn("Failed to add report entry on {}", deviceId);
            return false;
        }
    }

    private FlowRule buildReportEntry(DeviceId deviceId,IntConfig cfg) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder().matchExact(
                        IntConstants.HDR_INT_IS_VALID, (byte) 0x01)
                                 .build())
                .build();
        PiActionParam srcMacParam = new PiActionParam(
                IntConstants.SRC_MAC,
                ImmutableByteSequence.copyFrom(cfg.sinkMac().toBytes()));
        PiActionParam nextHopMacParam = new PiActionParam(
                IntConstants.MON_MAC,
                ImmutableByteSequence.copyFrom(cfg.collectorNextHopMac().toBytes()));
        // TODO:下面的SRC_IP,MON_IP应该是Ipv6地址。
//        final PiCriterion match = PiCriterion.builder()
//        .matchLpm(
//                PiMatchFieldId.of("hdr.ipv6.dst_addr"),
//                ip6Prefix.address().toOctets(),
//                ip6Prefix.prefixLength())
//        .build();
//        PiActionParam srcIpParam = new PiActionParam(
//                IntConstants.SRC_IP,
//                ImmutableByteSequence.copyFrom(cfg.sinkIp().toOctets()));
        PiActionParam srcIpParam = new PiActionParam(
                IntConstants.SRC_IP,
                ImmutableByteSequence.copyFrom(cfg.sinkIp().toOctets()));
        PiActionParam monIpParam = new PiActionParam(
                IntConstants.MON_IP,
                ImmutableByteSequence.copyFrom(cfg.collectorIp().toOctets()));
        PiActionParam monPortParam = new PiActionParam(
                IntConstants.MON_PORT,
                ImmutableByteSequence.copyFrom(cfg.collectorPort().toInt()));
        PiAction reportAction = PiAction.builder()
                .withId(IntConstants.EGRESS_PROCESS_INT_REPORT_DO_REPORT_ENCAPSULATION)
                .withParameter(srcMacParam)
                .withParameter(nextHopMacParam)
                .withParameter(srcIpParam)
                .withParameter(monIpParam)
                .withParameter(monPortParam)
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(reportAction)
                .build();

        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(IntConstants.EGRESS_TB_GENERATE_REPORT_TABLE)
                .build();
    }

}


//    private boolean setupBehaviour() {
//        deviceId = this.data().deviceId();
//        flowRuleService = handler().get(FlowRuleService.class);
//        coreService = handler().get(CoreService.class);
//        appId = coreService.getAppId(PIPELINE_APP_NAME);
//        if (appId == null) {
//            log.warn("Application ID is null. Cannot initialize behaviour.");
//            return false;
//        }
//        return true;
//    }

//                    sBuilder.matchPi(
//                            PiCriterion.builder().matchTernary(
//                                    IntConstants.HDR_HDR_IPV6_SRC_ADDR,
//                                    ip6Prefix.address().toOctets(),
////                                    ByteBuffer.allocate(16).putInt(128).array()
//                                    ByteBuffer.allocate(16).putInt(ip6Prefix.prefixLength()).array()
//                            )
//                                    .build());

//                    PiCriterion.builder().matchLpm(
//                            IntConstants.HDR_HDR_IPV6_SRC_ADDR,
//                            ip6Prefix.address().toOctets(),
//                            ip6Prefix.prefixLength())
//                            .build());