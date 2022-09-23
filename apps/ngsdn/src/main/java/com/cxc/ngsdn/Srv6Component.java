/*
 * Copyright 2019-present Open Networking Foundation
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
//package org.onosproject.ngsdn.tutorial;
package com.cxc.ngsdn;

import com.google.common.collect.Lists;
import org.onlab.packet.Ip6Address;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import com.cxc.ngsdn.common.FabricDeviceConfig;
import com.cxc.ngsdn.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

import static com.google.common.collect.Streams.stream;
import static com.cxc.ngsdn.AppConstants.INITIAL_SETUP_DELAY;

/**
 * Application which handles SRv6 segment routing.
 */
@Component(
        immediate = true,
        // *** TODO EXERCISE 6
        // set to true when ready
        enabled = true,
        service = Srv6Component.class
)
public class Srv6Component {

    private static final Logger log = LoggerFactory.getLogger(Srv6Component.class);

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private IntentReactiveForwarding intentReactiveForwarding;

    private final DeviceListener deviceListener = new Srv6Component.InternalDeviceListener();

    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        // Register listeners to be informed about device and host events.
        deviceService.addListener(deviceListener);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);

        log.info("Stopped");
    }

    //--------------------------------------------------------------------------
    // METHODS TO COMPLETE.
    //
    // Complete the implementation wherever you see TODO.
    //--------------------------------------------------------------------------

    /**
     * Populate the My SID table from the network configuration for the
     * specified device.
     *
     * @param deviceId the device Id
     */
    private void setUpMySidTable(DeviceId deviceId) {

        Ip6Address mySid = getMySid(deviceId);

        log.info("Adding mySid rule on {} (sid {})...", deviceId, mySid);

        // Fill in the table ID for the SRv6 my segment identifier table
        String tableId = "IngressPipeImpl.srv6_my_sid";

        // Modify the field and action id to match your P4Info
        PiCriterion match = PiCriterion.builder()
                .matchLpm(
                        PiMatchFieldId.of("hdr.ipv6.dst_addr"),
                        mySid.toOctets(), 128)
                .build();

        PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.srv6_end"))
                .build();

        FlowRule myStationRule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        flowRuleService.applyFlowRules(myStationRule);
    }

    /**
     * Insert a SRv6 transit insert policy that will inject an SRv6 header for
     * packets destined to destIp.
     *
     * @param deviceId     device ID
     * @param destIp       target IP address for the SRv6 policy
     * @param prefixLength prefix length for the target IP
     * @param segmentList  list of SRv6 SIDs that make up the path
     */
//    public void insertSrv6InsertRule(DeviceId deviceId, Ip6Address destIp, int prefixLength,
//                                     List<Ip6Address> segmentList) {
//        if (segmentList.size() < 2 || segmentList.size() > 3) {
//            throw new RuntimeException("List of " + segmentList.size() + " segments is not supported");
//        }
//
//        //cxc: Call the following function , if the destIP is not exist, it will probe the destIP, else ,will setup localroute.
//        //cxc: sometimes need more probe packets to trige teh associate hosts-add event
//        // intentReactiveForwarding.buildLocalRouteForHost(destIp);
//
//        // Fill in the table ID for the SRv6 transit table.
//        // ---- START SOLUTION ----
//        String tableId = "IngressPipeImpl.srv6_transit";
//        // ---- END SOLUTION ----
//
//        // Modify match field, action id, and action parameters to match your P4Info.
//        // ---- START SOLUTION ----
//        PiCriterion match = PiCriterion.builder()
//                .matchLpm(PiMatchFieldId.of("hdr.ipv6.dst_addr"), destIp.toOctets(), prefixLength)
//                .build();
//
//        List<PiActionParam> actionParams = Lists.newArrayList();
//
//        for (int i = 0; i < segmentList.size(); i++) {
//            PiActionParamId paramId = PiActionParamId.of("s" + (i + 1));
//            PiActionParam param = new PiActionParam(paramId, segmentList.get(i).toOctets());
//            actionParams.add(param);
//        }
//
//        PiAction action = PiAction.builder()
//                .withId(PiActionId.of("IngressPipeImpl.srv6_t_insert_" + segmentList.size()))
//                .withParameters(actionParams)
//                .build();
//        // ---- END SOLUTION ----
//
//        final FlowRule rule = Utils.buildFlowRule(
//                deviceId, appId, tableId, match, action);
//
//        flowRuleService.applyFlowRules(rule);
//
//    }

    public void insertSrv6InsertRule(DeviceId deviceId, Ip6Address destIp, int prefixLength,
                                     List<Ip6Address> segmentList) {

        //不能小于2段，也不能大于12段。
        if (segmentList.size() < 2 || segmentList.size() > 12) {
            throw new RuntimeException("List of " + segmentList.size() + " segments is not supported");
        }


        //cxc: Call the following function , if the destIP is not exist, it will probe the destIP, else ,will setup localroute.
        //cxc: sometimes need more probe packets to trige teh associate hosts-add event
//         intentReactiveForwarding.buildLocalRouteForHost(destIp);

        // Fill in the table ID for the SRv6 transit table.
        String tableId = "IngressPipeImpl.srv6_transit";

        // Modify match field, action id, and action parameters to match your P4Info.
        PiCriterion match = PiCriterion.builder()
                .matchLpm(PiMatchFieldId.of("hdr.ipv6.dst_addr"), destIp.toOctets(), prefixLength)
                .build();

        List<PiActionParam> actionParams = Lists.newArrayList();

        int sn = segmentList.size();

        for (int i = 0; i < segmentList.size(); i++) {
              //生成的是s1,s2,s3等，就是action里的参数的名称。
            PiActionParamId paramId = PiActionParamId.of("s" + (sn -1 -i));
            PiActionParam param = new PiActionParam(paramId, segmentList.get(i).toOctets());
            actionParams.add(param);
        }

        // SRV6_MAX_HOPS=12
        // cxc : only to fill in .
        // 如果segmentList数不足12个，那就把后面的填满。只是为了填满12个而已。
        for (int i = sn; i < 12; i++) {
            PiActionParamId paramId = PiActionParamId.of("s" + i );
//            PiActionParam param = new PiActionParam(paramId, segmentList.get(0).toOctets());
            PiActionParam param = new PiActionParam(paramId, Ip6Address.valueOf("1111:2222::3333").toOctets());
            actionParams.add(param);
        }

        PiActionParamId paramId = PiActionParamId.of("next_hop_ip");
        PiActionParam param = new PiActionParam(paramId, segmentList.get(0).toOctets());
        actionParams.add(param);

        PiActionParamId snparamId = PiActionParamId.of("segment_num");
        PiActionParam snparam = new PiActionParam(snparamId, sn);
        actionParams.add(snparam);

        //main.p4里的action有两种，一个是srv6_t_insert_2，另一个是srv6_t_insert_3。
        //         	        PiAction action = PiAction.builder()
        // 	                .withId(PiActionId.of("IngressPipeImpl.srv6_t_insert_" + segmentList.size()))
        // 	                .withParameters(actionParams)
        //                 .build();

        PiAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.srv6_t_insert"))
                .withParameters(actionParams)
                .build();

        final FlowRule rule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        flowRuleService.applyFlowRules(rule);

        intentReactiveForwarding.buildLocalRouteForHost(destIp);

    }

    /**
     * Remove all SRv6 transit insert polices for the specified device.
     *
     * @param deviceId device ID
     */
    public void clearSrv6InsertRules(DeviceId deviceId) {
        // Fill in the table ID for the SRv6 transit table
        String tableId = "IngressPipeImpl.srv6_transit";

        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        stream(flowRuleService.getFlowEntries(deviceId))
                .filter(fe -> fe.appId() == appId.id())
                .filter(fe -> fe.table().equals(PiTableId.of(tableId)))
                .forEach(ops::remove);
        flowRuleService.apply(ops.build());
    }

    // ---------- END METHODS TO COMPLETE ----------------

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of device events.
     */
    public class InternalDeviceListener implements DeviceListener {

        @Override
        public boolean isRelevant(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_ADDED:
                //设备上线或者下线
                case DEVICE_AVAILABILITY_CHANGED:
                    break;
                default:
                    // Ignore other events.
                    return false;
            }
            // Process only if this controller instance is the master.
            final DeviceId deviceId = event.subject().id();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(DeviceEvent event) {
            final DeviceId deviceId = event.subject().id();
            if (deviceService.isAvailable(deviceId)) {
                // A P4Runtime device is considered available in ONOS when there
                // is a StreamChannel session open and the pipeline
                // configuration has been set.
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event! deviceId={}", event.type(), deviceId);

                    setUpMySidTable(event.subject().id());
                });
            }
        }
    }


    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    /**
     * Sets up SRv6 My SID table on all devices known by ONOS and for which this
     * ONOS node instance is currently master.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(deviceId -> {
                    log.info("*** SRV6 - Starting initial set up for {}...", deviceId);
                    this.setUpMySidTable(deviceId);
                    //TODO: setup route to all neighbors' SID
                });
    }

    /**
     * Returns the Srv6 config for the given device.
     *
     * @param deviceId the device ID
     * @return Srv6  device config
     */
    private Optional<FabricDeviceConfig> getDeviceConfig(DeviceId deviceId) {
        FabricDeviceConfig config = networkConfigService.getConfig(deviceId, FabricDeviceConfig.class);
        return Optional.ofNullable(config);
    }

    /**
     * Returns Srv6 SID for the given device.
     *
     * @param deviceId the device ID
     * @return SID for the device
     */
    private Ip6Address getMySid(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::mySid)
                .orElseThrow(() -> new RuntimeException(
                        "Missing mySid config for " + deviceId));
    }
}


// 		//前面只遇到过怎么创建flowrule，这里提供了一个删除flowrule的很好例子。
// 	    public void clearSrv6InsertRules(DeviceId deviceId) {
// 	        // TODO: fill in the table ID for the SRv6 transit table
// 	        // ---- START SOLUTION ----
// 	        String tableId = "IngressPipeImpl.srv6_transit";
// 	        // ---- END SOLUTION ----
// 	        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
// 	//这里的stream的用法比较特别。
// 	        stream(flowRuleService.getFlowEntries(deviceId))
// 	                .filter(fe -> fe.appId() == appId.id())
// 	                .filter(fe -> fe.table().equals(PiTableId.of(tableId)))
// 	                .forEach(ops::remove);
// 	        flowRuleService.apply(ops.build());
//     }