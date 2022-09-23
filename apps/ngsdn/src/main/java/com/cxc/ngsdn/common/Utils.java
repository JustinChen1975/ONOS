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

//package com.cxc.ngsdn.common;
package com.cxc.ngsdn.common;

import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.*;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiGroupKey;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import shaded.org.apache.maven.model.Organization;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.net.group.DefaultGroupBucket.createAllGroupBucket;
import static org.onosproject.net.group.DefaultGroupBucket.createCloneGroupBucket;
import static com.cxc.ngsdn.AppConstants.DEFAULT_FLOW_RULE_PRIORITY;

public final class Utils {

//    @Reference(cardinality = ReferenceCardinality.MANDATORY)
//    private GroupService groupService;

    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    //@Reference(cardinality = ReferenceCardinality.MANDATORY)
    //private NetworkConfigService networkConfigService;

    public static GroupDescription buildMulticastGroup(
            ApplicationId appId,
            DeviceId deviceId,
            int groupId,
            Collection<PortNumber> ports) {
        return buildReplicationGroup(appId, deviceId, groupId, ports, false);
    }

    public static GroupDescription buildCloneGroup(
            ApplicationId appId,
            DeviceId deviceId,
            int groupId,
            Collection<PortNumber> ports) {
        return buildReplicationGroup(appId, deviceId, groupId, ports, true);
    }

    private static GroupDescription buildReplicationGroup(
            ApplicationId appId,
            DeviceId deviceId,
            int groupId,
            Collection<PortNumber> ports,
            boolean isClone) {

        checkNotNull(deviceId);
        checkNotNull(appId);
        checkArgument(!ports.isEmpty());

        //groupKey其实就是groupID的一个特殊表示方法？是根据groupID的一些属性hash生成的？
        final GroupKey groupKey = new DefaultGroupKey(
                ByteBuffer.allocate(4).putInt(groupId).array());

        /**
                * Group Bucket definition. A default group Bucket is collection of
                * Instructions that can be performed on a traffic flow. A failover
                * group bucket is associated with a specific port or group that
                * controls its liveness. A select group bucket contains optional
                * weight field to define the weights among the buckets in the group.
        // Group Bucket是可以应用到traffic flow上的指令的集合*/
        final List<GroupBucket> bucketList = ports.stream()
                //这里的给予的指令仅仅是让traffic要从相应的ports发生出去而已吧。这里的指令集合只有一个指令，就是setOutput而已吧。
                // 下面是在构建相关的treatment，这些treatment是作用在相关的ports上的
                .map(p -> DefaultTrafficTreatment.builder()
                        .setOutput(p).build())
                         //把上面的TrafficTreatment转换为group  bucket
                .map(t -> isClone ? createCloneGroupBucket(t)
                        : createAllGroupBucket(t))
                        //让流量从多个端口发送出去，就形成了组播或者广播。
                .collect(Collectors.toList());

        return new DefaultGroupDescription(
                deviceId,
                isClone ? GroupDescription.Type.CLONE : GroupDescription.Type.ALL,
                new GroupBuckets(bucketList),
                groupKey, groupId, appId);
    }


    public static FlowRule buildFlowRule(DeviceId switchId, ApplicationId appId,
                                         String tableId, PiCriterion piCriterion,
                                         PiTableAction piAction) {
        return DefaultFlowRule.builder()
                .forDevice(switchId)
                .forTable(PiTableId.of(tableId))
                .fromApp(appId)
                .withPriority(DEFAULT_FLOW_RULE_PRIORITY)
                .makePermanent()
                .withSelector(DefaultTrafficSelector.builder()
                                      .matchPi(piCriterion).build())
                .withTreatment(DefaultTrafficTreatment.builder()
                                       .piTableAction(piAction).build())
                .build();
    }

    public static GroupDescription buildSelectGroup(DeviceId deviceId,
                                                         String tableId,
                                                         String actionProfileId,
                                                         int groupId,
                                                         Collection<PiAction> actions,
                                                         ApplicationId appId) {

        final GroupKey groupKey = new PiGroupKey(
                PiTableId.of(tableId), PiActionProfileId.of(actionProfileId), groupId);

        //.piTableAction(action).build()) 告诉ONOS,对于待处理的流量进行piTableAction(action)。这里给出的就是处理的指令。
        // 这里是把多个action转换为group中的多个bucket吧。
        final List<GroupBucket> buckets = actions.stream()
                .map(action -> DefaultTrafficTreatment.builder()
                        .piTableAction(action).build()) 
                .map(DefaultGroupBucket::createSelectGroupBucket)
                .collect(Collectors.toList());
        return new DefaultGroupDescription(
                deviceId,
                 //*Load-balancing among different bucket sinagroup. 决定了怎么使用groupBuckets. 
                //  如果是CLONE类型，会和和ALL类似，但是在egress模块中会因为决策不同而有不同的独立处理方法吧。
                GroupDescription.Type.SELECT,
                new GroupBuckets(buckets),
                groupKey,
                groupId,
                appId);
    }


    public static void sleep(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            log.error("Interrupted!", e);
            Thread.currentThread().interrupt();
        }
    }


    /**
     * Returns the MAC address configured in the "myStationMac" property of the
     * given device config.
     *
     * @param deviceId the device ID
     * @return MyStation MAC address
     */
    /*
    public static MacAddress getSwitchMac(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::myStationMac)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing myStationMac config for " + deviceId));
    }

     */

    /**
     * Returns the FabricDeviceConfig config object for the given device.
     *
     * @param deviceId the device ID
     * @return FabricDeviceConfig device config
     */
    /*
    private Optional<FabricDeviceConfig> getDeviceConfig(DeviceId deviceId) {
        FabricDeviceConfig config = networkConfigService.getConfig(
                deviceId, FabricDeviceConfig.class);
        return Optional.ofNullable(config);
    }
    */




}
