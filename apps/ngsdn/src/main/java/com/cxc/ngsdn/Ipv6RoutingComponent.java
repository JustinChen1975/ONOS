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
import com.sun.jdi.ShortType;
import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.*;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.GroupId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.*;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flow.instructions.L2ModificationInstruction;
import org.onosproject.net.flow.instructions.PiInstruction;
import org.onosproject.net.group.*;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.pi.model.*;
import org.onosproject.net.pi.runtime.*;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import com.cxc.ngsdn.common.FabricDeviceConfig;
import com.cxc.ngsdn.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.net.driver.AbstractHandlerBehaviour;
//import shaded.org.apache.maven.model.Organization;
import org.onosproject.net.DeviceId;
import org.onosproject.net.MutableAnnotations;


//import javax.validation.metadata.ReturnValueDescriptor;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.Flow;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static com.google.common.collect.Streams.forEachPair;
import static com.google.common.collect.Streams.stream;
import static com.cxc.ngsdn.AppConstants.INITIAL_SETUP_DELAY;

/**
 * App component that configures devices to provide IPv6 routing capabilities
 * across the whole fabric.
 */
@Component(
        immediate = true,
        // *** TODO EXERCISE 5
        // set to true when ready
        enabled = true
)
public class Ipv6RoutingComponent {

    private static final Logger log = LoggerFactory.getLogger(Ipv6RoutingComponent.class);

    private static final int DEFAULT_ECMP_GROUP_ID = 0xec3b0000;
    private static final long GROUP_INSERT_DELAY_MILLIS = 200;

    private final HostListener hostListener = new InternalHostListener();
    private final LinkListener linkListener = new InternalLinkListener();
    private final DeviceListener deviceListener = new InternalDeviceListener();

    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private IntentReactiveForwarding intentReactiveForwarding;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        hostService.addListener(hostListener);
        linkService.addListener(linkListener);
        deviceService.addListener(deviceListener);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");

    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        linkService.removeListener(linkListener);
        deviceService.removeListener(deviceListener);

        log.info("Stopped");
    }

    //--------------------------------------------------------------------------
    // METHODS TO COMPLETE.
    //
    // Complete the implementation wherever you see TODO.
    //--------------------------------------------------------------------------

    /**
     * Sets up the "My Station" table for the given device using the
     * myStationMac address found in the config.
     * <p>
     * This method will be called at component activation for each device
     * (switch) known by ONOS, and every time a new device-added event is
     * captured by the InternalDeviceListener defined below.
     *这个仅仅是为了判断是否是设备自身的MAC而已，在flows里面会添加一条
     * @param deviceId the device ID
     */
    private void setUpMyStationTable(DeviceId deviceId) {

        log.info("Adding My Station rules to {}...", deviceId);

        final MacAddress myStationMac = getMyStationMac(deviceId);

        // HINT: in our solution, the My Station table matches on the *ethernet
        // destination* and there is only one action called *NoAction*, which is
        // used as an indication of "table hit" in the control block.

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        final String tableId = "IngressPipeImpl.my_station_table";

        final PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        myStationMac.toBytes())
                .build();

        // Creates an action which do *NoAction* when hit.
        final PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("NoAction"))
                .build();

        final FlowRule myStationRule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        flowRuleService.applyFlowRules(myStationRule);
    }

    /**
     * Creates an ONOS SELECT group for the routing table to provide ECMP
     * forwarding for the given collection of next hop MAC addresses. ONOS
     * SELECT groups are equivalent to P4Runtime action selector groups.
     * <p>
     		createNextHopGroup(): responsible of creating the ONOS equivalent of a P4Runtime action profile group for the ECMP selector of the routing table;
来自 <https://github.com/opennetworkinglab/ngsdn-tutorial/blob/advanced/EXERCISE-5.md> 
     * This method will be called by the routing policy methods below to insert
     * groups in the L3 table
     *
     * @param nextHopMacs the collection of mac addresses of next hops
     * @param deviceId    the device where the group will be installed
     * @return a SELECT group
     */
    // ONOS里的SELECT groups等同于P4Runtime里的Action selector groups
    // 创建了selector里的groupId与actions的对应关系。table里只有一个action，这个action带上不同的参数("dmac")就成为了不同的member。
    // 这样一个group里就有多个member,可以实现负载均衡。

//     		这里会创建一个group，该group有多个actions，每个actions的参数是dmac(具体场景里，也就是下一跳路由器的MAC地址）。group本身是没有selector的，可以把group看成是一个特殊的treatment。在创建flowrule的时候，把其中的treatment用group来代替。
// 		这里的action仅仅是替换了以太网包的目的MAC地址。
// 后面的l2_table还会根据目的MAC地址来替换为具体的端口。

    private GroupDescription createNextHopGroup(int groupId,
                                                Collection<MacAddress> nextHopMacs,
                                                DeviceId deviceId) {

        String actionProfileId = "IngressPipeImpl.ecmp_selector";

        final List<PiAction> actions = Lists.newArrayList();

        // Build one "set next hop" action for each next hop
        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        final String tableId = "IngressPipeImpl.routing_v6_table";
        for (MacAddress nextHopMac : nextHopMacs) {
            final PiAction action = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_next_hop"))
                    .withParameter(new PiActionParam(
                            // Action param name.
                            PiActionParamId.of("dmac"),
                            // Action param value.
                            nextHopMac.toBytes()))
                    .build();

            //actions会转化成为group里的buckets
            actions.add(action);
        }

        return Utils.buildSelectGroup(
                deviceId, tableId, actionProfileId, groupId, actions, appId);
    }

    /**
     * Creates a routing flow rule that matches on the given IPv6 prefix and
     * executes the given group ID (created before).
    //这里是创建一个flowRule，但是该flowRule的action/treatment是指向一个groupID的。
    // 也就是说如果匹配了相应的条件，那么具体的动作要由group里的bucket来决定（select的话就用group中的多个bucket中的一个来反应，可以实现负载均衡等）
     *
     * @param deviceId  the device where flow rule will be installed
     * @param ip6Prefix the IPv6 prefix
     * @param groupId   the group ID
     * @return a flow rule
     */
    private FlowRule createRoutingRule(DeviceId deviceId, Ip6Prefix ip6Prefix,
                                       int groupId) {

        // *** TODO EXERCISE 5
        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        final String tableId = "IngressPipeImpl.routing_v6_table";
        final PiCriterion match = PiCriterion.builder()
                .matchLpm(
                        PiMatchFieldId.of("hdr.ipv6.dst_addr"),
                        ip6Prefix.address().toOctets(),
                        ip6Prefix.prefixLength())
                .build();
        //这里的action为什么是groupID，而不是set_L2_next_hop。
        // 是把匹配本entry的直接送给action profile selector里的group，而该group前面已经建立了相应的member(也就是action set_l2_next_hop带上参数dmac)

        //下面用的是PiTableAction，而不是PiAction
        //这里就是把group当成了flowrule的action/treatment
        final PiTableAction action = PiActionProfileGroupId.of(groupId);

        return Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
    }



    //TODO:一个port下可以挂多个主机。这种情形要怎么处理？目前这里处理的主要是下一跳路由器的MAC地址，暂时不用考虑。
    private FlowRule createPortToSationMacRule(DeviceId deviceId, MacAddress nexthopMac,
                                         PortNumber outPort) {

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        final String tableId = "IngressPipeImpl.port_to_nextStationMac_table";
        final PiCriterion match = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("standard_metadata.egress_spec"),
                        outPort.toLong())
                .build();


        final PiAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_nextStation_Mac"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("dmac"),
                        nexthopMac.toBytes()))
                .build();

        return Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
    }

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of host events which triggers configuration of routing rules on
     * the device where the host is attached.
     */
    class InternalHostListener implements HostListener {

        //switch case 执行时，一定会先进行匹配，匹配成功返回当前 case 的值，再根据是否有 break，判断是否继续输出，或是跳出判断。
        //为什么host_added后就break了呢？break后会处理。
        //那么下面的三条应该也是会处理的。“如果 case 语句块中没有 break 语句时，匹配成功后，从当前 case 开始，后续所有 case 的值都会输出。“那么遇到下面3个事件，最好也是return false.等于不处理。
        @Override
        public boolean isRelevant(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                    break;
                case HOST_REMOVED:
                case HOST_UPDATED:
                case HOST_MOVED:
                default:
                    // Ignore other events.
                    // Food for thoughts:
                    // how to support host moved/removed events?
                    return false;
            }
            // Process host event only if this controller instance is the master
            // for the device where this host is attached.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(HostEvent event) {
            Host host = event.subject();
            DeviceId deviceId = host.location().deviceId();
            mainComponent.getExecutorService().execute(() -> {
                log.info("{} event! host={}, deviceId={}, port={}",
                        event.type(), host.id(), deviceId, host.location().port());
                //在这里主动加入主机路由，而不是被动加入的。
                host.ipAddresses()
                        .stream()
                        .filter(IpAddress::isIp6)
                        .map(IpAddress::getIp6Address)
                        .forEach(intentReactiveForwarding::buildLocalRouteForHost);
            });
        }
    }

    /**
     * Listener of link events, which triggers configuration of routing rules to
     * forward packets across the fabric, i.e. from leaves to spines and vice
     * versa.
     * <p>
     * Reacting to link events instead of device ones, allows us to make sure
     * all device are always configured with a topology view that includes all
     * links, e.g. modifying an ECMP group as soon as a new link is added. The
     * downside is that we might be configuring the same device twice for the
     * same set of links/paths. However, the ONOS core treats these cases as a
     * no-op when the device is already configured with the desired forwarding
     * state (i.e. flows and groups)
     */
    class InternalLinkListener implements LinkListener {

        @Override
        public boolean isRelevant(LinkEvent event) {
            switch (event.type()) {
                case LINK_ADDED:
                case LINK_REMOVED:
                    break;
                case LINK_UPDATED:
                default:
                    // Ignore other events.
                    // Food for thoughts: how to support host moved/removed?
                    return false;
            }
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();
            return mastershipService.isLocalMaster(srcDev) ||
                    mastershipService.isLocalMaster(dstDev);
        }

        @Override
        public void event(LinkEvent event) {
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();

            if (mastershipService.isLocalMaster(srcDev)) {
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event! Configuring {}... linkSrc={}, linkDst={}",
                            event.type(), srcDev, srcDev, dstDev);

                    switch (event.type()) {
                        case LINK_REMOVED:
                            List<GroupId> specificGroups=Collections.emptyList();
                            //TODO:不知道有什么更好的方法，等待一个普通函数的执行完毕，再去执行下一条。
                            try {
                                deleteGroupbucketOrAndFlowrules(event.subject(),specificGroups,true);
                                Thread.sleep(200);
//                            log.info("I am here!");
                            } catch (Exception e) {
                                e.printStackTrace();
                            }

//                        log.info("I am here now again");
                            //有一次发现有错。居然建立了一条经过刚刚linkdown的path。是因为topology还没有及时更新的缘故吗？
                            //TODO：那么平常要如何去发现一些错误的path，也就是该path路过了downlink?可能要写个函数来处理。
                            //TODO:这样会建立起来一些次优的路径。
                            intentReactiveForwarding.buildSinglePathForSW(srcDev,dstDev);
                            break;
                        case LINK_ADDED:
                            intentReactiveForwarding.buildSinglePathForSW(srcDev,dstDev);
//                            setupFullMeshRouting();
                            break;
                        default:
                            log.warn("Unknown link event {}", event.type());
                    }
                });
            }

//            if (mastershipService.isLocalMaster(dstDev)) {
//                mainComponent.getExecutorService().execute(() -> {
//                    log.info("{} event! Configuring {}... linkSrc={}, linkDst={}",
//                            event.type(), dstDev, srcDev, dstDev);
//                });
//            }

        }
    }

    // 生成某一个link上面的group buckets,根据link的源端所在的srcDev, link所在的port，link的对端的设备的MAC地址
    private GroupBuckets getRelatedGroupBuckets(Link influencedLink){
        DeviceId srcDev = influencedLink.src().deviceId();
        DeviceId dstDev = influencedLink.dst().deviceId();

        PortNumber downPort=influencedLink.src().port();

        MacAddress peerSwMac = getMyStationMac(dstDev);
        Pair<PortNumber, MacAddress> dstPortMacPair = Pair.of(downPort, peerSwMac);
        Collection<Pair<PortNumber, MacAddress>> dstPortMacPairs = Collections.singleton(dstPortMacPair);

        return generateBucket(dstPortMacPairs, srcDev);
    }

    
    //这是个递归调用的函数。第一次调用是因为link down的event被调用（用firstOrNot来标记）。
    // 接下来会循着后退路径删除路由（先删除group中的对应bucket;如果group中没有了bucket，才会真正把路由对应的flowrule删除掉。）
    // 因为本APP有个设定条件，那就是整条path上的groupID是一致的，因此递归调用的时候会传递groupID。
    private void deleteGroupbucketOrAndFlowrules (Link influencedLink,List<GroupId> specificGroups,boolean firstOrNot){
        //influencedLink可以是downlink，也可以不是downlink。第一次是downlink，后续的就不是。
        DeviceId srcDev = influencedLink.src().deviceId();
//        DeviceId dstDev = influencedLink.dst().deviceId();

        GroupBuckets groupBuckets=getRelatedGroupBuckets(influencedLink);

        List<Group> toDealGroups = stream(groupService.getGroups(srcDev, appId))
                .filter(group -> group.buckets().buckets().containsAll(groupBuckets.buckets()))
                .filter(group -> {
                    if(!firstOrNot) {return specificGroups.contains(group.id());}
                    else return true;
                })
                .collect(Collectors.toList());

        for (Group group : toDealGroups) {
            //removeGroup会报错.action_profile是在P4交换机上的，没法删除，也不应该被删除。
            // Unable to DELETE action profile group on device:r3:
            // OTHER_ERROR UNKNOWN Error when deleting group on target (:2)
            // [PiActionProfileGroupHandle{deviceId=device:r3, actionProfile=IngressPipeImpl.multipaths_selector, groupId=25174435}]
            //由于removeBucketsFromGroup要花很长的时间。所以在删除最后一条bucket前,就要判断bucket是否剩下最后一条。
            // 没法等到删除后再判断bucket数是否为0.
            //group不存在了以后，原先指向该group的flow还存在，所以删除group是没有意义的。
            if (group.buckets().buckets().size() == 1) {
                log.info("delete the LAST bucket on {} in group :{} ",srcDev, group.id().toString());
                groupService.removeBucketsFromGroup(srcDev, group.appCookie(), groupBuckets, group.appCookie(), appId);

                //当group中的bucket数量为0后，说明无路可走了。这个时候必须删除对应该group的flowrules，
                // 否则由于该flowrules的存在，P4交换机不会把原先路由指向该group的数据包上传给ONOS来分析。
                // 当数据包重新上传给ONOS后，ONOS会重新建立路由条目。
                //某个具体的例子： instruction type is PROTOCOL_INDEPENDENT , instruction: GROUP:0x18021a7
                getRelatedFlows(group.id(), srcDev).stream().forEach(flowRule -> {
                    log.info("delete the flowrules on {} which mapped to the group :{} ", srcDev, group.id().toString());
                    flowRuleService.removeFlowRules(flowRule);
                });
                //getRelatedFlows(group.id(),srcDev).stream().forEach(flowRuleService::removeFlowRules);


                //先找还有哪些活动的connectionPoint。接着找到link对端的路由器。
                // 到Link对端的路由器上寻找有没有groupID为特定值的group(参数1);
                // 如果有，在该group里面删除与relatedport(就是link一头所在的port)相关的bucket;
                // 删除bucket过后，如果group里没有了bucket，要把映射到该group的flowrule也一起删除掉。并且接着递归本函数。
                // 删除bucket过后，如果group里还有bucket，则不再继续了。
                linkService.getDeviceIngressLinks(srcDev).stream().filter(link -> link.state().equals(Link.State.ACTIVE))
                        .filter(otherlink -> !otherlink.equals(influencedLink))
                        .forEach(dealLink -> deleteGroupbucketOrAndFlowrules(dealLink,Collections.singletonList(group.id()),false)
                );

                //TODO:为了快速重路由，需要在拆除path之后（记得要在之后！），重新根据flowrule里的selector来重新构建路由。
                // 当R1-R3的链路中断的时候，R3会创建一条到R1的path: R3,R4,R1；
                // 之后R1-R3的链路恢复后，R5会创建一条到R1的path，经过R3, R5->R3->R1。
                // 那么从R3到R1就会有2个path，不是等cost的。这个要怎么优化呢？
                //TODO：怎么避免大的环路。


            } else {
                groupService.removeBucketsFromGroup(srcDev, group.appCookie(), groupBuckets, group.appCookie(), appId);
            }
        }

        //                                try {
//                                    Thread.sleep(10000);
//                                } catch (InterruptedException e) {
//                                    log.error("Interrupted!", e);
//                                    Thread.currentThread().interrupt();
//                                }

//                        stream(groupService.getGroups(srcDev,appId))
//                                .filter(group -> {
//                                   return group.buckets().buckets().stream()
//                                            .map(groupBucket -> groupBucket.treatment().allInstructions())
//                                            .flatMap(instructions -> instructions.stream())
//                                            .filter(instruction -> instruction.type().equals(Instruction.Type.OUTPUT))
//                                            .map(i -> (OutputInstruction) i)
//                                            .anyMatch(outputInstruction -> outputInstruction.port().equals(event.subject().src().port())); } )
//                                .forEach(group -> {log.info("Hit hit group :{}",group.toString());});

//                        stream(groupService.getGroups(srcDev,appId)).forEach(group ->
//                                        group.buckets().buckets().stream().forEach(groupBucket ->
//                                            groupBucket.treatment().immediate().stream().forEach(instruction ->
//                                                    {log.info("Hit group :{} , type: {} ",instruction.toString(),instruction.type());}
//                                                    )
//                                                )
//                                             );
//                                .filter(group -> {
//                                    return group.buckets().buckets().stream()
//                                            .map(groupBucket -> groupBucket.treatment().allInstructions())
//                                            .flatMap(instructions -> instructions.stream())
//                                            .filter(instruction -> instruction.type().equals(Instruction.Type.OUTPUT))
//                                            .map(i -> (OutputInstruction) i)
//                                            .anyMatch(outputInstruction -> outputInstruction.port().equals(event.subject().src().port())); } )
//                                .forEach(group -> {log.info("Hit hit group :{}",group.toString());});
    }

    private Set<FlowRule> getRelatedFlows(GroupId groupId,DeviceId srcDev) {
        //虽然是指向group的。但不是Instruction.Type.GROUP，而是PROTOCOL_INDEPENDENT
        //所以不能直接用.filter(inst -> inst.type() == Instruction.Type.GROUP)来过滤。
        // 因为要找的flowrule的action是指向group的，所以action就是groupId
        final PiTableAction action = PiActionProfileGroupId.of(groupId.id());

        //第一种方法
//        TrafficTreatment trafficTreatment =DefaultTrafficTreatment.builder().piTableAction(action).build();

//        return stream(flowRuleService.getFlowEntries(srcDev))
//                .filter(flowRule -> flowRule.treatment().equals(trafficTreatment))
//                .collect(Collectors.toSet());

        //第二种方法。应该优先使用第二种方法。
        return stream(flowRuleService.getFlowEntries(srcDev))
                .filter(flowRule ->
                    flowRule.treatment().allInstructions().stream()
                            .filter(instruction -> instruction.type().equals(Instruction.Type.PROTOCOL_INDEPENDENT))
                            .map(instruction -> (PiInstruction) instruction)
                            .anyMatch(piInstruction -> piInstruction.action().equals(action)))
                .collect(Collectors.toSet());


//        //TODO：为什么下面的data()会引用不了呢？pom里面缺乏了对一部分denpendency的使用？
//        StreamSupport.stream(flowRuleService.getFlowEntries(
//                data().deviceId()).spliterator(), false)
//                .filter(f -> f.table().type() == TableId.Type.PIPELINE_INDEPENDENT)
//                .filter(f -> TABLES_TO_CLEANUP.contains((PiTableId) f.table()))
//                .forEach(flowRuleService::removeFlowRules);
    }

    //下面这个函数的大部分内容与IntentReactiveForwarding里的是一样的。
    // 考虑下要怎么复用，以便保持一致。两者紧密相关，也必须保持一致。
    private GroupBuckets generateBucket( Collection<Pair<PortNumber,MacAddress>> dstPortMacPairs,
                                        DeviceId deviceId) {

        String actionProfileId = "IngressPipeImpl.multipaths_selector";

        final List<PiAction> actions = Lists.newArrayList();

        final String tableId = "IngressPipeImpl.v6routing_table";
        for (Pair<PortNumber,MacAddress> pair : dstPortMacPairs) {
            final PiAction action = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_output"))
                    .withParameter(new PiActionParam(
                            PiActionParamId.of("port_num"),
                            pair.getLeft().toLong()))
                    .withParameter(new PiActionParam(
                            PiActionParamId.of("dmac"),
                            pair.getRight().toBytes()))
                    .build();

            actions.add(action);
        }

        final List<GroupBucket> buckets = actions.stream()
                .map(action -> DefaultTrafficTreatment.builder()
                        .piTableAction(action).build())
                .map(DefaultGroupBucket::createSelectGroupBucket)
                .collect(Collectors.toList());

        return new GroupBuckets(buckets);

//        //先判断是否有该group的存在。
//        //下面的groupKey的生成方式要与Utils.buildSelectGroup里的保持一致才可以。
//        final GroupKey groupKey = new PiGroupKey(
//                PiTableId.of(tableId), PiActionProfileId.of(actionProfileId), groupId);
//
//        Optional<GroupDescription> optGroup =Optional.ofNullable(groupService.getGroup(deviceId,groupKey));
//
//
//
//        //如果有该group存在，那么就增加bucket。否则会覆盖原有的group，导致该group下原有的bucket消失掉。
//        //如果没有该group存在，那么就创建。
//        if(optGroup.isPresent()){
//            final List<GroupBucket> buckets = actions.stream()
//                    .map(action -> DefaultTrafficTreatment.builder()
//                            .piTableAction(action).build())
//                    .map(DefaultGroupBucket::createSelectGroupBucket)
//                    .collect(Collectors.toList());
//
//            groupService.addBucketsToGroup(deviceId,groupKey,new GroupBuckets(buckets),groupKey,appId);
//            return optGroup.get();
//        }else{
//            return Utils.buildSelectGroup(
//                    deviceId, tableId, actionProfileId, groupId, actions, appId);
//        }
    }

    /**
     * Listener of device events which triggers configuration of the My Station
     * table.
     */
    class InternalDeviceListener implements DeviceListener {

        @Override
        public boolean isRelevant(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_AVAILABILITY_CHANGED:
                case DEVICE_ADDED:
                    break;
                default:
                    return false;
            }
            // Process device event if this controller instance is the master
            // for the device and the device is available.
            DeviceId deviceId = event.subject().id();
            return mastershipService.isLocalMaster(deviceId) &&
                    deviceService.isAvailable(event.subject().id());
        }

        @Override
        public void event(DeviceEvent event) {
            mainComponent.getExecutorService().execute(() -> {
                DeviceId deviceId = event.subject().id();
                log.info("{} event! device id={}", event.type(), deviceId);
                setUpMyStationTable(deviceId);
                //TODO: setup route to all other device's SRv6 SID.
            });
        }
    }

    //--------------------------------------------------------------------------
    // ROUTING POLICY METHODS
    //
    // Called by event listeners, these methods implement the actual routing
    // policy, responsible of computing paths and creating ECMP groups.
    //--------------------------------------------------------------------------


    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------


    /**
     * Returns the MAC address configured in the "myStationMac" property of the
     * given device config.
     *
     * @param deviceId the device ID
     * @return MyStation MAC address
     */
    private MacAddress getMyStationMac(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::myStationMac)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing myStationMac config for " + deviceId));
    }

    /**
     * Returns the FabricDeviceConfig config object for the given device.
     *
     * @param deviceId the device ID
     * @return FabricDeviceConfig device config
     */
    private Optional<FabricDeviceConfig> getDeviceConfig(DeviceId deviceId) {
        FabricDeviceConfig config = networkConfigService.getConfig(
                deviceId, FabricDeviceConfig.class);
        return Optional.ofNullable(config);
    }

    /**
     * Returns the set of interface IPv6 subnets (prefixes) configured for the
     * given device.
     *
     * @param deviceId the device ID
     * @return set of IPv6 prefixes
     */
    private Set<Ip6Prefix> getInterfaceIpv6Prefixes(DeviceId deviceId) {
        return interfaceService.getInterfaces().stream()
                .filter(iface -> iface.connectPoint().deviceId().equals(deviceId))
                .map(Interface::ipAddressesList)
                .flatMap(Collection::stream)
                .map(InterfaceIpAddress::subnetAddress)
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .collect(Collectors.toSet());
    }

    /**
     * Returns a 32 bit bit group ID from the given MAC address.
     *
     * @param mac the MAC address
     * @return an integer
     */
    private int macToGroupId(MacAddress mac) {
        return mac.hashCode() & 0x7fffffff;
    }

    /**
     * Inserts the given groups and flow rules in order, groups first, then flow
     * rules. In P4Runtime, when operating on an indirect table (i.e. with
     * action selectors), groups must be inserted before table entries.
     *
     * @param group     the group
     * @param flowRules the flow rules depending on the group
     */
    //  因为这里的flowRules依赖于group，所以要先安装group
    private void insertInOrder(GroupDescription group, Collection<FlowRule> flowRules) {
        try {
            groupService.addGroup(group);
            // Wait for groups to be inserted.
            Thread.sleep(GROUP_INSERT_DELAY_MILLIS);
            flowRules.forEach(flowRuleService::applyFlowRules);
        } catch (InterruptedException e) {
            log.error("Interrupted!", e);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Gets Srv6 SID for the given device.
     *
     * @param deviceId the device ID
     * @return SID for the device
     */
    private Ip6Address getDeviceSid(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::mySid)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing mySid config for " + deviceId));
    }

    private void setupFullMeshRouting(){
        List<DeviceId> allDevice =
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .collect(Collectors.toList());

        for (DeviceId srcDev: allDevice) {
            for (DeviceId dstDev: allDevice) {
                if(!srcDev.equals(dstDev)){
                    intentReactiveForwarding.buildSinglePathForSW(srcDev,dstDev);
                }
            }
        }

    }

    /**
     * Sets up IPv6 routing on all devices known by ONOS and for which this ONOS
     * node instance is currently master.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        try {
            stream(deviceService.getAvailableDevices())
                    .map(Device::id)
                    .filter(mastershipService::isLocalMaster)
                    .forEach(deviceId -> {
                        //log.info("*** IPV6 ROUTING - Starting initial set up for {}...", deviceId);
                        //以太网目标地址是本设备的MAC地址，则不执行任何操作。
                        setUpMyStationTable(deviceId);
                    });
            Thread.sleep(200);
        } catch (Exception e) {
            e.printStackTrace();
        }
//        setupFullMeshRouting();
    }

    //  ===废弃函数=====

    /**
     * Set up L2 nexthop rules of a device to providing forwarding inside the
     * fabric, i.e. between leaf and spine switches.
     *
     * @param deviceId the device ID
     */
    private void setUpL2NextHopRules(DeviceId deviceId) {

        Set<Link> egressLinks = linkService.getDeviceEgressLinks(deviceId);

        for (Link link : egressLinks) {
            // For each other switch directly connected to this.
            final DeviceId nextHopDevice = link.dst().deviceId();
            // Get port of this device connecting to next hop.
            final PortNumber outPort = link.src().port();
            // Get next hop MAC address.
            final MacAddress nextHopMac = getMyStationMac(nextHopDevice);

            final FlowRule nextHopRule = createL2NextHopRule(
                    deviceId, nextHopMac, outPort);

            flowRuleService.applyFlowRules(nextHopRule);
        }
    }

    private void setUpPortToMacForRouterRules(DeviceId deviceId) {

        Set<Link> egressLinks = linkService.getDeviceEgressLinks(deviceId);


        for (Link link : egressLinks) {
            // For each other switch directly connected to this.
            final DeviceId nextHopDevice = link.dst().deviceId();
            // Get port of this device connecting to next hop.
            final PortNumber outPort = link.src().port();
            // Get next hop MAC address.
            final MacAddress nextHopMac = getMyStationMac(nextHopDevice);

            final FlowRule nextHopRule = createPortToSationMacRule(
                    deviceId, nextHopMac, outPort);

            flowRuleService.applyFlowRules(nextHopRule);
        }
    }

    private void setUpPortToMacForHostRules(DeviceId deviceId,Host host) {

        final FlowRule nextHopRule = createPortToSationMacRule(
                deviceId, host.mac(), host.location().port());

        flowRuleService.applyFlowRules(nextHopRule);
    }

    /**
     * Sets up the given device with the necessary rules to route packets to the
     * given host.
     *
     * @param deviceId deviceId the device ID
     * @param host     the host
     */
    //  如果host本身就在本device上面，那么这条路由的意义不够。要让所有的device都知道有这条路由才行。
    private void setUpHostRules(DeviceId deviceId, Host host) {

        // Get all IPv6 addresses associated to this host. In this tutorial we
        // use hosts with only 1 IPv6 address.
        //为什么只用一个IPv6地址？
        final Collection<Ip6Address> hostIpv6Addrs = host.ipAddresses().stream()
                .filter(IpAddress::isIp6)
                .map(IpAddress::getIp6Address)
                .collect(Collectors.toSet());

        if (hostIpv6Addrs.isEmpty()) {
            // Ignore.
            log.debug("No IPv6 addresses for host {}, ignore", host.id());
            return;
        } else {
            log.info("Adding routes on {} for host {} [{}]",
                    deviceId, host.id(), hostIpv6Addrs);
        }

        //group ID是由host MAC独立生成的
        //group里为什么只有一个member?如果只有一个member怎么平衡？这里的group应该是action selector里的group
        // Create an ECMP group with only one member, where the group ID is
        // derived from the host MAC.
        final MacAddress hostMac = host.mac();
        int groupId = macToGroupId(hostMac);

        //GroupDescription应该就是一组固定属性的不可变集合的一个描述，不同的属性的固定组合就形成了不同的group，是吧。ONOS里的group等同于P4里的action selector里的group。
        final GroupDescription group = createNextHopGroup(
                groupId, Collections.singleton(hostMac), deviceId);

        // Map each host IPV6 address to corresponding /128 prefix and obtain a
        // flow rule that points to the group ID. In this tutorial we expect
        // only one flow rule per host.
        //这里相当于ARP，所以必须是/128，但是底下哪里看到是128位？ .map(IpAddress::toIpPrefix)  //应该是这句，让IpPrefix和IP地址的长度一致了。
         // 128位那就是单个IP地址了。是有个带掩码的函数。
         //createRoutingRule这个函数为目的地为prefix的流量创建一条flowrules，该flowrule指向一个group（该group的id为groupId)
        final List<FlowRule> flowRules = hostIpv6Addrs.stream()
                .map(IpAddress::toIpPrefix)
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .map(prefix -> createRoutingRule(deviceId, prefix, groupId))
                .collect(Collectors.toList());

        // Helper function to install flows after groups, since here flows
        // points to the group and P4Runtime enforces this dependency during
        // write operations.
        // 这里的flows指向group，也就是这里的flowrules中的action是和groupID绑定到一起的。
        insertInOrder(group, flowRules);
    }

    //对于主机，建立主机IP和所在port的对应关系。
    private void setUpIPtoPortForHostRule(DeviceId deviceId, Host host) {

        // Get all IPv6 addresses associated to this host. In this tutorial we
        // use hosts with only 1 IPv6 address.
        final Collection<Ip6Address> hostIpv6Addrs = host.ipAddresses().stream()
                .filter(IpAddress::isIp6)
                .map(IpAddress::getIp6Address)
                .collect(Collectors.toSet());

        if (hostIpv6Addrs.isEmpty()) {
            // Ignore.
            log.debug("No IPv6 addresses for host {}, ignore", host.id());
            return;
        } else {
            log.info("Adding Host route on {} for host {} [{}]",
                    deviceId, host.id(), hostIpv6Addrs);
        }

        // Create an ECMP group with only one member, where the group ID is
        // derived from the host MAC.
        final MacAddress hostMac = host.mac();
        int groupId = macToGroupId(hostMac);

        PortNumber port =host.location().port();

        GroupDescription group = createNextHopsGroup(
                groupId, Collections.singleton(port), deviceId);

        // Map each host IPV6 address to corresponding /128 prefix and obtain a
        // flow rule that points to the group ID. In this tutorial we expect
        // only one flow rule per host.
        final List<FlowRule> flowRules = hostIpv6Addrs.stream()
                .map(IpAddress::toIpPrefix)
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .map(prefix -> createAnRoutingRule(deviceId, prefix, groupId))
                .collect(Collectors.toList());

        // Helper function to install flows after groups, since here flows
        // points to the group and P4Runtime enforces this dependency during
        // write operations.
        insertInOrder(group, flowRules);
    }

    /**
     * Set up routes on a given device to forward packets across the fabric,
     * making a distinction between spines and leaves.
     *
     * @param deviceId the device ID.
     */
    private void setUpFabricRoutes(DeviceId deviceId) {
        if (isSpine(deviceId)) {
            setUpSpineRoutes(deviceId);
        } else {
            setUpLeafRoutes(deviceId);
        }
    }

    /**
     * Insert routing rules on the given spine switch, matching on leaf
     * interface subnets and forwarding packets to the corresponding leaf.
     *
     * @param spineId the spine device ID
     */
    private void setUpSpineRoutes(DeviceId spineId) {

        log.info("Adding up spine routes on {}...", spineId);

        for (Device device : deviceService.getDevices()) {

            if (isSpine(device.id())) {
                // We only need routes to leaf switches. Ignore spines.
                continue;
            }

            final DeviceId leafId = device.id();
            final MacAddress leafMac = getMyStationMac(leafId);
            final Set<Ip6Prefix> subnetsToRoute = getInterfaceIpv6Prefixes(leafId);

            // Since we're here, we also add a route for SRv6 (Exercise 7), to
            // forward packets with IPv6 dst the SID of a leaf switch.
            final Ip6Address leafSid = getDeviceSid(leafId);
            subnetsToRoute.add(Ip6Prefix.valueOf(leafSid, 128));

            // Create a group with only one member.
            int groupId = macToGroupId(leafMac);

            //这里才真正去创建一个group，该group的group ID来自于MAC。参数为该MAC地址段actions作为该group的members
            GroupDescription group = createNextHopGroup(
                    groupId, Collections.singleton(leafMac), spineId);

            //这里相当于创建table里的entry . 让entry和groupID关联起来。这样一旦匹配到entry(这里是subnetsToRoute，就是leaf交换机上的接口的IPv6地址段),就指向到该group
            List<FlowRule> flowRules = subnetsToRoute.stream()
                    .map(subnet -> createRoutingRule(spineId, subnet, groupId))
                    .collect(Collectors.toList());

            insertInOrder(group, flowRules);
        }
    }

    /**
     * Insert routing rules on the given leaf switch, matching on interface
     * subnets associated to other leaves and forwarding packets the spines
     * using ECMP.
     *
     * @param leafId the leaf device ID
     */
    private void setUpLeafRoutes(DeviceId leafId) {
        log.info("Setting up leaf routes: {}", leafId);

        // Get the set of subnets (interface IPv6 prefixes) associated to other
        // leafs but not this one.
        Set<Ip6Prefix> subnetsToRouteViaSpines = stream(deviceService.getDevices())
                .map(Device::id)
                .filter(this::isLeaf)
                .filter(deviceId -> !deviceId.equals(leafId))
                .map(this::getInterfaceIpv6Prefixes)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());

        // Get myStationMac address of all spines.
        Set<MacAddress> spineMacs = stream(deviceService.getDevices())
                .map(Device::id)
                .filter(this::isSpine)
                .map(this::getMyStationMac)
                .collect(Collectors.toSet());

        // Create an ECMP group to distribute traffic across all spines.
        final int groupId = DEFAULT_ECMP_GROUP_ID;
        final GroupDescription ecmpGroup = createNextHopGroup(
                groupId, spineMacs, leafId);

        // Generate a flow rule for each subnet pointing to the ECMP group.
        List<FlowRule> flowRules = subnetsToRouteViaSpines.stream()
                .map(subnet -> createRoutingRule(leafId, subnet, groupId))
                .collect(Collectors.toList());

        insertInOrder(ecmpGroup, flowRules);

        // Since we're here, we also add a route for SRv6 (Exercise 7), to
        // forward packets with IPv6 dst the SID of a spine switch, in this case
        // using a single-member group.
        stream(deviceService.getDevices())
                .map(Device::id)
                .filter(this::isSpine)
                .forEach(spineId -> {
                    MacAddress spineMac = getMyStationMac(spineId);
                    Ip6Address spineSid = getDeviceSid(spineId);
                    int spineGroupId = macToGroupId(spineMac);
                    GroupDescription group = createNextHopGroup(
                            spineGroupId, Collections.singleton(spineMac), leafId);
                    FlowRule routingRule = createRoutingRule(
                            leafId, Ip6Prefix.valueOf(spineSid, 128),
                            spineGroupId);
                    insertInOrder(group, Collections.singleton(routingRule));
                });
    }


    /**
     * Returns true if the given device has isSpine flag set to true in the
     * config, false otherwise.
     *
     * @param deviceId the device ID
     * @return true if the device is a spine, false otherwise
     */
    private boolean isSpine(DeviceId deviceId) {
        return getDeviceConfig(deviceId).map(FabricDeviceConfig::isSpine)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing isSpine config for " + deviceId));
    }

    /**
     * Returns true if the given device is not configured as spine.
     *
     * @param deviceId the device ID
     * @return true if the device is a leaf, false otherwise
     */
    private boolean isLeaf(DeviceId deviceId) {
        return !isSpine(deviceId);
    }

    /**
     * Creates a flow rule for the L2 table mapping the given next hop MAC to
     * the given output port.
     * <p>
     * This is called by the routing policy methods below to establish L2-based
     * forwarding inside the fabric, e.g., when deviceId is a leaf switch and
     * nextHopMac is the one of a spine switch.
     *
     * @param deviceId   the device
     * @param nexthopMac the next hop (destination) mac
     * @param outPort    the output port
     */
    private FlowRule createL2NextHopRule(DeviceId deviceId, MacAddress nexthopMac,
                                         PortNumber outPort) {

        // *** TODO EXERCISE 5
        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        final String tableId = "IngressPipeImpl.l2_exact_table";
        final PiCriterion match = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        nexthopMac.toBytes())
                .build();


        final PiAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_egress_port"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("port_num"),
                        outPort.toLong()))
                .build();
        // ---- END SOLUTION ----

        return Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
    }

    //这里的nextHops和前面的nextHop不同。这里的nextHops是指向port的，而不是指向MAC地址的。
    private GroupDescription createNextHopsGroup(int groupId,
                                                 Collection<PortNumber> portToNextHops,
                                                 DeviceId deviceId) {

        String actionProfileId = "IngressPipeImpl.multipath_selector";

        final List<PiAction> actions = Lists.newArrayList();


        final String tableId = "IngressPipeImpl.v6_routing_table";
        for (PortNumber port : portToNextHops) {
            final PiAction action = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_output_port"))
                    .withParameter(new PiActionParam(
                            // Action param name.
                            PiActionParamId.of("port_num"),
                            // Action param value.
                            port.toLong()))
                    .build();

            actions.add(action);
        }


        return Utils.buildSelectGroup(
                deviceId, tableId, actionProfileId, groupId, actions, appId);
    }

    private FlowRule createAnRoutingRule(DeviceId deviceId, Ip6Prefix ip6Prefix,
                                         int groupId) {

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        final String tableId = "IngressPipeImpl.v6_routing_table";
        final PiCriterion match = PiCriterion.builder()
                .matchLpm(
                        PiMatchFieldId.of("hdr.ipv6.dst_addr"),
                        ip6Prefix.address().toOctets(),
                        ip6Prefix.prefixLength())
                .build();

        final PiTableAction action = PiActionProfileGroupId.of(groupId);

        return Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
    }

}

// 	    private synchronized void setUpAllDevices() {
// 	        // Set up host routes
// 	        stream(deviceService.getAvailableDevices())
// 	                .map(Device::id)
// 	                .filter(mastershipService::isLocalMaster)
// 	                .forEach(deviceId -> {
// 	                    log.info("*** IPV6 ROUTING - Starting initial set up for {}...", deviceId);
// 				//以太网目标地址是本设备的MAC地址，则不执行任何操作。
// 	                    setUpMyStationTable(deviceId);
// 				//在spine设备上添加到其他leaf设备的路由；在leaf设备上添加到其它leaf设备的路由。会先获取leaf设备上的所有interfaces的IP prefix路由段。类似于静态路由。
// 				//但是缺了从leaf到spine的路由呢，也缺了从spine到spine的路由呢。这个应该是由下面的函数来执行。
// 	                    setUpFabricRoutes(deviceId);
// 				//根据链路对端设备的MAC地址、链路这端的出端口。增加一条L2的规则。
// 	                    setUpL2NextHopRules(deviceId);
// 	                    hostService.getConnectedHosts(deviceId)
// 	                            .forEach(host -> setUpHostRules(deviceId, host));
// 	                });
//     }