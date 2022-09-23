/*
 * Copyright 2014 Open Networking Foundation
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
package com.cxc.ngsdn;


import com.google.common.collect.Lists;
//import org.aopalliance.reflect.CodeLocator;
import org.apache.commons.io.input.SwappedDataInputStream;
import org.apache.commons.lang3.tuple.Pair;
//import org.joda.time.Period;
import org.onlab.graph.ScalarWeight;
import org.onlab.packet.*;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.util.ItemNotFoundException;
//import org.onosproject.inbandtelemetry.api.IntService;
import org.onosproject.net.*;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.*;
//import org.onosproject.net.host.HostProbingService;
import org.onosproject.net.host.*;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkAdminService;
import org.onosproject.net.pi.model.*;
import org.onosproject.net.pi.runtime.*;
import org.onosproject.net.topology.Topology;
import com.cxc.ngsdn.common.FabricDeviceConfig;
import com.cxc.ngsdn.common.Utils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.IntentState;
import org.onosproject.net.intent.Key;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
//import org.onosproject.inbandtelemetry.impl.SimpleIntManager;
//import  org.onosproject.inbandtelemetry.api.IntService;
import org.slf4j.Logger;
//import shaded.org.apache.maven.model.Organization;
import org.onosproject.net.host.HostAdminService;
import org.onosproject.net.host.HostProviderRegistry;

//import javax.validation.metadata.ReturnValueDescriptor;
import javax.print.attribute.standard.Sides;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Streams.forEachPair;
import static com.google.common.collect.Streams.stream;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * WORK-IN-PROGRESS: Sample reactive forwarding application using intent framework.
 */
@Component(immediate = true,
        service = IntentReactiveForwarding.class,
        enabled = true
)
public class IntentReactiveForwarding {

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostProbingService hostProbingService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private EdgePortService edgePortService;

//    private IntService intService;
//    private SimpleIntManager simpleIntManager =new SimpleIntManager();

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    private ApplicationId appId;

    private static final int DROP_RULE_TIMEOUT = 300;
    private static final long GROUP_INSERT_DELAY_MILLIS = 200;


    //private HostManager hostManager;

    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
            IntentState.WITHDRAWING,
            IntentState.WITHDRAW_REQ);

    @Activate
    public void activate() {
        appId = mainComponent.getAppId();

        packetService.addProcessor(processor, PacketProcessor.director(2));

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        //selector.matchEthType(Ethernet.TYPE_IPV4);
        // 意味着只处理v6的数据包吧。
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("ReactiveForwrding Started");

    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(processor);
        processor = null;
        log.info("ReactiveForwarding Stopped");
    }


    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            // Bail if this is deemed to be a control packet.
            // Skip IPv6 multicast packet when IPv6 forward is disabled.
            if (isControlPacket(ethPkt) || isIpv6Multicast(ethPkt)) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {

                IPv6 iPv6Packet = (IPv6) ethPkt.getPayload();

                Ip6Address dstIp6Addr = Ip6Address.valueOf(iPv6Packet.getDestinationAddress());

                DeviceId srcDeviceId = context.inPacket().receivedFrom().deviceId();
                buildPathForHost(dstIp6Addr,srcDeviceId);
                log.info("IntentReactiveForwarding Received IPv6 packet from deice {}", srcDeviceId);
            }

            context.block();
            //TODO: context.send()会带来mapTreatment，需要研究下。
            //context.send();

             /*
            //TODO:没有把包发送出去的话，首包是不是就被丢弃了呢？
            forwardPacketToDst(context, dst);
                 */
        }

    }

    //=========路由建立相关的函数============

    //TODO:需要对代码进行改造。把setup path和insert flowrule分离开，而不是纠缠在一起。
    // 可能难以分离。后面再研究分离的方法。
    // 要考虑改动为是对Ip prefix的支持，而不仅仅是对单IP的支持。
    protected void buildPathForHost(Ip6Address dstIp6Addr,DeviceId srcDeviceId ){
        List<Ip6Address> dstIp6Address = Collections.singletonList(dstIp6Addr);
        List<Ip6Prefix> dstIp6Prefixes = Collections.emptyList();

        log.info("Search paths for {} on {}", dstIp6Addr, srcDeviceId);

        getLocationOfHost(dstIp6Addr)
                .ifPresent(dstDeviceId -> buildRoutingTable(dstIp6Address, dstIp6Prefixes, srcDeviceId, dstDeviceId));
    }

    protected void buildPathForSubnet(Ip6Prefix dstIp6Prefix,DeviceId srcDeviceId ){
        List<Ip6Address> dstIp6Address = Collections.emptyList();
        List<Ip6Prefix> dstIp6Prefixes = Collections.singletonList(dstIp6Prefix);

        getLocationOfSubnet(dstIp6Prefix)
                .ifPresent(dstDeviceId -> buildRoutingTable(dstIp6Address, dstIp6Prefixes, srcDeviceId, dstDeviceId));
    }

    //只是在srcDevice和dstDevice之间建立单边路径。安装的路由表为dstDevice上面的subnets，同时包括Srv6 SID。
    protected void buildSinglePathForSW(DeviceId srcDeviceId,DeviceId dstDeviceId ){
        List<Ip6Address> dstIp6Address = Collections.emptyList();

        List<Ip6Prefix> dstIp6Prefixes =
                interfaceService.getInterfaces().stream()
                        .filter(iface -> iface.connectPoint().deviceId().equals(dstDeviceId))
                        .map(Interface::ipAddressesList)
                        .flatMap(Collection::stream)
                        .map(InterfaceIpAddress::subnetAddress)
                        .filter(IpPrefix::isIp6)
                        .map(IpPrefix::getIp6Prefix)
                        .collect(Collectors.toList());

        //cxc:Adding support to Srv6. add  SID to route.
        final Ip6Address deviceSid = getDeviceSid(dstDeviceId);
        dstIp6Prefixes.add(Ip6Prefix.valueOf(deviceSid, 128));

        buildRoutingTable(dstIp6Address, dstIp6Prefixes, srcDeviceId, dstDeviceId);
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

    private void buildRoutingTable(List<Ip6Address> dstIp6Address,List<Ip6Prefix> dstIp6Prefixes,DeviceId srcDeviceId,DeviceId dstDeviceId){
        // 目标设备和源设备相同，就建立两个设备之间的路径；否则，就建立本地路由表。
        if (!srcDeviceId.equals(dstDeviceId)) {
            //setUpConnectivityBetweenDevice(dstIp6Addr, srcDeviceId, dstDeviceId);
            //setupConBetweenDevicesViaPort(dstIp6Addr,srcDeviceId,dstDeviceId);
//                List<Ip6Address> dstIp6Address = Collections.singletonList(dstIp6Addr);
//                List<Ip6Prefix> dstIp6Prefixes = Collections.emptyList();
            setupPathBetweenSW(dstIp6Address,dstIp6Prefixes,srcDeviceId,dstDeviceId);
            log.info("Setup paths from {} to {} for IP:{} and IP subnets: {} ", srcDeviceId, dstDeviceId, dstIp6Address,dstIp6Prefixes);
        }else{
            //TODO: if  is mysid, will not setup localpath
            dstIp6Address.stream().forEach(dstIp6Addr -> {
                hostService.getHostsByIp(dstIp6Addr).stream()
                        .map(host -> Pair.of(host.location().port(),host.mac())).findFirst()
                        .ifPresentOrElse(portNumberMacAddressPair ->
                                        setupLocalRoute(dstIp6Addr,dstDeviceId,Collections.singleton(portNumberMacAddressPair)),
                                () -> probe(dstIp6Addr));
            // 本APP的路由表是指向port和对端的MAC地址的，因此这里有用到portNumberMacAddressPair
            // 如果找不到host，就要probe该IP的host
            });
        }
    }

    protected void buildLocalRouteForHost(Ip6Address dstIp6Address){
        getLocationOfHost(dstIp6Address).ifPresent( dstDeviceId ->
                hostService.getHostsByIp(dstIp6Address).stream()
                        .map(host -> Pair.of(host.location().port(),host.mac())).findFirst()
                        .ifPresentOrElse(portNumberMacAddressPair ->
                                        setupLocalRoute(dstIp6Address,dstDeviceId,Collections.singleton(portNumberMacAddressPair)),
                                () -> probe(dstIp6Address))
        );

    }



    private Optional<DeviceId>  getLocationOfHost(Ip6Address dstIp6Addr) {
        // Do we know who this is for? If not, Search for it.
        // Maybe the hosts has been sent its packet to network.
        // If so , hostService will konw it and its location.

        //TODO:后面要考虑有多个Interface的subnet能匹配的情形，
        // 这时候要判断谁的mask是最长的。可能不需要，因为main.p4里面的table是lpm匹配的。
        // 还有要考虑这些匹配上的interface可能位于多台设备上。要用一个overlay的subnet网段来测试.
        // 下面的可能返回空集。

        //cxc: Adding support to SRv6. SRv6 Sid is been regarded as a host.

        return hostService.getHostsByIp(dstIp6Addr).stream()
                .map(host -> host.location().deviceId())
                .findFirst()
                .or(() -> interfaceService.getMatchingInterfaces(dstIp6Addr)
                        .stream()
                        .map(anInterface -> anInterface.connectPoint().deviceId())
                        .findFirst())
                .or(() -> stream(deviceService.getAvailableDevices())
                            .map(Device::id)
                            .filter(id -> getDeviceSid(id).equals(dstIp6Addr))
                            .findFirst());

//        final Ip6Address deviceSid = getDeviceSid(dstDeviceId);
//        dstIp6Prefixes.add(Ip6Prefix.valueOf(deviceSid, 128));

        //下面.or的2种方法中其实只要选择一种就可以。
        //上面是对interface进行扫描，寻找匹配的；还有一种方法，是对device进行扫描，寻找匹配的。
//                    .or(() -> stream(deviceService.getAvailableDevices())
//                            .map(Device::id)
//                            .filter(dstdd -> isDstLocation(dstdd,dstIp6Addr))
//                            .findFirst())
    }

    protected Optional<DeviceId>  getLocationOfSubnet(Ip6Prefix dstIp6Prefix) {
        // Do we know who this is for? If not, Search for it.
        // Maybe the hosts has been sent its packet to network.
        // If so , hostService will konw it and its location.

        //TODO:后面要考虑有多个Interface的subnet能匹配的情形，也就是要返回一个列表。而不是随机某个最长的。
        // 这时候要判断谁的mask是最长的。可能不需要，因为main.p4里面的table是lpm匹配的。
        // 还有要考虑这些匹配上的interface可能位于多台设备上。要用一个overlay的subnet网段来测试.
        // 下面的可能返回空集。

        return  interfaceService.getInterfaces().stream()
                .filter(anInterface -> includeTheSubnetOrNot(anInterface, dstIp6Prefix))
                .map(anInterface -> anInterface.connectPoint().deviceId())
                .findFirst();

        //下面.or的2种方法中其实只要选择一种就可以。
        //上面是对interface进行扫描，寻找匹配的；还有一种方法，是对device进行扫描，寻找匹配的。
//                    .or(() -> stream(deviceService.getAvailableDevices())
//                            .map(Device::id)
//                            .filter(dstdd -> isDstLocation(dstdd,dstIp6Addr))
//                            .findFirst())
    }

    protected Optional<ConnectPoint>  getConnectPointOfSubnet(Ip6Prefix dstIp6Prefix) {
        // Do we know who this is for? If not, Search for it.
        // Maybe the hosts has been sent its packet to network.
        // If so , hostService will konw it and its location.

        //TODO:后面要考虑有多个Interface的subnet能匹配的情形，也就是要返回一个列表。而不是随机某个最长的。
        // 这时候要判断谁的mask是最长的。可能不需要，因为main.p4里面的table是lpm匹配的。
        // 还有要考虑这些匹配上的interface可能位于多台设备上。要用一个overlay的subnet网段来测试.
        // 下面的可能返回空集。

        return  interfaceService.getInterfaces().stream()
                .filter(anInterface -> includeTheSubnetOrNot(anInterface, dstIp6Prefix))
                .map(anInterface -> anInterface.connectPoint())
                .findFirst();

        //下面.or的2种方法中其实只要选择一种就可以。
        //上面是对interface进行扫描，寻找匹配的；还有一种方法，是对device进行扫描，寻找匹配的。
//                    .or(() -> stream(deviceService.getAvailableDevices())
//                            .map(Device::id)
//                            .filter(dstdd -> isDstLocation(dstdd,dstIp6Addr))
//                            .findFirst())
    }


    // Install a rule forwarding the packet to the specified group(And the group point to some Ports).
    private void setupPathBetweenSW(List<Ip6Address> dstIp6Address, List<Ip6Prefix> dstIp6Prefixes, DeviceId srcSwitchId, DeviceId dstSwitchId) {

        if (srcSwitchId.equals(dstSwitchId)) {
            // Source and dest hosts are connected to the same switch.
//                pathLinks = Collections.emptyList();
            return;
        }

        Topology topo = topologyService.currentTopology();

        // Compute shortest path.
        // getPaths返回的就是最短路径。
        Set<Path> allPaths = topologyService.getPaths(topo, srcSwitchId, dstSwitchId);
        if (allPaths.size() == 0) {
            log.warn("No paths between {} and {}", srcSwitchId, dstSwitchId);
            return;
        }else{
            log.info("There are {} paths between {} and {}", allPaths.size(),srcSwitchId, dstSwitchId) ;
        }

//            int count=0;

        for (Path anPath:allPaths) {
//                count++;
            for (Link link : anPath.links()) {
                final DeviceId linkSrcSwId = link.src().deviceId();
                final DeviceId peerSwId = link.dst().deviceId();

                final MacAddress peerSwitchMac = getMyStationMac(peerSwId);
                PortNumber portToNextHop = link.src().port();

//                没法改成interface::mac
//                final MacAddress peerSwitchMaca =
//                        interfaceService.getInterfacesByPort(link.dst())
//                                .stream().map(Interface::mac).findFirst().get();
//
//                log.info("peerSwitchMac.toString() {}",peerSwitchMaca);
                //checkNotNull(peerSwitchMac);

                Pair<PortNumber, MacAddress> dstPortMacPair = Pair.of(portToNextHop, peerSwitchMac);

                //用dstSwitchID来生成groupID，而不是Link的peerSwID，这样可以保证该path经过的各设备上的group ID是一致的。
                int groupId = deviceToGroupId(dstSwitchId);

                // Create a group with only one member.
//                    log.info("Create {}th path betwenen {} and {}",count,linkSrcSwId,peerSwId) ;
//                    createRoutingEntry(groupId, linkSrcSwId, Collections.singleton(dstPortMacPair), subnetsToRoute);
//                    GroupDescription group = createGroup(groupId,linkSrcSwId,Collections.singleton(dstPortMacPair));
                GroupDescription group =createToNextHopsGroup(groupId, Collections.singleton(dstPortMacPair), linkSrcSwId);

                final Set<Ip6Prefix> subnetsToRoute = new HashSet<>();

                dstIp6Address.stream()
                        .map(dstIp6Addr -> Ip6Prefix.valueOf(dstIp6Addr, 128))
                        .forEach(subnetsToRoute::add);

                dstIp6Prefixes.stream().forEach(subnetsToRoute::add);

                List<FlowRule> flowRules = createFlowRules(groupId,linkSrcSwId,subnetsToRoute);
                insertInOrder(group, flowRules);
            }
        }
    }

    private void setupLocalRoute(Ip6Address dstIp6Addr, DeviceId dstSwitchId,
                                 Collection<Pair<PortNumber,MacAddress>> dstPortMacPairs) {

        log.info("Setup local path on {} for  {}", dstSwitchId, dstIp6Addr);

        final Set<Ip6Prefix> subnetsToRoute=new HashSet<>();
        subnetsToRoute.add(Ip6Prefix.valueOf(dstIp6Addr, 128));

        //最好用MAC address来生成groupID。暂时用IP地址来生成。
        int groupId = ipToGroupId(dstIp6Addr);

//                createRoutingEntry(groupId,dstSwitchId,dstPortMacPairs,subnetsToRoute);
//            GroupDescription group = createGroup(groupId,dstSwitchId,dstPortMacPairs);
        GroupDescription group =createToNextHopsGroup(groupId, dstPortMacPairs, dstSwitchId);
        List<FlowRule> flowRules = createFlowRules(groupId,dstSwitchId,subnetsToRoute);
        log.info("Setup Local route for host {} on {} ", dstIp6Addr,dstSwitchId);
        insertInOrder(group, flowRules);
    }


    private List<FlowRule> createFlowRules(int groupId,
                                           DeviceId deviceId,
                                           Set<Ip6Prefix> subnetsToRoute){

        //TODO:要研究下是否可以使用IntentService。要考虑pipeconf的翻译问题。
        // 要让pathIntent指向该该treatment(实际是指向上面的group).
        // 下面的改造为pathIntent里的selector。
        // 需要对pipeconf进行改造，让指向group的flowrule能自动绑定到"IngressPipeImpl.v6routing_table".
        // 完成类似于createV6RoutingRule的功能。
        return subnetsToRoute.stream()
                .map(subnet -> createV6RoutingRule(deviceId, subnet, groupId))
                .collect(Collectors.toList());

    }

    //这里的nextHops和前面的nextHop不同。这里的nextHops同时指向port和MAC地址。
    private GroupDescription createToNextHopsGroup(int groupId,
                                                   Collection<Pair<PortNumber,MacAddress>> dstPortMacPairs,
                                                   DeviceId deviceId) {

        String actionProfileId = "IngressPipeImpl.multipaths_selector";

        final List<PiAction> actions = Lists.newArrayList();

        final String tableId = "IngressPipeImpl.v6routing_table";
        for (Pair<PortNumber,MacAddress> pair : dstPortMacPairs) {
            final PiAction action = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_output"))
                    .withParameter(new PiActionParam(
                            // Action param name.
                            PiActionParamId.of("port_num"),
                            // Action param value.
                            pair.getLeft().toLong()))
                    .withParameter(new PiActionParam(
                            // Action param name.
                            PiActionParamId.of("dmac"),
                            // Action param value.
                            pair.getRight().toBytes()))
                    .build();

            actions.add(action);
        }


        //先判断是否有该group的存在，免得被覆盖。
        //下面的groupKey的生成方式要与Utils.buildSelectGroup里的保持一致才可以。
        final GroupKey groupKey = new PiGroupKey(
                PiTableId.of(tableId), PiActionProfileId.of(actionProfileId), groupId);

        Optional<GroupDescription> optGroup =Optional.ofNullable(groupService.getGroup(deviceId,groupKey));



        //如果有该group存在，那么就增加bucket。否则会覆盖原有的group，导致该group下原有的bucket消失掉。
        //如果没有该group存在，那么就创建。
        if(optGroup.isPresent()){
            final List<GroupBucket> buckets = actions.stream()
                    .map(action -> DefaultTrafficTreatment.builder()
                            .piTableAction(action).build())
                    .map(DefaultGroupBucket::createSelectGroupBucket)
                    .collect(Collectors.toList());

            groupService.addBucketsToGroup(deviceId,groupKey,new GroupBuckets(buckets),groupKey,appId);
            return optGroup.get();
        }else{
            return Utils.buildSelectGroup(
                    deviceId, tableId, actionProfileId, groupId, actions, appId);
        }
    }

    private FlowRule createV6RoutingRule(DeviceId deviceId, Ip6Prefix ip6Prefix,
                                         int groupId) {

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.

        final String tableId = "IngressPipeImpl.v6routing_table";
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

    //===主机探测相关的函数=======

    private void probe(IpAddress ip) {
        //Set<Host> hosts = hostManager.getHostsByIp(ip);
        Set<Host> hosts = hostService.getHostsByIp(ip);

        if (hosts.isEmpty()) {
            sendRequest(ip);
        }
    }

    /**
     * Sends an NDP request for the given IP address.
     *
     * @param targetIp IP address to send the request for
     */
    private void sendRequest(IpAddress targetIp) {
        interfaceService.getMatchingInterfaces(targetIp).forEach(intf -> {
            if (edgePortService.isEdgePoint(intf.connectPoint())) {

                //如果读取不到intf.vlan()会不会有问题？netcfg.json里没有配置vlan。
                intf.ipAddressesList().stream()
                        .filter(ia -> ia.subnetAddress().contains(targetIp))
                        .forEach(ia -> {
                            MacAddress probeMac = intf.mac();
                            IpAddress probeIp = !probeMac.equals(MacAddress.ONOS) ?
                                    ia.ipAddress() :
                                    (ia.ipAddress().isIp4() ? Ip4Address.ZERO : Ip6Address.ZERO);
                            sendProbe(intf.connectPoint(), targetIp, probeIp, probeMac, intf.vlan());

                            // account for use-cases where tagged-vlan config is used
                            if (!intf.vlanTagged().isEmpty()) {
                                intf.vlanTagged().forEach(tag -> {
                                    sendProbe(intf.connectPoint(), targetIp, probeIp, probeMac, tag);
                                });
                            }
                        });
            }

        });
    }

    public void sendProbe(ConnectPoint connectPoint, IpAddress targetIp, IpAddress sourceIp,
                          MacAddress sourceMac, VlanId vlan) {
        log.info("Sending probe from mac: {} for target:{} out of intf:{} vlan:{}", sourceMac,targetIp, connectPoint, vlan);

        Ethernet probePacket = new Ethernet();

        if (targetIp.isIp6()){
            // IPv6: Use Neighbor Discovery. According to the NDP protocol,
            // we should use the solicitation node address as IPv6 destination
            // and the multicast mac address as Ethernet destination.
            byte[] destIp = IPv6.getSolicitNodeAddress(targetIp.toOctets());
            probePacket = NeighborSolicitation.buildNdpSolicit(
                    targetIp.getIp6Address(),
                    sourceIp.getIp6Address(),
                    Ip6Address.valueOf(destIp),
                    sourceMac,
                    MacAddress.valueOf(IPv6.getMCastMacAddress(destIp)),
                    vlan
            );
        }

        //先只log，看能不能生成。
        if (probePacket == null) {
            log.warn("Not able to build the probe packet");
            return;
        }else {
            //下面这部分是复制来的源代码，没有改动过。不用改造也能通过Pipeconf发出去是因为里面的mapOutboundPackt会完成翻译。
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(connectPoint.port())
                    .build();

            OutboundPacket outboundPacket =
                    new DefaultOutboundPacket(connectPoint.deviceId(), treatment,
                            ByteBuffer.wrap(probePacket.serialize()));

            packetService.emit(outboundPacket);
            //log.info("Sending probe for target:{} out of intf:{} vlan:{} , NS: {}", targetIp, connectPoint, vlan, probePacket.toString() );
        }


    }


    // =====辅助函数===========  ////////////

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
     * Inserts the given groups and flow rules in order, groups first, then flow
     * rules. In P4Runtime, when operating on an indirect table (i.e. with
     * action selectors), groups must be inserted before table entries.
     *
     * @param group     the group
     * @param flowRules the flow rules depending on the group
     */
    private void insertInOrder(GroupDescription group, Collection<FlowRule> flowRules) {
        try {
            groupService.addGroup(group);
            Thread.sleep(GROUP_INSERT_DELAY_MILLIS);
            // Wait for groups to be inserted.
            flowRules.forEach(flowRuleService::applyFlowRules);
        } catch (InterruptedException e) {
            log.error("Interrupted!", e);
//            log.info("Insert group error",e);
            Thread.currentThread().interrupt();
        }

//        log.info("FlowRule : {}",flowRules.toString());
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

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Indicated whether this is an IPv6 multicast packet.
    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }

    /**
     * Returns a 32 bit bit group ID from the given MAC address.
     *
     *
     * @return an integer
     */
    private int deviceToGroupId(DeviceId deviceId) {
        //return mac.hashCode() & 0x7fffffff;
        return deviceId.hashCode() & 0x7fffffff;
    }

    private int ipToGroupId(Ip6Address dstIp6Addr) {
        //return mac.hashCode() & 0x7fffffff;
        return dstIp6Addr.hashCode() & 0x7fffffff;
    }


    //Get the location DeviceID of dstIPv6
    /**
     * Returns true if the given device has an interfaces  flag set to true in the
     * config, false otherwise.
     *
     * @param deviceId the device ID
     * @return true if the device is a spine, false otherwise
     */
    private boolean isDstLocation(DeviceId deviceId, Ip6Address dstIp6Addr) {
        return interfaceService.getInterfaces().stream()
                .filter(iface -> iface.connectPoint().deviceId().equals(deviceId))
                .map(Interface::ipAddressesList)
                .flatMap(Collection::stream)
                .map(InterfaceIpAddress::subnetAddress)
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .anyMatch(i -> i.equals(Ip6Prefix.valueOf(dstIp6Addr, i.getIp6Prefix().prefixLength())));
    }

    private boolean includeTheIPorNot(Interface anInterface, Ip6Address dstIp6Addr) {
        return anInterface.ipAddressesList().stream()
                .map(InterfaceIpAddress::subnetAddress).filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .anyMatch(i -> i.equals(Ip6Prefix.valueOf(dstIp6Addr, i.getIp6Prefix().prefixLength())));
    }

    private boolean includeTheSubnetOrNot(Interface anInterface, Ip6Prefix dstIp6Prefix) {
        return anInterface.ipAddressesList().stream()
                .map(InterfaceIpAddress::subnetAddress).filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .anyMatch(ip6Prefix -> ip6Prefix.contains(dstIp6Prefix));
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
        //return mac.hashCode() & 0x7fffffff;
        return mac.hashCode() & 0x77777777;
    }

    private Path pickOnePath(Set<Path> paths) {
//            for (Path path: paths) {
//                path.weight()
//                ((ScalarWeight) path.weight())
//
//            }

//            final double measureTolerance = 0.05; // 0.05% represent 5M(10G), 12.5M(25G), 50M(100G)
//
//            //Sort by Cost in order
//            //这个的排序法比较不好理解。
////            ScalarWeight.toWeight(1.0)
//
////            paths.stream().sorted((p1, p2) ->
////                    ((ScalarWeight) p1.weight()).value() > ((ScalarWeight) p2.weight()).value() ? 1 : (p1.weight() < p2.weight() ? -1 : 0));
//
////            paths.stream().sorted(path -> Comparator.comparing(((ScalarWeight) path.weight()).value())).
//            paths.stream().sorted(path -> Comparator.comparingDouble(((ScalarWeight) path.weight()).value())).collect(Collectors.toSet());
////                    paths.stream().sorted(Comparator.comparingDouble(((ScalarWeight) path.w).value())).
////
////            paths.sort((p1, p2) -> p1.cost() > p2.cost() ? 1 : (p1.cost() < p2.cost() ? -1 : 0));
//
//            // get paths with similar lowest cost within measureTolerance range.
//            List<Path> minCostPaths = new ArrayList<>();
//            // get(0)是获得list里的第一个元素吧
//            Path result = paths.get(0);
//            minCostPaths.add(result);
//            for (int i = 1, pathCount = paths.size(); i < pathCount; i++) {
//                Path temp = paths.get(i);
//                if (temp.cost() - result.cost() < measureTolerance) {
//                    minCostPaths.add(temp);
//                }
//            }
//
//            return minCostPaths;

        int item = new Random().nextInt(paths.size());
        List<Path> pathList = Lists.newArrayList(paths);
        return pathList.get(item);
    }

    // =====过时的函数 ============= ////////////


    private void forwardPacketToDst(PacketContext context, Host dst) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(),
                treatment, context.inPacket().unparsed());
        packetService.emit(packet);
        log.info("sending packet: {}", packet);
    }

    // Install a rule forwarding the packet to the specified port.
    private void setUpConnectivity(PacketContext context, HostId srcId, HostId dstId) {
        TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();


        Key key;
        if (srcId.toString().compareTo(dstId.toString()) < 0) {
            key = Key.of(srcId.toString() + dstId.toString(), appId);
        } else {
            key = Key.of(dstId.toString() + srcId.toString(), appId);
        }

        HostToHostIntent intent = (HostToHostIntent) intentService.getIntent(key);
        // TODO handle the FAILED state
        if (intent != null) {
            if (WITHDRAWN_STATES.contains(intentService.getIntentState(key))) {
                HostToHostIntent hostIntent = HostToHostIntent.builder()
                        .appId(appId)
                        .key(key)
                        .one(srcId)
                        .two(dstId)
                        .selector(selector)
                        .treatment(treatment)
                        .build();

                intentService.submit(hostIntent);
            } else if (intentService.getIntentState(key) == IntentState.FAILED) {

                TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

                TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                        .drop().build();

                ForwardingObjective objective = DefaultForwardingObjective.builder()
                        .withSelector(objectiveSelector)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(intent.priority() - 1)
                        .makeTemporary(DROP_RULE_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();

                flowObjectiveService.forward(context.outPacket().sendThrough(), objective);
            }

        } else if (intent == null) {
            HostToHostIntent hostIntent = HostToHostIntent.builder()
                    .appId(appId)
                    .key(key)
                    .one(srcId)
                    .two(dstId)
                    .selector(selector)
                    .treatment(treatment)
                    .build();

            intentService.submit(hostIntent);
        }

    }



    /**
     * Creates a routing flow rule that matches on the given IPv6 prefix and
     * executes the given group ID (created before).
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

        final PiTableAction action = PiActionProfileGroupId.of(groupId);
        // ---- END SOLUTION ----

        return Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
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

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    /**
     * Creates an ONOS SELECT group for the routing table to provide ECMP
     * forwarding for the given collection of next hop MAC addresses. ONOS
     * SELECT groups are equivalent to P4Runtime action selector groups.
     * <p>
     * This method will be called by the routing policy methods below to insert
     * groups in the L3 table
     *
     * @param nextHopMacs the collection of mac addresses of next hops
     * @param deviceId    the device where the group will be installed
     * @return a SELECT group
     */
    private GroupDescription createNextHopGroup(int groupId,
                                                Collection<MacAddress> nextHopMacs,
                                                DeviceId deviceId) {

        String actionProfileId = "IngressPipeImpl.ecmp_selector";

        final List<PiAction> actions = Lists.newArrayList();


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

            actions.add(action);
        }

        final GroupKey groupKey = new PiGroupKey(
                PiTableId.of(tableId), PiActionProfileId.of(actionProfileId), groupId);

        Optional<GroupDescription> optGroup =Optional.ofNullable(groupService.getGroup(deviceId,groupKey));

        if(optGroup.isPresent()){
            final List<GroupBucket> buckets = actions.stream()
                    .map(action -> DefaultTrafficTreatment.builder()
                            .piTableAction(action).build())
                    .map(DefaultGroupBucket::createSelectGroupBucket)
                    .collect(Collectors.toList());

            groupService.addBucketsToGroup(deviceId,groupKey,new GroupBuckets(buckets),groupKey,appId);
            return optGroup.get();
        }else{
            return Utils.buildSelectGroup(
                    deviceId, tableId, actionProfileId, groupId, actions, appId);
        }

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

        // 应该参照上面的写法吧。上面的比较严谨吧。
        return Utils.buildSelectGroup(
                deviceId, tableId, actionProfileId, groupId, actions, appId);
    }

//    // Install a rule forwarding the packet to the specified group(And the group point to some MACs).
//    private void setUpConnectivityBetweenDevice(Ip6Address dstIp6Addr, DeviceId srcSwitch, DeviceId dstSwitch) {
//
//        Topology topo = topologyService.currentTopology();
//
//        List<Link> pathLinks;
//        if (srcSwitch.equals(dstSwitch)) {
//            // Source and dest hosts are connected to the same switch.
//            pathLinks = Collections.emptyList();
//        } else {
//            // Compute shortest path.
//            Set<Path> allPaths = topologyService.getPaths(topo, srcSwitch, dstSwitch);
//            if (allPaths.size() == 0) {
//                log.warn("No paths between {} and {}", srcSwitch, dstSwitch);
//                return;
//            }
//            // If many shortest paths are available, pick a random one.
//            pathLinks = pickOnePath(allPaths).links();
//        }
//
//        for (Link link : pathLinks) {
//            final DeviceId linkSrcSwId = link.src().deviceId();
//            final DeviceId peerSwId = link.dst().deviceId();
//
//            final MacAddress peerSwitchMac = getMyStationMac(peerSwId);
//
//            final Set<Ip6Prefix> subnetsToRoute=new HashSet<>();
//            subnetsToRoute.add(Ip6Prefix.valueOf(dstIp6Addr, 128));
//
//            // Create a group with only one member.
//            int groupId = macToGroupId(peerSwitchMac);
//
//            GroupDescription group = createNextHopGroup(
//                    groupId, Collections.singleton(peerSwitchMac), linkSrcSwId);
//
//            List<FlowRule> flowRules = subnetsToRoute.stream()
//                    .map(subnet -> createRoutingRule(linkSrcSwId, subnet, groupId))
//                    .collect(Collectors.toList());
//
//            insertInOrder(group, flowRules);
//
//        }
//    }
//
//    // Install a rule forwarding the packet to the specified group(And the group point to some Ports).
//    private void setupConBetweenDevicesViaPort(Ip6Address dstIp6Addr, DeviceId srcSwitchId, DeviceId dstSwitchId) {
//
//        Topology topo = topologyService.currentTopology();
//
//        List<Link> pathLinks;
//        if (srcSwitchId.equals(dstSwitchId)) {
//            // Source and dest hosts are connected to the same switch.
//            pathLinks = Collections.emptyList();
//        } else {
//            // Compute shortest path.
//            Set<Path> allPaths = topologyService.getPaths(topo, srcSwitchId, dstSwitchId);
//            if (allPaths.size() == 0) {
//                log.warn("No paths between {} and {}", srcSwitchId, dstSwitchId);
//                return;
//            }
//            // If many shortest paths are available, pick a random one.
//            pathLinks = pickOnePath(allPaths).links();
//        }
//
//        for (Link link : pathLinks) {
//            final DeviceId linkSrcSwId = link.src().deviceId();
//            final DeviceId peerSwId = link.dst().deviceId();
//
//            //final MacAddress peerSwitchMac = getMyStationMac(peerSwId);
//            PortNumber portToNextHop = link.src().port();
//
//            final Set<Ip6Prefix> subnetsToRoute=new HashSet<>();
//            subnetsToRoute.add(Ip6Prefix.valueOf(dstIp6Addr, 128));
//            //后面需要再增加SRv6 sid的地址
//
//            //int groupId = macToGroupId(peerSwitchMac);
//            int groupId = deviceToGroupId(dstSwitchId);
//
//            //用dstSwitchID来生成groupID，而不是Link的peerSwID，这样可以保证该path经过的各设备上的group ID是一致的。
//            // Create a group with only one member.
//            GroupDescription group = createNextHopsGroup(
//                    groupId, Collections.singleton(portToNextHop), linkSrcSwId);
//
//            List<FlowRule> flowRules = subnetsToRoute.stream()
//                    .map(subnet -> createAnRoutingRule(linkSrcSwId, subnet, groupId))
//                    .collect(Collectors.toList());
//
//            insertInOrder(group, flowRules);
//        }
//
//    }

//    // Floods the specified packet if permissible.
//    private void flood(PacketContext context) {
//        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
//                context.inPacket().receivedFrom())) {
//            packetOut(context, PortNumber.FLOOD);
//        } else {
//            context.block();
//        }
//    }

}


