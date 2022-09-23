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

import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TableId;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import com.cxc.ngsdn.common.FabricDeviceConfig;
import com.cxc.ngsdn.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static com.cxc.ngsdn.AppConstants.INITIAL_SETUP_DELAY;

/**
 * App component that configures devices to provide L2 bridging capabilities.
 */
@Component(
        immediate = true,
        // *** TODO EXERCISE 4
        // Enable component (enabled = true)
        enabled = true
)
public class L2BridgingComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final int DEFAULT_BROADCAST_GROUP_ID = 255;


    private final DeviceListener deviceListener = new InternalDeviceListener();
    private final HostListener hostListener = new InternalHostListener();

    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService configService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

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
        hostService.addListener(hostListener);
        // Schedule set up of existing devices. Needed when reloading the app.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        hostService.removeListener(hostListener);

        log.info("Stopped");
    }

    //--------------------------------------------------------------------------
    // METHODS TO COMPLETE.
    //
    // Complete the implementation wherever you see TODO.
    //--------------------------------------------------------------------------

    /**
     * Sets up everything necessary to support L2 bridging on the given device.
     *
     * @param deviceId the device to set up
     */
    private void setUpDevice(DeviceId deviceId) {
        if (isSpine(deviceId)) {
            // Stop here. We support bridging only on leaf/tor switches.
            return;
        }
        insertMulticastGroup(deviceId);
        insertMulticastFlowRules(deviceId);
        // Uncomment the following line after you have implemented the method:
        //insertUnmatchedBridgingFlowRule(deviceId);
    }

    /**
     * Inserts an ALL group in the ONOS core to replicate packets on all host
     * facing ports. This group will be used to broadcast all ARP/NDP requests.
     * <p> 
     //往所有端口发送，不考虑端口的VLAN属性吧。
     * ALL groups in ONOS are equivalent to P4Runtime packet replication engine
     * (PRE) Multicast groups.
       *leaf1上的结果
            下面就是创建了一个group，group id是255,里面有4个bucket .
			group的TYPE有ALL， SELECT等，ALL是给所有bucket发送流量。SELECT是要在多个bucket中进行负载均衡。
			   id=0xff, state=ADDED, type=ALL, bytes=0, packets=0, appId=org.onosproject.ngsdn-tutorial, referenceCount=0
			       id=0xff, bucket=1, bytes=0, packets=0, weight=-1, actions=[OUTPUT:3]
			       id=0xff, bucket=2, bytes=0, packets=0, weight=-1, actions=[OUTPUT:4]
			       id=0xff, bucket=3, bytes=0, packets=0, weight=-1, actions=[OUTPUT:5]
       id=0xff, bucket=4, bytes=0, packets=0, weight=-1, actions=[OUTPUT:6]
     *
     * @param deviceId the device where to install the group
     */
    private void insertMulticastGroup(DeviceId deviceId) {

        // Replicate packets where we know hosts are attached.
        Set<PortNumber> ports = getHostFacingPorts(deviceId);

        if (ports.isEmpty()) {
            // Stop here.
            log.warn("Device {} has 0 host facing ports", deviceId);
            return;
        }

        log.info("Adding L2 multicast group with {} ports on {}...",
                ports.size(), deviceId);

        // Forge group object.
        //cxc :应该是在这里把具体的各个端口ports和DEFAULT_BROADCAST_GROUP_ID关联起来的。
        final GroupDescription multicastGroup = Utils.buildMulticastGroup(
                appId, deviceId, DEFAULT_BROADCAST_GROUP_ID, ports);

        // Insert.
        groupService.addGroup(multicastGroup);
    }

    /**
     * Insert flow rules matching ethernet destination
     * broadcast/multicast addresses (e.g. ARP requests, NDP Neighbor
     * Solicitation, etc.). Such packets should be processed by the multicast
     * group created before.
     * <p>
     * This method will be called at component activation for each device
     * (switch) known by ONOS, and every time a new device-added event is
     * captured by the InternalDeviceListener defined below.
     *
     *leaf1上的实际结果。
	    id=c00000a489d650, state=ADDED, bytes=344, packets=4, duration=41023, liveType=UNKNOWN, priority=10, tableId=IngressPipeImpl.l2_ternary_table, 
            appId=org.onosproject.ngsdn-tutorial, selector=[hdr.ethernet.dst_addr=0x333300000000&&&0xffff00000000],
            treatment=DefaultTrafficTreatment{immediate=[IngressPipeImpl.set_multicast_group(gid=0xff)], deferred=[], 
            transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}
        id=c00000c8cf6dac, state=ADDED, bytes=0, packets=0, duration=41023, liveType=UNKNOWN, priority=10, tableId=IngressPipeImpl.l2_ternary_table, 
            appId=org.onosproject.ngsdn-tutorial, selector=[hdr.ethernet.dst_addr=0xffffffffffff&&&0xffffffffffff], 
            treatment=DefaultTrafficTreatment{immediate=[IngressPipeImpl.set_multicast_group(gid=0xff)], deferred=[], 
            transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}
     * @param deviceId device ID where to install the rules
     */
    private void insertMulticastFlowRules(DeviceId deviceId) {

        log.info("Adding L2 multicast rules on {}...", deviceId);

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        // Match ARP request - Match exactly FF:FF:FF:FF:FF:FF
        // matchTernary，后面的那个是掩码
        // PiCriterion相当于P4 table里的entry/ONOS的selector ; 
        // PiAction 相当于P4里的action , withId就是action的动作名，withParameter就是传递给action的参数。
        // 在Utils.java里Actions是会被转化为treatment。
        final PiCriterion macBroadcastCriterion = PiCriterion.builder()
                .matchTernary(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        MacAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes(),
                        MacAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes())
                .build();

        // Match NDP NS - Match ternary 33:33:**:**:**:**
        //还要配合NdpReplyComponent.java吧。
        final PiCriterion ipv6MulticastCriterion = PiCriterion.builder()
                .matchTernary(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        MacAddress.valueOf("33:33:00:00:00:00").toBytes(),
                        MacAddress.valueOf("FF:FF:00:00:00:00").toBytes())
                .build();

        // Action: set multicast group id
        final PiAction setMcastGroupAction = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_multicast_group"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("gid"),
                        DEFAULT_BROADCAST_GROUP_ID))
                .build();
                 //该group ID=255对应的端口是哪些？应该是在上面的insertMulticastGroup里处理的。

        //  Build 2 flow rules.
        final String tableId = "IngressPipeImpl.l2_ternary_table";
        // ---- END SOLUTION ----

        final FlowRule rule1 = Utils.buildFlowRule(
                deviceId, appId, tableId,
                macBroadcastCriterion, setMcastGroupAction);

        final FlowRule rule2 = Utils.buildFlowRule(
                deviceId, appId, tableId,
                ipv6MulticastCriterion, setMcastGroupAction);

        // Insert rules.
        //是可变长的参数
        flowRuleService.applyFlowRules(rule1, rule2);
    }

    /**
     * Insert flow rule that matches all unmatched ethernet traffic. This
     * will implement the traditional briding behavior that floods all
     * unmatched traffic.
     * <p>
     该flowrule的优先级也是一样的，可是它匹配了所有流量，那么也会把其他的组播流量也给拦截了的。虽然流量最后都是送给了同一个group去处理的。因此需要注释掉。
     * This method will be called at component activation for each device
     * (switch) known by ONOS, and every time a new device-added event is
     * captured by the InternalDeviceListener defined below.
     *
     id=c0000023d5f663, state=PENDING_ADD, bytes=0, packets=0, duration=0, liveType=UNKNOWN, priority=10, tableId=IngressPipeImpl.l2_ternary_table, appId=org.onosproject.ngsdn-tutorial, selector=[hdr.ethernet.dst_addr=0x0&&&0x0], treatment=DefaultTrafficTreatment{immediate=[IngressPipeImpl.set_multicast_group(gid=0xff)], deferred=[], transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}
     * @param deviceId device ID where to install the rules
     */
    @SuppressWarnings("unused")
    private void insertUnmatchedBridgingFlowRule(DeviceId deviceId) {

        log.info("Adding L2 multicast rules on {}...", deviceId);

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----

        // Match unmatched traffic - Match ternary **:**:**:**:**:**
        final PiCriterion unmatchedTrafficCriterion = PiCriterion.builder()
                .matchTernary(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        MacAddress.valueOf("00:00:00:00:00:00").toBytes(),
                        MacAddress.valueOf("00:00:00:00:00:00").toBytes())
                .build();

        // Action: set multicast group id
        final PiAction setMcastGroupAction = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_multicast_group"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("gid"),
                        DEFAULT_BROADCAST_GROUP_ID))
                .build();

        //  Build flow rule.
        final String tableId = "IngressPipeImpl.l2_ternary_table";
        // ---- END SOLUTION ----

        final FlowRule rule = Utils.buildFlowRule(
                deviceId, appId, tableId,
                unmatchedTrafficCriterion, setMcastGroupAction);

        // Insert rules.
        flowRuleService.applyFlowRules(rule);
    }

    /**
     * Insert flow rules to forward packets to a given host located at the given
     * device and port.
     * <p>
     * This method will be called at component activation for each host known by
     * ONOS, and every time a new host-added event is captured by the
     * InternalHostListener defined below.
     *
     * @param host     host instance
     * @param deviceId device where the host is located
     * @param port     port where the host is attached to
     */
    private void learnHost(Host host, DeviceId deviceId, PortNumber port) {

        log.info("Adding L2 unicast rule on {} for host {} (port {})...",
                deviceId, host.id(), port);

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        final String tableId = "IngressPipeImpl.l2_exact_table";
        // Match exactly on the host MAC address.
        final MacAddress hostMac = host.mac();
        final PiCriterion hostMacCriterion = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        hostMac.toBytes())
                .build();

        // Action: set output port
        final PiAction l2UnicastAction = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_egress_port"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("port_num"),
                        port.toLong()))
                .build();
        // ---- END SOLUTION ----

        // Forge flow rule.
        final FlowRule rule = Utils.buildFlowRule(
                deviceId, appId, tableId, hostMacCriterion, l2UnicastAction);

        // Insert.
        flowRuleService.applyFlowRules(rule);
    }

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    // 定义了本APP对新设备、新host的相关事件的动作反应
    /**
     * Listener of device events.
     */
    //如果当前匹配成功的 case 语句块没有 break 语句，则从当前 case 开始，后续所有 case 的值都会输出，如果后续的 case 语句块有 break 语句则会跳出判断。
    // 		来自 <https://www.runoob.com/java/java-switch-case.html> 
    // 		如果匹配到 DEVICE_ADDED或者DEVICE_AVAILABILITY_CHANGED，到了break语句后，就会退出；
    // 		如果不匹配，到了default，就return false.默认的isRelevant是 return true。
    // return false后，后面的那2句就都不执行了。不仅仅是跳出了switch，还跳出了整个函数体。return从当前的方法中退出，返回到该调用的方法的语句处，继续执行
    public class InternalDeviceListener implements DeviceListener {

        @Override
        public boolean isRelevant(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_ADDED:
                case DEVICE_AVAILABILITY_CHANGED:
                    break;
                default:
                    // Ignore other events.
                    return false;
            }
            // Process only if this controller instance is the master.
               //这个的意思是只让master的控制器来处理。如果不是master的控制器，遇到了也不处理？
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
                // 从哪里看到设备的pipeline conf已经设置完成了？看pipeconf目录下的文件。

                // Events are processed using a thread pool defined in the
                // MainComponent.
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event! deviceId={}", event.type(), deviceId);
                    //新设备的哪些端口进入到multicastGroup呢？刚刚发现新设备的时候，应该还不知道它有哪些端口吧。
                    // 应该是用上面的mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);每个一个时间间隔刷新一次setupAllDevices.
                    setUpDevice(deviceId);
                });
            }
        }
    }

    /**
     * Listener of host events.
     */
    public class InternalHostListener implements HostListener {

        @Override
        public boolean isRelevant(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                    // Host added events will be generated by the
                    // HostLocationProvider by intercepting ARP/NDP packets.
                    break;
                case HOST_REMOVED:
                case HOST_UPDATED:
                case HOST_MOVED:
                default:
                    // Ignore other events.
                    // Food for thoughts: how to support host moved/removed?
                    return false;
            }
            // Process host event only if this controller instance is the master
            // for the device where this host is attached to.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(HostEvent event) {
            final Host host = event.subject();
            // Device and port where the host is located.
            final DeviceId deviceId = host.location().deviceId();
            final PortNumber port = host.location().port();

            mainComponent.getExecutorService().execute(() -> {
                log.info("{} event! host={}, deviceId={}, port={}",
                        event.type(), host.id(), deviceId, port);

                learnHost(host, deviceId, port);
            });
        }
    }

    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    /**
     * Returns a set of ports for the given device that are used to connect
     * hosts to the fabric.
     *
     * @param deviceId device ID
     * @return set of host facing ports
     */
    private Set<PortNumber> getHostFacingPorts(DeviceId deviceId) {
        //是哪个程序从netcfg里读取到设备的interfaces呢？是Srv6DeviceConfig吗？
        // Get all interfaces configured via netcfg for the given device ID and
        // return the corresponding device port number. Interface configuration
        // in the netcfg.json looks like this:
        // "device:leaf1/3": {
        //   "interfaces": [
        //     {
        //       "name": "leaf1-3",
        //       "ips": ["2001:1:1::ff/64"]
        //     }
        //   ]
        // }
        // .getInterfaces().stream() 是拿到所有设备上的所有interfaces吗,后面再根据deviceID来过滤
        //  .map(Interface::connectPoint) 是映射，把Interface转换为connectPoint
        return interfaceService.getInterfaces().stream()
                .map(Interface::connectPoint)
                .filter(cp -> cp.deviceId().equals(deviceId))
                .map(ConnectPoint::port)
                .collect(Collectors.toSet());
    }

    /**
     * Returns true if the given device is defined as a spine in the
     * netcfg.json.
     *
     * @param deviceId device ID
     * @return true if spine, false otherwise
     */
    private boolean isSpine(DeviceId deviceId) {
        // Example netcfg defining a device as spine:
        // "devices": {
        //   "device:spine1": {
        //     ...
        //     "fabricDeviceConfig": {
        //       "myStationMac": "...",
        //       "mySid": "...",
        //       "isSpine": true
        //     }
        //   },
        //   ...
        final FabricDeviceConfig cfg = configService.getConfig(
                deviceId, FabricDeviceConfig.class);
        return cfg != null && cfg.isSpine();
    }

    /**
     * Sets up L2 bridging on all devices known by ONOS and for which this ONOS
     * node instance is currently master.
     * <p>
     * This method is called at component activation.
     */
    private void setUpAllDevices() {
        deviceService.getAvailableDevices().forEach(device -> {
            if (mastershipService.isLocalMaster(device.id())) {
                log.info("*** L2 BRIDGING - Starting initial set up for {}...", device.id());
                setUpDevice(device.id());
                // For all hosts connected to this device...
                hostService.getConnectedHosts(device.id()).forEach(
                        host -> learnHost(host, host.location().deviceId(),
                                host.location().port()));
            }
        });
    }
}
