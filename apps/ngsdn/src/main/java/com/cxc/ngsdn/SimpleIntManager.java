/*
 * Copyright 2015-present Open Networking Foundation
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
// package org.onosproject.inbandtelemetry.impl;
package com.cxc.ngsdn;

import com.cxc.ngsdn.common.Utils;
import com.google.common.collect.Maps;
import com.google.common.util.concurrent.Striped;
import org.apache.commons.lang3.tuple.Triple;
import org.onlab.packet.IpPrefix;
import org.onlab.util.KryoNamespace;
import org.onlab.util.SharedScheduledExecutors;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import com.cxc.ngsdn.api.IntConfig;
import com.cxc.ngsdn.api.IntIntent;
import com.cxc.ngsdn.api.IntIntentId;
import com.cxc.ngsdn.api.IntObjective;
import com.cxc.ngsdn.api.IntProgrammable;
import com.cxc.ngsdn.api.IntService;
//import org.onosproject.incubator.net.tunnel.cli.TunnelRemoveCommand;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.AtomicIdGenerator;
import org.onosproject.store.service.AtomicValue;
import org.onosproject.store.service.AtomicValueEvent;
import org.onosproject.store.service.AtomicValueEventListener;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.MapEvent;
import org.onosproject.store.service.MapEventListener;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.util.*;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.stream.Collectors;

import static com.cxc.ngsdn.AppConstants.CPU_CLONE_SESSION_ID;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkPositionIndex;
import static org.slf4j.LoggerFactory.getLogger;

import static com.cxc.ngsdn.AppConstants.REPORT_MIRROR_SESSION_ID;

//import com.cxc.ngsdn.api.IntDevice;

/**
 * Simple implementation of IntService, for controlling INT-capable pipelines.
 * <p>
 * All INT intents are converted to an equivalent INT objective and applied to
 * all SOURCE_SINK devices. A device is deemed SOURCE_SINK if it has at least
 * one host attached.
 * <p>
 * The implementation listens for different types of events and when required it
 * configures a device by cleaning-up any previous state and applying the new
 * one.
 */
@Component(immediate = true, service = IntService.class)
public class SimpleIntManager implements IntService {

    private final Logger log = getLogger(getClass());

    private ApplicationId appId;

    private static final int CONFIG_EVENT_DELAY = 5; // Seconds.

    private static final int INT_SESSION_ID = 0; // Seconds.

    private final PortNumber mirrorPort = PortNumber.portNumber(4);

//    private static final String APP_NAME = "org.onosproject.inbandtelemetry";

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private IntentReactiveForwarding intentReactiveForwarding;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private com.cxc.ngsdn.IntDevice intDevice;

    private final Striped<Lock> deviceLocks = Striped.lock(10);

    private final ConcurrentMap<DeviceId, ScheduledFuture<?>> scheduledDeviceTasks = Maps.newConcurrentMap();
    private final ConcurrentMap<Triple<DeviceId,IntDeviceRole,Integer>, ScheduledFuture<?>> scheduledIntDeviceTasks = Maps.newConcurrentMap();

    // Distributed state.
    private ConsistentMap<IntIntentId, IntIntent> intentMap;
    private ConsistentMap<DeviceId, Long> devicesToConfigure;
    private ConsistentMap<Triple<DeviceId,IntDeviceRole,Integer>, Long> intDevicesToConfigure;
    private AtomicValue<IntConfig> intConfig;
    private AtomicValue<Boolean> intStarted;
    private AtomicIdGenerator intentIds;

    // Event listeners.
    private final InternalHostListener hostListener = new InternalHostListener();
    private final InternalDeviceListener deviceListener = new InternalDeviceListener();
    private final InternalIntentMapListener intentMapListener = new InternalIntentMapListener();
    private final InternalIntConfigListener intConfigListener = new InternalIntConfigListener();
    private final InternalIntStartedListener intStartedListener = new InternalIntStartedListener();
    private final InternalDeviceToConfigureListener devicesToConfigureListener =
            new InternalDeviceToConfigureListener();
    private final InternalIntDeviceToConfigureListener intDevicesToConfigureListener =
            new InternalIntDeviceToConfigureListener();

    // Kryo是一个快速高效的Java序列化框架，旨在提供快速、高效和易用的API。无论文件、数据库或网络数据Kryo都可以随时完成序列化。Kryo还可以执行自动深拷贝（克隆）、浅拷贝（克隆）。这是对象到对象的直接拷贝，而不是对象->字节->对象的拷贝。

    @Activate
    public void activate() {

        // final ApplicationId appId = coreService.registerApplication(APP_NAME);
        log.info("Int Service is activing.");
        appId = mainComponent.getAppId();

        // 注册要序列化的类.
        // 在注册类的时候，Kryo会给每个类关联一个唯一的ID，不同的类的ID不一样，当在序列化类的对象时，Kryo只需保存这个类的ID信息，就可以识别序列化对象的类信息了。相对于保存完整的类名称信息，这种序列化方式能够提高效率。因此，不同程序或线程在对同样的对象信息序列化和去序列化时，要保证同样的类的注册ID是一样的。
        KryoNamespace.Builder serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(IntIntent.class)
                .register(IntIntentId.class)
                .register(IntDeviceRole.class)
                .register(IntIntent.IntHeaderType.class)
                .register(IntIntent.IntMetadataType.class)
                .register(IntIntent.IntReportType.class)
                .register(IntIntent.TelemetryMode.class)
                .register(IntConfig.class)
                .register(IntConfig.TelemetrySpec.class);

        devicesToConfigure = storageService.<DeviceId, Long>consistentMapBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("onos-int-devices-to-configure")
                .withApplicationId(appId)
                .withPurgeOnUninstall()
                .build();
        devicesToConfigure.addListener(devicesToConfigureListener);

        intDevicesToConfigure = storageService.<Triple<DeviceId,IntDeviceRole,Integer>, Long>consistentMapBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("onos-int-devices-to-configure")
                .withApplicationId(appId)
                .withPurgeOnUninstall()
                .build();
        intDevicesToConfigure.addListener(intDevicesToConfigureListener);

        intentMap = storageService.<IntIntentId, IntIntent>consistentMapBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("onos-int-intents")
                .withApplicationId(appId)
                .withPurgeOnUninstall()
                .build();
        intentMap.addListener(intentMapListener);

        intStarted = storageService.<Boolean>atomicValueBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("onos-int-started")
                .withApplicationId(appId)
                .build()
                .asAtomicValue();
        intStarted.addListener(intStartedListener);

        intConfig = storageService.<IntConfig>atomicValueBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("onos-int-config")
                .withApplicationId(appId)
                .build()
                .asAtomicValue();
        intConfig.addListener(intConfigListener);

        intentIds = storageService.getAtomicIdGenerator("int-intent-id-generator");

        // Bootstrap config for already existing devices.
//        triggerAllDeviceConfigure();

//        hostService.addListener(hostListener);
//        deviceService.addListener(deviceListener);

//        startInt();
        log.info("Started", appId.id());
    }

    @Deactivate
    public void deactivate() {
        deviceService.removeListener(deviceListener);
        hostService.removeListener(hostListener);
        intentIds = null;
        intConfig.removeListener(intConfigListener);
        intConfig = null;
        intStarted.removeListener(intStartedListener);
        intStarted = null;
        intentMap.removeListener(intentMapListener);
        intentMap = null;
        devicesToConfigure.removeListener(devicesToConfigureListener);
        devicesToConfigure.destroy();
        devicesToConfigure = null;
        // Cancel tasks (if any).
        scheduledDeviceTasks.values().forEach(f -> {
            f.cancel(true);
            if (!f.isDone()) {
                try {
                    f.get(1, TimeUnit.SECONDS);
                } catch (InterruptedException | ExecutionException | TimeoutException e) {
                    // Don't care, we are terminating the service anyways.
                }
            }
        });
        // Clean up INT rules from existing devices.
        deviceService.getDevices().forEach(d -> cleanupDevice(d.id()));
        log.info("Deactivated");
    }
    
    // 这里的intStarted变量是全局性的。代表的整个INT是否启动了没有。并不是针对具体设备的。
    @Override
    public void startInt() {
        // Atomic value event will trigger device configure.
        log.info("Now Start INT");
//        triggerAllDeviceConfigure();
        intStarted.set(true);
        initAllIntDevice();
    }

    public void trigger(){
        triggerAllDeviceConfigure();
    }


    @Override
    public void startInt(Set<DeviceId> deviceIds) {
        log.warn("Starting INT for a subset of devices is not supported");
    }

    @Override
    public void stopInt() {
        // Atomic value event will trigger device configure.
        // 虽然也触发了设备配置，但感觉什么都没有做。应该要执行intProg.cleanup().
        // 当然，设置了intStarted flase以后，监听到新主机，新设备后不会再动设备的配置。
        intStarted.set(false);
    }

    @Override
    public void stopInt(Set<DeviceId> deviceIds) {
        log.warn("Stopping INT for a subset of devices is not supported");
    }

    @Override
    public void setConfig(IntConfig cfg) {
        checkNotNull(cfg);
        // Atomic value event will trigger device configure.
        intConfig.set(cfg);
    }

    @Override
    public IntConfig getConfig() {
        return intConfig.get();
    }

//    @Override
    public void initAllIntDevice(){
        log.info("init All Int Device");
        deviceService.getDevices().forEach(d ->{
                    configIntTransitDevice(d.id());
                }
        );
    }

    // 看起来，IntConfig其实是IntCollector的相关配置，主要用来发现INT report所需要的。
    // 而IntIntent是INT的真正的遥测意图，包含INT的类型，INT的对什么流量感兴趣，要采集什么样的数据，同时也包含了intConfig(也就是指示要如何收集INT的metadata)
    // 而intObject则是包含了包含INT的类型，INT的对什么流量感兴趣，要采集什么样的数据
    @Override
    public IntIntentId installIntIntent(IntIntent intent) {
        checkNotNull(intent);
        final Integer intentId = (int) intentIds.nextId();
        final IntIntentId intIntentId = IntIntentId.valueOf(intentId);
        // Intent map event will trigger device configure.
        // intentMap.put(intIntentId, intent);
        // 这里的intent里的内容会被转到intObjective里面，然后使用intProg.addObjective.

        initAllIntDevice();

        Set<ConnectPoint> sourceCPs  = new HashSet<>();

//        TODO: need to change to mulit ports. now it 's only one connetctpoint.
// 看起来scp已经是多个端口了？
// 这里是根据intIntent对什么流量感兴趣（目前在设置感兴趣流量的时候必须有指定源IPv6地址），来计算出INT的source port，而非把所有端口都设定为INT  source port。
// TODO: 这个获取sourcePOrt的功能看起来应该放到intIntent.class里才比较合理，别的地方要用的话只要调用相关函数就可以的。
//          Optional<ConnectPoint> sourceCP =

                  intent.selector().criteria().stream()
                // 有点局限。要求在定义intIntent的感兴趣的流量的时候，必须定义源IP地址。后面可能需要改进。
                .filter(criterion -> (criterion.type() == Criterion.Type.IPV6_SRC) )
                .map( criterion -> ((IPCriterion) criterion ).ip())
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .forEach(prefix -> {
                    Optional<ConnectPoint> scp =intentReactiveForwarding.getConnectPointOfSubnet(prefix);
                    if(scp.isPresent()){
                        sourceCPs.add(scp.get());
                    }
                    });

            if(sourceCPs.size() ==0 ){
                log.info("can't find source ports");
                return intIntentId;
            }

        final Collection<IntObjective> objectives =  Collections.singleton(intent.getIntObjectives());

        configIntSourceDevice(sourceCPs,objectives);


        Set<ConnectPoint> sinkCPs  = new HashSet<>();

        intent.selector().criteria().stream()
                .filter(criterion -> (criterion.type() == Criterion.Type.IPV6_DST) )
                .map( criterion -> ((IPCriterion) criterion ).ip())
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .forEach(prefix -> {
                    Optional<ConnectPoint> scp =intentReactiveForwarding.getConnectPointOfSubnet(prefix);
                    if(scp.isPresent()){
                        sinkCPs.add(scp.get());
                    }
                });

        if(sinkCPs.size() ==0 ){
            log.info("can't find sink ports");
            return intIntentId;
        }

        configIntSinkDevice(sinkCPs,intent.intConfig());
        return intIntentId;

    }


    @Override
    public void removeIntIntent(IntIntentId intentId) {
        checkNotNull(intentId);
        // Intent map event will trigger device configure.
        // TODO:好像也没有真正从设备上删除intIntent？？
        intentMap.remove(intentId).value();
    }

    @Override
    public IntIntent getIntIntent(IntIntentId intentId) {
        return Optional.ofNullable(intentMap.get(intentId).value()).orElse(null);
    }

    @Override
    public Map<IntIntentId, IntIntent> getIntIntents() {
        return intentMap.asJavaMap();
    }

    private boolean isConfigTaskValid(DeviceId deviceId, long creationTime) {
        Versioned<?> versioned = devicesToConfigure.get(deviceId);
        return versioned != null && versioned.creationTime() == creationTime;
    }

    private boolean isIntStarted() {
        return intStarted.get();
    }

    private boolean isNotIntConfigured() {
        return intConfig.get() == null;
    }

    private boolean isIntProgrammable(DeviceId deviceId) {
        final Device device = deviceService.getDevice(deviceId);
        //为什么 device.is(IntProgrammable.class)会失败？
//        return device != null && device.is(IntProgrammable.class);
        return device != null ;
    }

    private void triggerDeviceConfigure(DeviceId deviceId) {
        if (isIntProgrammable(deviceId)) {
            log.info("devicesToConfigure from here");
            devicesToConfigure.put(deviceId, System.nanoTime());
        }
    }

    private void triggerAllDeviceConfigure() {
        log.info("triggerAllDeviceConfigure from here");
//        deviceService.getDevices().forEach(d -> triggerDeviceConfigure(d.id()));
        deviceService.getDevices().forEach(d ->{
            log.info("triggerAllDeviceConfigure from here, {} ", d.id());
            triggerDeviceConfigure(d.id());
                }
        );
    }

    private void configDeviceTask(DeviceId deviceId, long creationTime) {
        if (isConfigTaskValid(deviceId, creationTime)) {
            // Task outdated.
            //TODO： 为什么Valid反而被认为是过期了呢？？？这个要研究下。到时候用log看下。
            // 后续有新的event触发对该设备的config的话，这个时候不是valid的，
            log.info("Do Nothing because configDevice is valid!");
            return;
        }
        if (!deviceService.isAvailable(deviceId)) {
            return;
        }
        final MastershipRole role = mastershipService.requestRoleForSync(deviceId);
        if (!role.equals(MastershipRole.MASTER)) {
            return;
        }
        deviceLocks.get(deviceId).lock();
        try {
            // Clean up first.
            cleanupDevice(deviceId);
            if (!configDevice(deviceId)) {
                // Clean up if fails.
                cleanupDevice(deviceId);
                return;
            }
            devicesToConfigure.remove(deviceId);
        } finally {
            deviceLocks.get(deviceId).unlock();
        }
    }

    private void configIntDeviceTask(Triple<DeviceId,IntDeviceRole,Integer> deviceWithRoleSession, long creationTime) {
//        if (isConfigTaskValid(deviceId, creationTime)) {
//            // Task outdated.
//            //TODO： 为什么Valid反而被认为是过期了呢？？？这个要研究下。到时候用log看下。
//            // 后续有新的event触发对该设备的config的话，这个时候不是valid的，
//            log.info("Do Nothing because configDevice is valid!");
//            return;
//        }
        DeviceId deviceId = deviceWithRoleSession.getLeft();
        if (!deviceService.isAvailable(deviceId)) {
            return;
        }
        final MastershipRole role = mastershipService.requestRoleForSync(deviceId);
        if (!role.equals(MastershipRole.MASTER)) {
            return;
        }
        deviceLocks.get(deviceId).lock();
        try {
            // Clean up first.
            cleanupDevice(deviceId);
            if (!configDevice(deviceId)) {
                // Clean up if fails.
                cleanupDevice(deviceId);
                return;
            }
            devicesToConfigure.remove(deviceId);
        } finally {
            deviceLocks.get(deviceId).unlock();
        }
    }

    private void cleanupDevice(DeviceId deviceId) {
        final Device device = deviceService.getDevice(deviceId);
        if (device == null || !device.is(IntProgrammable.class)) {
            return;
        }
        device.as(IntProgrammable.class).cleanup();
    }

    private boolean configDevice(DeviceId deviceId) {
        // Returns true if config was successful, false if not and a clean up is
        // needed.
        // 如果配置失败，那么才需要cleanupDevice。
        // 如果没法开始配置，比如设备不支持INT，那么这个时候就要返回true。否则返回false的话，会触发cleanupDevice.
        // 其实应该考虑分为三种状态：配置失败；配置成功；没法开始进行配置。现在是后面2种处于同一个状态下。


        final Device device = deviceService.getDevice(deviceId);
//        if (device == null || !device.is(IntProgrammable.class)) {
        if (device == null) {
            return true;
        }
//        else {
//            IntDevice intDevice = new IntDevice(deviceId,appId);
//        }


        if (isNotIntConfigured()) {
            log.warn("Missing INT config, aborting programming of INT device {}", deviceId);
            return true;
        }

        // 这个判断方法不是太好。太粗糙了，只是简单地把有主机的设备看成是边缘设备，就同时授予 sourc和sink的角色，而其他的所有设备就全部授予为SINK设备。
        // 中间的设备也应该可以授予source和SINK的角色。
        // 要把source, sink, transit完全分开，而且是相对自由的设定。
        final boolean isEdge = !hostService.getConnectedHosts(deviceId).isEmpty();
        final IntDeviceRole intDeviceRole = isEdge
                ? IntDeviceRole.SOURCE_SINK
                : IntDeviceRole.TRANSIT;

        log.info("Started programming of INT device {} with role {}...",
                 deviceId, intDeviceRole);

        final IntProgrammable intProg = device.as(IntProgrammable.class);

        if (!isIntStarted()) {
            // Leave device with no INT configuration.
            return true;
        }

        if (!intProg.init()) {
            log.warn("Unable to init INT pipeline on {}", deviceId);
            return false;
        }

        if (intDeviceRole != IntDeviceRole.SOURCE_SINK) {
            // Stop here, no more configuration needed for transit devices.
            return true;
        }

        // 如果是sink设备，就下发生成telemetry report的相关配置。
        // 其实这个if的结果必定是true。TRANSIT的设备已经不往下处理了。
        if (intProg.supportsFunctionality(IntProgrammable.IntFunctionality.SINK)) {
            if (!intProg.setupIntConfig(intConfig.get())) {
                log.warn("Unable to apply INT report config on {}", deviceId);
                return false;
            }
        }

        // Port configuration.
        // 找出有主机在线的端口。如果主机还没有上线怎么办？？
        final Set<PortNumber> hostPorts = deviceService.getPorts(deviceId)
                .stream()
                .map(port -> new ConnectPoint(deviceId, port.number()))
                .filter(cp -> !hostService.getConnectedHosts(cp).isEmpty())
                .map(ConnectPoint::port)
                .collect(Collectors.toSet());

        
        //  这里是把有主机连接的device设备都看成是SOURCE和SINK节点了。这个很粗暴，应该是真正区分设备的角色。
        //  设备如果支持SOURCE或者SINK，就把所有带主机的接口都设置为INT source port/INT sink port，看起来不是很合理。太粗暴了。
        for (PortNumber port : hostPorts) {
            if (intProg.supportsFunctionality(IntProgrammable.IntFunctionality.SOURCE)) {
                log.info("Setting port {}/{} as INT source port...", deviceId, port);
                if (!intProg.setSourcePort(port)) {
                    log.warn("Unable to set INT source port {} on {}", port, deviceId);
                    return false;
                }
            }
            if (intProg.supportsFunctionality(IntProgrammable.IntFunctionality.SINK)) {
                log.info("Setting port {}/{} as INT sink port...", deviceId, port);
                if (!intProg.setSinkPort(port)) {
                    log.warn("Unable to set INT sink port {} on {}", port, deviceId);
                    return false;
                }
            }
        }

        if (!intProg.supportsFunctionality(IntProgrammable.IntFunctionality.SOURCE)) {
            // Stop here, no more configuration needed for sink devices.
            return true;
        }

        // Apply intents.
        // This is a trivial implementation where we simply get the
        // corresponding INT objective from an intent and we apply to all source
        // device.
        final Collection<IntObjective> objectives = intentMap.values().stream()
                .map(v -> getIntObjective(v.value()))
                .collect(Collectors.toList());
        int appliedCount = 0;
        for (IntObjective objective : objectives) {
            if (intProg.addIntObjective(objective)) {
                appliedCount = appliedCount + 1;
            }
        }

        log.info("Completed programming of {}, applied {} INT objectives of {} total",
                 deviceId, appliedCount, objectives.size());

        return true;
    }

// set source ports for source node; set intobjects for source nodes.
    private boolean configIntSourceDevice(Set<ConnectPoint> sourceCPS,Collection<IntObjective> objectives) {

        for (ConnectPoint cp : sourceCPS
             ) {

            DeviceId deviceId = cp.deviceId();
            log.info("Started programming of INT device {} with role SOURCE.", deviceId);

//            IntDevice intDevice = new IntDevice(deviceId,appId);
            PortNumber port = cp.port();

                log.info("Setting port {}/{} as INT source port...", deviceId, port);
                if (!intDevice.setSourcePort(deviceId,port)) {
                    log.warn("Unable to set INT source port {} on {}", port, deviceId);
                    return false;
                }

        //TODO : maybe repeat apply flowrules. need to correct it.
            int appliedCount = 0;
            for (IntObjective objective : objectives) {
                if (intDevice.addIntObjective(deviceId,objective)) {
                    appliedCount = appliedCount + 1;
                }
            }


            if(appliedCount > 0 ) {
                log.info("Completed programming of {}, applied {} INT objectives of {} total",
                        deviceId, appliedCount, objectives.size());
            } else {
                return false;
            }

        }
        return  true;

    }

//    // set source ports for source node; set intobjects for source nodes.
//    private boolean configIntSourceDevice(DeviceId deviceId, Set<PortNumber> sourcePorts,Collection<IntObjective> objectives) {
//
//        log.info("Started programming of INT device {} with role SOURCE.", deviceId);
//
//        IntDevice intDevice = new IntDevice(deviceId);
//
//        //  这里是把有主机连接的device设备都看成是SOURCE和SINK节点了。这个很粗暴，应该是真正区分设备的角色。
//        //  设备如果支持SOURCE或者SINK，就把所有带主机的接口都设置为INT source port/INT sink port，看起来不是很合理。太粗暴了。
//        for (PortNumber port : sourcePorts) {
//            log.info("Setting port {}/{} as INT source port...", deviceId, port);
//            if (!intDevice.setSourcePort(port)) {
//                log.warn("Unable to set INT source port {} on {}", port, deviceId);
//                return false;
//            }
//        }
//
//        // Apply intents.
//        // This is a trivial implementation where we simply get the
//        // corresponding INT objective from an intent and we apply to all source
//        // device.
////        final Collection<IntObjective> objectives = intentMap.values().stream()
////                .map(v -> getIntObjective(v.value()))
////                .collect(Collectors.toList());
//        int appliedCount = 0;
//        for (IntObjective objective : objectives) {
//            if (intDevice.addIntObjective(objective)) {
//                appliedCount = appliedCount + 1;
//            }
//        }
//
//
//        if(appliedCount > 0 ) {
//            log.info("Completed programming of {}, applied {} INT objectives of {} total",
//                    deviceId, appliedCount, objectives.size());
//            return true;
//        } else {
//            return false;
//        }
//
//    }

    private boolean configIntTransitDevice(DeviceId deviceId) {

        log.info("Started programming of INT device {} with role Transit.", deviceId);

//        IntDevice intDevice = new IntDevice(deviceId,appId);

        intDevice.init(deviceId);
//        flowRuleService.applyFlowRules(intDevice.init());

        return true;
    }

    private boolean configIntSinkDevice(Set<ConnectPoint> sinkCPs, IntConfig intConfig) {

//        final Device device = deviceService.getDevice(deviceId);

        for ( ConnectPoint  cp : sinkCPs
             ) {

            DeviceId deviceId = cp.deviceId();
            PortNumber port = cp.port();
//            IntDevice intDevice = new IntDevice(deviceId,appId);

//        if (isNotIntConfigured()) {
//            log.warn("Missing INT config, aborting programming of INT device {}", deviceId);
//            return true;
//        }

            log.info("Started programming of INT device {} with role SINK.", deviceId);

//        final IntProgrammable intProg = device.as(IntProgrammable.class);

// TODO:            disable temp
            if (!intDevice.setupIntConfig(deviceId,intConfig)) {
                log.warn("Unable to apply INT report config on {}", deviceId);
                return false;
            }

                log.info("Setting port {}/{} as INT sink port...", deviceId, port);
                if (!intDevice.setSinkPort(deviceId,port)) {
                    log.warn("Unable to set INT sink port {} on {}", port, deviceId);
                    return false;
                }

            log.info("Setup the mirror port {}/{} ",deviceId,mirrorPort);

            final GroupDescription cloneGroup = Utils.buildCloneGroup(
                    appId,
                    deviceId,
                    REPORT_MIRROR_SESSION_ID,
//                    500,
                    // Ports where to clone the packet.
                    // Just controller in this case.
                    Collections.singleton(mirrorPort));

            groupService.addGroup(cloneGroup);

            log.info("Completed programming of INT sink device {} ",deviceId);

        }


        return true;

    }

//    private boolean configIntSinkDevice(DeviceId deviceId,Set<PortNumber> sinkPorts, IntConfig intConfig) {
//
////        final Device device = deviceService.getDevice(deviceId);
//        IntDevice intDevice = new IntDevice(deviceId);
//
////        if (isNotIntConfigured()) {
////            log.warn("Missing INT config, aborting programming of INT device {}", deviceId);
////            return true;
////        }
//
//        log.info("Started programming of INT device {} with role SINK.", deviceId);
//
////        final IntProgrammable intProg = device.as(IntProgrammable.class);
//
//
//        // 如果是sink设备，就下发生成telemetry report的相关配置。
//        // 其实这个if的结果必定是true。TRANSIT的设备已经不往下处理了。
//        if (!intDevice.setupIntConfig(intConfig)) {
//            log.warn("Unable to apply INT report config on {}", deviceId);
//            return false;
//        }
//
//        //  这里是把有主机连接的device设备都看成是SOURCE和SINK节点了。这个很粗暴，应该是真正区分设备的角色。
//        //  设备如果支持SOURCE或者SINK，就把所有带主机的接口都设置为INT source port/INT sink port，看起来不是很合理。太粗暴了。
//        for (PortNumber port : sinkPorts) {
//            log.info("Setting port {}/{} as INT sink port...", deviceId, port);
//            if (!intDevice.setSinkPort(port)) {
//                log.warn("Unable to set INT sink port {} on {}", port, deviceId);
//                return false;
//            }
//        }
//
//        log.info("Completed programming of INT sink device {} ",deviceId);
//        return true;
//    }

    private boolean configIntDevice(Triple<DeviceId,IntDeviceRole,Integer> deviceWithRoleSession) {
        // Returns true if config was successful, false if not and a clean up is
        // needed.
        // 如果配置失败，那么才需要cleanupDevice。
        // 如果没法开始配置，比如设备不支持INT，那么这个时候就要返回true。否则返回false的话，会触发cleanupDevice.
        // 其实应该考虑分为三种状态：配置失败；配置成功；没法开始进行配置。现在是后面2种处于同一个状态下。

        DeviceId deviceId = deviceWithRoleSession.getLeft();
        IntDeviceRole intDeviceRole = deviceWithRoleSession.getMiddle();
// TODO:       cxc: now we don't use the int session ID. will be used later. maybe need to storage IntSession ID.

        final Device device = deviceService.getDevice(deviceId);
//        if (device == null || !device.is(IntProgrammable.class)) {
        if (device == null) {
            return true;
        }
//        else {
//            IntDevice intDevice = new IntDevice(deviceId,appId);
//        }

        if (!isIntStarted()) {
            // Leave device with no INT configuration.
            return true;
        }

//        IntIntent.Builder  aa = IntIntent.builder();
//        aa.withHeaderType().build();




//only used for INT sink device.
        if (isNotIntConfigured()) {
            log.warn("Missing INT config, aborting programming of INT device {}", deviceId);
            return true;
        }

        // 这个判断方法不是太好。太粗糙了，只是简单地把有主机的设备看成是边缘设备，就同时授予 sourc和sink的角色，而其他的所有设备就全部授予为SINK设备。
        // 中间的设备也应该可以授予source和SINK的角色。
        // 要把source, sink, transit完全分开，而且是相对自由的设定。
//        final boolean isEdge = !hostService.getConnectedHosts(deviceId).isEmpty();
//        final IntDeviceRole intDeviceRole = isEdge
//                ? IntDeviceRole.SOURCE_SINK
//                : IntDeviceRole.TRANSIT;


//        log.info("Started programming of INT device {} with role {}...",
//                deviceId, intDeviceRole);

        final IntProgrammable intProg = device.as(IntProgrammable.class);


        if (!intProg.init()) {
            log.warn("Unable to init INT pipeline on {}", deviceId);
            return false;
        }


        // 如果是sink设备，就下发生成telemetry report的相关配置。
        // 其实这个if的结果必定是true。TRANSIT的设备已经不往下处理了。
        if (intProg.supportsFunctionality(IntProgrammable.IntFunctionality.SINK)) {
            if (!intProg.setupIntConfig(intConfig.get())) {
                log.warn("Unable to apply INT report config on {}", deviceId);
                return false;
            }
        }

        // Port configuration.
        // 找出有主机在线的端口。如果主机还没有上线怎么办？？
        final Set<PortNumber> hostPorts = deviceService.getPorts(deviceId)
                .stream()
                .map(port -> new ConnectPoint(deviceId, port.number()))
                .filter(cp -> !hostService.getConnectedHosts(cp).isEmpty())
                .map(ConnectPoint::port)
                .collect(Collectors.toSet());


        //  这里是把有主机连接的device设备都看成是SOURCE和SINK节点了。这个很粗暴，应该是真正区分设备的角色。
        //  设备如果支持SOURCE或者SINK，就把所有带主机的接口都设置为INT source port/INT sink port，看起来不是很合理。太粗暴了。
        for (PortNumber port : hostPorts) {
            if (intProg.supportsFunctionality(IntProgrammable.IntFunctionality.SOURCE)) {
                log.info("Setting port {}/{} as INT source port...", deviceId, port);
                if (!intProg.setSourcePort(port)) {
                    log.warn("Unable to set INT source port {} on {}", port, deviceId);
                    return false;
                }
            }
            if (intProg.supportsFunctionality(IntProgrammable.IntFunctionality.SINK)) {
                log.info("Setting port {}/{} as INT sink port...", deviceId, port);
                if (!intProg.setSinkPort(port)) {
                    log.warn("Unable to set INT sink port {} on {}", port, deviceId);
                    return false;
                }
            }
        }

        if (!intProg.supportsFunctionality(IntProgrammable.IntFunctionality.SOURCE)) {
            // Stop here, no more configuration needed for sink devices.
            return true;
        }

        // Apply intents.
        // This is a trivial implementation where we simply get the
        // corresponding INT objective from an intent and we apply to all source
        // device.
        final Collection<IntObjective> objectives = intentMap.values().stream()
                .map(v -> getIntObjective(v.value()))
                .collect(Collectors.toList());
        int appliedCount = 0;
        for (IntObjective objective : objectives) {
            if (intProg.addIntObjective(objective)) {
                appliedCount = appliedCount + 1;
            }
        }

        log.info("Completed programming of {}, applied {} INT objectives of {} total",
                deviceId, appliedCount, objectives.size());

        return true;
    }

    private IntObjective getIntObjective(IntIntent intent) {
        return new IntObjective.Builder()
                .withSelector(intent.selector())
                .withMetadataTypes(intent.metadataTypes())
                .withHeaderType(intent.headerType())
                .build();
    }

    /* Event listeners which trigger device configuration. */

    private class InternalHostListener implements HostListener {
        @Override
        public void event(HostEvent event) {
            final DeviceId deviceId = event.subject().location().deviceId();
            triggerDeviceConfigure(deviceId);
        }
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_ADDED:
                case DEVICE_UPDATED:
                case DEVICE_REMOVED:
                case DEVICE_SUSPENDED:
                case DEVICE_AVAILABILITY_CHANGED:
                case PORT_ADDED:
                case PORT_UPDATED:
                case PORT_REMOVED:
                    triggerDeviceConfigure(event.subject().id());
                    return;
                case PORT_STATS_UPDATED:
                    return;
                default:
                    log.warn("Unknown device event type {}", event.type());
            }
        }
    }

    private class InternalIntentMapListener
            implements MapEventListener<IntIntentId, IntIntent> {
        @Override
        public void event(MapEvent<IntIntentId, IntIntent> event) {
            triggerAllDeviceConfigure();
        }
    }

    private class InternalIntIntentMapListener
            implements MapEventListener<IntIntentId, IntIntent> {
        @Override
        public void event(MapEvent<IntIntentId, IntIntent> event) {

            triggerAllDeviceConfigure();

        }
    }

    private class InternalIntConfigListener
            implements AtomicValueEventListener<IntConfig> {
        @Override
        public void event(AtomicValueEvent<IntConfig> event) {
            triggerAllDeviceConfigure();
        }
    }

    private class InternalIntStartedListener
            implements AtomicValueEventListener<Boolean> {
        @Override
        public void event(AtomicValueEvent<Boolean> event) {
            log.info("capture intstart single!");
            // 要AtomicValue发生变化，才会触发这个event事件。
            triggerAllDeviceConfigure();
        }
    }

    private class InternalDeviceToConfigureListener
            implements MapEventListener<DeviceId, Long> {
        @Override
        public void event(MapEvent<DeviceId, Long> event) {
            if (event.type().equals(MapEvent.Type.REMOVE) ||
                    event.newValue() == null) {
                return;
            }
            // Schedule task in the future. Wait for events for this device to
            // stabilize.
            final DeviceId deviceId = event.key();
            final long creationTime = event.newValue().creationTime();
            ScheduledFuture<?> newTask = SharedScheduledExecutors.newTimeout(
                    () -> configDeviceTask(deviceId, creationTime),
                    CONFIG_EVENT_DELAY, TimeUnit.SECONDS);
            // 这个时候newTask还没有真正执行。
            // put()的使用是：添加时出现相同的键，那么后添加的值会替换（覆盖）掉此键对应的原来的值。并返回此键对应的原来的值。
            // 这样deviceId上如果有旧的任务，就会返回旧的任务，然后把旧的任务取消掉。
            // 但是如果oldTask is done呢？这时候的cancel就没有意义了。oldtask is done的时候，会告知scheduledDeviceTasks吗?
            // confiureDevice成功后，会有 devicesToConfigure.remove(deviceId);
            ScheduledFuture<?> oldTask = scheduledDeviceTasks.put(deviceId, newTask);
            if (oldTask != null) {
                oldTask.cancel(false);
            }
        }
    }

    private class InternalIntDeviceToConfigureListener
            implements MapEventListener<Triple<DeviceId,IntDeviceRole,Integer>, Long> {
        @Override
        public void event(MapEvent<Triple<DeviceId,IntDeviceRole,Integer>, Long> event) {
            if (event.type().equals(MapEvent.Type.REMOVE) ||
                    event.newValue() == null) {
                return;
            }
            // Schedule task in the future. Wait for events for this device to
            // stabilize.
            final DeviceId deviceId = event.key().getLeft();
            final long creationTime = event.newValue().creationTime();
            ScheduledFuture<?> newTask = SharedScheduledExecutors.newTimeout(
                    () -> configIntDeviceTask(event.key(), creationTime),
                    CONFIG_EVENT_DELAY, TimeUnit.SECONDS);
            // 这个时候newTask还没有真正执行。
            // put()的使用是：添加时出现相同的键，那么后添加的值会替换（覆盖）掉此键对应的原来的值。并返回此键对应的原来的值。
            // 这样deviceId上如果有旧的任务，就会返回旧的任务，然后把旧的任务取消掉。
            // 但是如果oldTask is done呢？这时候的cancel就没有意义了。oldtask is done的时候，会告知scheduledDeviceTasks吗?
            // confiureDevice成功后，会有 devicesToConfigure.remove(deviceId);
            ScheduledFuture<?> oldTask = scheduledIntDeviceTasks.put(event.key(), newTask);
            if (oldTask != null) {
                oldTask.cancel(false);
            }
        }
    }
}
