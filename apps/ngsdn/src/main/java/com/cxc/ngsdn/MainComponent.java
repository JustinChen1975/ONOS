//package org.onosproject.ngsdn.tutorial;
package com.cxc.ngsdn;

import com.google.common.collect.Lists;
import org.onlab.util.SharedScheduledExecutors;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.group.Group;
import org.onosproject.net.group.GroupService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import com.cxc.ngsdn.common.FabricDeviceConfig;
import com.cxc.ngsdn.pipeconf.PipeconfLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.cxc.ngsdn.AppConstants.APP_NAME;
import static com.cxc.ngsdn.AppConstants.CLEAN_UP_DELAY;
import static com.cxc.ngsdn.AppConstants.DEFAULT_CLEAN_UP_RETRY_TIMES;
import static com.cxc.ngsdn.common.Utils.sleep;

/**
 * A component which among other things registers the fabricDeviceConfig to the
 * netcfg subsystem.
 */
@Component(immediate = true, service = MainComponent.class)
public class MainComponent {

    private static final Logger log =
            LoggerFactory.getLogger(MainComponent.class.getName());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    //Force activation of this component after the pipeconf has been registered.
    @SuppressWarnings("unused")
    protected PipeconfLoader pipeconfLoader;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry configRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private ComponentConfigService compCfgService;

	//下面就是匿名类的写法。
    //但是不太清楚在写什么。可以先依样画葫芦。
    // FabricDeviceConfig.class是自己定义的。用于读取设备的相关配置信息（自定义的）。
    private final ConfigFactory<DeviceId, FabricDeviceConfig> fabricConfigFactory =
            new ConfigFactory<DeviceId, FabricDeviceConfig>(
                    SubjectFactories.DEVICE_SUBJECT_FACTORY, FabricDeviceConfig.class, FabricDeviceConfig.CONFIG_KEY) {
                @Override
                public FabricDeviceConfig createConfig() {
                    return new FabricDeviceConfig();
                }
            };

    private ApplicationId appId;

    // For the sake of simplicity and to facilitate reading logs, use a
    // single-thread executor to serialize all configuration tasks.
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);

        // Wait to remove flow and groups from previous executions.
        // 清理以前的groups和flows 
        waitPreviousCleanup();

        // 这应该是在设置一些ONOS的参数。
        compCfgService.preSetProperty("org.onosproject.net.flow.impl.FlowRuleManager",
                                      "fallbackFlowPollFrequency", "4", false);
        compCfgService.preSetProperty("org.onosproject.net.group.impl.GroupManager",
                                      "fallbackGroupPollFrequency", "3", false);
        compCfgService.preSetProperty("org.onosproject.provider.host.impl.HostLocationProvider",
                                      "requestIpv6ND", "true", false);
        compCfgService.preSetProperty("org.onosproject.provider.lldp.impl.LldpLinkProvider",
                                      "useBddp", "false", false);

        configRegistry.registerConfigFactory(fabricConfigFactory);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        configRegistry.unregisterConfigFactory(fabricConfigFactory);

        cleanUp();

        log.info("Stopped");
    }

    /**
     * Returns the application ID.
     *
     * @return application ID
     */
    ApplicationId getAppId() {
        return appId;
    }

    /**
     * Returns the executor service managed by this component.
     *
     * @return executor service
     */
    public ExecutorService getExecutorService() {
        return executorService;
    }

    /**
     * Schedules a task for the future using the executor service managed by
     * this component.
     在别的component中会调用到
     看起来是个通用的包装。会延时一定时间执行指定的task。
     *
     * @param task task runnable
     * @param delaySeconds delay in seconds
     */
    public void scheduleTask(Runnable task, int delaySeconds) {
        SharedScheduledExecutors.newTimeout(
                () -> executorService.execute(task),
                delaySeconds, TimeUnit.SECONDS);
    }

    /**
     * Triggers clean up of flows and groups from this app, returns false if no
     * flows or groups were found, true otherwise.
     *
     * @return false if no flows or groups were found, true otherwise
     */
    private boolean cleanUp() {
        Collection<FlowRule> flows = Lists.newArrayList(
                flowRuleService.getFlowEntriesById(appId).iterator());

		//这里的group的概念应该是ONOS的概念。看起来是给flowrules分组。分组后对不同的组进行操作。
		/**
		 * Service for create/update/delete "group" in the devices.
		 * Flow entries can point to a "group" defined in the devices that enables
		 * to represent additional methods of forwarding like load-balancing or
		 * failover among different group of ports or multicast to all ports
		 * specified in a group.
		group也可以跨越不同的flows里的通用的actions。
		 * "group" can also be used for grouping common actions of different flows,
		 * so that in some scenarios only one group entry required to be modified
		 * for all the referencing flow entries instead of modifying all of them.
		 *
		 * This implements semantics of a distributed authoritative group store
		 * where the master copy of the groups lies with the controller and
		 * the devices hold only the 'cached' copy.
        */
        Collection<Group> groups = Lists.newArrayList();
        for (Device device : deviceService.getAvailableDevices()) {
            groupService.getGroups(device.id(), appId).forEach(groups::add);
        }

        if (flows.isEmpty() && groups.isEmpty()) {
            return false;
        }

        flows.forEach(flowRuleService::removeFlowRules);
        if (!groups.isEmpty()) {
            // Wait for flows to be removed in case those depend on groups.
            sleep(1000);
            groups.forEach(g -> groupService.removeGroup(
                    g.deviceId(), g.appCookie(), g.appId()));
        }

        return true;
    }

    private void waitPreviousCleanup() {
        int retry = DEFAULT_CLEAN_UP_RETRY_TIMES;
        while (retry != 0) {

            if (!cleanUp()) {
                return;
            }

            log.info("Waiting to remove flows and groups from " +
                             "previous execution of {}...",
                     appId.name());

            sleep(CLEAN_UP_DELAY);

            --retry;
        }
    }
}

// ONOS中Interface和Port的区别：
// Port：
// 端口位于OSI模型的第1层，物理层。这层定义了设备的电气和物理规格，如铜或光纤媒体以及电压、线路阻抗、信号配时、和物理布局引脚连接装置如双绞线、同轴电缆或光纤电缆单模或多模的情况。
// Interface：
// 接口位于OSI模型的第2层，即数据链路层。这一层定义的功能和程序之间的传输网络设备数据的方法，如串口，以太网，FDDI和令牌环。此外，该层可能提供检测和纠正物理层可能发生的错误的能力。