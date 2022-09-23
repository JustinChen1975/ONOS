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



package com.cxc.ngsdn.pipeconf;

import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.NextGroup;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.behaviour.PipelinerContext;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.FilteringObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.NextObjective;
import org.onosproject.net.flowobjective.ObjectiveError;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import com.cxc.ngsdn.common.Utils;
import org.slf4j.Logger;

import java.util.Collections;
import java.util.List;

import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static com.cxc.ngsdn.AppConstants.CPU_CLONE_SESSION_ID;
import static org.slf4j.LoggerFactory.getLogger;

// pipelinerImple也并非一定需要的。
// Pipeliner 是專門將 FlowObjective 轉換成 Flow + Group 的一個組件

/**
 * Pipeliner implementation that maps all forwarding objectives to the ACL
 * table. All other types of objectives are not supported.
 */
//  	本程序只把forwarding objectives送给ACL table.其他类型的objective(比如filteringObjectve等）都不予以支持。
// 		是ONOS中的lldp等程序下发了如下的流表给设备。貌似生成流表之前的是ForwardingObjective。要求这个obj里的treatment是送个控制器的。
// 		也就是lldp等APP要下发一些流表给设备，这些流表是让满足条件的流量要被送给控制器去处理。满足条件的流量的类型是arp,bbdp,lldp, ICMP等。
// 		这些流表需要P4设备上的具体的table去处理，因此需要把main.p4里的具体的table名字和action名字告诉OONS APP。
// 			 private static final String ACL_TABLE = "IngressPipeImpl.acl_table";
// 			 private static final String CLONE_TO_CPU = "IngressPipeImpl.clone_to_cpu";
// 		但是这些流表规则可能会改写对前面的流量的处理方式。因为higher numbers mean higher priorities.
// 		通过这些流量，数据流会被送给ONOS，然后ONOS上的APP会侦听处理。比如自定的NdpReplyComponent。
// 如果多个APP在侦听，可能会有冲突。

	// 	cxc@root > flows | grep acl_table
	// 	    id=1000010a5cc8c, state=ADDED, bytes=3458022, packets=28114, duration=43577, liveType=UNKNOWN, priority=40000, tableId=IngressPipeImpl.acl_table, appId=org.onosproject.core, selector=[ETH_TYPE:lldp], treatment=DefaultTrafficTreatment{immediate=[IngressPipeImpl.clone_to_cpu()], deferred=[], transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}
	// 	    id=1000037c6f64c, state=ADDED, bytes=0, packets=0, duration=43577, liveType=UNKNOWN, priority=40000, tableId=IngressPipeImpl.acl_table, appId=org.onosproject.core, selector=[ETH_TYPE:arp], treatment=DefaultTrafficTreatment{immediate=[IngressPipeImpl.clone_to_cpu()], deferred=[], transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}
	// 	    id=1000044445b4a, state=ADDED, bytes=0, packets=0, duration=43577, liveType=UNKNOWN, priority=40000, tableId=IngressPipeImpl.acl_table, appId=org.onosproject.core, selector=[ETH_TYPE:bddp], treatment=DefaultTrafficTreatment{immediate=[IngressPipeImpl.clone_to_cpu()], deferred=[], transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}
	// 	    id=100005a67e58d, state=ADDED, bytes=0, packets=0, duration=43577, liveType=UNKNOWN, priority=40000, tableId=IngressPipeImpl.acl_table, appId=org.onosproject.core, selector=[ETH_TYPE:ipv6, IP_PROTO:58, ICMPV6_TYPE:135], treatment=DefaultTrafficTreatment{immediate=[IngressPipeImpl.clone_to_cpu()], deferred=[], transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}
    // id=10000fb13df92, state=ADDED, bytes=0, packets=0, duration=43577, liveType=UNKNOWN, priority=40000, tableId=IngressPipeImpl.acl_table, appId=org.onosproject.core, selector=[ETH_TYPE:ipv6, IP_PROTO:58, ICMPV6_TYPE:136], treatment=DefaultTrafficTreatment{immediate=[IngressPipeImpl.clone_to_cpu()], deferred=[], transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}


public class PipelinerImpl extends AbstractHandlerBehaviour implements Pipeliner {

    // From the P4Info file
    private static final String ACL_TABLE = "IngressPipeImpl.acl_table";
    private static final String CLONE_TO_CPU = "IngressPipeImpl.clone_to_cpu";

    private final Logger log = getLogger(getClass());

    private FlowRuleService flowRuleService;
    private GroupService groupService;
    private DeviceId deviceId;


    @Override
    public void init(DeviceId deviceId, PipelinerContext context) {
        this.deviceId = deviceId;
        this.flowRuleService = context.directory().get(FlowRuleService.class);
        this.groupService = context.directory().get(GroupService.class);
    }

    // FilteringObjective：用來表示允許或是擋掉封包進入 Pipeliner 的規則
    // 这个例子里下发特定的流表，这些流表要求一些在遇到一些数据包的时候，要上传给ONOS控制器。
    @Override
    public void filter(FilteringObjective obj) {
        //下面这句是什么意思？意味着如果被调用到filter的话，表明不支持。
        obj.context().ifPresent(c -> c.onError(obj, ObjectiveError.UNSUPPORTED));
    }

    // ForwardingObjective：用來描述封包在 Pipeliner 中需要如何去處理
    //只支持ForwardingObjective
    @Override
    public void forward(ForwardingObjective obj) {
        if (obj.treatment() == null) {
            obj.context().ifPresent(c -> c.onError(obj, ObjectiveError.UNSUPPORTED));
        }

        // Whether this objective specifies an OUTPUT:CONTROLLER instruction.
        final boolean hasCloneToCpuAction = obj.treatment()
                .allInstructions().stream()
                .filter(i -> i.type().equals(OUTPUT))
                .map(i -> (Instructions.OutputInstruction) i)
                .anyMatch(i -> i.port().equals(PortNumber.CONTROLLER));
        //anyMatch意味着有一个匹配到，那么就终止了。

        if (!hasCloneToCpuAction) {
            // We support only objectives for clone to CPU behaviours (e.g. for
            // host and link discovery)
              //那么谁给traffic的treatment()添加上instructions，要求送给控制器呢？
            obj.context().ifPresent(c -> c.onError(obj, ObjectiveError.UNSUPPORTED));
        }

        // 事实上，这个flowrule也应该可以在APP里完成吧，不一定非得在pipelinerimple.java完成吧？
        // Create an equivalent FlowRule with same selector and clone_to_cpu action.
        final PiAction cloneToCpuAction = PiAction.builder()
                .withId(PiActionId.of(CLONE_TO_CPU))
                .build();

        final FlowRule.Builder ruleBuilder = DefaultFlowRule.builder()
                .forTable(PiTableId.of(ACL_TABLE))
                .forDevice(deviceId)
                .withSelector(obj.selector())
                .fromApp(obj.appId())
                .withPriority(obj.priority())
                .withTreatment(DefaultTrafficTreatment.builder()
                                       .piTableAction(cloneToCpuAction).build());

        // 这里是定义flowrule的timeout或者设置为
        if (obj.permanent()) {
            ruleBuilder.makePermanent();
        } else {
            ruleBuilder.makeTemporary(obj.timeout());
        }

        final GroupDescription cloneGroup = Utils.buildCloneGroup(
                obj.appId(),
                deviceId,
                CPU_CLONE_SESSION_ID,
                // Ports where to clone the packet.
                // Just controller in this case.
                Collections.singleton(PortNumber.CONTROLLER));

        switch (obj.op()) {
            case ADD:
                flowRuleService.applyFlowRules(ruleBuilder.build());
                groupService.addGroup(cloneGroup);
                break;
            case REMOVE:
                flowRuleService.removeFlowRules(ruleBuilder.build());
                // Do not remove the clone group as other flow rules might be
                // pointing to it.
                break;
            default:
                log.warn("Unknown operation {}", obj.op());
        }

        obj.context().ifPresent(c -> c.onSuccess(obj));
    }
    
    // NextObjective：用來描述 Egress table 裡面需要放置什麼樣的東西
    @Override
    public void next(NextObjective obj) {
        obj.context().ifPresent(c -> c.onError(obj, ObjectiveError.UNSUPPORTED));
    }

    @Override
    public List<String> getNextMappings(NextGroup nextGroup) {
        // We do not use nextObjectives or groups.
        return Collections.emptyList();
    }
}
