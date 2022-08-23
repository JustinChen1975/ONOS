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

// interpreterImple并非一定需要的。
// 这个程序只对packet-in和packet-out的数据包进行处理。是吧？
// Interpreter 主要是處理 ONOS API 轉換至 PI API 的工作

package com.cxc.ngsdn.pipeconf;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPacketMetadataId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.PortNumber.CONTROLLER;
import static org.onosproject.net.PortNumber.FLOOD;
import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static org.onosproject.net.flow.instructions.Instructions.OutputInstruction;
import static org.onosproject.net.pi.model.PiPacketOperationType.PACKET_OUT;
// 在AppConstants文件里定义了CPU port ID
import static com.cxc.ngsdn.AppConstants.CPU_PORT_ID;
import static org.slf4j.LoggerFactory.getLogger;


/**
 * Interpreter implementation.
 */
public class InterpreterImpl extends AbstractHandlerBehaviour
        implements PiPipelineInterpreter {

    private final Logger log = getLogger(getClass());

    // From v1model.p4。v1model.p4中对port的定义为9个位的宽度。
    private static final int V1MODEL_PORT_BITWIDTH = 9;

    // From P4Info.
    //如果P4Info里有自定义的报文字段，没有与之相应的ONOS type，要怎么处理？
    private static final Map<Criterion.Type, String> CRITERION_MAP =
            new ImmutableMap.Builder<Criterion.Type, String>()
                    .put(Criterion.Type.IN_PORT, "standard_metadata.ingress_port")
                    .put(Criterion.Type.ETH_DST, "hdr.ethernet.dst_addr")
                    .put(Criterion.Type.ETH_SRC, "hdr.ethernet.src_addr")
                    .put(Criterion.Type.ETH_TYPE, "hdr.ethernet.ether_type")
                    .put(Criterion.Type.IPV6_DST, "hdr.ipv6.dst_addr")
                    .put(Criterion.Type.IP_PROTO, "local_metadata.ip_proto")
                    .put(Criterion.Type.ICMPV4_TYPE, "local_metadata.icmp_type")
                    .put(Criterion.Type.ICMPV6_TYPE, "local_metadata.icmp_type")
                    .build();

    /**
     * Returns a collection of PI packet operations populated with metadata
     * specific for this pipeconf and equivalent to the given ONOS
     * OutboundPacket instance.
     * ONOS发出来的数据报文，也就是packet-out的报文就在这里翻译的。
     *
     * @param packet ONOS OutboundPacket
     * @return collection of PI packet operations
     * @throws PiInterpreterException if the packet treatments cannot be
     *                                executed by this pipeline
     *
     */

    //  mapOutboundPacket: 將 ONOS PacketOut 轉換成 PI 格式，即 metadata + paylad
    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet)
            throws PiInterpreterException {
        TrafficTreatment treatment = packet.treatment();

        //这段程序应该是处理ONOS内部发出的packet-out，然后要转化为pipeconf上能理解的PiAction
        //实际处理P4程序中仅仅理解output port，因此对于packt-out报文里的指令不是output的，就不处理。

        // Packet-out in main.p4 supports only setting the output port,
        // i.e. we only understand OUTPUT instructions.
        List<OutputInstruction> outInstructions = treatment
                .allInstructions()
                .stream()
                .filter(i -> i.type().equals(OUTPUT))
                .map(i -> (OutputInstruction) i)
                .collect(toList());

        if (treatment.allInstructions().size() != outInstructions.size()) {
            // There are other instructions that are not of type OUTPUT.
            throw new PiInterpreterException("Treatment not supported: " + treatment);
        }

        ImmutableList.Builder<PiPacketOperation> builder = ImmutableList.builder();
        for (OutputInstruction outInst : outInstructions) {
            if (outInst.port().isLogical() && !outInst.port().equals(FLOOD)) {
                throw new PiInterpreterException(format(
                        "Packet-out on logical port '%s' not supported",
                        outInst.port()));
            } else if (outInst.port().equals(FLOOD)) {
                // To emulate flooding, we create a packet-out operation for
                // each switch port.
                 //下面这句话写了跟白写似的？
                final DeviceService deviceService = handler().get(DeviceService.class);
                for (Port port : deviceService.getPorts(packet.sendThrough())) {
                    builder.add(buildPacketOut(packet.data(), port.number().toLong()));
                }
            } else {
                // Create only one packet-out for the given OUTPUT instruction.
                builder.add(buildPacketOut(packet.data(), outInst.port().toLong()));
            }
        }

        //这里的build()应该是对应静态内部类builder，目的是生成一个collection
        return builder.build();
    }

    /**
     * Builds a pipeconf-specific packet-out instance with the given payload and
     * egress port.
     类型是packet_out， 有数据的payload， 还有metadata（这里的metadata是egress_port以及它的值）
     *
     * @param pktData    packet payload
     * @param portNumber egress port
     * @return packet-out
     * @throws PiInterpreterException if packet-out cannot be built
     */
    private PiPacketOperation buildPacketOut(ByteBuffer pktData, long portNumber)
            throws PiInterpreterException {

        // Make sure port number can fit in v1model port metadata bitwidth.
        final ImmutableByteSequence portBytes;
        try {
            portBytes = copyFrom(portNumber).fit(V1MODEL_PORT_BITWIDTH);
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            throw new PiInterpreterException(format(
                    "Port number %d too big, %s", portNumber, e.getMessage()));
        }

        // Create metadata instance for egress port.
        // *** TODO EXERCISE 4: modify metadata names to match P4 program
        // 会自动加上standard_metadata后成为standard_metadata.egress_port？
        // ---- START SOLUTION ----
        final String outPortMetadataName = "egress_port";
        // ---- END SOLUTION ----
        final PiPacketMetadata outPortMetadata = PiPacketMetadata.builder()
                .withId(PiPacketMetadataId.of(outPortMetadataName))
                .withValue(portBytes)
                .build();

        // Build packet out.
        return PiPacketOperation.builder()
                .withType(PACKET_OUT)
                .withData(copyFrom(pktData))
                .withMetadata(outPortMetadata)
                .build();
    }

    /**
     * Returns an ONS InboundPacket equivalent to the given pipeconf-specific
     * packet-in operation.
     *
    对于packet-in的数据包，
    把pipeconf的特定的packet-in转换成为ONOS的InboundPacket Instance吧。后端应该有ONOS的内置APP来解读这个InboundPacket,然后进行处理吧，处理后再发生flow rules的吧。
     * @param packetIn packet operation
     * @param deviceId ID of the device that originated the packet-in
     * @return inbound packet
     * @throws PiInterpreterException if the packet operation cannot be mapped
     *                                to an inbound packet
     */
    //  mapInboundPacket: 將 ONOS PacketIn 轉換成 PI 格式
    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId)
            throws PiInterpreterException {

        // Find the ingress_port metadata.
        // ---- START SOLUTION ----
        final String inportMetadataName = "ingress_port";
        // ---- END SOLUTION ----
        Optional<PiPacketMetadata> inportMetadata = packetIn.metadatas()
                .stream()
                .filter(meta -> meta.id().id().equals(inportMetadataName))
                .findFirst();
        // findFirst()是返回第一个值吧。

        //必须要有metaName为"ingress_port"，要和P4Info里的一致。不存在的话会被丢弃。
        if (!inportMetadata.isPresent()) {
            log.info("Receive packet from  {} ,but no metadata ", deviceId);
            throw new PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    inportMetadataName, deviceId, packetIn));
        }

        // Build ONOS InboundPacket instance with the given ingress port.

        // 1. Parse packet-in object into Ethernet packet instance.
        final byte[] payloadBytes = packetIn.data().asArray();
        final ByteBuffer rawData = ByteBuffer.wrap(payloadBytes);
        final Ethernet ethPkt;
        try {
            ethPkt = Ethernet.deserializer().deserialize(
                    payloadBytes, 0, packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiInterpreterException(dex.getMessage());
        }

        // 2. Get ingress port
        final ImmutableByteSequence portBytes = inportMetadata.get().value();
        final short portNum = portBytes.asReadOnlyBuffer().getShort();
        final ConnectPoint receivedFrom = new ConnectPoint(
                deviceId, PortNumber.portNumber(portNum));

        return new DefaultInboundPacket(receivedFrom, ethPkt, rawData);
    }

    @Override
    public Optional<Integer> mapLogicalPortNumber(PortNumber port) {
        if (CONTROLLER.equals(port)) {
            return Optional.of(CPU_PORT_ID);
        } else {
            return Optional.empty();
        }
    }

    // mapCriterionType: 將 ONOS Criterion 轉換成 PI match 欄位
    // mapPiMatchFieldId: 將 PI match 欄位轉換成普通的 Criterion
    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        if (CRITERION_MAP.containsKey(type)) {
            return Optional.of(PiMatchFieldId.of(CRITERION_MAP.get(type)));
        } else {
            return Optional.empty();
        }
    }

    // mapTreatment: 將 ONOS 的 TrafficTreatment 加上 TableId 轉換成 PiAction，這主要是要解決多個 Action 對到單一個 Action 的問題
    //cxc： treatment应该是ONOS的标准处理，里面包含instructions等。要翻译成为PiAction。PiAction是属于P4runtime的，不是ONOS固有的。这个函数就是把ONOS的“处理”指令翻译成为P4程序中的对应action名字以及该action所需要的参数。
    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId)
            throws PiInterpreterException {
        throw new PiInterpreterException("Treatment mapping not supported");
    }

    // • mapFlowRuleTableId: 將數字 Id 轉換成像是 P4 一樣使用字串的 Id
    //为什么要返回empty()?
    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        return Optional.empty();
    }

    // mapPiTableId: 將字串 Id 轉換回數字 Id

}




// 下面是来自于myTunnel的，放在下面用来参考的。

//AtomicInteger这个类的存在是为了满足在高并发的情况下,原生的整形数值自增线程不安全的问题
// private AtomicInteger nextTunnelId = new AtomicInteger();

//pathlinks是个列表，列表中的每个元素是个link
// List<Link> pathLinks;

//pathlinks是个列表，列表中的每个元素是个link。对每个link都执行insertTunnelFowrwardRule，就可以实现对path上的所有交换机进行处理。
//     for (Link link : pathLinks) {
//         DeviceId sw = link.src().deviceId();
//         PortNumber port = link.src().port();
//         insertTunnelForwardRule(sw, port, tunId, false);
// }

// 	//cxc： treatment应该是ONOS的标准处理，里面包含instructions等。要翻译成为PiAction。PiAction是属于P4runtime的，不是ONOS固有的。这个函数就是把ONOS的“处理”指令翻译成为P4程序中的对应action名字以及该action所需要的参数。
// 	    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId)
// 	            throws PiInterpreterException {
	
// 	        if (piTableId != TABLE_L2_FWD_ID) {
// 	            throw new PiInterpreterException(
// 	                    "Can map treatments only for 't_l2_fwd' table");
// 	        }
	
// 	        if (treatment.allInstructions().size() == 0) {
// 	            // 0 instructions means "NoAction"
// 	            //陈晓筹：如果指令的数量是0，那意味着"NoAction"
// 	            return PiAction.builder().withId(ACT_ID_NOP).build();
// 	        } else if (treatment.allInstructions().size() > 1) {
// 	            // We understand treatments with only 1 instruction. 
// 		//陈晓筹：意思是不能下多个指令吧。一次只能发一个指令。
// 	            throw new PiInterpreterException("Treatment has multiple instructions");
// 	        }
	
// 	        // Get the first and only instruction.
// 	        Instruction instruction = treatment.allInstructions().get(0);
	
		
// 	        if (instruction.type() != OUTPUT) {
// 	            // We can map only instructions of type OUTPUT.
// 		//有多个指令类型，但是这里只对OUTPUT类型的做翻译。
// 		//那么P4程序里的其他action类型，比如drop应该是在其它地方处理吧。
// 	            throw new PiInterpreterException(format(
// 	                    "Instruction of type '%s' not supported", instruction.type()));
// 	        }
	
// 	        OutputInstruction outInstruction = (OutputInstruction) instruction;
// 	        PortNumber port = outInstruction.port();
// 		//陈晓筹：isLogical就是看该port是不是个保留名，比如CONTROLLER之类的。
// 	        if (!port.isLogical()) {
// 	            return PiAction.builder()
// 		//陈晓筹：.withId(ACT_ID_SET_EGRESS_PORT) 这里翻译为C_INGRESS + DOT + "set_out_port" ， 也就是c_ingress.set_out_port
// 		//c_ingress.set_out_port对应的就是下面的P4程序中的action set_out_port，因为该action是在c_ingress这个block块里面，所以该action的全名是c_ingress.set_out_port
// 		   action set_out_port(port_t port) {
// 		        // Specifies the output port for this packet by setting the
// 		        // corresponding metadata.
// 		        standard_metadata.egress_spec = port;
// 		    }
// 		//
// 	                    .withId(ACT_ID_SET_EGRESS_PORT) 
// 	//  ACT_PARAM_ID_PORT对应的是“port”,也就是action set_out_port里需要的参数“port".
// 	                    .withParameter(new PiActionParam(
// 	                            ACT_PARAM_ID_PORT, copyFrom(port.toLong())))
// 	                    .build();
// 	        } else if (port.equals(CONTROLLER)) {
// 	            return PiAction.builder()
// 		//ACT_ID_SEND_TO_CPU对应的是c_ingress.send_to_cpu。 P4程序里的action send_to_cpu不需要参数。所以下面就不需要withParameter
// 	                    .withId(ACT_ID_SEND_TO_CPU)
// 	                    .build();
// 	        } else {
// 	            throw new PiInterpreterException(format(
// 	                    "Output on logical port '%s' not supported", port));
// 	        }
// 	    }
	
	
// 	/**
// 	PiPacketOperation是P4  runtime的
// 	 * Instance of a packet I/O operation that includes the packet body (frame) and
// 	 * its metadata, for a protocol-independent pipeline.
// 	 */
// 	    @Override
// 	    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet)
// 	            throws PiInterpreterException {
	
// 		//看来ONOS是会给packet提供treatment的。上一个函数的treatment是从哪里来的？
// 	        TrafficTreatment treatment = packet.treatment();
	
// 	        // We support only packet-out with OUTPUT instructions.
// 	        if (treatment.allInstructions().size() != 1 &&
// 	                treatment.allInstructions().get(0).type() != OUTPUT) {
// 	            throw new PiInterpreterException(
// 	                    "Treatment not supported: " + treatment.toString());
// 	        }
	
// 	        Instruction instruction = treatment.allInstructions().get(0);
// 	        PortNumber port = ((OutputInstruction) instruction).port();
// 	        List<PiPacketOperation> piPacketOps = Lists.newArrayList();
	
// 	        if (!port.isLogical()) {
// 	            piPacketOps.add(createPiPacketOp(packet.data(), port.toLong()));
// 	        } else if (port.equals(FLOOD)) {
// 	            // Since mytunnel.p4 does not support flooding, we create a packet
// 	            // operation for each switch port.
// 	           //看来可以考虑由P4程序直接提供对flood的支持。FLOOD应该是ONOS下发的port的名字，类似CONTROLLER等
// 		// handle()是来自于import org.onosproject.net.driver.AbstractHandlerBehaviour
// 		//下面这句不是太理解。
// 	            DeviceService deviceService = handler().get(DeviceService.class);
// 		//sendThrough()返回的是该packet应该被送往的设备的DeviceId
// 	            DeviceId deviceId = packet.sendThrough();
// 		//下面的for的写法很简练
// 	            for (Port p : deviceService.getPorts(deviceId)) {
// 	                piPacketOps.add(createPiPacketOp(packet.data(), p.number().toLong()));
// 	            }
// 	        } else {
// 	            throw new PiInterpreterException(format(
// 	                    "Output on logical port '%s' not supported", port));
// 	        }
	
// 		//piPacketOps后面要怎么用？
// 	        return piPacketOps;
// 	    }
	
// 	    @Override
// 	    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId)
// 	            throws PiInterpreterException {
// 	        // We assume that the packet is ethernet, which is fine since mytunnel.p4
// 	        // can deparse only ethernet packets.
// 	        Ethernet ethPkt;
	
// 	        try {
// 	            ethPkt = Ethernet.deserializer().deserialize(
// 	                    packetIn.data().asArray(), 0, packetIn.data().size());
// 	        } catch (DeserializationException dex) {
// 	            throw new PiInterpreterException(dex.getMessage());
// 	        }
	
// 	        // Returns the ingress port packet metadata.
// 	        Optional<PiPacketMetadata> packetMetadata = packetIn.metadatas().stream()
// 	                .filter(metadata -> metadata.id().toString().equals(INGRESS_PORT))
// 	                .findFirst();
	
// 	        if (packetMetadata.isPresent()) {
// 	            short s = packetMetadata.get().value().asReadOnlyBuffer().getShort();
// 	            ConnectPoint receivedFrom = new ConnectPoint(
// 	                    deviceId, PortNumber.portNumber(s));
// 	            return new DefaultInboundPacket(
// 	                    receivedFrom, ethPkt, packetIn.data().asReadOnlyBuffer());
// 	        } else {
// 	            throw new PiInterpreterException(format(
// 	                    "Missing metadata '%s' in packet-in received from '%s': %s",
// 	                    INGRESS_PORT, deviceId, packetIn));
// 	        }
// 	    }
	
// 	    private PiPacketOperation createPiPacketOp(ByteBuffer data, long portNumber)
// 	            throws PiInterpreterException {
// 	        PiPacketMetadata metadata = createPacketMetadata(portNumber);
// 	        return PiPacketOperation.builder()
// 	                .withType(PACKET_OUT)
// 	                .withData(copyFrom(data))
// 	//看起来可以包括多个的metaData。metaData是作为List存在的。
// 	                .withMetadatas(ImmutableList.of(metadata))
// 	                .build();
// 	    }
	
// 	//这里的metaData看起来仅仅是包含了output端口，egress_port字符串与 port端口号。
// 	//看起来是不完全的metaData;会自动加上standard_metadata后成为standard_metadata.egress_port
	
// 	    private PiPacketMetadata createPacketMetadata(long portNumber)
// 	            throws PiInterpreterException {
// 	        try {
// 	            return PiPacketMetadata.builder()
// 	                    .withId(PiPacketMetadataId.of(EGRESS_PORT))
// 	                    .withValue(copyFrom(portNumber).fit(PORT_FIELD_BITWIDTH))
// 	                    .build();
// 	        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
// 	            throw new PiInterpreterException(format(
// 	                    "Port number %d too big, %s", portNumber, e.getMessage()));
// 	        }
// 	    }
// }



// private void insertTunnelForwardRule(DeviceId switchId,
// 	                                         PortNumber outPort,
// 	                                         int tunId,
// 	                                         boolean isEgress) {
	
// 		//对应P4程序里的  table t_tunnel_fwd 
// 	        PiTableId tunnelForwardTableId = PiTableId.of("c_ingress.t_tunnel_fwd");
	
// 	        // Exact match on tun_id
// 	        PiMatchFieldId tunIdMatchFieldId = PiMatchFieldId.of("hdr.my_tunnel.tun_id");
// 		//生成匹配条件，结果是PiCriterion。matchExact()函数是要求"hdr.my_tunnel.tun_id"等于tunId的话，就算匹配上了。
// 	        PiCriterion match = PiCriterion.builder()
// 	                .matchExact(tunIdMatchFieldId, tunId)
// 	                .build();
	
// 	        // Action depend on isEgress parameter.
// 	        // if true, perform tunnel egress action on the given outPort, otherwise
// 	        // simply forward packet as is (set_out_port action).
// 	        PiActionParamId portParamId = PiActionParamId.of("port");
// 		//这里的PiActionParam()函数应该是为"port"这个参数提供具体的数值，也就是outPort.toLong()。
// 	        PiActionParam portParam = new PiActionParam(portParamId, (short) outPort.toLong());
	
// 	        final PiAction action;
// 	        if (isEgress) {
// 	            // Tunnel egress action.
// 	            // Remove MyTunnel header and forward to outPort.
// 		//P4程序里的t_tunnel_fwd有个action是my_tunnel_egress
// 	            PiActionId egressActionId = PiActionId.of("c_ingress.my_tunnel_egress");
// 	            action = PiAction.builder()
// 	                    .withId(egressActionId)
// 	                    .withParameter(portParam)
// 	                    .build();
// 	        } else {
// 	            // Tunnel transit action.
// 	            // Forward the packet as is to outPort.
// 	            /*
// 	             * TODO EXERCISE: create action object for the transit case.
// 	             * Look at the t_tunnel_fwd table in the P4 program. Which of the 3
// 	             * actions can be used to simply set the output port? Get the full
// 	             * action name from the P4Info file, and use that when creating the
// 	             * PiActionId object. When creating the PiAction object, remember to
// 	             * add all action parameters as defined in the P4 program.
// 	             *
// 	             * Hint: the code will be similar to the case when isEgress is true.
// 	             */
// 		// action = null; // Replace null with your solution.
// 		            // Tunnel transit action.
// 		            // Forward the packet as is to outPort.
// 		            PiActionId egressActionId = PiActionId.of("c_ingress.set_out_port");
// 		            action = PiAction.builder()
// 		                    .withId(egressActionId)
// 		                    .withParameter(portParam)
// 		                    .build();
		
// 	        }
	
// 	        log.info("Inserting {} rule on switch {}: table={}, match={}, action={}",
// 	                 isEgress ? "EGRESS" : "TRANSIT",
// 	                 switchId, tunnelForwardTableId, match, action);
	
// 	        insertPiFlowRule(switchId, tunnelForwardTableId, match, action);
// 	    }
	
// 	    /**
// 	     * Inserts a flow rule in the system that using a PI criterion and action.
// 	     *
// 	     * @param switchId    switch ID
// 	     * @param tableId     table ID
// 	     * @param piCriterion PI criterion
// 	     * @param piAction    PI action
// 	     */
// 	    private void insertPiFlowRule(DeviceId switchId, PiTableId tableId,
// 	                                  PiCriterion piCriterion, PiAction piAction) {
// 	        FlowRule rule = DefaultFlowRule.builder()
// 	                .forDevice(switchId)
// 	                .forTable(tableId)
// 	                .fromApp(appId)
// 	                .withPriority(FLOW_RULE_PRIORITY)
// 	                .makePermanent()
// 		//这里返回的是trafficSelector.要把piCriterion转化为ONOS标准的trafficSelector.
// 	                .withSelector(DefaultTrafficSelector.builder()
// 	                                      .matchPi(piCriterion).build())
// 	            //这里要把piAction转化为ONOS里的标准treatment.
// 	                .withTreatment(DefaultTrafficTreatment.builder()
// 	                                       .piTableAction(piAction).build())
// 	                .build();
// 	        flowRuleService.applyFlowRules(rule);
// 	    }
	
// 	    private int getNewTunnelId() {
// 	        return nextTunnelId.incrementAndGet();
// 	    }
	
// 	    private Path pickRandomPath(Set<Path> paths) {
// 		//带参的nextInt(int x)则会生成一个范围在0~x（不包含X）内的任意正整数
// 	        int item = new Random().nextInt(paths.size());
// 		//lists.是guava的工具
// 	        List<Path> pathList = Lists.newArrayList(paths);
// 	        return pathList.get(item);
// 	    }
	
// 	    /**
// 	     * A listener of host events that provisions two tunnels for each pair of
// 	     * hosts when a new host is discovered.
// 	     */
// 	    private class InternalHostListener implements HostListener {
		
// 		//对接口中的event进行了重写。
// 	        @Override
// 	        public void event(HostEvent event) {
// 	            if (event.type() != HostEvent.Type.HOST_ADDED) {
// 	                // Ignore other host events.
// 	                return;
// 	            }
// 	            synchronized (this) {
// 	                // Synchronizing here is an overkill, but safer for demo purposes.
// 	                Host host = event.subject();  //这里的subject会返回host，因为前面过滤了，只有HOST_ADDED的才过滤。
// 	                Topology topo = topologyService.currentTopology();
// 	                for (Host otherHost : hostService.getHosts()) {
// 	                    if (!host.equals(otherHost)) {
// 			//当遇到新的host pairs的时候，看起来是会自动创建一个新的TunnelID
// 	                        provisionTunnel(getNewTunnelId(), host, otherHost, topo);
// 	                        provisionTunnel(getNewTunnelId(), otherHost, host, topo);
// 	                    }
// 	                }
// 	            }
// 	        }
// 	    }
// 	}
	

