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
//package com.cxc.ngsdn.cli;
package com.cxc.ngsdn.cli;

import com.cxc.ngsdn.IntentReactiveForwarding;
import com.cxc.ngsdn.api.IntConfig;
import com.cxc.ngsdn.api.IntIntent;
import com.cxc.ngsdn.api.IntService;
import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.net.DeviceIdCompleter;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import com.cxc.ngsdn.Srv6Component;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;

import com.cxc.ngsdn.api.IntIntent.IntHeaderType;
import com.cxc.ngsdn.api.IntIntent.IntMetadataType;
import com.cxc.ngsdn.api.IntIntent.IntReportType;
import com.cxc.ngsdn.api.IntIntent.TelemetryMode;

//import com.cxc.ngsdn.pipeconf.IntProgrammableImpl;

import java.util.List;
import java.util.stream.Collectors;


/**
 * INT Insert Command
 */
@Service
@Command(scope = "onos", name = "int-insert",
         description = "Insert rules about INT into devices")
public class IntInsertCommand extends AbstractShellCommand {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private IntService intService;

//    @Argument(index = 0, name = "uri", description = "Device ID",
//              required = true, multiValued = false)
//    @Completion(DeviceIdCompleter.class)
//    String uri = null;
//
//    @Argument(index = 1, name = "segments",
//            description = "SRv6 Segments (space separated list); last segment is target IP address",
//            required = false, multiValued = true)
//    @Completion(Srv6SidCompleter.class)
//    List<String> segments = null;

    @Override
    protected void doExecute() {
        intService = get(IntService.class);

//        print("INT started");
        print("init all INT devices");
        intService.startInt();

        IntConfig.Builder intconfigBuilder = IntConfig.builder();

               intconfigBuilder.enabled(true)
                        .withCollectorIp(Ip6Address.valueOf("2001:6:1::1f"))
                        .withCollectorPort(TpPort.tpPort(1234))
                .withSinkIp(Ip6Address.valueOf("2001:6:1::ff"))
                .withSinkMac(MacAddress.NONE)
                .withCollectorNextHopMac(MacAddress.BROADCAST);

               IntConfig intConfig = intconfigBuilder.build();

        TrafficSelector.Builder sBuilder = DefaultTrafficSelector.builder();
//        sBuilder.
        sBuilder.matchIPv6Src(Ip6Address.valueOf("2001:1:1::a").toIpPrefix())
                .matchIPv6Dst(Ip6Address.valueOf("2001:6:1::f").toIpPrefix());
//                .matchIPSrc(IpAddress.valueOf("210.34.0.1").toIpPrefix())
//                .matchIPDst(IpAddress.valueOf("210.35.0.1").toIpPrefix());


        TrafficSelector intSelector = sBuilder.build();

        IntIntent.Builder builder = IntIntent.builder();

        IntIntent intIntent =
        builder.withSelector(intSelector)
                .withHeaderType(IntHeaderType.HOP_BY_HOP)
                .withReportType(IntReportType.TRACKED_FLOW)
                .withTelemetryMode(TelemetryMode.INBAND_TELEMETRY)
                .withMetadataType(IntMetadataType.SWITCH_ID)
                .withMetadataType(IntMetadataType.HOP_LATENCY)
                .withIntConfig(intConfig)
                .build();

        print("install INT intent");
        intService.installIntIntent(intIntent);

//      IntConfig.Builder builder = IntConfig.builder();

    }

}
//
//                            case "SWITCH_ID":
//                                    builder.withMetadataType(IntIntent.IntMetadataType.SWITCH_ID);
//                                    break;
//                                    case "PORT_ID":
//                                    builder.withMetadataType(IntIntent.IntMetadataType.L1_PORT_ID);
//                                    break;
//                                    case "HOP_LATENCY":
//                                    builder.withMetadataType(IntIntent.IntMetadataType.HOP_LATENCY);
//                                    break;
//                                    case "QUEUE_OCCUPANCY":
//                                    builder.withMetadataType(IntIntent.IntMetadataType.QUEUE_OCCUPANCY);
//                                    break;
//                                    case "INGRESS_TIMESTAMP":
//                                    builder.withMetadataType(IntIntent.IntMetadataType.INGRESS_TIMESTAMP);
//                                    break;
//                                    case "EGRESS_TIMESTAMP":
//                                    builder.withMetadataType(IntIntent.IntMetadataType.EGRESS_TIMESTAMP);
//                                    break;
//                                    case "EGRESS_TX_UTIL":
//                                    builder.withMetadataType(IntIntent.IntMetadataType.EGRESS_TX_UTIL);
//                                    break;


//        if (payload.get("collectorIp") != null) {
//            builder.withCollectorIp(IpAddress.valueOf(payload.get("collectorIp").asText()));
//        } else {
//            builder.withCollectorIp(IpAddress.valueOf("127.0.0.1"));
//        }
//
//        if (payload.get("collectorPort") != null) {
//            builder.withCollectorPort(TpPort.tpPort(
//                    payload.get("collectorPort").asInt()));
//        } else {
//            builder.withCollectorPort(TpPort.tpPort(1234));
//        }
//
//        builder.enabled(true)
//                .withSinkIp(IpAddress.valueOf("10.192.19.180"))
//                .withSinkMac(MacAddress.NONE)
//                .withCollectorNextHopMac(MacAddress.BROADCAST);
//
//        intService.setConfig(builder.build());

//        DeviceService deviceService = get(DeviceService.class);
//        Srv6Component app = get(Srv6Component.class);

//        Device device = deviceService.getDevice(DeviceId.deviceId(uri));
//        if (device == null) {
//            print("Device \"%s\" is not found", uri);
//            return;
//        }
//        if (segments.size() == 0) {
//            print("No segments listed");
//            return;
//        }
//        List<Ip6Address> sids = segments.stream()
//                .map(Ip6Address::valueOf)
//                .collect(Collectors.toList());
//        Ip6Address destIp = sids.get(sids.size() - 1);
//
//        print("Installing path on device %s: %s",
//                uri, sids.stream()
//                         .map(IpAddress::toString)
//                         .collect(Collectors.joining(", ")));
//        app.insertSrv6InsertRule(device.id(), destIp, 128, sids);

