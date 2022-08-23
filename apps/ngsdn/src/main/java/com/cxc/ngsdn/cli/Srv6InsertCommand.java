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

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.net.DeviceIdCompleter;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import com.cxc.ngsdn.Srv6Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * SRv6 Transit Insert Command
 */
@Service
@Command(scope = "onos", name = "srv6-insert",
         description = "Insert a t_insert rule into the SRv6 Transit table")
public class Srv6InsertCommand extends AbstractShellCommand {
    //uri是命令的参数
    @Argument(index = 0, name = "uri", description = "Device ID",
              required = true, multiValued = false)
    @Completion(DeviceIdCompleter.class)
    String uri = null;

    @Argument(index = 1, name = "segments",
            description = "SRv6 Segments (space separated list); last segment is target IP address",
            required = false, multiValued = true)
    @Completion(Srv6SidCompleter.class)
    List<String> segments = null;

    @Override
    protected void doExecute() {
        DeviceService deviceService = get(DeviceService.class);
        Srv6Component app = get(Srv6Component.class);

        Device device = deviceService.getDevice(DeviceId.deviceId(uri));
        if (device == null) {
            print("Device \"%s\" is not found", uri);
            return;
        }
        if (segments.size() == 0) {
            print("No segments listed");
            return;
        }

         //valueOf是把字符串转成系统识别的IPv6地址。

        List<Ip6Address> sids = segments.stream()
                .map(Ip6Address::valueOf)
                .collect(Collectors.toList());
        // 列表里的最后一个是真正的目的IPv6地址
        //原有的目的IP地址在list的最后一个。在main.p4里，是把参数中的最后一个放到了segment_list[0]里面的。按要求，原IP是需要放到seg_list[0]的。
        Ip6Address destIp = sids.get(sids.size() - 1);

        print("Installing path on device %s: %s",
                uri, sids.stream()
                         .map(IpAddress::toString)
                         .collect(Collectors.joining(", ")));
        app.insertSrv6InsertRule(device.id(), destIp, 128, sids);

    }

}
