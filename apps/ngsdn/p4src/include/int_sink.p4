/*
 * Copyright 2017-present Open Networking Foundation
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

/* -*- P4_16 -*- */
#ifndef __INT_SINK__
#define __INT_SINK__

//确定数据包要发送的端口是不是INT SINK的端口。
//要在路由和二层处理模块之后判断。因为经过了SRv6, L3, L2之后才确定了真正的egress_port。
control process_int_sink_port (
    inout parsed_headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    direct_counter(CounterType.packets_and_bytes) counter_set_sink;

    action int_set_sink () {
        local_metadata.int_meta.sink = _TRUE;
        counter_set_sink.count();
    }

    // 指定报文出来的端口，对于那些报文，该设备就是INT sink设备；
    // 是否还有event detection，决定哪些数据包才要生成报告？或者判断从该端口出去的数据包那些才是INT相关的报文？
    table tb_set_sink {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            int_set_sink;
            @defaultonly nop();
            // @defaultonly int_set_non_int();
        }
        counters = counter_set_sink;
        const default_action = nop();
        // const default_action = int_set_non_int();
        size = MAX_PORTS;
    }

    apply {
        tb_set_sink.apply();
    }
}


control process_int_sink (
    inout parsed_headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    @hidden
    action restore_header () {
        // 这里假设逐跳选项扩展报文里只有INT option以及padN option。        
        // 更新IPv6的报头
        hdr.ipv6.next_hdr = hdr.hopbyhop_ext_header.next_header ;               
        hdr.ipv6.payload_len = hdr.ipv6.payload_len -  (bit<16>)((hdr.hopbyhop_ext_header.extHdr_len + 1) << 3 )  ;
        //TODO ：如果是多INT session，那么不能这么简单地把整个逐跳选项扩展头去掉。
        // remove all the INT information from the packet
        hdr.hopbyhop_ext_header.setInvalid();
        hdr.int_opt_header.setInvalid();
        hdr.int_md_header.setInvalid();      
        hdr.int_data.setInvalid();
        hdr.int_switch_id.setInvalid();
        hdr.int_level1_port_ids.setInvalid();
        hdr.int_hop_latency.setInvalid();
        hdr.int_q_occupancy.setInvalid();
        hdr.int_ingress_tstamp.setInvalid();
        hdr.int_egress_tstamp.setInvalid();
        hdr.int_level2_port_ids.setInvalid();
        hdr.int_egress_tx_util.setInvalid();
        hdr.int_buffer_occupancy.setInvalid();
        hdr.int_data.setInvalid();
        hdr.pad4.setInvalid();
    }

    apply {        
        restore_header();
    }
}
#endif
