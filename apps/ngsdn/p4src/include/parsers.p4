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

#ifndef __PARSERS__
#define __PARSERS__

#include "headers.p4"
#include "defines.p4"

parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.cpu_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        local_metadata.ip_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_HOPOPT6: parse_hopbyhop_ext;
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            IP_PROTO_SRV6: parse_srv6;            
            default: accept;
        }
    }

    state parse_hopbyhop_ext{
        packet.extract(hdr.hopbyhop_ext_header);
        transition parse_int_option_header;
    }

    state parse_int_option_header {
        packet.extract(hdr.int_opt_header);
        transition parse_int_md_header;
    }

    state parse_int_md_header {
        packet.extract(hdr.int_md_header);
        transition parse_int_data;
    }
    
    state parse_int_data {
        // Parse INT metadata stack
        // INT metadata stack跟着INT-MD header之后。hdr.int_opt_header.optData_len包含了12个字节
        // extract的第二个参数是位数，所以要乘以8（一个字节是8位）
        packet.extract(hdr.int_data, ((bit<32>) (hdr.int_opt_header.optData_len -12 )) << 3 ) ;
        // packet.extract(hdr.int_data, ((bit<32>) (local_metadata.int_meta.intl4_shim_len - INT_HEADER_LEN_WORD)) << 5);
        //看下后面是否还有pad4或者有其他的option在
        // TODO：当前假设后面只可能跟随pad4，而没有其它的option跟随在后。后面再考虑有其他的option在。
        // 下面的单位是单个字节。
        //TODO ：下面的到底有没有错？ 注意，不能写成下面的语句，否则会出错： hdr.ipv6.payload_len = hdr.ipv6.payload_len +  ((bit<16>)(n1 -1 - n3)) << 3 ;
        bit<32> extHdr_len = ((bit<32>)(hdr.hopbyhop_ext_header.extHdr_len + 1)) << 3 ;
        // +4，是因为逐跳扩展头占2个字节； INT option头占2个字节。
        bit<32> current_len = (bit<32>) (hdr.int_opt_header.optData_len + 4 ) ;        
        transition  select(extHdr_len > current_len) {
            true  : parse_pad4; 
            false : parse_after_hopbyhop;
        }         
    }

    // 其实padding里的数据没有什么用
    state parse_pad4 {
        packet.extract(hdr.pad4);
        //当前假设INT option后面不再有其他的option，也没有追加其他的int_option，或者appended INT_option。
        transition parse_after_hopbyhop;
    }

    state parse_after_hopbyhop {
        transition select(hdr.hopbyhop_ext_header.next_header) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            IP_PROTO_SRV6: parse_srv6;            
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        local_metadata.icmp_type = hdr.icmp.type;
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        local_metadata.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition accept;
    }

    state parse_srv6 {
        packet.extract(hdr.srv6h);
        transition parse_srv6_list;
    }

    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        bool next_segment = (bit<32>)hdr.srv6h.segment_left - 1 == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            default: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        local_metadata.next_srv6_sid = hdr.srv6_list.last.segment_id;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        // working with bit<8> and int<32> which cannot be cast directly; using
        // bit<32> as common intermediate type for comparision
        bool last_segment = (bit<32>)hdr.srv6h.last_entry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
           true: parse_srv6_next_hdr;
           false: parse_srv6_list;
        }
    }

    state parse_srv6_next_hdr {
        transition select(hdr.srv6h.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }
}


control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.cpu_in);
        // INT report
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_ipv6);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_group_header);
        packet.emit(hdr.individual_report_header);        
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        // hop_ext, opt-headr
        packet.emit(hdr.hopbyhop_ext_header);
        packet.emit(hdr.int_opt_header);
        // INT-MD-header
        packet.emit(hdr.int_md_header);
        // INT metadata stack
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_level1_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_level2_port_ids);
        packet.emit(hdr.int_egress_tx_util);
        packet.emit(hdr.int_buffer_occupancy);
        packet.emit(hdr.int_data);
        packet.emit(hdr.pad4);
        // SRv6
        packet.emit(hdr.srv6h);
        packet.emit(hdr.srv6_list);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
    }
}

#endif

// parser parser_impl(packet_in packet,
//                   out headers_t hdr,
//                   inout local_metadata_t local_metadata,
//                   inout standard_metadata_t standard_metadata) {

//     state start {
//         transition select(standard_metadata.ingress_port) {
//             CPU_PORT: parse_packet_out;
//             default: parse_ethernet;
//         }
//     }

//     state parse_packet_out {
//         packet.extract(hdr.packet_out);
//         transition parse_ethernet;
//     }

//     state parse_ethernet {
//         packet.extract(hdr.ethernet);
//         transition select(hdr.ethernet.ether_type) {
//             ETH_TYPE_IPV4: parse_ipv4;
//             default: accept;
//         }
//     }

//     state parse_ipv4 {
//         packet.extract(hdr.ipv4);
//         transition select(hdr.ipv4.protocol) {
//             IP_PROTO_TCP: parse_tcp;
//             IP_PROTO_UDP: parse_udp;
//             default: accept;
//         }
//     }

//     state parse_tcp {
//         packet.extract(hdr.tcp);
//         local_metadata.l4_src_port = hdr.tcp.src_port;
//         local_metadata.l4_dst_port = hdr.tcp.dst_port;
//         transition accept;
//     }

//     state parse_udp {
//         packet.extract(hdr.udp);
//         local_metadata.l4_src_port = hdr.udp.src_port;
//         local_metadata.l4_dst_port = hdr.udp.dst_port;
//         transition accept;
//     }
// }

// control deparser(packet_out packet, in headers_t hdr) {
//     apply {
//         packet.emit(hdr.packet_in);
//         packet.emit(hdr.ethernet);
//         packet.emit(hdr.ipv4);
//         packet.emit(hdr.tcp);
//         packet.emit(hdr.udp);
//     }
// }
