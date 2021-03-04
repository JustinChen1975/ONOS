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
#ifndef __INT_REPORT__
#define __INT_REPORT__

// #include "telemetry_report_headers.p4"

control process_int_report (
    inout parsed_headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    action add_report_group_header() {
        hdr.report_group_header.setValid();
        hdr.report_group_header.ver = 2;
        //TODO : how to get information specific to the switch
        hdr.report_group_header.hw_id = HW_ID;
        //TODO:  how save a variable and increment
        hdr.report_group_header.seq_no = 0;
        //TODO : how to get information specific to the switch
        // 依赖于在int-transit里对local_metadata.int_meta.switch_id的赋值
        hdr.report_group_header.node_id = local_metadata.int_meta.switch_id;
    }

    action add_individual_report_header(bit<8>  report_length ) {
        hdr.individual_report_header.setValid();
        // 当前设计的RepType为inner only类型的，所以in_type=0
        hdr.individual_report_header.rep_type  = 0 ;        
        // 当前设计的Inner Type为IPv6，暂时不考虑其他类型。
        hdr.individual_report_header.in_type  = 5 ;        
        hdr.individual_report_header.report_length  = report_length ;
        // 当前设计为inner only类型的，所以md_length=0
        hdr.individual_report_header.md_length  = 0 ;
        // 先不考虑Dropped, Congested queue的情形，只考虑Tracked Flow 
        hdr.individual_report_header.d  = 0 ;        
        hdr.individual_report_header.q  = 0 ;        
        hdr.individual_report_header.f  = 1 ;   
        //  先不考虑Intermediate report。目前只考虑sink node发送report的情形。
        hdr.individual_report_header.i  = 0 ;        
        hdr.individual_report_header.rsvd  = 0 ;        
    }
    
    // 用IPv6封装的方式发送report。
    // 增加一台collector : h51。专门用来接收R5发出report。这种设计下，每台路由器都要有一台这样的collector。后面再考虑弄台全网通用的collector。    
    // 我们的报告包含：新创建的以太网报头 + 新的IPv6报头 + 新的UDP报头 + 
    //               Telemetry Group header(8个字节) +  telemetry individual header（4个字节） + 
    //               + Individual Report Inner Contents(原始报文:  IPv6报头、IPv6扩展报头的数据）；
    action do_report_encapsulation(mac_t src_mac, mac_t mon_mac, ipv6_addr_t src_ip,
                        ipv6_addr_t mon_ip, l4_port_t mon_port) {
        //Report Ethernet Header
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dst_addr = mon_mac;
        hdr.report_ethernet.src_addr = src_mac;
        hdr.report_ethernet.ether_type = ETHERTYPE_IPV6;

        //Report IPV6 Header        
        hdr.report_ipv6.setValid();
        hdr.report_ipv6.version = IP_VERSION_6;
        hdr.report_ipv6.traffic_class = hdr.ipv6.traffic_class;
        hdr.report_ipv6.flow_label = hdr.ipv6.flow_label;        

        bit<16> hopbyhop_ext_header_len = (((bit<16>) hdr.hopbyhop_ext_header.extHdr_len) + 1) << 3 ;
        // 该字段表示有效载荷的长度，有效载荷是指紧跟IPv6基本报头之后的载荷长度（其中包含IPv6扩展报头）。
        // 计算report_ipv6.payload_len的时候考虑到截短
        hdr.report_ipv6.payload_len =  (bit<16>) UDP_HEADER_LEN +
                                 (bit<16>) REPORT_GROUP_HEADER_FIXED_LEN +  (bit<16>) REPORT_INDIVIDUAL_HEADER_FIXED_LEN + 
                                (bit<16>)  IPV6_MIN_HEAD_LEN + hopbyhop_ext_header_len  ;
        hdr.report_ipv6.next_hdr = IP_PROTO_UDP;
        // hdr.report_ipv6.hop_limit = hdr.ipv6.hop_limit；
        hdr.report_ipv6.hop_limit = REPORT_HDR_TTL ;
        hdr.report_ipv6.src_addr = src_ip;
        hdr.report_ipv6.dst_addr = mon_ip;                       


        //Report UDP Header
        //TODO：是否要考虑UDP的checksum ?
        // Length 2字节 UDP首部加上UDP数据的字节数，最小为8。 
        // Checksum 2字节 覆盖UDP首部和UDP数据，是可选的。 
        hdr.report_udp.setValid();
        //TODO: src_port要设置为什么比较好？？原代码里是0，这里设置为3456； 
        hdr.report_udp.src_port = 3456;
        hdr.report_udp.dst_port = mon_port;
        // 对于telemetry report来说，report-IPv6报头后面只跟一个UDP报头。
        // udp_len包含了udp header本身；而report-ipv6_payload_len不包含report-ipv6 header本身，所以两者的长度值一样。
        hdr.report_udp.len = hdr.report_ipv6.payload_len ;

		// 对于IPv4，根据RFC 768， UDP可能设定一个zero的checksum，这会使得接收者忽略checksum filed的值。
        // 对于IPv6，根据RFC 6936,也可以设定一个zero的checksum。
        hdr.report_udp.checksum = 0 ; 

        // 下面的local_metadata.compute_checksum好像没有用到。
        local_metadata.compute_checksum = true;

        //  在没有Individual Report Main Contents的情况下，report length只取决于Individual Report Inner Contents的长度。
        // 这里也就是 IPV6_MIN_HEAD_LEN + hopbyhop_ext_header_len 
        //  Report length的单位是4字节。        
        //  从单字节转成4字节； 从8字节转成4字节；
        //不能写成 bit<8>  report_length = (IPV6_MIN_HEAD_LEN >> 2 )+ (hdr.hopbyhop_ext_header.extHdr_len +  1 ) << 1 ; 
        // 那样的结果会是先 + 后 <<
        bit<8>  report_length = (IPV6_MIN_HEAD_LEN >> 2 )+ ((hdr.hopbyhop_ext_header.extHdr_len +  1 ) << 1 ); 

        hdr.ethernet.setInvalid();

        add_report_group_header();       
        add_individual_report_header(report_length);        

        //这里用截短的方式，而不是对余下的部分进行setInvalid()。
        truncate((bit<32>) ETH_HEADER_LEN +  (bit<32>) IPV6_MIN_HEAD_LEN + (bit<32>)hdr.report_udp.len );
    }

    // Cloned packet is forwarded according to the mirroring_add command
    table tb_generate_report {
        // We don't really need a key here, however we add a dummy one as a
        // workaround to ONOS inability to properly support default actions.
        key = {
            hdr.int_opt_header.isValid(): exact @name("int_is_valid");
        }
        actions = {
            do_report_encapsulation;
            @defaultonly nop();
        }
        default_action = nop;
    }

    apply {
        tb_generate_report.apply();
    }
}
#endif

// 原来的版本
    // // 用IPv4封装的方式发送report。
    // action do_report_encapsulation(mac_t src_mac, mac_t mon_mac, ip_address_t src_ip,
    //                     ip_address_t mon_ip, l4_port_t mon_port) {
    //     //Report Ethernet Header
    //     hdr.report_ethernet.setValid();
    //     hdr.report_ethernet.dst_addr = mon_mac;
    //     hdr.report_ethernet.src_addr = src_mac;
    //     hdr.report_ethernet.ether_type = ETH_TYPE_IPV4;

    //     //Report IPV4 Header
    //     hdr.report_ipv4.setValid();
    //     hdr.report_ipv4.version = IP_VERSION_4;
    //     hdr.report_ipv4.ihl = IPV4_IHL_MIN;
    //     hdr.report_ipv4.dscp = 6w0;
    //     hdr.report_ipv4.ecn = 2w0;
    //     /* Total Len is report_ipv4_len + report_udp_len + report_fixed_hdr_len + ethernet_len + ipv4_totalLen */
    //     hdr.report_ipv4.total_len = (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_FIXED_HEADER_LEN +
    //                           (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + (((bit<16>) hdr.intl4_shim.len)<< 2);
    //     /* Dont Fragment bit should be set */
    //     hdr.report_ipv4.identification = 0;
    //     hdr.report_ipv4.flags = 0;
    //     hdr.report_ipv4.frag_offset = 0;
    //     hdr.report_ipv4.ttl = REPORT_HDR_TTL;
    //     hdr.report_ipv4.protocol = IP_PROTO_UDP;
    //     hdr.report_ipv4.src_addr = src_ip;
    //     hdr.report_ipv4.dst_addr = mon_ip;

    //     //Report UDP Header
    //     hdr.report_udp.setValid();
    //     hdr.report_udp.src_port = 0;
    //     hdr.report_udp.dst_port = mon_port;
    //     hdr.report_udp.len = (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_FIXED_HEADER_LEN +
    //                              (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN +
    //                              (((bit<16>) hdr.intl4_shim.len)<< 2);

    //     local_metadata.compute_checksum = true;
    //     add_report_fixed_header();

    //     truncate((bit<32>)hdr.report_ipv4.total_len + (bit<32>) ETH_HEADER_LEN);
    // }

    //     action add_report_fixed_header() {
    //     /* Device should include its own INT metadata as embedded,
    //      * we'll not use local_report_header for this purpose.
    //      */
    //     hdr.report_fixed_header.setValid();
    //     hdr.report_fixed_header.ver = 1;
    //     hdr.report_fixed_header.len = 4;
    //     /* only support for flow_watchlist */
    //     hdr.report_fixed_header.nproto = NPROTO_ETHERNET;
    //     hdr.report_fixed_header.rep_md_bits = 0;
    //     hdr.report_fixed_header.d = 0;
    //     hdr.report_fixed_header.q = 0;
    //     hdr.report_fixed_header.f = 1;
    //     hdr.report_fixed_header.rsvd = 0;
    //     //TODO how to get information specific to the switch
    //     hdr.report_fixed_header.hw_id = HW_ID;
    //     hdr.report_fixed_header.sw_id = local_metadata.int_meta.switch_id;
    //     // TODO how save a variable and increment
    //     hdr.report_fixed_header.seq_no = 0;
    //     //TODO how to get timestamp from ingress ns
    //     hdr.report_fixed_header.ingress_tstamp =  (bit<32>) standard_metadata.enq_timestamp;

    // }