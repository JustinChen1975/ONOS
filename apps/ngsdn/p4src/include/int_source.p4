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
#ifndef __INT_SOURCE__
#define __INT_SOURCE__

// #include "headers.p4"

// Insert INT header to the packet
control process_int_source (
    inout parsed_headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    direct_counter(CounterType.packets_and_bytes) counter_int_source;

    // 这个版本是插入头部的时候就更新了各个长度字段   
    //TODO：目前假设int source port都设置在主机端口上。其实也可以考虑设置在中间的一段路径上。
    // 那么在INT source port上就可能收到其他的INT source port/sink port对之间路过的携带INT报头的INT数据包。
    //TODO：上述场景之下，就不能重新插入INT包头了。这个后面再考虑。      
    action int_source_creat_int_option(bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {

        //目前只考虑纯IPv6的环境；
        // 修改IPv6报头；        
        // 保存原来的头。
        bit<8> original_next_hdr = hdr.ipv6.next_hdr ;
        //指向逐跳扩展头；
        hdr.ipv6.next_hdr = 0 ;
        // 修改Ipv6里面的payload长度.（单位为字节）。这个字段仅表示有效负载的长度.
        // 该字段表示有效载荷的长度，有效载荷是指紧跟IPv6基本报头之后的载荷长度（其中包含IPv6扩展报头）。
        // Payload Length: 16bits unsigned integer, ipv6的载荷长度，首部以外的长度(包括扩展首部).
        // --更新IPv6头部中的长度字段。增加了16个字节的逐跳扩展报头(目前里面没有INT metadata数据）。
        // 逐跳扩展头占2个字节；INT option header占2个字节；INT-MD的固定头部12个字节，加起来是16个字节。
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 16;


        // 填充逐跳扩展报头
        hdr.hopbyhop_ext_header.setValid();
        //在parse IPv6 header的时候，local_metadata.ip_proto = hdr.ipv6.next_hdr
        // hdr.hopbyhop_ext_header.next_header = local_metadata.ip_proto;
        hdr.hopbyhop_ext_header.next_header = original_next_hdr;
        //hdr.hopbyhop_ext_header.extHdr_len的（单位是8字节）
        // hdr.hopbyhop_ext_header.extHdr_len的当前实际长度为：逐跳扩展头占2个字节；INT option header占2个字节；INT-MD的固定头部12个字节，加起来是16个字节。
        // --更新逐跳扩展头的长度。 16/8 -1 = 1 (按照协议要忽略第一个8字节)
        hdr.hopbyhop_ext_header.extHdr_len = 1 ; 


        // 填充INT option的头。目前只考虑MD类型。
        hdr.int_opt_header.setValid();
        hdr.int_opt_header.option_type = INT_OPTION_TYPE_MD ;
        // -- 更新optData_len的（单位长度为字节）；12字节的固定的INT-MD header + hop_metadata_len * hops 
        // 可选项长度字段用于表示可选项的字节数，其中不包括可选项类型及可选项长度字段自身的长度。
        //这个时候只是插入了固定的12个字节的头部。 hop_metadata_len * hops 还没有插入，为0。
        hdr.int_opt_header.optData_len = 12 ;

        // 填充INT-MD 的12字节的固定头部
        // insert INT header
        hdr.int_md_header.setValid();       
        hdr.int_md_header.ver = 2;
        hdr.int_md_header.d = 0;
        hdr.int_md_header.e = 0;
        hdr.int_md_header.m = 0;
        hdr.int_md_header.rsvd1 = 0;
        // --更新HOP_ML的长度。当前还没有计算具体长度，所以临时设置为0。等第一次插入数据的时候再更新。
        hdr.int_md_header.hop_metadata_len = 0;
        hdr.int_md_header.remaining_hop_cnt = remaining_hop_cnt;
        hdr.int_md_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_md_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_md_header.instruction_mask_0811 = 0; 
        // hdr.int_md_header.instruction_mask_0811 = ins_mask0811; 
        // 后面再处理bit 08
        hdr.int_md_header.instruction_mask_1215 = 0; // not supported
        // 先不考虑Domain Specific相关的内容。
        hdr.int_md_header.domain_specific_id = 0; // not supported
        hdr.int_md_header.domain_specific_instruction = 0; // not supported
        hdr.int_md_header.domain_specific_flags = 0; // not supported

        //目前还没有写入int metadata stack.

        counter_int_source.count();

    }


    //这里才是真正的watchlist.
    table tb_int_source {
        key = {
            hdr.ipv6.src_addr: ternary;
            hdr.ipv6.dst_addr: ternary;
            // hdr.ipv4.src_addr: ternary;
            // hdr.ipv4.dst_addr: ternary;
            local_metadata.l4_src_port: ternary;
            local_metadata.l4_dst_port: ternary;
        }
        actions = {
            int_source_creat_int_option;
            @defaultonly nop();
        }
        counters = counter_int_source;
        const default_action = nop();
    }

    apply {
        tb_int_source.apply();
    }
}


//确定数据包上来的端口是不是INT source的端口。
//但还要经过watchlist的过滤，看是不是感兴趣的数据包。
control process_int_source_port (
    inout parsed_headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    direct_counter(CounterType.packets_and_bytes) counter_set_source;

    action int_set_source () {
        local_metadata.int_meta.source = _TRUE;
        counter_set_source.count();
    }

    //指定报文上来的端口，对于那些报文，该设备就是INT source设备；
    table tb_set_source {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            int_set_source;
            @defaultonly nop();
        }
        counters = counter_set_source;
        const default_action = nop();
        size = MAX_PORTS;
    }

    apply {
        tb_set_source.apply();
    }
}


#endif

    // action int_set_non_int () {
    //     local_metadata.int_meta.source = _FALSE;
    //     local_metadata.int_meta.transit = _FALSE;
    //     local_metadata.int_meta.sink = _FALSE;
    // }
            // @defaultonly int_set_non_int();
// const default_action = int_set_non_int();


   // 这个版本是插入头部的时候就更新了各个长度字段
    // action int_source_creat_int_option(bit<5> hop_metadata_len, bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407, bit<4> ins_mask0811) {
    // action int_source_creat_int_option(bit<5> hop_metadata_len, bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {

    //     //目前只考虑纯IPv6的环境；
    //     // 修改IPv6报头；
    //     //指向逐跳扩展头；
    //     hdr.ipv6.next_hdr = 0 ；

    //     // 填充逐跳扩展报头
    //     hdr.hopbyhop_ext_header.setValid();
    //     //在parse IPv6 header的时候，local_metadata.ip_proto = hdr.ipv6.next_hdr
    //     hdr.hopbyhop_ext_header.next_header = local_metadata.ip_proto;
    //     //hdr.hopbyhop_ext_header.extHdr_len的单位是8字节
    //     //下面3行的目的是为了64位对齐。
    //     bit<8> n= (bit<8>) hop_metadata_len;
    //     // bit<8> n= (bit<8>) (hop_metadata_len+1);
    //     bit<8> n1 =(n +1) >> 1; 
    //     bit<8> n2 = n1 << 1; 
    //     // hop_metadata_len这个长度包含了Domain Specific metadata在内，单位是4-bytes。
    //     hdr.hopbyhop_ext_header.extHdr_len = (n2*4 +16)/8 -1 ; 

    //     // 修改Ipv6里面的payload长度.单位为字节。
    //     // Payload Length: 16bits unsigned integer, ipv6的载荷长度，首部以外的长度(包括扩展首部).
    //     hdr.ipv6.payload_len = hdr.ipv6.payload_len + ((bit<16) (n2*4 +16))


    //     // 填充INT option的头。目前只考虑MD类型。
    //     hdr.int_opt_header.setValid();
    //     hdr.int_opt_header.option_type = INT_OPTION_TYPE_MD ;
    //     // optData_len的单位长度为字节；hop_metadata_len + 12字节的固定的INT-MD header
    //     hdr.int_opt_header.optData_len = n+12 ;

    //     // 填充INT-MD 的12字节的固定头部
    //     // insert INT header
    //     hdr.int_md_header.setValid();       
    //     hdr.int_md_header.ver = 2;
    //     hdr.int_md_header.d = 0;
    //     hdr.int_md_header.e = 0;
    //     hdr.int_md_header.m = 0;
    //     hdr.int_md_header.rsvd1 = 0;
    //     hdr.int_md_header.hop_metadata_len = hop_metadata_len;
    //     hdr.int_md_header.remaining_hop_cnt = remaining_hop_cnt;
    //     hdr.int_md_header.instruction_mask_0003 = ins_mask0003;
    //     hdr.int_md_header.instruction_mask_0407 = ins_mask0407;
    //     hdr.int_md_header.instruction_mask_0811 = 0; 
    //     // hdr.int_md_header.instruction_mask_0811 = ins_mask0811; 
    //     // 后面再处理bit 08
    //     hdr.int_md_header.instruction_mask_1215 = 0; // not supported
    //     // 先不考虑Domain Specific相关的内容。
    //     hdr.int_md_header.domain_specific_id = 0; // not supported
    //     hdr.int_md_header.domain_specific_instruction = 0; // not supported
    //     hdr.int_md_header.domain_specific_flags = 0; // not supported

    //     //目前还没有写入int metadata stack.

    //     // 如果n2 > n,说明64位不能对齐，需要padding.
    //     if( n2 > n) {
    //         hdr.pad4.setValid();
    //         hdr.pad4.option_type = 1;
    //         hdr.pad4.optData_len = 2;
    //         hdr.pad4.optData = 0;
    //     }
    //     else {
    //         hdr.pad4.setInvalid();
    //     }

    //     counter_int_source.count();

    // }

//下面是原来int.p4里自带的。
// Insert INT header to the packet
// control process_int_source (
//     inout headers_t hdr,
//     inout local_metadata_t local_metadata,
//     inout standard_metadata_t standard_metadata) {

//     direct_counter(CounterType.packets_and_bytes) counter_int_source;

//     action int_source(bit<5> hop_metadata_len, bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {
//         // insert INT shim header
//         hdr.intl4_shim.setValid();
//         // int_type: Hop-by-hop type (1) , destination type (2)
//         hdr.intl4_shim.int_type = 1;
//         hdr.intl4_shim.len = INT_HEADER_LEN_WORD;
//         hdr.intl4_shim.dscp = hdr.ipv4.dscp;

//         // insert INT header
//         hdr.int_header.setValid();
//         hdr.int_header.ver = 0;
//         hdr.int_header.rep = 0;
//         hdr.int_header.c = 0;
//         hdr.int_header.e = 0;
//         hdr.int_header.m = 0;
//         hdr.int_header.rsvd1 = 0;
//         hdr.int_header.rsvd2 = 0;
//         hdr.int_header.hop_metadata_len = hop_metadata_len;
//         hdr.int_header.remaining_hop_cnt = remaining_hop_cnt;
//         hdr.int_header.instruction_mask_0003 = ins_mask0003;
//         hdr.int_header.instruction_mask_0407 = ins_mask0407;
//         hdr.int_header.instruction_mask_0811 = 0; // not supported
//         hdr.int_header.instruction_mask_1215 = 0; // not supported

//         // add the header len (3 words) to total len
//         hdr.ipv4.total_len = hdr.ipv4.total_len + INT_HEADER_SIZE + INT_SHIM_HEADER_SIZE;
//         hdr.udp.len = hdr.udp.len + INT_HEADER_SIZE + INT_SHIM_HEADER_SIZE;
//     }
//     action int_source_dscp(bit<5> hop_metadata_len, bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {
//         int_source(hop_metadata_len, remaining_hop_cnt, ins_mask0003, ins_mask0407);
//         hdr.ipv4.dscp = DSCP_INT;
//         counter_int_source.count();
//     }

//     //这里才是真正的watchlist.
//     table tb_int_source {
//         key = {
//             hdr.ipv4.src_addr: ternary;
//             hdr.ipv4.dst_addr: ternary;
//             local_metadata.l4_src_port: ternary;
//             local_metadata.l4_dst_port: ternary;
//         }
//         actions = {
//             int_source_dscp;
//             @defaultonly nop();
//         }
//         counters = counter_int_source;
//         const default_action = nop();
//     }

//     apply {
//         tb_int_source.apply();
//     }
// }


// //用来确认对于处理中的该数据包而言，本设备是否充当INT的角色，是source，还是sink，或者不是。但还要经过watchlist的过滤。
// control process_int_source_sink (
//     inout parsed_headers_t hdr,
//     inout local_metadata_t local_metadata,
//     inout standard_metadata_t standard_metadata) {

//     direct_counter(CounterType.packets_and_bytes) counter_set_source;
//     direct_counter(CounterType.packets_and_bytes) counter_set_sink;

//     action int_set_non_int () {
//         local_metadata.int_meta.source = _FALSE;
//         local_metadata.int_meta.transit = _FALSE;
//         local_metadata.int_meta.sink = _FALSE;
//     }

//     action int_set_source () {
//         local_metadata.int_meta.source = _TRUE;
//         counter_set_source.count();
//     }

//     action int_set_sink () {
//         local_metadata.int_meta.sink = _TRUE;
//         counter_set_sink.count();
//     }

//     //指定报文上来的端口，对于那些报文，该设备就是INT source设备；
//     table tb_set_source {
//         key = {
//             standard_metadata.ingress_port: exact;
//         }
//         actions = {
//             int_set_source;
//             // @defaultonly nop();
//             @defaultonly int_set_non_int();
//         }
//         counters = counter_set_source;
//         // const default_action = nop();
//         const default_action = int_set_non_int();
//         size = MAX_PORTS;
//     }

//     // 指定报文出来的端口，对于那些报文，该设备就是INT sink设备；
//     // 是否还有event detection，决定哪些数据包才要生成报告？或者判断从该端口出去的数据包那些才是INT相关的报文？
//     table tb_set_sink {
//         key = {
//             standard_metadata.egress_spec: exact;
//         }
//         actions = {
//             int_set_sink;
//             // @defaultonly nop();
//             @defaultonly int_set_non_int();
//         }
//         counters = counter_set_sink;
//         // const default_action = nop();
//         const default_action = int_set_non_int();
//         size = MAX_PORTS;
//     }

//     apply {
//         tb_set_source.apply();
//         tb_set_sink.apply();
//     }
// }