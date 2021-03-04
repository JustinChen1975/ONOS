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
#ifndef __INT_TRANSIT__
#define __INT_TRANSIT__
control process_int_transit (
    inout parsed_headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    // 下发的switch ID是来自于ONOS里的deviceID的。
    action init_metadata(switch_id_t switch_id) {
        local_metadata.int_meta.transit = _TRUE;
        local_metadata.int_meta.switch_id = switch_id;
    }

    @hidden
    action int_set_header_0() { //switch_id
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = local_metadata.int_meta.switch_id;
    }
    @hidden
    action int_set_header_1() { //level1_port_id
        hdr.int_level1_port_ids.setValid();
        hdr.int_level1_port_ids.ingress_port_id = (bit<16>) standard_metadata.ingress_port;
        hdr.int_level1_port_ids.egress_port_id = (bit<16>) standard_metadata.egress_port;
    }
    @hidden
    action int_set_header_2() { //hop_latency
        hdr.int_hop_latency.setValid();
        // hdr.int_hop_latency.hop_latency = (bit<32>) standard_metadata.egress_global_timestamp - (bit<32>) standard_metadata.ingress_global_timestamp;
        hdr.int_hop_latency.hop_latency = (bit<32>)(standard_metadata.egress_global_timestamp -  standard_metadata.ingress_global_timestamp ) ;
    }
    @hidden
    action int_set_header_3() { //q_occupancy
        // TODO: Support egress queue ID
        hdr.int_q_occupancy.setValid();
        hdr.int_q_occupancy.q_id =
        0;
        // (bit<8>) standard_metadata.egress_qid;
        hdr.int_q_occupancy.q_occupancy =
        (bit<24>) standard_metadata.deq_qdepth;
    }
    @hidden
    action int_set_header_4() { //ingress_tstamp
        hdr.int_ingress_tstamp.setValid();
        hdr.int_ingress_tstamp.ingress_tstamp =
        (bit<64>) standard_metadata.ingress_global_timestamp;
    }
    @hidden
    action int_set_header_5() { //egress_timestamp
        hdr.int_egress_tstamp.setValid();
        hdr.int_egress_tstamp.egress_tstamp =
        (bit<64>) standard_metadata.egress_global_timestamp;
    }
    @hidden
    action int_set_header_6() { //level2_port_id
        hdr.int_level2_port_ids.setValid();
        // level2_port_id indicates Logical port ID
        hdr.int_level2_port_ids.ingress_port_id = (bit<32>) standard_metadata.ingress_port;
        hdr.int_level2_port_ids.egress_port_id = (bit<32>) standard_metadata.egress_port;
     }
    @hidden
    action int_set_header_7() { //egress_port_tx_utilization
        // TODO: implement tx utilization support in BMv2
        hdr.int_egress_tx_util.setValid();
        hdr.int_egress_tx_util.egress_port_tx_util =0;
        // (bit<32>) queueing_metadata.tx_utilization; 
        // 陈晓筹：为什么不用这个，却用0呢？V1model里可能还不支持。估计PSA才有支持。        
    }

    // Actions to keep track of the new metadata added.
    // local_metadata.int_meta.new_words刚开始的时候默认是0吧
    // TODO ：如果在多INT session的情形下，每次处理新的INT session option过来的时候，需要把local_metadata.int_meta.new_words 清0.
    @hidden
    action add_1() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 1;
        // local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 4;
    }

    @hidden
    action add_2() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 2;
    }

    @hidden
    action add_3() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 3;
    }

    @hidden
    action add_4() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 4;
    }

    @hidden
    action add_5() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 5;
    }

    @hidden
    action add_6() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 6;
    }

    @hidden
    action add_7() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 7;
    }

     /* action function for bits 0-3 combinations, 0 is msb, 3 is lsb */
     /* Each bit set indicates that corresponding INT header should be added */
    @hidden
     action int_set_header_0003_i0() {
     }
    @hidden
     action int_set_header_0003_i1() {
        int_set_header_3();
        add_1();
    }
    @hidden
    action int_set_header_0003_i2() {
        int_set_header_2();
        add_1();
    }
    @hidden
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
        add_2();
    }
    @hidden
    action int_set_header_0003_i4() {
        int_set_header_1();
        add_1();
    }
    @hidden
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
        add_2();
    }
    @hidden
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
        add_2();
    }
    @hidden
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        add_3();
    }
    @hidden
    action int_set_header_0003_i8() {
        int_set_header_0();
        add_1();
    }
    @hidden
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_4();
    }

    /* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
    //  要注意的是bit 4,5,6，对应的metadata是64位，而不仅仅是32位
    @hidden
    action int_set_header_0407_i0() {
    }
    @hidden
    action int_set_header_0407_i1() {
        int_set_header_7();
        add_1();
    }
    @hidden
    action int_set_header_0407_i2() {
        int_set_header_6();
        add_2();
    }
    @hidden
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
        add_3();
    }
    @hidden
    action int_set_header_0407_i4() {
        int_set_header_5();
        add_2();
    }
    @hidden
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
        add_3();
    }
    @hidden
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
        add_4();
    }
    @hidden
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        add_5();
    }
    @hidden
    action int_set_header_0407_i8() {
        int_set_header_4();
        add_2();
    }
    @hidden
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
        add_3();
    }
    @hidden
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
        add_4();
    }
    @hidden
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
        add_5();
    }
    @hidden
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
        add_4();
    }
    @hidden
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
        add_5();
    }
    @hidden
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_6();
    }
    @hidden
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_7();
    }

    // Default action used to set switch ID.
    // 这里会要求ONOS下发switch id. ONOS是要怎么下发switch id的呢？
    table tb_int_insert {
        // 这是什么意思？
        // We don't really need a key here, however we add a dummy one as a        
        // workaround to ONOS inability to properly support default actions.
        key = {
            hdr.int_opt_header.isValid(): exact @name("int_is_valid");
        }
        actions = {
            init_metadata;
            @defaultonly nop;
        }
        const default_action = nop();
        size = 1;
    }

    /* Table to process instruction bits 0-3 */
    @hidden
    table tb_int_inst_0003 {
        key = {
            hdr.int_md_header.instruction_mask_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        const entries = {
            (0x0) : int_set_header_0003_i0();
            (0x1) : int_set_header_0003_i1();
            (0x2) : int_set_header_0003_i2();
            (0x3) : int_set_header_0003_i3();
            (0x4) : int_set_header_0003_i4();
            (0x5) : int_set_header_0003_i5();
            (0x6) : int_set_header_0003_i6();
            (0x7) : int_set_header_0003_i7();
            (0x8) : int_set_header_0003_i8();
            (0x9) : int_set_header_0003_i9();
            (0xA) : int_set_header_0003_i10();
            (0xB) : int_set_header_0003_i11();
            (0xC) : int_set_header_0003_i12();
            (0xD) : int_set_header_0003_i13();
            (0xE) : int_set_header_0003_i14();
            (0xF) : int_set_header_0003_i15();
        }
    }

    /* Table to process instruction bits 4-7 */
    @hidden
    table tb_int_inst_0407 {
        key = {
            hdr.int_md_header.instruction_mask_0407 : exact;
        }
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
        }
        const entries = {
            (0x0) : int_set_header_0407_i0();
            (0x1) : int_set_header_0407_i1();
            (0x2) : int_set_header_0407_i2();
            (0x3) : int_set_header_0407_i3();
            (0x4) : int_set_header_0407_i4();
            (0x5) : int_set_header_0407_i5();
            (0x6) : int_set_header_0407_i6();
            (0x7) : int_set_header_0407_i7();
            (0x8) : int_set_header_0407_i8();
            (0x9) : int_set_header_0407_i9();
            (0xA) : int_set_header_0407_i10();
            (0xB) : int_set_header_0407_i11();
            (0xC) : int_set_header_0407_i12();
            (0xD) : int_set_header_0407_i13();
            (0xE) : int_set_header_0407_i14();
            (0xF) : int_set_header_0407_i15();
        }
    }

    apply {
        if (!hdr.ipv6.isValid()) {
            return;
        }

        //会先判断hdr.int_opt_header.isValid()。是的话，把transit的设置为true；同时会提供switch_id；
        tb_int_insert.apply();

        if (local_metadata.int_meta.transit == _FALSE) {
            return;
        }

        // 写入本设备的metadata的数据
        local_metadata.int_meta.new_words = 0;
        tb_int_inst_0003.apply();
        tb_int_inst_0407.apply();

        // Decrement remaining hop cnt
        hdr.int_md_header.remaining_hop_cnt = hdr.int_md_header.remaining_hop_cnt - 1;

        // Update headers lengths.
        
        //只有source node可以更新hop_ml
        if (local_metadata.int_meta.source == _TRUE) {
            // --更新INT-MD header里的长度。 Hop-ML的(单位是4个字节)
            hdr.int_md_header.hop_metadata_len = local_metadata.int_meta.new_words; 
        }          

        // --更新INT option的optData_len（单位长度为单字节）        
        bit<8> n= (bit<8>) local_metadata.int_meta.new_words;
        // 每个节点插入metadata占据n*4字节；
        // 在Int-source节点插入INT option header的时候，会一开始把optData_len设置为12. 
        hdr.int_opt_header.optData_len =  hdr.int_opt_header.optData_len +( n << 2) ; 


        // 当前整个扩展头的有效长度为current_length。current_length的单位为4字节
        // 逐跳扩展头占2个字节；INT option header占2个字节，所以要加4
        bit<8> current_length= (hdr.int_opt_header.optData_len +4) >> 2 ;
        // 使得扩展头满足64位(8字节)对齐。n2为对齐后的实际长度（单位为4字节）。              
        bit<8> n1 =(current_length +1) >> 1; 
        bit<8> n2 = n1 << 1; 
        // 在更新之前，用n3来保存原有的扩展头的长度
        bit<8> n3 = hdr.hopbyhop_ext_header.extHdr_len;
        // --更新逐跳扩展头的长度。协议规定长度数值不包含第一个8字节，所以要减去1.（单位为8字节长）
        // hdr.hopbyhop_ext_header.extHdr_len =((n2) >> 1) -1  ;  或者        
        hdr.hopbyhop_ext_header.extHdr_len =n1 -1  ; 

        // TODO: 在多INT session的情形下，判断是否要增加pad4需要在所有的INT session都被处理完成之后，所以需要独立出去处理。判断条件也会更复杂。
        //如果n2 > current_length，说明为了64位对齐，需要增加pad
        if ( n2 > current_length) {
                hdr.pad4.setValid();
                hdr.pad4.option_type = 1;
                hdr.pad4.optData_len = 2;
                hdr.pad4.optData = 0;            
        } else {
                hdr.pad4.setInvalid();
        }

        // 计算逐跳扩展头实际增加了多少长度。((bit<16>) (n1 -1 - n3)) << 3
        // TODO: 万一原来的位数不够移动3位呢？会不会溢出？
        // --更新IPv6 header里的长度字段
        hdr.ipv6.payload_len = hdr.ipv6.payload_len +  ((bit<16>)(n1 -1 - n3) << 3) ;
        // 注意，不能写成下面的语句，否则会出错：
        // hdr.ipv6.payload_len = hdr.ipv6.payload_len +  ((bit<16>)(n1 -1 - n3)) << 3 ;

        //d,e,m 等位的设置后面再考虑。
    }
}

#endif

