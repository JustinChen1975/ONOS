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

#ifndef __HEADERS__
#define __HEADERS__

#include "defines.p4"
// #include "int_headers.p4"
// #include "telemetry_report_headers.p4"
// #include "int_definitions.p4"

header ethernet_t {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr;
    bit<8>    hop_limit;
    bit<128>  src_addr;
    bit<128>  dst_addr;
}

header srv6h_t {
    bit<8>   next_hdr;
    bit<8>   hdr_ext_len;
    bit<8>   routing_type;
    bit<8>   segment_left;
    bit<8>   last_entry;
    bit<8>   flags;
    bit<16>  tag;
}

header srv6_list_t {
    bit<128>  segment_id;
}

header tcp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<3>   res;
    bit<3>   ecn;
    bit<6>   ctrl;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8>   type;
    bit<8>   icmp_code;
    bit<16>  checksum;
    bit<16>  identifier;
    bit<16>  sequence_number;
    bit<64>  timestamp;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_t {
    bit<32>      flags;
    ipv6_addr_t  target_ipv6_addr;
    // NDP option.
    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}

// Packet-in header. Prepended to packets sent to the CPU_PORT and used by the
// P4Runtime server (Stratum) to populate the PacketIn message metadata fields.
// Here we use it to carry the original ingress port where the packet was
// received.
@controller_header("packet_in")
header cpu_in_header_t {
    port_num_t  ingress_port;
    bit<7>      _pad;
}

// Packet-out header. Prepended to packets received from the CPU_PORT. Fields of
// this header are populated by the P4Runtime server based on the P4Runtime
// PacketOut metadata fields. Here we use it to inform the P4 pipeline on which
// port this packet-out should be transmitted.
@controller_header("packet_out")
header cpu_out_header_t {
    port_num_t  egress_port;
    bit<7>      _pad;
}

header hopbyhop_ext_header_t {
    bit<8> next_header;
    bit<8> extHdr_len;
}

header int_opt_header_t {
    bit<8> option_type;
    bit<8> optData_len;
}

// INT header。符合 INT version 2.0标准
header int_md_header_t {
    bit<4>  ver;
    bit<1>  d;
    bit<1>  e;    
    bit<1>  m;
    bit<12> rsvd1;
    // bit<3>  rsvd2;
    bit<5>  hop_metadata_len;
    bit<8>  remaining_hop_cnt;
    bit<4>  instruction_mask_0003; /* split the bits for lookup */
    bit<4>  instruction_mask_0407;
    bit<4>  instruction_mask_0811;
    bit<4>  instruction_mask_1215;
    bit<16> domain_specific_id;
    bit<16> domain_specific_instruction;
    bit<16> domain_specific_flags;
}

// INT meta-value headers - different header for each value type
// bit0 (MSB) : Node ID
header int_switch_id_t {
    bit<32> switch_id;
}
// – bit1: Level 1 Ingress Interface ID (16 bits) + Egress Interface ID (16 bits)
header int_level1_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}
// – bit2: Hop latency
header int_hop_latency_t {
    bit<32> hop_latency;
}
// – bit3: Queue ID (8 bits) + Queue occupancy (24 bits)
header int_q_occupancy_t {
    bit<8> q_id;
    bit<24> q_occupancy;
}

// – bit4: Ingress timestamp (8 bytes)
header int_ingress_tstamp_t {
    bit<64> ingress_tstamp;
}

// – bit5: Egress timestamp (8 bytes)
header int_egress_tstamp_t {
    bit<64> egress_tstamp;
}

// – bit6: Level 2 Ingress Interface ID + Egress Interface ID (4 bytes each)
header int_level2_port_ids_t {
    bit<32> ingress_port_id;
    bit<32> egress_port_id;
}

// – bit7: Egress interface Tx utilization
header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}

// – bit8: Buffer ID (8 bits) + Buffer occupancy (24 bits)
// 这个要怎么实现，还不知道。
header int_buffer_occupancy_t {
    bit<8> buffer_id;
    bit<24> buffer_occupancy;
}

// – bit15: Checksum Complement
// 后面再考虑这个字段。

// – The remaining bits are reserved.

header int_data_t {
    // Maximum int metadata stack size in INT-option:
    // (0xF0) * 8 = 240*8 =1920
    varbit<1920> data;
}


//这个padding固定占据4个字节； 
// option_type固定为1；
// optData_leng的值固定为2；
header pad4_t {
    bit<8> option_type; 
    bit<8> optData_len;
    bit<16>  optData;
}

const bit<3> NPROTO_ETHERNET = 0;
// 下面两个好像没有用上
const bit<3> NPROTO_TELEMETRY_DROP_HEADER = 1;
const bit<3> NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2;

// telemetry report group header -- INT 2.0
header report_group_header_t {
    bit<4>  ver;
    bit<6>  hw_id;
    bit<22> seq_no;
    // node_id应该就是switch id
    bit<32> node_id; 
}
const bit<8> REPORT_GROUP_HEADER_FIXED_LEN = 8;

// Individual Report Headers -- INT 2.0
header individual_report_header_t {
    bit<4>  rep_type;
    bit<4>  in_type;
    bit<8>  report_length;
    bit<8>  md_length;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<1>  i;
    bit<4>  rsvd;    
}
const bit<8> REPORT_INDIVIDUAL_HEADER_FIXED_LEN = 4;

// Individual Report Main Contents for RepType 1 (INT)  header -- INT 2.0
// 先忽略。sink的metadata也写入embedded metadata stack里。

/* Device should include its own INT metadata as embedded,
* we'll not use local_report_header for this purpose.
*/

// INT 2.0里面不再有drop header了


struct parsed_headers_t {
    cpu_out_header_t cpu_out;
    cpu_in_header_t cpu_in;
    // INT Report Encapsulation
    ethernet_t report_ethernet;
    // 本次不用ipv4封装INT telemetry report。但是保留，或许后面会用到。
    ipv4_t report_ipv4;
    ipv6_t report_ipv6;
    udp_t report_udp;
    // INT Report Headers
    report_group_header_t  report_group_header;
    individual_report_header_t individual_report_header;
    // Original packet's headers
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
    //逐跳可选项报头
    //开始
    hopbyhop_ext_header_t hopbyhop_ext_header;
    //INT-option的报头
    int_opt_header_t int_opt_header;
    // INT specific headers    
    // INT-MD header
    int_md_header_t int_md_header;    
    // INT-metadata stack
    int_data_t int_data;
    int_switch_id_t int_switch_id;
    int_level1_port_ids_t int_level1_port_ids;
    int_hop_latency_t int_hop_latency;
    int_q_occupancy_t int_q_occupancy;
    int_ingress_tstamp_t int_ingress_tstamp;
    int_egress_tstamp_t int_egress_tstamp;
    int_level2_port_ids_t int_level2_port_ids;
    int_egress_port_tx_util_t int_egress_tx_util;
    int_buffer_occupancy_t int_buffer_occupancy;
    //扩展头不足64位的时候需要补齐64位的长度
    pad4_t pad4;
    // 逐跳可选项报头的终止位置
    //下面是SRv6部分。这里的SRv6用的是next_proto=43,是路由头部。
    srv6h_t srv6h;
    srv6_list_t[SRV6_MAX_HOPS] srv6_list;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
    icmpv6_t icmpv6;
    ndp_t ndp;
}

// bit<5>  new_words; 改成 5 bits，是为了和hop_ml保持一致。
struct int_metadata_t {
    switch_id_t switch_id;
    // bit<16> new_bytes;
    bit<5>  new_words;
    _BOOL  source;
    _BOOL  sink;
    _BOOL  transit;
    bit<8> intl4_shim_len;
}

struct local_metadata_t {
    l4_port_t   l4_src_port;
    l4_port_t   l4_dst_port;
    bool        is_multicast;
    ipv6_addr_t next_srv6_sid;
    _BOOL       dstIP_replaced_bySRv6;
    _BOOL       srv6_processed;
    // _BOOL       dstIP_replaced;
    _BOOL       needtobe_resubmit;    
    bit<8>      ip_proto;
    bit<8>      icmp_type;
    //下面是从int_headers.p4搬过来的
    next_hop_id_t next_hop_id;
    bit<16>       selector;
    int_metadata_t int_meta;
    bool compute_checksum;
    bit<8>      srv6_segment_num;
    bit<128>    s0;
    bit<128>    s1;
    bit<128>    s2;
    bit<128>    s3;
    bit<128>    s4;
    bit<128>    s5;
    bit<128>    s6;
    bit<128>    s7;
    bit<128>    s8;
    bit<128>    s9;
    bit<128>    s10;
    bit<128>    s11;
}

#endif

/////////原来已有的。

// struct parsed_headers_t {
//     cpu_out_header_t cpu_out;
//     cpu_in_header_t cpu_in;
//     ethernet_t ethernet;
//     ipv4_t ipv4;
//     ipv6_t ipv6;
//     //这里的SRv6用的是next_proto=43,是路由头部。
//     srv6h_t srv6h;
//     srv6_list_t[SRV6_MAX_HOPS] srv6_list;
//     // hop_metadata_h[SRV6_MAX_HOPS] int_metadatas;
//     // try_meata_t try;
//     tcp_t tcp;
//     udp_t udp;
//     icmp_t icmp;
//     icmpv6_t icmpv6;
//     ndp_t ndp;
// }

// struct local_metadata_t {
//     l4_port_t   l4_src_port;
//     l4_port_t   l4_dst_port;
//     bool        is_multicast;
//     ipv6_addr_t next_srv6_sid;
//     bit<8>      ip_proto;
//     bit<8>      icmp_type;
// }

/////////原来已有的。

// // Report Telemetry Headers -- INT 1.0
// header report_fixed_header_t {
//     bit<4>  ver;
//     bit<4>  len;
//     bit<3>  nproto;
//     bit<6>  rep_md_bits;
//     bit<1>  d;
//     bit<1>  q;
//     bit<1>  f;
//     bit<6>  rsvd;
//     bit<6>  hw_id;
//     bit<32> sw_id;
//     bit<32> seq_no;
//     bit<32> ingress_tstamp;
// }
// const bit<8> REPORT_FIXED_HEADER_LEN = 16;


// // Telemetry drop report header
// header drop_report_header_t {
//     bit<32> switch_id;
//     bit<16> ingress_port_id;
//     bit<16> egress_port_id;
//     bit<8>  queue_id;
//     bit<8>  drop_reason;
//     bit<16> pad;
// }
// const bit<8> DROP_REPORT_HEADER_LEN = 12;

// // Switch Local Report Header
// header local_report_header_t {
//     bit<32> switch_id;
//     bit<16> ingress_port_id;
//     bit<16> egress_port_id;
//     bit<8>  queue_id;
//     bit<24> queue_occupancy;
//     bit<32> egress_tstamp;
// }
// const bit<8> LOCAL_REPORT_HEADER_LEN = 16;

// header_union local_report_t {
//     drop_report_header_t drop_report_header;
//     local_report_header_t local_report_header;
// }



