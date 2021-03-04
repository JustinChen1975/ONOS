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

#ifndef __DEFINES__
#define __DEFINES__

#define ETH_TYPE_IPV4 0x0800
// #define ETH_TYPE_IPV6 0x0806
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;

// #define IP_PROTO_TCP 8w6
// #define IP_PROTO_UDP 8w17
#define IP_VERSION_4 4w4
#define IP_VERSION_6 4w6
#define IPV4_IHL_MIN 4w5
#define MAX_PORTS 511

#define SRV6_MAX_HOPS 12

const bit<8> ETH_HEADER_LEN = 14;
const bit<8> IPV4_MIN_HEAD_LEN = 20;
const bit<8> UDP_HEADER_LEN = 8;

// IPv6基本报头的固定长度是40字节
const bit<8> IPV6_MIN_HEAD_LEN = 40 ;


#ifndef _BOOL
#define _BOOL bool
#endif
#ifndef _TRUE
#define _TRUE true
#endif
#ifndef _FALSE
#define _FALSE false
#endif

typedef bit<48> mac_t;
typedef bit<32> ip_address_t;
typedef bit<16> l4_port_t;
typedef bit<9>  port_t;
typedef bit<16> next_hop_id_t;

const port_t CPU_PORT = 255;

typedef bit<8> MeterColor;
const MeterColor MeterColor_GREEN = 8w0;
const MeterColor MeterColor_YELLOW = 8w1;
const MeterColor MeterColor_RED = 8w2;

// CPU_PORT specifies the P4 port number associated to controller packet-in and
// packet-out. All packets forwarded via this port will be delivered to the
// controller as P4Runtime PacketIn messages. Similarly, PacketOut messages from
// the controller will be seen by the P4 pipeline as coming from the CPU_PORT.
#define CPU_PORT 255

// CPU_CLONE_SESSION_ID specifies the mirroring session for packets to be cloned
// to the CPU port. Packets associated with this session ID will be cloned to
// the CPU_PORT as well as being transmitted via their egress port (set by the
// bridging/routing/acl table). For cloning to work, the P4Runtime controller
// needs first to insert a CloneSessionEntry that maps this session ID to the
// CPU_PORT.
#define CPU_CLONE_SESSION_ID 99

// Maximum number of hops supported when using SRv6.
// #define SRV6_MAX_HOPS 4

typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<16>  mcast_group_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
// typedef bit<16>  l4_port_t;


const bit<8> IP_PROTO_HOPOPT6 = 0;
const bit<8> IP_PROTO_ICMP   = 1;
const bit<8> IP_PROTO_TCP    = 6;
const bit<8> IP_PROTO_UDP    = 17;
const bit<8> IP_PROTO_SRV6   = 43;
const bit<8> IP_PROTO_ICMPV6 = 58;

const mac_addr_t IPV6_MCAST_01 = 0x33_33_00_00_00_01;

const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;
//自定义INT-MD的可选项类型为： 00,1,1,0001,  0x31, 十进制为49；
//自定义INT-MX的可选项类型为： 00,1,1,0011， 0x33, 十进制为51；
const bit<8> INT_OPTION_TYPE_MD = 49;
const bit<8> INT_OPTION_TYPE_MX = 51;

const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;

const bit<32> NDP_FLAG_ROUTER    = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;
const bit<32> NDP_FLAG_OVERRIDE  = 0x20000000;

//下方是与INT相关的。
/* indicate INT by DSCP value */
const bit<6> DSCP_INT = 0x17;
const bit<6> DSCP_MASK = 0x3F;

typedef bit<48> timestamp_t;
typedef bit<32> switch_id_t;

const bit<8> INT_HEADER_LEN_WORD = 3;
const bit<16> INT_HEADER_SIZE = 8;
// const bit<16> INT_SHIM_HEADER_SIZE = 4;

// const bit<8> CPU_MIRROR_SESSION_ID = 250;
const bit<32> REPORT_MIRROR_SESSION_ID = 500;
const bit<6> HW_ID = 1;
const bit<8> REPORT_HDR_TTL = 64;

// #ifdef TARGET_BMV2
// 一直不明白TARGET_BMV2是需要在哪里定义？要在P4交换机里定义吗？在Mininet里定义吗？
// These definitions are from:
// https://github.com/jafingerhut/p4-guide/blob/master/v1model-special-ops/v1model-special-ops.p4

// These definitions are derived from the numerical values of the enum
// named "PktInstanceType" in the p4lang/behavioral-model source file
// targets/simple_switch/simple_switch.h
// https://github.com/p4lang/behavioral-model/blob/master/targets/simple_switch/simple_switch.h#L126-L134

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

#define IS_RESUBMITTED(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT)
#define IS_RECIRCULATED(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)
#define IS_I2E_CLONE(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)
#define IS_REPLICATED(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION)
// #endif // TARGET__BMV2


#endif
