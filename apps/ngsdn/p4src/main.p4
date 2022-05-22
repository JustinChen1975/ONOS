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


#include <core.p4>
#include <v1model.p4>

#include "include/defines.p4"
#include "include/headers.p4"
#include "include/actions.p4"
#include "include/int_source.p4"
#include "include/int_transit.p4"
#include "include/int_sink.p4"
#include "include/int_report.p4"
#include "include/parsers.p4"

//------------------------------------------------------------------------------
// HEADER DEFINITIONS
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------


control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta)
{
    // Not used here. We assume all packets have valid checksum, if not, we let
    // the end hosts detect errors.
    apply { /* EMPTY */ }
}


control IngressPipeImpl (inout parsed_headers_t    hdr,
                         inout local_metadata_t    local_metadata,
                         inout standard_metadata_t standard_metadata) {

    // Drop action shared by many tables.
    action drop() {
        mark_to_drop(standard_metadata);
    }


    // *** L2 BRIDGING
    //
    // Here we define tables to forward packets based on their Ethernet
    // destination address. There are two types of L2 entries that we
    // need to support:
    //
    // 1. Unicast entries: which will be filled in by the control plane when the
    //    location (port) of new hosts is learned.
    // 2. Broadcast/multicast entries: used replicate NDP Neighbor Solicitation
    //    (NS) messages to all host-facing ports;
    //
    // For (2), unlike ARP messages in IPv4 which are broadcasted to Ethernet
    // destination address FF:FF:FF:FF:FF:FF, NDP messages are sent to special
    // Ethernet addresses specified by RFC2464. These addresses are prefixed
    // with 33:33 and the last four octets are the last four octets of the IPv6
    // destination multicast address. The most straightforward way of matching
    // on such IPv6 broadcast/multicast packets, without digging in the details
    // of RFC2464, is to use a ternary match on 33:33:**:**:**:**, where * means
    // "don't care".
    //
    // For this reason, our solution defines two tables. One that matches in an
    // exact fashion (easier to scale on switch ASIC memory) and one that uses
    // ternary matching (which requires more expensive TCAM memories, usually
    // much smaller).

    // --- l2_exact_table (for unicast entries) --------------------------------

    action set_egress_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    table l2_exact_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_egress_port;
            @defaultonly drop;
        }
        const default_action = drop;
        // The @name annotation is used here to provide a name to this table
        // counter, as it will be needed by the compiler to generate the
        // corresponding P4Info entity.
        @name("l2_exact_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- l2_ternary_table (for broadcast/multicast entries) ------------------

    action set_multicast_group(mcast_group_id_t gid) {
        // gid will be used by the Packet Replication Engine (PRE) in the
        // Traffic Manager--located right after the ingress pipeline, to
        // replicate a packet to multiple egress ports, specified by the control
        // plane by means of P4Runtime MulticastGroupEntry messages.
        standard_metadata.mcast_grp = gid;
        local_metadata.is_multicast = true;
    }

    // 目标MAC地址如果不是已知的，也不是广播类地址。那么会被丢弃掉。
    // TODO ： 是否要改进下，对于未知MAC地址进行怎么查询？
    table l2_ternary_table {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            @defaultonly drop;
        }
        const default_action = drop;
        @name("l2_ternary_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }


    // *** TODO EXERCISE 5 (IPV6 ROUTING)
    //
    // 1. Create a table to to handle NDP messages to resolve the MAC address of
    //    switch. This table should:
    //    - match on hdr.ndp.target_ipv6_addr (exact match)
    //    - provide action "ndp_ns_to_na" (look in snippets.p4)
    //    - default_action should be "NoAction"
    //
    // 2. Create table to handle IPv6 routing. Create a L2 my station table (hit
    //    when Ethernet destination address is the switch address). This table
    //    should not do anything to the packet (i.e., NoAction), but the control
    //    block below should use the result (table.hit) to decide how to process
    //    the packet.
    //
    // 3. Create a table for IPv6 routing. An action selector should be use to
    //    pick a next hop MAC address according to a hash of packet header
    //    fields (IPv6 source/destination address and the flow label). Look in
    //    snippets.p4 for an example of an action selector and table using it.
    //
    // You can name your tables whatever you like. You will need to fill
    // the name in elsewhere in this exercise.
    // hdr.ndp.target_ipv6_addr就是设备的网关的IPv6地址。主机发出NS报文来寻找网关IP地址的对应MAC地址。

    // --- ndp_reply_table -----------------------------------------------------

    action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp.length = 1;
        hdr.ndp.target_mac_addr = target_mac;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table ndp_reply_table {
        key = {
            hdr.ndp.target_ipv6_addr: exact;
        }
        actions = {
            ndp_ns_to_na;
        }
        @name("ndp_reply_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- my_station_table ---------------------------------------------------

    table my_station_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = { NoAction; }
        @name("my_station_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
  
    // --- v6routing_table ---------指向PORT和MAC地址-------------------------------------------
    //与前面的不同。这次对于某个特定路由，直接指定相应的端口，同时更改dst MAC地址。

    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) multipaths_selector;
    
    action set_output(port_num_t port_num,mac_addr_t dmac) {
        // 把src mac改换为Router MAC
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
        standard_metadata.egress_spec = port_num;
        // Decrement TTL
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    table v6routing_table {
      key = {
          hdr.ipv6.dst_addr:          lpm;
          // The following fields are not used for matching, but as input to the
          // ecmp_selector hash function.
          hdr.ipv6.dst_addr:          selector;
          hdr.ipv6.src_addr:          selector;
          hdr.ipv6.flow_label:        selector;
          // The rest of the 5-tuple is optional per RFC6438
          hdr.ipv6.next_hdr:          selector;
          local_metadata.l4_src_port: selector;
          local_metadata.l4_dst_port: selector;
      }
      actions = {
          set_output;          
      }
      implementation = multipaths_selector;
      @name("v6routing_table_counter")
      counters = direct_counter(CounterType.packets_and_bytes);
    }

    // (SRV6)
    //
    // Implement tables to provide SRV6 logic.

    // --- srv6_my_sid----------------------------------------------------------

    // Process the packet if the destination IP is the segemnt Id(sid) of this
    // device. This table will decrement the "segment left" field from the Srv6
    // header and set destination IP address to next segment.

    action srv6_end() {
        hdr.srv6h.segment_left = hdr.srv6h.segment_left - 1;
        hdr.ipv6.dst_addr = local_metadata.next_srv6_sid;        
    }

    direct_counter(CounterType.packets_and_bytes) srv6_my_sid_table_counter;
    table srv6_my_sid {
      key = {
          hdr.ipv6.dst_addr: lpm;
      }
      actions = {
          srv6_end;
      }
      counters = srv6_my_sid_table_counter;
    }

    // --- srv6_transit --------------------------------------------------------

    // Inserts the SRv6 header to the IPv6 header of the packet based on the
    // destination IP address.


    action insert_srv6h_header(bit<8> num_segments) {
        hdr.srv6h.setValid();
        //SRv6的位置固定在逐跳选项扩展头之后，其他的之前
        if( hdr.ipv6.next_hdr == IP_PROTO_HOPOPT6){
            hdr.srv6h.next_hdr = hdr.hopbyhop_ext_header.next_header;
            hdr.hopbyhop_ext_header.next_header  = IP_PROTO_SRV6; 
        }
        else {
            hdr.srv6h.next_hdr = hdr.ipv6.next_hdr;
            hdr.ipv6.next_hdr = IP_PROTO_SRV6;
        }       
        hdr.srv6h.hdr_ext_len =  num_segments * 2;
        hdr.srv6h.routing_type = 4;
        hdr.srv6h.segment_left = num_segments - 1;
        hdr.srv6h.last_entry = num_segments - 1;
        hdr.srv6h.flags = 0;
        hdr.srv6h.tag = 0;        
    }

    /*
       Single segment header doesn't make sense given PSP
       i.e. we will pop the SRv6 header when segments_left reaches 0
     */

    action srv6_t_insert_2(ipv6_addr_t s1, ipv6_addr_t s2) {
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 40;
        insert_srv6h_header(2);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s2;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s1;
    }

    action srv6_t_insert_3(ipv6_addr_t s1, ipv6_addr_t s2, ipv6_addr_t s3) {
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 56;
        insert_srv6h_header(3);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s3;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s2;
        hdr.srv6_list[2].setValid();
        hdr.srv6_list[2].segment_id = s1;
    }

    // action set_value(){

    // }

    // SRV6_MAX_HOPS =12
    action srv6_t_insert( 
                         ipv6_addr_t s0,
                        ipv6_addr_t s1, ipv6_addr_t s2, ipv6_addr_t s3,
                         ipv6_addr_t s4, ipv6_addr_t s5, ipv6_addr_t s6,
                         ipv6_addr_t s7, ipv6_addr_t s8, ipv6_addr_t s9,
                         ipv6_addr_t s10, ipv6_addr_t s11, 
                        ipv6_addr_t next_hop_ip,
                         bit<8> segment_num) {
       
        local_metadata.s0= s0;
        local_metadata.s1= s1;
        local_metadata.s2= s2;
        local_metadata.s3= s3;
        local_metadata.s4= s4;
        local_metadata.s5= s5;
        local_metadata.s6= s6;
        local_metadata.s7= s7;
        local_metadata.s8= s8;
        local_metadata.s9= s9;
        local_metadata.s10= s10;
        local_metadata.s11= s11;

        local_metadata.srv6_segment_num = segment_num;

        // action里不能有if语句；
        // hdr.srv6_list.pop_front(这里必须是constant，不能是变量)

        // 看起来next_hop_ip就是s0，就是SRv6的ingress router的下一跳。
        // 最后一个S11其实终端主机。所以ingress router +S0 + S1 + .. S10 ，总共支持12跳路由器。
        hdr.ipv6.dst_addr = next_hop_ip;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 8+ (bit<16>) segment_num * 16 ;
        insert_srv6h_header((bit<8>) segment_num);

    }

    direct_counter(CounterType.packets_and_bytes) srv6_transit_table_counter;
    // 判断ipv6的目标地址是否需要用SRv6封装。
    table srv6_transit {
      key = {
          hdr.ipv6.dst_addr: lpm;
          // TODO: what other fields do we want to match?
      }
      actions = {
          srv6_t_insert;
          srv6_t_insert_2;
          srv6_t_insert_3;
          // Extra credit: set a metadata field, then push label stack in egress
      }
      counters = srv6_transit_table_counter;
    }

    // Called directly in the apply block.
    action srv6_pop() {
        //SRv6的位置固定在逐跳选项扩展头之后，其他的之前
        if( hdr.ipv6.next_hdr == IP_PROTO_HOPOPT6){
            hdr.hopbyhop_ext_header.next_header  = hdr.srv6h.next_hdr; 
        }
        else {
            hdr.ipv6.next_hdr = hdr.srv6h.next_hdr;
        }  
        // SRv6 header is 8 bytes
        // SRv6 list entry is 16 bytes each
        // (((bit<16>)hdr.srv6h.last_entry + 1) * 16) + 8;
        bit<16> srv6h_size = (((bit<16>)hdr.srv6h.last_entry + 1) << 4) + 8;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len - srv6h_size;
        hdr.srv6h.setInvalid();
        // Need to set MAX_HOPS headers invalid
        hdr.srv6_list[0].setInvalid();
        hdr.srv6_list[1].setInvalid();
        hdr.srv6_list[2].setInvalid();
        hdr.srv6_list[3].setInvalid();
        hdr.srv6_list[4].setInvalid();
        hdr.srv6_list[5].setInvalid();
        hdr.srv6_list[6].setInvalid();
        hdr.srv6_list[7].setInvalid();
        hdr.srv6_list[8].setInvalid();
        hdr.srv6_list[9].setInvalid();
        hdr.srv6_list[10].setInvalid();
        hdr.srv6_list[11].setInvalid();        
    }

    // *** ACL
    //
    // Provides ways to override a previous forwarding decision, for example
    // requiring that a packet is cloned/sent to the CPU, or dropped.
    //
    // We use this table to clone all NDP packets to the control plane, so to
    // enable host discovery. When the location of a new host is discovered, the
    // controller is expected to update the L2 and L3 tables with the
    // correspionding brinding and routing entries.

    //TODO： send_to_cpu()和clone_to_cpu的不同，是否在于 send_to_cpu会失去standard_metadata呢？
    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action clone_to_cpu() {
        // Cloning is achieved by using a v1model-specific primitive. Here we
        // set the type of clone operation (ingress-to-egress pipeline), the
        // clone session ID (the CPU one), and the metadata fields we want to
        // preserve for the cloned packet replica.
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, { standard_metadata.ingress_port });
    }

    table acl_table {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr:          ternary;
            hdr.ethernet.src_addr:          ternary;
            hdr.ethernet.ether_type:        ternary;
            local_metadata.ip_proto:        ternary;
            local_metadata.icmp_type:       ternary;
            local_metadata.l4_src_port:     ternary;
            local_metadata.l4_dst_port:     ternary;
        }
        actions = {
            send_to_cpu;
            clone_to_cpu;
            drop;
        }
        @name("acl_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- Ingress Pipeline的总的逻辑 --------------------------------------------------------
    
    apply {

        if (hdr.cpu_out.isValid()) {
            // Implement logic such that if this is a packet-out from the
            // controller:
            // 1. Set the packet egress port to that found in the cpu_out header
            // 2. Remove (set invalid) the cpu_out header
            // 3. Exit the pipeline here (no need to go through other tables

            // 从控制器发送过来的数据包，就直接按照控制器的要求把数据从设定好的端口发送出去。
            // 不用再对数据包进行任何的处理。
            standard_metadata.egress_spec = hdr.cpu_out.egress_port;
            hdr.cpu_out.setInvalid();
            exit;
        }

        if(IS_RECIRCULATED(standard_metadata)){
            // 如果一个数据包是recirculated的，必须先修改instance_type。
            // 否则直接对它进行clone，会导致P4交换机崩溃。
            standard_metadata.instance_type = BMV2_V1MODEL_INSTANCE_TYPE_NORMAL ;
            local_metadata.needtobe_resubmit = _FALSE ;
            local_metadata.dstIP_replaced_bySRv6 = _FALSE;
            //TODO：  下面这句理论上可以不用写。
            local_metadata.srv6_processed = _TRUE ;                        
            // clone_to_cpu();            
            //  clone3(CloneType.I2E, REPORT_MIRROR_SESSION_ID, standard_metadata);
            //TODO： Recirculate后，上面进行了克隆；一个克隆包是原始的，另一个包会应该是因为下面的exit语句而不再执行后面的NDP等处理模块了吧。要用debug再确认下。
            // 必须exit，否则数据包会不断循环没完没了。
            // exit;
        }        
         
        // NDP处理语块  
        bool do_l3_l2 = true;        
        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            // Insert logic to handle NDP messages to resolve the MAC address of the
            // switch. You should apply the NDP reply table created before.
            // If this is an NDP NS packet, i.e., if a matching entry is found,
            // unset the "do_l3_l2" flag to skip the L3 and L2 tables, as the
            // "ndp_ns_to_na" action already set an egress port.

            //hit的话，意味着该NS报文在询问的是本地路由器接口IP地址的对应MAC地址。
            //所以本地路由器会进行报文回复。
            // 在 action "ndp_ns_to_na"里已经设置了egress port，所以不用处理后续的相关功能模块，但是要克隆给CPU。 
            // 克隆的目的是为了让ONOS知道有新的host上来了吧？
            if (ndp_reply_table.apply().hit) {                
                do_l3_l2 = false;      
            }
        }
        
        // INT source的判定的处理模块
        // 下面是INT部分的处理。
        // 应该先进行INT的处理。因为SRv6部分会修改IPv6的目的地。在IPv6的目的地被修改之前，应该先确定是否该数据包是在我们的watchlist之中。        
        //确定数据包上来的端口是不是INT source的端口。
        //但还要经过watchlist的过滤，看是不是感兴趣的数据包。
        //TODO：目前假设int source port都设置在主机端口上。其实也可以考虑设置在中间的一段路径上。
        // 那么在INT source port上就可能收到其他的INT source port/sink port对之间路过的携带INT报头的INT数据包。
        // 对于这种场景，后面再予以考虑。
        process_int_source_port.apply(hdr, local_metadata, standard_metadata);
        // TODO : hit语句是否包含了defaultonly ??不是的话，可以改写为.hit()。应该是不包括的。

        // 如果数据包来自于INT source端口，判断该数据包是不是我们感兴趣的(通过watchlist)，如果是，写入相关的header
        // 但这时候没有写入source node的metadata。
        if (local_metadata.int_meta.source == _TRUE) {
            //插入逐跳选项扩展头和INT option
            process_int_source.apply(hdr, local_metadata, standard_metadata);
        }


        // SRv6处理模块
        // Insert logic to match the My Station table and upon hit, the
        // routing table. You should also add a conditional to drop the
        // packet if the hop_limit reaches 0.

            // Insert logic to match the SRv6 My SID and Transit tables as well
            // as logic to perform PSP behavior. HINT: This logic belongs
            // somewhere between checking the switch's my station table and
            // applying the routing table.

        bool dst_mac_is_mystation = false;
        if ( my_station_table.apply().hit) {
            dst_mac_is_mystation = true; 
        }
        // local_metadata.srv6_processed如果是1的话，那么这应该是个recir的包。
        if ( do_l3_l2 && hdr.ipv6.isValid() && dst_mac_is_mystation && !local_metadata.srv6_processed ) {

                // 如果ipv6的目标地址是本设备的Srv6 id的话。
                if (srv6_my_sid.apply().hit) {
                    // PSP logic -- enabled for all packets
                    // 目的地址被替换为SRv6里面的地址了。        
                    local_metadata.dstIP_replaced_bySRv6 =_TRUE ;
                    if (hdr.srv6h.isValid() && hdr.srv6h.segment_left == 0) {
                        srv6_pop();                    
                    }
                } else {
                    // srv6_transit table判断是否需要用SRv6进行封装。
                    // srv6_transit table命中的话，仅仅是写入srv6 header，
                    if(srv6_transit.apply().hit){
                        bit<8> sn =  local_metadata.srv6_segment_num;
                        // 下面才写入srv6中的各个segment
                        if(sn >0 ) { 
                            hdr.srv6_list[0].setValid(); 
                            hdr.srv6_list[0].segment_id = local_metadata.s0;
                            sn = sn -1; }
                        if(sn >0 ) { 
                            hdr.srv6_list[1].setValid(); 
                            hdr.srv6_list[1].segment_id = local_metadata.s1;
                            sn = sn -1;  }                        
                        if(sn >0 ) { 
                            hdr.srv6_list[2].setValid(); 
                            hdr.srv6_list[2].segment_id = local_metadata.s2;
                            sn = sn -1;  }                        
                        if(sn >0 ) { 
                            hdr.srv6_list[3].setValid(); 
                            hdr.srv6_list[3].segment_id = local_metadata.s3;
                            sn = sn -1;  }      
                        if(sn >0 ) { 
                            hdr.srv6_list[4].setValid(); 
                            hdr.srv6_list[4].segment_id = local_metadata.s4;
                            sn = sn -1;  }      
                        if(sn >0 ) { 
                            hdr.srv6_list[5].setValid(); 
                            hdr.srv6_list[5].segment_id = local_metadata.s5;
                            sn = sn -1;  }       
                        if(sn >0 ) { 
                            hdr.srv6_list[6].setValid(); 
                            hdr.srv6_list[6].segment_id = local_metadata.s6;
                            sn = sn -1;  }                                   
                        if(sn >0 ) { 
                            hdr.srv6_list[7].setValid(); 
                            hdr.srv6_list[7].segment_id = local_metadata.s7;
                            sn = sn -1;  }                                   
                        if(sn >0 ) { 
                            hdr.srv6_list[8].setValid(); 
                            hdr.srv6_list[8].segment_id = local_metadata.s8;
                            sn = sn -1;  }                                   
                        if(sn >0 ) { 
                            hdr.srv6_list[9].setValid(); 
                            hdr.srv6_list[9].segment_id = local_metadata.s9;
                            sn = sn -1;  }                                   
                        if(sn >0 ) { 
                            hdr.srv6_list[10].setValid(); 
                            hdr.srv6_list[10].segment_id = local_metadata.s10;
                            sn = sn -1;  }                                   
                        if(sn >0 ) { 
                            hdr.srv6_list[11].setValid(); 
                            hdr.srv6_list[11].segment_id = local_metadata.s11;
                            sn = sn -1;  }      

                        // 下面这句其实应该写在action srv6_t_insert里。
                        local_metadata.dstIP_replaced_bySRv6 =_TRUE ;
                    }
                }      
                local_metadata.srv6_processed = _TRUE ;                        
        }


        // 三层路由处理模块
        bool canbe_routed = false;
        if ( do_l3_l2 && hdr.ipv6.isValid() && dst_mac_is_mystation ) {
                if(v6routing_table.apply().hit) {    
                    // local_metadata.dstIP_replaced_bySRv6 = _FALSE;
                    if(hdr.ipv6.hop_limit == 0)   { drop(); }  
                    else  {   canbe_routed = true;   }                           
                }else {
                    // 对于目的地址被SRv6程序段替换的数据包，同时目的地址又未能在路由表中查到的，需要送给ONOS去查找路由表。
                    // 所以直接送给了ONOS。不能用clone的方式。因为克隆送出ONOS的数据包是原始的数据包，那么前面SRv6所做的工作就白费了。
                    // 目的是要让ONOS提供新的目的地址中的路由。
                    // 还有一种方案就是用recirculate +  send_to_cpu的方式。（测试成功）
                    // 还有一种方案就是在ONOS里，把ACL table的action从clone_to_cpu改动为send_to_cpu。（未测试过）。
                    if (local_metadata.dstIP_replaced_bySRv6 ==_TRUE)  {    
                        send_to_cpu();                   
                        exit ;}
                }     
        }


        // 二层处理模块
        //对于MAC地址是本机的，就用上面的代码处理，也就是路由的方式处理。这里不考虑V4的数据包。
        // 已经路由处理过的数据包，它的目标MAC地址已经被修改为下一跳路由器的MAC地址，在下面又会被重新指定发送出去的port。
        // 但是上面路由命中之后的hit.else.exit，使得路由命中的数据包直接完成了ingress pipeline的处理，就不会再进行接下来的二层处理等了。
        // 但是没有路由命中的数据包，又不是SRv6处理的数据包，就会通过下面的二层处理。
        //还有，对于MAC地址不是本机的，也用下面的代码处理，也就是二层的方式处理。
        bool canbe_exact_switched = false;        
        if ( do_l3_l2 &&  !canbe_routed){
            if (l2_exact_table.apply().hit) {
                canbe_exact_switched=true; 
            }else {
                    // ...if an entry is NOT found, apply the ternary one in case
                    // this is a multicast/broadcast NDP NS packet.
                    //必须把这些广播包克隆给ONOS知道，否则就不正常。
                    //应该是克隆后才能让ONOS知道有这些主机的存在。
                    l2_ternary_table.apply();          
                    canbe_exact_switched = false; 
            }
        }

        // INT SINK的判定的处理模块
        // 确定数据包要发送的端口是不是INT SINK的端口。
        // 如果是INT数据包，数据包的发送端口又是INT sink port，那么会进行克隆。之所以要克隆，是因为要生成INT report的需要。
        // 要在路由和二层处理模块之后判断。因为经过了SRv6, L3, L2等模块的处理之后才确定了真正的egress_port。              
        // TODO： 考虑要引入INT session的概念。因为在同一个INT Domain里，INT source和INT sink应该是成对出现的。
        // 只有这样才能同时支持多个INT测量流的存在，从而不混淆。不然同一个物理端口可能同时作为多个INT 流的sink端口。
        // 对于是广播的报文，不会判断包的egress_port是不是INT sink端口。
        if ( canbe_routed || canbe_exact_switched ) {
            if ( hdr.int_opt_header.isValid()){
                // 如果数据包要发送的端口是INT sink端口，就会把local_metadata.int_meta.sink设置为TRUE.
                process_int_sink_port.apply(hdr, local_metadata, standard_metadata);
                if (local_metadata.int_meta.sink == _TRUE ) {   
                    // #ifdef TARGET_BMV2
                    // 标记为需要resubmit。rebumit之后会克隆。之所以不直接克隆，是因为直接克隆出来的数据包是原始的数据包。 
                    // 先不考虑SRv6。
                    // local_metadata.needtobe_resubmit = _TRUE ;
                    // clone_to_cpu();          
                    // 其实needtobe_resubmit这个名字起得不好。应该是needtobe_recir
                    // 要求local_metadata.dstIP_replaced_bySRv6 ==_TRUE，是要求SRv6倒数第二跳的处理吧；
                    // 如果是recir过来的数据包，就不是TRUE的。其实为什么不在上面的Recir block里处理呢？
                   if (local_metadata.dstIP_replaced_bySRv6 ==_TRUE)  {
                        local_metadata.needtobe_resubmit = _TRUE ;                    
                   }else {
                        local_metadata.needtobe_resubmit = _FALSE ;                    
                        // clone3(CloneType.I2E, REPORT_MIRROR_SESSION_ID, standard_metadata);    
                        clone3(CloneType.I2E, REPORT_MIRROR_SESSION_ID, {standard_metadata,local_metadata} );                                               
                   }                    
                    // exit ;
                    // #endif // TARGET_BMV2
                }   
            }     
        }       

        // Lastly, apply the ACL table.
        // 注意，clone发出去的是原始数据包，这样ingress pipeline里的改动就全部无效。
        // 下面的过滤条件很重要，可以大量减少发送给CPU的数据包。实现只有“首包”才发给SDN控制器的目的。
        if(!(canbe_routed || canbe_exact_switched)){
            acl_table.apply();
        }        
    }
}


control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {

        if( local_metadata.needtobe_resubmit == _TRUE ) {
            local_metadata.needtobe_resubmit = _FALSE;
            // recirculate(local_metadata.needto_clone);
            // TODO : 需要保留local_metadata吗？
            // 看来是需要的，因为recirculate后的数据包到了ingress pipeline后会被克隆，然后两个包都会接就来到这里（没有再经过ingress pipeline的处理），因此需要保留local_metadata，这样在egress pipeline的余下部分处理的时候可能会用上。
            recirculate({standard_metadata,local_metadata});            
            exit;
        }   

        if(hdr.int_opt_header.isValid()) {
            // 不管是source,transit,sink都会先插入自己的metadata的数据
            //TODO：后面再考虑不让sink把自己的metadata嵌入到INT option里，而是完全按照report的格式要求发送数据。
            process_int_transit.apply(hdr, local_metadata, standard_metadata);

            // 如果是个克隆包，就在克隆包的基础上发送INT report
            if (local_metadata.int_meta.sink == _TRUE && IS_I2E_CLONE(standard_metadata)) {
                /* send int report */
                process_int_report.apply(hdr, local_metadata, standard_metadata);
                // process_int_sink.apply(hdr, local_metadata, standard_metadata);
            }

            if (local_metadata.int_meta.sink == _TRUE && !IS_I2E_CLONE(standard_metadata)) {
                // 把INT的相关内容从正常数据包里剥除掉。
                // process_int_report.apply(hdr, local_metadata, standard_metadata);
                process_int_sink.apply(hdr, local_metadata, standard_metadata);
                }         
        }


        if (standard_metadata.egress_port == CPU_PORT) {
            // Implement logic such that if the packet is to be forwarded to the
            // CPU port, e.g., if in ingress we matched on the ACL table with
            // action send/clone_to_cpu...
            // 1. Set cpu_in header as valid
            // 2. Set the cpu_in.ingress_port field to the original packet's
            //    ingress port (standard_metadata.ingress_port).

            hdr.cpu_in.setValid();
            hdr.cpu_in.ingress_port = standard_metadata.ingress_port;
            exit;
        }

        // If this is a multicast packet (flag set by l2_ternary_table), make
        // sure we are not replicating the packet on the same port where it was
        // received. This is useful to avoid broadcasting NDP requests on the
        // ingress port.
        if (local_metadata.is_multicast == true &&
              standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        } 

    }
}


control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t local_metadata)
{
    apply {
        // The following is used to update the ICMPv6 checksum of NDP
        // NA packets generated by the ndp reply table in the ingress pipeline.
        // This function is executed only if the NDP header is present.
        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_ipv6_addr,
                hdr.ndp.type,
                hdr.ndp.length,
                hdr.ndp.target_mac_addr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}



V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;

        // if (IS_E2E_CLONE(standard_metadata) ) {
        //     hdr.ipv6.dst_addr = hdr.ipv6.src_addr ;
        //     mark_to_drop(standard_metadata);
        //              }    

        // if ( standard_metadata.egress_port == 6 && standard_metadata.ingress_port != CPU_PORT ) {
        //     clone3(CloneType.E2E, CPU_CLONE_SESSION_ID, { standard_metadata.ingress_port });                       
        //     hdr.ipv6.dst_addr = hdr.ipv6.src_addr ;
        // }
