/*
This code implements functionalities presented in CCP that can be offloaded to the NIC :

The nic cannot set the cwnd of the TCP flow, this still lies under the control of host (kernel/dpdk).
However, the intuition, is that NIC can monitor the TCP flow, and report the
statistics and also trigger the CCP directly, thus reducing the latency.
Hence, the structure is like this :
 ________
|        |
| kernel |
|  DPDK  |\
|________| \
    |       \
    |        \  ________
    |         V|        |
    |          |  CCP   |
    |         ^|________|
    V        /
 ________   /
|        | /
|  NIC   |/
|________|



*/
#include "includes/headers.p4"
#include "includes/parser.p4"

#define MAX_FLOWS 32768
#define MAX_LINKS 512
#define YES 1
#define NO 0

field_list flowkeys {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}


field_list_calculation flow_hash {
  input {
    flowkeys;
  }
  algorithm : crc16;
  output_width : 16;
}

register flowhash {
    width : 32;
    instance_count : 1;
}

register reportType {
    width : 32;
    instance_count : MAX_FLOWS;
}

register bytesAcked {
    width : 32;
    instance_count : MAX_FLOWS;
}

register packetsAcked {
    width : 32;
    instance_count : MAX_FLOWS;
}
register ooo_tester {
    width : 32;
    instance_count : MAX_FLOWS;
}

register seq {
    width : 32;
    instance_count : MAX_FLOWS;
}

register flow_timeout {
    width : 32;
    instance_count : MAX_FLOWS;
}
register ooo_test {
    width : 32;
    instance_count : 1;
}


register bytesMisordered {
    width : 32;
    instance_count : MAX_FLOWS;
}

register packetsMisordered {
    width : 32;
    instance_count : MAX_FLOWS;
}

register ecnBytes {
    width : 32;
    instance_count : MAX_FLOWS;
}

register ecnPackets {
    width : 32;
    instance_count : MAX_FLOWS;
}

register test1 {
    width : 32;
    instance_count : 1;
}

register tstamp {
    width : 32;
    instance_count : 1;
}

register outgoing_pkt_rate {
    width : 32;
    instance_count : MAX_FLOWS;
}

register outgoing_bit_rate {
    width : 32;
    instance_count : MAX_FLOWS;
}

register pkts_in_flight {
    width : 32;
    instance_count : MAX_FLOWS;
}

register bytes_in_flight {
    width : 32;
    instance_count : MAX_FLOWS;
}
/********End of Register ********/
primitive_action do_get_current_time();
primitive_action calc_outgoing_rate();

action do_forward(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}

action nop () {

}

action _drop () {
    drop();
}

action do_compute_flowhash () {
  modify_field_with_hash_based_offset(mdata.flow_hash, 0, flow_hash, 32768);
  register_write(flowhash, 0, mdata.flow_hash);
  shift_left(tcp_ipv4_metadata.scratch,tcp_ipv4_metadata.scratch, 2);
  subtract(tcp_ipv4_metadata.segLength, tcp_ipv4_metadata.tcpLength, tcp_ipv4_metadata.scratch);
}

action do_compute_bytesAcked () {
    register_read(mdata.bytesAcked, bytesAcked, mdata.flow_hash);
    add_to_field(mdata.bytesAcked, ipv4.totalLen);
    register_write(bytesAcked, mdata.flow_hash, mdata.bytesAcked);
}

action do_compute_packetsAcked () {
    register_read(mdata.packetsAcked, packetsAcked, mdata.flow_hash);
    add_to_field(mdata.packetsAcked, 1);
    register_write(packetsAcked, mdata.flow_hash, mdata.packetsAcked);
}

action do_compute_bytesMisordered () {
    register_read(mdata.bytesMisordered, bytesMisordered, mdata.flow_hash);
    add_to_field(mdata.bytesMisordered, ipv4.totalLen);
    register_write(bytesMisordered, mdata.flow_hash, mdata.bytesMisordered);
}

action do_compute_packetsMisordered () {
    register_read(mdata.packetsMisordered, packetsMisordered, mdata.flow_hash);
    add_to_field(mdata.packetsMisordered, 1);
    register_write(packetsMisordered, mdata.flow_hash, mdata.packetsMisordered);
}
action do_test_ooo () {
    register_read(mdata.ooo_tester, ooo_tester, mdata.flow_hash);
    subtract(mdata.ooo_test, tcp.ackNo, mdata.ooo_tester);
    register_write(ooo_tester, mdata.flow_hash, tcp.ackNo);
    register_write(ooo_test, 0 , mdata.ooo_test);
    bit_and(mdata.ooo_test, mdata.ooo_test, 0x80000000);
}

action do_compute_ecnPackets () {
    register_read(mdata.ecnPackets, ecnPackets, mdata.flow_hash);
    add_to_field(mdata.ecnPackets, 1);
    register_write(ecnPackets, mdata.flow_hash, mdata.ecnPackets);
}

action do_compute_ecnBytes () {
    register_read(mdata.ecnBytes, ecnBytes, mdata.flow_hash);
    add_to_field(mdata.ecnBytes, ipv4.totalLen);
    register_write(ecnBytes, mdata.flow_hash, mdata.ecnBytes);
}

action do_compute_flow_timeout_1 () {
    register_read(mdata.flow_timeout, seq, mdata.flow_hash);
    subtract(mdata.timeout, tcp.seqNo, mdata.flow_timeout);
    register_write(test1, 0, mdata.timeout);
}

action do_compute_flow_timeout_2 () {
    bit_and(mdata.timeout, mdata.timeout, 0x80000000);
}

action do_write_seqNo () {
    register_write(seq, mdata.flow_hash, tcp.seqNo);
}

action do_is_timeout () {
    register_write(flow_timeout, mdata.flow_hash, 1);
}

action do_write_current_time () {
    register_write(tstamp, 0, mdata.tstamp);
}

action do_store_current_tstamp () {
    //do_get_current_time();
    //register_write(tstamp, 0, mdata.tstamp);
    register_write(tstamp, mdata.flow_hash, intrinsic_metadata.ingress_global_tstamp);
}

action do_get_prev_tstamp () {
    register_read(mdata.prev_tstamp, tstamp, mdata.flow_hash);
}
action do_compute_outgoing_rate () {
    register_read(mdata.outgoing_bit_rate, outgoing_bit_rate, mdata.flow_hash);
    register_read(mdata.outgoing_pkt_rate, outgoing_pkt_rate, mdata.flow_hash);
    calc_outgoing_rate();
    register_write(outgoing_pkt_rate, mdata.flow_hash, mdata.outgoing_pkt_rate);
    register_write(outgoing_bit_rate, mdata.flow_hash, mdata.outgoing_bit_rate);

}

action do_compute_pkts_in_flight_inc () {
    register_read(mdata.pkts_in_flight, pkts_in_flight, mdata.flow_hash);
    add_to_field(mdata.pkts_in_flight, 1);
    register_write(pkts_in_flight, mdata.flow_hash, mdata.pkts_in_flight);
}

action do_compute_bytes_in_flight_inc () {
    register_read(mdata.bytes_in_flight, bytes_in_flight, mdata.flow_hash);
    add_to_field(mdata.bytes_in_flight, tcp_ipv4_metadata.segLength);
    register_write(bytes_in_flight, mdata.flow_hash, mdata.bytes_in_flight);
}

action do_compute_pkts_in_flight_dec () {
    register_read(mdata.pkts_in_flight, pkts_in_flight, mdata.flow_hash);
    subtract_from_field(mdata.pkts_in_flight, 1);
    register_write(pkts_in_flight, mdata.flow_hash, mdata.pkts_in_flight);
}


/****End of Egress Actions ***/

table compute_ooo_test {
    reads {
        tcp.ack : exact;
    }
    actions {
        do_test_ooo;
    }
}

table compute_flowhash {
    actions {
        do_compute_flowhash;
    }
}

table forward {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        do_forward;
        _drop;
    }
}

table compute_bytesMisordered {
    actions {
        do_compute_bytesMisordered;
    }
}

table compute_packetsMisordered {
    actions {
        do_compute_packetsMisordered;
    }
}

table compute_bytesAcked {
    reads {
        tcp.ack : exact;
    }
    actions {
        do_compute_bytesAcked;
        nop;
    }
}

table compute_packetsAcked {
    reads {
        tcp.ack : exact;
    }
    actions {
        do_compute_packetsAcked;
        nop;
    }
}

table compute_ecnBytes {
    reads {
        tcp.syn : exact;
        tcp.ecn : exact;
    }
    actions {
        do_compute_ecnBytes;
        nop;
    }
}

table compute_ecnPackets {
    reads {
        tcp.syn : exact;
        tcp.ecn : exact;
    }
    actions {
        do_compute_ecnPackets;
        nop;
    }
}

table compute_flow_timeout_1 {
    reads {
        tcp.ack : exact;
        tcp.fin : exact;
    }
    actions {
        do_compute_flow_timeout_1;
        nop;
    }
}

table compute_flow_timeout_2 {
    reads {
        tcp.ack : exact;
        tcp.fin : exact;
    }
    actions {
        do_compute_flow_timeout_2;
        nop;
    }
}

table write_seqNo {
    actions {
        do_write_seqNo;
    }
}

table is_timeout_1 {
    reads {
        mdata.timeout : exact;
        tcp.ackNo : exact;
        tcp.fin : exact;
    }
    actions {
        do_is_timeout;
        nop;
    }
}

table is_timeout_2 {
    actions {
        do_is_timeout;
    }
}


table get_prev_tstamp {
    actions {
        do_get_prev_tstamp;
    }
}

table store_current_tstamp {
    actions {
        do_store_current_tstamp;
    }
}

table write_current_time {
    actions {
        do_write_current_time;
    }
}

table compute_outgoing_rate {
    actions {
        do_compute_outgoing_rate;
    }
}

table compute_pkts_in_flight_inc {
    actions {
        do_compute_pkts_in_flight_inc;
    }
}

table compute_bytes_in_flight_inc {
    actions {
        do_compute_bytes_in_flight_inc;
    }
}

table compute_pkts_in_flight_dec {
    actions {
        do_compute_pkts_in_flight_dec;
    }
}
control ingress {
    if (valid(tcp)) {
        apply(compute_flowhash);

        // Ack-based Scopes
        apply(compute_ooo_test);
        if (mdata.ooo_test != 0) {
            apply(compute_bytesMisordered);
            apply(compute_packetsMisordered);
        } else {
            apply(compute_bytesAcked);
            apply(compute_packetsAcked);
        }
        apply(compute_ecnBytes);
        apply(compute_ecnPackets);

        // Flow-based Scopes
        // 1) Flow Timeout or retransmission
        apply(compute_flow_timeout_1);
        apply(is_timeout_1);
        if (mdata.timeout != 0) {
            apply(write_seqNo);
            // apply(compute_flow_timeout_2);
            // if (mdata.timeout == 0) {
            //     apply(write_seqNo);
            // } else {
            //     // timeout occured
            //     //apply(is_timeout_2);
            // }write_seqNo
        }
        apply(get_prev_tstamp);
        apply(compute_outgoing_rate);
        apply(store_current_tstamp);

        if (tcp.ackNo == 1) {
            apply(compute_pkts_in_flight_inc);
            //apply(compute_bytes_in_flight_inc);
        }
        //  else {
        //     apply(compute_pkts_in_flight_dec);
        // }
    }
    apply(forward);
}

control egress {

}
