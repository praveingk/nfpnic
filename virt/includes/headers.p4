/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Template headers.p4 file for basic_switching
// Edit this file as needed for your P4 program

// Here's an ethernet header to get started.

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}


field_list ipv4_field_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_chksum_calc {
    input {
        ipv4_field_list;
    }
    algorithm : csum16;
    output_width: 16;
}

calculated_field ipv4.hdrChecksum {
    update ipv4_chksum_calc;
}

header_type gre_t {
    fields {
        checksum : 1;
        _pad_ : 1;
        key : 1;
        sequence : 1;
        reserved : 8;
        version : 4;
        protocol : 16;
    }
}

header_type tcp_t {
    fields {
        srcPort     : 16;
        dstPort     : 16;
        seqNo       : 32;
        ackNo       : 32;
        dataOffset  : 4;
        res         : 3;
        ns          : 1;
        cwr         : 1;
        ecn         : 1;
        urg         : 1;
        ack         : 1;
        psh         : 1;
        rst         : 1;
        syn         : 1;
        fin         : 1;
        window      : 16;
        checksum    : 16;
        urgentPtr   : 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        len : 16;
        checksum : 16;
    }
}

header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t ucp;
header gre_t gre;
header ipv4_t inner_ipv4;
header_type local_metadata_t {
    fields {
        flow_hash : 16;
        packetsAcked : 32;
        bytesAcked : 32;
        packetsMisordered : 32;
        bytesMisordered : 32;
        ooo_tester  : 32;
        ooo_test : 32(signed);
        ooo : 32;
        ecnBytes : 32;
        ecnPackets : 32;
        flow_timeout : 32;
        timeout : 32;
        tstamp : 32;
        outgoing_pkt_rate : 32;
        outgoing_bit_rate : 32;
        prev_tstamp : 32;
        pkts_in_flight : 32;
        bytes_in_flight : 32;
    }
}
metadata local_metadata_t mdata;

header_type tcp_ipv4_metadata_t {
    fields {
        scratch : 16;
        tcpLength : 16;
        segLength : 16;
    }
}

header_type intrinsic_metadata_t {
	fields {
		ingress_global_tstamp : 32;
	}
}
metadata tcp_ipv4_metadata_t tcp_ipv4_metadata;
metadata intrinsic_metadata_t intrinsic_metadata;
