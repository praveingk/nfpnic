/*
 * Copyright 2015-2016 Netronome, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define ETHERTYPE_IPV4 0x0800
#define TCP_PROTO 0x06
#define UDP_PROTO 0x11
header_type ethernet_t {
  fields {
    dst : 48;
    src : 48;
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


header_type tcp_t {
    fields {
        srcPort     : 16;
        dstPort     : 16;
        seqNo       : 32;
        ackNo       : 32;
        dataOffset  : 4;
        res         : 4;
        flags       : 8;
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

header_type local_metadata_t {
    fields {
        c : 32;
    }
}


header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t ucp;
metadata local_metadata_t mdata;
//IPv4 Checksum
field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    16'0;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}
// /IPv4 Checksum

parser start {
  return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(ethernet.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select (ipv4.protocol) {
        TCP_PROTO : parse_tcp;
        default : ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    return ingress;
}

register proto_counter {
    width : 32;
    instance_count : 256;
}

primitive_action my_asm();


action drop_act () {
  drop();
}

action do_asm () {
    my_asm();
}

action do_forward(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}

action _drop () {
    drop();
}

table asm {
    actions {
        do_asm;
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

control ingress {
    apply(asm);
    apply(forward);
}
