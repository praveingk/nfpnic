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

// Template parser.p4 file for basic_switching
// Edit this file as needed for your P4 program

// This parses an ethernet header

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_BF_PKTGEN 0x9001
#define ETHERTYPE_COUNTER 0x1234
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_TEST 0x0fff

#define TCP_PROTO 0x06
#define UDP_PROTO 0x11
#define XCP_PROTO 0x07
#define GRE_PROTO 0x2F

parser parse_ethernet {
    extract(ethernet);
    return select(ethernet.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(tcp_ipv4_metadata.scratch, ipv4.ihl);
    return select (ipv4.protocol) {
        TCP_PROTO : parse_tcp;
        GRE_PROTO : parse_gre;
        default : ingress;
    }
}

parser parse_gre {
    extract(gre);
    return select(gre.protocol) {
        ETHERTYPE_IPV4 : parse_ipv4_2;
    }
}

parser parse_ipv4_2 {
    extract(inner_ipv4);
    set_metadata(tcp_ipv4_metadata.scratch, inner_ipv4.ihl);
    return select (inner_ipv4.protocol) {
        TCP_PROTO : parse_tcp;
        default : ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    set_metadata(tcp_ipv4_metadata.tcpLength, ipv4.totalLen - (tcp_ipv4_metadata.scratch << 2));
    set_metadata(tcp_ipv4_metadata.scratch, tcp.dataOffset);
    return ingress;
}

parser parse_tcp_2 {
    extract(tcp);
    set_metadata(tcp_ipv4_metadata.tcpLength, inner_ipv4.totalLen - (tcp_ipv4_metadata.scratch << 2));
    set_metadata(tcp_ipv4_metadata.scratch, tcp.dataOffset);
    return ingress;
}
