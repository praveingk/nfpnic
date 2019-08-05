/*
This code implements virtualization by adding an encapsulation header
*/
#include "includes/headers.p4"
#include "includes/parser.p4"

#define YES 1
#define NO 0

action do_forward(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}

action nop () {

}

action _drop () {
    drop();
}

action do_encap () {
    modify_field(ipv4.protocol, GRE_PROTO);
    add_header(gre);
    add_header(inner_ipv4);
    modify_field(gre.protocol, ETHERTYPE_IPV4);
    modify_field(inner_ipv4.version, ipv4.version);
    modify_field(inner_ipv4.ihl, ipv4.ihl);
    modify_field(inner_ipv4.diffserv, ipv4.diffserv);
    modify_field(inner_ipv4.totalLen, ipv4.totalLen);
    modify_field(inner_ipv4.identification, ipv4.identification);
    modify_field(inner_ipv4.flags, ipv4.flags);
    modify_field(inner_ipv4.fragOffset, ipv4.fragOffset);
    modify_field(inner_ipv4.ttl, ipv4.ttl);
    modify_field(inner_ipv4.protocol, ipv4.protocol);
    modify_field(inner_ipv4.hdrChecksum, ipv4.hdrChecksum);
    modify_field(inner_ipv4.srcAddr, 0x01010101);
    modify_field(inner_ipv4.dstAddr, 0x02020202);
}
/****End of Egress Actions ***/

table forward {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        do_forward;
        _drop;
    }
}

table encap {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        do_encap;
        nop;
    }
}


control ingress {
    apply(encap);
    apply(forward);
}

control egress {

}
