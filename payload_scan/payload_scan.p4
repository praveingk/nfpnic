/*
Payload-Scan : This program checks for existance of a string in the payload,
 and drop the packet.

 Noticed that the throughput degraded by 90% (abs value of 760 Mbps)
*/
#include "includes/headers.p4"
#include "includes/parser.p4"

#define MAX_FLOWS 32768
#define MAX_LINKS 512
#define YES 1
#define NO 0

register searchstring_matches {
    width : 32;
    instance_count : 1;
}
primitive_action payload_scan();


action do_scan_payload () {
    register_read(mdata.matches, searchstring_matches, 0);
    payload_scan();
    register_write(searchstring_matches, 0, mdata.matches);
}

action do_forward(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}

action _drop () {
    drop();
}

table scan_payload {
    actions {
        do_scan_payload;
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
    if (valid(tcp)) {
        apply(scan_payload);
    }
    apply(forward);
}

control egress {

}
