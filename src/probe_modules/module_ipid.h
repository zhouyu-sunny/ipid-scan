//
// Created by ubuntu on 17-6-3.
//

#ifndef ZMAP_MODULE_IPID_H
#define ZMAP_MODULE_IPID_H


#include "../../lib/includes.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"



static fielddef_t fields[] = {
        {.name="type", .type="int", .desc="icmp message type"},
        {.name="code", .type="int", .desc="icmp message sub type code"},
        {.name="icmp-id", .type="int", .desc="icmp id number"},
        {.name="seq", .type="int", .desc="icmp sequence number"},
        {.name="classification", .type="string", .desc="probe module classification"},
        {.name="success", .type="bool", .desc="did probe module classify response as success"}
};


probe_module_t module_ipid = {
        .name = "ipid_scan",
        .packet_length = 62,
        .pcap_filter = "icmp and icmp[0]!=8",
        .pcap_snaplen = 96,
        .port_args = 0,
        .thread_initialize = &icmp_echo_init_perthread,
        .make_packet = &icmp_echo_make_packet,
        .print_packet = &icmp_echo_print_packet,
        .process_packet = &icmp_echo_process_packet,
        .validate_packet = &icmp_validate_packet,
        .close = NULL,
        .output_type = OUTPUT_TYPE_STATIC,
        .fields = fields,
        .numfields = 6
};



#endif //ZMAP_MODULE_IPID_H
