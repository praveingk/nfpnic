#include <pif_plugin.h>
#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>


int pif_plugin_do_get_current_time (EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data) {
  uint64_t ctime;

  ctime = me_tsc_read();

  pif_plugin_meta_set__mdata__tstamp(headers, (uint32_t) (ctime & 0xffffffff));
  //pif_plugin_meta_set__mdata__tstamp__1(hea (ders, ctime & 0xffffffff00000000);

  return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_calc_outgoing_rate (EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data) {
  PIF_PLUGIN_ipv4_T *ipv4;
  uint32_t cur_pkt_tstamp;
  uint32_t prev_pkt_tstamp;
  uint32_t inter_pkt_gap;
  uint32_t outgoing_pkt_rate;
  uint32_t outgoing_bit_rate;
  ipv4 = pif_plugin_hdr_get_ipv4(headers);

  prev_pkt_tstamp = pif_plugin_meta_get__mdata__prev_tstamp(headers);
  cur_pkt_tstamp = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp(headers);

  inter_pkt_gap = cur_pkt_tstamp - prev_pkt_tstamp;

  outgoing_pkt_rate = pif_plugin_meta_get__mdata__outgoing_pkt_rate(headers);
  outgoing_bit_rate = pif_plugin_meta_get__mdata__outgoing_bit_rate(headers);

  outgoing_pkt_rate = (outgoing_pkt_rate + 1000000000/inter_pkt_gap) >> 1;


  outgoing_bit_rate = (outgoing_bit_rate + ((ipv4->totalLen<<3) * 1000000000)/ inter_pkt_gap ) >> 1;
  pif_plugin_meta_set__mdata__outgoing_pkt_rate(headers, outgoing_pkt_rate);
  pif_plugin_meta_set__mdata__outgoing_bit_rate(headers, outgoing_bit_rate);

  return PIF_PLUGIN_RETURN_FORWARD;
}
