#include <pif_plugin.h>
#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>

// A static search string
static __lmem uint8_t searchstring[] = {'h', 'e', 'l', 'l', 'o'};

volatile __export __mem uint32_t searchstring_detections = 0;

/* Payload chunk size in LW (32-bit) and bytes */
#define CHUNK_LW 8
#define CHUNK_B ((CHUNK_LW)*4)

volatile __export __mem uint32_t pif_mu_len = 0;

int pif_plugin_payload_scan (EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data) {
  PIF_PLUGIN_ipv4_T *ipv4;
  __mem uint8_t *payload;
  __xread uint32_t pl_data[CHUNK_LW];
  __lmem uint32_t pl_mem[CHUNK_LW];
  int i, count, to_read;
  uint32_t mu_len, ctm_len;
  int searchstring_progress = 0;
  uint32_t matches;
  matches = pif_plugin_meta_get__mdata__matches(headers);

  /* figure out how much data is in external memory vs ctm */
  if (pif_pkt_info_global.split) { /* payload split to MU */
    uint32_t sop; /* start of packet offset */
    sop = PIF_PKT_SOP(pif_pkt_info_global.pkt_buf, pif_pkt_info_global.pkt_num);
    mu_len = pif_pkt_info_global.pkt_len - (256 << pif_pkt_info_global.ctm_size) + sop;
  } else {/* no data in MU */
    mu_len = 0;
  }
  pif_mu_len = mu_len;
  count = pif_pkt_info_global.pkt_len - pif_pkt_info_global.pkt_pl_off - mu_len;
  /* Get a pointer to the ctm portion */
  payload = pif_pkt_info_global.pkt_buf;
  /* point to just beyond the parsed headers */
  payload += pif_pkt_info_global.pkt_pl_off;

  while (count) {
    /* grab a maximum of chunk */
    to_read = count > CHUNK_B ? CHUNK_B : count;
    mem_read8(&pl_data, payload, to_read);
    /* copy from transfer registers into local memory
     * we can iterate over local memory, where transfer
     * registers we cant
     */
    for (i = 0; i < CHUNK_LW; i++)
        pl_mem[i] = pl_data[i];
        /* iterate over all the bytes and do the search */
        for (i = 0; i < to_read; i++) {
            uint8_t val = pl_mem[i/4] >> (8 * (3 - (i % 4)));

            if (val == searchstring[searchstring_progress])
                searchstring_progress += 1;
            else
                searchstring_progress = 0;

            if (searchstring_progress >= sizeof(searchstring)) {
                mem_incr32((__mem uint32_t *)&searchstring_detections);
                /* drop if found */
                matches++;
                pif_plugin_meta_set__mdata__matches(headers, matches);
                return PIF_PLUGIN_RETURN_FORWARD;
            }
        }

        payload += to_read;
        count -= to_read;
  }


  /* same as above, but for mu. Code duplicated as a manual unroll */
  if (mu_len) {
      payload = (__addr40 void *)((uint64_t)pif_pkt_info_global.muptr << 11);
      /* skip over the ctm part */
      payload += 256 << pif_pkt_info_global.ctm_size;

      count = mu_len;
      while (count) {
          /* grab a maximum of chunk */
          to_read = count > CHUNK_B ? CHUNK_B : count;

          /* grab a chunk of memory into transfer registers */
          mem_read8(&pl_data, payload, to_read);

         /* copy from transfer registers into local memory
          * we can iterate over local memory, where transfer
          * registers we cant
          */
          for (i = 0; i < CHUNK_LW; i++)
              pl_mem[i] = pl_data[i];

          /* iterate over all the bytes and do the search */
          for (i = 0; i < to_read; i++) {
              uint8_t val = pl_mem[i/4] >> (8 * (3 - (i % 4)));

              if (val == searchstring[searchstring_progress])
                  searchstring_progress += 1;
              else
                  searchstring_progress = 0;

              if (searchstring_progress >= sizeof(searchstring)) {
                  mem_incr32((__mem uint32_t *)&searchstring_detections);
                  matches++;
                  pif_plugin_meta_set__mdata__matches(headers, matches);
                  return PIF_PLUGIN_RETURN_FORWARD;
              }
          }

          payload += to_read;
          count -= to_read;
      }
  }

  return PIF_PLUGIN_RETURN_FORWARD;
}
