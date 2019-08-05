#include <pif_plugin.h>
#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>
#include <stdlib.h>

__declspec(shared scope(global) export imem) uint64_t counters;
__declspec(shared scope(global) export imem) uint64_t avg_pktlen;

int pif_plugin_my_asm (EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data) {
  PIF_PLUGIN_tcp_T *tcp;
  PIF_PLUGIN_ipv4_T *ipv4;
  uint16_t pktlen;
  unsigned int len;
  unsigned int addr_hi, addr_lo;
  unsigned int pl_addr_hi, pl_addr_lo;

  __declspec(read_write_reg)	int	xfer;
  __declspec(read_write_reg)	int	dest_xfer;
  __declspec(read_write_reg)	int	read_xfer;


  int coeff = 10;
  if (! pif_plugin_hdr_ipv4_present(headers)) {
    return PIF_PLUGIN_RETURN_FORWARD;
  }
  if (! pif_plugin_hdr_tcp_present(headers)) {
    return PIF_PLUGIN_RETURN_FORWARD;
  }
  ipv4 = pif_plugin_hdr_get_ipv4(headers);

  //mem_incr64(&counters);
  //alu[counter, counter, +, 1]
  addr_hi	=	((unsigned long long int)&counters	>>	8)	&	0xff000000;
	addr_lo	=	(unsigned	long long	int)&counters	&	0xffffffff;

  pl_addr_hi	=	((unsigned long long int)&avg_pktlen	>>	8)	&	0xff000000;
	pl_addr_lo	=	(unsigned	long long	int)&avg_pktlen	&	0xffffffff;

  len = ipv4->totalLen;
  xfer = len;
  __asm {
    mem[incr64, --, addr_hi, <<8, addr_lo, 1];
    mem[atomic_read, read_xfer, pl_addr_hi, <<8, pl_addr_lo, 1];
    alu[dest_xfer, read_xfer, +, len];//read_xfer];
    mem[atomic_write, dest_xfer, pl_addr_hi, <<8, pl_addr_lo, 1];
    // mul_step[multiplicand,multiplier], 32x32_start
    // mul_step[multiplicand,multiplier], 32x32_step1
    // mul_step[multiplicand,multiplier], 32x32_step2
    // mul_step[multiplicand,multiplier], 32x32_step3
    // mul_step[multiplicand,multiplier], 32x32_step4
    // mul_step[dest,--], 32x32_last
  }
  return PIF_PLUGIN_RETURN_FORWARD;
}
