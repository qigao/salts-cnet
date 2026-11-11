#ifndef CNET_DATAGRAM_INTERNAL_H
#define CNET_DATAGRAM_INTERNAL_H

#include <cnet/cnet.h>

/* KCP owns retransmission when its shared UDP socket receives an ICMP port
 * error. The native receive demand stays armed for all other sessions. */
int cnet_datagram_init_kcp(cnet_datagram *datagram, const cnet_datagram_config *config,
                           native_io_backend *backend);

#endif
