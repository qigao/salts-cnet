#ifndef CNET_KCP_INTERNAL_H
#define CNET_KCP_INTERNAL_H

#include <cnet/cnet.h>

typedef struct cnet_kcp_send_marker {
  uint32_t final_sequence;
} cnet_kcp_send_marker;

int cnet_kcp_send_validate(const cnet_kcp *session, const void *data, size_t size,
                           bool marked);
int cnet_kcp_send_marked(cnet_kcp *session, const void *data, size_t size,
                         cnet_kcp_send_marker *out_marker);
bool cnet_kcp_send_marker_complete(const cnet_kcp *session, cnet_kcp_send_marker marker);

#endif /* CNET_KCP_INTERNAL_H */
