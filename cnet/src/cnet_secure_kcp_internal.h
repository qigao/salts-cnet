#ifndef CNET_SECURE_KCP_INTERNAL_H
#define CNET_SECURE_KCP_INTERNAL_H

#include <cnet/export.h>

#include <cnet/cnet.h>

#include "cnet_kcp_internal.h"

SALTS_CNET_EXPORT
bool cnet_secure_kcp_transport_config_valid(const cnet_kcp_config *kcp,
                                            const cnet_kcp_security_config *security);
SALTS_CNET_EXPORT
int cnet_secure_kcp_send_validate(const cnet_secure_kcp *session, const void *data, size_t size,
                                  bool marked);
SALTS_CNET_EXPORT
int cnet_secure_kcp_send_marked(cnet_secure_kcp *session, const void *data, size_t size,
                                cnet_kcp_send_marker *out_marker);
SALTS_CNET_EXPORT
bool cnet_secure_kcp_send_marker_complete(const cnet_secure_kcp *session,
                                          cnet_kcp_send_marker marker);
SALTS_CNET_EXPORT
int cnet_secure_kcp_input_classified(cnet_secure_kcp *session, const void *data, size_t size,
                                     bool *out_authenticated);

#endif /* CNET_SECURE_KCP_INTERNAL_H */
