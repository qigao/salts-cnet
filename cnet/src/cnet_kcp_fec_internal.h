#ifndef CNET_KCP_FEC_INTERNAL_H
#define CNET_KCP_FEC_INTERNAL_H

#include <cnet/export.h>

#include <cnet/cnet.h>

enum {
  CNET_KCP_FEC_DATA_LENGTH_BYTES = 2,
  CNET_KCP_FEC_HEADER_BYTES = 30,
  CNET_KCP_FEC_MAC_BYTES = 16,
  CNET_KCP_FEC_MAX_WIRE_OVERHEAD_BYTES =
      CNET_KCP_FEC_HEADER_BYTES + CNET_KCP_FEC_DATA_LENGTH_BYTES + CNET_KCP_FEC_MAC_BYTES
};

typedef struct cnet_kcp_fec_state cnet_kcp_fec_state;
typedef int (*cnet_kcp_fec_output_fn)(void *user, const void *data, size_t size);
typedef int (*cnet_kcp_fec_deliver_fn)(void *user, const void *data, size_t size);

SALTS_CNET_EXPORT
int cnet_kcp_fec_config_validate(const cnet_kcp_fec_config *config);
SALTS_CNET_EXPORT
int cnet_kcp_fec_init(const cnet_kcp_fec_config *config, cnet_kcp_fec_output_fn output,
                      void *output_user, cnet_kcp_fec_state **out_state);
SALTS_CNET_EXPORT
int cnet_kcp_fec_set_session(cnet_kcp_fec_state *state, uint64_t session_epoch,
                             const uint8_t key[CNET_KCP_PSK_BYTES]);
SALTS_CNET_EXPORT
int cnet_kcp_fec_send(cnet_kcp_fec_state *state, const void *data, size_t size);
SALTS_CNET_EXPORT
int cnet_kcp_fec_input(cnet_kcp_fec_state *state, const void *data, size_t size,
                       cnet_kcp_fec_deliver_fn deliver, void *deliver_user);
SALTS_CNET_EXPORT
void cnet_kcp_fec_destroy(cnet_kcp_fec_state *state);

#endif /* CNET_KCP_FEC_INTERNAL_H */
