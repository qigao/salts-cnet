#ifndef CNET_KCP_SECURE_INTERNAL_H
#define CNET_KCP_SECURE_INTERNAL_H

#include <cnet/export.h>

#include <cnet/cnet.h>

enum {
  CNET_KCP_SECURE_HANDSHAKE_BYTES = 64,
  CNET_KCP_SECURE_KEY_BYTES = 32
};

typedef struct cnet_kcp_secure_state {
  uint8_t psk[CNET_KCP_PSK_BYTES];
  uint8_t client_nonce[16];
  uint8_t server_nonce[16];
  uint8_t send_key[CNET_KCP_SECURE_KEY_BYTES];
  uint8_t receive_key[CNET_KCP_SECURE_KEY_BYTES];
  uint8_t fec_key[CNET_KCP_SECURE_KEY_BYTES];
  uint64_t session_epoch;
  uint64_t send_packet_number;
  uint64_t receive_highest;
  uint64_t receive_bitmap;
  cnet_secure_kcp_role role;
  bool hello_started;
  bool established;
} cnet_kcp_secure_state;

SALTS_CNET_EXPORT
int cnet_kcp_secure_state_init(cnet_kcp_secure_state *state, cnet_secure_kcp_role role,
                               const uint8_t psk[CNET_KCP_PSK_BYTES]);
SALTS_CNET_EXPORT
void cnet_kcp_secure_state_wipe(cnet_kcp_secure_state *state);
SALTS_CNET_EXPORT
bool cnet_kcp_secure_is_handshake(const void *data, size_t size);
SALTS_CNET_EXPORT
int cnet_kcp_secure_client_hello_authenticate(const cnet_kcp_security_config *config,
                                              const void *data, size_t size);
SALTS_CNET_EXPORT
int cnet_kcp_secure_build_client_hello(cnet_kcp_secure_state *state,
                                       uint8_t output[CNET_KCP_SECURE_HANDSHAKE_BYTES]);
SALTS_CNET_EXPORT
int cnet_kcp_secure_accept_client_hello(cnet_kcp_secure_state *state, const void *data,
                                        size_t size,
                                        uint8_t output[CNET_KCP_SECURE_HANDSHAKE_BYTES]);
SALTS_CNET_EXPORT
int cnet_kcp_secure_accept_server_hello(cnet_kcp_secure_state *state, const void *data,
                                        size_t size);
SALTS_CNET_EXPORT
int cnet_kcp_secure_seal(cnet_kcp_secure_state *state, const void *plain, size_t plain_size,
                         void *output, size_t output_capacity, size_t *output_size);
SALTS_CNET_EXPORT
int cnet_kcp_secure_open(cnet_kcp_secure_state *state, const void *record, size_t record_size,
                         void *output, size_t output_capacity, size_t *output_size);

#endif /* CNET_KCP_SECURE_INTERNAL_H */
