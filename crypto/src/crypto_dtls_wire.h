#ifndef CRYPTO_DTLS_WIRE_INTERNAL_H
#define CRYPTO_DTLS_WIRE_INTERNAL_H
#include "crypto_dtls_record.h"
#include <crypto/tls_peer_policy.h>
enum { CRYPTO_DTLS_WIRE_CHAIN_BYTES=4096, CRYPTO_DTLS_WIRE_DNS_BYTES=253 };
int crypto_dtls_dns_name(const char *name,size_t size);
int crypto_dtls_chain_views(const uint8_t *der,size_t size,crypto_tls_stream_peer_certificate_chain *out);
/* Pure framing, not authentication. Allows FEFF only for epoch-zero handshake. */
int crypto_dtls_wire_record(const uint8_t *wire,size_t size,crypto_dtls_record_view *out);
typedef struct crypto_dtls_fatal {
  uint8_t wire[CRYPTO_DTLS_RECORD_OVERHEAD+2]; size_t size;
  int error; uint8_t description,peer_description;
} crypto_dtls_fatal;
/* Exclusive owner, before erasing its write keys. One immutable sealed alert;
 * write_epoch follows ACTUAL successful local CCS send, not key derivation.
 * Sealing failure is recorded, never replaced by a plaintext alert. */
void crypto_dtls_fatal_prepare(crypto_dtls_fatal *,crypto_dtls_record_epoch *,bool write_epoch,
    uint64_t *plain_sequence,uint8_t description);
#endif
