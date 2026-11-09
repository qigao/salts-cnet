#ifndef CRYPTO_DTLS_COOKIE_INTERNAL_H
#define CRYPTO_DTLS_COOKIE_INTERNAL_H
#include <crypto/dtls_stream.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { CRYPTO_DTLS_COOKIE_BYTES=32, CRYPTO_DTLS_COOKIE_TAG_BYTES=24,
       CRYPTO_DTLS_COOKIE_MAX_HELLO=4096,
       CRYPTO_DTLS_COOKIE_MAX_ADDRESS=32, CRYPTO_DTLS_COOKIE_MAX_AGE_MS=60000,
       CRYPTO_DTLS_COOKIE_MAX_EXTENSIONS=32 };
/* Immutable after init; concurrent gates may borrow it. No per-peer state or
 * allocation. Clear requires quiescence; the listener context owns references. */
typedef struct crypto_dtls_cookie_context {
  uint8_t key[32];
  uint32_t lifetime_ms;
  bool ready;
} crypto_dtls_cookie_context;
typedef struct crypto_dtls_cookie_result {
  const uint8_t *client_hello;
  size_t client_hello_size;
  uint64_t record_sequence;
  uint16_t message_sequence;
  bool address_verified;
} crypto_dtls_cookie_result;

int crypto_dtls_cookie_init(crypto_dtls_cookie_context *ctx,uint32_t lifetime_ms);
void crypto_dtls_cookie_clear(crypto_dtls_cookie_context *ctx);
/* Canonical address includes family/IP/port without sockaddr padding. Exactly
 * one unfragmented epoch-zero DTLS1.2 ClientHello is admitted. An invalid/absent
 * cookie issues a stateless HVR, <= input datagram bytes; it allocates nothing.
 * Valid proof sets address_verified and a borrowed original ClientHello view,
 * not certificate/handshake readiness. Header sequencing/transcript admission
 * still belongs to the full handshake owner. Input views expire on reuse.
 * All outputs are disjoint from inputs/context/each other. Alias failure leaves
 * them unchanged; other admitted errors publish no result/reply. A valid MAC
 * with a future issuance timestamp is ESTATE (clock regression), not a retry. */
int crypto_dtls_cookie_gate(const crypto_dtls_cookie_context *ctx,const void *address,size_t address_size,
    const void *datagram,size_t size,uint64_t now,void *reply,size_t capacity,size_t *reply_size,
    crypto_dtls_cookie_result *result);
#endif
