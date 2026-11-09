#ifndef CRYPTO_DTLS_RECORD_INTERNAL_H
#define CRYPTO_DTLS_RECORD_INTERNAL_H
#include <crypto/status.h>
#include <gmssl/aes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Private RFC5288/6347 AES128-GCM record primitive, not a DTLS handshake/API.
 * Exclusive owner, no allocation or borrowed storage retained. Never clone a
 * live sending epoch. Fresh handshake-derived key material owns nonce reuse. */
enum { CRYPTO_DTLS_HEADER_SIZE=13, CRYPTO_DTLS_EXPLICIT_NONCE_SIZE=8,
       CRYPTO_DTLS_TAG_SIZE=16, CRYPTO_DTLS_AEAD_OVERHEAD=CRYPTO_DTLS_EXPLICIT_NONCE_SIZE+CRYPTO_DTLS_TAG_SIZE,
       CRYPTO_DTLS_RECORD_OVERHEAD=CRYPTO_DTLS_HEADER_SIZE+CRYPTO_DTLS_AEAD_OVERHEAD, CRYPTO_DTLS_REPLAY_BITS=64,
       CRYPTO_DTLS_MAX_PLAINTEXT=16384, CRYPTO_DTLS_RECORD_DROP=1 };
#define CRYPTO_DTLS_MAX_SEQUENCE UINT64_C(0x0000ffffffffffff)
typedef struct crypto_dtls_record_epoch {
  AES_KEY key;
  uint8_t salt[4];
  uint16_t epoch;
  uint64_t next_send, highest_received, replay_window;
  bool ready, received, send_failed;
} crypto_dtls_record_epoch;
typedef struct crypto_dtls_record_view {
  const uint8_t *payload;
  size_t payload_size, record_size;
  uint64_t sequence;
  uint16_t epoch;
  uint8_t type;
} crypto_dtls_record_view;

/* Init requires zero/cleared state and nonzero epoch. Inputs never alias state.
 * Reinit a live key is ESTATE. Clear requires no outstanding native use. */
int crypto_dtls_record_init(crypto_dtls_record_epoch *state, uint16_t epoch,
    const uint8_t key[16], const uint8_t salt[4]);
void crypto_dtls_record_clear(crypto_dtls_record_epoch *state);
/* Peek one complete record in a datagram. View is callback-scoped borrowing;
 * record_size permits walking coalesced records without flattening messages. */
int crypto_dtls_record_parse(const void *wire, size_t size, crypto_dtls_record_view *view);
/* Output, size/type storage and state must be disjoint from inputs/each other.
 * Invalid alias leaves everything unchanged. Other admitted errors set size=0.
 * Seal reserves sequence only on success; crypto failure latches ESTATE.
 * Open requires exactly one complete record and commits replay state only on
 * authentication. DROP means replay/wrong epoch; EVERIFY means malformed/tag
 * rejection. Neither may be used as authenticated application input. */
int crypto_dtls_record_seal(crypto_dtls_record_epoch *state, uint8_t type,
    const void *plain, size_t size, void *wire, size_t capacity, size_t *wire_size);
int crypto_dtls_record_open(crypto_dtls_record_epoch *state, const void *wire, size_t size,
    void *plain, size_t capacity, size_t *plain_size, uint8_t *type);
#endif
