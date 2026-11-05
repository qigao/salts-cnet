#ifndef SALTS_CRYPTO_SM9_EXCHANGE_H
#define SALTS_CRYPTO_SM9_EXCHANGE_H
#include <crypto/sm9.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM9_EXCHANGE_ID_MAX_SIZE 255u
#define SALTS_CRYPTO_SM9_EXCHANGE_CONTEXT_SIZE 2048u

/* Exchange extraction uses hid=0x02, distinct from encryption (0x03).
 * Generate a separate master with SALTS_CRYPTO_SM9_EXCHANGE. */
typedef struct salts_crypto_sm9_exchange_key {
  uint8_t private_point[129];
  uint8_t master_public[65];
} salts_crypto_sm9_exchange_key;
int salts_crypto_sm9_exchange_extract(const uint8_t master[32],
    const void *identity, size_t identity_size, salts_crypto_sm9_exchange_key *key);
void salts_crypto_sm9_exchange_key_clear(salts_crypto_sm9_exchange_key *key);

/* Single-owner, caller-allocated state: no heap, borrowed pointers, I/O, timers
 * or concurrent calls. Zero-initialize before use; never copy a live context.
 * start/respond replace and erase any prior state. clear aborts an exchange.
 * Identity lengths are 1..255; session key length is 1..1024. Both parties use
 * the same master public key, identities in initiator/responder order, and key
 * length. Authentication binds identities and shares; agree the key length and
 * application profile in the enclosing authenticated protocol.
 *
 * A: start -> send RA -> receive RB,SB -> finish_initiator -> send SA.
 * B: receive RA -> respond -> send RB,SB -> receive SA -> finish_responder.
 * No session key is returned before that party verifies peer confirmation.
 * Confirmation does not prove delivery of SA or application-level success.
 *
 * All output ranges (including context and written) must be disjoint from each
 * other and inputs. Invalid pointers/lengths/capacities/overlap leave everything
 * unchanged. Admitted protocol/state failures erase context and outputs.
 * finish requires capacity >= 1024; success writes requested key length and
 * written, failure erases 1024 bytes and sets written=0. Both finish paths erase
 * context, including on wrong phase or bad confirmation. Restart with fresh
 * shares after failure; clear unused contexts at cancellation/deadline. */
typedef union salts_crypto_sm9_exchange_ctx {
  uint64_t integer_alignment;
  long double floating_alignment;
  void *pointer_alignment;
  uint8_t bytes[SALTS_CRYPTO_SM9_EXCHANGE_CONTEXT_SIZE];
} salts_crypto_sm9_exchange_ctx;

int salts_crypto_sm9_exchange_start(salts_crypto_sm9_exchange_ctx *ctx,
    const salts_crypto_sm9_exchange_key *key,
    const void *initiator_id, size_t initiator_id_size,
    const void *responder_id, size_t responder_id_size,
    size_t key_size, uint8_t share_a[65]);
int salts_crypto_sm9_exchange_respond(salts_crypto_sm9_exchange_ctx *ctx,
    const salts_crypto_sm9_exchange_key *key,
    const void *initiator_id, size_t initiator_id_size,
    const void *responder_id, size_t responder_id_size,
    size_t key_size, const uint8_t share_a[65], uint8_t share_b[65], uint8_t confirm_b[32]);
int salts_crypto_sm9_exchange_finish_initiator(salts_crypto_sm9_exchange_ctx *ctx,
    const uint8_t share_b[65], const uint8_t confirm_b[32], uint8_t confirm_a[32],
    void *secret, size_t capacity, size_t *written);
int salts_crypto_sm9_exchange_finish_responder(salts_crypto_sm9_exchange_ctx *ctx,
    const uint8_t confirm_a[32], void *secret, size_t capacity, size_t *written);
void salts_crypto_sm9_exchange_clear(salts_crypto_sm9_exchange_ctx *ctx);

#ifdef __cplusplus
}
#endif
#endif
