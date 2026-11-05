#ifndef SALTS_CRYPTO_SM2_EXCHANGE_H
#define SALTS_CRYPTO_SM2_EXCHANGE_H
#include <crypto/sm2.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM2_EXCHANGE_CONTEXT_SIZE 1536u
#define SALTS_CRYPTO_SM2_EXCHANGE_KEY_MAX_SIZE 1024u

/* GB/T 32918.3 key agreement on curveSM2 (cofactor 1), with mandatory mutual
 * confirmation. This is not ordinary ECDH. Private scalar: 32-byte big-endian
 * [1,N-1]; public keys/shares: canonical uncompressed 65-byte points.
 * The caller must authenticate the peer's static public key and identity before
 * starting. This API does not validate certificates or establish a trust root.
 * Identity lengths 1..8191, key length 1..1024; no implicit default identity.
 * Both parties agree identities in initiator/responder order, key length and
 * profile. The standard confirmation transcript does not encode key length;
 * agree that parameter in the enclosing authenticated protocol.
 *
 * A: start -> send RA -> receive RB,SB -> finish_initiator -> send SA.
 * B: receive RA -> respond -> send RB,SB -> receive SA -> finish_responder.
 * Each party obtains a key only after verifying the other's confirmation.
 * SA delivery/application success requires the enclosing protocol's own ack.
 *
 * Single owner/thread; zero-initialize context, never copy live state. No heap,
 * I/O or borrowed pointers. Identities are consumed into Z values at admission.
 * start/respond erase and replace previous state. clear cancels an exchange.
 * Admitted protocol/state failures and both finishes erase all context state.
 * An all-zero derived key fails; restart with fresh shares after failure.
 *
 * All outputs (context, shares, confirmation, key, written) must be disjoint
 * from each other and inputs. Invalid pointer/size/capacity/overlap leaves
 * outputs/state unchanged. finish requires capacity >= 1024; success sets
 * written to requested key size, failure erases 1024 bytes and sets written=0.
 * Native/provider errors also erase admitted outputs. Caller owns framing,
 * retransmission, generation routing, timeout/cancellation and key erasure. */
typedef union salts_crypto_sm2_exchange_ctx {
  uint64_t integer_alignment;
  long double floating_alignment;
  void *pointer_alignment;
  uint8_t bytes[SALTS_CRYPTO_SM2_EXCHANGE_CONTEXT_SIZE];
} salts_crypto_sm2_exchange_ctx;

int salts_crypto_sm2_exchange_start(salts_crypto_sm2_exchange_ctx *ctx,
    const uint8_t private_key[32], const uint8_t peer_public[65],
    const void *initiator_id, size_t initiator_id_size,
    const void *responder_id, size_t responder_id_size,
    size_t key_size, uint8_t share_a[65]);
int salts_crypto_sm2_exchange_respond(salts_crypto_sm2_exchange_ctx *ctx,
    const uint8_t private_key[32], const uint8_t peer_public[65],
    const void *initiator_id, size_t initiator_id_size,
    const void *responder_id, size_t responder_id_size,
    size_t key_size, const uint8_t share_a[65], uint8_t share_b[65], uint8_t confirm_b[32]);
int salts_crypto_sm2_exchange_finish_initiator(salts_crypto_sm2_exchange_ctx *ctx,
    const uint8_t share_b[65], const uint8_t confirm_b[32], uint8_t confirm_a[32],
    void *secret, size_t capacity, size_t *written);
int salts_crypto_sm2_exchange_finish_responder(salts_crypto_sm2_exchange_ctx *ctx,
    const uint8_t confirm_a[32], void *secret, size_t capacity, size_t *written);
void salts_crypto_sm2_exchange_clear(salts_crypto_sm2_exchange_ctx *ctx);

#ifdef __cplusplus
}
#endif
#endif
