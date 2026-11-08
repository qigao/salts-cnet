#ifndef CRYPTO_DTLS_EXCHANGE_INTERNAL_H
#define CRYPTO_DTLS_EXCHANGE_INTERNAL_H
#include <crypto/status.h>
#include <gmssl/secp256r1_key.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { CRYPTO_DTLS_P256_PUBLIC_BYTES=65, CRYPTO_DTLS_P256_SHARED_BYTES=32,
       CRYPTO_DTLS_EXCHANGE_MAX_SIGNATURE=512 };
typedef struct crypto_dtls_ephemeral {
  SECP256R1_KEY key;
  bool ready, consumed, failed;
} crypto_dtls_ephemeral;

/* Private, exclusive one-handshake owner; never clone a live ephemeral.
 * Zero/cleared init. Public export copies, never borrows native key state.
 * The owner saves public flight bytes before exchange consumes the key. */
int crypto_dtls_ephemeral_init(crypto_dtls_ephemeral *state);
int crypto_dtls_ephemeral_public(const crypto_dtls_ephemeral *state,uint8_t out[65]);
/* Exactly one uncompressed on-curve canonical P256 point. After admission,
 * success or failure erases the private scalar and is terminal for this key.
 * Shared output is cleared on failure; all inputs/output/state are disjoint.
 * Alias/invalid argument rejection changes nothing. No pointer is retained. */
int crypto_dtls_ephemeral_exchange(crypto_dtls_ephemeral *state,const void *peer,size_t size,uint8_t out[32]);
void crypto_dtls_ephemeral_clear(crypto_dtls_ephemeral *state);

/* This verifies a proof using an ALREADY TRUST-ADMITTED leaf, not the leaf's
 * chain/expiry/purpose/hostname/revocation. The handshake owner must perform those
 * checks and admit the offered cipher/signature before calling this helper.
 * Finite private profile: P256, ECDHE_ECDSA/AES128GCM/SHA256 with ECDSA-SHA256,
 * or ECDHE_RSA/AES128GCM/SHA256 with RSA-PKCS1-SHA256, no scheme fallback.
 * Input is the complete ServerKeyExchange BODY, no TLS record/header shim.
 * Proof binds client_random || server_random || exact encoded EC parameters.
 * Only successful proof publishes peer octets; other admitted results erase
 * output. Certificate/body <=16KiB, signature <=512, no retained borrowing. */
int crypto_dtls_server_exchange_verify(const void *trusted_leaf,size_t leaf_size,uint16_t cipher,
    const uint8_t client_random[32],const uint8_t server_random[32],
    const void *body,size_t body_size,uint8_t peer[65]);
#endif
