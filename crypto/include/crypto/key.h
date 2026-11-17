#ifndef CRYPTO_KEY_H_INCLUDED
#define CRYPTO_KEY_H_INCLUDED

#include <crypto/symmetric.h>
#include <crypto/ecdsa.h>
#include <crypto/ed25519.h>
#include <crypto/ed448.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct salts_crypto_key salts_crypto_key;
typedef struct salts_crypto_bytes { const uint8_t *data; size_t size; } salts_crypto_bytes;
typedef enum salts_crypto_key_kind {
  SALTS_CRYPTO_KEY_RSA = 1, SALTS_CRYPTO_KEY_EC,
  SALTS_CRYPTO_KEY_ED25519, SALTS_CRYPTO_KEY_ED448
} salts_crypto_key_kind;
typedef enum salts_crypto_signature {
  SALTS_CRYPTO_RSA_PKCS1 = 1, SALTS_CRYPTO_RSA_PSS,
  SALTS_CRYPTO_ECDSA, SALTS_CRYPTO_EDDSA
} salts_crypto_signature;

/** Imports copy all input bytes. On success *output is an immutable owned key;
 * on failure it is NULL (EINVAL, ENOMEM, ERANDOM or ECRYPTO). The caller destroys
 * it after all synchronous/concurrent readers return. Destruction wipes secrets.
 * RSA accepts n/e and optional d; CRT values, if complete, are consistency-checked.
 * EC public input is SEC1 compressed/uncompressed, private input a scalar.
 * EdDSA private input is a seed. Supplied public/private components must agree.
 * PEM supports SPKI public keys, PKCS8 and traditional RSA/EC private keys.
 * No passphrase callback or encrypted-key import is provided.
 * Example: salts_crypto_key_from_pem(pem, length, 1, &key); ...;
 *          salts_crypto_key_destroy(key);
 */
int salts_crypto_key_from_rsa(salts_crypto_bytes n, salts_crypto_bytes e, salts_crypto_bytes d,
    salts_crypto_bytes p, salts_crypto_bytes q, salts_crypto_bytes dp,
    salts_crypto_bytes dq, salts_crypto_bytes qi, salts_crypto_key **output);
int salts_crypto_key_from_ec(salts_crypto_ec_curve curve, salts_crypto_bytes public_key,
    salts_crypto_bytes private_key, salts_crypto_key **output);
int salts_crypto_key_from_ed(salts_crypto_key_kind kind, salts_crypto_bytes public_key,
    salts_crypto_bytes private_key, salts_crypto_key **output);
int salts_crypto_key_from_pem(const void *pem, size_t size, int private_key, salts_crypto_key **output);
void salts_crypto_key_destroy(salts_crypto_key *key);
salts_crypto_key_kind salts_crypto_key_type(const salts_crypto_key *key);
size_t salts_crypto_key_signature_size(const salts_crypto_key *key);
/** Message signatures, caller-owned output. Capacity is at least signature_size.
 * PSS signing uses digest-length salt; verification accepts any encoded salt.
 * RSA hashes SHA256/384/512; ECDSA uses the selected hash with the imported curve.
 * EdDSA ignores hash. Failure leaves *size zero; invalid signatures return EVERIFY.
 */
int salts_crypto_key_sign(const salts_crypto_key *key, salts_crypto_signature scheme,
    salts_crypto_hash hash, const void *message, size_t message_size,
    uint8_t *signature, size_t capacity, size_t *size);
int salts_crypto_key_verify(const salts_crypto_key *key, salts_crypto_signature scheme,
    salts_crypto_hash hash, const void *message, size_t message_size,
    const uint8_t *signature, size_t size);
/** RSA OAEP with empty label, MGF1 uses hash. Caller owns disjoint input/output
 * and output_size. Decrypt exposes no plaintext on failure (EVERIFY); key/size
 * errors return EINVAL. Encrypt output needs key_signature_size bytes.
 */
int salts_crypto_key_oaep_encrypt(const salts_crypto_key *key, salts_crypto_hash hash,
    const uint8_t *input, size_t size, uint8_t *output, size_t capacity, size_t *output_size);
int salts_crypto_key_oaep_decrypt(const salts_crypto_key *key, salts_crypto_hash hash,
    const uint8_t *input, size_t size, uint8_t *output, size_t capacity, size_t *output_size);

#ifdef __cplusplus
}
#endif

#endif
