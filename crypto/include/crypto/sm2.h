#ifndef SALTS_CRYPTO_SM2_H
#define SALTS_CRYPTO_SM2_H
#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM2_PRIVATE_KEY_SIZE 32u
#define SALTS_CRYPTO_SM2_PUBLIC_KEY_SIZE 65u
#define SALTS_CRYPTO_SM2_SIGNATURE_SIZE 64u
#define SALTS_CRYPTO_SM2_CIPHERTEXT_MAX_SIZE 366u
#define SALTS_CRYPTO_SM2_PLAINTEXT_MAX_SIZE 255u
#define SALTS_CRYPTO_SM2_DEFAULT_ID "1234567812345678"

/* Raw private scalar: 32 big-endian bytes, range [1,n-2]. Public key:
 * uncompressed 04 || X || Y on curveSM2, 65 bytes. Caller owns and must
 * securely erase private keys. No native provider types or heap handles.
 * Output buffers must be disjoint from inputs and other outputs. */
int salts_crypto_sm2_keygen(uint8_t private_key[32], uint8_t public_key[65]);
int salts_crypto_sm2_public_key(const uint8_t private_key[32], uint8_t public_key[65]);

/* SM2-with-SM3 over Z(identity, public_key) || message. Identity is explicit,
 * 1..8191 bytes, and never implicitly defaulted or omitted. Signature is
 * fixed-width big-endian r || s (64 bytes); existing ASN1 signature helpers
 * convert its two components to/from canonical DER when required. */
int salts_crypto_sm2_sign(const uint8_t private_key[32],
    const void *identity, size_t identity_size, const void *message,
    size_t message_size, uint8_t signature[64]);
int salts_crypto_sm2_verify(const uint8_t public_key[65],
    const void *identity, size_t identity_size, const void *message,
    size_t message_size, const uint8_t signature[64]);

/* SM2 public-key encryption: canonical DER SEQUENCE { X, Y, C3, C2 }.
 * Plaintext is 1..255 bytes. Encrypt requires capacity >=366; decrypt
 * requires capacity >=255. written must be separate from all buffers.
 * Invalid arguments leave outputs unchanged. Operational failure clears
 * the respective maximum-size output and sets written=0. Decrypt holds
 * plaintext privately until authentication succeeds. */
int salts_crypto_sm2_encrypt(const uint8_t public_key[65],
    const void *plaintext, size_t plaintext_size,
    void *ciphertext, size_t capacity, size_t *written);
int salts_crypto_sm2_decrypt(const uint8_t private_key[32],
    const void *ciphertext, size_t ciphertext_size,
    void *plaintext, size_t capacity, size_t *written);

#ifdef __cplusplus
}
#endif
#endif
