#ifndef SALTS_CRYPTO_SM4_H
#define SALTS_CRYPTO_SM4_H
#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM4_KEY_SIZE 16u
#define SALTS_CRYPTO_SM4_BLOCK_SIZE 16u
typedef enum salts_crypto_sm4_mode {
  SALTS_CRYPTO_SM4_ECB = 1,
  SALTS_CRYPTO_SM4_CBC,
  SALTS_CRYPTO_SM4_CTR,
  SALTS_CRYPTO_SM4_OFB,
  SALTS_CRYPTO_SM4_CFB8,
  SALTS_CRYPTO_SM4_CFB64,
  SALTS_CRYPTO_SM4_CFB128,
  SALTS_CRYPTO_SM4_XTS
} salts_crypto_sm4_mode;

/* Low-level unauthenticated modes, with no implicit padding. ECB/CBC require
 * whole blocks. XTS requires a 32-byte pair of different keys and one data
 * unit of 16..16777216 bytes. Other modes use a 16-byte key. IV/tweak is
 * exactly 16 bytes except ECB (NULL). decrypt is 0 or 1. Output capacity
 * is at least size; it must not overlap any input. IV is never modified.
 * Protocols must authenticate unauthenticated modes separately. */
int salts_crypto_sm4_crypt(salts_crypto_sm4_mode mode, int decrypt,
    const void *key, size_t key_size, const uint8_t iv[16],
    const void *input, size_t size, void *output, size_t capacity);

typedef enum salts_crypto_sm4_aead {
  SALTS_CRYPTO_SM4_GCM = 1,
  SALTS_CRYPTO_SM4_CCM
} salts_crypto_sm4_aead;

/* One-shot authenticated encryption, without allocation. The caller owns
 * nonce uniqueness per key. GCM: nonce 1..64, tag 12..16 bytes. CCM: nonce
 * 7..13, even tag 4..16 bytes, payload fits its nonce-dependent length field.
 * This API bounds AAD to 16 MiB for both modes.
 * Output/tag ranges must not overlap inputs or each other. Output has size
 * bytes. Invalid arguments leave outputs unchanged. Auth failure clears
 * exactly size output bytes and returns EVERIFY; plaintext is usable only
 * after OK. No plaintext is exposed through callbacks during verification. */
int salts_crypto_sm4_aead_encrypt(salts_crypto_sm4_aead mode,
    const uint8_t key[16], const void *nonce, size_t nonce_size,
    const void *aad, size_t aad_size, const void *input, size_t size,
    void *output, size_t capacity, void *tag, size_t tag_size);
int salts_crypto_sm4_aead_decrypt(salts_crypto_sm4_aead mode,
    const uint8_t key[16], const void *nonce, size_t nonce_size,
    const void *aad, size_t aad_size, const void *input, size_t size,
    const void *tag, size_t tag_size, void *output, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
