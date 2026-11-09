#ifndef SALTS_CRYPTO_ZUC_H
#define SALTS_CRYPTO_ZUC_H
#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum salts_crypto_zuc_variant {
  SALTS_CRYPTO_ZUC128 = 1,
  SALTS_CRYPTO_ZUC256 = 2
} salts_crypto_zuc_variant;

/* One complete message per call, maximum 8188 bytes (65504 bits).
 * ZUC128 requires key=16, IV=16 bytes; ZUC256 requires key=32, IV=23 bytes
 * (packed 184-bit IV). Caller must never reuse a key/IV pair for distinct
 * messages. Encryption and decryption are identical and unauthenticated.
 * Output must not overlap key, IV or input; capacity must cover size. */
int salts_crypto_zuc_crypt(salts_crypto_zuc_variant variant,
    const void *key, size_t key_size, const void *iv, size_t iv_size,
    const void *input, size_t size, void *output, size_t capacity);

/* MAC input length is in bits, 0..65504. Bits within bytes are MSB first;
 * unused low bits of the final byte are ignored. ZUC128 tag=4 bytes;
 * ZUC256 tag=4,8,16 bytes. Tag must not overlap key, IV or input.
 * Verify compares all tag bytes and returns EVERIFY on a mismatch. */
int salts_crypto_zuc_mac(salts_crypto_zuc_variant variant,
    const void *key, size_t key_size, const void *iv, size_t iv_size,
    const void *input, size_t bits, void *tag, size_t tag_size);
int salts_crypto_zuc_verify(salts_crypto_zuc_variant variant,
    const void *key, size_t key_size, const void *iv, size_t iv_size,
    const void *input, size_t bits, const void *tag, size_t tag_size);

#ifdef __cplusplus
}
#endif
#endif
