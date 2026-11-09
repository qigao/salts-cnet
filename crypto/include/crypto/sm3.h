#ifndef SALTS_CRYPTO_SM3_H
#define SALTS_CRYPTO_SM3_H
#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM3_DIGEST_SIZE 32u
#define SALTS_CRYPTO_SM3_CONTEXT_SIZE 256u

/* Caller-owned, single-owner state for SM3 or HMAC-SM3. Initialize before
 * update/final; do not copy a live state. Final and clear erase key material.
 * No GmSSL type, allocation or native handle crosses this interface. */
typedef union salts_crypto_sm3_ctx {
  uint64_t integer_alignment;
  long double floating_alignment;
  void *pointer_alignment;
  uint8_t bytes[SALTS_CRYPTO_SM3_CONTEXT_SIZE];
} salts_crypto_sm3_ctx_t;

int salts_crypto_sm3_init(salts_crypto_sm3_ctx_t *ctx);
int salts_crypto_hmac_sm3_init(salts_crypto_sm3_ctx_t *ctx, const void *key, size_t key_size);
int salts_crypto_sm3_update(salts_crypto_sm3_ctx_t *ctx, const void *data, size_t size);
int salts_crypto_sm3_final(salts_crypto_sm3_ctx_t *ctx, uint8_t digest[32]);
void salts_crypto_sm3_clear(salts_crypto_sm3_ctx_t *ctx);
int salts_crypto_sm3(const void *data, size_t size, uint8_t digest[32]);
int salts_crypto_hmac_sm3(const void *key, size_t key_size,
                          const void *data, size_t size, uint8_t mac[32]);

/* RFC 5869 with SM3. NULL salt means the standard all-zero salt. Expand
 * accepts at most 255*32 output bytes; output must not overlap PRK/info. */
int salts_crypto_hkdf_sm3_extract(const void *salt, size_t salt_size,
    const void *ikm, size_t ikm_size, uint8_t prk[32]);
int salts_crypto_hkdf_sm3_expand(const uint8_t prk[32], const void *info,
    size_t info_size, void *output, size_t output_size);

/* PBKDF2-HMAC-SM3. The GmSSL production profile requires 10000..16777215
 * iterations and 1..64 salt bytes. No implicit count or salt is selected.
 * Output must not overlap password or salt. */
int salts_crypto_pbkdf2_sm3(const void *password, size_t password_size,
    const void *salt, size_t salt_size, uint32_t iterations,
    void *output, size_t output_size);

#ifdef __cplusplus
}
#endif
#endif
