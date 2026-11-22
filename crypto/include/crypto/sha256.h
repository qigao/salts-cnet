#ifndef CRYPTO_SHA256_H_INCLUDED
#define CRYPTO_SHA256_H_INCLUDED

#include <crypto/export.h>

#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SHA256_DIGEST_SIZE 32U
#define SALTS_CRYPTO_SHA256_CONTEXT_SIZE 128U

/**
 * SHA-256 streaming state with implementation-private storage. It has no
 * heap ownership and is not thread-safe. Do not copy it after initialization.
 */
typedef union salts_crypto_sha256_ctx_u {
  void *pointer_alignment;
  uint64_t integer_alignment;
  long double floating_alignment;
  uint8_t bytes[SALTS_CRYPTO_SHA256_CONTEXT_SIZE];
} salts_crypto_sha256_ctx_t;

/** Computes a SHA-256 digest in one call. NULL data is valid only for size zero. */
SALTS_CRYPTO_EXPORT
int salts_crypto_sha256(const void *data, size_t data_size,
                        uint8_t digest[SALTS_CRYPTO_SHA256_DIGEST_SIZE]);

/** Initializes a caller-owned streaming SHA-256 state. */
SALTS_CRYPTO_EXPORT
int salts_crypto_sha256_init(salts_crypto_sha256_ctx_t *context);

/** Adds input to an initialized SHA-256 state. */
SALTS_CRYPTO_EXPORT
int salts_crypto_sha256_update(salts_crypto_sha256_ctx_t *context, const void *data,
                               size_t data_size);

/** Finalizes a SHA-256 state. It cannot be updated or finalized again. */
SALTS_CRYPTO_EXPORT
int salts_crypto_sha256_final(salts_crypto_sha256_ctx_t *context,
                              uint8_t digest[SALTS_CRYPTO_SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_SHA256_H_INCLUDED */
