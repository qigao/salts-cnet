#ifndef CRYPTO_ED448_H_INCLUDED
#define CRYPTO_ED448_H_INCLUDED

#include <crypto/export.h>

#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE 57U
#define SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE 57U
#define SALTS_CRYPTO_ED448_SIGNATURE_SIZE 114U

/**
 * Derives an RFC 8032 Ed448 public key from a 57-byte private seed.
 *
 * @return SALTS_CRYPTO_OK, SALTS_CRYPTO_EINVAL for invalid arguments, or
 *         SALTS_CRYPTO_ECRYPTO when key derivation fails.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_ed448_public_key(const uint8_t private_key[SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE],
                                  uint8_t public_key[SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE]);

/**
 * Creates a random RFC 8032 Ed448 key pair using the platform CSPRNG.
 * The two output ranges must not overlap.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_ed448_keygen(uint8_t private_key[SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE],
                              uint8_t public_key[SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE]);

/**
 * Signs data with RFC 8032 pure Ed448. A null data pointer is valid only when
 * data_size is zero.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_ed448_sign(const uint8_t private_key[SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE],
                            const void *data, size_t data_size,
                            uint8_t signature[SALTS_CRYPTO_ED448_SIGNATURE_SIZE]);

/**
 * Verifies an RFC 8032 pure Ed448 signature.
 *
 * @return SALTS_CRYPTO_OK for a valid signature, SALTS_CRYPTO_EVERIFY for an
 *         invalid key or signature, or another salts_crypto_status on failure.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_ed448_verify(const uint8_t public_key[SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE],
                              const void *data, size_t data_size,
                              const uint8_t signature[SALTS_CRYPTO_ED448_SIGNATURE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ED448_H_INCLUDED */
