#ifndef CRYPTO_ECDSA_H_INCLUDED
#define CRYPTO_ECDSA_H_INCLUDED

#include <crypto/export.h>

#include <crypto/status.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum salts_crypto_ec_curve {
  SALTS_CRYPTO_EC_P256 = 1,
  SALTS_CRYPTO_EC_P384 = 2,
  SALTS_CRYPTO_EC_P521 = 3,
  SALTS_CRYPTO_EC_SECP256K1 = 4
} salts_crypto_ec_curve;

/**
 * ECDSA scalar/coordinate sizes are 32 (P256/k1), 48 (P384), 66 (P521).
 * Private keys are fixed-width big-endian scalars; public keys are X || Y,
 * signatures R || S (twice the scalar size), without SEC1/DER framing.
 * Curve/hash pairs are P256/k1 SHA-256, P384 SHA-384, P521 SHA-512.
 * All buffers are caller-owned; input/output may overlap. On a provider failure
 * output is cleared. Invalid arguments return EINVAL without changing output.
 * NULL data is allowed only for size zero; data_size must fit uint32_t.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_ecdsa_public_key(salts_crypto_ec_curve curve,
    const uint8_t *private_key, size_t private_size, uint8_t *public_key, size_t public_size);
SALTS_CRYPTO_EXPORT
int salts_crypto_ecdsa_sign(salts_crypto_ec_curve curve,
    const uint8_t *private_key, size_t private_size, const void *data, size_t data_size,
    uint8_t *signature, size_t signature_size);
/** Returns EVERIFY for invalid points/signatures, EINVAL for invalid sizes. */
SALTS_CRYPTO_EXPORT
int salts_crypto_ecdsa_verify(salts_crypto_ec_curve curve,
    const uint8_t *public_key, size_t public_size, const void *data, size_t data_size,
    const uint8_t *signature, size_t signature_size);

#ifdef __cplusplus
}
#endif

#endif
