#ifndef CRYPTO_ED25519_H_INCLUDED
#define CRYPTO_ED25519_H_INCLUDED

#include <crypto/status.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_ED25519_PRIVATE_KEY_SIZE 32U
#define SALTS_CRYPTO_ED25519_PUBLIC_KEY_SIZE 32U
#define SALTS_CRYPTO_ED25519_SIGNATURE_SIZE 64U

/**
 * RFC 8032 pure Ed25519 with a 32-byte seed, 32-byte encoded public key and
 * 64-byte signature. The ownership, overlap, empty-message and status contracts
 * are identical to the corresponding operations in <crypto/ed448.h>.
 */
int salts_crypto_ed25519_public_key(const uint8_t private_key[32], uint8_t public_key[32]);
int salts_crypto_ed25519_keygen(uint8_t private_key[32], uint8_t public_key[32]);
int salts_crypto_ed25519_sign(const uint8_t private_key[32], const void *data,
                              size_t data_size, uint8_t signature[64]);
int salts_crypto_ed25519_verify(const uint8_t public_key[32], const void *data,
                                size_t data_size, const uint8_t signature[64]);

#ifdef __cplusplus
}
#endif

#endif
