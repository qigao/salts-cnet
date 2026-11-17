#ifndef SALTS_CRYPTO_KEY_INTERNAL_H
#define SALTS_CRYPTO_KEY_INTERNAL_H
#include <crypto/key.h>
#include <gmssl/rsa_components.h>
struct salts_crypto_key {
  salts_crypto_key_kind kind;
  salts_crypto_ec_curve curve;
  size_t scalar_size;
  int has_private;
  union {
    RSA_COMPONENTS rsa;
    struct { uint8_t public_key[132], private_key[66]; } ec;
  } value;
};
/* libecc adapter TU has its own compile definitions, unlike GmSSL adapters. */
salts_crypto_ec_curve salts_crypto_ec_identify(salts_crypto_bytes p, salts_crypto_bytes a,
    salts_crypto_bytes b, salts_crypto_bytes generator, salts_crypto_bytes order,
    salts_crypto_bytes cofactor);
int salts_crypto_ec_decode(salts_crypto_ec_curve curve, const uint8_t *input, size_t size,
    uint8_t *output, size_t capacity);
int salts_crypto_ec_sign_hash(salts_crypto_ec_curve curve, salts_crypto_hash hash,
    const uint8_t *key, size_t key_size, const void *message, size_t size, uint8_t *signature, size_t signature_size);
int salts_crypto_ec_verify_hash(salts_crypto_ec_curve curve, salts_crypto_hash hash,
    const uint8_t *key, size_t key_size, const void *message, size_t size, const uint8_t *signature, size_t signature_size);
#endif
