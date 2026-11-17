#include <crypto/ed25519.h>
#include <crypto/symmetric.h>

#include <limits.h>
#include <string.h>

#include "crypto_internal.h"

#include <libecc/curves/curves.h>
#include <libecc/external_deps/rand.h>
#include <libecc/sig/eddsa.h>
#include <libecc/sig/sig_algs.h>

typedef struct eddsa_parameters {
  ec_curve_type curve;
  ec_alg_type algorithm;
  hash_alg_type hash;
  u8 key_size;
  u8 signature_size;
} eddsa_parameters;

static const eddsa_parameters ed25519 = {WEI25519, EDDSA25519, SHA512, 32, 64};
static const uint8_t salts_crypto_empty_message = 0U;

static int buffers_overlap(const void *left, const void *right, size_t size) {
  const uintptr_t left_address = (uintptr_t)left;
  const uintptr_t right_address = (uintptr_t)right;

  return left_address < right_address ? right_address - left_address < size
                                      : left_address - right_address < size;
}

static int eddsa_init_params(const eddsa_parameters *algorithm, ec_params *params) {
  const ec_str_params *string_params = NULL;

  memset(params, 0, sizeof(*params));
  if (ec_get_curve_params_by_type(algorithm->curve, &string_params) != 0 || string_params == NULL ||
      import_params(params, string_params) != 0) {
    return SALTS_CRYPTO_ECRYPTO;
  }
  return SALTS_CRYPTO_OK;
}

static int eddsa_import_key_pair(const eddsa_parameters *algorithm, ec_key_pair *key_pair, const ec_params *params,
                                 const uint8_t *private_key) {
  memset(key_pair, 0, sizeof(*key_pair));
  return eddsa_import_key_pair_from_priv_key_buf(
             key_pair, private_key, algorithm->key_size, params, algorithm->algorithm) == 0
             ? SALTS_CRYPTO_OK
             : SALTS_CRYPTO_ECRYPTO;
}

static int eddsa_public_key(const eddsa_parameters *algorithm, const uint8_t *private_key,
                                  uint8_t *public_key) {
  ec_params params;
  ec_key_pair key_pair;
  int status;

  if (private_key == NULL || public_key == NULL) return SALTS_CRYPTO_EINVAL;

  memset(&key_pair, 0, sizeof(key_pair));
  status = eddsa_init_params(algorithm, &params);
  if (status == SALTS_CRYPTO_OK) status = eddsa_import_key_pair(algorithm, &key_pair, &params, private_key);
  if (status == SALTS_CRYPTO_OK && eddsa_export_pub_key(&key_pair.pub_key, public_key,
                                                        algorithm->key_size) != 0) {
    status = SALTS_CRYPTO_ECRYPTO;
  }

  salts_crypto_secure_zero(&key_pair, sizeof(key_pair));
  salts_crypto_secure_zero(&params, sizeof(params));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(public_key, algorithm->key_size);
  return status;
}

static int eddsa_keygen(const eddsa_parameters *algorithm, uint8_t *private_key,
                              uint8_t *public_key) {
  int status;

  if (private_key == NULL || public_key == NULL ||
      buffers_overlap(private_key, public_key, algorithm->key_size)) {
    return SALTS_CRYPTO_EINVAL;
  }

  status = salts_crypto_random(private_key, algorithm->key_size);
  if (status == SALTS_CRYPTO_OK) status = eddsa_public_key(algorithm, private_key, public_key);
  if (status != SALTS_CRYPTO_OK) {
    salts_crypto_secure_zero(private_key, algorithm->key_size);
    salts_crypto_secure_zero(public_key, algorithm->key_size);
  }
  return status;
}

static int eddsa_sign(const eddsa_parameters *algorithm, const uint8_t *private_key,
                            const void *data, size_t data_size,
                            uint8_t *signature) {
  ec_params params;
  ec_key_pair key_pair;
  const uint8_t *message = (const uint8_t *)data;
  u8 signature_size = 0U;
  int status;

  if (private_key == NULL || signature == NULL || (data == NULL && data_size != 0U) ||
      data_size > UINT32_MAX) {
    return SALTS_CRYPTO_EINVAL;
  }
  if (message == NULL) message = &salts_crypto_empty_message;

  memset(&key_pair, 0, sizeof(key_pair));
  status = eddsa_init_params(algorithm, &params);
  if (status == SALTS_CRYPTO_OK) status = eddsa_import_key_pair(algorithm, &key_pair, &params, private_key);
  if (status == SALTS_CRYPTO_OK &&
      (ec_get_sig_len(&params, algorithm->algorithm, algorithm->hash, &signature_size) != 0 ||
       signature_size != algorithm->signature_size)) {
    status = SALTS_CRYPTO_ECRYPTO;
  }
  if (status == SALTS_CRYPTO_OK && ec_sign(signature, signature_size, &key_pair, message,
                                           (u32)data_size, algorithm->algorithm, algorithm->hash, NULL, 0U) != 0) {
    status = SALTS_CRYPTO_ECRYPTO;
  }

  salts_crypto_secure_zero(&key_pair, sizeof(key_pair));
  salts_crypto_secure_zero(&params, sizeof(params));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(signature, algorithm->signature_size);
  return status;
}

static int eddsa_verify(const eddsa_parameters *algorithm, const uint8_t *public_key,
                              const void *data, size_t data_size,
                              const uint8_t *signature) {
  ec_params params;
  ec_pub_key imported_public_key;
  const uint8_t *message = (const uint8_t *)data;
  int status;

  if (public_key == NULL || signature == NULL || (data == NULL && data_size != 0U) ||
      data_size > UINT32_MAX) {
    return SALTS_CRYPTO_EINVAL;
  }
  if (message == NULL) message = &salts_crypto_empty_message;

  memset(&imported_public_key, 0, sizeof(imported_public_key));
  status = eddsa_init_params(algorithm, &params);
  if (status == SALTS_CRYPTO_OK &&
      eddsa_import_pub_key(&imported_public_key, public_key, algorithm->key_size,
                           &params, algorithm->algorithm) != 0) {
    status = SALTS_CRYPTO_EVERIFY;
  }
  if (status == SALTS_CRYPTO_OK &&
      ec_verify(signature, algorithm->signature_size, &imported_public_key, message,
                (u32)data_size, algorithm->algorithm, algorithm->hash, NULL, 0U) != 0) {
    status = SALTS_CRYPTO_EVERIFY;
  }

  salts_crypto_secure_zero(&imported_public_key, sizeof(imported_public_key));
  salts_crypto_secure_zero(&params, sizeof(params));
  return status;
}

int salts_crypto_ed25519_public_key(const uint8_t *private_key, uint8_t *public_key) {
  return eddsa_public_key(&ed25519, private_key, public_key);
}
int salts_crypto_ed25519_keygen(uint8_t *private_key, uint8_t *public_key) {
  return eddsa_keygen(&ed25519, private_key, public_key);
}
int salts_crypto_ed25519_sign(const uint8_t *private_key, const void *data,
                            size_t data_size, uint8_t *signature) {
  return eddsa_sign(&ed25519, private_key, data, data_size, signature);
}
int salts_crypto_ed25519_verify(const uint8_t *public_key, const void *data,
                              size_t data_size, const uint8_t *signature) {
  return eddsa_verify(&ed25519, public_key, data, data_size, signature);
}
