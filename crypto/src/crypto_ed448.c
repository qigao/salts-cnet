#include <crypto/ed448.h>

#include <limits.h>
#include <string.h>

#include "crypto_internal.h"

#include <crypto/export.h>

/* libecc declares this callback in its own header. */
SALTS_CRYPTO_EXPORT int salts_crypto_libecc_get_random(unsigned char *buffer,
                                                     uint16_t size);

#include <libecc/curves/curves.h>
#include <libecc/external_deps/rand.h>
#include <libecc/sig/eddsa.h>
#include <libecc/sig/sig_algs.h>

static const uint8_t salts_crypto_empty_message = 0U;

static int salts_crypto_random(void *buffer, size_t size) {
  return salts_crypto_random_bytes(buffer, size) == 0 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ERANDOM;
}

/* libecc uses randomness to blind secret scalar multiplications. */
int salts_crypto_libecc_get_random(unsigned char *buffer, u16 size) {
  return salts_crypto_random(buffer, (size_t)size) == SALTS_CRYPTO_OK ? 0 : -1;
}

static int buffers_overlap(const void *left, const void *right, size_t size) {
  const uintptr_t left_address = (uintptr_t)left;
  const uintptr_t right_address = (uintptr_t)right;

  return left_address < right_address ? right_address - left_address < size
                                      : left_address - right_address < size;
}

static int ed448_init_params(ec_params *params) {
  const ec_str_params *string_params = NULL;

  memset(params, 0, sizeof(*params));
  if (ec_get_curve_params_by_type(WEI448, &string_params) != 0 || string_params == NULL ||
      import_params(params, string_params) != 0) {
    return SALTS_CRYPTO_ECRYPTO;
  }
  return SALTS_CRYPTO_OK;
}

static int ed448_import_key_pair(ec_key_pair *key_pair, const ec_params *params,
                                 const uint8_t private_key[SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE]) {
  memset(key_pair, 0, sizeof(*key_pair));
  return eddsa_import_key_pair_from_priv_key_buf(
             key_pair, private_key, SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE, params, EDDSA448) == 0
             ? SALTS_CRYPTO_OK
             : SALTS_CRYPTO_ECRYPTO;
}

int salts_crypto_ed448_public_key(const uint8_t private_key[SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE],
                                  uint8_t public_key[SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE]) {
  ec_params params;
  ec_key_pair key_pair;
  int status;

  if (private_key == NULL || public_key == NULL) return SALTS_CRYPTO_EINVAL;

  memset(&key_pair, 0, sizeof(key_pair));
  status = ed448_init_params(&params);
  if (status == SALTS_CRYPTO_OK) status = ed448_import_key_pair(&key_pair, &params, private_key);
  if (status == SALTS_CRYPTO_OK && eddsa_export_pub_key(&key_pair.pub_key, public_key,
                                                        SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE) != 0) {
    status = SALTS_CRYPTO_ECRYPTO;
  }

  salts_crypto_secure_zero(&key_pair, sizeof(key_pair));
  salts_crypto_secure_zero(&params, sizeof(params));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(public_key, SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE);
  return status;
}

int salts_crypto_ed448_keygen(uint8_t private_key[SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE],
                              uint8_t public_key[SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE]) {
  int status;

  if (private_key == NULL || public_key == NULL ||
      buffers_overlap(private_key, public_key, SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE)) {
    return SALTS_CRYPTO_EINVAL;
  }

  status = salts_crypto_random(private_key, SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE);
  if (status == SALTS_CRYPTO_OK) status = salts_crypto_ed448_public_key(private_key, public_key);
  if (status != SALTS_CRYPTO_OK) {
    salts_crypto_secure_zero(private_key, SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE);
    salts_crypto_secure_zero(public_key, SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE);
  }
  return status;
}

int salts_crypto_ed448_sign(const uint8_t private_key[SALTS_CRYPTO_ED448_PRIVATE_KEY_SIZE],
                            const void *data, size_t data_size,
                            uint8_t signature[SALTS_CRYPTO_ED448_SIGNATURE_SIZE]) {
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
  status = ed448_init_params(&params);
  if (status == SALTS_CRYPTO_OK) status = ed448_import_key_pair(&key_pair, &params, private_key);
  if (status == SALTS_CRYPTO_OK &&
      (ec_get_sig_len(&params, EDDSA448, SHAKE256, &signature_size) != 0 ||
       signature_size != SALTS_CRYPTO_ED448_SIGNATURE_SIZE)) {
    status = SALTS_CRYPTO_ECRYPTO;
  }
  if (status == SALTS_CRYPTO_OK && ec_sign(signature, signature_size, &key_pair, message,
                                           (u32)data_size, EDDSA448, SHAKE256, NULL, 0U) != 0) {
    status = SALTS_CRYPTO_ECRYPTO;
  }

  salts_crypto_secure_zero(&key_pair, sizeof(key_pair));
  salts_crypto_secure_zero(&params, sizeof(params));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(signature, SALTS_CRYPTO_ED448_SIGNATURE_SIZE);
  return status;
}

int salts_crypto_ed448_verify(const uint8_t public_key[SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE],
                              const void *data, size_t data_size,
                              const uint8_t signature[SALTS_CRYPTO_ED448_SIGNATURE_SIZE]) {
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
  status = ed448_init_params(&params);
  if (status == SALTS_CRYPTO_OK &&
      eddsa_import_pub_key(&imported_public_key, public_key, SALTS_CRYPTO_ED448_PUBLIC_KEY_SIZE,
                           &params, EDDSA448) != 0) {
    status = SALTS_CRYPTO_EVERIFY;
  }
  if (status == SALTS_CRYPTO_OK &&
      ec_verify(signature, SALTS_CRYPTO_ED448_SIGNATURE_SIZE, &imported_public_key, message,
                (u32)data_size, EDDSA448, SHAKE256, NULL, 0U) != 0) {
    status = SALTS_CRYPTO_EVERIFY;
  }

  salts_crypto_secure_zero(&imported_public_key, sizeof(imported_public_key));
  salts_crypto_secure_zero(&params, sizeof(params));
  return status;
}
