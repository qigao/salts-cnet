#include <crypto/symmetric.h>
#include "crypto_internal.h"
#include <gmssl/md5.h>
#include <gmssl/aes.h>
#include <gmssl/digest.h>
#include <gmssl/hmac.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/mem.h>
#include <string.h>

static const DIGEST *crypto_digest(salts_crypto_hash hash) {
  switch (hash) {
  case SALTS_CRYPTO_SHA1: return DIGEST_sha1();
  case SALTS_CRYPTO_SHA256: return DIGEST_sha256();
  case SALTS_CRYPTO_SHA384: return DIGEST_sha384();
  case SALTS_CRYPTO_SHA512: return DIGEST_sha512();
  default: return NULL;
  }
}

void salts_crypto_clear(void *data, size_t size) {
  if (data && size) gmssl_secure_clear(data, size);
}

int salts_crypto_equal(const void *a, const void *b, size_t size) {
  if ((!a || !b) && size) return SALTS_CRYPTO_EINVAL;
  return !size || gmssl_secure_memcmp(a, b, size) == 0 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
}

int salts_crypto_random(void *output, size_t size) {
  if (!output && size) return SALTS_CRYPTO_EINVAL;
  if (salts_crypto_random_bytes(output, size) == 0) return SALTS_CRYPTO_OK;
  salts_crypto_secure_zero(output, size);
  return SALTS_CRYPTO_ERANDOM;
}

int salts_crypto_digest(salts_crypto_hash hash, const void *data, size_t size,
    uint8_t *output, size_t capacity, size_t *output_size) {
  const DIGEST *md = crypto_digest(hash);
  uint8_t result[DIGEST_MAX_SIZE];
  size_t n = 0;
  int status = SALTS_CRYPTO_ECRYPTO;
  if (output_size) *output_size = 0;
  if (!md || (!data && size) || !output || !output_size || capacity < md->digest_size)
    return SALTS_CRYPTO_EINVAL;
  if (digest(md, data, size, result, &n) == 1 && n == md->digest_size) {
    memcpy(output, result, n);
    *output_size = n;
    status = SALTS_CRYPTO_OK;
  }
  salts_crypto_clear(result, sizeof(result));
  return status;
}

int salts_crypto_hmac(salts_crypto_hash hash, const void *key, size_t key_size,
    const void *data, size_t size, uint8_t *output, size_t capacity, size_t *output_size) {
  const DIGEST *md = crypto_digest(hash);
  uint8_t result[DIGEST_MAX_SIZE];
  size_t n = 0;
  int status = SALTS_CRYPTO_ECRYPTO;
  if (output_size) *output_size = 0;
  if (!md || (!key && key_size) || (!data && size) || !output || !output_size ||
      capacity < md->digest_size) return SALTS_CRYPTO_EINVAL;
  if (hmac(md, key, key_size, data, size, result, &n) == 1 && n == md->digest_size) {
    memcpy(output, result, n);
    *output_size = n;
    status = SALTS_CRYPTO_OK;
  }
  salts_crypto_clear(result, sizeof(result));
  return status;
}

int salts_crypto_pbkdf2(salts_crypto_hash hash, const void *password, size_t password_size,
    const void *salt, size_t salt_size, uint32_t iterations, uint8_t *output, size_t size) {
  const DIGEST *md = crypto_digest(hash);
  if (!md || (!password && password_size) || (!salt && salt_size) ||
      !iterations || !output || !size ||
      (uint64_t)size > (uint64_t)UINT32_MAX * md->digest_size) return SALTS_CRYPTO_EINVAL;
  if (pbkdf2_hmac_genkey(md, password, password_size, salt, salt_size, iterations, size, output) == 1)
    return SALTS_CRYPTO_OK;
  salts_crypto_clear(output, size);
  return SALTS_CRYPTO_ECRYPTO;
}

static int gcm_arguments(const uint8_t *key, size_t key_size, const uint8_t *iv, size_t iv_size,
    const void *aad, size_t aad_size, const uint8_t *input, size_t size,
    uint8_t *output, size_t capacity, const uint8_t *tag, size_t tag_size) {
  return key && (key_size == 16 || key_size == 24 || key_size == 32) &&
    iv && iv_size && (uint64_t)iv_size < AES_GCM_IV_MAX_SIZE &&
    (aad || !aad_size) && (uint64_t)aad_size < AES_GCM_MAX_AAD_SIZE &&
    (input || !size) && (output || !size) && capacity >= size &&
    (uint64_t)size <= AES_GCM_MAX_PLAINTEXT_SIZE && tag && tag_size && tag_size <= 16;
}

int salts_crypto_aes_gcm_encrypt(const uint8_t *key, size_t key_size,
    const uint8_t *iv, size_t iv_size, const void *aad, size_t aad_size,
    const uint8_t *input, size_t size, uint8_t *output, size_t capacity,
    uint8_t *tag, size_t tag_size) {
  AES_KEY state;
  int ret;
  if (!gcm_arguments(key, key_size, iv, iv_size, aad, aad_size, input, size,
                    output, capacity, tag, tag_size)) return SALTS_CRYPTO_EINVAL;
  ret = aes_set_encrypt_key(&state, key, key_size);
  if (ret == 1) ret = aes_gcm_encrypt(&state, iv, iv_size, aad, aad_size, input, size, output, tag_size, tag);
  salts_crypto_clear(&state, sizeof(state));
  return ret == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
}

int salts_crypto_aes_gcm_decrypt(const uint8_t *key, size_t key_size,
    const uint8_t *iv, size_t iv_size, const void *aad, size_t aad_size,
    const uint8_t *input, size_t size, const uint8_t *tag, size_t tag_size,
    uint8_t *output, size_t capacity) {
  AES_KEY state;
  int ret;
  if (!gcm_arguments(key, key_size, iv, iv_size, aad, aad_size, input, size,
                    output, capacity, tag, tag_size)) return SALTS_CRYPTO_EINVAL;
  ret = aes_set_encrypt_key(&state, key, key_size);
  if (ret == 1) ret = aes_gcm_decrypt(&state, iv, iv_size, aad, aad_size, input, size, tag, tag_size, output);
  salts_crypto_clear(&state, sizeof(state));
  return ret == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
}

int salts_crypto_md5(const void *data, size_t size, uint8_t output[SALTS_CRYPTO_MD5_DIGEST_SIZE]) {
  MD5_CTX context;
  if (!output || (!data && size)) return SALTS_CRYPTO_EINVAL;
  md5_init(&context);
  if (size) md5_update(&context, data, size);
  md5_finish(&context, output);
  salts_crypto_secure_zero(&context, sizeof(context));
  return SALTS_CRYPTO_OK;
}
