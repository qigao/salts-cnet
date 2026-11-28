#include <crypto/symmetric.h>
#include "crypto_internal.h"
#include <gmssl/aes.h>
#include <gmssl/des.h>
#include <gmssl/md5.h>
#include <string.h>

int salts_crypto_hmac_md5(const void *key, size_t key_size, const void *data,
                          size_t size, uint8_t output[SALTS_CRYPTO_MD5_DIGEST_SIZE]) {
  enum { HMAC_INNER_PAD = 0x36, HMAC_OUTER_PAD = 0x5c };
  MD5_CTX context;
  uint8_t key_block[MD5_BLOCK_SIZE] = {0};
  uint8_t inner_pad[MD5_BLOCK_SIZE];
  uint8_t outer_pad[MD5_BLOCK_SIZE];
  uint8_t inner_digest[SALTS_CRYPTO_MD5_DIGEST_SIZE];

  if (!output || (!key && key_size) || (!data && size)) return SALTS_CRYPTO_EINVAL;
  /* GmSSL's generic HMAC dispatch omits MD5. Keep the legacy Salts
   * construction with the provider's MD5 primitive for protocol interop. */
  if (key_size > sizeof(key_block)) {
    int status = salts_crypto_md5(key, key_size, key_block);
    if (status != SALTS_CRYPTO_OK) return status;
  } else if (key_size) {
    memcpy(key_block, key, key_size);
  }
  for (size_t i = 0; i < sizeof(key_block); ++i) {
    inner_pad[i] = (uint8_t)(key_block[i] ^ HMAC_INNER_PAD);
    outer_pad[i] = (uint8_t)(key_block[i] ^ HMAC_OUTER_PAD);
  }
  md5_init(&context);
  md5_update(&context, inner_pad, sizeof(inner_pad));
  if (size) md5_update(&context, data, size);
  md5_finish(&context, inner_digest);
  md5_init(&context);
  md5_update(&context, outer_pad, sizeof(outer_pad));
  md5_update(&context, inner_digest, sizeof(inner_digest));
  md5_finish(&context, output);

  salts_crypto_clear(&context, sizeof(context));
  salts_crypto_clear(key_block, sizeof(key_block));
  salts_crypto_clear(inner_pad, sizeof(inner_pad));
  salts_crypto_clear(outer_pad, sizeof(outer_pad));
  salts_crypto_clear(inner_digest, sizeof(inner_digest));
  return SALTS_CRYPTO_OK;
}

static int legacy_cipher_arguments(int decrypt, const uint8_t *key, const uint8_t *iv,
                                   size_t block_size, const void *input, size_t size,
                                   void *output, size_t capacity) {
  return (decrypt == 0 || decrypt == 1) && key && iv &&
    ((input && output) || size == 0) && capacity >= size &&
    (input == output || !salts_crypto_overlap(input, size, output, size)) &&
    !salts_crypto_overlap(output, size, key, block_size) &&
    !salts_crypto_overlap(output, size, iv, block_size);
}

int salts_crypto_des_cbc_crypt(int decrypt,
    const uint8_t key[SALTS_CRYPTO_DES_BLOCK_SIZE], const uint8_t iv[SALTS_CRYPTO_DES_BLOCK_SIZE],
    const void *input, size_t size, void *output, size_t capacity) {
  if (size % SALTS_CRYPTO_DES_BLOCK_SIZE ||
      !legacy_cipher_arguments(decrypt, key, iv, SALTS_CRYPTO_DES_BLOCK_SIZE,
                               input, size, output, capacity)) return SALTS_CRYPTO_EINVAL;
  if (!size) return SALTS_CRYPTO_OK;
  int result = decrypt ? des_cbc_decrypt(key, iv, input, size, output)
                       : des_cbc_encrypt(key, iv, input, size, output);
  if (result == 1) return SALTS_CRYPTO_OK;
  salts_crypto_clear(output, size);
  return SALTS_CRYPTO_ECRYPTO;
}

int salts_crypto_aes128_cfb_crypt(int decrypt,
    const uint8_t key[SALTS_CRYPTO_AES128_BLOCK_SIZE], const uint8_t iv[SALTS_CRYPTO_AES128_BLOCK_SIZE],
    const void *input, size_t size, void *output, size_t capacity) {
  if (!legacy_cipher_arguments(decrypt, key, iv, SALTS_CRYPTO_AES128_BLOCK_SIZE,
                               input, size, output, capacity)) return SALTS_CRYPTO_EINVAL;
  if (!size) return SALTS_CRYPTO_OK;

  AES_KEY native;
  if (aes_set_encrypt_key(&native, key, SALTS_CRYPTO_AES128_BLOCK_SIZE) != 1) {
    salts_crypto_clear(&native, sizeof(native));
    salts_crypto_clear(output, size);
    return SALTS_CRYPTO_ECRYPTO;
  }
  const uint8_t *source = input;
  uint8_t *destination = output;
  uint8_t feedback[SALTS_CRYPTO_AES128_BLOCK_SIZE];
  uint8_t stream[SALTS_CRYPTO_AES128_BLOCK_SIZE];
  memcpy(feedback, iv, sizeof(feedback));
  for (size_t i = 0; i < size; ++i) {
    size_t offset = i % sizeof(feedback);
    if (offset == 0) aes_encrypt(&native, feedback, stream);
    uint8_t byte = source[i];
    destination[i] = byte ^ stream[offset];
    feedback[offset] = decrypt ? byte : destination[i];
  }
  salts_crypto_clear(&native, sizeof(native));
  salts_crypto_clear(feedback, sizeof(feedback));
  salts_crypto_clear(stream, sizeof(stream));
  return SALTS_CRYPTO_OK;
}
