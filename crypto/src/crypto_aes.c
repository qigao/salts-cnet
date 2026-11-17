#include <crypto/symmetric.h>
#include "crypto_internal.h"
#include <gmssl/aes.h>
#include <string.h>

int salts_crypto_aes_crypt(salts_crypto_aes_mode mode, int decrypt,
    const uint8_t *key, size_t key_size, const uint8_t iv[16],
    const uint8_t *input, size_t size, uint8_t *output, size_t capacity) {
  AES_KEY native;
  uint8_t counter[16];
  uint8_t block[16];
  uint64_t carry;
  int ret;
  if ((mode != SALTS_CRYPTO_AES_CBC && mode != SALTS_CRYPTO_AES_CTR) ||
      (decrypt != 0 && decrypt != 1) || !key || !iv ||
      (key_size != 16 && key_size != 24 && key_size != 32) ||
      (!input && size) || (!output && size) || capacity < size ||
      (mode == SALTS_CRYPTO_AES_CBC && size % 16) ||
      (input != output && salts_crypto_overlap(input, size, output, size)) ||
      salts_crypto_overlap(output, size, key, key_size) ||
      salts_crypto_overlap(output, size, iv, 16)) return SALTS_CRYPTO_EINVAL;
  if (!size) return SALTS_CRYPTO_OK;
  if (mode == SALTS_CRYPTO_AES_CTR) {
    /* Check the last counter used, allowing a single final all-ones block. */
    carry = (uint64_t)(size / 16 + (size % 16 != 0)) - 1;
    for (int i = 15; i >= 0; --i) { carry += iv[i]; carry >>= 8; }
    if (carry) return SALTS_CRYPTO_EINVAL;
  }
  ret = mode == SALTS_CRYPTO_AES_CBC && decrypt ?
    aes_set_decrypt_key(&native, key, key_size) : aes_set_encrypt_key(&native, key, key_size);
  if (ret == 1) {
    if (mode == SALTS_CRYPTO_AES_CTR) {
      memcpy(counter, iv, sizeof(counter));
      aes_ctr_encrypt(&native, counter, input, size, output);
    } else if (decrypt && input == output) {
      /* The provider's multi-block CBC decrypt borrows the previous input
       * block as its IV; preserve that block before an identical output write. */
      memcpy(counter, iv, sizeof(counter));
      for (size_t offset = 0; offset < size; offset += 16) {
        memcpy(block, input + offset, sizeof(block));
        aes_cbc_decrypt_blocks(&native, counter, input + offset, 1, output + offset);
        memcpy(counter, block, sizeof(counter));
      }
    } else if (decrypt) aes_cbc_decrypt_blocks(&native, iv, input, size / 16, output);
    else aes_cbc_encrypt_blocks(&native, iv, input, size / 16, output);
  } else salts_crypto_clear(output, size);
  salts_crypto_clear(counter, sizeof(counter));
  salts_crypto_clear(block, sizeof(block));
  salts_crypto_clear(&native, sizeof(native));
  return ret == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
}
