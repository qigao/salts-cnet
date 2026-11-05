#include <crypto/zuc.h>
#include "crypto_internal.h"
#include <gmssl/zuc.h>

static int key_valid(salts_crypto_zuc_variant variant,
    const void *key, size_t kn, const void *iv, size_t ivn) {
  return key && iv && ((variant == SALTS_CRYPTO_ZUC128 && kn == 16u && ivn == 16u) ||
      (variant == SALTS_CRYPTO_ZUC256 && kn == 32u && ivn == 23u));
}

int salts_crypto_zuc_crypt(salts_crypto_zuc_variant variant,
    const void *key, size_t kn, const void *iv, size_t ivn,
    const void *in, size_t n, void *out, size_t cap) {
  ZUC_STATE state;
  if (!key_valid(variant, key, kn, iv, ivn) || n > 8188u || (!in && n) ||
      (!out && n) || cap < n || salts_crypto_overlap(out, n, key, kn) ||
      salts_crypto_overlap(out, n, iv, ivn) || salts_crypto_overlap(out, n, in, n))
    return SALTS_CRYPTO_EINVAL;
  if (!n) return SALTS_CRYPTO_OK;
  if (variant == SALTS_CRYPTO_ZUC128) zuc_init(&state, key, iv);
  else zuc256_init(&state, key, iv);
  for (size_t offset = 0; offset < n; offset += 4u) {
    uint32_t word = zuc_generate_keyword(&state);
    for (size_t i = 0; i < 4u && offset + i < n; ++i)
      ((uint8_t *)out)[offset + i] = ((const uint8_t *)in)[offset + i] ^
          (uint8_t)(word >> (24u - 8u*i));
    salts_crypto_secure_zero(&word, sizeof(word));
  }
  salts_crypto_secure_zero(&state, sizeof(state));
  return SALTS_CRYPTO_OK;
}

int salts_crypto_zuc_mac(salts_crypto_zuc_variant variant,
    const void *key, size_t kn, const void *iv, size_t ivn,
    const void *in, size_t bits, void *tag, size_t tn) {
  if (!key_valid(variant, key, kn, iv, ivn) || bits > 65504u || (!in && bits) || !tag ||
      (tn != 4u && (variant != SALTS_CRYPTO_ZUC256 || (tn != 8u && tn != 16u))) ||
      salts_crypto_overlap(tag, tn, key, kn) || salts_crypto_overlap(tag, tn, iv, ivn) ||
      salts_crypto_overlap(tag, tn, in, (bits + 7u) / 8u)) return SALTS_CRYPTO_EINVAL;
  const size_t bytes = bits / 8u;
  const uint8_t *tail = in ? (const uint8_t *)in + bytes : NULL;
  if (variant == SALTS_CRYPTO_ZUC128) {
    ZUC_MAC_CTX ctx;
    zuc_mac_init(&ctx, key, iv);
    if (bytes) zuc_mac_update(&ctx, in, bytes);
    zuc_mac_finish(&ctx, tail, bits % 8u, tag);
    salts_crypto_secure_zero(&ctx, sizeof(ctx));
  } else {
    ZUC256_MAC_CTX ctx;
    zuc256_mac_init(&ctx, key, iv, (int)(tn * 8u));
    if (bytes) zuc256_mac_update(&ctx, in, bytes);
    zuc256_mac_finish(&ctx, tail, bits % 8u, tag);
    salts_crypto_secure_zero(&ctx, sizeof(ctx));
  }
  return SALTS_CRYPTO_OK;
}

int salts_crypto_zuc_verify(salts_crypto_zuc_variant variant,
    const void *key, size_t kn, const void *iv, size_t ivn,
    const void *in, size_t bits, const void *tag, size_t tn) {
  uint8_t expected[16];
  unsigned different = 0;
  if (!tag || tn > sizeof(expected)) return SALTS_CRYPTO_EINVAL;
  int status = salts_crypto_zuc_mac(variant, key, kn, iv, ivn, in, bits, expected, tn);
  if (status == SALTS_CRYPTO_OK) {
    for (size_t i = 0; i < tn; ++i) different |= expected[i] ^ ((const uint8_t *)tag)[i];
    if (different) status = SALTS_CRYPTO_EVERIFY;
  }
  salts_crypto_secure_zero(expected, sizeof(expected));
  return status;
}
