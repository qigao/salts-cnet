#include <crypto/sm4.h>
#include "crypto_internal.h"
#include <gmssl/sm4.h>
#include <string.h>

int salts_crypto_sm4_crypt(salts_crypto_sm4_mode mode, int decrypt,
    const void *raw, size_t kn, const uint8_t iv[16],
    const void *in, size_t n, void *out, size_t cap) {
  SM4_KEY key, tweak;
  uint8_t counter[16] = {0};
  int ok = 1;
  if (mode < SALTS_CRYPTO_SM4_ECB || mode > SALTS_CRYPTO_SM4_XTS ||
      (decrypt != 0 && decrypt != 1) || !raw ||
      kn != (mode == SALTS_CRYPTO_SM4_XTS ? 32u : 16u) ||
      (mode == SALTS_CRYPTO_SM4_ECB ? iv != NULL : iv == NULL) ||
      (!in && n) || (!out && n) || cap < n ||
      salts_crypto_overlap(out, n, in, n) || salts_crypto_overlap(out, n, raw, kn) ||
      salts_crypto_overlap(out, n, iv, iv ? 16u : 0u) ||
      ((mode == SALTS_CRYPTO_SM4_ECB || mode == SALTS_CRYPTO_SM4_CBC) && n % 16u) ||
      (mode == SALTS_CRYPTO_SM4_XTS && (n < 16u || n > 16777216u)))
    return SALTS_CRYPTO_EINVAL;
  if (mode == SALTS_CRYPTO_SM4_XTS) {
    unsigned different = 0u;
    for (size_t i = 0; i < 16u; ++i)
      different |= ((const uint8_t *)raw)[i] ^ ((const uint8_t *)raw)[16u + i];
    if (!different) return SALTS_CRYPTO_EINVAL;
  }
  if (!n) return SALTS_CRYPTO_OK;
  if (mode == SALTS_CRYPTO_SM4_CTR) {
    size_t carry = n / 16u + (n % 16u != 0u) - 1u;
    for (size_t i = 16u; i > 0u; --i) {
      const unsigned sum = iv[i - 1u] + (unsigned)(carry & 255u);
      carry = (carry >> 8u) + (sum >> 8u);
    }
    if (carry) return SALTS_CRYPTO_EINVAL;
  }
  if (iv) memcpy(counter, iv, sizeof(counter));
  if (decrypt && (mode == SALTS_CRYPTO_SM4_ECB || mode == SALTS_CRYPTO_SM4_CBC || mode == SALTS_CRYPTO_SM4_XTS))
    sm4_set_decrypt_key(&key, raw);
  else sm4_set_encrypt_key(&key, raw);
  switch (mode) {
    case SALTS_CRYPTO_SM4_ECB:
      sm4_encrypt_blocks(&key, in, n / 16u, out); break;
    case SALTS_CRYPTO_SM4_CBC:
      if (decrypt) sm4_cbc_decrypt_blocks(&key, counter, in, n / 16u, out);
      else sm4_cbc_encrypt_blocks(&key, counter, in, n / 16u, out);
      break;
    case SALTS_CRYPTO_SM4_CTR: sm4_ctr_encrypt(&key, counter, in, n, out); break;
    case SALTS_CRYPTO_SM4_OFB: sm4_ofb_encrypt(&key, counter, in, n, out); break;
    case SALTS_CRYPTO_SM4_CFB8:
    case SALTS_CRYPTO_SM4_CFB64:
    case SALTS_CRYPTO_SM4_CFB128: {
      size_t segment = mode == SALTS_CRYPTO_SM4_CFB8 ? 1u : mode == SALTS_CRYPTO_SM4_CFB64 ? 8u : 16u;
      if (decrypt) sm4_cfb_decrypt(&key, segment, counter, in, n, out);
      else sm4_cfb_encrypt(&key, segment, counter, in, n, out);
      break;
    }
    case SALTS_CRYPTO_SM4_XTS:
      sm4_set_encrypt_key(&tweak, (const uint8_t *)raw + 16u);
      ok = decrypt ? sm4_xts_decrypt(&key, &tweak, iv, in, n, out)
                   : sm4_xts_encrypt(&key, &tweak, iv, in, n, out);
      salts_crypto_secure_zero(&tweak, sizeof(tweak));
      break;
    default: ok = -1; break;
  }
  salts_crypto_secure_zero(&key, sizeof(key));
  salts_crypto_secure_zero(counter, sizeof(counter));
  if (ok != 1) { salts_crypto_secure_zero(out, n); return SALTS_CRYPTO_ECRYPTO; }
  return SALTS_CRYPTO_OK;
}

static int aead_valid(salts_crypto_sm4_aead mode, const uint8_t *key,
    const void *nonce, size_t nn, const void *aad, size_t an,
    const void *in, size_t n, const void *tag, size_t tn, void *out, size_t cap) {
  if (!key || !nonce || (!aad && an) || (!in && n) || !tag || (!out && n) || cap < n ||
      salts_crypto_overlap(out, n, key, 16u) || salts_crypto_overlap(out, n, nonce, nn) ||
      salts_crypto_overlap(out, n, aad, an) || salts_crypto_overlap(out, n, in, n) ||
      salts_crypto_overlap(out, n, tag, tn)) return 0;
  if (mode == SALTS_CRYPTO_SM4_GCM)
    return nn >= 1u && nn <= 64u && tn >= 12u && tn <= 16u &&
        an <= (1u << 24u) && (uint64_t)n <= SM4_GCM_MAX_PLAINTEXT_SIZE;
  if (mode != SALTS_CRYPTO_SM4_CCM || nn < 7u || nn > 13u ||
      tn < 4u || tn > 16u || tn % 2u || an > (1u << 24u)) return 0;
  const unsigned bits = (unsigned)(15u - nn) * 8u;
  return bits == 64u || (uint64_t)n < (UINT64_C(1) << bits);
}

int salts_crypto_sm4_aead_encrypt(salts_crypto_sm4_aead mode,
    const uint8_t raw[16], const void *nonce, size_t nn, const void *aad, size_t an,
    const void *in, size_t n, void *out, size_t cap, void *tag, size_t tn) {
  SM4_KEY key;
  uint8_t empty = 0;
  if (!aead_valid(mode, raw, nonce, nn, aad, an, in, n, tag, tn, out, cap) ||
      salts_crypto_overlap(tag, tn, raw, 16u) || salts_crypto_overlap(tag, tn, nonce, nn) ||
      salts_crypto_overlap(tag, tn, aad, an) || salts_crypto_overlap(tag, tn, in, n))
    return SALTS_CRYPTO_EINVAL;
  sm4_set_encrypt_key(&key, raw);
  int ok = mode == SALTS_CRYPTO_SM4_GCM
      ? sm4_gcm_encrypt(&key, nonce, nn, aad, an, in, n, out ? out : &empty, tn, tag)
      : sm4_ccm_encrypt(&key, nonce, nn, aad, an, in, n, out ? out : &empty, tn, tag);
  salts_crypto_secure_zero(&key, sizeof(key));
  if (ok != 1) {
    salts_crypto_secure_zero(out, n); salts_crypto_secure_zero(tag, tn);
    return SALTS_CRYPTO_ECRYPTO;
  }
  return SALTS_CRYPTO_OK;
}

int salts_crypto_sm4_aead_decrypt(salts_crypto_sm4_aead mode,
    const uint8_t raw[16], const void *nonce, size_t nn, const void *aad, size_t an,
    const void *in, size_t n, const void *tag, size_t tn, void *out, size_t cap) {
  SM4_KEY key;
  uint8_t empty = 0;
  if (!aead_valid(mode, raw, nonce, nn, aad, an, in, n, tag, tn, out, cap))
    return SALTS_CRYPTO_EINVAL;
  sm4_set_encrypt_key(&key, raw);
  int ok = mode == SALTS_CRYPTO_SM4_GCM
      ? sm4_gcm_decrypt(&key, nonce, nn, aad, an, in, n, tag, tn, out ? out : &empty)
      : sm4_ccm_decrypt(&key, nonce, nn, aad, an, in, n, tag, tn, out ? out : &empty);
  salts_crypto_secure_zero(&key, sizeof(key));
  if (ok != 1) { salts_crypto_secure_zero(out, n); return SALTS_CRYPTO_EVERIFY; }
  return SALTS_CRYPTO_OK;
}
