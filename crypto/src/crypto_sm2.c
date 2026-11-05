#include <crypto/sm2.h>
#include "crypto_internal.h"
#include <gmssl/sm2.h>
#include <string.h>

static int import_private(SM2_KEY *key, const uint8_t raw[32]) {
  sm2_z256_t scalar;
  sm2_z256_from_bytes(scalar, raw);
  int ok = sm2_key_set_private_key(key, scalar);
  salts_crypto_secure_zero(scalar, sizeof(scalar));
  return ok == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EINVAL;
}

static int import_public(SM2_KEY *key, const uint8_t raw[65]) {
  if (raw[0] != 4u || sm2_z256_point_from_bytes(&key->public_key, raw + 1u) != 1)
    return SALTS_CRYPTO_EINVAL;
  return SALTS_CRYPTO_OK;
}

int salts_crypto_sm2_public_key(const uint8_t raw[32], uint8_t pub[65]) {
  SM2_KEY key = {0};
  if (!raw || !pub || salts_crypto_overlap(raw, 32u, pub, 65u)) return SALTS_CRYPTO_EINVAL;
  /* Public derivation admits the full group range, including exchange-only
   * scalar N-1. Signing still excludes it because (1+d)^-1 is undefined. */
  sm2_z256_from_bytes(key.private_key, raw);
  int status = SALTS_CRYPTO_EINVAL;
  if (!sm2_z256_is_zero(key.private_key) && sm2_z256_cmp(key.private_key, sm2_z256_order()) < 0) {
    sm2_z256_point_mul_generator(&key.public_key, key.private_key);
    status = sm2_z256_point_to_uncompressed_octets(&key.public_key, pub) == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
  }
  salts_crypto_secure_zero(&key, sizeof(key));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(pub, 65u);
  return status;
}

int salts_crypto_sm2_keygen(uint8_t raw[32], uint8_t pub[65]) {
  SM2_KEY key = {0};
  if (!raw || !pub || salts_crypto_overlap(raw, 32u, pub, 65u)) return SALTS_CRYPTO_EINVAL;
  int status = sm2_key_generate(&key) == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
  if (status == SALTS_CRYPTO_OK) {
    sm2_z256_to_bytes(key.private_key, raw);
    if (sm2_z256_point_to_uncompressed_octets(&key.public_key, pub) != 1)
      status = SALTS_CRYPTO_ECRYPTO;
  }
  salts_crypto_secure_zero(&key, sizeof(key));
  if (status != SALTS_CRYPTO_OK) {
    salts_crypto_secure_zero(raw, 32u);
    salts_crypto_secure_zero(pub, 65u);
  }
  return status;
}

static int message_valid(const void *id, size_t idn, const void *data, size_t n) {
  return id && idn >= 1u && idn <= SM2_MAX_ID_LENGTH &&
      (data || !n) && n <= UINT64_MAX / 8u - 32u;
}

static int message_digest(const SM2_KEY *key, const void *id, size_t idn,
    const void *data, size_t n, uint8_t digest[32]) {
  SM3_CTX hash;
  uint8_t z[32];
  if (sm2_compute_z(z, &key->public_key, id, idn) != 1) return SALTS_CRYPTO_ECRYPTO;
  sm3_init(&hash);
  sm3_update(&hash, z, sizeof(z));
  if (n) sm3_update(&hash, data, n);
  sm3_finish(&hash, digest);
  salts_crypto_secure_zero(z, sizeof(z));
  salts_crypto_secure_zero(&hash, sizeof(hash));
  return SALTS_CRYPTO_OK;
}

int salts_crypto_sm2_sign(const uint8_t raw[32], const void *id, size_t idn,
    const void *data, size_t n, uint8_t signature[64]) {
  SM2_KEY key = {0};
  SM2_SIGNATURE sig = {0};
  uint8_t digest[32] = {0};
  if (!raw || !signature || !message_valid(id, idn, data, n) ||
      salts_crypto_overlap(signature, 64u, raw, 32u) ||
      salts_crypto_overlap(signature, 64u, id, idn) ||
      salts_crypto_overlap(signature, 64u, data, n)) return SALTS_CRYPTO_EINVAL;
  int status = import_private(&key, raw);
  if (status == SALTS_CRYPTO_OK) status = message_digest(&key, id, idn, data, n, digest);
  if (status == SALTS_CRYPTO_OK && sm2_do_sign(&key, digest, &sig) != 1)
    status = SALTS_CRYPTO_ECRYPTO;
  if (status == SALTS_CRYPTO_OK) {
    memcpy(signature, sig.r, 32u); memcpy(signature + 32u, sig.s, 32u);
  } else salts_crypto_secure_zero(signature, 64u);
  salts_crypto_secure_zero(digest, sizeof(digest));
  salts_crypto_secure_zero(&sig, sizeof(sig));
  salts_crypto_secure_zero(&key, sizeof(key));
  return status;
}

int salts_crypto_sm2_verify(const uint8_t pub[65], const void *id, size_t idn,
    const void *data, size_t n, const uint8_t signature[64]) {
  SM2_KEY key = {0};
  SM2_SIGNATURE sig;
  uint8_t digest[32] = {0};
  if (!pub || !signature || !message_valid(id, idn, data, n)) return SALTS_CRYPTO_EINVAL;
  int status = import_public(&key, pub);
  if (status == SALTS_CRYPTO_OK) status = message_digest(&key, id, idn, data, n, digest);
  memcpy(sig.r, signature, 32u); memcpy(sig.s, signature + 32u, 32u);
  if (status == SALTS_CRYPTO_OK && sm2_do_verify(&key, digest, &sig) != 1)
    status = SALTS_CRYPTO_EVERIFY;
  salts_crypto_secure_zero(digest, sizeof(digest));
  salts_crypto_secure_zero(&key, sizeof(key));
  return status;
}

static int buffers_valid(const void *key, size_t kn, const void *in, size_t n,
    void *out, size_t bound, size_t cap, size_t *written) {
  return key && in && out && written && cap >= bound &&
      !salts_crypto_overlap(out, bound, key, kn) &&
      !salts_crypto_overlap(out, bound, in, n) &&
      !salts_crypto_overlap(written, sizeof(*written), key, kn) &&
      !salts_crypto_overlap(written, sizeof(*written), in, n) &&
      !salts_crypto_overlap(written, sizeof(*written), out, bound);
}

int salts_crypto_sm2_encrypt(const uint8_t pub[65], const void *in, size_t n,
    void *out, size_t cap, size_t *written) {
  SM2_KEY key = {0};
  uint8_t encrypted[SM2_MAX_CIPHERTEXT_SIZE];
  size_t size = 0;
  if (n < 1u || n > 255u || !buffers_valid(pub, 65u, in, n, out, 366u, cap, written))
    return SALTS_CRYPTO_EINVAL;
  int status = import_public(&key, pub);
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(&key, sizeof(key)); return status; }
  if (sm2_encrypt(&key, in, n, encrypted, &size) != 1 || size > sizeof(encrypted))
    status = SALTS_CRYPTO_ECRYPTO;
  if (status == SALTS_CRYPTO_OK) { memcpy(out, encrypted, size); *written = size; }
  else { salts_crypto_secure_zero(out, 366u); *written = 0; }
  salts_crypto_secure_zero(encrypted, sizeof(encrypted));
  salts_crypto_secure_zero(&key, sizeof(key));
  return status;
}

int salts_crypto_sm2_decrypt(const uint8_t raw[32], const void *in, size_t n,
    void *out, size_t cap, size_t *written) {
  SM2_KEY key = {0};
  SM2_CIPHERTEXT cipher = {0};
  uint8_t plaintext[255] = {0}, canonical[366];
  const uint8_t *cursor = in;
  uint8_t *encoded = canonical;
  size_t remaining = n, encoded_size = 0, size = 0;
  if (!n || n > 366u || !buffers_valid(raw, 32u, in, n, out, 255u, cap, written))
    return SALTS_CRYPTO_EINVAL;
  int status = import_private(&key, raw);
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(&key, sizeof(key)); return status; }
  if (sm2_ciphertext_from_der(&cipher, &cursor, &remaining) != 1 || remaining ||
      sm2_ciphertext_to_der(&cipher, &encoded, &encoded_size) != 1 ||
      encoded_size != n || memcmp(canonical, in, n) != 0 ||
      sm2_do_decrypt(&key, &cipher, plaintext, &size) != 1 || size < 1u || size > sizeof(plaintext))
    status = SALTS_CRYPTO_EVERIFY;
  if (status == SALTS_CRYPTO_OK) { memcpy(out, plaintext, size); *written = size; }
  else { salts_crypto_secure_zero(out, 255u); *written = 0; }
  salts_crypto_secure_zero(plaintext, sizeof(plaintext));
  salts_crypto_secure_zero(&key, sizeof(key));
  return status;
}
