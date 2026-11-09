#include <crypto/sm2_keys.h>
#include <crypto/sm2.h>
#include <crypto/sm3.h>
#include <crypto/sm4.h>
#include <salts/asn1.h>
#include <gmssl/sm2.h>
#include <gmssl/rand.h>
#include <gmssl/aes.h>
#include <gmssl/pbkdf2.h>
#include "crypto_internal.h"
#include <string.h>

static const uint8_t ec_oid[] = {0x2a,0x86,0x48,0xce,0x3d,2,1};
static const uint8_t sm2_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x82,0x2d};
static const uint8_t pbes2_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,13};
static const uint8_t pbkdf2_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,12};
static const uint8_t hmac_sm3_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x83,0x11,2};
static const uint8_t sm4_cbc_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x68,2};
static const uint8_t hmac_sha256_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,2,9};
static const uint8_t aes256_cbc_oid[] = {0x60,0x86,0x48,1,0x65,3,4,1,42};

/* Format composition only; all tag/length/DER validation has one ASN1 owner. */
typedef struct der_writer { uint8_t data[320]; size_t size; int failed; } der_writer;
static void put(der_writer *w, uint8_t cls, uint8_t constructed, uint32_t tag,
    const void *data, size_t n) {
  size_t added = 0;
  if (w->failed) return;
  if (asn1_encode_tlv(cls, constructed, tag, data, n, SALTS_ASN1_DER, 0,
      w->data + w->size, sizeof(w->data) - w->size, &added) != SALTS_ASN1_OK)
    w->failed = 1;
  else w->size += added;
}
static void sequence(der_writer *w, const der_writer *child) {
  if (child->failed) w->failed = 1;
  else put(w, 0, 1, 16, child->data, child->size);
}
static void integer(der_writer *w, uint32_t value) {
  uint8_t bytes[5] = {0, (uint8_t)(value >> 24), (uint8_t)(value >> 16),
      (uint8_t)(value >> 8), (uint8_t)value};
  size_t i = 0;
  while (i < 4u && bytes[i] == 0u && (bytes[i+1u] & 0x80u) == 0u) ++i;
  put(w, 0, 0, 2, bytes+i, sizeof(bytes)-i);
}
#define oid(w, name) put(w, 0, 0, 6, name, sizeof(name))
static int take(asn1_reader *r, uint8_t cls, uint8_t constructed,
    uint32_t tag, asn1_tlv *v) {
  return asn1_reader_next(r, v) == SALTS_ASN1_OK &&
      v->tag_class == cls && v->constructed == constructed && v->tag_number == tag;
}
static int end(const asn1_reader *r) { return r->offset == r->size; }
static int children(asn1_reader *r, const asn1_tlv *v) {
  return asn1_reader_init(r, v->content, v->content_size, SALTS_ASN1_DER) == SALTS_ASN1_OK;
}
static int enter(asn1_reader *parent, asn1_reader *child) {
  asn1_tlv v;
  return take(parent, 0, 1, 16, &v) && children(child, &v);
}
static int root(const void *data, size_t n, asn1_reader *child) {
  asn1_reader r;
  return asn1_reader_init(&r, data, n, SALTS_ASN1_DER) == SALTS_ASN1_OK &&
      enter(&r, child) && end(&r);
}
static int match_oid(asn1_reader *r, const uint8_t *bytes, size_t n) {
  asn1_tlv v;
  return take(r, 0, 0, 6, &v) && v.content_size == n && memcmp(v.content, bytes, n) == 0;
}
#define match(r, name) match_oid(r, name, sizeof(name))
static int number(asn1_reader *r, uint32_t *out) {
  asn1_tlv v; uint32_t value = 0;
  if (!take(r, 0, 0, 2, &v) || !v.content_size || v.content_size > 4u ||
      (v.content[0] & 0x80u)) return 0;
  for (size_t i = 0; i < v.content_size; ++i) value = (value << 8) | v.content[i];
  *out = value;
  return 1;
}
static int ec_algorithm(asn1_reader *r) {
  asn1_reader alg;
  return enter(r, &alg) && match(&alg, ec_oid) && match(&alg, sm2_oid) && end(&alg);
}
static int valid_public(const uint8_t pub[65]) {
  SM2_Z256_POINT point; uint8_t canonical[65];
  return pub[0] == 4u && sm2_z256_point_from_octets(&point, pub, 65u) == 1 &&
      !sm2_z256_point_is_at_infinity(&point) &&
      sm2_z256_point_to_uncompressed_octets(&point, canonical) == 1 &&
      memcmp(canonical, pub, 65u) == 0;
}
static int export_args(const void *in, size_t n, void *out, size_t cap,
    size_t required, size_t *written) {
  return in && out && written && cap >= required &&
      !salts_crypto_overlap(in, n, out, required) &&
      !salts_crypto_overlap(in, n, written, sizeof(*written)) &&
      !salts_crypto_overlap(out, required, written, sizeof(*written));
}
static int import_args(const void *in, size_t n, size_t max, void *out, size_t on) {
  return in && n && n <= max && out && !salts_crypto_overlap(in, n, out, on);
}
static int finish_export(int status, const der_writer *w, void *out, size_t max, size_t *written) {
  if (status == SALTS_CRYPTO_OK && (w->failed || w->size > max)) status = SALTS_CRYPTO_ECRYPTO;
  if (status == SALTS_CRYPTO_OK) { memcpy(out, w->data, w->size); *written = w->size; }
  else { salts_crypto_secure_zero(out, max); *written = 0; }
  return status;
}
static void write_algorithm(der_writer *w) {
  der_writer alg = {0};
  oid(&alg, ec_oid); oid(&alg, sm2_oid); sequence(w, &alg);
}

int salts_crypto_sm2_spki_export(const uint8_t pub[65], void *out, size_t cap, size_t *written) {
  der_writer body = {0}, result = {0}; uint8_t bits[66] = {0};
  if (!export_args(pub, 65, out, cap, 91, written)) return SALTS_CRYPTO_EINVAL;
  int status = valid_public(pub) ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
  if (status == SALTS_CRYPTO_OK) {
    write_algorithm(&body); memcpy(bits+1, pub, 65); put(&body, 0, 0, 3, bits, sizeof(bits));
    sequence(&result, &body);
  }
  return finish_export(status, &result, out, 91, written);
}
int salts_crypto_sm2_spki_import(const void *der, size_t n, uint8_t pub[65]) {
  asn1_reader r; asn1_tlv v;
  if (!import_args(der, n, 91, pub, 65)) return SALTS_CRYPTO_EINVAL;
  if (!root(der, n, &r) || !ec_algorithm(&r) || !take(&r, 0, 0, 3, &v) ||
      v.content_size != 66u || v.content[0] != 0u || !end(&r) || !valid_public(v.content+1)) {
    salts_crypto_secure_zero(pub, 65); return SALTS_CRYPTO_EVERIFY;
  }
  memcpy(pub, v.content+1, 65); return SALTS_CRYPTO_OK;
}

static int write_private(const uint8_t key[32], der_writer *result) {
  der_writer ec = {0}, named = {0}, public_bits = {0}, encoded_ec = {0}, body = {0};
  uint8_t bits[66] = {0};
  int status = salts_crypto_sm2_public_key(key, bits+1);
  if (status != SALTS_CRYPTO_OK) { status = SALTS_CRYPTO_EVERIFY; goto done; }
  integer(&ec, 1); put(&ec, 0, 0, 4, key, 32);
  oid(&named, sm2_oid); put(&ec, 2, 1, 0, named.data, named.size);
  put(&public_bits, 0, 0, 3, bits, sizeof(bits));
  put(&ec, 2, 1, 1, public_bits.data, public_bits.size);
  sequence(&encoded_ec, &ec);
  integer(&body, 0); write_algorithm(&body);
  put(&body, 0, 0, 4, encoded_ec.data, encoded_ec.size);
  sequence(result, &body);
  if (ec.failed || named.failed || public_bits.failed || encoded_ec.failed || body.failed || result->failed)
    status = SALTS_CRYPTO_ECRYPTO;
done:
  salts_crypto_secure_zero(&ec, sizeof(ec)); salts_crypto_secure_zero(&encoded_ec, sizeof(encoded_ec));
  salts_crypto_secure_zero(&body, sizeof(body));
  return status;
}
static int read_private(const void *der, size_t n, uint8_t key[32]) {
  asn1_reader r, ec, opt; asn1_tlv v, secret; uint32_t version;
  uint8_t pub[65] = {0}; int ok = 0;
  if (!root(der, n, &r) || !number(&r, &version) || version != 0u || !ec_algorithm(&r) ||
      !take(&r, 0, 0, 4, &v) || !end(&r) || !root(v.content, v.content_size, &ec) ||
      !number(&ec, &version) || version != 1u || !take(&ec, 0, 0, 4, &secret) ||
      secret.content_size != 32u) goto done;
  if (salts_crypto_sm2_public_key(secret.content, pub) != SALTS_CRYPTO_OK) goto done;
  if (!end(&ec)) {
    if (asn1_reader_next(&ec, &v) != SALTS_ASN1_OK) goto done;
    if (v.tag_class == 2u && v.constructed && v.tag_number == 0u) {
      if (!children(&opt, &v) || !match(&opt, sm2_oid) || !end(&opt)) goto done;
      if (end(&ec)) { ok = 1; goto done; }
      if (asn1_reader_next(&ec, &v) != SALTS_ASN1_OK) goto done;
    }
    if (v.tag_class != 2u || !v.constructed || v.tag_number != 1u ||
        !children(&opt, &v) || !take(&opt, 0, 0, 3, &v) || v.content_size != 66u ||
        v.content[0] != 0u || memcmp(v.content+1, pub, 65u) || !end(&opt) || !end(&ec)) goto done;
  }
  ok = 1;
done:
  if (ok) memcpy(key, secret.content, 32);
  salts_crypto_secure_zero(pub, sizeof(pub));
  return ok ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
}
int salts_crypto_sm2_pkcs8_export(const uint8_t key[32], void *out, size_t cap, size_t *written) {
  der_writer result = {0};
  if (!export_args(key, 32, out, cap, 150, written)) return SALTS_CRYPTO_EINVAL;
  int status = write_private(key, &result);
  status = finish_export(status, &result, out, 150, written);
  salts_crypto_secure_zero(&result, sizeof(result)); return status;
}
int salts_crypto_sm2_pkcs8_import(const void *der, size_t n, uint8_t key[32]) {
  if (!import_args(der, n, 150, key, 32)) return SALTS_CRYPTO_EINVAL;
  int status = read_private(der, n, key);
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(key, 32);
  return status;
}

static int password_valid(const void *password, size_t n, uint32_t iterations) {
  return password && n >= 1u && n <= SALTS_CRYPTO_SM2_KEY_PASSWORD_MAX_SIZE &&
      iterations >= SALTS_CRYPTO_SM2_KEY_ITERATIONS_MIN && iterations <= SALTS_CRYPTO_SM2_KEY_ITERATIONS_MAX;
}
static void write_encrypted(der_writer *result, const uint8_t salt[16], uint32_t iterations,
    const uint8_t iv[16], const uint8_t ciphertext[160], int aes) {
  der_writer prf = {0}, params = {0}, kdf = {0}, scheme = {0}, pair = {0}, alg = {0}, body = {0};
  put(&params, 0, 0, 4, salt, 16); integer(&params, iterations); integer(&params, aes ? 32u : 16u);
  if (aes) { oid(&prf, hmac_sha256_oid); put(&prf, 0, 0, 5, NULL, 0); }
  else oid(&prf, hmac_sm3_oid);
  sequence(&params, &prf);
  oid(&kdf, pbkdf2_oid); sequence(&kdf, &params);
  if (aes) oid(&scheme, aes256_cbc_oid);
  else oid(&scheme, sm4_cbc_oid);
  put(&scheme, 0, 0, 4, iv, 16);
  sequence(&pair, &kdf); sequence(&pair, &scheme);
  oid(&alg, pbes2_oid); sequence(&alg, &pair);
  sequence(&body, &alg); put(&body, 0, 0, 4, ciphertext, 160);
  sequence(result, &body);
}
typedef struct encrypted_view {
  const uint8_t *salt, *iv, *ciphertext;
  size_t salt_size, ciphertext_size;
  uint32_t iterations;
} encrypted_view;
static int read_encrypted(const void *der, size_t n, uint32_t max, int aes, encrypted_view *out) {
  asn1_reader r, alg, pair, kdf, params, prf, scheme; asn1_tlv v; uint32_t key_size;
  if (!root(der, n, &r) || !enter(&r, &alg) || !match(&alg, pbes2_oid) ||
      !enter(&alg, &pair) || !end(&alg) || !enter(&pair, &kdf) || !match(&kdf, pbkdf2_oid) ||
      !enter(&kdf, &params) || !end(&kdf) || !take(&params, 0, 0, 4, &v) ||
      v.content_size < 16u || v.content_size > 64u) return 0;
  out->salt = v.content; out->salt_size = v.content_size;
  if (!number(&params, &out->iterations) || out->iterations < SALTS_CRYPTO_SM2_KEY_ITERATIONS_MIN ||
      out->iterations > max) return 0;
  asn1_reader probe = params;
  if (number(&probe, &key_size)) {
    if (key_size != (aes ? 32u : 16u)) return 0;
    params = probe;
  }
  /* Absent PRF is HMAC-SHA1, never one of our explicitly selected profiles. */
  if (!enter(&params, &prf) ||
      !(aes ? match(&prf, hmac_sha256_oid) : match(&prf, hmac_sm3_oid)) || !end(&params)) return 0;
  if (!end(&prf) && (!take(&prf, 0, 0, 5, &v) || v.content_size)) return 0;
  if (!end(&prf) || !enter(&pair, &scheme) || !end(&pair) ||
      !(aes ? match(&scheme, aes256_cbc_oid) : match(&scheme, sm4_cbc_oid)) ||
      !take(&scheme, 0, 0, 4, &v) || v.content_size != 16u || !end(&scheme)) return 0;
  out->iv = v.content;
  if (!take(&r, 0, 0, 4, &v) || !end(&r) || v.content_size < 16u ||
      v.content_size > 160u || v.content_size % 16u) return 0;
  out->ciphertext = v.content; out->ciphertext_size = v.content_size;
  return 1;
}
static int derive_password(const void *password, size_t pn, const uint8_t *salt, size_t sn,
    uint32_t iterations, int aes, uint8_t derived[32]) {
  if (aes) return pbkdf2_hmac_genkey(DIGEST_sha256(), password, pn, salt, sn,
      iterations, 32u, derived) == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
  return salts_crypto_pbkdf2_sm3(password, pn, salt, sn, iterations, derived, 16u);
}
/* Both finite profiles share admission, canonical DER, padding and secret
 * cleanup. Only the selected KDF/cipher changes; there is no trial dispatch. */
static int crypt_blocks(int aes, int decrypt, const uint8_t derived[32], const uint8_t iv[16],
    const uint8_t *in, size_t n, uint8_t *out) {
  if (!aes) return salts_crypto_sm4_crypt(SALTS_CRYPTO_SM4_CBC, decrypt, derived, 16u,
      iv, in, n, out, n);
  AES_KEY key = {0};
  int status = SALTS_CRYPTO_ECRYPTO;
  if (decrypt ? aes_set_decrypt_key(&key, derived, 32u) == 1 :
      aes_set_encrypt_key(&key, derived, 32u) == 1) {
    if (decrypt) aes_cbc_decrypt_blocks(&key, iv, in, n / 16u, out);
    else aes_cbc_encrypt_blocks(&key, iv, in, n / 16u, out);
    status = SALTS_CRYPTO_OK;
  }
  salts_crypto_secure_zero(&key, sizeof(key));
  return status;
}
static int encrypt_private(const uint8_t key[32], const void *password, size_t pn,
    uint32_t iterations, void *out, size_t cap, size_t *written, int aes) {
  der_writer plain = {0}, result = {0};
  uint8_t salt[16] = {0}, iv[16] = {0}, derived[32] = {0}, ciphertext[160] = {0};
  if (!export_args(key, 32, out, cap, 320, written) || !password_valid(password, pn, iterations) ||
      salts_crypto_overlap(password, pn, out, 320) || salts_crypto_overlap(password, pn, written, sizeof(*written)))
    return SALTS_CRYPTO_EINVAL;
  int status = write_private(key, &plain);
  if (status != SALTS_CRYPTO_OK) goto done;
  if (plain.size != 150u) { status = SALTS_CRYPTO_ECRYPTO; goto done; }
  if (rand_bytes(salt, sizeof(salt)) != 1 || rand_bytes(iv, sizeof(iv)) != 1) {
    status = SALTS_CRYPTO_ERANDOM; goto done;
  }
  status = derive_password(password, pn, salt, sizeof(salt), iterations, aes, derived);
  if (status != SALTS_CRYPTO_OK) goto done;
  memset(plain.data+plain.size, 10, 10); /* 150-byte key, full PKCS#7 block padding. */
  status = crypt_blocks(aes, 0, derived, iv, plain.data, 160u, ciphertext);
  if (status == SALTS_CRYPTO_OK) write_encrypted(&result, salt, iterations, iv, ciphertext, aes);
done:
  status = finish_export(status, &result, out, 320, written);
  salts_crypto_secure_zero(&plain, sizeof(plain)); salts_crypto_secure_zero(derived, sizeof(derived));
  return status;
}
static int decrypt_private(const void *der, size_t n, const void *password, size_t pn,
    uint32_t max_iterations, uint8_t key[32], int aes) {
  encrypted_view view = {0}; uint8_t derived[32] = {0}, plain[160] = {0};
  int status = SALTS_CRYPTO_EVERIFY;
  if (!import_args(der, n, 320, key, 32) || !password_valid(password, pn, max_iterations) ||
      salts_crypto_overlap(password, pn, key, 32)) return SALTS_CRYPTO_EINVAL;
  if (!read_encrypted(der, n, max_iterations, aes, &view)) goto done;
  status = derive_password(password, pn, view.salt, view.salt_size, view.iterations, aes, derived);
  if (status != SALTS_CRYPTO_OK) goto done;
  status = crypt_blocks(aes, 1, derived, view.iv, view.ciphertext, view.ciphertext_size, plain);
  if (status != SALTS_CRYPTO_OK) goto done;
  unsigned padding = plain[view.ciphertext_size-1u], bad = (padding == 0u || padding > 16u);
  for (size_t i = 0; i < 16u; ++i)
    bad |= (unsigned)(i < padding) * (unsigned)(plain[view.ciphertext_size-1u-i] ^ padding);
  status = SALTS_CRYPTO_EVERIFY;
  if (!bad && view.ciphertext_size-padding <= 150u)
    status = read_private(plain, view.ciphertext_size-padding, key);
done:
  salts_crypto_secure_zero(derived, sizeof(derived)); salts_crypto_secure_zero(plain, sizeof(plain));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(key, 32);
  return status;
}

int salts_crypto_sm2_pkcs8_encrypt(const uint8_t key[32], const void *password, size_t pn,
    uint32_t iterations, void *out, size_t cap, size_t *written) {
  return encrypt_private(key, password, pn, iterations, out, cap, written, 0);
}
int salts_crypto_sm2_pkcs8_decrypt(const void *der, size_t n, const void *password, size_t pn,
    uint32_t max_iterations, uint8_t key[32]) {
  return decrypt_private(der, n, password, pn, max_iterations, key, 0);
}
int salts_crypto_sm2_pkcs8_aes256_encrypt(const uint8_t key[32], const void *password, size_t pn,
    uint32_t iterations, void *out, size_t cap, size_t *written) {
  return encrypt_private(key, password, pn, iterations, out, cap, written, 1);
}
int salts_crypto_sm2_pkcs8_aes256_decrypt(const void *der, size_t n, const void *password, size_t pn,
    uint32_t max_iterations, uint8_t key[32]) {
  return decrypt_private(der, n, password, pn, max_iterations, key, 1);
}
