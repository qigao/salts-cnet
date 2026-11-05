#include <crypto/sm9.h>
#include <crypto/sm3.h>
#include <asn1.h>
#include "crypto_internal.h"
#include <gmssl/sm9.h>
#include <string.h>

static int id_valid(const void *id, size_t n) {
  return id && n && n <= SALTS_CRYPTO_SM9_ID_MAX_SIZE;
}
static int scalar_import(sm9_z256_t scalar, const uint8_t raw[32]) {
  sm9_z256_from_bytes(scalar, raw);
  return !sm9_z256_is_zero(scalar) && sm9_z256_cmp(scalar, sm9_z256_order()) < 0;
}
static int g1_import(SM9_Z256_POINT *point, const uint8_t raw[65]) {
  SM9_Z256_POINT multiple;
  if (sm9_z256_point_from_uncompressed_octets(point, raw) != 1 ||
      sm9_z256_point_is_at_infinity(point)) return 0;
  sm9_z256_point_mul(&multiple, sm9_z256_order(), point);
  int ok = sm9_z256_point_is_at_infinity(&multiple);
  salts_crypto_secure_zero(&multiple, sizeof(multiple));
  return ok;
}
static int g2_import(SM9_Z256_TWIST_POINT *point, const uint8_t raw[129]) {
  SM9_Z256_TWIST_POINT multiple;
  if (sm9_z256_twist_point_from_uncompressed_octets(point, raw) != 1 ||
      sm9_z256_twist_point_is_at_infinity(point)) return 0;
  sm9_z256_twist_point_mul(&multiple, sm9_z256_order(), point);
  int ok = sm9_z256_twist_point_is_at_infinity(&multiple);
  salts_crypto_secure_zero(&multiple, sizeof(multiple));
  return ok;
}
static size_t public_size(salts_crypto_sm9_purpose purpose) {
  return purpose == SALTS_CRYPTO_SM9_SIGN ? 129u : purpose == SALTS_CRYPTO_SM9_ENCRYPT ? 65u : 0u;
}
static int sign_master(SM9_SIGN_MASTER_KEY *key, const uint8_t raw[32]) {
  if (!scalar_import(key->ks, raw)) return 0;
  sm9_z256_twist_point_mul_generator(&key->Ppubs, key->ks);
  return 1;
}
static int enc_master(SM9_ENC_MASTER_KEY *key, const uint8_t raw[32]) {
  if (!scalar_import(key->ke, raw)) return 0;
  sm9_z256_point_mul_generator(&key->Ppube, key->ke);
  return 1;
}
static int enc_key_import(SM9_ENC_KEY *key, const salts_crypto_sm9_enc_key *raw) {
  return g2_import(&key->de, raw->private_point) && g1_import(&key->Ppube, raw->master_public);
}

int salts_crypto_sm9_master_public(salts_crypto_sm9_purpose purpose,
    const uint8_t raw[32], void *pub, size_t cap) {
  size_t n = public_size(purpose);
  int ok;
  if (!n || !raw || !pub || cap < n || salts_crypto_overlap(pub, n, raw, 32u))
    return SALTS_CRYPTO_EINVAL;
  if (purpose == SALTS_CRYPTO_SM9_SIGN) {
    SM9_SIGN_MASTER_KEY key = {0};
    ok = sign_master(&key, raw) && sm9_z256_twist_point_to_uncompressed_octets(&key.Ppubs, pub) == 1;
    salts_crypto_secure_zero(&key, sizeof(key));
  } else {
    SM9_ENC_MASTER_KEY key = {0};
    ok = enc_master(&key, raw) && sm9_z256_point_to_uncompressed_octets(&key.Ppube, pub) == 1;
    salts_crypto_secure_zero(&key, sizeof(key));
  }
  if (!ok) salts_crypto_secure_zero(pub, n);
  return ok ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EINVAL;
}

int salts_crypto_sm9_master_generate(salts_crypto_sm9_purpose purpose,
    uint8_t raw[32], void *pub, size_t cap) {
  uint8_t candidate[32];
  sm9_z256_t scalar;
  const size_t n = public_size(purpose);
  int status = SALTS_CRYPTO_ERANDOM;
  if (!n || !raw || !pub || cap < n || salts_crypto_overlap(pub, n, raw, 32u))
    return SALTS_CRYPTO_EINVAL;
  for (unsigned attempt = 0; attempt < 128u; ++attempt) {
    if (salts_crypto_random_bytes(candidate, sizeof(candidate)) != 0) break;
    if (!scalar_import(scalar, candidate)) continue;
    status = salts_crypto_sm9_master_public(purpose, candidate, pub, cap);
    if (status == SALTS_CRYPTO_OK) memcpy(raw, candidate, sizeof(candidate));
    break;
  }
  salts_crypto_secure_zero(candidate, sizeof(candidate));
  salts_crypto_secure_zero(scalar, sizeof(scalar));
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(raw, 32u); salts_crypto_secure_zero(pub, n); }
  return status;
}

int salts_crypto_sm9_sign_extract(const uint8_t raw[32], const void *id, size_t idn,
    salts_crypto_sm9_sign_key *out) {
  SM9_SIGN_MASTER_KEY master = {0};
  SM9_SIGN_KEY key = {0};
  if (!raw || !out || !id_valid(id, idn) || salts_crypto_overlap(out, sizeof(*out), raw, 32u) ||
      salts_crypto_overlap(out, sizeof(*out), id, idn)) return SALTS_CRYPTO_EINVAL;
  int status = sign_master(&master, raw) ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EINVAL;
  if (status == SALTS_CRYPTO_OK && (sm9_sign_master_key_extract_key(&master, id, idn, &key) != 1 ||
      sm9_z256_point_to_uncompressed_octets(&key.ds, out->private_point) != 1 ||
      sm9_z256_twist_point_to_uncompressed_octets(&key.Ppubs, out->master_public) != 1))
    status = SALTS_CRYPTO_ECRYPTO;
  salts_crypto_secure_zero(&key, sizeof(key));
  salts_crypto_secure_zero(&master, sizeof(master));
  if (status != SALTS_CRYPTO_OK) salts_crypto_sm9_sign_key_clear(out);
  return status;
}

int salts_crypto_sm9_enc_extract(const uint8_t raw[32], const void *id, size_t idn,
    salts_crypto_sm9_enc_key *out) {
  SM9_ENC_MASTER_KEY master = {0};
  SM9_ENC_KEY key = {0};
  if (!raw || !out || !id_valid(id, idn) || salts_crypto_overlap(out, sizeof(*out), raw, 32u) ||
      salts_crypto_overlap(out, sizeof(*out), id, idn)) return SALTS_CRYPTO_EINVAL;
  int status = enc_master(&master, raw) ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EINVAL;
  if (status == SALTS_CRYPTO_OK && (sm9_enc_master_key_extract_key(&master, id, idn, &key) != 1 ||
      sm9_z256_twist_point_to_uncompressed_octets(&key.de, out->private_point) != 1 ||
      sm9_z256_point_to_uncompressed_octets(&key.Ppube, out->master_public) != 1))
    status = SALTS_CRYPTO_ECRYPTO;
  salts_crypto_secure_zero(&key, sizeof(key));
  salts_crypto_secure_zero(&master, sizeof(master));
  if (status != SALTS_CRYPTO_OK) salts_crypto_sm9_enc_key_clear(out);
  return status;
}
void salts_crypto_sm9_sign_key_clear(salts_crypto_sm9_sign_key *key) {
  if (key) salts_crypto_secure_zero(key, sizeof(*key));
}
void salts_crypto_sm9_enc_key_clear(salts_crypto_sm9_enc_key *key) {
  if (key) salts_crypto_secure_zero(key, sizeof(*key));
}

/* Format-specific composition over the canonical ASN1 owner. */
static int append_field(uint32_t tag, const void *data, size_t n,
    uint8_t *out, size_t cap, size_t *used) {
  size_t written = 0;
  if (salts_asn1_encode_tlv(0, 0, tag, data, n, SALTS_ASN1_DER, 0,
      out + *used, cap - *used, &written) != SALTS_ASN1_OK) return 0;
  *used += written;
  return 1;
}
static int read_fields(const void *der, size_t n, const uint32_t *tags,
    salts_asn1_tlv *fields, size_t count) {
  salts_asn1_reader outer, inner;
  salts_asn1_tlv seq, extra;
  if (salts_asn1_reader_init(&outer, der, n, SALTS_ASN1_DER) != SALTS_ASN1_OK ||
      salts_asn1_reader_next(&outer, &seq) != SALTS_ASN1_OK || outer.offset != n ||
      seq.tag_class || !seq.constructed || seq.tag_number != 16u ||
      salts_asn1_reader_open_children(&outer, &seq, &inner) != SALTS_ASN1_OK) return 0;
  for (size_t i = 0; i < count; ++i) {
    if (salts_asn1_reader_next(&inner, fields + i) != SALTS_ASN1_OK ||
        fields[i].tag_class || fields[i].constructed || fields[i].tag_number != tags[i]) return 0;
  }
  return salts_asn1_reader_next(&inner, &extra) == SALTS_ASN1_DONE;
}

int salts_crypto_sm9_sign(const salts_crypto_sm9_sign_key *raw,
    const void *message, size_t n, uint8_t out[104]) {
  SM9_SIGN_KEY key = {0};
  SM9_SIGN_CTX ctx = {0};
  SM9_SIGNATURE sig = {0};
  uint8_t content[102], h[32], point[66] = {0};
  size_t used = 0, written = 0;
  int status = SALTS_CRYPTO_EINVAL;
  if (!raw || !out || (!message && n) || n > UINT64_MAX / 8u - 389u ||
      salts_crypto_overlap(out, 104u, raw, sizeof(*raw)) || salts_crypto_overlap(out, 104u, message, n))
    return SALTS_CRYPTO_EINVAL;
  if (!g1_import(&key.ds, raw->private_point) || !g2_import(&key.Ppubs, raw->master_public)) goto done;
  status = SALTS_CRYPTO_ECRYPTO;
  if (sm9_sign_init(&ctx) != 1 || sm9_sign_update(&ctx, message, n) != 1 ||
      sm9_do_sign(&key, &ctx.sm3_ctx, &sig) != 1) goto done;
  sm9_z256_to_bytes(sig.h, h);
  if (sm9_z256_point_to_uncompressed_octets(&sig.S, point + 1u) != 1 ||
      !append_field(4u, h, sizeof(h), content, sizeof(content), &used) ||
      !append_field(3u, point, sizeof(point), content, sizeof(content), &used) ||
      salts_asn1_encode_tlv(0, 1, 16, content, used, SALTS_ASN1_DER, 0,
          out, 104u, &written) != SALTS_ASN1_OK || written != 104u) goto done;
  status = SALTS_CRYPTO_OK;
done:
  salts_crypto_secure_zero(&key, sizeof(key));
  salts_crypto_secure_zero(&ctx, sizeof(ctx));
  salts_crypto_secure_zero(&sig, sizeof(sig));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(out, 104u);
  return status;
}

int salts_crypto_sm9_verify(const uint8_t pub[129], const void *id, size_t idn,
    const void *message, size_t n, const void *der, size_t dern) {
  SM9_SIGN_MASTER_KEY master = {0};
  SM9_SIGN_CTX ctx = {0};
  SM9_SIGNATURE sig = {0};
  salts_asn1_tlv fields[2];
  const uint32_t tags[] = {4u, 3u};
  int status = SALTS_CRYPTO_EVERIFY;
  if (!pub || !id_valid(id, idn) || (!message && n) || !der || n > UINT64_MAX / 8u - 389u)
    return SALTS_CRYPTO_EINVAL;
  if (!g2_import(&master.Ppubs, pub) || dern != 104u || !read_fields(der, dern, tags, fields, 2u) ||
      fields[0].content_size != 32u || fields[1].content_size != 66u || fields[1].content[0] ||
      !scalar_import(sig.h, fields[0].content) || !g1_import(&sig.S, fields[1].content + 1u)) goto done;
  if (sm9_verify_init(&ctx) != 1 || sm9_verify_update(&ctx, message, n) != 1) {
    status = SALTS_CRYPTO_ECRYPTO; goto done;
  }
  if (sm9_do_verify(&master, id, idn, &ctx.sm3_ctx, &sig) == 1) status = SALTS_CRYPTO_OK;
done:
  salts_crypto_secure_zero(&ctx, sizeof(ctx));
  salts_crypto_secure_zero(&master, sizeof(master));
  salts_crypto_secure_zero(&sig, sizeof(sig));
  return status;
}

int salts_crypto_sm9_encapsulate(const uint8_t pub[65], const void *id, size_t idn,
    void *secret, size_t n, uint8_t capsule[65]) {
  SM9_ENC_MASTER_KEY master = {0};
  SM9_Z256_POINT point = {0};
  int status = SALTS_CRYPTO_EINVAL;
  if (!pub || !id_valid(id, idn) || !secret || !n || n > SALTS_CRYPTO_SM9_KEM_MAX_SIZE || !capsule ||
      salts_crypto_overlap(secret, n, pub, 65u) || salts_crypto_overlap(secret, n, id, idn) ||
      salts_crypto_overlap(capsule, 65u, pub, 65u) || salts_crypto_overlap(capsule, 65u, id, idn) ||
      salts_crypto_overlap(secret, n, capsule, 65u)) return SALTS_CRYPTO_EINVAL;
  if (!g1_import(&master.Ppube, pub)) goto done;
  status = SALTS_CRYPTO_ECRYPTO;
  if (sm9_kem_encrypt(&master, id, idn, n, secret, &point) != 1 ||
      sm9_z256_point_to_uncompressed_octets(&point, capsule) != 1) goto done;
  status = SALTS_CRYPTO_OK;
done:
  salts_crypto_secure_zero(&master, sizeof(master));
  salts_crypto_secure_zero(&point, sizeof(point));
  if (status != SALTS_CRYPTO_OK) {
    salts_crypto_secure_zero(secret, n);
    salts_crypto_secure_zero(capsule, 65u);
  }
  return status;
}

int salts_crypto_sm9_decapsulate(const salts_crypto_sm9_enc_key *raw,
    const void *id, size_t idn, const uint8_t capsule[65], void *secret, size_t n) {
  SM9_ENC_KEY key = {0};
  SM9_Z256_POINT point = {0};
  int status = SALTS_CRYPTO_EVERIFY;
  if (!raw || !id_valid(id, idn) || !capsule || !secret || !n || n > SALTS_CRYPTO_SM9_KEM_MAX_SIZE ||
      salts_crypto_overlap(secret, n, raw, sizeof(*raw)) || salts_crypto_overlap(secret, n, id, idn) ||
      salts_crypto_overlap(secret, n, capsule, 65u)) return SALTS_CRYPTO_EINVAL;
  if (!enc_key_import(&key, raw) || !g1_import(&point, capsule)) goto done;
  if (sm9_kem_decrypt(&key, id, idn, &point, n, secret) == 1) status = SALTS_CRYPTO_OK;
done:
  salts_crypto_secure_zero(&key, sizeof(key));
  salts_crypto_secure_zero(&point, sizeof(point));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(secret, n);
  return status;
}

static int nonzero(const uint8_t *p, size_t n) {
  unsigned bits = 0;
  for (size_t i = 0; i < n; ++i) bits |= p[i];
  return bits != 0;
}
static int xor_tag(const uint8_t *cipher, size_t n, const uint8_t k2[32], uint8_t tag[32]) {
  salts_crypto_sm3_ctx_t ctx;
  int status = salts_crypto_sm3_init(&ctx);
  if (status == SALTS_CRYPTO_OK) status = salts_crypto_sm3_update(&ctx, cipher, n);
  if (status == SALTS_CRYPTO_OK) status = salts_crypto_sm3_update(&ctx, k2, 32u);
  if (status == SALTS_CRYPTO_OK) status = salts_crypto_sm3_final(&ctx, tag);
  salts_crypto_sm3_clear(&ctx);
  return status;
}
static int cipher_overlap(const void *key, size_t kn, const void *id, size_t idn,
    const void *in, size_t n, void *out, size_t outn, size_t *written) {
  return salts_crypto_overlap(out, outn, key, kn) || salts_crypto_overlap(out, outn, id, idn) ||
      salts_crypto_overlap(out, outn, in, n) || salts_crypto_overlap(written, sizeof(*written), key, kn) ||
      salts_crypto_overlap(written, sizeof(*written), id, idn) ||
      salts_crypto_overlap(written, sizeof(*written), in, n) ||
      salts_crypto_overlap(written, sizeof(*written), out, outn);
}

int salts_crypto_sm9_encrypt(const uint8_t pub[65], const void *id, size_t idn,
    const void *in, size_t n, void *out, size_t cap, size_t *written) {
  uint8_t secret[287] = {0}, point[66] = {0}, cipher[255], tag[32], content[363], zero = 0;
  size_t used = 0;
  int status = SALTS_CRYPTO_ECRYPTO;
  if (!pub || !id_valid(id, idn) || !in || !n || n > 255u || !out || cap < 367u || !written ||
      cipher_overlap(pub, 65u, id, idn, in, n, out, 367u, written)) return SALTS_CRYPTO_EINVAL;
  *written = 0;
  /* XOR mode retries when K1 alone is zero, even if the full KEM key is not. */
  for (unsigned attempt = 0; attempt < 128u; ++attempt) {
    status = salts_crypto_sm9_encapsulate(pub, id, idn, secret, n + 32u, point + 1u);
    if (status != SALTS_CRYPTO_OK) goto done;
    if (nonzero(secret, n)) break;
    status = SALTS_CRYPTO_ECRYPTO;
  }
  if (status != SALTS_CRYPTO_OK) goto done;
  for (size_t i = 0; i < n; ++i) cipher[i] = ((const uint8_t *)in)[i] ^ secret[i];
  status = xor_tag(cipher, n, secret + n, tag);
  if (status != SALTS_CRYPTO_OK) goto done;
  status = SALTS_CRYPTO_ECRYPTO;
  if (!append_field(2u, &zero, 1u, content, sizeof(content), &used) ||
      !append_field(3u, point, sizeof(point), content, sizeof(content), &used) ||
      !append_field(4u, tag, sizeof(tag), content, sizeof(content), &used) ||
      !append_field(4u, cipher, n, content, sizeof(content), &used) ||
      salts_asn1_encode_tlv(0, 1, 16, content, used, SALTS_ASN1_DER, 0,
          out, 367u, written) != SALTS_ASN1_OK) goto done;
  status = SALTS_CRYPTO_OK;
done:
  salts_crypto_secure_zero(secret, sizeof(secret));
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(out, 367u); *written = 0; }
  return status;
}

int salts_crypto_sm9_decrypt(const salts_crypto_sm9_enc_key *raw, const void *id, size_t idn,
    const void *in, size_t n, void *out, size_t cap, size_t *written) {
  uint8_t secret[287] = {0}, tag[32] = {0};
  const uint32_t tags[] = {2u, 3u, 4u, 4u};
  salts_asn1_tlv fields[4];
  unsigned mismatch = 0;
  int status = SALTS_CRYPTO_EVERIFY;
  if (!raw || !id_valid(id, idn) || !in || !out || cap < 255u || !written ||
      cipher_overlap(raw, sizeof(*raw), id, idn, in, n, out, 255u, written)) return SALTS_CRYPTO_EINVAL;
  *written = 0;
  if (n > 367u || !read_fields(in, n, tags, fields, 4u) || fields[0].content_size != 1u ||
      fields[0].content[0] || fields[1].content_size != 66u || fields[1].content[0] ||
      fields[2].content_size != 32u || !fields[3].content_size || fields[3].content_size > 255u) goto done;
  size_t plain_size = fields[3].content_size;
  if (salts_crypto_sm9_decapsulate(raw, id, idn, fields[1].content + 1u,
          secret, plain_size + 32u) != SALTS_CRYPTO_OK || !nonzero(secret, plain_size)) goto done;
  if (xor_tag(fields[3].content, plain_size, secret + plain_size, tag) != SALTS_CRYPTO_OK) {
    status = SALTS_CRYPTO_ECRYPTO; goto done;
  }
  for (size_t i = 0; i < 32u; ++i) mismatch |= tag[i] ^ fields[2].content[i];
  if (mismatch) goto done;
  for (size_t i = 0; i < plain_size; ++i) ((uint8_t *)out)[i] = fields[3].content[i] ^ secret[i];
  *written = plain_size;
  status = SALTS_CRYPTO_OK;
done:
  salts_crypto_secure_zero(secret, sizeof(secret));
  salts_crypto_secure_zero(tag, sizeof(tag));
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(out, 255u);
  return status;
}
