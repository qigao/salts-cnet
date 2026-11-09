#include <crypto/sm9.h>
#include <crypto/sm9_exchange.h>
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
  return purpose == SALTS_CRYPTO_SM9_SIGN ? 129u :
      (purpose == SALTS_CRYPTO_SM9_ENCRYPT || purpose == SALTS_CRYPTO_SM9_EXCHANGE) ? 65u : 0u;
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
  if (asn1_encode_tlv(0, 0, tag, data, n, SALTS_ASN1_DER, 0,
      out + *used, cap - *used, &written) != SALTS_ASN1_OK) return 0;
  *used += written;
  return 1;
}
static int read_fields(const void *der, size_t n, const uint32_t *tags,
    asn1_tlv *fields, size_t count) {
  asn1_reader outer, inner;
  asn1_tlv seq, extra;
  if (asn1_reader_init(&outer, der, n, SALTS_ASN1_DER) != SALTS_ASN1_OK ||
      asn1_reader_next(&outer, &seq) != SALTS_ASN1_OK || outer.offset != n ||
      seq.tag_class || !seq.constructed || seq.tag_number != 16u ||
      asn1_reader_open_children(&outer, &seq, &inner) != SALTS_ASN1_OK) return 0;
  for (size_t i = 0; i < count; ++i) {
    if (asn1_reader_next(&inner, fields + i) != SALTS_ASN1_OK ||
        fields[i].tag_class || fields[i].constructed || fields[i].tag_number != tags[i]) return 0;
  }
  return asn1_reader_next(&inner, &extra) == SALTS_ASN1_DONE;
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
      asn1_encode_tlv(0, 1, 16, content, used, SALTS_ASN1_DER, 0,
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
  asn1_tlv fields[2];
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
      asn1_encode_tlv(0, 1, 16, content, used, SALTS_ASN1_DER, 0,
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
  asn1_tlv fields[4];
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

int salts_crypto_sm9_exchange_extract(const uint8_t raw[32], const void *id, size_t idn,
    salts_crypto_sm9_exchange_key *out) {
  SM9_EXCH_MASTER_KEY master = {0};
  SM9_EXCH_KEY key = {0};
  if (!raw || !out || !id_valid(id, idn) || idn > SALTS_CRYPTO_SM9_EXCHANGE_ID_MAX_SIZE ||
      salts_crypto_overlap(out, sizeof(*out), raw, 32u) ||
      salts_crypto_overlap(out, sizeof(*out), id, idn)) return SALTS_CRYPTO_EINVAL;
  int status = enc_master(&master, raw) ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EINVAL;
  if (status == SALTS_CRYPTO_OK && (sm9_exch_master_key_extract_key(&master, id, idn, &key) != 1 ||
      sm9_z256_twist_point_to_uncompressed_octets(&key.de, out->private_point) != 1 ||
      sm9_z256_point_to_uncompressed_octets(&key.Ppube, out->master_public) != 1))
    status = SALTS_CRYPTO_ECRYPTO;
  salts_crypto_secure_zero(&key, sizeof(key));
  salts_crypto_secure_zero(&master, sizeof(master));
  if (status != SALTS_CRYPTO_OK) salts_crypto_sm9_exchange_key_clear(out);
  return status;
}
void salts_crypto_sm9_exchange_key_clear(salts_crypto_sm9_exchange_key *key) {
  if (key) salts_crypto_secure_zero(key, sizeof(*key));
}
void salts_crypto_sm9_exchange_clear(salts_crypto_sm9_exchange_ctx *ctx) {
  if (ctx) salts_crypto_secure_zero(ctx, sizeof(*ctx));
}

typedef struct sm9_exchange_state {
  uint32_t phase;
  size_t key_size, id_a_size, id_b_size;
  salts_crypto_sm9_exchange_key key;
  uint8_t nonce[32], own_share[65], id_a[255], id_b[255];
  uint8_t pending[1024], expected_a[32];
} sm9_exchange_state;
enum { SM9_WAIT_B = 0x534d3901u, SM9_WAIT_A = 0x534d3902u };
_Static_assert(sizeof(sm9_exchange_state) <= SALTS_CRYPTO_SM9_EXCHANGE_CONTEXT_SIZE,
    "SM9 exchange context capacity");

typedef struct sm9_range { const void *data; size_t size; } sm9_range;
/* Outputs precede inputs. Read-only inputs may alias one another. */
static int exchange_alias(const sm9_range *ranges, size_t outputs, size_t count) {
  for (size_t i = 0; i < outputs; ++i)
    for (size_t j = i + 1u; j < count; ++j)
      if (salts_crypto_overlap(ranges[i].data, ranges[i].size, ranges[j].data, ranges[j].size)) return 1;
  return 0;
}
static int exchange_sizes(const void *a, size_t an, const void *b, size_t bn, size_t kn) {
  return id_valid(a, an) && an <= 255u && id_valid(b, bn) && bn <= 255u && kn && kn <= 1024u;
}
static int exchange_point(SM9_Z256_POINT *q, const SM9_Z256_POINT *pub, const void *id, size_t n) {
  sm9_z256_t h;
  sm9_z256_hash1(h, id, n, SM9_HID_EXCH);
  sm9_z256_point_mul_generator(q, h);
  sm9_z256_point_add(q, q, pub);
  salts_crypto_secure_zero(h, sizeof(h));
  return !sm9_z256_point_is_at_infinity(q);
}
static int exchange_prepare(sm9_exchange_state *state, const salts_crypto_sm9_exchange_key *raw,
    const void *a, size_t an, const void *b, size_t bn, size_t kn, int initiator) {
  SM9_EXCH_KEY key = {0};
  SM9_Z256_POINT q = {0}, share = {0};
  sm9_z256_fp12_t expected, actual;
  sm9_z256_t r = {0};
  int status = SALTS_CRYPTO_EINVAL;
  if (!g1_import(&key.Ppube, raw->master_public) || !g2_import(&key.de, raw->private_point) ||
      !exchange_point(&q, &key.Ppube, initiator ? a : b, initiator ? an : bn)) goto done;
  /* Bind the local private point to its claimed identity, master and hid.
   * Encryption keys (hid=0x03) cannot enter exchange (hid=0x02). */
  sm9_z256_pairing(expected, sm9_z256_twist_generator(), &key.Ppube);
  sm9_z256_pairing(actual, &key.de, &q);
  if (!sm9_z256_fp12_equ(expected, actual) ||
      !exchange_point(&q, &key.Ppube, initiator ? b : a, initiator ? bn : an)) goto done;
  status = SALTS_CRYPTO_ERANDOM;
  for (unsigned attempt = 0; attempt < 128u; ++attempt) {
    if (sm9_z256_rand_range(r, sm9_z256_order()) != 1) goto done;
    if (!sm9_z256_is_zero(r)) { status = SALTS_CRYPTO_OK; break; }
  }
  if (status != SALTS_CRYPTO_OK) goto done;
  sm9_z256_point_mul(&share, r, &q);
  if (sm9_z256_point_to_uncompressed_octets(&share, state->own_share) != 1) {
    status = SALTS_CRYPTO_ECRYPTO; goto done;
  }
  state->key = *raw; state->key_size = kn;
  state->id_a_size = an; state->id_b_size = bn;
  memcpy(state->id_a, a, an); memcpy(state->id_b, b, bn);
  sm9_z256_to_bytes(r, state->nonce);
done:
  salts_crypto_secure_zero(&key, sizeof(key));
  salts_crypto_secure_zero(&q, sizeof(q)); salts_crypto_secure_zero(&share, sizeof(share));
  salts_crypto_secure_zero(expected, sizeof(expected)); salts_crypto_secure_zero(actual, sizeof(actual));
  salts_crypto_secure_zero(r, sizeof(r));
  return status;
}

/* Complete the standard transcript and both role-specific confirmation hashes.
 * Uses existing provider primitives, not its unfinished exchange entrypoints. */
static int exchange_derive(const sm9_exchange_state *state, const uint8_t peer[65], int initiator,
    uint8_t secret[1024], uint8_t sa[32], uint8_t sb[32]) {
  SM9_EXCH_KEY key = {0};
  SM9_Z256_POINT point = {0};
  sm9_z256_t r = {0};
  sm9_z256_fp12_t g1, g2, g3;
  uint8_t encoded[3][384], inner[32], prefix;
  SM3_CTX hash;
  SM3_KDF_CTX kdf;
  const uint8_t *ra = initiator ? state->own_share : peer;
  const uint8_t *rb = initiator ? peer : state->own_share;
  int status = SALTS_CRYPTO_EVERIFY;
  if (!g1_import(&point, peer) || !g1_import(&key.Ppube, state->key.master_public) ||
      !g2_import(&key.de, state->key.private_point) || !scalar_import(r, state->nonce)) goto done;
  if (initiator) {
    sm9_z256_pairing(g1, sm9_z256_twist_generator(), &key.Ppube);
    sm9_z256_fp12_pow(g1, g1, r);
    sm9_z256_pairing(g2, &key.de, &point);
    sm9_z256_fp12_pow(g3, g2, r);
  } else {
    sm9_z256_pairing(g1, &key.de, &point);
    sm9_z256_pairing(g2, sm9_z256_twist_generator(), &key.Ppube);
    sm9_z256_fp12_pow(g2, g2, r);
    sm9_z256_fp12_pow(g3, g1, r);
  }
  sm9_z256_fp12_to_bytes(g1, encoded[0]);
  sm9_z256_fp12_to_bytes(g2, encoded[1]);
  sm9_z256_fp12_to_bytes(g3, encoded[2]);
  sm3_kdf_init(&kdf, state->key_size);
  sm3_kdf_update(&kdf, state->id_a, state->id_a_size);
  sm3_kdf_update(&kdf, state->id_b, state->id_b_size);
  sm3_kdf_update(&kdf, ra + 1u, 64u); sm3_kdf_update(&kdf, rb + 1u, 64u);
  for (size_t i = 0; i < 3u; ++i) sm3_kdf_update(&kdf, encoded[i], sizeof(encoded[i]));
  sm3_kdf_finish(&kdf, secret);
  if (!nonzero(secret, state->key_size)) { status = SALTS_CRYPTO_ECRYPTO; goto done; }
  sm3_init(&hash);
  sm3_update(&hash, encoded[1], sizeof(encoded[1]));
  sm3_update(&hash, encoded[2], sizeof(encoded[2]));
  sm3_update(&hash, state->id_a, state->id_a_size);
  sm3_update(&hash, state->id_b, state->id_b_size);
  sm3_update(&hash, ra + 1u, 64u); sm3_update(&hash, rb + 1u, 64u);
  sm3_finish(&hash, inner);
  prefix = 0x82u;
  sm3_init(&hash); sm3_update(&hash, &prefix, 1u);
  sm3_update(&hash, encoded[0], 384u); sm3_update(&hash, inner, sizeof(inner)); sm3_finish(&hash, sb);
  prefix = 0x83u;
  sm3_init(&hash); sm3_update(&hash, &prefix, 1u);
  sm3_update(&hash, encoded[0], 384u); sm3_update(&hash, inner, sizeof(inner)); sm3_finish(&hash, sa);
  status = SALTS_CRYPTO_OK;
done:
  salts_crypto_secure_zero(&key, sizeof(key)); salts_crypto_secure_zero(&point, sizeof(point));
  salts_crypto_secure_zero(r, sizeof(r)); salts_crypto_secure_zero(g1, sizeof(g1));
  salts_crypto_secure_zero(g2, sizeof(g2)); salts_crypto_secure_zero(g3, sizeof(g3));
  salts_crypto_secure_zero(encoded, sizeof(encoded)); salts_crypto_secure_zero(inner, sizeof(inner));
  salts_crypto_secure_zero(&hash, sizeof(hash)); salts_crypto_secure_zero(&kdf, sizeof(kdf));
  return status;
}

int salts_crypto_sm9_exchange_start(salts_crypto_sm9_exchange_ctx *ctx,
    const salts_crypto_sm9_exchange_key *key, const void *a, size_t an,
    const void *b, size_t bn, size_t kn, uint8_t ra[65]) {
  sm9_exchange_state state = {0};
  const sm9_range ranges[] = {{ctx, sizeof(*ctx)}, {ra, 65u}, {key, sizeof(*key)}, {a, an}, {b, bn}};
  if (!ctx || !key || !ra || !exchange_sizes(a, an, b, bn, kn) || exchange_alias(ranges, 2u, 5u))
    return SALTS_CRYPTO_EINVAL;
  salts_crypto_sm9_exchange_clear(ctx);
  int status = exchange_prepare(&state, key, a, an, b, bn, kn, 1);
  if (status == SALTS_CRYPTO_OK) {
    state.phase = SM9_WAIT_B;
    memcpy(ctx->bytes, &state, sizeof(state)); memcpy(ra, state.own_share, 65u);
  } else salts_crypto_secure_zero(ra, 65u);
  salts_crypto_secure_zero(&state, sizeof(state));
  return status;
}

int salts_crypto_sm9_exchange_respond(salts_crypto_sm9_exchange_ctx *ctx,
    const salts_crypto_sm9_exchange_key *key, const void *a, size_t an,
    const void *b, size_t bn, size_t kn, const uint8_t ra[65], uint8_t rb[65], uint8_t sb[32]) {
  sm9_exchange_state state = {0}, pending = {0};
  SM9_Z256_POINT peer;
  const sm9_range ranges[] = {{ctx, sizeof(*ctx)}, {rb, 65u}, {sb, 32u},
      {key, sizeof(*key)}, {a, an}, {b, bn}, {ra, 65u}};
  if (!ctx || !key || !ra || !rb || !sb || !exchange_sizes(a, an, b, bn, kn) || exchange_alias(ranges, 3u, 7u))
    return SALTS_CRYPTO_EINVAL;
  salts_crypto_sm9_exchange_clear(ctx);
  int status = SALTS_CRYPTO_EVERIFY;
  if (!g1_import(&peer, ra)) goto done;
  status = exchange_prepare(&state, key, a, an, b, bn, kn, 0);
  if (status != SALTS_CRYPTO_OK) goto done;
  status = exchange_derive(&state, ra, 0, pending.pending, pending.expected_a, sb);
  if (status != SALTS_CRYPTO_OK) goto done;
  pending.phase = SM9_WAIT_A; pending.key_size = kn;
  memcpy(ctx->bytes, &pending, sizeof(pending)); memcpy(rb, state.own_share, 65u);
done:
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(rb, 65u); salts_crypto_secure_zero(sb, 32u); }
  salts_crypto_secure_zero(&peer, sizeof(peer));
  salts_crypto_secure_zero(&state, sizeof(state)); salts_crypto_secure_zero(&pending, sizeof(pending));
  return status;
}

int salts_crypto_sm9_exchange_finish_initiator(salts_crypto_sm9_exchange_ctx *ctx,
    const uint8_t rb[65], const uint8_t sb[32], uint8_t sa[32], void *out, size_t cap, size_t *written) {
  sm9_exchange_state state;
  uint8_t secret[1024] = {0}, expected[32] = {0}, confirmation[32] = {0};
  unsigned diff = 0;
  const sm9_range ranges[] = {{ctx, sizeof(*ctx)}, {out, 1024u}, {written, sizeof(*written)},
      {sa, 32u}, {rb, 65u}, {sb, 32u}};
  if (!ctx || !rb || !sb || !sa || !out || cap < 1024u || !written || exchange_alias(ranges, 4u, 6u))
    return SALTS_CRYPTO_EINVAL;
  *written = 0;
  memcpy(&state, ctx->bytes, sizeof(state)); salts_crypto_sm9_exchange_clear(ctx);
  int status = SALTS_CRYPTO_ESTATE;
  if (state.phase != SM9_WAIT_B || !exchange_sizes(state.id_a, state.id_a_size,
          state.id_b, state.id_b_size, state.key_size)) goto done;
  status = exchange_derive(&state, rb, 1, secret, confirmation, expected);
  if (status != SALTS_CRYPTO_OK) goto done;
  for (size_t i = 0; i < 32u; ++i) diff |= expected[i] ^ sb[i];
  if (diff) { status = SALTS_CRYPTO_EVERIFY; goto done; }
  memcpy(out, secret, state.key_size); memcpy(sa, confirmation, 32u); *written = state.key_size;
done:
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(out, 1024u); salts_crypto_secure_zero(sa, 32u); }
  salts_crypto_secure_zero(secret, sizeof(secret)); salts_crypto_secure_zero(expected, sizeof(expected));
  salts_crypto_secure_zero(confirmation, sizeof(confirmation)); salts_crypto_secure_zero(&state, sizeof(state));
  return status;
}

int salts_crypto_sm9_exchange_finish_responder(salts_crypto_sm9_exchange_ctx *ctx,
    const uint8_t sa[32], void *out, size_t cap, size_t *written) {
  sm9_exchange_state state;
  unsigned diff = 0;
  const sm9_range ranges[] = {{ctx, sizeof(*ctx)}, {out, 1024u}, {written, sizeof(*written)}, {sa, 32u}};
  if (!ctx || !sa || !out || cap < 1024u || !written || exchange_alias(ranges, 3u, 4u))
    return SALTS_CRYPTO_EINVAL;
  *written = 0;
  memcpy(&state, ctx->bytes, sizeof(state)); salts_crypto_sm9_exchange_clear(ctx);
  int status = SALTS_CRYPTO_ESTATE;
  if (state.phase != SM9_WAIT_A || !state.key_size || state.key_size > 1024u) goto done;
  for (size_t i = 0; i < 32u; ++i) diff |= state.expected_a[i] ^ sa[i];
  if (diff) { status = SALTS_CRYPTO_EVERIFY; goto done; }
  memcpy(out, state.pending, state.key_size); *written = state.key_size; status = SALTS_CRYPTO_OK;
done:
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(out, 1024u);
  salts_crypto_secure_zero(&state, sizeof(state));
  return status;
}
