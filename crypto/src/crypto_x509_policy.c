#include "crypto_x509_policy.h"
#include "crypto_key_internal.h"

#include <crypto/sm2_keys.h>
#include <gmssl/rsa.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_cer.h>

#include <limits.h>
#include <string.h>

static int tag(const asn1_tlv *v, uint32_t number, unsigned constructed) {
  return !v->tag_class && v->tag_number == number && v->constructed == constructed;
}
static int next(asn1_reader *r, asn1_tlv *v, uint32_t number, unsigned constructed) {
  return asn1_reader_next(r, v) == SALTS_ASN1_OK && tag(v, number, constructed);
}
static int end(const asn1_reader *r) { return r->offset == r->size; }
static int sequence(const void *data, size_t n, asn1_reader *r) {
  asn1_reader top; asn1_tlv v;
  return asn1_reader_init(&top, data, n, SALTS_ASN1_DER) == SALTS_ASN1_OK &&
      next(&top, &v, 16, 1) && end(&top) &&
      asn1_reader_open_children(&top, &v, r) == SALTS_ASN1_OK;
}
static const uint8_t *encoded(const asn1_tlv *v) {
  return v->content - (v->encoded_size - v->content_size);
}

typedef struct x509_algorithm_view {
  asn1_tlv oid;
  asn1_tlv parameter;
  int has_parameter;
} x509_algorithm_view;

static int x509_algorithm(const asn1_reader *parent, const asn1_tlv *value,
    x509_algorithm_view *out) {
  asn1_reader fields;
  asn1_tlv extra;
  memset(out, 0, sizeof(*out));
  if (!tag(value, 16u, 1u) ||
      asn1_reader_open_children(parent, value, &fields) != SALTS_ASN1_OK ||
      !next(&fields, &out->oid, 6u, 0u)) return 0;
  switch (asn1_reader_next(&fields, &out->parameter)) {
  case SALTS_ASN1_DONE:
    return 1;
  case SALTS_ASN1_OK:
    out->has_parameter = 1;
    return asn1_reader_next(&fields, &extra) == SALTS_ASN1_DONE;
  default:
    return 0;
  }
}

static int oid_is(const asn1_tlv *oid, const uint8_t *value, size_t size) {
  return oid->content_size == size && memcmp(oid->content, value, size) == 0;
}

static int null_or_absent(const x509_algorithm_view *algorithm) {
  return !algorithm->has_parameter ||
      (tag(&algorithm->parameter, 5u, 0u) && algorithm->parameter.content_size == 0u);
}

static int signature_supported(const asn1_reader *parent, const asn1_tlv *value) {
  static const uint8_t rsa_prefix[] = {0x2au,0x86u,0x48u,0x86u,0xf7u,0x0du,0x01u,0x01u};
  static const uint8_t ecdsa_sha1[] = {0x2au,0x86u,0x48u,0xceu,0x3du,0x04u,0x01u};
  static const uint8_t ecdsa_sha2_prefix[] = {0x2au,0x86u,0x48u,0xceu,0x3du,0x04u,0x03u};
  static const uint8_t sm2_sm3[] = {0x2au,0x81u,0x1cu,0xcfu,0x55u,0x01u,0x83u,0x75u};
  static const uint8_t rsa_sm3[] = {0x2au,0x81u,0x1cu,0xcfu,0x55u,0x01u,0x83u,0x78u};
  x509_algorithm_view algorithm;
  const uint8_t *oid;
  size_t size;
  int supported = 0;
  if (!x509_algorithm(parent, value, &algorithm)) return SALTS_CRYPTO_X509_TLS_MALFORMED;
  oid = algorithm.oid.content;
  size = algorithm.oid.content_size;
#ifdef GMSSL_X509_RSA_PSS_SHA256
  if (size == sizeof(rsa_prefix) + 1u && memcmp(oid, rsa_prefix, sizeof(rsa_prefix)) == 0 &&
      oid[sizeof(rsa_prefix)] == 10u) {
    const uint8_t *der = encoded(value);
    size_t der_size = value->encoded_size;
    int scheme;
    return x509_signature_algor_from_der(&scheme, &der, &der_size) == 1 &&
        der_size == 0u && scheme == OID_rsassa_pss_sha256
        ? SALTS_CRYPTO_X509_TLS_ADMITTED : SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  }
#endif
  if (!null_or_absent(&algorithm)) return SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  if (size == sizeof(rsa_prefix) + 1u && memcmp(oid, rsa_prefix, sizeof(rsa_prefix)) == 0) {
    const uint8_t suffix = oid[sizeof(rsa_prefix)];
    supported = suffix == 4u || suffix == 5u || suffix == 11u ||
        suffix == 12u || suffix == 13u || suffix == 14u;
  } else if (oid_is(&algorithm.oid, ecdsa_sha1, sizeof(ecdsa_sha1))) {
    supported = 1;
  } else if (size == sizeof(ecdsa_sha2_prefix) + 1u &&
      memcmp(oid, ecdsa_sha2_prefix, sizeof(ecdsa_sha2_prefix)) == 0) {
    supported = oid[sizeof(ecdsa_sha2_prefix)] >= 1u &&
        oid[sizeof(ecdsa_sha2_prefix)] <= 4u;
  } else if (oid_is(&algorithm.oid, sm2_sm3, sizeof(sm2_sm3)) ||
      oid_is(&algorithm.oid, rsa_sm3, sizeof(rsa_sm3))) {
    supported = 1;
  }
  return supported ? SALTS_CRYPTO_X509_TLS_ADMITTED : SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
}

static int positive_integer(const asn1_tlv *value, const uint8_t **bytes, size_t *size) {
  const uint8_t *p;
  size_t n;
  if (!tag(value, 2u, 0u) || value->content_size == 0u) return 0;
  p = value->content;
  n = value->content_size;
  if (p[0] == 0u) {
    if (n == 1u || (p[1] & 0x80u) == 0u) return 0;
    ++p;
    --n;
  } else if ((p[0] & 0x80u) != 0u) {
    return 0;
  }
  *bytes = p;
  *size = n;
  return 1;
}

static int rsa_public_key_supported(const uint8_t *der, size_t size) {
  asn1_reader fields;
  asn1_tlv modulus_value, exponent_value;
  const uint8_t *modulus, *exponent_bytes;
  size_t modulus_size, exponent_size;
  uint32_t exponent = 0u;
  if (!sequence(der, size, &fields) ||
      asn1_reader_next(&fields, &modulus_value) != SALTS_ASN1_OK ||
      asn1_reader_next(&fields, &exponent_value) != SALTS_ASN1_OK || !end(&fields) ||
      !positive_integer(&modulus_value, &modulus, &modulus_size) ||
      !positive_integer(&exponent_value, &exponent_bytes, &exponent_size))
    return SALTS_CRYPTO_X509_TLS_MALFORMED;
  if (exponent_size > sizeof(exponent)) return SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  for (size_t index = 0u; index < exponent_size; ++index)
    exponent = (exponent << 8) | exponent_bytes[index];
  if (modulus_size < RSA_MIN_MODULUS_SIZE || modulus_size > RSA_MAX_MODULUS_SIZE ||
      (modulus_size & 3u) != 0u || modulus[0] == 0u ||
      (modulus[modulus_size - 1u] & 1u) == 0u || exponent < 3u ||
      exponent > INT_MAX || (exponent & 1u) == 0u)
    return SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  return SALTS_CRYPTO_X509_TLS_ADMITTED;
}

static int public_key_supported(const asn1_reader *parent, const asn1_tlv *spki) {
  static const uint8_t rsa[] = {0x2au,0x86u,0x48u,0x86u,0xf7u,0x0du,0x01u,0x01u,0x01u};
  static const uint8_t ec[] = {0x2au,0x86u,0x48u,0xceu,0x3du,0x02u,0x01u};
  static const uint8_t p256[] = {0x2au,0x86u,0x48u,0xceu,0x3du,0x03u,0x01u,0x07u};
  static const uint8_t p384[] = {0x2bu,0x81u,0x04u,0x00u,0x22u};
  static const uint8_t sm2[] = {0x2au,0x81u,0x1cu,0xcfu,0x55u,0x01u,0x82u,0x2du};
  asn1_reader fields;
  asn1_tlv algorithm_value, bits;
  x509_algorithm_view algorithm;
  const uint8_t *key;
  size_t key_size;
  uint8_t decoded[96];
  if (asn1_reader_open_children(parent, spki, &fields) != SALTS_ASN1_OK ||
      !next(&fields, &algorithm_value, 16u, 1u) ||
      !next(&fields, &bits, 3u, 0u) || !end(&fields) ||
      bits.content_size < 2u || bits.content[0] != 0u ||
      !x509_algorithm(&fields, &algorithm_value, &algorithm))
    return SALTS_CRYPTO_X509_TLS_MALFORMED;
  key = bits.content + 1u;
  key_size = bits.content_size - 1u;
  if (oid_is(&algorithm.oid, rsa, sizeof(rsa))) {
    if (!null_or_absent(&algorithm)) return SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
    return rsa_public_key_supported(key, key_size);
  }
  if (!oid_is(&algorithm.oid, ec, sizeof(ec)) || !algorithm.has_parameter ||
      !tag(&algorithm.parameter, 6u, 0u))
    return SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  if (oid_is(&algorithm.parameter, p256, sizeof(p256))) {
    return key_size == 65u && key[0] == 4u &&
        salts_crypto_ec_decode(SALTS_CRYPTO_EC_P256, key, key_size,
            decoded, sizeof(decoded)) == SALTS_CRYPTO_OK
        ? SALTS_CRYPTO_X509_TLS_ADMITTED : SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  }
  if (oid_is(&algorithm.parameter, p384, sizeof(p384))) {
    return key_size == 97u && key[0] == 4u &&
        salts_crypto_ec_decode(SALTS_CRYPTO_EC_P384, key, key_size,
            decoded, sizeof(decoded)) == SALTS_CRYPTO_OK
        ? SALTS_CRYPTO_X509_TLS_ADMITTED : SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  }
  if (oid_is(&algorithm.parameter, sm2, sizeof(sm2))) {
    uint8_t point[65];
    return salts_crypto_sm2_spki_import(encoded(spki), spki->encoded_size, point) == SALTS_CRYPTO_OK
        ? SALTS_CRYPTO_X509_TLS_ADMITTED : SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  }
  return SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
}

static int certificate_profile(const void *der, size_t size) {
  asn1_reader certificate, tbs, version;
  asn1_tlv tbs_value, outer_algorithm, signature, value, inner_algorithm, spki;
  int status;
  if (!sequence(der, size, &certificate) ||
      !next(&certificate, &tbs_value, 16u, 1u) ||
      !next(&certificate, &outer_algorithm, 16u, 1u) ||
      !next(&certificate, &signature, 3u, 0u) || !end(&certificate) ||
      signature.content_size < 2u || signature.content[0] != 0u ||
      asn1_reader_open_children(&certificate, &tbs_value, &tbs) != SALTS_ASN1_OK ||
      asn1_reader_next(&tbs, &value) != SALTS_ASN1_OK)
    return SALTS_CRYPTO_X509_TLS_MALFORMED;
  if (value.tag_class == 2u && value.constructed && value.tag_number == 0u) {
    asn1_tlv number;
    if (asn1_reader_open_children(&tbs, &value, &version) != SALTS_ASN1_OK ||
        !next(&version, &number, 2u, 0u) || !end(&version) ||
        number.content_size != 1u || number.content[0] < 1u || number.content[0] > 2u ||
        asn1_reader_next(&tbs, &value) != SALTS_ASN1_OK)
      return SALTS_CRYPTO_X509_TLS_MALFORMED;
  }
  if (!tag(&value, 2u, 0u) || value.content_size == 0u ||
      !next(&tbs, &inner_algorithm, 16u, 1u) ||
      !next(&tbs, &value, 16u, 1u) ||
      !next(&tbs, &value, 16u, 1u) ||
      !next(&tbs, &value, 16u, 1u) ||
      !next(&tbs, &spki, 16u, 1u) ||
      inner_algorithm.encoded_size != outer_algorithm.encoded_size ||
      memcmp(encoded(&inner_algorithm), encoded(&outer_algorithm),
          inner_algorithm.encoded_size) != 0)
    return SALTS_CRYPTO_X509_TLS_MALFORMED;
  status = signature_supported(&certificate, &outer_algorithm);
  if (status != SALTS_CRYPTO_X509_TLS_ADMITTED) return status;
  return public_key_supported(&tbs, &spki);
}

salts_crypto_x509_tls_admission salts_crypto_x509_tls_certificate_admission(
    const void *der, size_t available, size_t *consumed) {
  asn1_reader input;
  asn1_tlv certificate;
  const uint8_t *cursor, *parsed;
  size_t size, remaining, parsed_size;
  int status;
  if (consumed == NULL) return SALTS_CRYPTO_X509_TLS_MALFORMED;
  *consumed = 0u;
  if (der == NULL || available == 0u ||
      asn1_reader_init(&input, der, available, SALTS_ASN1_DER) != SALTS_ASN1_OK ||
      asn1_reader_next(&input, &certificate) != SALTS_ASN1_OK ||
      !tag(&certificate, 16u, 1u))
    return SALTS_CRYPTO_X509_TLS_MALFORMED;
  size = certificate.encoded_size;
  status = certificate_profile(encoded(&certificate), size);
  if (status == SALTS_CRYPTO_X509_TLS_MALFORMED)
    return SALTS_CRYPTO_X509_TLS_MALFORMED;
  *consumed = size;
  if (status == SALTS_CRYPTO_X509_TLS_UNSUPPORTED)
    return SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  cursor = encoded(&certificate);
  remaining = size;
  parsed = NULL;
  parsed_size = 0u;
  if (x509_cert_from_der(&parsed, &parsed_size, &cursor, &remaining) != 1 || remaining != 0u)
    return SALTS_CRYPTO_X509_TLS_UNSUPPORTED;
  return SALTS_CRYPTO_X509_TLS_ADMITTED;
}

static unsigned decimal(const uint8_t *p, size_t n) {
  unsigned value = 0;
  while (n--) value = value*10u + *p++ - '0';
  return value;
}
static int leap(unsigned y) { return y%4u == 0u && (y%100u != 0u || y%400u == 0u); }
static int date_value(const asn1_tlv *v, int64_t *out, int x509) {
  static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
  size_t digits = v->tag_number == 23u ? 12u : 14u, k;
  if (v->tag_class || v->constructed || (v->tag_number != 23u && v->tag_number != 24u) ||
      v->content_size != digits+1 || v->content[digits] != 'Z') return 0;
  for (size_t i=0; i<digits; ++i) if (v->content[i] < '0' || v->content[i] > '9') return 0;
  k = digits-10u;
  unsigned y = decimal(v->content, k), m = decimal(v->content+k, 2), d = decimal(v->content+k+2, 2);
  unsigned h = decimal(v->content+k+4, 2), min = decimal(v->content+k+6, 2), sec = decimal(v->content+k+8, 2);
  if (k == 2) y += y >= 50u ? 1900u : 2000u;
  else if (!y || (x509 && y < 2050u)) return 0; /* RFC5280 uses UTCTime through 2049. */
  if (m < 1 || m > 12 || d < 1 || d > days[m-1]+(unsigned)(m == 2 && leap(y)) || h > 23 || min > 59 || sec > 59) return 0;
  /* Gregorian days before Jan 1 y, relative to Jan 1 1970; bounded by year9999. */
  int64_t before = (int64_t)(y-1u)*365 + (y-1u)/4u - (y-1u)/100u + (y-1u)/400u - 719162;
  for (unsigned i=1; i<m; ++i) before += days[i-1]+(unsigned)(i == 2 && leap(y));
  *out = (before+d-1)*86400 + h*3600 + min*60 + sec;
  return 1;
}
int salts_crypto_x509_date(const asn1_tlv *v, int64_t *out) {
  return date_value(v,out,1);
}
int salts_crypto_generalized_time(const asn1_tlv *v, int64_t *out) {
  return v->tag_number == 24u && date_value(v,out,0);
}
int salts_crypto_x509_valid_time(const crypto_x509_der_view *v, int64_t now) {
  asn1_reader r; asn1_tlv first, last; int64_t a, b;
  return sequence(v->validity_der, v->validity_size, &r) &&
      asn1_reader_next(&r, &first) == SALTS_ASN1_OK &&
      asn1_reader_next(&r, &last) == SALTS_ASN1_OK && end(&r) &&
      salts_crypto_x509_date(&first, &a) && salts_crypto_x509_date(&last, &b) && a <= b && a <= now && now <= b;
}
int salts_crypto_x509_valid_name(const void *der, size_t n) {
  asn1_reader rdns, attrs, fields; asn1_tlv rdn, attr, oid, value;
  if (!sequence(der, n, &rdns) || end(&rdns)) return 0;
  while (!end(&rdns)) {
    if (!next(&rdns, &rdn, 17, 1) || asn1_reader_open_children(&rdns, &rdn, &attrs) != SALTS_ASN1_OK || end(&attrs)) return 0;
    while (!end(&attrs)) {
      if (!next(&attrs, &attr, 16, 1) || asn1_reader_open_children(&attrs, &attr, &fields) != SALTS_ASN1_OK ||
          !next(&fields, &oid, 6, 0) || asn1_reader_next(&fields, &value) != SALTS_ASN1_OK ||
          value.tag_class || value.constructed || !value.content_size || !end(&fields)) return 0;
    }
  }
  return 1;
}
