#include <crypto/sm2_crl.h>
#include <crypto/sm2_x509.h>
#include "crypto_x509_policy.h"
#include <string.h>

typedef struct span { const uint8_t *data; size_t size; } span;
typedef struct extension { span oid, value; unsigned critical; } extension;
typedef struct extension_list { extension values[64]; size_t count; } extension_list;
static int tag(const salts_asn1_tlv *v, uint32_t n, unsigned constructed) {
  return !v->tag_class && v->tag_number == n && v->constructed == constructed;
}
static int next(salts_asn1_reader *r, salts_asn1_tlv *v, uint32_t n, unsigned constructed) {
  return salts_asn1_reader_next(r, v) == SALTS_ASN1_OK && tag(v, n, constructed);
}
static int end(const salts_asn1_reader *r) { return r->offset == r->size; }
static span encoded(const salts_asn1_tlv *v) {
  span s = {v->content - (v->encoded_size-v->content_size), v->encoded_size}; return s;
}
static int same(span a, span b) {
  return a.size == b.size && !memcmp(a.data, b.data, a.size);
}
static int init(salts_asn1_reader *r, span s) {
  return salts_asn1_reader_init(r, s.data, s.size, SALTS_ASN1_DER) == SALTS_ASN1_OK;
}
static int children(salts_asn1_reader *r, const salts_asn1_tlv *v) {
  span s = {v->content, v->content_size}; return init(r, s);
}
static int only(span s, salts_asn1_tlv *v, uint32_t n, unsigned constructed) {
  salts_asn1_reader r; return init(&r, s) && next(&r, v, n, constructed) && end(&r);
}
static int extension_sequence(span der, extension_list *list) {
  salts_asn1_reader r, fields; salts_asn1_tlv seq, ext, oid, value;
  list->count = 0;
  if (!only(der, &seq, 16, 1) || !children(&r, &seq) || end(&r)) return 0;
  while (!end(&r)) {
    if (list->count == 64 || !next(&r, &ext, 16, 1) || !children(&fields, &ext) ||
        !next(&fields, &oid, 6, 0) || salts_asn1_reader_next(&fields, &value) != SALTS_ASN1_OK) return 0;
    extension *e = &list->values[list->count];
    e->oid = (span){oid.content, oid.content_size}; e->critical = 0;
    for (size_t i=0; i<list->count; ++i) if (same(e->oid, list->values[i].oid)) return 0;
    if (tag(&value, 1, 0)) {
      if (value.content_size != 1 || value.content[0] != 0xff) return 0;
      e->critical = 1;
      if (salts_asn1_reader_next(&fields, &value) != SALTS_ASN1_OK) return 0;
    }
    if (!tag(&value, 4, 0) || !end(&fields)) return 0;
    e->value = (span){value.content, value.content_size}; ++list->count;
  }
  return 1;
}
static unsigned ce(const extension *e) {
  return e->oid.size == 3 && e->oid.data[0] == 0x55 && e->oid.data[1] == 0x1d ? e->oid.data[2] : 0;
}
static int integer(const salts_asn1_tlv *v, uint64_t *out) {
  if (!tag(v, 2, 0) || !v->content_size || (v->content[0] & 128) || v->content_size > 9 ||
      (v->content_size == 9 && v->content[0])) return 0;
  *out = 0;
  for (size_t i=0; i<v->content_size; ++i) *out = (*out << 8) | v->content[i];
  return 1;
}
static int serial(span s) {
  if (!s.size || s.size > 20 || (s.data[0] & 128)) return 0;
  for (size_t i=0; i<s.size; ++i) if (s.data[i]) return 1;
  return 0;
}
static int certificate_profile(const crypto_x509_der_view *cert, int issuer, span *ski) {
  extension_list exts; salts_asn1_reader r; salts_asn1_tlv value, field;
  unsigned ca = 0, crl_sign = 0;
  if (cert->version != 2 || !cert->extensions_der ||
      !extension_sequence((span){cert->extensions_der, cert->extensions_size}, &exts)) return 0;
  for (size_t i=0; i<exts.count; ++i) {
    const extension *e = &exts.values[i]; unsigned kind = ce(e);
    if (!issuer) {
      if (kind == 31 || kind == 46) return 0; /* No distribution-point routing profile. */
      continue; /* Certificate constraints/trust belong to the authenticated path. */
    }
    if (kind == 14) {
      if (e->critical || !only(e->value, &value, 4, 0) || !value.content_size || value.content_size > 64) return 0;
      *ski = (span){value.content, value.content_size};
    } else if (kind == 19) {
      if (!e->critical || !only(e->value, &value, 16, 1) || !children(&r, &value) ||
          !next(&r, &field, 1, 0) || field.content_size != 1 || field.content[0] != 0xff) return 0;
      if (!end(&r)) { uint64_t limit; if (!next(&r, &field, 2, 0) || !integer(&field, &limit) || !end(&r)) return 0; }
      ca = 1;
    } else if (kind == 15) {
      if (!only(e->value, &value, 3, 0) || value.content_size < 2 || value.content_size > 3) return 0;
      unsigned bits = (unsigned)(value.content_size-1)*8u-value.content[0];
      if (!bits || bits > 9 || !(value.content[value.content_size-1] & (1u << value.content[0]))) return 0;
      if (bits > 7 && ((value.content[1] & 1) || (bits == 9 && (value.content[2] & 128))) && !(value.content[1] & 8)) return 0;
      crl_sign = (value.content[1] & 2u) != 0;
    }
  }
  return !issuer || (ca && crl_sign && ski->size);
}
static int crl_extensions(const salts_asn1_tlv *wrapper, span ski, uint64_t minimum) {
  extension_list exts; salts_asn1_tlv value, id; salts_asn1_reader r;
  unsigned aki = 0, number = 0;
  if (wrapper->tag_class != 2 || wrapper->tag_number != 0 || !wrapper->constructed ||
      !extension_sequence((span){wrapper->content, wrapper->content_size}, &exts)) return 0;
  for (size_t i=0; i<exts.count; ++i) {
    const extension *e = &exts.values[i]; unsigned kind = ce(e);
    if (e->critical || kind == 27 || kind == 28 || kind == 29 || kind == 46) return 0;
    if (kind == 35) {
      if (!only(e->value, &value, 16, 1) || !children(&r, &value) ||
          salts_asn1_reader_next(&r, &id) != SALTS_ASN1_OK || id.tag_class != 2 || id.tag_number != 0 ||
          id.constructed || !same((span){id.content, id.content_size}, ski) || !end(&r)) return 0;
      aki = 1;
    } else if (kind == 20) {
      uint64_t n;
      if (!only(e->value, &value, 2, 0) || !integer(&value, &n) || n < minimum) return 0;
      number = 1;
    }
  }
  return aki && number;
}
static int entry_extensions(const salts_asn1_tlv *seq) {
  extension_list exts; salts_asn1_tlv value;
  if (!extension_sequence(encoded(seq), &exts)) return 0;
  for (size_t i=0; i<exts.count; ++i) {
    const extension *e = &exts.values[i]; unsigned kind = ce(e);
    /* Keep entry semantics finite; no indirect issuer, invalidity-date or delta state. */
    if (e->critical || kind != 21 || !only(e->value, &value, 10, 0) || value.content_size != 1) return 0;
    unsigned reason = value.content[0];
    if (reason > 10 || reason == 7 || reason == 8) return 0;
  }
  return 1;
}
static int entries(const salts_asn1_tlv *seq, span target, int64_t issued, unsigned *revoked) {
  salts_asn1_reader r, fields; salts_asn1_tlv entry, number, date, exts;
  span seen[SALTS_CRYPTO_SM2_CRL_MAX_ENTRIES]; size_t count = 0; int64_t when;
  if (!children(&r, seq) || end(&r)) return 0;
  while (!end(&r)) {
    if (count == SALTS_CRYPTO_SM2_CRL_MAX_ENTRIES || !next(&r, &entry, 16, 1) || !children(&fields, &entry) ||
        !next(&fields, &number, 2, 0) || !serial((span){number.content, number.content_size}) ||
        salts_asn1_reader_next(&fields, &date) != SALTS_ASN1_OK || !salts_crypto_x509_date(&date, &when) || when > issued) return 0;
    span current = {number.content, number.content_size};
    for (size_t i=0; i<count; ++i) if (same(seen[i], current)) return 0;
    seen[count++] = current;
    if (same(target, current)) *revoked = 1;
    if (!end(&fields) && (!next(&fields, &exts, 16, 1) || !entry_extensions(&exts))) return 0;
    if (!end(&fields)) return 0;
  }
  return 1;
}
int salts_crypto_sm2_check_crl(const salts_crypto_sm2_cert_span *certificate,
    const salts_crypto_sm2_cert_span *issuer, int64_t now, const salts_crypto_sm2_crl_policy *policy) {
  crypto_x509_der_view cert, ca; uint8_t key[65]; span ski = {0};
  salts_asn1_reader outer, body; salts_asn1_tlv seq, tbs, algorithm, signature, version, inner, name, first, last, value;
  int64_t issued, expires; unsigned revoked = 0;
  if (!certificate || !issuer || !policy || !certificate->der || !certificate->size || certificate->size > 4096 ||
      !issuer->der || !issuer->size || issuer->size > 4096 || !policy->der || !policy->size ||
      policy->size > SALTS_CRYPTO_SM2_CRL_MAX_BYTES || !policy->issuer_identity || !policy->issuer_identity_size ||
      policy->issuer_identity_size > 8191 || !policy->maximum_age_seconds || now < 0 || now > INT64_C(253402300799)) return SALTS_CRYPTO_EINVAL;
  if (crypto_x509_der_inspect(certificate->der, certificate->size, &cert) != SALTS_ASN1_OK ||
      crypto_x509_der_inspect(issuer->der, issuer->size, &ca) != SALTS_ASN1_OK ||
      !serial((span){cert.serial_number, cert.serial_number_size}) ||
      !salts_crypto_x509_valid_name(ca.subject_der, ca.subject_size) ||
      !same((span){cert.issuer_der, cert.issuer_size}, (span){ca.subject_der, ca.subject_size}) ||
      !salts_crypto_x509_valid_time(&cert, now) || !salts_crypto_x509_valid_time(&ca, now) ||
      !certificate_profile(&cert, 0, &ski) || !certificate_profile(&ca, 1, &ski) ||
      salts_crypto_sm2_x509_public_key(issuer->der, issuer->size, key) != SALTS_CRYPTO_OK) return SALTS_CRYPTO_EVERIFY;
  if (!only((span){policy->der, policy->size}, &seq, 16, 1) || !children(&outer, &seq) ||
      !next(&outer, &tbs, 16, 1) || !next(&outer, &algorithm, 16, 1) ||
      !next(&outer, &signature, 3, 0) || !end(&outer) || signature.content_size < 2 || signature.content[0] ||
      !children(&body, &tbs) || !next(&body, &version, 2, 0) || version.content_size != 1 || version.content[0] != 1 ||
      !next(&body, &inner, 16, 1) || !same(encoded(&inner), encoded(&algorithm)) ||
      !next(&body, &name, 16, 1) || !same(encoded(&name), (span){ca.subject_der, ca.subject_size}) ||
      salts_asn1_reader_next(&body, &first) != SALTS_ASN1_OK || !salts_crypto_x509_date(&first, &issued) ||
      salts_asn1_reader_next(&body, &last) != SALTS_ASN1_OK || !salts_crypto_x509_date(&last, &expires) ||
      issued > now || expires <= now || (uint64_t)(now-issued) > policy->maximum_age_seconds) return SALTS_CRYPTO_EVERIFY;
  if (salts_asn1_reader_next(&body, &value) != SALTS_ASN1_OK) return SALTS_CRYPTO_EVERIFY;
  if (tag(&value, 16, 1)) {
    if (!entries(&value, (span){cert.serial_number, cert.serial_number_size}, issued, &revoked) ||
        salts_asn1_reader_next(&body, &value) != SALTS_ASN1_OK) return SALTS_CRYPTO_EVERIFY;
  }
  if (!crl_extensions(&value, ski, policy->minimum_number) || !end(&body)) return SALTS_CRYPTO_EVERIFY;
  span signed_bytes = encoded(&tbs);
  if (salts_crypto_sm2_signed_der(&algorithm, signed_bytes.data, signed_bytes.size,
      signature.content+1, signature.content_size-1, key, policy->issuer_identity, policy->issuer_identity_size) != SALTS_CRYPTO_OK)
    return SALTS_CRYPTO_EVERIFY;
  return revoked ? SALTS_CRYPTO_EVERIFY : SALTS_CRYPTO_OK;
}
