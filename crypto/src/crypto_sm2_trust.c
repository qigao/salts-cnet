#include <crypto/sm2_trust.h>
#include <crypto/sm2_x509.h>
#include <crypto/x509_der.h>
#include "crypto_internal.h"
#include "crypto_x509_policy.h"
#include <string.h>

typedef struct cert_policy {
  crypto_x509_der_view view;
  uint8_t public_key[65];
  unsigned ca, basic, basic_critical, ku, eku, purpose;
  uint32_t path_length;
} cert_policy;
static int tag(const salts_asn1_tlv *v, uint32_t number, unsigned constructed) {
  return !v->tag_class && v->tag_number == number && v->constructed == constructed;
}
static int next(salts_asn1_reader *r, salts_asn1_tlv *v, uint32_t number, unsigned constructed) {
  return salts_asn1_reader_next(r, v) == SALTS_ASN1_OK && tag(v, number, constructed);
}
static int end(const salts_asn1_reader *r) { return r->offset == r->size; }
static int sequence(const void *data, size_t n, salts_asn1_reader *r) {
  salts_asn1_reader top; salts_asn1_tlv v;
  return salts_asn1_reader_init(&top, data, n, SALTS_ASN1_DER) == SALTS_ASN1_OK &&
      next(&top, &v, 16, 1) && end(&top) &&
      salts_asn1_reader_open_children(&top, &v, r) == SALTS_ASN1_OK;
}
static int basic_constraints(cert_policy *p, const salts_asn1_tlv *value, unsigned critical) {
  salts_asn1_reader r; salts_asn1_tlv v;
  p->basic = 1; p->basic_critical = critical;
  if (!sequence(value->content, value->content_size, &r)) return 0;
  if (end(&r)) return 1;
  if (!next(&r, &v, 1, 0) || v.content_size != 1 || v.content[0] != 0xff) return 0;
  p->ca = 1;
  if (end(&r)) return 1;
  if (!next(&r, &v, 2, 0) || !v.content_size || v.content_size > 4 || (v.content[0] & 128) || !end(&r)) return 0;
  p->path_length = 0;
  for (size_t i=0; i<v.content_size; ++i) p->path_length = (p->path_length << 8) | v.content[i];
  return 1;
}
static int key_usage(cert_policy *p, const salts_asn1_tlv *value) {
  salts_asn1_reader r; salts_asn1_tlv v;
  if (salts_asn1_reader_init(&r, value->content, value->content_size, SALTS_ASN1_DER) != SALTS_ASN1_OK ||
      !next(&r, &v, 3, 0) || !end(&r) || v.content_size < 2 || v.content_size > 3) return 0;
  unsigned bits = (unsigned)(v.content_size-1u)*8u-v.content[0];
  if (!bits || bits > 9 || !(v.content[v.content_size-1] & (1u << v.content[0]))) return 0;
  p->ku = 0;
  for (unsigned i=0; i<bits; ++i) if (v.content[1+i/8u] & (128u >> (i%8u))) p->ku |= 1u << i;
  /* encipherOnly/decipherOnly require keyAgreement. */
  return !(p->ku & ((1u << 7)|(1u << 8))) || (p->ku & (1u << 4));
}
static int extended_usage(cert_policy *p, const salts_asn1_tlv *value, unsigned purpose) {
  const uint8_t prefix[] = {0x2b,6,1,5,5,7,3};
  salts_asn1_reader r; salts_asn1_tlv v;
  if (!sequence(value->content, value->content_size, &r) || end(&r)) return 0;
  p->eku = 1;
  while (!end(&r)) {
    if (!next(&r, &v, 6, 0)) return 0;
    if (v.content_size == sizeof(prefix)+1 && !memcmp(v.content, prefix, sizeof(prefix)) &&
        v.content[sizeof(prefix)] == purpose) p->purpose = 1;
  }
  return 1;
}
static int extensions(cert_policy *p, unsigned purpose) {
  salts_asn1_reader r, fields; salts_asn1_tlv ext, oid, value;
  p->path_length = UINT32_MAX;
  if (!p->view.extensions_der) return 1;
  if (!sequence(p->view.extensions_der, p->view.extensions_size, &r)) return 0;
  while (!end(&r)) {
    unsigned critical = 0;
    if (!next(&r, &ext, 16, 1) || salts_asn1_reader_open_children(&r, &ext, &fields) != SALTS_ASN1_OK ||
        !next(&fields, &oid, 6, 0) || salts_asn1_reader_next(&fields, &value) != SALTS_ASN1_OK) return 0;
    if (tag(&value, 1, 0)) {
      if (value.content_size != 1 || value.content[0] != 0xff) return 0;
      critical = 1;
      if (salts_asn1_reader_next(&fields, &value) != SALTS_ASN1_OK) return 0;
    }
    if (!tag(&value, 4, 0) || !end(&fields)) return 0;
    unsigned ce = oid.content_size == 3 && oid.content[0] == 0x55 && oid.content[1] == 0x1d ? oid.content[2] : 0;
    if (ce == 19) { if (!basic_constraints(p, &value, critical)) return 0; }
    else if (ce == 15) { if (!key_usage(p, &value)) return 0; }
    else if (ce == 37) { if (!extended_usage(p, &value, purpose)) return 0; }
    else if (critical || ce == 30 || ce == 32 || ce == 33 || ce == 36 || ce == 54) return 0;
  }
  return 1;
}
static int same(const void *a, size_t an, const void *b, size_t bn) {
  return an == bn && !memcmp(a, b, an);
}
static int valid_span(const salts_crypto_sm2_cert_span *span) {
  return span->der && span->size && span->size <= SALTS_CRYPTO_SM2_TRUST_MAX_CERT_SIZE;
}
int salts_crypto_sm2_trust_admitted(const salts_crypto_sm2_chain_entry *chain, size_t count,
    const salts_crypto_sm2_trust_policy *p, const uint8_t *out) {
  if (!chain || !count || count > SALTS_CRYPTO_SM2_TRUST_MAX_CHAIN || !p || !out ||
      !valid_span(&p->anchor) || !p->expected_leaf_public_key || p->validation_time < 0 ||
      p->validation_time > INT64_C(253402300799) ||
      (p->purpose != SALTS_CRYPTO_SM2_TRUST_SERVER_SIGNING && p->purpose != SALTS_CRYPTO_SM2_TRUST_CLIENT_SIGNING &&
       p->purpose != SALTS_CRYPTO_SM2_TRUST_CODE_SIGNING && p->purpose != SALTS_CRYPTO_SM2_TRUST_EMAIL_PROTECTION &&
       p->purpose != SALTS_CRYPTO_SM2_TRUST_TIME_STAMPING && p->purpose != SALTS_CRYPTO_SM2_TRUST_OCSP_SIGNING &&
       p->purpose != SALTS_CRYPTO_SM2_TRUST_EMAIL_ENCRYPTION) ||
      (p->revocation != SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL && p->revocation != SALTS_CRYPTO_SM2_REVOCATION_NOT_CHECKED)) return 0;
  if (p->revocation == SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL) { if (!p->check_revocation) return 0; }
  else if (p->check_revocation || p->revocation_context) return 0;
  if (salts_crypto_overlap(out, 65, p, sizeof(*p)) || salts_crypto_overlap(out, 65, chain, count*sizeof(*chain)) ||
      salts_crypto_overlap(out, 65, p->expected_leaf_public_key, 65) ||
      salts_crypto_overlap(out, 65, p->anchor.der, p->anchor.size)) return 0;
  for (size_t i=0; i<count; ++i)
    if (!valid_span(&chain[i].certificate) || !chain[i].issuer_identity || !chain[i].issuer_identity_size ||
        chain[i].issuer_identity_size > 8191 || salts_crypto_overlap(out, 65, chain[i].certificate.der, chain[i].certificate.size) ||
        salts_crypto_overlap(out, 65, chain[i].issuer_identity, chain[i].issuer_identity_size)) return 0;
  return 1;
}
int salts_crypto_sm2_validate_pinned_chain(const salts_crypto_sm2_chain_entry *chain,
    size_t count, const salts_crypto_sm2_trust_policy *policy, uint8_t public_key[65]) {
  cert_policy certs[SALTS_CRYPTO_SM2_TRUST_MAX_CHAIN+1] = {0};
  if (!salts_crypto_sm2_trust_admitted(chain, count, policy, public_key)) return SALTS_CRYPTO_EINVAL;
  for (size_t i=0; i<=count; ++i) {
    const salts_crypto_sm2_cert_span *span = i == count ? &policy->anchor : &chain[i].certificate;
    cert_policy *c = &certs[i];
    if (crypto_x509_der_inspect(span->der, span->size, &c->view) != SALTS_ASN1_OK || c->view.version != 2 ||
        !salts_crypto_x509_valid_name(c->view.subject_der, c->view.subject_size) || !salts_crypto_x509_valid_name(c->view.issuer_der, c->view.issuer_size) ||
        salts_crypto_sm2_x509_public_key(span->der, span->size, c->public_key) != SALTS_CRYPTO_OK ||
        !salts_crypto_x509_valid_time(&c->view, policy->validation_time) || !extensions(c, policy->purpose == SALTS_CRYPTO_SM2_TRUST_EMAIL_ENCRYPTION ? 4u : (unsigned)policy->purpose)) goto reject;
    if (i == 0) {
      const unsigned required_usage = policy->purpose == SALTS_CRYPTO_SM2_TRUST_EMAIL_ENCRYPTION ? 1u << 2 : 1u;
      if (c->ca || !(c->ku & required_usage) || (c->ku & ((1u<<5)|(1u<<6))) || !c->eku || !c->purpose ||
          memcmp(c->public_key, policy->expected_leaf_public_key, 65)) goto reject;
    } else {
      if (!c->basic || !c->basic_critical || !c->ca || !(c->ku & (1u<<5)) || c->path_length < i-1u ||
          (c->eku && !c->purpose)) goto reject;
      if (i != count && same(c->view.issuer_der, c->view.issuer_size, c->view.subject_der, c->view.subject_size)) goto reject;
    }
    for (size_t j=0; j<i; ++j)
      if (same(c->view.certificate_der, c->view.certificate_size, certs[j].view.certificate_der, certs[j].view.certificate_size)) goto reject;
  }
  for (size_t i=0; i<count; ++i) {
    const crypto_x509_der_view *child = &certs[i].view, *issuer = &certs[i+1].view;
    if (!same(child->issuer_der, child->issuer_size, issuer->subject_der, issuer->subject_size) ||
        salts_crypto_sm2_x509_verify_signature(child->certificate_der, child->certificate_size, certs[i+1].public_key,
          chain[i].issuer_identity, chain[i].issuer_identity_size) != SALTS_CRYPTO_OK) goto reject;
  }
  if (policy->revocation == SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL)
    for (size_t i=0; i<count; ++i) {
      const salts_crypto_sm2_cert_span *issuer = i+1 == count ? &policy->anchor : &chain[i+1].certificate;
      if (policy->check_revocation(policy->revocation_context, i, &chain[i].certificate, issuer,
          policy->validation_time) != SALTS_CRYPTO_OK) goto reject;
    }
  memcpy(public_key, certs[0].public_key, 65);
  return SALTS_CRYPTO_OK;
reject:
  salts_crypto_secure_zero(public_key, 65);
  return SALTS_CRYPTO_EVERIFY;
}
