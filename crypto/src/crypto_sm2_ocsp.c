#include <crypto/sm2_ocsp.h>
#include <crypto/sm2_x509.h>
#include "crypto_x509_policy.h"
#include <gmssl/digest.h>
#include <gmssl/mem.h>
#include <string.h>
#include <stdbool.h>

typedef struct ocsp_span { const uint8_t *data; size_t size; } ocsp_span;
static const uint8_t basic_oid[] = {0x2b,6,1,5,5,7,0x30,1,1};
static const uint8_t nonce_oid[] = {0x2b,6,1,5,5,7,0x30,1,2};
static const uint8_t sm3_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x83,0x11};
static const uint8_t sha256_oid[] = {0x60,0x86,0x48,1,0x65,3,4,2,1};
static const uint8_t sha1_oid[] = {0x2b,0x0e,3,2,0x1a};
static int done(const salts_asn1_reader *r) { return r->offset == r->size; }
static int take(salts_asn1_reader *r, unsigned cls, unsigned constructed, unsigned tag, salts_asn1_tlv *v) {
  return salts_asn1_reader_next(r,v) == SALTS_ASN1_OK && v->tag_class == cls &&
      v->constructed == constructed && v->tag_number == tag;
}
static int enter(salts_asn1_reader *r, unsigned cls, unsigned tag, salts_asn1_reader *out) {
  salts_asn1_tlv v;
  return take(r,cls,1u,tag,&v) && salts_asn1_reader_open_children(r,&v,out) == SALTS_ASN1_OK;
}
static int root(ocsp_span s, salts_asn1_reader *out) {
  salts_asn1_reader r;
  return salts_asn1_reader_init(&r,s.data,s.size,SALTS_ASN1_DER) == SALTS_ASN1_OK && enter(&r,0u,16u,out) && done(&r);
}
static int same(ocsp_span a, ocsp_span b) {
  return a.size == b.size && (!a.size || !memcmp(a.data,b.data,a.size));
}
static ocsp_span encoded(const salts_asn1_tlv *v) {
  return (ocsp_span){v->content-(v->encoded_size-v->content_size),v->encoded_size};
}
static int oid_is(const salts_asn1_tlv *v, const uint8_t *p, size_t n) {
  return same((ocsp_span){v->content,v->content_size},(ocsp_span){p,n});
}
#define OID(v,name) oid_is(v,name,sizeof(name))
static int cert_span(const salts_crypto_sm2_cert_span *s) {
  return s && s->der && s->size && s->size <= SALTS_CRYPTO_SM2_TRUST_MAX_CERT_SIZE;
}
static int admitted(const salts_crypto_sm2_cert_span *cert, const salts_crypto_sm2_cert_span *issuer,
    int64_t now, const salts_crypto_sm2_ocsp_policy *p, bool target) {
  return (!target || cert_span(cert)) && cert_span(issuer) && now >= 0 && now <= INT64_C(253402300799) && p &&
      p->der && p->size && p->size <= SALTS_CRYPTO_SM2_OCSP_MAX_BYTES &&
      p->signer_identity && p->signer_identity_size && p->signer_identity_size <= 8191u &&
      p->maximum_age_seconds && p->maximum_clock_skew_seconds <= SALTS_CRYPTO_SM2_OCSP_MAX_CLOCK_SKEW &&
      p->minimum_this_update >= 0 && p->minimum_this_update <= INT64_C(253402300799) &&
      ((!p->nonce && !p->nonce_size) || (p->nonce && p->nonce_size >= 32u && p->nonce_size <= SALTS_CRYPTO_SM2_OCSP_MAX_NONCE));
}
static int ca_profile(const crypto_x509_der_view *v) {
  if (!v->extensions_der) return 0;
  salts_asn1_reader exts, ext, value; salts_asn1_tlv name, encoded_value, primitive;
  unsigned basic = 0u, key_usage = 0u;
  if (!root((ocsp_span){v->extensions_der,v->extensions_size},&exts)) return 0;
  while (!done(&exts)) {
    bool critical = false;
    if (!enter(&exts,0u,16u,&ext) || !take(&ext,0u,0u,6u,&name) || salts_asn1_reader_next(&ext,&encoded_value) != SALTS_ASN1_OK) return 0;
    if (encoded_value.tag_class == 0u && !encoded_value.constructed && encoded_value.tag_number == 1u) {
      if (encoded_value.content_size != 1u || encoded_value.content[0] != 0xffu) return 0;
      critical = true;
      if (salts_asn1_reader_next(&ext,&encoded_value) != SALTS_ASN1_OK) return 0;
    }
    if (encoded_value.tag_class || encoded_value.constructed || encoded_value.tag_number != 4u || !done(&ext)) return 0;
    unsigned kind = name.content_size == 3u && name.content[0] == 0x55u && name.content[1] == 0x1du ? name.content[2] : 0u;
    if (kind == 19u) {
      if (!critical || !root((ocsp_span){encoded_value.content,encoded_value.content_size},&value) ||
          !take(&value,0u,0u,1u,&primitive) || primitive.content_size != 1u || primitive.content[0] != 0xffu) return 0;
      if (!done(&value) && (!take(&value,0u,0u,2u,&primitive) || !primitive.content_size ||
          (primitive.content[0] & 128u) || primitive.content_size > 4u)) return 0;
      if (!done(&value)) return 0;
      basic = 1u;
    } else if (kind == 15u) {
      salts_asn1_reader bits;
      if (salts_asn1_reader_init(&bits,encoded_value.content,encoded_value.content_size,SALTS_ASN1_DER) != SALTS_ASN1_OK ||
          !take(&bits,0u,0u,3u,&primitive) || !done(&bits) || primitive.content_size < 2u ||
          primitive.content_size > 3u || !(primitive.content[1] & 4u)) return 0;
      key_usage = 1u;
    }
  }
  return basic && key_usage;
}
static int time_value(salts_asn1_reader *r, int64_t *out) {
  salts_asn1_tlv v;
  return take(r,0u,0u,24u,&v) && salts_crypto_generalized_time(&v,out) && *out >= 0;
}
static const DIGEST *identifier_digest(salts_asn1_reader *r) {
  salts_asn1_reader a; salts_asn1_tlv value;
  if (!enter(r,0u,16u,&a) || !take(&a,0u,0u,6u,&value)) return NULL;
  const DIGEST *md = OID(&value,sm3_oid) ? DIGEST_sm3() : OID(&value,sha256_oid) ? DIGEST_sha256() :
      OID(&value,sha1_oid) ? DIGEST_sha1() : NULL;
  if (!md) return NULL;
  if (!done(&a) && (!take(&a,0u,0u,5u,&value) || value.content_size)) return NULL;
  return done(&a) ? md : NULL;
}
static int serial(const salts_asn1_tlv *v) {
  if (!v->content_size || v->content_size > 20u || (v->content[0] & 128u)) return 0;
  unsigned nonzero = 0u;
  for (size_t i = 0u; i < v->content_size; ++i) nonzero |= v->content[i];
  return nonzero != 0u;
}
static int cert_id(salts_asn1_reader *r, const crypto_x509_der_view *cert,
    const crypto_x509_der_view *issuer, const uint8_t pub[65], bool *matches) {
  salts_asn1_reader id; salts_asn1_tlv name_hash, key_hash, serial_number;
  if (!enter(r,0u,16u,&id)) return 0;
  const DIGEST *md = identifier_digest(&id);
  if (!md || !take(&id,0u,0u,4u,&name_hash) || name_hash.content_size != md->digest_size ||
      !take(&id,0u,0u,4u,&key_hash) || key_hash.content_size != md->digest_size ||
      !take(&id,0u,0u,2u,&serial_number) || !serial(&serial_number) || !done(&id)) return 0;
  uint8_t name[32], key[32]; size_t n;
  if (digest(md,issuer->subject_der,issuer->subject_size,name,&n) != 1 || n != md->digest_size ||
      digest(md,pub,65u,key,&n) != 1 || n != md->digest_size) return 0;
  if (gmssl_secure_memcmp(name,name_hash.content,n) || gmssl_secure_memcmp(key,key_hash.content,n)) return 0;
  *matches = cert && same((ocsp_span){cert->serial_number,cert->serial_number_size},
      (ocsp_span){serial_number.content,serial_number.content_size});
  return 1;
}
static int single_responses(salts_asn1_reader *r, const crypto_x509_der_view *cert,
    const crypto_x509_der_view *issuer, const uint8_t pub[65], int64_t produced, int64_t now,
    const salts_crypto_sm2_ocsp_policy *policy) {
  salts_asn1_reader list, response, child;
  salts_asn1_tlv id, status, reason;
  ocsp_span ids[SALTS_CRYPTO_SM2_OCSP_MAX_RESPONSES]; size_t count = 0u, matches = 0u;
  bool good = false;
  if (!enter(r,0u,16u,&list)) return 0;
  while (!done(&list)) {
    bool match;
    if (count == SALTS_CRYPTO_SM2_OCSP_MAX_RESPONSES || !enter(&list,0u,16u,&response)) return 0;
    salts_asn1_reader id_reader = response;
    if (!take(&id_reader,0u,1u,16u,&id) || !cert_id(&response,cert,issuer,pub,&match)) return 0;
    ocsp_span current = encoded(&id);
    for (size_t i = 0u; i < count; ++i) if (same(current,ids[i])) return 0;
    ids[count++] = current;
    if (salts_asn1_reader_next(&response,&status) != SALTS_ASN1_OK || status.tag_class != 2u || status.tag_number > 2u) return 0;
    int64_t revocation_time = -1;
    if (status.tag_number == 1u) {
      if (!status.constructed || salts_asn1_reader_open_children(&response,&status,&child) != SALTS_ASN1_OK ||
          !time_value(&child,&revocation_time) || revocation_time > produced) return 0;
      if (!done(&child)) {
        salts_asn1_reader explicit_reason;
        if (!enter(&child,2u,0u,&explicit_reason) || !take(&explicit_reason,0u,0u,10u,&reason) ||
            reason.content_size != 1u || reason.content[0] > 10u || reason.content[0] == 7u ||
            !done(&explicit_reason) || !done(&child)) return 0;
      }
    } else if (status.constructed || status.content_size) return 0;
    int64_t this_update, next_update;
    if (!time_value(&response,&this_update) || !enter(&response,2u,0u,&child) ||
        !time_value(&child,&next_update) || !done(&child) || !done(&response) ||
        revocation_time > this_update || this_update > produced || produced >= next_update || this_update < policy->minimum_this_update ||
        this_update > now + policy->maximum_clock_skew_seconds || now - (int64_t)policy->maximum_clock_skew_seconds >= next_update ||
        (now > this_update && (uint64_t)(now-this_update) > policy->maximum_age_seconds)) return 0;
    if (match) { ++matches; good = status.tag_number == 0u; }
  }
  return count && (!cert || (matches == 1u && good));
}
static int response_nonce(salts_asn1_reader *r, const salts_crypto_sm2_ocsp_policy *p) {
  if (done(r)) return !p->nonce;
  salts_asn1_reader explicit_value, exts, ext, value; salts_asn1_tlv name, field;
  if (!enter(r,2u,1u,&explicit_value) || !done(r) || !enter(&explicit_value,0u,16u,&exts) || !done(&explicit_value) ||
      !enter(&exts,0u,16u,&ext) || !done(&exts) || !take(&ext,0u,0u,6u,&name) || !OID(&name,nonce_oid) ||
      salts_asn1_reader_next(&ext,&field) != SALTS_ASN1_OK) return 0;
  if (field.tag_class == 0u && !field.constructed && field.tag_number == 1u) {
    if (field.content_size != 1u || field.content[0] != 0xffu || salts_asn1_reader_next(&ext,&field) != SALTS_ASN1_OK) return 0;
  }
  if (field.tag_class || field.constructed || field.tag_number != 4u || !done(&ext) ||
      salts_asn1_reader_init(&value,field.content,field.content_size,SALTS_ASN1_DER) != SALTS_ASN1_OK ||
      !take(&value,0u,0u,4u,&field) || !done(&value) || !p->nonce || field.content_size != p->nonce_size) return 0;
  return gmssl_secure_memcmp(field.content,p->nonce,p->nonce_size) == 0;
}
static int responder_id(salts_asn1_reader *r, const crypto_x509_der_view *issuer, const uint8_t pub[65]) {
  salts_asn1_tlv value; salts_asn1_reader inner;
  if (salts_asn1_reader_next(r,&value) != SALTS_ASN1_OK || value.tag_class != 2u || !value.constructed ||
      salts_asn1_reader_open_children(r,&value,&inner) != SALTS_ASN1_OK) return 0;
  if (value.tag_number == 1u) {
    if (!take(&inner,0u,1u,16u,&value) || !done(&inner)) return 0;
    return same(encoded(&value),(ocsp_span){issuer->subject_der,issuer->subject_size});
  }
  if (value.tag_number == 2u) {
    uint8_t hash[20]; size_t n;
    return take(&inner,0u,0u,4u,&value) && done(&inner) && value.content_size == sizeof(hash) &&
        digest(DIGEST_sha1(),pub,65u,hash,&n) == 1 && n == sizeof(hash) &&
        !gmssl_secure_memcmp(hash,value.content,sizeof(hash));
  }
  return 0;
}

static int delegated_profile(const salts_crypto_sm2_cert_span *issuer, int64_t now,
    const salts_crypto_sm2_delegated_ocsp_policy *d, crypto_x509_der_view *signer, uint8_t pub[65]) {
  if (crypto_x509_der_inspect(d->responder_certificate.der,d->responder_certificate.size,signer) != SALTS_ASN1_OK ||
      salts_crypto_sm2_x509_public_key(d->responder_certificate.der,d->responder_certificate.size,pub) != SALTS_CRYPTO_OK ||
      !signer->extensions_der) return 0;
  salts_asn1_reader list, ext; salts_asn1_tlv name, value;
  static const uint8_t nocheck_oid[] = {0x2b,6,1,5,5,7,0x30,1,5};
  unsigned nocheck = 0u;
  if (!root((ocsp_span){signer->extensions_der,signer->extensions_size},&list)) return 0;
  while (!done(&list)) {
    if (!enter(&list,0u,16u,&ext) || !take(&ext,0u,0u,6u,&name)) return 0;
    if (OID(&name,nocheck_oid)) {
      if (!take(&ext,0u,0u,4u,&value) || !done(&ext) || value.content_size != 2u ||
          value.content[0] != 5u || value.content[1] != 0u) return 0;
      ++nocheck;
    }
  }
  if (nocheck != 1u) return 0;
  salts_crypto_sm2_chain_entry entry = {d->responder_certificate,d->responder_issuer_identity,d->responder_issuer_identity_size};
  /* The responder key is selected explicitly; authority comes from the complete
   * CA signature/path, exact OCSP purpose and the issuer's no-check extension. */
  uint8_t validated[65];
  salts_crypto_sm2_trust_policy trust = {*issuer,pub,now,SALTS_CRYPTO_SM2_TRUST_OCSP_SIGNING,
      SALTS_CRYPTO_SM2_REVOCATION_NOT_CHECKED,NULL,NULL};
  return salts_crypto_sm2_validate_pinned_chain(&entry,1u,&trust,validated) == SALTS_CRYPTO_OK;
}
static int check_response(const salts_crypto_sm2_cert_span *certificate,
    const salts_crypto_sm2_cert_span *issuer, int64_t now, const salts_crypto_sm2_ocsp_policy *p, bool target,
    const salts_crypto_sm2_delegated_ocsp_policy *delegate) {
  if (!admitted(certificate,issuer,now,p,target)) return SALTS_CRYPTO_EINVAL;
  crypto_x509_der_view cert, ca;
  uint8_t public_key[65];
  if (crypto_x509_der_inspect(issuer->der,issuer->size,&ca) != SALTS_ASN1_OK || ca.version != 2u || !ca_profile(&ca) ||
      !salts_crypto_x509_valid_name(ca.subject_der,ca.subject_size) || !salts_crypto_x509_valid_time(&ca,now) ||
      salts_crypto_sm2_x509_public_key(issuer->der,issuer->size,public_key) != SALTS_CRYPTO_OK) return SALTS_CRYPTO_EVERIFY;
  if (target && (crypto_x509_der_inspect(certificate->der,certificate->size,&cert) != SALTS_ASN1_OK || cert.version != 2u ||
      !same((ocsp_span){cert.issuer_der,cert.issuer_size},(ocsp_span){ca.subject_der,ca.subject_size}) ||
      !salts_crypto_x509_valid_time(&cert,now))) return SALTS_CRYPTO_EVERIFY;
  crypto_x509_der_view signer = ca;
  uint8_t signer_key[65]; memcpy(signer_key,public_key,sizeof(signer_key));
  if (delegate && !delegated_profile(issuer,now,delegate,&signer,signer_key)) return SALTS_CRYPTO_EVERIFY;
  salts_asn1_reader response, explicit_value, bytes, basic, data, certs, embedded;
  salts_asn1_tlv field, signed_data, algorithm, signature;
  if (!root((ocsp_span){p->der,p->size},&response) || !take(&response,0u,0u,10u,&field) ||
      field.content_size != 1u || field.content[0] != 0u || !enter(&response,2u,0u,&explicit_value) || !done(&response) ||
      !enter(&explicit_value,0u,16u,&bytes) || !done(&explicit_value) || !take(&bytes,0u,0u,6u,&field) || !OID(&field,basic_oid) ||
      !take(&bytes,0u,0u,4u,&field) || !done(&bytes) || !root((ocsp_span){field.content,field.content_size},&basic) ||
      !take(&basic,0u,1u,16u,&signed_data) || !take(&basic,0u,1u,16u,&algorithm) || !take(&basic,0u,0u,3u,&signature) ||
      signature.content_size < 2u || signature.content[0] != 0u) return SALTS_CRYPTO_EVERIFY;
  if (!done(&basic)) {
    const salts_crypto_sm2_cert_span *first = delegate ? &delegate->responder_certificate : issuer;
    if (!enter(&basic,2u,0u,&certs) || !done(&basic) || !enter(&certs,0u,16u,&embedded) || !done(&certs) ||
        !take(&embedded,0u,1u,16u,&field) ||
        !same(encoded(&field),(ocsp_span){first->der,first->size})) return SALTS_CRYPTO_EVERIFY;
    if (!done(&embedded) && (!delegate || !take(&embedded,0u,1u,16u,&field) ||
        !same(encoded(&field),(ocsp_span){issuer->der,issuer->size}))) return SALTS_CRYPTO_EVERIFY;
    if (!done(&embedded)) return SALTS_CRYPTO_EVERIFY;
  }
  if (salts_asn1_reader_open_children(&basic,&signed_data,&data) != SALTS_ASN1_OK ||
      !responder_id(&data,&signer,signer_key)) return SALTS_CRYPTO_EVERIFY;
  int64_t produced;
  if (!time_value(&data,&produced) || produced > now + p->maximum_clock_skew_seconds ||
      (delegate && !salts_crypto_x509_valid_time(&signer,produced)) ||
      !single_responses(&data,target ? &cert : NULL,&ca,public_key,produced,now,p) || !response_nonce(&data,p)) return SALTS_CRYPTO_EVERIFY;
  ocsp_span tbs = encoded(&signed_data);
  return salts_crypto_sm2_signed_der(&algorithm,tbs.data,tbs.size,signature.content+1u,signature.content_size-1u,
      signer_key,p->signer_identity,p->signer_identity_size) == SALTS_CRYPTO_OK ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
}

int salts_crypto_sm2_check_direct_ocsp(const salts_crypto_sm2_cert_span *certificate,
    const salts_crypto_sm2_cert_span *issuer, int64_t time, const salts_crypto_sm2_ocsp_policy *policy) {
  return check_response(certificate,issuer,time,policy,true,NULL);
}
int salts_crypto_sm2_validate_direct_ocsp(const salts_crypto_sm2_cert_span *issuer,
    int64_t time, const salts_crypto_sm2_ocsp_policy *policy) {
  return check_response(NULL,issuer,time,policy,false,NULL);
}

static int delegate_admitted(const salts_crypto_sm2_delegated_ocsp_policy *p) {
  return p && cert_span(&p->responder_certificate) && p->responder_issuer_identity &&
      p->responder_issuer_identity_size && p->responder_issuer_identity_size <= 8191u;
}
int salts_crypto_sm2_check_delegated_ocsp(const salts_crypto_sm2_cert_span *cert,
    const salts_crypto_sm2_cert_span *issuer, int64_t time, const salts_crypto_sm2_delegated_ocsp_policy *p) {
  if (!delegate_admitted(p)) return SALTS_CRYPTO_EINVAL;
  return check_response(cert,issuer,time,&p->response,true,p);
}
int salts_crypto_sm2_validate_delegated_ocsp(const salts_crypto_sm2_cert_span *issuer,
    int64_t time, const salts_crypto_sm2_delegated_ocsp_policy *p) {
  if (!delegate_admitted(p)) return SALTS_CRYPTO_EINVAL;
  return check_response(NULL,issuer,time,&p->response,false,p);
}
