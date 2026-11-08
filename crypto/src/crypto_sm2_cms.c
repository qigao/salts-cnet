#include <crypto/sm2_cms.h>
#include <crypto/sm2.h>
#include <crypto/sm2_x509.h>
#include <crypto/sm3.h>
#include <crypto/asn1_crypto.h>
#include "crypto_cms_der.h"
#include "crypto_x509_policy.h"
#include <gmssl/mem.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t rfc_prefix[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7};
static const uint8_t gm_prefix[] = {0x2a,0x81,0x1c,0xcf,0x55,6,1,4,2};
static const uint8_t sm3_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x83,0x11};
static const uint8_t sm2_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x82,0x2d,1};
static const uint8_t sm2_sm3_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x83,0x75};
static const uint8_t attr_prefix[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9};
enum { CMS_ATTRIBUTES_MAX = 256, CMS_SIGNER_MAX = SALTS_CRYPTO_SM2_TRUST_MAX_CERT_SIZE + 512 };
/* Schema composition only: every TLV and canonical universal value is encoded
 * and parsed by the existing ASN1 owner. No second tag/length implementation. */

static void one(cms_writer *w) { const uint8_t v = 1u; put(w, 0u, 0u, 2u, &v, 1u); }

static void content_oid(cms_writer *w, salts_crypto_sm2_cms_format format, unsigned type) {
  uint8_t value[sizeof(gm_prefix) + 1u];
  const uint8_t *prefix = format == SALTS_CRYPTO_SM2_CMS_RFC5652 ? rfc_prefix : gm_prefix;
  size_t n = format == SALTS_CRYPTO_SM2_CMS_RFC5652 ? sizeof(rfc_prefix) : sizeof(gm_prefix);
  memcpy(value, prefix, n); value[n++] = (uint8_t)type;
  oid(w, value, n);
}
static void algorithm(cms_writer *w, const void *value, size_t n) {
  uint8_t storage[32]; cms_writer a = {storage,0u,sizeof(storage),0};
  oid(&a, value, n); put(&a, 0u, 0u, 5u, NULL, 0u);
  wrap(w, 0u, 16u, &a);
}

static int format_valid(salts_crypto_sm2_cms_format f) {
  return f == SALTS_CRYPTO_SM2_CMS_RFC5652 || f == SALTS_CRYPTO_SM2_CMS_SHANGMI;
}
static int id_valid(const void *id, size_t n) { return id && n && n <= 8191u; }

static void attribute(cms_writer *attrs, unsigned type, const cms_writer *value) {
  uint8_t bytes[128], name[sizeof(attr_prefix)+1u];
  cms_writer a = {bytes,0u,sizeof(bytes),0};
  memcpy(name, attr_prefix, sizeof(attr_prefix)); name[sizeof(attr_prefix)] = (uint8_t)type;
  oid(&a, name, sizeof(name)); wrap(&a, 0u, 17u, value); wrap(attrs, 0u, 16u, &a);
}
static int signed_attributes(salts_crypto_sm2_cms_format format, const void *content, size_t n,
    uint8_t out[CMS_ATTRIBUTES_MAX], size_t *written) {
  uint8_t digest[32], bytes[64], attrs[CMS_ATTRIBUTES_MAX];
  cms_writer value = {bytes,0u,sizeof(bytes),0}, list = {attrs,0u,sizeof(attrs),0};
  cms_writer encoded = {out,0u,CMS_ATTRIBUTES_MAX,0};
  int status = salts_crypto_sm3(content, n, digest);
  if (status != SALTS_CRYPTO_OK) return 0;
  content_oid(&value, format, 1u); attribute(&list, 3u, &value);
  value.size = 0u; put(&value, 0u, 0u, 4u, digest, sizeof(digest)); attribute(&list, 4u, &value);
  /* contentType's shorter DER precedes messageDigest. The ASN1 encoder also
   * enforces SET order; never sign a differently ordered implicit encoding. */
  wrap(&encoded, 0u, 17u, &list);
  salts_crypto_secure_zero(digest, sizeof(digest));
  if (encoded.failed) return 0;
  *written = encoded.size;
  return 1;
}

int salts_crypto_sm2_cms_sign(const salts_crypto_sm2_cms_sign_config *c,
    const void *content, size_t n, void *out, size_t cap, size_t *written) {
  const size_t bound = SALTS_CRYPTO_SM2_CMS_MAX_DER;
  if (!c || !output_valid(out,cap,bound,written) || !format_valid(c->format) || !c->private_key ||
      !id_valid(c->signer_identity,c->signer_identity_size) || (!content && n) ||
      n > SALTS_CRYPTO_SM2_CMS_MAX_CONTENT || !c->certificates || !c->certificate_count ||
      c->certificate_count > SALTS_CRYPTO_SM2_TRUST_MAX_CHAIN ||
      !disjoint(out,bound,written,c,sizeof(*c)) || !disjoint(out,bound,written,c->private_key,32u) ||
      !disjoint(out,bound,written,c->signer_identity,c->signer_identity_size) ||
      !disjoint(out,bound,written,content,n) ||
      !disjoint(out,bound,written,c->certificates,c->certificate_count*sizeof(*c->certificates))) return SALTS_CRYPTO_EINVAL;
  size_t cert_bytes = 0u;
  cms_span certs[SALTS_CRYPTO_SM2_TRUST_MAX_CHAIN];
  for (size_t i = 0u; i < c->certificate_count; ++i) {
    const salts_crypto_sm2_cert_span *v = c->certificates + i;
    if (!v->der || !v->size || v->size > SALTS_CRYPTO_SM2_TRUST_MAX_CERT_SIZE ||
        !disjoint(out,bound,written,v->der,v->size)) return SALTS_CRYPTO_EINVAL;
    certs[i] = (cms_span){v->der,v->size}; cert_bytes += v->size;
  }
  int status = SALTS_CRYPTO_EVERIFY;
  uint8_t attrs[CMS_ATTRIBUTES_MAX], signature[64], der_signature[72];
  uint8_t signer_content[CMS_SIGNER_MAX], signer_der[CMS_SIGNER_MAX+8u];
  uint8_t *workspace = NULL;
  size_t attrs_size = 0u, signature_size = 0u;
  crypto_x509_der_view leaf;
  for (size_t i = 0u; i < c->certificate_count; ++i) {
    crypto_x509_der_view checked;
    if (crypto_x509_der_inspect(certs[i].data,certs[i].size,&checked) != SALTS_ASN1_OK) goto end;
    if (i == 0u) leaf = checked;
    for (size_t j = 0u; j < i; ++j) if (same(certs[i],certs[j])) goto end;
  }
  if (salts_crypto_sm2_x509_matches_private_key(leaf.certificate_der,leaf.certificate_size,c->private_key) != SALTS_CRYPTO_OK)
    goto end;
  if (!signed_attributes(c->format,content,n,attrs,&attrs_size)) { status = SALTS_CRYPTO_ECRYPTO; goto end; }
  status = salts_crypto_sm2_sign(c->private_key,c->signer_identity,c->signer_identity_size,attrs,attrs_size,signature);
  if (status != SALTS_CRYPTO_OK) { status = SALTS_CRYPTO_ECRYPTO; goto end; }
  if (crypto_asn1_ecdsa_signature_encode(signature,32u,signature+32u,32u,
      der_signature,sizeof(der_signature),&signature_size) != SALTS_ASN1_OK) { status = SALTS_CRYPTO_ECRYPTO; goto end; }
  for (size_t i = 1u; i < c->certificate_count; ++i) {
    cms_span v = certs[i]; size_t j = i;
    while (j && compare(certs[j-1u],v) > 0) { certs[j] = certs[j-1u]; --j; }
    certs[j] = v;
  }
  cms_writer si = {signer_content,0u,sizeof(signer_content),0};
  cms_writer signer = {signer_der,0u,sizeof(signer_der),0};
  uint8_t sid_bytes[SALTS_CRYPTO_SM2_TRUST_MAX_CERT_SIZE+32u];
  cms_writer sid = {sid_bytes,0u,sizeof(sid_bytes),0};
  raw(&sid,leaf.issuer_der,leaf.issuer_size);
  put(&sid,0u,0u,2u,leaf.serial_number,leaf.serial_number_size);
  one(&si); wrap(&si,0u,16u,&sid); algorithm(&si,sm3_oid,sizeof(sm3_oid));
  /* Reuse the exact canonical SET encoding as IMPLICIT [0]. */
  attrs[0] = 0xa0u; raw(&si,attrs,attrs_size); attrs[0] = 0x31u;
  algorithm(&si,sm2_oid,sizeof(sm2_oid)); put(&si,0u,0u,4u,der_signature,signature_size);
  wrap(&signer,0u,16u,&si);
  if (signer.failed) { status = SALTS_CRYPTO_ECRYPTO; goto end; }
  const size_t local_bound = (c->detached ? 0u : n) + cert_bytes + leaf.issuer_size + 1024u;
  const size_t content_bound = c->detached ? 8u : n + 8u;
  const size_t allocation = 2u*local_bound + content_bound;
  workspace = malloc(allocation);
  if (!workspace) { status = SALTS_CRYPTO_ECRYPTO; goto end; }
  cms_writer a = {workspace,0u,local_bound,0}, b = {workspace+local_bound,0u,local_bound,0};
  cms_writer octet = {workspace+2u*local_bound,0u,content_bound,0};
  /* SignedData content in b; a is reused after each complete child is copied. */
  one(&b); algorithm(&a,sm3_oid,sizeof(sm3_oid)); wrap(&b,0u,17u,&a);
  a.size = 0u; content_oid(&a,c->format,1u);
  if (!c->detached) { put(&octet,0u,0u,4u,content,n); wrap(&a,2u,0u,&octet); }
  wrap(&b,0u,16u,&a);
  a.size = 0u;
  for (size_t i = 0u; i < c->certificate_count; ++i) raw(&a,certs[i].data,certs[i].size);
  wrap(&b,2u,0u,&a); put(&b,0u,1u,17u,signer.data,signer.size);
  a.size = 0u; wrap(&a,0u,16u,&b);
  b.size = 0u; content_oid(&b,c->format,2u); wrap(&b,2u,0u,&a);
  a.size = 0u; wrap(&a,0u,16u,&b);
  if (a.failed || a.size > bound) status = SALTS_CRYPTO_ECRYPTO;
  else { memcpy(out,a.data,a.size); *written = a.size; status = SALTS_CRYPTO_OK; }
  salts_crypto_secure_zero(workspace,allocation); free(workspace); workspace = NULL;
end:
  salts_crypto_secure_zero(signature,sizeof(signature));
  salts_crypto_secure_zero(attrs,sizeof(attrs));
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(out,bound); *written = 0u; }
  return status;
}

static int match_content(salts_asn1_reader *r, salts_crypto_sm2_cms_format f, unsigned type) {
  uint8_t value[sizeof(gm_prefix)+1u];
  const uint8_t *prefix = f == SALTS_CRYPTO_SM2_CMS_RFC5652 ? rfc_prefix : gm_prefix;
  size_t n = f == SALTS_CRYPTO_SM2_CMS_RFC5652 ? sizeof(rfc_prefix) : sizeof(gm_prefix);
  memcpy(value,prefix,n); value[n++] = (uint8_t)type;
  salts_asn1_tlv v;
  return take(r,0u,0u,6u,&v) && is_oid(&v,value,n);
}
static int version_one(salts_asn1_reader *r) {
  salts_asn1_tlv v;
  return take(r,0u,0u,2u,&v) && v.content_size == 1u && v.content[0] == 1u;
}
static int parse_algorithm(salts_asn1_reader *r, int signature) {
  salts_asn1_reader a; salts_asn1_tlv value;
  if (!enter(r,0u,16u,&a) || !take(&a,0u,0u,6u,&value)) return 0;
  if (signature ? (!is_oid(&value,sm2_oid,sizeof(sm2_oid)) && !is_oid(&value,sm2_sm3_oid,sizeof(sm2_sm3_oid)))
                : !is_oid(&value,sm3_oid,sizeof(sm3_oid))) return 0;
  if (!done(&a) && (!take(&a,0u,0u,5u,&value) || value.content_size)) return 0;
  return done(&a);
}
static int parse_certificates(salts_asn1_reader *r, const salts_crypto_sm2_cms_verify_config *c) {
  salts_asn1_reader set; salts_asn1_tlv cert;
  bool seen[SALTS_CRYPTO_SM2_TRUST_MAX_CHAIN] = {false};
  cms_span previous = {NULL,0u}; size_t count = 0u;
  if (!enter(r,2u,0u,&set)) return 0;
  while (!done(&set)) {
    size_t start = set.offset;
    if (++count > c->chain_count || !take(&set,0u,1u,16u,&cert)) return 0;
    cms_span current = {set.data+start,cert.encoded_size};
    if (previous.data && compare(previous,current) >= 0) return 0;
    previous = current;
    size_t i;
    for (i = 0u; i < c->chain_count; ++i)
      if (same(current,(cms_span){c->chain[i].certificate.der,c->chain[i].certificate.size})) break;
    if (i == c->chain_count || seen[i]) return 0;
    seen[i] = true;
  }
  return count == c->chain_count;
}
static int parse_attributes(salts_asn1_reader *r, salts_crypto_sm2_cms_format f,
    const void *content, size_t n, uint8_t encoded[CMS_ATTRIBUTES_MAX], size_t *encoded_size) {
  size_t start = r->offset;
  salts_asn1_reader attrs, attribute, values; salts_asn1_tlv list, name, value;
  if (!take(r,2u,1u,0u,&list) || list.encoded_size > CMS_ATTRIBUTES_MAX ||
      salts_asn1_reader_open_children(r,&list,&attrs) != SALTS_ASN1_OK) return 0;
  memcpy(encoded,r->data+start,list.encoded_size); encoded[0] = 0x31u; *encoded_size = list.encoded_size;
  /* IMPLICIT [0] is semantically SET OF; validate its canonical ordering using
   * the same ASN1 owner rather than re-encoding the signed attribute values. */
  if (salts_asn1_validate(encoded,*encoded_size,SALTS_ASN1_DER) != SALTS_ASN1_OK) return 0;
  uint8_t digest[32]; unsigned seen = 0u;
  if (salts_crypto_sm3(content,n,digest) != SALTS_CRYPTO_OK) return 0;
  int ok = 0;
  while (!done(&attrs)) {
    if (!enter(&attrs,0u,16u,&attribute) || !take(&attribute,0u,0u,6u,&name) ||
        name.content_size != sizeof(attr_prefix)+1u || memcmp(name.content,attr_prefix,sizeof(attr_prefix)) ||
        !enter(&attribute,0u,17u,&values) || !done(&attribute)) goto end;
    unsigned type = name.content[sizeof(attr_prefix)];
    unsigned bit = type == 3u ? 1u : type == 4u ? 2u : type == 5u ? 4u : 0u;
    if (!bit || (seen & bit)) goto end;
    seen |= bit;
    if (type == 3u) { if (!match_content(&values,f,1u)) goto end; }
    else if (type == 4u) {
      if (!take(&values,0u,0u,4u,&value) || value.content_size != sizeof(digest) ||
          gmssl_secure_memcmp(value.content,digest,sizeof(digest))) goto end;
    } else {
      int64_t seconds;
      if (salts_asn1_reader_next(&values,&value) != SALTS_ASN1_OK || !salts_crypto_x509_date(&value,&seconds)) goto end;
    }
    if (!done(&values)) goto end;
  }
  ok = (seen & 3u) == 3u;
end:
  salts_crypto_secure_zero(digest,sizeof(digest));
  return ok;
}

static int verify_admitted(const salts_crypto_sm2_cms_verify_config *c, const void *der, size_t size,
    const void *detached, size_t detached_size, void *out, size_t cap, size_t *written) {
  const size_t bound = SALTS_CRYPTO_SM2_CMS_MAX_CONTENT;
  uint8_t public_key[65];
  if (!c || !output_valid(out,cap,bound,written) || !der || !size || size > SALTS_CRYPTO_SM2_CMS_MAX_DER ||
      !format_valid(c->format) || !id_valid(c->signer_identity,c->signer_identity_size) ||
      !c->trust || c->trust->purpose == SALTS_CRYPTO_SM2_TRUST_EMAIL_ENCRYPTION ||
      (!detached && detached_size) || detached_size > bound || (!c->detached && (detached || detached_size)) ||
      !disjoint(out,bound,written,c,sizeof(*c)) || !disjoint(out,bound,written,der,size) ||
      !disjoint(out,bound,written,detached,detached_size) ||
      !disjoint(out,bound,written,c->signer_identity,c->signer_identity_size) ||
      !salts_crypto_sm2_trust_admitted(c->chain,c->chain_count,c->trust,public_key)) return 0;
  if (!disjoint(out,bound,written,c->chain,c->chain_count*sizeof(*c->chain)) ||
      !disjoint(out,bound,written,c->trust,sizeof(*c->trust)) ||
      !disjoint(out,bound,written,c->trust->anchor.der,c->trust->anchor.size) ||
      !disjoint(out,bound,written,c->trust->expected_leaf_public_key,65u)) return 0;
  for (size_t i = 0u; i < c->chain_count; ++i)
    if (!disjoint(out,bound,written,c->chain[i].certificate.der,c->chain[i].certificate.size) ||
        !disjoint(out,bound,written,c->chain[i].issuer_identity,c->chain[i].issuer_identity_size)) return 0;
  return 1;
}

int salts_crypto_sm2_cms_verify(const salts_crypto_sm2_cms_verify_config *c,
    const void *der, size_t size, const void *detached, size_t detached_size,
    void *out, size_t cap, size_t *written) {
  if (!verify_admitted(c,der,size,detached,detached_size,out,cap,written)) return SALTS_CRYPTO_EINVAL;
  salts_asn1_reader outer, explicit_value, sd, digests, eci, content_reader, signers, signer, sid;
  salts_asn1_tlv value;
  cms_span content = {detached,detached_size};
  uint8_t attributes[CMS_ATTRIBUTES_MAX], signature[64] = {0}, public_key[65] = {0};
  size_t attribute_size = 0u;
  int status = SALTS_CRYPTO_EVERIFY;
  if (!root(der,size,&outer) || !match_content(&outer,c->format,2u) || !enter(&outer,2u,0u,&explicit_value) || !done(&outer) ||
      !enter(&explicit_value,0u,16u,&sd) || !done(&explicit_value) || !version_one(&sd) ||
      !enter(&sd,0u,17u,&digests) || !parse_algorithm(&digests,0) || !done(&digests) ||
      !enter(&sd,0u,16u,&eci) || !match_content(&eci,c->format,1u)) goto end;
  if (c->detached) { if (!done(&eci)) goto end; }
  else {
    if (!enter(&eci,2u,0u,&content_reader) || !done(&eci) || !take(&content_reader,0u,0u,4u,&value) || !done(&content_reader) ||
        value.content_size > SALTS_CRYPTO_SM2_CMS_MAX_CONTENT) goto end;
    content = (cms_span){value.content,value.content_size};
  }
  if (!parse_certificates(&sd,c) || !enter(&sd,0u,17u,&signers) || !done(&sd) ||
      !enter(&signers,0u,16u,&signer) || !done(&signers) || !version_one(&signer) || !enter(&signer,0u,16u,&sid)) goto end;
  crypto_x509_der_view leaf;
  if (crypto_x509_der_inspect(c->chain[0].certificate.der,c->chain[0].certificate.size,&leaf) != SALTS_ASN1_OK) goto end;
  size_t issuer_start = sid.offset;
  if (!take(&sid,0u,1u,16u,&value) || !same((cms_span){sid.data+issuer_start,value.encoded_size},(cms_span){leaf.issuer_der,leaf.issuer_size}) ||
      !take(&sid,0u,0u,2u,&value) || !same((cms_span){value.content,value.content_size},(cms_span){leaf.serial_number,leaf.serial_number_size}) || !done(&sid) ||
      !parse_algorithm(&signer,0) || !parse_attributes(&signer,c->format,content.data,content.size,attributes,&attribute_size) ||
      !parse_algorithm(&signer,1) || !take(&signer,0u,0u,4u,&value) || !done(&signer)) goto end;
  const uint8_t *r, *s; size_t rn, sn;
  if (crypto_asn1_ecdsa_signature_decode(value.content,value.content_size,&r,&rn,&s,&sn) != SALTS_ASN1_OK ||
      !rn || rn > 32u || !sn || sn > 32u) goto end;
  memcpy(signature+32u-rn,r,rn); memcpy(signature+64u-sn,s,sn);
  if (salts_crypto_sm2_x509_public_key(leaf.certificate_der,leaf.certificate_size,public_key) != SALTS_CRYPTO_OK ||
      salts_crypto_sm2_verify(public_key,c->signer_identity,c->signer_identity_size,attributes,attribute_size,signature) != SALTS_CRYPTO_OK ||
      salts_crypto_sm2_validate_pinned_chain(c->chain,c->chain_count,c->trust,public_key) != SALTS_CRYPTO_OK) goto end;
  if (content.size) memcpy(out,content.data,content.size);
  *written = content.size; status = SALTS_CRYPTO_OK;
end:
  salts_crypto_secure_zero(public_key,sizeof(public_key));
  salts_crypto_secure_zero(signature,sizeof(signature));
  salts_crypto_secure_zero(attributes,sizeof(attributes));
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(out,SALTS_CRYPTO_SM2_CMS_MAX_CONTENT); *written = 0u; }
  return status;
}
