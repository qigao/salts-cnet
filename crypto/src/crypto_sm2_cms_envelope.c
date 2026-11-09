#include <crypto/sm2_cms_envelope.h>
#include <crypto/sm2.h>
#include <crypto/sm2_x509.h>
#include <crypto/sm4.h>
#include "crypto_cms_der.h"
#include "crypto_x509_policy.h"
#include <stdlib.h>

static const uint8_t envelope_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9,0x10,1,0x17};
static const uint8_t data_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1};
static const uint8_t key_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x82,0x2d,3};
static const uint8_t cipher_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x68,8};
static void zero(cms_writer *w) { const uint8_t v = 0u; put(w,0u,0u,2u,&v,1u); }
static int version_zero(asn1_reader *r) {
  asn1_tlv v;
  return take(r,0u,0u,2u,&v) && v.content_size == 1u && !v.content[0];
}
static int expect_oid(asn1_reader *r, const void *data, size_t n) {
  asn1_tlv v;
  return take(r,0u,0u,6u,&v) && is_oid(&v,data,n);
}
static int encrypt_admitted(const salts_crypto_sm2_cms_envelope_recipient *c,
    const void *in, size_t n, void *out, size_t cap, size_t *written) {
  const size_t bound = SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER;
  uint8_t probe[65];
  if (!c || !output_valid(out,cap,bound,written) || (!in && n) ||
      n > SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_CONTENT || !c->trust ||
      c->trust->purpose != SALTS_CRYPTO_SM2_TRUST_EMAIL_ENCRYPTION ||
      !disjoint(out,bound,written,c,sizeof(*c)) || !disjoint(out,bound,written,in,n) ||
      !salts_crypto_sm2_trust_admitted(c->chain,c->chain_count,c->trust,probe) ||
      !disjoint(out,bound,written,c->chain,c->chain_count*sizeof(*c->chain)) ||
      !disjoint(out,bound,written,c->trust,sizeof(*c->trust)) ||
      !disjoint(out,bound,written,c->trust->anchor.der,c->trust->anchor.size) ||
      !disjoint(out,bound,written,c->trust->expected_leaf_public_key,65u)) return 0;
  for (size_t i = 0u; i < c->chain_count; ++i)
    if (!disjoint(out,bound,written,c->chain[i].certificate.der,c->chain[i].certificate.size) ||
        !disjoint(out,bound,written,c->chain[i].issuer_identity,c->chain[i].issuer_identity_size)) return 0;
  return 1;
}
int salts_crypto_sm2_cms_envelope_encrypt(const salts_crypto_sm2_cms_envelope_recipient *c,
    const void *in, size_t n, void *out, size_t cap, size_t *written) {
  const size_t bound = SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER;
  if (!encrypt_admitted(c,in,n,out,cap,written)) return SALTS_CRYPTO_EINVAL;
  int status = SALTS_CRYPTO_EVERIFY;
  uint8_t public_key[65], cek[16] = {0}, nonce[12] = {0}, tag[16] = {0};
  uint8_t wrapped[SALTS_CRYPTO_SM2_CIPHERTEXT_MAX_SIZE] = {0}; size_t wrapped_size = 0u;
  uint8_t *workspace = NULL;
  const size_t allocation = 2u*bound+n;
  crypto_x509_der_view leaf;
  if (salts_crypto_sm2_validate_pinned_chain(c->chain,c->chain_count,c->trust,public_key) != SALTS_CRYPTO_OK ||
      crypto_x509_der_inspect(c->chain[0].certificate.der,c->chain[0].certificate.size,&leaf) != SALTS_ASN1_OK) goto end;
  status = SALTS_CRYPTO_ECRYPTO;
  workspace = malloc(allocation);
  if (!workspace || salts_crypto_random_bytes(cek,sizeof(cek)) != SALTS_CRYPTO_OK ||
      salts_crypto_random_bytes(nonce,sizeof(nonce)) != SALTS_CRYPTO_OK ||
      salts_crypto_sm2_encrypt(public_key,cek,sizeof(cek),wrapped,sizeof(wrapped),&wrapped_size) != SALTS_CRYPTO_OK ||
      salts_crypto_sm4_aead_encrypt(SALTS_CRYPTO_SM4_GCM,cek,nonce,sizeof(nonce),NULL,0u,in,n,
          workspace+2u*bound,n,tag,sizeof(tag)) != SALTS_CRYPTO_OK) goto end;
  cms_writer a = {workspace,0u,bound,0}, b = {workspace+bound,0u,bound,0};
  uint8_t sid_bytes[4200], ri_bytes[4700], small[128], params[64];
  cms_writer sid = {sid_bytes,0u,sizeof(sid_bytes),0}, ri = {ri_bytes,0u,sizeof(ri_bytes),0};
  cms_writer alg = {small,0u,sizeof(small),0}, parameter = {params,0u,sizeof(params),0};
  raw(&sid,leaf.issuer_der,leaf.issuer_size); put(&sid,0u,0u,2u,leaf.serial_number,leaf.serial_number_size);
  zero(&ri); wrap(&ri,0u,16u,&sid);
  oid(&alg,key_oid,sizeof(key_oid)); put(&alg,0u,0u,5u,NULL,0u); wrap(&ri,0u,16u,&alg);
  put(&ri,0u,0u,4u,wrapped,wrapped_size);
  zero(&b); wrap(&a,0u,16u,&ri); wrap(&b,0u,17u,&a);
  a.size = 0u; oid(&a,data_oid,sizeof(data_oid));
  alg.size = 0u; oid(&alg,cipher_oid,sizeof(cipher_oid));
  put(&parameter,0u,0u,4u,nonce,sizeof(nonce));
  const uint8_t tag_length = 16u; put(&parameter,0u,0u,2u,&tag_length,1u);
  wrap(&alg,0u,16u,&parameter); wrap(&a,0u,16u,&alg);
  put(&a,2u,0u,0u,workspace+2u*bound,n); wrap(&b,0u,16u,&a); put(&b,0u,0u,4u,tag,sizeof(tag));
  a.size = 0u; wrap(&a,0u,16u,&b);
  b.size = 0u; oid(&b,envelope_oid,sizeof(envelope_oid)); wrap(&b,2u,0u,&a);
  a.size = 0u; wrap(&a,0u,16u,&b);
  if (!a.failed && !b.failed && !ri.failed && !alg.failed) {
    memcpy(out,a.data,a.size); *written = a.size; status = SALTS_CRYPTO_OK;
  }
end:
  if (workspace) { salts_crypto_secure_zero(workspace,allocation); free(workspace); }
  salts_crypto_secure_zero(cek,sizeof(cek)); salts_crypto_secure_zero(nonce,sizeof(nonce));
  salts_crypto_secure_zero(wrapped,sizeof(wrapped)); salts_crypto_secure_zero(tag,sizeof(tag));
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(out,bound); *written = 0u; }
  return status;
}
int salts_crypto_sm2_cms_envelope_decrypt(const salts_crypto_sm2_cms_envelope_key *c,
    const void *der, size_t n, void *out, size_t cap, size_t *written) {
  const size_t bound = SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_CONTENT;
  if (!c || !output_valid(out,cap,bound,written) || !c->private_key || !c->certificate.der ||
      !c->certificate.size || c->certificate.size > SALTS_CRYPTO_SM2_TRUST_MAX_CERT_SIZE ||
      !der || !n || n > SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER ||
      !disjoint(out,bound,written,c,sizeof(*c)) || !disjoint(out,bound,written,c->private_key,32u) ||
      !disjoint(out,bound,written,c->certificate.der,c->certificate.size) ||
      !disjoint(out,bound,written,der,n)) return SALTS_CRYPTO_EINVAL;
  int status = SALTS_CRYPTO_EVERIFY;
  asn1_reader outer, explicit_value, envelope, recipients, recipient, sid, alg, eci, parameter;
  asn1_tlv name, serial, wrapped, nonce, ciphertext, tag, value;
  crypto_x509_der_view leaf;
  uint8_t cek[SALTS_CRYPTO_SM2_PLAINTEXT_MAX_SIZE] = {0}; size_t cek_size = 0u;
  uint8_t *plain = NULL;
  if (crypto_x509_der_inspect(c->certificate.der,c->certificate.size,&leaf) != SALTS_ASN1_OK ||
      !root(der,n,&outer) || !expect_oid(&outer,envelope_oid,sizeof(envelope_oid)) ||
      !enter(&outer,2u,0u,&explicit_value) || !done(&outer) || !enter(&explicit_value,0u,16u,&envelope) || !done(&explicit_value) ||
      !version_zero(&envelope) || !enter(&envelope,0u,17u,&recipients) ||
      !enter(&recipients,0u,16u,&recipient) || !done(&recipients) || !version_zero(&recipient) ||
      !enter(&recipient,0u,16u,&sid) || !take(&sid,0u,1u,16u,&name) ||
      !same((cms_span){name.content-(name.encoded_size-name.content_size),name.encoded_size},(cms_span){leaf.issuer_der,leaf.issuer_size}) ||
      !take(&sid,0u,0u,2u,&serial) || !same((cms_span){serial.content,serial.content_size},(cms_span){leaf.serial_number,leaf.serial_number_size}) ||
      !done(&sid) || !enter(&recipient,0u,16u,&alg) || !expect_oid(&alg,key_oid,sizeof(key_oid))) goto end;
  if (!done(&alg) && (!take(&alg,0u,0u,5u,&value) || value.content_size)) goto end;
  if (!done(&alg) || !take(&recipient,0u,0u,4u,&wrapped) || !done(&recipient) ||
      !wrapped.content_size || wrapped.content_size > SALTS_CRYPTO_SM2_CIPHERTEXT_MAX_SIZE ||
      !enter(&envelope,0u,16u,&eci) || !expect_oid(&eci,data_oid,sizeof(data_oid)) ||
      !enter(&eci,0u,16u,&alg) || !expect_oid(&alg,cipher_oid,sizeof(cipher_oid)) ||
      !enter(&alg,0u,16u,&parameter) || !done(&alg) || !take(&parameter,0u,0u,4u,&nonce) || nonce.content_size != 12u ||
      !take(&parameter,0u,0u,2u,&value) || value.content_size != 1u || value.content[0] != 16u || !done(&parameter) ||
      !take(&eci,2u,0u,0u,&ciphertext) || ciphertext.content_size > bound || !done(&eci) ||
      !take(&envelope,0u,0u,4u,&tag) || tag.content_size != 16u || !done(&envelope) ||
      salts_crypto_sm2_x509_matches_private_key(c->certificate.der,c->certificate.size,c->private_key) != SALTS_CRYPTO_OK ||
      salts_crypto_sm2_decrypt(c->private_key,wrapped.content,wrapped.content_size,cek,sizeof(cek),&cek_size) != SALTS_CRYPTO_OK || cek_size != 16u) goto end;
  /* Plaintext remains private even if a provider decrypts before checking tag. */
  plain = malloc(ciphertext.content_size ? ciphertext.content_size : 1u);
  if (!plain) { status = SALTS_CRYPTO_ECRYPTO; goto end; }
  if (salts_crypto_sm4_aead_decrypt(SALTS_CRYPTO_SM4_GCM,cek,nonce.content,nonce.content_size,NULL,0u,
      ciphertext.content,ciphertext.content_size,tag.content,tag.content_size,plain,ciphertext.content_size) != SALTS_CRYPTO_OK) goto end;
  if (ciphertext.content_size) memcpy(out,plain,ciphertext.content_size);
  *written = ciphertext.content_size; status = SALTS_CRYPTO_OK;
end:
  if (plain) { salts_crypto_secure_zero(plain,ciphertext.content_size); free(plain); }
  salts_crypto_secure_zero(cek,sizeof(cek));
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(out,bound); *written = 0u; }
  return status;
}
