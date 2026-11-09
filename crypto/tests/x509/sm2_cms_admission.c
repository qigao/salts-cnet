#include <crypto/sm2_cms.h>
#include <crypto/sm2_cms_envelope.h>
#include <tinytest.h>
#include <string.h>
static int filled(const uint8_t *bytes, size_t n, uint8_t value) {
  for (size_t i = 0u; i < n; ++i) if (bytes[i] != value) return 0;
  return 1;
}
spec("SM2 CMS admission, erasure and output ownership") {
  static uint8_t out[SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER+1u];
  it("rejects invalid sign inputs without touching caller outputs") {
    uint8_t der[] = {0x30u,0u}, key[32] = {0};
    salts_crypto_sm2_cert_span cert = {der,sizeof(der)};
    salts_crypto_sm2_cms_sign_config c = {SALTS_CRYPTO_SM2_CMS_RFC5652,false,key,"id",2u,&cert,1u};
    size_t written = 77u; memset(out,0xa5,sizeof(out));
    check_equal(salts_crypto_sm2_cms_sign(NULL,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_sign(&c,NULL,1u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_sign(&c,NULL,0u,out,0u,&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_sign(&c,NULL,0u,out,sizeof(out),NULL),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_sign(&c,out,1u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_sign(&c,NULL,0u,out,sizeof(out),(size_t *)(void *)out),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_sign(&c,key,SALTS_CRYPTO_SM2_CMS_MAX_CONTENT+1u,
        out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    c.certificate_count = 5u;
    check_equal(salts_crypto_sm2_cms_sign(&c,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    c.certificate_count = 1u; c.format = 0;
    check_equal(salts_crypto_sm2_cms_sign(&c,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    c.format = SALTS_CRYPTO_SM2_CMS_RFC5652; c.signer_identity_size = 8192u;
    check_equal(salts_crypto_sm2_cms_sign(&c,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_true(filled(out,sizeof(out),0xa5)); check_equal(written,77u);
  }
  it("clears only the admitted sign output on malformed certificate failure") {
    uint8_t der[] = {0x30u,0u}, key[32] = {0};
    salts_crypto_sm2_cert_span cert = {der,sizeof(der)};
    salts_crypto_sm2_cms_sign_config c = {SALTS_CRYPTO_SM2_CMS_SHANGMI,true,key,"id",2u,&cert,1u};
    size_t written = 77u; memset(out,0xa5,sizeof(out));
    check_equal(salts_crypto_sm2_cms_sign(&c,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EVERIFY);
    check_true(filled(out,SALTS_CRYPTO_SM2_CMS_MAX_DER,0u));
    check_equal(out[SALTS_CRYPTO_SM2_CMS_MAX_DER],0xa5); check_equal(written,0u);
  }
  it("requires a complete explicit verify policy before touching output") {
    uint8_t der[] = {0x30u,0u}, pin[65] = {0};
    salts_crypto_sm2_chain_entry chain = {{der,sizeof(der)},"id",2u};
    salts_crypto_sm2_trust_policy trust = {{der,sizeof(der)},pin,0,
        SALTS_CRYPTO_SM2_TRUST_CODE_SIGNING,SALTS_CRYPTO_SM2_REVOCATION_NOT_CHECKED,NULL,NULL};
    salts_crypto_sm2_cms_verify_config c = {SALTS_CRYPTO_SM2_CMS_RFC5652,false,"id",2u,&chain,1u,&trust};
    size_t written = 77u; memset(out,0xa5,sizeof(out));
    c.trust = NULL;
    check_equal(salts_crypto_sm2_cms_verify(&c,der,sizeof(der),NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    c.trust = &trust;
    check_equal(salts_crypto_sm2_cms_verify(&c,der,SALTS_CRYPTO_SM2_CMS_MAX_DER+1u,NULL,0u,
        out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_verify(&c,der,sizeof(der),der,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_verify(&c,out,2u,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    trust.purpose = SALTS_CRYPTO_SM2_TRUST_EMAIL_ENCRYPTION;
    check_equal(salts_crypto_sm2_cms_verify(&c,der,sizeof(der),NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    trust.purpose = 7;
    check_equal(salts_crypto_sm2_cms_verify(&c,der,sizeof(der),NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_true(filled(out,sizeof(out),0xa5)); check_equal(written,77u);
    trust.purpose = SALTS_CRYPTO_SM2_TRUST_CODE_SIGNING;
    check_equal(salts_crypto_sm2_cms_verify(&c,der,sizeof(der),NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EVERIFY);
    check_true(filled(out,SALTS_CRYPTO_SM2_CMS_MAX_CONTENT,0u));
    check_equal(out[SALTS_CRYPTO_SM2_CMS_MAX_CONTENT],0xa5); check_equal(written,0u);
  }
  it("enforces authenticated-encryption admission and disjoint output ownership") {
    uint8_t der[] = {0x30u,0u}, pin[65] = {0}, key[32] = {0};
    salts_crypto_sm2_chain_entry chain = {{der,sizeof(der)},"id",2u};
    salts_crypto_sm2_trust_policy trust = {{der,sizeof(der)},pin,0,
        SALTS_CRYPTO_SM2_TRUST_EMAIL_ENCRYPTION,SALTS_CRYPTO_SM2_REVOCATION_NOT_CHECKED,NULL,NULL};
    salts_crypto_sm2_cms_envelope_recipient c = {&chain,1u,&trust};
    salts_crypto_sm2_cms_envelope_key own = {{der,sizeof(der)},key};
    size_t written = 77u; memset(out,0xa5,sizeof(out));
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(NULL,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,NULL,1u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,NULL,0u,out,0u,&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,NULL,0u,out,sizeof(out),NULL),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,key,SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_CONTENT+1u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,out,1u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,NULL,0u,out,sizeof(out),(size_t *)(void *)out),SALTS_CRYPTO_EINVAL);
    trust.expected_leaf_public_key = out;
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    trust.expected_leaf_public_key = pin; trust.purpose = SALTS_CRYPTO_SM2_TRUST_EMAIL_PROTECTION;
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    trust.purpose = SALTS_CRYPTO_SM2_TRUST_EMAIL_ENCRYPTION;
    check_equal(salts_crypto_sm2_cms_envelope_decrypt(NULL,der,sizeof(der),out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_decrypt(&own,der,0u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_decrypt(&own,der,SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER+1u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_cms_envelope_decrypt(&own,out,1u,out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    own.private_key = out;
    check_equal(salts_crypto_sm2_cms_envelope_decrypt(&own,der,sizeof(der),out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    own.private_key = key; own.certificate.der = out;
    check_equal(salts_crypto_sm2_cms_envelope_decrypt(&own,der,sizeof(der),out,sizeof(out),&written),SALTS_CRYPTO_EINVAL);
    check_true(filled(out,sizeof(out),0xa5)); check_equal(written,77u);
    check_equal(salts_crypto_sm2_cms_envelope_encrypt(&c,NULL,0u,out,sizeof(out),&written),SALTS_CRYPTO_EVERIFY);
    check_true(filled(out,SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER,0));
    check_equal(written,0u); check_equal(out[SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER],0xa5);
    memset(out,0xa5,sizeof(out)); written = 77u; own.certificate.der = der;
    check_equal(salts_crypto_sm2_cms_envelope_decrypt(&own,der,sizeof(der),out,sizeof(out),&written),SALTS_CRYPTO_EVERIFY);
    check_true(filled(out,SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_CONTENT,0));
    check_equal(written,0u); check_equal(out[SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_CONTENT],0xa5);
  }
}
