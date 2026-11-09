#include <crypto/sm2_ocsp.h>
#include <crypto/tls_sm2_ocsp_policy.h>
#include <crypto/tls_stream.h>
#include <string.h>
#include <tinytest.h>
spec("Direct-issuer SM2 OCSP bounded explicit admission") {
  it("rejects absent, oversized and implicit security configuration") {
    const uint8_t der[] = {0x30u,0u};
    salts_crypto_sm2_cert_span cert = {der,sizeof(der)};
    salts_crypto_sm2_ocsp_policy p = {der,sizeof(der),"id",2u,60u,0u,0,NULL,0u};
    check_equal(salts_crypto_sm2_check_direct_ocsp(NULL,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,NULL,0,&p),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,NULL),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,-1,&p),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,INT64_C(253402300800),&p),SALTS_CRYPTO_EINVAL);
    p.maximum_age_seconds = 0u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.maximum_age_seconds = 1u; p.maximum_clock_skew_seconds = 3601u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.maximum_clock_skew_seconds = 0u; p.minimum_this_update = -1;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.minimum_this_update = 0; p.signer_identity_size = 8192u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.signer_identity_size = 2u; p.size = SALTS_CRYPTO_SM2_OCSP_MAX_BYTES+1u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.size = sizeof(der); p.nonce_size = 32u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.nonce = der; p.nonce_size = 0u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.nonce_size = 31u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.nonce_size = 129u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.nonce = NULL; p.nonce_size = 0u;
    check_equal(salts_crypto_sm2_check_direct_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EVERIFY);
  }
  it("preserves aliased input even when another configuration field is invalid") {
    crypto_tls_stream_peer_policy out, saved;
    memset(&out,0xa5,sizeof(out));
    memcpy(&saved,&out,sizeof(out));
    const uint8_t der[] = {0x30u,0u};
    crypto_tls_sm2_ocsp_config c = {.size = sizeof(c),
        .issuer_certificate = der, .issuer_certificate_size = sizeof(der),
        .response = &out, .response_size = sizeof(out),
        .certificate_signing_identity = "id", .certificate_signing_identity_size = 2u,
        .response_signing_identity = "id", .response_signing_identity_size = 2u,
        .maximum_age_seconds = 0u};
    check_equal(crypto_tls_sm2_ocsp_peer_policy_create(&c,&out),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(memcmp(&out,&saved,sizeof(out)),0);
    c.response = der; c.response_size = sizeof(der);
    c.issuer_certificate = &out; c.issuer_certificate_size = sizeof(out);
    check_equal(crypto_tlcp_sm2_ocsp_peer_policy_create(&c,&out),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(memcmp(&out,&saved,sizeof(out)),0);
    c.issuer_certificate = der; c.issuer_certificate_size = sizeof(der);
    c.certificate_signing_identity = &out; c.certificate_signing_identity_size = sizeof(out);
    check_equal(crypto_tls_sm2_ocsp_peer_policy_create(&c,&out),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(memcmp(&out,&saved,sizeof(out)),0);
    c.certificate_signing_identity = "id"; c.certificate_signing_identity_size = 2u;
    c.response_signing_identity = &out; c.response_signing_identity_size = sizeof(out);
    check_equal(crypto_tls_sm2_ocsp_peer_policy_create(&c,&out),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(memcmp(&out,&saved,sizeof(out)),0);
    c.response_signing_identity = "id"; c.response_signing_identity_size = 2u;
    c.responder_certificate = &out; c.responder_certificate_size = sizeof(out);
    check_equal(crypto_tls_sm2_ocsp_peer_policy_create(&c,&out),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(memcmp(&out,&saved,sizeof(out)),0);
    c.responder_certificate = NULL; c.responder_certificate_size = 0u;
    c.responder_issuer_identity = &out; c.responder_issuer_identity_size = sizeof(out);
    check_equal(crypto_tls_sm2_ocsp_peer_policy_create(&c,&out),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(memcmp(&out,&saved,sizeof(out)),0);
    c.responder_issuer_identity = NULL; c.responder_issuer_identity_size = 0u;
    check_equal(crypto_tls_sm2_ocsp_peer_policy_create(&c,&out),CRYPTO_TLS_STREAM_EINVAL);
    const crypto_tls_stream_peer_policy zero = {0};
    check_equal(memcmp(&out,&zero,sizeof(out)),0);
  }
  it("requires a complete explicit delegated authority and bounded issuer ID") {
    const uint8_t der[] = {0x30u,0u};
    salts_crypto_sm2_cert_span cert = {der,sizeof(der)};
    salts_crypto_sm2_delegated_ocsp_policy p = {
        {der,sizeof(der),"response",8u,60u,0u,0,NULL,0u},cert,"issuer",6u};
    check_equal(salts_crypto_sm2_check_delegated_ocsp(&cert,&cert,0,NULL),SALTS_CRYPTO_EINVAL);
    p.responder_certificate.size = 4097u;
    check_equal(salts_crypto_sm2_validate_delegated_ocsp(&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.responder_certificate = cert; p.responder_issuer_identity = NULL;
    check_equal(salts_crypto_sm2_check_delegated_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.responder_issuer_identity = "issuer"; p.responder_issuer_identity_size = 8192u;
    check_equal(salts_crypto_sm2_check_delegated_ocsp(&cert,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    p.responder_issuer_identity_size = 6u;
    check_equal(salts_crypto_sm2_check_delegated_ocsp(NULL,&cert,0,&p),SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_delegated_ocsp(&cert,0,&p),SALTS_CRYPTO_EVERIFY);
    crypto_tls_sm2_ocsp_config c = {.size = sizeof(c),.issuer_certificate = der,
        .issuer_certificate_size = sizeof(der),.response = der,.response_size = sizeof(der),
        .certificate_signing_identity = "id",.certificate_signing_identity_size = 2u,
        .response_signing_identity = "id",.response_signing_identity_size = 2u,
        .maximum_age_seconds = 60u};
    static const uint8_t oversized_cert[4097] = {0}, oversized_id[8192] = {0};
    for (unsigned i = 0u; i < 6u; ++i) {
      crypto_tls_sm2_ocsp_config bad = c;
      bad.responder_certificate = der; bad.responder_certificate_size = sizeof(der);
      bad.responder_issuer_identity = "id"; bad.responder_issuer_identity_size = 2u;
      if (i == 0u) bad.responder_certificate = NULL;
      if (i == 1u) bad.responder_certificate_size = 0u;
      if (i == 2u) { bad.responder_certificate = oversized_cert; bad.responder_certificate_size = sizeof(oversized_cert); }
      if (i == 3u) bad.responder_issuer_identity = NULL;
      if (i == 4u) bad.responder_issuer_identity_size = 0u;
      if (i == 5u) { bad.responder_issuer_identity = oversized_id; bad.responder_issuer_identity_size = sizeof(oversized_id); }
      crypto_tls_stream_peer_policy out;
      memset(&out,0xa5,sizeof(out));
      check_equal(crypto_tls_sm2_ocsp_peer_policy_create(&bad,&out),CRYPTO_TLS_STREAM_EINVAL);
      check_true(out.context == NULL && out.check == NULL && out.retain == NULL && out.release == NULL);
    }
  }
}
