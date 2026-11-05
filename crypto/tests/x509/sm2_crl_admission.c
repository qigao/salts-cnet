#include <crypto/sm2_crl.h>
#include <tinytest.h>
#include <string.h>

spec("SM2 full CRL admission") {
  it("requires bounded certificates, CRL, signing identity, time and explicit freshness") {
    uint8_t der[] = {0x30,0};
    salts_crypto_sm2_cert_span cert = {der, sizeof(der)}, issuer = cert;
    salts_crypto_sm2_crl_policy p = {der, sizeof(der), "id", 2, 0, 60};
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm2_validate_crl(&issuer, 0, &p), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm2_validate_crl(NULL, 0, &p), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_crl(&issuer, -1, &p), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_crl(&issuer, 0, NULL), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_crl(NULL, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_crl(&cert, NULL, 0, &p), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, NULL), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, -1, &p), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, INT64_C(253402300800), &p), SALTS_CRYPTO_EINVAL);
    p.maximum_age_seconds = 0;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    p.maximum_age_seconds = 60; p.size = 65537;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    p.size = 0;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    p.size = 2; p.der = NULL;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    p.der = der; p.issuer_identity_size = 0;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    p.issuer_identity_size = 8192;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    p.issuer_identity_size = 2; p.issuer_identity = NULL;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    p.issuer_identity = "id"; cert.size = 4097;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    cert = issuer; issuer.size = 4097;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    issuer = cert; cert.der = NULL;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    cert = issuer; issuer.size = 0;
    check_equal(salts_crypto_sm2_check_crl(&cert, &issuer, 0, &p), SALTS_CRYPTO_EINVAL);
    check_equal(der[0], 0x30); check_equal(der[1], 0);
  }
}
