#include <crypto/sm2_trust.h>
#include <tinytest.h>
#include <string.h>

static unsigned calls;
static int revoked(void *ctx, size_t depth, const salts_crypto_sm2_cert_span *cert,
    const salts_crypto_sm2_cert_span *issuer, int64_t now) {
  (void)ctx; (void)depth; (void)cert; (void)issuer; (void)now;
  ++calls; return SALTS_CRYPTO_EVERIFY;
}
static int filled(const void *p, size_t n, uint8_t byte) {
  const uint8_t *data = p;
  for (size_t i=0; i<n; ++i) if (data[i] != byte) return 0;
  return 1;
}
spec("Pinned SM2 trust admission and output ownership") {
  it("requires explicit policy and bounded immutable inputs before touching output") {
    uint8_t input[128] = {0}, out[66];
    salts_crypto_sm2_chain_entry chain = {{input, 100}, "id", 2};
    salts_crypto_sm2_trust_policy p = {{input, 100}, input, 0,
      SALTS_CRYPTO_SM2_TRUST_SERVER_SIGNING, SALTS_CRYPTO_SM2_REVOCATION_NOT_CHECKED, NULL, NULL};
    memset(out, 0xa5, sizeof(out)); calls = 0;
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 0, &p, out), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 5, &p, out), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_pinned_chain(NULL, 1, &p, out), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, NULL, out), SALTS_CRYPTO_EINVAL);
    p.revocation = 0;
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EINVAL);
    p.revocation = SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL;
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EINVAL);
    p.check_revocation = revoked; p.purpose = 0;
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EINVAL);
    p.purpose = SALTS_CRYPTO_SM2_TRUST_SERVER_SIGNING; p.validation_time = -1;
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EINVAL);
    p.validation_time = INT64_C(253402300800);
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EINVAL);
    p.validation_time = 0; chain.issuer_identity_size = 8192;
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EINVAL);
    chain.issuer_identity_size = 2; chain.certificate.size = 4097;
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EINVAL);
    check_true(filled(out, sizeof(out), 0xa5)); check_equal(calls, 0u);
  }
  it("rejects output aliases with descriptors, DER, identities or the expected pin") {
    uint8_t input[200], pin[65], out[65]; const uint8_t saved = 0xa5;
    memset(input, saved, sizeof(input)); memset(pin, saved, sizeof(pin));
    salts_crypto_sm2_chain_entry chain = {{input, 100}, input+100, 100};
    salts_crypto_sm2_trust_policy p = {{input, 100}, pin, 0,
      SALTS_CRYPTO_SM2_TRUST_SERVER_SIGNING, SALTS_CRYPTO_SM2_REVOCATION_NOT_CHECKED, NULL, NULL};
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, input), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, input+100), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, pin), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, (uint8_t *)(void *)&p), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, (uint8_t *)(void *)&chain), SALTS_CRYPTO_EINVAL);
    check_true(filled(input, sizeof(input), saved)); check_true(filled(pin, sizeof(pin), saved));
    p.check_revocation = revoked;
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EINVAL);
  }
  it("erases admitted malformed input without invoking the revocation policy") {
    uint8_t der[] = {0x30,0}, out[66], pin[65] = {0}; calls = 0;
    salts_crypto_sm2_chain_entry chain = {{der, sizeof(der)}, "id", 2};
    salts_crypto_sm2_trust_policy p = {{der, sizeof(der)}, pin, 0,
      SALTS_CRYPTO_SM2_TRUST_CLIENT_SIGNING, SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL, revoked, NULL};
    memset(out, 0xa5, sizeof(out));
    check_equal(salts_crypto_sm2_validate_pinned_chain(&chain, 1, &p, out), SALTS_CRYPTO_EVERIFY);
    check_true(filled(out, 65, 0)); check_equal(out[65], 0xa5); check_equal(calls, 0u);
  }
}
