#include <crypto/sm2_x509.h>
#include <crypto/sm2.h>
#include <crypto/sm2_keys.h>
#include <crypto/x509_der.h>
#include <crypto/asn1_crypto.h>
#include <gmssl/sm2.h>
#include <tinytest.h>
#include <string.h>
#include "fixtures/openssl3_sm2_certificate.h"

typedef struct bytes { uint8_t data[4096]; size_t size; } bytes;
static int append(bytes *b, const void *data, size_t n) {
  if (n > sizeof(b->data)-b->size) return 0;
  memcpy(b->data+b->size, data, n); b->size += n; return 1;
}
static int wrap(bytes *out, uint8_t tag, const void *data, size_t n) {
  size_t added;
  if (asn1_encode_tlv(tag >> 6, (tag >> 5) & 1, tag & 31,
      data, n, SALTS_ASN1_DER, 0, out->data+out->size, sizeof(out->data)-out->size, &added) != SALTS_ASN1_OK) return 0;
  out->size += added; return 1;
}
static const uint8_t key_one[32] = {[31]=1}, key_two[32] = {[31]=2};
static const char issuer_id[] = "test-issuer-identity";
static const uint8_t name[] = {0x30,15,0x31,13,0x30,11,6,3,0x55,4,3,0x0c,4,'t','e','s','t'};
static const uint8_t validity[] = {0x30,30,0x17,13,'2','4','0','1','0','1','0','0','0','0','0','0','Z',
  0x17,13,'2','5','0','1','0','1','0','0','0','0','0','0','Z'};

/* Formal fixture composition uses the native provider's signing API, not
 * the public certificate-verification function. No fixture is a trust anchor. */
static int certificate(bytes *out, int params, int outer_params, int wrong_oid,
    const uint8_t *sig_override, size_t sig_size, int foreign_subject) {
  bytes alg_body = {0}, alg = {0}, outer = {0}, tbs_body = {0}, tbs = {0}, body = {0};
  uint8_t oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x83,0x75};
  const uint8_t version_serial[] = {0xa0,3,2,1,2,2,1,1};
  const uint8_t zero = 0;
  uint8_t pub[65], spki[91], sig[73] = {0}; size_t spki_size, native_sig_size = 0;
  SM2_KEY native = {0}; SM2_SIGN_CTX signer; sm2_z256_t d = {1,0,0,0};
  out->size = 0;
  if (wrong_oid) oid[7] ^= 1;
  if (!wrap(&alg_body, 6, oid, sizeof(oid))) return 0;
  if (params && !wrap(&alg_body, params == 1 ? 5 : 2, &zero, params == 1 ? 0 : 1)) return 0;
  if (!wrap(&alg, 0x30, alg_body.data, alg_body.size)) return 0;
  alg_body.size = 0;
  if (!wrap(&alg_body, 6, oid, sizeof(oid))) return 0;
  if (outer_params && !wrap(&alg_body, outer_params == 1 ? 5 : 2, &zero, outer_params == 1 ? 0 : 1)) return 0;
  if (!wrap(&outer, 0x30, alg_body.data, alg_body.size)) return 0;
  if (salts_crypto_sm2_public_key(key_two, pub) != SALTS_CRYPTO_OK ||
      salts_crypto_sm2_spki_export(pub, spki, sizeof(spki), &spki_size) != SALTS_CRYPTO_OK) return 0;
  /* Structurally valid, deliberately unsupported subject curve identifier.
   * Signature verification must not be confused with subject-key admission. */
  if (foreign_subject) spki[22] ^= 1;
  if (!append(&tbs_body, version_serial, sizeof(version_serial)) || !append(&tbs_body, alg.data, alg.size) ||
      !append(&tbs_body, name, sizeof(name)) || !append(&tbs_body, validity, sizeof(validity)) ||
      !append(&tbs_body, name, sizeof(name)) || !append(&tbs_body, spki, spki_size) ||
      !wrap(&tbs, 0x30, tbs_body.data, tbs_body.size)) return 0;
  if (sig_override) {
    if (sig_size > sizeof(sig)-1) return 0;
    memcpy(sig+1, sig_override, sig_size); native_sig_size = sig_size;
  } else {
    if (sm2_key_set_private_key(&native, d) != 1 ||
        sm2_sign_init(&signer, &native, issuer_id, sizeof(issuer_id)-1) != 1 ||
        sm2_sign_update(&signer, tbs.data, tbs.size) != 1 ||
        sm2_sign_finish(&signer, sig+1, &native_sig_size) != 1) return 0;
  }
  return append(&body, tbs.data, tbs.size) && append(&body, outer.data, outer.size) &&
      wrap(&body, 3, sig, native_sig_size+1) && wrap(out, 0x30, body.data, body.size);
}
static int filled(const uint8_t *p, size_t n, uint8_t value) {
  for (size_t i=0; i<n; ++i) if (p[i] != value) return 0;
  return 1;
}
static int verify(const bytes *cert, const uint8_t pub[65]) {
  return salts_crypto_sm2_x509_verify_signature(cert->data, cert->size, pub, issuer_id, sizeof(issuer_id)-1);
}

spec("SM2 certificate primitives with explicit trust boundaries") {
  it("verifies native signatures with absent or NULL parameters and binds the separate subject key") {
    bytes cert; uint8_t issuer[65], subject[65], expected[65];
    check_equal(salts_crypto_sm2_public_key(key_one, issuer), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_public_key(key_two, expected), SALTS_CRYPTO_OK);
    for (int params=0; params<=1; ++params) {
      check_true(certificate(&cert, params, params, 0, NULL, 0, 0));
      check_equal(verify(&cert, issuer), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm2_x509_public_key(cert.data, cert.size, subject), SALTS_CRYPTO_OK);
      check_equal(subject, expected, sizeof(subject));
      check_equal(salts_crypto_sm2_x509_matches_private_key(cert.data, cert.size, key_two), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm2_x509_matches_private_key(cert.data, cert.size, key_one), SALTS_CRYPTO_EVERIFY);
      check_equal(verify(&cert, subject), SALTS_CRYPTO_EVERIFY);
      check_equal(salts_crypto_sm2_x509_verify_signature(cert.data, cert.size, issuer, "wrong-id", 8), SALTS_CRYPTO_EVERIFY);
    }
  }
  it("rejects the published OpenSSL empty-ID certificate under the standard nonempty ID profile") {
    crypto_x509_der_view view; uint8_t issuer[65], out[65];
    check_equal(crypto_x509_der_inspect(openssl3_certificate, sizeof(openssl3_certificate), &view), SALTS_ASN1_OK);
    /* Published fixture uses the alternate id-SM2 SPKI OID. Its raw issuer
     * point is explicit test input; our extraction profile rejects that OID. */
    check_true(view.spki_size >= 65);
    memcpy(issuer, view.spki_der+view.spki_size-65, 65);
    check_equal(salts_crypto_sm2_x509_verify_signature(openssl3_certificate, sizeof(openssl3_certificate),
        issuer, SALTS_CRYPTO_SM2_DEFAULT_ID, 16), SALTS_CRYPTO_EVERIFY);
    /* Establish why the original parser-only fixture is not a positive
     * default-ID signature vector: it is signed with an empty SM2 identity.
     * This native diagnostic belongs only to the formal test; the public API
     * never retries identities or admits an empty identity implicitly. */
    SM2_KEY native = {0}; SM2_SIGNATURE sig; SM3_CTX hash; uint8_t z[32], digest[32];
    const uint8_t *p = view.signature; size_t remaining = view.signature_size;
    check_equal(sm2_z256_point_from_octets(&native.public_key, issuer, 65), 1);
    check_equal(sm2_compute_z(z, &native.public_key, "", 0), 1);
    sm3_init(&hash); sm3_update(&hash, z, 32); sm3_update(&hash, view.tbs_der, view.tbs_size); sm3_finish(&hash, digest);
    check_equal(sm2_signature_from_der(&sig, &p, &remaining), 1);
    check_equal(remaining, (size_t)0);
    check_equal(sm2_do_verify(&native, digest, &sig), 1);
    check_equal(salts_crypto_sm2_x509_public_key(openssl3_certificate, sizeof(openssl3_certificate), out), SALTS_CRYPTO_EVERIFY);
    check_true(filled(out, sizeof(out), 0));
  }
  it("rejects wrong algorithm, forbidden parameters and mismatched inner/outer identifiers") {
    bytes cert; uint8_t issuer[65];
    check_equal(salts_crypto_sm2_public_key(key_one, issuer), SALTS_CRYPTO_OK);
    const int params[][3] = {{2,2,0},{0,1,0},{1,0,0},{0,0,1}};
    for (size_t i=0; i<4; ++i) {
      check_true(certificate(&cert, params[i][0], params[i][1], params[i][2], NULL, 0, 0));
      check_equal(verify(&cert, issuer), SALTS_CRYPTO_EVERIFY);
    }
  }
  it("rejects tampered signatures and TBS, truncation, trailing bytes and noncanonical DER") {
    bytes cert; uint8_t issuer[65]; crypto_x509_der_view view;
    check_equal(salts_crypto_sm2_public_key(key_one, issuer), SALTS_CRYPTO_OK);
    check_true(certificate(&cert, 0, 0, 0, NULL, 0, 0));
    check_equal(crypto_x509_der_inspect(cert.data, cert.size, &view), SALTS_ASN1_OK);
    size_t serial_at = (size_t)(view.serial_number-cert.data);
    cert.data[serial_at] ^= 2;
    check_equal(verify(&cert, issuer), SALTS_CRYPTO_EVERIFY);
    cert.data[serial_at] ^= 2;
    cert.data[cert.size-1] ^= 1;
    check_equal(verify(&cert, issuer), SALTS_CRYPTO_EVERIFY);
    cert.data[cert.size-1] ^= 1;
    for (size_t i=1; i<cert.size; ++i)
      check_equal(salts_crypto_sm2_x509_verify_signature(cert.data, i, issuer, issuer_id, sizeof(issuer_id)-1), SALTS_CRYPTO_EVERIFY);
    cert.data[cert.size++] = 0;
    check_equal(verify(&cert, issuer), SALTS_CRYPTO_EVERIFY);
    --cert.size; cert.data[1] = 0x80;
    check_equal(verify(&cert, issuer), SALTS_CRYPTO_EVERIFY);
  }
  it("rejects invalid DER signature integers and out-of-range scalars") {
    bytes cert; uint8_t issuer[65];
    check_equal(salts_crypto_sm2_public_key(key_one, issuer), SALTS_CRYPTO_OK);
    static const uint8_t zero_r[] = {0x30,6,2,1,0,2,1,1};
    static const uint8_t negative_r[] = {0x30,6,2,1,0xff,2,1,1};
    static const uint8_t padded_r[] = {0x30,7,2,2,0,1,2,1,1};
    static const uint8_t extra[] = {0x30,9,2,1,1,2,1,1,2,1,1};
    const struct { const uint8_t *p; size_t n; } bad[] = {
      {zero_r,sizeof(zero_r)},{negative_r,sizeof(negative_r)},{padded_r,sizeof(padded_r)},{extra,sizeof(extra)}};
    for (size_t i=0; i<4; ++i) {
      check_true(certificate(&cert, 0, 0, 0, bad[i].p, bad[i].n, 0));
      check_equal(verify(&cert, issuer), SALTS_CRYPTO_EVERIFY);
    }
    uint8_t big[33], one=1, der[141]; size_t n;
    memset(big, 0xff, sizeof(big));
    for (size_t size=32; size<=33; ++size) {
      check_equal(crypto_asn1_ecdsa_signature_encode(big, size, &one, 1, der, sizeof(der), &n), SALTS_ASN1_OK);
      check_true(certificate(&cert, 0, 0, 0, der, n, 0));
      check_equal(verify(&cert, issuer), SALTS_CRYPTO_EVERIFY);
    }
  }
  it("preserves output on admission failure and clears it on invalid SPKI or malformed certificate") {
    bytes cert; uint8_t out[66], before[4096], invalid[32]={0}; crypto_x509_der_view view;
    check_true(certificate(&cert, 0, 0, 0, NULL, 0, 0));
    memset(out, 0xa5, sizeof(out)); memcpy(before, cert.data, cert.size);
    check_equal(salts_crypto_sm2_x509_public_key(NULL, cert.size, out), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_x509_public_key(cert.data, 4097, out), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_x509_public_key(cert.data, 0, out), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_x509_public_key(cert.data, cert.size, cert.data+20), SALTS_CRYPTO_EINVAL);
    check_true(filled(out, sizeof(out), 0xa5)); check_equal(cert.data, before, cert.size);
    check_equal(salts_crypto_sm2_x509_matches_private_key(cert.data, cert.size, invalid), SALTS_CRYPTO_EVERIFY);
    memset(invalid, 0xff, sizeof(invalid));
    check_equal(salts_crypto_sm2_x509_matches_private_key(cert.data, cert.size, invalid), SALTS_CRYPTO_EVERIFY);
    check_equal(crypto_x509_der_inspect(cert.data, cert.size, &view), SALTS_ASN1_OK);
    size_t point = (size_t)(view.spki_der-cert.data)+view.spki_size-65;
    memset(cert.data+point+1, 0, 64); /* (0,0) is not a curveSM2 point. */
    check_equal(salts_crypto_sm2_x509_public_key(cert.data, cert.size, out), SALTS_CRYPTO_EVERIFY);
    check_true(filled(out, 65, 0)); check_equal(out[65], 0xa5);
    memset(out, 0xa5, sizeof(out));
    check_equal(salts_crypto_sm2_x509_public_key(cert.data, cert.size-1, out), SALTS_CRYPTO_EVERIFY);
    check_true(filled(out, 65, 0)); check_equal(out[65], 0xa5);
  }
  it("keeps signature validation separate from subject curve and validity/trust decisions") {
    bytes cert; uint8_t issuer[65], out[65];
    check_equal(salts_crypto_sm2_public_key(key_one, issuer), SALTS_CRYPTO_OK);
    /* All generated fixtures expire in 2025. This signature-only operation
     * has no clock or trust anchor and intentionally makes no validity claim. */
    check_true(certificate(&cert, 0, 0, 0, NULL, 0, 1));
    check_equal(verify(&cert, issuer), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_x509_public_key(cert.data, cert.size, out), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm2_x509_matches_private_key(cert.data, cert.size, key_two), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm2_x509_verify_signature(cert.data, cert.size, issuer, NULL, 1), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_x509_verify_signature(cert.data, cert.size, issuer, issuer_id, 0), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_x509_verify_signature(cert.data, cert.size, issuer, issuer_id, 8192), SALTS_CRYPTO_EINVAL);
    memset(issuer, 0, sizeof(issuer));
    check_equal(verify(&cert, issuer), SALTS_CRYPTO_EVERIFY);
  }
}
