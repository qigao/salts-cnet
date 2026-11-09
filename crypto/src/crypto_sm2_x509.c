#include <crypto/sm2_x509.h>
#include <crypto/sm2.h>
#include <crypto/sm2_keys.h>
#include <crypto/x509_der.h>
#include <crypto/asn1_crypto.h>
#include "crypto_internal.h"
#include "crypto_x509_policy.h"
#include <string.h>

_Static_assert(SALTS_CRYPTO_SM2_X509_MAX_CERT_SIZE == CRYPTO_X509_DER_MAX_CERT_BYTES,
    "SM2 certificate admission must match the canonical inspector bound");

static int valid_input(const void *cert, size_t n) {
  return cert && n && n <= SALTS_CRYPTO_SM2_X509_MAX_CERT_SIZE;
}
static int inspect(const void *cert, size_t n, crypto_x509_der_view *view) {
  return crypto_x509_der_inspect(cert, n, view) == SALTS_ASN1_OK ?
      SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
}
int salts_crypto_sm2_x509_public_key(const void *cert, size_t n, uint8_t pub[65]) {
  crypto_x509_der_view view;
  if (!valid_input(cert, n) || !pub || salts_crypto_overlap(cert, n, pub, 65))
    return SALTS_CRYPTO_EINVAL;
  int status = inspect(cert, n, &view);
  if (status == SALTS_CRYPTO_OK && salts_crypto_sm2_spki_import(view.spki_der, view.spki_size, pub) != SALTS_CRYPTO_OK)
    status = SALTS_CRYPTO_EVERIFY;
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(pub, 65);
  return status;
}
int salts_crypto_sm2_x509_matches_private_key(const void *cert, size_t n, const uint8_t key[32]) {
  uint8_t expected[65] = {0}, actual[65] = {0};
  if (!valid_input(cert, n) || !key) return SALTS_CRYPTO_EINVAL;
  int status = salts_crypto_sm2_x509_public_key(cert, n, expected);
  if (status == SALTS_CRYPTO_OK &&
      (salts_crypto_sm2_public_key(key, actual) != SALTS_CRYPTO_OK || memcmp(actual, expected, 65)))
    status = SALTS_CRYPTO_EVERIFY;
  salts_crypto_secure_zero(expected, sizeof(expected));
  salts_crypto_secure_zero(actual, sizeof(actual));
  return status;
}
static int signature_algorithm(const asn1_tlv *alg) {
  static const uint8_t sm2_sm3_oid[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x83,0x75};
  asn1_reader fields; asn1_tlv value;
  if (alg->tag_class || !alg->constructed || alg->tag_number != 16u ||
      asn1_reader_init(&fields, alg->content, alg->content_size, SALTS_ASN1_DER) != SALTS_ASN1_OK ||
      asn1_reader_next(&fields, &value) != SALTS_ASN1_OK ||
      value.tag_class || value.constructed || value.tag_number != 6u ||
      value.content_size != sizeof(sm2_sm3_oid) || memcmp(value.content, sm2_sm3_oid, sizeof(sm2_sm3_oid))) return 0;
  asn1_status status = asn1_reader_next(&fields, &value);
  if (status == SALTS_ASN1_DONE) return 1;
  return status == SALTS_ASN1_OK && !value.tag_class && !value.constructed &&
      value.tag_number == 5u && value.content_size == 0u &&
      asn1_reader_next(&fields, &value) == SALTS_ASN1_DONE;
}
int salts_crypto_sm2_signed_der(const asn1_tlv *algorithm,
    const void *tbs, size_t tbs_size, const void *signature, size_t signature_size,
    const uint8_t issuer[65], const void *id, size_t idn) {
  const uint8_t *r, *s; size_t rn, sn; uint8_t raw[64] = {0};
  if (!signature_algorithm(algorithm) || signature_size > 72u ||
      crypto_asn1_ecdsa_signature_decode(signature, signature_size, &r, &rn, &s, &sn) != SALTS_ASN1_OK ||
      rn > 32u || sn > 32u) return SALTS_CRYPTO_EVERIFY;
  memcpy(raw+32u-rn, r, rn); memcpy(raw+64u-sn, s, sn);
  int status = salts_crypto_sm2_verify(issuer, id, idn, tbs, tbs_size, raw);
  return status == SALTS_CRYPTO_EINVAL ? SALTS_CRYPTO_EVERIFY : status;
}
int salts_crypto_sm2_x509_verify_signature(const void *cert, size_t n,
    const uint8_t issuer[65], const void *id, size_t idn) {
  crypto_x509_der_view view; asn1_reader reader; asn1_tlv algorithm;
  if (!valid_input(cert, n) || !issuer || !id || !idn || idn > 8191u) return SALTS_CRYPTO_EINVAL;
  if (inspect(cert, n, &view) != SALTS_CRYPTO_OK) return SALTS_CRYPTO_EVERIFY;
  /* Inspector established exact inner/outer AlgorithmIdentifier equality. */
  const uint8_t *start = view.tbs_der + view.tbs_size;
  size_t remaining = view.certificate_size - (size_t)(start - view.certificate_der);
  if (asn1_reader_init(&reader, start, remaining, SALTS_ASN1_DER) != SALTS_ASN1_OK ||
      asn1_reader_next(&reader, &algorithm) != SALTS_ASN1_OK) return SALTS_CRYPTO_EVERIFY;
  return salts_crypto_sm2_signed_der(&algorithm, view.tbs_der, view.tbs_size,
      view.signature, view.signature_size, issuer, id, idn);
}
