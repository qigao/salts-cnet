#ifndef CRYPTO_X509_POLICY_INTERNAL_H
#define CRYPTO_X509_POLICY_INTERNAL_H

#include <crypto/export.h>
#include <crypto/x509_der.h>
#include <crypto/sm2_trust.h>

/* Private shared certificate/CRL profile checks. Inputs must already be DER. */
typedef enum salts_crypto_x509_tls_admission {
  SALTS_CRYPTO_X509_TLS_MALFORMED = -1,
  SALTS_CRYPTO_X509_TLS_UNSUPPORTED = 0,
  SALTS_CRYPTO_X509_TLS_ADMITTED = 1
} salts_crypto_x509_tls_admission;

/* Classify the first certificate in a possibly concatenated DER buffer for the
 * TLS provider profile. ADMITTED and UNSUPPORTED return its encoded size in
 * *consumed; MALFORMED leaves *consumed zero. This is parser/key admission,
 * never chain, hostname, time, usage or trust-anchor validation. */
SALTS_CRYPTO_EXPORT
salts_crypto_x509_tls_admission salts_crypto_x509_tls_certificate_admission(
    const void *der, size_t available, size_t *consumed);
SALTS_CRYPTO_EXPORT
int salts_crypto_x509_date(const asn1_tlv *value, int64_t *seconds);
SALTS_CRYPTO_EXPORT
int salts_crypto_generalized_time(const asn1_tlv *value, int64_t *seconds);
SALTS_CRYPTO_EXPORT
int salts_crypto_x509_valid_time(const crypto_x509_der_view *view, int64_t now);
SALTS_CRYPTO_EXPORT
int salts_crypto_x509_valid_name(const void *der, size_t size);
SALTS_CRYPTO_EXPORT
int salts_crypto_sm2_trust_admitted(const salts_crypto_sm2_chain_entry *chain,
    size_t count, const salts_crypto_sm2_trust_policy *policy, const uint8_t *out);
SALTS_CRYPTO_EXPORT
int salts_crypto_sm2_signed_der(const asn1_tlv *algorithm,
    const void *tbs, size_t tbs_size, const void *signature, size_t signature_size,
    const uint8_t issuer[65], const void *identity, size_t identity_size);
#endif
