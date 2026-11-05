#ifndef CRYPTO_X509_POLICY_INTERNAL_H
#define CRYPTO_X509_POLICY_INTERNAL_H
#include <crypto/x509_der.h>

/* Private shared certificate/CRL profile checks. Inputs must already be DER. */
int salts_crypto_x509_date(const salts_asn1_tlv *value, int64_t *seconds);
int salts_crypto_x509_valid_time(const crypto_x509_der_view *view, int64_t now);
int salts_crypto_x509_valid_name(const void *der, size_t size);
int salts_crypto_sm2_signed_der(const salts_asn1_tlv *algorithm,
    const void *tbs, size_t tbs_size, const void *signature, size_t signature_size,
    const uint8_t issuer[65], const void *identity, size_t identity_size);
#endif
