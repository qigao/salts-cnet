/* SPDX-License-Identifier: Apache-2.0
 * Read-only X.509 DER metadata from the one provider-neutral Salts::ASN1.
 * This is NOT certificate-chain validation, authentication or TLS policy.
 */
#ifndef CRYPTO_X509_DER_H
#define CRYPTO_X509_DER_H

#include <asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_X509_DER_MAX_CERT_BYTES 4096u
#define CRYPTO_X509_DER_MAX_CHAIN_BYTES 4096u
#define CRYPTO_X509_DER_MAX_EXTENSIONS 64u

/* All spans borrow the caller's DER input. No allocations, no retained state.
 * Spans named *_der include their original tag and length octets.
 * OID spans contain the canonical DER OID CONTENT octets (no tag/length).
 * Signature spans omit the BIT STRING's initial unused-bits octet.
 *
 * Fields are structural metadata only; NOT a statement about certificate
 * validity, trust roots, signature verification, time, hostname or usage.
 * The caller must retain the original DER buffer while using any span.
 */
typedef struct crypto_x509_der_view {
    const uint8_t *certificate_der;
    size_t certificate_size;
    const uint8_t *tbs_der;
    size_t tbs_size;
    uint32_t version;  /* 0=v1, 1=v2, 2=v3. */
    const uint8_t *serial_number;
    size_t serial_number_size;
    const uint8_t *issuer_der;
    size_t issuer_size;
    const uint8_t *subject_der;
    size_t subject_size;
    const uint8_t *validity_der;
    size_t validity_size;
    const uint8_t *spki_der;
    size_t spki_size;
    const uint8_t *public_key_algorithm_oid;
    size_t public_key_algorithm_oid_size;
    const uint8_t *signature_algorithm_oid;
    size_t signature_algorithm_oid_size;
    const uint8_t *signature;
    size_t signature_size;
    const uint8_t *extensions_der; /* NULL if absent; DER Extensions SEQUENCE. */
    size_t extensions_size;
} crypto_x509_der_view;

/* Parse ONE complete DER X.509 Certificate with exact structure, strict
 * AlgorithmIdentifier equality and bounded, ordered optional fields.
 * No BER, PEM, trailing bytes, heap allocation or partial output on error.
 * DER dates are syntax-checked; no clock or trust decision is performed. */
SALTS_ASN1_PUBLIC asn1_status crypto_x509_der_inspect(
    const void *certificate_der, size_t certificate_size,
    crypto_x509_der_view *out);

/* Walk a concatenated DER chain returned by
 * crypto_tls_session_copy_peer_chain_v1_2(), without touching TLS state.
 * *offset starts at 0, advances only on success; DONE at exact exhaustion.
 * The view and offset are unchanged on any error or DONE. A complete
 * chain is accepted ONLY after iteration reaches DONE.
 */
SALTS_ASN1_PUBLIC asn1_status crypto_x509_der_chain_next(
    const void *chain, size_t chain_size, size_t *offset,
    crypto_x509_der_view *out);

/* A narrow, read-only public-key AlgorithmIdentifier classification.
 * UNKNOWN is a valid structural result, not a rejected certificate or
 * cryptographic statement. No keys are allocated or validated. */
typedef enum crypto_x509_der_public_key_kind {
    CRYPTO_X509_DER_KEY_UNKNOWN = 0,
    CRYPTO_X509_DER_KEY_RSA = 1,
    CRYPTO_X509_DER_KEY_EC = 2,
    CRYPTO_X509_DER_KEY_ED25519 = 3
} crypto_x509_der_public_key_kind;

SALTS_ASN1_PUBLIC asn1_status crypto_x509_der_get_public_key_kind(
    const crypto_x509_der_view *view,
    crypto_x509_der_public_key_kind *out);

/* Find exactly one CN attribute in the borrowed Subject or Issuer DER Name.
 * issuer=0 means subject, issuer=1 means issuer. Returns DONE when no CN
 * exists; rejects malformed or ambiguous multiple CN attributes.
 * The result is a length-bounded borrowed string, NOT NUL terminated and
 * NOT suitable for TLS hostname or identity authentication. */
SALTS_ASN1_PUBLIC asn1_status crypto_x509_der_common_name(
    const crypto_x509_der_view *view, uint8_t issuer,
    const uint8_t **out_data, size_t *out_size);


#ifdef __cplusplus
}
#endif
#endif /* CRYPTO_X509_DER_H */
