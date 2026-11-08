#ifndef SALTS_CRYPTO_SM2_OCSP_H
#define SALTS_CRYPTO_SM2_OCSP_H
#include <crypto/sm2_trust.h>
#ifdef __cplusplus
extern "C" {
#endif
enum {
  SALTS_CRYPTO_SM2_OCSP_MAX_BYTES = 65536,
  SALTS_CRYPTO_SM2_OCSP_MAX_RESPONSES = 16,
  SALTS_CRYPTO_SM2_OCSP_MAX_NONCE = 128,
  SALTS_CRYPTO_SM2_OCSP_MAX_CLOCK_SKEW = 3600
};
typedef struct salts_crypto_sm2_ocsp_policy {
  const void *der;
  size_t size;
  const void *signer_identity; /* explicit response-signing SM2 ID, 1..8191 bytes */
  size_t signer_identity_size;
  uint32_t maximum_age_seconds; /* nonzero; measured from thisUpdate */
  uint32_t maximum_clock_skew_seconds; /* 0..3600, no implicit allowance */
  int64_t minimum_this_update; /* authenticated caller-maintained rollback floor */
  const void *nonce; /* NULL/0 requires no nonce; otherwise exact 32..128 bytes */
  size_t nonce_size;
} salts_crypto_sm2_ocsp_policy;

/** Verify an RFC 6960 BasicOCSPResponse signed by the target's direct SM2
 * issuer. Intended for an authenticated path's EXTERNAL revocation callback:
 * certificate and issuer/path trust have ALREADY been established by the caller.
 * This operation never creates trust from embedded certificates. Issuer and
 * target must be canonical v3 DER, valid at validation_time, with exact issuer/
 * subject name binding. Issuer must be CA=true with critical basicConstraints,
 * keyCertSign, and a validated curveSM2 public key. Response signature is SM2/SM3
 * with the explicit identity above. Delegated responders are outside this API.
 * Optional embedded certificates must contain exactly the supplied issuer.
 *
 * CertID uses SHA1, SHA256 or SM3 over the issuer's exact Name/public-key bits;
 * SHA1 is identifier-only, never a response signature. ResponderID byName binds
 * the exact Name; byKey binds RFC 6960's SHA1 key hash. One successful response
 * must contain exactly one matching CertID with good status. Revoked, unknown,
 * missing/duplicate matches, malformed/unsupported entries and trailing DER fail.
 * All entries must bind the supplied issuer and are parsed, including those
 * after the match; max 16, no duplicate
 * DER CertIDs. Single-response extensions are rejected. Response extensions
 * support only one exact nonce, nested OCTET STRING syntax per RFC 9654.
 * Expected nonces are caller-generated 32..128 cryptographically random bytes;
 * none is generated or guessed here. NULL/0 admits only nonce-free responses.
 *
 * Mandatory thisUpdate <= producedAt < nextUpdate; time values are exact
 * GeneralizedTime. thisUpdate/producedAt <= time+skew, time-skew < nextUpdate,
 * age <= maximum_age_seconds, thisUpdate >= minimum_this_update. Every entry
 * must satisfy the freshness profile. No implicit current clock, request retry,
 * fetching, cache, persistence or rollback-floor mutation. Caller authenticates
 * and persists its floor; replay of still-current older status is possible with
 * a stale floor and no request nonce. No soft-fail for unavailable status.
 *
 * Inputs are immutable borrows for this synchronous allocation-free call.
 * Safe concurrent calls use immutable inputs. No callbacks or output storage.
 * OK means authenticated/current matching good status, not general certificate
 * trust or assurance that the certificate was issued. EINVAL rejects admission;
 * EVERIFY includes revoked/unknown/stale/unsupported/unverifiable response.
 */
int salts_crypto_sm2_check_direct_ocsp(const salts_crypto_sm2_cert_span *certificate,
    const salts_crypto_sm2_cert_span *issuer, int64_t validation_time,
    const salts_crypto_sm2_ocsp_policy *policy);
/** Authenticate a direct-issuer status snapshot without checking a target.
 * Same input/algorithm/freshness/entry limits as check_direct_ocsp. Every CertID
 * must bind the authenticated issuer. Revoked/unknown entries may be present:
 * OK authenticates the collection, never a certificate's status. Call
 * check_direct_ocsp for each actual peer at admission time. No retained state. */
int salts_crypto_sm2_validate_direct_ocsp(const salts_crypto_sm2_cert_span *issuer,
    int64_t validation_time, const salts_crypto_sm2_ocsp_policy *policy);
/** Explicit delegated-responder profile. The responder certificate is supplied
 * by the caller, never discovered or promoted from embedded response data.
 * It must be directly signed by the same issuer key as the target, with its own
 * explicit issuer-signing ID, digitalSignature KU, OCSPSigning EKU, CA=false,
 * and noncritical id-pkix-ocsp-nocheck containing exact DER NULL. The last
 * extension is the issuer's authorization to omit responder revocation for the
 * certificate lifetime; without it this finite profile fails, never soft-fails.
 * Canonical certificate, issuer/name/path constraints and current validity use
 * the same pinned-path owner as sm2_trust.h. The response signer ID remains
 * independent in response.signer_identity. Responder must also be valid at
 * producedAt. Caller has already authenticated issuer and target path.
 *
 * Response/CertID/freshness/nonce/ownership/error rules match direct checking.
 * ResponderID binds this explicit responder, CertIDs still bind the target CA.
 * Optional embedded certificates contain exactly responder then optional exact
 * issuer. No indirect delegate chain, responder lookup, CRL fetch or recursion.
 * Synchronous and allocation-free; all policy/certificate bytes are immutable
 * borrows. A successful collection check never asserts any target is good.
 */
typedef struct salts_crypto_sm2_delegated_ocsp_policy {
  salts_crypto_sm2_ocsp_policy response;
  salts_crypto_sm2_cert_span responder_certificate;
  const void *responder_issuer_identity;
  size_t responder_issuer_identity_size;
} salts_crypto_sm2_delegated_ocsp_policy;
int salts_crypto_sm2_check_delegated_ocsp(const salts_crypto_sm2_cert_span *certificate,
    const salts_crypto_sm2_cert_span *issuer, int64_t validation_time,
    const salts_crypto_sm2_delegated_ocsp_policy *policy);
int salts_crypto_sm2_validate_delegated_ocsp(const salts_crypto_sm2_cert_span *issuer,
    int64_t validation_time, const salts_crypto_sm2_delegated_ocsp_policy *policy);
#ifdef __cplusplus
}
#endif
#endif
