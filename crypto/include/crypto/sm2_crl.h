#ifndef SALTS_CRYPTO_SM2_CRL_H
#define SALTS_CRYPTO_SM2_CRL_H
#include <crypto/sm2_trust.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM2_CRL_MAX_BYTES 65536u
#define SALTS_CRYPTO_SM2_CRL_MAX_ENTRIES 256u

typedef struct salts_crypto_sm2_crl_policy {
  const void *der;
  size_t size;
  const void *issuer_identity; /* Explicit CRL signing ID, 1..8191 binary bytes. */
  size_t issuer_identity_size;
  uint64_t minimum_number; /* Authenticated caller-maintained rollback floor. */
  uint32_t maximum_age_seconds; /* Required, nonzero; no implicit freshness. */
} salts_crypto_sm2_crl_policy;

/* Check one authenticated path certificate against a complete, direct-issuer
 * SM2/SM3 v2 CRL. Intended for the EXTERNAL revocation callback in sm2_trust.h:
 * the caller has ALREADY authenticated the issuer and certificate/path. This
 * function alone does not establish trust or verify the certificate signature.
 * The issuer must be a v3 CA with critical basicConstraints, cRLSign and SKI.
 * CRL issuer and certificate issuer must exactly match its nonempty subject.
 * Both certificates must be valid at validation_time (Unix seconds).
 *
 * Canonical DER only; mandatory nextUpdate, CRL number (uint64 profile), and
 * keyIdentifier-only AKI matching the issuer SKI. thisUpdate <= time < nextUpdate
 * and age <= maximum_age_seconds; number >= minimum_number. No clock/network,
 * fetching, cache or rollback state exists inside this operation. The caller
 * authenticates/persists the floor and updates CRLs; accepting a still-current
 * older CRL is possible if it supplies a stale floor.
 *
 * Full issuer-wide CRLs only: delta/freshest/issuingDistributionPoint and indirect
 * certificateIssuer extensions are rejected, even noncritical. Certificates
 * with CRL distribution/freshest points are outside this restricted profile.
 * Unknown critical extensions reject. Reason codes 0..6,9,10 are supported;
 * removeFromCRL and undefined reasons reject. Every listed serial is revoked,
 * including certificateHold. Future revocation dates reject the CRL.
 * All entries are checked, including after finding the target; duplicates,
 * malformed/empty entry lists and unsupported entry extensions fail closed.
 * At most 256 entries, 64 extensions per list; serials positive, <=20 DER bytes.
 *
 * Inputs are immutable caller-owned borrows for this synchronous call. No heap,
 * callbacks, retained storage or outputs. Safe concurrent calls use immutable
 * inputs. OK means valid full CRL and serial absent; EVERIFY includes revoked,
 * stale, unsupported or unverifiable data. EINVAL is invalid argument admission.
 */
int salts_crypto_sm2_check_crl(const salts_crypto_sm2_cert_span *certificate,
    const salts_crypto_sm2_cert_span *issuer, int64_t validation_time,
    const salts_crypto_sm2_crl_policy *policy);

#ifdef __cplusplus
}
#endif
#endif
