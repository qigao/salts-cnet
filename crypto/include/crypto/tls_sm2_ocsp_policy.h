#ifndef CRYPTO_TLS_SM2_OCSP_POLICY_H
#define CRYPTO_TLS_SM2_OCSP_POLICY_H
#include <crypto/tls_peer_policy.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct crypto_tls_sm2_ocsp_config {
  size_t size;
  const void *issuer_certificate;
  size_t issuer_certificate_size; /* authenticated direct SM2 issuer DER, 1..4096 */
  const void *response;
  size_t response_size; /* explicitly selected issuer/delegate OCSP DER, 1..65536 */
  const void *certificate_signing_identity;
  size_t certificate_signing_identity_size; /* explicit 1..8191 bytes */
  const void *response_signing_identity;
  size_t response_signing_identity_size; /* explicit 1..8191 bytes */
  uint32_t maximum_age_seconds;
  uint32_t maximum_clock_skew_seconds; /* 0..3600 */
  int64_t minimum_this_update; /* caller-authenticated/persisted rollback floor */
  bool peer_is_server;
  /* All four zero selects direct issuer. Otherwise explicit delegated signer,
   * with same-issuer OCSPSigning/digitalSignature/no-check certificate profile. */
  const void *responder_certificate;
  size_t responder_certificate_size;
  const void *responder_issuer_identity;
  size_t responder_issuer_identity_size;
} crypto_tls_sm2_ocsp_config;

/** Create an immutable SHANGMI_TLS13 OCSP admission snapshot.
 * Creation verifies the complete response/issuer/signature/freshness profile
 * using host UTC. Revoked/unknown status may be present in an authenticated
 * snapshot. Every handshake rechecks current time and the actual peer's matching
 * good status after mandatory TLS authentication; failures reject permanently.
 * Peer chain is one leaf, optionally the byte-identical configured issuer.
 * Optional explicit delegated responder uses sm2_ocsp.h's no-check profile;
 * no responder discovery, longer paths, fetching, wire stapling or soft-fail.
 * Snapshot responses must be nonce-free; request-nonce validation uses
 * salts_crypto_sm2_check_direct_ocsp in an application-owned policy instead.
 *
 * Owns one bounded allocation (<100 KiB metadata+copied public inputs), atomic
 * references, no mutable cache or new I/O owner. TLS constructors retain their
 * own reference; caller releases its original via out_policy->release(context).
 * Checks allocate nothing and may run concurrently on immutable storage.
 * Retain is infallible for live references; impossible reference overflow aborts
 * as an ownership invariant violation. Inputs are synchronous borrows and may
 * be freed on return. Keep owning code loaded through final release.
 * out_policy must own no reference on entry and be disjoint from all inputs.
 * Alias errors return EINVAL preserving storage; other failures clear output
 * and publish no reference. Returns crypto_tls_stream_result: EINVAL, ENOMEM,
 * EIO (clock), ECONNABORTED (response/issuer/responder verification), or OK.
 * No established-connection revalidation or hot update; publish a new context
 * to select a new response/floor. Caller authenticates issuer configuration and
 * maintains fresh responses and a nondecreasing rollback floor.
 */
int crypto_tls_sm2_ocsp_peer_policy_create(const crypto_tls_sm2_ocsp_config *config,
    crypto_tls_stream_peer_policy *out_policy);

/** Same-issuer TLCP11 server variant: peer_is_server must be true (otherwise
 * ENOTSUP). Both distinct signing/encryption leaves must have one matching good
 * status in the response. Optional third certificate is the exact issuer.
 * Declares only TLCP11/SERVER applicability; the TLS constructor rejects other
 * profiles/roles before trust I/O/retain. Does not add TLCP client authentication,
 * separate issuers/IDs or migration of established connections. */
int crypto_tlcp_sm2_ocsp_peer_policy_create(const crypto_tls_sm2_ocsp_config *config,
    crypto_tls_stream_peer_policy *out_policy);
#ifdef __cplusplus
}
#endif
#endif
