/* Provider-neutral configuration for an owned SM2 CRL admission snapshot. */
#ifndef CRYPTO_TLS_SM2_CRL_POLICY_H
#define CRYPTO_TLS_SM2_CRL_POLICY_H
#include <crypto/tls_peer_policy.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_tls_sm2_crl_config {
  size_t size;
  const void *issuer_certificate; /* Authenticated direct issuer DER, 1..4096 bytes. */
  size_t issuer_certificate_size;
  const void *crl; /* Complete direct-issuer CRL DER, 1..65536 bytes. */
  size_t crl_size;
  const void *certificate_signing_identity; /* Explicit binary SM2 ID, 1..8191 bytes. */
  size_t certificate_signing_identity_size;
  const void *crl_signing_identity; /* Explicit binary SM2 ID, 1..8191 bytes. */
  size_t crl_signing_identity_size;
  uint64_t minimum_crl_number;
  uint32_t maximum_age_seconds; /* Nonzero, enforced again on every handshake. */
  bool peer_is_server;
} crypto_tls_sm2_crl_config;

/* Create a SHANGMI_TLS13-only, direct-issuer admission policy. Uses the trusted
 * host UTC clock at creation AND each handshake; clock failure rejects.
 * Caller authenticates issuer configuration and persists/updates the rollback
 * floor. Creation authenticates CRL signature/profile/time/number, not a peer's
 * status. Handshake checks peer role/profile, issuer signature binding and CRL
 * status after mandatory TLS PKI/identity/possession verification. Peer chain
 * must contain just the leaf, or leaf + the byte-identical configured issuer.
 * Declares exactly SHANGMI_TLS13 and the configured peer role: incompatible
 * TLS context creation returns ENOTSUP before trust loading or retain.
 * Longer paths reject during handshake; there is no discovery or fallback.
 *
 * Immutable snapshot copies all bytes in one bounded allocation (less than
 * 87 KiB including metadata); no allocation/fetching or locks during checking.
 * Atomic retain/release supports shared contexts on concurrent owners. Success
 * returns one owned reference in out_policy. TLS context creation retains its
 * own reference; caller releases its reference with out_policy->release(context).
 * Copying a descriptor does not acquire another reference. Retain before sharing
 * independent ownership; keep the owning DSO loaded through final release.
 * out_policy must not own a reference on entry. Inputs are synchronous borrows
 * and may be released after return; inputs and
 * output must not overlap. Failure clears out_policy and retains nothing.
 * Never mutate the snapshot: refresh by creating a new policy and TLS context.
 * Established connections are not revalidated. No OCSP or CRL distribution.
 * Returns crypto_tls_stream_result (EINVAL, ENOMEM, EIO, ECONNABORTED or OK).
 */
int crypto_tls_sm2_crl_peer_policy_create(const crypto_tls_sm2_crl_config *config,
    crypto_tls_stream_peer_policy *out_policy);

/* TLCP11 server-authentication variant, with the same ownership and snapshot
 * limits. peer_is_server must be true; false returns ENOTSUP. Checks BOTH the
 * signing and encryption certificate, in wire order, against the same explicit
 * issuer, certificate-signing ID and complete CRL. Two distinct certificates
 * are required; a third must be the byte-identical configured issuer. Different
 * issuers/IDs and longer paths reject during handshake. Declares TLCP11 and
 * the SERVER peer role; incompatible TLS context creation returns ENOTSUP.
 * Mandatory TLCP
 * authentication/role/identity checks still precede this additional policy.
 * Does not add TLCP client authentication or silently select another profile.
 */
int crypto_tlcp_sm2_crl_peer_policy_create(const crypto_tls_sm2_crl_config *config,
    crypto_tls_stream_peer_policy *out_policy);

#ifdef __cplusplus
}
#endif
#endif
