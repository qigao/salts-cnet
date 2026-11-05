#ifndef SALTS_CRYPTO_SM2_TRUST_H
#define SALTS_CRYPTO_SM2_TRUST_H
#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM2_TRUST_MAX_CHAIN 4u /* leaf plus up to three intermediates */
#define SALTS_CRYPTO_SM2_TRUST_MAX_CERT_SIZE 4096u

typedef struct salts_crypto_sm2_cert_span {
  const void *der;
  size_t size;
} salts_crypto_sm2_cert_span;

typedef struct salts_crypto_sm2_chain_entry {
  salts_crypto_sm2_cert_span certificate;
  const void *issuer_identity; /* SM2 signing ID for THIS certificate's signature */
  size_t issuer_identity_size; /* 1..8191, explicit binary bytes */
} salts_crypto_sm2_chain_entry;

typedef enum salts_crypto_sm2_trust_purpose {
  SALTS_CRYPTO_SM2_TRUST_SERVER_SIGNING = 1,
  SALTS_CRYPTO_SM2_TRUST_CLIENT_SIGNING = 2
} salts_crypto_sm2_trust_purpose;
typedef enum salts_crypto_sm2_revocation_policy {
  SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL = 1,
  SALTS_CRYPTO_SM2_REVOCATION_NOT_CHECKED = 2
} salts_crypto_sm2_revocation_policy;

/* Synchronous external revocation decision, after all structural, signature,
 * time, usage, path and pin checks pass. Called leaf-first for every non-anchor
 * certificate, at most four times, stopping on first failure. Return OK only
 * for accepted status at validation_time; revoked/unknown/stale/unavailable
 * status must return an error. Spans borrow immutable caller input until the
 * callback returns. No callback/result is retained. Context is caller-owned.
 * The callback must not mutate inputs/options/output or recursively use the
 * same output. Core neither fetches nor verifies CRL/OCSP data on its behalf.
 */
typedef int (*salts_crypto_sm2_revocation_check)(void *context, size_t depth,
    const salts_crypto_sm2_cert_span *certificate,
    const salts_crypto_sm2_cert_span *issuer, int64_t validation_time);

typedef struct salts_crypto_sm2_trust_policy {
  salts_crypto_sm2_cert_span anchor; /* authenticated out of band, never from peer chain */
  const uint8_t *expected_leaf_public_key; /* exactly 65 authenticated curveSM2 bytes */
  int64_t validation_time; /* explicit Unix seconds, 0..253402300799, inclusive */
  salts_crypto_sm2_trust_purpose purpose;
  salts_crypto_sm2_revocation_policy revocation;
  salts_crypto_sm2_revocation_check check_revocation;
  void *revocation_context;
} salts_crypto_sm2_trust_policy;

/* Restricted certificate-path profile for a PINNED signing peer, not general
 * WebPKI path discovery or hostname verification. Pass leaf-first chain without
 * anchor, 1..4 entries, each canonical v3 DER <=4096 bytes, all curveSM2.
 * Every signature uses the next entry/explicit anchor and its supplied SM2 ID.
 * Subject/issuer Names must be nonempty and match byte-for-byte; no DN normalization/search.
 * RDNs must be nonempty with primitive, nonempty attribute values.
 * Intermediates must not be self-issued; duplicate certificates are rejected.
 * Anchor self-signature is not required: trust comes from caller configuration.
 * Anchor, intermediates and leaf must be valid at the explicit time (Gregorian
 * dates, inclusive boundaries). CA certificates require critical CA=true basic
 * constraints, keyCertSign and sufficient pathLen; leaf requires CA=false,
 * digitalSignature, no keyCertSign/cRLSign and the exact requested EKU. CA EKU,
 * when present, must also contain that purpose; anyEKU alone is insufficient.
 * Leaf basicConstraints may be absent. KU and leaf EKU are mandatory.
 * Unsupported critical extensions, name constraints and policy constraint/
 * mapping/policies/inhibitAnyPolicy extensions are rejected even if noncritical.
 * Noncritical SAN/SKI/AKI and other noncritical metadata are not identity checks.
 * Identity is the authenticated expected leaf key; no CN/SAN/wildcard fallback.
 * This profile does not qualify DNS/HTTP identity, TLCP encryption certificates,
 * revocation data parsing or a TLS handshake by itself.
 *
 * Explicit revocation policy is required. EXTERNAL requires a callback; only
 * OK admits each certificate. NOT_CHECKED requires NULL callback/context and
 * reports no revocation assurance. There is no unavailable-to-allow fallback.
 *
 * Synchronous, bounded, allocation-free; no clocks/files/network/retained state.
 * Caller keeps all inputs immutable until return and exclusively owns output.
 * Output (65 bytes) must not overlap policy, entries, pins, certificates or IDs.
 * Invalid admission returns EINVAL without touching output or calling callbacks.
 * Admitted rejection returns EVERIFY, clears exactly 65 output bytes and never
 * publishes a partial result. Only complete success releases the leaf key.
 */
int salts_crypto_sm2_validate_pinned_chain(const salts_crypto_sm2_chain_entry *chain,
    size_t count, const salts_crypto_sm2_trust_policy *policy, uint8_t public_key[65]);

#ifdef __cplusplus
}
#endif
#endif
