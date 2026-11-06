#ifndef CRYPTO_TLS_DIAGNOSTIC_H
#define CRYPTO_TLS_DIAGNOSTIC_H
#include <stddef.h>
#include <stdint.h>

/* Stable, provider-neutral categories. CERTIFICATE includes parsing, validity
 * and usage failures when the verifier does not distinguish them. HANDSHAKE
 * means no more specific local verification result is available; it must not
 * be interpreted as a certificate failure or a peer's verification result. */
typedef enum crypto_tls_failure_reason {
  CRYPTO_TLS_FAILURE_NONE = 0,
  CRYPTO_TLS_FAILURE_HANDSHAKE,
  CRYPTO_TLS_FAILURE_CERTIFICATE,
  CRYPTO_TLS_FAILURE_CHAIN_SIGNATURE,
  CRYPTO_TLS_FAILURE_TRUST_ANCHOR,
  CRYPTO_TLS_FAILURE_DEPTH,
  CRYPTO_TLS_FAILURE_CRL,
  CRYPTO_TLS_FAILURE_OCSP,
  CRYPTO_TLS_FAILURE_CONSTRAINTS,
  CRYPTO_TLS_FAILURE_CERTIFICATE_EXTENSIONS,
  CRYPTO_TLS_FAILURE_IDENTITY,
  CRYPTO_TLS_FAILURE_MISSING_CERTIFICATE,
  CRYPTO_TLS_FAILURE_PEER_POLICY,
  CRYPTO_TLS_FAILURE_PROFILE,
  CRYPTO_TLS_FAILURE_PLATFORM_TRUST,
  /* Actual local verifier time failure, not inferred from a remote alert.
   * Missing certificate position remains SIZE_MAX. Malformed validity keeps
   * the existing generic diagnosis; an unavailable clock remains CERTIFICATE. */
  CRYPTO_TLS_FAILURE_NOT_YET_VALID,
  CRYPTO_TLS_FAILURE_EXPIRED,
  /* Decoded KU/EKU incompatible with the required peer/issuer role. Missing
   * or malformed extensions retain the verifier's existing behavior/category. */
  CRYPTO_TLS_FAILURE_PURPOSE
} crypto_tls_failure_reason;

/* Owned value with no certificate, key, hostname or provider pointers.
 * Index is zero-based in the peer's presented chain; SIZE_MAX means unknown.
 * Validity/purpose/signature failures identify the checked peer certificate,
 * including intermediate CAs and the TLCP encryption leaf. Root-selection
 * failures and local-only trust anchors remain unknown; no position is inferred.
 * Ignore index when reason is NONE. This records local handshake failure only,
 * not transport failures, post-handshake errors or context-init failures. */
typedef struct crypto_tls_diagnostic {
  crypto_tls_failure_reason reason;
  size_t certificate_index;
} crypto_tls_diagnostic;
#endif
