/* Provider-neutral TLS admission data contract; no native provider dependency. */
#ifndef CRYPTO_TLS_PEER_POLICY_H
#define CRYPTO_TLS_PEER_POLICY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
  CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_CERTIFICATES = 5,
  CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_BYTES = 4096
};

/** Immutable secure transport choice, fixed when client/server TLS context is created.
 * STANDARD preserves existing verified TLS 1.2-1.3 behavior; SHANGMI_TLS13
 * requires RFC 8998 TLS 1.3 with SM2/SM3/SM4-GCM. TLCP11 requires TLCP 1.1
 * with ECC-SM2/SM4-GCM/SM3. The profiles never fall back to each other.
 */
typedef enum crypto_tls_stream_security_profile {
  CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD = 0,
  CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13 = 1,
  CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 = 2
} crypto_tls_stream_security_profile;

/* Bit sets for policy applicability, independent of negotiated cipher suites. */
enum {
  CRYPTO_TLS_PEER_POLICY_STANDARD = 1u << CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD,
  CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13 = 1u << CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13,
  CRYPTO_TLS_PEER_POLICY_TLCP11 = 1u << CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11,
  CRYPTO_TLS_PEER_POLICY_CLIENT = 1u,
  CRYPTO_TLS_PEER_POLICY_SERVER = 2u
};

typedef struct crypto_tls_stream_peer_certificate_chain crypto_tls_stream_peer_certificate_chain;

/** Additional authenticated-peer admission (for example, local revocation).
 * This never replaces mandatory certificate, identity or proof-of-possession
 * checks. check runs once after those checks, before handshake completion and
 * application I/O. Only zero admits; every other result permanently rejects the
 * stream with ECONNABORTED. The peer-supplied chain is NOT a constructed trust
 * path: policy must select/authenticate its issuers and cover its required
 * certificates (including both TLCP certificates). Views are callback-scoped.
 *
 * All three functions are required. Context creation copies this descriptor
 * and, on success only, calls retain once; final context destruction calls
 * release once, after all streams release their references. The source
 * descriptor may then go away. The caller owns its original reference.
 * retain/release must be thread-safe and infallible. check runs synchronously
 * on the stream owner; shared contexts may check concurrently. Use immutable
 * snapshots or synchronization. No blocking, network fetching, reentry into
 * the stream, or retaining the chain. Time, freshness and rollback state are
 * policy responsibilities. Replace contexts to publish new immutable policy.
 * A server policy requires REQUIRED client authentication.
 *
 * supported_profiles and supported_peer_roles restrict context creation. Zero
 * in either mask means unrestricted in that dimension. Unknown bits fail with
 * EINVAL; a known but excluded profile/peer role fails with ENOTSUP, before
 * allocation, trust loading or retain. Roles describe the remote peer, not the
 * local context. These declarations do not replace check or mandatory TLS
 * verification. Decorators must preserve the wrapped policy's restrictions.
 */
typedef struct crypto_tls_stream_peer_policy {
  int (*check)(void *context, const crypto_tls_stream_peer_certificate_chain *chain,
               bool peer_is_server, crypto_tls_stream_security_profile profile);
  void (*retain)(void *context);
  void (*release)(void *context);
  void *context;
  uint32_t supported_profiles;
  uint32_t supported_peer_roles;
} crypto_tls_stream_peer_policy;

typedef struct crypto_tls_stream_peer_certificate {
  const uint8_t *data;
  size_t size;
} crypto_tls_stream_peer_certificate;

struct crypto_tls_stream_peer_certificate_chain {
  crypto_tls_stream_peer_certificate certificates[CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_CERTIFICATES];
  size_t count;
  size_t total_bytes;
};

#ifdef __cplusplus
}
#endif
#endif
