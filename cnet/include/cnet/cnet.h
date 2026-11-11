#ifndef CNET_CNET_H
#define CNET_CNET_H

#include <core/error_codes.h>
#include <native_io.h>
#include <cnet/resources.h>
#include <memory/buffer.h>
#include <crypto/tls_peer_policy.h>
#include <crypto/tls_diagnostic.h>
#include <crypto/tls_sm2_crl_policy.h>
#include <crypto/tls_sm2_ocsp_policy.h>
#include <crypto/tls_credentials.h>
#include <crypto/tls_cipher.h>
#include <crypto/tls_signature.h>
#include <crypto/tls_group.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Caller-driven CNet client over NativeIO. */
typedef struct cnet_client {
  void *impl;
} cnet_client;

/** Single-owner nonblocking TCP or Linux VSOCK listener used by CNet-based servers. */
typedef struct cnet_listener {
  void *impl;
} cnet_listener;

/** Caller-driven bound UDP socket over NativeIO. The wrapper address stays stable until destroy. */
typedef struct cnet_datagram {
  void *impl;
} cnet_datagram;

/** Caller-driven bounded KCP protocol session. The wrapper address stays stable until destroy. */
typedef struct cnet_kcp {
  void *impl;
} cnet_kcp;

/** Caller-driven authenticated KCP v1 session with Reed-Solomon FEC. */
typedef struct cnet_secure_kcp {
  void *impl;
} cnet_secure_kcp;

/** Unified bound endpoint for unreliable UDP or reliable ordered KCP messages. */
typedef struct cnet_packet_endpoint {
  void *impl;
} cnet_packet_endpoint;

/** Generation-checked packet peer/session handle; never an OS descriptor or pointer. */
typedef struct cnet_packet_session {
  uint32_t slot;
  uint32_t generation;
} cnet_packet_session;

/** Reusable immutable TLS client context. */
typedef struct cnet_tls_client {
  void *impl;
} cnet_tls_client;

/** Reusable TLS server context. */
typedef struct cnet_tls_server {
  void *impl;
} cnet_tls_server;

/** Generation-checked value handle; never an OS descriptor or pointer. */
typedef struct cnet_connection {
  uint32_t slot;
  uint32_t generation;
} cnet_connection;

/** Fixed RFC 9266-style TLS exporter binding used to bind application handshakes to one connection.
 */
#define CNET_TLS_CHANNEL_BINDING_BYTES 32u

/** Maximum digest width of an RFC 5929 tls-server-end-point binding. */
#define CNET_TLS_SERVER_END_POINT_MAX_BYTES 64u

typedef enum cnet_connection_state {
  CNET_CONNECTION_CONNECTING = 1,
  CNET_CONNECTION_CONNECTED,
  CNET_CONNECTION_CLOSING,
  CNET_CONNECTION_CLOSED,
  CNET_CONNECTION_FAILED,
  /** An existing plaintext TCP stream is performing an in-place TLS handshake. */
  CNET_CONNECTION_TLS_HANDSHAKING
} cnet_connection_state;

typedef enum cnet_message_kind { CNET_MESSAGE_BYTES = 1, CNET_MESSAGE_DATAGRAM } cnet_message_kind;

/** `stage` is a stable CNet-owned string. */
typedef struct cnet_error {
  int status;
  int native_status;
  const char *stage;
  /** Local TLS handshake failure snapshot, copied through terminal delivery.
   * NONE for other failures. Contains no borrowed credential/provider storage;
   * the application may copy this value beyond the callback. */
  crypto_tls_diagnostic tls;
} cnet_error;

/** Borrowed view valid only for the duration of `on_receive`. */
typedef struct cnet_receive_view {
  const void *data;
  size_t size;
  cnet_message_kind kind;
} cnet_receive_view;

/** One immutable byte range borrowed by a synchronous CNet admission call. */
typedef struct cnet_const_buffer {
  const void *data;
  size_t size;
} cnet_const_buffer;

/**
 * Maximum retained ranges in one CNet logical scatter/gather write.
 *
 * NativeIO still receives at most NATIVE_IO_VECTOR_MAX spans per individual
 * backend submission. CNet advances larger retained vectors through multiple
 * bounded native submissions while preserving one logical send terminal.
 */
enum { CNET_RETAINED_VECTOR_MAX = 32u };

typedef enum cnet_datagram_address_family {
  CNET_DATAGRAM_ADDRESS_IPV4 = 4,
  CNET_DATAGRAM_ADDRESS_IPV6 = 6
} cnet_datagram_address_family;

/** Portable copied UDP peer address. Multi-byte scalar fields are in host byte order. */
typedef struct cnet_datagram_peer {
  cnet_datagram_address_family family;
  uint16_t port;
  uint32_t scope_id;
  uint8_t address[16];
} cnet_datagram_peer;

/** Portable copied TCP peer address. Multi-byte scalar fields are in host byte order. */
typedef struct cnet_stream_peer {
  cnet_datagram_address_family family;
  uint16_t port;
  uint32_t scope_id;
  uint8_t address[16];
} cnet_stream_peer;

/**
 * Move-owned accepted TCP stream used only between listener admission and one
 * final CNet owner. Zero initialization is the empty state.
 *
 * internal_socket and internal_active are implementation state and must not
 * be modified directly. peer is a copied portable endpoint and remains valid
 * after the stream is adopted or closed.
 */
typedef struct cnet_accepted_stream {
  uintptr_t internal_socket;
  cnet_stream_peer peer;
  uint32_t internal_active;
} cnet_accepted_stream;

#define CNET_ACCEPTED_STREAM_INIT \
  {0u, {(cnet_datagram_address_family)0, 0u, 0u, {0}}, 0u}

enum { CNET_STREAM_ENDPOINT_API_VERSION = 1 };

/**
 * Versioned lossless TCP endpoint for protocols that need the complete IPv6
 * sockaddr surface, including sin6_flowinfo. Multi-byte scalar fields are
 * carried as portable numeric values; native ABI representation stays private.
 */
typedef struct cnet_stream_endpoint {
  size_t size;
  uint32_t version;
  cnet_datagram_address_family family;
  uint16_t port;
  uint32_t flow_info;
  uint32_t scope_id;
  uint8_t address[16];
} cnet_stream_endpoint;

#define CNET_STREAM_ENDPOINT_INIT \
  {sizeof(cnet_stream_endpoint), CNET_STREAM_ENDPOINT_API_VERSION, 0, 0u, 0u, 0u, {0}}

/** Portable Linux VSOCK address constants; ANY values are valid only for listeners. */
#define CNET_VSOCK_CID_ANY UINT32_MAX
#define CNET_VSOCK_PORT_ANY UINT32_MAX
#define CNET_VSOCK_CID_LOCAL UINT32_C(1)
#define CNET_VSOCK_CID_HOST UINT32_C(2)

/** Portable copied AF_VSOCK endpoint. Both fields are in host byte order. */
typedef struct cnet_vsock_peer {
  uint32_t cid;
  uint32_t port;
} cnet_vsock_peer;

typedef void (*cnet_datagram_receive_fn)(void *user, cnet_datagram *datagram,
                                         const cnet_datagram_peer *peer,
                                         const cnet_receive_view *view);
/** Terminal result for one successfully admitted copied datagram, including its copied tag. */
typedef void (*cnet_datagram_send_fn)(void *user, cnet_datagram *datagram,
                                      const cnet_datagram_peer *peer, size_t size, int status,
                                      uint64_t tag);

typedef struct cnet_datagram_observer {
  cnet_datagram_receive_fn on_receive;
  cnet_datagram_send_fn on_send;
  void *user;
} cnet_datagram_observer;

/** Borrowed wire packet that must be copied or synchronously admitted before return. */
typedef int (*cnet_kcp_output_fn)(void *user, cnet_kcp *session, const void *data, size_t size);
/** Borrowed complete message valid only for the duration of the callback. */
typedef void (*cnet_kcp_receive_fn)(void *user, cnet_kcp *session, const cnet_receive_view *view);

typedef struct cnet_kcp_observer {
  cnet_kcp_output_fn output;
  cnet_kcp_receive_fn on_receive;
  void *user;
} cnet_kcp_observer;

typedef enum cnet_secure_kcp_role {
  CNET_SECURE_KCP_CLIENT = 1,
  CNET_SECURE_KCP_SERVER = 2
} cnet_secure_kcp_role;

typedef enum cnet_kcp_security_mode {
  CNET_KCP_SECURITY_NONE = 0,
  /** CoroNet-compatible TKSH/TKSR/TKF1 authenticated encryption and FEC. */
  CNET_KCP_SECURITY_PSK_V1 = 1
} cnet_kcp_security_mode;

typedef enum cnet_kcp_fec_backend {
  CNET_KCP_FEC_NONE = 0,
  CNET_KCP_FEC_REED_SOLOMON = 1
} cnet_kcp_fec_backend;

typedef int (*cnet_secure_kcp_output_fn)(void *user, cnet_secure_kcp *session, const void *data,
                                         size_t size);
typedef void (*cnet_secure_kcp_receive_fn)(void *user, cnet_secure_kcp *session,
                                           const cnet_receive_view *view);
typedef void (*cnet_secure_kcp_established_fn)(void *user, cnet_secure_kcp *session);

typedef struct cnet_secure_kcp_observer {
  cnet_secure_kcp_output_fn output;
  cnet_secure_kcp_receive_fn on_receive;
  cnet_secure_kcp_established_fn on_established;
  void *user;
} cnet_secure_kcp_observer;

typedef enum cnet_packet_protocol { CNET_PACKET_UDP = 1, CNET_PACKET_KCP = 2 } cnet_packet_protocol;

typedef struct cnet_packet_session_info {
  cnet_packet_protocol protocol;
  cnet_datagram_peer peer;
  uint32_t conversation;
} cnet_packet_session_info;

typedef enum cnet_packet_session_state {
  CNET_PACKET_SESSION_OPEN = 1,
  CNET_PACKET_SESSION_CLOSED = 2,
  CNET_PACKET_SESSION_CONNECTING = 3
} cnet_packet_session_state;

/** Return SALTS_OK to admit an unknown inbound peer/session; any other value rejects it. */
typedef int (*cnet_packet_admit_fn)(void *user, cnet_packet_endpoint *endpoint,
                                    cnet_packet_protocol protocol, const cnet_datagram_peer *peer,
                                    uint32_t conversation);
typedef void (*cnet_packet_state_fn)(void *user, cnet_packet_endpoint *endpoint,
                                     cnet_packet_session session, cnet_packet_session_state state,
                                     const cnet_datagram_peer *peer, uint32_t conversation);
typedef void (*cnet_packet_receive_fn)(void *user, cnet_packet_endpoint *endpoint,
                                       cnet_packet_session session, const cnet_receive_view *view);
typedef void (*cnet_packet_error_fn)(void *user, cnet_packet_endpoint *endpoint,
                                     cnet_packet_session session, int status);

typedef struct cnet_packet_observer {
  cnet_packet_admit_fn on_admit;
  cnet_packet_state_fn on_state;
  cnet_packet_receive_fn on_receive;
  cnet_packet_error_fn on_error;
  void *user;
} cnet_packet_observer;

enum { CNET_PACKET_TERMINAL_API_VERSION = 1u };

/**
 * Version 1 guarantees that datagram and packet endpoint stop return a
 * concrete error only after all admitted datagram sends and accepted tagged
 * packet sends have published their terminal callbacks. `SALTS_ETIMEDOUT`
 * remains retryable and does not discard the first concrete error.
 */
#define CNET_STOP_DRAIN_CONTRACT_VERSION 1u

/**
 * Authoritative terminal for one successfully admitted tagged logical send.
 * Callback arguments are borrowed through callback return. UDP reports its
 * NativeIO datagram terminal; KCP reports completion only after every segment
 * in the logical message is acknowledged by the peer.
 */
typedef void (*cnet_packet_send_terminal_fn)(void *user, cnet_packet_endpoint *endpoint,
                                             cnet_packet_session session, size_t size, int status,
                                             uint64_t tag);

/** Optional additive terminal policy consumed synchronously by endpoint init. */
typedef struct cnet_packet_terminal_config {
  size_t size;
  uint32_t version;
  /** Hard bound for concurrently admitted tagged logical sends. */
  size_t send_capacity;
  cnet_packet_send_terminal_fn on_send;
  void *user;
} cnet_packet_terminal_config;

#define CNET_PACKET_TERMINAL_CONFIG_INIT                                                           \
  {sizeof(cnet_packet_terminal_config), CNET_PACKET_TERMINAL_API_VERSION, 0u, NULL, NULL}

typedef void (*cnet_state_fn)(void *user, cnet_connection connection, cnet_connection_state state,
                              const cnet_error *error);
typedef void (*cnet_receive_fn)(void *user, cnet_connection connection,
                                const cnet_receive_view *view);

/**
 * Owned receive callback.
 *
 * For a non-empty receive, `slice` owns exactly one canonical Salts Core
 * buffer reference. A zero-length receive (for example an empty UDP datagram)
 * is delivered as an empty slice with no backing reference. The callback may
 * keep a non-empty descriptor after return and must eventually release that
 * reference with mem_slice_release(). The configured receive provider keeps
 * each backing alive independently, so an already delivered slice is valid across
 * later cnet_client_poll(), connection close, cnet_client_stop(), and
 * cnet_client_destroy().
 *
 * This is an explicit ownership/materialization surface, not a kernel
 * zero-copy guarantee. Existing borrowed on_receive semantics are unchanged.
 */
typedef void (*cnet_receive_slice_fn)(void *user, cnet_connection connection,
                                      mem_slice_t slice, cnet_message_kind kind);

/** Reports one successfully completed ordered write. An opt-in dedicated WS
 * transport binding consumes its own frame notifications instead of forwarding
 * them here; receive/state observer ownership is unchanged. */
typedef void (*cnet_send_fn)(void *user, cnet_connection connection, size_t size);

typedef struct cnet_observer {
  cnet_state_fn on_state;
  cnet_receive_fn on_receive;
  void *user;
  cnet_send_fn on_send;
} cnet_observer;

enum {
  CNET_TLS_ALPN_NAME_MAX_BYTES = 255,
  /** Lowercase SHA-256 hexadecimal digest plus the trailing NUL. */
  CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY = 65,
  /** Minimum fixed capacity of each TLS network BIO and scratch buffer. */
  CNET_TLS_MIN_IO_BUFFER_BYTES = 17 * 1024,
  CNET_TLS_KEY_UPDATE_RECORD_LIMIT_MAX = 1u << 20
};

#define CNET_TLS_KEY_UPDATE_BYTE_LIMIT_MAX (UINT64_C(1) << 34)

typedef enum cnet_tls_protocol_version {
  CNET_TLS_PROTOCOL_VERSION_DEFAULT = 0,
  CNET_TLS_PROTOCOL_VERSION_1_2 = 12,
  CNET_TLS_PROTOCOL_VERSION_1_3 = 13
} cnet_tls_protocol_version;

typedef enum cnet_tls_client_auth {
  CNET_TLS_CLIENT_AUTH_NONE = 0,
  CNET_TLS_CLIENT_AUTH_REQUIRED = 1
} cnet_tls_client_auth;

/** Immutable secure transport choice, fixed when client/server TLS context is created.
 * STANDARD preserves existing verified TLS 1.2-1.3 behavior; SHANGMI_TLS13
 * requires RFC 8998 TLS 1.3 with SM2/SM3/SM4-GCM. TLCP11 requires TLCP 1.1
 * with ECC-SM2/SM4-GCM/SM3. The profiles never fall back to each other.
 */
typedef enum cnet_tls_security_profile {
  CNET_TLS_SECURITY_PROFILE_STANDARD = 0,
  CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13 = 1,
  CNET_TLS_SECURITY_PROFILE_TLCP11 = 2
} cnet_tls_security_profile;

/** Crypto-owned authenticated-peer policy and callback-scoped certificate views.
 * Runs before CONNECTED; cannot bypass built-in TLS verification. See the
 * applicability masks, retain/release and concurrency contract in
 * crypto/tls_peer_policy.h. Unknown mask bits return SALTS_EINVAL; excluded
 * profiles/peer roles return SALTS_ENOTSUP during TLS initialization. */
typedef crypto_tls_stream_peer_policy cnet_tls_peer_policy;
typedef crypto_tls_sm2_crl_config cnet_tls_sm2_crl_config;

typedef crypto_tls_sm2_ocsp_config cnet_tls_sm2_ocsp_config;
/** Owned current-time OCSP snapshot; crypto/tls_sm2_ocsp_policy.h defines
 * admission, exact applicability, bounds, ownership and limitations. SALTS status.
 * Source bytes may be freed on return; caller releases the returned reference. */
int cnet_tls_sm2_ocsp_peer_policy_create(const cnet_tls_sm2_ocsp_config *config,
    cnet_tls_peer_policy *out_policy);
int cnet_tlcp_sm2_ocsp_peer_policy_create(const cnet_tls_sm2_ocsp_config *config,
    cnet_tls_peer_policy *out_policy);

typedef crypto_tls_data cnet_tls_data;

typedef crypto_tls_password cnet_tls_password;
typedef crypto_tls_cipher_suite cnet_tls_cipher_suite;
typedef crypto_tls_signature_scheme cnet_tls_signature_scheme;
typedef crypto_tls_group cnet_tls_group;
typedef crypto_tls_credentials cnet_tls_credentials;
typedef crypto_tls_credential_object cnet_tls_credential_object;
typedef crypto_tls_credential_kind cnet_tls_credential_kind;

/** Crypto-owned reusable immutable identity; see crypto/tls_credentials.h.
 * Returns SALTS status. Use a credentials descriptor with only .object set;
 * initialization imports independent keys before the caller releases it. */
int cnet_tls_credential_object_create(const cnet_tls_credentials *input,
    cnet_tls_credential_kind kind, cnet_tls_credential_object **out);
/** Authenticated PFX import; see crypto_tls_credential_object_from_pkcs12.
 * Returns mapped SALTS status and publishes no object on failure. */
int cnet_tls_credential_object_from_pkcs12(const cnet_tls_data *input,
    const cnet_tls_password *password, cnet_tls_credential_kind kind,
    cnet_tls_credential_object **out);
int cnet_tls_credential_object_retain(cnet_tls_credential_object *object);
void cnet_tls_credential_object_release(cnet_tls_credential_object *object);
enum {
  CNET_TLS_SERVER_IDENTITY_MAX_COUNT = CRYPTO_TLS_SERVER_IDENTITY_MAX_COUNT,
  CNET_TLS_CLIENT_IDENTITY_MAX_COUNT = CRYPTO_TLS_CLIENT_IDENTITY_MAX_COUNT
};
typedef crypto_tls_client_identity cnet_tls_client_identity;
typedef crypto_tls_server_identity cnet_tls_server_identity;

/** Creates a retained direct-issuer SM2 CRL policy inside CNet's Crypto owner.
 * Uses the snapshot contract in crypto/tls_sm2_crl_policy.h; returns SALTS status.
 * Attach to client/server peer_policy, then release the caller's reference via
 * policy.release(policy.context). Consumers link only Salts::CNet. */
int cnet_tls_sm2_crl_peer_policy_create(const cnet_tls_sm2_crl_config *config,
    cnet_tls_peer_policy *out_policy);

/** TLCP11 dual-server-certificate variant; peer_is_server must be true.
 * Same retained snapshot contract, checks both certificates against one issuer.
 * Unsupported client authentication returns SALTS_ENOTSUP at creation. */
int cnet_tlcp_sm2_crl_peer_policy_create(const cnet_tls_sm2_crl_config *config,
    cnet_tls_peer_policy *out_policy);

/**
 * Per-connection client policy. The configuration is consumed synchronously
 * by `cnet_connect()` and is not retained. Peer and hostname verification are
 * always enabled. Absent ca_file/ca_path/ca_data selects platform trust. TLCP11
 * client certificates are not qualified and return `SALTS_ENOTSUP`.
 */
typedef struct cnet_tls_client_config {
  size_t size;
  /** Optional PEM trust file and hashed trust directory. */
  const char *ca_file;
  const char *ca_path;
  /** Optional PEM client certificate chain and private key; configure both or neither. */
  const char *cert_file;
  const char *key_file;
  const char *key_password;
  /** Optional verified identity and SNI override; NULL uses the URI host. */
  const char *server_name;
  /** Optional ordered ALPN offer; each non-empty name is at most 255 bytes. */
  const char *const *alpn_protocols;
  size_t alpn_protocol_count;
  /** Explicit security profile; zero retains verified STANDARD TLS. */
  cnet_tls_security_profile security_profile;
  /** Optional extra admission; descriptor copied, context retained until quiescence. */
  const cnet_tls_peer_policy *peer_policy;
  /** SHANGMI_TLS13 local sending-key rotation threshold, 1..2^20 records.
   * Zero disables this record-count trigger, not the independent byte budget
   * or mandatory peer responses.
   * At the threshold, KeyUpdate precedes the next application record and
   * requests reciprocal rotation unless answering a pending peer request.
   * Counts records per application traffic key,
   * not CNet sends/bytes/time; control records are separate overhead.
   * Nonzero STANDARD/TLCP returns SALTS_ENOTSUP; above maximum SALTS_EINVAL.
   * Fixed per TLS context; no timer. Peer updates use peer_key_update_limit. */
  uint32_t key_update_record_limit;
  /** SHANGMI_TLS13 local sending-key application-plaintext budget, copied at
   * init. Zero disables it; 1..2^34 bytes is accepted. Above MAX: SALTS_EINVAL;
   * nonzero STANDARD/TLCP: SALTS_ENOTSUP, before trust I/O or policy retention.
   * Application records split at the remaining budget. Successful encryption
   * charges once despite pending ciphertext/partial writes. KeyUpdate precedes
   * further application data after exhaustion; control/alert bytes are excluded.
   * Local sending-key updates reset the budget; receiving-key updates do not.
   * Either byte or record limit triggers rotation; peer responses remain
   * mandatory. No timer, background work or application-message boundaries. */
  uint64_t key_update_byte_limit;
  /** SHANGMI_TLS13 local sending-key interval, copied at init. Zero disables;
   * nonzero uint32 milliseconds uses a monotonic clock starting at handshake
   * completion. Before each new application record, an expired interval sends
   * KeyUpdate first. Pending ciphertext finishes unchanged. Successful local
   * sending-key changes reset age; receiving-key changes do not. Any enabled
   * time/record/byte limit can trigger one update; mandatory responses remain.
   * Nonzero STANDARD/TLCP: SALTS_ENOTSUP, before trust I/O or policy retention.
   * Clock failure/regression is fatal. No idle traffic/background timer;
   * clock resolution and suspend accounting follow the OS monotonic clock. */
  uint32_t key_update_interval_ms;
  /** SHANGMI_TLS13 consecutive authenticated peer KeyUpdate limit; zero is
   * unlimited. Both request kinds count across polls. Only nonempty authenticated
   * application data resets the count. Exceeding it fails with SALTS_EPROTO.
   * Burst bound only, not a time/byte rate. Nonzero STANDARD/TLCP: SALTS_ENOTSUP. */
  uint32_t peer_key_update_limit;
  /** SHANGMI_TLS13 minimum spacing between admitted peer KeyUpdates, copied
   * at init. Each zero disables its minimum; every nonzero uint32 is accepted.
   * The first valid peer update is free. Later updates must satisfy BOTH enabled
   * minima: monotonic elapsed milliseconds, and newly authenticated received
   * application bytes since the last admitted update. Bytes are credited once
   * per decrypted record and cap at the minimum; surplus cannot be banked.
   * Empty/control/padding/outgoing bytes earn no credit. Both request kinds,
   * including replies, count. Local key changes never reset peer spacing.
   * Violation: fatal SALTS_EPROTO before peer key derivation; clock failure/regression
   * is fatal. Nonzero STANDARD/TLCP: SALTS_ENOTSUP before trust I/O or policy retain.
   * Independent of peer_key_update_limit. Can reject valid crossed/requested
   * bursts; configure compatible local rotation. No idle timer or worker. */
  uint32_t peer_key_update_min_interval_ms;
  uint32_t peer_key_update_min_bytes;
  /** Explicit memory anchors, excluding ca_file/ca_path. See tls_credentials.h. */
  const cnet_tls_data *ca_data;
  /** Memory identity, excluding cert_file/key_file/key_password. */
  const cnet_tls_credentials *credentials;
  /** STANDARD defaults to TLS1.2..1.3; SHANGMI permits only TLS1.3;
   * TLCP requires DEFAULT. Immutable for all connections using the context.
   * Unknown/reversed bounds: EINVAL; profile conflict: ENOTSUP. */
  cnet_tls_protocol_version minimum_version;
  cnet_tls_protocol_version maximum_version;
  /** Maximum peer-supplied issuer certificates after the leaf (after both
   * TLCP leaves). Transmitted anchors count; local anchors do not. Zero uses
   * default 4; explicit 1..5 is immutable. Above 5: EINVAL. Nonzero with iOS
   * implicit system trust: ENOTSUP. Does not bypass other verification. */
  uint32_t verification_depth;
  /** Optional copied certificate-validity Unix time; NULL uses system time.
   * Same range, lifetime and applicability as Crypto verification_time.
   * Peer-policy/revocation clocks and other authentication checks are unchanged. */
  const int64_t *verification_time;
  /** Copied immutable cipher allowlist; same admission/profile/version contract
   * as crypto_tls_stream_client_config.cipher_suites. NULL/0 keeps defaults. */
  const cnet_tls_cipher_suite *cipher_suites;
  size_t cipher_suite_count;
  /** Immutable copied key-exchange group allowlist, 1..GROUP_MAX_COUNT unique
   * entries. NULL/0 keeps the profile default. STANDARD currently implements
   * P256; SHANGMI_TLS13 implements SM2. Unsupported groups return ENOTSUP before
   * trust I/O. TLCP's static-key profile rejects explicit group lists. */
  const cnet_tls_group *supported_groups;
  size_t supported_group_count;
  /** Same copied signature-list contract as Crypto TLS stream configuration. */
  const cnet_tls_signature_scheme *signature_algorithms;
  size_t signature_algorithm_count;
  /** Independent TLS/TLCP certificate-chain signature allowlist, copied at init.
   * NULL/0 uses signature_algorithms. Explicit lists contain 1..4 unique
   * RSA-PKCS1-SHA256 or ECDSA P256/SHA256, P384/SHA384 (STANDARD), or SM2/SM3
   * (SHANGMI). RSA-PSS certificate signatures are unsupported. STANDARD permits
   * TLS1.2/1.3 and ranges. TLCP clients admit SM2/SM3 or RSA-PKCS1-SHA256
   * certificate issuers while retaining SM2 handshake signatures; the policy is
   * local admission, without adding TLS extension 50 to TLCP. TLCP server lists
   * return ENOTSUP while client authentication is unsupported. TLS1.2 client
   * identity selection also obeys the peer CertificateRequest's shared list.
   * Controls certificate extension offers, selection and peer-chain verification.
   * Handshake signatures remain controlled by signature_algorithms. */
  const cnet_tls_signature_scheme *certificate_signature_algorithms;
  size_t certificate_signature_algorithm_count;
  /** Ordered immutable client identities; see crypto_tls_stream_client_config.
   * Borrowed only during cnet_connect; copied before handshake progress.
   * Excludes top-level identity fields. NULL/0 keeps single-identity behavior.
   * First CertificateRequest-compatible identity wins; no match sends an empty
   * Certificate. TLCP client identities are unsupported. */
  const cnet_tls_client_identity *identities;
  size_t identity_count;
  /** Reusable-client owned cache: 0 disables, 1..16 bounded TLS1.3 entries.
   * Requires exact STANDARD TLS1.3 bounds or SHANGMI_TLS13. Other profiles/
   * ranges and implicit iOS system trust return ENOTSUP before trust I/O;
   * >16 returns EINVAL. Only connections sharing this TLS client share tickets.
   * Entries bind exact name/cipher/ALPN and original peer chain; selected entries
   * are consumed once, including failed connects. Resumed chains and peer policy
   * are rechecked before OPEN. No 0RTT, persistence or server ticket issuance.
   * See crypto_tls_stream_client_config for full cache ownership semantics. */
  uint32_t session_cache_capacity;
} cnet_tls_client_config;

/** Configuration copied into a reusable server context during initialization. */
typedef struct cnet_tls_server_config {
  size_t size;
  /** PEM server certificate chain and private key; required unless credentials is set.
   * For TLCP11, cert_file contains the signing certificate first, encryption
   * certificate second, then issuer certificates. key_file contains the
   * matching signing key first and encryption key second. Both keys use
   * key_password. CNet validates the two KeyUsage roles and the provider
   * independently verifies each certificate/private-key match.
   */
  const char *cert_file;
  const char *key_file;
  const char *key_password;
  /** Required only when `client_auth` is REQUIRED. */
  const char *ca_file;
  const char *ca_path;
  /** TLCP11 currently accepts NONE only; REQUIRED returns `SALTS_ENOTSUP`. */
  cnet_tls_client_auth client_auth;
  /** Optional server-preference ALPN list. */
  const char *const *alpn_protocols;
  size_t alpn_protocol_count;
  /** Explicit security profile; zero retains verified STANDARD TLS. */
  cnet_tls_security_profile security_profile;
  /** Optional extra admission; requires REQUIRED client authentication. */
  const cnet_tls_peer_policy *peer_policy;
  /** Same local sending-key rotation contract as the client configuration. */
  uint32_t key_update_record_limit;
  /** Same local plaintext-byte budget as the client configuration. */
  uint64_t key_update_byte_limit;
  /** Same immutable sending-key interval contract as the client configuration. */
  uint32_t key_update_interval_ms;
  /** Same consecutive peer-update contract as the client configuration. */
  uint32_t peer_key_update_limit;
  /** Same immutable peer-spacing contract as the client configuration. */
  uint32_t peer_key_update_min_interval_ms;
  uint32_t peer_key_update_min_bytes;
  /** Same memory-input contract as the client; CA required for REQUIRED auth. */
  const cnet_tls_data *ca_data;
  const cnet_tls_credentials *credentials;
  /** STANDARD defaults to TLS1.2..1.3; SHANGMI permits only TLS1.3;
   * TLCP requires DEFAULT. Immutable for all connections using the context.
   * Unknown/reversed bounds: EINVAL; profile conflict: ENOTSUP. */
  cnet_tls_protocol_version minimum_version;
  cnet_tls_protocol_version maximum_version;
  /** Same depth contract as client; nonzero requires REQUIRED client auth. */
  uint32_t verification_depth;
  /** Same certificate-time contract as client; requires REQUIRED client auth. */
  const int64_t *verification_time;
  /** Copied immutable cipher allowlist; same admission/profile/version contract
   * as crypto_tls_stream_client_config.cipher_suites. NULL/0 keeps defaults. */
  const cnet_tls_cipher_suite *cipher_suites;
  size_t cipher_suite_count;
  /** Immutable copied key-exchange group allowlist, 1..GROUP_MAX_COUNT unique
   * entries. NULL/0 keeps the profile default. STANDARD currently implements
   * P256; SHANGMI_TLS13 implements SM2. Unsupported groups return ENOTSUP before
   * trust I/O. TLCP's static-key profile rejects explicit group lists. */
  const cnet_tls_group *supported_groups;
  size_t supported_group_count;
  /** Same copied signature-list contract as Crypto TLS stream configuration. */
  const cnet_tls_signature_scheme *signature_algorithms;
  size_t signature_algorithm_count;
  /** Independent TLS/TLCP certificate-chain signature allowlist, copied at init.
   * NULL/0 uses signature_algorithms. Explicit lists contain 1..4 unique
   * RSA-PKCS1-SHA256 or ECDSA P256/SHA256, P384/SHA384 (STANDARD), or SM2/SM3
   * (SHANGMI). RSA-PSS certificate signatures are unsupported. STANDARD permits
   * TLS1.2/1.3 and ranges. TLCP clients admit SM2/SM3 or RSA-PKCS1-SHA256
   * certificate issuers while retaining SM2 handshake signatures; the policy is
   * local admission, without adding TLS extension 50 to TLCP. TLCP server lists
   * return ENOTSUP while client authentication is unsupported. TLS1.2 client
   * identity selection also obeys the peer CertificateRequest's shared list.
   * Controls certificate extension offers, selection and peer-chain verification.
   * Handshake signatures remain controlled by signature_algorithms. */
  const cnet_tls_signature_scheme *certificate_signature_algorithms;
  size_t certificate_signature_algorithm_count;
  /** Same immutable SNI identity-set contract as Crypto server configuration.
   * Replaces the single identity fields; consumed during server init. */
  const cnet_tls_server_identity *identities;
  size_t identity_count;
  /** Same context-owned TLS1.3 stateful server ticket contract as Crypto:
   * both zero disables, otherwise capacity 1..16 and lifetime 1..604800 seconds.
   * Requires exact STANDARD TLS1.3 or SHANGMI_TLS13. Reuse one tls_server to
   * share tickets across accepted connections; no 0RTT or persistence. */
  uint32_t session_ticket_capacity;
  uint32_t session_ticket_lifetime_seconds;
} cnet_tls_server_config;

typedef struct cnet_connect_options {
  const char *uri;
  cnet_observer observer;
  /** Optional TLS policy; valid only with `tls://`. NULL selects verified defaults. */
  const cnet_tls_client_config *tls;
  /** Optional reusable TLS policy; mutually exclusive with `tls`. */
  const cnet_tls_client *tls_client;
} cnet_connect_options;

/** Client policy consumed synchronously when upgrading one connected plaintext TCP stream. */
typedef struct cnet_start_tls_options {
  size_t size;
  /** Required verified identity unless supplied by `tls` or `tls_client`. */
  const char *server_name;
  /** Optional one-shot policy; mutually exclusive with `tls_client`. */
  const cnet_tls_client_config *tls;
  /** Optional reusable policy; mutually exclusive with `tls`. */
  const cnet_tls_client *tls_client;
} cnet_start_tls_options;

#define CNET_START_TLS_OPTIONS_INIT {sizeof(cnet_start_tls_options), NULL, NULL, NULL}

/**
 * Optional OS policy for future TCP-backed connections owned by one client.
 * Zero buffer sizes preserve platform defaults. Millisecond durations are
 * rounded up when a platform exposes only whole-second socket options.
 * Windows linger durations cannot exceed 65,535,000 ms; larger values
 * return `SALTS_ERANGE` before any socket option is applied.
 * Keepalive detail requires `keepalive == 1`; `linger_ms == 0` with
 * `linger == 1` requests abortive close. `nodelay == 1` requests
 * `TCP_NODELAY` for latency-sensitive TCP/TLS streams; zero preserves the
 * platform's default Nagle policy.
 */
typedef struct cnet_stream_socket_options {
  size_t size;
  size_t receive_buffer_bytes;
  size_t send_buffer_bytes;
  uint32_t keepalive_idle_ms;
  uint32_t keepalive_interval_ms;
  uint32_t keepalive_count;
  uint32_t linger_ms;
  int keepalive;
  int linger;
  int nodelay;
} cnet_stream_socket_options;

#define CNET_STREAM_SOCKET_OPTIONS_INIT                                                            \
  {sizeof(cnet_stream_socket_options), 0u, 0u, 0u, 0u, 0u, 0u, 0, 0, 0}

/**
 * Live portable TCP socket properties. Values use the units named by each
 * option and are read back from the platform after any clamp/rounding.
 */
typedef enum cnet_tcp_socket_option {
  CNET_TCP_SOCKET_KEEPALIVE_ENABLED = 1,
  CNET_TCP_SOCKET_KEEPALIVE_IDLE_MS,
  CNET_TCP_SOCKET_KEEPALIVE_INTERVAL_MS,
  CNET_TCP_SOCKET_KEEPALIVE_COUNT,
  CNET_TCP_SOCKET_HOP_LIMIT,
  CNET_TCP_SOCKET_RECEIVE_BUFFER_BYTES,
  CNET_TCP_SOCKET_SEND_BUFFER_BYTES,
  CNET_TCP_SOCKET_NODELAY
} cnet_tcp_socket_option;

/** Optional listener policy consumed synchronously by `cnet_listener_init_ex()`. */
typedef struct cnet_listener_options {
  size_t size;
  /** Request SO_REUSEPORT. Unsupported platforms return `SALTS_ENOTSUP`. */
  int reuse_port;
} cnet_listener_options;

#define CNET_LISTENER_OPTIONS_INIT {sizeof(cnet_listener_options), 0}

/**
 * All capacities are hard bounds and must be positive. Command and event
 * capacities must be powers of two. Completion batch capacity cannot exceed
 * request capacity. Zero connect/read/write timeouts disable that deadline.
 */
typedef struct cnet_client_config {
  native_io_backend_kind backend;
  size_t connection_capacity;
  size_t command_capacity;
  size_t request_capacity;
  size_t completion_batch_capacity;
  size_t event_capacity;
  size_t max_send_bytes;
  size_t receive_buffer_bytes;
  uint32_t connect_timeout_ms;
  uint32_t read_timeout_ms;
  uint32_t write_timeout_ms;
  /** Zero disables TLS admission. Otherwise this is each TLS BIO/I/O hard bound. */
  size_t tls_io_buffer_bytes;
  /** Required with non-zero TLS storage; bounds only the TLS handshake. */
  uint32_t tls_handshake_timeout_ms;
  /**
   * Aggregate bytes available to copied pending commands. Zero preserves the
   * full command_capacity times maximum-command bound. A non-zero value must
   * cover at least one maximum-sized command and can reduce retained memory.
   */
  size_t command_buffer_bytes;
  /**
   * Aggregate bytes available to copied pending events. Zero preserves the
   * full event_capacity times maximum-event bound without preallocating it. A
   * non-zero value must cover at least one maximum-sized event.
   */
  size_t event_buffer_bytes;
  cnet_resources resources;
  cnet_send_limits send_limits;
  cnet_send_admission_policy send_admission;
} cnet_client_config;

/**
 * Listener configuration copied by `cnet_listener_init()`. `host` must be a
 * numeric IPv4 or IPv6 address. Port zero requests an ephemeral port. Backlog
 * is a positive hard bound accepted by the platform listener.
 */
typedef struct cnet_listener_config {
  native_io_backend_kind backend;
  const char *host;
  uint16_t port;
  size_t backlog;
} cnet_listener_config;

/**
 * Versioned Linux AF_VSOCK listener configuration copied during initialization.
 * ANY CID/port values request the platform-selected local endpoint.
 */
typedef struct cnet_vsock_listener_config {
  size_t size;
  native_io_backend_kind backend;
  uint32_t cid;
  uint32_t port;
  size_t backlog;
} cnet_vsock_listener_config;

#define CNET_VSOCK_LISTENER_CONFIG_INIT                                                           \
  {sizeof(cnet_vsock_listener_config), (native_io_backend_kind)0, CNET_VSOCK_CID_ANY,              \
   CNET_VSOCK_PORT_ANY, 0u}

enum { CNET_DATAGRAM_MAX_PAYLOAD_BYTES = 65507u };

/**
 * Every capacity is a hard bound. One request is reserved for receive, so
 * request_capacity must be greater than send_capacity. The receive buffer must
 * cover max_datagram_bytes; truncation is never reported as a successful value.
 */
typedef struct cnet_datagram_config {
  size_t size;
  native_io_backend_kind backend;
  const char *host;
  uint16_t port;
  size_t send_capacity;
  size_t request_capacity;
  size_t completion_batch_capacity;
  size_t max_datagram_bytes;
  size_t receive_buffer_bytes;
  cnet_datagram_observer observer;
  /** Request SO_REUSEPORT before bind. Unsupported platforms return `SALTS_ENOTSUP`. */
  int reuse_port;
} cnet_datagram_config;

#define CNET_DATAGRAM_CONFIG_INIT                                                                  \
  {sizeof(cnet_datagram_config),                                                                   \
   (native_io_backend_kind)0,                                                                      \
   NULL,                                                                                           \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   {NULL, NULL, NULL},                                                                             \
   0}

enum {
  CNET_KCP_DEFAULT_MTU = 1400,
  CNET_KCP_DEFAULT_WINDOW = 128,
  CNET_KCP_DEFAULT_INTERVAL_MS = 10,
  CNET_KCP_DEFAULT_FAST_RESEND = 2,
  CNET_KCP_DEFAULT_SEND_SEGMENT_CAPACITY = 1024,
  CNET_KCP_DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024
};

/**
 * KCP is a reliable ordered protocol over untrusted datagrams; it provides no
 * encryption or peer authentication. All protocol calls belong to one owner.
 * send_segment_capacity bounds retained outbound KCP segments, receive_window
 * bounds inbound segments, and max_message_bytes bounds callback storage.
 */
typedef struct cnet_kcp_config {
  size_t size;
  uint32_t conversation;
  uint32_t mtu;
  uint32_t send_window;
  uint32_t receive_window;
  uint32_t interval_ms;
  uint32_t fast_resend;
  bool no_congestion_window;
  bool stream_mode;
  size_t send_segment_capacity;
  size_t max_message_bytes;
  cnet_kcp_observer observer;
} cnet_kcp_config;

#define CNET_KCP_CONFIG_INIT                                                                       \
  {                                                                                                \
    sizeof(cnet_kcp_config), 0u, CNET_KCP_DEFAULT_MTU, CNET_KCP_DEFAULT_WINDOW,                    \
        CNET_KCP_DEFAULT_WINDOW, CNET_KCP_DEFAULT_INTERVAL_MS, CNET_KCP_DEFAULT_FAST_RESEND,       \
        false, false, CNET_KCP_DEFAULT_SEND_SEGMENT_CAPACITY, CNET_KCP_DEFAULT_MAX_MESSAGE_BYTES,  \
    {                                                                                              \
      NULL, NULL, NULL                                                                             \
    }                                                                                              \
  }

enum {
  CNET_KCP_PSK_BYTES = 32,
  CNET_KCP_SECURE_RECORD_OVERHEAD = 48,
  CNET_KCP_DEFAULT_HANDSHAKE_RETRY_MS = 200,
  CNET_KCP_DEFAULT_FEC_DATA_SHARDS = 8,
  CNET_KCP_DEFAULT_FEC_PARITY_SHARDS = 2,
  CNET_KCP_DEFAULT_FEC_MAX_PAYLOAD_BYTES = 1248,
  CNET_KCP_DEFAULT_FEC_RECEIVE_GROUPS = 16
};

typedef struct cnet_kcp_fec_config {
  cnet_kcp_fec_backend backend;
  uint16_t data_shards;
  uint16_t parity_shards;
  /** At most UINT16_MAX - 2; parity also encodes the two-byte data length. */
  uint16_t max_payload_bytes;
  uint16_t receive_group_count;
} cnet_kcp_fec_config;

/**
 * Copied PSK v1 policy. A zero key, NONE FEC, or partial FEC config is rejected.
 * Packet endpoint datagram send/receive capacities must cover fec.max_payload_bytes + 48
 * bytes, including parity length metadata, the wire header, and the MAC.
 */
typedef struct cnet_kcp_security_config {
  size_t size;
  cnet_kcp_security_mode mode;
  uint8_t pre_shared_key[CNET_KCP_PSK_BYTES];
  uint32_t handshake_retry_ms;
  cnet_kcp_fec_config fec;
} cnet_kcp_security_config;

#define CNET_KCP_SECURITY_CONFIG_INIT                                                              \
  {                                                                                                \
    sizeof(cnet_kcp_security_config), CNET_KCP_SECURITY_NONE, {0},                                 \
        CNET_KCP_DEFAULT_HANDSHAKE_RETRY_MS, {                                                     \
      CNET_KCP_FEC_REED_SOLOMON, CNET_KCP_DEFAULT_FEC_DATA_SHARDS,                                 \
          CNET_KCP_DEFAULT_FEC_PARITY_SHARDS, CNET_KCP_DEFAULT_FEC_MAX_PAYLOAD_BYTES,              \
          CNET_KCP_DEFAULT_FEC_RECEIVE_GROUPS                                                      \
    }                                                                                              \
  }

/**
 * Protocol-only secure session. The embedded KCP conversation and observer
 * fields must be zero because the authenticated session derives and owns them.
 */
typedef struct cnet_secure_kcp_config {
  size_t size;
  cnet_secure_kcp_role role;
  cnet_kcp_config kcp;
  cnet_kcp_security_config security;
  cnet_secure_kcp_observer observer;
} cnet_secure_kcp_config;

#define CNET_SECURE_KCP_CONFIG_INIT                                                                \
  {                                                                                                \
    sizeof(cnet_secure_kcp_config), (cnet_secure_kcp_role)0, CNET_KCP_CONFIG_INIT,                 \
        CNET_KCP_SECURITY_CONFIG_INIT, {                                                           \
      NULL, NULL, NULL, NULL                                                                       \
    }                                                                                              \
  }

/**
 * Unified packet endpoint configuration. datagram and kcp observer fields
 * must remain zero because the endpoint owns their internal composition.
 * session_capacity is a hard bound for the pre-reserved peer index and slots.
 */
typedef struct cnet_packet_endpoint_config {
  size_t size;
  cnet_packet_protocol protocol;
  size_t session_capacity;
  cnet_datagram_config datagram;
  cnet_kcp_config kcp;
  cnet_kcp_security_config security;
  cnet_packet_observer observer;
} cnet_packet_endpoint_config;

#define CNET_PACKET_ENDPOINT_CONFIG_INIT                                                           \
  {                                                                                                \
    sizeof(cnet_packet_endpoint_config), (cnet_packet_protocol)0, 0u, CNET_DATAGRAM_CONFIG_INIT,   \
        CNET_KCP_CONFIG_INIT, CNET_KCP_SECURITY_CONFIG_INIT, {                                     \
      NULL, NULL, NULL, NULL, NULL                                                                 \
    }                                                                                              \
  }

/**
 * Initializes one caller-driven NativeIO owner without creating an I/O worker
 * thread. Callbacks execute inline from `cnet_client_poll()` after a coroutine
 * observes its terminal NativeIO completion. All callbacks are ordered and
 * non-concurrent. After initialization, client operations and progress belong
 * to one calling thread; cross-thread admission requires an external mailbox.
 * A callback may issue send/receive/close but must not block.
 *
 * @param client Zero-initialized output owner.
 * @param config Borrowed configuration copied during initialization.
 * @return `SALTS_OK`, `SALTS_EINVAL` for an invalid bound/backend, or a
 * resource/backend initialization error. No partial client is published.
 */
int cnet_client_init(cnet_client *client, const cnet_client_config *config);

/**
 * Initializes the same bounded CNet client while borrowing one caller-owned
 * NativeIO backend. CNet submits/cancels against this backend but never
 * observes, closes, or destroys it. The backend kind and capacities must cover
 * the client configuration. Progress is then owned by the embedding runtime
 * through the external APIs below; cnet_client_poll() is disabled.
 *
 * The borrowed backend must outlive the client and must not be closed while
 * any CNet request or endpoint remains live.
 */
int cnet_client_init_external(cnet_client *client,
                              const cnet_client_config *config,
                              native_io_backend *borrowed_backend);

/** Validates platform bounds and option dependencies without touching a socket. */
int cnet_stream_socket_options_validate(const cnet_stream_socket_options *options);

/**
 * Copies policy for future TCP/TLS connections. Detached TCP streams produced
 * by a CNet listener receive this final-owner policy when consumed through
 * cnet_client_adopt_accepted() or cnet_client_adopt_accepted_tls(). Generic
 * native-socket adoption and direct cnet_listener_accept*() calls preserve
 * the socket's existing live policy, including configured listener options.
 * No active connection may exist while replacing this client-global policy.
 * IPC/Pipe connection admission rejects enabled TCP-only policy with
 * SALTS_ENOTSUP; reset it to defaults before connecting those transports.
 */
int cnet_client_set_stream_socket_options(cnet_client *client,
                                          const cnet_stream_socket_options *options);

/**
 * Copies all options needed after return. On immediate failure `out_connection`
 * remains zero and no callback is delivered. `observer.on_state` is required.
 * Bracketed network hosts must be IPv6 literals; invalid literals return
 * `SALTS_EINVAL`, and unsupported IPvFuture returns `SALTS_ENOTSUP`, before
 * connection admission or DNS lookup.
 *
 * @return `SALTS_OK` for asynchronous admission, a URI/configuration error,
 * `SALTS_ENOBUFS` at the hard connection/command bound, or `SALTS_ESHUTDOWN`
 * after stop begins.
 */
int cnet_connect(cnet_client *client, const cnet_connect_options *options,
                 cnet_connection *out_connection);

/**
 * Connects directly to one numeric portable TCP peer without URI parsing or
 * DNS. `local_peer == NULL` leaves local address selection to the OS; a
 * non-NULL local peer is bound before the asynchronous connect begins.
 *
 * The observer is copied synchronously. Both peer values are copied before
 * return and never retained by pointer. Address families must match.
 */
int cnet_connect_peer(cnet_client *client, const cnet_stream_peer *remote_peer,
                      const cnet_stream_peer *local_peer,
                      const cnet_observer *observer,
                      cnet_connection *out_connection);

/** Lossless IPv6-flow-info counterpart of cnet_connect_peer(). */
int cnet_connect_endpoint(cnet_client *client,
                          const cnet_stream_endpoint *remote_endpoint,
                          const cnet_stream_endpoint *local_endpoint,
                          const cnet_observer *observer,
                          cnet_connection *out_connection);

/**
 * Copies the current local or remote TCP endpoint for one live generation-
 * checked connection. No native descriptor is exposed.
 */
int cnet_connection_local_peer(cnet_client *client, cnet_connection connection,
                               cnet_stream_peer *out_peer);
int cnet_connection_remote_peer(cnet_client *client, cnet_connection connection,
                                cnet_stream_peer *out_peer);

int cnet_connection_local_endpoint(cnet_client *client,
                                   cnet_connection connection,
                                   cnet_stream_endpoint *out_endpoint);
int cnet_connection_remote_endpoint(cnet_client *client,
                                    cnet_connection connection,
                                    cnet_stream_endpoint *out_endpoint);

typedef enum cnet_tcp_shutdown {
  CNET_TCP_SHUTDOWN_RECEIVE = 1,
  CNET_TCP_SHUTDOWN_SEND = 2,
  CNET_TCP_SHUTDOWN_BOTH = 3
} cnet_tcp_shutdown;

/**
 * Performs a generation-safe TCP half-shutdown. Repeating a direction that is
 * already shut down is idempotent. This does not drop the connection handle.
 * Receive shutdown cancels/discards already-admitted receive work. Send
 * shutdown rejects new writes immediately and defers the native FIN until
 * already-admitted writes have drained.
 */
int cnet_connection_shutdown(cnet_client *client,
                             cnet_connection connection,
                             cnet_tcp_shutdown how);

/**
 * Opts one connected plaintext TCP owner into directional peer EOF handling.
 * Install on the owner thread before receive demand, outside callbacks. EOF
 * emits exactly one empty CNET_MESSAGE_BYTES receive callback, closes receive
 * admission and keeps send admission open. Normal terminal state is still
 * delivered only after close/failure. Existing connections retain close-on-EOF
 * behavior unless explicitly opted in. This does not alter observer/config ABI.
 * Returns SALTS_EINVAL, SALTS_ENOENT, SALTS_ENOTSUP, SALTS_EBUSY or SALTS_OK.
 */
int cnet_connection_preserve_send_on_eof(cnet_client *client, cnet_connection connection);

/**
 * Reads or mutates one live TCP property through the generation-checked CNet
 * owner. These calls obey the same single-owner thread rule as client progress.
 * No native descriptor is exposed. Unsupported host properties return
 * SALTS_ENOTSUP.
 */
int cnet_connection_tcp_option_get(cnet_client *client, cnet_connection connection,
                                   cnet_tcp_socket_option option, uint64_t *out_value);
int cnet_connection_tcp_option_set(cnet_client *client, cnet_connection connection,
                                   cnet_tcp_socket_option option, uint64_t value);

/**
 * Transfers one connected Linux AF_VSOCK SOCK_STREAM socket to `client`.
 * The socket is consumed on every call except when it equals `UINTPTR_MAX`.
 * Unsupported platforms/backends close the socket and return `SALTS_ENOTSUP`
 * without publishing a connection or callback.
 * @param client Initialized client that will own the admitted connection.
 * @param native_socket Connected native socket, transferred on entry unless it is `UINTPTR_MAX`.
 * @param observer Required observer copied into the connection record.
 * @param out_connection Cleared before validation and populated only after successful admission.
 * @return `SALTS_OK`, `SALTS_EINVAL`, `SALTS_ENOTSUP`, or a bounded admission error.
 */
int cnet_client_adopt_vsock(cnet_client *client, uintptr_t native_socket,
                            const cnet_observer *observer, cnet_connection *out_connection);

/**
 * Upgrades one quiescent connected plaintext TCP stream in place. The handle
 * remains stable. Success admits a bounded command; callbacks then report
 * `CNET_CONNECTION_TLS_HANDSHAKING` followed by CONNECTED or FAILED. A close
 * admitted during the handshake instead reports CLOSING followed by CLOSED.
 *
 * No send, receive, close, or other upgrade may be pending. TLS failure is
 * terminal and never falls back to plaintext.
 *
 * @param client Initialized single-owner client.
 * @param connection Live plaintext TCP handle, preserved across the upgrade.
 * @param options Borrowed policy consumed before this call returns.
 * @return `SALTS_OK` for asynchronous admission; `SALTS_EINVAL` for malformed
 * policy; `SALTS_ENOTSUP` when TLS storage is disabled or the stream is not
 * plaintext TCP; `SALTS_EBUSY` unless the stream is connected and quiescent;
 * `SALTS_ENOENT` for a stale handle; or a bounded queue error.
 */
int cnet_start_tls(cnet_client *client, cnet_connection connection,
                   const cnet_start_tls_options *options);

/**
 * Server-side counterpart to `cnet_start_tls()` using one reusable context.
 * The server wrapper is borrowed during admission; the accepted command keeps
 * its own reference.
 *
 * @param client Initialized single-owner client.
 * @param connection Live plaintext TCP handle, preserved across the upgrade.
 * @param server Initialized immutable server TLS context.
 * @return The same connection-state, capacity, and shutdown results as
 * `cnet_start_tls()`, plus `SALTS_EINVAL` for an invalid server context.
 */
int cnet_start_tls_server(cnet_client *client, cnet_connection connection,
                          const cnet_tls_server *server);

/**
 * Retains one non-empty immutable buffer on successful admission and sends the
 * first mem_buffer_used(buffer) bytes without copying them into CNet write
 * storage. Multiple non-TLS retained writes share the same bounded FIFO. The
 * caller may release its reference immediately after SALTS_OK,
 * but must not mutate data/used/capacity while the logical send is in flight.
 * Rejection retains no lasting reference.
 */
/* Logical send identity, unique across client lifetimes; not an ownership ref. */
typedef struct cnet_operation { uint64_t id; } cnet_operation;
typedef struct cnet_send_result {
  cnet_operation operation;
  cnet_connection connection;
  size_t requested_bytes;
  /* OK means the logical write completed locally. Failure does not prove that
   * no prefix reached the peer, nor authorize application replay. */
  int status;
} cnet_send_result;
typedef void (*cnet_send_complete_fn)(void *user, const cnet_send_result *result);
typedef struct cnet_send_options {
  const mem_slice_t *segments;
  size_t segment_count;
  bool close_after_send;
  cnet_send_complete_fn complete;
  void *user;
} cnet_send_options;
/* One bounded FIFO operation. Rejection zeroes output and retains nothing.
 * Acceptance produces exactly one completion on the progress owner, after the
 * logical write settles, before the connection terminal observer on failure.
 * The callback/user are borrowed until completion. No inline completion during
 * admission. A callback may send/close, but cannot poll/stop/destroy recursively.
 * A successful completion precedes the existing observer.on_send notification;
 * that notification remains enabled and is not another operation completion.
 * Convenience send_buffer/slice/slicev use this same admission and accounting. */
int cnet_send(cnet_client *client, cnet_connection connection,
              const cnet_send_options *options, cnet_operation *out_operation,
              cnet_admission_limit *out_limit);
/* Owner-only accounting. Zero connection returns aggregate usage. */
int cnet_client_send_usage(cnet_client *client, cnet_connection connection,
                            cnet_send_usage *out);
/* Owner-only, outside callbacks/progress. Copied policy applies to subsequent
 * sends; accepted operations retain their original completion obligations.
 * Old policy user can be released after replacement returns. Hard limits and
 * resource providers are immutable for this client lifetime. Replacing this
 * client gate leaves all connection-specific gates in place. */
int cnet_client_set_send_admission(cnet_client *client,
                                   const cnet_send_admission_policy *policy);
/* Extra gate for one live connection generation, initially empty. Hard limits,
 * then the client gate, then this gate must all accept each send. A zero binding
 * clears only this gate. Owner-only, outside callbacks/progress; may be set
 * after connect/adopt and before CONNECTED. Does not grant transport readiness.
 * Policy is copied; user is borrowed until successful replacement or terminal
 * notification. Existing operations keep their retained storage and completion.
 * Stale/unknown handle: ENOENT; sealed connection: ESHUTDOWN; invalid binding:
 * EINVAL; wrong owner: EPERM; callbacks/progress: EBUSY. No change on failure. */
int cnet_set_send_admission(cnet_client *client, cnet_connection connection,
                             const cnet_send_admission_policy *policy);
int cnet_send_buffer(cnet_client *client, cnet_connection connection, mem_buffer_t *buffer);

/**
 * Retains exactly one backing-buffer reference for a canonical non-empty slice
 * on successful admission and sends only that subrange without copying payload
 * bytes into CNet write storage. The mem_slice_t descriptor itself is borrowed
 * only for this call; the caller may immediately mem_slice_release(slice) after
 * SALTS_OK. The admitted backing bytes and buffer data/used/capacity must remain
 * immutable until the logical send terminal. Invalid, forged, stale or
 * out-of-range slices return SALTS_EINVAL without retaining.
 */
int cnet_send_slice(cnet_client *client, cnet_connection connection, const mem_slice_t *slice);

/**
 * Retains 1..CNET_RETAINED_VECTOR_MAX canonical slice ranges on successful
 * admission without copying plaintext payload bytes into CNet storage.
 * Distinct backing buffers are retained once per logical write. The slice
 * descriptor array is borrowed only for this call; after SALTS_OK the caller
 * may immediately release every slice and other caller references, but admitted
 * backing bytes and buffer data/used/capacity must remain immutable until
 * terminal send settlement.
 *
 * Plain stream transports preserve the ranges into bounded NativeIO
 * scatter/gather. One native submission contains at most NATIVE_IO_VECTOR_MAX
 * spans; larger admitted vectors continue across multiple bounded native
 * submissions under the same CNet logical write.
 *
 * TLS preserves the same retained-vector ownership but cannot pass plaintext
 * scatter/gather directly to the socket because the TLS engine must transform
 * it first. CNet feeds the retained plaintext ranges to the TLS engine in order,
 * advances only accepted ranges, sends generated ciphertext through NativeIO,
 * and still publishes exactly one ordinary send terminal for the logical write.
 * No plaintext flatten fallback is introduced. TLS record/callback boundaries
 * are not part of the slicev API contract, and excessive small-range
 * fragmentation can increase TLS write/record overhead.
 *
 * Unsupported datagram/vector transports return SALTS_ENOTSUP without
 * retaining or silently copying. Invalid, empty, forged, out-of-range, or
 * over-limit vectors are rejected without lasting ownership.
 */
int cnet_send_slicev(cnet_client *client, cnet_connection connection,
                     const mem_slice_t *segments, size_t segment_count);

/**
 * Retained vectored final send.
 *
 * Admission matches cnet_send_slicev(), but the accepted vector is the final
 * logical write for the connection. CNet retains the canonical backing buffers,
 * preserves plain-stream scatter/gather or TLS span-wise plaintext ownership,
 * publishes one ordinary send terminal, and closes only after the final bytes
 * settle. No plaintext flattening or copied-byte storage is introduced.
 * Unsupported transports return SALTS_ENOTSUP without retaining or silently
 * copying.
 */
int cnet_send_slicev_and_close(cnet_client *client, cnet_connection connection,
                               const mem_slice_t *segments, size_t segment_count);

/**
 * Retains one non-empty immutable buffer as the final logical write without
 * copying payload bytes into CNet storage. Ordering and close semantics are
 * identical to retained final-send semantics: previously admitted writes drain first,
 * further public send/receive admission closes immediately after success, and
 * the transport/TLS close starts only after this retained logical write reaches
 * terminal success. The caller may release its reference immediately after
 * SALTS_OK but must not mutate data/used/capacity while CNet owns its retain.
 * Rejection retains no lasting reference.
 */
int cnet_send_buffer_and_close(cnet_client *client, cnet_connection connection,
                               mem_buffer_t *buffer);

/**
 * Installs or clears the explicit owned-receive handler for one live
 * connection. Passing NULL clears it and restores ordinary borrowed
 * `observer.on_receive` delivery. While installed, owned delivery takes
 * precedence and borrowed `on_receive` is not invoked for receive values.
 *
 * The handler may be changed only when no receive demand is outstanding;
 * otherwise SALTS_EBUSY is returned so already-admitted demand cannot switch
 * lifetime contracts in flight.
 */
int cnet_set_receive_slice_handler(cnet_client *client,
                                   cnet_connection connection,
                                   cnet_receive_slice_fn handler,
                                   void *user);

/**
 * Requests exactly `demand` future receive values. Either borrowed
 * `observer.on_receive` or an installed owned receive-slice handler is
 * required. Receive demand accounting is identical for both surfaces.
 * @return The same handle/state/queue errors as `cnet_send`; zero demand is
 * `SALTS_EINVAL`.
 */
int cnet_receive(cnet_client *client, cnet_connection connection, size_t demand);

/**
 * Asynchronously begins an idempotence-checked close transition.
 * An established TLS connection waits for the peer's authenticated
 * close_notify after flushing its own. When application read deadlines are
 * disabled, a 500 ms shutdown deadline bounds this wait. Expiry reports
 * `CNET_CONNECTION_FAILED` with `SALTS_ETIMEDOUT` at the shutdown stage.
 * @return `SALTS_OK`, `SALTS_EALREADY`, `SALTS_ENOENT`, `SALTS_ESHUTDOWN`, or
 * a bounded queue error.
 */
int cnet_close(cnet_client *client, cnet_connection connection);

/**
 * Advances bounded CNet and NativeIO work on the calling thread.
 *
 * This client has one progress owner. Calls must not overlap and poll cannot
 * be entered recursively from a callback. State and receive callbacks execute
 * inline before this function returns. The call continues through internal
 * command and completion progress until it delivers at least one callback or
 * reaches the timeout. `timeout_ms == 0` performs one non-blocking progress
 * pass. An idle timeout is successful and reports zero events.
 *
 * @param client Initialized client owned by the calling progress thread.
 * @param timeout_ms Maximum time to wait for progress.
 * @param out_events Receives the number of callbacks delivered by this call.
 * @return `SALTS_OK`, `SALTS_EINVAL`, `SALTS_EBUSY` for concurrent or
 * recursive polling, `SALTS_ESHUTDOWN` after stop begins, or the first owner
 * progress error.
 */
int cnet_client_poll(cnet_client *client, uint32_t timeout_ms, size_t *out_events);

#define CNET_PROGRESS_STRATEGY_VERSION 1u
#define CNET_PROGRESS_DEFAULT_PASSES 32u
#define CNET_PROGRESS_DEFAULT_IDLE_WAIT_MS 10u
#define CNET_PROGRESS_MAX_PASSES 1024u

/** Caller-owned value configuration; no threads, buffers or retained pointers. */
typedef struct cnet_progress_strategy {
  size_t size;
  size_t max_poll_passes;
  uint32_t idle_wait_ms;
} cnet_progress_strategy;

#define CNET_PROGRESS_STRATEGY_INIT \
  { sizeof(cnet_progress_strategy), CNET_PROGRESS_DEFAULT_PASSES, \
    CNET_PROGRESS_DEFAULT_IDLE_WAIT_MS }

/** Explicit CPU-for-latency tradeoff: bounded draining with no idle blocking. */
#define CNET_PROGRESS_STRATEGY_SPIN_INIT \
  { sizeof(cnet_progress_strategy), CNET_PROGRESS_DEFAULT_PASSES, 0u }

/**
 * Drives an ordinary client using bounded draining followed by an idle wait.
 *
 * Performs up to max_poll_passes nonblocking progress passes, stopping at the
 * first pass without callbacks. If no callback was delivered by the entire
 * call, it may then request a wait for a callback or external wake for at most
 * min(timeout_ms, idle_wait_ms), less time already spent in this call. Once
 * callbacks have been delivered it never enters an idle wait. A callback that
 * issues cnet_client_wake() ends draining and preserves that wake for the next
 * call. One pass can deliver multiple callbacks; this is not a message budget.
 *
 * NULL strategy selects CNET_PROGRESS_STRATEGY_INIT. A non-NULL strategy must
 * have size == sizeof(cnet_progress_strategy) and max_poll_passes in [1, 1024].
 * idle_wait_ms == 0 or timeout_ms == 0 disables blocking, not bounded draining.
 * Timeout caps the requested wait, not scheduling latency: OS timer granularity
 * and descheduling may delay return beyond it. Timeout and pass limits cannot
 * preempt a callback; callbacks must not block.
 * Zero callbacks does not establish quiescence or release pending I/O storage.
 *
 * Call on the client's fixed owner, outside callbacks. No owner migration,
 * workers, application queues or send aggregation are introduced. External
 * clients must use their host's progress policy instead (SALTS_ENOTSUP).
 * The configuration is copied on entry; no pointer is retained. *out_events
 * reports all callbacks delivered, including before a progress error.
 * Returns the same errors as cnet_client_poll, plus SALTS_EINVAL for an invalid
 * strategy. Existing cnet_client_poll semantics are unchanged.
 *
 * Example: cnet_client_poll_strategy(&client, NULL, remaining_ms, &events).
 * Pass timeout zero while the application has runnable work; otherwise cap
 * the wait by its next timer/cancellation-check deadline. Other threads may
 * use cnet_client_wake(), not this progress function.
 */
int cnet_client_poll_strategy(cnet_client *client,
                              const cnet_progress_strategy *strategy,
                              uint32_t timeout_ms, size_t *out_events);

/**
 * Advances CNet-owned command, session, resolver and deadline state without
 * observing NativeIO. Valid only for a client created by
 * cnet_client_init_external(). Callbacks remain ordered and execute inline.
 */
int cnet_client_advance_external(cnet_client *client, size_t *out_events);

/**
 * Routes one terminal completion already observed by the embedding runtime.
 * A completion not owned by this client returns SALTS_OK with
 * *out_consumed == false and is not modified.
 * The host must route every observed owned completion even after requesting
 * close. NativeIO observation invalidates its request identity before CNet
 * settles the request/backing; stop/destroy remain busy until routing drains it.
 */
int cnet_client_route_external_completion(
    cnet_client *client,
    const native_io_completion *completion,
    bool *out_consumed,
    size_t *out_events);

/**
 * Returns CNet's next timer requirement capped by max_wait_ms. The embedding
 * runtime should arm this deadline alongside its NativeIO wait and call
 * cnet_client_advance_external() when it expires.
 */
int cnet_client_external_timeout(cnet_client *client,
                                 uint32_t max_wait_ms,
                                 uint32_t *out_timeout_ms);

/**
 * Copies the currently active NativeIO request identities for one live
 * connection. The snapshot contains only NativeIO slot/generation identities;
 * endpoint/native-handle state remains private to CNet/NativeIO.
 *
 * The snapshot is transient and must be refreshed after any admission,
 * external advance, routed completion or cancellation. If capacity is too
 * small, SALTS_ENOBUFS reports the required count in out_count without writing
 * a partial snapshot.
 */
int cnet_client_external_requests(cnet_client *client,
                                  cnet_connection connection,
                                  native_io_request *out_requests,
                                  size_t capacity,
                                  size_t *out_count);

/**
 * Typed counterpart of cnet_client_external_requests().
 *
 * operation_kind is the exact NativeIO operation currently associated with
 * request. Endpoint/native-handle state and CNet-private request role/stage
 * remain private. The snapshot has the same transient lifetime and
 * SALTS_ENOBUFS all-or-nothing capacity contract as the untyped API.
 */
typedef struct cnet_external_request_snapshot {
  native_io_request request;
  native_io_operation_kind operation_kind;
} cnet_external_request_snapshot;

int cnet_client_external_request_snapshots(
    cnet_client *client,
    cnet_connection connection,
    cnet_external_request_snapshot *out_requests,
    size_t capacity,
    size_t *out_count);

/**
 * Completes teardown for an external-progress client only after every live
 * connection has reached its terminal callback. It never observes NativeIO.
 * SALTS_EBUSY means the embedding runtime must continue routing/advancing.
 */
int cnet_client_stop_external(cnet_client *client);

/**
 * Wakes a thread blocked in cnet_client_poll without publishing a callback or
 * changing connection state. This is the only progress-control operation that
 * may be called concurrently from a non-owner thread. Concurrent wakes are
 * coalesced. Wake callers must stop before client destroy.
 *
 * @return SALTS_OK, SALTS_EINVAL, SALTS_ESHUTDOWN, or a native wake error.
 */
int cnet_client_wake(cnet_client *client);

/**
 * Closes admission and live connections, then drives terminal callbacks and
 * coroutine completions to quiescence within `timeout_ms`. Retry after
 * `SALTS_ETIMEDOUT`.
 * Calling from this client's callback returns `SALTS_EBUSY`.
 * @return `SALTS_OK` only after quiescence, or the first drain/progress error.
 * A non-timeout progress error may be returned after quiescence was reached;
 * the caller must still attempt `cnet_client_destroy()` to release the client.
 */
/**
 * External-progress clients return SALTS_ENOTSUP here. They must drive
 * completions externally and finish with cnet_client_stop_external().
 */
int cnet_client_stop(cnet_client *client, uint32_t timeout_ms);

/**
 * Requires a completed stop. Calling from this client's callback is rejected.
 * A NULL internal implementation is already destroyed and returns `SALTS_OK`.
 */
int cnet_client_destroy(cnet_client *client);

/**
 * Builds one reusable fail-closed TLS 1.2+ client context. Configuration,
 * credentials, and ALPN are consumed synchronously and are not retained.
 * Peer and hostname verification remain mandatory.
 *
 * @param client Zero-initialized reusable output profile.
 * @param config Explicit trust, client identity, SNI, and ALPN policy.
 * @return `SALTS_OK`, `SALTS_EINVAL`, `SALTS_EALREADY`, `SALTS_ERANGE`,
 * `SALTS_ENOMEM`, or `SALTS_EIO` for trust/certificate/GmSSL setup failure.
 */
int cnet_tls_client_init(cnet_tls_client *client, const cnet_tls_client_config *config);

/**
 * Releases the public context reference. Connections already admitted with
 * this profile retain their own reference. Repeated destroy is successful.
 * This control-plane call must not overlap init or connect using the same
 * wrapper.
 * @return `SALTS_OK`, or `SALTS_EINVAL` for a NULL wrapper.
 */
int cnet_tls_client_destroy(cnet_tls_client *client);

/**
 * Builds one fail-closed TLS 1.2+ server context. Certificate/key and ALPN
 * input are copied or retained by CNet for the provider context lifetime before return. No partial context is
 * published on failure.
 *
 * @param server Zero-initialized reusable output context.
 * @param config Synchronously consumed certificate, trust, client-auth, and ALPN policy.
 * @return `SALTS_OK`, `SALTS_EINVAL`, `SALTS_EALREADY`, `SALTS_ERANGE`,
 * `SALTS_ENOMEM`, or `SALTS_EIO` for certificate/GmSSL setup failure.
 */
int cnet_tls_server_init(cnet_tls_server *server, const cnet_tls_server_config *config);

/**
 * Releases the public context reference. Existing accepted sessions retain
 * their own reference. This control-plane call must not overlap init or accept
 * using the same `server` wrapper.
 * @return `SALTS_OK` (including an already destroyed wrapper), or `SALTS_EINVAL`.
 */
int cnet_tls_server_destroy(cnet_tls_server *server);

/**
 * Copies the negotiated ALPN protocol into `buffer` after a TLS connection is
 * open. `capacity` includes the trailing NUL and `out_size` excludes it.
 * Returns `SALTS_ENOENT` when no protocol was negotiated and `SALTS_ENOTSUP`
 * for a plaintext connection. Other errors are `SALTS_ENOTCONN`,
 * `SALTS_EMSGSIZE`, and the standard invalid/stale-handle statuses.
 */
int cnet_tls_negotiated_alpn(cnet_client *client, cnet_connection connection, char *buffer,
                             size_t capacity, size_t *out_size);

/**
 * Copies the negotiated TLS protocol name (for example `TLSv1.3`) into
 * `buffer` after a TLS connection is open. `capacity` includes the trailing
 * NUL and `out_size` excludes it. Plaintext returns `SALTS_ENOTSUP`;
 * incomplete TLS handshakes return `SALTS_ENOTCONN`; an undersized buffer
 * returns `SALTS_EMSGSIZE`.
 */
int cnet_tls_negotiated_version(cnet_client *client, cnet_connection connection, char *buffer,
                                size_t capacity, size_t *out_size);

/** Actual accepted session restoration, queried on the progress owner for an
 * OPEN TLS connection. False on errors; plain streams return ENOTSUP, stale
 * generations ENOENT and non-open TLS connections ENOTCONN. Invalid pointers
 * return EINVAL. out_reused borrows caller storage only during this call. */
int cnet_tls_session_reused(cnet_client *client, cnet_connection connection, bool *out_reused);

/**
 * Copies the negotiated TLS cipher-suite name into `buffer` after a TLS
 * connection is open. `capacity` includes the trailing NUL and `out_size`
 * excludes it. Plaintext returns `SALTS_ENOTSUP`; incomplete TLS handshakes
 * return `SALTS_ENOTCONN`; an undersized buffer returns `SALTS_EMSGSIZE`.
 */
int cnet_tls_negotiated_cipher(cnet_client *client, cnet_connection connection, char *buffer,
                               size_t capacity, size_t *out_size);

/**
 * Copies the verified peer leaf certificate SHA-256 digest as 64 lowercase
 * hexadecimal characters plus a trailing NUL. The query is valid only while
 * the TLS connection remains open. A server connection without a presented
 * client certificate returns `SALTS_ENOENT`; plaintext returns `SALTS_ENOTSUP`.
 * Other errors are `SALTS_ENOTCONN` and the standard invalid/stale-handle
 * statuses. Resumed clients inspect the revalidated original peer certificate.
 */
int cnet_tls_peer_certificate_sha256(cnet_client *client, cnet_connection connection,
                                     char buffer[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY]);

/**
 * Copies the RFC 5929 `tls-server-end-point` binding for the server's
 * handshake leaf certificate on this exact TLS connection: the verified
 * peer leaf for a client, the selected local leaf for a server (also in mTLS).
 * MD5/SHA-1 certificate signatures are upgraded to SHA-256; otherwise the certificate signature
 * digest is used. `out_size` receives the required/copied digest width.
 *
 * The query is valid only after TLS verification succeeds and while the
 * generation-checked connection remains open. Plaintext returns
 * `SALTS_ENOTSUP`; incomplete TLS returns `SALTS_ENOTCONN`; a missing server
 * certificate returns `SALTS_ENOENT`; an unsupported certificate signature
 * digest returns `SALTS_ENOTSUP`; an undersized output returns
 * `SALTS_EMSGSIZE` with the required width in `out_size`.
 */
int cnet_tls_server_end_point_binding(cnet_client *client, cnet_connection connection,
                                      uint8_t *output, size_t capacity,
                                      size_t *out_size);

/**
 * Exports exactly CNET_TLS_CHANNEL_BINDING_BYTES using the
 * `EXPORTER-Channel-Binding` label and an explicit empty context. The query is
 * valid only while the TLS connection remains open. Plaintext returns
 * `SALTS_ENOTSUP`; incomplete TLS handshakes return `SALTS_ENOTCONN`.
 */
int cnet_tls_export_channel_binding(cnet_client *client, cnet_connection connection,
                                    uint8_t output[CNET_TLS_CHANNEL_BINDING_BYTES]);

/**
 * Creates a nonblocking TCP listener. The listener has one owner thread;
 * ownership may move from initialization to a worker before the first wait or
 * accept, but calls must not overlap.
 */
int cnet_listener_init(cnet_listener *listener, const cnet_listener_config *config);

/** Validates the versioned listener policy without creating a socket. */
int cnet_listener_options_validate(const cnet_listener_options *options);

/**
 * Creates a real nonblocking but unbound TCP socket owner. This permits
 * per-socket options to be queried/mutated before bind/connect without
 * exposing the native socket identity.
 */
int cnet_listener_open(cnet_listener *listener,
                       native_io_backend_kind backend,
                       cnet_datagram_address_family family);
int cnet_listener_open_ex(cnet_listener *listener,
                          native_io_backend_kind backend,
                          cnet_datagram_address_family family,
                          const cnet_listener_options *options);

/**
 * Binds an already-open unbound TCP owner to one numeric portable peer.
 * Port zero requests an ephemeral port. The owner remains non-listening.
 */
int cnet_listener_bind_open_peer(cnet_listener *listener,
                                 const cnet_stream_peer *local_peer);

int cnet_listener_bind_open_endpoint(
    cnet_listener *listener,
    const cnet_stream_endpoint *local_endpoint);

/**
 * Two-phase TCP listener lifecycle. bind[_ex] owns a nonblocking bound socket
 * but does not call listen(). listen() transitions that bound owner to
 * listening exactly once. This is useful for protocols that expose bind and
 * listen as distinct semantic states.
 */
int cnet_listener_bind(cnet_listener *listener, const cnet_listener_config *config);
int cnet_listener_bind_ex(cnet_listener *listener, const cnet_listener_config *config,
                          const cnet_listener_options *options);

/**
 * Binds directly from one numeric portable peer. Port zero requests an
 * ephemeral port. The peer is copied synchronously; no text parsing or DNS is
 * involved.
 */
int cnet_listener_bind_peer(cnet_listener *listener,
                            native_io_backend_kind backend,
                            const cnet_stream_peer *local_peer);
int cnet_listener_bind_peer_ex(cnet_listener *listener,
                               native_io_backend_kind backend,
                               const cnet_stream_peer *local_peer,
                               const cnet_listener_options *options);

int cnet_listener_bind_endpoint(
    cnet_listener *listener,
    native_io_backend_kind backend,
    const cnet_stream_endpoint *local_endpoint);
int cnet_listener_bind_endpoint_ex(
    cnet_listener *listener,
    native_io_backend_kind backend,
    const cnet_stream_endpoint *local_endpoint,
    const cnet_listener_options *options);

int cnet_listener_listen(cnet_listener *listener, size_t backlog);

/**
 * Updates the desired TCP listen backlog without changing bound/listening
 * ownership. Before listen this only stores the hint; while listening it asks
 * the platform to update the existing queue.
 */
int cnet_listener_set_backlog(cnet_listener *listener, size_t backlog);

/** Live TCP options on one unbound/bound/listening TCP owner. */
int cnet_listener_tcp_option_get(cnet_listener *listener,
                                 cnet_tcp_socket_option option,
                                 uint64_t *out_value);
int cnet_listener_tcp_option_set(cnet_listener *listener,
                                 cnet_tcp_socket_option option,
                                 uint64_t value);

/**
 * Consumes one unbound or bound, not-yet-listening TCP owner and starts an
 * asynchronous client connect on that exact socket. An unbound owner receives
 * an implicit same-family ephemeral bind before ConnectEx/connect admission.
 */
int cnet_listener_connect_peer(cnet_listener *listener, cnet_client *client,
                               const cnet_stream_peer *remote_peer,
                               const cnet_observer *observer,
                               cnet_connection *out_connection);

int cnet_listener_connect_endpoint(
    cnet_listener *listener, cnet_client *client,
    const cnet_stream_endpoint *remote_endpoint,
    const cnet_observer *observer,
    cnet_connection *out_connection);

/** Creates and listens in one call; equivalent to bind_ex + listen. */
int cnet_listener_init_ex(cnet_listener *listener, const cnet_listener_config *config,
                          const cnet_listener_options *options);

/** Copies the currently bound numeric TCP endpoint. */
int cnet_listener_local(const cnet_listener *listener, cnet_stream_peer *out_local);

int cnet_listener_local_endpoint(const cnet_listener *listener,
                                 cnet_stream_endpoint *out_local);

/**
 * Creates a nonblocking Linux AF_VSOCK listener. Unsupported platforms or
 * NativeIO backends return `SALTS_ENOTSUP` without publishing an owner.
 * The configuration is copied synchronously; ANY CID/port values are valid
 * only for listener bind.
 * @param listener Zero-initialized listener that receives ownership on success.
 * @param config Versioned configuration with an explicit supported backend and nonzero backlog.
 * @return `SALTS_OK`, `SALTS_EINVAL`, `SALTS_EALREADY`, `SALTS_ENOTSUP`, or a native socket error.
 */
int cnet_listener_init_vsock(cnet_listener *listener,
                             const cnet_vsock_listener_config *config);

/** Returns the bound host-order port, including an OS-selected ephemeral port. */
int cnet_listener_port(const cnet_listener *listener, uint16_t *out_port);

/**
 * Queries the current bound VSOCK CID/port. The value is not cached because a
 * live migration can change the local CID.
 * @param listener Open VSOCK listener.
 * @param out_local Cleared before validation and populated on success.
 * @return `SALTS_OK`, `SALTS_EINVAL`, `SALTS_ESHUTDOWN`, `SALTS_ENOTSUP`, or a native socket error.
 */
int cnet_listener_vsock_local(const cnet_listener *listener, cnet_vsock_peer *out_local);

/**
 * Waits for accept readiness. Timeout is successful with `out_ready == 0`.
 * This function does not accept or allocate a connection.
 */
int cnet_listener_wait(cnet_listener *listener, uint32_t timeout_ms, int *out_ready);

/**
 * Attaches this listening TCP owner to a caller-owned NativeIO backend for
 * external accept progress. CNet borrows but never observes, closes or
 * destroys the backend. The backend kind must match the listener backend and
 * must outlive the listener.
 *
 * This is mutually exclusive with cnet_listener_wait() for progress ownership.
 */
int cnet_listener_attach_external(cnet_listener *listener,
                                  native_io_backend *borrowed_backend);

/**
 * Ensures exactly one external stream-accept request is active and returns its
 * generation-safe NativeIO identity. Repeated calls while that request is
 * active return the same identity and do not submit another OS accept.
 *
 * SALTS_EALREADY means a terminal accepted child is already pending consumption
 * by cnet_listener_accept*().
 */
int cnet_listener_submit_external_accept(cnet_listener *listener,
                                         native_io_request *out_request);

/**
 * Routes one completion already observed by the embedding runtime. Unrelated
 * completions return SALTS_OK with *out_consumed == false. A successful accept
 * consumes the backend-private child escrow into CNet listener ownership; no
 * native handle crosses this API.
 */
int cnet_listener_route_external_completion(
    cnet_listener *listener,
    const native_io_completion *completion,
    bool *out_consumed);

/**
 * Accepts at most one pending TCP peer and transfers its socket into `client`.
 * Success publishes a generation-checked handle and guarantees a later state
 * callback. No pending peer returns `SALTS_ETIMEDOUT`. Admission failure closes
 * the native peer and leaves `out_connection` zero. The child preserves the
 * listener's TCP policy; the client's future-connection policy is not applied.
 */
int cnet_listener_accept(cnet_listener *listener, cnet_client *client,
                         const cnet_observer *observer, cnet_connection *out_connection);

/**
 * Accepts one plaintext TCP peer and also copies its portable remote endpoint.
 * `out_peer` is cleared on failure and remains independent of the connection lifetime.
 */
int cnet_listener_accept_peer(cnet_listener *listener, cnet_client *client,
                              const cnet_observer *observer, cnet_connection *out_connection,
                              cnet_stream_peer *out_peer);

/**
 * Accepts one pending TCP peer without attaching it to a CNet client.
 *
 * Success transfers exactly one accepted native stream into out_accepted
 * after applying listener TCP policy and nonblocking mode. The descriptor is a
 * bounded move-only value intended for one connection-admission handoff to the
 * final CNet owner. No pending peer returns SALTS_ETIMEDOUT.
 *
 * The caller must pass an empty/zero-initialized descriptor. A live descriptor
 * returns SALTS_EALREADY and is left unchanged.
 */
int cnet_listener_accept_detached(cnet_listener *listener,
                                  cnet_accepted_stream *out_accepted);

/**
 * Consumes one detached accepted stream into this client's owner-local TCP
 * state. The client's configured stream socket policy is applied to the child
 * before owner admission. The descriptor becomes empty on every consuming
 * attempt, including bounded admission failure; ownership is never returned to
 * the caller.
 */
int cnet_client_adopt_accepted(cnet_client *client,
                               cnet_accepted_stream *accepted,
                               const cnet_observer *observer,
                               cnet_connection *out_connection);

/**
 * TLS counterpart of cnet_client_adopt_accepted(). TLS handshake state is
 * created only on the final CNet owner; the detached descriptor carries no TLS
 * provider/runtime state.
 */
int cnet_client_adopt_accepted_tls(cnet_client *client,
                                   cnet_accepted_stream *accepted,
                                   const cnet_tls_server *server,
                                   const cnet_observer *observer,
                                   cnet_connection *out_connection);

/**
 * Closes one still-detached stream and empties the descriptor.
 * Empty/double-close returns SALTS_EALREADY.
 */
int cnet_accepted_stream_close(cnet_accepted_stream *accepted);

/**
 * Accepts one pending VSOCK stream and transfers it into `client`.
 * @param listener Open VSOCK listener.
 * @param client Initialized client that receives the accepted stream.
 * @param observer Required observer copied into the connection record.
 * @param out_connection Cleared before validation and populated only after successful admission.
 * @return The VSOCK peer-accept statuses; no pending peer returns `SALTS_ETIMEDOUT`.
 */
int cnet_listener_accept_vsock(cnet_listener *listener, cnet_client *client,
                               const cnet_observer *observer,
                               cnet_connection *out_connection);

/**
 * Accepts one VSOCK stream and copies its full-width remote CID/port.
 * `out_peer` is cleared on failure and remains independent of the connection lifetime.
 * @param listener Open VSOCK listener.
 * @param client Initialized client that receives the accepted stream.
 * @param observer Required observer copied into the connection record.
 * @param out_connection Cleared before validation and populated only after successful admission.
 * @param out_peer Cleared before validation and populated with host-order CID/port on success.
 * @return `SALTS_OK`, validation/lifecycle errors, `SALTS_ETIMEDOUT`, or a native socket error.
 */
int cnet_listener_accept_vsock_peer(cnet_listener *listener, cnet_client *client,
                                    const cnet_observer *observer,
                                    cnet_connection *out_connection,
                                    cnet_vsock_peer *out_peer);

/**
 * Accepts one TCP peer and begins a server-side TLS handshake before
 * CONNECTED. The caller must not destroy `server` concurrently with this call.
 * Like plaintext direct accept, the child preserves the listener's TCP policy.
 * @return The plaintext accept statuses, plus `SALTS_ENOTSUP` when `client`
 * has no bounded TLS storage or `SALTS_EINVAL` for an invalid TLS context.
 */
int cnet_listener_accept_tls(cnet_listener *listener, cnet_client *client,
                             const cnet_tls_server *server, const cnet_observer *observer,
                             cnet_connection *out_connection);

/** TLS counterpart of `cnet_listener_accept_peer()`. */
int cnet_listener_accept_tls_peer(cnet_listener *listener, cnet_client *client,
                                  const cnet_tls_server *server, const cnet_observer *observer,
                                  cnet_connection *out_connection, cnet_stream_peer *out_peer);

/** Closes listener admission. Existing CNet connections are unaffected. */
int cnet_listener_close(cnet_listener *listener);

/** Requires a closed listener and releases its platform-module reference. */
int cnet_listener_destroy(cnet_listener *listener);

/**
 * Binds one numeric IPv4/IPv6 UDP endpoint and preallocates all request,
 * receive, send and completion storage. No worker thread is created.
 */
int cnet_datagram_init(cnet_datagram *datagram, const cnet_datagram_config *config);

/** SDK capability for the complete borrowed-backend datagram progress API. */
#define CNET_DATAGRAM_EXTERNAL_PROGRESS_VERSION 1u

/**
 * Initializes a fixed-owner UDP endpoint on a live borrowed backend.
 * config has the same validation as owned init; backend kind must match and
 * its request capacity must cover config.request_capacity. The host budgets
 * aggregate endpoint/request capacity across all borrowers. The host's batch
 * capacity controls observe; no private completion array is allocated here.
 * Backend storage must outlive the datagram and all concurrent wake callers.
 * Failure leaves datagram uninitialized and never closes the host backend.
 * Returns SALTS_OK, SALTS_EINVAL, SALTS_EALREADY, SALTS_ESHUTDOWN,
 * SALTS_ENOBUFS, SALTS_ERANGE, SALTS_ENOMEM, SALTS_ENOTSUP, or a native error.
 */
int cnet_datagram_init_external(cnet_datagram *datagram, const cnet_datagram_config *config,
                                 native_io_backend *backend);

/** Additive socket-control capability; existing bound init/config layout is unchanged. */
#define CNET_DATAGRAM_SOCKET_CONTROL_VERSION 1u
/** Opens an unbound IP datagram socket on a borrowed backend. config.host/port
 * must be NULL/zero. All other bounds/observer rules match external init.
 * No receive/send admission is allowed before bind. No worker is created. */
int cnet_datagram_open_external(cnet_datagram *datagram, const cnet_datagram_config *config,
                               native_io_backend *backend, cnet_datagram_address_family family);
/** Binds once; endpoint permits an unspecified IP and port zero. Preserves
 * IPv6 flow-info/scope. EALREADY on rebinding, EBUSY on callback reentry. */
int cnet_datagram_bind_endpoint(cnet_datagram *datagram, const cnet_stream_endpoint *endpoint);
/** Native UDP connect/disconnect. NULL disconnects. Requires a bound socket
 * and no retained receive/send requests; EBUSY preserves the association.
 * Query the local address again after successful association/disassociation. */
int cnet_datagram_associate_endpoint(cnet_datagram *datagram, const cnet_stream_endpoint *endpoint);
int cnet_datagram_local_endpoint(const cnet_datagram *datagram, cnet_stream_endpoint *out);
int cnet_datagram_remote_endpoint(const cnet_datagram *datagram, cnet_stream_endpoint *out);
/** Lossless peer query allowed only during on_receive; its returned copy owns no socket. */
int cnet_datagram_received_endpoint(const cnet_datagram *datagram, cnet_stream_endpoint *out);
/** Stops receive demand and requests cancellation without early release. Route
 * the actual terminal before quiescent becomes true. Accepted send terminals
 * still run. Pause is idempotent and does not stop the socket or backend. */
int cnet_datagram_pause_receive(cnet_datagram *datagram);
int cnet_datagram_quiescent(const cnet_datagram *datagram, bool *out);
/** UDP supports HOP_LIMIT, RECEIVE_BUFFER_BYTES and SEND_BUFFER_BYTES only.
 * Queries report platform values; unsupported options return ENOTSUP.
 * Values above platform int range clamp to INT_MAX; zero is invalid. */
int cnet_datagram_option_get(const cnet_datagram *datagram, cnet_tcp_socket_option option, uint64_t *out);
int cnet_datagram_option_set(cnet_datagram *datagram, cnet_tcp_socket_option option, uint64_t value);
/** Endpoint NULL uses the current native association. Empty payloads are real
 * datagrams; NULL data is allowed only with size zero. Same terminal tag and
 * copied ownership contract as cnet_datagram_send. */
int cnet_datagram_send_endpoint(cnet_datagram *datagram, const cnet_stream_endpoint *endpoint,
                                const void *data, size_t size, uint64_t tag);

/**
 * Advances deferred receive rearm and stop cleanup without observe or waiting.
 * Valid during STOPPING. Receive errors require explicit receive admission;
 * advance only retries a deferred rearm, never a failed receive terminal.
 * out_events is required and receives the callback count (currently zero).
 * Returns SALTS_OK, a rearm/cleanup error, SALTS_EINVAL, SALTS_ENOTSUP for an
 * owned instance, or SALTS_EBUSY for recursive progress/callback execution.
 */
int cnet_datagram_advance_external(cnet_datagram *datagram, size_t *out_events);

/**
 * Routes one terminal observed by the host from this instance's backend.
 * Never route across backends. Foreign/duplicate requests return SALTS_OK,
 * consumed=false and zero events. Matching slot/generation claims the terminal
 * before validating metadata; malformed owned terminals return SALTS_EPROTO
 * with consumed=true and settle the request, including one failed send callback.
 * The input is unchanged. Callbacks run inline; receive views last only through
 * their callback. Process the rest of a host batch even when one route fails.
 * Returns SALTS_OK, SALTS_EINVAL, SALTS_ENOTSUP, SALTS_EBUSY, or a receive/rearm
 * error. out_consumed and out_events are required and cleared before validation.
 */
int cnet_datagram_route_external_completion(cnet_datagram *datagram,
                                             const native_io_completion *completion,
                                             bool *out_consumed, size_t *out_events);

/**
 * Closes admission and cancels only this instance's requests without observe.
 * out_stopped is required and true only after all terminals/callbacks and owned
 * endpoint cleanup have finished. SALTS_EBUSY means continue host route/advance.
 * cancel ENOENT/EALREADY on retained requests waits for their real terminal;
 * it never releases payload or fabricates a callback. Receive callbacks cease
 * during stop; every accepted send still gets exactly one terminal.
 * Other cancellation/cleanup errors are retained and returned independently of
 * out_stopped. Retry cleanup on error; destroy requires out_stopped=true.
 * Never closes/destroys the host backend. Repeated calls are safe.
 * Returns SALTS_OK, SALTS_EBUSY, SALTS_EINVAL, SALTS_ENOTSUP, or the first error.
 */
int cnet_datagram_stop_external(cnet_datagram *datagram, bool *out_stopped);

/** Returns the host-order bound port, including an OS-selected ephemeral port. */
int cnet_datagram_port(const cnet_datagram *datagram, uint16_t *out_port);

/**
 * Adds exactly demand receive values. Each successful callback consumes one;
 * overflow fails without changing current demand.
 */
int cnet_datagram_receive(cnet_datagram *datagram, size_t demand);

/**
 * Copies peer and payload into one bounded send slot before returning success.
 * The opaque tag is copied with the peer and payload. A successful call
 * publishes exactly one terminal on_send callback with the same tag.
 */
int cnet_datagram_send(cnet_datagram *datagram, const cnet_datagram_peer *peer, const void *data,
                       size_t size, uint64_t tag);

/**
 * Advances NativeIO and invokes callbacks inline on the non-overlapping owner.
 * An idle timeout is successful with zero events.
 */
int cnet_datagram_poll(cnet_datagram *datagram, uint32_t timeout_ms, size_t *out_events);

/** The only datagram operation allowed concurrently from a non-owner thread. */
int cnet_datagram_wake(cnet_datagram *datagram);

/**
 * Closes admission, cancels retained I/O and drains terminal send callbacks.
 * A concrete cancellation/progress error is returned only after every admitted
 * send has reached its terminal callback. `SALTS_ETIMEDOUT` leaves the bounded
 * drain retryable without discarding the first concrete error.
 */
int cnet_datagram_stop(cnet_datagram *datagram, uint32_t timeout_ms);

/** Requires a completed stop and releases all fixed storage. */
int cnet_datagram_destroy(cnet_datagram *datagram);

/**
 * Creates one protocol-only session from a zero-initialized owner and
 * preallocates its receive message buffer. A live owner returns SALTS_EALREADY.
 */
int cnet_kcp_init(cnet_kcp *session, const cnet_kcp_config *config);

/**
 * Copies one ordered message into KCP after conservative segment-capacity admission.
 * Returns SALTS_ENOBUFS without retaining input when the hard bound would be exceeded.
 * At most 127 new segments may be added per call, after any stream-tail merge.
 * Exceeding this limit or max_message_bytes returns SALTS_EMSGSIZE without retaining input.
 */
int cnet_kcp_send(cnet_kcp *session, const void *data, size_t size);

/** Borrows one wire datagram until return and synchronously emits complete messages. */
int cnet_kcp_input(cnet_kcp *session, const void *data, size_t size);

/** Advances the KCP clock and synchronously emits wire packets through output. */
int cnet_kcp_update(cnet_kcp *session, uint32_t now_ms);

/** Returns KCP's next absolute 32-bit millisecond update time. */
int cnet_kcp_check(const cnet_kcp *session, uint32_t now_ms, uint32_t *out_next_ms);

/** Releases all queued segments and receive storage; no UDP/timer calls may overlap. */
int cnet_kcp_destroy(cnet_kcp *session);

/** Creates a zero-initialized PSK v1/FEC session without emitting wire data. */
int cnet_secure_kcp_init(cnet_secure_kcp *session, const cnet_secure_kcp_config *config);

/** Starts the role state machine; a client synchronously emits its first authenticated hello. */
int cnet_secure_kcp_start(cnet_secure_kcp *session, uint32_t now_ms);

/** Returns true only after the authenticated hello exchange and KCP activation complete. */
bool cnet_secure_kcp_established(const cnet_secure_kcp *session);

/** Copies the session-derived non-zero KCP conversation after establishment. */
int cnet_secure_kcp_conversation(const cnet_secure_kcp *session, uint32_t *out_conversation);

/** Copies one application message into bounded KCP storage; handshaking returns SALTS_EBUSY. */
int cnet_secure_kcp_send(cnet_secure_kcp *session, const void *data, size_t size);

/** Borrows one complete TKSH or TKF1 datagram and authenticates it before state mutation. */
int cnet_secure_kcp_input(cnet_secure_kcp *session, const void *data, size_t size);

/** Advances handshake retry and established KCP timers. */
int cnet_secure_kcp_update(cnet_secure_kcp *session, uint32_t now_ms);

/** Returns the next absolute millisecond deadline for handshake or KCP progress. */
int cnet_secure_kcp_check(const cnet_secure_kcp *session, uint32_t now_ms, uint32_t *out_next_ms);

/** Releases KCP/FEC storage and wipes copied and derived secret material. */
int cnet_secure_kcp_destroy(cnet_secure_kcp *session);

/**
 * Initializes a zero-initialized fixed-capacity UDP/KCP endpoint and arms
 * continuous bounded receive. A live owner returns SALTS_EALREADY.
 * A passive plain KCP session is admitted only on a valid sequence-zero
 * PUSH. Explicitly opened sessions accept normal out-of-order input.
 */
int cnet_packet_endpoint_init(cnet_packet_endpoint *endpoint,
                              const cnet_packet_endpoint_config *config);

/**
 * Initializes an endpoint with authoritative tagged logical-send terminals.
 * `terminal` is copied and its fixed capacity is reserved before publication.
 * KCP stream mode is rejected because it does not retain logical-message
 * boundaries. Passing NULL preserves `cnet_packet_endpoint_init()` behavior.
 */
int cnet_packet_endpoint_init_ex(cnet_packet_endpoint *endpoint,
                                 const cnet_packet_endpoint_config *config,
                                 const cnet_packet_terminal_config *terminal);

/**
 * Initializes the same UDP/KCP endpoint on a borrowed NativeIO backend.
 * The host owns observe and routes every observed terminal to its borrower.
 * config and optional terminal policy match cnet_packet_endpoint_init_ex().
 * The backend must outlive the endpoint and concurrent wake callers. Failed
 * initialization leaves the endpoint unpublished and the backend open.
 */
int cnet_packet_endpoint_init_external(cnet_packet_endpoint *endpoint,
    const cnet_packet_endpoint_config *config,
    const cnet_packet_terminal_config *terminal, native_io_backend *backend);

/** Returns the host-order UDP port shared by all endpoint sessions. */
int cnet_packet_endpoint_port(const cnet_packet_endpoint *endpoint, uint16_t *out_port);

bool cnet_packet_session_valid(cnet_packet_session session);

/** Copies immutable protocol, peer and conversation identity for a live session. */
int cnet_packet_session_get_info(const cnet_packet_endpoint *endpoint, cnet_packet_session session,
                                 cnet_packet_session_info *out_info);

/**
 * Explicitly opens one peer mapping. UDP requires conversation zero. Plain KCP
 * requires a non-zero conversation id; authenticated KCP requires zero because
 * its conversation id is derived during the handshake. Duplicate keys return
 * SALTS_EALREADY.
 */
int cnet_packet_session_open(cnet_packet_endpoint *endpoint, const cnet_datagram_peer *peer,
                             uint32_t conversation, cnet_packet_session *out_session);

/** Closes one generation-checked session after its copied UDP writes drain. */
int cnet_packet_session_close(cnet_packet_endpoint *endpoint, cnet_packet_session session);

/** Copies and admits one UDP datagram or one reliable ordered KCP message. */
int cnet_packet_send(cnet_packet_endpoint *endpoint, cnet_packet_session session, const void *data,
                     size_t size);

/**
 * Copies and admits one logical message associated with the opaque caller tag.
 * Success guarantees exactly one later terminal callback. Failure retains no
 * operation and produces no terminal callback. A missing terminal policy
 * returns `SALTS_ENOTSUP`; tagged-operation capacity returns `SALTS_ENOBUFS`.
 */
int cnet_packet_send_tagged(cnet_packet_endpoint *endpoint, cnet_packet_session session,
                            const void *data, size_t size, uint64_t tag);

/** Drives socket completions and all due KCP timers on the owned backend.
 * A borrowed endpoint returns SALTS_ENOTSUP. */
int cnet_packet_poll(cnet_packet_endpoint *endpoint, uint32_t timeout_ms, size_t *out_events);

/**
 * Advances one borrowed endpoint without observing or waiting. The positive
 * timer_budget bounds the session slots visited for timer updates. Successive
 * calls resume at the next slot. Advances deferred UDP work during stop.
 * out_events counts UDP I/O callbacks, as in cnet_packet_poll(). KCP timers
 * may publish packet callbacks even when that count is zero.
 */
int cnet_packet_advance_external(cnet_packet_endpoint *endpoint,
                                 size_t timer_budget, size_t *out_events);

/**
 * After advance, query the maximum wait for the host's next observe. The result
 * is capped at max_wait_ms. Due timers return zero, including any left by the
 * advance budget. An idle endpoint without active KCP timers returns the cap.
 */
int cnet_packet_external_timeout(const cnet_packet_endpoint *endpoint,
                                  uint32_t max_wait_ms, uint32_t *out_timeout_ms);

/**
 * Routes one terminal observed on the endpoint's borrowed backend. Foreign and
 * duplicate requests return SALTS_OK with consumed=false. A claimed terminal
 * sets consumed=true even when validation or a packet callback reports an
 * error. Route the entire observed batch before acting on its first error.
 * Receive views are borrowed through callback return. out_events counts UDP
 * I/O callbacks and both outputs are cleared before validation.
 */
int cnet_packet_route_external_completion(cnet_packet_endpoint *endpoint,
    const native_io_completion *completion, bool *out_consumed, size_t *out_events);

/** The only packet endpoint operation allowed concurrently from a non-owner thread. */
int cnet_packet_wake(cnet_packet_endpoint *endpoint);

/**
 * Stops admission, KCP timers and UDP I/O, then drains terminal socket writes.
 * Except for retryable `SALTS_ETIMEDOUT`, an error is returned only after every
 * accepted tagged send has published exactly one terminal callback.
 * A borrowed endpoint returns SALTS_ENOTSUP.
 */
int cnet_packet_endpoint_stop(cnet_packet_endpoint *endpoint, uint32_t timeout_ms);

/**
 * Stops a borrowed endpoint without observing or closing the host backend.
 * out_stopped becomes true after all UDP and packet terminals and endpoint
 * cleanup have finished. On SALTS_EBUSY continue host observe/route and retry.
 * A concrete error is retained and reported independently of out_stopped.
 * Continue draining and cleanup until out_stopped is true. Repeated calls are
 * safe. Owned endpoints return SALTS_ENOTSUP. Recursive progress, query, or
 * stop on an active packet callback returns SALTS_EBUSY.
 */
int cnet_packet_endpoint_stop_external(cnet_packet_endpoint *endpoint, bool *out_stopped);

/** Requires completed stop and releases the peer index and all fixed storage. */
int cnet_packet_endpoint_destroy(cnet_packet_endpoint *endpoint);

#ifdef __cplusplus
}
#endif

#endif /* CNET_CNET_H */
