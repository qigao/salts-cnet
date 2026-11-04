/* SPDX-License-Identifier: Apache-2.0
 * Provider-neutral, bounded TLS streams. No socket, scheduler or GmSSL types.
 */
#ifndef CRYPTO_TLS_STREAM_H
#define CRYPTO_TLS_STREAM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* All int results are crypto_tls_stream_result. No fallback on errors. */
typedef enum crypto_tls_stream_result {
  CRYPTO_TLS_STREAM_OK = 0,
  CRYPTO_TLS_STREAM_EALREADY = -1,
  CRYPTO_TLS_STREAM_EBUSY = -2,
  CRYPTO_TLS_STREAM_ECONNABORTED = -3,
  CRYPTO_TLS_STREAM_EINVAL = -4,
  CRYPTO_TLS_STREAM_EIO = -5,
  CRYPTO_TLS_STREAM_EMSGSIZE = -6,
  CRYPTO_TLS_STREAM_ENOBUFS = -7,
  CRYPTO_TLS_STREAM_ENOENT = -8,
  CRYPTO_TLS_STREAM_ENOMEM = -9,
  CRYPTO_TLS_STREAM_ENOTCONN = -10,
  CRYPTO_TLS_STREAM_ENOTSUP = -11,
  CRYPTO_TLS_STREAM_EOF = -12,
  CRYPTO_TLS_STREAM_EPROTO = -13,
  CRYPTO_TLS_STREAM_ERANGE = -14,
} crypto_tls_stream_result;

enum {
  CRYPTO_TLS_STREAM_ALPN_NAME_MAX_BYTES = 255,
  CRYPTO_TLS_STREAM_PEER_CERTIFICATE_SHA256_CAPACITY = 65,
  CRYPTO_TLS_STREAM_MIN_IO_BUFFER_BYTES = 17 * 1024,
  CRYPTO_TLS_STREAM_SERVER_NAME_CAPACITY = 254,
  CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_CERTIFICATES = 5,
  CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_BYTES = 4096,
  CRYPTO_TLS_STREAM_CHANNEL_BINDING_BYTES = 32,
  CRYPTO_TLS_STREAM_SERVER_END_POINT_MAX_BYTES = 64
};

typedef enum crypto_tls_stream_client_auth {
  CRYPTO_TLS_STREAM_CLIENT_AUTH_NONE = 0,
  CRYPTO_TLS_STREAM_CLIENT_AUTH_REQUIRED = 1
} crypto_tls_stream_client_auth;

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

/**
 * Per-connection client policy. The configuration is consumed synchronously
 * by context creation and is not retained. Peer and hostname verification are
 * always enabled. NULL CA fields select the platform trust store. TLCP11
 * client certificates are not qualified and return `CRYPTO_TLS_STREAM_ENOTSUP`.
 */
typedef struct crypto_tls_stream_client_config {
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
  crypto_tls_stream_security_profile security_profile;
} crypto_tls_stream_client_config;

/** Configuration copied into a reusable server context during initialization. */
typedef struct crypto_tls_stream_server_config {
  size_t size;
  /** Required PEM server certificate chain and private key.
   * For TLCP11, cert_file contains the signing certificate first, encryption
   * certificate second, then issuer certificates. key_file contains the
   * matching signing key first and encryption key second. Both keys use
   * key_password. Crypto validates the two KeyUsage roles and the provider
   * independently verifies each certificate/private-key match.
   */
  const char *cert_file;
  const char *key_file;
  const char *key_password;
  /** Required only when `client_auth` is REQUIRED. */
  const char *ca_file;
  const char *ca_path;
  /** TLCP11 currently accepts NONE only; REQUIRED returns `CRYPTO_TLS_STREAM_ENOTSUP`. */
  crypto_tls_stream_client_auth client_auth;
  /** Optional server-preference ALPN list. */
  const char *const *alpn_protocols;
  size_t alpn_protocol_count;
  /** Explicit security profile; zero retains verified STANDARD TLS. */
  crypto_tls_stream_security_profile security_profile;
} crypto_tls_stream_server_config;

typedef struct crypto_tls_stream_peer_certificate {
  const uint8_t *data;
  size_t size;
} crypto_tls_stream_peer_certificate;

typedef struct crypto_tls_stream_peer_certificate_chain {
  crypto_tls_stream_peer_certificate certificates[CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_CERTIFICATES];
  size_t count;
  size_t total_bytes;
} crypto_tls_stream_peer_certificate_chain;

typedef struct crypto_tls_stream_context crypto_tls_stream_context;

typedef enum crypto_tls_stream_protocol_version {
  CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT = 0,
  CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2 = 12,
  CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3 = 13
} crypto_tls_stream_protocol_version;


typedef struct crypto_tls_stream crypto_tls_stream;

/* Immutable reusable contexts: create consumes config synchronously, including
 * certificates, trust roots and ALPN. Context retain/release is thread-safe;
 * publish a live reference before another thread creates a stream from it.
 * Each stream has ONE exclusive progress owner; no implicit locks or workers.
 * Client verification is mandatory. Explicit CA sources never fall back to
 * system trust. Security profiles cannot downgrade to each other.
 * Creates set *out_context=NULL on failure. */
int crypto_tls_stream_client_context_create(
    const crypto_tls_stream_client_config *config,
    crypto_tls_stream_context **out_context);
int crypto_tls_stream_server_context_create(
    const crypto_tls_stream_server_config *config,
    crypto_tls_stream_context **out_context);
void crypto_tls_stream_context_retain(crypto_tls_stream_context *context);
void crypto_tls_stream_context_release(crypto_tls_stream_context *context);
/* Borrowed immutable override, or NULL; valid until the context is released. */
const char *crypto_tls_stream_context_server_name(const crypto_tls_stream_context *context);

/* Success retains context; failure retains nothing and sets *out_stream=NULL.
 * io_buffer_bytes >= MIN_IO_BUFFER_BYTES; checked fixed allocations only.
 * Cipher input/output rings and plaintext staging never grow. feed_cipher is
 * all-or-nothing (ENOBUFS); write resumes the identical immutable range until
 * out_complete. Plaintext ranges remain borrowed while a write is incomplete.
 * Host owns socket/NativeIO completion truth and must drain outstanding native
 * reads/writes BEFORE destroy. The two I/O buffers returned below have stable
 * addresses until destroy and must never alias TLS plaintext staging.
 * Destroy requires exclusive quiescence; it releases the stream's context ref.
 * No transport EOF is an authenticated peer close_notify. The host terminates
 * the connection on EOF or fatal EIO/EPROTO/ECONNABORTED; it must not retry a
 * failed TLS stream or reinterpret it as plaintext. Admission EINVAL/ENOBUFS,
 * empty-output ENOENT and incomplete OK results do not authorize teardown of
 * buffers still borrowed by native I/O. */
int crypto_tls_stream_create(crypto_tls_stream_context *context, bool server,
    const char *server_name, size_t io_buffer_bytes, crypto_tls_stream **out_stream);
void crypto_tls_stream_destroy(crypto_tls_stream *stream);

int crypto_tls_stream_handshake(crypto_tls_stream *state, bool *out_complete);
bool crypto_tls_stream_handshake_complete(const crypto_tls_stream *state);
/* Select before the first handshake call; changes after that call are rejected. */
int crypto_tls_stream_set_protocol_range(crypto_tls_stream *state,
                                      crypto_tls_stream_protocol_version minimum,
                                      crypto_tls_stream_protocol_version maximum);
void *crypto_tls_stream_read_buffer(crypto_tls_stream *state);
void *crypto_tls_stream_write_buffer(crypto_tls_stream *state);
size_t crypto_tls_stream_io_buffer_bytes(const crypto_tls_stream *state);
size_t crypto_tls_stream_cipher_input_capacity(const crypto_tls_stream *state);
/* Owner-thread query only; false for an invalid stream. This checks the
 * output ring, not ciphertext already borrowed by a native write. */
bool crypto_tls_stream_cipher_output_empty(const crypto_tls_stream *state);
int crypto_tls_stream_feed_cipher(crypto_tls_stream *state, const void *data, size_t size);
/* ENOENT with *out_size=0 means no queued ciphertext, not a connection error. */
int crypto_tls_stream_take_cipher(crypto_tls_stream *state, void *buffer, size_t capacity, size_t *out_size);
int crypto_tls_stream_write(crypto_tls_stream *state, const void *data, size_t size, bool *out_complete);
int crypto_tls_stream_read(crypto_tls_stream *state, void *buffer, size_t capacity, size_t *out_size,
                  bool *out_peer_closed);
/**
 * Advances TLS control state without consuming application plaintext.
 * out_plaintext_pending is true when application data is retained in the
 * engine's plaintext buffer until receive demand exists.
 */
int crypto_tls_stream_probe_peer_close(crypto_tls_stream *state, bool *out_peer_closed,
                              bool *out_plaintext_pending);
/* out_peer_notify_received is true only for an authenticated TLS close_notify.
 * A socket EOF cannot satisfy a locally initiated reciprocal shutdown.
 * An incomplete write returns EBUSY without starting shutdown; finish that
 * identical write first. Once shutdown starts, new writes return ENOTCONN,
 * including when output backpressure delays the first close_notify byte. */
int crypto_tls_stream_shutdown(crypto_tls_stream *state, bool *out_notify_generated,
                      bool *out_peer_notify_received);
/* ALPN and peer-chain views borrow immutable stream storage until destroy.
 * The standalone chain parser instead borrows its input DER for every view.
 * Inspection never substitutes for handshake authentication. */
int crypto_tls_stream_get_negotiated_alpn(const crypto_tls_stream *state, const unsigned char **out_data,
                                 size_t *out_size);
int crypto_tls_stream_negotiated_version(const crypto_tls_stream *state, char *buffer, size_t capacity,
                                      size_t *out_size);
int crypto_tls_stream_negotiated_cipher(const crypto_tls_stream *state, char *buffer, size_t capacity,
                                     size_t *out_size);
int crypto_tls_stream_peer_certificate_sha256(
    const crypto_tls_stream *state,
    char buffer[CRYPTO_TLS_STREAM_PEER_CERTIFICATE_SHA256_CAPACITY]);
int crypto_tls_stream_peer_certificate_chain_parse(
    const uint8_t *data, size_t size,
    crypto_tls_stream_peer_certificate_chain *out_chain);
int crypto_tls_stream_get_peer_certificate_chain(
    const crypto_tls_stream *state,
    crypto_tls_stream_peer_certificate_chain *out_chain);
int crypto_tls_stream_server_end_point_binding_from_certificate(
    const uint8_t *certificate, size_t certificate_size,
    uint8_t *output, size_t capacity, size_t *out_size);
/* RFC 5929: hashes the server's handshake certificate on BOTH endpoints.
 * A server uses its selected local leaf; a client uses its verified peer leaf.
 * Client certificates used for mTLS do not change this binding. */
int crypto_tls_stream_server_end_point_binding(
    const crypto_tls_stream *state, uint8_t *output, size_t capacity,
    size_t *out_size);
int crypto_tls_stream_export_channel_binding(
    const crypto_tls_stream *state, uint8_t output[CRYPTO_TLS_STREAM_CHANNEL_BINDING_BYTES]);


#ifdef __cplusplus
}
#endif
#endif /* CRYPTO_TLS_STREAM_H */
