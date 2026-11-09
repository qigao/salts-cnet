#ifndef CRYPTO_DTLS_STREAM_H
#define CRYPTO_DTLS_STREAM_H
#include <crypto/status.h>
#include <crypto/tls_credentials.h>
#include <crypto/tls_peer_policy.h>
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Finite DTLS1.2 client/server: mandatory cookie/EMS, P256 ECDHE, AES128-GCM,
 * ECDSA/RSA SHA256 proof, explicit trust/DNS identity, optional client identity
 * and one ALPN. No socket, worker, resumption or renegotiation. */
enum {
  CRYPTO_DTLS_IDLE = 1,
  CRYPTO_DTLS_BUSY = 2,
  CRYPTO_DTLS_DROP = 3,
  CRYPTO_DTLS_ENOMEM = -6,
  CRYPTO_DTLS_MTU = 1200,
  CRYPTO_DTLS_MAX_DATAGRAM_BYTES = 16421,
  CRYPTO_DTLS_MAX_APPLICATION_BYTES = 1163,
  CRYPTO_DTLS_COOKIE_REPLY_BYTES = 60,
  CRYPTO_DTLS_MAX_PEER_BYTES = 32,
  CRYPTO_DTLS_MAC_INPUT_BYTES = 4096,
  CRYPTO_DTLS_EXPORT_LABEL_BYTES = 255,
  CRYPTO_DTLS_EXPORT_CONTEXT_BYTES = 1024,
  CRYPTO_DTLS_EXPORT_OUTPUT_BYTES = 1024
};
typedef struct crypto_dtls_stream crypto_dtls_stream;
typedef struct crypto_dtls_listener crypto_dtls_listener;
typedef struct crypto_dtls_export_request {
  const void *label;
  size_t label_size;
  const void *context;
  size_t context_size;
  bool use_context;
} crypto_dtls_export_request;
typedef enum crypto_dtls_stream_state {
  CRYPTO_DTLS_HANDSHAKING = 1,
  CRYPTO_DTLS_READY,
  CRYPTO_DTLS_CLOSING,
  CRYPTO_DTLS_CLOSED,
  CRYPTO_DTLS_FAILED
} crypto_dtls_stream_state;
typedef struct crypto_dtls_stream_info {
  crypto_dtls_stream_state state;
  int error, alert_error;
  uint8_t local_alert, peer_alert;
  bool pending_send;
  bool pending_receive; /* Bounded authenticated delivery / owned wire tail. */
} crypto_dtls_stream_info;
typedef int (*crypto_dtls_data_fn)(void *user, crypto_dtls_stream *,
                                   const uint8_t *, size_t);
/* CRYPTO_DTLS_BUSY means non-consuming delivery backpressure: retain one
 * authenticated record and one bounded datagram tail, retry from next().
 * Other nonzero callback results terminate the protocol. */
typedef struct crypto_dtls_stream_config {
  crypto_tls_data
      roots; /* Required DER/PEM; <=4096 decoded bytes, <=5 certs. */
  const char *server_name;
  size_t server_name_size; /* ASCII DNS, 1..253. */
  const void *alpn;
  size_t alpn_size; /* Optional single protocol, <=255. */
  const crypto_tls_credentials
      *credentials; /* Optional single RSA/P256 identity. */
  const crypto_tls_stream_peer_policy *peer_policy;
  crypto_dtls_data_fn on_data;
  void *user;
  bool enable_exporter; /* Default false; retains master until close/failure. */
} crypto_dtls_stream_config;

/* Exclusive owner. Config/bytes/password/object borrows end on return; policy
 * retains once until successful destroy. User lives until destroy. on_data
 * borrows one authenticated record until return; mutation reentry is rejected.
 * Output slot must not alias config or its inputs. Failure publishes NULL. */
int crypto_dtls_stream_create(const crypto_dtls_stream_config *,
                              crypto_dtls_stream **);
typedef struct crypto_dtls_listener_config {
  const crypto_tls_credentials *credentials; /* One RSA/P256 identity. */
  const crypto_tls_data *client_roots; /* Required iff client auth enabled;
                                        * <=4096 decoded bytes/five certs. */
  const crypto_tls_stream_peer_policy *peer_policy; /* Client auth only. */
  const char *server_name; /* NULL/0: fixed identity, no SNI admission. */
  size_t server_name_size; /* Otherwise exact required ASCII DNS SNI. */
  const void *alpn;
  size_t alpn_size;
  uint32_t cookie_lifetime_ms; /* 1..60000, monotonic milliseconds. */
  bool require_client_certificate, enable_exporter;
} crypto_dtls_listener_config;
/* Immutable identity/cookie context. Copies config and imports keys/roots;
 * policy retains once. Create/admission/destroy are lifecycle-exclusive;
 * distinct admitted streams can progress concurrently. Destroy returns BUSY
 * until all streams are destroyed, and rejects policy-release recursion.
 * NULL destroy is OK. No automatic listener shutdown or stream cancellation. */
int crypto_dtls_listener_create(const crypto_dtls_listener_config *,
                                crypto_dtls_listener **);
int crypto_dtls_listener_destroy(crypto_dtls_listener *);
/* Allocation-free cookie gate, no stream lease. Canonical peer bytes (1..32)
 * must include family/IP/port, never sockaddr padding; same encoding at accept.
 * Require a 60-byte reply buffer; reply_size/verified are disjoint from all
 * inputs and each other. Peer/wire must not overlap listener storage.
 * On OK, verified=true means return-routable address,
 * NOT authenticated identity/READY. Otherwise reply_size may hold one bounded
 * HVR no larger than input. DROP publishes no reply for malformed input. Other
 * negatives report argument/state/crypto error. Alias errors leave outputs
 * unchanged; admitted errors clear both outputs. Input borrowed until return.
 * Caller owns reply send storage/terminal, rate/capacity limits and peer table.
 */
int crypto_dtls_listener_gate(const crypto_dtls_listener *, const void *peer,
                              size_t peer_size, const void *wire, size_t,
                              uint64_t now, void *reply, size_t capacity,
                              size_t *reply_size, bool *verified);
/* Rechecks cookie BEFORE allocating stream or acquiring context lease. On DROP
 * or negative status no stream is published. All inputs are immutable borrows
 * through return; outputs cannot alias them. OK publishes an admitted stream,
 * not READY: post-cookie negotiation can already be FAILED, with get_info's
 * error and one possible fatal to drain through next/sent. Destroy that stream
 * to release its listener lease. on_data/user follow the client callback rules.
 * Host must bound simultaneous stream admissions; no hidden peer table. */
int crypto_dtls_stream_accept(crypto_dtls_listener *, const void *peer,
                              size_t peer_size, const void *wire, size_t,
                              uint64_t now, crypto_dtls_data_fn, void *user,
                              crypto_dtls_stream **);
/* One immutable datagram borrowed until EXACTLY ONE sent terminal. Use
 * monotonic milliseconds. IDLE publishes no output; BUSY leaves previous output
 * intact. FAILED can still publish ONE fatal; sent preserves the original
 * error. */
int crypto_dtls_stream_next(crypto_dtls_stream *, uint64_t now,
                            const uint8_t **, size_t *);
/* Actual local terminal, or proven non-admission. Accepted async output must
 * wait for its real completion; cancellation/deadline does not release it. */
int crypto_dtls_stream_sent(crypto_dtls_stream *, uint64_t now, bool success);
/* Whole peer datagram borrowed through return. BUSY consumes nothing; caller
 * keeps/retries it after sends settle. DROP is unauthenticated record discard.
 */
int crypto_dtls_stream_receive(crypto_dtls_stream *, uint64_t now, const void *,
                               size_t);
/* Copies one application datagram on success, READY only. BUSY retains no
 * input. max=1163; empty messages allowed. Completion is the later actual wire
 * terminal. */
int crypto_dtls_stream_write(crypto_dtls_stream *, const void *, size_t);
int crypto_dtls_stream_close(crypto_dtls_stream *);
/* Export is opt-in and READY-only, even with pending sends. No state mutation.
 * Printable label, reserved handshake prefix collisions rejected. Absent versus
 * present-empty context is distinct. Invalid args/state leave output unchanged;
 * native PRF failure clears it. Caller owns and erases exported bytes. */
int crypto_dtls_stream_export(const crypto_dtls_stream *,
                              const crypto_dtls_export_request *, void *,
                              size_t);
/* READY/exporter opt-in only: derive a 32-byte key with the same exporter
 * request, then HMAC-SHA256 a bounded <=4096-byte application proof (e.g. SCTP
 * cookie). GmSSL owns HMAC; derived key/context are erased before return.
 * Disjoint output/inputs/owner; invalid args/state leave output unchanged.
 * The application chooses a purpose-specific exporter label/context. */
/* Exporter material is shared with the peer. A server-only cookie MAC MUST
 * additionally use a secret local context/key, never just a public label. */
int crypto_dtls_stream_hmac(const crypto_dtls_stream *,
                            const crypto_dtls_export_request *, const void *,
                            size_t, uint8_t output[32]);
int crypto_dtls_stream_get_info(const crypto_dtls_stream *,
                                crypto_dtls_stream_info *);
/* Abort discards unprepared output, never a pending wire borrow. Destroy is
 * BUSY until every prepared output has an actual terminal. NULL destroy is OK.
 * No implicit I/O or wait. All non-success results leave the object allocated.
 */
int crypto_dtls_stream_abort(crypto_dtls_stream *);
int crypto_dtls_stream_destroy(crypto_dtls_stream *);
#ifdef __cplusplus
}
#endif
#endif
