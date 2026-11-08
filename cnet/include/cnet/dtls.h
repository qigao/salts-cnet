#ifndef CNET_DTLS_H
#define CNET_DTLS_H
#include <cnet/cnet.h>
#include <crypto/dtls_stream.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct cnet_dtls {
  void *impl;
} cnet_dtls;
typedef int (*cnet_dtls_receive_fn)(void *, cnet_dtls *,
                                    const cnet_receive_view *);
/* on_receive returns OK, ENOBUFS (non-consuming bounded backpressure), or a
 * terminal negative Salts error. ENOBUFS retains one authenticated record and
 * wire tail for later advance; other errors preserve the first failure. */
typedef void (*cnet_dtls_send_fn)(void *, cnet_dtls *, size_t, int, uint64_t);
typedef struct cnet_dtls_observer {
  cnet_dtls_receive_fn on_receive;
  cnet_dtls_send_fn on_send;
  void *user;
} cnet_dtls_observer;
enum { CNET_DTLS_MAX_INPUT_SLOTS = 64 };
typedef struct cnet_dtls_config {
  cnet_datagram
      *datagram; /* Borrowed bound socket; outlives successful destroy. */
  cnet_datagram_peer peer; /* Copied fixed route, not TLS reference identity. */
  crypto_dtls_stream_config
      security; /* on_data/user must be NULL; adapter owns them. */
  cnet_dtls_observer observer;
  size_t input_slots; /* 1..64 full wire packets, preallocated at init. */
  uint32_t
      tag_domain; /* Nonzero high-32-bit namespace reserved among ALL sends
                   * sharing this datagram; do not reuse before quiescence. */
} cnet_dtls_config;
typedef struct cnet_dtls_info {
  crypto_dtls_stream_info security;
  int error;
  size_t queued_input, free_input;
  /* Includes an admitted application tag before its wire is prepared. */
  bool send_pending, stopping;
  uint64_t
      binding; /* Nonzero incarnation, never reused by this loaded CNet owner. */
} cnet_dtls_info;

/* Complete client bridge, fixed exclusive progress owner. No poll/observer,
 * worker, backend ownership or raw socket replacement. Host drives datagram
 * normally or via external NativeIO and routes its callbacks below. Bind with
 * max_datagram_bytes/receive_buffer_bytes >= CRYPTO_DTLS_MAX_DATAGRAM_BYTES.
 * Config bytes/credentials are consumed at init; observer user lives to
 * destroy. Public wrapper address stays fixed. Failure leaves zero instance
 * unchanged. */
int cnet_dtls_init(cnet_dtls *, const cnet_dtls_config *);
typedef struct cnet_dtls_accept_config {
  cnet_datagram *datagram; /* Borrowed bound socket, same lifetime as client. */
  cnet_datagram_peer peer; /* Fixed copied route after cookie verification. */
  crypto_dtls_listener *listener; /* Leased until successful bridge destroy. */
  cnet_dtls_observer observer;
  size_t input_slots;  /* 1..64, same bounded ring as client. */
  uint32_t tag_domain; /* Same global datagram tag reservation as client. */
} cnet_dtls_accept_config;
/* Create/destroy through the CNet DSO's sole Crypto instance; returns Salts
 * status (including EBUSY with live stream leases). CNet consumers do not link
 * a second static Crypto archive. Configuration/ownership is the Crypto
 * listener contract above; NULL destroy is OK. */
int cnet_dtls_listener_create(const crypto_dtls_listener_config *,
                              crypto_dtls_listener **);
int cnet_dtls_listener_destroy(crypto_dtls_listener *);
/* Stateless server gate with canonical family/address/port/scope encoding.
 * No I/O, allocation or bridge admission. Malformed packets return OK with
 * verified=false/reply_size=0. Other errors propagate. Host owns reply storage,
 * actual raw send terminal, amplification/rate limits and receive credits. */
int cnet_dtls_cookie_gate(const crypto_dtls_listener *,
                          const cnet_datagram_peer *, const cnet_receive_view *,
                          uint64_t now, void *reply, size_t capacity,
                          size_t *reply_size, bool *verified);
/* Rechecks cookie before bridge allocation. Invalid proof returns EPROTO,
 * leaving zero owner unchanged. OK admits a protocol owner, not READY; inspect
 * security state and drive any failed admission's fatal through normal drain.
 * Host bounds the peer table and must not admit an already routed association.
 * The cookie-bearing packet is consumed/copied; do not feed it again as input.
 * Remaining progress/send/close/abort/destroy API is shared by both roles. */
int cnet_dtls_accept(cnet_dtls *, const cnet_dtls_accept_config *,
                     const cnet_receive_view *, uint64_t now);
/* Call from the datagram's observer. Unmatched socket/peer/tag returns OK with
 * matched=false. Successful receive copies the entire packet. ENOBUFS consumes
 * nothing: host must retain/retry before its borrowed receive view expires.
 * Host owns receive demand and must budget slots across its routed peers. */
int cnet_dtls_receive(cnet_dtls *, cnet_datagram *, const cnet_datagram_peer *,
                      const cnet_receive_view *, bool *matched);
/* Exact real on_send terminal only. NativeIO request/generation matching stays
 * in cnet_datagram; adapter additionally matches socket, peer and per-send tag.
 * Always route the rest of an observed batch, including after an error. */
int cnet_dtls_send_complete(cnet_dtls *, cnet_datagram *,
                            const cnet_datagram_peer *, size_t, int, uint64_t,
                            uint64_t now, bool *matched);
/* Before host observe, process queued input/terminals and submit bounded
 * output. Error does not waive routing/drain. One ENOBUFS-proven non-admitted
 * wire may wait for later capacity; accepted output is never resubmitted. */
int cnet_dtls_advance(cnet_dtls *, uint64_t now, size_t *events);
/* Copied application datagram, READY only, <=1163 bytes. One admitted tag gets
 * exactly one local send terminal (not peer receipt). Empty messages supported.
 * Callback mutation reentry is rejected. Input rejection retains no bytes/tag.
 */
int cnet_dtls_send(cnet_dtls *, const void *, size_t, uint64_t tag);
/* Queues authenticated close. Host must advance/route to CLOSED for delivery;
 * destroying with unprepared protocol output can discard that output. */
int cnet_dtls_close(cnet_dtls *);
int cnet_dtls_export(cnet_dtls *, const crypto_dtls_export_request *, void *,
                     size_t);
/* Same exporter-bound HMAC proof through this DSO's sole Crypto instance. */
int cnet_dtls_hmac(cnet_dtls *, const crypto_dtls_export_request *,
                   const void *, size_t, uint8_t output[32]);
int cnet_dtls_get_info(const cnet_dtls *, cnet_dtls_info *);
/* Stops this protocol's admission, erases keys, discards queued input. Never
 * cancels/stops the borrowed datagram or host backend. Continue routing its
 * real send completion and advancing; accepted local sends report their real
 * result. Retire input routing after abort or terminal protocol failure, while
 * still routing every actual send terminal. Returns BUSY while output is in
 * native I/O. Destroy requires
 * quiescence and rejects callback reentry; it does not implicitly stop any
 * shared owner. */
int cnet_dtls_abort(cnet_dtls *);
int cnet_dtls_destroy(cnet_dtls *);
#ifdef __cplusplus
}
#endif
#endif
