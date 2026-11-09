#ifndef CNET_SCTP_DTLS_H
#define CNET_SCTP_DTLS_H
#include <cnet/dtls.h>
#include <sctp_session.h>

typedef struct cnet_sctp_dtls {
  void *impl;
} cnet_sctp_dtls;
typedef struct cnet_sctp_dtls_config {
  cnet_dtls *transport; /* Borrowed, same fixed owner; outlives destroy. */
  cnet_sctp_session *session; /* Borrowed; peer_binding must match transport. */
  size_t input_slots; /* 1..64 preallocated SCTP packets, <=1280 each. */
  uint32_t
      tag_domain; /* Nonzero app-tag namespace reserved among all DTLS users. */
} cnet_sctp_dtls_config;
typedef struct cnet_sctp_dtls_info {
  uint64_t binding;
  size_t queued_input, free_input;
  int error;
  bool reserved, output_pending, submitted, stopping;
} cnet_sctp_dtls_info;

/* Complete transport adapter, no second protocol engine/poller/backend.
 * Fixed exclusive owner; all Session/DTLS/provider borrows outlive destroy.
 * init requires authenticated READY and exact Session peer_binding. Errors use
 * Salts codes. Zero instance is unchanged on failure. No new provider. */
int cnet_sctp_dtls_init(cnet_sctp_dtls *, const cnet_sctp_dtls_config *);
/* From DTLS on_receive; copies one authenticated SCTP packet. ENOBUFS consumes
 * nothing: return that result from DTLS on_receive so DTLS retains the record
 * for later advance. Does not mutate Session or submit I/O in the callback. */
int cnet_sctp_dtls_receive(cnet_sctp_dtls *, cnet_dtls *,
                           const cnet_receive_view *);
/* From exact DTLS on_send; wrong transport/tag is unmatched. Success means
 * local send only; SCTP cumulative ACK/abandonment/business events stay
 * separate. Keep routing after error/abort; duplicate/stale callbacks never
 * settle twice. */
int cnet_sctp_dtls_send_complete(cnet_sctp_dtls *, cnet_dtls *, size_t, int,
                                 uint64_t, bool *matched);
/* Reserve one 1163-byte packet slot BEFORE calling any output-producing public
 * Session operation (start/open/send/poll/close). Pointer is borrowed until
 * exactly one commit; no mutation/progress/abort during that reservation.
 * Commit the actual Session result and written count, including failure/EMPTY.
 * CAPACITY releases reservation without wire admission; preserves Session's
 * noncommitting result as ENOBUFS. Successful output stays immutable through
 * its real DTLS callback. No business terminal is invented on commit. */
int cnet_sctp_dtls_reserve(cnet_sctp_dtls *, void **packet, size_t *capacity);
int cnet_sctp_dtls_commit(cnet_sctp_dtls *, cnet_sctp_session_status,
                          size_t written);
/* Before DTLS advance/host observe: drain copied ingress, Session timers and
 * queued message fragments through the same one output reservation. Bounded
 * work; no automatic peer replacement, retransmit of accepted DTLS output or
 * observation. Session CAPACITY is visible ENOBUFS; host polls its bounded
 * events/receipts using reserve/commit before retry. */
int cnet_sctp_dtls_advance(cnet_sctp_dtls *, uint64_t now, size_t *events);
int cnet_sctp_dtls_get_info(const cnet_sctp_dtls *, cnet_sctp_dtls_info *);
/* Stops Session, discards unsubmitted staging/input. Never stops or cancels
 * borrowed DTLS/datagram/backend. BUSY until submitted output has its real
 * callback. Destroy requires successful abort and no active reservation/send;
 * it frees only this bridge. Then host destroys Session and drains DTLS. */
int cnet_sctp_dtls_abort(cnet_sctp_dtls *);
int cnet_sctp_dtls_destroy(cnet_sctp_dtls *);
#endif
