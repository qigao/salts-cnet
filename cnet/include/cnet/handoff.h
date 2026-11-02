#ifndef CNET_HANDOFF_H
#define CNET_HANDOFF_H

#include <cnet/cnet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNET_HANDOFF_VERSION 1u

/** Optional bounded MPSC admission inbox; link Salts::CNet.
 * One inbox belongs to one final owner. Producers reserve and publish; the
 * owner takes streams and adopts them through CNet or cnet_manager_adopt.
 * No transport progress, callbacks, TLS state, threads or wake are created.
 * Init/destroy require exclusive lifecycle access. Other operations serialize
 * internally. Do not copy ownership of a live wrapper. Before first use the
 * wrapper may be moved provided the original is zeroed.
 */
typedef struct cnet_handoff { void *impl; } cnet_handoff;

/** Value identity, not a retained reference. Copies do not duplicate a credit.
 * A stale/foreign ticket cannot name a reused slot or reinitialized inbox.
 */
typedef struct cnet_handoff_ticket {
  uint64_t incarnation;
  uint64_t generation;
  size_t slot;
} cnet_handoff_ticket;

typedef struct cnet_handoff_config {
  size_t size;
  uint32_t version;
  size_t connection_capacity;
  size_t queue_capacity;
  cnet_allocator storage;
} cnet_handoff_config;

typedef struct cnet_handoff_snapshot {
  size_t connection_capacity;
  size_t queue_capacity;
  size_t reserved;
  size_t queued;
  size_t taken;
  bool sealed;
  bool drained;
} cnet_handoff_snapshot;

/** Both capacities positive; queue_capacity <= connection_capacity.
 * Allocates all storage up front. Invalid config/version: EINVAL; overflow:
 * ERANGE; allocation failure: ENOMEM; initialized wrapper: EALREADY.
 * Failure leaves the zero wrapper unchanged. No raw CNet capacity is reserved.
 */
int cnet_handoff_init(cnet_handoff *handoff, const cnet_handoff_config *config);
/** Reserve one final-owner credit. ENOBUFS when reserved + queued + taken is
 * at capacity; ESHUTDOWN after seal. Output is zero on failure. A successful
 * ticket must reach publish or release, including after seal.
 */
int cnet_handoff_reserve(cnet_handoff *handoff, cnet_handoff_ticket *out_ticket);
/** Publish a RESERVED ticket and move an active detached TCP stream into FIFO.
 * Success empties accepted and transfers the ticket to the inbox. Every failure
 * leaves both with the producer: ENOBUFS if queue full, ESHUTDOWN after seal,
 * ENOENT for stale/foreign ticket, EALREADY for non-reserved ticket, EINVAL for
 * empty/invalid input. Do not release/re-publish after success even if a later
 * host wake fails. The host must still arrange owner progress or cancellation.
 * peer is copied; TLS/policy objects stay with the final owner, not in entries.
 */
int cnet_handoff_publish(cnet_handoff *handoff, cnet_handoff_ticket ticket,
                         cnet_accepted_stream *accepted);
/** Owner takes the next published ticket and stream, including after seal.
 * ENOENT when empty. Outputs are empty on failure and must not already own
 * resources. Queue space is returned; the connection credit remains TAKEN.
 * Adopt or close the stream, then release the ticket after the owner no longer
 * needs its capacity (normally transport terminal or context retirement).
 */
int cnet_handoff_take(cnet_handoff *handoff, cnet_handoff_ticket *out_ticket,
                      cnet_accepted_stream *out_accepted);
/** Return RESERVED or TAKEN credit exactly once. Does not close a taken stream
 * or connection. EBUSY for a queued ticket, ENOENT for stale/foreign/released.
 */
int cnet_handoff_release(cnet_handoff *handoff, cnet_handoff_ticket ticket);
/** Idempotently block reserve/publish; does not revoke tickets or close sockets.
 * Drain queued entries using take -> close/adopt -> release on the owner.
 */
int cnet_handoff_seal(cnet_handoff *handoff);
/** Coherent O(1) credit/queue snapshot. drained does NOT prove producer/wake
 * quiescence and is not authorization to destroy a concurrently used inbox.
 */
int cnet_handoff_get_snapshot(cnet_handoff *handoff, cnet_handoff_snapshot *out);
/** Requires drained (otherwise EBUSY) AND host-established quiescence:
 * stop/join ALL producers, including publish -> wake tails, and end all owner
 * operations before this call or destroying their wake targets. A raw pointer
 * or ticket retains neither inbox nor backend. No calls may overlap destroy.
 * Empty wrapper: EALREADY. Remaining sockets/credits are never silently dropped.
 */
int cnet_handoff_destroy(cnet_handoff *handoff);

#ifdef __cplusplus
}
#endif
#endif
