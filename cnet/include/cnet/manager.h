#ifndef CNET_MANAGER_H
#define CNET_MANAGER_H

#include <cnet/ipc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNET_MANAGER_VERSION 1u

/** Optional owner-local attachment manager. Zero initialize; link Salts::CNet.
 * No thread, poll, timer, handoff queue, or implicit client stop is created.
 * All operations and callbacks belong to the initializing thread. The borrowed
 * client must remain initialized until manager destroy. Do not copy a live wrapper.
 */
typedef struct cnet_manager {
  void *impl;
} cnet_manager;

/** Value identity, not a retained reference. Valid only with the original manager.
 * Stale identities cannot name a recycled record or a reinitialized manager.
 */
typedef struct cnet_managed_connection {
  uintptr_t manager;
  uint64_t incarnation;
  uint64_t generation;
  size_t slot;
} cnet_managed_connection;

typedef struct cnet_manager_config {
  size_t size;
  uint32_t version;
  cnet_client *client;
  size_t record_capacity;
  size_t connection_capacity;
  cnet_allocator storage;
} cnet_manager_config;

typedef struct cnet_manager_attachment {
  cnet_observer observer;
  /** Optional once-only cleanup, on the owner during advance, after all callbacks
   * and the explicit context hold end. Receives observer.user, including on
   * reservation cancellation or immediate connect/adopt failure.
   */
  void (*on_recycle)(void *user);
  /** One extra post-terminal context hold. Host aggregates business references
   * and calls release_context once when they end. Never keeps transport alive.
   */
  bool hold_context;
} cnet_manager_attachment;

typedef enum cnet_manager_record_state {
  CNET_MANAGER_RESERVED = 1,
  CNET_MANAGER_BOUND,
  CNET_MANAGER_RETIRED
} cnet_manager_record_state;

typedef struct cnet_manager_entry {
  cnet_managed_connection managed;
  cnet_connection connection;
  cnet_manager_record_state state;
  void *context;
  bool context_held;
} cnet_manager_entry;

typedef struct cnet_manager_snapshot {
  size_t record_capacity;
  size_t connection_capacity;
  size_t reserved;
  size_t bound;
  size_t retired;
  size_t context_holds;
  size_t ready_to_recycle;
  bool sealed;
  bool runnable;
  bool drained;
} cnet_manager_snapshot;

/** Positive capacities; connection_capacity <= record_capacity. Copies config,
 * allocates all records up front. EINVAL for invalid/versioned input, ERANGE for
 * size/identity overflow, ENOMEM on allocation failure, EALREADY for live wrapper.
 * Failure leaves the zero wrapper unchanged. Does not reserve CNet capacity.
 * Must initialize on the borrowed client's fixed Owner; another thread returns
 * EPERM before storage allocation or publishing a Manager implementation.
 */
int cnet_manager_init(cnet_manager *manager, const cnet_manager_config *config);

/** Reserves one record and one helper admission credit; copies attachment.
 * on_state is required. Observer user remains borrowed through recycle.
 * Output is zero on rejection: ENOBUFS at either bound, ESHUTDOWN after seal.
 * Successful reserve must reach connect/adopt or cancel, even during shutdown.
 */
int cnet_manager_reserve(cnet_manager *manager, const cnet_manager_attachment *attachment,
                         cnet_managed_connection *out_managed);
/** Cancels RESERVED only (EBUSY for BOUND, EALREADY for RETIRED). Returns credit
 * immediately; record/cleanup wait for advance and any explicit context hold.
 */
int cnet_manager_cancel(cnet_manager *manager, cnet_managed_connection managed);

/** Consumes a valid RESERVED record on every attempt, including invalid options,
 * seal and CNet admission failure. Rejection retires the attachment; no state
 * callback is fabricated. Output is zero on failure. Uses attachment.observer,
 * ignoring options.observer. Supports tcp/tls/ipc stream URIs (ENOTSUP otherwise).
 * Binding is complete before return, without polling or allocation by the helper.
 */
int cnet_manager_connect(cnet_manager *manager, cnet_managed_connection managed,
                         const cnet_connect_options *options, cnet_connection *out_connection);
/** TCP/TLS detached adoption. A non-NULL tls selects TLS. A valid RESERVED attempt
 * consumes accepted (including rejection before calling CNet) and retires on
 * failure. Invalid manager/identity/state leaves accepted untouched. This is an
 * owner-local consuming call, NOT a cross-thread queue-publication contract.
 */
int cnet_manager_adopt(cnet_manager *manager, cnet_managed_connection managed,
                       cnet_accepted_stream *accepted, const cnet_tls_server *tls,
                       cnet_connection *out_connection);

/** Adopt a detached IPC stream on its final Owner. A valid RESERVED attempt
 * consumes a valid accepted descriptor and retires the reservation on failure.
 * Manager/identity/state rejection leaves the descriptor with the caller.
 * Invalid descriptors return EINVAL. Output is zero on failure. The attachment
 * observer and context hold govern the admitted connection's lifetime.
 */
int cnet_manager_adopt_ipc(cnet_manager *manager, cnet_managed_connection managed,
                           cnet_ipc_accepted *accepted, cnet_connection *out_connection);

/** Releases the optional extra context hold once (EALREADY if absent). Does not
 * recycle during a callback; cleanup runs later in advance. Transport/observer
 * borrows still apply when released before terminal.
 */
int cnet_manager_release_context(cnet_manager *manager, cnet_managed_connection managed);
/** O(1) identity lookup. ENOENT for stale/foreign identity; output is a borrowed
 * snapshot and its context must not outlive the record. Does not validate sends.
 */
int cnet_manager_lookup(cnet_manager *manager, cnet_managed_connection managed,
                        cnet_manager_entry *out_entry);
/** O(1) inspection for bounded host enumeration. Index is zero-based and must
 * be below record_capacity; ENOENT for a free slot, ERANGE for an invalid index.
 */
int cnet_manager_inspect(cnet_manager *manager, size_t index, cnet_manager_entry *out_entry);
/** Owned receive-slice adapter preserving CNet transfer semantics and manager
 * callback guards. Use this instead of installing a raw handler on a managed
 * connection. NULL restores the attachment's borrowed receive observer.
 */
int cnet_manager_set_receive_slice_handler(cnet_manager *manager, cnet_managed_connection managed,
                                           cnet_receive_slice_fn handler, void *user);

/** Seal is idempotent; blocks new reserve/connect/adopt, not raw client operations.
 * Existing reservations must still be canceled/consumed. No close is implied.
 */
int cnet_manager_seal(cnet_manager *manager);
/** Idempotently seals and schedules cancellation of RESERVED and close of BOUND
 * records. Does not close unmanaged neighbors or release context holds.
 */
int cnet_manager_request_close(cnet_manager *manager);
/** Visits at most budget records (positive), round-robin, issuing pending closes
 * or recycling ready attachments. Never polls/waits. out_work counts actions;
 * first close error is returned while other visited records still progress.
 * Busy/full close attempts remain runnable for retry. All other close errors
 * likewise preserve the record; no error fabricates a terminal.
 * No scanning when there is no runnable management work. Recursive advance or
 * advance from a managed callback/cleanup returns EBUSY.
 */
int cnet_manager_advance(cnet_manager *manager, size_t budget, size_t *out_work);
/** O(1) obligations snapshot; drained means no record or callback obligations,
 * independent of any previously returned error. Not proof of client quiescence.
 */
int cnet_manager_get_snapshot(cnet_manager *manager, cnet_manager_snapshot *out_snapshot);
/** Requires drained and no active callback/advance; otherwise EBUSY. No implicit
 * cleanup, close, or client/backend destruction. Zero wrapper returns EALREADY.
 * Owner-only operations return EPERM from another thread; invalid inputs EINVAL.
 */
int cnet_manager_destroy(cnet_manager *manager);

#ifdef __cplusplus
}
#endif
#endif
