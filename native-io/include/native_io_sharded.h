#ifndef SALTS_NATIVE_IO_SHARDED_H
#define SALTS_NATIVE_IO_SHARDED_H

#include <native_io.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct native_io_sharded native_io_sharded;
typedef struct native_io_sharded_context native_io_sharded_context;

/* One registered, Owner-local long-lived host consumer of an SG backend.
 * Explicit lease prevents SG shutdown while external CNet/FlowMQ connections
 * still borrow the backend. This is not a raw backend pointer without a
 * lifetime; the owner must destroy all borrowed clients before releasing.
 * No second observe owner, hidden poll task or cross-shard backend access. */
#define NATIVE_IO_SHARDED_HOST_VERSION 1u
typedef struct native_io_sharded_host_lease {
  uint64_t owner_identity;
  uint32_t owner_shard;
  uint32_t version;
  uint64_t generation;
} native_io_sharded_host_lease;

/* Called on the selected shard during release to prove host-owned clients
 * have stopped and destroyed their NativeIO endpoints. The callback is
 * borrowed through successful release; it must not recurse into SG. */
typedef bool (*native_io_sharded_host_quiescent_fn)(void *user);


/**
 * Runs one routed task on its selected NativeIO owner shard.
 *
 * The context is borrowed for the duration of the callback and must not be
 * retained. The callback runs on exactly one fixed shard.
 */
typedef void (*native_io_sharded_task_fn)(native_io_sharded_context *context, void *arg);
typedef void (*native_io_sharded_cancel_fn)(void *arg, int status);
typedef void (*native_io_sharded_finalize_fn)(void *arg);

/**
 * Copied bounded-routing descriptor.
 *
 * Successful off-shard admission copies this descriptor into fixed-capacity
 * runtime storage. Rejected admission invokes no callback. Successful
 * admission invokes run, or cancel when the underlying executor cannot start
 * the accepted task, and then invokes finalize exactly once when non-NULL.
 *
 * arg is borrowed through finalize, or through run/cancel when finalize is
 * NULL. Cross-shard callers must therefore supply an explicitly
 * cross-thread-safe owner/token for any storage reachable through arg. This
 * API does not turn an arbitrary borrowed payload pointer into safe
 * cross-shard storage.
 */
typedef struct native_io_sharded_task {
  native_io_sharded_task_fn run;
  native_io_sharded_cancel_fn cancel;
  native_io_sharded_finalize_fn finalize;
  void *arg;
} native_io_sharded_task;

/**
 * Runtime- and shard-bound endpoint identity.
 *
 * Raw NativeIO endpoint ABI remains unchanged. The wrapper adds immutable
 * runtime/shard affinity only in the Sharded adapter. There is no rebind or
 * migration API for a live endpoint.
 */
typedef struct native_io_sharded_endpoint {
  uint64_t owner_identity;
  uint32_t owner_shard;
  uint32_t reserved;
  native_io_endpoint native_endpoint;
} native_io_sharded_endpoint;

/** Runtime- and shard-bound request identity. */
typedef struct native_io_sharded_request {
  uint64_t owner_identity;
  uint32_t owner_shard;
  uint32_t reserved;
  native_io_request native_request;
} native_io_sharded_request;

/**
 * Owner-local I/O descriptor.
 *
 * buffer/address ownership is exactly the raw NativeIO borrow contract and is
 * valid only when this descriptor is submitted from its endpoint owner shard.
 * This type is not a cross-shard borrowed-payload transport.
 */
typedef struct native_io_sharded_operation {
  native_io_operation_kind kind;
  native_io_sharded_endpoint endpoint;
  void *buffer;
  size_t length;
  uintptr_t user_data;
  void *address;
  size_t address_capacity;
  size_t address_length;
} native_io_sharded_operation;

typedef struct native_io_sharded_completion {
  native_io_sharded_request request;
  native_io_sharded_endpoint endpoint;
  native_io_completion_kind kind;
  size_t bytes;
  int status;
  uint32_t native_status;
  uintptr_t user_data;
  size_t address_length;
  /* True only when SG already detached/settled a registered owned-request
   * token during this observe batch. Host must not route this completion to
   * external CNet or treat it as an unknown foreign raw request. */
  bool sharded_owned;
} native_io_sharded_completion;

/**
 * One explicit payload/storage ownership token transferred to an admitted
 * NativeIO request.
 *
 * terminal, when non-NULL, runs on the endpoint owner shard after the matching
 * terminal completion has been copied to the caller-visible sharded completion
 * and while storage reachable through arg is still owned by this token.
 * It may submit new owner-local work, but recursive observe on the same shard
 * returns SALTS_EBUSY so the bounded completion scratch cannot be reentered.
 * finalize then runs exactly once.
 *
 * A failed submit/prepare transfers no ownership and invokes neither callback.
 * Cancellation does not release ownership by itself: the token remains owned
 * by the request until its terminal completion is observed.
 */
typedef void (*native_io_sharded_terminal_fn)(native_io_sharded_context *context,
                                              const native_io_sharded_completion *completion,
                                              void *arg);

typedef struct native_io_sharded_ownership {
  native_io_sharded_terminal_fn terminal;
  native_io_sharded_finalize_fn finalize;
  void *arg;
} native_io_sharded_ownership;

/**
 * Reports owner-local raw NativeIO admission for one accepted routed operation.
 *
 * The callback runs on the endpoint owner shard. SALTS_OK carries a valid
 * shard-bound request. Any other status carries an invalid request and means no
 * raw NativeIO request was created. This is an admission/control result, not a
 * synthesized I/O terminal completion.
 */
typedef void (*native_io_sharded_admission_fn)(native_io_sharded_context *context, int status,
                                               native_io_sharded_request request, void *arg);

bool native_io_sharded_endpoint_valid(native_io_sharded_endpoint endpoint);
bool native_io_sharded_request_valid(native_io_sharded_request request);
bool native_io_sharded_operation_valid(const native_io_sharded_operation *operation);

/** Returns SIZE_MAX for an invalid endpoint wrapper. */
size_t native_io_sharded_endpoint_owner_shard(native_io_sharded_endpoint endpoint);

/** Returns SIZE_MAX for an invalid request wrapper. */
size_t native_io_sharded_request_owner_shard(native_io_sharded_request request);

typedef struct native_io_sharded_config {
  /** Fixed number of owner shards. Must be nonzero. */
  size_t shard_count;
  /** Exact bounded queued-dispatch capacity per shard. Must be a power of two. */
  size_t queue_capacity_per_shard;
  /** Copied configuration used to initialize one NativeIO backend per shard. */
  native_io_backend_config backend;
} native_io_sharded_config;

enum { NATIVE_IO_SHARDED_STATS_ABI_V1 = 1u };

typedef struct native_io_sharded_stats {
  uint32_t abi_version;
  size_t struct_size;
  size_t shard_count;
  size_t queue_capacity_per_shard;
  size_t command_slot_capacity_per_shard;
  uint64_t submitted_tasks;
  uint64_t same_shard_direct_tasks;
  uint64_t queued_dispatches;
  uint64_t completed_tasks;
  uint64_t cancelled_tasks;
  uint64_t rejected_tasks;
  uint64_t active_command_slots;
  uint64_t peak_command_slots;
  bool accepting;
} native_io_sharded_stats;

#define NATIVE_IO_SHARDED_STATS_V1_INITIALIZER                                                     \
  {NATIVE_IO_SHARDED_STATS_ABI_V1,                                                                 \
   sizeof(native_io_sharded_stats),                                                                \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   0u,                                                                                             \
   false}

/**
 * Creates a fixed-shard NativeIO routing runtime.
 *
 * Each shard owns one Coroutine Executor worker and one NativeIO backend. The
 * backend is initialized on that owner shard. No backend or transport fallback
 * is selected.
 *
 * The runtime preallocates queue_capacity_per_shard + 1 command slots per
 * shard: enough for one active routed task plus the exact bounded executor
 * queue. No command-slot allocation occurs after successful creation.
 *
 * @param config Copied fixed topology/backend configuration.
 * @param out_runtime Cleared on entry and receives ownership on success.
 * @return SALTS_OK, SALTS_EINVAL, SALTS_ERANGE, SALTS_ENOTSUP, SALTS_ENOMEM,
 *         or the first NativeIO backend initialization/bootstrap cancellation
 *         error in shard order. Failed creation leaves out_runtime NULL and joins all accepted
 *         bootstrap tasks before reclaiming their borrowed shard storage.
 */
int native_io_sharded_create(const native_io_sharded_config *config,
                             native_io_sharded **out_runtime);

/**
 * Routes a task to one explicit shard.
 *
 * When called from the same runtime and target shard, run/finalize execute
 * immediately with zero message hop. Otherwise the copied descriptor uses the
 * bounded target-shard queue. External callers may wait for bounded queue
 * space; a runtime callback receives SALTS_EBUSY rather than blocking on
 * another saturated shard.
 */
int native_io_sharded_submit_to(native_io_sharded *runtime, size_t shard,
                                const native_io_sharded_task *task);

/**
 * Nonblocking explicit-shard routing.
 *
 * Same-shard dispatch remains direct. Off-shard/full admission returns
 * SALTS_ENOBUFS. Rejection never transfers arg ownership and invokes no task
 * callback.
 */
int native_io_sharded_try_submit_to(native_io_sharded *runtime, size_t shard,
                                    const native_io_sharded_task *task);

/**
 * Routes one explicitly owned operation to its endpoint's fixed owner shard.
 *
 * SALTS_OK means the bounded routing command was accepted, not that raw NativeIO
 * admission succeeded. admission, when non-NULL, reports the owner-local raw
 * admission result exactly once for every accepted route. On successful raw
 * admission the ownership token transfers to the request and settles only at
 * terminal observe. On owner-local admission failure or executor cancellation,
 * admission runs first and ownership.finalize then runs exactly once.
 *
 * Rejected routing admission transfers no ownership and invokes no callback.
 * The owner shard is taken only from operation->endpoint; there is no explicit
 * alternate-shard parameter, silent forwarding, or live endpoint migration.
 */
int native_io_sharded_submit_owned(native_io_sharded *runtime,
                                   const native_io_sharded_operation *operation,
                                   const native_io_sharded_ownership *ownership,
                                   native_io_sharded_admission_fn admission, void *admission_arg);

/** Nonblocking counterpart of native_io_sharded_submit_owned. */
int native_io_sharded_try_submit_owned(native_io_sharded *runtime,
                                       const native_io_sharded_operation *operation,
                                       const native_io_sharded_ownership *ownership,
                                       native_io_sharded_admission_fn admission,
                                       void *admission_arg);

/**
 * Attempts deterministic owner-local shutdown without stealing caller-managed
 * raw completions.
 *
 * Public routing admission closes first and every previously accepted command
 * reaches its fixed owner before shutdown probes raw state. If a backend has an
 * active request without a matching sharded ownership token, shutdown returns
 * SALTS_EBUSY and restores public admission without observing that request.
 *
 * When all active requests are sharded-owned, each owner rejects new
 * attach/submit/prepare/flush work, requests cancellation for those requests,
 * and observes authoritative terminal completions until every ownership token
 * settles. Live endpoints still belong to the caller: if any remain after the
 * request drain, shutdown returns SALTS_EBUSY and restores public admission so
 * the caller can close/release native identity and retry.
 *
 * Only request=0 and endpoint=0 on every shard commits teardown and executor
 * shutdown. Recoverable SALTS_EBUSY restores ordinary admission; fatal
 * quiescence/progress errors keep new public and owner-local I/O closed while
 * preserving the runtime for diagnosis or a later shutdown retry.
 * Repeated calls after committed shutdown are harmless.
 * Calling from a callback owned by this runtime returns SALTS_EBUSY.
 */
int native_io_sharded_shutdown(native_io_sharded *runtime);

/**
 * Waits for all currently accepted routed/control tasks.
 *
 * Use shutdown first for a stable drain boundary. Calling from this runtime's
 * callback returns SALTS_EBUSY.
 */
int native_io_sharded_wait(native_io_sharded *runtime);

/**
 * Shuts down, drains, destroys every owner-local backend on its shard, destroys
 * the reused Coroutine Executor, and releases runtime storage.
 *
 * Calling from this runtime's callback returns SALTS_EBUSY and preserves
 * ownership.
 */
int native_io_sharded_destroy(native_io_sharded *runtime);

/** Returns the current fixed shard, or SIZE_MAX outside this runtime. */
size_t native_io_sharded_current_shard(const native_io_sharded *runtime);

/** Returns the shard named by a callback context, or SIZE_MAX for NULL. */
size_t native_io_sharded_context_shard(const native_io_sharded_context *context);

/**
 * Attaches a socket to the callback's owner backend and returns an affinity
 * wrapper. Must run from the live callback context. out_endpoint is cleared on
 * failure.
 */
int native_io_sharded_context_attach_socket(native_io_sharded_context *context,
                                            uintptr_t native_socket,
                                            native_io_sharded_endpoint *out_endpoint);

/** Owner-local counterpart of native_io_backend_attach_pipe. */
int native_io_sharded_context_attach_pipe(native_io_sharded_context *context,
                                          uintptr_t native_handle, uint32_t flags,
                                          native_io_sharded_endpoint *out_endpoint);

/**
 * Releases a drained socket endpoint on its fixed owner shard.
 *
 * Returns SALTS_EPERM when the wrapper belongs to another shard of the same
 * runtime and SALTS_ENOENT when it belongs to another runtime or is stale.
 */
int native_io_sharded_context_release_socket(native_io_sharded_context *context,
                                             native_io_sharded_endpoint endpoint);

/** Owner-local counterpart of native_io_backend_release_pipe. */
int native_io_sharded_context_release_pipe(native_io_sharded_context *context,
                                           native_io_sharded_endpoint endpoint);

/**
 * Starts one owner-local operation using raw NativeIO borrow semantics.
 *
 * Cross-shard callers must first route execution to endpoint.owner_shard and
 * keep payload/address storage alive through the routed task/finalizer. This
 * function never silently forwards or migrates a wrong-shard operation.
 */
int native_io_sharded_context_submit(native_io_sharded_context *context,
                                     const native_io_sharded_operation *operation,
                                     native_io_sharded_request *out_request);

/**
 * Starts one owner-local operation and transfers one explicit ownership token
 * to the admitted raw request.
 *
 * ownership->finalize is required. SALTS_OK transfers the copied token to the
 * request slot; any failure transfers nothing and invokes no ownership
 * callback. The token settles only when the terminal completion is observed.
 */
int native_io_sharded_context_submit_owned(native_io_sharded_context *context,
                                           const native_io_sharded_operation *operation,
                                           const native_io_sharded_ownership *ownership,
                                           native_io_sharded_request *out_request);

/** Owner-local batched admission counterpart of native_io_backend_prepare. */
int native_io_sharded_context_prepare(native_io_sharded_context *context,
                                      const native_io_sharded_operation *operation,
                                      native_io_sharded_request *out_request);

/**
 * Prepared counterpart of native_io_sharded_context_submit_owned.
 *
 * Successful prepare transfers ownership even before flush because the raw
 * request already owns the borrowed descriptor/payload at that point.
 */
int native_io_sharded_context_prepare_owned(native_io_sharded_context *context,
                                            const native_io_sharded_operation *operation,
                                            const native_io_sharded_ownership *ownership,
                                            native_io_sharded_request *out_request);

/** Flushes the callback's owner backend. */
int native_io_sharded_context_flush(native_io_sharded_context *context);

/** Requests cancellation only on the request's fixed owner shard. */
int native_io_sharded_context_cancel(native_io_sharded_context *context,
                                     native_io_sharded_request request);

/**
 * Observes owner-local terminal completions and restores runtime/shard affinity
 * on each returned endpoint/request wrapper. Uses runtime-preallocated scratch
 * storage; no steady-state allocation is introduced.
 */
/*
 * Called only from a routed callback on its exact SG Owner shard.
 * At most one host-observe authority is registered per shard. The supplied
 * backend pointer is valid through release and only on the fixed Owner. The
 * host controls when to run bounded progress tasks: registration itself does
 * not start an endless executor task, poll loop, thread or timer.
 *
 * The host must use native_io_sharded_context_observe_host(), which observes
 * once, first settles SG-owned terminal callbacks and returns the complete
 * bounded batch for demultiplexing to attached CNet clients. Unleased observe
 * is refused while the host is registered, to prevent completion stealing.
 */
int native_io_sharded_context_acquire_host(
    native_io_sharded_context *context,
    native_io_sharded_host_quiescent_fn quiescent, void *user,
    native_io_sharded_host_lease *out_lease, native_io_backend **out_backend);
/* EBUSY until callback confirms consumer quiescence and backend has no
 * untracked active requests; no native endpoint/connection is forcibly closed. */
int native_io_sharded_context_release_host(
    native_io_sharded_context *context, native_io_sharded_host_lease lease);

int native_io_sharded_context_observe_host(
    native_io_sharded_context *context, native_io_sharded_host_lease lease,
    native_io_sharded_completion *events, size_t event_capacity,
    uint32_t timeout_ms, size_t *out_count);

int native_io_sharded_context_observe(native_io_sharded_context *context,
                                      native_io_sharded_completion *events, size_t event_capacity,
                                      uint32_t timeout_ms, size_t *out_count);

/** Copies a versioned concurrent statistics snapshot. */
bool native_io_sharded_get_stats(const native_io_sharded *runtime,
                                 native_io_sharded_stats *out_stats);


#ifdef __cplusplus
}
#endif

#endif /* SALTS_NATIVE_IO_SHARDED_H */
