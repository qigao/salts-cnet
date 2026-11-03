#ifndef SALTS_NATIVE_IO_H
#define SALTS_NATIVE_IO_H

#include <error_codes.h>

#ifndef __cplusplus
  #include <stdbool.h>
#endif
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct native_io_backend {
  void *impl;
} native_io_backend;

typedef enum native_io_model {
  NATIVE_IO_MODEL_NONE = 0,
  NATIVE_IO_MODEL_COMPLETION = 1,
  NATIVE_IO_MODEL_READINESS = 2
} native_io_model;

typedef enum native_io_backend_kind {
  NATIVE_IO_BACKEND_IOCP = 1,
  NATIVE_IO_BACKEND_EPOLL,
  NATIVE_IO_BACKEND_IO_URING,
  NATIVE_IO_BACKEND_KQUEUE
} native_io_backend_kind;

typedef struct native_io_endpoint {
  uint32_t slot;
  uint32_t generation;
} native_io_endpoint;

typedef struct native_io_request {
  uint32_t slot;
  uint32_t generation;
} native_io_request;

typedef struct native_io_coroutine native_io_coroutine;

typedef struct native_io_coroutine_task {
  uint32_t slot;
  uint32_t generation;
} native_io_coroutine_task;

typedef void (*native_io_coroutine_entry_fn)(native_io_coroutine *coroutine, void *user_data);

typedef enum native_io_operation_kind {
  NATIVE_IO_OPERATION_STREAM_RECV = 1,
  NATIVE_IO_OPERATION_TCP_RECV = NATIVE_IO_OPERATION_STREAM_RECV,
  NATIVE_IO_OPERATION_STREAM_SEND = 2,
  NATIVE_IO_OPERATION_TCP_SEND = NATIVE_IO_OPERATION_STREAM_SEND,
  NATIVE_IO_OPERATION_UDP_RECV_FROM = 3,
  NATIVE_IO_OPERATION_UDP_SEND_TO = 4,
  NATIVE_IO_OPERATION_PIPE_READ = 5,
  NATIVE_IO_OPERATION_PIPE_WRITE = 6,
  NATIVE_IO_OPERATION_STREAM_CONNECT = 7,
  NATIVE_IO_OPERATION_TCP_CONNECT = NATIVE_IO_OPERATION_STREAM_CONNECT
} native_io_operation_kind;

typedef enum native_io_pipe_endpoint_flags {
  NATIVE_IO_PIPE_ENDPOINT_ASYNC_CAPABLE = 1u << 0
} native_io_pipe_endpoint_flags;

enum { NATIVE_IO_VECTOR_MAX = 16u };

typedef struct native_io_buffer_span {
  void *data;
  size_t length;
} native_io_buffer_span;

/**
 * One caller-owned operation descriptor copied by submit.
 *
 * endpoint is a live handle returned by attach_socket or attach_pipe. buffer
 * is borrowed from successful submit until the matching completion is
 * returned by observe.
 * Send storage is immutable during the borrow; receive storage is exclusively
 * mutable by NativeIO. user_data is copied verbatim into the completion.
 *
 * STREAM_CONNECT and UDP_SEND_TO read address[0..address_length) as a native sockaddr.
 * STREAM_CONNECT requires buffer == NULL and length == 0; its address storage is
 * borrowed until observe returns the matching terminal completion.
 * UDP_RECV_FROM writes at most address_capacity bytes and publishes the actual
 * length in its completion. For an OS-connected datagram socket, UDP_RECV_FROM
 * and UDP_SEND_TO accept all address fields as zero and use connected recv/send
 * semantics. Stream send/receive and pipe operations require all address fields
 * to be zero. Address storage has the same borrow as payload storage.
 */
typedef struct native_io_operation {
  native_io_operation_kind kind;
  native_io_endpoint endpoint;
  void *buffer;
  size_t length;
  uintptr_t user_data;
  void *address;
  size_t address_capacity;
  size_t address_length;
} native_io_operation;

/**
 * One bounded caller-owned vectored write descriptor copied by submit_vector.
 *
 * spans contains 1..NATIVE_IO_VECTOR_MAX non-empty immutable payload ranges.
 * NativeIO copies the span descriptors into fixed request storage; payload
 * bytes remain borrowed until observe returns the matching terminal completion.
 * One completion byte count denotes the transferred prefix across the logical
 * concatenation of all spans. NativeIO does not mutate caller descriptors and
 * does not resubmit a partial write internally.
 *
 * STREAM_SEND is supported when the attached stream endpoint/backend reports
 * vector-write capability. PIPE_WRITE may be supported independently; an
 * unsupported backend/resource combination returns SALTS_ENOTSUP and never
 * flattens the spans into a contiguous copy.
 */
typedef struct native_io_vector_operation {
  native_io_operation_kind kind;
  native_io_endpoint endpoint;
  const native_io_buffer_span *spans;
  size_t span_count;
  uintptr_t user_data;
} native_io_vector_operation;

typedef enum native_io_completion_kind {
  NATIVE_IO_COMPLETION_OK = 1,
  NATIVE_IO_COMPLETION_EOF,
  NATIVE_IO_COMPLETION_CANCELLED,
  NATIVE_IO_COMPLETION_FAILED
} native_io_completion_kind;

typedef struct native_io_completion {
  native_io_request request;
  native_io_endpoint endpoint;
  native_io_completion_kind kind;
  size_t bytes;
  int status;
  uint32_t native_status;
  uintptr_t user_data;
  size_t address_length;
} native_io_completion;

typedef struct native_io_backend_config {
  native_io_backend_kind kind;
  /** Hard cap for socket and pipe endpoints retained by this backend. */
  size_t endpoint_capacity;
  /** Hard cap for operations whose terminal completion is not yet observed. */
  size_t request_capacity;
  /** Maximum completions returned by one observe call. */
  size_t completion_batch_capacity;
} native_io_backend_config;

typedef struct native_io_backend_stats {
  size_t endpoint_capacity;
  size_t endpoint_count;
  size_t request_capacity;
  size_t active_requests;
  uint64_t submitted;
  uint64_t completed;
  uint64_t cancelled;
  uint64_t failed;
  uint64_t rejected_full;
  uint64_t native_submit_errors;
  uint64_t native_cancel_errors;
  bool admission_open;
} native_io_backend_stats;

enum { NATIVE_IO_COROUTINE_STATS_ABI_V1 = 1u };

typedef struct native_io_coroutine_stats {
  uint32_t abi_version;
  size_t struct_size;
  /** Hard cap shared by coroutine task slots and in-flight requests. */
  size_t capacity;
  /** Coroutine entries that have not returned yet. */
  size_t active;
  /** Lazily allocated frames retained for bounded reuse. */
  size_t retained_frames;
} native_io_coroutine_stats;

#define NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER                                                   \
  {NATIVE_IO_COROUTINE_STATS_ABI_V1, sizeof(native_io_coroutine_stats), 0u, 0u, 0u}

/** Returns the communication model represented by kind, or NONE if invalid. */
native_io_model native_io_backend_kind_model(native_io_backend_kind kind);

/** Returns compile-time availability; no fallback backend is selected. */
bool native_io_backend_kind_supported(native_io_backend_kind kind);

/** Returns whether kind supports async-capable connected byte pipes. */
bool native_io_backend_kind_supports_pipe(native_io_backend_kind kind);

bool native_io_endpoint_valid(native_io_endpoint endpoint);
bool native_io_request_valid(native_io_request request);
bool native_io_coroutine_task_valid(native_io_coroutine_task task);
bool native_io_operation_valid(const native_io_operation *operation);
bool native_io_vector_operation_valid(const native_io_vector_operation *operation);

/**
 * Initializes a fixed-capacity backend selected by config.kind.
 *
 * The zero-state backend is owned by the caller. All methods on one backend
 * except native_io_backend_wake are single-owner-thread operations and must
 * not execute concurrently. No backend creates a worker thread: the owner
 * submits and observes directly.
 *
 * @return SALTS_OK; SALTS_EINVAL for malformed handles or capacities;
 *         SALTS_ERANGE for allocation overflow; SALTS_ENOMEM; SALTS_ENOTSUP
 *         when kind is unavailable; otherwise a negative native error code.
 */
int native_io_backend_init(native_io_backend *backend, const native_io_backend_config *config);

/**
 * Associates one native socket with the backend and returns a generation
 * checked endpoint. SOCK_STREAM endpoints admit only STREAM operations; the
 * legacy TCP operation names are source-compatible aliases.
 * SOCK_DGRAM endpoints admit only UDP operations. IPv4 and IPv6 use the same
 * endpoint type because the address family is independent of transport
 * admission. The backend borrows the socket and never closes it. IOCP requires
 * an overlapped socket; readiness drivers use per-call nonblocking operations
 * and do not change the socket's blocking mode. A socket used with STREAM_CONNECT
 * must already be nonblocking when attached to a readiness backend.
 *
 * The caller must retain the returned endpoint, stop submitting before close,
 * drain every request, close the native socket, and then call release_socket.
 *
 * @return SALTS_OK; SALTS_EINVAL; SALTS_ESHUTDOWN; SALTS_EALREADY if the
 *         socket is already attached; SALTS_ENOBUFS at endpoint capacity;
 *         SALTS_ENOTSUP for another socket type; or a negative native query or
 *         association error.
 */
int native_io_backend_attach_socket(native_io_backend *backend, uintptr_t native_socket,
                                    native_io_endpoint *out_endpoint);

/**
 * Releases backend metadata after the caller closed the native socket.
 * SALTS_EBUSY preserves the endpoint while any request remains unobserved.
 */
int native_io_backend_release_socket(native_io_backend *backend, native_io_endpoint endpoint);

/**
 * Associates one connected byte-pipe handle with the backend. The backend
 * borrows the handle and never closes it. flags must be exactly
 * NATIVE_IO_PIPE_ENDPOINT_ASYNC_CAPABLE; no worker fallback is selected.
 * IOCP accepts byte-mode named-pipe handles opened with FILE_FLAG_OVERLAPPED
 * and rejects synchronous handles. epoll and kqueue accept nonblocking byte
 * pipe descriptors. Linux io_uring accepts blocking or nonblocking pipe/FIFO
 * descriptors. The selected backend remains the only progress owner.
 * out_endpoint is cleared on failure.
 */
int native_io_backend_attach_pipe(native_io_backend *backend, uintptr_t native_handle,
                                  uint32_t flags, native_io_endpoint *out_endpoint);

/** Releases metadata for a drained pipe endpoint without closing its handle. */
int native_io_backend_release_pipe(native_io_backend *backend, native_io_endpoint endpoint);

/** Returns whether this live endpoint can preserve a bounded vector write without copying. */
bool native_io_backend_endpoint_supports_vector_write(const native_io_backend *backend,
                                                      native_io_endpoint endpoint);

/**
 * Starts one operation without allocating or copying payload messages. For one
 * endpoint, read operations and write operations are admitted in independent
 * FIFO lanes. A backend may retain the copied descriptor in its fixed request
 * storage until that operation reaches the head of its lane.
 * The descriptor is copied; its payload remains borrowed until observe returns
 * the matching terminal completion. out_request is cleared on failure.
 *
 * @return SALTS_OK; SALTS_EINVAL for an invalid operation or an endpoint whose
 *         socket transport does not match it; SALTS_ENOENT for a stale
 *         endpoint; SALTS_EALREADY for duplicate connect; SALTS_EBUSY when
 *         connect conflicts with retained stream operations; SALTS_ESHUTDOWN
 *         after close; SALTS_ENOBUFS when all request slots are retained; or a
 *         negative native submission error.
 */
int native_io_backend_submit(native_io_backend *backend, const native_io_operation *operation,
                             native_io_request *out_request);

/**
 * Starts one bounded vectored write without flattening payload bytes.
 * Descriptor spans are copied into fixed backend request storage while payload
 * ranges remain borrowed until the matching terminal completion is observed.
 * Unsupported endpoint/backend combinations return SALTS_ENOTSUP.
 */
int native_io_backend_submit_vector(native_io_backend *backend,
                                    const native_io_vector_operation *operation,
                                    native_io_request *out_request);

/**
 * Admits one operation for backend-native batching. Validation, capacity, FIFO,
 * handle and payload-borrow rules match submit. SALTS_OK transfers the descriptor
 * to the backend, not necessarily the kernel. io_uring stages eligible lane heads;
 * readiness/IOCP may start immediately. Do not rely on absence of side effects.
 * Call flush or observe to progress prepared operations. Errors discovered after
 * admission are terminal completions, including a later native submission error.
 * Failure clears out_request and retains no borrow. Owner thread only.
 */
int native_io_backend_prepare(native_io_backend *backend, const native_io_operation *operation,
                              native_io_request *out_request);

/**
 * Starts eligible prepared operations without waiting for their completion.
 * Already-started lane heads retain FIFO precedence. Empty flush succeeds, even
 * after close, so accepted work can drain. A native flush failure is returned
 * immediately; affected unsubmitted requests also receive FAILED completions.
 * Submitted requests are never rolled back. All admitted handles/payloads remain
 * retained until their terminal completions are observed, including on failure.
 */
int native_io_backend_flush(native_io_backend *backend);

/**
 * Starts one bounded coroutine on the backend owner thread.
 *
 * The entry runs immediately until it returns or calls
 * native_io_coroutine_await. A suspended coroutine is resumed only after the
 * matching terminal NativeIO completion is observed. The backend owns and
 * reuses the coroutine frame; entry must not retain coroutine after returning.
 * The task handle becomes stale when entry returns.
 */
int native_io_backend_spawn_coroutine(native_io_backend *backend,
                                      native_io_coroutine_entry_fn entry, void *user_data,
                                      native_io_coroutine_task *out_task);

/**
 * Submits one operation and suspends the currently running NativeIO coroutine.
 *
 * The operation descriptor is copied by the backend. Its borrowed payload and
 * address storage must remain valid across suspension until this function
 * returns. SALTS_OK means out_completion contains the terminal result; native
 * I/O failure remains encoded in completion.kind/status. Submission failures
 * are returned before suspension and leave out_completion cleared.
 */
int native_io_coroutine_await(native_io_coroutine *coroutine, const native_io_operation *operation,
                              native_io_completion *out_completion);

/** Like await, but submits one bounded vectored write through the same request/completion owner. */
int native_io_coroutine_await_vector(native_io_coroutine *coroutine,
                                     const native_io_vector_operation *operation,
                                     native_io_completion *out_completion);

/** Like await, but admits through prepare so separate coroutine entries can
 * share a backend submission batch. Owner observe flushes before waiting. */
int native_io_coroutine_await_prepared(native_io_coroutine *coroutine,
                                       const native_io_operation *operation,
                                       native_io_completion *out_completion);

/** Requests cancellation of the operation currently awaited by task. */
int native_io_backend_cancel_coroutine(native_io_backend *backend, native_io_coroutine_task task);

/**
 * Requests cancellation of an active operation. SALTS_OK means cancellation
 * was marked, not that the operation is terminal. Only an observed CANCELLED
 * completion proves cancellation. SALTS_EALREADY means the native operation
 * was already completing; its terminal completion must still be observed.
 */
int native_io_backend_cancel(native_io_backend *backend, native_io_request request);

/**
 * Flushes eligible prepared operations, then directly dequeues up to
 * min(event_capacity, configured batch capacity)
 * completion packets on the owner thread. Completions owned by a coroutine
 * await resume that coroutine and are not copied to events; processing only
 * such completions returns SALTS_OK with out_count == 0. NativeIO resolves
 * ownership for the complete dequeued batch before resuming any coroutine, so
 * a resumed coroutine may immediately await again without capturing a request
 * slot still named by a later packet in that batch. timeout_ms == 0 polls and
 * UINT32_MAX waits indefinitely. No packet before the deadline returns
 * SALTS_ETIMEDOUT with out_count == 0. Failed I/O is a successfully observed
 * event whose kind/status carry the terminal error. A returned event ends the
 * payload borrow and invalidates that request handle.
 * Readiness backends sample pending OS readiness without blocking when local
 * terminals are queued, so a stream of immediate completions cannot prevent
 * other ready endpoints from producing their terminal. Terminal delivery stays
 * bounded by the configured batch and preserves queued completion order.
 */
int native_io_backend_observe(native_io_backend *backend, native_io_completion *events,
                              size_t event_capacity, uint32_t timeout_ms, size_t *out_count);

/**
 * Wakes an owner blocked in observe without publishing a completion.
 *
 * This is the only backend operation that may be called from a non-owner
 * thread. Concurrent wake calls are coalesced into one bounded control signal.
 * A pure control wake makes observe return SALTS_OK with out_count == 0. The
 * caller must publish its command before wake and must stop all wake callers
 * before close/destroy; wake after close returns SALTS_ESHUTDOWN.
 */
int native_io_backend_wake(native_io_backend *backend);

/**
 * Closes admission. Accepted direct and coroutine requests must still be
 * cancelled or drained.
 */
int native_io_backend_close(native_io_backend *backend);

/**
 * Destroys a closed, fully drained backend with no retained endpoints or
 * active coroutine entries. Retained inactive coroutine frames are released.
 * SALTS_EBUSY preserves ownership when those preconditions are not satisfied.
 */
int native_io_backend_destroy(native_io_backend *backend);

bool native_io_backend_get_stats(const native_io_backend *backend,
                                 native_io_backend_stats *out_stats);

/**
 * Queries the immutable backend kind/capacity contract selected at init.
 * The returned structure contains no native handle or mutable runtime state.
 */
bool native_io_backend_get_config(const native_io_backend *backend,
                                  native_io_backend_config *out_config);

/** Queries versioned coroutine-owner capacity and retention statistics. */
bool native_io_backend_get_coroutine_stats(const native_io_backend *backend,
                                           native_io_coroutine_stats *out_stats);


#ifdef __cplusplus
}
#endif

#endif /* SALTS_NATIVE_IO_H */
