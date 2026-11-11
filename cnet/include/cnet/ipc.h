#ifndef CNET_IPC_H
#define CNET_IPC_H

#include <cnet/cnet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNET_IPC_VERSION 1u

typedef struct cnet_ipc_listener {
  void *impl;
} cnet_ipc_listener;

typedef enum cnet_ipc_resource_kind {
  CNET_IPC_RESOURCE_NONE = 0,
  CNET_IPC_RESOURCE_PIPE,
  CNET_IPC_RESOURCE_SOCKET
} cnet_ipc_resource_kind;

/** Move-owned descriptor. Initialize to zero; copying does not duplicate ownership.
 * Fields are transport-private and must not be edited. Transfer only while no
 * I/O, backend association or callback borrow exists. Never cast to TCP accept.
 */
typedef struct cnet_ipc_accepted {
  uintptr_t native_handle;
  cnet_ipc_resource_kind kind;
} cnet_ipc_accepted;

typedef struct cnet_ipc_listener_config {
  size_t size;
  uint32_t version;
  native_io_backend_kind backend;
  const char *uri;
  size_t accept_capacity;
  size_t child_capacity;
  size_t input_buffer_bytes;
  size_t output_buffer_bytes;
} cnet_ipc_listener_config;

typedef enum cnet_ipc_wait_kind {
  CNET_IPC_WAIT_WINDOWS_EVENT = 1,
  CNET_IPC_WAIT_READABLE_FD
} cnet_ipc_wait_kind;

typedef struct cnet_ipc_wait_source {
  cnet_ipc_wait_kind kind;
  uintptr_t native_handle;
} cnet_ipc_wait_source;

/**
 * Initializes a single-owner, threadless local byte-stream listener. Windows
 * ipc://name uses overlapped byte-mode named pipes; names are local single path
 * components (no slash/backslash/colon). POSIX ipc:///absolute/path uses AF_UNIX.
 * No DNS, implicit directory creation, unlink, or TCP fallback. POSIX path
 * cleanup belongs to the caller even after bind succeeds but later init fails.
 * Capacities are positive; accept_capacity <= child_capacity and <=255 on
 * Windows. Pending + completed-undetached children never exceed child_capacity.
 * Backend kind must be supported; only the final data owner attaches children.
 * All config input is consumed before return. Init submits no Windows accepts:
 * call advance before waiting. Failure leaves a zero wrapper unchanged.
 * Returns SALTS_OK, SALTS_EINVAL, SALTS_EALREADY, SALTS_ENOTSUP, SALTS_ERANGE,
 * SALTS_ENOMEM, or a native error. OS permissions/umask remain authoritative.
 */
int cnet_ipc_listener_init(cnet_ipc_listener *listener, const cnet_ipc_listener_config *config);

/** Attach a POSIX listener to a matching epoll or kqueue backend on the
 * calling owner. The backend is borrowed through completed stop. Unregister
 * any borrowed wait source before attaching. Windows returns ENOTSUP.
 * An attached listener uses submit/route for accept progress.
 */
int cnet_ipc_listener_attach_external(cnet_ipc_listener *listener,
                                      native_io_backend *borrowed_backend);

/** Submit one accept to the borrowed backend. Repeated submission returns
 * the active request. A full detached queue returns ENOBUFS before admission.
 * Stop seals admission with ESHUTDOWN. Failure clears out_request.
 */
int cnet_ipc_listener_submit_external_accept(cnet_ipc_listener *listener,
                                             native_io_request *out_request);

/** Route a real completion from the borrowed backend. Only the active request
 * and endpoint generations match. A matching success transfers the child
 * into the detached queue, or closes it if stop has begun. A matching terminal
 * consumes the request once. Foreign and stale requests leave out_consumed
 * false. The embedding owner is responsible for observing the backend.
 */
int cnet_ipc_listener_route_external_completion(cnet_ipc_listener *listener,
                                                 const native_io_completion *completion,
                                                 bool *out_consumed);

/** Observes at most max_events terminal accepts (positive), never waits; on
 * Windows also submits at most max_events replacements. out_events reports
 * observed terminals and is required. Continues cancellation drain during stop; returns first progress
 * error without discarding other observed terminals. Recursive use is EBUSY.
 * Returns ENOTSUP while the listener is attached to an external backend.
 */
int cnet_ipc_listener_advance(cnet_ipc_listener *listener, size_t max_events, size_t *out_events);

/** Moves one completed child to an empty output; ENOENT when none is ready,
 * EALREADY for a live output, ESHUTDOWN after stop. No pending native request or
 * accept callback borrow crosses this boundary. Call advance to replenish accepts.
 */
int cnet_ipc_listener_accept_detached(cnet_ipc_listener *listener, cnet_ipc_accepted *out_accepted);

/**
 * Borrowed host-wait snapshot: read-ready fd on POSIX, pending accept events on
 * Windows. out_ready reports immediate work/queued children; do not wait then.
 * Zero-capacity NULL output queries required count; ENOBUFS writes no partial
 * array. Refresh after every mutation; unregister before advance/stop/destroy.
 * Never close or reset sources. Host supplies its own command/stop wake source
 * and obeys native wait limits. Returns ENOTSUP for an attached listener.
 */
int cnet_ipc_listener_wait_sources(const cnet_ipc_listener *listener,
                                   cnet_ipc_wait_source *out_sources, size_t capacity,
                                   size_t *out_count, bool *out_ready);

/** Stops admission, closes queued children, and requests native cancellation.
 * EBUSY and out_stopped=false require progress before retrying. An attached
 * listener requires routing its terminal completion through the borrowed
 * backend. Errors are independent of quiescence. Detached children keep their
 * existing ownership.
 */
int cnet_ipc_listener_stop(cnet_ipc_listener *listener, bool *out_stopped);
/** Requires completed stop; idempotent on an empty wrapper. */
int cnet_ipc_listener_destroy(cnet_ipc_listener *listener);

/** Closes using the resource kind and clears the descriptor. Empty is EALREADY. */
int cnet_ipc_accepted_close(cnet_ipc_accepted *accepted);

/** Consumes a valid descriptor on the final client's owner, including failed
 * admission (then closes it). Empty/invalid descriptor is EINVAL. Returns the
 * ordinary CNet connection admission errors; admitted connections use the
 * existing send/receive/close and owned/external progress APIs.
 */
int cnet_client_adopt_ipc(cnet_client *client, cnet_ipc_accepted *accepted,
                          const cnet_observer *observer, cnet_connection *out_connection);

#ifdef __cplusplus
}
#endif
#endif
