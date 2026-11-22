#ifndef CNET_WEBSOCKET_TRANSPORT_H
#define CNET_WEBSOCKET_TRANSPORT_H

#include <cnet/export.h>

#include <cnet/cnet.h>
#include <cnet/websocket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cnet_websocket_transport {
  void *impl;
} cnet_websocket_transport;

/* Bind a dedicated, connected TCP/TLS stream after the host has validated HTTP
 * Upgrade/authentication. This is a write/terminal bridge, not an HTTP parser
 * or H2 adapter. Requires no outstanding writes, shutdown or TLS upgrade;
 * EBUSY leaves both objects unchanged. configuration.write must be NULL and
 * output_buffer must supply the retained frame storage. The bridge copies the
 * configuration, retains output through the engine, and borrows callback users.
 * The maximum encoded frame must fit the client's send budget (EMSGSIZE).
 * Other errors: EINVAL, ENOENT (stale connection), ENOTSUP (non TCP/TLS),
 * ENOTCONN, ESHUTDOWN (client stopping), ENOMEM/ERANGE, and underlying
 * tagged-engine configuration errors.
 *
 * Success exclusively owns stream writes until real CLOSED/FAILED: ordinary
 * cnet_send_* are rejected with EBUSY; in-place TLS/shutdown are blocked.
 * CNet successful sends are routed directly to the engine, not the original
 * observer.on_send. Original
 * receive/state observers remain installed. Host drives receive demand and
 * feeds borrowed input into the session on this same Owner, respecting EBUSY.
 * Queue-full non-admission becomes bounded WS EBUSY; permanent errors remain
 * errors. Close through CNet, keep advancing both CNet and WS until drained.
 * No worker, backend, retry loop, protocol READY or application replay is added.
 * client must remain alive until its terminal callback; all operations are
 * single-Owner, and the bridge/engine must outlive their callbacks.
 */
SALTS_CNET_EXPORT
int cnet_websocket_transport_init(cnet_websocket_transport *transport, cnet_client *client,
                                  cnet_connection connection,
                                  const cnet_websocket_config *configuration,
                                  const cnet_websocket_tagged_policy *policy);

/* Borrow the owned engine for send_tagged/feed/close/state queries. Do not
 * reinitialize or destroy it separately. Borrow ends at transport destroy.
 * Example: get_session(&link, &ws); cnet_websocket_send_tagged(ws, ..., tag);
 * then alternate host CNet progress and transport_advance(&link, budget, &n). */
SALTS_CNET_EXPORT
int cnet_websocket_transport_session(cnet_websocket_transport *transport,
                                     cnet_websocket **out_session);
/* Bounded engine progress, including logical terminals after native failure.
 * Returns the first bridge/engine error but still performs drain work. A
 * nonzero result never permits early destruction. out_events is always set. */
SALTS_CNET_EXPORT
int cnet_websocket_transport_advance(cnet_websocket_transport *transport, size_t max_frames,
                                     size_t *out_events);
/* EBUSY until real transport terminal AND all engine callbacks/tags/output
 * settle. Does not close or poll. NULL/uninitialized input: EINVAL; foreign
 * Owner: EPERM. Success invalidates the borrowed session. */
SALTS_CNET_EXPORT
int cnet_websocket_transport_destroy(cnet_websocket_transport *transport);

#ifdef __cplusplus
}
#endif
#endif
