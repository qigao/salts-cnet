#ifndef CNET_WEBSOCKET_H
#define CNET_WEBSOCKET_H

#include <salts/error_codes.h>
#include <memory/buffer.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  CNET_WEBSOCKET_MAX_HEADER_BYTES = 14,
  CNET_WEBSOCKET_MAX_CONTROL_BYTES = 125,
  CNET_WEBSOCKET_MIN_FRAME_BYTES = 2,
  CNET_WEBSOCKET_CLOSE_NORMAL = 1000,
  CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR = 1002,
  CNET_WEBSOCKET_CLOSE_INVALID_TEXT = 1007,
  CNET_WEBSOCKET_CLOSE_MESSAGE_TOO_BIG = 1009,
  CNET_WEBSOCKET_CLOSE_ABNORMAL = 1006,
  CNET_WEBSOCKET_WRITE_PENDING = 1
};

typedef struct cnet_websocket {
  void *impl;
} cnet_websocket;

typedef enum cnet_websocket_role {
  CNET_WEBSOCKET_CLIENT = 1,
  CNET_WEBSOCKET_SERVER
} cnet_websocket_role;

typedef enum cnet_websocket_state {
  CNET_WEBSOCKET_OPEN = 1,
  CNET_WEBSOCKET_CLOSING,
  CNET_WEBSOCKET_CLOSED,
  CNET_WEBSOCKET_FAILED
} cnet_websocket_state;

typedef enum cnet_websocket_message_type {
  CNET_WEBSOCKET_MESSAGE_NONE = 0,
  CNET_WEBSOCKET_MESSAGE_TEXT,
  CNET_WEBSOCKET_MESSAGE_BINARY
} cnet_websocket_message_type;

typedef enum cnet_websocket_event_kind {
  CNET_WEBSOCKET_EVENT_MESSAGE = 1,
  CNET_WEBSOCKET_EVENT_PING,
  CNET_WEBSOCKET_EVENT_PONG,
  CNET_WEBSOCKET_EVENT_CLOSE
} cnet_websocket_event_kind;

/** Event data is borrowed only until the event callback returns. */
typedef struct cnet_websocket_event {
  cnet_websocket_event_kind kind;
  cnet_websocket_message_type message_type;
  const uint8_t *data;
  size_t size;
  uint16_t close_code;
} cnet_websocket_event;

/**
 * Write one complete frame.
 *
 * SALTS_OK means the frame reached a synchronous terminal before return.
 * SALTS_EBUSY means the frame was not admitted and remains queued for retry.
 * CNET_WEBSOCKET_WRITE_PENDING is valid only when config.output_buffer is
 * supplied: async retained admission succeeded, the engine freezes that frame,
 * and the owner must later call cnet_websocket_write_complete() from the
 * authoritative transport terminal.
 */
typedef int (*cnet_websocket_write_fn)(void *user, const uint8_t *data, size_t size);
typedef void (*cnet_websocket_event_fn)(void *user, cnet_websocket *websocket,
                                        const cnet_websocket_event *event);

typedef struct cnet_websocket_config {
  size_t size;
  cnet_websocket_role role;
  size_t max_frame_bytes;
  size_t max_message_bytes;
  size_t max_buffered_input_bytes;
  cnet_websocket_write_fn write;
  cnet_websocket_event_fn on_event;
  void *user;
  mem_buffer_t *output_buffer;
} cnet_websocket_config;

/**
 * Initialize fixed-capacity input, message, and one-frame output storage.
 * The session is single-owner and performs no I/O or thread creation itself.
 *
 * @param websocket Zero-initialized caller-owned wrapper.
 * @param config Role, hard byte limits, callbacks, and callback context.
 * max_frame_bytes must be at least CNET_WEBSOCKET_MIN_FRAME_BYTES so a
 * protocol-error Close status can always be admitted.
 * @return SALTS_OK, SALTS_EINVAL for an invalid configuration, SALTS_ERANGE
 * for capacity arithmetic overflow, or SALTS_ENOMEM.
 */
int cnet_websocket_init(cnet_websocket *websocket, const cnet_websocket_config *config);

#define CNET_WEBSOCKET_TAGGED_SEND_VERSION 1u

/** One terminal per admitted logical message; size is the original payload size.
 * Runs only from advance(), after send_tagged() has returned. Success proves
 * local transport completion, not peer application receipt. No payload is borrowed.
 */
typedef void (*cnet_websocket_send_complete_fn)(void *user, cnet_websocket *websocket,
                                                uint64_t tag, size_t size, int status);

/** Explicit opt-in to authoritative write terminals; legacy copied-admission
 * writers must not enable this policy. SALTS_OK from write must mean complete
 * synchronous transport success; async adapters use WRITE_PENDING/write_complete.
 */
typedef struct cnet_websocket_tagged_policy {
  size_t size;
  uint32_t version;
  size_t fragment_bytes;
  cnet_websocket_send_complete_fn on_send;
  void *user;
} cnet_websocket_tagged_policy;

/**
 * Initializes a tagged-send session with one extra max_message_bytes owned
 * buffer and one terminal record. fragment_bytes must be in [1,max_frame_bytes].
 * Existing config layout is unchanged. Returns init errors, SALTS_ERANGE for
 * total storage overflow, or SALTS_EINVAL for an invalid policy/version.
 * Failure leaves the wrapper uninitialized; existing live wrappers are unchanged.
 */
int cnet_websocket_init_tagged(cnet_websocket *websocket, const cnet_websocket_config *config,
                                const cnet_websocket_tagged_policy *policy);

/**
 * Copies one complete text/binary message into bounded owned storage; performs
 * no write and no callback. Empty messages are valid. Strict UTF-8 is validated
 * before text admission. Exactly one terminal follows successful admission,
 * including close/error; rejected admission has no terminal.
 * Returns SALTS_OK, SALTS_EINVAL, SALTS_ENOTSUP without tagged policy,
 * SALTS_EMSGSIZE, SALTS_ECHARSET, SALTS_ESHUTDOWN, or SALTS_EBUSY while a prior
 * tag/legacy fragment/output is pending. Legacy data sends cannot interleave.
 */
int cnet_websocket_send_tagged(cnet_websocket *websocket,
                                cnet_websocket_message_type message_type,
                                const void *data, size_t size, uint64_t tag);

/**
 * Owner-local nonblocking progress for tagged sessions. Attempts at most
 * max_frames queued/new output frames, processes bounded buffered input, and
 * dispatches at most one logical send terminal into *out_events. Both arguments
 * are required (max_frames > 0). Call after admission, writer capacity recovery,
 * write_complete, and close/transport_closed, even without another send.
 * Async-pending output is never retried. Busy transport is normal zero-event
 * progress; other transport/protocol errors are returned after preserving the
 * reserved terminal. Continue advance/drain on error until terminals dispatch.
 * Returns SALTS_OK, SALTS_EINVAL, SALTS_ENOTSUP, SALTS_EBUSY for recursion, or
 * the progress error. Destroy remains busy while an accepted tag is unsettled.
 */
int cnet_websocket_advance(cnet_websocket *websocket, size_t max_frames, size_t *out_events);

/** Destroy all fixed storage. Active callback/feed/write execution returns SALTS_EBUSY. */
int cnet_websocket_destroy(cnet_websocket *websocket);

/** Copy the current state into out_state. */
int cnet_websocket_state_get(const cnet_websocket *websocket, cnet_websocket_state *out_state);

/** Copy the first terminal error, or SALTS_OK when no terminal error exists. */
int cnet_websocket_last_error(const cnet_websocket *websocket, int *out_status);

/** Return true while exactly one complete output frame is retained for retry. */
bool cnet_websocket_has_pending_output(const cnet_websocket *websocket);

/**
 * Copy and process an ordered byte-stream chunk. When one output frame is
 * retained for backpressure, further feed calls return SALTS_EBUSY without
 * consuming their input until cnet_websocket_flush() succeeds.
 *
 * @return SALTS_OK, SALTS_EINVAL, SALTS_EBUSY, SALTS_ENOSPC,
 * SALTS_ESHUTDOWN, or the terminal protocol/charset/size/write error.
 */
int cnet_websocket_feed(cnet_websocket *websocket, const void *data, size_t size);

/**
 * Retry the retained frame, then process already buffered input on success.
 * SALTS_EBUSY means that retained frame is still blocked. SALTS_OK confirms
 * that retry transferred, but buffered input may immediately admit one new
 * retained frame; inspect cnet_websocket_has_pending_output(). Other write
 * errors are terminal and move the session to CNET_WEBSOCKET_FAILED.
 */
int cnet_websocket_flush(cnet_websocket *websocket);

/**
 * Settle one async retained output admitted with CNET_WEBSOCKET_WRITE_PENDING.
 *
 * status == SALTS_OK requires bytes to equal the complete retained frame size.
 * A successful terminal clears that frame and resumes buffered input/state
 * progress. A failed terminal records status and makes the session FAILED.
 */
int cnet_websocket_write_complete(cnet_websocket *websocket, size_t bytes, int status);

/**
 * Send one data fragment. message_type identifies the complete message on
 * every fragment; the engine selects Text/Binary versus Continuation opcodes.
 * Text validation may span fragments and final_fragment requires a complete
 * UTF-8 sequence.
 *
 * All cnet_websocket_send_* functions return SALTS_OK when the complete frame
 * was transferred or copied into the single retained slot after transport
 * backpressure. While that slot is occupied, further sends return SALTS_EBUSY.
 * A non-backpressure write error is returned and makes the session terminal.
 */
int cnet_websocket_send_fragment(cnet_websocket *websocket,
                                 cnet_websocket_message_type message_type, const void *data,
                                 size_t size, bool final_fragment);

/** Send one complete, strictly valid UTF-8 text message. */
int cnet_websocket_send_text(cnet_websocket *websocket, const void *data, size_t size);

/** Send one complete binary message. */
int cnet_websocket_send_binary(cnet_websocket *websocket, const void *data, size_t size);

/** Send an unfragmented Ping control frame with at most 125 payload bytes. */
int cnet_websocket_send_ping(cnet_websocket *websocket, const void *data, size_t size);

/** Send an unfragmented Pong control frame with at most 125 payload bytes. */
int cnet_websocket_send_pong(cnet_websocket *websocket, const void *data, size_t size);

/**
 * Start the closing handshake. Code zero sends an empty Close payload and
 * requires an empty reason; a non-empty reason must be strict UTF-8.
 * An accepted tagged message returns EBUSY until advance dispatches its terminal;
 * continue progress then retry close. The adapter owns the close deadline and
 * drains transport writes before reporting an abort through transport_closed.
 * SALTS_OK includes admission into the retained slot after transport
 * backpressure; inspect cnet_websocket_has_pending_output().
 */
int cnet_websocket_close(cnet_websocket *websocket, uint16_t code, const void *reason,
                         size_t reason_size);

/**
 * Notify the engine after terminal transport EOF/close. Unless the session is
 * already FAILED or a Close event was previously delivered, an incomplete
 * closing handshake publishes one borrowed Close event with code 1006 and no
 * wire data. Active/reentrant execution returns SALTS_EBUSY; an already CLOSED
 * session returns SALTS_EALREADY.
 */
/* Call only after the adapter has drained all transport borrows of output.
 * In tagged mode this cancels an unfinished message; advance dispatches its
 * terminal. Notification of a socket error alone does not prove drain. */
int cnet_websocket_transport_closed(cnet_websocket *websocket);

#ifdef __cplusplus
}
#endif

#endif /* CNET_WEBSOCKET_H */
