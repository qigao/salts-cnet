#ifndef CNET_EVENT_H
#define CNET_EVENT_H

#include "cnet_session.h"

#include <memory/buffer.h>
#include <crypto/tls_diagnostic.h>

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef struct cnet_event_queue {
  void *impl;
  /* Admission must outlive impl so late publishers never touch reclaimed storage. */
  atomic_size_t _publisher_lifecycle;
} cnet_event_queue;

typedef struct cnet_event_queue_config {
  uint64_t capacity;
  size_t data_capacity;
  size_t max_payload_bytes;
  size_t payload_capacity_bytes;
  cnet_allocator storage;
} cnet_event_queue_config;

typedef struct cnet_event_queue_stats {
  size_t live_events;
  size_t live_payload_bytes;
  size_t peak_payload_bytes;
  uint64_t rejected_payload_bytes;
  bool admission_open;
} cnet_event_queue_stats;

typedef enum cnet_event_kind {
  CNET_EVENT_NONE = 0,
  CNET_EVENT_RECEIVE,
  CNET_EVENT_SEND,
  CNET_EVENT_STATE
} cnet_event_kind;

typedef enum cnet_event_state {
  CNET_EVENT_STATE_NONE = 0,
  CNET_EVENT_STATE_CONNECTED,
  CNET_EVENT_STATE_CLOSING,
  CNET_EVENT_STATE_CLOSED,
  CNET_EVENT_STATE_FAILED,
  CNET_EVENT_STATE_TLS_HANDSHAKING
} cnet_event_state;

/**
 * One owner-produced callback event. `data` is borrowed only during publish.
 * RECEIVE may additionally name a canonical retained `backing`; queue
 * publication retains that backing instead of copying DATA bytes. Events
 * without a backing preserve the bounded copied-payload path.
 */
typedef struct cnet_event {
  cnet_event_kind kind;
  cnet_session_handle session;
  cnet_event_state state;
  int status;
  cnet_session_stage stage;
  const void *data;
  size_t size;
  size_t argument;
  mem_buffer_t *backing;
  crypto_tls_diagnostic tls;
} cnet_event;

/** Single-consumer borrowed view; release invalidates `data`. */
typedef struct cnet_event_view {
  cnet_event_kind kind;
  cnet_session_handle session;
  cnet_event_state state;
  int status;
  cnet_session_stage stage;
  const void *data;
  size_t size;
  size_t argument;
  uint64_t _sequence;
  /** Canonical retained backing when publication supplied one; otherwise NULL. */
  mem_buffer_t *backing;
  crypto_tls_diagnostic tls;
} cnet_event_view;

typedef int (*cnet_event_keep_waiting_fn)(void *context);

int cnet_event_queue_init(cnet_event_queue *queue, const cnet_event_queue_config *config);
bool cnet_event_queue_get_config(const cnet_event_queue *queue,
                                 cnet_event_queue_config *out_config);
bool cnet_event_queue_get_stats(const cnet_event_queue *queue,
                                cnet_event_queue_stats *out_stats);

/**
 * MPSC, nonblocking; data and total capacity exhaustion return `SALTS_ENOBUFS`.
 * The wrapper must remain alive until every publisher has returned, including
 * publishers rejected after close/destroy. Reinitialization requires quiescence.
 */
int cnet_event_queue_publish(cnet_event_queue *queue, const cnet_event *event);

/** Single-consumer take; empty-open returns `SALTS_ETIMEDOUT`. */
int cnet_event_queue_take(cnet_event_queue *queue, cnet_event_view *out_view);
/** Sleeps without polling until an event arrives or `keep_waiting` becomes false and wakes. */
int cnet_event_queue_take_wait(cnet_event_queue *queue, cnet_event_view *out_view,
                               cnet_event_keep_waiting_fn keep_waiting, void *context);
/** Wakes blocked takers so they can re-check their stop predicate. */
int cnet_event_queue_wake(cnet_event_queue *queue);
/** A taken view may be released exactly once by its dispatcher consumer. */
int cnet_event_queue_release(cnet_event_queue *queue, cnet_event_view *view);

/** Stops new publication and returns `SALTS_EBUSY` until entered publishers leave. */
int cnet_event_queue_close(cnet_event_queue *queue);

/** Requires completed close, no borrowed views, and a fully drained, quiescent consumer. */
int cnet_event_queue_destroy(cnet_event_queue *queue);

#endif /* CNET_EVENT_H */
