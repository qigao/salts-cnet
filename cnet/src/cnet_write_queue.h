#ifndef CNET_WRITE_QUEUE_H
#define CNET_WRITE_QUEUE_H

#include "cnet_session.h"

#include <cnet/cnet.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct cnet_write_queue {
  void *impl;
} cnet_write_queue;

typedef struct cnet_write_queue_config {
  size_t connection_capacity;
  size_t capacity;
  size_t max_payload_bytes;
  cnet_allocator storage;
} cnet_write_queue_config;

typedef struct cnet_write_handle {
  uint32_t slot;
  uint32_t generation;
} cnet_write_handle;

typedef struct cnet_write_view {
  cnet_write_handle handle;
  cnet_session_handle connection;
  const void *data;
  size_t size;
  size_t offset;
  size_t remaining;
  bool vector_write;
  bool close_after_send;
  uint64_t _token;
} cnet_write_view;

typedef struct cnet_write_queue_stats {
  size_t live_writes;
  size_t peak_writes;
  size_t capacity;
  size_t connection_capacity;
  bool admission_open;
} cnet_write_queue_stats;

bool cnet_write_handle_valid(cnet_write_handle handle);

int cnet_write_queue_init(cnet_write_queue *queue, const cnet_write_queue_config *config);

int cnet_write_queue_enqueue_buffer(cnet_write_queue *queue, cnet_session_handle connection,
                                    mem_buffer_t *buffer, bool close_after_send,
                                    cnet_write_handle *out_handle);

int cnet_write_queue_enqueue_slice(cnet_write_queue *queue, cnet_session_handle connection,
                                   const mem_slice_t *slice, bool close_after_send,
                                   cnet_write_handle *out_handle);

int cnet_write_queue_enqueue_slicev(cnet_write_queue *queue, cnet_session_handle connection,
                                    const mem_slice_t *segments, size_t segment_count,
                                    bool close_after_send, cnet_write_handle *out_handle);

/** Returns the current per-connection FIFO head. Empty-open returns SALTS_ETIMEDOUT. */
int cnet_write_queue_peek(cnet_write_queue *queue, cnet_session_handle connection,
                          cnet_write_view *out_view);

/**
 * Returns the largest current retained-vector prefix that is byte-contiguous
 * inside one backing buffer. This is a read-only view for consumers such as
 * TLS that accept contiguous plaintext; the logical vector boundaries remain
 * unchanged for NativeIO scatter/gather submission.
 */
int cnet_write_queue_build_contiguous(cnet_write_queue *queue,
                                      const cnet_write_view *view, size_t max_bytes,
                                      const void **out_data, size_t *out_bytes);

/**
 * Rebuilds the current retained-vector suffix directly from stable write-slot
 * ownership. max_bytes bounds this one native submission without mutating the
 * logical cursor.
 */
int cnet_write_queue_build_vector(cnet_write_queue *queue, const cnet_write_view *view,
                                  size_t max_bytes,
                                  native_io_buffer_span out_spans[NATIVE_IO_VECTOR_MAX],
                                  size_t *out_count, size_t *out_bytes);

/** Advances the current FIFO head after one successful partial native write. */
int cnet_write_queue_advance(cnet_write_queue *queue, cnet_write_view *view, size_t bytes);

/**
 * Removes and releases the current FIFO head after logical success/failure.
 * The view is cleared on success.
 */
int cnet_write_queue_settle(cnet_write_queue *queue, cnet_write_view *view);

/** Returns the live logical-write count for one generation-checked connection. */
int cnet_write_queue_count(cnet_write_queue *queue, cnet_session_handle connection,
                           size_t *out_count);

/** Removes exactly the matching per-connection FIFO tail; used for admission rollback. */
int cnet_write_queue_cancel_tail(cnet_write_queue *queue, cnet_session_handle connection,
                                 cnet_write_handle handle);

/**
 * Releases queued logical writes for one connection. keep_head preserves the
 * current FIFO head when it is already owned by an active NativeIO request.
 */
int cnet_write_queue_discard(cnet_write_queue *queue, cnet_session_handle connection,
                             bool keep_head, size_t *out_discarded);

int cnet_write_queue_close(cnet_write_queue *queue);
bool cnet_write_queue_get_stats(const cnet_write_queue *queue,
                                cnet_write_queue_stats *out_stats);

/** Requires closed admission and no live write slots. */
int cnet_write_queue_destroy(cnet_write_queue *queue);

#endif /* CNET_WRITE_QUEUE_H */
