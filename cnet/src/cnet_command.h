#ifndef CNET_COMMAND_H
#define CNET_COMMAND_H

#include "cnet_session.h"

#include <cnet/cnet.h>

#include <stddef.h>
#include <stdint.h>

typedef struct cnet_command_queue {
  void *impl;
} cnet_command_queue;

typedef struct cnet_command_queue_config {
  uint64_t capacity;
  size_t max_payload_bytes;
  /** Aggregate live copied-payload budget; zero preserves capacity times max payload. */
  size_t payload_capacity_bytes;
  cnet_allocator storage;
} cnet_command_queue_config;

typedef struct cnet_command_queue_stats {
  size_t live_commands;
  size_t peak_commands;
  /** Copied payload bytes retained by live commands; retained buffers do not consume this budget. */
  size_t queued_bytes;
  size_t peak_queued_bytes;
  uint64_t rejected_commands;
  uint64_t rejected_bytes;
  bool admission_open;
} cnet_command_queue_stats;

#if defined(CNET_INTERNAL_PROFILING)
/**
 * Inclusive command-publication timing collected only during an explicit
 * diagnostic sample. `publish_ns` covers every successful command;
 * `payload_publish_ns` covers successful payload-bearing commands and includes
 * `payload_copy_ns` only for copied payloads.
 */
typedef struct cnet_command_queue_profile {
  uint64_t publish_ns;
  uint64_t payload_publish_ns;
  uint64_t payload_copy_ns;
  uint64_t publish_calls;
  uint64_t payload_publish_calls;
  uint64_t payload_copy_calls;
} cnet_command_queue_profile;
#endif

typedef enum cnet_command_kind {
  CNET_COMMAND_NONE = 0,
  CNET_COMMAND_CONNECT,
  CNET_COMMAND_RECEIVE,
  CNET_COMMAND_START_TLS,
  CNET_COMMAND_CLOSE,
  CNET_COMMAND_STOP
} cnet_command_kind;

/** One producer-owned control descriptor. Payload bytes are copied on publication. */
typedef struct cnet_command {
  cnet_command_kind kind;
  cnet_session_handle connection;
  const void *data;
  size_t size;
  size_t argument;
} cnet_command;

/**
 * One owner-only borrowed queue view. `data` becomes invalid when the view is
 * released. The underscored sequence is an opaque release token.
 */
typedef struct cnet_command_view {
  cnet_command_kind kind;
  cnet_session_handle connection;
  const void *data;
  size_t size;
  size_t argument;
  uint64_t _sequence;
} cnet_command_view;

int cnet_command_queue_init(cnet_command_queue *queue, const cnet_command_queue_config *config);

/** Single-owner, nonblocking; full capacity returns `SALTS_ENOBUFS`. */
int cnet_command_queue_publish(cnet_command_queue *queue, const cnet_command *command);

/** Single-owner, nonblocking; empty-open returns `SALTS_ETIMEDOUT`. */
int cnet_command_queue_take(cnet_command_queue *queue, cnet_command_view *out_view);
int cnet_command_queue_release(cnet_command_queue *queue, cnet_command_view *view);

/**
 * Closes admission on the owner thread. A repeated close returns
 * `SALTS_EALREADY`.
 */
int cnet_command_queue_close(cnet_command_queue *queue);

/** Returns one owner-thread diagnostic snapshot. */
bool cnet_command_queue_get_stats(const cnet_command_queue *queue,
                                  cnet_command_queue_stats *out_stats);

#if defined(CNET_INTERNAL_PROFILING)
/** Starts one diagnostic sample and clears the previous sample. */
int cnet_command_queue_profile_begin(cnet_command_queue *queue);
/** Takes the current diagnostic sample and disables command profiling. */
int cnet_command_queue_profile_take(cnet_command_queue *queue,
                                    cnet_command_queue_profile *out_profile);
#endif

/** Requires closed admission, no borrowed view, and a fully drained queue. */
int cnet_command_queue_destroy(cnet_command_queue *queue);

#endif /* CNET_COMMAND_H */
