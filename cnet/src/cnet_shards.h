#ifndef CNET_SHARDS_H
#define CNET_SHARDS_H

#include "cnet_owner.h"

typedef struct cnet_shards {
  void *impl;
} cnet_shards;

typedef struct cnet_shard_connection {
  uint32_t shard;
  cnet_session_handle session;
} cnet_shard_connection;

typedef struct cnet_shards_config {
  native_io_backend_kind backend_kind;
  /** Optional shared backend; production external-progress mode requires one shard. */
  native_io_backend *borrowed_backend;
  size_t shard_count;
  size_t connection_capacity_per_shard;
  size_t command_capacity_per_shard;
  size_t request_capacity_per_shard;
  size_t completion_batch_capacity;
  size_t event_capacity_per_shard;
  size_t receive_buffer_bytes;
  /** Additional copied state-event payload bound; zero when no protocol needs one. */
  size_t max_state_payload_bytes;
  size_t max_command_payload_bytes;
  size_t command_buffer_bytes;
  size_t write_capacity_per_shard;
  size_t max_write_payload_bytes;
  size_t event_buffer_bytes;
  cnet_resources resources;
} cnet_shards_config;

typedef struct cnet_shards_layout {
  size_t shard_count;
  size_t connection_capacity_per_shard;
  size_t max_event_payload_bytes;
} cnet_shards_layout;

typedef int (*cnet_shards_event_sink_fn)(void *context, uint32_t shard, const cnet_event *event);

bool cnet_shard_connection_valid(cnet_shard_connection connection);

/** Initializes the production single-owner layout without creating a worker thread. */
int cnet_shards_init(cnet_shards *shards, const cnet_shards_config *config);

#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
/**
 * Internal Phase-B1 POC only. Allows more than one bounded owner while keeping
 * the production cnet_shards_init() single-owner contract unchanged.
 */
int cnet_shards_init_multi_owner_experimental(cnet_shards *shards,
                                              const cnet_shards_config *config);
/** Initializes one deferred owner/backend on its final owner thread. */
int cnet_shards_init_owner_experimental(cnet_shards *shards, uint32_t shard);
#endif

bool cnet_shards_get_layout(const cnet_shards *shards, cnet_shards_layout *out_layout);

/** Advances the production single owner on the calling thread. */
int cnet_shards_poll(cnet_shards *shards, uint32_t timeout_ms);

/** Internal non-observing post-callback command/session progression. */
int cnet_shards_flush_deferred(cnet_shards *shards);

/** Non-observing progress for a single owner using a borrowed NativeIO backend. */
int cnet_shards_advance_external(cnet_shards *shards);
int cnet_shards_route_external_completion(cnet_shards *shards,
                                          const native_io_completion *completion,
                                          bool *out_consumed);
int cnet_shards_external_timeout(cnet_shards *shards, uint32_t max_wait_ms,
                                 uint32_t *out_timeout_ms);
int cnet_shards_external_requests(cnet_shards *shards,
                                  cnet_shard_connection connection,
                                  native_io_request *out_requests,
                                  size_t capacity,
                                  size_t *out_count);
int cnet_shards_external_request_snapshots(
    cnet_shards *shards,
    cnet_shard_connection connection,
    cnet_owner_external_request_snapshot *out_requests,
    size_t capacity,
    size_t *out_count);

#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
/** Internal Phase-B1 owner-specific progress; exactly one caller owns each shard. */
int cnet_shards_poll_owner(cnet_shards *shards, uint32_t shard,
                           uint32_t timeout_ms);
#endif

#if defined(CNET_INTERNAL_PROFILING)
/** Internal diagnostic sampling; caller must exclude concurrent poll/stop operations. */
int cnet_shards_profile_begin(cnet_shards *shards);
int cnet_shards_profile_trace_bind(cnet_shards *shards,
                                   cnet_owner_trace_event *events,
                                   size_t capacity);
int cnet_shards_profile_take(cnet_shards *shards, cnet_owner_profile *out_profile);
#endif

/** Thread-safe advisory wake for the production single owner blocked in poll. */
int cnet_shards_wake(cnet_shards *shards);

#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
/** Internal Phase-B1 advisory wake for one fixed owner. */
int cnet_shards_wake_owner(cnet_shards *shards, uint32_t shard);
#endif

/**
 * Binds the single event sink called directly by the caller-owned progress loop. The sink
 * must copy or retain event data before returning and must never block.
 */
int cnet_shards_bind_event_sink(cnet_shards *shards, cnet_shards_event_sink_fn sink, void *context);

/** Reserves one stable shard/session pair and publishes a copied connect command. */
int cnet_shards_connect(cnet_shards *shards, const cnet_owner_connect_payload *payload,
                        cnet_shard_connection *out_connection);
/** Owner-local retained send ownership paths; no generic command publication. */
int cnet_shards_send_buffer_direct(cnet_shards *shards, cnet_shard_connection connection,
                                   mem_buffer_t *buffer);
int cnet_shards_send_slice_direct(cnet_shards *shards, cnet_shard_connection connection,
                                  const mem_slice_t *slice);
int cnet_shards_send_slicev_direct(cnet_shards *shards, cnet_shard_connection connection,
                                   const mem_slice_t *segments, size_t segment_count);
int cnet_shards_send_slicev_close_direct(cnet_shards *shards,
                                         cnet_shard_connection connection,
                                         const mem_slice_t *segments,
                                         size_t segment_count);
int cnet_shards_send_buffer_close_direct(cnet_shards *shards,
                                         cnet_shard_connection connection,
                                         mem_buffer_t *buffer);
int cnet_shards_receive(cnet_shards *shards, cnet_shard_connection connection, size_t demand);
/**
 * Single-owner fast path used outside callbacks. Bypasses admission_lock and
 * the command queue; the owner starts I/O only from its next drive.
 */
int cnet_shards_receive_direct(cnet_shards *shards, cnet_shard_connection connection,
                               size_t demand);
int cnet_shards_start_tls(cnet_shards *shards, cnet_shard_connection connection,
                          const cnet_owner_start_tls_payload *payload);
int cnet_shards_close(cnet_shards *shards, cnet_shard_connection connection);
/** Single-owner quiescent close fast path; callbacks remain deferred to poll. */
int cnet_shards_close_direct(cnet_shards *shards, cnet_shard_connection connection);

int cnet_shards_state(cnet_shards *shards, cnet_shard_connection connection,
                      cnet_session_state *out_state);
int cnet_shards_tcp_local_peer(cnet_shards *shards, cnet_shard_connection connection,
                               cnet_stream_peer *out_peer);
int cnet_shards_tcp_remote_peer(cnet_shards *shards, cnet_shard_connection connection,
                                cnet_stream_peer *out_peer);
int cnet_shards_tcp_local_endpoint(
    cnet_shards *shards, cnet_shard_connection connection,
    cnet_stream_endpoint *out_endpoint);
int cnet_shards_tcp_remote_endpoint(
    cnet_shards *shards, cnet_shard_connection connection,
    cnet_stream_endpoint *out_endpoint);
int cnet_shards_tcp_option_get(cnet_shards *shards, cnet_shard_connection connection,
                               cnet_tcp_socket_option option, uint64_t *out_value);
int cnet_shards_tcp_option_set(cnet_shards *shards, cnet_shard_connection connection,
                               cnet_tcp_socket_option option, uint64_t value);
int cnet_shards_tcp_shutdown(cnet_shards *shards, cnet_shard_connection connection,
                             cnet_tcp_shutdown how);
int cnet_shards_preserve_send_on_eof(cnet_shards *shards, cnet_shard_connection connection);
int cnet_shards_tls_negotiated_version(cnet_shards *shards, cnet_shard_connection connection,
                                       char *buffer, size_t capacity, size_t *out_size);
int cnet_shards_tls_negotiated_cipher(cnet_shards *shards, cnet_shard_connection connection,
                                      char *buffer, size_t capacity, size_t *out_size);
int cnet_shards_tls_peer_certificate_sha256(cnet_shards *shards, cnet_shard_connection connection,
                                            char buffer[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY]);
int cnet_shards_tls_server_end_point_binding(
    cnet_shards *shards, cnet_shard_connection connection,
    uint8_t *output, size_t capacity, size_t *out_size);
int cnet_shards_tls_export_channel_binding(cnet_shards *shards, cnet_shard_connection connection,
                                           uint8_t output[CNET_TLS_CHANNEL_BINDING_BYTES]);
int cnet_shards_take_event(cnet_shards *shards, uint32_t shard, cnet_event_view *out_event);
int cnet_shards_release_event(cnet_shards *shards, uint32_t shard, cnet_event_view *event);

/** Consumes the terminal record and releases the stable shard assignment. */
int cnet_shards_recycle(cnet_shards *shards, cnet_shard_connection connection,
                        cnet_session_terminal *out_terminal);

/**
 * Closes a quiescent owner. Live connections return SALTS_EBUSY; client stop
 * closes and drives them first.
 */
int cnet_shards_stop(cnet_shards *shards, uint32_t timeout_ms);
bool cnet_shards_stopped(const cnet_shards *shards);
int cnet_shards_destroy(cnet_shards *shards);

#endif /* CNET_SHARDS_H */
