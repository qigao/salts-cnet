#include <cnet/cnet.h>
#include <cnet/ipc.h>
#include <cnet/websocket_transport.h>

#include "cnet_client_internal.h"
#include "cnet_resources.h"
#include "cnet_reuse.h"
#include "cnet_dispatcher.h"
#include "cnet_module.h"
#include "cnet_shards.h"
#include "cnet_transport.h"
#include "cnet_uri.h"

#include <clock.h>
#include <thread.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct cnet_client_impl cnet_client_impl;
typedef struct cnet_ws_transport_impl {
  cnet_client *client;
  cnet_connection connection;
  cnet_websocket websocket;
  mem_buffer_t *output;
  cnet_websocket_event_fn on_event;
  void *event_user;
  const void *owner;
  int error;
  bool submitting;
  bool pending;
  bool terminal;
} cnet_ws_transport_impl;

static void cnet_ws_sent(cnet_ws_transport_impl *bridge, size_t size);
static void cnet_ws_terminal(cnet_ws_transport_impl *bridge, int status);

typedef struct cnet_send_record {
  cnet_operation operation;
  cnet_send_complete_fn complete;
  void *user;
  size_t bytes, backing_bytes, next;
} cnet_send_record;
static atomic_uint_fast64_t cnet_operation_sequence;

typedef struct cnet_client_record {
  cnet_client_impl *client;
  cnet_shard_connection internal;
  cnet_connection public_handle;
  cnet_observer observer;
  cnet_ws_transport_impl *ws_transport;
  cnet_receive_slice_fn receive_slice_handler;
  void *receive_slice_user;
  cnet_uri_scheme scheme;
  size_t negotiated_alpn_size;
  size_t receive_pending;
  uint8_t tcp_shutdown_mask;
  char negotiated_alpn[CNET_TLS_ALPN_NAME_MAX_BYTES + 1u];
  /* Public-handle/observer slot occupancy; not CNet session lifecycle truth. */
  bool active;
  /** Number of admitted logical writes not yet settled by send/terminal callback. */
  size_t pending_writes;
  size_t send_head, send_tail;
  cnet_send_usage send_usage;
  /* Same-owner command reservations only; canonical lifecycle lives in cnet_session_table. */
  bool close_command_pending;
  bool tls_command_pending;
  bool preserve_send_on_eof;
} cnet_client_record;

struct cnet_client_impl {
  const void *owner_thread;
  cnet_resources resources;
  cnet_send_limits send_limits;
  cnet_send_admission_policy send_admission;
  cnet_send_usage send_usage;
  cnet_send_record *sends;
  size_t send_free;
  bool evaluating_policy;
  cnet_shards shards;
  cnet_dispatcher dispatcher;
  cnet_client_record *records;
  /** Synchronizes only poll/profile/wake/stop/destroy control-plane overlap. */
  cmeta_mutex_t control_lock;
  size_t shard_count;
  size_t capacity_per_shard;
  size_t record_count;
  size_t connection_capacity;
  size_t active_count;
  size_t max_send_bytes;
  size_t tls_io_buffer_bytes;
  native_io_backend_kind backend_kind;
  cnet_stream_socket_options socket_options;
  uint32_t connect_timeout_ms;
  uint32_t read_timeout_ms;
  uint32_t write_timeout_ms;
  uint32_t tls_handshake_timeout_ms;
  atomic_int callback_error;
  atomic_int external_wake_pending;
  size_t poll_callback_count;
  bool admission_open;
  bool external_progress;
  bool poll_active;
  bool stop_active;
  bool stopped;
#if defined(CNET_INTERNAL_PROFILING)
  uint64_t profile_client_poll_ns;
  uint64_t profile_client_poll_calls;
  bool profile_active;
#endif
};

static SALTS_THREAD_LOCAL cnet_client_impl *cnet_active_callback_client;
static SALTS_THREAD_LOCAL cnet_client_impl *cnet_active_policy_client;

static cnet_client_impl *cnet_client_get(cnet_client *client) {
  cnet_client_impl *impl = client != NULL ? (cnet_client_impl *)client->impl : NULL;
  return impl != NULL && impl == cnet_active_policy_client ? NULL : impl;
}

static bool cnet_power_of_two(size_t value) { return value != 0u && (value & (value - 1u)) == 0u; }

static bool cnet_client_config_valid(const cnet_client_config *config) {
  if (config == NULL || !native_io_backend_kind_supported(config->backend) ||
      config->connection_capacity == 0u || !cnet_power_of_two(config->command_capacity) ||
      config->request_capacity == 0u || config->completion_batch_capacity == 0u ||
      config->completion_batch_capacity > config->request_capacity ||
      !cnet_power_of_two(config->event_capacity) || config->event_capacity < 2u ||
      config->max_send_bytes == 0u || config->receive_buffer_bytes == 0u ||
      !cnet_resources_valid(&config->resources) ||
      (config->send_admission.evaluate == NULL && config->send_admission.user != NULL) ||
      (config->event_buffer_bytes != 0u &&
       config->event_buffer_bytes < config->receive_buffer_bytes) ||
      ((config->tls_io_buffer_bytes == 0u) != (config->tls_handshake_timeout_ms == 0u)) ||
      (config->tls_io_buffer_bytes != 0u &&
       (config->tls_io_buffer_bytes < CNET_TLS_MIN_IO_BUFFER_BYTES ||
        config->tls_io_buffer_bytes > INT_MAX)))
    return false;
  return config->connection_capacity <= UINT32_MAX &&
         config->connection_capacity <= SIZE_MAX / sizeof(cnet_client_record);
}

static uint32_t cnet_client_remaining_ms(uint64_t started_ms, uint32_t timeout_ms) {
  const uint64_t elapsed = cmeta_monotonic_ms() - started_ms;
  return elapsed >= timeout_ms ? 0u : timeout_ms - (uint32_t)elapsed;
}

static void cnet_client_record_error(cnet_client_impl *impl, int status) {
  int expected = SALTS_OK;
  if (status == SALTS_OK) return;
  (void)atomic_compare_exchange_strong_explicit(&impl->callback_error, &expected, status,
                                                memory_order_acq_rel, memory_order_acquire);
}

static int cnet_client_dispatch(void *context, uint32_t shard, const cnet_event *event) {
  return cnet_dispatcher_publish((cnet_dispatcher *)context, shard, event);
}

static bool cnet_client_cmeta_status(int status) {
  if (status == SALTS_OK) return true;
  switch (status) {
#define CNET_STATUS_CASE(name, value, name_text, message_text)                                     \
  case name:                                                                                       \
    return true;
    SALTS_ERROR_CODE_ITEMS(CNET_STATUS_CASE)
#undef CNET_STATUS_CASE
  default:
    return false;
  }
}

static const char *cnet_client_stage_name(cnet_session_stage stage) {
  switch (stage) {
  case CNET_SESSION_STAGE_RESOLVE:
    return "resolve";
  case CNET_SESSION_STAGE_CONNECT:
    return "connect";
  case CNET_SESSION_STAGE_HANDSHAKE:
    return "handshake";
  case CNET_SESSION_STAGE_READ:
    return "read";
  case CNET_SESSION_STAGE_WRITE:
    return "write";
  case CNET_SESSION_STAGE_SHUTDOWN:
    return "shutdown";
  case CNET_SESSION_STAGE_CALLBACK:
    return "callback";
  default:
    return "unknown";
  }
}

static cnet_connection_state cnet_client_state(cnet_event_state state) {
  switch (state) {
  case CNET_EVENT_STATE_CONNECTED:
    return CNET_CONNECTION_CONNECTED;
  case CNET_EVENT_STATE_CLOSING:
    return CNET_CONNECTION_CLOSING;
  case CNET_EVENT_STATE_CLOSED:
    return CNET_CONNECTION_CLOSED;
  case CNET_EVENT_STATE_FAILED:
    return CNET_CONNECTION_FAILED;
  case CNET_EVENT_STATE_TLS_HANDSHAKING:
    return CNET_CONNECTION_TLS_HANDSHAKING;
  default:
    return CNET_CONNECTION_FAILED;
  }
}

static bool cnet_client_terminal(cnet_event_state state) {
  return state == CNET_EVENT_STATE_CLOSED || state == CNET_EVENT_STATE_FAILED;
}

static int cnet_client_materialize_receive(cnet_client_impl *impl, const cnet_dispatch_view *view,
                                           mem_slice_t *out_slice) {
  mem_buffer_t *buffer;
  if (view == NULL || out_slice == NULL || view->kind != CNET_EVENT_RECEIVE ||
      (view->size != 0u && view->data == NULL))
    return SALTS_EINVAL;
  memset(out_slice, 0, sizeof(*out_slice));
  if (view->size == 0u) return SALTS_OK;

  if (view->backing != NULL) {
    if (view->data != mem_buffer_const_data(view->backing) ||
        view->size > mem_buffer_used(view->backing))
      return SALTS_EPROTO;
    *out_slice = mem_slice(view->backing, 0u, view->size);
    return out_slice->buffer != NULL ? SALTS_OK : SALTS_ENOMEM;
  }

  /*
   * Compatibility path for internal/legacy receive events that do not carry
   * canonical ownership. Producer-owned CNet receive events should never need
   * this materialization after #595.
   */
  const int acquire_status = cnet_buffer_acquire(&impl->resources.receive, view->size, &buffer);
  if (acquire_status != SALTS_OK) return acquire_status;
  memcpy(mem_buffer_data(buffer), view->data, view->size);
  mem_set_used(buffer, view->size);
  *out_slice = mem_slice(buffer, 0u, view->size);
  mem_buffer_release(buffer);
  return out_slice->buffer != NULL ? SALTS_OK : SALTS_ENOMEM;
}

static void cnet_client_send_settle(cnet_client_record *record, int status) {
  cnet_client_impl *impl = record->client;
  if (record->send_head == 0u) { cnet_client_record_error(impl, SALTS_EPROTO); return; }
  const size_t slot = record->send_head;
  const cnet_send_record saved = impl->sends[slot - 1u];
  const cnet_send_result result = {saved.operation, record->public_handle, saved.bytes, status};
  record->send_head = saved.next;
  if (record->send_head == 0u) record->send_tail = 0u;
  --record->send_usage.operations;
  record->send_usage.bytes -= saved.bytes;
  record->send_usage.backing_bytes -= saved.backing_bytes;
  --impl->send_usage.operations;
  impl->send_usage.bytes -= saved.bytes;
  impl->send_usage.backing_bytes -= saved.backing_bytes;
  impl->sends[slot - 1u] = (cnet_send_record){.next = impl->send_free};
  impl->send_free = slot;
  if (saved.complete != NULL) {
    saved.complete(saved.user, &result);
    ++impl->poll_callback_count;
  }
}

static void cnet_client_observe(void *context, const cnet_dispatch_view *view) {
  cnet_client_record *record = (cnet_client_record *)context;
  cnet_client_impl *impl = record->client;
  cnet_client_impl *previous = cnet_active_callback_client;

  cnet_active_callback_client = impl;
  if (view->kind == CNET_EVENT_STATE && cnet_client_terminal(view->state)) {
    record->close_command_pending = true;
    while (record->send_head != 0u)
      cnet_client_send_settle(record, view->state == CNET_EVENT_STATE_FAILED
          ? (cnet_client_cmeta_status(view->status) ? view->status : SALTS_EIO)
          : SALTS_ECANCELED);
  }
  if (view->kind == CNET_EVENT_RECEIVE) {
    const bool peer_eof = record->preserve_send_on_eof && record->scheme == CNET_URI_TCP && view->size == 0u;
    const cnet_message_kind kind =
        record->scheme == CNET_URI_UDP ? CNET_MESSAGE_DATAGRAM : CNET_MESSAGE_BYTES;
    const bool receive_shutdown =
        record->scheme == CNET_URI_TCP &&
        (record->tcp_shutdown_mask &
         (uint8_t)CNET_TCP_SHUTDOWN_RECEIVE) != 0u;
    if (record->active && record->internal.session.slot == view->session.slot &&
        record->internal.session.generation == view->session.generation) {
      if (!receive_shutdown) {
        if (record->receive_pending == 0u) cnet_client_record_error(impl, SALTS_EPROTO);
        else --record->receive_pending;
      }
    }
    if (peer_eof) {
      record->tcp_shutdown_mask |= (uint8_t)CNET_TCP_SHUTDOWN_RECEIVE;
      record->receive_pending = 0u;
    }
    if (receive_shutdown) {
      /*
       * WASI-style receive shutdown discards already-queued receive data.
       * Dispatcher-owned backing is released after this observer returns.
       */
    } else if (record->receive_slice_handler != NULL) {
      mem_slice_t slice = {0};
      const int materialize_status = cnet_client_materialize_receive(impl, view, &slice);
      if (materialize_status != SALTS_OK) {
        cnet_client_record_error(impl, materialize_status);
      } else {
        /*
         * Ownership of this single retained slice reference transfers to the
         * callback by value. CNet must not release it after invocation.
         */
        record->receive_slice_handler(record->receive_slice_user, record->public_handle,
                                      slice, kind);
        ++impl->poll_callback_count;
      }
    } else if (record->observer.on_receive != NULL) {
      const cnet_receive_view public_view = {view->data, view->size, kind};
      record->observer.on_receive(record->observer.user, record->public_handle, &public_view);
      ++impl->poll_callback_count;
    }
  } else if (view->kind == CNET_EVENT_SEND) {
    if (record->active && record->internal.session.slot == view->session.slot &&
        record->internal.session.generation == view->session.generation) {
      if (record->pending_writes == 0u) cnet_client_record_error(impl, SALTS_EPROTO);
      else --record->pending_writes;
    }
    cnet_client_send_settle(record, SALTS_OK);
    if (record->ws_transport != NULL) {
      cnet_ws_sent(record->ws_transport, view->argument);
      ++impl->poll_callback_count;
    } else if (record->observer.on_send != NULL) {
      record->observer.on_send(record->observer.user, record->public_handle, view->argument);
      ++impl->poll_callback_count;
    }
  } else if (view->kind == CNET_EVENT_STATE && record->observer.on_state != NULL) {
    cnet_error error;
    const cnet_error *error_view = NULL;
    if (view->state == CNET_EVENT_STATE_CONNECTED) {
      record->tls_command_pending = false;
      record->negotiated_alpn_size = view->size;
      if (view->size != 0u && view->size <= CNET_TLS_ALPN_NAME_MAX_BYTES) {
        memcpy(record->negotiated_alpn, view->data, view->size);
        record->negotiated_alpn[view->size] = '\0';
      }
    }
    if (view->state == CNET_EVENT_STATE_FAILED) {
      error.status = cnet_client_cmeta_status(view->status) ? view->status : SALTS_EIO;
      error.native_status = cnet_client_cmeta_status(view->status) ? 0 : view->status;
      error.stage = cnet_client_stage_name(view->stage);
      error_view = &error;
    }
    if (cnet_client_terminal(view->state) && record->ws_transport != NULL) {
      cnet_ws_transport_impl *bridge = record->ws_transport;
      record->ws_transport = NULL;
      cnet_ws_terminal(bridge, error_view != NULL ? error_view->status : SALTS_ECANCELED);
    }
    record->observer.on_state(record->observer.user, record->public_handle,
                              cnet_client_state(view->state), error_view);
    ++impl->poll_callback_count;
  }
  cnet_active_callback_client = previous;

  if (view->kind == CNET_EVENT_STATE && cnet_client_terminal(view->state)) {
    if (record->active && record->internal.session.slot == view->session.slot &&
        record->internal.session.generation == view->session.generation) {
      record->active = false;
      record->pending_writes = 0u;
      record->close_command_pending = false;
      record->tls_command_pending = false;
      record->receive_pending = 0u;
      record->observer = (cnet_observer){0};
      record->receive_slice_handler = NULL;
      record->receive_slice_user = NULL;
      record->negotiated_alpn_size = 0u;
      record->negotiated_alpn[0] = '\0';
      if (impl->active_count == 0u) cnet_client_record_error(impl, SALTS_EPROTO);
      else --impl->active_count;
    }
  }
}

static void cnet_client_cleanup_init(cnet_client_impl *impl) {
  if (impl == NULL) return;
  if (impl->shards.impl != NULL) (void)cnet_shards_stop(&impl->shards, 5000u);
  if (impl->dispatcher.impl != NULL) {
    (void)cnet_dispatcher_drain(&impl->dispatcher, 0u);
    (void)cnet_dispatcher_destroy(&impl->dispatcher);
  }
  if (impl->shards.impl != NULL) (void)cnet_shards_destroy(&impl->shards);
  cmeta_mutex_destroy(&impl->control_lock);
  cnet_storage_free(impl->sends);
  cnet_storage_free(impl->records);
  cnet_storage_free(impl);
  (void)cnet_module_shutdown();
}

static int cnet_client_init_impl(cnet_client *client,
                                 const cnet_client_config *config,
                                 native_io_backend *borrowed_backend) {
  cnet_client_impl *impl;
  cnet_shards_config shards_config;
  size_t max_command_payload_bytes;
  size_t command_buffer_bytes;
  size_t max_event_payload_bytes;
  size_t event_buffer_bytes;
  size_t index;
  int status;

  if (client == NULL || config == NULL) return SALTS_EINVAL;
  if (client->impl != NULL) return SALTS_EALREADY;
  if (!cnet_client_config_valid(config)) return SALTS_EINVAL;
  status = cnet_module_init();
  if (status != SALTS_OK) return status;

  impl = (cnet_client_impl *)cnet_storage_alloc(&config->resources.storage, 1u, sizeof(*impl));
  if (impl == NULL) {
    (void)cnet_module_shutdown();
    return SALTS_ENOMEM;
  }
  impl->owner_thread = cmeta_thread_current_token();
  impl->resources = config->resources;
  impl->send_admission = config->send_admission;
  impl->send_limits = config->send_limits;
  if (impl->send_limits.operations == 0u) impl->send_limits.operations = config->command_capacity;
  if (impl->send_limits.operations > config->command_capacity ||
      (impl->send_limits.bytes == 0u &&
       impl->send_limits.operations > SIZE_MAX / config->max_send_bytes)) {
    cnet_storage_free(impl); (void)cnet_module_shutdown(); return SALTS_EINVAL;
  }
  if (impl->send_limits.bytes == 0u)
    impl->send_limits.bytes = impl->send_limits.operations * config->max_send_bytes;
  if (impl->send_limits.backing_bytes == 0u) impl->send_limits.backing_bytes = SIZE_MAX;
  if (impl->send_limits.connection_operations == 0u)
    impl->send_limits.connection_operations = impl->send_limits.operations;
  if (impl->send_limits.connection_bytes == 0u)
    impl->send_limits.connection_bytes = impl->send_limits.bytes;
  if (impl->send_limits.connection_backing_bytes == 0u)
    impl->send_limits.connection_backing_bytes = impl->send_limits.backing_bytes;
  impl->shard_count = 1u;
  impl->capacity_per_shard = config->connection_capacity;
  impl->record_count = config->connection_capacity;
  impl->connection_capacity = config->connection_capacity;
  impl->max_send_bytes = config->max_send_bytes;
  impl->tls_io_buffer_bytes = config->tls_io_buffer_bytes;
  impl->backend_kind = config->backend;
  impl->external_progress = borrowed_backend != NULL;
  impl->connect_timeout_ms = config->connect_timeout_ms;
  impl->read_timeout_ms = config->read_timeout_ms;
  impl->write_timeout_ms = config->write_timeout_ms;
  impl->tls_handshake_timeout_ms = config->tls_handshake_timeout_ms;
  impl->socket_options = (cnet_stream_socket_options)CNET_STREAM_SOCKET_OPTIONS_INIT;
  impl->admission_open = true;
  atomic_init(&impl->callback_error, SALTS_OK);
  atomic_init(&impl->external_wake_pending, 0);
  cmeta_mutex_init(&impl->control_lock);
  impl->records = (cnet_client_record *)cnet_storage_alloc(&impl->resources.storage, impl->record_count, sizeof(*impl->records));
  if (impl->records == NULL) {
    cnet_client_cleanup_init(impl);
    return SALTS_ENOMEM;
  }
  for (index = 0u; index < impl->record_count; ++index)
    impl->records[index].client = impl;
  impl->sends = cnet_storage_alloc(&impl->resources.storage,
      impl->send_limits.operations, sizeof(*impl->sends));
  if (impl->sends == NULL) { cnet_client_cleanup_init(impl); return SALTS_ENOMEM; }
  for (index = 0u; index < impl->send_limits.operations; ++index)
    impl->sends[index].next = index + 1u == impl->send_limits.operations ? 0u : index + 2u;
  impl->send_free = 1u;

  max_command_payload_bytes =
      sizeof(cnet_owner_connect_payload) > sizeof(cnet_owner_start_tls_payload)
          ? sizeof(cnet_owner_connect_payload)
          : sizeof(cnet_owner_start_tls_payload);
  if (config->command_buffer_bytes != 0u &&
      config->command_buffer_bytes < max_command_payload_bytes) {
    cnet_client_cleanup_init(impl);
    return SALTS_EINVAL;
  }
  if (config->command_buffer_bytes == 0u &&
      config->command_capacity > SIZE_MAX / max_command_payload_bytes) {
    cnet_client_cleanup_init(impl);
    return SALTS_ERANGE;
  }
  command_buffer_bytes = config->command_buffer_bytes != 0u
                             ? config->command_buffer_bytes
                             : config->command_capacity * max_command_payload_bytes;
  max_event_payload_bytes = config->receive_buffer_bytes;
  if (config->tls_io_buffer_bytes != 0u &&
      max_event_payload_bytes < CNET_TLS_ALPN_NAME_MAX_BYTES)
    max_event_payload_bytes = CNET_TLS_ALPN_NAME_MAX_BYTES;
  if (config->event_buffer_bytes != 0u &&
      config->event_buffer_bytes < max_event_payload_bytes) {
    cnet_client_cleanup_init(impl);
    return SALTS_EINVAL;
  }
  if (config->event_buffer_bytes == 0u &&
      config->event_capacity > SIZE_MAX / max_event_payload_bytes) {
    cnet_client_cleanup_init(impl);
    return SALTS_ERANGE;
  }
  event_buffer_bytes = config->event_buffer_bytes != 0u
                           ? config->event_buffer_bytes
                           : config->event_capacity * max_event_payload_bytes;
  shards_config = (cnet_shards_config){
      .backend_kind = config->backend,
      .resources = config->resources,
      .borrowed_backend = borrowed_backend,
      .shard_count = 1u,
      .connection_capacity_per_shard = impl->capacity_per_shard,
      .command_capacity_per_shard = config->command_capacity,
      .request_capacity_per_shard = config->request_capacity,
      .completion_batch_capacity = config->completion_batch_capacity,
      .event_capacity_per_shard = config->event_capacity,
      .receive_buffer_bytes = config->receive_buffer_bytes,
      .max_state_payload_bytes =
          config->tls_io_buffer_bytes != 0u ? CNET_TLS_ALPN_NAME_MAX_BYTES : 0u,
      .max_command_payload_bytes = max_command_payload_bytes,
      .command_buffer_bytes = command_buffer_bytes,
      .write_capacity_per_shard = config->command_capacity,
      .max_write_payload_bytes = config->max_send_bytes,
      .event_buffer_bytes = event_buffer_bytes};
  status = cnet_shards_init(&impl->shards, &shards_config);
  if (status != SALTS_OK) {
    cnet_client_cleanup_init(impl);
    return status;
  }
  status = cnet_dispatcher_init_with_storage(&impl->dispatcher, &impl->shards, &impl->resources.storage);
  if (status == SALTS_OK)
    status = cnet_shards_bind_event_sink(&impl->shards, cnet_client_dispatch, &impl->dispatcher);
  if (status != SALTS_OK) {
    cnet_client_cleanup_init(impl);
    return status;
  }
  client->impl = impl;
  return SALTS_OK;
}

int cnet_client_init(cnet_client *client, const cnet_client_config *config) {
  return cnet_client_init_impl(client, config, NULL);
}

int cnet_client_init_external(cnet_client *client,
                              const cnet_client_config *config,
                              native_io_backend *borrowed_backend) {
  if (borrowed_backend == NULL) return SALTS_EINVAL;
  return cnet_client_init_impl(client, config, borrowed_backend);
}

int cnet_client_set_stream_socket_options(cnet_client *client,
                                          const cnet_stream_socket_options *options) {
  cnet_client_impl *impl = cnet_client_get(client);
  int status = cnet_stream_socket_options_validate(options);
  if (status != SALTS_OK) return status;
  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->admission_open || impl->stopped) status = SALTS_ESHUTDOWN;
  else if (impl->active_count != 0u || impl->poll_active || impl->stop_active) status = SALTS_EBUSY;
  else impl->socket_options = *options;
  return status;
}

static cnet_client_record *cnet_client_find_record(cnet_client_impl *impl,
                                                   cnet_connection connection,
                                                   cnet_shard_connection *out_internal) {
  cnet_client_record *record;
  size_t index;
  if (connection.slot == 0u || connection.generation == 0u ||
      (size_t)connection.slot > impl->record_count)
    return NULL;
  index = (size_t)connection.slot - 1u;
  record = &impl->records[index];
  if (!record->active || record->public_handle.generation != connection.generation) return NULL;
  if (out_internal != NULL) *out_internal = record->internal;
  return record;
}

static int cnet_client_record_session_state(cnet_client_impl *impl,
                                            const cnet_client_record *record,
                                            cnet_session_state *out_state) {
  if (impl == NULL || record == NULL || out_state == NULL || !record->active)
    return SALTS_ENOENT;
  return cnet_shards_state(&impl->shards, record->internal, out_state);
}

int cnet_client_reuse_status(cnet_client *client, cnet_connection connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_session_state state = CNET_SESSION_FREE;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->owner_thread != cmeta_thread_current_token()) return SALTS_EPERM;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  cnet_client_record *record = cnet_client_find_record(impl, connection, NULL);
  if (record == NULL) return SALTS_ENOENT;
  if (record->close_command_pending || record->tcp_shutdown_mask != 0u)
    return SALTS_ESHUTDOWN;
  if (record->tls_command_pending) return SALTS_EBUSY;
  int status = cnet_client_record_session_state(impl, record, &state);
  if (status != SALTS_OK) return status;
  if (state == CNET_SESSION_DRAINING || state == CNET_SESSION_TERMINAL ||
      state == CNET_SESSION_RETIRED)
    return SALTS_ESHUTDOWN;
  return state == CNET_SESSION_OPEN ? SALTS_OK : SALTS_EBUSY;
}

static int cnet_client_admit(cnet_client_impl *impl, const cnet_owner_connect_payload *payload,
                             cnet_uri_scheme scheme, const cnet_observer *observer,
                             cnet_connection *out_connection, bool *out_transferred) {
  cnet_owner_connect_payload admitted_payload;
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  size_t index;
  int status;

  if (out_transferred != NULL) *out_transferred = false;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  if (impl->active_count >= impl->connection_capacity) return SALTS_ENOBUFS;
  admitted_payload = *payload;
  /*
   * Fresh client-created sockets inherit the client's future-connection
   * policy. Adopted sockets already carry their live policy (for example an
   * accepted listener child or a bound socket transferred into connect) and
   * must not be rewritten here.
   */
  if (!admitted_payload.adopted)
    admitted_payload.socket_options = impl->socket_options;
  status = cnet_shards_connect(&impl->shards, &admitted_payload, &internal);
  if (status != SALTS_OK) return status;
  if (out_transferred != NULL) *out_transferred = true;
  index = (size_t)internal.shard * impl->capacity_per_shard + (size_t)internal.session.slot - 1u;
  record = &impl->records[index];
  record->internal = internal;
  record->public_handle = (cnet_connection){(uint32_t)(index + 1u), internal.session.generation};
  record->observer = *observer;
  record->receive_slice_handler = NULL;
  record->receive_slice_user = NULL;
  record->scheme = scheme;
  record->active = true;
  record->pending_writes = 0u;
  record->receive_pending = 0u;
  record->tcp_shutdown_mask = 0u;
  record->preserve_send_on_eof = false;
  record->close_command_pending = false;
  record->tls_command_pending = false;
  ++impl->active_count;
  status = cnet_dispatcher_register(&impl->dispatcher, internal, cnet_client_observe, record);
  if (status == SALTS_OK) {
    *out_connection = record->public_handle;
  } else {
    record->active = false;
    record->observer = (cnet_observer){0};
    record->receive_slice_handler = NULL;
    record->receive_slice_user = NULL;
    --impl->active_count;
    (void)cnet_shards_close(&impl->shards, internal);
  }
  return status;
}

int cnet_connect(cnet_client *client, const cnet_connect_options *options,
                 cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  cnet_uri uri = {0};
  bool transferred = false;
  int status;

  if (out_connection == NULL) return SALTS_EINVAL;
  *out_connection = (cnet_connection){0};
  if (impl == NULL || options == NULL || options->uri == NULL || options->observer.on_state == NULL)
    return SALTS_EINVAL;
  status = cnet_uri_parse(options->uri, &uri);
  if (status != SALTS_OK) return status;
  if (options->tls != NULL && options->tls_client != NULL) return SALTS_EINVAL;
  if ((options->tls != NULL || options->tls_client != NULL) && uri.scheme != CNET_URI_TLS)
    return SALTS_EINVAL;
  if (uri.scheme == CNET_URI_TLS && impl->tls_io_buffer_bytes == 0u) return SALTS_ENOTSUP;
  if ((uri.scheme == CNET_URI_IPC || uri.scheme == CNET_URI_PIPE) &&
      (impl->socket_options.receive_buffer_bytes != 0u || impl->socket_options.send_buffer_bytes != 0u ||
       impl->socket_options.keepalive || impl->socket_options.linger || impl->socket_options.nodelay))
    return SALTS_ENOTSUP;
  if (uri.scheme == CNET_URI_VSOCK && !cnet_transport_vsock_supported(impl->backend_kind))
    return SALTS_ENOTSUP;
  payload.scheme = uri.scheme;
  payload.connect_timeout_ms = impl->connect_timeout_ms;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;
  if (uri.scheme == CNET_URI_TLS) {
    const char *profile_server_name = cnet_tls_client_server_name(options->tls_client);
    const char *server_name = options->tls != NULL && options->tls->server_name != NULL
                                  ? options->tls->server_name
                              : profile_server_name != NULL ? profile_server_name
                                                            : uri.host;
    if (options->tls_client != NULL) {
      payload.tls_context = cnet_tls_client_context(options->tls_client);
      if (payload.tls_context == NULL) return SALTS_EINVAL;
      cnet_tls_context_retain(payload.tls_context);
    } else {
      status = cnet_tls_client_context_create(options->tls, &payload.tls_context);
      if (status != SALTS_OK) return status;
    }
    memcpy(payload.tls_server_name, server_name, strlen(server_name) + 1u);
    payload.tls_io_buffer_bytes = impl->tls_io_buffer_bytes;
    payload.tls_handshake_timeout_ms = impl->tls_handshake_timeout_ms;
  }
  if (uri.scheme == CNET_URI_PIPE) {
    memcpy(payload.pipe_name, uri.path, strlen(uri.path) + 1u);
  } else if (uri.scheme == CNET_URI_IPC) {
#if defined(_WIN32)
    memcpy(payload.pipe_name, uri.path, strlen(uri.path) + 1u);
#else
    status = cnet_transport_ipc_address(uri.path, payload.address, sizeof(payload.address),
                                      &payload.address_length);
    if (status != SALTS_OK) return status;
#endif
  } else if (uri.scheme == CNET_URI_VSOCK) {
    status = cnet_transport_parse_vsock_address(uri.vsock_cid, uri.vsock_port, false,
                                                payload.address, sizeof(payload.address),
                                                &payload.address_length);
    if (status != SALTS_OK) return status;
  } else {
    status = cnet_transport_parse_numeric_address(uri.host, uri.port, payload.address,
                                                  sizeof(payload.address), &payload.address_length);
    if (status == SALTS_ENOENT) {
      memcpy(payload.host, uri.host, strlen(uri.host) + 1u);
      payload.port = uri.port;
    } else if (status != SALTS_OK) {
      if (payload.tls_context != NULL) cnet_tls_context_release(payload.tls_context);
      return status;
    }
  }

  status = cnet_client_admit(impl, &payload, uri.scheme, &options->observer, out_connection,
                             &transferred);
  if (!transferred && payload.tls_context != NULL) cnet_tls_context_release(payload.tls_context);
  return status;
}

int cnet_connect_peer(cnet_client *client, const cnet_stream_peer *remote_peer,
                      const cnet_stream_peer *local_peer,
                      const cnet_observer *observer,
                      cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  bool transferred = false;
  int status;

  if (out_connection == NULL) return SALTS_EINVAL;
  *out_connection = (cnet_connection){0};
  if (impl == NULL || remote_peer == NULL || observer == NULL ||
      observer->on_state == NULL)
    return SALTS_EINVAL;
  if (local_peer != NULL && local_peer->family != remote_peer->family)
    return SALTS_EAFNOSUPPORT;

  payload.scheme = CNET_URI_TCP;
  payload.connect_timeout_ms = impl->connect_timeout_ms;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;

  status = cnet_transport_stream_peer_address(
      remote_peer, false, payload.address, sizeof(payload.address),
      &payload.address_length);
  if (status != SALTS_OK) return status;

  if (local_peer != NULL) {
    status = cnet_transport_stream_peer_address(
        local_peer, true, payload.local_address, sizeof(payload.local_address),
        &payload.local_address_length);
    if (status != SALTS_OK) return status;
  }

  status = cnet_client_admit(
      impl, &payload, CNET_URI_TCP, observer, out_connection, &transferred);
  return status;
}

int cnet_connect_endpoint(cnet_client *client,
                          const cnet_stream_endpoint *remote_endpoint,
                          const cnet_stream_endpoint *local_endpoint,
                          const cnet_observer *observer,
                          cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  bool transferred = false;
  int status;

  if (out_connection == NULL) return SALTS_EINVAL;
  *out_connection = (cnet_connection){0};
  if (impl == NULL || remote_endpoint == NULL ||
      remote_endpoint->size < sizeof(*remote_endpoint) ||
      remote_endpoint->version != CNET_STREAM_ENDPOINT_API_VERSION ||
      observer == NULL || observer->on_state == NULL)
    return SALTS_EINVAL;
  if (local_endpoint != NULL &&
      (local_endpoint->size < sizeof(*local_endpoint) ||
       local_endpoint->version != CNET_STREAM_ENDPOINT_API_VERSION))
    return SALTS_EINVAL;
  if (local_endpoint != NULL &&
      local_endpoint->family != remote_endpoint->family)
    return SALTS_EAFNOSUPPORT;

  payload.scheme = CNET_URI_TCP;
  payload.connect_timeout_ms = impl->connect_timeout_ms;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;

  status = cnet_transport_stream_endpoint_address(
      remote_endpoint, false, payload.address, sizeof(payload.address),
      &payload.address_length);
  if (status != SALTS_OK) return status;

  if (local_endpoint != NULL) {
    status = cnet_transport_stream_endpoint_address(
        local_endpoint, true, payload.local_address,
        sizeof(payload.local_address),
        &payload.local_address_length);
    if (status != SALTS_OK) return status;
  }

  return cnet_client_admit(
      impl, &payload, CNET_URI_TCP, observer,
      out_connection, &transferred);
}

int cnet_connection_local_peer(cnet_client *client, cnet_connection connection,
                               cnet_stream_peer *out_peer) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;

  if (out_peer == NULL) return SALTS_EINVAL;
  *out_peer = (cnet_stream_peer){0};
  if (impl == NULL) return SALTS_EINVAL;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP && record->scheme != CNET_URI_TLS)
    return SALTS_ENOTSUP;
  return cnet_shards_tcp_local_peer(&impl->shards, internal, out_peer);
}

int cnet_connection_remote_peer(cnet_client *client, cnet_connection connection,
                                cnet_stream_peer *out_peer) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;

  if (out_peer == NULL) return SALTS_EINVAL;
  *out_peer = (cnet_stream_peer){0};
  if (impl == NULL) return SALTS_EINVAL;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP && record->scheme != CNET_URI_TLS)
    return SALTS_ENOTSUP;
  return cnet_shards_tcp_remote_peer(&impl->shards, internal, out_peer);
}

int cnet_connection_local_endpoint(
    cnet_client *client, cnet_connection connection,
    cnet_stream_endpoint *out_endpoint) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;

  if (out_endpoint == NULL) return SALTS_EINVAL;
  *out_endpoint = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  if (impl == NULL) return SALTS_EINVAL;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP && record->scheme != CNET_URI_TLS)
    return SALTS_ENOTSUP;
  return cnet_shards_tcp_local_endpoint(
      &impl->shards, internal, out_endpoint);
}

int cnet_connection_remote_endpoint(
    cnet_client *client, cnet_connection connection,
    cnet_stream_endpoint *out_endpoint) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;

  if (out_endpoint == NULL) return SALTS_EINVAL;
  *out_endpoint = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  if (impl == NULL) return SALTS_EINVAL;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP && record->scheme != CNET_URI_TLS)
    return SALTS_ENOTSUP;
  return cnet_shards_tcp_remote_endpoint(
      &impl->shards, internal, out_endpoint);
}

int cnet_connection_shutdown(cnet_client *client,
                             cnet_connection connection,
                             cnet_tcp_shutdown how) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  int status;

  if (impl == NULL ||
      (how != CNET_TCP_SHUTDOWN_RECEIVE &&
       how != CNET_TCP_SHUTDOWN_SEND &&
       how != CNET_TCP_SHUTDOWN_BOTH))
    return SALTS_EINVAL;

  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP) return SALTS_ENOTSUP;
  if (record->close_command_pending || record->ws_transport != NULL) return SALTS_EBUSY;

  status = cnet_shards_tcp_shutdown(
      &impl->shards, internal, how);
  if (status != SALTS_OK)
    return status;

  record->tcp_shutdown_mask =
      (uint8_t)(record->tcp_shutdown_mask | (uint8_t)how);
  if ((how & CNET_TCP_SHUTDOWN_RECEIVE) != 0)
    record->receive_pending = 0u;
  return SALTS_OK;
}

int cnet_connection_preserve_send_on_eof(cnet_client *client, cnet_connection connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  int status;
  if (impl == NULL) return SALTS_EINVAL;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP) return SALTS_ENOTSUP;
  if (record->receive_pending || record->close_command_pending || record->tcp_shutdown_mask ||
      record->ws_transport != NULL) return SALTS_EBUSY;
  status = cnet_shards_preserve_send_on_eof(&impl->shards, internal);
  if (status == SALTS_OK) record->preserve_send_on_eof = true;
  return status;
}

int cnet_connection_tcp_option_get(cnet_client *client, cnet_connection connection,
                                   cnet_tcp_socket_option option, uint64_t *out_value) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;

  if (out_value == NULL) return SALTS_EINVAL;
  *out_value = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP && record->scheme != CNET_URI_TLS)
    return SALTS_ENOTSUP;
  return cnet_shards_tcp_option_get(
      &impl->shards, internal, option, out_value);
}

int cnet_connection_tcp_option_set(cnet_client *client, cnet_connection connection,
                                   cnet_tcp_socket_option option, uint64_t value) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;

  if (impl == NULL) return SALTS_EINVAL;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP && record->scheme != CNET_URI_TLS)
    return SALTS_ENOTSUP;
  return cnet_shards_tcp_option_set(
      &impl->shards, internal, option, value);
}

static bool cnet_client_tls_server_name_valid(const char *server_name) {
  return server_name != NULL && server_name[0] != '\0' &&
         memchr(server_name, '\0', CNET_TLS_SERVER_NAME_CAPACITY) != NULL;
}

static int cnet_client_start_tls_ready(cnet_client_impl *impl, cnet_connection connection,
                                       cnet_shard_connection *out_internal) {
  cnet_client_record *record;
  cnet_session_state session_state = CNET_SESSION_FREE;
  int status = SALTS_OK;
  if (!impl->admission_open) status = SALTS_ESHUTDOWN;
  else if (impl->tls_io_buffer_bytes == 0u) status = SALTS_ENOTSUP;
  else {
    record = cnet_client_find_record(impl, connection, out_internal);
    if (record == NULL) status = SALTS_ENOENT;
    else if (record->tls_command_pending || record->ws_transport != NULL) status = SALTS_EBUSY;
    else if (record->scheme != CNET_URI_TCP) status = SALTS_ENOTSUP;
    else {
      status = cnet_client_record_session_state(impl, record, &session_state);
      if (status == SALTS_OK &&
          (session_state != CNET_SESSION_OPEN || record->pending_writes != 0u ||
           record->receive_pending != 0u || record->close_command_pending))
        status = SALTS_EBUSY;
    }
  }
  return status;
}

static int cnet_client_admit_start_tls(cnet_client_impl *impl, cnet_connection connection,
                                       const cnet_owner_start_tls_payload *payload) {
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  int status;
  if (impl->evaluating_policy) return SALTS_EBUSY;
  if (!impl->admission_open) status = SALTS_ESHUTDOWN;
  else if (impl->tls_io_buffer_bytes == 0u) status = SALTS_ENOTSUP;
  else {
    record = cnet_client_find_record(impl, connection, &internal);
    if (record == NULL) status = SALTS_ENOENT;
    else if (record->tls_command_pending || record->ws_transport != NULL) status = SALTS_EBUSY;
    else if (record->scheme != CNET_URI_TCP) status = SALTS_ENOTSUP;
    else if (record->pending_writes != 0u || record->receive_pending != 0u ||
             record->close_command_pending)
      status = SALTS_EBUSY;
    else {
      status = cnet_shards_start_tls(&impl->shards, internal, payload);
      if (status == SALTS_OK) {
        record->scheme = CNET_URI_TLS;
        record->tls_command_pending = true;
        record->negotiated_alpn_size = 0u;
        record->negotiated_alpn[0] = '\0';
      }
    }
  }
  return status;
}

int cnet_start_tls(cnet_client *client, cnet_connection connection,
                   const cnet_start_tls_options *options) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_start_tls_payload payload = {0};
  const char *profile_server_name;
  const char *server_name;
  int status;
  if (impl == NULL || options == NULL || options->size != sizeof(*options) ||
      (options->tls != NULL && options->tls_client != NULL))
    return SALTS_EINVAL;
  status = cnet_client_start_tls_ready(impl, connection, NULL);
  if (status != SALTS_OK) return status;

  profile_server_name = cnet_tls_client_server_name(options->tls_client);
  server_name = options->tls != NULL && options->tls->server_name != NULL
                    ? options->tls->server_name
                : profile_server_name != NULL ? profile_server_name
                                              : options->server_name;
  if (!cnet_client_tls_server_name_valid(server_name)) return SALTS_EINVAL;
  if (options->tls_client != NULL) {
    payload.tls_context = cnet_tls_client_context(options->tls_client);
    if (payload.tls_context == NULL) return SALTS_EINVAL;
    cnet_tls_context_retain(payload.tls_context);
  } else {
    status = cnet_tls_client_context_create(options->tls, &payload.tls_context);
    if (status != SALTS_OK) return status;
  }
  memcpy(payload.tls_server_name, server_name, strlen(server_name) + 1u);
  payload.tls_io_buffer_bytes = impl->tls_io_buffer_bytes;
  payload.tls_handshake_timeout_ms = impl->tls_handshake_timeout_ms;
  status = cnet_client_admit_start_tls(impl, connection, &payload);
  if (status != SALTS_OK) cnet_tls_context_release(payload.tls_context);
  return status;
}

int cnet_start_tls_server(cnet_client *client, cnet_connection connection,
                          const cnet_tls_server *server) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_start_tls_payload payload = {0};
  int status;
  if (impl == NULL || server == NULL) return SALTS_EINVAL;
  status = cnet_client_start_tls_ready(impl, connection, NULL);
  if (status != SALTS_OK) return status;
  payload.tls_context = cnet_tls_server_context(server);
  if (payload.tls_context == NULL) return SALTS_EINVAL;
  cnet_tls_context_retain(payload.tls_context);
  payload.tls_io_buffer_bytes = impl->tls_io_buffer_bytes;
  payload.tls_handshake_timeout_ms = impl->tls_handshake_timeout_ms;
  payload.tls_server = true;
  status = cnet_client_admit_start_tls(impl, connection, &payload);
  if (status != SALTS_OK) cnet_tls_context_release(payload.tls_context);
  return status;
}

int cnet_client_adopt_ipc(cnet_client *client, cnet_ipc_accepted *accepted,
                         const cnet_observer *observer, cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  cnet_ipc_accepted owned;
  bool transferred = false;
  int status;
  if (out_connection != NULL) *out_connection = (cnet_connection){0};
  if (accepted == NULL || accepted->native_handle == UINTPTR_MAX ||
      (accepted->kind != CNET_IPC_RESOURCE_PIPE && accepted->kind != CNET_IPC_RESOURCE_SOCKET))
    return SALTS_EINVAL;
  owned = *accepted;
  *accepted = (cnet_ipc_accepted){0};
  if (impl == NULL || observer == NULL || observer->on_state == NULL || out_connection == NULL
#if defined(_WIN32)
      || owned.kind != CNET_IPC_RESOURCE_PIPE
#else
      || owned.kind != CNET_IPC_RESOURCE_SOCKET
#endif
  ) {
    (void)cnet_ipc_accepted_close(&owned);
    return SALTS_EINVAL;
  }
  payload.scheme = CNET_URI_IPC;
  payload.adopted_socket = owned.native_handle;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;
  payload.adopted = true;
  status = cnet_client_admit(impl, &payload, CNET_URI_IPC, observer, out_connection, &transferred);
  if (!transferred) (void)cnet_ipc_accepted_close(&owned);
  return status;
}

int cnet_client_adopt_tcp(cnet_client *client, uintptr_t native_socket,
                          const cnet_observer *observer, cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  bool transferred = false;
  int status;

  if (out_connection == NULL) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }
  *out_connection = (cnet_connection){0};
  if (impl == NULL || observer == NULL || observer->on_state == NULL ||
      native_socket == UINTPTR_MAX) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }
  payload.scheme = CNET_URI_TCP;
  payload.adopted_socket = native_socket;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;
  payload.adopted = true;
  status = cnet_client_admit(impl, &payload, CNET_URI_TCP, observer, out_connection, &transferred);
  if (!transferred) cnet_transport_close_socket(native_socket);
  return status;
}

static int cnet_client_apply_accepted_stream_policy(
    cnet_client *client, uintptr_t native_socket) {
  cnet_client_impl *impl = cnet_client_get(client);
  if (impl == NULL || native_socket == UINTPTR_MAX) return SALTS_EINVAL;
  return cnet_transport_apply_stream_socket_options(
      native_socket, &impl->socket_options);
}

int cnet_client_adopt_accepted(cnet_client *client,
                               cnet_accepted_stream *accepted,
                               const cnet_observer *observer,
                               cnet_connection *out_connection) {
  uintptr_t native_socket;
  int status;
  if (accepted == NULL) {
    if (out_connection != NULL) *out_connection = (cnet_connection){0};
    return SALTS_EINVAL;
  }
  if (accepted->internal_active == 0u) {
    if (out_connection != NULL) *out_connection = (cnet_connection){0};
    return SALTS_EALREADY;
  }
  native_socket = accepted->internal_socket;
  accepted->internal_socket = 0u;
  accepted->internal_active = 0u;
  status = cnet_client_apply_accepted_stream_policy(client, native_socket);
  if (status != SALTS_OK) {
    if (out_connection != NULL) *out_connection = (cnet_connection){0};
    cnet_transport_close_socket(native_socket);
    return status;
  }
  return cnet_client_adopt_tcp(client, native_socket, observer,
                               out_connection);
}

int cnet_client_adopt_accepted_tls(cnet_client *client,
                                   cnet_accepted_stream *accepted,
                                   const cnet_tls_server *server,
                                   const cnet_observer *observer,
                                   cnet_connection *out_connection) {
  uintptr_t native_socket;
  cnet_tls_context *context;
  int status;
  if (accepted == NULL) {
    if (out_connection != NULL) *out_connection = (cnet_connection){0};
    return SALTS_EINVAL;
  }
  if (accepted->internal_active == 0u) {
    if (out_connection != NULL) *out_connection = (cnet_connection){0};
    return SALTS_EALREADY;
  }
  native_socket = accepted->internal_socket;
  accepted->internal_socket = 0u;
  accepted->internal_active = 0u;
  status = cnet_client_apply_accepted_stream_policy(client, native_socket);
  if (status != SALTS_OK) {
    if (out_connection != NULL) *out_connection = (cnet_connection){0};
    cnet_transport_close_socket(native_socket);
    return status;
  }
  context = cnet_tls_server_context(server);
  return cnet_client_adopt_tls_server(client, native_socket, context, observer,
                                      out_connection);
}

int cnet_client_adopt_bound_tcp_connect(
    cnet_client *client, uintptr_t native_socket,
    const cnet_stream_peer *remote_peer,
    const cnet_observer *observer,
    cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  bool transferred = false;
  int status;

  if (out_connection == NULL) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }
  *out_connection = (cnet_connection){0};
  if (impl == NULL || remote_peer == NULL ||
      observer == NULL || observer->on_state == NULL ||
      native_socket == UINTPTR_MAX) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }

  payload.scheme = CNET_URI_TCP;
  payload.adopted_socket = native_socket;
  payload.adopted = true;
  payload.adopted_connect = true;
  payload.connect_timeout_ms = impl->connect_timeout_ms;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;

  status = cnet_transport_stream_peer_address(
      remote_peer, false, payload.address, sizeof(payload.address),
      &payload.address_length);
  if (status != SALTS_OK) {
    cnet_transport_close_socket(native_socket);
    return status;
  }

  status = cnet_client_admit(
      impl, &payload, CNET_URI_TCP, observer,
      out_connection, &transferred);
  if (!transferred) cnet_transport_close_socket(native_socket);
  return status;
}

int cnet_client_adopt_bound_tcp_connect_endpoint(
    cnet_client *client, uintptr_t native_socket,
    const cnet_stream_endpoint *remote_endpoint,
    const cnet_observer *observer,
    cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  bool transferred = false;
  int status;

  if (out_connection == NULL) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }
  *out_connection = (cnet_connection){0};
  if (impl == NULL || remote_endpoint == NULL ||
      observer == NULL || observer->on_state == NULL ||
      native_socket == UINTPTR_MAX) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }

  payload.scheme = CNET_URI_TCP;
  payload.adopted_socket = native_socket;
  payload.adopted = true;
  payload.adopted_connect = true;
  payload.connect_timeout_ms = impl->connect_timeout_ms;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;

  status = cnet_transport_stream_endpoint_address(
      remote_endpoint, false, payload.address, sizeof(payload.address),
      &payload.address_length);
  if (status != SALTS_OK) {
    cnet_transport_close_socket(native_socket);
    return status;
  }

  status = cnet_client_admit(
      impl, &payload, CNET_URI_TCP, observer,
      out_connection, &transferred);
  if (!transferred) cnet_transport_close_socket(native_socket);
  return status;
}

int cnet_client_adopt_vsock(cnet_client *client, uintptr_t native_socket,
                            const cnet_observer *observer, cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  bool transferred = false;
  int status;

  if (out_connection == NULL) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }
  *out_connection = (cnet_connection){0};
  if (impl == NULL || observer == NULL || observer->on_state == NULL ||
      native_socket == UINTPTR_MAX) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }
  if (!cnet_transport_vsock_supported(impl->backend_kind)) {
    cnet_transport_close_socket(native_socket);
    return SALTS_ENOTSUP;
  }
  payload.scheme = CNET_URI_VSOCK;
  payload.adopted_socket = native_socket;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;
  payload.adopted = true;
  status =
      cnet_client_admit(impl, &payload, CNET_URI_VSOCK, observer, out_connection, &transferred);
  if (!transferred) cnet_transport_close_socket(native_socket);
  return status;
}

int cnet_client_adopt_tls_server(cnet_client *client, uintptr_t native_socket,
                                 cnet_tls_context *context, const cnet_observer *observer,
                                 cnet_connection *out_connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_connect_payload payload = {0};
  bool transferred = false;
  int status;

  if (out_connection == NULL) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }
  *out_connection = (cnet_connection){0};
  if (impl == NULL || observer == NULL || observer->on_state == NULL || context == NULL ||
      native_socket == UINTPTR_MAX) {
    cnet_transport_close_socket(native_socket);
    return SALTS_EINVAL;
  }
  if (impl->tls_io_buffer_bytes == 0u) {
    cnet_transport_close_socket(native_socket);
    return SALTS_ENOTSUP;
  }

  cnet_tls_context_retain(context);
  payload.scheme = CNET_URI_TLS;
  payload.adopted_socket = native_socket;
  payload.read_timeout_ms = impl->read_timeout_ms;
  payload.write_timeout_ms = impl->write_timeout_ms;
  payload.tls_handshake_timeout_ms = impl->tls_handshake_timeout_ms;
  payload.tls_io_buffer_bytes = impl->tls_io_buffer_bytes;
  payload.tls_context = context;
  payload.adopted = true;
  payload.tls_server = true;
  status = cnet_client_admit(impl, &payload, CNET_URI_TLS, observer, out_connection, &transferred);
  if (!transferred) {
    cnet_tls_context_release(context);
    cnet_transport_close_socket(native_socket);
  }
  return status;
}

int cnet_tls_negotiated_alpn(cnet_client *client, cnet_connection connection, char *buffer,
                             size_t capacity, size_t *out_size) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_client_record *record;
  cnet_session_state session_state = CNET_SESSION_FREE;
  int status = SALTS_OK;
  if (out_size == NULL) return SALTS_EINVAL;
  *out_size = 0u;
  if (impl == NULL || buffer == NULL || capacity == 0u) return SALTS_EINVAL;

  record = cnet_client_find_record(impl, connection, NULL);
  if (record == NULL) status = SALTS_ENOENT;
  else if (record->scheme != CNET_URI_TLS) status = SALTS_ENOTSUP;
  else if (cnet_client_record_session_state(impl, record, &session_state) != SALTS_OK ||
           session_state != CNET_SESSION_OPEN)
    status = SALTS_ENOTCONN;
  else if (record->negotiated_alpn_size == 0u) status = SALTS_ENOENT;
  else if (capacity <= record->negotiated_alpn_size) status = SALTS_EMSGSIZE;
  else {
    memcpy(buffer, record->negotiated_alpn, record->negotiated_alpn_size + 1u);
    *out_size = record->negotiated_alpn_size;
  }
  return status;
}

int cnet_tls_negotiated_version(cnet_client *client, cnet_connection connection, char *buffer,
                                size_t capacity, size_t *out_size) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  cnet_session_state session_state = CNET_SESSION_FREE;
  int status;
  if (out_size == NULL) return SALTS_EINVAL;
  *out_size = 0u;
  if (impl == NULL || buffer == NULL || capacity == 0u) return SALTS_EINVAL;
  buffer[0] = '\0';
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) status = SALTS_ENOENT;
  else if (record->scheme != CNET_URI_TLS) status = SALTS_ENOTSUP;
  else if (cnet_client_record_session_state(impl, record, &session_state) != SALTS_OK ||
           session_state != CNET_SESSION_OPEN)
    status = SALTS_ENOTCONN;
  else
    status = cnet_shards_tls_negotiated_version(&impl->shards, internal, buffer, capacity,
                                                out_size);
  return status;
}

int cnet_tls_negotiated_cipher(cnet_client *client, cnet_connection connection, char *buffer,
                               size_t capacity, size_t *out_size) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  cnet_session_state session_state = CNET_SESSION_FREE;
  int status;
  if (out_size == NULL) return SALTS_EINVAL;
  *out_size = 0u;
  if (impl == NULL || buffer == NULL || capacity == 0u) return SALTS_EINVAL;
  buffer[0] = '\0';
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) status = SALTS_ENOENT;
  else if (record->scheme != CNET_URI_TLS) status = SALTS_ENOTSUP;
  else if (cnet_client_record_session_state(impl, record, &session_state) != SALTS_OK ||
           session_state != CNET_SESSION_OPEN)
    status = SALTS_ENOTCONN;
  else
    status =
        cnet_shards_tls_negotiated_cipher(&impl->shards, internal, buffer, capacity, out_size);
  return status;
}

int cnet_tls_peer_certificate_sha256(cnet_client *client, cnet_connection connection,
                                     char buffer[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY]) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  cnet_session_state session_state = CNET_SESSION_FREE;
  int status;
  if (impl == NULL || buffer == NULL) return SALTS_EINVAL;
  buffer[0] = '\0';
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) status = SALTS_ENOENT;
  else if (record->scheme != CNET_URI_TLS) status = SALTS_ENOTSUP;
  else if (cnet_client_record_session_state(impl, record, &session_state) != SALTS_OK ||
           session_state != CNET_SESSION_OPEN)
    status = SALTS_ENOTCONN;
  else status = cnet_shards_tls_peer_certificate_sha256(&impl->shards, internal, buffer);
  return status;
}

int cnet_tls_server_end_point_binding(
    cnet_client *client, cnet_connection connection,
    uint8_t *output, size_t capacity, size_t *out_size) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  cnet_session_state session_state = CNET_SESSION_FREE;
  size_t clear_size;
  int status;

  if (output == NULL || capacity == 0u || out_size == NULL)
    return SALTS_EINVAL;
  clear_size = capacity < CNET_TLS_SERVER_END_POINT_MAX_BYTES
                   ? capacity
                   : CNET_TLS_SERVER_END_POINT_MAX_BYTES;
  memset(output, 0, clear_size);
  *out_size = 0u;
  if (impl == NULL) return SALTS_EINVAL;

  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) status = SALTS_ENOENT;
  else if (record->scheme != CNET_URI_TLS) status = SALTS_ENOTSUP;
  else if (cnet_client_record_session_state(impl, record, &session_state) !=
               SALTS_OK ||
           session_state != CNET_SESSION_OPEN)
    status = SALTS_ENOTCONN;
  else
    status = cnet_shards_tls_server_end_point_binding(
        &impl->shards, internal, output, capacity, out_size);
  return status;
}

int cnet_tls_export_channel_binding(cnet_client *client, cnet_connection connection,
                                    uint8_t output[CNET_TLS_CHANNEL_BINDING_BYTES]) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  cnet_session_state session_state = CNET_SESSION_FREE;
  int status;
  if (impl == NULL || output == NULL) return SALTS_EINVAL;
  memset(output, 0, CNET_TLS_CHANNEL_BINDING_BYTES);
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) status = SALTS_ENOENT;
  else if (record->scheme != CNET_URI_TLS) status = SALTS_ENOTSUP;
  else if (cnet_client_record_session_state(impl, record, &session_state) != SALTS_OK ||
           session_state != CNET_SESSION_OPEN)
    status = SALTS_ENOTCONN;
  else status = cnet_shards_tls_export_channel_binding(&impl->shards, internal, output);
  return status;
}

typedef struct cnet_client_send_input {
  mem_buffer_t *retained_buffer;
  const mem_slice_t *retained_slice;
  const mem_slice_t *retained_slices;
  size_t size;
  size_t segment_count;
  bool close_after_send;
  cnet_send_complete_fn complete;
  void *user;
  cnet_operation *out_operation;
  cnet_admission_limit *out_limit;
} cnet_client_send_input;

static int cnet_client_send_charge(cnet_client_impl *impl, cnet_client_record *record,
                                    const cnet_client_send_input *input,
                                    size_t *backing, uint64_t *operation) {
  mem_buffer_t *buffers[CNET_RETAINED_VECTOR_MAX];
  size_t count = input->retained_slices != NULL ? input->segment_count : 1u;
  cnet_admission_limit limit = CNET_LIMIT_NONE;
  *backing = 0u;
  for (size_t i = 0u; i < count; ++i) {
    mem_buffer_t *buffer = input->retained_slices != NULL ? input->retained_slices[i].buffer
        : input->retained_slice != NULL ? input->retained_slice->buffer : input->retained_buffer;
    bool duplicate = false;
    buffers[i] = buffer;
    for (size_t j = 0u; j < i; ++j) if (buffers[j] == buffer) duplicate = true;
    if (!duplicate) {
      size_t capacity = mem_buffer_capacity(buffer);
      if (capacity > SIZE_MAX - *backing) return SALTS_ERANGE;
      *backing += capacity;
    }
  }
  const cnet_send_limits *l = &impl->send_limits;
  const cnet_send_usage *a = &impl->send_usage, *c = &record->send_usage;
  if (a->operations >= l->operations) limit = CNET_LIMIT_OPERATIONS;
  else if (input->size > l->bytes - a->bytes) limit = CNET_LIMIT_BYTES;
  else if (*backing > l->backing_bytes - a->backing_bytes) limit = CNET_LIMIT_BACKING_BYTES;
  else if (c->operations >= l->connection_operations) limit = CNET_LIMIT_CONNECTION_OPERATIONS;
  else if (input->size > l->connection_bytes - c->bytes) limit = CNET_LIMIT_CONNECTION_BYTES;
  else if (*backing > l->connection_backing_bytes - c->backing_bytes)
    limit = CNET_LIMIT_CONNECTION_BACKING_BYTES;
  if (limit != CNET_LIMIT_NONE) {
    if (input->out_limit != NULL) *input->out_limit = limit;
    return SALTS_ENOBUFS;
  }
  if (impl->send_admission.evaluate != NULL) {
    cnet_client_impl *previous_policy = cnet_active_policy_client;
    cnet_active_policy_client = impl;
    impl->evaluating_policy = true;
    int status = impl->send_admission.evaluate(impl->send_admission.user, a, c, input->size, *backing);
    impl->evaluating_policy = false;
    cnet_active_policy_client = previous_policy;
    if (status != SALTS_OK) {
      if (input->out_limit != NULL) *input->out_limit = CNET_LIMIT_POLICY;
      return status;
    }
  }
  uint_fast64_t current = atomic_load_explicit(&cnet_operation_sequence, memory_order_relaxed);
  do {
    if (current == UINT64_MAX) return SALTS_ERANGE;
  } while (!atomic_compare_exchange_weak_explicit(&cnet_operation_sequence, &current, current + 1u,
                                                  memory_order_relaxed, memory_order_relaxed));
  *operation = current + 1u;
  return SALTS_OK;
}

static int cnet_client_send_admit(cnet_client_impl *impl, cnet_connection connection,
                                  const cnet_client_send_input *input) {
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  size_t backing = 0u;
  uint64_t operation = 0u;
  if (impl->owner_thread != cmeta_thread_current_token()) return SALTS_EPERM;
  if (impl->evaluating_policy) return SALTS_EBUSY;
  int status;
  if (!impl->admission_open) status = SALTS_ESHUTDOWN;
  else {
    record = cnet_client_find_record(impl, connection, &internal);
    if (record == NULL) status = SALTS_ENOENT;
    else if ((record->ws_transport != NULL && !record->ws_transport->submitting) ||
             record->close_command_pending || record->tls_command_pending)
      status = SALTS_EBUSY;
    else if (record->scheme == CNET_URI_TCP &&
             (record->tcp_shutdown_mask &
              (uint8_t)CNET_TCP_SHUTDOWN_SEND) != 0u)
      status = SALTS_ESHUTDOWN;
    else if (record->pending_writes == SIZE_MAX)
      status = SALTS_ERANGE;
    else {
      status = cnet_client_send_charge(impl, record, input, &backing, &operation);
      if (status != SALTS_OK) return status;
      if (input->close_after_send) {
        if (input->retained_slices != NULL)
          status = cnet_shards_send_slicev_close_direct(
              &impl->shards, internal, input->retained_slices, input->segment_count);
        else if (input->retained_buffer != NULL)
          status = cnet_shards_send_buffer_close_direct(
              &impl->shards, internal, input->retained_buffer);
        else
          status = SALTS_EINVAL;
      } else if (input->retained_slices != NULL) {
        status = cnet_shards_send_slicev_direct(
            &impl->shards, internal, input->retained_slices, input->segment_count);
      } else if (input->retained_slice != NULL) {
        status = cnet_shards_send_slice_direct(
            &impl->shards, internal, input->retained_slice);
      } else if (input->retained_buffer != NULL) {
        status = cnet_shards_send_buffer_direct(
            &impl->shards, internal, input->retained_buffer);
      } else {
        status = SALTS_EINVAL;
      }
      if (status == SALTS_OK) {
        size_t slot = impl->send_free;
        cnet_send_record *send = &impl->sends[slot - 1u];
        impl->send_free = send->next;
        *send = (cnet_send_record){.operation = {operation}, .complete = input->complete,
            .user = input->user, .bytes = input->size, .backing_bytes = backing};
        if (record->send_tail != 0u) impl->sends[record->send_tail - 1u].next = slot;
        else record->send_head = slot;
        record->send_tail = slot;
        ++impl->send_usage.operations;
        impl->send_usage.bytes += input->size;
        impl->send_usage.backing_bytes += backing;
        ++record->send_usage.operations;
        record->send_usage.bytes += input->size;
        record->send_usage.backing_bytes += backing;
        if (input->out_operation != NULL) input->out_operation->id = operation;
        ++record->pending_writes;
        record->close_command_pending = input->close_after_send;
      }
    }
  }
  return status;
}
int cnet_send_buffer(cnet_client *client, cnet_connection connection, mem_buffer_t *buffer) {
  cnet_client_impl *impl = cnet_client_get(client);
  size_t size;
  cnet_client_send_input input;

  if (impl == NULL || buffer == NULL) return SALTS_EINVAL;
  size = mem_buffer_used(buffer);
  if (size == 0u || mem_buffer_const_data(buffer) == NULL) return SALTS_EINVAL;
  if (size > impl->max_send_bytes) return SALTS_EMSGSIZE;
  input = (cnet_client_send_input){.retained_buffer = buffer, .size = size};
  return cnet_client_send_admit(impl, connection, &input);
}

static bool cnet_client_slice_canonical(const mem_slice_t *slice) {
  const char *backing;
  size_t used;
  uintptr_t base;
  uintptr_t data;
  uintptr_t delta;

  if (slice == NULL || slice->buffer == NULL || slice->data == NULL || slice->length == 0u)
    return false;
  backing = mem_buffer_const_data(slice->buffer);
  used = mem_buffer_used(slice->buffer);
  if (backing == NULL || used == 0u) return false;
  base = (uintptr_t)(const void *)backing;
  data = (uintptr_t)(const void *)slice->data;
  if (data < base) return false;
  delta = data - base;
  if (delta > (uintptr_t)SIZE_MAX) return false;
  return (size_t)delta < used && slice->length <= used - (size_t)delta;
}

int cnet_send(cnet_client *client, cnet_connection connection,
              const cnet_send_options *options, cnet_operation *out_operation,
              cnet_admission_limit *out_limit) {
  cnet_client_impl *impl = cnet_client_get(client);
  if (out_operation != NULL) *out_operation = (cnet_operation){0};
  if (out_limit != NULL) *out_limit = CNET_LIMIT_NONE;
  if (impl == NULL || options == NULL || out_operation == NULL ||
      options->complete == NULL || options->segments == NULL || options->segment_count == 0u ||
      options->segment_count > CNET_RETAINED_VECTOR_MAX) return SALTS_EINVAL;
  cnet_client_send_input input = {.retained_slices = options->segments,
      .segment_count = options->segment_count, .close_after_send = options->close_after_send,
      .complete = options->complete, .user = options->user, .out_operation = out_operation,
      .out_limit = out_limit};
  for (size_t i = 0u; i < options->segment_count; ++i) {
    if (!cnet_client_slice_canonical(&options->segments[i])) return SALTS_EINVAL;
    if (options->segments[i].length > SIZE_MAX - input.size) return SALTS_ERANGE;
    input.size += options->segments[i].length;
  }
  if (input.size > impl->max_send_bytes) return SALTS_EMSGSIZE;
  return cnet_client_send_admit(impl, connection, &input);
}

int cnet_client_send_usage(cnet_client *client, cnet_connection connection,
                            cnet_send_usage *out) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_send_usage){0};
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->owner_thread != cmeta_thread_current_token()) return SALTS_EPERM;
  if (connection.slot == 0u && connection.generation == 0u) { *out = impl->send_usage; return SALTS_OK; }
  cnet_client_record *record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  *out = record->send_usage;
  return SALTS_OK;
}

int cnet_client_set_send_admission(cnet_client *client,
                                   const cnet_send_admission_policy *policy) {
  cnet_client_impl *impl = cnet_client_get(client);
  if (impl == NULL || policy == NULL ||
      (policy->evaluate == NULL && policy->user != NULL)) return SALTS_EINVAL;
  if (impl->owner_thread != cmeta_thread_current_token()) return SALTS_EPERM;
  if (cnet_active_callback_client == impl || impl->poll_active || impl->stop_active)
    return SALTS_EBUSY;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  impl->send_admission = *policy;
  return SALTS_OK;
}

int cnet_send_slice(cnet_client *client, cnet_connection connection,
                    const mem_slice_t *slice) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_client_send_input input;
  if (impl == NULL || !cnet_client_slice_canonical(slice)) return SALTS_EINVAL;
  if (slice->length > impl->max_send_bytes) return SALTS_EMSGSIZE;
  input = (cnet_client_send_input){.retained_slice = slice, .size = slice->length};
  return cnet_client_send_admit(impl, connection, &input);
}

int cnet_send_slicev(cnet_client *client, cnet_connection connection,
                     const mem_slice_t *segments, size_t segment_count) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_client_send_input input = {
      .retained_slices = segments, .segment_count = segment_count};
  if (impl == NULL || segments == NULL || segment_count == 0u ||
      segment_count > CNET_RETAINED_VECTOR_MAX)
    return SALTS_EINVAL;
  for (size_t index = 0u; index < segment_count; ++index) {
    if (!cnet_client_slice_canonical(&segments[index])) return SALTS_EINVAL;
    if (segments[index].length > impl->max_send_bytes - input.size) return SALTS_EMSGSIZE;
    input.size += segments[index].length;
  }
  return cnet_client_send_admit(impl, connection, &input);
}

int cnet_send_slicev_and_close(cnet_client *client, cnet_connection connection,
                               const mem_slice_t *segments, size_t segment_count) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_client_send_input input = {
      .retained_slices = segments,
      .segment_count = segment_count,
      .close_after_send = true};
  if (impl == NULL || segments == NULL || segment_count == 0u ||
      segment_count > CNET_RETAINED_VECTOR_MAX)
    return SALTS_EINVAL;
  for (size_t index = 0u; index < segment_count; ++index) {
    if (!cnet_client_slice_canonical(&segments[index])) return SALTS_EINVAL;
    if (segments[index].length > impl->max_send_bytes - input.size) return SALTS_EMSGSIZE;
    input.size += segments[index].length;
  }
  return cnet_client_send_admit(impl, connection, &input);
}

int cnet_send_buffer_and_close(cnet_client *client, cnet_connection connection,
                               mem_buffer_t *buffer) {
  cnet_client_impl *impl = cnet_client_get(client);
  size_t size;
  cnet_client_send_input input;

  if (impl == NULL || buffer == NULL) return SALTS_EINVAL;
  size = mem_buffer_used(buffer);
  if (size == 0u || mem_buffer_const_data(buffer) == NULL) return SALTS_EINVAL;
  if (size > impl->max_send_bytes) return SALTS_EMSGSIZE;
  input = (cnet_client_send_input){
      .retained_buffer = buffer, .size = size, .close_after_send = true};
  return cnet_client_send_admit(impl, connection, &input);
}

int cnet_set_receive_slice_handler(cnet_client *client,
                                   cnet_connection connection,
                                   cnet_receive_slice_fn handler,
                                   void *user) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_client_record *record;
  cnet_session_state state = CNET_SESSION_FREE;
  int status;

  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  record = cnet_client_find_record(impl, connection, NULL);
  if (record == NULL) return SALTS_ENOENT;
  if (record->receive_pending != 0u) return SALTS_EBUSY;
  status = cnet_client_record_session_state(impl, record, &state);
  if (status != SALTS_OK) return status;
  if (state == CNET_SESSION_DRAINING || state == CNET_SESSION_TERMINAL ||
      state == CNET_SESSION_RETIRED)
    return SALTS_EBUSY;

  record->receive_slice_handler = handler;
  record->receive_slice_user = handler != NULL ? user : NULL;
  return SALTS_OK;
}

int cnet_receive(cnet_client *client, cnet_connection connection, size_t demand) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  int status;

  if (impl == NULL || demand == 0u) return SALTS_EINVAL;

  /*
   * Callback-issued admission stays deferred: later entries in the NativeIO
   * completion batch may still name request slots that an inline callback must
   * not cause CNet to reuse. Ordinary owner calls have no in-batch hazard.
   */
  if (cnet_active_callback_client == impl) {
    if (!impl->admission_open) status = SALTS_ESHUTDOWN;
    else {
      record = cnet_client_find_record(impl, connection, &internal);
      if (record == NULL) status = SALTS_ENOENT;
      else if (record->observer.on_receive == NULL && record->receive_slice_handler == NULL)
        status = SALTS_EINVAL;
      else if (record->close_command_pending || record->tls_command_pending)
        status = SALTS_EBUSY;
      else if (record->scheme == CNET_URI_TCP &&
               (record->tcp_shutdown_mask &
                (uint8_t)CNET_TCP_SHUTDOWN_RECEIVE) != 0u)
        status = SALTS_ESHUTDOWN;
      else if (demand > SIZE_MAX - record->receive_pending) {
        cnet_session_state session_state = CNET_SESSION_FREE;
        status = cnet_client_record_session_state(impl, record, &session_state);
        if (status == SALTS_OK)
          status = session_state == CNET_SESSION_OPEN ? SALTS_ERANGE : SALTS_EBUSY;
      } else {
        status = cnet_shards_receive(&impl->shards, internal, demand);
        if (status == SALTS_OK) record->receive_pending += demand;
      }
    }
    return status;
  }

  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->observer.on_receive == NULL && record->receive_slice_handler == NULL)
    return SALTS_EINVAL;
  if (record->close_command_pending || record->tls_command_pending) return SALTS_EBUSY;
  if (record->scheme == CNET_URI_TCP &&
      (record->tcp_shutdown_mask &
       (uint8_t)CNET_TCP_SHUTDOWN_RECEIVE) != 0u)
    return SALTS_ESHUTDOWN;
  if (demand > SIZE_MAX - record->receive_pending) {
    cnet_session_state session_state = CNET_SESSION_FREE;
    status = cnet_client_record_session_state(impl, record, &session_state);
    return status != SALTS_OK ? status
                              : (session_state == CNET_SESSION_OPEN ? SALTS_ERANGE : SALTS_EBUSY);
  }

  status = cnet_shards_receive_direct(&impl->shards, internal, demand);
  if (status == SALTS_OK) record->receive_pending += demand;
  return status;
}

int cnet_close(cnet_client *client, cnet_connection connection) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  int status;

  if (impl == NULL) return SALTS_EINVAL;

  if (cnet_active_callback_client == impl) {
      if (!impl->admission_open) status = SALTS_ESHUTDOWN;
    else {
      record = cnet_client_find_record(impl, connection, &internal);
      if (record == NULL) status = SALTS_ENOENT;
      else if (record->close_command_pending) status = SALTS_EALREADY;
      else {
        status = cnet_shards_close(&impl->shards, internal);
        if (status == SALTS_OK) record->close_command_pending = true;
      }
    }
      return status;
  }

  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  record = cnet_client_find_record(impl, connection, &internal);
  if (record == NULL) return SALTS_ENOENT;
  if (record->close_command_pending) return SALTS_EALREADY;

  if (record->pending_writes == 0u && record->receive_pending == 0u &&
      !record->tls_command_pending) {
    cnet_session_state session_state = CNET_SESSION_FREE;
    status = cnet_client_record_session_state(impl, record, &session_state);
    if (status != SALTS_OK) return status;
    if (session_state == CNET_SESSION_DRAINING || session_state == CNET_SESSION_TERMINAL)
      return SALTS_EALREADY;
    if (session_state == CNET_SESSION_OPEN) {
      status = cnet_shards_close_direct(&impl->shards, internal);
      if (status == SALTS_OK || status == SALTS_EALREADY) return status;
      if (status != SALTS_EBUSY && status != SALTS_ENOBUFS) return status;
    }
  }

  status = cnet_shards_close(&impl->shards, internal);
  if (status == SALTS_OK) record->close_command_pending = true;
  return status;
}

static int cnet_client_external_progress_begin(cnet_client_impl *impl) {
  int status;
  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->external_progress) return SALTS_ENOTSUP;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;

  cmeta_mutex_lock(&impl->control_lock);
  if (!impl->admission_open || impl->stopped)
    status = SALTS_ESHUTDOWN;
  else if (impl->poll_active || impl->stop_active)
    status = SALTS_EBUSY;
  else {
    impl->poll_active = true;
    impl->poll_callback_count = 0u;
    status = SALTS_OK;
  }
  cmeta_mutex_unlock(&impl->control_lock);
  return status;
}

static int cnet_client_external_progress_finish(
    cnet_client_impl *impl,
    int status,
    size_t *out_events) {
  int callback_status;

  cmeta_mutex_lock(&impl->control_lock);
  if (out_events != NULL)
    *out_events = impl->poll_callback_count;
  callback_status =
      atomic_load_explicit(&impl->callback_error, memory_order_acquire);
  impl->poll_active = false;
  cmeta_mutex_unlock(&impl->control_lock);

  return status == SALTS_OK && callback_status != SALTS_OK
      ? callback_status
      : status;
}

int cnet_client_advance_external(cnet_client *client, size_t *out_events) {
  cnet_client_impl *impl = cnet_client_get(client);
  int status;

  if (out_events == NULL) return SALTS_EINVAL;
  *out_events = 0u;
  status = cnet_client_external_progress_begin(impl);
  if (status != SALTS_OK) return status;

  status = cnet_shards_advance_external(&impl->shards);
  return cnet_client_external_progress_finish(
      impl, status, out_events);
}

int cnet_client_route_external_completion(
    cnet_client *client,
    const native_io_completion *completion,
    bool *out_consumed,
    size_t *out_events) {
  cnet_client_impl *impl = cnet_client_get(client);
  int status;

  if (completion == NULL || out_consumed == NULL ||
      out_events == NULL)
    return SALTS_EINVAL;
  *out_consumed = false;
  *out_events = 0u;
  status = cnet_client_external_progress_begin(impl);
  if (status != SALTS_OK) return status;

  status = cnet_shards_route_external_completion(
      &impl->shards, completion, out_consumed);
  return cnet_client_external_progress_finish(
      impl, status, out_events);
}

int cnet_client_external_timeout(cnet_client *client,
                                 uint32_t max_wait_ms,
                                 uint32_t *out_timeout_ms) {
  cnet_client_impl *impl = cnet_client_get(client);
  int status;

  if (out_timeout_ms == NULL) return SALTS_EINVAL;
  *out_timeout_ms = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->external_progress) return SALTS_ENOTSUP;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;

  cmeta_mutex_lock(&impl->control_lock);
  if (impl->stopped)
    status = SALTS_ESHUTDOWN;
  else if (impl->poll_active || impl->stop_active)
    status = SALTS_EBUSY;
  else
    status = cnet_shards_external_timeout(
        &impl->shards, max_wait_ms, out_timeout_ms);
  cmeta_mutex_unlock(&impl->control_lock);
  return status;
}

int cnet_client_external_requests(cnet_client *client,
                                  cnet_connection connection,
                                  native_io_request *out_requests,
                                  size_t capacity,
                                  size_t *out_count) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  int status;

  if (out_count == NULL) return SALTS_EINVAL;
  *out_count = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->external_progress) return SALTS_ENOTSUP;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;

  cmeta_mutex_lock(&impl->control_lock);
  if (impl->stopped)
    status = SALTS_ESHUTDOWN;
  else if (impl->poll_active || impl->stop_active)
    status = SALTS_EBUSY;
  else {
    record = cnet_client_find_record(
        impl, connection, &internal);
    status = record == NULL
        ? SALTS_ENOENT
        : cnet_shards_external_requests(
              &impl->shards, internal,
              out_requests, capacity, out_count);
  }
  cmeta_mutex_unlock(&impl->control_lock);
  return status;
}

int cnet_client_external_request_snapshots(
    cnet_client *client,
    cnet_connection connection,
    cnet_external_request_snapshot *out_requests,
    size_t capacity,
    size_t *out_count) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_shard_connection internal = {0};
  cnet_client_record *record;
  int status;

  if (out_count == NULL) return SALTS_EINVAL;
  *out_count = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->external_progress) return SALTS_ENOTSUP;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;

  cmeta_mutex_lock(&impl->control_lock);
  if (impl->stopped)
    status = SALTS_ESHUTDOWN;
  else if (impl->poll_active || impl->stop_active)
    status = SALTS_EBUSY;
  else {
    record = cnet_client_find_record(
        impl, connection, &internal);
    status = record == NULL
        ? SALTS_ENOENT
        : cnet_shards_external_request_snapshots(
              &impl->shards, internal,
              out_requests, capacity, out_count);
  }
  cmeta_mutex_unlock(&impl->control_lock);
  return status;
}

int cnet_client_stop_external(cnet_client *client) {
  cnet_client_impl *impl = cnet_client_get(client);
  bool fully_stopped;
  int first_status = SALTS_OK;
  int status;

  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->external_progress) return SALTS_ENOTSUP;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;

  cmeta_mutex_lock(&impl->control_lock);
  if (impl->stopped) {
    cmeta_mutex_unlock(&impl->control_lock);
    return SALTS_EALREADY;
  }
  if (impl->poll_active || impl->stop_active ||
      impl->active_count != 0u) {
    cmeta_mutex_unlock(&impl->control_lock);
    return SALTS_EBUSY;
  }
  impl->stop_active = true;
  impl->admission_open = false;
  cmeta_mutex_unlock(&impl->control_lock);

  status = cnet_dispatcher_drain(&impl->dispatcher, 0u);
  if (status == SALTS_EALREADY) status = SALTS_OK;
  if (status != SALTS_OK) first_status = status;

  if (cnet_dispatcher_drained(&impl->dispatcher)) {
    status = cnet_shards_stop(&impl->shards, 0u);
    if (status == SALTS_EALREADY) status = SALTS_OK;
    if (first_status == SALTS_OK && status != SALTS_OK)
      first_status = status;
  }

  fully_stopped =
      cnet_dispatcher_drained(&impl->dispatcher) &&
      cnet_shards_stopped(&impl->shards);
  cmeta_mutex_lock(&impl->control_lock);
  impl->stop_active = false;
  if (fully_stopped) impl->stopped = true;
  cmeta_mutex_unlock(&impl->control_lock);
  return first_status;
}

static int cnet_client_poll_impl(cnet_client *client, uint32_t timeout_ms,
                                 size_t drain_passes, size_t *out_events) {
  cnet_client_impl *impl = cnet_client_get(client);
  const uint64_t started_ms = cmeta_monotonic_ms();
  uint32_t remaining_ms = drain_passes != 0u ? 0u : timeout_ms;
  size_t drained = 0u;
  bool waiting = drain_passes == 0u;
  int status;
#if defined(CNET_INTERNAL_PROFILING)
  uint64_t profile_started = 0u;
#endif
  if (out_events == NULL) return SALTS_EINVAL;
  *out_events = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->external_progress) return SALTS_ENOTSUP;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;
  cmeta_mutex_lock(&impl->control_lock);
  if (!impl->admission_open || impl->stopped) status = SALTS_ESHUTDOWN;
  else if (impl->poll_active || impl->stop_active) status = SALTS_EBUSY;
  else {
    impl->poll_active = true;
    impl->poll_callback_count = 0u;
    status = SALTS_OK;
  }
  cmeta_mutex_unlock(&impl->control_lock);
  if (status != SALTS_OK) return status;
#if defined(CNET_INTERNAL_PROFILING)
  if (impl->profile_active) profile_started = cmeta_hrtime();
#endif

  for (;;) {
    bool externally_woken = false;
    const size_t callbacks_before = impl->poll_callback_count;
    if (atomic_exchange_explicit(&impl->external_wake_pending, 0, memory_order_acq_rel) != 0) break;
    if (!waiting) ++drained;
    status = cnet_shards_poll(&impl->shards, remaining_ms);
    if (status == SALTS_OK)
      status = atomic_load_explicit(&impl->callback_error, memory_order_acquire);
    if (status == SALTS_OK && impl->poll_callback_count != callbacks_before)
      status = cnet_shards_flush_deferred(&impl->shards);
    /* A callback may publish a wake after the backend selected its callback
       event. Preserve that edge for the next poll so native wake coalescing
       cannot hide later external work. */
    if (status == SALTS_OK && impl->poll_callback_count == 0u)
      externally_woken =
          atomic_exchange_explicit(&impl->external_wake_pending, 0, memory_order_acq_rel) != 0;
    if (status != SALTS_OK || externally_woken) break;
    if (impl->poll_callback_count != 0u) {
      /* A fixed owner drains under one admission guard. Do not consume a
         callback-issued wake merely to enter another internal pass. */
      if (waiting || drained >= drain_passes ||
          impl->poll_callback_count == callbacks_before ||
          atomic_load_explicit(&impl->external_wake_pending, memory_order_acquire) != 0)
        break;
      remaining_ms = 0u;
      continue;
    }
    if (timeout_ms == 0u) break;
    {
      const uint64_t elapsed_ms = cmeta_monotonic_ms() - started_ms;
      if (elapsed_ms >= timeout_ms) break;
      waiting = true;
      remaining_ms = timeout_ms - (uint32_t)elapsed_ms;
    }
  }

  cmeta_mutex_lock(&impl->control_lock);
  *out_events = impl->poll_callback_count;
#if defined(CNET_INTERNAL_PROFILING)
  if (profile_started != 0u) {
    impl->profile_client_poll_ns += cmeta_hrtime() - profile_started;
    ++impl->profile_client_poll_calls;
  }
#endif
  impl->poll_active = false;
  cmeta_mutex_unlock(&impl->control_lock);
  return status;
}

int cnet_client_poll(cnet_client *client, uint32_t timeout_ms, size_t *out_events) {
  return cnet_client_poll_impl(client, timeout_ms, 0u, out_events);
}

int cnet_client_poll_strategy(cnet_client *client,
                              const cnet_progress_strategy *strategy,
                              uint32_t timeout_ms, size_t *out_events) {
  cnet_progress_strategy selected = CNET_PROGRESS_STRATEGY_INIT;
  if (out_events == NULL) return SALTS_EINVAL;
  *out_events = 0u;
  if (strategy != NULL) {
    if (strategy->size != sizeof(selected)) return SALTS_EINVAL;
    selected = *strategy;
  }
  if (selected.max_poll_passes == 0u || selected.max_poll_passes > CNET_PROGRESS_MAX_PASSES)
    return SALTS_EINVAL;
  if (timeout_ms > selected.idle_wait_ms) timeout_ms = selected.idle_wait_ms;
  return cnet_client_poll_impl(client, timeout_ms, selected.max_poll_passes, out_events);
}

#if defined(CNET_INTERNAL_PROFILING)
int cnet_client_profile_begin(cnet_client *client) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_owner_profile ignored_owner = {0};
  bool shards_started = false;
  int status;
  if (impl == NULL) return SALTS_EINVAL;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;
  cmeta_mutex_lock(&impl->control_lock);
  if (!impl->admission_open || impl->stopped) status = SALTS_ESHUTDOWN;
  else if (impl->poll_active || impl->stop_active || impl->profile_active) status = SALTS_EBUSY;
  else {
    status = cnet_shards_profile_begin(&impl->shards);
    if (status == SALTS_OK) {
      shards_started = true;
      status = cnet_dispatcher_profile_begin(&impl->dispatcher);
    }
    if (status == SALTS_OK) {
      impl->profile_client_poll_ns = 0u;
      impl->profile_client_poll_calls = 0u;
      impl->profile_active = true;
    } else if (shards_started) {
      (void)cnet_shards_profile_take(&impl->shards, &ignored_owner);
    }
  }
  cmeta_mutex_unlock(&impl->control_lock);
  return status;
}

int cnet_client_profile_trace_bind(cnet_client *client,
                                   cnet_owner_trace_event *events,
                                   size_t capacity) {
  cnet_client_impl *impl = cnet_client_get(client);
  int status;
  if (impl == NULL || events == NULL || capacity == 0u)
    return SALTS_EINVAL;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;
  cmeta_mutex_lock(&impl->control_lock);
  if (impl->poll_active || impl->stop_active || !impl->profile_active)
    status = SALTS_EBUSY;
  else
    status = cnet_shards_profile_trace_bind(&impl->shards, events,
                                            capacity);
  cmeta_mutex_unlock(&impl->control_lock);
  return status;
}

int cnet_client_profile_take(cnet_client *client, cnet_client_poll_profile *out_profile) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_dispatcher_profile dispatcher_profile = {0};
  int status;
  if (impl == NULL || out_profile == NULL) return SALTS_EINVAL;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;
  cmeta_mutex_lock(&impl->control_lock);
  if (impl->poll_active || impl->stop_active || !impl->profile_active) status = SALTS_EBUSY;
  else {
    memset(out_profile, 0, sizeof(*out_profile));
    status = cnet_shards_profile_take(&impl->shards, &out_profile->owner);
    if (status == SALTS_OK)
      status = cnet_dispatcher_profile_take(&impl->dispatcher, &dispatcher_profile);
    if (status == SALTS_OK) {
      out_profile->client_poll_ns = impl->profile_client_poll_ns;
      out_profile->client_poll_calls = impl->profile_client_poll_calls;
      out_profile->dispatcher_prepare_ns = dispatcher_profile.prepare_ns;
      out_profile->dispatcher_prepare_calls = dispatcher_profile.prepare_calls;
      out_profile->dispatcher_invoke_ns = dispatcher_profile.invoke_ns;
      out_profile->dispatcher_invoke_calls = dispatcher_profile.invoke_calls;
      out_profile->dispatcher_observer_ns = dispatcher_profile.observer_ns;
      out_profile->dispatcher_observer_calls = dispatcher_profile.observer_calls;
      out_profile->dispatcher_release_ns = dispatcher_profile.release_ns;
      out_profile->dispatcher_release_calls = dispatcher_profile.release_calls;
      impl->profile_active = false;
    }
  }
  cmeta_mutex_unlock(&impl->control_lock);
  return status;
}
#endif

int cnet_client_wake(cnet_client *client) {
  cnet_client_impl *impl = cnet_client_get(client);
  bool admission_open;
  if (impl == NULL) return SALTS_EINVAL;
  cmeta_mutex_lock(&impl->control_lock);
  admission_open = impl->admission_open && !impl->stopped;
  cmeta_mutex_unlock(&impl->control_lock);
  if (!admission_open) return SALTS_ESHUTDOWN;
  atomic_store_explicit(&impl->external_wake_pending, 1, memory_order_release);
  return cnet_shards_wake(&impl->shards);
}

int cnet_client_stop(cnet_client *client, uint32_t timeout_ms) {
  cnet_client_impl *impl = cnet_client_get(client);
  const uint64_t started_ms = cmeta_monotonic_ms();
  bool fully_stopped;
  int first_status = SALTS_OK;
  int status;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->external_progress) return SALTS_ENOTSUP;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;
  cmeta_mutex_lock(&impl->control_lock);
  if (impl->stopped) {
    cmeta_mutex_unlock(&impl->control_lock);
    return SALTS_EALREADY;
  }
  if (impl->stop_active) {
    cmeta_mutex_unlock(&impl->control_lock);
    return SALTS_EBUSY;
  }
  impl->stop_active = true;
  impl->admission_open = false;
  cmeta_mutex_unlock(&impl->control_lock);

  status =
      cnet_dispatcher_drain(&impl->dispatcher, cnet_client_remaining_ms(started_ms, timeout_ms));
  if (status == SALTS_EALREADY) status = SALTS_OK;
  if (status != SALTS_OK) first_status = status;
  status = atomic_load_explicit(&impl->callback_error, memory_order_acquire);
  if (first_status == SALTS_OK && status != SALTS_OK) first_status = status;
  if (cnet_dispatcher_drained(&impl->dispatcher)) {
    status = cnet_shards_stop(&impl->shards, cnet_client_remaining_ms(started_ms, timeout_ms));
    if (status == SALTS_EALREADY) status = SALTS_OK;
    if (first_status == SALTS_OK && status != SALTS_OK) first_status = status;
  }

  fully_stopped = cnet_dispatcher_drained(&impl->dispatcher) && cnet_shards_stopped(&impl->shards);
  cmeta_mutex_lock(&impl->control_lock);
  impl->stop_active = false;
  if (fully_stopped) impl->stopped = true;
  cmeta_mutex_unlock(&impl->control_lock);
  return first_status;
}

int cnet_client_destroy(cnet_client *client) {
  cnet_client_impl *impl = cnet_client_get(client);
  int status;
  if (client == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;
  if (cnet_active_callback_client == impl) return SALTS_EBUSY;
  cmeta_mutex_lock(&impl->control_lock);
  if (!impl->stopped || impl->stop_active) {
    cmeta_mutex_unlock(&impl->control_lock);
    return SALTS_EBUSY;
  }
  cmeta_mutex_unlock(&impl->control_lock);

  status = cnet_dispatcher_destroy(&impl->dispatcher);
  if (status != SALTS_OK) return status;
  status = cnet_shards_destroy(&impl->shards);
  if (status != SALTS_OK) return status;
  cmeta_mutex_destroy(&impl->control_lock);
  cnet_storage_free(impl->sends);
  cnet_storage_free(impl->records);
  cnet_storage_free(impl);
  client->impl = NULL;
  return cnet_module_shutdown();
}

/* Dedicated WS write binding lives beside admission/dispatch so it uses the
 * actual pending-write and terminal facts, not an advisory host counter. */
static int cnet_ws_check(cnet_websocket_transport *transport, cnet_ws_transport_impl **out) {
  if (out != NULL) *out = NULL;
  if (transport == NULL || transport->impl == NULL || out == NULL) return SALTS_EINVAL;
  *out = (cnet_ws_transport_impl *)transport->impl;
  return (*out)->owner == cmeta_thread_current_token() ? SALTS_OK : SALTS_EPERM;
}
static void cnet_ws_remember(cnet_ws_transport_impl *bridge, int status) {
  if (status != SALTS_OK && bridge->error == SALTS_OK) bridge->error = status;
}
static void cnet_ws_event(void *user, cnet_websocket *ws, const cnet_websocket_event *event) {
  cnet_ws_transport_impl *bridge = (cnet_ws_transport_impl *)user;
  bridge->on_event(bridge->event_user, ws, event);
}
static int cnet_ws_write(void *user, const uint8_t *data, size_t size) {
  cnet_ws_transport_impl *bridge = (cnet_ws_transport_impl *)user;
  cnet_client_impl *client = cnet_client_get(bridge->client);
  cnet_client_record *record;
  int status;
  if (bridge->owner != cmeta_thread_current_token()) return SALTS_EPERM;
  if (bridge->terminal) return SALTS_ESHUTDOWN;
  if (client == NULL) return SALTS_EINVAL;
  record = cnet_client_find_record(client, bridge->connection, NULL);
  if (record == NULL) return SALTS_ENOENT;
  if (record->ws_transport != bridge || bridge->pending || bridge->submitting ||
      (const void *)data != (const void *)mem_buffer_const_data(bridge->output) ||
      size != mem_buffer_used(bridge->output))
    return SALTS_EPROTO;
  /* Closing is not a recoverable capacity shortage. */
  if (!client->admission_open || record->close_command_pending || record->tcp_shutdown_mask)
    return SALTS_ESHUTDOWN;
  bridge->submitting = true;
  status = cnet_send_buffer(bridge->client, bridge->connection, bridge->output);
  bridge->submitting = false;
  if (status == SALTS_OK) {
    bridge->pending = true;
    return CNET_WEBSOCKET_WRITE_PENDING;
  }
  return status == SALTS_ENOBUFS ? SALTS_EBUSY : status;
}
static void cnet_ws_sent(cnet_ws_transport_impl *bridge, size_t size) {
  if (!bridge->pending || bridge->terminal) {
    cnet_ws_remember(bridge, SALTS_EPROTO);
    return;
  }
  bridge->pending = false;
  cnet_ws_remember(bridge, cnet_websocket_write_complete(&bridge->websocket, size, SALTS_OK));
}
static void cnet_ws_terminal(cnet_ws_transport_impl *bridge, int status) {
  int result;
  bridge->terminal = true;
  if (bridge->pending) {
    bridge->pending = false;
    cnet_ws_remember(bridge, cnet_websocket_write_complete(&bridge->websocket, 0u, status));
  }
  result = cnet_websocket_transport_closed(&bridge->websocket);
  if (result != SALTS_EALREADY) cnet_ws_remember(bridge, result);
}
int cnet_websocket_transport_init(cnet_websocket_transport *transport,
    cnet_client *client, cnet_connection connection,
    const cnet_websocket_config *configuration,
    const cnet_websocket_tagged_policy *policy) {
  cnet_client_impl *impl = cnet_client_get(client);
  cnet_client_record *record;
  cnet_ws_transport_impl *bridge;
  cnet_websocket_config config;
  cnet_session_state state;
  int status;
  if (transport == NULL || transport->impl != NULL || impl == NULL ||
      configuration == NULL || configuration->size != sizeof(*configuration) ||
      configuration->write != NULL || configuration->output_buffer == NULL ||
      configuration->on_event == NULL || policy == NULL) return SALTS_EINVAL;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  record = cnet_client_find_record(impl, connection, NULL);
  if (record == NULL) return SALTS_ENOENT;
  if (record->scheme != CNET_URI_TCP && record->scheme != CNET_URI_TLS) return SALTS_ENOTSUP;
  if (record->ws_transport != NULL || record->pending_writes != 0u ||
      record->close_command_pending || record->tls_command_pending ||
      record->tcp_shutdown_mask || record->preserve_send_on_eof) return SALTS_EBUSY;
  status = cnet_client_record_session_state(impl, record, &state);
  if (status != SALTS_OK) return status;
  if (state != CNET_SESSION_OPEN) return SALTS_ENOTCONN;
  if (configuration->max_frame_bytes > SIZE_MAX - CNET_WEBSOCKET_MAX_HEADER_BYTES)
    return SALTS_ERANGE;
  if (configuration->max_frame_bytes + CNET_WEBSOCKET_MAX_HEADER_BYTES > impl->max_send_bytes)
    return SALTS_EMSGSIZE;
  bridge = (cnet_ws_transport_impl *)cnet_storage_alloc(&impl->resources.storage, 1u, sizeof(*bridge));
  if (bridge == NULL) return SALTS_ENOMEM;
  bridge->client = client;
  bridge->connection = connection;
  bridge->output = configuration->output_buffer;
  bridge->on_event = configuration->on_event;
  bridge->event_user = configuration->user;
  bridge->owner = cmeta_thread_current_token();
  config = *configuration;
  config.write = cnet_ws_write;
  config.on_event = cnet_ws_event;
  config.user = bridge;
  status = cnet_websocket_init_tagged(&bridge->websocket, &config, policy);
  if (status != SALTS_OK) { cnet_storage_free(bridge); return status; }
  record->ws_transport = bridge;
  transport->impl = bridge;
  return SALTS_OK;
}
int cnet_websocket_transport_session(cnet_websocket_transport *transport,
                                    cnet_websocket **out_session) {
  cnet_ws_transport_impl *bridge;
  int status;
  if (out_session == NULL) return SALTS_EINVAL;
  *out_session = NULL;
  status = cnet_ws_check(transport, &bridge);
  if (status == SALTS_OK) *out_session = &bridge->websocket;
  return status;
}
int cnet_websocket_transport_advance(cnet_websocket_transport *transport,
                                    size_t max_frames, size_t *out_events) {
  cnet_ws_transport_impl *bridge;
  int status;
  if (out_events != NULL) *out_events = 0u;
  if (out_events == NULL || max_frames == 0u) return SALTS_EINVAL;
  status = cnet_ws_check(transport, &bridge);
  if (status != SALTS_OK) return status;
  status = cnet_websocket_advance(&bridge->websocket, max_frames, out_events);
  if (status == SALTS_EBUSY) return status;
  cnet_ws_remember(bridge, status);
  return bridge->error;
}
int cnet_websocket_transport_destroy(cnet_websocket_transport *transport) {
  cnet_ws_transport_impl *bridge;
  int status = cnet_ws_check(transport, &bridge);
  if (status != SALTS_OK) return status;
  if (!bridge->terminal || bridge->pending || bridge->submitting) return SALTS_EBUSY;
  status = cnet_websocket_destroy(&bridge->websocket);
  if (status != SALTS_OK) return status;
  cnet_storage_free(bridge);
  transport->impl = NULL;
  return SALTS_OK;
}
