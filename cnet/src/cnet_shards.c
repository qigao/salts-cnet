#include "cnet_resources.h"
#include "cnet_shards.h"

#include <thread.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct cnet_shards_impl cnet_shards_impl;

typedef struct cnet_shard_record {
  cnet_shards_impl *shards;
  cnet_owner owner;
  cnet_session_table sessions;
  cnet_command_queue commands;
  cnet_event_queue events;
  atomic_int drive_status;
  uint32_t shard;
  bool owner_closed;
} cnet_shard_record;

struct cnet_shards_impl {
  cnet_shard_record *records;
  cmeta_mutex_t admission_lock;
  size_t shard_count;
  size_t connection_capacity_per_shard;
  size_t max_event_payload_bytes;
  size_t active_connections;
  size_t next_shard;
  size_t max_command_payload_bytes;
  size_t max_write_payload_bytes;
#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
  cnet_resources experimental_resources;
  native_io_backend_kind experimental_backend_kind;
  size_t experimental_request_capacity;
  size_t experimental_completion_batch_capacity;
  size_t experimental_receive_buffer_bytes;
  size_t experimental_write_capacity;
  bool experimental_deferred_owner_init;
#endif
  _Atomic(cnet_shards_event_sink_fn) event_sink;
  _Atomic(void *) event_sink_context;
  bool admission_open;
  bool stopping;
  bool stopped;
};

static cnet_shards_impl *cnet_shards_get(cnet_shards *shards) {
  return shards != NULL ? (cnet_shards_impl *)shards->impl : NULL;
}

static cnet_shard_record *cnet_shards_get_record(cnet_shards_impl *impl, uint32_t shard) {
  if (impl == NULL || (size_t)shard >= impl->shard_count) return NULL;
  return &impl->records[shard];
}

static int cnet_shards_first_error(cnet_shards_impl *impl) {
  size_t index;
  for (index = 0u; index < impl->shard_count; ++index) {
    const int status =
        atomic_load_explicit(&impl->records[index].drive_status, memory_order_acquire);
    if (status != SALTS_OK) return status;
  }
  return SALTS_OK;
}

static void cnet_shards_record_error(cnet_shard_record *record, int status) {
  int expected = SALTS_OK;
  if (record == NULL || status == SALTS_OK || status == SALTS_ETIMEDOUT) return;
  (void)atomic_compare_exchange_strong_explicit(&record->drive_status, &expected, status,
                                                memory_order_acq_rel, memory_order_acquire);
}

static int cnet_shards_publish_owner_event(void *context, const cnet_event *event) {
  cnet_shard_record *record = (cnet_shard_record *)context;
  cnet_shards_event_sink_fn sink =
      atomic_load_explicit(&record->shards->event_sink, memory_order_acquire);

  if (sink != NULL) {
    void *sink_context =
        atomic_load_explicit(&record->shards->event_sink_context, memory_order_relaxed);
    return sink(sink_context, record->shard, event);
  }
  return cnet_event_queue_publish(&record->events, event);
}

static void cnet_shards_cleanup_records(cnet_shards_impl *impl, size_t count) {
  size_t index;
  for (index = 0u; index < count; ++index) {
    cnet_shard_record *record = &impl->records[index];
    if (record->owner.impl != NULL) {
      (void)cnet_owner_close(&record->owner);
      (void)cnet_owner_destroy(&record->owner);
    }
    if (record->events.impl != NULL) {
      (void)cnet_event_queue_close(&record->events);
      (void)cnet_event_queue_destroy(&record->events);
    }
    if (record->commands.impl != NULL) {
      (void)cnet_command_queue_close(&record->commands);
      (void)cnet_command_queue_destroy(&record->commands);
    }
    if (record->sessions.impl != NULL) (void)cnet_session_table_destroy(&record->sessions);
  }
}

bool cnet_shard_connection_valid(cnet_shard_connection connection) {
  return cnet_session_handle_valid(connection.session);
}

static int cnet_shards_init_impl(cnet_shards *shards, const cnet_shards_config *config,
                                  bool allow_multi_owner) {
  cnet_shards_impl *impl;
  size_t initialized = 0u;
  size_t write_capacity;
  size_t max_write_payload_bytes;
  size_t index;
  int status = SALTS_OK;

  if (shards == NULL || config == NULL) return SALTS_EINVAL;
  if (shards->impl != NULL) return SALTS_EALREADY;
  if (config->borrowed_backend != NULL && config->shard_count != 1u)
    return SALTS_EINVAL;
  if (config->shard_count == 0u ||
      (!allow_multi_owner && config->shard_count != 1u) ||
      config->shard_count > UINT32_MAX ||
      config->connection_capacity_per_shard == 0u ||
      config->command_capacity_per_shard == 0u || config->request_capacity_per_shard == 0u ||
      config->completion_batch_capacity == 0u || config->event_capacity_per_shard < 2u ||
      config->receive_buffer_bytes == 0u ||
      config->max_command_payload_bytes < sizeof(cnet_owner_connect_payload) ||
      config->shard_count > SIZE_MAX / sizeof(cnet_shard_record))
    return SALTS_EINVAL;

  write_capacity = config->write_capacity_per_shard != 0u
                       ? config->write_capacity_per_shard
                       : config->command_capacity_per_shard;
  max_write_payload_bytes = config->max_write_payload_bytes != 0u
                                ? config->max_write_payload_bytes
                                : config->max_command_payload_bytes;
  impl = (cnet_shards_impl *)cnet_storage_alloc(&config->resources.storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->records = (cnet_shard_record *)cnet_storage_alloc(&config->resources.storage, config->shard_count, sizeof(*impl->records));
  if (impl->records == NULL) {
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  impl->shard_count = config->shard_count;
  impl->connection_capacity_per_shard = config->connection_capacity_per_shard;
  impl->max_event_payload_bytes = config->receive_buffer_bytes > config->max_state_payload_bytes
                                      ? config->receive_buffer_bytes
                                      : config->max_state_payload_bytes;
  impl->max_command_payload_bytes = config->max_command_payload_bytes;
  impl->max_write_payload_bytes = max_write_payload_bytes;
#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
  if (allow_multi_owner) {
    impl->experimental_resources = config->resources;
    impl->experimental_backend_kind = config->backend_kind;
    impl->experimental_request_capacity = config->request_capacity_per_shard;
    impl->experimental_completion_batch_capacity = config->completion_batch_capacity;
    impl->experimental_receive_buffer_bytes = config->receive_buffer_bytes;
    impl->experimental_write_capacity = write_capacity;
    impl->experimental_deferred_owner_init = true;
  }
#endif
  impl->admission_open = true;
  atomic_init(&impl->event_sink, NULL);
  atomic_init(&impl->event_sink_context, NULL);
  cmeta_mutex_init(&impl->admission_lock);

  for (index = 0u; index < impl->shard_count; ++index) {
    cnet_shard_record *record = &impl->records[index];
    const cnet_command_queue_config command_config = {config->command_capacity_per_shard,
                                                      config->max_command_payload_bytes,
                                                      config->command_buffer_bytes, config->resources.storage};
    const cnet_event_queue_config event_config = {config->event_capacity_per_shard,
                                                  config->event_capacity_per_shard / 2u,
                                                  impl->max_event_payload_bytes,
                                                  config->event_buffer_bytes, config->resources.storage};
    const cnet_owner_config owner_config = {
        .backend_kind = config->backend_kind,
        .resources = config->resources,
        .borrowed_backend = config->borrowed_backend,
        .connection_capacity = config->connection_capacity_per_shard,
        .request_capacity = config->request_capacity_per_shard,
        .completion_batch_capacity = config->completion_batch_capacity,
        .receive_buffer_bytes = config->receive_buffer_bytes,
        .receive_buffer_count = config->connection_capacity_per_shard,
        .write_capacity = write_capacity,
        .max_write_bytes = max_write_payload_bytes,
        .sessions = &record->sessions,
        .commands = &record->commands,
        .events = &record->events,
        .publish_event = cnet_shards_publish_owner_event,
        .event_context = record};

    record->shards = impl;
    record->shard = (uint32_t)index;
    atomic_init(&record->drive_status, SALTS_OK);
    status = cnet_session_table_init_with_storage(&record->sessions, config->connection_capacity_per_shard, &config->resources.storage);
    if (status == SALTS_OK) status = cnet_command_queue_init(&record->commands, &command_config);
    if (status == SALTS_OK) status = cnet_event_queue_init(&record->events, &event_config);
#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
    if (status == SALTS_OK && !allow_multi_owner)
      status = cnet_owner_init(&record->owner, &owner_config);
#else
    if (status == SALTS_OK)
      status = cnet_owner_init(&record->owner, &owner_config);
#endif
    ++initialized;
    if (status != SALTS_OK) break;
  }
  if (status != SALTS_OK) {
    cnet_shards_cleanup_records(impl, initialized);
    cmeta_mutex_destroy(&impl->admission_lock);
    cnet_storage_free(impl->records);
    cnet_storage_free(impl);
    return status;
  }

  shards->impl = impl;
  return SALTS_OK;
}


int cnet_shards_init(cnet_shards *shards, const cnet_shards_config *config) {
  return cnet_shards_init_impl(shards, config, false);
}

#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
int cnet_shards_init_multi_owner_experimental(
    cnet_shards *shards, const cnet_shards_config *config) {
  return cnet_shards_init_impl(shards, config, true);
}

int cnet_shards_init_owner_experimental(cnet_shards *shards, uint32_t shard) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  cnet_owner_config owner_config;
  int status;

  if (impl == NULL || !impl->experimental_deferred_owner_init)
    return SALTS_EINVAL;
  record = cnet_shards_get_record(impl, shard);
  if (record == NULL) return SALTS_EINVAL;
  if (record->owner.impl != NULL) return SALTS_EALREADY;
  if (impl->stopping || impl->stopped) return SALTS_ESHUTDOWN;

  owner_config = (cnet_owner_config){
      .backend_kind = impl->experimental_backend_kind,
      .resources = impl->experimental_resources,
      .connection_capacity = impl->connection_capacity_per_shard,
      .request_capacity = impl->experimental_request_capacity,
      .completion_batch_capacity = impl->experimental_completion_batch_capacity,
      .receive_buffer_bytes = impl->experimental_receive_buffer_bytes,
      .receive_buffer_count = impl->connection_capacity_per_shard,
      .write_capacity = impl->experimental_write_capacity,
      .max_write_bytes = impl->max_write_payload_bytes,
      .sessions = &record->sessions,
      .commands = &record->commands,
      .events = &record->events,
      .publish_event = cnet_shards_publish_owner_event,
      .event_context = record};

  status = cnet_owner_init(&record->owner, &owner_config);
  if (status != SALTS_OK)
    cnet_shards_record_error(record, status);
  return status;
}
#endif

static int cnet_shards_poll_owner_impl(cnet_shards *shards, uint32_t shard,
                                       uint32_t timeout_ms) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  int first_status;
  int status;

  if (impl == NULL) return SALTS_EINVAL;
  record = cnet_shards_get_record(impl, shard);
  if (record == NULL) return SALTS_EINVAL;
  if (impl->stopping || impl->stopped) return SALTS_ESHUTDOWN;
  if (record->owner.impl == NULL) return SALTS_EBUSY;

  first_status = cnet_shards_first_error(impl);
  status = cnet_owner_drive(&record->owner, timeout_ms);
  cnet_shards_record_error(record, status);
  return first_status != SALTS_OK ? first_status : status;
}

#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
int cnet_shards_poll_owner(cnet_shards *shards, uint32_t shard,
                           uint32_t timeout_ms) {
  return cnet_shards_poll_owner_impl(shards, shard, timeout_ms);
}
#endif

int cnet_shards_poll(cnet_shards *shards, uint32_t timeout_ms) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->shard_count != 1u) return SALTS_EINVAL;
  return cnet_shards_poll_owner_impl(shards, 0u, timeout_ms);
}

int cnet_shards_flush_deferred(cnet_shards *shards) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  int status;
  if (impl == NULL || impl->shard_count != 1u) return SALTS_EINVAL;
  if (impl->stopping || impl->stopped) return SALTS_ESHUTDOWN;
  status = cnet_owner_flush_deferred(&impl->records[0].owner);
  cnet_shards_record_error(&impl->records[0], status);
  return status;
}

int cnet_shards_advance_external(cnet_shards *shards) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  if (impl == NULL || impl->shard_count != 1u) return SALTS_EINVAL;
  if (impl->stopping || impl->stopped) return SALTS_ESHUTDOWN;
  return cnet_owner_advance_external(&impl->records[0].owner);
}

int cnet_shards_route_external_completion(
    cnet_shards *shards,
    const native_io_completion *completion,
    bool *out_consumed) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  int status;
  if (out_consumed == NULL) return SALTS_EINVAL;
  *out_consumed = false;
  if (impl == NULL || impl->shard_count != 1u) return SALTS_EINVAL;
  status = cnet_owner_route_external_completion(
      &impl->records[0].owner, completion, out_consumed);
  cnet_shards_record_error(&impl->records[0], status);
  return status;
}

int cnet_shards_external_timeout(cnet_shards *shards,
                                 uint32_t max_wait_ms,
                                 uint32_t *out_timeout_ms) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  if (impl == NULL || impl->shard_count != 1u) return SALTS_EINVAL;
  return cnet_owner_external_timeout(
      &impl->records[0].owner, max_wait_ms, out_timeout_ms);
}

int cnet_shards_external_requests(cnet_shards *shards,
                                  cnet_shard_connection connection,
                                  native_io_request *out_requests,
                                  size_t capacity,
                                  size_t *out_count) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  if (impl == NULL || impl->shard_count != 1u ||
      connection.shard != 0u)
    return SALTS_EINVAL;
  return cnet_owner_external_requests(
      &impl->records[0].owner, connection.session,
      out_requests, capacity, out_count);
}

int cnet_shards_external_request_snapshots(
    cnet_shards *shards,
    cnet_shard_connection connection,
    cnet_owner_external_request_snapshot *out_requests,
    size_t capacity,
    size_t *out_count) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  if (impl == NULL || impl->shard_count != 1u ||
      connection.shard != 0u)
    return SALTS_EINVAL;
  return cnet_owner_external_request_snapshots(
      &impl->records[0].owner, connection.session,
      out_requests, capacity, out_count);
}

#if defined(CNET_INTERNAL_PROFILING)
int cnet_shards_profile_begin(cnet_shards *shards) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_command_queue_profile command_profile = {0};
  int status;
  if (impl == NULL || impl->stopping || impl->stopped ||
      impl->shard_count != 1u)
    return SALTS_EINVAL;
  status = cnet_command_queue_profile_begin(&impl->records[0].commands);
  if (status != SALTS_OK) return status;
  status = cnet_owner_profile_begin(&impl->records[0].owner);
  if (status != SALTS_OK)
    (void)cnet_command_queue_profile_take(&impl->records[0].commands, &command_profile);
  return status;
}

int cnet_shards_profile_trace_bind(cnet_shards *shards,
                                   cnet_owner_trace_event *events,
                                   size_t capacity) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  if (impl == NULL || impl->stopping || impl->stopped ||
      impl->shard_count != 1u)
    return SALTS_EINVAL;
  return cnet_owner_profile_trace_bind(&impl->records[0].owner,
                                       events, capacity);
}

int cnet_shards_profile_take(cnet_shards *shards, cnet_owner_profile *out_profile) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_command_queue_profile command_profile = {0};
  int status;
  if (impl == NULL || out_profile == NULL || impl->shard_count != 1u)
    return SALTS_EINVAL;
  status = cnet_owner_profile_take(&impl->records[0].owner, out_profile);
  if (status != SALTS_OK) {
    (void)cnet_command_queue_profile_take(&impl->records[0].commands, &command_profile);
    return status;
  }
  status = cnet_command_queue_profile_take(&impl->records[0].commands, &command_profile);
  if (status != SALTS_OK) return status;
  out_profile->command_queue_publish_ns = command_profile.publish_ns;
  out_profile->command_queue_payload_publish_ns = command_profile.payload_publish_ns;
  out_profile->command_queue_payload_copy_ns = command_profile.payload_copy_ns;
  out_profile->command_queue_publish_calls = command_profile.publish_calls;
  out_profile->command_queue_payload_publish_calls = command_profile.payload_publish_calls;
  out_profile->command_queue_payload_copy_calls = command_profile.payload_copy_calls;
  return SALTS_OK;
}
#endif

static int cnet_shards_wake_owner_impl(cnet_shards *shards, uint32_t shard) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (impl == NULL) return SALTS_EINVAL;
  record = cnet_shards_get_record(impl, shard);
  return record != NULL ? cnet_owner_wake(&record->owner) : SALTS_EINVAL;
}

#if defined(CNET_INTERNAL_MULTI_OWNER_POC)
int cnet_shards_wake_owner(cnet_shards *shards, uint32_t shard) {
  return cnet_shards_wake_owner_impl(shards, shard);
}
#endif

int cnet_shards_wake(cnet_shards *shards) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  if (impl == NULL || impl->shard_count != 1u) return SALTS_EINVAL;
  return cnet_shards_wake_owner_impl(shards, 0u);
}

int cnet_shards_bind_event_sink(cnet_shards *shards, cnet_shards_event_sink_fn sink,
                                void *context) {
  cnet_shards_impl *impl = cnet_shards_get(shards);

  if (impl == NULL || sink == NULL || context == NULL) return SALTS_EINVAL;
  cmeta_mutex_lock(&impl->admission_lock);
  if (atomic_load_explicit(&impl->event_sink, memory_order_relaxed) != NULL) {
    cmeta_mutex_unlock(&impl->admission_lock);
    return SALTS_EALREADY;
  }
  atomic_store_explicit(&impl->event_sink_context, context, memory_order_relaxed);
  atomic_store_explicit(&impl->event_sink, sink, memory_order_release);
  cmeta_mutex_unlock(&impl->admission_lock);
  return SALTS_OK;
}

bool cnet_shards_get_layout(const cnet_shards *shards, cnet_shards_layout *out_layout) {
  const cnet_shards_impl *impl = shards != NULL ? (const cnet_shards_impl *)shards->impl : NULL;
  if (impl == NULL || out_layout == NULL) return false;
  *out_layout = (cnet_shards_layout){impl->shard_count, impl->connection_capacity_per_shard,
                                     impl->max_event_payload_bytes};
  return true;
}

int cnet_shards_connect(cnet_shards *shards, const cnet_owner_connect_payload *payload,
                        cnet_shard_connection *out_connection) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_connection connection = {0};
  size_t offset;
  int status;

  if (out_connection == NULL) return SALTS_EINVAL;
  memset(out_connection, 0, sizeof(*out_connection));
  if (impl == NULL || payload == NULL) return SALTS_EINVAL;

  cmeta_mutex_lock(&impl->admission_lock);
  status = cnet_shards_first_error(impl);
  if (!impl->admission_open || status != SALTS_OK) {
    cmeta_mutex_unlock(&impl->admission_lock);
    return status != SALTS_OK ? status : SALTS_ESHUTDOWN;
  }
  status = SALTS_ENOBUFS;
  for (offset = 0u; offset < impl->shard_count; ++offset) {
    const size_t shard = (impl->next_shard + offset) % impl->shard_count;
    status = cnet_session_table_reserve(&impl->records[shard].sessions, &connection.session);
    if (status == SALTS_ENOBUFS) continue;
    if (status != SALTS_OK) break;
    connection.shard = (uint32_t)shard;
    break;
  }
  if (status == SALTS_OK) {
    cnet_shard_record *record = &impl->records[connection.shard];
    const cnet_command command = {CNET_COMMAND_CONNECT, connection.session, payload,
                                  sizeof(*payload), 0u};
    status = cnet_command_queue_publish(&record->commands, &command);
    if (status == SALTS_OK) {
      impl->next_shard = ((size_t)connection.shard + 1u) % impl->shard_count;
      ++impl->active_connections;
      *out_connection = connection;
    } else {
      (void)cnet_session_table_release_reservation(&record->sessions, connection.session);
    }
  }
  cmeta_mutex_unlock(&impl->admission_lock);
  return status;
}

static int cnet_shards_publish(cnet_shards_impl *impl, cnet_shard_connection connection,
                               const cnet_command *command) {
  cnet_shard_record *record;
  cnet_session_state state = CNET_SESSION_FREE;
  const cnet_command_kind kind = command != NULL ? command->kind : CNET_COMMAND_NONE;
  int status;

  if (command == NULL) return SALTS_EINVAL;
  if (!cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  if (record == NULL) return SALTS_ENOENT;

  cmeta_mutex_lock(&impl->admission_lock);
  if (!impl->admission_open) {
    cmeta_mutex_unlock(&impl->admission_lock);
    return SALTS_ESHUTDOWN;
  }
  status = cnet_shards_first_error(impl);
  if (status == SALTS_OK || kind == CNET_COMMAND_CLOSE)
    status = cnet_session_table_state(&record->sessions, connection.session, &state);
  if (status == SALTS_OK &&
      (kind == CNET_COMMAND_RECEIVE || kind == CNET_COMMAND_START_TLS) &&
      state != CNET_SESSION_OPEN)
    status = SALTS_EBUSY;
  if (status == SALTS_OK && kind == CNET_COMMAND_CLOSE && state == CNET_SESSION_DRAINING)
    status = SALTS_EALREADY;
  if (status == SALTS_OK && state == CNET_SESSION_TERMINAL) status = SALTS_EALREADY;
  if (status == SALTS_OK) status = cnet_command_queue_publish(&record->commands, command);
  cmeta_mutex_unlock(&impl->admission_lock);
  return status;
}
static int cnet_shards_direct_write_ready(cnet_shards_impl *impl,
                                          cnet_shard_connection connection,
                                          cnet_shard_record **out_record) {
  cnet_shard_record *record;
  cnet_session_state state = CNET_SESSION_FREE;
  int status;

  if (out_record == NULL) return SALTS_EINVAL;
  *out_record = NULL;
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  if (record == NULL) return SALTS_ENOENT;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  status = cnet_shards_first_error(impl);
  if (status != SALTS_OK) return status;
  status = cnet_session_table_state(&record->sessions, connection.session, &state);
  if (status != SALTS_OK) return status;
  if (state != CNET_SESSION_OPEN) return SALTS_EBUSY;
  *out_record = record;
  return SALTS_OK;
}
int cnet_shards_send_buffer_direct(cnet_shards *shards, cnet_shard_connection connection,
                                   mem_buffer_t *buffer) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  size_t size;
  int status;
  if (buffer == NULL) return SALTS_EINVAL;
  size = mem_buffer_used(buffer);
  if (size == 0u || mem_buffer_const_data(buffer) == NULL) return SALTS_EINVAL;
  if (impl != NULL && size > impl->max_write_payload_bytes) return SALTS_EMSGSIZE;
  status = cnet_shards_direct_write_ready(impl, connection, &record);
  return status == SALTS_OK
             ? cnet_owner_send_buffer_direct(&record->owner, connection.session, buffer)
             : status;
}

int cnet_shards_send_slice_direct(cnet_shards *shards, cnet_shard_connection connection,
                                  const mem_slice_t *slice) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  int status;
  if (slice == NULL || slice->buffer == NULL || slice->data == NULL || slice->length == 0u)
    return SALTS_EINVAL;
  if (impl != NULL && slice->length > impl->max_write_payload_bytes) return SALTS_EMSGSIZE;
  status = cnet_shards_direct_write_ready(impl, connection, &record);
  return status == SALTS_OK
             ? cnet_owner_send_slice_direct(&record->owner, connection.session, slice)
             : status;
}

int cnet_shards_send_slicev_direct(cnet_shards *shards,
                                   cnet_shard_connection connection,
                                   const mem_slice_t *segments, size_t segment_count) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  int status;
  if (segments == NULL || segment_count == 0u || segment_count > CNET_RETAINED_VECTOR_MAX)
    return SALTS_EINVAL;
  status = cnet_shards_direct_write_ready(impl, connection, &record);
  return status == SALTS_OK
             ? cnet_owner_send_slicev_direct(&record->owner, connection.session,
                                             segments, segment_count)
             : status;
}

int cnet_shards_send_slicev_close_direct(cnet_shards *shards,
                                         cnet_shard_connection connection,
                                         const mem_slice_t *segments,
                                         size_t segment_count) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  int status;
  if (segments == NULL || segment_count == 0u || segment_count > CNET_RETAINED_VECTOR_MAX)
    return SALTS_EINVAL;
  status = cnet_shards_direct_write_ready(impl, connection, &record);
  return status == SALTS_OK
             ? cnet_owner_send_slicev_close_direct(&record->owner, connection.session,
                                                   segments, segment_count)
             : status;
}

int cnet_shards_send_buffer_close_direct(cnet_shards *shards,
                                         cnet_shard_connection connection,
                                         mem_buffer_t *buffer) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  size_t size;
  int status;
  if (buffer == NULL) return SALTS_EINVAL;
  size = mem_buffer_used(buffer);
  if (size == 0u || mem_buffer_const_data(buffer) == NULL) return SALTS_EINVAL;
  if (impl != NULL && size > impl->max_write_payload_bytes) return SALTS_EMSGSIZE;
  status = cnet_shards_direct_write_ready(impl, connection, &record);
  return status == SALTS_OK
             ? cnet_owner_send_buffer_close_direct(&record->owner, connection.session, buffer)
             : status;
}

int cnet_shards_receive(cnet_shards *shards, cnet_shard_connection connection, size_t demand) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  const cnet_command command = {
      .kind = CNET_COMMAND_RECEIVE, .connection = connection.session, .argument = demand};
  if (impl == NULL || demand == 0u) return SALTS_EINVAL;
  return cnet_shards_publish(impl, connection, &command);
}

int cnet_shards_receive_direct(cnet_shards *shards, cnet_shard_connection connection,
                               size_t demand) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  int status;

  if (impl == NULL || demand == 0u) return SALTS_EINVAL;
  if (!cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  if (record == NULL) return SALTS_ENOENT;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  status = cnet_shards_first_error(impl);
  if (status != SALTS_OK) return status;
  return cnet_owner_receive_direct(&record->owner, connection.session, demand);
}

int cnet_shards_start_tls(cnet_shards *shards, cnet_shard_connection connection,
                          const cnet_owner_start_tls_payload *payload) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  const cnet_command command = {.kind = CNET_COMMAND_START_TLS,
                                .connection = connection.session,
                                .data = payload,
                                .size = sizeof(*payload)};
  if (impl == NULL || payload == NULL || payload->tls_context == NULL) return SALTS_EINVAL;
  return cnet_shards_publish(impl, connection, &command);
}

int cnet_shards_close(cnet_shards *shards, cnet_shard_connection connection) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  const cnet_command command = {.kind = CNET_COMMAND_CLOSE, .connection = connection.session};
  if (impl == NULL) return SALTS_EINVAL;
  return cnet_shards_publish(impl, connection, &command);
}

int cnet_shards_close_direct(cnet_shards *shards, cnet_shard_connection connection) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (impl == NULL) return SALTS_EINVAL;
  if (!cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  if (record == NULL) return SALTS_ENOENT;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  return cnet_owner_close_direct(&record->owner, connection.session);
}

int cnet_shards_state(cnet_shards *shards, cnet_shard_connection connection,
                      cnet_session_state *out_state) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (out_state == NULL) return SALTS_EINVAL;
  *out_state = CNET_SESSION_FREE;
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL ? cnet_session_table_state(&record->sessions, connection.session, out_state)
                        : SALTS_ENOENT;
}

int cnet_shards_tcp_local_peer(cnet_shards *shards, cnet_shard_connection connection,
                               cnet_stream_peer *out_peer) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (out_peer == NULL) return SALTS_EINVAL;
  *out_peer = (cnet_stream_peer){0};
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tcp_local_peer(&record->owner, connection.session, out_peer)
             : SALTS_ENOENT;
}

int cnet_shards_tcp_remote_peer(cnet_shards *shards, cnet_shard_connection connection,
                                cnet_stream_peer *out_peer) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (out_peer == NULL) return SALTS_EINVAL;
  *out_peer = (cnet_stream_peer){0};
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tcp_remote_peer(&record->owner, connection.session, out_peer)
             : SALTS_ENOENT;
}

int cnet_shards_tcp_local_endpoint(
    cnet_shards *shards, cnet_shard_connection connection,
    cnet_stream_endpoint *out_endpoint) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (out_endpoint == NULL) return SALTS_EINVAL;
  *out_endpoint = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  if (impl == NULL || !cnet_shard_connection_valid(connection))
    return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tcp_local_endpoint(
                   &record->owner, connection.session, out_endpoint)
             : SALTS_ENOENT;
}

int cnet_shards_tcp_remote_endpoint(
    cnet_shards *shards, cnet_shard_connection connection,
    cnet_stream_endpoint *out_endpoint) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (out_endpoint == NULL) return SALTS_EINVAL;
  *out_endpoint = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  if (impl == NULL || !cnet_shard_connection_valid(connection))
    return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tcp_remote_endpoint(
                   &record->owner, connection.session, out_endpoint)
             : SALTS_ENOENT;
}

int cnet_shards_tcp_option_get(cnet_shards *shards, cnet_shard_connection connection,
                               cnet_tcp_socket_option option, uint64_t *out_value) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (out_value == NULL) return SALTS_EINVAL;
  *out_value = 0u;
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tcp_option_get(&record->owner, connection.session, option, out_value)
             : SALTS_ENOENT;
}

int cnet_shards_tcp_option_set(cnet_shards *shards, cnet_shard_connection connection,
                               cnet_tcp_socket_option option, uint64_t value) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tcp_option_set(&record->owner, connection.session, option, value)
             : SALTS_ENOENT;
}

int cnet_shards_preserve_send_on_eof(cnet_shards *shards, cnet_shard_connection connection) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL ? cnet_owner_preserve_send_on_eof(&record->owner, connection.session) : SALTS_ENOENT;
}

int cnet_shards_tcp_shutdown(cnet_shards *shards, cnet_shard_connection connection,
                             cnet_tcp_shutdown how) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (impl == NULL || !cnet_shard_connection_valid(connection))
    return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tcp_shutdown(&record->owner, connection.session, how)
             : SALTS_ENOENT;
}

int cnet_shards_tls_negotiated_version(cnet_shards *shards, cnet_shard_connection connection,
                                       char *buffer, size_t capacity, size_t *out_size) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (out_size == NULL) return SALTS_EINVAL;
  *out_size = 0u;
  if (buffer == NULL || capacity == 0u) return SALTS_EINVAL;
  buffer[0] = '\0';
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tls_negotiated_version(&record->owner, connection.session, buffer,
                                                 capacity, out_size)
             : SALTS_ENOENT;
}

int cnet_shards_tls_negotiated_cipher(cnet_shards *shards, cnet_shard_connection connection,
                                      char *buffer, size_t capacity, size_t *out_size) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (out_size == NULL) return SALTS_EINVAL;
  *out_size = 0u;
  if (buffer == NULL || capacity == 0u) return SALTS_EINVAL;
  buffer[0] = '\0';
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tls_negotiated_cipher(&record->owner, connection.session, buffer,
                                                capacity, out_size)
             : SALTS_ENOENT;
}

int cnet_shards_tls_peer_certificate_sha256(
    cnet_shards *shards, cnet_shard_connection connection,
    char buffer[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY]) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (buffer == NULL) return SALTS_EINVAL;
  buffer[0] = '\0';
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tls_peer_certificate_sha256(&record->owner, connection.session, buffer)
             : SALTS_ENOENT;
}

int cnet_shards_tls_server_end_point_binding(
    cnet_shards *shards, cnet_shard_connection connection,
    uint8_t *output, size_t capacity, size_t *out_size) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  size_t clear_size;
  if (output == NULL || capacity == 0u || out_size == NULL)
    return SALTS_EINVAL;
  clear_size = capacity < CNET_TLS_SERVER_END_POINT_MAX_BYTES
                   ? capacity
                   : CNET_TLS_SERVER_END_POINT_MAX_BYTES;
  memset(output, 0, clear_size);
  *out_size = 0u;
  if (impl == NULL || !cnet_shard_connection_valid(connection))
    return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tls_server_end_point_binding(
                   &record->owner, connection.session, output, capacity,
                   out_size)
             : SALTS_ENOENT;
}

int cnet_shards_tls_export_channel_binding(cnet_shards *shards, cnet_shard_connection connection,
                                           uint8_t output[CNET_TLS_CHANNEL_BINDING_BYTES]) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  if (output == NULL) return SALTS_EINVAL;
  memset(output, 0, CNET_TLS_CHANNEL_BINDING_BYTES);
  if (impl == NULL || !cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  return record != NULL
             ? cnet_owner_tls_export_channel_binding(&record->owner, connection.session, output)
             : SALTS_ENOENT;
}

int cnet_shards_take_event(cnet_shards *shards, uint32_t shard, cnet_event_view *out_event) {
  cnet_shard_record *record = cnet_shards_get_record(cnet_shards_get(shards), shard);
  return record != NULL ? cnet_event_queue_take(&record->events, out_event) : SALTS_EINVAL;
}

int cnet_shards_release_event(cnet_shards *shards, uint32_t shard, cnet_event_view *event) {
  cnet_shard_record *record = cnet_shards_get_record(cnet_shards_get(shards), shard);
  return record != NULL ? cnet_event_queue_release(&record->events, event) : SALTS_EINVAL;
}

int cnet_shards_recycle(cnet_shards *shards, cnet_shard_connection connection,
                        cnet_session_terminal *out_terminal) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  cnet_shard_record *record;
  int status;

  if (impl == NULL || out_terminal == NULL) return SALTS_EINVAL;
  memset(out_terminal, 0, sizeof(*out_terminal));
  if (!cnet_shard_connection_valid(connection)) return SALTS_ENOENT;
  record = cnet_shards_get_record(impl, connection.shard);
  if (record == NULL) return SALTS_ENOENT;

  cmeta_mutex_lock(&impl->admission_lock);
  status = cnet_session_table_take_terminal(&record->sessions, connection.session, out_terminal);
  if (status == SALTS_OK)
    status = cnet_session_table_recycle(&record->sessions, connection.session);
  if (status == SALTS_OK) status = cnet_owner_release_session(&record->owner, connection.session);
  if (status == SALTS_OK) {
    if (impl->active_connections == 0u) status = SALTS_EPROTO;
    else --impl->active_connections;
  }
  cmeta_mutex_unlock(&impl->admission_lock);
  return status;
}

int cnet_shards_stop(cnet_shards *shards, uint32_t timeout_ms) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  size_t index;
  int first_status;
  int status;

  (void)timeout_ms;
  if (impl == NULL) return SALTS_EINVAL;
  cmeta_mutex_lock(&impl->admission_lock);
  if (impl->stopped) {
    cmeta_mutex_unlock(&impl->admission_lock);
    return SALTS_EALREADY;
  }
  if (!impl->stopping) {
    if (impl->active_connections != 0u) {
      cmeta_mutex_unlock(&impl->admission_lock);
      return SALTS_EBUSY;
    }
    impl->admission_open = false;
    for (index = 0u; index < impl->shard_count; ++index) {
      status = cnet_command_queue_close(&impl->records[index].commands);
      if (status != SALTS_OK) {
        cmeta_mutex_unlock(&impl->admission_lock);
        return status;
      }
    }
    impl->stopping = true;
  }
  cmeta_mutex_unlock(&impl->admission_lock);

  first_status = cnet_shards_first_error(impl);
  for (index = 0u; index < impl->shard_count; ++index) {
    cnet_shard_record *record = &impl->records[index];
    if (!record->owner_closed) {
      if (record->owner.impl != NULL) {
        status = cnet_owner_close(&record->owner);
        if (status != SALTS_OK) return status;
      }
      record->owner_closed = true;
    }
    status = cnet_event_queue_close(&record->events);
    if (status != SALTS_OK && status != SALTS_EALREADY) return status;
  }
  impl->stopped = true;
  return first_status;
}

bool cnet_shards_stopped(const cnet_shards *shards) {
  const cnet_shards_impl *impl = shards != NULL ? (const cnet_shards_impl *)shards->impl : NULL;
  return impl != NULL && impl->stopped;
}

int cnet_shards_destroy(cnet_shards *shards) {
  cnet_shards_impl *impl = cnet_shards_get(shards);
  size_t index;
  int status;

  if (shards == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;
  if (!impl->stopped || impl->active_connections != 0u) return SALTS_EBUSY;
  for (index = 0u; index < impl->shard_count; ++index) {
    cnet_shard_record *record = &impl->records[index];
    status = cnet_event_queue_destroy(&record->events);
    if (status != SALTS_OK) return status;
    status = cnet_owner_destroy(&record->owner);
    if (status != SALTS_OK) return status;
    status = cnet_command_queue_destroy(&record->commands);
    if (status != SALTS_OK) return status;
    status = cnet_session_table_destroy(&record->sessions);
    if (status != SALTS_OK) return status;
  }
  cmeta_mutex_destroy(&impl->admission_lock);
  cnet_storage_free(impl->records);
  cnet_storage_free(impl);
  shards->impl = NULL;
  return SALTS_OK;
}
