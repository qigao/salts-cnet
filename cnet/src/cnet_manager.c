#include "cnet_resources.h"
#include "cnet_client_internal.h"
#include <cnet/manager.h>
#include <thread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct manager_impl manager_impl;
typedef struct manager_record {
  manager_impl *owner;
  cnet_manager_attachment attachment;
  cnet_managed_connection identity;
  cnet_connection connection;
  cnet_receive_slice_fn slice_handler;
  void *slice_user;
  size_t next_free;
  cnet_manager_record_state state;
  bool held;
  bool close_sent;
} manager_record;

struct manager_impl {
  cnet_client *client;
  const void *thread;
  manager_record *records;
  size_t capacity, limit, free_head, cursor;
  size_t reserved, bound, retired, holds, ready, close_pending, callbacks;
  bool sealed, closing, advancing;
};

/* An incarnation source, not a connection registry. Never wrap into a live or
 * previously issued identity. The wrapper address also qualifies each handle. */
static atomic_uint_fast64_t manager_incarnation;

static int get_manager(cnet_manager *manager, manager_impl **out) {
  if (manager == NULL || manager->impl == NULL) return SALTS_EINVAL;
  *out = manager->impl;
  return (*out)->thread == cmeta_thread_current_token() ? SALTS_OK : SALTS_EPERM;
}
static manager_record *find_record(manager_impl *impl, cnet_managed_connection id) {
  manager_record *record;
  if (id.slot == 0u || id.slot > impl->capacity) return NULL;
  record = &impl->records[id.slot - 1u];
  if (record->state == 0 || record->identity.manager != id.manager ||
      record->identity.incarnation != id.incarnation ||
      record->identity.generation != id.generation)
    return NULL;
  return record;
}
static int get_record(cnet_manager *manager, cnet_managed_connection id, manager_impl **impl,
                      manager_record **record) {
  int status = get_manager(manager, impl);
  if (status != SALTS_OK) return status;
  *record = find_record(*impl, id);
  return *record != NULL ? SALTS_OK : SALTS_ENOENT;
}
static void retire_record(manager_record *record) {
  manager_impl *impl = record->owner;
  if (record->state == CNET_MANAGER_RESERVED) --impl->reserved;
  else --impl->bound;
  if (impl->closing && !record->close_sent) --impl->close_pending;
  record->state = CNET_MANAGER_RETIRED;
  ++impl->retired;
  if (!record->held) ++impl->ready;
}
static void observe_state(void *user, cnet_connection connection, cnet_connection_state state,
                          const cnet_error *error) {
  manager_record *record = user;
  manager_impl *impl = record->owner;
  ++impl->callbacks;
  if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) retire_record(record);
  record->attachment.observer.on_state(record->attachment.observer.user, connection, state, error);
  --impl->callbacks;
}
static void observe_receive(void *user, cnet_connection connection, const cnet_receive_view *view) {
  manager_record *record = user;
  ++record->owner->callbacks;
  record->attachment.observer.on_receive(record->attachment.observer.user, connection, view);
  --record->owner->callbacks;
}
static void observe_send(void *user, cnet_connection connection, size_t size) {
  manager_record *record = user;
  ++record->owner->callbacks;
  record->attachment.observer.on_send(record->attachment.observer.user, connection, size);
  --record->owner->callbacks;
}
static void observe_slice(void *user, cnet_connection connection, mem_slice_t slice,
                          cnet_message_kind kind) {
  manager_record *record = user;
  ++record->owner->callbacks;
  record->slice_handler(record->slice_user, connection, slice, kind);
  --record->owner->callbacks;
}
static cnet_observer bridge(manager_record *record) {
  return (cnet_observer){
      .on_state = observe_state,
      .on_receive = record->attachment.observer.on_receive != NULL ? observe_receive : NULL,
      .on_send = record->attachment.observer.on_send != NULL ? observe_send : NULL,
      .user = record};
}

int cnet_manager_init(cnet_manager *manager, const cnet_manager_config *config) {
  manager_impl *impl;
  uint_fast64_t incarnation;
  int status;
  if (manager == NULL || config == NULL) return SALTS_EINVAL;
  if (manager->impl != NULL) return SALTS_EALREADY;
  if (!cnet_allocator_valid(&config->storage) || config->size != sizeof(*config) || config->version != CNET_MANAGER_VERSION ||
      config->client == NULL || config->client->impl == NULL || config->record_capacity == 0u ||
      config->connection_capacity == 0u || config->connection_capacity > config->record_capacity)
    return SALTS_EINVAL;
  if (config->record_capacity > SIZE_MAX / sizeof(manager_record)) return SALTS_ERANGE;
  status = cnet_client_check_owner(config->client);
  if (status != SALTS_OK) return status;
  impl = cnet_storage_alloc(&config->storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->records = cnet_storage_alloc(&config->storage, config->record_capacity, sizeof(*impl->records));
  if (impl->records == NULL) {
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  incarnation = atomic_load_explicit(&manager_incarnation, memory_order_relaxed);
  do {
    if (incarnation >= UINT64_MAX) {
      cnet_storage_free(impl->records);
      cnet_storage_free(impl);
      return SALTS_ERANGE;
    }
  } while (!atomic_compare_exchange_weak_explicit(&manager_incarnation, &incarnation,
                                                  incarnation + 1u, memory_order_relaxed,
                                                  memory_order_relaxed));
  impl->client = config->client;
  impl->thread = cmeta_thread_current_token();
  impl->capacity = config->record_capacity;
  impl->limit = config->connection_capacity;
  for (size_t i = 0u; i < impl->capacity; ++i) {
    manager_record *record = &impl->records[i];
    record->owner = impl;
    record->identity =
        (cnet_managed_connection){(uintptr_t)manager, (uint64_t)(incarnation + 1u), 0u, i + 1u};
    record->next_free = i + 1u;
  }
  manager->impl = impl;
  return SALTS_OK;
}

int cnet_manager_reserve(cnet_manager *manager, const cnet_manager_attachment *attachment,
                         cnet_managed_connection *out) {
  manager_impl *impl;
  manager_record *record;
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_managed_connection){0};
  status = get_manager(manager, &impl);
  if (status != SALTS_OK) return status;
  if (attachment == NULL || attachment->observer.on_state == NULL) return SALTS_EINVAL;
  if (impl->advancing) return SALTS_EBUSY;
  if (impl->sealed) return SALTS_ESHUTDOWN;
  if (impl->reserved + impl->bound >= impl->limit || impl->free_head == impl->capacity)
    return SALTS_ENOBUFS;
  record = &impl->records[impl->free_head];
  if (record->identity.generation == UINT64_MAX) return SALTS_ERANGE;
  impl->free_head = record->next_free;
  ++record->identity.generation;
  record->attachment = *attachment;
  record->connection = (cnet_connection){0};
  record->slice_handler = NULL;
  record->slice_user = NULL;
  record->held = attachment->hold_context;
  record->close_sent = false;
  record->state = CNET_MANAGER_RESERVED;
  ++impl->reserved;
  if (record->held) ++impl->holds;
  *out = record->identity;
  return SALTS_OK;
}
int cnet_manager_cancel(cnet_manager *manager, cnet_managed_connection id) {
  manager_impl *impl;
  manager_record *record;
  int status = get_record(manager, id, &impl, &record);
  if (status != SALTS_OK) return status;
  if (impl->advancing) return SALTS_EBUSY;
  if (record->state == CNET_MANAGER_BOUND) return SALTS_EBUSY;
  if (record->state == CNET_MANAGER_RETIRED) return SALTS_EALREADY;
  retire_record(record);
  return SALTS_OK;
}
static int begin_admit(cnet_manager *manager, cnet_managed_connection id, manager_impl **impl,
                       manager_record **record) {
  int status = get_record(manager, id, impl, record);
  if (status != SALTS_OK) return status;
  if ((*impl)->advancing) return SALTS_EBUSY;
  return (*record)->state == CNET_MANAGER_RESERVED ? SALTS_OK : SALTS_EALREADY;
}
static int end_admit(manager_record *record, int status, cnet_connection connection,
                     cnet_connection *out) {
  if (status != SALTS_OK) retire_record(record);
  else {
    --record->owner->reserved;
    ++record->owner->bound;
    record->state = CNET_MANAGER_BOUND;
    record->connection = connection;
    *out = connection;
  }
  return status;
}
int cnet_manager_connect(cnet_manager *manager, cnet_managed_connection id,
                         const cnet_connect_options *options, cnet_connection *out) {
  manager_impl *impl;
  manager_record *record;
  cnet_connection connection = {0};
  cnet_connect_options copied;
  int status;
  if (out != NULL) *out = (cnet_connection){0};
  status = begin_admit(manager, id, &impl, &record);
  if (status != SALTS_OK) return status;
  if (out == NULL || options == NULL || options->uri == NULL) status = SALTS_EINVAL;
  else if (impl->sealed) status = SALTS_ESHUTDOWN;
  else if (strncmp(options->uri, "tcp://", 6u) != 0 && strncmp(options->uri, "tls://", 6u) != 0)
    status = SALTS_ENOTSUP;
  else {
    copied = *options;
    copied.observer = bridge(record);
    status = cnet_connect(impl->client, &copied, &connection);
  }
  return end_admit(record, status, connection, out);
}
int cnet_manager_adopt(cnet_manager *manager, cnet_managed_connection id,
                       cnet_accepted_stream *accepted, const cnet_tls_server *tls,
                       cnet_connection *out) {
  manager_impl *impl;
  manager_record *record;
  cnet_connection connection = {0};
  cnet_observer observer;
  int status;
  if (out != NULL) *out = (cnet_connection){0};
  status = begin_admit(manager, id, &impl, &record);
  if (status != SALTS_OK) return status;
  if (out == NULL || accepted == NULL) status = SALTS_EINVAL;
  else if (impl->sealed) status = SALTS_ESHUTDOWN;
  else {
    observer = bridge(record);
    status =
        tls != NULL
            ? cnet_client_adopt_accepted_tls(impl->client, accepted, tls, &observer, &connection)
            : cnet_client_adopt_accepted(impl->client, accepted, &observer, &connection);
  }
  if (status != SALTS_OK && accepted != NULL && accepted->internal_active != 0u) {
    const int close_status = cnet_accepted_stream_close(accepted);
    if (close_status != SALTS_OK) status = close_status;
  }
  return end_admit(record, status, connection, out);
}
int cnet_manager_release_context(cnet_manager *manager, cnet_managed_connection id) {
  manager_impl *impl;
  manager_record *record;
  int status = get_record(manager, id, &impl, &record);
  if (status != SALTS_OK) return status;
  if (impl->advancing) return SALTS_EBUSY;
  if (!record->held) return SALTS_EALREADY;
  record->held = false;
  --impl->holds;
  if (record->state == CNET_MANAGER_RETIRED) ++impl->ready;
  return SALTS_OK;
}
static void entry_for(manager_record *record, cnet_manager_entry *out) {
  *out = (cnet_manager_entry){record->identity, record->connection, record->state,
                              record->attachment.observer.user, record->held};
}
int cnet_manager_lookup(cnet_manager *manager, cnet_managed_connection id,
                        cnet_manager_entry *out) {
  manager_impl *impl;
  manager_record *record;
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_manager_entry){0};
  status = get_record(manager, id, &impl, &record);
  if (status == SALTS_OK) entry_for(record, out);
  return status;
}
int cnet_manager_inspect(cnet_manager *manager, size_t index, cnet_manager_entry *out) {
  manager_impl *impl;
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_manager_entry){0};
  status = get_manager(manager, &impl);
  if (status != SALTS_OK) return status;
  if (index >= impl->capacity) return SALTS_ERANGE;
  if (impl->records[index].state == 0) return SALTS_ENOENT;
  entry_for(&impl->records[index], out);
  return SALTS_OK;
}
int cnet_manager_set_receive_slice_handler(cnet_manager *manager, cnet_managed_connection id,
                                           cnet_receive_slice_fn handler, void *user) {
  manager_impl *impl;
  manager_record *record;
  int status = get_record(manager, id, &impl, &record);
  if (status != SALTS_OK) return status;
  if (impl->advancing) return SALTS_EBUSY;
  if (record->state != CNET_MANAGER_BOUND) return SALTS_EBUSY;
  status = cnet_set_receive_slice_handler(impl->client, record->connection,
                                          handler != NULL ? observe_slice : NULL, record);
  if (status == SALTS_OK) {
    record->slice_handler = handler;
    record->slice_user = user;
  }
  return status;
}
int cnet_manager_seal(cnet_manager *manager) {
  manager_impl *impl;
  int status = get_manager(manager, &impl);
  if (status != SALTS_OK) return status;
  if (impl->advancing) return SALTS_EBUSY;
  impl->sealed = true;
  return SALTS_OK;
}
int cnet_manager_request_close(cnet_manager *manager) {
  manager_impl *impl;
  int status = get_manager(manager, &impl);
  if (status != SALTS_OK) return status;
  if (impl->advancing) return SALTS_EBUSY;
  impl->sealed = true;
  if (!impl->closing) {
    impl->closing = true;
    impl->close_pending = impl->reserved + impl->bound;
  }
  return SALTS_OK;
}
int cnet_manager_advance(cnet_manager *manager, size_t budget, size_t *out_work) {
  manager_impl *impl;
  int status, first = SALTS_OK;
  if (out_work == NULL) return SALTS_EINVAL;
  *out_work = 0u;
  status = get_manager(manager, &impl);
  if (status != SALTS_OK) return status;
  if (budget == 0u) return SALTS_EINVAL;
  if (impl->advancing || impl->callbacks != 0u) return SALTS_EBUSY;
  impl->advancing = true;
  if (budget > impl->capacity) budget = impl->capacity;
  for (size_t i = 0u; i < budget && (impl->ready != 0u || impl->close_pending != 0u); ++i) {
    manager_record *record = &impl->records[impl->cursor];
    impl->cursor = impl->cursor + 1u == impl->capacity ? 0u : impl->cursor + 1u;
    if (impl->closing && record->state == CNET_MANAGER_RESERVED) {
      retire_record(record);
      ++*out_work;
    } else if (impl->closing && record->state == CNET_MANAGER_BOUND && !record->close_sent) {
      status = cnet_close(impl->client, record->connection);
      if (status == SALTS_OK || status == SALTS_EALREADY) {
        record->close_sent = true;
        --impl->close_pending;
      } else if (first == SALTS_OK) first = status;
      ++*out_work;
    } else if (record->state == CNET_MANAGER_RETIRED && !record->held) {
      if (record->attachment.on_recycle != NULL)
        record->attachment.on_recycle(record->attachment.observer.user);
      record->attachment = (cnet_manager_attachment){0};
      record->state = 0;
      record->next_free = impl->free_head;
      impl->free_head = record->identity.slot - 1u;
      --impl->retired;
      --impl->ready;
      ++*out_work;
    }
  }
  impl->advancing = false;
  return first;
}
int cnet_manager_get_snapshot(cnet_manager *manager, cnet_manager_snapshot *out) {
  manager_impl *impl;
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_manager_snapshot){0};
  status = get_manager(manager, &impl);
  if (status != SALTS_OK) return status;
  *out = (cnet_manager_snapshot){impl->capacity,
                                 impl->limit,
                                 impl->reserved,
                                 impl->bound,
                                 impl->retired,
                                 impl->holds,
                                 impl->ready,
                                 impl->sealed,
                                 impl->ready != 0u || impl->close_pending != 0u,
                                 impl->reserved == 0u && impl->bound == 0u && impl->retired == 0u &&
                                     impl->callbacks == 0u && !impl->advancing};
  return SALTS_OK;
}
int cnet_manager_destroy(cnet_manager *manager) {
  manager_impl *impl;
  int status;
  if (manager == NULL) return SALTS_EINVAL;
  if (manager->impl == NULL) return SALTS_EALREADY;
  status = get_manager(manager, &impl);
  if (status != SALTS_OK) return status;
  if (impl->advancing || impl->callbacks != 0u || impl->reserved != 0u || impl->bound != 0u ||
      impl->retired != 0u)
    return SALTS_EBUSY;
  cnet_storage_free(impl->records);
  cnet_storage_free(impl);
  manager->impl = NULL;
  return SALTS_OK;
}
