#include "cnet_resources.h"
#include "cnet_session.h"

#include <thread.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct cnet_session_entry {
  cnet_session_state state;
  uint32_t generation;
  cnet_session_terminal terminal;
  bool terminal_taken;
} cnet_session_entry;

typedef struct cnet_session_table_impl {
  cnet_session_entry *entries;
  uint32_t *free_slots;
  size_t capacity;
  size_t active;
  size_t free_count;
  cmeta_mutex_t lock;
} cnet_session_table_impl;

static cnet_session_table_impl *cnet_session_impl(cnet_session_table *table) {
  return table != NULL ? (cnet_session_table_impl *)table->impl : NULL;
}

static const cnet_session_table_impl *cnet_session_const_impl(const cnet_session_table *table) {
  return table != NULL ? (const cnet_session_table_impl *)table->impl : NULL;
}

static cnet_session_entry *cnet_session_find(cnet_session_table_impl *impl,
                                             cnet_session_handle handle) {
  cnet_session_entry *entry;

  if (impl == NULL || !cnet_session_handle_valid(handle) || (size_t)handle.slot > impl->capacity)
    return NULL;
  entry = &impl->entries[handle.slot - 1u];
  if (entry->state == CNET_SESSION_FREE || entry->state == CNET_SESSION_RETIRED ||
      entry->generation != handle.generation)
    return NULL;
  return entry;
}

static const cnet_session_entry *cnet_session_const_find(const cnet_session_table_impl *impl,
                                                         cnet_session_handle handle) {
  const cnet_session_entry *entry;

  if (impl == NULL || !cnet_session_handle_valid(handle) || (size_t)handle.slot > impl->capacity)
    return NULL;
  entry = &impl->entries[handle.slot - 1u];
  if (entry->state == CNET_SESSION_FREE || entry->state == CNET_SESSION_RETIRED ||
      entry->generation != handle.generation)
    return NULL;
  return entry;
}

static bool cnet_session_transition_allowed(cnet_session_state current, cnet_session_state next) {
  switch (current) {
  case CNET_SESSION_RESERVED:
    return next == CNET_SESSION_RESOLVING || next == CNET_SESSION_TRANSPORT_CONNECTING ||
           next == CNET_SESSION_DRAINING;
  case CNET_SESSION_RESOLVING:
    return next == CNET_SESSION_TRANSPORT_CONNECTING || next == CNET_SESSION_DRAINING;
  case CNET_SESSION_TRANSPORT_CONNECTING:
    return next == CNET_SESSION_PROTOCOL_HANDSHAKING || next == CNET_SESSION_OPEN ||
           next == CNET_SESSION_DRAINING;
  case CNET_SESSION_PROTOCOL_HANDSHAKING:
    return next == CNET_SESSION_OPEN || next == CNET_SESSION_DRAINING;
  case CNET_SESSION_OPEN:
    return next == CNET_SESSION_PROTOCOL_HANDSHAKING || next == CNET_SESSION_DRAINING;
  default:
    return false;
  }
}

static void cnet_session_set_terminal(cnet_session_entry *entry, cnet_session_terminal_kind kind,
                                      int status, cnet_session_stage stage) {
  entry->state = CNET_SESSION_TERMINAL;
  entry->terminal.kind = kind;
  entry->terminal.status = status;
  entry->terminal.stage = stage;
  entry->terminal_taken = false;
}

static int cnet_session_release_entry(cnet_session_table_impl *impl, cnet_session_entry *entry) {
  const size_t index = (size_t)(entry - impl->entries);
  if (impl->active == 0u || index >= impl->capacity ||
      (entry->generation != UINT32_MAX && impl->free_count >= impl->capacity))
    return SALTS_EPROTO;
  --impl->active;
  if (entry->generation == UINT32_MAX) {
    entry->state = CNET_SESSION_RETIRED;
  } else {
    ++entry->generation;
    entry->state = CNET_SESSION_FREE;
    impl->free_slots[impl->free_count++] = (uint32_t)index;
  }
  return SALTS_OK;
}

bool cnet_session_handle_valid(cnet_session_handle handle) {
  return handle.slot != 0u && handle.generation != 0u;
}

int cnet_session_table_init(cnet_session_table *table, size_t capacity) {
  return cnet_session_table_init_with_storage(table, capacity, NULL);
}
int cnet_session_table_init_with_storage(cnet_session_table *table, size_t capacity, const cnet_allocator *storage) {
  cnet_session_table_impl *impl;

  if (table == NULL) return SALTS_EINVAL;
  if (table->impl != NULL) return SALTS_EALREADY;
  if (capacity == 0u) return SALTS_EINVAL;
  if (capacity > UINT32_MAX || capacity > SIZE_MAX / sizeof(cnet_session_entry) ||
      capacity > SIZE_MAX / sizeof(uint32_t))
    return SALTS_ERANGE;

  impl = (cnet_session_table_impl *)cnet_storage_alloc(storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->entries = (cnet_session_entry *)cnet_storage_alloc(storage, capacity, sizeof(*impl->entries));
  impl->free_slots = (uint32_t *)cnet_storage_alloc(storage, capacity, sizeof(*impl->free_slots));
  if (impl->entries == NULL || impl->free_slots == NULL) {
    cnet_storage_free(impl->free_slots);
    cnet_storage_free(impl->entries);
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  impl->capacity = capacity;
  impl->free_count = capacity;
  for (size_t index = 0u; index < capacity; ++index)
    impl->free_slots[index] = (uint32_t)(capacity - index - 1u);
  cmeta_mutex_init(&impl->lock);
  table->impl = impl;
  return SALTS_OK;
}

int cnet_session_table_destroy(cnet_session_table *table) {
  cnet_session_table_impl *impl = cnet_session_impl(table);

  if (table == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;
  cmeta_mutex_lock(&impl->lock);
  if (impl->active != 0u) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EBUSY;
  }
  cmeta_mutex_unlock(&impl->lock);
  cmeta_mutex_destroy(&impl->lock);
  cnet_storage_free(impl->free_slots);
  cnet_storage_free(impl->entries);
  cnet_storage_free(impl);
  table->impl = NULL;
  return SALTS_OK;
}

int cnet_session_table_reserve(cnet_session_table *table, cnet_session_handle *out_handle) {
  cnet_session_table_impl *impl = cnet_session_impl(table);
  cnet_session_entry *entry;
  size_t index;

  if (out_handle == NULL) return SALTS_EINVAL;
  memset(out_handle, 0, sizeof(*out_handle));
  if (impl == NULL) return SALTS_EINVAL;

  cmeta_mutex_lock(&impl->lock);
  if (impl->free_count == 0u) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOBUFS;
  }
  index = impl->free_slots[impl->free_count - 1u];
  if (index >= impl->capacity || impl->entries[index].state != CNET_SESSION_FREE) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EPROTO;
  }
  --impl->free_count;
  entry = &impl->entries[index];
  if (entry->generation == 0u) entry->generation = 1u;
  entry->state = CNET_SESSION_RESERVED;
  memset(&entry->terminal, 0, sizeof(entry->terminal));
  entry->terminal_taken = false;
  ++impl->active;
  out_handle->slot = (uint32_t)(index + 1u);
  out_handle->generation = entry->generation;
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}

int cnet_session_table_release_reservation(cnet_session_table *table, cnet_session_handle handle) {
  cnet_session_table_impl *impl = cnet_session_impl(table);
  cnet_session_entry *entry;

  if (impl == NULL) return SALTS_ENOENT;
  cmeta_mutex_lock(&impl->lock);
  entry = cnet_session_find(impl, handle);
  if (entry == NULL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOENT;
  }
  if (entry->state != CNET_SESSION_RESERVED) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EBUSY;
  }
  {
    const int status = cnet_session_release_entry(impl, entry);
    if (status != SALTS_OK) {
      cmeta_mutex_unlock(&impl->lock);
      return status;
    }
  }
  memset(&entry->terminal, 0, sizeof(entry->terminal));
  entry->terminal_taken = false;
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}

int cnet_session_table_state(const cnet_session_table *table, cnet_session_handle handle,
                             cnet_session_state *out_state) {
  const cnet_session_entry *entry;

  if (out_state == NULL) return SALTS_EINVAL;
  cnet_session_table_impl *impl = (cnet_session_table_impl *)cnet_session_const_impl(table);
  if (impl == NULL) return SALTS_ENOENT;
  cmeta_mutex_lock(&impl->lock);
  entry = cnet_session_const_find(impl, handle);
  if (entry == NULL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOENT;
  }
  *out_state = entry->state;
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}

int cnet_session_table_transition(cnet_session_table *table, cnet_session_handle handle,
                                  cnet_session_state next) {
  cnet_session_table_impl *impl = cnet_session_impl(table);
  cnet_session_entry *entry;

  if (impl == NULL) return SALTS_ENOENT;
  cmeta_mutex_lock(&impl->lock);
  entry = cnet_session_find(impl, handle);
  if (entry == NULL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOENT;
  }
  if (!cnet_session_transition_allowed(entry->state, next)) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EPROTO;
  }
  entry->state = next;
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}

int cnet_session_table_begin_close(cnet_session_table *table, cnet_session_handle handle) {
  cnet_session_table_impl *impl = cnet_session_impl(table);
  cnet_session_entry *entry;

  if (impl == NULL) return SALTS_ENOENT;
  cmeta_mutex_lock(&impl->lock);
  entry = cnet_session_find(impl, handle);
  if (entry == NULL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOENT;
  }
  if (entry->state == CNET_SESSION_DRAINING || entry->state == CNET_SESSION_TERMINAL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EALREADY;
  }
  if (!cnet_session_transition_allowed(entry->state, CNET_SESSION_DRAINING)) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EPROTO;
  }
  entry->state = CNET_SESSION_DRAINING;
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}

int cnet_session_table_finish_close(cnet_session_table *table, cnet_session_handle handle) {
  cnet_session_table_impl *impl = cnet_session_impl(table);
  cnet_session_entry *entry;

  if (impl == NULL) return SALTS_ENOENT;
  cmeta_mutex_lock(&impl->lock);
  entry = cnet_session_find(impl, handle);
  if (entry == NULL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOENT;
  }
  if (entry->state == CNET_SESSION_TERMINAL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EALREADY;
  }
  if (entry->state != CNET_SESSION_DRAINING) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EPROTO;
  }
  cnet_session_set_terminal(entry, CNET_SESSION_TERMINAL_CLOSED, SALTS_OK, CNET_SESSION_STAGE_NONE);
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}

int cnet_session_table_fail(cnet_session_table *table, cnet_session_handle handle, int status,
                            cnet_session_stage stage) {
  cnet_session_entry *entry;
  cnet_session_table_impl *impl;

  if (status >= SALTS_OK || stage <= CNET_SESSION_STAGE_NONE || stage > CNET_SESSION_STAGE_CALLBACK)
    return SALTS_EINVAL;
  impl = cnet_session_impl(table);
  if (impl == NULL) return SALTS_ENOENT;
  cmeta_mutex_lock(&impl->lock);
  entry = cnet_session_find(impl, handle);
  if (entry == NULL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOENT;
  }
  if (entry->state == CNET_SESSION_TERMINAL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EALREADY;
  }
  cnet_session_set_terminal(entry, CNET_SESSION_TERMINAL_FAILED, status, stage);
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}

int cnet_session_table_take_terminal(cnet_session_table *table, cnet_session_handle handle,
                                     cnet_session_terminal *out_terminal) {
  cnet_session_entry *entry;
  cnet_session_table_impl *impl;

  if (out_terminal == NULL) return SALTS_EINVAL;
  memset(out_terminal, 0, sizeof(*out_terminal));
  impl = cnet_session_impl(table);
  if (impl == NULL) return SALTS_ENOENT;
  cmeta_mutex_lock(&impl->lock);
  entry = cnet_session_find(impl, handle);
  if (entry == NULL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOENT;
  }
  if (entry->state != CNET_SESSION_TERMINAL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EBUSY;
  }
  if (entry->terminal_taken) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EALREADY;
  }
  *out_terminal = entry->terminal;
  entry->terminal_taken = true;
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}

int cnet_session_table_recycle(cnet_session_table *table, cnet_session_handle handle) {
  cnet_session_table_impl *impl = cnet_session_impl(table);
  cnet_session_entry *entry;

  if (impl == NULL) return SALTS_ENOENT;
  cmeta_mutex_lock(&impl->lock);
  entry = cnet_session_find(impl, handle);
  if (entry == NULL) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_ENOENT;
  }
  if (entry->state != CNET_SESSION_TERMINAL || !entry->terminal_taken) {
    cmeta_mutex_unlock(&impl->lock);
    return SALTS_EBUSY;
  }

  {
    const int status = cnet_session_release_entry(impl, entry);
    if (status != SALTS_OK) {
      cmeta_mutex_unlock(&impl->lock);
      return status;
    }
  }
  memset(&entry->terminal, 0, sizeof(entry->terminal));
  entry->terminal_taken = false;
  cmeta_mutex_unlock(&impl->lock);
  return SALTS_OK;
}
