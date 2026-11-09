#include "cnet_resources.h"
#include "cnet_write_queue.h"

#include <core/error_codes.h>
#include <memory/buffer.h>

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CNET_WRITE_SLOT_NONE UINT32_MAX

_Static_assert(CNET_RETAINED_VECTOR_MAX >= NATIVE_IO_VECTOR_MAX,
               "CNet logical retained vectors must cover one NativeIO window");

typedef enum cnet_write_entry_state {
  CNET_WRITE_ENTRY_FREE = 0,
  CNET_WRITE_ENTRY_QUEUED
} cnet_write_entry_state;

typedef enum cnet_write_payload_kind {
  CNET_WRITE_PAYLOAD_RETAINED = 0,
  CNET_WRITE_PAYLOAD_RETAINED_VECTOR
} cnet_write_payload_kind;

typedef struct cnet_write_range {
  mem_buffer_t *buffer;
  size_t base_offset;
  size_t length;
} cnet_write_range;

typedef struct cnet_write_entry {
  cnet_session_handle connection;
  mem_buffer_t *payload;
  size_t size;
  size_t base_offset;
  size_t offset;
  cnet_write_range ranges[CNET_RETAINED_VECTOR_MAX];
  mem_buffer_t *owners[CNET_RETAINED_VECTOR_MAX];
  size_t range_count;
  size_t owner_count;
  uint32_t generation;
  uint32_t next;
  cnet_write_entry_state state;
  cnet_write_payload_kind payload_kind;
  bool close_after_send;
} cnet_write_entry;

typedef struct cnet_write_queue_impl {
  cnet_write_entry *entries;
  uint32_t *free_slots;
  uint32_t *heads;
  uint32_t *tails;
  size_t *counts;
  size_t connection_capacity;
  size_t capacity;
  size_t max_payload_bytes;
  size_t free_count;
  size_t live_writes;
  size_t peak_writes;
  bool admission_open;
} cnet_write_queue_impl;

static cnet_write_queue_impl *cnet_write_impl(cnet_write_queue *queue) {
  return queue != NULL ? (cnet_write_queue_impl *)queue->impl : NULL;
}

static const cnet_write_queue_impl *cnet_write_const_impl(const cnet_write_queue *queue) {
  return queue != NULL ? (const cnet_write_queue_impl *)queue->impl : NULL;
}

static uint32_t cnet_write_next_generation(uint32_t generation) {
  return generation == UINT32_MAX ? 1u : generation + 1u;
}

static uint64_t cnet_write_token(size_t slot, uint32_t generation) {
  return ((uint64_t)generation << 32u) | ((uint64_t)slot + 1u);
}

static size_t cnet_write_connection_index(const cnet_write_queue_impl *impl,
                                          cnet_session_handle connection) {
  if (!cnet_session_handle_valid(connection) || (size_t)connection.slot > impl->connection_capacity)
    return SIZE_MAX;
  return (size_t)connection.slot - 1u;
}

static bool cnet_write_entry_matches(const cnet_write_entry *entry,
                                     cnet_session_handle connection) {
  return entry->state == CNET_WRITE_ENTRY_QUEUED &&
         entry->connection.slot == connection.slot &&
         entry->connection.generation == connection.generation;
}

static int cnet_write_validate_payload(cnet_write_queue_impl *impl, cnet_session_handle connection,
                                       size_t size) {
  if (cnet_write_connection_index(impl, connection) == SIZE_MAX || size == 0u) return SALTS_EINVAL;
  if (size > impl->max_payload_bytes) return SALTS_EMSGSIZE;
  if (!impl->admission_open) return SALTS_ESHUTDOWN;
  if (impl->free_count == 0u) return SALTS_ENOBUFS;
  return SALTS_OK;
}

static int cnet_write_enqueue_owned(cnet_write_queue_impl *impl, cnet_session_handle connection,
                                    mem_buffer_t *payload, size_t size, size_t base_offset,
                                    cnet_write_payload_kind payload_kind,
                                    bool close_after_send, cnet_write_handle *out_handle) {
  const size_t connection_index = cnet_write_connection_index(impl, connection);
  cnet_write_entry *entry;
  uint32_t slot;
  uint32_t tail;

  if (out_handle == NULL) return SALTS_EINVAL;
  *out_handle = (cnet_write_handle){0};
  if (connection_index == SIZE_MAX || payload == NULL || size == 0u) return SALTS_EINVAL;

  if (impl->heads[connection_index] != CNET_WRITE_SLOT_NONE) {
    const cnet_write_entry *head = &impl->entries[impl->heads[connection_index]];
    if (!cnet_write_entry_matches(head, connection)) return SALTS_EBUSY;
  }

  slot = impl->free_slots[--impl->free_count];
  entry = &impl->entries[slot];
  if (entry->state != CNET_WRITE_ENTRY_FREE) {
    ++impl->free_count;
    return SALTS_EPROTO;
  }

  entry->generation = cnet_write_next_generation(entry->generation);
  entry->connection = connection;
  entry->payload = payload;
  entry->size = size;
  entry->base_offset = base_offset;
  entry->offset = 0u;
  entry->range_count = 0u;
  entry->owner_count = 0u;
  entry->next = CNET_WRITE_SLOT_NONE;
  entry->payload_kind = payload_kind;
  entry->close_after_send = close_after_send;
  entry->state = CNET_WRITE_ENTRY_QUEUED;

  tail = impl->tails[connection_index];
  if (tail == CNET_WRITE_SLOT_NONE) {
    impl->heads[connection_index] = slot;
  } else {
    if (tail >= impl->capacity || impl->entries[tail].state != CNET_WRITE_ENTRY_QUEUED) {
      entry->state = CNET_WRITE_ENTRY_FREE;
      entry->payload = NULL;
      impl->free_slots[impl->free_count++] = slot;
      return SALTS_EPROTO;
    }
    impl->entries[tail].next = slot;
  }
  impl->tails[connection_index] = slot;
  ++impl->counts[connection_index];
  ++impl->live_writes;
  if (impl->peak_writes < impl->live_writes) impl->peak_writes = impl->live_writes;

  *out_handle = (cnet_write_handle){slot + 1u, entry->generation};
  return SALTS_OK;
}

bool cnet_write_handle_valid(cnet_write_handle handle) {
  return handle.slot != 0u && handle.generation != 0u;
}

int cnet_write_queue_init(cnet_write_queue *queue, const cnet_write_queue_config *config) {
  cnet_write_queue_impl *impl;
  size_t index;

  if (queue == NULL || config == NULL) return SALTS_EINVAL;
  if (queue->impl != NULL) return SALTS_EALREADY;
  if (config->connection_capacity == 0u || config->capacity == 0u ||
      config->max_payload_bytes == 0u)
    return SALTS_EINVAL;
  if (config->connection_capacity > UINT32_MAX || config->capacity > UINT32_MAX ||
      config->capacity > SIZE_MAX / sizeof(cnet_write_entry) ||
      config->capacity > SIZE_MAX / sizeof(uint32_t) ||
      config->connection_capacity > SIZE_MAX / sizeof(uint32_t) ||
      config->connection_capacity > SIZE_MAX / sizeof(size_t))
    return SALTS_ERANGE;

  impl = (cnet_write_queue_impl *)cnet_storage_alloc(&config->storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->entries = (cnet_write_entry *)cnet_storage_alloc(&config->storage, config->capacity, sizeof(*impl->entries));
  impl->free_slots = (uint32_t *)cnet_storage_alloc(&config->storage, config->capacity, sizeof(*impl->free_slots));
  impl->heads = (uint32_t *)cnet_storage_alloc(&config->storage, config->connection_capacity, sizeof(*impl->heads));
  impl->tails = (uint32_t *)cnet_storage_alloc(&config->storage, config->connection_capacity, sizeof(*impl->tails));
  impl->counts = (size_t *)cnet_storage_alloc(&config->storage, config->connection_capacity, sizeof(*impl->counts));
  if (impl->entries == NULL || impl->free_slots == NULL || impl->heads == NULL ||
      impl->tails == NULL || impl->counts == NULL) {
    cnet_storage_free(impl->counts);
    cnet_storage_free(impl->tails);
    cnet_storage_free(impl->heads);
    cnet_storage_free(impl->free_slots);
    cnet_storage_free(impl->entries);
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }

  impl->connection_capacity = config->connection_capacity;
  impl->capacity = config->capacity;
  impl->max_payload_bytes = config->max_payload_bytes;
  impl->free_count = config->capacity;
  impl->admission_open = true;
  for (index = 0u; index < config->capacity; ++index)
    impl->free_slots[index] = (uint32_t)(config->capacity - index - 1u);
  for (index = 0u; index < config->connection_capacity; ++index) {
    impl->heads[index] = CNET_WRITE_SLOT_NONE;
    impl->tails[index] = CNET_WRITE_SLOT_NONE;
  }
  queue->impl = impl;
  return SALTS_OK;
}

int cnet_write_queue_enqueue_buffer(cnet_write_queue *queue, cnet_session_handle connection,
                                    mem_buffer_t *buffer, bool close_after_send,
                                    cnet_write_handle *out_handle) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  mem_buffer_t *payload;
  size_t size;
  int status;

  if (out_handle == NULL) return SALTS_EINVAL;
  *out_handle = (cnet_write_handle){0};
  if (impl == NULL || buffer == NULL) return SALTS_EINVAL;
  size = mem_buffer_used(buffer);
  if (size == 0u || mem_buffer_const_data(buffer) == NULL) return SALTS_EINVAL;
  status = cnet_write_validate_payload(impl, connection, size);
  if (status != SALTS_OK) return status;

  payload = mem_buffer_retain(buffer);
  if (payload == NULL) return SALTS_EINVAL;
  status = cnet_write_enqueue_owned(impl, connection, payload, size, 0u,
                                    CNET_WRITE_PAYLOAD_RETAINED, close_after_send, out_handle);
  if (status != SALTS_OK) mem_buffer_release(payload);
  return status;
}

static int cnet_write_slice_canonical(const mem_slice_t *slice, size_t *out_offset) {
  const char *backing;
  size_t used;
  uintptr_t base;
  uintptr_t data;
  uintptr_t delta;

  if (out_offset == NULL) return SALTS_EINVAL;
  *out_offset = 0u;
  if (slice == NULL || slice->buffer == NULL || slice->data == NULL || slice->length == 0u)
    return SALTS_EINVAL;
  backing = mem_buffer_const_data(slice->buffer);
  used = mem_buffer_used(slice->buffer);
  if (backing == NULL || used == 0u) return SALTS_EINVAL;
  base = (uintptr_t)(const void *)backing;
  data = (uintptr_t)(const void *)slice->data;
  if (data < base) return SALTS_EINVAL;
  delta = data - base;
  if (delta > (uintptr_t)SIZE_MAX) return SALTS_EINVAL;
  *out_offset = (size_t)delta;
  if (*out_offset >= used || slice->length > used - *out_offset) return SALTS_EINVAL;
  return SALTS_OK;
}

int cnet_write_queue_enqueue_slice(cnet_write_queue *queue, cnet_session_handle connection,
                                   const mem_slice_t *slice, bool close_after_send,
                                   cnet_write_handle *out_handle) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  mem_buffer_t *payload;
  size_t base_offset = 0u;
  int status;

  if (out_handle == NULL) return SALTS_EINVAL;
  *out_handle = (cnet_write_handle){0};
  if (impl == NULL) return SALTS_EINVAL;
  status = cnet_write_slice_canonical(slice, &base_offset);
  if (status != SALTS_OK) return status;
  status = cnet_write_validate_payload(impl, connection, slice->length);
  if (status != SALTS_OK) return status;

  payload = mem_buffer_retain(slice->buffer);
  if (payload == NULL) return SALTS_EINVAL;
  status = cnet_write_enqueue_owned(impl, connection, payload, slice->length, base_offset,
                                    CNET_WRITE_PAYLOAD_RETAINED, close_after_send, out_handle);
  if (status != SALTS_OK) mem_buffer_release(payload);
  return status;
}

int cnet_write_queue_enqueue_slicev(cnet_write_queue *queue,
                                    cnet_session_handle connection,
                                    const mem_slice_t *segments, size_t segment_count,
                                    bool close_after_send, cnet_write_handle *out_handle) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  const size_t connection_index =
      impl != NULL ? cnet_write_connection_index(impl, connection) : SIZE_MAX;
  size_t base_offsets[CNET_RETAINED_VECTOR_MAX];
  size_t total = 0u;
  uint32_t slot;
  uint32_t tail;
  cnet_write_entry *entry;
  int status;

  if (out_handle == NULL) return SALTS_EINVAL;
  *out_handle = (cnet_write_handle){0};
  if (impl == NULL || segments == NULL || segment_count == 0u ||
      segment_count > CNET_RETAINED_VECTOR_MAX)
    return SALTS_EINVAL;

  for (size_t index = 0u; index < segment_count; ++index) {
    status = cnet_write_slice_canonical(&segments[index], &base_offsets[index]);
    if (status != SALTS_OK) return status;
    if (segments[index].length > SIZE_MAX - total) return SALTS_EMSGSIZE;
    total += segments[index].length;
  }
  status = cnet_write_validate_payload(impl, connection, total);
  if (status != SALTS_OK) return status;
  if (connection_index == SIZE_MAX) return SALTS_EINVAL;
  if (impl->heads[connection_index] != CNET_WRITE_SLOT_NONE) {
    const cnet_write_entry *head = &impl->entries[impl->heads[connection_index]];
    if (!cnet_write_entry_matches(head, connection)) return SALTS_EBUSY;
  }

  slot = impl->free_slots[--impl->free_count];
  entry = &impl->entries[slot];
  if (entry->state != CNET_WRITE_ENTRY_FREE) {
    ++impl->free_count;
    return SALTS_EPROTO;
  }

  entry->owner_count = 0u;
  for (size_t index = 0u; index < segment_count; ++index) {
    size_t owner_index = 0u;
    while (owner_index < entry->owner_count &&
           entry->owners[owner_index] != segments[index].buffer)
      ++owner_index;
    if (owner_index == entry->owner_count) {
      mem_buffer_t *retained = mem_buffer_retain(segments[index].buffer);
      if (retained == NULL) {
        for (size_t release = 0u; release < entry->owner_count; ++release)
          mem_buffer_release(entry->owners[release]);
        memset(entry->owners, 0, sizeof(entry->owners));
        memset(entry->ranges, 0, sizeof(entry->ranges));
        entry->owner_count = 0u;
        ++impl->free_count;
        return SALTS_EINVAL;
      }
      entry->owners[entry->owner_count++] = retained;
    }
    entry->ranges[index] =
        (cnet_write_range){segments[index].buffer, base_offsets[index], segments[index].length};
  }

  entry->generation = cnet_write_next_generation(entry->generation);
  entry->connection = connection;
  entry->payload = NULL;
  entry->size = total;
  entry->base_offset = 0u;
  entry->offset = 0u;
  entry->range_count = segment_count;
  entry->next = CNET_WRITE_SLOT_NONE;
  entry->payload_kind = CNET_WRITE_PAYLOAD_RETAINED_VECTOR;
  entry->close_after_send = close_after_send;
  entry->state = CNET_WRITE_ENTRY_QUEUED;

  tail = impl->tails[connection_index];
  if (tail == CNET_WRITE_SLOT_NONE) {
    impl->heads[connection_index] = slot;
  } else {
    if (tail >= impl->capacity || impl->entries[tail].state != CNET_WRITE_ENTRY_QUEUED) {
      for (size_t index = 0u; index < entry->owner_count; ++index)
        mem_buffer_release(entry->owners[index]);
      memset(entry->owners, 0, sizeof(entry->owners));
      memset(entry->ranges, 0, sizeof(entry->ranges));
      entry->owner_count = 0u;
      entry->range_count = 0u;
      entry->connection = (cnet_session_handle){0};
      entry->size = 0u;
      entry->payload_kind = CNET_WRITE_PAYLOAD_RETAINED;
      entry->state = CNET_WRITE_ENTRY_FREE;
      impl->free_slots[impl->free_count++] = slot;
      return SALTS_EPROTO;
    }
    impl->entries[tail].next = slot;
  }

  impl->tails[connection_index] = slot;
  ++impl->counts[connection_index];
  ++impl->live_writes;
  if (impl->peak_writes < impl->live_writes) impl->peak_writes = impl->live_writes;
  *out_handle = (cnet_write_handle){slot + 1u, entry->generation};
  return SALTS_OK;
}

int cnet_write_queue_peek(cnet_write_queue *queue, cnet_session_handle connection,
                          cnet_write_view *out_view) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  cnet_write_entry *entry;
  size_t connection_index;
  uint32_t slot;

  if (out_view == NULL) return SALTS_EINVAL;
  *out_view = (cnet_write_view){0};
  if (impl == NULL) return SALTS_EINVAL;
  connection_index = cnet_write_connection_index(impl, connection);
  if (connection_index == SIZE_MAX) return SALTS_EINVAL;
  slot = impl->heads[connection_index];
  if (slot == CNET_WRITE_SLOT_NONE) return SALTS_ETIMEDOUT;
  if ((size_t)slot >= impl->capacity) return SALTS_EPROTO;
  entry = &impl->entries[slot];
  if (!cnet_write_entry_matches(entry, connection) || entry->offset > entry->size)
    return SALTS_EPROTO;

  *out_view = (cnet_write_view){
      .handle = {slot + 1u, entry->generation},
      .connection = entry->connection,
      .size = entry->size,
      .offset = entry->offset,
      .remaining = entry->size - entry->offset,
      .close_after_send = entry->close_after_send,
      ._token = cnet_write_token(slot, entry->generation)};

  if (entry->payload_kind == CNET_WRITE_PAYLOAD_RETAINED_VECTOR) {
    if (entry->range_count == 0u || entry->owner_count == 0u) return SALTS_EPROTO;
    out_view->vector_write = true;
  } else {
    if (entry->payload == NULL) return SALTS_EPROTO;
    out_view->data = (const unsigned char *)mem_buffer_const_data(entry->payload) +
                     entry->base_offset + entry->offset;
  }
  return SALTS_OK;
}

int cnet_write_queue_build_contiguous(cnet_write_queue *queue,
                                      const cnet_write_view *view, size_t max_bytes,
                                      const void **out_data, size_t *out_bytes) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  cnet_write_entry *entry;
  size_t connection_index;
  uint32_t slot;
  size_t consumed;

  if (out_data == NULL || out_bytes == NULL) return SALTS_EINVAL;
  *out_data = NULL;
  *out_bytes = 0u;
  if (impl == NULL || view == NULL || max_bytes == 0u || !view->vector_write ||
      !cnet_write_handle_valid(view->handle))
    return SALTS_EINVAL;

  slot = view->handle.slot - 1u;
  if ((size_t)slot >= impl->capacity) return SALTS_ENOENT;
  entry = &impl->entries[slot];
  connection_index = cnet_write_connection_index(impl, view->connection);
  if (connection_index == SIZE_MAX || impl->heads[connection_index] != slot ||
      entry->generation != view->handle.generation ||
      view->_token != cnet_write_token(slot, entry->generation) ||
      !cnet_write_entry_matches(entry, view->connection) ||
      entry->payload_kind != CNET_WRITE_PAYLOAD_RETAINED_VECTOR ||
      entry->offset != view->offset || entry->offset > entry->size)
    return SALTS_ENOENT;

  consumed = entry->offset;
  if (max_bytes > entry->size - consumed) max_bytes = entry->size - consumed;
  for (size_t index = 0u; index < entry->range_count; ++index) {
    const cnet_write_range *range = &entry->ranges[index];
    const char *data;
    size_t local;
    size_t bytes;
    size_t next_offset;

    if (consumed >= range->length) {
      consumed -= range->length;
      continue;
    }

    local = consumed;
    data = mem_buffer_const_data(range->buffer);
    if (data == NULL || local >= range->length) return SALTS_EPROTO;
    bytes = range->length - local;
    if (bytes > max_bytes) bytes = max_bytes;
    next_offset = range->base_offset + range->length;

    for (size_t next = index + 1u; bytes < max_bytes && next < entry->range_count; ++next) {
      const cnet_write_range *candidate = &entry->ranges[next];
      size_t take;

      if (candidate->buffer != range->buffer || candidate->base_offset != next_offset) break;
      take = candidate->length;
      if (take > max_bytes - bytes) take = max_bytes - bytes;
      bytes += take;
      if (take != candidate->length) break;
      next_offset += candidate->length;
    }

    if (bytes == 0u) return SALTS_EPROTO;
    *out_data = data + range->base_offset + local;
    *out_bytes = bytes;
    return SALTS_OK;
  }

  return SALTS_EPROTO;
}

int cnet_write_queue_build_vector(cnet_write_queue *queue,
                                  const cnet_write_view *view, size_t max_bytes,
                                  native_io_buffer_span out_spans[NATIVE_IO_VECTOR_MAX],
                                  size_t *out_count, size_t *out_bytes) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  cnet_write_entry *entry;
  size_t connection_index;
  uint32_t slot;
  size_t consumed;
  size_t output = 0u;
  size_t bytes = 0u;

  if (out_count == NULL || out_bytes == NULL) return SALTS_EINVAL;
  *out_count = 0u;
  *out_bytes = 0u;
  if (impl == NULL || view == NULL || out_spans == NULL || max_bytes == 0u ||
      !view->vector_write || !cnet_write_handle_valid(view->handle))
    return SALTS_EINVAL;
  slot = view->handle.slot - 1u;
  if ((size_t)slot >= impl->capacity) return SALTS_ENOENT;
  entry = &impl->entries[slot];
  connection_index = cnet_write_connection_index(impl, view->connection);
  if (connection_index == SIZE_MAX || impl->heads[connection_index] != slot ||
      entry->generation != view->handle.generation ||
      view->_token != cnet_write_token(slot, entry->generation) ||
      !cnet_write_entry_matches(entry, view->connection) ||
      entry->payload_kind != CNET_WRITE_PAYLOAD_RETAINED_VECTOR ||
      entry->offset != view->offset || entry->offset > entry->size)
    return SALTS_ENOENT;

  consumed = entry->offset;
  if (max_bytes > entry->size - consumed) max_bytes = entry->size - consumed;
  for (size_t index = 0u; index < entry->range_count && bytes < max_bytes; ++index) {
    const cnet_write_range *range = &entry->ranges[index];
    size_t local;
    size_t take;
    const char *data;
    if (consumed >= range->length) {
      consumed -= range->length;
      continue;
    }
    local = consumed;
    consumed = 0u;
    take = range->length - local;
    if (take > max_bytes - bytes) take = max_bytes - bytes;
    data = mem_buffer_const_data(range->buffer);
    if (data == NULL || take == 0u) return SALTS_EPROTO;
    if (output == NATIVE_IO_VECTOR_MAX) break;
    out_spans[output++] =
        (native_io_buffer_span){(void *)(data + range->base_offset + local), take};
    bytes += take;
  }
  if (output == 0u || bytes == 0u) return SALTS_EPROTO;
  *out_count = output;
  *out_bytes = bytes;
  return SALTS_OK;
}

int cnet_write_queue_advance(cnet_write_queue *queue, cnet_write_view *view, size_t bytes) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  cnet_write_entry *entry;
  size_t connection_index;
  uint32_t slot;

  if (impl == NULL || view == NULL || !cnet_write_handle_valid(view->handle) || bytes == 0u)
    return SALTS_EINVAL;
  slot = view->handle.slot - 1u;
  if ((size_t)slot >= impl->capacity) return SALTS_ENOENT;
  entry = &impl->entries[slot];
  connection_index = cnet_write_connection_index(impl, view->connection);
  if (connection_index == SIZE_MAX || impl->heads[connection_index] != slot ||
      entry->generation != view->handle.generation ||
      view->_token != cnet_write_token(slot, entry->generation) ||
      !cnet_write_entry_matches(entry, view->connection))
    return SALTS_ENOENT;
  if (entry->offset > entry->size || bytes > entry->size - entry->offset) return SALTS_ERANGE;

  entry->offset += bytes;
  return cnet_write_queue_peek(queue, view->connection, view);
}

static int cnet_write_release_slot(cnet_write_queue_impl *impl, size_t connection_index,
                                   uint32_t slot) {
  cnet_write_entry *entry;
  if (impl == NULL || connection_index >= impl->connection_capacity ||
      (size_t)slot >= impl->capacity)
    return SALTS_EINVAL;
  entry = &impl->entries[slot];
  if (entry->state != CNET_WRITE_ENTRY_QUEUED ||
      impl->live_writes == 0u || impl->free_count >= impl->capacity)
    return SALTS_EPROTO;

  --impl->live_writes;
  if (entry->payload_kind == CNET_WRITE_PAYLOAD_RETAINED_VECTOR) {
    for (size_t index = 0u; index < entry->owner_count; ++index)
      mem_buffer_release(entry->owners[index]);
    memset(entry->owners, 0, sizeof(entry->owners));
    memset(entry->ranges, 0, sizeof(entry->ranges));
  } else {
    mem_buffer_release(entry->payload);
  }
  entry->connection = (cnet_session_handle){0};
  entry->payload = NULL;
  entry->size = 0u;
  entry->base_offset = 0u;
  entry->offset = 0u;
  entry->range_count = 0u;
  entry->owner_count = 0u;
  entry->next = CNET_WRITE_SLOT_NONE;
  entry->close_after_send = false;
  entry->state = CNET_WRITE_ENTRY_FREE;
  impl->free_slots[impl->free_count++] = slot;
  return SALTS_OK;
}

int cnet_write_queue_settle(cnet_write_queue *queue, cnet_write_view *view) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  cnet_write_entry *entry;
  size_t connection_index;
  uint32_t slot;
  uint32_t next;

  if (impl == NULL || view == NULL || !cnet_write_handle_valid(view->handle)) return SALTS_EINVAL;
  slot = view->handle.slot - 1u;
  if ((size_t)slot >= impl->capacity) return SALTS_ENOENT;
  entry = &impl->entries[slot];
  connection_index = cnet_write_connection_index(impl, view->connection);
  if (connection_index == SIZE_MAX || impl->heads[connection_index] != slot ||
      entry->generation != view->handle.generation ||
      view->_token != cnet_write_token(slot, entry->generation) ||
      !cnet_write_entry_matches(entry, view->connection))
    return SALTS_ENOENT;

  next = entry->next;
  if (impl->counts[connection_index] == 0u) return SALTS_EPROTO;

  impl->heads[connection_index] = next;
  --impl->counts[connection_index];
  if (next == CNET_WRITE_SLOT_NONE) impl->tails[connection_index] = CNET_WRITE_SLOT_NONE;
  if (cnet_write_release_slot(impl, connection_index, slot) != SALTS_OK) return SALTS_EPROTO;
  *view = (cnet_write_view){0};
  return SALTS_OK;
}

int cnet_write_queue_count(cnet_write_queue *queue, cnet_session_handle connection,
                           size_t *out_count) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  size_t connection_index;
  uint32_t head;
  if (out_count == NULL) return SALTS_EINVAL;
  *out_count = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  connection_index = cnet_write_connection_index(impl, connection);
  if (connection_index == SIZE_MAX) return SALTS_EINVAL;
  head = impl->heads[connection_index];
  if (head != CNET_WRITE_SLOT_NONE &&
      ((size_t)head >= impl->capacity ||
       !cnet_write_entry_matches(&impl->entries[head], connection)))
    return SALTS_ENOENT;
  *out_count = impl->counts[connection_index];
  return SALTS_OK;
}

int cnet_write_queue_cancel_tail(cnet_write_queue *queue, cnet_session_handle connection,
                                 cnet_write_handle handle) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  size_t connection_index;
  uint32_t tail;
  uint32_t previous = CNET_WRITE_SLOT_NONE;
  uint32_t cursor;

  if (impl == NULL || !cnet_write_handle_valid(handle)) return SALTS_EINVAL;
  connection_index = cnet_write_connection_index(impl, connection);
  if (connection_index == SIZE_MAX) return SALTS_EINVAL;
  tail = impl->tails[connection_index];
  if (tail == CNET_WRITE_SLOT_NONE || handle.slot == 0u ||
      (size_t)(handle.slot - 1u) >= impl->capacity)
    return SALTS_ENOENT;
  tail = handle.slot - 1u;
  if (impl->tails[connection_index] != tail ||
      impl->entries[tail].generation != handle.generation ||
      !cnet_write_entry_matches(&impl->entries[tail], connection))
    return SALTS_ENOENT;

  cursor = impl->heads[connection_index];
  while (cursor != CNET_WRITE_SLOT_NONE && cursor != tail) {
    if ((size_t)cursor >= impl->capacity) return SALTS_EPROTO;
    previous = cursor;
    cursor = impl->entries[cursor].next;
  }
  if (cursor != tail || impl->counts[connection_index] == 0u) return SALTS_EPROTO;

  if (previous == CNET_WRITE_SLOT_NONE) {
    impl->heads[connection_index] = CNET_WRITE_SLOT_NONE;
    impl->tails[connection_index] = CNET_WRITE_SLOT_NONE;
  } else {
    impl->entries[previous].next = CNET_WRITE_SLOT_NONE;
    impl->tails[connection_index] = previous;
  }
  --impl->counts[connection_index];
  return cnet_write_release_slot(impl, connection_index, tail);
}

int cnet_write_queue_discard(cnet_write_queue *queue, cnet_session_handle connection,
                             bool keep_head, size_t *out_discarded) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  size_t connection_index;
  uint32_t cursor;
  size_t discarded = 0u;

  if (out_discarded != NULL) *out_discarded = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  connection_index = cnet_write_connection_index(impl, connection);
  if (connection_index == SIZE_MAX) return SALTS_EINVAL;
  cursor = impl->heads[connection_index];
  if (cursor == CNET_WRITE_SLOT_NONE) return SALTS_OK;
  if ((size_t)cursor >= impl->capacity ||
      !cnet_write_entry_matches(&impl->entries[cursor], connection))
    return SALTS_ENOENT;

  if (keep_head) {
    cursor = impl->entries[cursor].next;
    impl->entries[impl->heads[connection_index]].next = CNET_WRITE_SLOT_NONE;
    impl->tails[connection_index] = impl->heads[connection_index];
    if (impl->counts[connection_index] == 0u) return SALTS_EPROTO;
    discarded = impl->counts[connection_index] - 1u;
    impl->counts[connection_index] = 1u;
  } else {
    discarded = impl->counts[connection_index];
    impl->heads[connection_index] = CNET_WRITE_SLOT_NONE;
    impl->tails[connection_index] = CNET_WRITE_SLOT_NONE;
    impl->counts[connection_index] = 0u;
  }

  while (cursor != CNET_WRITE_SLOT_NONE) {
    cnet_write_entry *entry;
    uint32_t next;
    if ((size_t)cursor >= impl->capacity) return SALTS_EPROTO;
    entry = &impl->entries[cursor];
    if (!cnet_write_entry_matches(entry, connection)) return SALTS_EPROTO;
    next = entry->next;
    if (cnet_write_release_slot(impl, connection_index, cursor) != SALTS_OK) return SALTS_EPROTO;
    cursor = next;
  }
  if (out_discarded != NULL) *out_discarded = discarded;
  return SALTS_OK;
}

int cnet_write_queue_close(cnet_write_queue *queue) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->admission_open) return SALTS_EALREADY;
  impl->admission_open = false;
  return SALTS_OK;
}

bool cnet_write_queue_get_stats(const cnet_write_queue *queue,
                                cnet_write_queue_stats *out_stats) {
  const cnet_write_queue_impl *impl = cnet_write_const_impl(queue);
  if (impl == NULL || out_stats == NULL) return false;
  *out_stats = (cnet_write_queue_stats){
      .live_writes = impl->live_writes,
      .peak_writes = impl->peak_writes,
      .capacity = impl->capacity,
      .connection_capacity = impl->connection_capacity,
      .admission_open = impl->admission_open};
  return true;
}

int cnet_write_queue_destroy(cnet_write_queue *queue) {
  cnet_write_queue_impl *impl = cnet_write_impl(queue);
  if (queue == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;
  if (impl->admission_open || impl->live_writes != 0u || impl->free_count != impl->capacity)
    return SALTS_EBUSY;

  cnet_storage_free(impl->counts);
  cnet_storage_free(impl->tails);
  cnet_storage_free(impl->heads);
  cnet_storage_free(impl->free_slots);
  cnet_storage_free(impl->entries);
  cnet_storage_free(impl);
  queue->impl = NULL;
  return SALTS_OK;
}
