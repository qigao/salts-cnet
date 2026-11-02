#include "cnet_resources.h"
#include <cnet/handoff.h>
#include <ring_buffer.h>
#include <thread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum { HANDOFF_FREE, HANDOFF_RESERVED, HANDOFF_QUEUED, HANDOFF_TAKEN };
typedef struct handoff_record {
  cnet_accepted_stream accepted;
  uint64_t generation;
  size_t next_free;
  unsigned state;
} handoff_record;
typedef struct handoff_impl {
  cmeta_mutex_t mutex;
  handoff_record *records;
  /* The non-atomic byte ring is accessed only under mutex, including its
   * acquire/release pairs. No ring view escapes the critical section. */
  ring_data_type queue;
  uint64_t incarnation;
  size_t capacity, queue_capacity, free_head;
  size_t reserved, queued, taken;
  bool sealed;
} handoff_impl;

static atomic_uint_fast64_t handoff_incarnation;

static handoff_record *find_record(handoff_impl *impl, cnet_handoff_ticket ticket) {
  if (ticket.incarnation != impl->incarnation || ticket.slot == 0u ||
      ticket.slot > impl->capacity) return NULL;
  handoff_record *record = &impl->records[ticket.slot - 1u];
  return record->state != HANDOFF_FREE && record->generation == ticket.generation
             ? record : NULL;
}

int cnet_handoff_init(cnet_handoff *handoff, const cnet_handoff_config *config) {
  handoff_impl *impl;
  uint_fast64_t incarnation;
  if (handoff == NULL || config == NULL) return SALTS_EINVAL;
  if (handoff->impl != NULL) return SALTS_EALREADY;
  if (!cnet_allocator_valid(&config->storage) || config->size != sizeof(*config) || config->version != CNET_HANDOFF_VERSION ||
      config->connection_capacity == 0u || config->queue_capacity == 0u ||
      config->queue_capacity > config->connection_capacity) return SALTS_EINVAL;
  /* One unused ring entry distinguishes full from empty. */
  if (config->connection_capacity > SIZE_MAX / sizeof(handoff_record) ||
      config->queue_capacity >= SIZE_MAX / sizeof(size_t)) return SALTS_ERANGE;
  impl = cnet_storage_alloc(&config->storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->records = cnet_storage_alloc(&config->storage, config->connection_capacity, sizeof(*impl->records));
  impl->queue.data = cnet_storage_alloc(&config->storage, config->queue_capacity + 1u, sizeof(size_t));
  if (impl->records == NULL || impl->queue.data == NULL) {
    cnet_storage_free(impl->queue.data);
    cnet_storage_free(impl->records);
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  incarnation = atomic_load_explicit(&handoff_incarnation, memory_order_relaxed);
  do {
    if (incarnation >= UINT64_MAX) {
      cnet_storage_free(impl->queue.data);
      cnet_storage_free(impl->records);
      cnet_storage_free(impl);
      return SALTS_ERANGE;
    }
  } while (!atomic_compare_exchange_weak_explicit(&handoff_incarnation, &incarnation,
      incarnation + 1u, memory_order_relaxed, memory_order_relaxed));
  impl->incarnation = (uint64_t)(incarnation + 1u);
  impl->capacity = config->connection_capacity;
  impl->queue_capacity = config->queue_capacity;
  for (size_t i = 0u; i < impl->capacity; ++i) impl->records[i].next_free = i + 1u;
  ring_init(&impl->queue, impl->queue.data, (config->queue_capacity + 1u) * sizeof(size_t));
  cmeta_mutex_init(&impl->mutex);
  if (impl->mutex == NULL) {
    cnet_storage_free(impl->queue.data);
    cnet_storage_free(impl->records);
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  handoff->impl = impl;
  return SALTS_OK;
}

int cnet_handoff_reserve(cnet_handoff *handoff, cnet_handoff_ticket *out) {
  int status = SALTS_OK;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_handoff_ticket){0};
  if (handoff == NULL || handoff->impl == NULL) return SALTS_EINVAL;
  handoff_impl *impl = handoff->impl;
  cmeta_mutex_lock(&impl->mutex);
  if (impl->sealed) status = SALTS_ESHUTDOWN;
  else if (impl->free_head == impl->capacity) status = SALTS_ENOBUFS;
  else {
    const size_t slot = impl->free_head;
    handoff_record *record = &impl->records[slot];
    if (record->generation == UINT64_MAX) status = SALTS_ERANGE;
    else {
      impl->free_head = record->next_free;
      record->state = HANDOFF_RESERVED;
      ++record->generation;
      ++impl->reserved;
      *out = (cnet_handoff_ticket){impl->incarnation, record->generation, slot + 1u};
    }
  }
  cmeta_mutex_unlock(&impl->mutex);
  return status;
}

int cnet_handoff_publish(cnet_handoff *handoff, cnet_handoff_ticket ticket,
                         cnet_accepted_stream *accepted) {
  int status = SALTS_OK;
  if (handoff == NULL || handoff->impl == NULL || accepted == NULL ||
      accepted->internal_active != 1u) return SALTS_EINVAL;
  handoff_impl *impl = handoff->impl;
  cmeta_mutex_lock(&impl->mutex);
  handoff_record *record = find_record(impl, ticket);
  if (record == NULL) status = SALTS_ENOENT;
  else if (record->state != HANDOFF_RESERVED) status = SALTS_EALREADY;
  else if (impl->sealed) status = SALTS_ESHUTDOWN;
  else if (impl->queued == impl->queue_capacity) status = SALTS_ENOBUFS;
  else {
    uint8_t *entry = ring_write_acquire(&impl->queue, sizeof(ticket.slot));
    if (entry == NULL) status = SALTS_EPROTO;
    else {
      memcpy(entry, &ticket.slot, sizeof(ticket.slot));
      record->accepted = *accepted;
      *accepted = (cnet_accepted_stream)CNET_ACCEPTED_STREAM_INIT;
      record->state = HANDOFF_QUEUED;
      --impl->reserved;
      ++impl->queued;
      ring_write_release(&impl->queue, sizeof(ticket.slot));
    }
  }
  cmeta_mutex_unlock(&impl->mutex);
  return status;
}

int cnet_handoff_take(cnet_handoff *handoff, cnet_handoff_ticket *out,
                      cnet_accepted_stream *accepted) {
  int status = SALTS_OK;
  if (out != NULL) *out = (cnet_handoff_ticket){0};
  if (accepted != NULL) *accepted = (cnet_accepted_stream)CNET_ACCEPTED_STREAM_INIT;
  if (handoff == NULL || handoff->impl == NULL || out == NULL || accepted == NULL)
    return SALTS_EINVAL;
  handoff_impl *impl = handoff->impl;
  cmeta_mutex_lock(&impl->mutex);
  if (impl->queued == 0u) status = SALTS_ENOENT;
  else {
    size_t bytes, slot;
    const uint8_t *entry = ring_read_acquire(&impl->queue, &bytes);
    if (entry == NULL || bytes < sizeof(slot)) status = SALTS_EPROTO;
    else {
      memcpy(&slot, entry, sizeof(slot));
      handoff_record *record = &impl->records[slot - 1u];
      *out = (cnet_handoff_ticket){impl->incarnation, record->generation, slot};
      *accepted = record->accepted;
      record->accepted = (cnet_accepted_stream)CNET_ACCEPTED_STREAM_INIT;
      record->state = HANDOFF_TAKEN;
      --impl->queued;
      ++impl->taken;
      ring_read_release(&impl->queue, sizeof(slot));
    }
  }
  cmeta_mutex_unlock(&impl->mutex);
  return status;
}

int cnet_handoff_release(cnet_handoff *handoff, cnet_handoff_ticket ticket) {
  int status = SALTS_OK;
  if (handoff == NULL || handoff->impl == NULL) return SALTS_EINVAL;
  handoff_impl *impl = handoff->impl;
  cmeta_mutex_lock(&impl->mutex);
  handoff_record *record = find_record(impl, ticket);
  if (record == NULL) status = SALTS_ENOENT;
  else if (record->state == HANDOFF_QUEUED) status = SALTS_EBUSY;
  else {
    if (record->state == HANDOFF_RESERVED) --impl->reserved;
    else --impl->taken;
    record->state = HANDOFF_FREE;
    record->next_free = impl->free_head;
    impl->free_head = ticket.slot - 1u;
  }
  cmeta_mutex_unlock(&impl->mutex);
  return status;
}

int cnet_handoff_seal(cnet_handoff *handoff) {
  if (handoff == NULL || handoff->impl == NULL) return SALTS_EINVAL;
  handoff_impl *impl = handoff->impl;
  cmeta_mutex_lock(&impl->mutex);
  impl->sealed = true;
  cmeta_mutex_unlock(&impl->mutex);
  return SALTS_OK;
}
int cnet_handoff_get_snapshot(cnet_handoff *handoff, cnet_handoff_snapshot *out) {
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_handoff_snapshot){0};
  if (handoff == NULL || handoff->impl == NULL) return SALTS_EINVAL;
  handoff_impl *impl = handoff->impl;
  cmeta_mutex_lock(&impl->mutex);
  *out = (cnet_handoff_snapshot){impl->capacity, impl->queue_capacity,
      impl->reserved, impl->queued, impl->taken, impl->sealed,
      impl->reserved == 0u && impl->queued == 0u && impl->taken == 0u};
  cmeta_mutex_unlock(&impl->mutex);
  return SALTS_OK;
}
int cnet_handoff_destroy(cnet_handoff *handoff) {
  if (handoff == NULL) return SALTS_EINVAL;
  if (handoff->impl == NULL) return SALTS_EALREADY;
  handoff_impl *impl = handoff->impl;
  /* Exclusive lifecycle access is a host precondition, not inferred from an
   * empty queue. In particular a producer may still be about to wake a backend. */
  if (impl->reserved != 0u || impl->queued != 0u || impl->taken != 0u) return SALTS_EBUSY;
  cmeta_mutex_destroy(&impl->mutex);
  cnet_storage_free(impl->queue.data);
  cnet_storage_free(impl->records);
  cnet_storage_free(impl);
  handoff->impl = NULL;
  return SALTS_OK;
}
