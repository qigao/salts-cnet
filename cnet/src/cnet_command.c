#include "cnet_resources.h"
#include "cnet_command.h"

#include <memory/buffer.h>
#if defined(CNET_INTERNAL_PROFILING)
  #include <core/clock.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef enum cnet_command_entry_state {
  CNET_COMMAND_ENTRY_FREE = 0,
  CNET_COMMAND_ENTRY_QUEUED,
  CNET_COMMAND_ENTRY_BORROWED
} cnet_command_entry_state;

typedef struct cnet_command_entry {
  cnet_command_kind kind;
  cnet_session_handle connection;
  size_t size;
  size_t argument;
  uint32_t generation;
  cnet_command_entry_state state;
  size_t copied_payload_bytes;
  mem_buffer_t *payload;
} cnet_command_entry;

typedef struct cnet_command_queue_impl {
  cnet_command_entry *entries;
  uint32_t *free_slots;
  uint32_t *queued_slots;
  mem_pool_t payload_pool;
  size_t capacity;
  size_t mask;
  size_t max_payload_bytes;
  size_t payload_capacity_bytes;
  size_t free_count;
  size_t queued_head;
  size_t queued_count;
  size_t live_commands;
  size_t peak_commands;
  size_t queued_bytes;
  size_t peak_queued_bytes;
  uint64_t rejected_commands;
  uint64_t rejected_bytes;
#if defined(CNET_INTERNAL_PROFILING)
  cnet_command_queue_profile profile;
  bool profile_active;
#endif
  bool admission_open;
  bool close_complete;
} cnet_command_queue_impl;

static cnet_command_queue_impl *cnet_command_impl(cnet_command_queue *queue) {
  return queue != NULL ? (cnet_command_queue_impl *)queue->impl : NULL;
}

static const cnet_command_queue_impl *cnet_command_const_impl(const cnet_command_queue *queue) {
  return queue != NULL ? (const cnet_command_queue_impl *)queue->impl : NULL;
}

static cnet_command_entry *cnet_command_entry_at(cnet_command_queue_impl *impl, size_t slot) {
  return &impl->entries[slot];
}

static void cnet_command_saturating_add(uint64_t *counter, uint64_t value) {
  *counter = *counter > UINT64_MAX - value ? UINT64_MAX : *counter + value;
}

static void cnet_command_record_rejection(cnet_command_queue_impl *impl, size_t bytes) {
  cnet_command_saturating_add(&impl->rejected_commands, 1u);
  cnet_command_saturating_add(&impl->rejected_bytes, (uint64_t)bytes);
}

#if defined(CNET_INTERNAL_PROFILING)
static uint64_t cnet_command_profile_start(const cnet_command_queue_impl *impl) {
  return impl->profile_active ? hrtime() : 0u;
}

static void cnet_command_profile_finish(cnet_command_queue_impl *impl, uint64_t started_ns,
                                        uint64_t *elapsed_ns, uint64_t *calls) {
  uint64_t elapsed;
  if (!impl->profile_active) return;
  elapsed = hrtime() - started_ns;
  cnet_command_saturating_add(elapsed_ns, elapsed);
  cnet_command_saturating_add(calls, 1u);
}
#endif

static uint32_t cnet_command_next_generation(uint32_t generation) {
  return generation == UINT32_MAX ? 1u : generation + 1u;
}

static uint64_t cnet_command_token(size_t slot, uint32_t generation) {
  return ((uint64_t)generation << 32u) | ((uint64_t)slot + 1u);
}

static bool cnet_is_power_of_two(uint64_t value) {
  return value != 0u && (value & (value - 1u)) == 0u;
}

static bool cnet_command_valid(const cnet_command *command) {
  if (command == NULL || command->kind <= CNET_COMMAND_NONE || command->kind > CNET_COMMAND_STOP)
    return false;

  if (command->kind == CNET_COMMAND_STOP)
    return !cnet_session_handle_valid(command->connection) && command->data == NULL &&
           command->size == 0u;

  if (!cnet_session_handle_valid(command->connection)) return false;
  if (command->kind == CNET_COMMAND_CONNECT || command->kind == CNET_COMMAND_START_TLS)
    return command->data != NULL && command->size != 0u && command->argument == 0u;
  if (command->kind == CNET_COMMAND_RECEIVE)
    return command->data == NULL && command->size == 0u && command->argument != 0u;
  return command->data == NULL && command->size == 0u && command->argument == 0u;
}

int cnet_command_queue_init(cnet_command_queue *queue, const cnet_command_queue_config *config) {
  cnet_command_queue_impl *impl;
  size_t payload_capacity_bytes;
  size_t capacity;

  if (queue == NULL) return SALTS_EINVAL;
  if (queue->impl != NULL) return SALTS_EALREADY;
  if (config == NULL || !cnet_is_power_of_two(config->capacity) || config->max_payload_bytes == 0u)
    return SALTS_EINVAL;
  if (config->capacity > UINT32_MAX) return SALTS_ERANGE;
  capacity = (size_t)config->capacity;
  if (config->payload_capacity_bytes == 0u && capacity > SIZE_MAX / config->max_payload_bytes)
    return SALTS_ERANGE;
  payload_capacity_bytes = config->payload_capacity_bytes != 0u
                               ? config->payload_capacity_bytes
                               : capacity * config->max_payload_bytes;
  if (payload_capacity_bytes < config->max_payload_bytes) return SALTS_EINVAL;
  if (capacity > SIZE_MAX / sizeof(cnet_command_entry) || capacity > SIZE_MAX / sizeof(uint32_t))
    return SALTS_ERANGE;

  impl = (cnet_command_queue_impl *)cnet_storage_alloc(&config->storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->entries = (cnet_command_entry *)cnet_storage_alloc(&config->storage, capacity, sizeof(*impl->entries));
  impl->free_slots = (uint32_t *)cnet_storage_alloc(&config->storage, capacity, sizeof(*impl->free_slots));
  impl->queued_slots = (uint32_t *)cnet_storage_alloc(&config->storage, capacity, sizeof(*impl->queued_slots));
  if (impl->entries == NULL || impl->free_slots == NULL || impl->queued_slots == NULL ||
      mem_init(&impl->payload_pool, 0u) != 0) {
    cnet_storage_free(impl->queued_slots);
    cnet_storage_free(impl->free_slots);
    cnet_storage_free(impl->entries);
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  impl->capacity = capacity;
  impl->mask = capacity - 1u;
  impl->max_payload_bytes = config->max_payload_bytes;
  impl->payload_capacity_bytes = payload_capacity_bytes;
  impl->free_count = capacity;
  impl->admission_open = true;
  for (size_t index = 0u; index < capacity; ++index)
    impl->free_slots[index] = (uint32_t)(capacity - index - 1u);
  queue->impl = impl;
  return SALTS_OK;
}

int cnet_command_queue_publish(cnet_command_queue *queue, const cnet_command *command) {
  cnet_command_queue_impl *impl = cnet_command_impl(queue);
  cnet_command_entry *entry;
  mem_buffer_t *payload = NULL;
  const size_t copied_bytes = command != NULL ? command->size : 0u;
  size_t slot;
  size_t queue_tail;
#if defined(CNET_INTERNAL_PROFILING)
  uint64_t publish_started;
  uint64_t payload_publish_started = 0u;
  uint64_t payload_copy_started = 0u;
#endif

  if (impl == NULL || !cnet_command_valid(command)) return SALTS_EINVAL;
  if (command->size > impl->max_payload_bytes) {
    cnet_command_record_rejection(impl, command->size);
    return SALTS_EMSGSIZE;
  }
  if (!impl->admission_open) {
    cnet_command_record_rejection(impl, command->size);
    return SALTS_ESHUTDOWN;
  }
  if (impl->free_count == 0u) {
    cnet_command_record_rejection(impl, command->size);
    return SALTS_ENOBUFS;
  }
  if (impl->queued_bytes > impl->payload_capacity_bytes ||
      copied_bytes > impl->payload_capacity_bytes - impl->queued_bytes) {
    cnet_command_record_rejection(impl, command->size);
    return SALTS_ENOBUFS;
  }
#if defined(CNET_INTERNAL_PROFILING)
  publish_started = cnet_command_profile_start(impl);
  if (command->size != 0u) payload_publish_started = publish_started;
#endif
  slot = impl->free_slots[impl->free_count - 1u];
  entry = cnet_command_entry_at(impl, slot);
  if (entry->state != CNET_COMMAND_ENTRY_FREE) return SALTS_EPROTO;
  if (command->size != 0u) {
    payload = mem_get_buffer(&impl->payload_pool, command->size);
    if (payload == NULL) {
      cnet_command_record_rejection(impl, command->size);
      return SALTS_ENOMEM;
    }
  }

  --impl->free_count;
  entry->kind = command->kind;
  entry->connection = command->connection;
  entry->size = command->size;
  entry->argument = command->argument;
  entry->copied_payload_bytes = copied_bytes;
  entry->payload = payload;
  entry->generation = cnet_command_next_generation(entry->generation);
  entry->state = CNET_COMMAND_ENTRY_QUEUED;
#if defined(CNET_INTERNAL_PROFILING)
  if (command->size != 0u) payload_copy_started = cnet_command_profile_start(impl);
#endif
  if (command->size != 0u)
    memcpy(mem_buffer_data(entry->payload), command->data, command->size);
#if defined(CNET_INTERNAL_PROFILING)
  if (command->size != 0u)
    cnet_command_profile_finish(impl, payload_copy_started, &impl->profile.payload_copy_ns,
                                &impl->profile.payload_copy_calls);
#endif
  if (entry->payload != NULL) mem_set_used(entry->payload, entry->size);

  queue_tail = (impl->queued_head + impl->queued_count) & impl->mask;
  impl->queued_slots[queue_tail] = (uint32_t)slot;
  ++impl->queued_count;
  ++impl->live_commands;
  impl->queued_bytes += copied_bytes;
  if (impl->peak_commands < impl->live_commands) impl->peak_commands = impl->live_commands;
  if (impl->peak_queued_bytes < impl->queued_bytes) impl->peak_queued_bytes = impl->queued_bytes;
#if defined(CNET_INTERNAL_PROFILING)
  if (command->size != 0u)
    cnet_command_profile_finish(impl, payload_publish_started, &impl->profile.payload_publish_ns,
                                &impl->profile.payload_publish_calls);
  cnet_command_profile_finish(impl, publish_started, &impl->profile.publish_ns,
                              &impl->profile.publish_calls);
#endif
  return SALTS_OK;
}

int cnet_command_queue_take(cnet_command_queue *queue, cnet_command_view *out_view) {
  cnet_command_queue_impl *impl = cnet_command_impl(queue);
  cnet_command_entry *entry;
  size_t slot;

  if (out_view == NULL) return SALTS_EINVAL;
  memset(out_view, 0, sizeof(*out_view));
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->queued_count == 0u)
    return impl->close_complete && impl->live_commands == 0u ? SALTS_EOF : SALTS_ETIMEDOUT;

  slot = impl->queued_slots[impl->queued_head];
  impl->queued_head = (impl->queued_head + 1u) & impl->mask;
  --impl->queued_count;
  entry = cnet_command_entry_at(impl, slot);
  if (entry->state != CNET_COMMAND_ENTRY_QUEUED) return SALTS_EPROTO;
  entry->state = CNET_COMMAND_ENTRY_BORROWED;
  out_view->kind = entry->kind;
  out_view->connection = entry->connection;
  out_view->data = entry->size != 0u ? mem_buffer_const_data(entry->payload) : NULL;
  out_view->size = entry->size;
  out_view->argument = entry->argument;
  out_view->_sequence = cnet_command_token(slot, entry->generation);
  return SALTS_OK;
}

int cnet_command_queue_release(cnet_command_queue *queue, cnet_command_view *view) {
  cnet_command_queue_impl *impl = cnet_command_impl(queue);
  cnet_command_entry *entry;
  const uint32_t encoded_slot = view != NULL ? (uint32_t)view->_sequence : 0u;
  const uint32_t generation = view != NULL ? (uint32_t)(view->_sequence >> 32u) : 0u;
  size_t slot;

  if (impl == NULL || view == NULL || encoded_slot == 0u || generation == 0u) return SALTS_EINVAL;
  slot = (size_t)encoded_slot - 1u;
  if (slot >= impl->capacity) return SALTS_EINVAL;
  entry = cnet_command_entry_at(impl, slot);
  if (entry->state != CNET_COMMAND_ENTRY_BORROWED || entry->generation != generation)
    return SALTS_EINVAL;
  if (impl->live_commands == 0u || impl->queued_bytes < entry->copied_payload_bytes ||
      impl->free_count >= impl->capacity)
    return SALTS_EPROTO;
  if ((entry->size != 0u &&
       (entry->payload == NULL || entry->copied_payload_bytes != entry->size)) ||
      (entry->size == 0u &&
       (entry->payload != NULL || entry->copied_payload_bytes != 0u)))
    return SALTS_EPROTO;

  --impl->live_commands;
  impl->queued_bytes -= entry->copied_payload_bytes;
  mem_buffer_release(entry->payload);
  entry->payload = NULL;
  entry->copied_payload_bytes = 0u;
  entry->kind = CNET_COMMAND_NONE;
  entry->connection = (cnet_session_handle){0};
  entry->size = 0u;
  entry->argument = 0u;
  entry->state = CNET_COMMAND_ENTRY_FREE;
  impl->free_slots[impl->free_count++] = (uint32_t)slot;
  memset(view, 0, sizeof(*view));
  return SALTS_OK;
}

int cnet_command_queue_close(cnet_command_queue *queue) {
  cnet_command_queue_impl *impl = cnet_command_impl(queue);
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->close_complete) return SALTS_EALREADY;
  impl->admission_open = false;
  impl->close_complete = true;
  return SALTS_OK;
}

bool cnet_command_queue_get_stats(const cnet_command_queue *queue,
                                  cnet_command_queue_stats *out_stats) {
  const cnet_command_queue_impl *impl = cnet_command_const_impl(queue);
  if (impl == NULL || out_stats == NULL) return false;
  *out_stats = (cnet_command_queue_stats){
      impl->live_commands,     impl->peak_commands,  impl->queued_bytes,  impl->peak_queued_bytes,
      impl->rejected_commands, impl->rejected_bytes, impl->admission_open};
  return true;
}

#if defined(CNET_INTERNAL_PROFILING)
int cnet_command_queue_profile_begin(cnet_command_queue *queue) {
  cnet_command_queue_impl *impl = cnet_command_impl(queue);
  if (impl == NULL) return SALTS_EINVAL;
  memset(&impl->profile, 0, sizeof(impl->profile));
  impl->profile_active = true;
  return SALTS_OK;
}

int cnet_command_queue_profile_take(cnet_command_queue *queue,
                                    cnet_command_queue_profile *out_profile) {
  cnet_command_queue_impl *impl = cnet_command_impl(queue);
  if (impl == NULL || out_profile == NULL) return SALTS_EINVAL;
  *out_profile = impl->profile;
  impl->profile_active = false;
  return SALTS_OK;
}
#endif

int cnet_command_queue_destroy(cnet_command_queue *queue) {
  cnet_command_queue_impl *impl = cnet_command_impl(queue);
  if (queue == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;
  if (!impl->close_complete || impl->live_commands != 0u || impl->queued_count != 0u ||
      impl->free_count != impl->capacity)
    return SALTS_EBUSY;
  cnet_storage_free(impl->queued_slots);
  cnet_storage_free(impl->free_slots);
  cnet_storage_free(impl->entries);
  mem_destroy(&impl->payload_pool);
  cnet_storage_free(impl);
  queue->impl = NULL;
  return SALTS_OK;
}
