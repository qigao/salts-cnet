#include "cnet_resources.h"
#include "cnet_event.h"

#include <cnet/cnet.h>
#include <disruptor.h>
#include <cmeta_buffer.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct cnet_event_entry {
  cnet_event_kind kind;
  cnet_session_handle session;
  cnet_event_state state;
  int status;
  cnet_session_stage stage;
  size_t size;
  size_t argument;
  mem_buffer_t *payload;
  bool canonical_backing;
  crypto_tls_diagnostic tls;
} cnet_event_entry;

typedef struct cnet_event_queue_impl {
  disruptor_t *ring;
  size_t data_capacity;
  size_t max_payload_bytes;
  size_t payload_capacity_bytes;
  mem_pool_t payload_pool;
  atomic_size_t live_events;
  atomic_size_t live_data_events;
  atomic_size_t live_payload_bytes;
  atomic_size_t peak_payload_bytes;
  _Atomic uint64_t rejected_payload_bytes;
  atomic_bool close_complete;
  _Atomic uint64_t *borrowed_sequences;
  size_t borrowed_capacity;
  atomic_size_t borrowed_count;
} cnet_event_queue_impl;

typedef struct cnet_event_wait_context {
  cnet_event_queue_impl *impl;
  cnet_event_keep_waiting_fn keep_waiting;
  void *context;
} cnet_event_wait_context;

#define CNET_EVENT_PUBLISHER_CLOSED ((size_t)1u << (sizeof(size_t) * CHAR_BIT - 1u))
#define CNET_EVENT_PUBLISHER_DESTROYED ((size_t)1u << (sizeof(size_t) * CHAR_BIT - 2u))
#define CNET_EVENT_PUBLISHER_FLAGS (CNET_EVENT_PUBLISHER_CLOSED | CNET_EVENT_PUBLISHER_DESTROYED)
#define CNET_EVENT_PUBLISHER_COUNT_MASK (~CNET_EVENT_PUBLISHER_FLAGS)

static cnet_event_queue_impl *cnet_event_impl(cnet_event_queue *queue) {
  return queue != NULL ? (cnet_event_queue_impl *)queue->impl : NULL;
}

static const cnet_event_queue_impl *cnet_event_const_impl(const cnet_event_queue *queue) {
  return queue != NULL ? (const cnet_event_queue_impl *)queue->impl : NULL;
}

static int cnet_event_publisher_enter(cnet_event_queue *queue, cnet_event_queue_impl **out_impl) {
  size_t observed;
  if (queue == NULL || out_impl == NULL) return SALTS_EINVAL;
  *out_impl = NULL;
  observed = atomic_load_explicit(&queue->_publisher_lifecycle, memory_order_acquire);
  for (;;) {
    if ((observed & CNET_EVENT_PUBLISHER_DESTROYED) != 0u) return SALTS_EINVAL;
    if ((observed & CNET_EVENT_PUBLISHER_CLOSED) != 0u) return SALTS_ESHUTDOWN;
    if ((observed & CNET_EVENT_PUBLISHER_COUNT_MASK) == CNET_EVENT_PUBLISHER_COUNT_MASK)
      return SALTS_ERANGE;
    if (atomic_compare_exchange_weak_explicit(&queue->_publisher_lifecycle, &observed,
                                              observed + 1u, memory_order_acq_rel,
                                              memory_order_acquire))
      break;
  }
  *out_impl = cnet_event_impl(queue);
  if (*out_impl == NULL) {
    atomic_fetch_sub_explicit(&queue->_publisher_lifecycle, 1u, memory_order_release);
    return SALTS_EINVAL;
  }
  return SALTS_OK;
}

static void cnet_event_publisher_leave(cnet_event_queue *queue) {
  atomic_fetch_sub_explicit(&queue->_publisher_lifecycle, 1u, memory_order_release);
}

static bool cnet_event_power_of_two(uint64_t value) {
  return value != 0u && (value & (value - 1u)) == 0u;
}

static bool cnet_event_valid(const cnet_event *event) {
  if (event == NULL || !cnet_session_handle_valid(event->session)) return false;
  if (event->kind == CNET_EVENT_RECEIVE) {
    if (event->state != CNET_EVENT_STATE_NONE || event->status != SALTS_OK ||
        event->stage != CNET_SESSION_STAGE_NONE ||
        (event->data == NULL && event->size != 0u))
      return false;
    if (event->backing != NULL) {
      if (event->size == 0u) return false;
      if (event->data != mem_buffer_const_data(event->backing) ||
          event->size > mem_buffer_used(event->backing))
        return false;
    }
    return true;
  }
  if (event->kind == CNET_EVENT_SEND)
    return event->state == CNET_EVENT_STATE_NONE && event->status == SALTS_OK &&
           event->stage == CNET_SESSION_STAGE_NONE && event->data == NULL && event->size == 0u &&
           event->argument != 0u && event->backing == NULL;
  if (event->kind != CNET_EVENT_STATE || event->backing != NULL) return false;
  if (event->state < CNET_EVENT_STATE_CONNECTED || event->state > CNET_EVENT_STATE_TLS_HANDSHAKING)
    return false;
  if (event->state == CNET_EVENT_STATE_CONNECTED) {
    if (event->size > CNET_TLS_ALPN_NAME_MAX_BYTES ||
        ((event->data == NULL) != (event->size == 0u)))
      return false;
  } else if (event->data != NULL || event->size != 0u) {
    return false;
  }
  if (event->state == CNET_EVENT_STATE_FAILED)
    return event->status != SALTS_OK && event->stage != CNET_SESSION_STAGE_NONE;
  return event->status == SALTS_OK && event->stage == CNET_SESSION_STAGE_NONE;
}

static bool cnet_event_reserve_data(cnet_event_queue_impl *impl) {
  size_t observed = atomic_load_explicit(&impl->live_data_events, memory_order_relaxed);
  while (observed < impl->data_capacity) {
    if (atomic_compare_exchange_weak_explicit(&impl->live_data_events, &observed, observed + 1u,
                                              memory_order_acq_rel, memory_order_relaxed))
      return true;
  }
  return false;
}

static void cnet_event_saturating_add(_Atomic uint64_t *counter, size_t value) {
  uint64_t observed = atomic_load_explicit(counter, memory_order_relaxed);
  const uint64_t increment = value > UINT64_MAX ? UINT64_MAX : (uint64_t)value;
  for (;;) {
    const uint64_t desired = observed > UINT64_MAX - increment ? UINT64_MAX : observed + increment;
    if (atomic_compare_exchange_weak_explicit(counter, &observed, desired, memory_order_relaxed,
                                              memory_order_relaxed))
      return;
  }
}

static bool cnet_event_reserve_payload(cnet_event_queue_impl *impl, size_t size) {
  size_t observed;
  size_t desired;
  if (size == 0u) return true;
  observed = atomic_load_explicit(&impl->live_payload_bytes, memory_order_relaxed);
  for (;;) {
    if (observed > impl->payload_capacity_bytes ||
        size > impl->payload_capacity_bytes - observed) {
      cnet_event_saturating_add(&impl->rejected_payload_bytes, size);
      return false;
    }
    desired = observed + size;
    if (atomic_compare_exchange_weak_explicit(&impl->live_payload_bytes, &observed, desired,
                                              memory_order_acq_rel, memory_order_relaxed)) {
      size_t peak = atomic_load_explicit(&impl->peak_payload_bytes, memory_order_relaxed);
      while (peak < desired &&
             !atomic_compare_exchange_weak_explicit(&impl->peak_payload_bytes, &peak, desired,
                                                    memory_order_relaxed, memory_order_relaxed)) {
      }
      return true;
    }
  }
}

int cnet_event_queue_init(cnet_event_queue *queue, const cnet_event_queue_config *config) {
  cnet_event_queue_impl *impl;
  disruptor_config_t ring_config;
  size_t payload_capacity_bytes;
  size_t index;

  if (queue == NULL) return SALTS_EINVAL;
  if (queue->impl != NULL) return SALTS_EALREADY;
  if (config == NULL || !cnet_event_power_of_two(config->capacity) || config->data_capacity == 0u ||
      config->data_capacity >= config->capacity || config->max_payload_bytes == 0u)
    return SALTS_EINVAL;
  if (config->capacity > SIZE_MAX / sizeof(cnet_event_entry) ||
      (config->payload_capacity_bytes == 0u &&
       config->capacity > SIZE_MAX / config->max_payload_bytes))
    return SALTS_ERANGE;
  payload_capacity_bytes = config->payload_capacity_bytes != 0u
                               ? config->payload_capacity_bytes
                               : (size_t)config->capacity * config->max_payload_bytes;
  if (payload_capacity_bytes < config->max_payload_bytes) return SALTS_EINVAL;

  impl = (cnet_event_queue_impl *)cnet_storage_alloc(&config->storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  ring_config.entry_size = sizeof(cnet_event_entry);
  ring_config.capacity = config->capacity;
  ring_config.consumer_capacity = 1u;
  ring_config.mode = DISRUPTOR_MODE_WORKER_POOL;
  impl->ring = disruptor_create(&ring_config);
  if (impl->ring == NULL) {
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  impl->borrowed_sequences =
      (_Atomic uint64_t *)cnet_storage_alloc(&config->storage, (size_t)config->capacity, sizeof(*impl->borrowed_sequences));
  if (impl->borrowed_sequences == NULL || mem_init(&impl->payload_pool, 0u) != 0) {
    disruptor_destroy(impl->ring);
    cnet_storage_free((void *)impl->borrowed_sequences);
    cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  impl->data_capacity = config->data_capacity;
  impl->max_payload_bytes = config->max_payload_bytes;
  impl->payload_capacity_bytes = payload_capacity_bytes;
  impl->borrowed_capacity = (size_t)config->capacity;
  for (index = 0u; index < impl->borrowed_capacity; ++index)
    atomic_init(&impl->borrowed_sequences[index], 0u);
  atomic_init(&impl->live_events, 0u);
  atomic_init(&impl->live_data_events, 0u);
  atomic_init(&impl->live_payload_bytes, 0u);
  atomic_init(&impl->peak_payload_bytes, 0u);
  atomic_init(&impl->rejected_payload_bytes, 0u);
  atomic_init(&impl->close_complete, false);
  atomic_init(&impl->borrowed_count, 0u);
  queue->impl = impl;
  atomic_store_explicit(&queue->_publisher_lifecycle, 0u, memory_order_release);
  return SALTS_OK;
}

bool cnet_event_queue_get_config(const cnet_event_queue *queue,
                                 cnet_event_queue_config *out_config) {
  const cnet_event_queue_impl *impl = cnet_event_const_impl(queue);
  if (impl == NULL || out_config == NULL) return false;
  *out_config = (cnet_event_queue_config){impl->borrowed_capacity, impl->data_capacity,
                                          impl->max_payload_bytes, impl->payload_capacity_bytes};
  return true;
}

bool cnet_event_queue_get_stats(const cnet_event_queue *queue,
                                cnet_event_queue_stats *out_stats) {
  const cnet_event_queue_impl *impl = cnet_event_const_impl(queue);
  if (impl == NULL || out_stats == NULL) return false;
  *out_stats = (cnet_event_queue_stats){
      atomic_load_explicit(&impl->live_events, memory_order_acquire),
      atomic_load_explicit(&impl->live_payload_bytes, memory_order_acquire),
      atomic_load_explicit(&impl->peak_payload_bytes, memory_order_acquire),
      atomic_load_explicit(&impl->rejected_payload_bytes, memory_order_acquire),
      (atomic_load_explicit(&queue->_publisher_lifecycle, memory_order_acquire) &
       CNET_EVENT_PUBLISHER_CLOSED) == 0u};
  return true;
}

int cnet_event_queue_publish(cnet_event_queue *queue, const cnet_event *event) {
  cnet_event_queue_impl *impl = NULL;
  disruptor_cursor_t cursor = {0};
  cnet_event_entry *entry;
  mem_buffer_t *payload = NULL;
  const bool data_event = event != NULL && event->kind == CNET_EVENT_RECEIVE;
  int status;

  if (!cnet_event_valid(event)) return SALTS_EINVAL;
  status = cnet_event_publisher_enter(queue, &impl);
  if (status != SALTS_OK) return status;
  if (event->size > impl->max_payload_bytes) {
    cnet_event_publisher_leave(queue);
    return SALTS_EMSGSIZE;
  }
  if (data_event && !cnet_event_reserve_data(impl)) {
    cnet_event_publisher_leave(queue);
    return SALTS_ENOBUFS;
  }
  if (!cnet_event_reserve_payload(impl, event->size)) {
    if (data_event) atomic_fetch_sub_explicit(&impl->live_data_events, 1u, memory_order_release);
    cnet_event_publisher_leave(queue);
    return SALTS_ENOBUFS;
  }
  if (event->size != 0u) {
    if (data_event && event->backing != NULL) {
      payload = mem_buffer_retain(event->backing);
    } else {
      payload = mem_get_buffer(&impl->payload_pool, event->size);
      if (payload != NULL) {
        memcpy(mem_buffer_data(payload), event->data, event->size);
        mem_set_used(payload, event->size);
      }
    }
    if (payload == NULL) {
      atomic_fetch_sub_explicit(&impl->live_payload_bytes, event->size, memory_order_release);
      if (data_event)
        atomic_fetch_sub_explicit(&impl->live_data_events, 1u, memory_order_release);
      cnet_event_publisher_leave(queue);
      return SALTS_ENOMEM;
    }
  }
  if (!disruptor_publisher_try_claim(impl->ring, &cursor)) {
    mem_buffer_release(payload);
    if (event->size != 0u)
      atomic_fetch_sub_explicit(&impl->live_payload_bytes, event->size, memory_order_release);
    if (data_event) atomic_fetch_sub_explicit(&impl->live_data_events, 1u, memory_order_release);
    cnet_event_publisher_leave(queue);
    return SALTS_ENOBUFS;
  }

  entry = (cnet_event_entry *)disruptor_acquire_entry(impl->ring, &cursor);
  entry->kind = event->kind;
  entry->session = event->session;
  entry->state = event->state;
  entry->status = event->status;
  entry->stage = event->stage;
  entry->size = event->size;
  entry->argument = event->argument;
  entry->tls = event->tls;
  entry->payload = payload;
  entry->canonical_backing = data_event && event->backing != NULL;
  atomic_fetch_add_explicit(&impl->live_events, 1u, memory_order_release);
  (void)disruptor_publisher_publish(impl->ring, &cursor);
  cnet_event_publisher_leave(queue);
  return SALTS_OK;
}

static int cnet_event_queue_take_claimed(cnet_event_queue_impl *impl,
                                         const disruptor_cursor_t *cursor,
                                         cnet_event_view *out_view) {
  const cnet_event_entry *entry;
  entry = (const cnet_event_entry *)disruptor_show_entry(impl->ring, cursor);
  out_view->kind = entry->kind;
  out_view->session = entry->session;
  out_view->state = entry->state;
  out_view->status = entry->status;
  out_view->stage = entry->stage;
  out_view->data = entry->size != 0u ? mem_buffer_const_data(entry->payload) : NULL;
  out_view->size = entry->size;
  out_view->argument = entry->argument;
  out_view->tls = entry->tls;
  out_view->_sequence = cursor->sequence;
  out_view->backing = entry->canonical_backing ? entry->payload : NULL;
  atomic_store_explicit(
      &impl->borrowed_sequences[(size_t)((cursor->sequence - 1u) & (impl->borrowed_capacity - 1u))],
      cursor->sequence, memory_order_release);
  atomic_fetch_add_explicit(&impl->borrowed_count, 1u, memory_order_release);
  return SALTS_OK;
}

static int cnet_event_wait_keep_running(void *context) {
  cnet_event_wait_context *wait = (cnet_event_wait_context *)context;
  return !atomic_load_explicit(&wait->impl->close_complete, memory_order_acquire) &&
         wait->keep_waiting(wait->context);
}

int cnet_event_queue_take(cnet_event_queue *queue, cnet_event_view *out_view) {
  cnet_event_queue_impl *impl = cnet_event_impl(queue);
  disruptor_cursor_t cursor = {0};

  if (out_view == NULL) return SALTS_EINVAL;
  memset(out_view, 0, sizeof(*out_view));
  if (impl == NULL) return SALTS_EINVAL;
  if (!disruptor_worker_try_claim(impl->ring, &cursor)) {
    if (atomic_load_explicit(&impl->close_complete, memory_order_acquire) &&
        atomic_load_explicit(&impl->live_events, memory_order_acquire) == 0u)
      return SALTS_EOF;
    return SALTS_ETIMEDOUT;
  }
  return cnet_event_queue_take_claimed(impl, &cursor, out_view);
}

int cnet_event_queue_take_wait(cnet_event_queue *queue, cnet_event_view *out_view,
                               cnet_event_keep_waiting_fn keep_waiting, void *context) {
  cnet_event_queue_impl *impl = cnet_event_impl(queue);
  disruptor_cursor_t cursor = {0};
  cnet_event_wait_context wait;

  if (out_view == NULL) return SALTS_EINVAL;
  memset(out_view, 0, sizeof(*out_view));
  if (impl == NULL || keep_waiting == NULL) return SALTS_EINVAL;
  wait = (cnet_event_wait_context){impl, keep_waiting, context};
  if (!disruptor_worker_claim_wait(impl->ring, &cursor, cnet_event_wait_keep_running, &wait))
    return atomic_load_explicit(&impl->close_complete, memory_order_acquire) ? SALTS_EOF
                                                                             : SALTS_ECANCELED;
  return cnet_event_queue_take_claimed(impl, &cursor, out_view);
}

int cnet_event_queue_wake(cnet_event_queue *queue) {
  cnet_event_queue_impl *impl = cnet_event_impl(queue);
  if (impl == NULL) return SALTS_EINVAL;
  disruptor_worker_wake_all(impl->ring);
  return SALTS_OK;
}

int cnet_event_queue_release(cnet_event_queue *queue, cnet_event_view *view) {
  cnet_event_queue_impl *impl = cnet_event_impl(queue);
  disruptor_cursor_t cursor;
  cnet_event_entry *entry;
  bool data_event;
  size_t slot;
  uint64_t expected;

  if (impl == NULL || view == NULL || view->_sequence == 0u) return SALTS_EINVAL;
  slot = (size_t)((view->_sequence - 1u) & (impl->borrowed_capacity - 1u));
  cursor.sequence = view->_sequence;
  entry = (cnet_event_entry *)disruptor_show_entry(impl->ring, &cursor);
  if (entry == NULL || ((entry->payload == NULL) != (entry->size == 0u))) return SALTS_EPROTO;
  data_event = entry->kind == CNET_EVENT_RECEIVE;
  expected = view->_sequence;
  if (!atomic_compare_exchange_strong_explicit(&impl->borrowed_sequences[slot], &expected, 0u,
                                               memory_order_acq_rel, memory_order_acquire))
    return SALTS_EINVAL;
  mem_buffer_release(entry->payload);
  entry->payload = NULL;
  entry->canonical_backing = false;
  if (entry->size != 0u)
    atomic_fetch_sub_explicit(&impl->live_payload_bytes, entry->size, memory_order_release);
  disruptor_worker_release_entry(impl->ring, &cursor);
  atomic_fetch_sub_explicit(&impl->live_events, 1u, memory_order_release);
  if (data_event)
    atomic_fetch_sub_explicit(&impl->live_data_events, 1u, memory_order_release);
  atomic_fetch_sub_explicit(&impl->borrowed_count, 1u, memory_order_release);
  memset(view, 0, sizeof(*view));
  return SALTS_OK;
}

int cnet_event_queue_close(cnet_event_queue *queue) {
  cnet_event_queue_impl *impl = cnet_event_impl(queue);
  size_t lifecycle;

  if (impl == NULL) return SALTS_EINVAL;
  lifecycle = atomic_fetch_or_explicit(&queue->_publisher_lifecycle, CNET_EVENT_PUBLISHER_CLOSED,
                                       memory_order_acq_rel);
  if ((lifecycle & CNET_EVENT_PUBLISHER_DESTROYED) != 0u) return SALTS_EINVAL;
  if ((lifecycle & CNET_EVENT_PUBLISHER_COUNT_MASK) != 0u) return SALTS_EBUSY;
  if (atomic_exchange_explicit(&impl->close_complete, true, memory_order_acq_rel))
    return SALTS_EALREADY;
  disruptor_worker_wake_all(impl->ring);
  return SALTS_OK;
}

int cnet_event_queue_destroy(cnet_event_queue *queue) {
  cnet_event_queue_impl *impl = cnet_event_impl(queue);
  const size_t lifecycle =
      queue != NULL ? atomic_load_explicit(&queue->_publisher_lifecycle, memory_order_acquire) : 0u;

  if (queue == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;
  if ((lifecycle & CNET_EVENT_PUBLISHER_CLOSED) == 0u ||
      (lifecycle & CNET_EVENT_PUBLISHER_COUNT_MASK) != 0u ||
      !atomic_load_explicit(&impl->close_complete, memory_order_acquire) ||
      atomic_load_explicit(&impl->live_events, memory_order_acquire) != 0u ||
      atomic_load_explicit(&impl->borrowed_count, memory_order_acquire) != 0u)
    return SALTS_EBUSY;
  disruptor_destroy(impl->ring);
  mem_destroy(&impl->payload_pool);
  cnet_storage_free((void *)impl->borrowed_sequences);
  cnet_storage_free(impl);
  queue->impl = NULL;
  atomic_store_explicit(&queue->_publisher_lifecycle,
                        CNET_EVENT_PUBLISHER_CLOSED | CNET_EVENT_PUBLISHER_DESTROYED,
                        memory_order_release);
  return SALTS_OK;
}
