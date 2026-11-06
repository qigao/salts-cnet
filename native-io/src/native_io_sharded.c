#include <native_io_sharded.h>

#include <thread.h>
#include <coro_executor.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct native_io_sharded_shard native_io_sharded_shard;
typedef struct native_io_sharded_slot native_io_sharded_slot;
typedef struct native_io_sharded_request_ownership native_io_sharded_request_ownership;
typedef struct native_io_sharded_ownership_settlement native_io_sharded_ownership_settlement;
typedef struct native_io_sharded_owned_route native_io_sharded_owned_route;
typedef struct native_io_sharded_endpoint_record {
  uint32_t generation;
  bool active;
} native_io_sharded_endpoint_record;

struct native_io_sharded_context {
  native_io_sharded *runtime;
  size_t shard;
};

struct native_io_sharded_slot {
  native_io_sharded *runtime;
  native_io_sharded_shard *shard;
  native_io_sharded_task task;
  size_t index;
  int active;
};

struct native_io_sharded_request_ownership {
  native_io_sharded_ownership ownership;
  uint32_t generation;
  int active;
};

struct native_io_sharded_ownership_settlement {
  native_io_sharded_ownership ownership;
  int active;
};

struct native_io_sharded_owned_route {
  native_io_sharded *runtime;
  native_io_sharded_shard *shard;
  native_io_sharded_operation operation;
  native_io_sharded_ownership ownership;
  native_io_sharded_admission_fn admission;
  void *admission_arg;
  native_io_sharded_request request;
  size_t index;
  int admission_status;
  int raw_owned;
  int active;
};

struct native_io_sharded_shard {
  native_io_sharded *runtime;
  size_t index;
  native_io_backend backend;
  native_io_sharded_context context;
  native_io_completion *completion_scratch;
  native_io_sharded_completion *drain_events;
  native_io_sharded_ownership_settlement *ownership_settlements;
  size_t completion_capacity;
  native_io_sharded_request_ownership *request_ownerships;
  size_t request_ownership_capacity;
  int observe_active;
  /* Keep separate counts for SG-wrapped endpoints and host-borrowed NativeIO
   * endpoints. A raw host endpoint may be idle with zero active requests. */
  native_io_sharded_endpoint_record *endpoint_records;
  size_t endpoint_record_capacity;
  size_t owned_endpoint_count;
  int host_verifying;
  int host_active;
  uint64_t host_generation;
  native_io_sharded_host_quiescent_fn host_quiescent;
  void *host_user;

  native_io_sharded_slot *slots;
  size_t *free_slots;
  size_t slot_capacity;
  size_t free_count;
  native_io_sharded_owned_route *owned_routes;
  size_t *free_owned_routes;
  size_t owned_route_capacity;
  size_t free_owned_route_count;
  cmeta_mutex_t slot_lock;
  cmeta_cond_t slot_space;

  atomic_int bootstrap_done;
  atomic_int backend_initialized;
  atomic_int init_status;
  atomic_int draining;
  atomic_int shutdown_probe_done;
  atomic_int shutdown_probe_status;
  atomic_int shutdown_drain_done;
  atomic_int shutdown_drain_status;
  atomic_size_t shutdown_drain_endpoint_count;
  atomic_int teardown_done;
  atomic_int teardown_status;
  int teardown_submitted;
};

struct native_io_sharded {
  coro_executor_t *executor;
  native_io_sharded_shard *shards;
  native_io_backend_config backend_config;
  size_t shard_count;
  size_t queue_capacity_per_shard;
  size_t command_slot_capacity_per_shard;
  uint64_t identity;

  cmeta_mutex_t admission_lock;
  cmeta_cond_t admission_idle;
  size_t inflight_dispatches;
  atomic_int accepting;
  int shutdown_active;
  int executor_shutdown;

  atomic_uint_fast64_t submitted_tasks;
  atomic_uint_fast64_t same_shard_direct_tasks;
  atomic_uint_fast64_t queued_dispatches;
  atomic_uint_fast64_t completed_tasks;
  atomic_uint_fast64_t cancelled_tasks;
  atomic_uint_fast64_t rejected_tasks;
  atomic_uint_fast64_t active_command_slots;
  atomic_uint_fast64_t peak_command_slots;
};

static atomic_uint_fast64_t native_io_sharded_identity_source = 0u;

static uint64_t native_io_sharded_next_identity(void) {
  uint64_t identity = (uint64_t)atomic_fetch_add(&native_io_sharded_identity_source, 1u) + 1u;
  if (identity == 0u)
    identity = (uint64_t)atomic_fetch_add(&native_io_sharded_identity_source, 1u) + 1u;
  return identity;
}

static int native_io_sharded_is_power_of_two(size_t value) {
  return value != 0u && (value & (value - 1u)) == 0u;
}

static void native_io_sharded_update_peak(atomic_uint_fast64_t *peak, uint64_t candidate) {
  uint_fast64_t seen = atomic_load(peak);
  while (candidate > seen &&
         !atomic_compare_exchange_weak(peak, &seen, (uint_fast64_t)candidate)) {
  }
}

static int native_io_sharded_in_callback(const native_io_sharded *runtime) {
  return runtime != NULL && runtime->executor != NULL &&
         coro_executor_current() == runtime->executor;
}

static native_io_sharded_shard *
native_io_sharded_context_owner(native_io_sharded_context *context) {
  native_io_sharded *runtime;
  if (context == NULL || context->runtime == NULL) return NULL;
  runtime = context->runtime;
  if (runtime->executor == NULL || context->shard >= runtime->shard_count ||
      coro_executor_current_shard(runtime->executor) != context->shard)
    return NULL;
  return &runtime->shards[context->shard];
}

static size_t native_io_sharded_owned_request_count(const native_io_sharded_shard *shard) {
  size_t count = 0u;
  if (shard == NULL || shard->request_ownerships == NULL) return 0u;
  for (size_t index = 0u; index < shard->request_ownership_capacity; ++index)
    if (shard->request_ownerships[index].active) ++count;
  return count;
}

static void native_io_sharded_restore_after_shutdown_attempt(native_io_sharded *runtime) {
  if (runtime == NULL) return;
  for (size_t index = 0u; index < runtime->shard_count; ++index)
    atomic_store(&runtime->shards[index].draining, 0);
  cmeta_mutex_lock(&runtime->admission_lock);
  if (!runtime->executor_shutdown) atomic_store(&runtime->accepting, 1);
  runtime->shutdown_active = 0;
  cmeta_mutex_unlock(&runtime->admission_lock);
}

static void native_io_sharded_finish_fatal_shutdown_attempt(native_io_sharded *runtime) {
  if (runtime == NULL) return;
  /*
   * A fatal probe/drain error means the quiescence invariant itself could not
   * be established. Keep both public and owner-local new I/O closed; callers
   * may retry shutdown, but must not resume ordinary work on uncertain state.
   */
  for (size_t index = 0u; index < runtime->shard_count; ++index)
    atomic_store(&runtime->shards[index].draining, 1);
  cmeta_mutex_lock(&runtime->admission_lock);
  atomic_store(&runtime->accepting, 0);
  runtime->shutdown_active = 0;
  cmeta_mutex_unlock(&runtime->admission_lock);
}

static int native_io_sharded_finish_shutdown_error(native_io_sharded *runtime, int status) {
  if (status == SALTS_EBUSY)
    native_io_sharded_restore_after_shutdown_attempt(runtime);
  else
    native_io_sharded_finish_fatal_shutdown_attempt(runtime);
  return status;
}

static native_io_operation
native_io_sharded_native_operation(const native_io_sharded_operation *operation) {
  native_io_operation native_operation = {0};
  if (operation == NULL) return native_operation;
  native_operation.kind = operation->kind;
  native_operation.endpoint = operation->endpoint.native_endpoint;
  native_operation.buffer = operation->buffer;
  native_operation.length = operation->length;
  native_operation.user_data = operation->user_data;
  native_operation.address = operation->address;
  native_operation.address_capacity = operation->address_capacity;
  native_operation.address_length = operation->address_length;
  return native_operation;
}

static int native_io_sharded_endpoint_access(native_io_sharded_context *context,
                                             native_io_sharded_endpoint endpoint,
                                             native_io_sharded_shard **out_shard) {
  native_io_sharded_shard *shard = native_io_sharded_context_owner(context);
  if (out_shard != NULL) *out_shard = NULL;
  if (shard == NULL || !native_io_sharded_endpoint_valid(endpoint)) return SALTS_EINVAL;
  if (endpoint.owner_identity != shard->runtime->identity) return SALTS_ENOENT;
  if ((size_t)endpoint.owner_shard != shard->index) return SALTS_EPERM;
  /* Runtime/shard IDs alone do not certify that an endpoint was attached by
   * SG: host consumers can borrow and attach raw endpoints on this backend.
   * Require the exact attached SG generation, never accept a forged wrapper. */
  if (endpoint.native_endpoint.slot == 0u ||
      (size_t)endpoint.native_endpoint.slot > shard->endpoint_record_capacity)
    return SALTS_ENOENT;
  {
    const native_io_sharded_endpoint_record *record =
        &shard->endpoint_records[endpoint.native_endpoint.slot - 1u];
    if (!record->active || record->generation != endpoint.native_endpoint.generation)
      return SALTS_ENOENT;
  }
  if (out_shard != NULL) *out_shard = shard;
  return SALTS_OK;
}

static int native_io_sharded_request_access(native_io_sharded_context *context,
                                            native_io_sharded_request request,
                                            native_io_sharded_shard **out_shard) {
  native_io_sharded_shard *shard = native_io_sharded_context_owner(context);
  if (out_shard != NULL) *out_shard = NULL;
  if (shard == NULL || !native_io_sharded_request_valid(request)) return SALTS_EINVAL;
  if (request.owner_identity != shard->runtime->identity) return SALTS_ENOENT;
  if ((size_t)request.owner_shard != shard->index) return SALTS_EPERM;
  if (out_shard != NULL) *out_shard = shard;
  return SALTS_OK;
}

static int native_io_sharded_dispatch_begin(native_io_sharded *runtime) {
  cmeta_mutex_lock(&runtime->admission_lock);
  if (!atomic_load(&runtime->accepting)) {
    cmeta_mutex_unlock(&runtime->admission_lock);
    return SALTS_ESHUTDOWN;
  }
  runtime->inflight_dispatches++;
  cmeta_mutex_unlock(&runtime->admission_lock);
  return SALTS_OK;
}

static void native_io_sharded_dispatch_end(native_io_sharded *runtime) {
  cmeta_mutex_lock(&runtime->admission_lock);
  if (runtime->inflight_dispatches != 0u) runtime->inflight_dispatches--;
  if (runtime->inflight_dispatches == 0u) cmeta_cond_broadcast(&runtime->admission_idle);
  cmeta_mutex_unlock(&runtime->admission_lock);
}

static void native_io_sharded_release_slot(native_io_sharded_slot *slot) {
  native_io_sharded_shard *shard;
  native_io_sharded *runtime;

  if (slot == NULL || !slot->active) return;
  shard = slot->shard;
  runtime = slot->runtime;

  cmeta_mutex_lock(&shard->slot_lock);
  if (slot->active) {
    slot->active = 0;
    slot->task = (native_io_sharded_task){0};
    shard->free_slots[shard->free_count++] = slot->index;
    atomic_fetch_sub(&runtime->active_command_slots, 1u);
    cmeta_cond_signal(&shard->slot_space);
  }
  cmeta_mutex_unlock(&shard->slot_lock);
}

static int native_io_sharded_claim_slot(native_io_sharded *runtime,
                                        native_io_sharded_shard *shard,
                                        const native_io_sharded_task *task, int blocking,
                                        native_io_sharded_slot **out_slot) {
  native_io_sharded_slot *slot;
  uint64_t active;
  size_t index;

  if (out_slot != NULL) *out_slot = NULL;
  if (runtime == NULL || shard == NULL || task == NULL || out_slot == NULL) return SALTS_EINVAL;

  cmeta_mutex_lock(&shard->slot_lock);
  for (;;) {
    if (!atomic_load(&runtime->accepting)) {
      cmeta_mutex_unlock(&shard->slot_lock);
      return SALTS_ESHUTDOWN;
    }
    if (shard->free_count != 0u) break;
    if (!blocking) {
      cmeta_mutex_unlock(&shard->slot_lock);
      return SALTS_ENOBUFS;
    }
    if (native_io_sharded_in_callback(runtime)) {
      cmeta_mutex_unlock(&shard->slot_lock);
      return SALTS_EBUSY;
    }
    cmeta_cond_wait(&shard->slot_space, &shard->slot_lock);
  }

  index = shard->free_slots[--shard->free_count];
  slot = &shard->slots[index];
  slot->task = *task;
  slot->active = 1;
  active = atomic_fetch_add(&runtime->active_command_slots, 1u) + 1u;
  native_io_sharded_update_peak(&runtime->peak_command_slots, active);
  cmeta_mutex_unlock(&shard->slot_lock);

  *out_slot = slot;
  return SALTS_OK;
}

static void native_io_sharded_release_owned_route(native_io_sharded_owned_route *route) {
  native_io_sharded_shard *shard;
  if (route == NULL || !route->active) return;
  shard = route->shard;
  cmeta_mutex_lock(&shard->slot_lock);
  if (route->active) {
    const size_t index = route->index;
    native_io_sharded *runtime = route->runtime;
    memset(route, 0, sizeof(*route));
    route->runtime = runtime;
    route->shard = shard;
    route->index = index;
    route->active = 0;
    shard->free_owned_routes[shard->free_owned_route_count++] = index;
    cmeta_cond_signal(&shard->slot_space);
  }
  cmeta_mutex_unlock(&shard->slot_lock);
}

static int native_io_sharded_claim_owned_route(
    native_io_sharded *runtime, native_io_sharded_shard *shard,
    const native_io_sharded_operation *operation,
    const native_io_sharded_ownership *ownership,
    native_io_sharded_admission_fn admission, void *admission_arg, int blocking,
    native_io_sharded_owned_route **out_route) {
  native_io_sharded_owned_route *route;
  size_t index;

  if (out_route != NULL) *out_route = NULL;
  if (runtime == NULL || shard == NULL || operation == NULL || ownership == NULL ||
      ownership->finalize == NULL || out_route == NULL)
    return SALTS_EINVAL;

  cmeta_mutex_lock(&shard->slot_lock);
  for (;;) {
    if (!atomic_load(&runtime->accepting)) {
      cmeta_mutex_unlock(&shard->slot_lock);
      return SALTS_ESHUTDOWN;
    }
    if (shard->free_owned_route_count != 0u) break;
    if (!blocking) {
      cmeta_mutex_unlock(&shard->slot_lock);
      return SALTS_ENOBUFS;
    }
    if (native_io_sharded_in_callback(runtime)) {
      cmeta_mutex_unlock(&shard->slot_lock);
      return SALTS_EBUSY;
    }
    cmeta_cond_wait(&shard->slot_space, &shard->slot_lock);
  }

  index = shard->free_owned_routes[--shard->free_owned_route_count];
  route = &shard->owned_routes[index];
  route->operation = *operation;
  route->ownership = *ownership;
  route->admission = admission;
  route->admission_arg = admission_arg;
  route->request = (native_io_sharded_request){0};
  route->admission_status = SALTS_EINVAL;
  route->raw_owned = 0;
  route->active = 1;
  cmeta_mutex_unlock(&shard->slot_lock);

  *out_route = route;
  return SALTS_OK;
}

static void native_io_sharded_owned_route_run(native_io_sharded_context *context, void *arg) {
  native_io_sharded_owned_route *route = (native_io_sharded_owned_route *)arg;
  route->admission_status = native_io_sharded_context_submit_owned(
      context, &route->operation, &route->ownership, &route->request);
  route->raw_owned = route->admission_status == SALTS_OK;
  if (route->admission != NULL)
    route->admission(context, route->admission_status, route->request, route->admission_arg);
}

static void native_io_sharded_owned_route_cancel(void *arg, int status) {
  native_io_sharded_owned_route *route = (native_io_sharded_owned_route *)arg;
  route->admission_status = status;
  route->request = (native_io_sharded_request){0};
  route->raw_owned = 0;
  if (route->admission != NULL)
    route->admission(&route->shard->context, status, route->request, route->admission_arg);
}

static void native_io_sharded_owned_route_finalize(void *arg) {
  native_io_sharded_owned_route *route = (native_io_sharded_owned_route *)arg;
  native_io_sharded_finalize_fn finalize = route->ownership.finalize;
  void *ownership_arg = route->ownership.arg;
  const int raw_owned = route->raw_owned;

  if (!raw_owned && finalize != NULL) finalize(ownership_arg);
  native_io_sharded_release_owned_route(route);
}

static void native_io_sharded_routed_run(coro_t *coroutine, void *arg) {
  native_io_sharded_slot *slot = (native_io_sharded_slot *)arg;
  native_io_sharded *runtime = slot->runtime;
  (void)coroutine;

  slot->task.run(&slot->shard->context, slot->task.arg);
  atomic_fetch_add(&runtime->completed_tasks, 1u);
}

static void native_io_sharded_routed_cancel(void *arg, int status) {
  native_io_sharded_slot *slot = (native_io_sharded_slot *)arg;
  native_io_sharded *runtime = slot->runtime;

  if (slot->task.cancel != NULL) slot->task.cancel(slot->task.arg, status);
  atomic_fetch_add(&runtime->cancelled_tasks, 1u);
}

static void native_io_sharded_routed_finalize(void *arg) {
  native_io_sharded_slot *slot = (native_io_sharded_slot *)arg;
  native_io_sharded_finalize_fn finalize = slot->task.finalize;
  void *user_arg = slot->task.arg;

  if (finalize != NULL) finalize(user_arg);
  native_io_sharded_release_slot(slot);
}

static void native_io_sharded_bootstrap(coro_t *coroutine, void *arg) {
  native_io_sharded_shard *shard = (native_io_sharded_shard *)arg;
  int status;
  (void)coroutine;

  status = native_io_backend_init(&shard->backend, &shard->runtime->backend_config);
  atomic_store(&shard->init_status, status);
  if (status == SALTS_OK) atomic_store(&shard->backend_initialized, 1);
  atomic_store(&shard->bootstrap_done, 1);
}

static void native_io_sharded_bootstrap_cancel(void *arg, int status) {
  native_io_sharded_shard *shard = (native_io_sharded_shard *)arg;
  /* An accepted bootstrap either runs or is cancelled before backend creation.
   * Publish its original terminal status before create() joins and reads it. */
  atomic_store(&shard->init_status, status);
  atomic_store(&shard->bootstrap_done, 1);
}

static void native_io_sharded_shutdown_probe(coro_t *coroutine, void *arg) {
  native_io_sharded_shard *shard = (native_io_sharded_shard *)arg;
  native_io_backend_stats stats = {0};
  const size_t owned = native_io_sharded_owned_request_count(shard);
  int status = SALTS_OK;
  (void)coroutine;

  if (shard->host_active) {
    status = SALTS_EBUSY; /* A borrowed backend cannot be destroyed. */
  } else if (!native_io_backend_get_stats(&shard->backend, &stats)) {
    status = SALTS_EIO;
  } else if (stats.active_requests < owned) {
    status = SALTS_EPROTO;
  } else if (stats.active_requests > owned) {
    status = SALTS_EBUSY;
  }
  atomic_store(&shard->shutdown_probe_status, status);
  atomic_store(&shard->shutdown_probe_done, 1);
}

static void native_io_sharded_shutdown_drain(coro_t *coroutine, void *arg) {
  native_io_sharded_shard *shard = (native_io_sharded_shard *)arg;
  native_io_backend_stats stats = {0};
  int status = SALTS_OK;
  (void)coroutine;

  for (size_t index = 0u; index < shard->request_ownership_capacity; ++index) {
    native_io_sharded_request_ownership *record = &shard->request_ownerships[index];
    native_io_request request;
    int cancel_status;
    if (!record->active) continue;
    request = (native_io_request){(uint32_t)(index + 1u), record->generation};
    cancel_status = native_io_backend_cancel(&shard->backend, request);
    if (cancel_status != SALTS_OK && cancel_status != SALTS_EALREADY) {
      status = cancel_status == SALTS_ENOENT ? SALTS_EPROTO : cancel_status;
      break;
    }
  }

  while (status == SALTS_OK && native_io_sharded_owned_request_count(shard) != 0u) {
    size_t count = 0u;
    status = native_io_sharded_context_observe(
        &shard->context, shard->drain_events, shard->completion_capacity,
        UINT32_MAX, &count);
    if (status == SALTS_OK && count == 0u) continue;
  }

  if (status == SALTS_OK) {
    if (!native_io_backend_get_stats(&shard->backend, &stats)) {
      status = SALTS_EIO;
    } else if (stats.active_requests != 0u) {
      status = SALTS_EPROTO;
    }
  }
  atomic_store(&shard->shutdown_drain_endpoint_count, stats.endpoint_count);
  atomic_store(&shard->shutdown_drain_status, status);
  atomic_store(&shard->shutdown_drain_done, 1);
}

static void native_io_sharded_teardown(coro_t *coroutine, void *arg) {
  native_io_sharded_shard *shard = (native_io_sharded_shard *)arg;
  int status = SALTS_OK;
  (void)coroutine;

  if (atomic_load(&shard->backend_initialized)) {
    status = native_io_backend_close(&shard->backend);
    if (status == SALTS_OK) status = native_io_backend_destroy(&shard->backend);
    if (status == SALTS_OK) atomic_store(&shard->backend_initialized, 0);
  }
  atomic_store(&shard->teardown_status, status);
  atomic_store(&shard->teardown_done, 1);
}

static void native_io_sharded_wake_slot_waiters(native_io_sharded *runtime) {
  if (runtime == NULL || runtime->shards == NULL) return;
  for (size_t index = 0u; index < runtime->shard_count; ++index) {
    native_io_sharded_shard *shard = &runtime->shards[index];
    cmeta_mutex_lock(&shard->slot_lock);
    cmeta_cond_broadcast(&shard->slot_space);
    cmeta_mutex_unlock(&shard->slot_lock);
  }
}

static void native_io_sharded_destroy_storage(native_io_sharded *runtime) {
  if (runtime == NULL) return;
  if (runtime->shards != NULL) {
    for (size_t index = 0u; index < runtime->shard_count; ++index) {
      native_io_sharded_shard *shard = &runtime->shards[index];
      free(shard->request_ownerships);
      free(shard->endpoint_records);
      free(shard->ownership_settlements);
      free(shard->drain_events);
      free(shard->completion_scratch);
      free(shard->free_owned_routes);
      free(shard->owned_routes);
      free(shard->free_slots);
      free(shard->slots);
      cmeta_mutex_destroy(&shard->slot_lock);
      cmeta_cond_destroy(&shard->slot_space);
    }
  }
  free(runtime->shards);
  cmeta_cond_destroy(&runtime->admission_idle);
  cmeta_mutex_destroy(&runtime->admission_lock);
  free(runtime);
}

static void native_io_sharded_cleanup_failed_create(native_io_sharded *runtime) {
  if (runtime == NULL) return;
  if (runtime->executor != NULL) {
    for (size_t index = 0u; index < runtime->shard_count; ++index) {
      native_io_sharded_shard *shard = &runtime->shards[index];
      if (atomic_load(&shard->backend_initialized)) {
        const coro_executor_task_t task = {
            native_io_sharded_teardown, NULL, NULL, shard};
        if (coro_executor_submit_to(runtime->executor, index, &task) == SALTS_OK)
          shard->teardown_submitted = 1;
      }
    }
    (void)coro_executor_shutdown(runtime->executor);
    (void)coro_executor_wait(runtime->executor);
    (void)coro_executor_destroy(runtime->executor);
    runtime->executor = NULL;
  }
  native_io_sharded_destroy_storage(runtime);
}

int native_io_sharded_create(const native_io_sharded_config *config,
                             native_io_sharded **out_runtime) {
  coro_executor_config_t executor_config = CORO_EXECUTOR_CONFIG_DEFAULT;
  native_io_sharded *runtime;
  size_t slot_capacity;
  int status = SALTS_OK;

  if (out_runtime != NULL) *out_runtime = NULL;
  if (config == NULL || out_runtime == NULL || config->shard_count == 0u ||
      !native_io_sharded_is_power_of_two(config->queue_capacity_per_shard))
    return SALTS_EINVAL;
  if (config->queue_capacity_per_shard > (size_t)INT64_MAX ||
      config->queue_capacity_per_shard == SIZE_MAX ||
      config->shard_count > (size_t)INT_MAX ||
      config->shard_count > SIZE_MAX / sizeof(native_io_sharded_shard))
    return SALTS_ERANGE;
  if (!native_io_backend_kind_supported(config->backend.kind)) return SALTS_ENOTSUP;

  slot_capacity = config->queue_capacity_per_shard + 1u;
  if (slot_capacity > SIZE_MAX / sizeof(native_io_sharded_slot) ||
      slot_capacity > SIZE_MAX / sizeof(native_io_sharded_owned_route) ||
      slot_capacity > SIZE_MAX / sizeof(size_t) ||
      (config->backend.completion_batch_capacity != 0u &&
       (config->backend.completion_batch_capacity > SIZE_MAX / sizeof(native_io_completion) ||
        config->backend.completion_batch_capacity >
            SIZE_MAX / sizeof(native_io_sharded_completion) ||
        config->backend.completion_batch_capacity >
            SIZE_MAX / sizeof(native_io_sharded_ownership_settlement))) ||
      (config->backend.request_capacity != 0u &&
       config->backend.request_capacity >
           SIZE_MAX / sizeof(native_io_sharded_request_ownership)) ||
      (config->backend.endpoint_capacity != 0u &&
       config->backend.endpoint_capacity >
           SIZE_MAX / sizeof(native_io_sharded_endpoint_record)))
    return SALTS_ERANGE;

  runtime = (native_io_sharded *)calloc(1, sizeof(*runtime));
  if (runtime == NULL) return SALTS_ENOMEM;
  runtime->backend_config = config->backend;
  runtime->shard_count = config->shard_count;
  runtime->queue_capacity_per_shard = config->queue_capacity_per_shard;
  runtime->command_slot_capacity_per_shard = slot_capacity;
  runtime->identity = native_io_sharded_next_identity();
  cmeta_mutex_init(&runtime->admission_lock);
  cmeta_cond_init(&runtime->admission_idle);
  if (runtime->admission_lock == NULL || runtime->admission_idle == NULL) {
    native_io_sharded_destroy_storage(runtime);
    return SALTS_ENOMEM;
  }

  runtime->shards =
      (native_io_sharded_shard *)calloc(runtime->shard_count, sizeof(*runtime->shards));
  if (runtime->shards == NULL) {
    native_io_sharded_destroy_storage(runtime);
    return SALTS_ENOMEM;
  }

  for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
    native_io_sharded_shard *shard = &runtime->shards[shard_index];
    shard->runtime = runtime;
    shard->index = shard_index;
    shard->context.runtime = runtime;
    shard->context.shard = shard_index;
    shard->slot_capacity = slot_capacity;
    shard->free_count = slot_capacity;
    shard->owned_route_capacity = slot_capacity;
    shard->free_owned_route_count = slot_capacity;
    shard->completion_capacity = runtime->backend_config.completion_batch_capacity;
    shard->request_ownership_capacity = runtime->backend_config.request_capacity;
    shard->endpoint_record_capacity = runtime->backend_config.endpoint_capacity;
    cmeta_mutex_init(&shard->slot_lock);
    cmeta_cond_init(&shard->slot_space);
    shard->slots = (native_io_sharded_slot *)calloc(slot_capacity, sizeof(*shard->slots));
    shard->free_slots = (size_t *)calloc(slot_capacity, sizeof(*shard->free_slots));
    shard->owned_routes =
        (native_io_sharded_owned_route *)calloc(slot_capacity, sizeof(*shard->owned_routes));
    shard->free_owned_routes =
        (size_t *)calloc(slot_capacity, sizeof(*shard->free_owned_routes));
    if (shard->completion_capacity != 0u) {
      shard->completion_scratch = (native_io_completion *)calloc(
          shard->completion_capacity, sizeof(*shard->completion_scratch));
      shard->drain_events = (native_io_sharded_completion *)calloc(
          shard->completion_capacity, sizeof(*shard->drain_events));
      shard->ownership_settlements = (native_io_sharded_ownership_settlement *)calloc(
          shard->completion_capacity, sizeof(*shard->ownership_settlements));
    }
    if (shard->request_ownership_capacity != 0u)
      shard->request_ownerships = (native_io_sharded_request_ownership *)calloc(
          shard->request_ownership_capacity, sizeof(*shard->request_ownerships));
    if (shard->endpoint_record_capacity != 0u)
      shard->endpoint_records = (native_io_sharded_endpoint_record *)calloc(
          shard->endpoint_record_capacity, sizeof(*shard->endpoint_records));
    if (shard->slot_lock == NULL || shard->slot_space == NULL || shard->slots == NULL ||
        shard->free_slots == NULL || shard->owned_routes == NULL ||
        shard->free_owned_routes == NULL ||
        (shard->completion_capacity != 0u &&
         (shard->completion_scratch == NULL || shard->drain_events == NULL ||
          shard->ownership_settlements == NULL)) ||
        (shard->request_ownership_capacity != 0u && shard->request_ownerships == NULL) ||
        (shard->endpoint_record_capacity != 0u && shard->endpoint_records == NULL)) {
      native_io_sharded_cleanup_failed_create(runtime);
      return SALTS_ENOMEM;
    }
    for (size_t slot = 0u; slot < slot_capacity; ++slot) {
      shard->slots[slot].runtime = runtime;
      shard->slots[slot].shard = shard;
      shard->slots[slot].index = slot;
      shard->free_slots[slot] = slot_capacity - slot - 1u;
      shard->owned_routes[slot].runtime = runtime;
      shard->owned_routes[slot].shard = shard;
      shard->owned_routes[slot].index = slot;
      shard->free_owned_routes[slot] = slot_capacity - slot - 1u;
    }
  }

  executor_config.worker_count = runtime->shard_count;
  executor_config.queue_capacity_per_worker = runtime->queue_capacity_per_shard;
  executor_config.coroutine_pool.initial_capacity = 1u;
  executor_config.coroutine_pool.max_capacity = 1u;
  runtime->executor = coro_executor_create(&executor_config);
  if (runtime->executor == NULL) {
    native_io_sharded_cleanup_failed_create(runtime);
    return SALTS_ENOMEM;
  }

  for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
    const coro_executor_task_t task = {
        native_io_sharded_bootstrap, native_io_sharded_bootstrap_cancel, NULL,
        &runtime->shards[shard_index]};
    status = coro_executor_submit_to(runtime->executor, shard_index, &task);
    if (status != SALTS_OK) break;
  }
  {
    const int wait_status = coro_executor_wait(runtime->executor);
    if (status == SALTS_OK) status = wait_status;
  }

  if (status == SALTS_OK) {
    for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
      native_io_sharded_shard *shard = &runtime->shards[shard_index];
      if (!atomic_load(&shard->bootstrap_done)) {
        status = SALTS_EIO;
        break;
      }
      if (atomic_load(&shard->init_status) != SALTS_OK) {
        status = atomic_load(&shard->init_status);
        break;
      }
    }
  }

  if (status != SALTS_OK) {
    native_io_sharded_cleanup_failed_create(runtime);
    return status;
  }

  atomic_store(&runtime->accepting, 1);
  *out_runtime = runtime;
  return SALTS_OK;
}

static int native_io_sharded_submit_internal(native_io_sharded *runtime, size_t shard_index,
                                             const native_io_sharded_task *task, int blocking) {
  native_io_sharded_shard *shard;
  native_io_sharded_slot *slot = NULL;
  size_t current_shard;
  int status;

  if (runtime == NULL) return SALTS_EINVAL;
  if (task == NULL || task->run == NULL || shard_index >= runtime->shard_count) {
    atomic_fetch_add(&runtime->rejected_tasks, 1u);
    return SALTS_EINVAL;
  }

  status = native_io_sharded_dispatch_begin(runtime);
  if (status != SALTS_OK) {
    atomic_fetch_add(&runtime->rejected_tasks, 1u);
    return status;
  }

  current_shard = coro_executor_current_shard(runtime->executor);
  if (current_shard == shard_index) {
    atomic_fetch_add(&runtime->submitted_tasks, 1u);
    atomic_fetch_add(&runtime->same_shard_direct_tasks, 1u);
    task->run(&runtime->shards[shard_index].context, task->arg);
    atomic_fetch_add(&runtime->completed_tasks, 1u);
    if (task->finalize != NULL) task->finalize(task->arg);
    native_io_sharded_dispatch_end(runtime);
    return SALTS_OK;
  }

  shard = &runtime->shards[shard_index];
  status = native_io_sharded_claim_slot(runtime, shard, task, blocking, &slot);
  if (status != SALTS_OK) {
    native_io_sharded_dispatch_end(runtime);
    atomic_fetch_add(&runtime->rejected_tasks, 1u);
    return status;
  }

  /*
   * Publish the Sharded accounting before handing the task to the executor.
   * Once executor submission succeeds, the target shard may run immediately
   * and observe these counters from inside the routed task. Counting only
   * after submit_to() returns lets that task race ahead of its own accounting,
   * which can leak an earlier external dispatch into a later stats window.
   */
  atomic_fetch_add(&runtime->submitted_tasks, 1u);
  atomic_fetch_add(&runtime->queued_dispatches, 1u);
  {
    const coro_executor_task_t routed = {
        native_io_sharded_routed_run, native_io_sharded_routed_cancel,
        native_io_sharded_routed_finalize, slot};
    status = blocking ? coro_executor_submit_to(runtime->executor, shard_index, &routed)
                      : coro_executor_try_submit_to(runtime->executor, shard_index, &routed);
  }

  if (status != SALTS_OK) {
    atomic_fetch_sub(&runtime->queued_dispatches, 1u);
    atomic_fetch_sub(&runtime->submitted_tasks, 1u);
    native_io_sharded_release_slot(slot);
  }
  native_io_sharded_dispatch_end(runtime);

  if (status != SALTS_OK) atomic_fetch_add(&runtime->rejected_tasks, 1u);
  return status;
}

int native_io_sharded_submit_to(native_io_sharded *runtime, size_t shard,
                                const native_io_sharded_task *task) {
  return native_io_sharded_submit_internal(runtime, shard, task, 1);
}

int native_io_sharded_try_submit_to(native_io_sharded *runtime, size_t shard,
                                    const native_io_sharded_task *task) {
  return native_io_sharded_submit_internal(runtime, shard, task, 0);
}

static int native_io_sharded_submit_owned_internal(
    native_io_sharded *runtime, const native_io_sharded_operation *operation,
    const native_io_sharded_ownership *ownership,
    native_io_sharded_admission_fn admission, void *admission_arg, int blocking) {
  native_io_sharded_owned_route *route = NULL;
  native_io_sharded_shard *shard;
  native_io_sharded_task task;
  size_t shard_index;
  int status;

  if (runtime == NULL || operation == NULL || ownership == NULL ||
      ownership->finalize == NULL || !native_io_sharded_operation_valid(operation))
    return SALTS_EINVAL;
  if (operation->endpoint.owner_identity != runtime->identity) return SALTS_ENOENT;
  shard_index = (size_t)operation->endpoint.owner_shard;
  if (shard_index >= runtime->shard_count) return SALTS_ENOENT;
  shard = &runtime->shards[shard_index];

  /*
   * Keep the route-slot claim and the command admission inside one outer
   * dispatch transaction. shutdown closes accepting first, then waits for this
   * transaction to release either caller ownership or an accepted route.
   */
  status = native_io_sharded_dispatch_begin(runtime);
  if (status != SALTS_OK) return status;

  status = native_io_sharded_claim_owned_route(
      runtime, shard, operation, ownership, admission, admission_arg, blocking, &route);
  if (status != SALTS_OK) {
    native_io_sharded_dispatch_end(runtime);
    return status;
  }

  task = (native_io_sharded_task){
      native_io_sharded_owned_route_run, native_io_sharded_owned_route_cancel,
      native_io_sharded_owned_route_finalize, route};
  status = native_io_sharded_submit_internal(runtime, shard_index, &task, blocking);
  if (status != SALTS_OK) native_io_sharded_release_owned_route(route);
  native_io_sharded_dispatch_end(runtime);
  return status;
}

int native_io_sharded_submit_owned(native_io_sharded *runtime,
                                   const native_io_sharded_operation *operation,
                                   const native_io_sharded_ownership *ownership,
                                   native_io_sharded_admission_fn admission,
                                   void *admission_arg) {
  return native_io_sharded_submit_owned_internal(
      runtime, operation, ownership, admission, admission_arg, 1);
}

int native_io_sharded_try_submit_owned(native_io_sharded *runtime,
                                       const native_io_sharded_operation *operation,
                                       const native_io_sharded_ownership *ownership,
                                       native_io_sharded_admission_fn admission,
                                       void *admission_arg) {
  return native_io_sharded_submit_owned_internal(
      runtime, operation, ownership, admission, admission_arg, 0);
}

int native_io_sharded_shutdown(native_io_sharded *runtime) {
  int first_status = SALTS_OK;
  int all_teardowns_submitted = 1;

  if (runtime == NULL) return SALTS_EINVAL;
  if (native_io_sharded_in_callback(runtime)) return SALTS_EBUSY;

  cmeta_mutex_lock(&runtime->admission_lock);
  if (runtime->executor_shutdown) {
    cmeta_mutex_unlock(&runtime->admission_lock);
    return SALTS_OK;
  }
  if (runtime->shutdown_active) {
    cmeta_mutex_unlock(&runtime->admission_lock);
    return SALTS_EBUSY;
  }
  runtime->shutdown_active = 1;
  atomic_store(&runtime->accepting, 0);
  native_io_sharded_wake_slot_waiters(runtime);
  while (runtime->inflight_dispatches != 0u)
    cmeta_cond_wait(&runtime->admission_idle, &runtime->admission_lock);
  cmeta_mutex_unlock(&runtime->admission_lock);

  /*
   * Probe behind all previously accepted owner commands. A raw request without
   * a matching sharded ownership record is caller-managed; shutdown must not
   * steal its completion by observing it.
   */
  for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
    native_io_sharded_shard *shard = &runtime->shards[shard_index];
    const coro_executor_task_t task = {
        native_io_sharded_shutdown_probe, NULL, NULL, shard};
    atomic_store(&shard->shutdown_probe_done, 0);
    atomic_store(&shard->shutdown_probe_status, SALTS_EIO);
    if (first_status == SALTS_OK) {
      const int status = coro_executor_submit_to(runtime->executor, shard_index, &task);
      if (status != SALTS_OK) first_status = status;
    }
  }
  {
    const int status = coro_executor_wait(runtime->executor);
    if (first_status == SALTS_OK && status != SALTS_OK) first_status = status;
  }
  if (first_status == SALTS_OK) {
    int probe_status = SALTS_OK;
    for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
      native_io_sharded_shard *shard = &runtime->shards[shard_index];
      const int status = atomic_load(&shard->shutdown_probe_status);
      if (!atomic_load(&shard->shutdown_probe_done)) {
        probe_status = SALTS_EIO;
        break;
      }
      if (status == SALTS_OK) continue;
      if (status != SALTS_EBUSY) {
        probe_status = status;
        break;
      }
      if (probe_status == SALTS_OK) probe_status = SALTS_EBUSY;
    }
    first_status = probe_status;
  }
  if (first_status != SALTS_OK)
    return native_io_sharded_finish_shutdown_error(runtime, first_status);

  for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index)
    atomic_store(&runtime->shards[shard_index].draining, 1);

  /*
   * From here no new owner-local attach/submit/prepare/flush is admitted.
   * Cancel only requests termination; observe remains the sole terminal source
   * and owns the exact terminal/finalize edge.
   */
  for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
    native_io_sharded_shard *shard = &runtime->shards[shard_index];
    const coro_executor_task_t task = {
        native_io_sharded_shutdown_drain, NULL, NULL, shard};
    atomic_store(&shard->shutdown_drain_done, 0);
    atomic_store(&shard->shutdown_drain_status, SALTS_EIO);
    if (first_status == SALTS_OK) {
      const int status = coro_executor_submit_to(runtime->executor, shard_index, &task);
      if (status != SALTS_OK) first_status = status;
    }
  }
  {
    const int status = coro_executor_wait(runtime->executor);
    if (first_status == SALTS_OK && status != SALTS_OK) first_status = status;
  }
  if (first_status == SALTS_OK) {
    int drain_status = SALTS_OK;
    int endpoint_busy = 0;
    for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
      native_io_sharded_shard *shard = &runtime->shards[shard_index];
      const int status = atomic_load(&shard->shutdown_drain_status);
      if (!atomic_load(&shard->shutdown_drain_done)) {
        drain_status = SALTS_EIO;
        break;
      }
      if (status != SALTS_OK) {
        drain_status = status;
        break;
      }
      if (atomic_load(&shard->shutdown_drain_endpoint_count) != 0u) endpoint_busy = 1;
    }
    first_status = drain_status != SALTS_OK ? drain_status
                                           : endpoint_busy ? SALTS_EBUSY : SALTS_OK;
  }
  if (first_status != SALTS_OK)
    return native_io_sharded_finish_shutdown_error(runtime, first_status);

  /* Request and endpoint quiescence is now proven on every owner. */
  for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
    native_io_sharded_shard *shard = &runtime->shards[shard_index];
    int status;
    if (shard->teardown_submitted) continue;
    if (!atomic_load(&shard->backend_initialized)) {
      atomic_store(&shard->teardown_status, SALTS_OK);
      atomic_store(&shard->teardown_done, 1);
      shard->teardown_submitted = 1;
      continue;
    }
    atomic_store(&shard->teardown_done, 0);
    atomic_store(&shard->teardown_status, SALTS_EIO);
    {
      const coro_executor_task_t task = {
          native_io_sharded_teardown, NULL, NULL, shard};
      status = coro_executor_submit_to(runtime->executor, shard_index, &task);
    }
    if (status == SALTS_OK) {
      shard->teardown_submitted = 1;
    } else {
      all_teardowns_submitted = 0;
      if (first_status == SALTS_OK) first_status = status;
    }
  }

  if (all_teardowns_submitted && first_status == SALTS_OK) {
    const int status = coro_executor_shutdown(runtime->executor);
    if (status == SALTS_OK)
      runtime->executor_shutdown = 1;
    else
      first_status = status;
  }

  cmeta_mutex_lock(&runtime->admission_lock);
  runtime->shutdown_active = 0;
  cmeta_mutex_unlock(&runtime->admission_lock);
  return first_status;
}

int native_io_sharded_wait(native_io_sharded *runtime) {
  int status;

  if (runtime == NULL) return SALTS_EINVAL;
  if (native_io_sharded_in_callback(runtime)) return SALTS_EBUSY;
  status = coro_executor_wait(runtime->executor);
  if (status != SALTS_OK) return status;

  for (size_t shard_index = 0u; shard_index < runtime->shard_count; ++shard_index) {
    native_io_sharded_shard *shard = &runtime->shards[shard_index];
    if (!shard->teardown_submitted) continue;
    if (!atomic_load(&shard->teardown_done)) return SALTS_EIO;
    status = atomic_load(&shard->teardown_status);
    if (status != SALTS_OK) return status;
  }
  return SALTS_OK;
}

int native_io_sharded_destroy(native_io_sharded *runtime) {
  int status;

  if (runtime == NULL) return SALTS_EINVAL;
  if (native_io_sharded_in_callback(runtime)) return SALTS_EBUSY;

  status = native_io_sharded_shutdown(runtime);
  if (status != SALTS_OK) return status;
  status = native_io_sharded_wait(runtime);
  if (status != SALTS_OK) return status;
  status = coro_executor_destroy(runtime->executor);
  if (status != SALTS_OK) return status;
  runtime->executor = NULL;
  native_io_sharded_destroy_storage(runtime);
  return SALTS_OK;
}

size_t native_io_sharded_current_shard(const native_io_sharded *runtime) {
  if (runtime == NULL || runtime->executor == NULL) return SIZE_MAX;
  return coro_executor_current_shard(runtime->executor);
}

size_t native_io_sharded_context_shard(const native_io_sharded_context *context) {
  return context == NULL ? SIZE_MAX : context->shard;
}

bool native_io_sharded_endpoint_valid(native_io_sharded_endpoint endpoint) {
  return endpoint.owner_identity != 0u && endpoint.reserved == 0u &&
         native_io_endpoint_valid(endpoint.native_endpoint);
}

bool native_io_sharded_request_valid(native_io_sharded_request request) {
  return request.owner_identity != 0u && request.reserved == 0u &&
         native_io_request_valid(request.native_request);
}

bool native_io_sharded_operation_valid(const native_io_sharded_operation *operation) {
  native_io_operation native_operation;
  if (operation == NULL || !native_io_sharded_endpoint_valid(operation->endpoint)) return false;
  native_operation = native_io_sharded_native_operation(operation);
  return native_io_operation_valid(&native_operation);
}

size_t native_io_sharded_endpoint_owner_shard(native_io_sharded_endpoint endpoint) {
  return native_io_sharded_endpoint_valid(endpoint) ? (size_t)endpoint.owner_shard : SIZE_MAX;
}

size_t native_io_sharded_request_owner_shard(native_io_sharded_request request) {
  return native_io_sharded_request_valid(request) ? (size_t)request.owner_shard : SIZE_MAX;
}

static int native_io_sharded_record_endpoint(
    native_io_sharded_shard *shard, native_io_endpoint endpoint) {
  native_io_sharded_endpoint_record *record;
  if (endpoint.slot == 0u || (size_t)endpoint.slot > shard->endpoint_record_capacity ||
      shard->owned_endpoint_count >= shard->endpoint_record_capacity)
    return SALTS_EPROTO;
  record = &shard->endpoint_records[endpoint.slot - 1u];
  if (record->active) return SALTS_EPROTO;
  record->generation = endpoint.generation;
  record->active = true;
  ++shard->owned_endpoint_count;
  return SALTS_OK;
}
static void native_io_sharded_forget_endpoint(
    native_io_sharded_shard *shard, native_io_endpoint endpoint) {
  native_io_sharded_endpoint_record *record =
      &shard->endpoint_records[endpoint.slot - 1u];
  record->active = false;
  --shard->owned_endpoint_count;
}

int native_io_sharded_context_attach_socket(native_io_sharded_context *context,
                                            uintptr_t native_socket,
                                            native_io_sharded_endpoint *out_endpoint) {
  native_io_sharded_shard *shard = native_io_sharded_context_owner(context);
  native_io_endpoint endpoint = {0};
  int status;
  if (out_endpoint != NULL) *out_endpoint = (native_io_sharded_endpoint){0};
  if (shard == NULL || out_endpoint == NULL) return SALTS_EINVAL;
  if (atomic_load(&shard->draining)) return SALTS_ESHUTDOWN;
  status = native_io_backend_attach_socket(&shard->backend, native_socket, &endpoint);
  if (status == SALTS_OK) {
    status = native_io_sharded_record_endpoint(shard, endpoint);
    if (status != SALTS_OK) {
      (void)native_io_backend_release_socket(&shard->backend, endpoint);
      return status;
    }
    out_endpoint->owner_identity = shard->runtime->identity;
    out_endpoint->owner_shard = (uint32_t)shard->index;
    out_endpoint->native_endpoint = endpoint;
  }
  return status;
}

int native_io_sharded_context_attach_pipe(native_io_sharded_context *context,
                                          uintptr_t native_handle, uint32_t flags,
                                          native_io_sharded_endpoint *out_endpoint) {
  native_io_sharded_shard *shard = native_io_sharded_context_owner(context);
  native_io_endpoint endpoint = {0};
  int status;
  if (out_endpoint != NULL) *out_endpoint = (native_io_sharded_endpoint){0};
  if (shard == NULL || out_endpoint == NULL) return SALTS_EINVAL;
  if (atomic_load(&shard->draining)) return SALTS_ESHUTDOWN;
  status = native_io_backend_attach_pipe(&shard->backend, native_handle, flags, &endpoint);
  if (status == SALTS_OK) {
    status = native_io_sharded_record_endpoint(shard, endpoint);
    if (status != SALTS_OK) {
      (void)native_io_backend_release_pipe(&shard->backend, endpoint);
      return status;
    }
    out_endpoint->owner_identity = shard->runtime->identity;
    out_endpoint->owner_shard = (uint32_t)shard->index;
    out_endpoint->native_endpoint = endpoint;
  }
  return status;
}

int native_io_sharded_context_release_socket(native_io_sharded_context *context,
                                             native_io_sharded_endpoint endpoint) {
  native_io_sharded_shard *shard = NULL;
  int status = native_io_sharded_endpoint_access(context, endpoint, &shard);
  if (status != SALTS_OK) return status;
  status = native_io_backend_release_socket(&shard->backend, endpoint.native_endpoint);
  if (status == SALTS_OK)
    native_io_sharded_forget_endpoint(shard, endpoint.native_endpoint);
  return status;
}

int native_io_sharded_context_release_pipe(native_io_sharded_context *context,
                                           native_io_sharded_endpoint endpoint) {
  native_io_sharded_shard *shard = NULL;
  int status = native_io_sharded_endpoint_access(context, endpoint, &shard);
  if (status != SALTS_OK) return status;
  status = native_io_backend_release_pipe(&shard->backend, endpoint.native_endpoint);
  if (status == SALTS_OK)
    native_io_sharded_forget_endpoint(shard, endpoint.native_endpoint);
  return status;
}

static int native_io_sharded_context_admit(native_io_sharded_context *context,
                                           const native_io_sharded_operation *operation,
                                           const native_io_sharded_ownership *ownership,
                                           native_io_sharded_request *out_request, bool prepared) {
  native_io_sharded_shard *shard = NULL;
  native_io_operation native_operation;
  native_io_request request = {0};
  int status;
  if (out_request != NULL) *out_request = (native_io_sharded_request){0};
  if (operation == NULL || out_request == NULL || !native_io_sharded_operation_valid(operation) ||
      (ownership != NULL && ownership->finalize == NULL))
    return SALTS_EINVAL;
  status = native_io_sharded_endpoint_access(context, operation->endpoint, &shard);
  if (status != SALTS_OK) return status;
  if (atomic_load(&shard->draining)) return SALTS_ESHUTDOWN;
  native_operation = native_io_sharded_native_operation(operation);
  status = prepared ? native_io_backend_prepare(&shard->backend, &native_operation, &request)
                    : native_io_backend_submit(&shard->backend, &native_operation, &request);
  if (status == SALTS_OK) {
    out_request->owner_identity = shard->runtime->identity;
    out_request->owner_shard = (uint32_t)shard->index;
    out_request->native_request = request;
    if (ownership != NULL) {
      native_io_sharded_request_ownership *record =
          &shard->request_ownerships[request.slot - 1u];
      record->ownership = *ownership;
      record->generation = request.generation;
      record->active = 1;
    }
  }
  return status;
}

int native_io_sharded_context_submit(native_io_sharded_context *context,
                                     const native_io_sharded_operation *operation,
                                     native_io_sharded_request *out_request) {
  return native_io_sharded_context_admit(context, operation, NULL, out_request, false);
}

int native_io_sharded_context_submit_owned(native_io_sharded_context *context,
                                           const native_io_sharded_operation *operation,
                                           const native_io_sharded_ownership *ownership,
                                           native_io_sharded_request *out_request) {
  return native_io_sharded_context_admit(context, operation, ownership, out_request, false);
}

int native_io_sharded_context_prepare(native_io_sharded_context *context,
                                      const native_io_sharded_operation *operation,
                                      native_io_sharded_request *out_request) {
  return native_io_sharded_context_admit(context, operation, NULL, out_request, true);
}

int native_io_sharded_context_prepare_owned(native_io_sharded_context *context,
                                            const native_io_sharded_operation *operation,
                                            const native_io_sharded_ownership *ownership,
                                            native_io_sharded_request *out_request) {
  return native_io_sharded_context_admit(context, operation, ownership, out_request, true);
}

int native_io_sharded_context_flush(native_io_sharded_context *context) {
  native_io_sharded_shard *shard = native_io_sharded_context_owner(context);
  if (shard == NULL) return SALTS_EINVAL;
  if (atomic_load(&shard->draining)) return SALTS_ESHUTDOWN;
  return native_io_backend_flush(&shard->backend);
}

int native_io_sharded_context_cancel(native_io_sharded_context *context,
                                     native_io_sharded_request request) {
  native_io_sharded_shard *shard = NULL;
  int status = native_io_sharded_request_access(context, request, &shard);
  if (status != SALTS_OK) return status;
  return native_io_backend_cancel(&shard->backend, request.native_request);
}


static int native_io_sharded_host_validate(
    const native_io_sharded_shard *shard, native_io_sharded_host_lease lease) {
  if (shard == NULL || lease.version != NATIVE_IO_SHARDED_HOST_VERSION ||
      lease.owner_identity != shard->runtime->identity ||
      (size_t)lease.owner_shard != shard->index ||
      !shard->host_active || lease.generation != shard->host_generation)
    return SALTS_ENOENT;
  return SALTS_OK;
}

int native_io_sharded_context_acquire_host(
    native_io_sharded_context *context,
    native_io_sharded_host_quiescent_fn quiescent, void *user,
    native_io_sharded_host_lease *out_lease, native_io_backend **out_backend) {
  native_io_sharded_shard *shard = native_io_sharded_context_owner(context);
  if (out_lease != NULL) *out_lease = (native_io_sharded_host_lease){0};
  if (out_backend != NULL) *out_backend = NULL;
  if (shard == NULL || out_lease == NULL || out_backend == NULL ||
      quiescent == NULL) return SALTS_EINVAL;
  if (atomic_load(&shard->draining) || !atomic_load(&shard->runtime->accepting))
    return SALTS_ESHUTDOWN;
  if (shard->host_active || shard->observe_active || shard->host_verifying)
    return SALTS_EBUSY;
  if (shard->host_generation == UINT64_MAX) return SALTS_ERANGE;
  if (!atomic_load(&shard->backend_initialized)) return SALTS_ESHUTDOWN;
  ++shard->host_generation;
  shard->host_quiescent = quiescent;
  shard->host_user = user;
  shard->host_active = 1;
  *out_lease = (native_io_sharded_host_lease){
      shard->runtime->identity, (uint32_t)shard->index,
      NATIVE_IO_SHARDED_HOST_VERSION, shard->host_generation};
  *out_backend = &shard->backend;
  return SALTS_OK;
}

int native_io_sharded_context_release_host(
    native_io_sharded_context *context, native_io_sharded_host_lease lease) {
  native_io_sharded_shard *shard = native_io_sharded_context_owner(context);
  native_io_backend_stats stats = {0};
  size_t sg_owned;
  int status = native_io_sharded_host_validate(shard, lease);
  if (status != SALTS_OK) return status;
  if (shard->observe_active || shard->host_verifying) return SALTS_EBUSY;
  /* The quiescence predicate must not recursively release or observe this
   * backend; it is an assertion, not authority to bypass raw NativeIO stats. */
  shard->host_verifying = 1;
  const bool host_quiescent = shard->host_quiescent(shard->host_user);
  shard->host_verifying = 0;
  if (!host_quiescent) return SALTS_EBUSY;
  if (!native_io_backend_get_stats(&shard->backend, &stats)) return SALTS_EIO;
  sg_owned = native_io_sharded_owned_request_count(shard);
  if (stats.active_requests < sg_owned ||
      stats.endpoint_count < shard->owned_endpoint_count) return SALTS_EPROTO;
  if (stats.active_requests > sg_owned ||
      stats.endpoint_count > shard->owned_endpoint_count) return SALTS_EBUSY;
  shard->host_active = 0;
  shard->host_quiescent = NULL;
  shard->host_user = NULL;
  return SALTS_OK;
}

static int native_io_sharded_context_observe_impl(native_io_sharded_context *context,
                                      const native_io_sharded_host_lease *lease,
                                      native_io_sharded_completion *events,
                                      size_t event_capacity, uint32_t timeout_ms,
                                      size_t *out_count) {
  native_io_sharded_shard *shard = native_io_sharded_context_owner(context);
  size_t count = 0u;
  size_t limit;
  int status;
  if (out_count != NULL) *out_count = 0u;
  if (shard == NULL || events == NULL || event_capacity == 0u || out_count == NULL ||
      shard->completion_scratch == NULL || shard->completion_capacity == 0u)
    return SALTS_EINVAL;
  if (shard->observe_active || shard->host_verifying) return SALTS_EBUSY;
  if (shard->host_active) {
    if (lease == NULL || native_io_sharded_host_validate(shard, *lease) != SALTS_OK)
      return SALTS_EPERM;
  } else if (lease != NULL) {
    return SALTS_ENOENT;
  }
  shard->observe_active = 1;
  limit = event_capacity < shard->completion_capacity ? event_capacity : shard->completion_capacity;
  status = native_io_backend_observe(&shard->backend, shard->completion_scratch, limit,
                                     timeout_ms, &count);
  if (status != SALTS_OK) {
    shard->observe_active = 0;
    return status;
  }
  /*
   * Detach ownership for the complete dequeued batch before running any
   * terminal callback. Raw NativeIO may make every slot in this batch reusable
   * before observe returns, so a callback that immediately submits new work
   * must not overwrite an ownership record belonging to a later completion in
   * the same batch.
   */
  for (size_t index = 0u; index < count; ++index) {
    const native_io_completion *native_event = &shard->completion_scratch[index];
    native_io_sharded_completion *event = &events[index];
    native_io_sharded_ownership_settlement *settlement =
        &shard->ownership_settlements[index];
    memset(event, 0, sizeof(*event));
    memset(settlement, 0, sizeof(*settlement));
    event->request.owner_identity = shard->runtime->identity;
    event->request.owner_shard = (uint32_t)shard->index;
    event->request.native_request = native_event->request;
    event->endpoint.owner_identity = shard->runtime->identity;
    event->endpoint.owner_shard = (uint32_t)shard->index;
    event->endpoint.native_endpoint = native_event->endpoint;
    event->kind = native_event->kind;
    event->bytes = native_event->bytes;
    event->status = native_event->status;
    event->native_status = native_event->native_status;
    event->user_data = native_event->user_data;
    event->address_length = native_event->address_length;

    if (native_event->request.slot != 0u &&
        native_event->request.slot <= shard->request_ownership_capacity) {
      native_io_sharded_request_ownership *record =
          &shard->request_ownerships[native_event->request.slot - 1u];
      if (record->active && record->generation == native_event->request.generation) {
        settlement->ownership = record->ownership;
        settlement->active = 1;
        event->sharded_owned = true;
        memset(record, 0, sizeof(*record));
      }
    }
  }

  for (size_t index = 0u; index < count; ++index) {
    native_io_sharded_ownership_settlement *settlement =
        &shard->ownership_settlements[index];
    if (settlement->active) {
      native_io_sharded_ownership ownership = settlement->ownership;
      memset(settlement, 0, sizeof(*settlement));
      if (ownership.terminal != NULL) ownership.terminal(context, &events[index], ownership.arg);
      ownership.finalize(ownership.arg);
    }
  }
  shard->observe_active = 0;
  *out_count = count;
  return SALTS_OK;
}

int native_io_sharded_context_observe(native_io_sharded_context *context,
                                      native_io_sharded_completion *events,
                                      size_t event_capacity, uint32_t timeout_ms,
                                      size_t *out_count) {
  return native_io_sharded_context_observe_impl(
      context, NULL, events, event_capacity, timeout_ms, out_count);
}

int native_io_sharded_context_observe_host(
    native_io_sharded_context *context, native_io_sharded_host_lease lease,
    native_io_sharded_completion *events, size_t event_capacity,
    uint32_t timeout_ms, size_t *out_count) {
  return native_io_sharded_context_observe_impl(
      context, &lease, events, event_capacity, timeout_ms, out_count);
}

bool native_io_sharded_get_stats(const native_io_sharded *runtime,
                                 native_io_sharded_stats *out_stats) {
  native_io_sharded_stats stats = NATIVE_IO_SHARDED_STATS_V1_INITIALIZER;

  if (runtime == NULL || out_stats == NULL ||
      out_stats->abi_version != NATIVE_IO_SHARDED_STATS_ABI_V1 ||
      out_stats->struct_size != sizeof(*out_stats))
    return false;

  stats.shard_count = runtime->shard_count;
  stats.queue_capacity_per_shard = runtime->queue_capacity_per_shard;
  stats.command_slot_capacity_per_shard = runtime->command_slot_capacity_per_shard;
  stats.submitted_tasks = atomic_load(&runtime->submitted_tasks);
  stats.same_shard_direct_tasks = atomic_load(&runtime->same_shard_direct_tasks);
  stats.queued_dispatches = atomic_load(&runtime->queued_dispatches);
  stats.completed_tasks = atomic_load(&runtime->completed_tasks);
  stats.cancelled_tasks = atomic_load(&runtime->cancelled_tasks);
  stats.rejected_tasks = atomic_load(&runtime->rejected_tasks);
  stats.active_command_slots = atomic_load(&runtime->active_command_slots);
  stats.peak_command_slots = atomic_load(&runtime->peak_command_slots);
  stats.accepting = atomic_load(&runtime->accepting) != 0;
  *out_stats = stats;
  return true;
}
