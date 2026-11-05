#ifndef CNET_DISPATCHER_H
#define CNET_DISPATCHER_H
#include <cnet/resources.h>

#include "cnet_shards.h"

/**
 * @internal Client-owned single-owner bridge from shard events to inline callbacks.
 * Registration, publish, recycle, drain and profiling are serialized by the
 * CNet owner contract; the dispatcher therefore owns no mutex or worker thread.
 */
typedef struct cnet_dispatcher {
  void *impl;
} cnet_dispatcher;

typedef struct cnet_dispatch_view {
  cnet_event_kind kind;
  cnet_session_handle session;
  cnet_event_state state;
  int status;
  cnet_session_stage stage;
  const void *data;
  size_t size;
  size_t argument;
  mem_buffer_t *backing;
  crypto_tls_diagnostic tls;
} cnet_dispatch_view;

typedef void (*cnet_dispatch_fn)(void *context, const cnet_dispatch_view *view);

int cnet_dispatcher_init(cnet_dispatcher *dispatcher, cnet_shards *shards);
int cnet_dispatcher_init_with_storage(cnet_dispatcher *dispatcher, cnet_shards *shards, const cnet_allocator *storage);

/** Registers immutable callback ownership for one generation-checked connection. */
int cnet_dispatcher_register(cnet_dispatcher *dispatcher, cnet_shard_connection connection,
                             cnet_dispatch_fn observer, void *observer_context);

/** Invokes one callback synchronously on the publishing NativeIO owner. */
int cnet_dispatcher_publish(cnet_dispatcher *dispatcher, uint32_t shard, const cnet_event *event);

/**
 * Single-consumer, nonblocking drive for one fallback event queue. The callback
 * completes before the retained event lease is released.
 */
int cnet_dispatcher_drive(cnet_dispatcher *dispatcher, uint32_t shard);

/**
 * Drives events until every registered connection has completed and recycled.
 * This control-plane wait must not run from an inline callback.
 */
int cnet_dispatcher_wait_idle(cnet_dispatcher *dispatcher, uint32_t timeout_ms);

/**
 * Closes admission and live connections, then drives all terminal callbacks.
 * Retry after SALTS_ETIMEDOUT; do not call from an inline callback.
 */
int cnet_dispatcher_drain(cnet_dispatcher *dispatcher, uint32_t timeout_ms);
bool cnet_dispatcher_drained(const cnet_dispatcher *dispatcher);

#if defined(CNET_INTERNAL_PROFILING)
typedef struct cnet_dispatcher_profile {
  uint64_t prepare_ns;
  uint64_t prepare_calls;
  uint64_t invoke_ns;
  uint64_t invoke_calls;
  uint64_t observer_ns;
  uint64_t observer_calls;
  uint64_t release_ns;
  uint64_t release_calls;
} cnet_dispatcher_profile;

int cnet_dispatcher_profile_begin(cnet_dispatcher *dispatcher);
int cnet_dispatcher_profile_take(cnet_dispatcher *dispatcher,
                                 cnet_dispatcher_profile *out_profile);
#endif

/** Requires a completed drain and no retained event lease. */
int cnet_dispatcher_destroy(cnet_dispatcher *dispatcher);

#endif /* CNET_DISPATCHER_H */
