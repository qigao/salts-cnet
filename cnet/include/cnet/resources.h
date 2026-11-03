#ifndef CNET_RESOURCES_H
#define CNET_RESOURCES_H

#include <cmeta_buffer.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Value bindings copied at initialization. Callbacks must not block or reenter
 * their CNet owner. Storage is max_align_t aligned; free receives exactly the
 * pointer and size returned to allocate. Both callbacks are required together.
 * The provider and user must outlive all of their allocations. A zero binding
 * explicitly selects the system allocator. No fallback after provider failure. */
typedef struct cnet_allocator {
  void *(*allocate)(void *user, size_t bytes);
  void (*deallocate)(void *user, void *storage, size_t bytes);
  void *user;
} cnet_allocator;

/* Returns one owned canonical buffer, with refcount 1 and capacity >= bytes.
 * Each returned buffer must independently keep its storage and final-release
 * authority alive, including after client destruction and on the consumer's
 * release thread. A borrowed arena/pool without that lifetime is not valid.
 * Failure must leave *out NULL. Zero binding uses the shared Core buffer pool.
 * This is a receive-payload provider, not a TLS/NativeIO allocator override. */
typedef struct cnet_buffer_provider {
  int (*acquire)(void *user, size_t bytes, mem_buffer_t **out);
  void *user;
} cnet_buffer_provider;

typedef struct cnet_resources {
  cnet_allocator storage;
  cnet_buffer_provider receive;
} cnet_resources;

/* Zero operation/byte limits derive from bounded write capacity/max send size.
 * Zero backing limits select SIZE_MAX; configure them for physical-retention
 * isolation. Connection limits default to the corresponding aggregate limit.
 * backing_bytes counts full backing capacity once per distinct buffer in EACH
 * operation: conservative retention accounting, not process RSS. */
typedef struct cnet_send_limits {
  size_t operations;
  size_t bytes;
  size_t backing_bytes;
  size_t connection_operations;
  size_t connection_bytes;
  size_t connection_backing_bytes;
} cnet_send_limits;

typedef struct cnet_send_usage {
  size_t operations;
  size_t bytes;
  size_t backing_bytes;
} cnet_send_usage;

typedef enum cnet_admission_limit {
  CNET_LIMIT_NONE = 0,
  CNET_LIMIT_OPERATIONS,
  CNET_LIMIT_BYTES,
  CNET_LIMIT_BACKING_BYTES,
  CNET_LIMIT_CONNECTION_OPERATIONS,
  CNET_LIMIT_CONNECTION_BYTES,
  CNET_LIMIT_CONNECTION_BACKING_BYTES,
  CNET_LIMIT_POLICY,
  CNET_LIMIT_CONNECTION_POLICY
} cnet_admission_limit;

/* Pure extra admission gate. Hard limits are enforced before this callback;
 * returning OK cannot override them. No ownership transfers to this callback.
 * Configuration is copied; user is borrowed until replacement or destruction
 * (connection binding: until replacement or connection terminal notification).
 * Usage pointers are callback-local views and must not be retained. */
typedef struct cnet_send_admission_policy {
  int (*evaluate)(void *user, const cnet_send_usage *total,
                  const cnet_send_usage *connection,
                  size_t bytes, size_t backing_bytes);
  void *user;
} cnet_send_admission_policy;

bool cnet_allocator_valid(const cnet_allocator *allocator);
bool cnet_resources_valid(const cnet_resources *resources);
int cnet_buffer_acquire(const cnet_buffer_provider *provider, size_t bytes,
                         mem_buffer_t **out);

#ifdef __cplusplus
}
#endif
#endif
