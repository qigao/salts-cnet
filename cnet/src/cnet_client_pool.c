#include <cnet/client_pool.h>
#include "cnet_resources.h"
#include <thread.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef enum pool_state { POOL_FREE = 0, POOL_CONNECTING, POOL_READY, POOL_TERMINAL } pool_state;
typedef struct pool_physical {
  cnet_pool_key key;
  cnet_managed_connection managed;
  uint64_t generation;
  size_t protocol_capacity;
  size_t leases;
  pool_state state;
  bool draining;
} pool_physical;
typedef struct pool_lease_record {
  cnet_pool_protocol_ops protocol;
  uint64_t generation, token, physical_generation;
  size_t physical_index;
  bool active;
} pool_lease_record;
typedef struct pool_impl {
  cnet_manager *manager;
  const void *thread;
  cnet_pool_selection_policy selection;
  cnet_pool_candidate *candidates;
  uint64_t sequence;
  pool_physical *physical;
  pool_lease_record *leases;
  size_t max_physical, max_connecting, max_leases;
  size_t in_use, connecting, active_leases;
  uint64_t owner_id, incarnation;
  bool sealed, in_callback;
} pool_impl;

static atomic_uint_fast64_t pool_incarnation_source;

static int pool_owner(cnet_client_pool *pool, pool_impl **out) {
  if (out != NULL) *out = NULL;
  if (pool == NULL || pool->impl == NULL || out == NULL) return SALTS_EINVAL;
  *out = (pool_impl *)pool->impl;
  if ((*out)->thread != cmeta_thread_current_token()) return SALTS_EPERM;
  return (*out)->in_callback ? SALTS_EBUSY : SALTS_OK;
}
static bool key_valid(const cnet_pool_key *key) {
  return key != NULL && key->size == sizeof(*key) &&
         key->version == CNET_CLIENT_POOL_VERSION &&
         key->runtime_id != 0u && key->owner_id != 0u &&
         key->endpoint_id != 0u && key->authority_id != 0u &&
         key->transport_id != 0u && key->protocol_id != 0u;
}
static bool key_equal(const cnet_pool_key *a, const cnet_pool_key *b) {
  return a->runtime_id == b->runtime_id && a->owner_id == b->owner_id &&
         a->endpoint_id == b->endpoint_id && a->peer_generation == b->peer_generation &&
         a->authority_id == b->authority_id && a->transport_id == b->transport_id &&
         a->tls_trust_id == b->tls_trust_id && a->tls_sni_id == b->tls_sni_id &&
         a->client_identity_id == b->client_identity_id && a->alpn_id == b->alpn_id &&
         a->protocol_id == b->protocol_id && a->session_id == b->session_id;
}
static bool managed_equal(cnet_managed_connection a, cnet_managed_connection b) {
  return a.manager == b.manager && a.incarnation == b.incarnation &&
         a.generation == b.generation && a.slot == b.slot;
}
static int get_physical(cnet_client_pool *pool, cnet_pool_connection identity,
                        pool_impl **impl, pool_physical **physical) {
  int status = pool_owner(pool, impl);
  if (physical != NULL) *physical = NULL;
  if (status != SALTS_OK) return status;
  if (physical == NULL || identity.pool != (uintptr_t)pool ||
      identity.incarnation != (*impl)->incarnation ||
      identity.slot == 0u || identity.slot > (*impl)->max_physical)
    return SALTS_ENOENT;
  *physical = &(*impl)->physical[identity.slot - 1u];
  return (*physical)->state != POOL_FREE && identity.generation == (*physical)->generation
             ? SALTS_OK : SALTS_ENOENT;
}
static void reclaim(pool_impl *impl, pool_physical *slot) {
  /* Never reuse an identity while an accepted protocol lease remains. */
  if (slot->state != POOL_TERMINAL || slot->leases != 0u) return;
  --impl->in_use;
  slot->state = POOL_FREE;
  slot->draining = false;
  slot->protocol_capacity = 0u;
  slot->managed = (cnet_managed_connection){0};
  memset(&slot->key, 0, sizeof(slot->key));
}

int cnet_pool_init(cnet_client_pool *pool, const cnet_pool_config *config) {
  pool_impl *impl;
  cnet_manager_snapshot manager_snapshot;
  uint_fast64_t incarnation;
  if (pool == NULL || config == NULL || pool->impl != NULL ||
      !cnet_allocator_valid(&config->storage) || config->size != sizeof(*config) || config->version != CNET_CLIENT_POOL_VERSION ||
      config->manager == NULL || config->owner_id == 0u ||
      (config->selection.select == NULL && config->selection.user != NULL) ||
      config->max_connections == 0u || config->max_connecting == 0u ||
      config->max_connecting > config->max_connections || config->max_leases == 0u)
    return SALTS_EINVAL;
  if (config->max_connections > SIZE_MAX / sizeof(pool_physical) ||
      config->max_leases > SIZE_MAX / sizeof(pool_lease_record)) return SALTS_ERANGE;
  if (cnet_manager_get_snapshot(config->manager, &manager_snapshot) != SALTS_OK ||
      manager_snapshot.sealed || config->max_connections > manager_snapshot.connection_capacity)
    return SALTS_EINVAL;
  impl = (pool_impl *)cnet_storage_alloc(&config->storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->physical = (pool_physical *)cnet_storage_alloc(&config->storage, config->max_connections, sizeof(*impl->physical));
  impl->leases = (pool_lease_record *)cnet_storage_alloc(&config->storage, config->max_leases, sizeof(*impl->leases));
  impl->selection = config->selection;
  impl->candidates = cnet_storage_alloc(&config->storage, config->max_connections, sizeof(*impl->candidates));
  if (impl->physical == NULL || impl->leases == NULL || impl->candidates == NULL) {
    cnet_storage_free(impl->physical); cnet_storage_free(impl->leases); cnet_storage_free(impl->candidates); cnet_storage_free(impl);
    return SALTS_ENOMEM;
  }
  incarnation = atomic_load_explicit(&pool_incarnation_source, memory_order_relaxed);
  do {
    if (incarnation == UINT64_MAX) {
      cnet_storage_free(impl->physical); cnet_storage_free(impl->leases); cnet_storage_free(impl->candidates); cnet_storage_free(impl);
      return SALTS_ERANGE;
    }
  } while (!atomic_compare_exchange_weak_explicit(
      &pool_incarnation_source, &incarnation, incarnation + 1u,
      memory_order_relaxed, memory_order_relaxed));
  impl->manager = config->manager;
  impl->thread = cmeta_thread_current_token();
  impl->incarnation = (uint64_t)(incarnation + 1u);
  impl->owner_id = config->owner_id;
  impl->max_physical = config->max_connections;
  impl->max_connecting = config->max_connecting;
  impl->max_leases = config->max_leases;
  pool->impl = impl;
  return SALTS_OK;
}

int cnet_pool_reserve_connecting(cnet_client_pool *pool, const cnet_pool_key *key,
                                 cnet_pool_connection *out) {
  pool_impl *impl;
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_pool_connection){0};
  status = pool_owner(pool, &impl);
  if (status != SALTS_OK) return status;
  if (!key_valid(key) || key->owner_id != impl->owner_id) return SALTS_EINVAL;
  if (impl->sealed) return SALTS_ESHUTDOWN;
  if (impl->in_use >= impl->max_physical || impl->connecting >= impl->max_connecting)
    return SALTS_ENOBUFS;
  for (size_t i = 0u; i < impl->max_physical; ++i) {
    pool_physical *entry = &impl->physical[i];
    if (entry->state != POOL_FREE) continue;
    if (entry->generation == UINT64_MAX) return SALTS_ERANGE;
    ++entry->generation;
    entry->key = *key;
    entry->state = POOL_CONNECTING;
    ++impl->in_use;
    ++impl->connecting;
    *out = (cnet_pool_connection){(uintptr_t)pool, impl->incarnation,
                                  entry->generation, i + 1u};
    return SALTS_OK;
  }
  return SALTS_ENOBUFS;
}

int cnet_pool_bind_ready(cnet_client_pool *pool, cnet_pool_connection connection,
                         cnet_managed_connection managed, size_t capacity) {
  pool_impl *impl;
  pool_physical *entry;
  cnet_manager_entry manager_entry;
  int status = get_physical(pool, connection, &impl, &entry);
  if (status != SALTS_OK) return status;
  if (entry->state != POOL_CONNECTING) return SALTS_EALREADY;
  if (entry->draining || impl->sealed) return SALTS_ESHUTDOWN;
  if (capacity == 0u || capacity > impl->max_leases || managed.slot == 0u)
    return SALTS_EINVAL;
  status = cnet_manager_lookup(impl->manager, managed, &manager_entry);
  if (status != SALTS_OK) return status;
  if (manager_entry.state != CNET_MANAGER_BOUND) return SALTS_EBUSY;
  for (size_t i = 0u; i < impl->max_physical; ++i) {
    pool_physical *other = &impl->physical[i];
    if (other != entry && other->state != POOL_FREE && other->state != POOL_TERMINAL &&
        managed_equal(other->managed, managed)) return SALTS_EALREADY;
  }
  entry->managed = managed;
  entry->protocol_capacity = capacity;
  entry->state = POOL_READY;
  --impl->connecting;
  return SALTS_OK;
}

int cnet_pool_select_first(void *user, const cnet_pool_candidate *c, size_t n,
                            uint64_t sequence, size_t *out) {
  (void)user; (void)sequence;
  if (out == NULL || c == NULL || n == 0u) return SALTS_EINVAL;
  *out = SIZE_MAX;
  for (size_t i = 0; i < n; ++i) if (c[i].eligible) { *out = i; return SALTS_OK; }
  return SALTS_ENOBUFS;
}
int cnet_pool_select_round_robin(void *user, const cnet_pool_candidate *c, size_t n,
                                  uint64_t sequence, size_t *out) {
  (void)user;
  if (out == NULL || c == NULL || n == 0u) return SALTS_EINVAL;
  *out = SIZE_MAX;
  for (size_t j = 0, i = (size_t)(sequence % n); j < n; ++j, i = i + 1u == n ? 0u : i + 1u)
    if (c[i].eligible) { *out = i; return SALTS_OK; }
  return SALTS_ENOBUFS;
}
int cnet_pool_select_least_used(void *user, const cnet_pool_candidate *c, size_t n,
                                 uint64_t sequence, size_t *out) {
  int status = cnet_pool_select_round_robin(user, c, n, sequence, out);
  if (status != SALTS_OK) return status;
  for (size_t i = 0; i < n; ++i)
    if (c[i].eligible && c[i].leases < c[*out].leases) *out = i;
  return SALTS_OK;
}
int cnet_pool_set_selection(cnet_client_pool *pool, const cnet_pool_selection_policy *policy) {
  pool_impl *impl;
  int status = pool_owner(pool, &impl);
  if (status != SALTS_OK) return status;
  if (policy == NULL || (policy->select == NULL && policy->user != NULL)) return SALTS_EINVAL;
  if (impl->sealed) return SALTS_ESHUTDOWN;
  impl->selection = *policy;
  return SALTS_OK;
}

int cnet_pool_try_acquire(cnet_client_pool *pool, const cnet_pool_key *key,
                          const cnet_pool_protocol_ops *protocol,
                          cnet_pool_lease *out_lease, cnet_managed_connection *out_managed) {
  pool_impl *impl;
  size_t free_lease = SIZE_MAX;
  int status;
  if (out_lease == NULL || out_managed == NULL) return SALTS_EINVAL;
  *out_lease = (cnet_pool_lease){0};
  *out_managed = (cnet_managed_connection){0};
  status = pool_owner(pool, &impl);
  if (status != SALTS_OK) return status;
  if (!key_valid(key) || key->owner_id != impl->owner_id ||
      (protocol != NULL && (protocol->reserve == NULL || protocol->release == NULL)))
    return SALTS_EINVAL;
  if (impl->sealed) return SALTS_ESHUTDOWN;
  if (impl->active_leases >= impl->max_leases) return SALTS_ENOBUFS;
  for (size_t i = 0u; i < impl->max_leases; ++i) {
    if (!impl->leases[i].active && impl->leases[i].generation != UINT64_MAX) {
      free_lease = i;
      break;
    }
  }
  if (free_lease == SIZE_MAX) return SALTS_ENOBUFS;
  for (size_t i = 0u; i < impl->max_physical; ++i) {
    pool_physical *entry = &impl->physical[i];
    cnet_pool_candidate *candidate = &impl->candidates[i];
    *candidate = (cnet_pool_candidate){.managed = entry->managed,
        .leases = entry->leases, .capacity = entry->protocol_capacity};
    if (entry->state != POOL_READY || entry->draining || !key_equal(&entry->key, key) ||
        entry->leases >= entry->protocol_capacity) continue;
    cnet_manager_entry managed_entry = {0};
    status = cnet_manager_lookup(impl->manager, entry->managed, &managed_entry);
    if (status == SALTS_ENOENT || (status == SALTS_OK && managed_entry.state != CNET_MANAGER_BOUND)) {
      entry->draining = true; continue;
    }
    if (status != SALTS_OK) return status;
    candidate->eligible = true;
  }
  const uint64_t sequence = impl->sequence++;
  for (size_t attempt = 0u; attempt < impl->max_physical; ++attempt) {
    size_t i = SIZE_MAX;
    cnet_pool_select_fn select = impl->selection.select != NULL
        ? impl->selection.select : cnet_pool_select_first;
    impl->in_callback = true;
    status = select(impl->selection.user, impl->candidates, impl->max_physical, sequence, &i);
    impl->in_callback = false;
    if (status != SALTS_OK) return status;
    if (i >= impl->max_physical || !impl->candidates[i].eligible) return SALTS_EINVAL;
    impl->candidates[i].eligible = false;
    pool_physical *entry = &impl->physical[i];
    pool_lease_record *lease;
    uint64_t token = 0u;
    if (entry->protocol_capacity != 1u && protocol == NULL) return SALTS_ENOTSUP;
    if (protocol != NULL) {
      impl->in_callback = true;
      status = protocol->reserve(protocol->user, entry->managed, &token);
      impl->in_callback = false;
      if (status == SALTS_ENOBUFS) continue;
      if (status != SALTS_OK) return status;
    }
    lease = &impl->leases[free_lease];
    ++lease->generation;
    lease->active = true;
    lease->token = token;
    lease->physical_index = i;
    lease->physical_generation = entry->generation;
    lease->protocol = protocol != NULL ? *protocol : (cnet_pool_protocol_ops){0};
    ++entry->leases;
    ++impl->active_leases;
    *out_lease = (cnet_pool_lease){(uintptr_t)pool, impl->incarnation,
                                   lease->generation, free_lease + 1u};
    *out_managed = entry->managed;
    return SALTS_OK;
  }
  return SALTS_ENOBUFS;
}

int cnet_pool_release(cnet_client_pool *pool, cnet_pool_lease identity) {
  pool_impl *impl;
  pool_lease_record *lease;
  pool_physical *entry;
  int status = pool_owner(pool, &impl);
  if (status != SALTS_OK) return status;
  if (identity.pool != (uintptr_t)pool || identity.incarnation != impl->incarnation ||
      identity.slot == 0u || identity.slot > impl->max_leases) return SALTS_ENOENT;
  lease = &impl->leases[identity.slot - 1u];
  if (!lease->active || lease->generation != identity.generation)
    return SALTS_ENOENT;
  entry = &impl->physical[lease->physical_index];
  if (entry->generation != lease->physical_generation || entry->leases == 0u)
    return SALTS_EPROTO;
  if (lease->protocol.release != NULL) {
    impl->in_callback = true;
    lease->protocol.release(lease->protocol.user, lease->token);
    impl->in_callback = false;
  }
  --entry->leases;
  --impl->active_leases;
  lease->active = false;
  lease->protocol = (cnet_pool_protocol_ops){0};
  if (entry->state == POOL_TERMINAL) reclaim(impl, entry);
  return SALTS_OK;
}
int cnet_pool_begin_drain(cnet_client_pool *pool, cnet_pool_connection identity) {
  pool_impl *impl;
  pool_physical *entry;
  int status = get_physical(pool, identity, &impl, &entry);
  if (status != SALTS_OK) return status;
  if (entry->state == POOL_TERMINAL) return SALTS_EALREADY;
  entry->draining = true;
  return SALTS_OK;
}
int cnet_pool_terminal(cnet_client_pool *pool, cnet_pool_connection identity) {
  pool_impl *impl;
  pool_physical *entry;
  int status = get_physical(pool, identity, &impl, &entry);
  if (status != SALTS_OK) return status;
  if (entry->state == POOL_TERMINAL) return SALTS_EALREADY;
  if (entry->state == POOL_READY) {
    cnet_manager_entry managed_entry = {0};
    status = cnet_manager_lookup(impl->manager, entry->managed, &managed_entry);
    if (status != SALTS_OK && status != SALTS_ENOENT) return status;
    /* The Manager is the authoritative physical transport owner. A pool
     * caller cannot free its capacity merely by declaring a live connection
     * terminal; only Manager RETIRED (or recycled generation) is accepted. */
    if (status == SALTS_OK && managed_entry.state != CNET_MANAGER_RETIRED)
      return SALTS_EBUSY;
  }
  if (entry->state == POOL_CONNECTING) --impl->connecting;
  entry->state = POOL_TERMINAL;
  entry->draining = true;
  reclaim(impl, entry);
  return SALTS_OK;
}
int cnet_pool_seal(cnet_client_pool *pool) {
  pool_impl *impl;
  int status = pool_owner(pool, &impl);
  if (status != SALTS_OK) return status;
  impl->sealed = true;
  for (size_t i = 0u; i < impl->max_physical; ++i)
    if (impl->physical[i].state != POOL_FREE) impl->physical[i].draining = true;
  return SALTS_OK;
}
int cnet_pool_get_snapshot(cnet_client_pool *pool, cnet_pool_snapshot *out) {
  pool_impl *impl;
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_pool_snapshot){0};
  status = pool_owner(pool, &impl);
  if (status != SALTS_OK) return status;
  out->max_connections = impl->max_physical;
  out->max_connecting = impl->max_connecting;
  out->max_leases = impl->max_leases;
  out->connecting = impl->connecting;
  out->physical_in_use = impl->in_use;
  out->active_leases = impl->active_leases;
  out->sealed = impl->sealed;
  for (size_t i = 0u; i < impl->max_physical; ++i) {
    pool_physical *entry = &impl->physical[i];
    if (entry->state == POOL_READY) {
      if (entry->draining) ++out->draining;
      else ++out->ready;
    } else if (entry->state == POOL_TERMINAL) {
      ++out->terminal_waiting_for_leases;
    } else if (entry->state == POOL_CONNECTING && entry->draining) {
      ++out->draining;
    }
  }
  out->drained = impl->in_use == 0u && impl->active_leases == 0u;
  return SALTS_OK;
}
int cnet_pool_destroy(cnet_client_pool *pool) {
  pool_impl *impl;
  int status = pool_owner(pool, &impl);
  if (status != SALTS_OK) return status;
  if (impl->in_use != 0u || impl->active_leases != 0u) return SALTS_EBUSY;
  cnet_storage_free(impl->physical);
  cnet_storage_free(impl->leases);
  cnet_storage_free(impl->candidates); cnet_storage_free(impl);
  pool->impl = NULL;
  return SALTS_OK;
}
