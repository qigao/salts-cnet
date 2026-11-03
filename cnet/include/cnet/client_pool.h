#ifndef CNET_CLIENT_POOL_H
#define CNET_CLIENT_POOL_H

#include <cnet/manager.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNET_CLIENT_POOL_VERSION 1u

/* Owner-local physical connection + protocol-slot admission. Does not own a
 * thread, native backend, connection state machine, resolver, or retry loop.
 * A compatible protocol session must be fully READY before bind_ready().
 * No cross-owner reuse or silent wait/reconnect/replay is performed. */
typedef struct cnet_client_pool {
  void *impl;
} cnet_client_pool;

/* Stable host-assigned identities, never raw credential pointers or secrets.
 * All fields participate in exact compatibility. Optional fields may be zero,
 * but runtime, owner, endpoint, authority, transport and protocol must not. */
typedef struct cnet_pool_key {
  size_t size;
  uint32_t version;
  uint64_t runtime_id;
  uint64_t owner_id;
  uint64_t endpoint_id;
  uint64_t peer_generation;
  uint64_t authority_id;
  uint64_t transport_id;
  uint64_t tls_trust_id;
  uint64_t tls_sni_id;
  uint64_t client_identity_id;
  uint64_t alpn_id;
  uint64_t protocol_id;
  uint64_t session_id;
} cnet_pool_key;

/* Borrowed callback-local snapshot. Selection must not change Manager/CNet or
 * protocol state; only the core reserves a token after validating the choice. */
typedef struct cnet_pool_candidate {
  cnet_managed_connection managed;
  size_t leases;
  size_t capacity;
  bool eligible;
} cnet_pool_candidate;
typedef int (*cnet_pool_select_fn)(void *user, const cnet_pool_candidate *candidates,
                                   size_t count, uint64_t sequence, size_t *out_index);
typedef struct cnet_pool_selection_policy { cnet_pool_select_fn select; void *user; } cnet_pool_selection_policy;
/* Built-ins and custom callbacks share the same contract. Core filters exact
 * compatibility/READY first, then validates the returned eligible index and
 * reserves the real protocol token. Callbacks cannot mutate/reenter the pool. */
int cnet_pool_select_first(void *user, const cnet_pool_candidate *candidates,
                            size_t count, uint64_t sequence, size_t *out_index);
int cnet_pool_select_least_used(void *user, const cnet_pool_candidate *candidates,
                                 size_t count, uint64_t sequence, size_t *out_index);
int cnet_pool_select_round_robin(void *user, const cnet_pool_candidate *candidates,
                                  size_t count, uint64_t sequence, size_t *out_index);

typedef struct cnet_pool_config {
  size_t size;
  uint32_t version;
  cnet_manager *manager; /* Borrowed; must outlive the pool and every lease. */
  uint64_t owner_id;
  size_t max_connections;
  size_t max_connecting;
  size_t max_leases;
  cnet_allocator storage;
  cnet_pool_selection_policy selection;
} cnet_pool_config;

typedef struct cnet_pool_connection {
  uintptr_t pool;
  uint64_t incarnation;
  uint64_t generation;
  size_t slot; /* 1-based; zero is invalid. */
} cnet_pool_connection;

typedef struct cnet_pool_lease {
  uintptr_t pool;
  uint64_t incarnation;
  uint64_t generation;
  size_t slot; /* 1-based lease record, not physical connection slot. */
} cnet_pool_lease;

/* The protocol must reserve a *real* stream/operation slot; an advisory
 * can_reuse snapshot is not a capacity reservation. Both callbacks execute
 * inline on the pool Owner. user is borrowed until the lease is released.
 * The callback/user binding is copied before any selection/reserve callback
 * and kept for the whole acquire, including candidate retries. Updating the
 * host's original binding during reserve affects subsequent acquires only.
 * release must settle the admitted token exactly once and must not reenter
 * the pool; cancellation/transport terminal does not implicitly release it. */
typedef struct cnet_pool_protocol_ops {
  int (*reserve)(void *user, cnet_managed_connection managed, uint64_t *out_token);
  void (*release)(void *user, uint64_t token);
  void *user;
} cnet_pool_protocol_ops;

typedef struct cnet_pool_snapshot {
  size_t max_connections;
  size_t max_connecting;
  size_t max_leases;
  size_t connecting;
  size_t ready;
  size_t draining;
  size_t terminal_waiting_for_leases;
  size_t physical_in_use;
  size_t active_leases;
  bool sealed;
  bool drained;
} cnet_pool_snapshot;

/* Allocates all physical and lease records up front. All later calls are
 * owner-thread only, including callbacks; foreign owner returns EPERM.
 * Pool helper budgets are separate from authoritative Manager/CNet credits. */
int cnet_pool_init(cnet_client_pool *pool, const cnet_pool_config *config);

/* Reserves one connecting/physical budget token. Caller must subsequently
 * cnet_manager_reserve/connect on the same Owner, then bind_ready or terminal.
 * No socket is opened here. The key is copied and cannot change in place. */
int cnet_pool_reserve_connecting(cnet_client_pool *pool, const cnet_pool_key *key,
                                 cnet_pool_connection *out_connection);

/* Caller asserts an actual Manager BOUND connection is protocol READY. Pool
 * validates Manager identity and refuses duplicate bindings. For multiplexed
 * capacity >1, every acquire must supply protocol reserve/release callbacks. */
int cnet_pool_bind_ready(cnet_client_pool *pool, cnet_pool_connection connection,
                         cnet_managed_connection managed, size_t protocol_capacity);

/* No queue and no implicit dial. On success reserve a unique generation-safe
 * lease and, when supplied, an authoritative protocol slot. Returns ENOBUFS
 * when no ready compatible slot has both physical and protocol capacity.
 * Manager identity is rechecked at admission: an asynchronously RETIRED or
 * recycled physical connection is marked draining, never leased again. */
int cnet_pool_try_acquire(cnet_client_pool *pool, const cnet_pool_key *key,
                          const cnet_pool_protocol_ops *protocol,
                          cnet_pool_lease *out_lease,
                          cnet_managed_connection *out_managed);
/* Copied on the owner outside callbacks; takes effect on the next acquire.
 * Existing leases keep their original protocol release authority. The old
 * selection user can be released after replacement returns. */
int cnet_pool_set_selection(cnet_client_pool *pool, const cnet_pool_selection_policy *policy);
int cnet_pool_release(cnet_client_pool *pool, cnet_pool_lease lease);

/* Disable future acquisition (including when currently leased), but neither
 * close the transport nor free borrowed protocol storage. Caller closes via
 * CNet/Manager and calls terminal on the real terminal callback.
 * READY entries cannot be declared terminal while Manager is still BOUND:
 * terminal returns EBUSY and leaves the physical record unchanged. A
 * CONNECTING entry with no binding can be aborted, but the caller must first
 * cancel any separately admitted Manager reservation. */
int cnet_pool_begin_drain(cnet_client_pool *pool, cnet_pool_connection connection);
int cnet_pool_terminal(cnet_client_pool *pool, cnet_pool_connection connection);

/* Stops new reservations/acquisitions and marks all live entries draining.
 * Manager close/terminal and outstanding lease release remain caller duties. */
int cnet_pool_seal(cnet_client_pool *pool);
int cnet_pool_get_snapshot(cnet_client_pool *pool, cnet_pool_snapshot *out);
int cnet_pool_destroy(cnet_client_pool *pool); /* EBUSY until fully drained. */

#ifdef __cplusplus
}
#endif
#endif
