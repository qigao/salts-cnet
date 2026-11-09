#include "cnet_resolver.h"

#include "cnet_module.h"

#include <ares.h>
#include <cnet/name_lookup.h>
#include <core/clock.h>
#include <stdatomic.h>
#include <threads/threads.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
  #include <winsock2.h>
typedef WSAPOLLFD cnet_resolver_pollfd;
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <sys/socket.h>
typedef struct pollfd cnet_resolver_pollfd;
#endif

typedef enum cnet_resolver_slot_state {
  CNET_RESOLVER_SLOT_FREE = 0,
  CNET_RESOLVER_SLOT_ACTIVE,
  CNET_RESOLVER_SLOT_READY,
  CNET_RESOLVER_SLOT_RETIRED
} cnet_resolver_slot_state;

struct cnet_resolver_impl;

typedef struct cnet_resolver_slot {
  struct cnet_resolver_impl *owner;
  cnet_resolver_slot_state state;
  uint32_t generation;
  uintptr_t user_data;
  int socket_type;
  /* Connection caller's authoritative host-order port. c-ares is only
   * responsible for resolving the address, never selecting the port. */
  uint16_t requested_port;
  bool cancelled;
  bool dropped;
  bool expired;
  uint64_t deadline;
  size_t address_count, address_index;
  cnet_ip_address *addresses;
  char host[CNET_RESOLVER_HOST_CAPACITY];
  char service[6];
  cnet_resolver_result result;
} cnet_resolver_slot;

typedef struct cnet_resolver_socket {
  ares_socket_t descriptor;
  unsigned int events;
} cnet_resolver_socket;

typedef struct cnet_resolver_impl {
  ares_channel_t *channel;
  cnet_resolver_slot *slots;
  uint32_t *free_slots;
  uint32_t *ready_slots;
  cnet_resolver_socket *sockets;
  cnet_resolver_pollfd *poll_fds;
  ares_fd_events_t *ready_events;
  size_t capacity;
  size_t socket_capacity;
  size_t socket_count;
  size_t free_count;
  size_t ready_head;
  size_t ready_count;
  size_t active_count;
  bool admission_open;
  sync_mutex_t control_lock;
  sync_mutex_t state_lock;
  bool socket_overflow;
  uint64_t lookup_identity;
  size_t result_capacity, name_capacity;
  uint32_t lookup_timeout;
  cnet_ip_address *lookup_storage;
} cnet_resolver_impl;

static cnet_resolver_impl *cnet_resolver_get_impl(cnet_resolver *resolver) {
  return resolver != NULL ? (cnet_resolver_impl *)resolver->impl : NULL;
}

static int cnet_resolver_map_status(int status) {
  switch (status) {
  case ARES_SUCCESS:
    return SALTS_OK;
  case ARES_ENODATA:
    return SALTS_EAI_NODATA;
  case ARES_ENOTFOUND:
  case ARES_ENONAME:
    return SALTS_EAI_NONAME;
  case ARES_ETIMEOUT:
  case ARES_ESERVFAIL:
    return SALTS_EAI_AGAIN;
  case ARES_EBADFAMILY:
    return SALTS_EAI_FAMILY;
  case ARES_ESERVICE:
    return SALTS_EAI_SERVICE;
  case ARES_ENOMEM:
    return SALTS_EAI_MEMORY;
  case ARES_ECANCELLED:
  case ARES_EDESTRUCTION:
    return SALTS_EAI_CANCELED;
  default:
    return SALTS_EAI_FAIL;
  }
}

/*
 * CNet owns its requested transport port. c-ares may deliver a sockaddr
 * whose sin_port/sin6_port is in host byte order (Windows numeric-host first
 * RED: requested 0xC605 / 50693; received 0x05C6 / 1478). Never carry
 * a provider's service-port bytes through to ConnectEx or TLS transport.
 *
 * Patch only the well-defined family-specific field with htons(port).
 * Byte copy avoids misaligned sockaddr aliases in the result byte array.
 * This is one canonical endpoint, not a retry or alternate DNS provider.
 */
static int cnet_resolver_apply_requested_port(void *address, size_t address_length,
                                               int family, uint16_t port) {
  size_t offset;
  const uint16_t network_port = htons(port);
  if (address == NULL || port == 0u) return SALTS_EINVAL;
  if (family == AF_INET) {
    if (address_length < sizeof(struct sockaddr_in)) return SALTS_EINVAL;
    offset = offsetof(struct sockaddr_in, sin_port);
  } else if (family == AF_INET6) {
    if (address_length < sizeof(struct sockaddr_in6)) return SALTS_EINVAL;
    offset = offsetof(struct sockaddr_in6, sin6_port);
  } else {
    return SALTS_EAI_FAMILY;
  }
  memcpy((unsigned char *)address + offset, &network_port, sizeof(network_port));
  return SALTS_OK;
}

#if defined(CNET_INTERNAL_TESTING)
/* Test binary only, absent from the installed CNet ABI. */
int cnet_resolver_test_apply_requested_port(void *address, size_t address_length,
                                            int family, uint16_t port) {
  return cnet_resolver_apply_requested_port(address, address_length, family, port);
}
#endif

static cnet_resolver_slot *cnet_resolver_find_slot(cnet_resolver_impl *impl,
                                                   cnet_resolver_query query) {
  cnet_resolver_slot *slot;

  if (!cnet_resolver_query_valid(query) || (size_t)query.slot > impl->capacity) return NULL;
  slot = &impl->slots[query.slot - 1u];
  if (slot->state == CNET_RESOLVER_SLOT_FREE || slot->state == CNET_RESOLVER_SLOT_RETIRED ||
      slot->generation != query.generation)
    return NULL;
  return slot;
}

static void cnet_resolver_socket_state(void *context, ares_socket_t descriptor, int readable,
                                       int writable) {
  cnet_resolver_impl *impl = (cnet_resolver_impl *)context;
  const unsigned int events =
      (readable ? ARES_FD_EVENT_READ : 0u) | (writable ? ARES_FD_EVENT_WRITE : 0u);
  size_t index;
  for (index = 0u; index < impl->socket_count; ++index)
    if (impl->sockets[index].descriptor == descriptor) break;
  if (events == 0u) {
    if (index < impl->socket_count) {
      --impl->socket_count;
      if (index != impl->socket_count) impl->sockets[index] = impl->sockets[impl->socket_count];
    }
    return;
  }
  if (index < impl->socket_count) {
    impl->sockets[index].events = events;
    return;
  }
  if (impl->socket_count == impl->socket_capacity) {
    impl->socket_overflow = true;
    return;
  }
  impl->sockets[impl->socket_count++] = (cnet_resolver_socket){descriptor, events};
}

static void cnet_resolver_callback(void *argument, int status, int timeouts,
                                   struct ares_addrinfo *addresses) {
  cnet_resolver_slot *slot = (cnet_resolver_slot *)argument;
  cnet_resolver_impl *impl = slot->owner;
  const struct ares_addrinfo_node *node = NULL;

  if (status == ARES_SUCCESS) {
    for (node = addresses != NULL ? addresses->nodes : NULL; node != NULL; node = node->ai_next) {
      if (node->ai_socktype == slot->socket_type && node->ai_addr != NULL &&
          node->ai_addrlen <= CNET_RESOLVER_ADDRESS_CAPACITY &&
          ((node->ai_family == AF_INET &&
            node->ai_addrlen >= sizeof(struct sockaddr_in)) ||
           (node->ai_family == AF_INET6 &&
            node->ai_addrlen >= sizeof(struct sockaddr_in6))))
        break;
    }
    if (node == NULL) status = ARES_ENODATA;
  }

  sync_mutex_lock(&impl->state_lock);
  if (slot->state == CNET_RESOLVER_SLOT_ACTIVE) {
    memset(&slot->result, 0, sizeof(slot->result));
    slot->result.query.slot = (uint32_t)(slot - impl->slots) + 1u;
    slot->result.query.generation = slot->generation;
    slot->result.user_data = slot->user_data;
    slot->result.native_status = status;
    slot->result.timeouts = timeouts;
    slot->result.status = slot->expired ? SALTS_EAI_AGAIN : slot->cancelled ? SALTS_EAI_CANCELED : cnet_resolver_map_status(status);
    if (slot->result.status == SALTS_OK && node != NULL) {
      int port_status;
      slot->result.address_length = (size_t)node->ai_addrlen;
      memcpy(slot->result.address, node->ai_addr, slot->result.address_length);
      /* The query's original port is authoritative, irrespective of the
       * platform/provider's intermittent service-byte-order behavior. */
      port_status = cnet_resolver_apply_requested_port(
          slot->result.address, slot->result.address_length,
          node->ai_family, slot->requested_port);
      if (port_status != SALTS_OK) {
        slot->result.status = port_status;
        slot->result.address_length = 0u;
      }
    }
    if (impl->lookup_identity && slot->result.status == SALTS_OK) {
      for (node = addresses ? addresses->nodes : NULL; node; node = node->ai_next) {
        cnet_ip_address a = {0}; bool duplicate = false;
        if (!node->ai_addr) continue;
        if (node->ai_family == AF_INET && node->ai_addrlen >= sizeof(struct sockaddr_in)) {
          a.family = CNET_DATAGRAM_ADDRESS_IPV4;
          memcpy(a.address, &((const struct sockaddr_in *)node->ai_addr)->sin_addr, 4);
        } else if (node->ai_family == AF_INET6 && node->ai_addrlen >= sizeof(struct sockaddr_in6)) {
          const struct sockaddr_in6 *ip = (const struct sockaddr_in6 *)node->ai_addr;
          if (IN6_IS_ADDR_V4MAPPED(&ip->sin6_addr)) continue;
          a.family = CNET_DATAGRAM_ADDRESS_IPV6; memcpy(a.address, &ip->sin6_addr, 16);
        } else continue;
        for (size_t i = 0; i < slot->address_count; ++i)
          if (slot->addresses[i].family == a.family && !memcmp(slot->addresses[i].address, a.address, 16)) duplicate = true;
        if (duplicate) continue;
        if (slot->address_count == impl->result_capacity) { slot->result.status = SALTS_ENOBUFS; slot->address_count = 0; break; }
        slot->addresses[slot->address_count++] = a;
      }
      if (!slot->address_count && slot->result.status == SALTS_OK) slot->result.status = SALTS_EAI_NODATA;
    }
    slot->state = CNET_RESOLVER_SLOT_READY;
    impl->ready_slots[(impl->ready_head + impl->ready_count) % impl->capacity] =
        slot->result.query.slot - 1u;
    ++impl->ready_count;
  }
  sync_mutex_unlock(&impl->state_lock);

  if (addresses != NULL) ares_freeaddrinfo(addresses);
}

bool cnet_resolver_query_valid(cnet_resolver_query query) {
  return query.slot != 0u && query.generation != 0u;
}

int cnet_resolver_init(cnet_resolver *resolver, const cnet_resolver_config *config) {
  cnet_resolver_impl *impl;
  struct ares_options options;
  size_t socket_capacity;
  int status;
  size_t index;

  if (resolver == NULL || config == NULL || config->query_capacity == 0u) return SALTS_EINVAL;
  if (resolver->impl != NULL) return SALTS_EALREADY;
  if (config->query_capacity > UINT32_MAX ||
      config->query_capacity > SIZE_MAX / sizeof(cnet_resolver_slot) ||
      config->query_capacity > SIZE_MAX / sizeof(uint32_t))
    return SALTS_ERANGE;
  if (config->query_capacity > (SIZE_MAX - ARES_GETSOCK_MAXNUM) / 2u) return SALTS_ERANGE;
  socket_capacity = config->query_capacity * 2u + ARES_GETSOCK_MAXNUM;
  if (socket_capacity > SIZE_MAX / sizeof(cnet_resolver_socket) ||
      socket_capacity > SIZE_MAX / sizeof(cnet_resolver_pollfd) ||
      socket_capacity > SIZE_MAX / sizeof(ares_fd_events_t))
    return SALTS_ERANGE;

  status = cnet_module_acquire_resolver();
  if (status != SALTS_OK) return status;

  impl = (cnet_resolver_impl *)calloc(1u, sizeof(*impl));
  if (impl == NULL) {
    cnet_module_release_resolver();
    return SALTS_ENOMEM;
  }
  impl->slots = (cnet_resolver_slot *)calloc(config->query_capacity, sizeof(*impl->slots));
  impl->free_slots = (uint32_t *)malloc(config->query_capacity * sizeof(*impl->free_slots));
  impl->ready_slots = (uint32_t *)malloc(config->query_capacity * sizeof(*impl->ready_slots));
  impl->sockets = (cnet_resolver_socket *)calloc(socket_capacity, sizeof(*impl->sockets));
  impl->poll_fds = (cnet_resolver_pollfd *)calloc(socket_capacity, sizeof(*impl->poll_fds));
  impl->ready_events = (ares_fd_events_t *)calloc(socket_capacity, sizeof(*impl->ready_events));
  if (impl->slots == NULL || impl->free_slots == NULL || impl->ready_slots == NULL ||
      impl->sockets == NULL || impl->poll_fds == NULL || impl->ready_events == NULL) {
    free(impl->ready_events);
    free(impl->poll_fds);
    free(impl->sockets);
    free(impl->ready_slots);
    free(impl->free_slots);
    free(impl->slots);
    free(impl);
    cnet_module_release_resolver();
    return SALTS_ENOMEM;
  }

  impl->capacity = config->query_capacity;
  impl->socket_capacity = socket_capacity;
  impl->free_count = config->query_capacity;
  impl->admission_open = true;
  for (index = 0u; index < impl->capacity; ++index) {
    impl->slots[index].owner = impl;
    impl->free_slots[index] = (uint32_t)(impl->capacity - index - 1u);
  }
  sync_mutex_init(&impl->control_lock);
  sync_mutex_init(&impl->state_lock);

  memset(&options, 0, sizeof(options));
  options.sock_state_cb = cnet_resolver_socket_state;
  options.sock_state_cb_data = impl;
  status = ares_init_options(&impl->channel, &options, ARES_OPT_SOCK_STATE_CB);
  if (status != ARES_SUCCESS) {
    sync_mutex_destroy(&impl->state_lock);
    sync_mutex_destroy(&impl->control_lock);
    free(impl->ready_events);
    free(impl->poll_fds);
    free(impl->sockets);
    free(impl->ready_slots);
    free(impl->free_slots);
    free(impl->slots);
    free(impl);
    cnet_module_release_resolver();
    return status == ARES_ENOMEM ? SALTS_ENOMEM : SALTS_EAI_FAIL;
  }

  resolver->impl = impl;
  return SALTS_OK;
}

int cnet_resolver_poll(cnet_resolver *resolver) {
  cnet_resolver_impl *impl = cnet_resolver_get_impl(resolver);
  size_t ready_count = 0u;
  size_t offset = 0u;
  int polled;
  ares_status_t status;
  if (impl == NULL) return SALTS_EINVAL;

  sync_mutex_lock(&impl->control_lock);
  if (impl->socket_overflow) {
    impl->socket_overflow = false;
    ares_cancel(impl->channel);
    sync_mutex_unlock(&impl->control_lock);
    return SALTS_ENOBUFS;
  }
  while (offset < impl->socket_count) {
    const size_t batch = impl->socket_count - offset > ARES_GETSOCK_MAXNUM
                             ? ARES_GETSOCK_MAXNUM
                             : impl->socket_count - offset;
    size_t index;
    for (index = 0u; index < batch; ++index) {
      const cnet_resolver_socket *socket = &impl->sockets[offset + index];
      cnet_resolver_pollfd *poll_fd = &impl->poll_fds[index];
      poll_fd->fd = socket->descriptor;
      poll_fd->events = 0;
      poll_fd->revents = 0;
      if ((socket->events & ARES_FD_EVENT_READ) != 0u) poll_fd->events |= POLLIN;
      if ((socket->events & ARES_FD_EVENT_WRITE) != 0u) poll_fd->events |= POLLOUT;
    }
#if defined(_WIN32)
    polled = WSAPoll(impl->poll_fds, (ULONG)batch, 0);
#else
    polled = poll(impl->poll_fds, (nfds_t)batch, 0);
#endif
    if (polled < 0) {
      sync_mutex_unlock(&impl->control_lock);
      return SALTS_EAI_FAIL;
    }
    for (index = 0u; polled > 0 && index < batch; ++index) {
      const short revents = impl->poll_fds[index].revents;
      unsigned int events = 0u;
      if ((revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0) events |= ARES_FD_EVENT_READ;
      if ((revents & POLLOUT) != 0) events |= ARES_FD_EVENT_WRITE;
      if (events != 0u) {
        impl->ready_events[ready_count++] = (ares_fd_events_t){impl->poll_fds[index].fd, events};
      }
    }
    offset += batch;
  }
  status = ares_process_fds(impl->channel, ready_count != 0u ? impl->ready_events : NULL,
                            ready_count, ARES_PROCESS_FLAG_NONE);
  sync_mutex_unlock(&impl->control_lock);
  if (status == ARES_SUCCESS) return SALTS_OK;
  return status == ARES_ENOMEM ? SALTS_ENOMEM : SALTS_EAI_FAIL;
}

bool cnet_resolver_has_pending(cnet_resolver *resolver) {
  cnet_resolver_impl *impl = cnet_resolver_get_impl(resolver);
  bool pending;
  if (impl == NULL) return false;
  sync_mutex_lock(&impl->state_lock);
  pending = impl->active_count != 0u;
  sync_mutex_unlock(&impl->state_lock);
  return pending;
}

int cnet_resolver_submit(cnet_resolver *resolver, const char *host, uint16_t port, int socket_type,
                         uintptr_t user_data, cnet_resolver_query *out_query) {
  cnet_resolver_impl *impl = cnet_resolver_get_impl(resolver);
  cnet_resolver_slot *slot;
  struct ares_addrinfo_hints hints;
  size_t host_length;
  uint32_t slot_index;

  if (out_query == NULL) return SALTS_EINVAL;
  memset(out_query, 0, sizeof(*out_query));
  if (impl == NULL || host == NULL || port == 0u) return SALTS_EINVAL;
  if (socket_type != SOCK_STREAM && socket_type != SOCK_DGRAM) return SALTS_EAI_SOCKTYPE;
  host_length = strnlen(host, CNET_RESOLVER_HOST_CAPACITY);
  if (host_length == 0u || host_length == CNET_RESOLVER_HOST_CAPACITY) return SALTS_ENAMETOOLONG;

  sync_mutex_lock(&impl->control_lock);
  sync_mutex_lock(&impl->state_lock);
  if (!impl->admission_open) {
    sync_mutex_unlock(&impl->state_lock);
    sync_mutex_unlock(&impl->control_lock);
    return SALTS_ESHUTDOWN;
  }
  if (impl->free_count == 0u) {
    sync_mutex_unlock(&impl->state_lock);
    sync_mutex_unlock(&impl->control_lock);
    return SALTS_ENOBUFS;
  }

  slot_index = impl->free_slots[--impl->free_count];
  slot = &impl->slots[slot_index];
  ++slot->generation;
  slot->state = CNET_RESOLVER_SLOT_ACTIVE;
  slot->user_data = user_data;
  slot->socket_type = socket_type;
  slot->requested_port = port;
  slot->cancelled = false;
  slot->dropped = slot->expired = false; slot->address_count = slot->address_index = 0;
  slot->deadline = monotonic_ms() + impl->lookup_timeout;
  memcpy(slot->host, host, host_length + 1u);
  (void)snprintf(slot->service, sizeof(slot->service), "%u", (unsigned int)port);
  ++impl->active_count;
  out_query->slot = slot_index + 1u;
  out_query->generation = slot->generation;
  sync_mutex_unlock(&impl->state_lock);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = socket_type;
  hints.ai_protocol = socket_type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
  ares_getaddrinfo(impl->channel, slot->host, slot->service, &hints, cnet_resolver_callback, slot);
  sync_mutex_unlock(&impl->control_lock);
  return SALTS_OK;
}

int cnet_resolver_cancel(cnet_resolver *resolver, cnet_resolver_query query) {
  cnet_resolver_impl *impl = cnet_resolver_get_impl(resolver);
  cnet_resolver_slot *slot;

  if (impl == NULL) return SALTS_EINVAL;
  sync_mutex_lock(&impl->state_lock);
  slot = cnet_resolver_find_slot(impl, query);
  if (slot == NULL) {
    sync_mutex_unlock(&impl->state_lock);
    return SALTS_ENOENT;
  }
  slot->cancelled = true;
  if (slot->state == CNET_RESOLVER_SLOT_READY) {
    slot->result.status = SALTS_EAI_CANCELED;
    slot->result.address_length = 0u;
  }
  sync_mutex_unlock(&impl->state_lock);
  return SALTS_OK;
}

int cnet_resolver_take(cnet_resolver *resolver, cnet_resolver_result *out_result) {
  cnet_resolver_impl *impl = cnet_resolver_get_impl(resolver);
  cnet_resolver_slot *slot;
  uint32_t slot_index;
  bool drained;

  if (out_result == NULL) return SALTS_EINVAL;
  memset(out_result, 0, sizeof(*out_result));
  if (impl == NULL) return SALTS_EINVAL;

  sync_mutex_lock(&impl->state_lock);
  if (impl->ready_count == 0u) {
    drained = !impl->admission_open && impl->active_count == 0u;
    sync_mutex_unlock(&impl->state_lock);
    return drained ? SALTS_EOF : SALTS_ETIMEDOUT;
  }

  slot_index = impl->ready_slots[impl->ready_head];
  impl->ready_head = (impl->ready_head + 1u) % impl->capacity;
  --impl->ready_count;
  slot = &impl->slots[slot_index];
  *out_result = slot->result;
  memset(&slot->result, 0, sizeof(slot->result));
  slot->state =
      slot->generation == UINT32_MAX ? CNET_RESOLVER_SLOT_RETIRED : CNET_RESOLVER_SLOT_FREE;
  slot->cancelled = false;
  --impl->active_count;
  if (slot->state == CNET_RESOLVER_SLOT_FREE) impl->free_slots[impl->free_count++] = slot_index;
  sync_mutex_unlock(&impl->state_lock);
  return SALTS_OK;
}

int cnet_resolver_close(cnet_resolver *resolver, uint32_t timeout_ms) {
  cnet_resolver_impl *impl = cnet_resolver_get_impl(resolver);

  if (impl == NULL) return SALTS_EINVAL;
  (void)timeout_ms;

  sync_mutex_lock(&impl->control_lock);
  sync_mutex_lock(&impl->state_lock);
  if (!impl->admission_open) {
    sync_mutex_unlock(&impl->state_lock);
    sync_mutex_unlock(&impl->control_lock);
    return SALTS_EALREADY;
  }
  impl->admission_open = false;
  sync_mutex_unlock(&impl->state_lock);
  ares_cancel(impl->channel);
  sync_mutex_unlock(&impl->control_lock);
  return SALTS_OK;
}

int cnet_resolver_destroy(cnet_resolver *resolver) {
  cnet_resolver_impl *impl = cnet_resolver_get_impl(resolver);

  if (resolver == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;

  sync_mutex_lock(&impl->control_lock);
  sync_mutex_lock(&impl->state_lock);
  if (impl->admission_open || impl->active_count != 0u) {
    sync_mutex_unlock(&impl->state_lock);
    sync_mutex_unlock(&impl->control_lock);
    return SALTS_EBUSY;
  }
  sync_mutex_unlock(&impl->state_lock);
  ares_destroy(impl->channel);
  sync_mutex_unlock(&impl->control_lock);

  sync_mutex_destroy(&impl->state_lock);
  sync_mutex_destroy(&impl->control_lock);
  free(impl->lookup_storage);
  free(impl->ready_events);
  free(impl->poll_fds);
  free(impl->sockets);
  free(impl->ready_slots);
  free(impl->free_slots);
  free(impl->slots);
  free(impl);
  resolver->impl = NULL;
  cnet_module_release_resolver();
  return SALTS_OK;
}

/* The public address-stream owner reuses this resolver's c-ares channel,
 * readiness arrays and stable callback slots. The legacy connection resolver
 * continues to take one native address; only address-stream mode keeps a
 * bounded ordered array until its explicit query drop. */
static atomic_uint_fast64_t lookup_identity;
static uint64_t lookup_new_identity(void) {
  uint_fast64_t n = atomic_load(&lookup_identity);
  while (n != UINT64_MAX) if (atomic_compare_exchange_weak(&lookup_identity, &n, n + 1u)) return n + 1u;
  return 0;
}
static cnet_resolver_impl *lookup_impl(cnet_name_lookup *lookup) {
  cnet_resolver_impl *p = lookup ? lookup->impl : NULL;
  return p && p->lookup_identity ? p : NULL;
}
static cnet_resolver_slot *lookup_slot(cnet_resolver_impl *p, cnet_name_query q) {
  cnet_resolver_slot *s;
  if (!p || q.owner != p->lookup_identity) return NULL;
  s = cnet_resolver_find_slot(p, (cnet_resolver_query){q.slot, q.generation});
  return s && !s->dropped ? s : NULL;
}
void cnet_name_lookup_config_init(cnet_name_lookup_config *c) {
  if (c) *c = (cnet_name_lookup_config){sizeof(*c), 1, 16, 64, 4096, 30000, NULL};
}
int cnet_name_lookup_init(cnet_name_lookup *lookup, const cnet_name_lookup_config *config) {
  cnet_name_lookup_config defaults; cnet_resolver resolver = {0}; cnet_resolver_impl *p;
  int rc;
  if (!config) { cnet_name_lookup_config_init(&defaults); config = &defaults; }
  if (!lookup || lookup->impl || config->size != sizeof(*config) || config->version != 1 ||
      !config->query_capacity || !config->results_per_query || !config->max_name_bytes ||
      config->max_name_bytes > 4096 || !config->timeout_ms ||
      config->query_capacity > SIZE_MAX / config->results_per_query ||
      config->query_capacity * config->results_per_query > SIZE_MAX / sizeof(cnet_ip_address)) return SALTS_EINVAL;
  rc = cnet_module_init(); if (rc != SALTS_OK) return rc;
  rc = cnet_resolver_init(&resolver, &(cnet_resolver_config){config->query_capacity});
  if (rc != SALTS_OK) { (void)cnet_module_shutdown(); return rc; }
  p = resolver.impl;
  p->lookup_storage = calloc(config->query_capacity * config->results_per_query, sizeof(cnet_ip_address));
  p->lookup_identity = lookup_new_identity();
  p->result_capacity = config->results_per_query; p->name_capacity = config->max_name_bytes;
  p->lookup_timeout = config->timeout_ms;
  rc = !p->lookup_storage || !p->lookup_identity ? SALTS_ENOMEM : SALTS_OK;
  if (rc == SALTS_OK && config->servers_csv) {
    ares_status_t status = ares_set_servers_ports_csv(p->channel, config->servers_csv);
    if (status != ARES_SUCCESS) rc = status == ARES_ENOMEM ? SALTS_ENOMEM : SALTS_EINVAL;
  }
  if (rc != SALTS_OK) {
    (void)cnet_resolver_close(&resolver, 0); (void)cnet_resolver_destroy(&resolver); (void)cnet_module_shutdown(); return rc;
  }
  for (size_t i = 0; i < p->capacity; ++i) p->slots[i].addresses = p->lookup_storage + i * p->result_capacity;
  lookup->impl = p; return SALTS_OK;
}
/* CNet DNS accepts ASCII LDH hostnames and already-encoded A-labels only.
 * Unicode/UTS #46 and Punycode validation belong to future #1088. */
static int cnet_name_lookup_ascii_hostname(const char *name, size_t size,
                                           char result[256]) {
  size_t label_size = 0u;
  if (size == 0u || size > 254u ||
      (size == 254u && name[size - 1u] != '.')) return SALTS_EINVAL;
  for (size_t i = 0u; i < size; ++i) {
    unsigned char c = (unsigned char)name[i];
    if (c == '.') {
      if (label_size == 0u || result[i - 1u] == '-') return SALTS_EINVAL;
      label_size = 0u;
      result[i] = '.';
      continue;
    }
    if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
          (c == '-' && label_size != 0u))) return SALTS_EINVAL;
    if (++label_size > 63u) return SALTS_EINVAL;
    result[i] = (char)c;
  }
  if (label_size != 0u && result[size - 1u] == '-') return SALTS_EINVAL;
  if (size - (name[size - 1u] == '.' ? 1u : 0u) > 253u) return SALTS_EINVAL;
  result[size] = '\0';
  return SALTS_OK;
}

int cnet_name_lookup_normalize(cnet_name_lookup *lookup, const char *name, size_t size,
                              char *ascii, size_t capacity, size_t *out_size,
                              bool *out_numeric, cnet_ip_address *out_address) {
  cnet_resolver_impl *p = lookup_impl(lookup);
  char result[256], numeric[4097];
  cnet_ip_address address = {0};
  bool is_numeric = false;
  if (!p || !name || !ascii || !out_size || !size ||
      size > p->name_capacity || capacity < sizeof(result) ||
      memchr(name, 0, size)) return SALTS_EINVAL;
  memcpy(numeric, name, size);
  numeric[size] = '\0';
  if (inet_pton(AF_INET, numeric, address.address) == 1) {
    address.family = CNET_DATAGRAM_ADDRESS_IPV4;
    is_numeric = true;
  } else if (inet_pton(AF_INET6, numeric, address.address) == 1) {
    address.family = CNET_DATAGRAM_ADDRESS_IPV6;
    is_numeric = true;
    struct in6_addr ip;
    memcpy(&ip, address.address, 16);
    if (IN6_IS_ADDR_V4MAPPED(&ip)) {
      memmove(address.address, address.address + 12, 4);
      memset(address.address + 4, 0, 12);
      address.family = CNET_DATAGRAM_ADDRESS_IPV4;
    }
  }
  if (is_numeric) {
    if (size >= sizeof(result)) return SALTS_EINVAL;
    memcpy(result, name, size);
    result[size] = '\0';
  } else if (cnet_name_lookup_ascii_hostname(name, size, result) != SALTS_OK) {
    return SALTS_EINVAL;
  }
  memcpy(ascii, result, size + 1u);
  *out_size = size;
  if (out_numeric) *out_numeric = is_numeric;
  if (out_address) *out_address = address;
  return SALTS_OK;
}
int cnet_name_lookup_submit(cnet_name_lookup *lookup, const char *name, size_t size, cnet_name_query *out) {
  cnet_resolver_impl *p = lookup_impl(lookup); cnet_resolver carrier = {p}; cnet_resolver_query query = {0};
  char ascii[256]; size_t count; bool numeric; cnet_ip_address address; int rc;
  if (!p || !out || out->owner || out->slot || out->generation) return SALTS_EINVAL;
  if (!p->admission_open) return SALTS_ESHUTDOWN;
  rc = cnet_name_lookup_normalize(lookup, name, size, ascii, sizeof(ascii), &count, &numeric, &address);
  if (rc != SALTS_OK) return rc;
  if (!numeric) {
    rc = cnet_resolver_submit(&carrier, ascii, 1, SOCK_STREAM, 0, &query);
    if (rc != SALTS_OK) return rc;
  } else {
    if (!p->free_count) return SALTS_ENOBUFS;
    uint32_t index = p->free_slots[--p->free_count]; cnet_resolver_slot *s = &p->slots[index];
    ++s->generation; s->state = CNET_RESOLVER_SLOT_READY; s->cancelled = s->dropped = s->expired = false;
    s->address_count = 1; s->address_index = 0; s->addresses[0] = address;
    memset(&s->result, 0, sizeof(s->result));
    s->result.query = (cnet_resolver_query){index + 1u, s->generation};
    p->ready_slots[(p->ready_head + p->ready_count++) % p->capacity] = index; ++p->active_count;
    query = s->result.query;
  }
  *out = (cnet_name_query){p->lookup_identity, query.slot, query.generation}; return SALTS_OK;
}
static void lookup_retire(cnet_resolver_impl *p, cnet_resolver_slot *s) {
  size_t found = 0, index = (size_t)(s - p->slots);
  while (found < p->ready_count && p->ready_slots[(p->ready_head + found) % p->capacity] != index) ++found;
  if (found == p->ready_count) return;
  for (size_t i = found; i + 1 < p->ready_count; ++i)
    p->ready_slots[(p->ready_head + i) % p->capacity] = p->ready_slots[(p->ready_head + i + 1) % p->capacity];
  --p->ready_count; --p->active_count;
  s->state = s->generation == UINT32_MAX ? CNET_RESOLVER_SLOT_RETIRED : CNET_RESOLVER_SLOT_FREE;
  if (s->state == CNET_RESOLVER_SLOT_FREE) p->free_slots[p->free_count++] = (uint32_t)index;
}
int cnet_name_lookup_advance(cnet_name_lookup *lookup) {
  cnet_resolver_impl *p = lookup_impl(lookup); cnet_resolver carrier = {p}; int rc;
  if (!p) return SALTS_EINVAL;
  for (size_t i = 0; i < p->capacity; ++i)
    if (p->slots[i].state == CNET_RESOLVER_SLOT_ACTIVE && !p->slots[i].cancelled && monotonic_ms() >= p->slots[i].deadline) p->slots[i].expired = true;
  rc = cnet_resolver_poll(&carrier);
  for (size_t i = 0; i < p->capacity; ++i)
    if (p->slots[i].state == CNET_RESOLVER_SLOT_READY && p->slots[i].dropped) lookup_retire(p, &p->slots[i]);
  return rc;
}
int cnet_name_lookup_next_timeout(cnet_name_lookup *lookup, uint32_t max_wait, uint32_t *out) {
  cnet_resolver_impl *p = lookup_impl(lookup); uint64_t now = monotonic_ms(); struct timeval maximum, timeout;
  if (!p || !out) return SALTS_EINVAL;
  *out = max_wait;
  for (size_t i = 0; i < p->capacity; ++i) if (p->slots[i].state == CNET_RESOLVER_SLOT_ACTIVE && !p->slots[i].cancelled && !p->slots[i].expired) {
    uint64_t remaining = p->slots[i].deadline > now ? p->slots[i].deadline - now : 0;
    if (remaining < *out) *out = (uint32_t)remaining;
  }
  maximum.tv_sec = *out / 1000; maximum.tv_usec = (*out % 1000) * 1000;
  struct timeval *wait = ares_timeout(p->channel, &maximum, &timeout);
  if (wait) { uint64_t ms = (uint64_t)wait->tv_sec * 1000 + ((uint64_t)wait->tv_usec + 999) / 1000;
    if (ms < *out) *out = (uint32_t)ms; }
  return SALTS_OK;
}
int cnet_name_lookup_ready(cnet_name_lookup *lookup, cnet_name_query query, bool *out) {
  cnet_resolver_slot *s = lookup_slot(lookup_impl(lookup), query);
  if (!s || !out) return SALTS_EINVAL;
  *out = s->state == CNET_RESOLVER_SLOT_READY || s->cancelled || monotonic_ms() >= s->deadline; return SALTS_OK;
}
int cnet_name_lookup_next(cnet_name_lookup *lookup, cnet_name_query query, cnet_ip_address *out) {
  cnet_resolver_slot *s = lookup_slot(lookup_impl(lookup), query);
  if (!s || !out) return SALTS_EINVAL;
  if (s->state != CNET_RESOLVER_SLOT_READY) {
    if (s->cancelled) return SALTS_EAI_CANCELED;
    if (monotonic_ms() >= s->deadline) s->expired = true;
    return s->expired ? SALTS_EAI_AGAIN : SALTS_ETIMEDOUT;
  }
  if (s->result.status != SALTS_OK) return s->result.status;
  if (s->address_index == s->address_count) return SALTS_EOF;
  *out = s->addresses[s->address_index++]; return SALTS_OK;
}
int cnet_name_lookup_cancel(cnet_name_lookup *lookup, cnet_name_query query) {
  cnet_resolver_slot *s = lookup_slot(lookup_impl(lookup), query);
  if (!s) return SALTS_EINVAL;
  if (s->state == CNET_RESOLVER_SLOT_READY) return SALTS_EALREADY;
  s->cancelled = true; return SALTS_OK;
}
int cnet_name_lookup_query_drop(cnet_name_lookup *lookup, cnet_name_query *query) {
  cnet_resolver_impl *p = lookup_impl(lookup); cnet_resolver_slot *s;
  if (!query || !(s = lookup_slot(p, *query))) return SALTS_EINVAL;
  s->dropped = true;
  if (s->state == CNET_RESOLVER_SLOT_READY) lookup_retire(p, s); else s->cancelled = true;
  memset(query, 0, sizeof(*query)); return SALTS_OK;
}
int cnet_name_lookup_close(cnet_name_lookup *lookup) {
  cnet_resolver_impl *p = lookup_impl(lookup); cnet_resolver carrier = {p}; int rc;
  if (!p) return SALTS_EINVAL;
  rc = cnet_resolver_close(&carrier, 0);
  if (rc == SALTS_EALREADY) rc = SALTS_OK;
  if (rc == SALTS_OK) rc = cnet_name_lookup_advance(lookup);
  return rc;
}
int cnet_name_lookup_destroy(cnet_name_lookup *lookup) {
  cnet_resolver_impl *p = lookup_impl(lookup); cnet_resolver carrier = {p}; int rc;
  if (!lookup) return SALTS_EINVAL;
  if (!lookup->impl) return SALTS_OK;
  if (!p) return SALTS_EINVAL;
  rc = cnet_resolver_destroy(&carrier);
  if (rc == SALTS_OK) { lookup->impl = NULL; rc = cnet_module_shutdown(); }
  return rc;
}
