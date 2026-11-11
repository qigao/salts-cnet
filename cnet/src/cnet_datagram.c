#if defined(_WIN32)
  #include <winsock2.h>
  #include <mswsock.h>
#endif

#include <cnet/cnet.h>

#include "cnet_datagram_internal.h"
#include "cnet_module.h"
#include "cnet_transport.h"

#include <core/clock.h>
#include <threads/threads.h>

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef uintptr_t cnet_datagram_socket;
#define CNET_DATAGRAM_INVALID_SOCKET UINTPTR_MAX

enum { CNET_DATAGRAM_STOP_ERROR_RETRY_MS = 1 };

typedef struct cnet_datagram_send_slot {
  native_io_request request;
  native_io_socket_address native_peer;
  cnet_datagram_peer peer;
  unsigned char *data;
  size_t size;
  uint64_t tag;
  bool active;
} cnet_datagram_send_slot;

typedef struct cnet_datagram_impl {
  cnet_datagram *public_datagram;
  native_io_backend backend;
  native_io_endpoint endpoint;
  cnet_datagram_socket socket_value;
  cnet_datagram_observer observer;
  cnet_datagram_send_slot *send_slots;
  uint32_t *free_sends;
  unsigned char *send_storage;
  unsigned char *receive_buffer;
  native_io_completion *completions;
  native_io_socket_address receive_peer;
  native_io_request receive_request;
  size_t send_capacity;
  size_t free_send_count;
  size_t active_send_count;
  size_t request_capacity;
  size_t completion_batch_capacity;
  size_t max_datagram_bytes;
  size_t receive_buffer_bytes;
  size_t receive_demand;
  uint16_t port;
  int stop_status;
  int native_family;
  bool receive_callback_active;
  bool receive_active;
  bool polling;
  bool callback_active;
  bool stopping;
  bool stopped;
  bool backend_borrowed;
  bool receive_rearm;
  bool bound;
  bool receive_paused;
  bool kcp;
#if defined(CNET_INTERNAL_TESTING)
  int test_drive_status;
  int test_persistent_drive_status;
  int test_cancel_status;
  int test_release_status;
#endif
} cnet_datagram_impl;

static cnet_datagram_impl *cnet_datagram_get(cnet_datagram *datagram) {
  return datagram != NULL ? (cnet_datagram_impl *)datagram->impl : NULL;
}

static const cnet_datagram_impl *cnet_datagram_const_get(const cnet_datagram *datagram) {
  return datagram != NULL ? (const cnet_datagram_impl *)datagram->impl : NULL;
}

#if defined(CNET_INTERNAL_TESTING)
int cnet_test_datagram_fail_next_cancel(cnet_datagram *datagram, int status) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  if (impl == NULL || status >= SALTS_OK || impl->test_cancel_status != SALTS_OK) return SALTS_EINVAL;
  impl->test_cancel_status = status;
  return SALTS_OK;
}

int cnet_test_datagram_fail_next_release(cnet_datagram *datagram, int status) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  if (impl == NULL || status >= SALTS_OK || impl->test_release_status != SALTS_OK) return SALTS_EINVAL;
  impl->test_release_status = status;
  return SALTS_OK;
}

int cnet_test_datagram_fail_next_drive(cnet_datagram *datagram, int status) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  if (impl == NULL || status >= SALTS_OK || status == SALTS_ETIMEDOUT ||
      impl->test_drive_status != SALTS_OK)
    return SALTS_EINVAL;
  impl->test_drive_status = status;
  return SALTS_OK;
}

int cnet_test_datagram_set_persistent_drive_failure(cnet_datagram *datagram, int status) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  if (impl == NULL || status > SALTS_OK || status == SALTS_ETIMEDOUT) return SALTS_EINVAL;
  impl->test_persistent_drive_status = status;
  return SALTS_OK;
}

#endif

static int cnet_datagram_socket_status(native_io_socket_result result) {
  return result.native_status > 0 ? -result.native_status : result.status;
}

static void cnet_datagram_close_socket(cnet_datagram_impl *impl) {
  if (impl == NULL || impl->socket_value == CNET_DATAGRAM_INVALID_SOCKET) return;
  (void)native_io_socket_close(impl->socket_value);
  impl->socket_value = CNET_DATAGRAM_INVALID_SOCKET;
}

static int cnet_datagram_bound_port(cnet_datagram_socket socket_value, uint16_t *out_port) {
  native_io_socket_address address;
  size_t length;
  if (!out_port) return SALTS_EINVAL;
  *out_port = 0;
  int status = cnet_datagram_socket_status(native_io_socket_query(socket_value, false, &address, sizeof(address), &length));
  if (status != SALTS_OK) return status;
  cnet_stream_endpoint endpoint = CNET_STREAM_ENDPOINT_INIT;
  status = cnet_transport_decode_endpoint(&address, length, true, &endpoint);
  if (status != SALTS_OK) return SALTS_EPROTO;
  *out_port = endpoint.port;
  return *out_port != 0u ? SALTS_OK : SALTS_EPROTO;
}

static int cnet_datagram_peer_from_native(const native_io_socket_address *address,
    size_t length, cnet_datagram_peer *peer) {
  cnet_stream_endpoint endpoint = CNET_STREAM_ENDPOINT_INIT;
  memset(peer, 0, sizeof(*peer));
  int status = cnet_transport_decode_endpoint(address, length, true, &endpoint);
  if (status != SALTS_OK) return SALTS_EPROTO;
  peer->family = endpoint.family; peer->port = endpoint.port; peer->scope_id = endpoint.scope_id;
  memcpy(peer->address, endpoint.address, sizeof(peer->address));
  return peer->port ? SALTS_OK : SALTS_EPROTO;
}

static int cnet_datagram_peer_to_native(const cnet_datagram_peer *peer,
    native_io_socket_address *address, size_t *length, uint32_t flow_info) {
  if (!peer || !address || !length || !peer->port) return SALTS_EINVAL;
  if (peer->family != CNET_DATAGRAM_ADDRESS_IPV4 && peer->family != CNET_DATAGRAM_ADDRESS_IPV6)
    return SALTS_EINVAL;
  cnet_stream_endpoint endpoint = CNET_STREAM_ENDPOINT_INIT;
  endpoint.family = peer->family; endpoint.port = peer->port;
  endpoint.flow_info = peer->family == CNET_DATAGRAM_ADDRESS_IPV6 ? flow_info : 0;
  endpoint.scope_id = peer->scope_id;
  memcpy(endpoint.address, peer->address, sizeof(endpoint.address));
  memset(address, 0, sizeof(*address));
  return cnet_transport_encode_datagram_endpoint(&endpoint, address, sizeof(*address), length);
}

static int cnet_datagram_arm_receive(cnet_datagram_impl *impl) {
  native_io_operation operation;
  int status;
  /* A callback still borrows receive_buffer; reentrant demand must wait for its return. */
  if (impl->receive_active || impl->receive_demand == 0u || impl->stopping || impl->receive_paused)
    return SALTS_OK;
  if (impl->callback_active) {
    impl->receive_rearm = true;
    return SALTS_OK;
  }
  memset(&impl->receive_peer, 0, sizeof(impl->receive_peer));
  operation = (native_io_operation){.kind = NATIVE_IO_OPERATION_UDP_RECV_FROM,
                                    .endpoint = impl->endpoint,
                                    .buffer = impl->receive_buffer,
                                    .length = impl->receive_buffer_bytes,
                                    .user_data = 0u,
                                    .address = &impl->receive_peer,
                                    .address_capacity = sizeof(impl->receive_peer)};
  status = native_io_backend_submit(&impl->backend, &operation, &impl->receive_request);
  if (status == SALTS_OK) impl->receive_active = true;
  impl->receive_rearm = impl->backend_borrowed && status == SALTS_ENOBUFS;
  return status;
}

static void cnet_datagram_send_slot_release(cnet_datagram_impl *impl, size_t index) {
  cnet_datagram_send_slot *slot = &impl->send_slots[index];
  memset(&slot->request, 0, sizeof(slot->request));
  memset(&slot->native_peer, 0, sizeof(slot->native_peer));
  memset(&slot->peer, 0, sizeof(slot->peer));
  slot->size = 0u;
  slot->tag = 0u;
  slot->active = false;
  impl->free_sends[impl->free_send_count++] = (uint32_t)index;
  --impl->active_send_count;
}

static int cnet_datagram_completion_status(const native_io_completion *completion) {
  if (completion->kind == NATIVE_IO_COMPLETION_OK) return SALTS_OK;
  if (completion->kind == NATIVE_IO_COMPLETION_CANCELLED) return SALTS_ECANCELED;
  return completion->status < SALTS_OK ? completion->status : SALTS_EIO;
}

static bool cnet_datagram_port_unreachable(int status) {
#if defined(_WIN32)
  if (status == -(int)ERROR_PORT_UNREACHABLE || status == -(int)WSAECONNRESET)
    return true;
#endif
  return status == SALTS_ECONNREFUSED;
}

/* The local tag is not an identity on a shared backend. Receive uses the
 * sentinel send_capacity; only retained request identities can claim a terminal. */
static bool cnet_datagram_find_request(const cnet_datagram_impl *impl,
                                       native_io_request request, size_t *out_index) {
  if (impl->receive_active && request.slot == impl->receive_request.slot &&
      request.generation == impl->receive_request.generation) {
    *out_index = impl->send_capacity;
    return true;
  }
  for (size_t index = 0u; index < impl->send_capacity; ++index) {
    const cnet_datagram_send_slot *slot = &impl->send_slots[index];
    if (slot->active && request.slot == slot->request.slot &&
        request.generation == slot->request.generation) {
      *out_index = index;
      return true;
    }
  }
  return false;
}

static int cnet_datagram_complete(cnet_datagram_impl *impl,
                                  const native_io_completion *completion,
                                  size_t *callback_count) {
  size_t index;
  bool malformed;
  if (!cnet_datagram_find_request(impl, completion->request, &index)) return SALTS_EPROTO;
  malformed = completion->endpoint.slot != impl->endpoint.slot ||
              completion->endpoint.generation != impl->endpoint.generation ||
              completion->user_data != (index == impl->send_capacity ? 0u : index + 1u) ||
              (completion->kind != NATIVE_IO_COMPLETION_OK &&
               completion->kind != NATIVE_IO_COMPLETION_CANCELLED &&
               completion->kind != NATIVE_IO_COMPLETION_FAILED) ||
              (completion->kind == NATIVE_IO_COMPLETION_OK && completion->status != SALTS_OK) ||
              (completion->kind == NATIVE_IO_COMPLETION_FAILED && completion->status >= SALTS_OK);
  if (index == impl->send_capacity) {
    cnet_datagram_peer peer;
    cnet_receive_view view;
    int status;
    impl->receive_active = false;
    impl->receive_rearm = false;
    memset(&impl->receive_request, 0, sizeof(impl->receive_request));
    if (malformed) return SALTS_EPROTO;
    if (impl->receive_paused) return SALTS_OK;
    if (completion->kind == NATIVE_IO_COMPLETION_CANCELLED && impl->stopping) return SALTS_OK;
    status = cnet_datagram_completion_status(completion);
    if (impl->kcp && cnet_datagram_port_unreachable(status))
      return cnet_datagram_arm_receive(impl);
    if (status != SALTS_OK) return status;
    if (impl->stopping) return SALTS_OK;
    if (completion->bytes > impl->max_datagram_bytes || impl->receive_demand == 0u)
      return SALTS_EPROTO;
    status = cnet_datagram_peer_from_native(&impl->receive_peer, completion->address_length, &peer);
    if (status != SALTS_OK) return status;
    --impl->receive_demand;
    view = (cnet_receive_view){impl->receive_buffer, completion->bytes, CNET_MESSAGE_DATAGRAM};
    impl->callback_active = true;
    impl->receive_callback_active = true;
    impl->observer.on_receive(impl->observer.user, impl->public_datagram, &peer, &view);
    impl->receive_callback_active = false;
    impl->callback_active = false;
    ++*callback_count;
    return cnet_datagram_arm_receive(impl);
  }
  {
    cnet_datagram_peer peer;
    size_t size;
    size_t prior_receive_demand;
    uint64_t tag;
    int status;
    peer = impl->send_slots[index].peer;
    size = impl->send_slots[index].size;
    tag = impl->send_slots[index].tag;
    status = malformed ? SALTS_EPROTO : cnet_datagram_completion_status(completion);
    if (status == SALTS_OK && completion->bytes != size) status = SALTS_EIO;
    cnet_datagram_send_slot_release(impl, index);
    prior_receive_demand = impl->receive_demand;
    impl->callback_active = true;
    impl->observer.on_send(impl->observer.user, impl->public_datagram, &peer, size, status, tag);
    impl->callback_active = false;
    ++*callback_count;
    {
      const int rearm_status = impl->receive_demand > prior_receive_demand
                                   ? cnet_datagram_arm_receive(impl) : SALTS_OK;
      return malformed ? SALTS_EPROTO : rearm_status;
    }
  }
}

static int cnet_datagram_process_completions(cnet_datagram_impl *impl,
                                             const native_io_completion *completions,
                                             size_t completion_count,
                                             size_t *out_callbacks) {
  size_t callback_count = 0u;
  int first_status = SALTS_OK;
  for (size_t index = 0u; index < completion_count; ++index) {
    const int status = cnet_datagram_complete(impl, &completions[index], &callback_count);
    if (status != SALTS_OK && first_status == SALTS_OK) first_status = status;
  }
  *out_callbacks = callback_count;
  return first_status;
}

#if defined(CNET_INTERNAL_TESTING)
typedef struct cnet_test_batch_probe {
  size_t callbacks;
} cnet_test_batch_probe;

static void cnet_test_batch_send(void *user, cnet_datagram *datagram,
                                 const cnet_datagram_peer *peer, size_t size, int status,
                                 uint64_t tag) {
  cnet_test_batch_probe *probe = (cnet_test_batch_probe *)user;
  (void)datagram;
  (void)peer;
  (void)size;
  (void)status;
  (void)tag;
  ++probe->callbacks;
}

int cnet_test_datagram_process_mixed_batch(size_t *out_callbacks) {
  cnet_datagram_impl impl = {0};
  cnet_datagram_send_slot send_slot = {0};
  uint32_t free_send = 0u;
  cnet_test_batch_probe probe = {0};
  native_io_completion completions[2] = {0};
  size_t callbacks = 0u;
  int status;
  if (out_callbacks == NULL) return SALTS_EINVAL;
  *out_callbacks = 0u;
  send_slot.request = (native_io_request){7u, 11u};
  send_slot.size = 1u;
  send_slot.active = true;
  impl.send_slots = &send_slot;
  impl.free_sends = &free_send;
  impl.send_capacity = 1u;
  impl.active_send_count = 1u;
  impl.observer.on_send = cnet_test_batch_send;
  impl.observer.user = &probe;
  completions[0].user_data = 2u;
  completions[1].request = send_slot.request;
  completions[1].kind = NATIVE_IO_COMPLETION_OK;
  completions[1].bytes = send_slot.size;
  completions[1].user_data = 1u;
  status = cnet_datagram_process_completions(&impl, completions, 2u, &callbacks);
  if (callbacks != probe.callbacks || impl.active_send_count != 0u) return SALTS_EPROTO;
  *out_callbacks = callbacks;
  return status;
}
#endif

static int cnet_datagram_drive(cnet_datagram_impl *impl, uint32_t timeout_ms,
                               size_t *out_callbacks) {
  size_t completion_count = 0u;
#if defined(CNET_INTERNAL_TESTING)
  if (impl->test_persistent_drive_status != SALTS_OK)
    return impl->test_persistent_drive_status;
  if (impl->test_drive_status != SALTS_OK) {
    const int status = impl->test_drive_status;
    impl->test_drive_status = SALTS_OK;
    return status;
  }
#endif
  int status = native_io_backend_observe(&impl->backend, impl->completions,
                                         impl->completion_batch_capacity, timeout_ms,
                                         &completion_count);
  if (status == SALTS_ETIMEDOUT) status = SALTS_OK;
  if (status != SALTS_OK) return status;
  return cnet_datagram_process_completions(impl, impl->completions, completion_count,
                                           out_callbacks);
}

static int cnet_datagram_init_impl(cnet_datagram *datagram, const cnet_datagram_config *config,
                                    native_io_backend *borrowed_backend,
                                    cnet_datagram_address_family unbound_family, bool kcp) {
  cnet_datagram_impl *impl = NULL;
  native_io_backend_config borrowed_config = {0};
  native_io_backend_stats borrowed_stats = {0};
  _Alignas(native_io_socket_address) unsigned char native_address[sizeof(native_io_socket_address)];
  size_t native_address_size = 0u;
  int family;
  int status;
  if (datagram == NULL || config == NULL || config->size != sizeof(*config)) return SALTS_EINVAL;
  if (datagram->impl != NULL) return SALTS_EALREADY;
  if (borrowed_backend != NULL &&
      (!native_io_backend_get_config(borrowed_backend, &borrowed_config) ||
       !native_io_backend_get_stats(borrowed_backend, &borrowed_stats) ||
       borrowed_config.kind != config->backend))
    return SALTS_EINVAL;
  if (borrowed_backend != NULL && !borrowed_stats.admission_open) return SALTS_ESHUTDOWN;
  if ((unbound_family == 0 ? config->host == NULL || config->host[0] == '\0' :
       config->host != NULL || config->port != 0 ||
       (unbound_family != CNET_DATAGRAM_ADDRESS_IPV4 && unbound_family != CNET_DATAGRAM_ADDRESS_IPV6)) || config->send_capacity == 0u ||
      config->request_capacity <= config->send_capacity ||
      config->completion_batch_capacity == 0u ||
      config->completion_batch_capacity > config->request_capacity ||
      config->max_datagram_bytes == 0u ||
      config->max_datagram_bytes > CNET_DATAGRAM_MAX_PAYLOAD_BYTES ||
      config->receive_buffer_bytes < config->max_datagram_bytes ||
      config->receive_buffer_bytes > CNET_DATAGRAM_MAX_PAYLOAD_BYTES ||
      config->observer.on_receive == NULL || config->observer.on_send == NULL ||
      (config->reuse_port != 0 && config->reuse_port != 1) ||
      !native_io_backend_kind_supported(config->backend) ||
      config->send_capacity > SIZE_MAX / config->max_datagram_bytes)
    return SALTS_EINVAL;
  if (config->send_capacity > UINT32_MAX ||
      config->send_capacity > SIZE_MAX / sizeof(cnet_datagram_send_slot) ||
      config->send_capacity > SIZE_MAX / sizeof(uint32_t) ||
      config->completion_batch_capacity > SIZE_MAX / sizeof(native_io_completion))
    return SALTS_ERANGE;
  if (borrowed_backend != NULL && borrowed_config.request_capacity < config->request_capacity)
    return SALTS_ENOBUFS;
  if (config->reuse_port && !native_io_socket_reuse_port_supported()) return SALTS_ENOTSUP;
  status = cnet_transport_parse_bind_address(unbound_family == CNET_DATAGRAM_ADDRESS_IPV4 ? "0.0.0.0" :
                                             unbound_family == CNET_DATAGRAM_ADDRESS_IPV6 ? "::" : config->host, config->port, native_address,
                                             sizeof(native_address), &native_address_size);
  if (status != SALTS_OK) return status;
  family = native_io_socket_address_family(native_address, native_address_size);
  status = cnet_module_init();
  if (status != SALTS_OK) return status;
  impl = (cnet_datagram_impl *)calloc(1u, sizeof(*impl));
  if (impl == NULL) {
    (void)cnet_module_shutdown();
    return SALTS_ENOMEM;
  }
  impl->socket_value = CNET_DATAGRAM_INVALID_SOCKET;
  impl->native_family = family;
  impl->public_datagram = datagram;
  impl->observer = config->observer;
  impl->backend_borrowed = borrowed_backend != NULL;
  impl->send_capacity = config->send_capacity;
  impl->free_send_count = config->send_capacity;
  impl->request_capacity = config->request_capacity;
  impl->completion_batch_capacity = config->completion_batch_capacity;
  impl->max_datagram_bytes = config->max_datagram_bytes;
  impl->receive_buffer_bytes = config->receive_buffer_bytes;
  impl->send_slots = (cnet_datagram_send_slot *)calloc(config->send_capacity,
                                                       sizeof(*impl->send_slots));
  impl->free_sends = (uint32_t *)calloc(config->send_capacity, sizeof(*impl->free_sends));
  impl->send_storage = (unsigned char *)calloc(config->send_capacity, config->max_datagram_bytes);
  impl->receive_buffer = (unsigned char *)malloc(config->receive_buffer_bytes);
  if (!impl->backend_borrowed)
    impl->completions = (native_io_completion *)calloc(config->completion_batch_capacity,
                                                        sizeof(*impl->completions));
  if (impl->send_slots == NULL || impl->free_sends == NULL || impl->send_storage == NULL ||
      impl->receive_buffer == NULL || (!impl->backend_borrowed && impl->completions == NULL)) {
    status = SALTS_ENOMEM;
    goto fail;
  }
  for (size_t index = 0u; index < config->send_capacity; ++index) {
    impl->send_slots[index].data = impl->send_storage + index * config->max_datagram_bytes;
    impl->free_sends[index] = (uint32_t)(config->send_capacity - index - 1u);
  }
  if (impl->backend_borrowed) {
    impl->backend = *borrowed_backend;
    status = SALTS_OK;
  } else {
    status = native_io_backend_init(
        &impl->backend,
        &(native_io_backend_config){config->backend, 1u, config->request_capacity,
                                    config->completion_batch_capacity});
  }
  if (status != SALTS_OK) goto fail;
  status = cnet_datagram_socket_status(native_io_socket_create(config->backend, family, true, &impl->socket_value));
  if (status != SALTS_OK) goto fail;
#if defined(_WIN32)
  if (kcp) {
    /* An ICMP port error can also fail an immediate Winsock receive submission.
     * Keep the shared socket usable and let KCP handle the lost datagram. */
    BOOL report_unreachable = FALSE;
    DWORD bytes = 0u;
    if (WSAIoctl((SOCKET)impl->socket_value, SIO_UDP_CONNRESET,
                 &report_unreachable, sizeof(report_unreachable),
                 NULL, 0u, &bytes, NULL, NULL) != 0) {
      status = -WSAGetLastError();
      goto fail;
    }
  }
#endif
  if (config->reuse_port) {
    status = cnet_datagram_socket_status(native_io_socket_reuse(impl->socket_value, true, true));
    if (status != SALTS_OK) goto fail;
  }
  if (!unbound_family) {
    status = cnet_datagram_socket_status(native_io_socket_bind(impl->socket_value, native_address, native_address_size));
    if (status != SALTS_OK) goto fail;
  }
  status = unbound_family ? SALTS_OK : cnet_datagram_bound_port(impl->socket_value, &impl->port);
  impl->bound = unbound_family == 0;
  if (status != SALTS_OK) goto fail;
  status = native_io_backend_attach_socket(&impl->backend, (uintptr_t)impl->socket_value,
                                           &impl->endpoint);
  if (status != SALTS_OK) goto fail;
  impl->kcp = kcp;
  datagram->impl = impl;
  return SALTS_OK;

fail:
  cnet_datagram_close_socket(impl);
  if (native_io_endpoint_valid(impl->endpoint))
    (void)native_io_backend_release_socket(&impl->backend, impl->endpoint);
  if (!impl->backend_borrowed) {
    (void)native_io_backend_close(&impl->backend);
    (void)native_io_backend_destroy(&impl->backend);
  }
  free(impl->completions);
  free(impl->receive_buffer);
  free(impl->send_storage);
  free(impl->free_sends);
  free(impl->send_slots);
  free(impl);
  (void)cnet_module_shutdown();
  return status;
}

int cnet_datagram_init(cnet_datagram *datagram, const cnet_datagram_config *config) {
  return cnet_datagram_init_impl(datagram, config, NULL, 0, false);
}

int cnet_datagram_init_external(cnet_datagram *datagram, const cnet_datagram_config *config,
                                 native_io_backend *backend) {
  if (backend == NULL) return SALTS_EINVAL;
  return cnet_datagram_init_impl(datagram, config, backend, 0, false);
}

int cnet_datagram_init_kcp(cnet_datagram *datagram, const cnet_datagram_config *config,
                           native_io_backend *backend) {
  return cnet_datagram_init_impl(datagram, config, backend, 0, true);
}

int cnet_datagram_open_external(cnet_datagram *datagram, const cnet_datagram_config *config,
                               native_io_backend *backend, cnet_datagram_address_family family) {
  if (!backend || !family) return SALTS_EINVAL;
  return cnet_datagram_init_impl(datagram, config, backend, family, false);
}

static int endpoint_to_native(const cnet_stream_endpoint *endpoint,
    native_io_socket_address *address, size_t *length) {
  if (address) memset(address, 0, sizeof(*address));
  return cnet_transport_encode_datagram_endpoint(endpoint, address, sizeof(*address), length);
}

static int endpoint_from_native(const native_io_socket_address *address, cnet_stream_endpoint *out) {
  cnet_stream_endpoint result = CNET_STREAM_ENDPOINT_INIT;
  int status = cnet_transport_decode_endpoint(address, sizeof(*address), true, &result);
  if (status == SALTS_OK) *out = result;
  return status;
}

int cnet_datagram_bind_endpoint(cnet_datagram *datagram, const cnet_stream_endpoint *endpoint) {
  cnet_datagram_impl *p = cnet_datagram_get(datagram); native_io_socket_address address; size_t size; int rc;
  if (!p) return SALTS_EINVAL;
  if (p->stopping) return SALTS_ESHUTDOWN;
  if (p->polling || p->callback_active) return SALTS_EBUSY;
  if (p->bound) return SALTS_EALREADY;
  rc = endpoint_to_native(endpoint, &address, &size); if (rc != SALTS_OK) return rc;
  rc = cnet_datagram_socket_status(native_io_socket_bind(p->socket_value, &address, size));
  if (rc != SALTS_OK) return rc;
  p->bound = true;
  return cnet_datagram_bound_port(p->socket_value, &p->port);
}
static int endpoint_query(const cnet_datagram *datagram, cnet_stream_endpoint *out, bool remote) {
  const cnet_datagram_impl *p = cnet_datagram_const_get(datagram);
  native_io_socket_address address;
  size_t length;
  if (!p || !out) return SALTS_EINVAL;
  if (p->stopping) return SALTS_ESHUTDOWN;
  if (!p->bound) return SALTS_ENOTCONN;
  int status = cnet_datagram_socket_status(native_io_socket_query(p->socket_value, remote, &address, sizeof(address), &length));
  return status == SALTS_OK ? endpoint_from_native(&address, out) : status;
}

int cnet_datagram_local_endpoint(const cnet_datagram *d, cnet_stream_endpoint *out) { return endpoint_query(d, out, false); }
int cnet_datagram_remote_endpoint(const cnet_datagram *d, cnet_stream_endpoint *out) { return endpoint_query(d, out, true); }
int cnet_datagram_received_endpoint(const cnet_datagram *d, cnet_stream_endpoint *out) {
  const cnet_datagram_impl *p = cnet_datagram_const_get(d);
  if (!p || !out || !p->receive_callback_active) return SALTS_EINVAL;
  return endpoint_from_native(&p->receive_peer, out);
}
int cnet_datagram_associate_endpoint(cnet_datagram *d, const cnet_stream_endpoint *endpoint) {
  cnet_datagram_impl *p = cnet_datagram_get(d);
  native_io_socket_address address;
  size_t size = 0;
  if (!p) return SALTS_EINVAL;
  if (p->stopping) return SALTS_ESHUTDOWN;
  if (!p->bound) return SALTS_ENOTCONN;
  if (p->polling || p->callback_active || p->receive_active || p->active_send_count) return SALTS_EBUSY;
  if (endpoint) {
    if (!endpoint->port) return SALTS_EINVAL;
    int status = endpoint_to_native(endpoint, &address, &size);
    if (status != SALTS_OK) return status;
  }
  return cnet_datagram_socket_status(native_io_socket_associate(p->socket_value, endpoint ? &address : NULL, size));
}

int cnet_datagram_pause_receive(cnet_datagram *d) {
  cnet_datagram_impl *p = cnet_datagram_get(d); int rc;
  if (!p) return SALTS_EINVAL;
  if (p->polling || p->callback_active) return SALTS_EBUSY;
  p->receive_paused = true; p->receive_demand = 0; p->receive_rearm = false;
  if (!p->receive_active) return SALTS_OK;
  rc = native_io_backend_cancel(&p->backend, p->receive_request);
  return rc == SALTS_ENOENT || rc == SALTS_EALREADY ? SALTS_OK : rc;
}
int cnet_datagram_quiescent(const cnet_datagram *d, bool *out) {
  const cnet_datagram_impl *p = cnet_datagram_const_get(d);
  if (!p || !out) return SALTS_EINVAL;
  *out = !p->receive_active && !p->active_send_count && !p->polling && !p->callback_active; return SALTS_OK;
}
static bool datagram_option(cnet_tcp_socket_option option) {
  return option == CNET_TCP_SOCKET_HOP_LIMIT || option == CNET_TCP_SOCKET_RECEIVE_BUFFER_BYTES ||
         option == CNET_TCP_SOCKET_SEND_BUFFER_BYTES;
}
int cnet_datagram_option_get(const cnet_datagram *d, cnet_tcp_socket_option option, uint64_t *out) {
  const cnet_datagram_impl *p = cnet_datagram_const_get(d);
  if (!p || !out) return SALTS_EINVAL;
  if (p->stopping) return SALTS_ESHUTDOWN;
  if (!datagram_option(option)) return SALTS_ENOTSUP;
  return cnet_transport_tcp_native_option_get_family((uintptr_t)p->socket_value, p->native_family, option, out);
}
int cnet_datagram_option_set(cnet_datagram *d, cnet_tcp_socket_option option, uint64_t value) {
  cnet_datagram_impl *p = cnet_datagram_get(d);
  if (!p || !value) return SALTS_EINVAL;
  if (p->stopping) return SALTS_ESHUTDOWN;
  if (p->polling || p->callback_active) return SALTS_EBUSY;
  if (!datagram_option(option)) return SALTS_ENOTSUP;
  if (option != CNET_TCP_SOCKET_HOP_LIMIT && value > INT_MAX) value = INT_MAX;
  return cnet_transport_tcp_native_option_set_family((uintptr_t)p->socket_value, p->native_family, option, value);
}

int cnet_datagram_port(const cnet_datagram *datagram, uint16_t *out_port) {
  const cnet_datagram_impl *impl = cnet_datagram_const_get(datagram);
  if (out_port == NULL) return SALTS_EINVAL;
  *out_port = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  *out_port = impl->port;
  return SALTS_OK;
}

int cnet_datagram_receive(cnet_datagram *datagram, size_t demand) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  if (impl == NULL || demand == 0u || !impl->bound) return SALTS_EINVAL;
  if (impl->receive_paused && impl->receive_active) return SALTS_EBUSY;
  impl->receive_paused = false;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  if (demand > SIZE_MAX - impl->receive_demand) return SALTS_ERANGE;
  {
    const bool prior_rearm = impl->receive_rearm;
    impl->receive_demand += demand;
    const int status = cnet_datagram_arm_receive(impl);
    if (status != SALTS_OK) {
      impl->receive_demand -= demand;
      impl->receive_rearm = prior_rearm;
    }
    return status;
  }
}

static int cnet_datagram_send_impl(cnet_datagram *datagram, const cnet_datagram_peer *peer,
                       const void *data, size_t size, uint64_t tag, uint32_t flow_info, bool connected) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  cnet_datagram_send_slot *slot;
  native_io_operation operation;
  size_t native_peer_size = 0u;
  size_t index;
  int status;
  if (impl == NULL || peer == NULL || (data == NULL && size != 0u) || !impl->bound) return SALTS_EINVAL;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  if (size > impl->max_datagram_bytes) return SALTS_EMSGSIZE;
  if (impl->free_send_count == 0u) return SALTS_ENOBUFS;
  index = impl->free_sends[--impl->free_send_count];
  slot = &impl->send_slots[index];
  status = cnet_datagram_peer_to_native(peer, &slot->native_peer, &native_peer_size, flow_info);
  if (status != SALTS_OK) {
    impl->free_sends[impl->free_send_count++] = (uint32_t)index;
    return status;
  }
  if (size) memcpy(slot->data, data, size);
  slot->peer = *peer;
  slot->size = size;
  slot->tag = tag;
  slot->active = true;
  operation = (native_io_operation){.kind = NATIVE_IO_OPERATION_UDP_SEND_TO,
                                    .endpoint = impl->endpoint,
                                    .buffer = slot->data,
                                    .length = size,
                                    .user_data = (uintptr_t)(index + 1u),
                                    .address = connected ? NULL : &slot->native_peer,
                                    .address_capacity = connected ? 0 : sizeof(slot->native_peer),
                                    .address_length = connected ? 0 : native_peer_size};
  status = native_io_backend_submit(&impl->backend, &operation, &slot->request);
  if (status != SALTS_OK) {
    slot->active = false;
    slot->size = 0u;
    slot->tag = 0u;
    impl->free_sends[impl->free_send_count++] = (uint32_t)index;
    return status;
  }
  ++impl->active_send_count;
  return SALTS_OK;
}

int cnet_datagram_send(cnet_datagram *datagram, const cnet_datagram_peer *peer,
                       const void *data, size_t size, uint64_t tag) {
  if (!data || !size) return SALTS_EINVAL;
  return cnet_datagram_send_impl(datagram, peer, data, size, tag, 0, false);
}
int cnet_datagram_send_endpoint(cnet_datagram *d, const cnet_stream_endpoint *endpoint,
                                const void *data, size_t size, uint64_t tag) {
  cnet_stream_endpoint remote = CNET_STREAM_ENDPOINT_INIT; cnet_datagram_peer peer = {0};
  bool connected = endpoint == NULL; int rc;
  if (!endpoint) { rc = cnet_datagram_remote_endpoint(d, &remote); if (rc != SALTS_OK) return rc; endpoint = &remote; }
  if (endpoint->size != sizeof(*endpoint) || endpoint->version != CNET_STREAM_ENDPOINT_API_VERSION) return SALTS_EINVAL;
  peer.family = endpoint->family; peer.port = endpoint->port; peer.scope_id = endpoint->scope_id;
  memcpy(peer.address, endpoint->address, 16);
  return cnet_datagram_send_impl(d, &peer, data, size, tag, endpoint->flow_info, connected);
}

int cnet_datagram_poll(cnet_datagram *datagram, uint32_t timeout_ms, size_t *out_events) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  int status;
  if (out_events == NULL) return SALTS_EINVAL;
  *out_events = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->backend_borrowed) return SALTS_ENOTSUP;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  if (impl->polling || impl->callback_active) return SALTS_EBUSY;
  impl->polling = true;
  status = cnet_datagram_drive(impl, timeout_ms, out_events);
  impl->polling = false;
  return status;
}

int cnet_datagram_wake(cnet_datagram *datagram) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  return native_io_backend_wake(&impl->backend);
}

static void cnet_datagram_cancel_status(cnet_datagram_impl *impl, int status) {
  /* In borrowed mode observe may already have retired the native slot while
   * its terminal is still in the host's batch. CNet retains its own record. */
  if (status == SALTS_OK || status == SALTS_EALREADY ||
      (impl->backend_borrowed && status == SALTS_ENOENT)) return;
  if (impl->stop_status == SALTS_OK) impl->stop_status = status;
}

static int cnet_datagram_cancel_request(cnet_datagram_impl *impl, native_io_request request) {
#if defined(CNET_INTERNAL_TESTING)
  if (impl->test_cancel_status != SALTS_OK) {
    const int status = impl->test_cancel_status;
    impl->test_cancel_status = SALTS_OK;
    return status;
  }
#endif
  return native_io_backend_cancel(&impl->backend, request);
}

static void cnet_datagram_begin_stop(cnet_datagram_impl *impl) {
  impl->stopping = true;
  impl->receive_demand = 0u;
  impl->receive_rearm = false;
  if (impl->receive_active) {
    const int status = cnet_datagram_cancel_request(impl, impl->receive_request);
    cnet_datagram_cancel_status(impl, status);
  }
  for (size_t index = 0u; index < impl->send_capacity; ++index) {
    if (impl->send_slots[index].active) {
      const int status = cnet_datagram_cancel_request(impl, impl->send_slots[index].request);
      cnet_datagram_cancel_status(impl, status);
    }
  }
}

static int cnet_datagram_finish_stop(cnet_datagram_impl *impl) {
  int status;
  if (impl->stopped) return impl->stop_status;
  if (impl->receive_active || impl->active_send_count != 0u) return SALTS_EBUSY;
  cnet_datagram_close_socket(impl);
  if (native_io_endpoint_valid(impl->endpoint)) {
#if defined(CNET_INTERNAL_TESTING)
    if (impl->test_release_status != SALTS_OK) {
      status = impl->test_release_status;
      impl->test_release_status = SALTS_OK;
    } else
#endif
    status = native_io_backend_release_socket(&impl->backend, impl->endpoint);
    if (status != SALTS_OK) {
      if (impl->stop_status == SALTS_OK) impl->stop_status = status;
      return impl->stop_status;
    }
    impl->endpoint = (native_io_endpoint){0};
  }
  if (!impl->backend_borrowed) {
    status = native_io_backend_close(&impl->backend);
    if (status != SALTS_OK) {
      if (impl->stop_status == SALTS_OK) impl->stop_status = status;
      return impl->stop_status;
    }
  }
  impl->stopped = true;
  return impl->stop_status;
}

int cnet_datagram_stop_external(cnet_datagram *datagram, bool *out_stopped) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  int status;
  if (out_stopped == NULL) return SALTS_EINVAL;
  *out_stopped = false;
  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->backend_borrowed) return SALTS_ENOTSUP;
  if (impl->callback_active || impl->polling) return SALTS_EBUSY;
  if (!impl->stopped) cnet_datagram_begin_stop(impl);
  status = cnet_datagram_finish_stop(impl);
  *out_stopped = impl->stopped;
  return impl->stop_status != SALTS_OK ? impl->stop_status : status;
}

int cnet_datagram_advance_external(cnet_datagram *datagram, size_t *out_events) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  int status = SALTS_OK;
  if (out_events == NULL) return SALTS_EINVAL;
  *out_events = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (!impl->backend_borrowed) return SALTS_ENOTSUP;
  if (impl->callback_active || impl->polling) return SALTS_EBUSY;
  impl->polling = true;
  if (impl->stopping) {
    if (!impl->stopped) cnet_datagram_begin_stop(impl);
    status = cnet_datagram_finish_stop(impl);
    if (status == SALTS_EBUSY) status = SALTS_OK;
    if (impl->stop_status != SALTS_OK) status = impl->stop_status;
  } else if (impl->receive_rearm) {
    status = cnet_datagram_arm_receive(impl);
  }
  impl->polling = false;
  return status;
}

int cnet_datagram_route_external_completion(cnet_datagram *datagram,
                                             const native_io_completion *completion,
                                             bool *out_consumed, size_t *out_events) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  size_t index;
  int status;
  if (out_consumed != NULL) *out_consumed = false;
  if (out_events != NULL) *out_events = 0u;
  if (impl == NULL || completion == NULL || out_consumed == NULL || out_events == NULL)
    return SALTS_EINVAL;
  if (!impl->backend_borrowed) return SALTS_ENOTSUP;
  if (impl->callback_active || impl->polling) return SALTS_EBUSY;
  if (!cnet_datagram_find_request(impl, completion->request, &index)) return SALTS_OK;
  *out_consumed = true;
  impl->polling = true;
  status = cnet_datagram_complete(impl, completion, out_events);
  if (impl->stopping && status != SALTS_OK && impl->stop_status == SALTS_OK)
    impl->stop_status = status;
  impl->polling = false;
  return status;
}

int cnet_datagram_stop(cnet_datagram *datagram, uint32_t timeout_ms) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  const uint64_t started_ms = monotonic_ms();
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->backend_borrowed) return SALTS_ENOTSUP;
  if (impl->callback_active || impl->polling) return SALTS_EBUSY;
  if (impl->stopped) return SALTS_OK;
  cnet_datagram_begin_stop(impl);
  while (impl->receive_active || impl->active_send_count != 0u) {
    const uint64_t elapsed_ms = monotonic_ms() - started_ms;
    uint32_t remaining_ms;
    size_t callbacks = 0u;
    int status;
    if (elapsed_ms >= timeout_ms) return SALTS_ETIMEDOUT;
    remaining_ms = (uint32_t)((uint64_t)timeout_ms - elapsed_ms);
    status = cnet_datagram_drive(impl, remaining_ms, &callbacks);
    if (status != SALTS_OK) {
      const uint64_t retry_elapsed_ms = monotonic_ms() - started_ms;
      uint32_t retry_delay_ms = CNET_DATAGRAM_STOP_ERROR_RETRY_MS;
      if (impl->stop_status == SALTS_OK) impl->stop_status = status;
      if (retry_elapsed_ms >= timeout_ms) continue;
      if ((uint64_t)retry_delay_ms > (uint64_t)timeout_ms - retry_elapsed_ms)
        retry_delay_ms = (uint32_t)((uint64_t)timeout_ms - retry_elapsed_ms);
      sleep_ms(retry_delay_ms);
    }
  }
  return cnet_datagram_finish_stop(impl);
}

int cnet_datagram_destroy(cnet_datagram *datagram) {
  cnet_datagram_impl *impl = cnet_datagram_get(datagram);
  int status;
  if (datagram == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;
  if (impl->callback_active || impl->polling) return SALTS_EBUSY;
  if (!impl->stopped) return SALTS_EBUSY;
  if (!impl->backend_borrowed) {
    status = native_io_backend_destroy(&impl->backend);
    if (status != SALTS_OK) return status;
  }
  free(impl->completions);
  free(impl->receive_buffer);
  free(impl->send_storage);
  free(impl->free_sends);
  free(impl->send_slots);
  free(impl);
  datagram->impl = NULL;
  return cnet_module_shutdown();
}
