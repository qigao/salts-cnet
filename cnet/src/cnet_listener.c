#include <cnet/cnet.h>

#include "cnet_client_internal.h"
#include "cnet_module.h"
#include "cnet_transport.h"
#include <native_io_accept.h>

#include <core/clock.h>

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef uintptr_t cnet_listener_socket;
#define CNET_LISTENER_INVALID_SOCKET UINTPTR_MAX

enum {
  CNET_LISTENER_ADDRESS_CAPACITY = 128,
  CNET_LISTENER_TCP_OPTION_COUNT = CNET_TCP_SOCKET_NODELAY + 1
};
_Static_assert(CNET_LISTENER_TCP_OPTION_COUNT <= sizeof(uint16_t) * CHAR_BIT,
               "listener TCP option mask must cover every recorded option");

typedef enum cnet_listener_kind {
  CNET_LISTENER_KIND_NONE = 0,
  CNET_LISTENER_KIND_TCP,
  CNET_LISTENER_KIND_VSOCK
} cnet_listener_kind;

typedef struct cnet_listener_impl {
  cnet_listener_socket socket_value;
  native_io_backend_kind backend;
  cnet_listener_kind kind;
  int native_family;
  uint16_t port;
  size_t backlog;
  uint64_t tcp_option_values[CNET_LISTENER_TCP_OPTION_COUNT];
  uint16_t tcp_option_set_mask;

  native_io_backend *external_backend;
  native_io_endpoint external_endpoint;
  native_io_request external_accept_request;
  uintptr_t external_accepted_socket;
  int external_accept_status;
  bool external_attached;
  bool external_accept_active;

  bool bound;
  bool listening;
  bool closed;
} cnet_listener_impl;

static cnet_listener_impl *cnet_listener_get(cnet_listener *listener) {
  return listener != NULL ? (cnet_listener_impl *)listener->impl : NULL;
}

static const cnet_listener_impl *cnet_listener_const_get(const cnet_listener *listener) {
  return listener != NULL ? (const cnet_listener_impl *)listener->impl : NULL;
}

static int cnet_listener_stream_endpoint(const void *address, size_t size,
                                           cnet_stream_endpoint *out) {
  return cnet_transport_decode_endpoint(address, size, false, out);
}

static int cnet_listener_stream_peer(
    const void *native_peer,
    size_t native_size,
    cnet_stream_peer *peer) {
  cnet_stream_endpoint endpoint = CNET_STREAM_ENDPOINT_INIT;
  int status;

  if (peer == NULL) return SALTS_EINVAL;
  *peer = (cnet_stream_peer){0};
  status = cnet_listener_stream_endpoint(
      native_peer, native_size, &endpoint);
  if (status != SALTS_OK) return status;

  peer->family = endpoint.family;
  peer->port = endpoint.port;
  peer->scope_id = endpoint.scope_id;
  memcpy(peer->address, endpoint.address, sizeof(peer->address));
  return SALTS_OK;
}

static int cnet_listener_native_local_endpoint(cnet_listener_socket socket_value,
    cnet_stream_endpoint *out) {
  native_io_socket_address address;
  size_t length;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  int status = native_io_socket_query(socket_value, false, &address, sizeof(address), &length).status;
  return status == SALTS_OK ? cnet_listener_stream_endpoint(&address, length, out) : status;
}

static int cnet_listener_remote_peer(cnet_listener_socket socket_value, cnet_stream_peer *out) {
  native_io_socket_address address;
  size_t length;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_stream_peer){0};
  int status = native_io_socket_query(socket_value, true, &address, sizeof(address), &length).status;
  return status == SALTS_OK ? cnet_listener_stream_peer(&address, length, out) : status;
}

static int cnet_listener_local_peer(cnet_listener_socket socket_value,
                                    cnet_stream_peer *out_peer) {
  cnet_stream_endpoint endpoint = CNET_STREAM_ENDPOINT_INIT;
  int status;

  if (out_peer == NULL) return SALTS_EINVAL;
  *out_peer = (cnet_stream_peer){0};
  status = cnet_listener_native_local_endpoint(socket_value, &endpoint);
  if (status != SALTS_OK) return status;
  out_peer->family = endpoint.family;
  out_peer->port = endpoint.port;
  out_peer->scope_id = endpoint.scope_id;
  memcpy(out_peer->address, endpoint.address, sizeof(out_peer->address));
  return SALTS_OK;
}

static void cnet_listener_close_native(cnet_listener_impl *impl) {
  if (impl == NULL || impl->socket_value == CNET_LISTENER_INVALID_SOCKET) return;
  (void)native_io_socket_close(impl->socket_value);
  impl->socket_value = CNET_LISTENER_INVALID_SOCKET;
}

static int cnet_listener_set_nonblocking(cnet_listener_socket socket_value) {
  return native_io_socket_nonblocking(socket_value).status;
}

static int cnet_listener_bound_port(cnet_listener_socket socket_value, uint16_t *out_port) {
  cnet_stream_peer peer = {0};
  int status;
  if (out_port == NULL) return SALTS_EINVAL;
  *out_port = 0u;
  status = cnet_listener_local_peer(socket_value, &peer);
  if (status != SALTS_OK) return status;
  *out_port = peer.port;
  return *out_port != 0u ? SALTS_OK : SALTS_EPROTO;
}

int cnet_listener_options_validate(const cnet_listener_options *options) {
  if (options == NULL || options->size != sizeof(*options) ||
      (options->reuse_port != 0 && options->reuse_port != 1))
    return SALTS_EINVAL;
  return SALTS_OK;
}

static int cnet_listener_open_family(cnet_listener *listener, native_io_backend_kind backend,
    int family, size_t backlog_hint, const cnet_listener_options *options) {
  cnet_listener_impl *impl;
  int status;
  if (listener == NULL || listener->impl != NULL || !native_io_backend_kind_supported(backend))
    return SALTS_EINVAL;
  if (family != native_io_socket_domain(NATIVE_IO_SOCKET_IPV4) &&
      family != native_io_socket_domain(NATIVE_IO_SOCKET_IPV6)) return SALTS_EAFNOSUPPORT;
  status = cnet_listener_options_validate(options);
  if (status != SALTS_OK) return status;
  if (options->reuse_port && !native_io_socket_reuse_port_supported()) return SALTS_ENOTSUP;
  status = cnet_module_init();
  if (status != SALTS_OK) return status;
  impl = calloc(1u, sizeof(*impl));
  if (impl == NULL) { (void)cnet_module_shutdown(); return SALTS_ENOMEM; }
  impl->socket_value = UINTPTR_MAX;
  impl->external_accepted_socket = UINTPTR_MAX;
  impl->backend = backend;
  impl->kind = CNET_LISTENER_KIND_TCP;
  impl->native_family = family;
  impl->backlog = backlog_hint;
  status = native_io_socket_create(backend, family, false, &impl->socket_value).status;
  if (status == SALTS_OK)
    status = native_io_socket_listener_prepare(impl->socket_value, options->reuse_port != 0).status;
  if (status != SALTS_OK) {
    cnet_listener_close_native(impl); free(impl); (void)cnet_module_shutdown(); return status;
  }
  listener->impl = impl;
  return SALTS_OK;
}

static int cnet_listener_bind_existing_address(
    cnet_listener *listener,
    const void *address,
    size_t address_length) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  int family;
  int status;

  if (impl == NULL || address == NULL ||
      address_length == 0u)
    return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (impl->bound || impl->listening) return SALTS_EALREADY;

  family = native_io_socket_address_family(address, address_length);
  if (family != impl->native_family)
    return SALTS_EAFNOSUPPORT;

  status = native_io_socket_bind(impl->socket_value, address, address_length).status;
  if (status != SALTS_OK) return status;

  status = cnet_listener_bound_port(
      impl->socket_value, &impl->port);
  if (status != SALTS_OK)
    return status;
  impl->bound = true;
  return SALTS_OK;
}

static int cnet_listener_bind_address(
    cnet_listener *listener, native_io_backend_kind backend,
    const void *address, size_t address_length, size_t backlog_hint,
    const cnet_listener_options *options) {
  cnet_listener_impl *impl;
  int family;
  int status;

  if (listener == NULL || address == NULL ||
      address_length == 0u ||
      listener->impl != NULL)
    return SALTS_EINVAL;
  family = native_io_socket_address_family(address, address_length);

  status = cnet_listener_open_family(
      listener, backend, family, backlog_hint, options);
  if (status != SALTS_OK)
    return status;

  status = cnet_listener_bind_existing_address(
      listener, address, address_length);
  if (status == SALTS_OK)
    return SALTS_OK;

  impl = cnet_listener_get(listener);
  cnet_listener_close_native(impl);
  free(impl);
  listener->impl = NULL;
  (void)cnet_module_shutdown();
  return status;
}

int cnet_listener_open_ex(cnet_listener *listener,
                          native_io_backend_kind backend,
                          cnet_datagram_address_family family,
                          const cnet_listener_options *options) {
  int native_family;

  if (family == CNET_DATAGRAM_ADDRESS_IPV4)
    native_family = native_io_socket_domain(NATIVE_IO_SOCKET_IPV4);
  else if (family == CNET_DATAGRAM_ADDRESS_IPV6)
    native_family = native_io_socket_domain(NATIVE_IO_SOCKET_IPV6);
  else
    return SALTS_EAFNOSUPPORT;

  return cnet_listener_open_family(
      listener, backend, native_family, 0u, options);
}

int cnet_listener_open(cnet_listener *listener,
                       native_io_backend_kind backend,
                       cnet_datagram_address_family family) {
  const cnet_listener_options options =
      CNET_LISTENER_OPTIONS_INIT;
  return cnet_listener_open_ex(
      listener, backend, family, &options);
}

int cnet_listener_bind_open_peer(
    cnet_listener *listener,
    const cnet_stream_peer *local_peer) {
  _Alignas(native_io_socket_address) unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
  size_t address_length = 0u;
  int status;

  status = cnet_transport_stream_peer_address(
      local_peer, true, address, sizeof(address),
      &address_length);
  if (status != SALTS_OK)
    return status;
  return cnet_listener_bind_existing_address(
      listener, address, address_length);
}

int cnet_listener_bind_open_endpoint(
    cnet_listener *listener,
    const cnet_stream_endpoint *local_endpoint) {
  _Alignas(native_io_socket_address) unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
  size_t address_length = 0u;
  int status;

  status = cnet_transport_stream_endpoint_address(
      local_endpoint, true, address, sizeof(address),
      &address_length);
  if (status != SALTS_OK)
    return status;
  return cnet_listener_bind_existing_address(
      listener, address, address_length);
}

int cnet_listener_bind_ex(cnet_listener *listener, const cnet_listener_config *config,
                          const cnet_listener_options *options) {
  _Alignas(native_io_socket_address) unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
  size_t address_length = 0u;
  int status;

  if (listener == NULL || config == NULL || config->host == NULL ||
      config->backlog == 0u || config->backlog > INT_MAX)
    return SALTS_EINVAL;
  status = cnet_transport_parse_bind_address(
      config->host, config->port, address, sizeof(address), &address_length);
  if (status != SALTS_OK) return status;
  return cnet_listener_bind_address(
      listener, config->backend, address, address_length,
      config->backlog, options);
}

int cnet_listener_bind_peer_ex(cnet_listener *listener,
                               native_io_backend_kind backend,
                               const cnet_stream_peer *local_peer,
                               const cnet_listener_options *options) {
  _Alignas(native_io_socket_address) unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
  size_t address_length = 0u;
  int status;

  status = cnet_transport_stream_peer_address(
      local_peer, true, address, sizeof(address), &address_length);
  if (status != SALTS_OK) return status;
  return cnet_listener_bind_address(
      listener, backend, address, address_length, 0u, options);
}

int cnet_listener_bind_peer(cnet_listener *listener,
                            native_io_backend_kind backend,
                            const cnet_stream_peer *local_peer) {
  const cnet_listener_options options = CNET_LISTENER_OPTIONS_INIT;
  return cnet_listener_bind_peer_ex(
      listener, backend, local_peer, &options);
}

int cnet_listener_bind_endpoint_ex(
    cnet_listener *listener,
    native_io_backend_kind backend,
    const cnet_stream_endpoint *local_endpoint,
    const cnet_listener_options *options) {
  _Alignas(native_io_socket_address) unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
  size_t address_length = 0u;
  int status;

  status = cnet_transport_stream_endpoint_address(
      local_endpoint, true, address, sizeof(address),
      &address_length);
  if (status != SALTS_OK) return status;
  return cnet_listener_bind_address(
      listener, backend, address, address_length, 0u, options);
}

int cnet_listener_bind_endpoint(
    cnet_listener *listener,
    native_io_backend_kind backend,
    const cnet_stream_endpoint *local_endpoint) {
  const cnet_listener_options options = CNET_LISTENER_OPTIONS_INIT;
  return cnet_listener_bind_endpoint_ex(
      listener, backend, local_endpoint, &options);
}

int cnet_listener_bind(cnet_listener *listener, const cnet_listener_config *config) {
  const cnet_listener_options options = CNET_LISTENER_OPTIONS_INIT;
  return cnet_listener_bind_ex(listener, config, &options);
}

int cnet_listener_listen(cnet_listener *listener, size_t backlog) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  if (impl == NULL || backlog == 0u || backlog > (size_t)INT_MAX) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (!impl->bound) return SALTS_EBUSY;
  if (impl->listening) return SALTS_EALREADY;
  int status = native_io_socket_listen(impl->socket_value, backlog).status;
  if (status != SALTS_OK) return status;
  impl->backlog = backlog;
  impl->listening = true;
  return SALTS_OK;
}

int cnet_listener_set_backlog(cnet_listener *listener, size_t backlog) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  if (impl == NULL || backlog == 0u || backlog > (size_t)INT_MAX) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (impl->listening) {
    int status = native_io_socket_listen(impl->socket_value, backlog).status;
    if (status != SALTS_OK) return status;
  }
  impl->backlog = backlog;
  return SALTS_OK;
}

int cnet_listener_tcp_option_get(cnet_listener *listener,
                                 cnet_tcp_socket_option option,
                                 uint64_t *out_value) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  if (out_value == NULL) return SALTS_EINVAL;
  *out_value = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  return cnet_transport_tcp_native_option_get_family(
      (uintptr_t)impl->socket_value, impl->native_family,
      option, out_value);
}

int cnet_listener_tcp_option_set(cnet_listener *listener,
                                 cnet_tcp_socket_option option,
                                 uint64_t value) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  int status;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  status = cnet_transport_tcp_native_option_set_family(
      (uintptr_t)impl->socket_value, impl->native_family,
      option, value);
  if (status == SALTS_OK &&
      option >= CNET_TCP_SOCKET_KEEPALIVE_ENABLED &&
      (unsigned int)option < CNET_LISTENER_TCP_OPTION_COUNT) {
    impl->tcp_option_values[(unsigned int)option] = value;
    impl->tcp_option_set_mask =
        (uint16_t)(impl->tcp_option_set_mask |
                   (uint16_t)(1u << (unsigned int)option));
  }
  return status;
}

static int cnet_listener_apply_tcp_options(
    const cnet_listener_impl *impl,
    cnet_listener_socket socket_value) {
  unsigned int option;
  if (impl == NULL) return SALTS_EINVAL;
  for (option = (unsigned int)CNET_TCP_SOCKET_KEEPALIVE_ENABLED;
       option < CNET_LISTENER_TCP_OPTION_COUNT;
       ++option) {
    int status;
    if ((impl->tcp_option_set_mask &
         (uint16_t)(1u << option)) == 0u)
      continue;
    status = cnet_transport_tcp_native_option_set_family(
        (uintptr_t)socket_value, impl->native_family,
        (cnet_tcp_socket_option)option,
        impl->tcp_option_values[option]);
    if (status != SALTS_OK) return status;
  }
  return SALTS_OK;
}

int cnet_listener_connect_endpoint(
    cnet_listener *listener, cnet_client *client,
    const cnet_stream_endpoint *remote_endpoint,
    const cnet_observer *observer,
    cnet_connection *out_connection) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  cnet_stream_endpoint local = CNET_STREAM_ENDPOINT_INIT;
  uintptr_t native_socket;
  int status;
  int shutdown_status;

  if (out_connection == NULL) return SALTS_EINVAL;
  *out_connection = (cnet_connection){0};
  if (impl == NULL || client == NULL || client->impl == NULL ||
      remote_endpoint == NULL ||
      remote_endpoint->size < sizeof(*remote_endpoint) ||
      remote_endpoint->version != CNET_STREAM_ENDPOINT_API_VERSION ||
      observer == NULL || observer->on_state == NULL)
    return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (impl->listening) return SALTS_EBUSY;
  if (remote_endpoint->port == 0u ||
      (remote_endpoint->family != CNET_DATAGRAM_ADDRESS_IPV4 &&
       remote_endpoint->family != CNET_DATAGRAM_ADDRESS_IPV6))
    return SALTS_EINVAL;

  if (!impl->bound) {
    cnet_stream_endpoint any = CNET_STREAM_ENDPOINT_INIT;
    any.family = remote_endpoint->family;
    status = cnet_listener_bind_open_endpoint(listener, &any);
    if (status != SALTS_OK) return status;
    impl = cnet_listener_get(listener);
    if (impl == NULL) return SALTS_EPROTO;
  }

  status = cnet_listener_native_local_endpoint(
      impl->socket_value, &local);
  if (status != SALTS_OK) return status;
  if (local.family != remote_endpoint->family)
    return SALTS_EAFNOSUPPORT;

  native_socket = (uintptr_t)impl->socket_value;
  impl->socket_value = CNET_LISTENER_INVALID_SOCKET;
  listener->impl = NULL;
  free(impl);

  status = cnet_client_adopt_bound_tcp_connect_endpoint(
      client, native_socket, remote_endpoint,
      observer, out_connection);
  shutdown_status = cnet_module_shutdown();
  return status != SALTS_OK ? status : shutdown_status;
}

int cnet_listener_connect_peer(cnet_listener *listener, cnet_client *client,
                               const cnet_stream_peer *remote_peer,
                               const cnet_observer *observer,
                               cnet_connection *out_connection) {
  cnet_stream_endpoint endpoint = CNET_STREAM_ENDPOINT_INIT;
  if (remote_peer == NULL) {
    if (out_connection != NULL)
      *out_connection = (cnet_connection){0};
    return SALTS_EINVAL;
  }
  endpoint.family = remote_peer->family;
  endpoint.port = remote_peer->port;
  endpoint.scope_id = remote_peer->scope_id;
  memcpy(endpoint.address, remote_peer->address, sizeof(endpoint.address));
  return cnet_listener_connect_endpoint(
      listener, client, &endpoint, observer, out_connection);
}

int cnet_listener_init_ex(cnet_listener *listener, const cnet_listener_config *config,
                          const cnet_listener_options *options) {
  int status = cnet_listener_bind_ex(listener, config, options);
  if (status != SALTS_OK) return status;
  status = cnet_listener_listen(listener, config->backlog);
  if (status != SALTS_OK) {
    (void)cnet_listener_close(listener);
    (void)cnet_listener_destroy(listener);
  }
  return status;
}

int cnet_listener_init(cnet_listener *listener, const cnet_listener_config *config) {
  const cnet_listener_options options = CNET_LISTENER_OPTIONS_INIT;
  return cnet_listener_init_ex(listener, config, &options);
}

int cnet_listener_local(const cnet_listener *listener, cnet_stream_peer *out_local) {
  const cnet_listener_impl *impl = cnet_listener_const_get(listener);
  if (out_local == NULL) return SALTS_EINVAL;
  *out_local = (cnet_stream_peer){0};
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (!impl->bound) return SALTS_EBUSY;
  return cnet_listener_local_peer(impl->socket_value, out_local);
}

int cnet_listener_local_endpoint(
    const cnet_listener *listener,
    cnet_stream_endpoint *out_local) {
  const cnet_listener_impl *impl = cnet_listener_const_get(listener);
  if (out_local == NULL) return SALTS_EINVAL;
  *out_local = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (!impl->bound) return SALTS_EBUSY;
  return cnet_listener_native_local_endpoint(
      impl->socket_value, out_local);
}

int cnet_listener_init_vsock(cnet_listener *listener, const cnet_vsock_listener_config *config) {
  native_io_socket_address address;
  size_t length;
  if (!listener || listener->impl || !config || config->size != sizeof(*config) ||
      !config->backlog || config->backlog > INT_MAX || !native_io_backend_kind_supported(config->backend))
    return SALTS_EINVAL;
  if (!cnet_transport_vsock_supported(config->backend)) return SALTS_ENOTSUP;
  int status = cnet_transport_parse_vsock_address(config->cid, config->port, true,
      &address, sizeof(address), &length);
  if (status != SALTS_OK) return status;
  status = cnet_module_init();
  if (status != SALTS_OK) return status;
  cnet_listener_impl *impl = calloc(1, sizeof(*impl));
  if (!impl) { (void)cnet_module_shutdown(); return SALTS_ENOMEM; }
  impl->socket_value = UINTPTR_MAX;
  impl->backend = config->backend;
  impl->kind = CNET_LISTENER_KIND_VSOCK;
  impl->listening = true;
  status = native_io_socket_create(config->backend, native_io_socket_domain(NATIVE_IO_SOCKET_VSOCK),
      false, &impl->socket_value).status;
  if (status == SALTS_OK) status = cnet_listener_set_nonblocking(impl->socket_value);
  if (status == SALTS_OK) status = native_io_socket_bind(impl->socket_value, &address, length).status;
  if (status == SALTS_OK) status = native_io_socket_listen(impl->socket_value, config->backlog).status;
  if (status != SALTS_OK) {
    cnet_listener_close_native(impl); free(impl); (void)cnet_module_shutdown(); return status;
  }
  listener->impl = impl;
  return SALTS_OK;
}

int cnet_listener_port(const cnet_listener *listener, uint16_t *out_port) {
  const cnet_listener_impl *impl = cnet_listener_const_get(listener);
  if (out_port == NULL) return SALTS_EINVAL;
  *out_port = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (!impl->bound) return SALTS_EBUSY;
  *out_port = impl->port;
  return SALTS_OK;
}

int cnet_listener_vsock_local(const cnet_listener *listener, cnet_vsock_peer *out) {
  const cnet_listener_impl *impl = cnet_listener_const_get(listener);
  if (!out) return SALTS_EINVAL;
  *out = (cnet_vsock_peer){0};
  if (!impl) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_VSOCK) return SALTS_ENOTSUP;
  native_io_socket_address address;
  size_t length;
  int status = native_io_socket_query(impl->socket_value, false, &address, sizeof(address), &length).status;
  if (status != SALTS_OK) return status;
  return native_io_socket_decode_vsock(&address, length, &out->cid, &out->port);
}

int cnet_listener_attach_external(
    cnet_listener *listener,
    native_io_backend *borrowed_backend) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  native_io_backend_config backend_config = {0};
  native_io_endpoint endpoint = {0};
  int status;

  if (impl == NULL || borrowed_backend == NULL ||
      borrowed_backend->impl == NULL)
    return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP)
    return SALTS_ENOTSUP;
  if (!impl->listening) return SALTS_EBUSY;
  if (impl->external_attached)
    return impl->external_backend == borrowed_backend
               ? SALTS_EALREADY
               : SALTS_EBUSY;
  if (!native_io_backend_get_config(
          borrowed_backend, &backend_config) ||
      backend_config.kind != impl->backend)
    return SALTS_EINVAL;

  status = native_io_backend_attach_socket(
      borrowed_backend, (uintptr_t)impl->socket_value,
      &endpoint);
  if (status != SALTS_OK)
    return status;

  impl->external_backend = borrowed_backend;
  impl->external_endpoint = endpoint;
  impl->external_accept_request = (native_io_request){0};
  impl->external_accepted_socket = UINTPTR_MAX;
  impl->external_accept_status = SALTS_OK;
  impl->external_accept_active = false;
  impl->external_attached = true;
  return SALTS_OK;
}

int cnet_listener_submit_external_accept(
    cnet_listener *listener,
    native_io_request *out_request) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  native_io_request request = {0};
  int status;

  if (out_request == NULL)
    return SALTS_EINVAL;
  *out_request = (native_io_request){0};
  if (impl == NULL)
    return SALTS_EINVAL;
  if (impl->closed)
    return SALTS_ESHUTDOWN;
  if (!impl->external_attached ||
      impl->external_backend == NULL)
    return SALTS_ENOTSUP;
  if (!impl->listening)
    return SALTS_EBUSY;

  if (impl->external_accept_active) {
    *out_request = impl->external_accept_request;
    return SALTS_OK;
  }
  if (impl->external_accepted_socket != UINTPTR_MAX ||
      impl->external_accept_status != SALTS_OK)
    return SALTS_EALREADY;

  status = native_io_internal_submit_stream_accept(
      impl->external_backend,
      impl->external_endpoint,
      &request);
  if (status != SALTS_OK)
    return status;

  impl->external_accept_request = request;
  impl->external_accept_active = true;
  *out_request = request;
  return SALTS_OK;
}

int cnet_listener_route_external_completion(
    cnet_listener *listener,
    const native_io_completion *completion,
    bool *out_consumed) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  uintptr_t accepted = UINTPTR_MAX;
  int status;

  if (out_consumed == NULL || completion == NULL)
    return SALTS_EINVAL;
  *out_consumed = false;
  if (impl == NULL)
    return SALTS_EINVAL;
  if (!impl->external_attached ||
      !impl->external_accept_active)
    return SALTS_OK;
  if (completion->request.slot !=
          impl->external_accept_request.slot ||
      completion->request.generation !=
          impl->external_accept_request.generation)
    return SALTS_OK;
  if (completion->endpoint.slot !=
          impl->external_endpoint.slot ||
      completion->endpoint.generation !=
          impl->external_endpoint.generation)
    return SALTS_EPROTO;

  *out_consumed = true;
  impl->external_accept_active = false;
  impl->external_accept_request = (native_io_request){0};

  if (completion->kind == NATIVE_IO_COMPLETION_OK &&
      completion->status == SALTS_OK) {
    status = native_io_internal_take_stream_accept(
        impl->external_backend,
        completion->request,
        &accepted);
    if (status != SALTS_OK)
      return status;
    if (accepted == UINTPTR_MAX)
      return SALTS_EPROTO;
    if (impl->external_accepted_socket != UINTPTR_MAX) {
      cnet_transport_close_socket(accepted);
      return SALTS_EPROTO;
    }
    impl->external_accepted_socket = accepted;
    impl->external_accept_status = SALTS_OK;
    return SALTS_OK;
  }

  /*
   * Cancellation belongs to the logical subscription lifetime, not to the
   * listener's next accept result. It simply retires this request so another
   * subscribe may submit a fresh one.
   */
  if (completion->kind == NATIVE_IO_COMPLETION_CANCELLED ||
      completion->status == SALTS_ECANCELED) {
    impl->external_accept_status = SALTS_OK;
    return SALTS_OK;
  }

  impl->external_accept_status =
      completion->status != SALTS_OK
          ? completion->status
          : SALTS_EIO;
  return SALTS_OK;
}

int cnet_listener_wait(cnet_listener *listener, uint32_t timeout_ms, int *out_ready) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  if (!out_ready) return SALTS_EINVAL;
  *out_ready = 0;
  if (!impl) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->external_attached) return SALTS_ENOTSUP;
  if (impl->kind == CNET_LISTENER_KIND_TCP && !impl->listening) return SALTS_EBUSY;
  return native_io_socket_wait(impl->socket_value, timeout_ms, out_ready).status;
}

int cnet_listener_accept(cnet_listener *listener, cnet_client *client,
                         const cnet_observer *observer, cnet_connection *out_connection) {
  cnet_stream_peer peer;
  return cnet_listener_accept_peer(listener, client, observer, out_connection, &peer);
}

int cnet_listener_accept_detached(cnet_listener *listener,
                                  cnet_accepted_stream *out_accepted) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  native_io_socket_address native_peer;
  size_t native_peer_size = 0;
  cnet_listener_socket accepted;
  cnet_stream_peer peer = {0};
  int status;

  if (out_accepted == NULL) return SALTS_EINVAL;
  if (out_accepted->internal_active != 0u) return SALTS_EALREADY;
  out_accepted->peer = (cnet_stream_peer){0};
  out_accepted->internal_socket = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (!impl->listening) return SALTS_EBUSY;

  if (impl->external_attached) {
    if (impl->external_accept_status != SALTS_OK) {
      status = impl->external_accept_status;
      impl->external_accept_status = SALTS_OK;
      return status;
    }
    if (impl->external_accepted_socket == UINTPTR_MAX)
      return SALTS_ETIMEDOUT;

    accepted = (cnet_listener_socket)impl->external_accepted_socket;
    impl->external_accepted_socket = UINTPTR_MAX;
    status = cnet_listener_remote_peer(accepted, &peer);
    if (status != SALTS_OK) {
      cnet_transport_close_socket((uintptr_t)accepted);
      return status;
    }
  } else {
    native_io_socket_result result;
    do {
      result = native_io_socket_accept(impl->socket_value, &accepted,
          &native_peer, sizeof(native_peer), &native_peer_size);
    } while (result.status == SALTS_EINTR);
    if (result.status != SALTS_OK) return result.status;
    status = cnet_listener_stream_peer(&native_peer, (size_t)native_peer_size,
                                       &peer);
    if (status != SALTS_OK) {
      cnet_transport_close_socket((uintptr_t)accepted);
      return status;
    }
  }

  status = cnet_listener_apply_tcp_options(impl, accepted);
  if (status != SALTS_OK) {
    cnet_transport_close_socket((uintptr_t)accepted);
    return status;
  }

  out_accepted->internal_socket = (uintptr_t)accepted;
  out_accepted->peer = peer;
  out_accepted->internal_active = 1u;
  return SALTS_OK;
}

int cnet_accepted_stream_close(cnet_accepted_stream *accepted) {
  uintptr_t native_socket;
  if (accepted == NULL) return SALTS_EINVAL;
  if (accepted->internal_active == 0u) return SALTS_EALREADY;
  native_socket = accepted->internal_socket;
  accepted->internal_socket = 0u;
  accepted->internal_active = 0u;
  cnet_transport_close_socket(native_socket);
  return SALTS_OK;
}

int cnet_listener_accept_peer(cnet_listener *listener, cnet_client *client,
                              const cnet_observer *observer,
                              cnet_connection *out_connection,
                              cnet_stream_peer *out_peer) {
  cnet_accepted_stream accepted = CNET_ACCEPTED_STREAM_INIT;
  uintptr_t native_socket;
  int status;
  if (out_connection == NULL) return SALTS_EINVAL;
  *out_connection = (cnet_connection){0};
  if (out_peer != NULL) *out_peer = (cnet_stream_peer){0};
  if (client == NULL || observer == NULL || observer->on_state == NULL ||
      out_peer == NULL)
    return SALTS_EINVAL;

  status = cnet_listener_accept_detached(listener, &accepted);
  if (status != SALTS_OK) return status;
  *out_peer = accepted.peer;
  native_socket = accepted.internal_socket;
  accepted.internal_socket = 0u;
  accepted.internal_active = 0u;
  /* Direct accept preserves listener policy; detached handoff applies client policy. */
  status = cnet_client_adopt_tcp(client, native_socket, observer, out_connection);
  if (status != SALTS_OK) *out_peer = (cnet_stream_peer){0};
  return status;
}

int cnet_listener_accept_vsock(cnet_listener *listener, cnet_client *client,
                               const cnet_observer *observer,
                               cnet_connection *out_connection) {
  cnet_vsock_peer peer;
  return cnet_listener_accept_vsock_peer(listener, client, observer, out_connection, &peer);
}

int cnet_listener_accept_vsock_peer(cnet_listener *listener, cnet_client *client,
    const cnet_observer *observer, cnet_connection *out_connection, cnet_vsock_peer *out_peer) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  if (out_peer) *out_peer = (cnet_vsock_peer){0};
  if (!out_connection) return SALTS_EINVAL;
  *out_connection = (cnet_connection){0};
  if (!impl || !client || !observer || !observer->on_state || !out_peer) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_VSOCK) return SALTS_ENOTSUP;
  native_io_socket_address peer;
  size_t length;
  uintptr_t accepted;
  native_io_socket_result result;
  do { result = native_io_socket_accept(impl->socket_value, &accepted, &peer, sizeof(peer), &length); }
  while (result.status == SALTS_EINTR);
  if (result.status != SALTS_OK) return result.status;
  int status = native_io_socket_decode_vsock(&peer, length, &out_peer->cid, &out_peer->port);
  if (status != SALTS_OK) { cnet_transport_close_socket(accepted); return status; }
  status = cnet_client_adopt_vsock(client, accepted, observer, out_connection);
  if (status != SALTS_OK) *out_peer = (cnet_vsock_peer){0};
  return status;
}

int cnet_listener_accept_tls(cnet_listener *listener, cnet_client *client,
                             const cnet_tls_server *server,
                             const cnet_observer *observer,
                             cnet_connection *out_connection) {
  cnet_stream_peer peer;
  return cnet_listener_accept_tls_peer(listener, client, server, observer,
                                       out_connection, &peer);
}

int cnet_listener_accept_tls_peer(cnet_listener *listener, cnet_client *client,
                                  const cnet_tls_server *server,
                                  const cnet_observer *observer,
                                  cnet_connection *out_connection,
                                  cnet_stream_peer *out_peer) {
  cnet_accepted_stream accepted = CNET_ACCEPTED_STREAM_INIT;
  uintptr_t native_socket;
  int status;
  if (out_connection == NULL) return SALTS_EINVAL;
  *out_connection = (cnet_connection){0};
  if (out_peer != NULL) *out_peer = (cnet_stream_peer){0};
  if (client == NULL || server == NULL ||
      cnet_tls_server_context(server) == NULL || observer == NULL ||
      observer->on_state == NULL || out_peer == NULL)
    return SALTS_EINVAL;

  status = cnet_listener_accept_detached(listener, &accepted);
  if (status != SALTS_OK) return status;
  *out_peer = accepted.peer;
  native_socket = accepted.internal_socket;
  accepted.internal_socket = 0u;
  accepted.internal_active = 0u;
  status = cnet_client_adopt_tls_server(client, native_socket,
                                       cnet_tls_server_context(server), observer,
                                       out_connection);
  if (status != SALTS_OK) *out_peer = (cnet_stream_peer){0};
  return status;
}

int cnet_listener_close(cnet_listener *listener) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  int status;

  if (impl == NULL) return SALTS_EINVAL;

  if (impl->closed) {
    if (!impl->external_attached)
      return SALTS_EALREADY;
    status = native_io_backend_release_socket(
        impl->external_backend, impl->external_endpoint);
    if (status != SALTS_OK)
      return status;
    impl->external_attached = false;
    impl->external_backend = NULL;
    impl->external_endpoint = (native_io_endpoint){0};
    return SALTS_OK;
  }

  if (impl->external_accept_active) {
    status = native_io_backend_cancel(
        impl->external_backend,
        impl->external_accept_request);
    if (status == SALTS_OK ||
        status == SALTS_EALREADY ||
        status == SALTS_ENOENT)
      return SALTS_EBUSY;
    return status;
  }

  cnet_listener_close_native(impl);
  impl->closed = true;

  if (impl->external_attached) {
    status = native_io_backend_release_socket(
        impl->external_backend, impl->external_endpoint);
    if (status != SALTS_OK)
      return status;
    impl->external_attached = false;
    impl->external_backend = NULL;
    impl->external_endpoint = (native_io_endpoint){0};
  }
  return SALTS_OK;
}

int cnet_listener_destroy(cnet_listener *listener) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  int status;
  if (listener == NULL) return SALTS_EINVAL;
  if (impl == NULL) return SALTS_OK;
  if (!impl->closed || impl->external_attached ||
      impl->external_accept_active)
    return SALTS_EBUSY;

  if (impl->external_accepted_socket != UINTPTR_MAX) {
    cnet_transport_close_socket(
        impl->external_accepted_socket);
    impl->external_accepted_socket = UINTPTR_MAX;
  }

  free(impl);
  listener->impl = NULL;
  status = cnet_module_shutdown();
  return status;
}
