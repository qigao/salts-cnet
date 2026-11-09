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

#if defined(_WIN32)
// clang-format off
  #include <winsock2.h>
  #include <windows.h>
  #include <ws2tcpip.h>
// clang-format on
typedef SOCKET cnet_listener_socket;
  #define CNET_LISTENER_INVALID_SOCKET INVALID_SOCKET
#else
  #include <errno.h>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <sys/socket.h>
  #if defined(__linux__)
    #include <linux/vm_sockets.h>
  #endif
  #include <unistd.h>
typedef int cnet_listener_socket;
  #define CNET_LISTENER_INVALID_SOCKET (-1)
#endif

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

#if defined(__linux__)
_Static_assert(sizeof(struct sockaddr_vm) <= CNET_LISTENER_ADDRESS_CAPACITY,
               "CNet listener address storage must hold sockaddr_vm");
#endif

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

static int cnet_listener_native_status(int error) {
#if defined(_WIN32)
  if (error == WSAEADDRINUSE) return SALTS_EADDRINUSE;
  if (error == WSAEADDRNOTAVAIL) return SALTS_EADDRNOTAVAIL;
  if (error == WSAEAFNOSUPPORT) return SALTS_EAFNOSUPPORT;
  if (error == WSAEALREADY) return SALTS_EALREADY;
  if (error == WSAEBADF) return SALTS_EBADF;
  if (error == WSAEACCES) return SALTS_EPERM;
  if (error == WSAECONNABORTED) return SALTS_ECONNABORTED;
  if (error == WSAECONNREFUSED) return SALTS_ECONNREFUSED;
  if (error == WSAECONNRESET) return SALTS_ECONNRESET;
  if (error == WSAEDESTADDRREQ) return SALTS_EDESTADDRREQ;
  if (error == WSAEFAULT) return SALTS_EFAULT;
  if (error == WSAEHOSTUNREACH) return SALTS_EHOSTUNREACH;
  if (error == WSAEINTR) return SALTS_EINTR;
  if (error == WSAEINVAL) return SALTS_EINVAL;
  if (error == WSAEISCONN) return SALTS_EISCONN;
  if (error == WSAEMFILE) return SALTS_EMFILE;
  if (error == WSAEMSGSIZE) return SALTS_EMSGSIZE;
  if (error == WSAENETDOWN) return SALTS_ENETDOWN;
  if (error == WSAENETUNREACH) return SALTS_ENETUNREACH;
  if (error == WSAENOBUFS) return SALTS_ENOBUFS;
  if (error == WSAENOPROTOOPT) return SALTS_ENOPROTOOPT;
  if (error == WSAENOTCONN) return SALTS_ENOTCONN;
  if (error == WSAENOTSOCK) return SALTS_ENOTSOCK;
  if (error == WSAEOPNOTSUPP) return SALTS_ENOTSUP;
  if (error == WSAEPROTONOSUPPORT) return SALTS_EPROTONOSUPPORT;
  if (error == WSAEPROTOTYPE) return SALTS_EPROTOTYPE;
  if (error == WSAESHUTDOWN) return SALTS_ESHUTDOWN;
  if (error == WSAETIMEDOUT) return SALTS_ETIMEDOUT;
  if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) return SALTS_EBUSY;
#else
  if (error == EADDRINUSE) return SALTS_EADDRINUSE;
  if (error == EADDRNOTAVAIL) return SALTS_EADDRNOTAVAIL;
  if (error == EAFNOSUPPORT) return SALTS_EAFNOSUPPORT;
  if (error == EALREADY) return SALTS_EALREADY;
  if (error == EBADF) return SALTS_EBADF;
  if (error == EBUSY) return SALTS_EBUSY;
  if (error == EACCES || error == EPERM) return SALTS_EPERM;
  if (error == ECONNABORTED) return SALTS_ECONNABORTED;
  if (error == ECONNREFUSED) return SALTS_ECONNREFUSED;
  if (error == ECONNRESET) return SALTS_ECONNRESET;
  if (error == EDESTADDRREQ) return SALTS_EDESTADDRREQ;
  if (error == EFAULT) return SALTS_EFAULT;
  if (error == EHOSTUNREACH) return SALTS_EHOSTUNREACH;
  if (error == EINTR) return SALTS_EINTR;
  if (error == EINVAL) return SALTS_EINVAL;
  if (error == EISCONN) return SALTS_EISCONN;
  if (error == EMFILE) return SALTS_EMFILE;
  if (error == EMSGSIZE) return SALTS_EMSGSIZE;
  if (error == ENETDOWN) return SALTS_ENETDOWN;
  if (error == ENETUNREACH) return SALTS_ENETUNREACH;
  if (error == ENFILE) return SALTS_ENFILE;
  if (error == ENODEV) return SALTS_ENODEV;
  if (error == ENOBUFS) return SALTS_ENOBUFS;
  if (error == ENOMEM) return SALTS_ENOMEM;
  if (error == ENOPROTOOPT) return SALTS_ENOPROTOOPT;
  if (error == ENOTCONN) return SALTS_ENOTCONN;
  if (error == ENOTSOCK) return SALTS_ENOTSOCK;
  if (error == EOPNOTSUPP) return SALTS_ENOTSUP;
  if (error == EPROTONOSUPPORT) return SALTS_EPROTONOSUPPORT;
  if (error == EPROTOTYPE) return SALTS_EPROTOTYPE;
  if (error == EPIPE) return SALTS_EPIPE;
  if (error == ETIMEDOUT) return SALTS_ETIMEDOUT;
  if (error == EAGAIN || error == EWOULDBLOCK || error == EINPROGRESS) return SALTS_EBUSY;
#endif
  return SALTS_EIO;
}

static int cnet_listener_native_error(void) {
#if defined(_WIN32)
  return cnet_listener_native_status(WSAGetLastError());
#else
  return cnet_listener_native_status(errno);
#endif
}

static bool cnet_listener_would_block(void) {
#if defined(_WIN32)
  return WSAGetLastError() == WSAEWOULDBLOCK;
#else
  return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static int cnet_listener_stream_endpoint(
    const struct sockaddr_storage *native_peer,
    size_t native_size,
    cnet_stream_endpoint *endpoint) {
  if (native_peer == NULL || endpoint == NULL)
    return SALTS_EINVAL;
  *endpoint = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;

  if (native_peer->ss_family == AF_INET &&
      native_size >= sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *address =
        (const struct sockaddr_in *)native_peer;
    endpoint->family = CNET_DATAGRAM_ADDRESS_IPV4;
    endpoint->port = ntohs(address->sin_port);
    memcpy(endpoint->address, &address->sin_addr, 4u);
    return SALTS_OK;
  }

  if (native_peer->ss_family == AF_INET6 &&
      native_size >= sizeof(struct sockaddr_in6)) {
    const struct sockaddr_in6 *address =
        (const struct sockaddr_in6 *)native_peer;
    endpoint->family = CNET_DATAGRAM_ADDRESS_IPV6;
    endpoint->port = ntohs(address->sin6_port);
    endpoint->flow_info = address->sin6_flowinfo;
    endpoint->scope_id = address->sin6_scope_id;
    memcpy(endpoint->address, &address->sin6_addr, 16u);
    return SALTS_OK;
  }

  return SALTS_EAFNOSUPPORT;
}

static int cnet_listener_stream_peer(
    const struct sockaddr_storage *native_peer,
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

static int cnet_listener_native_local_endpoint(
    cnet_listener_socket socket_value,
    cnet_stream_endpoint *out_endpoint) {
  struct sockaddr_storage address;
#if defined(_WIN32)
  int address_length = (int)sizeof(address);
#else
  socklen_t address_length = (socklen_t)sizeof(address);
#endif
  if (out_endpoint == NULL) return SALTS_EINVAL;
  *out_endpoint = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  memset(&address, 0, sizeof(address));
  if (getsockname(
          socket_value, (struct sockaddr *)&address,
          &address_length) != 0)
    return cnet_listener_native_error();
  return cnet_listener_stream_endpoint(
      &address, (size_t)address_length, out_endpoint);
}

static int cnet_listener_remote_peer(
    cnet_listener_socket socket_value,
    cnet_stream_peer *out_peer) {
  struct sockaddr_storage address;
#if defined(_WIN32)
  int address_length = (int)sizeof(address);
#else
  socklen_t address_length = (socklen_t)sizeof(address);
#endif
  if (out_peer == NULL) return SALTS_EINVAL;
  *out_peer = (cnet_stream_peer){0};
  memset(&address, 0, sizeof(address));
  if (getpeername(
          socket_value, (struct sockaddr *)&address,
          &address_length) != 0)
    return cnet_listener_native_error();
  return cnet_listener_stream_peer(
      &address, (size_t)address_length, out_peer);
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
#if defined(_WIN32)
  (void)closesocket(impl->socket_value);
#else
  (void)close(impl->socket_value);
#endif
  impl->socket_value = CNET_LISTENER_INVALID_SOCKET;
}

static int cnet_listener_set_nonblocking(cnet_listener_socket socket_value) {
#if defined(_WIN32)
  u_long enabled = 1u;
  if (ioctlsocket(socket_value, FIONBIO, &enabled) == 0) return SALTS_OK;
#else
  const int flags = fcntl(socket_value, F_GETFL, 0);
  if (flags >= 0 && fcntl(socket_value, F_SETFL, flags | O_NONBLOCK) == 0) return SALTS_OK;
#endif
  return cnet_listener_native_error();
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

static int cnet_listener_open_family(
    cnet_listener *listener, native_io_backend_kind backend,
    int family, size_t backlog_hint,
    const cnet_listener_options *options) {
  cnet_listener_impl *impl;
  int status;
#if !defined(_WIN32)
  const int reuse_address = 1;
#endif

  if (listener == NULL || listener->impl != NULL ||
      !native_io_backend_kind_supported(backend))
    return SALTS_EINVAL;
  if (family != AF_INET && family != AF_INET6)
    return SALTS_EAFNOSUPPORT;
  status = cnet_listener_options_validate(options);
  if (status != SALTS_OK) return status;
#if !defined(SO_REUSEPORT)
  if (options->reuse_port) return SALTS_ENOTSUP;
#endif

  status = cnet_module_init();
  if (status != SALTS_OK) return status;
  impl = (cnet_listener_impl *)calloc(1u, sizeof(*impl));
  if (impl == NULL) {
    (void)cnet_module_shutdown();
    return SALTS_ENOMEM;
  }

  impl->socket_value = CNET_LISTENER_INVALID_SOCKET;
  impl->external_accepted_socket = UINTPTR_MAX;
  impl->external_accept_status = SALTS_OK;
  impl->backend = backend;
  impl->kind = CNET_LISTENER_KIND_TCP;
  impl->native_family = family;
  impl->backlog = backlog_hint;
#if defined(_WIN32)
  if (backend != NATIVE_IO_BACKEND_IOCP) status = SALTS_ENOTSUP;
  else {
    impl->socket_value =
        WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0u, WSA_FLAG_OVERLAPPED);
    status = impl->socket_value != CNET_LISTENER_INVALID_SOCKET
                 ? SALTS_OK
                 : cnet_listener_native_error();
  }
#else
  impl->socket_value = socket(family, SOCK_STREAM, IPPROTO_TCP);
  status = impl->socket_value != CNET_LISTENER_INVALID_SOCKET
               ? SALTS_OK
               : cnet_listener_native_error();
  if (status == SALTS_OK &&
      setsockopt(impl->socket_value, SOL_SOCKET, SO_REUSEADDR,
                 &reuse_address, (socklen_t)sizeof(reuse_address)) != 0)
    status = cnet_listener_native_error();
#endif
#if defined(SO_REUSEPORT)
  if (status == SALTS_OK && options->reuse_port) {
    const int reuse_port = 1;
#if defined(_WIN32)
    if (setsockopt(impl->socket_value, SOL_SOCKET, SO_REUSEPORT,
                   (const char *)&reuse_port,
                   (int)sizeof(reuse_port)) != 0)
#else
    if (setsockopt(impl->socket_value, SOL_SOCKET, SO_REUSEPORT,
                   &reuse_port, (socklen_t)sizeof(reuse_port)) != 0)
#endif
      status = cnet_listener_native_error();
  }
#endif
  if (status == SALTS_OK)
    status = cnet_listener_set_nonblocking(impl->socket_value);
  if (status != SALTS_OK) {
    cnet_listener_close_native(impl);
    free(impl);
    (void)cnet_module_shutdown();
    return status;
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
      address_length < sizeof(struct sockaddr))
    return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (impl->bound || impl->listening) return SALTS_EALREADY;

  family = ((const struct sockaddr *)address)->sa_family;
  if (family != impl->native_family)
    return SALTS_EAFNOSUPPORT;

  if (bind(impl->socket_value, (const struct sockaddr *)address,
           (int)address_length) != 0)
    return cnet_listener_native_error();

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
      address_length < sizeof(struct sockaddr) ||
      listener->impl != NULL)
    return SALTS_EINVAL;
  family = ((const struct sockaddr *)address)->sa_family;

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
    native_family = AF_INET;
  else if (family == CNET_DATAGRAM_ADDRESS_IPV6)
    native_family = AF_INET6;
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
  unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
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
  unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
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
  unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
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
  unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
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
  unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
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
  if (listen(impl->socket_value, (int)backlog) != 0) return cnet_listener_native_error();
  impl->backlog = backlog;
  impl->listening = true;
  return SALTS_OK;
}

int cnet_listener_set_backlog(cnet_listener *listener, size_t backlog) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  if (impl == NULL || backlog == 0u || backlog > (size_t)INT_MAX) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_TCP) return SALTS_ENOTSUP;
  if (impl->listening && listen(impl->socket_value, (int)backlog) != 0)
    return cnet_listener_native_error();
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

int cnet_listener_init_vsock(cnet_listener *listener,
                             const cnet_vsock_listener_config *config) {
  cnet_listener_impl *impl;
  unsigned char address[CNET_LISTENER_ADDRESS_CAPACITY];
  size_t address_length = 0u;
  int status;

  if (listener == NULL || config == NULL) return SALTS_EINVAL;
  if (listener->impl != NULL) return SALTS_EALREADY;
  if (config->size != sizeof(*config) || config->backlog == 0u || config->backlog > INT_MAX ||
      !native_io_backend_kind_supported(config->backend))
    return SALTS_EINVAL;
  if (!cnet_transport_vsock_supported(config->backend)) return SALTS_ENOTSUP;
#if defined(__linux__)
  status = cnet_transport_parse_vsock_address(config->cid, config->port, true, address,
                                              sizeof(address), &address_length);
  if (status != SALTS_OK) return status;
  status = cnet_module_init();
  if (status != SALTS_OK) return status;
  impl = (cnet_listener_impl *)calloc(1u, sizeof(*impl));
  if (impl == NULL) {
    (void)cnet_module_shutdown();
    return SALTS_ENOMEM;
  }
  impl->socket_value = CNET_LISTENER_INVALID_SOCKET;
  impl->backend = config->backend;
  impl->kind = CNET_LISTENER_KIND_VSOCK;
  impl->listening = true;
  impl->socket_value = socket(AF_VSOCK, SOCK_STREAM, 0);
  status = impl->socket_value != CNET_LISTENER_INVALID_SOCKET ? SALTS_OK
                                                              : cnet_listener_native_error();
  if (status == SALTS_OK) status = cnet_listener_set_nonblocking(impl->socket_value);
  if (status == SALTS_OK &&
      bind(impl->socket_value, (const struct sockaddr *)address, (socklen_t)address_length) != 0)
    status = cnet_listener_native_error();
  if (status == SALTS_OK && listen(impl->socket_value, (int)config->backlog) != 0)
    status = cnet_listener_native_error();
  if (status != SALTS_OK) {
    cnet_listener_close_native(impl);
    free(impl);
    (void)cnet_module_shutdown();
    return status;
  }
  listener->impl = impl;
  return SALTS_OK;
#else
  (void)impl;
  (void)address;
  (void)address_length;
  (void)status;
  return SALTS_ENOTSUP;
#endif
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

int cnet_listener_vsock_local(const cnet_listener *listener, cnet_vsock_peer *out_local) {
  const cnet_listener_impl *impl = cnet_listener_const_get(listener);
  if (out_local == NULL) return SALTS_EINVAL;
  *out_local = (cnet_vsock_peer){0};
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_VSOCK) return SALTS_ENOTSUP;
#if defined(__linux__)
  {
    struct sockaddr_vm address;
    socklen_t address_length = (socklen_t)sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockname(impl->socket_value, (struct sockaddr *)&address, &address_length) != 0)
      return cnet_listener_native_error();
    if (address_length < sizeof(address) || address.svm_family != AF_VSOCK) return SALTS_EPROTO;
    out_local->cid = address.svm_cid;
    out_local->port = address.svm_port;
    return SALTS_OK;
  }
#else
  return SALTS_ENOTSUP;
#endif
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
  int native_timeout = timeout_ms > (uint32_t)INT_MAX ? INT_MAX : (int)timeout_ms;
  int result;
  if (out_ready == NULL) return SALTS_EINVAL;
  *out_ready = 0;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->external_attached) return SALTS_ENOTSUP;
  if (impl->kind == CNET_LISTENER_KIND_TCP && !impl->listening) return SALTS_EBUSY;
#if defined(_WIN32)
  {
    WSAPOLLFD poll_fd = {impl->socket_value, POLLRDNORM, 0};
    result = WSAPoll(&poll_fd, 1u, native_timeout);
    if (result > 0 && (poll_fd.revents & (POLLRDNORM | POLLERR | POLLHUP | POLLNVAL)) != 0)
      *out_ready = 1;
  }
#else
  {
    struct pollfd poll_fd = {impl->socket_value, POLLIN, 0};
    const uint64_t started_ms = monotonic_ms();
    for (;;) {
      poll_fd.revents = 0;
      result = poll(&poll_fd, 1u, native_timeout);
      if (result >= 0 || errno != EINTR) break;
      if (timeout_ms == 0u) {
        result = 0;
        break;
      }
      {
        const uint64_t elapsed_ms = monotonic_ms() - started_ms;
        const uint64_t remaining_ms =
            elapsed_ms >= timeout_ms ? 0u : (uint64_t)timeout_ms - elapsed_ms;
        if (remaining_ms == 0u) {
          result = 0;
          break;
        }
        native_timeout = remaining_ms > (uint64_t)INT_MAX ? INT_MAX : (int)remaining_ms;
      }
    }
    if (result > 0 && (poll_fd.revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0)
      *out_ready = 1;
  }
#endif
  if (result < 0) return cnet_listener_native_error();
  return SALTS_OK;
}

int cnet_listener_accept(cnet_listener *listener, cnet_client *client,
                         const cnet_observer *observer, cnet_connection *out_connection) {
  cnet_stream_peer peer;
  return cnet_listener_accept_peer(listener, client, observer, out_connection, &peer);
}

int cnet_listener_accept_detached(cnet_listener *listener,
                                  cnet_accepted_stream *out_accepted) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
  struct sockaddr_storage native_peer;
#if defined(_WIN32)
  int native_peer_size = (int)sizeof(native_peer);
#else
  socklen_t native_peer_size = (socklen_t)sizeof(native_peer);
#endif
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
    memset(&native_peer, 0, sizeof(native_peer));
    do {
      accepted = accept(impl->socket_value, (struct sockaddr *)&native_peer,
                        &native_peer_size);
#if defined(_WIN32)
    } while (false);
#else
    } while (accepted == CNET_LISTENER_INVALID_SOCKET && errno == EINTR);
#endif
    if (accepted == CNET_LISTENER_INVALID_SOCKET)
      return cnet_listener_would_block() ? SALTS_ETIMEDOUT
                                         : cnet_listener_native_error();
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
#if !defined(_WIN32)
  status = cnet_listener_set_nonblocking(accepted);
  if (status != SALTS_OK) {
    cnet_transport_close_socket((uintptr_t)accepted);
    return status;
  }
#endif

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
                                    const cnet_observer *observer,
                                    cnet_connection *out_connection,
                                    cnet_vsock_peer *out_peer) {
  cnet_listener_impl *impl = cnet_listener_get(listener);
#if defined(__linux__)
  struct sockaddr_vm native_peer;
  socklen_t native_peer_size = (socklen_t)sizeof(native_peer);
  cnet_listener_socket accepted;
  int status;
#endif
  if (out_peer != NULL) *out_peer = (cnet_vsock_peer){0};
  if (out_connection == NULL) return SALTS_EINVAL;
  *out_connection = (cnet_connection){0};
  if (impl == NULL || client == NULL || observer == NULL || observer->on_state == NULL ||
      out_peer == NULL)
    return SALTS_EINVAL;
  if (impl->closed) return SALTS_ESHUTDOWN;
  if (impl->kind != CNET_LISTENER_KIND_VSOCK) return SALTS_ENOTSUP;
#if defined(__linux__)
  memset(&native_peer, 0, sizeof(native_peer));
  do {
    accepted = accept(impl->socket_value, (struct sockaddr *)&native_peer, &native_peer_size);
  } while (accepted == CNET_LISTENER_INVALID_SOCKET && errno == EINTR);
  if (accepted == CNET_LISTENER_INVALID_SOCKET)
    return cnet_listener_would_block() ? SALTS_ETIMEDOUT : cnet_listener_native_error();
  if (native_peer_size < sizeof(native_peer) || native_peer.svm_family != AF_VSOCK) {
    cnet_transport_close_socket((uintptr_t)accepted);
    return SALTS_EAFNOSUPPORT;
  }
  out_peer->cid = native_peer.svm_cid;
  out_peer->port = native_peer.svm_port;
  status = cnet_listener_set_nonblocking(accepted);
  if (status != SALTS_OK) {
    cnet_transport_close_socket((uintptr_t)accepted);
    *out_peer = (cnet_vsock_peer){0};
    return status;
  }
  status = cnet_client_adopt_vsock(client, (uintptr_t)accepted, observer, out_connection);
  if (status != SALTS_OK) *out_peer = (cnet_vsock_peer){0};
  return status;
#else
  return SALTS_ENOTSUP;
#endif
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
