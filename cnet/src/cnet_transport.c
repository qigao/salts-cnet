#include "cnet_transport.h"
#include <string.h>

/* Only portable policy/value adaptation remains here. NativeIO owns every
 * platform handle operation and its endpoint lifecycle. */
_Static_assert(sizeof(cnet_stream_socket_options) == sizeof(native_io_stream_socket_options),
               "socket policy layouts must agree");
_Static_assert(sizeof(cnet_stream_peer) == sizeof(native_io_stream_peer),
               "peer layouts must agree");

_Static_assert(offsetof(cnet_stream_socket_options, size) == offsetof(native_io_stream_socket_options, size),
               "stream_socket_options.size layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, receive_buffer_bytes) == offsetof(native_io_stream_socket_options, receive_buffer_bytes),
               "stream_socket_options.receive_buffer_bytes layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, send_buffer_bytes) == offsetof(native_io_stream_socket_options, send_buffer_bytes),
               "stream_socket_options.send_buffer_bytes layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, keepalive_idle_ms) == offsetof(native_io_stream_socket_options, keepalive_idle_ms),
               "stream_socket_options.keepalive_idle_ms layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, keepalive_interval_ms) == offsetof(native_io_stream_socket_options, keepalive_interval_ms),
               "stream_socket_options.keepalive_interval_ms layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, keepalive_count) == offsetof(native_io_stream_socket_options, keepalive_count),
               "stream_socket_options.keepalive_count layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, linger_ms) == offsetof(native_io_stream_socket_options, linger_ms),
               "stream_socket_options.linger_ms layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, keepalive) == offsetof(native_io_stream_socket_options, keepalive),
               "stream_socket_options.keepalive layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, linger) == offsetof(native_io_stream_socket_options, linger),
               "stream_socket_options.linger layouts must agree");
_Static_assert(offsetof(cnet_stream_socket_options, nodelay) == offsetof(native_io_stream_socket_options, nodelay),
               "stream_socket_options.nodelay layouts must agree");
_Static_assert(offsetof(cnet_stream_peer, family) == offsetof(native_io_stream_peer, family),
               "stream_peer.family layouts must agree");
_Static_assert(offsetof(cnet_stream_peer, port) == offsetof(native_io_stream_peer, port),
               "stream_peer.port layouts must agree");
_Static_assert(offsetof(cnet_stream_peer, scope_id) == offsetof(native_io_stream_peer, scope_id),
               "stream_peer.scope_id layouts must agree");
_Static_assert(offsetof(cnet_stream_peer, address) == offsetof(native_io_stream_peer, address),
               "stream_peer.address layouts must agree");
_Static_assert((int)CNET_TCP_SOCKET_KEEPALIVE_ENABLED == (int)NATIVE_IO_TCP_SOCKET_KEEPALIVE_ENABLED,
               "TCP_SOCKET_KEEPALIVE_ENABLED values must agree");
_Static_assert((int)CNET_TCP_SOCKET_KEEPALIVE_IDLE_MS == (int)NATIVE_IO_TCP_SOCKET_KEEPALIVE_IDLE_MS,
               "TCP_SOCKET_KEEPALIVE_IDLE_MS values must agree");
_Static_assert((int)CNET_TCP_SOCKET_KEEPALIVE_INTERVAL_MS == (int)NATIVE_IO_TCP_SOCKET_KEEPALIVE_INTERVAL_MS,
               "TCP_SOCKET_KEEPALIVE_INTERVAL_MS values must agree");
_Static_assert((int)CNET_TCP_SOCKET_KEEPALIVE_COUNT == (int)NATIVE_IO_TCP_SOCKET_KEEPALIVE_COUNT,
               "TCP_SOCKET_KEEPALIVE_COUNT values must agree");
_Static_assert((int)CNET_TCP_SOCKET_HOP_LIMIT == (int)NATIVE_IO_TCP_SOCKET_HOP_LIMIT,
               "TCP_SOCKET_HOP_LIMIT values must agree");
_Static_assert((int)CNET_TCP_SOCKET_RECEIVE_BUFFER_BYTES == (int)NATIVE_IO_TCP_SOCKET_RECEIVE_BUFFER_BYTES,
               "TCP_SOCKET_RECEIVE_BUFFER_BYTES values must agree");
_Static_assert((int)CNET_TCP_SOCKET_SEND_BUFFER_BYTES == (int)NATIVE_IO_TCP_SOCKET_SEND_BUFFER_BYTES,
               "TCP_SOCKET_SEND_BUFFER_BYTES values must agree");
_Static_assert((int)CNET_TCP_SOCKET_NODELAY == (int)NATIVE_IO_TCP_SOCKET_NODELAY,
               "TCP_SOCKET_NODELAY values must agree");
_Static_assert((int)CNET_TCP_SHUTDOWN_RECEIVE == (int)NATIVE_IO_TCP_SHUTDOWN_RECEIVE,
               "TCP_SHUTDOWN_RECEIVE values must agree");
_Static_assert((int)CNET_TCP_SHUTDOWN_SEND == (int)NATIVE_IO_TCP_SHUTDOWN_SEND,
               "TCP_SHUTDOWN_SEND values must agree");
_Static_assert((int)CNET_TCP_SHUTDOWN_BOTH == (int)NATIVE_IO_TCP_SHUTDOWN_BOTH,
               "TCP_SHUTDOWN_BOTH values must agree");
_Static_assert((int)CNET_DATAGRAM_ADDRESS_IPV4 == (int)NATIVE_IO_DATAGRAM_ADDRESS_IPV4,
               "DATAGRAM_ADDRESS_IPV4 values must agree");
_Static_assert((int)CNET_DATAGRAM_ADDRESS_IPV6 == (int)NATIVE_IO_DATAGRAM_ADDRESS_IPV6,
               "DATAGRAM_ADDRESS_IPV6 values must agree");

/* Reject a truncated descriptor before reading fields beyond its size. The
 * NativeIO operation remains responsible for validation and output cleanup. */
static native_io_stream_socket_options cnet_to_native_options(
    const cnet_stream_socket_options *source) {
  native_io_stream_socket_options value = {0};
  if (source != NULL) {
    value.size = source->size;
    if (source->size == sizeof(*source)) memcpy(&value, source, sizeof(value));
  }
  return value;
}

static native_io_stream_endpoint cnet_to_native_endpoint(const cnet_stream_endpoint *source) {
  native_io_stream_endpoint value = {0};
  value.family = (native_io_datagram_address_family)source->family;
  value.port = source->port;
  value.flow_info = source->flow_info;
  value.scope_id = source->scope_id;
  memcpy(value.address, source->address, sizeof(value.address));
  return value;
}

static void cnet_from_native_endpoint(cnet_stream_endpoint *target,
                                     const native_io_stream_endpoint *source) {
  *target = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  target->family = (cnet_datagram_address_family)source->family;
  target->port = source->port;
  target->flow_info = source->flow_info;
  target->scope_id = source->scope_id;
  memcpy(target->address, source->address, sizeof(target->address));
}

int cnet_transport_decode_endpoint(const void *address, size_t length, bool datagram,
                                   cnet_stream_endpoint *out_endpoint) {
  native_io_stream_endpoint endpoint = {0};
  if (!out_endpoint) return SALTS_EINVAL;
  *out_endpoint = (cnet_stream_endpoint)CNET_STREAM_ENDPOINT_INIT;
  int status = native_io_socket_decode_endpoint(address, length, &endpoint, datagram);
  if (status == SALTS_OK) cnet_from_native_endpoint(out_endpoint, &endpoint);
  return status;
}

int cnet_transport_encode_datagram_endpoint(const cnet_stream_endpoint *endpoint,
    void *address, size_t capacity, size_t *out_length) {
  if (!endpoint || endpoint->size != sizeof(*endpoint) ||
      endpoint->version != CNET_STREAM_ENDPOINT_API_VERSION) return SALTS_EINVAL;
  native_io_stream_endpoint native = cnet_to_native_endpoint(endpoint);
  return native_io_socket_encode_datagram_endpoint(&native, address, capacity, out_length);
}

int cnet_stream_socket_options_validate(const cnet_stream_socket_options *options) {
  if (options == NULL) return SALTS_EINVAL;
  native_io_stream_socket_options converted = cnet_to_native_options(options);
  return native_io_stream_socket_options_validate(&converted);
}

int cnet_transport_apply_stream_socket_options(
    uintptr_t native_socket, const cnet_stream_socket_options *options) {
  native_io_stream_socket_options native_options = cnet_to_native_options(options);
  return native_io_transport_apply_stream_socket_options(native_socket, options != NULL ? &native_options : NULL);
}

int cnet_transport_parse_numeric_address(const char *host, uint16_t port, void *out_address,
                                         size_t address_capacity, size_t *out_address_length) {
  return native_io_transport_parse_numeric_address(host, port, out_address, address_capacity, out_address_length);
}

int cnet_transport_validate_ipv6_literal(const char *host) {
  return native_io_transport_validate_ipv6_literal(host);
}

int cnet_transport_parse_bind_address(const char *host, uint16_t port, void *out_address,
                                      size_t address_capacity, size_t *out_address_length) {
  return native_io_transport_parse_bind_address(host, port, out_address, address_capacity, out_address_length);
}

int cnet_transport_stream_peer_address(const cnet_stream_peer *peer, bool allow_zero_port,
                                       void *out_address, size_t address_capacity,
                                       size_t *out_address_length) {
  native_io_stream_peer native_peer = {0};
  if (peer != NULL) memcpy(&native_peer, peer, sizeof(native_peer));
  return native_io_transport_stream_peer_address(peer != NULL ? &native_peer : NULL, allow_zero_port, out_address, address_capacity, out_address_length);
}

int cnet_transport_stream_endpoint_address(
    const cnet_stream_endpoint *endpoint, bool allow_zero_port,
    void *out_address, size_t address_capacity,
    size_t *out_address_length) {
  native_io_stream_endpoint native_endpoint = {0};
  if (out_address_length == NULL) return SALTS_EINVAL;
  *out_address_length = 0u;
  if (endpoint == NULL || endpoint->size < sizeof(*endpoint) ||
      endpoint->version != CNET_STREAM_ENDPOINT_API_VERSION) return SALTS_EINVAL;
  native_endpoint = cnet_to_native_endpoint(endpoint);
  return native_io_transport_stream_endpoint_address(endpoint != NULL ? &native_endpoint : NULL, allow_zero_port, out_address, address_capacity, out_address_length);
}

int cnet_transport_tcp_prepare_connect(cnet_transport *transport, native_io_backend *backend,
                                       native_io_backend_kind backend_kind, const void *address,
                                       size_t address_length,
                                       const cnet_stream_socket_options *socket_options,
                                       uintptr_t user_data,
                                       native_io_operation *out_operation) {
  native_io_stream_socket_options native_socket_options = cnet_to_native_options(socket_options);
  return native_io_transport_tcp_prepare_connect(transport, backend, backend_kind, address, address_length, socket_options != NULL ? &native_socket_options : NULL, user_data, out_operation);
}

int cnet_transport_tcp_prepare_connect_bound(
    cnet_transport *transport, native_io_backend *backend,
    native_io_backend_kind backend_kind, const void *remote_address,
    size_t remote_address_length, const void *local_address,
    size_t local_address_length,
    const cnet_stream_socket_options *socket_options,
    uintptr_t user_data, native_io_operation *out_operation) {
  native_io_stream_socket_options native_socket_options = cnet_to_native_options(socket_options);
  return native_io_transport_tcp_prepare_connect_bound(transport, backend, backend_kind, remote_address, remote_address_length, local_address, local_address_length, socket_options != NULL ? &native_socket_options : NULL, user_data, out_operation);
}

bool cnet_transport_vsock_supported(native_io_backend_kind backend_kind) {
  return native_io_transport_vsock_supported(backend_kind);
}

int cnet_transport_parse_vsock_address(uint32_t cid, uint32_t port, bool allow_any,
                                       void *out_address, size_t address_capacity,
                                       size_t *out_address_length) {
  return native_io_transport_parse_vsock_address(cid, port, allow_any, out_address, address_capacity, out_address_length);
}

int cnet_transport_vsock_prepare_connect(cnet_transport *transport, native_io_backend *backend,
                                         native_io_backend_kind backend_kind, const void *address,
                                         size_t address_length,
                                         const cnet_stream_socket_options *socket_options,
                                         uintptr_t user_data,
                                         native_io_operation *out_operation) {
  native_io_stream_socket_options native_socket_options = cnet_to_native_options(socket_options);
  return native_io_transport_vsock_prepare_connect(transport, backend, backend_kind, address, address_length, socket_options != NULL ? &native_socket_options : NULL, user_data, out_operation);
}

int cnet_transport_adopt_vsock(cnet_transport *transport, native_io_backend *backend,
                               uintptr_t native_socket,
                               const cnet_stream_socket_options *socket_options) {
  native_io_stream_socket_options native_socket_options = cnet_to_native_options(socket_options);
  return native_io_transport_adopt_vsock(transport, backend, native_socket, socket_options != NULL ? &native_socket_options : NULL);
}

int cnet_transport_stream_prepare_connect(cnet_transport *transport, native_io_backend *backend,
                                          native_io_backend_kind backend_kind, int family,
                                          int protocol, bool socket_options_supported,
                                          const void *address, size_t address_length,
                                          const cnet_stream_socket_options *socket_options,
                                          uintptr_t user_data,
                                          native_io_operation *out_operation) {
  native_io_stream_socket_options native_socket_options = cnet_to_native_options(socket_options);
  return native_io_transport_stream_prepare_connect(transport, backend, backend_kind, family, protocol, socket_options_supported, address, address_length, socket_options != NULL ? &native_socket_options : NULL, user_data, out_operation);
}

int cnet_transport_adopt_stream(cnet_transport *transport, native_io_backend *backend,
                                uintptr_t native_socket, bool socket_options_supported,
                                const cnet_stream_socket_options *socket_options) {
  native_io_stream_socket_options native_socket_options = cnet_to_native_options(socket_options);
  return native_io_transport_adopt_stream(transport, backend, native_socket, socket_options_supported, socket_options != NULL ? &native_socket_options : NULL);
}

int cnet_transport_tcp_connect(cnet_transport *transport, native_io_backend *backend,
                               native_io_backend_kind backend_kind, const void *address,
                               size_t address_length, uintptr_t user_data,
                               native_io_request *out_request) {
  return native_io_transport_tcp_connect(transport, backend, backend_kind, address, address_length, user_data, out_request);
}

int cnet_transport_adopt_tcp(cnet_transport *transport, native_io_backend *backend,
                             uintptr_t native_socket,
                             const cnet_stream_socket_options *socket_options) {
  native_io_stream_socket_options native_socket_options = cnet_to_native_options(socket_options);
  return native_io_transport_adopt_tcp(transport, backend, native_socket, socket_options != NULL ? &native_socket_options : NULL);
}

int cnet_transport_adopt_tcp_prepare_connect(
    cnet_transport *transport, native_io_backend *backend,
    uintptr_t native_socket, const void *remote_address,
    size_t remote_address_length,
    const cnet_stream_socket_options *socket_options,
    uintptr_t user_data, native_io_operation *out_operation) {
  native_io_stream_socket_options native_socket_options = cnet_to_native_options(socket_options);
  return native_io_transport_adopt_tcp_prepare_connect(transport, backend, native_socket, remote_address, remote_address_length, socket_options != NULL ? &native_socket_options : NULL, user_data, out_operation);
}

void cnet_transport_close_socket(uintptr_t native_socket) {
  native_io_transport_close_socket(native_socket);
}

int cnet_transport_udp_connect(cnet_transport *transport, native_io_backend *backend,
                               native_io_backend_kind backend_kind, const void *address,
                               size_t address_length) {
  return native_io_transport_udp_connect(transport, backend, backend_kind, address, address_length);
}

int cnet_transport_adopt_pipe(cnet_transport *transport, native_io_backend *backend,
                              uintptr_t read_handle, uintptr_t write_handle) {
  return native_io_transport_adopt_pipe(transport, backend, read_handle, write_handle);
}

int cnet_transport_pipe_connect(cnet_transport *transport, native_io_backend *backend,
                                native_io_backend_kind backend_kind, const char *name) {
  return native_io_transport_pipe_connect(transport, backend, backend_kind, name);
}

int cnet_transport_ipc_validate_name(const char *name, size_t length) {
  return native_io_transport_ipc_validate_name(name, length);
}

int cnet_transport_ipc_native_name(const char *name, char **out_name) {
  return native_io_transport_ipc_native_name(name, out_name);
}

int cnet_transport_ipc_address(const char *name, void *address, size_t capacity, size_t *out_length) {
  return native_io_transport_ipc_address(name, address, capacity, out_length);
}

int cnet_transport_ipc_prepare_connect(cnet_transport *transport, native_io_backend *backend,
                                        native_io_backend_kind backend_kind, const char *name,
                                        void *address, size_t address_length,
                                        native_io_operation *out_operation, bool *out_immediate) {
  return native_io_transport_ipc_prepare_connect(transport, backend, backend_kind, name, address, address_length, out_operation, out_immediate);
}

int cnet_transport_adopt_ipc(cnet_transport *transport, native_io_backend *backend,
                              uintptr_t native_handle) {
  return native_io_transport_adopt_ipc(transport, backend, native_handle);
}

int cnet_transport_close_ipc(uintptr_t native_handle) {
  return native_io_transport_close_ipc(native_handle);
}

native_io_endpoint cnet_transport_read_endpoint(const cnet_transport *transport) {
  return native_io_transport_read_endpoint(transport);
}

native_io_endpoint cnet_transport_write_endpoint(const cnet_transport *transport) {
  return native_io_transport_write_endpoint(transport);
}

int cnet_transport_tcp_local_peer(const cnet_transport *transport, cnet_stream_peer *out_peer) {
  native_io_stream_peer native_out_peer = {0};
  int status = native_io_transport_tcp_local_peer(transport, out_peer != NULL ? &native_out_peer : NULL);
  if (out_peer != NULL) memcpy(out_peer, &native_out_peer, sizeof(native_out_peer));
  return status;
}

int cnet_transport_tcp_remote_peer(const cnet_transport *transport, cnet_stream_peer *out_peer) {
  native_io_stream_peer native_out_peer = {0};
  int status = native_io_transport_tcp_remote_peer(transport, out_peer != NULL ? &native_out_peer : NULL);
  if (out_peer != NULL) memcpy(out_peer, &native_out_peer, sizeof(native_out_peer));
  return status;
}

int cnet_transport_tcp_local_endpoint(
    const cnet_transport *transport,
    cnet_stream_endpoint *out_endpoint) {
  native_io_stream_endpoint native_out_endpoint = {0};
  int status = native_io_transport_tcp_local_endpoint(transport, out_endpoint != NULL ? &native_out_endpoint : NULL);
  if (out_endpoint != NULL) cnet_from_native_endpoint(out_endpoint, &native_out_endpoint);
  return status;
}

int cnet_transport_tcp_remote_endpoint(
    const cnet_transport *transport,
    cnet_stream_endpoint *out_endpoint) {
  native_io_stream_endpoint native_out_endpoint = {0};
  int status = native_io_transport_tcp_remote_endpoint(transport, out_endpoint != NULL ? &native_out_endpoint : NULL);
  if (out_endpoint != NULL) cnet_from_native_endpoint(out_endpoint, &native_out_endpoint);
  return status;
}

int cnet_transport_tcp_option_get(const cnet_transport *transport,
                                  cnet_tcp_socket_option option,
                                  uint64_t *out_value) {
  return native_io_transport_tcp_option_get(transport, (native_io_tcp_socket_option)option, out_value);
}

int cnet_transport_tcp_option_set(cnet_transport *transport,
                                  cnet_tcp_socket_option option,
                                  uint64_t value) {
  return native_io_transport_tcp_option_set(transport, (native_io_tcp_socket_option)option, value);
}

int cnet_transport_tcp_native_option_get(uintptr_t native_socket,
                                         cnet_tcp_socket_option option,
                                         uint64_t *out_value) {
  return native_io_transport_tcp_native_option_get(native_socket, (native_io_tcp_socket_option)option, out_value);
}

int cnet_transport_tcp_native_option_set(uintptr_t native_socket,
                                         cnet_tcp_socket_option option,
                                         uint64_t value) {
  return native_io_transport_tcp_native_option_set(native_socket, (native_io_tcp_socket_option)option, value);
}

int cnet_transport_tcp_native_option_get_family(
    uintptr_t native_socket, int native_family,
    cnet_tcp_socket_option option, uint64_t *out_value) {
  return native_io_transport_tcp_native_option_get_family(native_socket, native_family, (native_io_tcp_socket_option)option, out_value);
}

int cnet_transport_tcp_native_option_set_family(
    uintptr_t native_socket, int native_family,
    cnet_tcp_socket_option option, uint64_t value) {
  return native_io_transport_tcp_native_option_set_family(native_socket, native_family, (native_io_tcp_socket_option)option, value);
}

int cnet_transport_tcp_shutdown(cnet_transport *transport,
                                cnet_tcp_shutdown how) {
  return native_io_transport_tcp_shutdown(transport, (native_io_tcp_shutdown)how);
}

bool cnet_transport_active(const cnet_transport *transport) {
  return native_io_transport_active(transport);
}

int cnet_transport_close(cnet_transport *transport, native_io_backend *backend) {
  return native_io_transport_close(transport, backend);
}
