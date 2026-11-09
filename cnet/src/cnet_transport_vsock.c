#include "cnet_transport.h"

#include <salts/error_codes.h>

#include <string.h>

#if defined(__linux__)
  #include <errno.h>
  #include <sys/socket.h>
  /* Android's vm_sockets.h requires the complete sockaddr definition. */
  #include <linux/vm_sockets.h>
#endif

static void cnet_transport_vsock_reset(cnet_transport *transport) {
  if (transport == NULL) return;
  *transport = (cnet_transport){.native_handle = UINTPTR_MAX,
                                .write_native_handle = UINTPTR_MAX,
                                .resource_kind = CNET_TRANSPORT_RESOURCE_NONE};
}

bool cnet_transport_vsock_supported(native_io_backend_kind backend_kind) {
#if defined(__linux__)
  return native_io_backend_kind_supported(backend_kind) &&
         (backend_kind == NATIVE_IO_BACKEND_EPOLL || backend_kind == NATIVE_IO_BACKEND_IO_URING);
#else
  (void)backend_kind;
  return false;
#endif
}

int cnet_transport_parse_vsock_address(uint32_t cid, uint32_t port, bool allow_any,
                                       void *out_address, size_t address_capacity,
                                       size_t *out_address_length) {
  if (out_address_length == NULL) return SALTS_EINVAL;
  *out_address_length = 0u;
  if (out_address == NULL) return SALTS_EINVAL;
#if defined(__linux__)
  {
    struct sockaddr_vm address;
    if (!allow_any && (cid == CNET_VSOCK_CID_ANY || port == CNET_VSOCK_PORT_ANY))
      return SALTS_EINVAL;
    if (address_capacity < sizeof(address)) return SALTS_ERANGE;
    memset(&address, 0, sizeof(address));
    address.svm_family = AF_VSOCK;
    address.svm_cid = cid;
    address.svm_port = port;
    memcpy(out_address, &address, sizeof(address));
    *out_address_length = sizeof(address);
    return SALTS_OK;
  }
#else
  (void)cid;
  (void)port;
  (void)allow_any;
  (void)address_capacity;
  return SALTS_ENOTSUP;
#endif
}

int cnet_transport_vsock_prepare_connect(cnet_transport *transport, native_io_backend *backend,
                                         native_io_backend_kind backend_kind, const void *address,
                                         size_t address_length,
                                         const cnet_stream_socket_options *socket_options,
                                         uintptr_t user_data,
                                         native_io_operation *out_operation) {
  if (transport == NULL || out_operation == NULL) return SALTS_EINVAL;
  cnet_transport_vsock_reset(transport);
  *out_operation = (native_io_operation){0};
  if (backend == NULL || address == NULL || socket_options == NULL) return SALTS_EINVAL;
  if (!cnet_transport_vsock_supported(backend_kind)) return SALTS_ENOTSUP;
#if defined(__linux__)
  return cnet_transport_stream_prepare_connect(transport, backend, backend_kind, AF_VSOCK, 0,
                                               false, address, address_length, socket_options,
                                               user_data, out_operation);
#else
  (void)address_length;
  (void)user_data;
  return SALTS_ENOTSUP;
#endif
}

int cnet_transport_adopt_vsock(cnet_transport *transport, native_io_backend *backend,
                               uintptr_t native_socket,
                               const cnet_stream_socket_options *socket_options) {
  if (transport == NULL) return SALTS_EINVAL;
  cnet_transport_vsock_reset(transport);
  if (backend == NULL || native_socket == UINTPTR_MAX || socket_options == NULL)
    return SALTS_EINVAL;
#if defined(__linux__)
  {
    struct sockaddr_vm peer;
    socklen_t peer_length = (socklen_t)sizeof(peer);
    if (getpeername((int)native_socket, (struct sockaddr *)&peer, &peer_length) != 0) {
      const int native_error = errno;
      cnet_transport_close_socket(native_socket);
      return native_error > 0 ? -native_error : SALTS_EIO;
    }
    if (peer_length < sizeof(peer) || peer.svm_family != AF_VSOCK) {
      cnet_transport_close_socket(native_socket);
      return SALTS_EAFNOSUPPORT;
    }
  }
  return cnet_transport_adopt_stream(transport, backend, native_socket, false, socket_options);
#else
  cnet_transport_close_socket(native_socket);
  return SALTS_ENOTSUP;
#endif
}
