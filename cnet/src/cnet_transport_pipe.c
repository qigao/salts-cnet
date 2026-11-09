#include "cnet_transport.h"

#include "cnet_uri.h"

#include <salts/error_codes.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
// clang-format off
  #include <winsock2.h>
  #include <windows.h>
// clang-format on
#else
  #include <errno.h>
  #include <fcntl.h>
  #include <stdio.h>
  #include <unistd.h>
#endif

enum { CNET_PIPE_SUFFIX_BYTES = 3 };

static void cnet_transport_pipe_reset(cnet_transport *transport) {
  if (transport == NULL) return;
  *transport = (cnet_transport){.native_handle = UINTPTR_MAX,
                                .write_native_handle = UINTPTR_MAX,
                                .resource_kind = CNET_TRANSPORT_RESOURCE_NONE};
}

static int cnet_transport_pipe_name_length(const char *name, size_t *out_length) {
  size_t length;
  if (name == NULL || out_length == NULL) return SALTS_EINVAL;
  for (length = 0u; length < CNET_URI_PATH_CAPACITY; ++length) {
    if (name[length] == '\0') {
      if (length == 0u) return SALTS_EINVAL;
      *out_length = length;
      return SALTS_OK;
    }
  }
  return SALTS_ERANGE;
}

#if defined(_WIN32)
static int cnet_transport_pipe_open(const char *name, size_t name_length, uintptr_t *out_read,
                                    uintptr_t *out_write) {
  static const char prefix[] = "\\\\.\\pipe\\";
  char native_name[sizeof(prefix) + CNET_URI_PATH_CAPACITY];
  HANDLE handle;
  size_t index;
  memcpy(native_name, prefix, sizeof(prefix) - 1u);
  for (index = 0u; index < name_length; ++index)
    native_name[sizeof(prefix) - 1u + index] = name[index] == '/' ? '\\' : name[index];
  native_name[sizeof(prefix) - 1u + name_length] = '\0';
  handle = CreateFileA(native_name, GENERIC_READ | GENERIC_WRITE, 0u, NULL, OPEN_EXISTING,
                       FILE_FLAG_OVERLAPPED, NULL);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    return error != ERROR_SUCCESS ? -(int)error : SALTS_EIO;
  }
  *out_read = *out_write = (uintptr_t)handle;
  return SALTS_OK;
}

static void cnet_transport_pipe_close_handles(uintptr_t read_handle, uintptr_t write_handle) {
  if (read_handle != UINTPTR_MAX) (void)CloseHandle((HANDLE)read_handle);
  if (write_handle != UINTPTR_MAX && write_handle != read_handle)
    (void)CloseHandle((HANDLE)write_handle);
}
#else
static int cnet_transport_pipe_set_close_on_exec(int descriptor) {
  const int flags = fcntl(descriptor, F_GETFD, 0);
  if (flags < 0 || fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != 0) return -errno;
  return SALTS_OK;
}

static int cnet_transport_pipe_open(const char *name, size_t name_length, uintptr_t *out_read,
                                    uintptr_t *out_write) {
  char read_name[CNET_URI_PATH_CAPACITY + CNET_PIPE_SUFFIX_BYTES + 1u];
  char write_name[CNET_URI_PATH_CAPACITY + CNET_PIPE_SUFFIX_BYTES + 1u];
  int read_descriptor = -1;
  int write_descriptor = -1;
  int status;
  memcpy(read_name, name, name_length);
  memcpy(read_name + name_length, ".rx", CNET_PIPE_SUFFIX_BYTES + 1u);
  memcpy(write_name, name, name_length);
  memcpy(write_name + name_length, ".tx", CNET_PIPE_SUFFIX_BYTES + 1u);

  read_descriptor = open(read_name, O_RDONLY | O_NONBLOCK);
  if (read_descriptor < 0) return -errno;
  status = cnet_transport_pipe_set_close_on_exec(read_descriptor);
  if (status != SALTS_OK) goto failed;
  write_descriptor = open(write_name, O_WRONLY | O_NONBLOCK);
  if (write_descriptor < 0) {
    status = -errno;
    goto failed;
  }
  status = cnet_transport_pipe_set_close_on_exec(write_descriptor);
  if (status != SALTS_OK) goto failed;
  *out_read = (uintptr_t)read_descriptor;
  *out_write = (uintptr_t)write_descriptor;
  return SALTS_OK;

failed:
  if (write_descriptor >= 0) (void)close(write_descriptor);
  (void)close(read_descriptor);
  return status;
}

static void cnet_transport_pipe_close_handles(uintptr_t read_handle, uintptr_t write_handle) {
  if (read_handle != UINTPTR_MAX) (void)close((int)read_handle);
  if (write_handle != UINTPTR_MAX && write_handle != read_handle) (void)close((int)write_handle);
}
#endif

int cnet_transport_pipe_connect(cnet_transport *transport, native_io_backend *backend,
                                native_io_backend_kind backend_kind, const char *name) {
  uintptr_t read_handle = UINTPTR_MAX;
  uintptr_t write_handle = UINTPTR_MAX;
  size_t name_length = 0u;
  int status;
  if (transport == NULL) return SALTS_EINVAL;
  cnet_transport_pipe_reset(transport);
  if (backend == NULL) return SALTS_EINVAL;
  if (!native_io_backend_kind_supported(backend_kind) ||
      !native_io_backend_kind_supports_pipe(backend_kind))
    return SALTS_ENOTSUP;
  status = cnet_transport_pipe_name_length(name, &name_length);
  if (status != SALTS_OK) return status;
  status = cnet_transport_pipe_open(name, name_length, &read_handle, &write_handle);
  if (status != SALTS_OK) return status;
  status = cnet_transport_adopt_pipe(transport, backend, read_handle, write_handle);
  if (status != SALTS_OK) cnet_transport_pipe_close_handles(read_handle, write_handle);
  return status;
}
