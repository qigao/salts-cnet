#ifndef CNET_TEST_PIPE_H
#define CNET_TEST_PIPE_H

#include <salts/error_codes.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if defined(_WIN32)
  // clang-format off
  #include <winsock2.h>
  #include <windows.h>
  // clang-format on
#else
  #include <fcntl.h>
  #include <unistd.h>
#endif

typedef struct cnet_shared_test_pipe_pair {
  uintptr_t cnet_read;
  uintptr_t cnet_write;
  uintptr_t peer_read;
  uintptr_t peer_write;
} cnet_shared_test_pipe_pair;

static inline void cnet_shared_test_pipe_reset(cnet_shared_test_pipe_pair *pair) {
#if defined(_WIN32)
  pair->cnet_read = pair->cnet_write = pair->peer_read = pair->peer_write =
      (uintptr_t)INVALID_HANDLE_VALUE;
#else
  pair->cnet_read = pair->cnet_write = pair->peer_read = pair->peer_write = UINTPTR_MAX;
#endif
}

static inline void cnet_shared_test_close_pipe_handle(uintptr_t handle) {
#if defined(_WIN32)
  if (handle != (uintptr_t)INVALID_HANDLE_VALUE) (void)CloseHandle((HANDLE)handle);
#else
  if (handle <= (uintptr_t)INT_MAX) (void)close((int)handle);
#endif
}

static inline void cnet_shared_test_close_pipe_pair(cnet_shared_test_pipe_pair *pair) {
  uintptr_t handles[4];
  size_t index;
  size_t prior;
  if (pair == NULL) return;
  handles[0] = pair->cnet_read;
  handles[1] = pair->cnet_write;
  handles[2] = pair->peer_read;
  handles[3] = pair->peer_write;
  for (index = 0u; index < 4u; ++index) {
    bool duplicate = false;
    for (prior = 0u; prior < index; ++prior)
      if (handles[prior] == handles[index]) duplicate = true;
    if (!duplicate) cnet_shared_test_close_pipe_handle(handles[index]);
  }
  cnet_shared_test_pipe_reset(pair);
}

static inline int cnet_shared_test_make_pipe_pair(cnet_shared_test_pipe_pair *pair) {
#if defined(_WIN32)
  static LONG sequence = 0;
  char name[128];
  OVERLAPPED connected = {0};
  HANDLE event = NULL;
  HANDLE server = INVALID_HANDLE_VALUE;
  HANDLE client = INVALID_HANDLE_VALUE;
  DWORD error = ERROR_SUCCESS;
  BOOL pending = FALSE;
  int name_length;

  if (pair == NULL) return SALTS_EINVAL;
  cnet_shared_test_pipe_reset(pair);
  name_length = snprintf(name, sizeof(name), "\\\\.\\pipe\\cnet-owner-test-%lu-%ld",
                         GetCurrentProcessId(), InterlockedIncrement(&sequence));
  if (name_length < 0 || (size_t)name_length >= sizeof(name)) return SALTS_ERANGE;
  server =
      CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1u, 4096u, 4096u, 0u, NULL);
  if (server == INVALID_HANDLE_VALUE) return -(int)GetLastError();
  event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (event == NULL) {
    error = GetLastError();
    goto failed;
  }
  connected.hEvent = event;
  if (!ConnectNamedPipe(server, &connected)) {
    error = GetLastError();
    if (error == ERROR_IO_PENDING) pending = TRUE;
    else if (error != ERROR_PIPE_CONNECTED) goto failed;
  }
  client = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0u, NULL, OPEN_EXISTING, 0u, NULL);
  if (client == INVALID_HANDLE_VALUE) {
    error = GetLastError();
    goto failed;
  }
  if (pending) {
    DWORD transferred = 0u;
    if (!GetOverlappedResult(server, &connected, &transferred, TRUE)) {
      error = GetLastError();
      goto failed;
    }
  }
  (void)CloseHandle(event);
  pair->cnet_read = pair->cnet_write = (uintptr_t)server;
  pair->peer_read = pair->peer_write = (uintptr_t)client;
  return SALTS_OK;

failed:
  if (client != INVALID_HANDLE_VALUE) (void)CloseHandle(client);
  if (server != INVALID_HANDLE_VALUE) (void)CloseHandle(server);
  if (event != NULL) (void)CloseHandle(event);
  return -(int)error;
#else
  int inbound[2] = {-1, -1};
  int outbound[2] = {-1, -1};
  int flags;
  int saved_error;
  if (pair == NULL) return SALTS_EINVAL;
  cnet_shared_test_pipe_reset(pair);
  if (pipe(inbound) != 0 || pipe(outbound) != 0) goto failed;
  flags = fcntl(inbound[0], F_GETFL, 0);
  if (flags < 0 || fcntl(inbound[0], F_SETFL, flags | O_NONBLOCK) != 0) goto failed;
  flags = fcntl(outbound[1], F_GETFL, 0);
  if (flags < 0 || fcntl(outbound[1], F_SETFL, flags | O_NONBLOCK) != 0) goto failed;
  pair->cnet_read = (uintptr_t)inbound[0];
  pair->peer_write = (uintptr_t)inbound[1];
  pair->peer_read = (uintptr_t)outbound[0];
  pair->cnet_write = (uintptr_t)outbound[1];
  return SALTS_OK;

failed:
  saved_error = errno;
  if (inbound[0] >= 0) (void)close(inbound[0]);
  if (inbound[1] >= 0) (void)close(inbound[1]);
  if (outbound[0] >= 0) (void)close(outbound[0]);
  if (outbound[1] >= 0) (void)close(outbound[1]);
  return -saved_error;
#endif
}

static inline int cnet_shared_test_pipe_peer_write(uintptr_t handle, const void *data,
                                                   size_t size) {
#if defined(_WIN32)
  DWORD written = 0u;
  if (!WriteFile((HANDLE)handle, data, (DWORD)size, &written, NULL)) return -(int)GetLastError();
  return written == size ? SALTS_OK : SALTS_EIO;
#else
  const ssize_t written = write((int)handle, data, size);
  return written == (ssize_t)size ? SALTS_OK : (written < 0 ? -errno : SALTS_EIO);
#endif
}

static inline int cnet_shared_test_pipe_peer_read(uintptr_t handle, void *data, size_t size) {
#if defined(_WIN32)
  DWORD read_bytes = 0u;
  if (!ReadFile((HANDLE)handle, data, (DWORD)size, &read_bytes, NULL)) return -(int)GetLastError();
  return read_bytes == size ? SALTS_OK : SALTS_EIO;
#else
  const ssize_t read_bytes = read((int)handle, data, size);
  return read_bytes == (ssize_t)size ? SALTS_OK : (read_bytes < 0 ? -errno : SALTS_EIO);
#endif
}

#endif /* CNET_TEST_PIPE_H */
