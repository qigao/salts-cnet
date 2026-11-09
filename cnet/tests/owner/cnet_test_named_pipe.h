#ifndef CNET_TEST_NAMED_PIPE_H
#define CNET_TEST_NAMED_PIPE_H

#include "cnet_test_pipe.h"
#include "cnet_uri.h"
#include "tinytest.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
typedef struct cnet_shared_test_named_pipe {
  cnet_shared_test_pipe_pair pair;
  char name[CNET_URI_PATH_CAPACITY];
  HANDLE connect_event;
  OVERLAPPED connect_operation;
  bool connect_pending;
} cnet_shared_test_named_pipe;
#else
  #include <sys/stat.h>

typedef struct cnet_shared_test_named_pipe {
  cnet_shared_test_pipe_pair pair;
  char name[CNET_URI_PATH_CAPACITY];
  char read_name[CNET_URI_PATH_CAPACITY + 4u];
  char write_name[CNET_URI_PATH_CAPACITY + 4u];
  char *directory;
} cnet_shared_test_named_pipe;
#endif

static void cnet_shared_test_named_pipe_reset(cnet_shared_test_named_pipe *pipe) {
  if (pipe == NULL) return;
  memset(pipe, 0, sizeof(*pipe));
  cnet_shared_test_pipe_reset(&pipe->pair);
}

static int cnet_shared_test_named_pipe_start(cnet_shared_test_named_pipe *pipe) {
  if (pipe == NULL) return SALTS_EINVAL;
  cnet_shared_test_named_pipe_reset(pipe);
#if defined(_WIN32)
  static LONG sequence = 0;
  char native_name[CNET_URI_PATH_CAPACITY + 10u];
  HANDLE server;
  DWORD error;
  int length = snprintf(pipe->name, sizeof(pipe->name), "cnet-test-%lu-%ld", GetCurrentProcessId(),
                        InterlockedIncrement(&sequence));
  if (length < 0 || (size_t)length >= sizeof(pipe->name)) return SALTS_ERANGE;
  length = snprintf(native_name, sizeof(native_name), "\\\\.\\pipe\\%s", pipe->name);
  if (length < 0 || (size_t)length >= sizeof(native_name)) return SALTS_ERANGE;
  server =
      CreateNamedPipeA(native_name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1u, 4096u, 4096u, 0u, NULL);
  if (server == INVALID_HANDLE_VALUE) return -(int)GetLastError();
  pipe->connect_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (pipe->connect_event == NULL) {
    error = GetLastError();
    (void)CloseHandle(server);
    return -(int)error;
  }
  pipe->connect_operation.hEvent = pipe->connect_event;
  if (!ConnectNamedPipe(server, &pipe->connect_operation)) {
    error = GetLastError();
    if (error == ERROR_IO_PENDING) pipe->connect_pending = true;
    else if (error != ERROR_PIPE_CONNECTED) {
      (void)CloseHandle(pipe->connect_event);
      (void)CloseHandle(server);
      cnet_shared_test_named_pipe_reset(pipe);
      return -(int)error;
    }
  }
  pipe->pair.peer_read = pipe->pair.peer_write = (uintptr_t)server;
  return SALTS_OK;
#else
  int dummy_read;
  int peer_write;
  int saved_errno;
  int length;
  pipe->directory = tt_make_temp_dir("cnetpipe");
  if (pipe->directory == NULL) return SALTS_EIO;
  length = snprintf(pipe->name, sizeof(pipe->name), "%s/endpoint", pipe->directory);
  if (length < 0 || (size_t)length >= sizeof(pipe->name)) return SALTS_ERANGE;
  length = snprintf(pipe->read_name, sizeof(pipe->read_name), "%s.rx", pipe->name);
  if (length < 0 || (size_t)length >= sizeof(pipe->read_name)) return SALTS_ERANGE;
  length = snprintf(pipe->write_name, sizeof(pipe->write_name), "%s.tx", pipe->name);
  if (length < 0 || (size_t)length >= sizeof(pipe->write_name)) return SALTS_ERANGE;
  if (mkfifo(pipe->read_name, 0600) != 0 || mkfifo(pipe->write_name, 0600) != 0) return -errno;
  pipe->pair.peer_read = (uintptr_t)open(pipe->write_name, O_RDONLY | O_NONBLOCK);
  if ((int)pipe->pair.peer_read < 0) {
    pipe->pair.peer_read = UINTPTR_MAX;
    return -errno;
  }
  dummy_read = open(pipe->read_name, O_RDONLY | O_NONBLOCK);
  if (dummy_read < 0) return -errno;
  peer_write = open(pipe->read_name, O_WRONLY | O_NONBLOCK);
  if (peer_write < 0) {
    saved_errno = errno;
    (void)close(dummy_read);
    return -saved_errno;
  }
  (void)close(dummy_read);
  pipe->pair.peer_write = (uintptr_t)peer_write;
  return SALTS_OK;
#endif
}

static int cnet_shared_test_named_pipe_finish(cnet_shared_test_named_pipe *pipe) {
  if (pipe == NULL) return SALTS_EINVAL;
#if defined(_WIN32)
  if (pipe->connect_pending) {
    DWORD transferred = 0u;
    if (!GetOverlappedResult((HANDLE)pipe->pair.peer_read, &pipe->connect_operation, &transferred,
                             TRUE))
      return -(int)GetLastError();
    pipe->connect_pending = false;
  }
  return SALTS_OK;
#else
  return pipe->pair.peer_write <= (uintptr_t)INT_MAX ? SALTS_OK : SALTS_EIO;
#endif
}

#if defined(_WIN32)
static int cnet_shared_test_named_pipe_io(HANDLE handle, void *data, size_t size, bool write_data) {
  OVERLAPPED operation = {0};
  HANDLE event = CreateEventA(NULL, TRUE, FALSE, NULL);
  DWORD transferred = 0u;
  DWORD error;
  BOOL accepted;
  if (event == NULL) return -(int)GetLastError();
  operation.hEvent = event;
  accepted = write_data ? WriteFile(handle, data, (DWORD)size, NULL, &operation)
                        : ReadFile(handle, data, (DWORD)size, NULL, &operation);
  if (!accepted) {
    error = GetLastError();
    if (error != ERROR_IO_PENDING) {
      (void)CloseHandle(event);
      return -(int)error;
    }
  }
  if (!GetOverlappedResult(handle, &operation, &transferred, TRUE)) {
    error = GetLastError();
    (void)CloseHandle(event);
    return -(int)error;
  }
  (void)CloseHandle(event);
  return transferred == size ? SALTS_OK : SALTS_EIO;
}
#endif

static int cnet_shared_test_named_pipe_peer_write(cnet_shared_test_named_pipe *pipe,
                                                  const void *data, size_t size) {
#if defined(_WIN32)
  return cnet_shared_test_named_pipe_io((HANDLE)pipe->pair.peer_write, (void *)data, size, true);
#else
  return cnet_shared_test_pipe_peer_write(pipe->pair.peer_write, data, size);
#endif
}

static int cnet_shared_test_named_pipe_peer_read(cnet_shared_test_named_pipe *pipe, void *data,
                                                 size_t size) {
#if defined(_WIN32)
  return cnet_shared_test_named_pipe_io((HANDLE)pipe->pair.peer_read, data, size, false);
#else
  return cnet_shared_test_pipe_peer_read(pipe->pair.peer_read, data, size);
#endif
}

static void cnet_shared_test_named_pipe_close(cnet_shared_test_named_pipe *pipe) {
  if (pipe == NULL) return;
#if defined(_WIN32)
  if (pipe->connect_event != NULL) (void)CloseHandle(pipe->connect_event);
#else
  if (pipe->read_name[0] != '\0') (void)unlink(pipe->read_name);
  if (pipe->write_name[0] != '\0') (void)unlink(pipe->write_name);
#endif
  cnet_shared_test_close_pipe_pair(&pipe->pair);
#if !defined(_WIN32)
  if (pipe->directory != NULL) {
    (void)tt_remove_tree(pipe->directory);
    free(pipe->directory);
  }
#endif
  cnet_shared_test_named_pipe_reset(pipe);
}

#endif /* CNET_TEST_NAMED_PIPE_H */
