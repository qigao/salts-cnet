#include "cnet_module.h"
#include "cnet_owner.h"
#if defined(CNET_INTERNAL_TESTING)
  #include "cnet_test_internal.h"
#endif
#if defined(__linux__)
#include "cnet_transport.h"
#endif
#include "cnet_test_named_pipe.h"
#include "cnet_test_pipe.h"
#include "tinytest.h"
#include <clock.h>
#include <thread.h>
#include <cmeta_buffer.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
typedef SOCKET cnet_owner_test_socket;
  #define CNET_OWNER_TEST_INVALID_SOCKET INVALID_SOCKET
#else
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
typedef int cnet_owner_test_socket;
  #define CNET_OWNER_TEST_INVALID_SOCKET (-1)
#endif

enum {
  CNET_OWNER_TEST_TIMEOUT_MS = 5000,
  CNET_OWNER_TEST_MAX_BACKENDS = 2,
  CNET_OWNER_TEST_UDP_ECHO_CAPACITY = 64
};

typedef struct cnet_owner_test_clock {
  uint64_t now_ms;
  uint64_t next_ms;
  size_t calls;
} cnet_owner_test_clock;

static uint64_t cnet_owner_test_now(void *context) {
  cnet_owner_test_clock *clock = (cnet_owner_test_clock *)context;
  const uint64_t now_ms = clock->now_ms;
  ++clock->calls;
  clock->now_ms = clock->next_ms;
  return now_ms;
}

typedef enum cnet_owner_test_timeout {
  CNET_OWNER_TEST_NO_TIMEOUT = 0,
  CNET_OWNER_TEST_CONNECT_TIMEOUT,
  CNET_OWNER_TEST_READ_TIMEOUT,
  CNET_OWNER_TEST_WRITE_TIMEOUT
} cnet_owner_test_timeout;

static int cnet_owner_test_send_bytes(cnet_owner *owner,
                                      cnet_session_handle session,
                                      const void *data, size_t size,
                                      bool close_after_send) {
  mem_buffer_t *buffer;
  int status;
  if (owner == NULL || data == NULL || size == 0u) return SALTS_EINVAL;
  buffer = mem_get_buffer(mem_global(), size);
  if (buffer == NULL) return SALTS_ENOMEM;
  memcpy(mem_buffer_data(buffer), data, size);
  mem_set_used(buffer, size);
  status = close_after_send
               ? cnet_owner_send_buffer_close_direct(owner, session, buffer)
               : cnet_owner_send_buffer_direct(owner, session, buffer);
  mem_buffer_release(buffer);
  return status;
}

typedef struct cnet_owner_test_udp_echo {
  cnet_owner_test_socket socket_value;
  const unsigned char *expected;
  size_t expected_size;
  const unsigned char *reply;
  size_t reply_size;
  int status;
} cnet_owner_test_udp_echo;

static void cnet_owner_test_udp_echo_entry(void *argument) {
  cnet_owner_test_udp_echo *echo = (cnet_owner_test_udp_echo *)argument;
  struct sockaddr_storage peer;
#if defined(_WIN32)
  int peer_length = (int)sizeof(peer);
#else
  socklen_t peer_length = (socklen_t)sizeof(peer);
#endif
  unsigned char buffer[CNET_OWNER_TEST_UDP_ECHO_CAPACITY];
  int received;
  int sent;

  echo->status = SALTS_EIO;
  if (echo->expected_size > sizeof(buffer) || echo->reply_size > INT_MAX) return;
#if defined(_WIN32)
  received = recvfrom(echo->socket_value, (char *)buffer, (int)sizeof(buffer), 0,
                      (struct sockaddr *)&peer, &peer_length);
  if (received == (int)echo->expected_size &&
      memcmp(buffer, echo->expected, echo->expected_size) == 0)
    sent = sendto(echo->socket_value, (const char *)echo->reply, (int)echo->reply_size, 0,
                  (const struct sockaddr *)&peer, peer_length);
  else return;
#else
  received = (int)recvfrom(echo->socket_value, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer,
                           &peer_length);
  if (received == (int)echo->expected_size &&
      memcmp(buffer, echo->expected, echo->expected_size) == 0)
    sent = (int)sendto(echo->socket_value, echo->reply, echo->reply_size, 0,
                       (const struct sockaddr *)&peer, peer_length);
  else return;
#endif
  if (sent == (int)echo->reply_size) echo->status = SALTS_OK;
}

static size_t
cnet_owner_test_backends(native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS]) {
#if defined(_WIN32)
  backends[0] = NATIVE_IO_BACKEND_IOCP;
  return 1u;
#elif defined(__linux__)
  backends[0] = NATIVE_IO_BACKEND_EPOLL;
  backends[1] = NATIVE_IO_BACKEND_IO_URING;
  return 2u;
#elif defined(__APPLE__) && UINTPTR_MAX > UINT32_MAX
  backends[0] = NATIVE_IO_BACKEND_KQUEUE;
  return 1u;
#else
  (void)backends;
  return 0u;
#endif
}

static void cnet_owner_test_close_socket(cnet_owner_test_socket socket_value) {
  if (socket_value == CNET_OWNER_TEST_INVALID_SOCKET) return;
#if defined(_WIN32)
  (void)closesocket(socket_value);
#else
  (void)close(socket_value);
#endif
}

static int cnet_owner_test_receive_all(cnet_owner_test_socket socket_value,
                                       unsigned char *data, size_t size) {
  size_t offset = 0u;
  while (offset < size) {
#if defined(_WIN32)
    const size_t remaining = size - offset;
    const int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
    const int received = recv(socket_value, (char *)data + offset, chunk, 0);
#else
    const ssize_t received = recv(socket_value, data + offset, size - offset, 0);
#endif
    if (received <= 0) return SALTS_EIO;
    offset += (size_t)received;
  }
  return SALTS_OK;
}

static int cnet_owner_test_listener(cnet_owner_test_socket *out_listener,
                                    struct sockaddr_in *out_address) {
#if defined(_WIN32)
  int length = (int)sizeof(*out_address);
#else
  socklen_t length = (socklen_t)sizeof(*out_address);
#endif
  *out_listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (*out_listener == CNET_OWNER_TEST_INVALID_SOCKET) return SALTS_EIO;
  memset(out_address, 0, sizeof(*out_address));
  out_address->sin_family = AF_INET;
  out_address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(*out_listener, (const struct sockaddr *)out_address, (int)sizeof(*out_address)) != 0 ||
      getsockname(*out_listener, (struct sockaddr *)out_address, &length) != 0 ||
      listen(*out_listener, 1) != 0) {
    cnet_owner_test_close_socket(*out_listener);
    *out_listener = CNET_OWNER_TEST_INVALID_SOCKET;
    return SALTS_EIO;
  }
  return SALTS_OK;
}

#if defined(_WIN32)
/* Issue #64: record the real loopback listener at command admission and
 * on the first unexpected terminal. Diagnostics must never change outcome. */
static void cnet_owner_test_issue64_listener_snapshot(
    const char *phase, cnet_owner_test_socket listener,
    const struct sockaddr_in *expected, cnet_session_handle session) {
  struct sockaddr_in actual = {0};
  int actual_length = (int)sizeof(actual);
  int accepting = 0;
  int accepting_length = (int)sizeof(accepting);
  const int name_rc =
      getsockname(listener, (struct sockaddr *)&actual, &actual_length);
  const int name_error = name_rc == SOCKET_ERROR ? WSAGetLastError() : 0;
  int listen_rc = SOCKET_ERROR;
  int listen_error = 0;
#if defined(SO_ACCEPTCONN)
  listen_rc = getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN,
                         (char *)&accepting, &accepting_length);
  if (listen_rc == SOCKET_ERROR) listen_error = WSAGetLastError();
#endif
  fprintf(stderr,
          "CNET_ISSUE64_LISTENER phase=%s socket=%llu session=%u:%u"
          " expected_family=%u expected_ipv4=%08lx expected_port=%u"
          " actual_family=%u actual_ipv4=%08lx actual_port=%u"
          " getsockname_rc=%d getsockname_error=%d"
          " acceptconn_rc=%d acceptconn=%d acceptconn_error=%d\n",
          phase, (unsigned long long)(uintptr_t)listener,
          (unsigned)session.slot, (unsigned)session.generation,
          (unsigned)expected->sin_family,
          (unsigned long)ntohl(expected->sin_addr.s_addr),
          (unsigned)ntohs(expected->sin_port),
          name_rc == 0 ? (unsigned)actual.sin_family : 0u,
          name_rc == 0 ? (unsigned long)ntohl(actual.sin_addr.s_addr) : 0ul,
          name_rc == 0 ? (unsigned)ntohs(actual.sin_port) : 0u,
          name_rc, name_error, listen_rc, accepting, listen_error);
}
#endif

static int cnet_owner_test_udp_peer(cnet_owner_test_socket *out_socket,
                                    struct sockaddr_in *out_address) {
#if defined(_WIN32)
  int length = (int)sizeof(*out_address);
#else
  socklen_t length = (socklen_t)sizeof(*out_address);
#endif
  *out_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (*out_socket == CNET_OWNER_TEST_INVALID_SOCKET) return SALTS_EIO;
  memset(out_address, 0, sizeof(*out_address));
  out_address->sin_family = AF_INET;
  out_address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(*out_socket, (const struct sockaddr *)out_address, (int)sizeof(*out_address)) != 0 ||
      getsockname(*out_socket, (struct sockaddr *)out_address, &length) != 0) {
    cnet_owner_test_close_socket(*out_socket);
    *out_socket = CNET_OWNER_TEST_INVALID_SOCKET;
    return SALTS_EIO;
  }
  return SALTS_OK;
}

static int cnet_owner_test_drive_to_state(cnet_owner *owner, cnet_session_table *sessions,
                                          cnet_session_handle handle, cnet_session_state expected) {
  const uint64_t deadline = cmeta_monotonic_ms() + CNET_OWNER_TEST_TIMEOUT_MS;
  for (;;) {
    cnet_session_state state = CNET_SESSION_FREE;
    int status = cnet_session_table_state(sessions, handle, &state);
    if (status != SALTS_OK) return status;
    if (state == expected) return SALTS_OK;
    if (state == CNET_SESSION_TERMINAL) {
      /* Diagnostic only on an unexpected failure; no retry, no acceptance
       * reduction, no mutation of the live production Owner. Capture the
       * original terminal stage before TinyTest reports its assertion. */
      cnet_session_terminal terminal = {0};
      const int received = cnet_session_table_take_terminal(
          sessions, handle, &terminal);
      fprintf(stderr,
          "Unexpected CNet Owner terminal during state admission:"
          " expected=%d terminal-read=%d kind=%d status=%d stage=%d\n",
          (int)expected, received, (int)terminal.kind,
          terminal.status, (int)terminal.stage);
      return SALTS_EIO;
    }
    status = cnet_owner_drive(owner, 10u);
    if (status != SALTS_OK) {
      fprintf(stderr, "CNET_ORIGINAL_OWNER_DRIVE_FAILED state=%d expected=%d status=%d\n",
              (int)state, (int)expected, status);
      return status;
    }
    if (cmeta_monotonic_ms() >= deadline) {
      fprintf(stderr,
          "CNet Owner state admission deadline:"
          " state=%d expected=%d elapsed-limit-ms=%d\n",
          (int)state, (int)expected, CNET_OWNER_TEST_TIMEOUT_MS);
      return SALTS_ETIMEDOUT;
    }
  }
}

static int cnet_owner_test_drive_to_event(cnet_owner *owner, cnet_event_queue *events,
                                          cnet_event_view *out_event) {
  const uint64_t deadline = cmeta_monotonic_ms() + CNET_OWNER_TEST_TIMEOUT_MS;
  for (;;) {
    int status = cnet_event_queue_take(events, out_event);
    if (status == SALTS_OK) return SALTS_OK;
    if (status != SALTS_ETIMEDOUT) return status;
    status = cnet_owner_drive(owner, 10u);
    if (status != SALTS_OK) return status;
    if (cmeta_monotonic_ms() >= deadline) return SALTS_ETIMEDOUT;
  }
}

static void cnet_owner_test_tcp(native_io_backend_kind backend_kind, bool resolve_host,
                                cnet_owner_test_timeout timeout) {
  static const unsigned char payload[] = {1u, 3u, 5u, 7u};
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  cnet_owner_test_clock clock = {.now_ms = 100u,
                                 .next_ms = timeout == CNET_OWNER_TEST_CONNECT_TIMEOUT ||
                                                    timeout == CNET_OWNER_TEST_WRITE_TIMEOUT
                                                ? 111u
                                                : 100u,
                                 .calls = 0u};
  const cnet_owner_config owner_config = {
      .backend_kind = backend_kind,
      .connection_capacity = 1u,
      .request_capacity = 4u,
      .completion_batch_capacity = 4u,
      .receive_buffer_bytes = 64u,
      .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
      .commands = &commands,
      .events = &events,
      .now_ms = timeout != CNET_OWNER_TEST_NO_TIMEOUT ? cnet_owner_test_now : NULL,
      .clock_context = timeout != CNET_OWNER_TEST_NO_TIMEOUT ? &clock : NULL};
  cnet_owner_test_socket listener = CNET_OWNER_TEST_INVALID_SOCKET;
  cnet_owner_test_socket accepted = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in address;
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_command command = {0};
  cnet_event queued_state = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
#if defined(CNET_INTERNAL_TESTING)
  cnet_owner_test_request_snapshot first_request = {0};
  cnet_owner_test_request_snapshot second_request = {0};
  cnet_owner_test_request_snapshot after_stale = {0};
#endif
#if defined(CNET_INTERNAL_PROFILING)
  cnet_owner_profile receive_profile = {0};
  cnet_owner_profile send_profile = {0};
  const bool profile_suspended_receive = timeout == CNET_OWNER_TEST_NO_TIMEOUT && !resolve_host;
  const bool profile_partial_send = timeout == CNET_OWNER_TEST_NO_TIMEOUT && !resolve_host;
#endif
  unsigned char received[sizeof(payload)] = {0};
  size_t event_index;

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(cnet_owner_test_listener(&listener, &address), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);
  queued_state = (cnet_event){CNET_EVENT_STATE,
                              {UINT32_MAX, UINT32_MAX},
                              CNET_EVENT_STATE_CLOSING,
                              SALTS_OK,
                              CNET_SESSION_STAGE_NONE,
                              NULL,
                              0u};
  for (event_index = 0u; event_index < event_config.capacity; ++event_index)
    check_equal(cnet_event_queue_publish(&events, &queued_state), SALTS_OK);
  connect_payload.scheme = CNET_URI_TCP;
  connect_payload.connect_timeout_ms = timeout == CNET_OWNER_TEST_CONNECT_TIMEOUT ? 10u : 0u;
  connect_payload.read_timeout_ms = timeout == CNET_OWNER_TEST_READ_TIMEOUT ? 10u : 0u;
  connect_payload.write_timeout_ms = timeout == CNET_OWNER_TEST_WRITE_TIMEOUT ? 10u : 0u;
  if (resolve_host) {
    memcpy(connect_payload.host, "127.0.0.1", sizeof("127.0.0.1"));
    connect_payload.port = ntohs(address.sin_port);
  } else {
    connect_payload.address_length = sizeof(address);
    memcpy(connect_payload.address, &address, sizeof(address));
  }
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
#if defined(_WIN32)
  if (resolve_host && timeout == CNET_OWNER_TEST_NO_TIMEOUT)
    cnet_owner_test_issue64_listener_snapshot("before_drive", listener,
                                              &address, session);
#endif
  if (timeout == CNET_OWNER_TEST_CONNECT_TIMEOUT) {
    check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
                SALTS_OK);
    for (event_index = 0u; event_index < event_config.capacity; ++event_index) {
      check_equal(cnet_owner_test_drive_to_event(&owner, &events, &event), SALTS_OK);
      check_equal(event.state, CNET_EVENT_STATE_CLOSING);
      check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
    }
    check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
    check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
    check_equal(event.kind, CNET_EVENT_STATE);
    check_equal(event.state, CNET_EVENT_STATE_FAILED);
    check_equal(event.status, SALTS_ETIMEDOUT);
    check_equal(event.stage,
                resolve_host ? CNET_SESSION_STAGE_RESOLVE : CNET_SESSION_STAGE_CONNECT);
    check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
    check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
    check_equal(terminal.kind, CNET_SESSION_TERMINAL_FAILED);
    check_equal(terminal.status, SALTS_ETIMEDOUT);
    check_equal(terminal.stage,
                resolve_host ? CNET_SESSION_STAGE_RESOLVE : CNET_SESSION_STAGE_CONNECT);
#if defined(CNET_INTERNAL_TESTING)
    /*
     * Owner work is advisory and may be queued by a callback before a later
     * completion in the same batch makes this generation terminal. Recycling
     * must remove that hint before the session record is zeroed.
     */
    check_equal(cnet_owner_test_queue_session_work(&owner, session), SALTS_OK);
#endif
    check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
    check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);
#if defined(CNET_INTERNAL_TESTING)
    check_equal(cnet_owner_test_process_session_work(&owner), SALTS_OK);
#endif
    goto cleanup;
  }
  if (resolve_host && timeout == CNET_OWNER_TEST_NO_TIMEOUT) {
    const int admission_status =
        cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN);
#if defined(_WIN32)
    if (admission_status != SALTS_OK) {
      native_io_backend_stats native_stats = {0};
      native_io_coroutine_stats coroutine_stats =
          NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER;
      const bool has_stats =
          cnet_owner_test_backend_stats(&owner, &native_stats, &coroutine_stats);
      cnet_owner_test_issue64_listener_snapshot("after_failure", listener,
                                                &address, session);
      fprintf(stderr,
              "CNET_ISSUE64_OWNER_FAILURE status=%d"
              " backend_stats=%d active_requests=%zu"
              " coroutine_active=%zu retained_frames=%zu\n",
              admission_status, has_stats ? 1 : 0,
              has_stats ? (size_t)native_stats.active_requests : 0u,
              has_stats ? (size_t)coroutine_stats.active : 0u,
              has_stats ? (size_t)coroutine_stats.retained_frames : 0u);
    }
#endif
    check_equal(admission_status, SALTS_OK);
  } else {
    check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN),
                SALTS_OK);
  }
#if defined(_WIN32) && defined(CNET_INTERNAL_TESTING)
  if (timeout == CNET_OWNER_TEST_NO_TIMEOUT) {
    struct sockaddr_in selected = {0};
    size_t selected_length = 0u;
    check_equal(cnet_owner_test_copy_peer_sockaddr(
                    &owner, session, &selected, sizeof(selected),
                    &selected_length), SALTS_OK);
    check_equal(selected_length, sizeof(address));
    check_equal(selected.sin_family, AF_INET);
    check_equal(selected.sin_addr.s_addr, address.sin_addr.s_addr);
    check_equal(selected.sin_port, address.sin_port);
  }
#endif
  for (event_index = 0u; event_index < event_config.capacity; ++event_index) {
    check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
    check_equal(event.state, CNET_EVENT_STATE_CLOSING);
    check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  }
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CONNECTED);
  check_equal(event.session.slot, session.slot);
  check_equal(event.session.generation, session.generation);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  accepted = accept(listener, NULL, NULL);
  check_true(accepted != CNET_OWNER_TEST_INVALID_SOCKET);

  command = (cnet_command){CNET_COMMAND_RECEIVE, session, NULL, 0u, 1u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
#if defined(CNET_INTERNAL_PROFILING)
  if (profile_suspended_receive) check_equal(cnet_owner_profile_begin(&owner), SALTS_OK);
#endif
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
#if defined(CNET_INTERNAL_TESTING)
  {
    native_io_backend_stats native_stats = {0};
    native_io_coroutine_stats coroutine_stats =
        NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER;
    check_true(cnet_owner_test_backend_stats(&owner, &native_stats, &coroutine_stats));
    check_equal(native_stats.active_requests, 1u);
    check_equal(coroutine_stats.active, 0u);
    check_equal(coroutine_stats.retained_frames, 0u);
  }
#endif
#if defined(CNET_INTERNAL_TESTING)
  if (timeout == CNET_OWNER_TEST_NO_TIMEOUT && resolve_host)
    check_true(cnet_owner_test_get_request_snapshot(&owner, 0u, &first_request));
#endif
  if (timeout == CNET_OWNER_TEST_READ_TIMEOUT) {
    clock.now_ms = 111u;
    clock.next_ms = 111u;
  } else {
#if defined(CNET_INTERNAL_PROFILING)
    if (profile_suspended_receive) cmeta_sleep_ms(10u);
#endif
    check_equal(send(accepted, (const char *)payload, (int)sizeof(payload), 0),
                (int)sizeof(payload));
#if defined(CNET_INTERNAL_TESTING)
    if (resolve_host) {
      native_io_completion observed[1] = {{0}};
      native_io_completion batch[2] = {{0}};
      size_t observed_count = 0u;
      check_equal(cnet_owner_test_observe_raw(&owner, observed, 1u,
                                              CNET_OWNER_TEST_TIMEOUT_MS,
                                              &observed_count),
                  SALTS_OK);
      check_equal(observed_count, 1u);
      batch[0].kind = NATIVE_IO_COMPLETION_FAILED;
      batch[0].status = SALTS_EPROTO;
      batch[0].user_data = 0u;
      batch[1] = observed[0];
      check_equal(cnet_owner_test_process_completion_batch(&owner, batch, 2u), SALTS_EPROTO);
      check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
    } else
#endif
    {
      check_equal(cnet_owner_test_drive_to_event(&owner, &events, &event), SALTS_OK);
    }
    check_equal(event.kind, CNET_EVENT_RECEIVE);
    check_equal(event.data, payload, sizeof(payload));
    check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
#if defined(CNET_INTERNAL_TESTING)
    if (resolve_host) {
      native_io_completion stale = {0};
      command = (cnet_command){CNET_COMMAND_RECEIVE, session, NULL, 0u, 1u};
      check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
      check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
      check_true(cnet_owner_test_get_request_snapshot(&owner, 0u, &second_request));
      check_equal(second_request.token, first_request.token);
      check_true(second_request.native_request.slot != first_request.native_request.slot ||
                 second_request.native_request.generation != first_request.native_request.generation);
      stale.request = first_request.native_request;
      stale.endpoint = second_request.endpoint;
      stale.kind = NATIVE_IO_COMPLETION_CANCELLED;
      stale.status = SALTS_OK;
      stale.user_data = second_request.token;
      check_equal(cnet_owner_test_process_completion_batch(&owner, &stale, 1u), SALTS_EPROTO);
      check_true(cnet_owner_test_get_request_snapshot(&owner, 0u, &after_stale));
      check_true(after_stale.active);
      check_equal(after_stale.native_request.slot, second_request.native_request.slot);
      check_equal(after_stale.native_request.generation, second_request.native_request.generation);
    }
#endif
#if defined(CNET_INTERNAL_PROFILING)
    if (profile_suspended_receive) {
      check_equal(cnet_owner_profile_take(&owner, &receive_profile), SALTS_OK);
      check_equal(receive_profile.request_completion_calls, UINT64_C(1));
      check_equal(receive_profile.event_publish_calls, UINT64_C(1));
      check_true(receive_profile.owner_drive_ns >= receive_profile.request_completion_ns);
    }
#endif

    if (timeout == CNET_OWNER_TEST_WRITE_TIMEOUT) {
      check_equal(clock.calls, 0u);
      clock.now_ms = 100u;
      clock.next_ms = 111u;
    }
#if defined(CNET_INTERNAL_PROFILING) && defined(CNET_INTERNAL_TESTING)
    if (profile_partial_send) {
      check_equal(cnet_owner_test_set_send_chunk_bytes(&owner, 1u), SALTS_OK);
      check_equal(cnet_owner_profile_begin(&owner), SALTS_OK);
    }
#endif
    check_equal(cnet_owner_test_send_bytes(
                    &owner, session, payload, sizeof(payload),
                    timeout == CNET_OWNER_TEST_WRITE_TIMEOUT),
                SALTS_OK);
    if (timeout == CNET_OWNER_TEST_WRITE_TIMEOUT) {
      check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
                  SALTS_OK);
    } else {
      check_equal(cnet_owner_drive(&owner, CNET_OWNER_TEST_TIMEOUT_MS), SALTS_OK);
      check_equal(cnet_owner_test_receive_all(accepted, received, sizeof(received)), SALTS_OK);
      check_equal(received, payload, sizeof(payload));
      check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
      check_equal(event.kind, CNET_EVENT_SEND);
      check_equal(event.argument, sizeof(payload));
      check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
#if defined(CNET_INTERNAL_PROFILING) && defined(CNET_INTERNAL_TESTING)
      if (profile_partial_send) {
        check_equal(cnet_owner_profile_take(&owner, &send_profile), SALTS_OK);
        check_equal(send_profile.request_start_calls, UINT64_C(1));
        check_equal(send_profile.request_resubmit_calls, UINT64_C(3));
        check_equal(send_profile.request_completion_calls, UINT64_C(1));
        check_equal(cnet_owner_test_set_send_chunk_bytes(&owner, 0u), SALTS_OK);
      }
#endif

      command = (cnet_command){CNET_COMMAND_CLOSE, session, NULL, 0u, 0u};
      check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
    }
  }
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, timeout != CNET_OWNER_TEST_NO_TIMEOUT ? CNET_EVENT_STATE_FAILED
                                                                 : CNET_EVENT_STATE_CLOSING);
  if (timeout == CNET_OWNER_TEST_READ_TIMEOUT || timeout == CNET_OWNER_TEST_WRITE_TIMEOUT) {
    check_equal(event.status, SALTS_ETIMEDOUT);
    check_equal(event.stage, timeout == CNET_OWNER_TEST_READ_TIMEOUT ? CNET_SESSION_STAGE_READ
                                                                     : CNET_SESSION_STAGE_WRITE);
  }
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  if (timeout == CNET_OWNER_TEST_NO_TIMEOUT) {
    check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
    check_equal(event.state, CNET_EVENT_STATE_CLOSED);
    check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  }
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, timeout != CNET_OWNER_TEST_NO_TIMEOUT ? CNET_SESSION_TERMINAL_FAILED
                                                                   : CNET_SESSION_TERMINAL_CLOSED);
  if (timeout == CNET_OWNER_TEST_READ_TIMEOUT || timeout == CNET_OWNER_TEST_WRITE_TIMEOUT) {
    check_equal(terminal.status, SALTS_ETIMEDOUT);
    check_equal(terminal.stage, timeout == CNET_OWNER_TEST_READ_TIMEOUT ? CNET_SESSION_STAGE_READ
                                                                        : CNET_SESSION_STAGE_WRITE);
  }
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

cleanup:
  cnet_owner_test_close_socket(accepted);
  cnet_owner_test_close_socket(listener);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}

#if defined(CNET_INTERNAL_TESTING)
/* Deterministically reproduce the byte-swapped Windows first-RED input
 * (0xC605 -> 0x05C6) without requiring a coincidental ephemeral port. */
static void cnet_owner_test_requested_port_byte_order(void) {
  const uint16_t requested_port = UINT16_C(50693);
  struct sockaddr_in v4 = {0};
  struct sockaddr_in6 v6 = {0};
  v4.sin_family = AF_INET;
  v4.sin_port = htons(UINT16_C(1478));
  v6.sin6_family = AF_INET6;
  v6.sin6_port = htons(UINT16_C(1478));
  check_equal(ntohs(v4.sin_port), UINT16_C(1478));
  check_equal(ntohs(v6.sin6_port), UINT16_C(1478));
  check_equal(cnet_resolver_test_apply_requested_port(
                  &v4, sizeof(v4), AF_INET, requested_port), SALTS_OK);
  check_equal(cnet_resolver_test_apply_requested_port(
                  &v6, sizeof(v6), AF_INET6, requested_port), SALTS_OK);
  check_equal(ntohs(v4.sin_port), requested_port);
  check_equal(ntohs(v6.sin6_port), requested_port);
  check_equal(cnet_resolver_test_apply_requested_port(
                  &v4, sizeof(v4) - 1u, AF_INET, requested_port), SALTS_EINVAL);
  check_equal(cnet_resolver_test_apply_requested_port(
                  &v6, sizeof(v6) - 1u, AF_INET6, requested_port), SALTS_EINVAL);
  check_equal(cnet_resolver_test_apply_requested_port(
                  &v4, sizeof(v4), AF_UNSPEC, requested_port), SALTS_EAI_FAMILY);
  check_equal(cnet_resolver_test_apply_requested_port(
                  &v4, sizeof(v4), AF_INET, 0u), SALTS_EINVAL);
}
#endif

#if defined(_WIN32)
/*
 * Issue #64: deterministic real ConnectEx refusal. Keep an exclusive
 * TCP port BOUND but NOT LISTENING while the Owner connects. Unlike
 * closing a listener, this avoids releasing its ephemeral port to a
 * different process between fixture creation and client admission.
 *
 * Both the direct sockaddr and numeric-host resolver paths must report
 * one native connect refusal, retire the physical request and endpoint,
 * and publish exactly one failed terminal. No retry/fallback/mock IOCP.
 */
static void cnet_owner_test_refused_connect_win32(bool via_resolver) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {
      4u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {4u, 1u, 64u};
  const cnet_owner_config config = {
      .backend_kind = NATIVE_IO_BACKEND_IOCP,
      .connection_capacity = 1u,
      .request_capacity = 2u,
      .completion_batch_capacity = 2u,
      .receive_buffer_bytes = 64u,
      .receive_buffer_count = 1u,
      .write_capacity = 4u,
      .max_write_bytes = 128u,
      .sessions = &sessions,
      .commands = &commands,
      .events = &events};
  cnet_owner_test_socket reserved = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in bound = {0};
  int bound_length = (int)sizeof(bound);
  int exclusive = 1;
  int listening = -1;
  int listening_length = (int)sizeof(listening);
  cnet_session_handle session = {0};
  cnet_owner_connect_payload payload = {0};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  native_io_backend_stats stats = {0};
  native_io_coroutine_stats coroutines =
      NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER;
  int published_status = SALTS_OK;

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &config), SALTS_OK);
  reserved = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  check_true(reserved != INVALID_SOCKET);
  check_equal(setsockopt(reserved, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                         (const char *)&exclusive, (int)sizeof(exclusive)), 0);
  bound.sin_family = AF_INET;
  bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  check_equal(bind(reserved, (const struct sockaddr *)&bound,
                   (int)sizeof(bound)), 0);
  check_equal(getsockname(reserved, (struct sockaddr *)&bound,
                          &bound_length), 0);
  check_equal(bound.sin_family, AF_INET);
  check_equal(bound.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
  check_true(ntohs(bound.sin_port) != 0u);
  check_equal(getsockopt(reserved, SOL_SOCKET, SO_ACCEPTCONN,
                         (char *)&listening, &listening_length), 0);
  check_equal(listening, 0);

  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);
  payload.scheme = CNET_URI_TCP;
  if (via_resolver) {
    memcpy(payload.host, "127.0.0.1", sizeof("127.0.0.1"));
    payload.port = ntohs(bound.sin_port);
  } else {
    memcpy(payload.address, &bound, sizeof(bound));
    payload.address_length = sizeof(bound);
  }
  command = (cnet_command){
      CNET_COMMAND_CONNECT, session, &payload, sizeof(payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(
                  &owner, &sessions, session, CNET_SESSION_TERMINAL), SALTS_OK);
  /* A refused connection to the wrong resolved endpoint would also produce
   * a refusal. Prove the exact bound listener IP/port survived resolution. */
  {
    struct sockaddr_in selected = {0};
    size_t selected_length = 0u;
    check_equal(cnet_owner_test_copy_peer_sockaddr(
                    &owner, session, &selected, sizeof(selected),
                    &selected_length), SALTS_OK);
    check_equal(selected_length, sizeof(bound));
    check_equal(selected.sin_family, AF_INET);
    check_equal(selected.sin_addr.s_addr, bound.sin_addr.s_addr);
    check_equal(selected.sin_port, bound.sin_port);
  }
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_FAILED);
  check_equal(event.stage, CNET_SESSION_STAGE_CONNECT);
  published_status = event.status;
  /* Win32 returns ERROR_CONNECTION_REFUSED (1225) from ConnectEx
   * completions, or WSAECONNREFUSED (10061) from a socket API. */
  check_true(published_status == -1225 ||
             published_status == -(int)WSAECONNREFUSED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_ETIMEDOUT);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal),
              SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_FAILED);
  check_equal(terminal.stage, CNET_SESSION_STAGE_CONNECT);
  check_equal(terminal.status, published_status);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal),
              SALTS_EALREADY);
  check_true(cnet_owner_test_backend_stats(&owner, &stats, &coroutines));
  check_equal(stats.active_requests, 0u);
  check_equal(stats.endpoint_count, 0u);
  check_equal(stats.submitted, stats.completed);
  check_equal(stats.cancelled, UINT64_C(0));
  check_equal(stats.native_submit_errors + stats.failed, UINT64_C(1));
  check_equal(coroutines.active, 0u);
  check_equal(coroutines.retained_frames, 0u);
  fprintf(stderr,
          "CNET_ISSUE64_CONTROLLED_REFUSAL path=%s port=%u status=%d"
          " submitted=%llu completed=%llu native_submit_errors=%llu"
          " failed=%llu active_requests=%zu endpoints=%zu\n",
          via_resolver ? "numeric-host" : "direct-sockaddr",
          (unsigned)ntohs(bound.sin_port), published_status,
          (unsigned long long)stats.submitted,
          (unsigned long long)stats.completed,
          (unsigned long long)stats.native_submit_errors,
          (unsigned long long)stats.failed,
          stats.active_requests, stats.endpoint_count);

  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
  cnet_owner_test_close_socket(reserved);
}
#endif

#if defined(CNET_INTERNAL_TESTING)
static void cnet_owner_test_expired_partial_send(native_io_backend_kind backend_kind) {
  enum { PAYLOAD_BYTES = 8, WRITE_TIMEOUT_MS = 10 };
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  cnet_owner_test_clock clock = {.now_ms = 100u, .next_ms = 100u};
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config config = {.backend_kind = backend_kind,
                                   .connection_capacity = 1u, .request_capacity = 2u,
                                   .completion_batch_capacity = 2u, .receive_buffer_bytes = 64u,
                                   .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
                                   .commands = &commands, .events = &events,
                                   .now_ms = cnet_owner_test_now, .clock_context = &clock};
  cnet_owner_test_socket listener = CNET_OWNER_TEST_INVALID_SOCKET;
  cnet_owner_test_socket accepted = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in address;
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {.scheme = CNET_URI_TCP,
                                               .write_timeout_ms = WRITE_TIMEOUT_MS};
  unsigned char payload[PAYLOAD_BYTES] = {0};
  cnet_command command;
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  native_io_completion completion = {0};
  native_io_backend_stats before = {0}, after = {0};
  native_io_coroutine_stats coroutine = NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER;
  size_t count = 0u;

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &config), SALTS_OK);
  check_equal(cnet_owner_test_listener(&listener, &address), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);
  connect_payload.address_length = sizeof(address);
  memcpy(connect_payload.address, &address, sizeof(address));
  command = (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  accepted = accept(listener, NULL, NULL);
  check_true(accepted != CNET_OWNER_TEST_INVALID_SOCKET);
  check_equal(cnet_owner_test_set_send_chunk_bytes(&owner, 1u), SALTS_OK);
  check_equal(cnet_owner_test_send_bytes(&owner, session, payload, sizeof(payload), false),
              SALTS_OK);
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
  check_equal(cnet_owner_test_observe_raw(&owner, &completion, 1u,
                                         CNET_OWNER_TEST_TIMEOUT_MS, &count), SALTS_OK);
  check_equal(count, 1u);
  check_equal(completion.kind, NATIVE_IO_COMPLETION_OK);
  check_equal(completion.bytes, 1u);
  check_true(cnet_owner_test_backend_stats(&owner, &before, &coroutine));
  clock.now_ms += WRITE_TIMEOUT_MS + 1u;
  clock.next_ms = clock.now_ms;
  /* NativeIO has released the observed handle, but CNet still owns its payload.
     Expire the owner deadline before routing that successful partial completion. */
  check_equal(cnet_owner_test_process_deadlines(&owner), SALTS_ENOENT);
  check_equal(cnet_owner_test_process_completion_batch(&owner, &completion, count), SALTS_OK);
  check_true(cnet_owner_test_backend_stats(&owner, &after, &coroutine));
  check_equal(after.submitted, before.submitted);
  check_equal(after.active_requests, 0u);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.status, SALTS_ETIMEDOUT);
  check_equal(terminal.stage, CNET_SESSION_STAGE_WRITE);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_FAILED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);
  cnet_owner_test_close_socket(accepted);
  cnet_owner_test_close_socket(listener);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}

static void cnet_owner_test_expired_partial_vector_send(
    native_io_backend_kind backend_kind, bool expire_before_observe,
    bool force_cancel_ealready) {
  enum { PAYLOAD_BYTES = 8, WRITE_TIMEOUT_MS = 10 };
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  mem_pool_t pool;
  cnet_owner_test_clock clock = {.now_ms = 100u, .next_ms = 100u};
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config config = {.backend_kind = backend_kind,
                                   .connection_capacity = 1u,
                                   .request_capacity = 2u,
                                   .completion_batch_capacity = 2u,
                                   .receive_buffer_bytes = 64u,
                                   .receive_buffer_count = 1u,
                                   .write_capacity = 8u,
                                   .max_write_bytes = 256u,
                                   .sessions = &sessions,
                                   .commands = &commands,
                                   .events = &events,
                                   .now_ms = cnet_owner_test_now,
                                   .clock_context = &clock};
  cnet_owner_test_socket listener = CNET_OWNER_TEST_INVALID_SOCKET;
  cnet_owner_test_socket accepted = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in address;
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {.scheme = CNET_URI_TCP,
                                               .write_timeout_ms = WRITE_TIMEOUT_MS};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  native_io_completion completion = {0};
  native_io_backend_stats before = {0}, after = {0};
  native_io_coroutine_stats coroutine = NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER;
  mem_buffer_t *buffer = NULL;
  mem_buffer_t *original_buffer = NULL;
  mem_buffer_t *recycled_buffer = NULL;
  mem_buffer_t *competing[4] = {0};
  mem_slice_t slices[2] = {{0}};
  size_t count = 0u;

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &config), SALTS_OK);
  check_equal(mem_init(&pool, 0u), 0);
  check_equal(cnet_owner_test_listener(&listener, &address), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);
  connect_payload.address_length = sizeof(address);
  memcpy(connect_payload.address, &address, sizeof(address));
  {
    const cnet_command command =
        (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload,
                       sizeof(connect_payload), 0u};
    check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  }
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  accepted = accept(listener, NULL, NULL);
  check_true(accepted != CNET_OWNER_TEST_INVALID_SOCKET);

  buffer = mem_get_buffer(&pool, PAYLOAD_BYTES);
  check_true(buffer != NULL);
  memset(mem_buffer_data(buffer), 0x5au, PAYLOAD_BYTES);
  mem_set_used(buffer, PAYLOAD_BYTES);
  slices[0] = mem_slice(buffer, 0u, 3u);
  slices[1] = mem_slice(buffer, 3u, 5u);
  check_equal(mem_buffer_ref_count(buffer), UINT32_C(3));
  check_equal(cnet_owner_test_set_send_chunk_bytes(&owner, 1u), SALTS_OK);
  check_equal(cnet_owner_send_slicev_direct(&owner, session, slices, 2u), SALTS_OK);
  check_equal(mem_buffer_ref_count(buffer), UINT32_C(4));
  mem_slice_release(&slices[0]);
  mem_slice_release(&slices[1]);
  check_equal(mem_buffer_ref_count(buffer), UINT32_C(2));

  /* After the caller releases its final reference, the *native CNet Owner*
   * is the sole keeper of the original pooled backing. It must not be
   * returned to the pool while the real partial send is still outstanding.
   * Keep each competing allocation alive so no unrelated free can satisfy
   * the later exact-block recycle check. No sleeps or synthetic I/O. */
  original_buffer = buffer;
  mem_buffer_release(buffer);
  buffer = NULL;
  check_equal(mem_buffer_ref_count(original_buffer), UINT32_C(1));
  for (size_t index = 0u; index < 4u; ++index) {
    competing[index] = mem_get_buffer(&pool, PAYLOAD_BYTES);
    check_not_null(competing[index]);
    check_true(competing[index] != original_buffer);
    memset(mem_buffer_data(competing[index]), 0xa5, PAYLOAD_BYTES);
    mem_set_used(competing[index], PAYLOAD_BYTES);
  }
  for (size_t index = 0u; index < PAYLOAD_BYTES; ++index)
    check_equal((unsigned char)mem_buffer_const_data(original_buffer)[index],
                (unsigned char)0x5a);

  check_equal(cnet_owner_test_process_session_work(&owner), SALTS_OK);
  /* Internal test-only hook exercises a NativeIO EALREADY report after the
   * underlying cancellation call. The original kernel terminal still must
   * be observed; no completion is synthesized or ownership released here. */
  if (force_cancel_ealready)
    check_equal(cnet_owner_test_force_cancel_ealready_once(&owner), SALTS_OK);
  if (expire_before_observe) {
    /* Cancel first while NativeIO owns the real submitted write, without
     * previously observing its completion. A raced native success is valid,
     * but neither outcome may retire CNet's backing prematurely. */
    clock.now_ms += WRITE_TIMEOUT_MS + 1u;
    clock.next_ms = clock.now_ms;
    /* No completion was observed yet: NativeIO still owns the pending
     * request and accepts the Owner's cancellation (SALTS_OK). The old
     * completion-first ordering instead returns ENOENT at expiry. */
    check_equal(cnet_owner_test_process_deadlines(&owner), SALTS_OK);
    check_equal(mem_buffer_ref_count(original_buffer), UINT32_C(1));
  }
  check_equal(cnet_owner_test_observe_raw(&owner, &completion, 1u,
                                         CNET_OWNER_TEST_TIMEOUT_MS, &count),
              SALTS_OK);
  check_equal(count, 1u);
  if (!expire_before_observe) {
    check_equal(completion.kind, NATIVE_IO_COMPLETION_OK);
    check_equal(completion.bytes, 1u);
  } else {
    /* Cancellation may win or the original one-byte kernel completion
     * may have already won; neither authorizes an eight-byte logical send. */
    check_true(completion.kind == NATIVE_IO_COMPLETION_OK ||
               completion.kind == NATIVE_IO_COMPLETION_CANCELLED);
    if (completion.kind == NATIVE_IO_COMPLETION_OK)
      check_equal(completion.bytes, 1u);
  }
  /* The real first-byte kernel completion is retrieved, but has not been
   * dispatched to CNet. Even here no pooled buffer may be recycled. */
  check_equal(mem_buffer_ref_count(original_buffer), UINT32_C(1));
  check_true(cnet_owner_test_backend_stats(&owner, &before, &coroutine));

  if (!expire_before_observe) {
    clock.now_ms += WRITE_TIMEOUT_MS + 1u;
    clock.next_ms = clock.now_ms;
    check_equal(cnet_owner_test_process_deadlines(&owner), SALTS_ENOENT);
  }
  check_equal(cnet_owner_test_process_completion_batch(&owner, &completion, count), SALTS_OK);
  check_true(cnet_owner_test_backend_stats(&owner, &after, &coroutine));
  check_equal(after.submitted, before.submitted);
  check_equal(after.active_requests, 0u);

  /* The write deadline and original native completion have both been
   * settled. The sole recyclable backing in this private pool must now be
   * the exact block CNet had retained until the terminal. Its fresh ref=1
   * also rejects a missing release and avoids dereferencing retired bytes. */
  recycled_buffer = mem_get_buffer(&pool, PAYLOAD_BYTES);
  check_not_null(recycled_buffer);
  check_true(recycled_buffer == original_buffer);
  check_equal(mem_buffer_ref_count(recycled_buffer), UINT32_C(1));
  check_equal(mem_buffer_used(recycled_buffer), (size_t)0u);
  memset(mem_buffer_data(recycled_buffer), 0x3c, PAYLOAD_BYTES);
  mem_set_used(recycled_buffer, PAYLOAD_BYTES);

  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.status, SALTS_ETIMEDOUT);
  check_equal(terminal.stage, CNET_SESSION_STAGE_WRITE);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_FAILED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  mem_buffer_release(recycled_buffer);
  recycled_buffer = NULL;
  for (size_t index = 0u; index < 4u; ++index) {
    mem_buffer_release(competing[index]);
    competing[index] = NULL;
  }
  check_equal(cnet_owner_test_set_send_chunk_bytes(&owner, 0u), SALTS_OK);
  cnet_owner_test_close_socket(accepted);
  cnet_owner_test_close_socket(listener);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
  mem_destroy(&pool);
}

static void cnet_owner_test_close_observed_receive(native_io_backend_kind backend_kind) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config config = {
      .backend_kind = backend_kind, .connection_capacity = 1u,
      .request_capacity = 2u, .completion_batch_capacity = 2u,
      .receive_buffer_bytes = 64u, .receive_buffer_count = 1u,
      .write_capacity = 8u, .max_write_bytes = 256u,
      .sessions = &sessions, .commands = &commands, .events = &events};
  cnet_owner_test_socket listener = CNET_OWNER_TEST_INVALID_SOCKET;
  cnet_owner_test_socket accepted = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in address;
  cnet_session_handle session = {0};
  cnet_owner_connect_payload peer = {.scheme = CNET_URI_TCP, .read_timeout_ms = 1000u};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  native_io_completion observed[2] = {{0}};
  native_io_backend_stats stats = {0};
  native_io_coroutine_stats coroutine = NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER;
  uintptr_t send_token = 0u;
  size_t count = 0u;
  unsigned char received = 0u;
  const unsigned char payload = 0x47u;
  mem_buffer_t *buffer = NULL;
  uint64_t deadline;

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &config), SALTS_OK);
  check_equal(cnet_owner_test_listener(&listener, &address), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);
  peer.address_length = sizeof(address);
  memcpy(peer.address, &address, sizeof(address));
  {
    const cnet_command command = {CNET_COMMAND_CONNECT, session, &peer, sizeof(peer), 0u};
    check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  }
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CONNECTED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  accepted = accept(listener, NULL, NULL);
  check_true(accepted != CNET_OWNER_TEST_INVALID_SOCKET);

  buffer = mem_get_buffer(mem_global(), 1u);
  check_not_null(buffer);
  *mem_buffer_data(buffer) = payload;
  mem_set_used(buffer, 1u);
  check_equal(cnet_owner_send_buffer_close_direct(&owner, session, buffer), SALTS_OK);
  check_equal(cnet_owner_test_process_session_work(&owner), SALTS_OK);
  for (size_t index = 0u; index < config.request_capacity; ++index) {
    cnet_owner_test_request_snapshot request = {0};
    check_true(cnet_owner_test_get_request_snapshot(&owner, index, &request));
    if (request.active) send_token = request.token;
  }
  check_not_equal(send_token, (uintptr_t)0u);
  check_equal(cnet_owner_receive_direct(&owner, session, 1u), SALTS_OK);
  check_equal(cnet_owner_test_process_session_work(&owner), SALTS_OK);
  check_equal(send(accepted, (const char *)&payload, 1, 0), 1);

  /* Observe two REAL native terminals before routing either one. Their
   * NativeIO slots are retired, but CNet still owns both generations and
   * their backing. Route the final send first to exercise close cancelling
   * the already-observed receive, independent of kernel completion order. */
  deadline = cmeta_monotonic_ms() + CNET_OWNER_TEST_TIMEOUT_MS;
  while (count < 2u && cmeta_monotonic_ms() < deadline) {
    size_t next = 0u;
    const int status = cnet_owner_test_observe_raw(
        &owner, &observed[count], 2u - count, 10u, &next);
    check_true(status == SALTS_OK || status == SALTS_ETIMEDOUT);
    count += next;
  }
  check_equal(count, (size_t)2u);
  if (observed[1].user_data == send_token) {
    const native_io_completion swap = observed[0];
    observed[0] = observed[1];
    observed[1] = swap;
  }
  check_equal(observed[0].user_data, send_token);
  check_not_equal(observed[1].user_data, send_token);
  for (size_t index = 0u; index < count; ++index) {
    check_equal(observed[index].kind, NATIVE_IO_COMPLETION_OK);
    check_equal(observed[index].bytes, (size_t)1u);
  }
  /* io_uring submits its prepared SQEs while observing. Never block the
   * independent peer on a send before the sole NativeIO owner has run. */
  check_equal(cnet_owner_test_receive_all(accepted, &received, 1u), SALTS_OK);
  check_equal(received, payload);
  check_equal(mem_buffer_ref_count(buffer), UINT32_C(2));
  check_true(cnet_owner_test_backend_stats(&owner, &stats, &coroutine));
  check_equal(stats.active_requests, 0u);
  check_equal(cnet_owner_test_process_completion_batch(&owner, observed, count), SALTS_OK);
  check_equal(mem_buffer_ref_count(buffer), UINT32_C(1));
  mem_buffer_release(buffer);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_CLOSED);
  check_equal(terminal.status, SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_SEND);
  check_equal(event.argument, (size_t)1u);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CLOSING);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CLOSED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_ETIMEDOUT);
  check_true(cnet_owner_test_backend_stats(&owner, &stats, &coroutine));
  check_equal(stats.active_requests, 0u);
  check_equal(stats.endpoint_count, 0u);
  check_equal(coroutine.active, 0u);
  check_equal(coroutine.retained_frames, 0u);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);
  cnet_owner_test_close_socket(accepted);
  cnet_owner_test_close_socket(listener);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}

static void cnet_owner_test_cancel_ealready(native_io_backend_kind backend_kind) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  cnet_owner_test_clock clock = {.now_ms = 1000u, .next_ms = 1000u};
  const cnet_owner_config owner_config = {.backend_kind = backend_kind,
                                          .connection_capacity = 1u,
                                          .request_capacity = 2u,
                                          .completion_batch_capacity = 2u,
                                          .receive_buffer_bytes = 64u,
                                          .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
                                          .commands = &commands,
                                          .events = &events,
                                          .now_ms = cnet_owner_test_now,
                                          .clock_context = &clock};
  cnet_owner_test_socket listener = CNET_OWNER_TEST_INVALID_SOCKET;
  cnet_owner_test_socket accepted = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in address;
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  native_io_backend_stats native_stats = {0};
  native_io_coroutine_stats coroutine_stats = NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER;

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(cnet_owner_test_listener(&listener, &address), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);

  connect_payload.scheme = CNET_URI_TCP;
  /* A real NativeIO receive owns a configured READ deadline while pending.
   * User close must invalidate it on accepted cancellation, not on the
   * eventual CANCELLED/EALREADY completion. */
  connect_payload.read_timeout_ms = 20u;
  connect_payload.address_length = sizeof(address);
  memcpy(connect_payload.address, &address, sizeof(address));
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CONNECTED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  accepted = accept(listener, NULL, NULL);
  check_true(accepted != CNET_OWNER_TEST_INVALID_SOCKET);

  command = (cnet_command){CNET_COMMAND_RECEIVE, session, NULL, 0u, 1u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
  check_true(cnet_owner_test_backend_stats(&owner, &native_stats, &coroutine_stats));
  check_equal(native_stats.active_requests, 1u);

  check_equal(cnet_owner_test_force_cancel_ealready_once(&owner), SALTS_OK);
  command = (cnet_command){CNET_COMMAND_CLOSE, session, NULL, 0u, 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
  check_true(cnet_owner_test_backend_stats(&owner, &native_stats, &coroutine_stats));
  check_equal(native_stats.active_requests, 1u);

  /* The cancellation was accepted but its real kernel terminal has not
   * yet been routed to this Owner. Move the SAME owner clock past the
   * previously armed READ deadline. Expiring an obsolete timer here would
   * wrongly turn an intentionally closing session into FAILED. No sleep,
   * no fabricated completion and no early request/buffer retirement. */
  clock.now_ms = 1100u;
  clock.next_ms = clock.now_ms;
  check_equal(cnet_owner_test_process_deadlines(&owner), SALTS_OK);
  check_true(cnet_owner_test_backend_stats(&owner, &native_stats, &coroutine_stats));
  check_equal(native_stats.active_requests, 1u);

  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);
  check_true(cnet_owner_test_backend_stats(&owner, &native_stats, &coroutine_stats));
  check_equal(native_stats.active_requests, 0u);
  check_equal(coroutine_stats.active, 0u);
  check_equal(coroutine_stats.retained_frames, 0u);

  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CLOSING);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CLOSED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_ETIMEDOUT);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_CLOSED);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  cnet_owner_test_close_socket(accepted);
  cnet_owner_test_close_socket(listener);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}

/* QA-only Linux VSOCK connect/close ordering with the EXISTING private
 * EALREADY cancellation seam. This runs real epoll/AF_VSOCK NativeIO.
 * All ownership and event assertions remain strict. */
#if defined(__linux__)
static void cnet_owner_test_vsock_cancel_ealready(void) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {
      8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config owner_config = {
      .backend_kind = NATIVE_IO_BACKEND_EPOLL,
      .connection_capacity = 1u, .request_capacity = 2u,
      .completion_batch_capacity = 2u,
      .receive_buffer_bytes = 64u, .receive_buffer_count = 1u,
      .write_capacity = 8u, .max_write_bytes = 256u,
      .sessions = &sessions, .commands = &commands, .events = &events};
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {.scheme = CNET_URI_VSOCK};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  cnet_session_state state = CNET_SESSION_FREE;
  native_io_backend_stats native_stats = {0};
  native_io_coroutine_stats coroutine_stats =
      NATIVE_IO_COROUTINE_STATS_V1_INITIALIZER;
  size_t active_records = 0u;

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);
  check_equal(cnet_transport_parse_vsock_address(
                  2u, 5000u, false, connect_payload.address,
                  sizeof(connect_payload.address),
                  &connect_payload.address_length), SALTS_OK);

  /* Both Owner commands are admitted before its first NativeIO observation.
   * The connect request is real; the forced EALREADY only changes the
   * caller-visible cancellation status, not backend cancellation or the
   * generation-checked native terminal completion. */
  check_equal(cnet_owner_test_force_cancel_ealready_once(&owner), SALTS_OK);
  command = (cnet_command){CNET_COMMAND_CONNECT, session,
                            &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  command = (cnet_command){CNET_COMMAND_CLOSE, session, NULL, 0u, 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
  check_equal(cnet_session_table_state(&sessions, session, &state), SALTS_OK);
  check_equal(state, CNET_SESSION_DRAINING);
  check_true(cnet_owner_test_backend_stats(&owner, &native_stats, &coroutine_stats));
  check_equal(native_stats.active_requests, 1u);
  for (size_t index = 0u; index < owner_config.request_capacity; ++index) {
    cnet_owner_test_request_snapshot request = {0};
    check_true(cnet_owner_test_get_request_snapshot(&owner, index, &request));
    if (request.active) {
      ++active_records;
      check_true(native_io_request_valid(request.native_request));
    }
  }
  check_equal(active_records, (size_t)1u);
  /* The EALREADY one-shot was consumed by the *actual* close cancellation. */
  check_equal(cnet_owner_test_force_cancel_ealready_once(&owner), SALTS_OK);

  check_equal(cnet_owner_test_drive_to_state(
                  &owner, &sessions, session, CNET_SESSION_TERMINAL), SALTS_OK);
  check_true(cnet_owner_test_backend_stats(&owner, &native_stats, &coroutine_stats));
  check_equal(native_stats.active_requests, 0u);
  check_equal(coroutine_stats.active, 0u);
  check_equal(coroutine_stats.retained_frames, 0u);

  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CLOSING);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CLOSED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_ETIMEDOUT);
  check_equal(cnet_session_table_take_terminal(
                  &sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_CLOSED);
  check_equal(terminal.status, SALTS_OK);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}
#endif
#endif

static void cnet_owner_test_start_tls_init_failure(native_io_backend_kind backend_kind) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config owner_config = {.backend_kind = backend_kind,
                                          .connection_capacity = 1u,
                                          .request_capacity = 4u,
                                          .completion_batch_capacity = 4u,
                                          .receive_buffer_bytes = 64u,
                                          .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
                                          .commands = &commands,
                                          .events = &events};
  cnet_owner_test_socket listener = CNET_OWNER_TEST_INVALID_SOCKET;
  cnet_owner_test_socket accepted = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in address;
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_owner_start_tls_payload start_tls_payload = {0};
  cnet_tls_context *tls_context = NULL;
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(cnet_owner_test_listener(&listener, &address), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);

  connect_payload.scheme = CNET_URI_TCP;
  connect_payload.address_length = sizeof(address);
  memcpy(connect_payload.address, &address, sizeof(address));
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CONNECTED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  accepted = accept(listener, NULL, NULL);
  check_true(accepted != CNET_OWNER_TEST_INVALID_SOCKET);

  check_equal(cnet_tls_client_context_create(NULL, &tls_context), SALTS_OK);
  start_tls_payload.tls_context = tls_context;
  start_tls_payload.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
  start_tls_payload.tls_handshake_timeout_ms = CNET_OWNER_TEST_TIMEOUT_MS;
  start_tls_payload.tls_server = true;
  command = (cnet_command){CNET_COMMAND_START_TLS, session, &start_tls_payload,
                           sizeof(start_tls_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  tls_context = NULL;
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);

  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_TLS_HANDSHAKING);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_FAILED);
  check_equal(event.status, SALTS_EINVAL);
  check_equal(event.stage, CNET_SESSION_STAGE_HANDSHAKE);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);

  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_FAILED);
  check_equal(terminal.status, SALTS_EINVAL);
  check_equal(terminal.stage, CNET_SESSION_STAGE_HANDSHAKE);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  cnet_owner_test_close_socket(accepted);
  cnet_owner_test_close_socket(listener);
  cnet_tls_context_release(tls_context);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}

static void cnet_owner_test_udp(native_io_backend_kind backend_kind) {
  static const unsigned char outbound[] = {2u, 4u, 6u, 8u};
  static const unsigned char inbound[] = {1u, 9u, 3u, 7u};
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  mem_pool_t vector_pool;
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config owner_config = {.backend_kind = backend_kind,
                                          .connection_capacity = 1u,
                                          .request_capacity = 4u,
                                          .completion_batch_capacity = 4u,
                                          .receive_buffer_bytes = 64u,
                                          .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
                                          .commands = &commands,
                                          .events = &events};
  cnet_owner_test_socket peer = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in peer_address;
  cnet_owner_test_udp_echo echo = {0};
  cmeta_thread_t echo_thread = {0};
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  mem_buffer_t *unsupported_buffer = NULL;
  mem_slice_t unsupported_slices[2] = {{0}};
  int echo_start_status;

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(mem_init(&vector_pool, 0u), 0);
  check_equal(cnet_owner_test_udp_peer(&peer, &peer_address), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);

  connect_payload.scheme = CNET_URI_UDP;
  connect_payload.address_length = sizeof(peer_address);
  memcpy(connect_payload.address, &peer_address, sizeof(peer_address));
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CONNECTED);
  check_equal(event.session.slot, session.slot);
  check_equal(event.session.generation, session.generation);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);

  unsupported_buffer = mem_get_buffer(&vector_pool, 4u);
  check_true(unsupported_buffer != NULL);
  if (unsupported_buffer != NULL) {
    memset(mem_buffer_data(unsupported_buffer), 0x5au, 4u);
    mem_set_used(unsupported_buffer, 4u);
    unsupported_slices[0] = mem_slice(unsupported_buffer, 0u, 2u);
    unsupported_slices[1] = mem_slice(unsupported_buffer, 2u, 2u);
    check_equal(mem_buffer_ref_count(unsupported_buffer), UINT32_C(3));
    check_equal(cnet_owner_send_slicev_direct(&owner, session, unsupported_slices, 2u),
                SALTS_ENOTSUP);
    check_equal(mem_buffer_ref_count(unsupported_buffer), UINT32_C(3));
    mem_slice_release(&unsupported_slices[0]);
    mem_slice_release(&unsupported_slices[1]);
    check_equal(mem_buffer_ref_count(unsupported_buffer), UINT32_C(1));
    mem_buffer_release(unsupported_buffer);
    unsupported_buffer = NULL;
  }

  echo = (cnet_owner_test_udp_echo){peer,    outbound,        sizeof(outbound),
                                    inbound, sizeof(inbound), SALTS_EIO};
  echo_start_status = cmeta_thread_create(&echo_thread, cnet_owner_test_udp_echo_entry, &echo);
  check_equal(echo_start_status, SALTS_OK);
  if (echo_start_status == SALTS_OK) {
    int send_event_seen = 0;
    command = (cnet_command){CNET_COMMAND_RECEIVE, session, NULL, 0u, 1u};
    check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
    check_equal(cnet_owner_test_send_bytes(&owner, session, outbound, sizeof(outbound), false),
                SALTS_OK);
    check_equal(cnet_owner_drive(&owner, CNET_OWNER_TEST_TIMEOUT_MS), SALTS_OK);
    check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
    if (event.kind == CNET_EVENT_SEND) {
      check_equal(event.argument, sizeof(outbound));
      check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
      send_event_seen = 1;
      check_equal(cnet_owner_test_drive_to_event(&owner, &events, &event), SALTS_OK);
    }
    check_equal(event.kind, CNET_EVENT_RECEIVE);
    check_equal(event.data, inbound, sizeof(inbound));
    check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
    if (!send_event_seen) {
      check_equal(cnet_owner_test_drive_to_event(&owner, &events, &event), SALTS_OK);
      check_equal(event.kind, CNET_EVENT_SEND);
      check_equal(event.argument, sizeof(outbound));
      check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
    }
    check_equal(cmeta_thread_join(&echo_thread), SALTS_OK);
    cmeta_thread_destroy(&echo_thread);
    check_equal(echo.status, SALTS_OK);
  }

  command = (cnet_command){CNET_COMMAND_CLOSE, session, NULL, 0u, 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CLOSING);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CLOSED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_CLOSED);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  cnet_owner_test_close_socket(peer);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
  mem_destroy(&vector_pool);
}

static void cnet_owner_test_resolve_failure(native_io_backend_kind backend_kind) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {4u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {4u, 1u, 64u};
  const cnet_owner_config owner_config = {.backend_kind = backend_kind,
                                          .connection_capacity = 1u,
                                          .request_capacity = 2u,
                                          .completion_batch_capacity = 2u,
                                          .receive_buffer_bytes = 64u,
                                          .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
                                          .commands = &commands,
                                          .events = &events};
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);

  connect_payload.scheme = CNET_URI_TCP;
  memcpy(connect_payload.host, "bad host", sizeof("bad host"));
  connect_payload.port = 443u;
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_FAILED);
  check_equal(event.stage, CNET_SESSION_STAGE_RESOLVE);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_FAILED);
  check_equal(terminal.stage, CNET_SESSION_STAGE_RESOLVE);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}

static void cnet_owner_test_pipe_open_failure(native_io_backend_kind backend_kind) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {4u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {4u, 1u, 64u};
  const cnet_owner_config owner_config = {.backend_kind = backend_kind,
                                          .connection_capacity = 1u,
                                          .request_capacity = 2u,
                                          .completion_batch_capacity = 2u,
                                          .receive_buffer_bytes = 64u,
                                          .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
                                          .commands = &commands,
                                          .events = &events};
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);

  connect_payload.scheme = CNET_URI_PIPE;
  memcpy(connect_payload.pipe_name, "cnet-owner-missing-platform-pipe",
         sizeof("cnet-owner-missing-platform-pipe"));
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_FAILED);
  check(event.status != SALTS_OK);
  check_equal(event.stage, CNET_SESSION_STAGE_CONNECT);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_FAILED);
  check_equal(terminal.stage, CNET_SESSION_STAGE_CONNECT);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}

static void cnet_owner_test_vsock_rejected_policy(native_io_backend_kind backend_kind) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {4u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {4u, 1u, 64u};
  const cnet_owner_config owner_config = {.backend_kind = backend_kind,
                                          .connection_capacity = 1u,
                                          .request_capacity = 2u,
                                          .completion_batch_capacity = 2u,
                                          .receive_buffer_bytes = 64u,
                                          .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
                                          .commands = &commands,
                                          .events = &events};
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);

  connect_payload.scheme = CNET_URI_VSOCK;
#if defined(__linux__)
  check_equal(cnet_transport_parse_vsock_address(
                  CNET_VSOCK_CID_HOST, UINT32_C(5000), false, connect_payload.address,
                  sizeof(connect_payload.address), &connect_payload.address_length),
              SALTS_OK);
#else
  connect_payload.address[0] = 1u;
  connect_payload.address_length = 1u;
#endif
  connect_payload.socket_options =
      (cnet_stream_socket_options)CNET_STREAM_SOCKET_OPTIONS_INIT;
  connect_payload.socket_options.keepalive = 1;
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_FAILED);
  check_equal(event.status, SALTS_ENOTSUP);
  check_equal(event.stage, CNET_SESSION_STAGE_CONNECT);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_FAILED);
  check_equal(terminal.status, SALTS_ENOTSUP);
  check_equal(terminal.stage, CNET_SESSION_STAGE_CONNECT);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
}

static void cnet_owner_test_pipe(native_io_backend_kind backend_kind) {
  static const unsigned char outbound[] = {5u, 6u, 7u, 8u};
  static const unsigned char inbound[] = {8u, 3u, 2u, 1u};
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config owner_config = {.backend_kind = backend_kind,
                                          .connection_capacity = 1u,
                                          .request_capacity = 4u,
                                          .completion_batch_capacity = 4u,
                                          .receive_buffer_bytes = 64u,
                                          .receive_buffer_count = 1u,
                                          .write_capacity = 8u,
                                          .max_write_bytes = 256u,
                                          .sessions = &sessions,
                                          .commands = &commands,
                                          .events = &events};
  cnet_shared_test_named_pipe pipe;
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  mem_pool_t vector_pool;
  mem_buffer_t *vector_buffer = NULL;
  mem_slice_t vector_slices[2] = {{0}};
  unsigned char vector_received[3] = {0};
  const unsigned char vector_expected[3] = {0x71u, 0x72u, 0x75u};
  unsigned char received[sizeof(outbound)] = {0};

  check_equal(cnet_shared_test_named_pipe_start(&pipe), SALTS_OK);
  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(mem_init(&vector_pool, 0u), 0);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);

  connect_payload.scheme = CNET_URI_PIPE;
  memcpy(connect_payload.pipe_name, pipe.name, strlen(pipe.name) + 1u);
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN),
              SALTS_OK);
  check_equal(cnet_shared_test_named_pipe_finish(&pipe), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CONNECTED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);

  vector_buffer = mem_get_buffer(&vector_pool, 8u);
  check_true(vector_buffer != NULL);
  for (size_t index = 0u; index < 8u; ++index)
    mem_buffer_data(vector_buffer)[index] = (char)(0x70u + index);
  mem_set_used(vector_buffer, 8u);
  vector_slices[0] = mem_slice(vector_buffer, 1u, 2u);
  vector_slices[1] = mem_slice(vector_buffer, 5u, 1u);
  check_equal(mem_buffer_ref_count(vector_buffer), UINT32_C(3));
  {
    const int vector_status =
        cnet_owner_send_slicev_direct(&owner, session, vector_slices, 2u);
#if defined(_WIN32)
    check_equal(vector_status, SALTS_ENOTSUP);
    check_equal(mem_buffer_ref_count(vector_buffer), UINT32_C(3));
#else
    check_equal(vector_status, SALTS_OK);
    check_equal(mem_buffer_ref_count(vector_buffer), UINT32_C(4));
#endif
  }
  for (size_t index = 0u; index < 2u; ++index) mem_slice_release(&vector_slices[index]);
#if defined(_WIN32)
  check_equal(mem_buffer_ref_count(vector_buffer), UINT32_C(1));
#else
  check_equal(mem_buffer_ref_count(vector_buffer), UINT32_C(2));
  check_equal(cnet_owner_drive(&owner, CNET_OWNER_TEST_TIMEOUT_MS), SALTS_OK);
  check_equal(cnet_shared_test_named_pipe_peer_read(&pipe, vector_received,
                                                    sizeof(vector_received)),
              SALTS_OK);
  check_equal(vector_received, vector_expected, sizeof(vector_expected));
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_SEND);
  check_equal(event.argument, sizeof(vector_expected));
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(mem_buffer_ref_count(vector_buffer), UINT32_C(1));
#endif
  mem_buffer_release(vector_buffer);
  vector_buffer = NULL;

  check_equal(cnet_owner_test_send_bytes(&owner, session, outbound, sizeof(outbound), false),
              SALTS_OK);
  check_equal(cnet_owner_drive(&owner, CNET_OWNER_TEST_TIMEOUT_MS), SALTS_OK);
  check_equal(cnet_shared_test_named_pipe_peer_read(&pipe, received, sizeof(received)), SALTS_OK);
  check_equal(received, outbound, sizeof(outbound));
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_SEND);
  check_equal(event.argument, sizeof(outbound));
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);

  command = (cnet_command){CNET_COMMAND_RECEIVE, session, NULL, 0u, 1u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_drive(&owner, 0u), SALTS_OK);
  check_equal(cnet_shared_test_named_pipe_peer_write(&pipe, inbound, sizeof(inbound)), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_event(&owner, &events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_RECEIVE);
  check_equal(event.data, inbound, sizeof(inbound));
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);

  command = (cnet_command){CNET_COMMAND_CLOSE, session, NULL, 0u, 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CLOSING);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CLOSED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_CLOSED);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  cnet_shared_test_named_pipe_close(&pipe);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
  mem_destroy(&vector_pool);
}

#if defined(CNET_INTERNAL_TESTING) && defined(CNET_INTERNAL_PROFILING)
static void cnet_owner_test_retained_vector_partial_send(native_io_backend_kind backend_kind) {
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  mem_pool_t pool;
  const cnet_command_queue_config command_config = {8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config owner_config = {
      .backend_kind = backend_kind,
      .connection_capacity = 1u,
      .request_capacity = 4u,
      .completion_batch_capacity = 4u,
      .receive_buffer_bytes = 64u,
      .receive_buffer_count = 1u,
      .write_capacity = 8u,
      .max_write_bytes = 256u,
      .sessions = &sessions,
      .commands = &commands,
      .events = &events};
  cnet_owner_test_socket listener = CNET_OWNER_TEST_INVALID_SOCKET;
  cnet_owner_test_socket accepted = CNET_OWNER_TEST_INVALID_SOCKET;
  struct sockaddr_in address;
  cnet_session_handle session = {0};
  cnet_owner_connect_payload connect_payload = {0};
  cnet_command command = {0};
  cnet_event_view event = {0};
  cnet_session_terminal terminal = {0};
  cnet_owner_profile profile = {0};
  mem_buffer_t *buffer = NULL;
  mem_slice_t slices[3] = {{0}};
  unsigned char received[8] = {0};
  const unsigned char expected[8] = {0x31u, 0x32u, 0x33u, 0x34u,
                                     0x35u, 0x36u, 0x37u, 0x38u};

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_OK);
  check_equal(mem_init(&pool, 0u), 0);
  check_equal(cnet_owner_test_listener(&listener, &address), SALTS_OK);
  check_equal(cnet_session_table_reserve(&sessions, &session), SALTS_OK);

  connect_payload.scheme = CNET_URI_TCP;
  connect_payload.address_length = sizeof(address);
  memcpy(connect_payload.address, &address, sizeof(address));
  command =
      (cnet_command){CNET_COMMAND_CONNECT, session, &connect_payload, sizeof(connect_payload), 0u};
  check_equal(cnet_command_queue_publish(&commands, &command), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_OPEN),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_STATE);
  check_equal(event.state, CNET_EVENT_STATE_CONNECTED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  accepted = accept(listener, NULL, NULL);
  check_true(accepted != CNET_OWNER_TEST_INVALID_SOCKET);

  buffer = mem_get_buffer(&pool, sizeof(expected));
  check_true(buffer != NULL);
  memcpy(mem_buffer_data(buffer), expected, sizeof(expected));
  mem_set_used(buffer, sizeof(expected));
  slices[0] = mem_slice(buffer, 0u, 3u);
  slices[1] = mem_slice(buffer, 3u, 2u);
  slices[2] = mem_slice(buffer, 5u, 3u);
  check_equal(cnet_owner_test_set_send_chunk_bytes(&owner, 2u), SALTS_OK);
  check_equal(cnet_owner_profile_begin(&owner), SALTS_OK);
  check_equal(cnet_owner_send_slicev_direct(&owner, session, slices, 3u), SALTS_OK);
  for (size_t index = 0u; index < 3u; ++index) mem_slice_release(&slices[index]);
  mem_buffer_release(buffer);
  buffer = NULL;

  check_equal(cnet_owner_test_drive_to_event(&owner, &events, &event), SALTS_OK);
  check_equal(event.kind, CNET_EVENT_SEND);
  check_equal(event.argument, sizeof(expected));
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_owner_profile_take(&owner, &profile), SALTS_OK);
  check_equal(profile.request_start_calls, UINT64_C(1));
  check_equal(profile.request_resubmit_calls, UINT64_C(3));
  check_equal(profile.request_completion_calls, UINT64_C(1));
  check_equal(cnet_owner_test_set_send_chunk_bytes(&owner, 0u), SALTS_OK);
  check_equal(cnet_owner_test_receive_all(accepted, received, sizeof(received)), SALTS_OK);
  check_equal(memcmp(received, expected, sizeof(expected)), 0);

  check_equal(cnet_owner_close_direct(&owner, session), SALTS_OK);
  check_equal(cnet_owner_test_drive_to_state(&owner, &sessions, session, CNET_SESSION_TERMINAL),
              SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CLOSING);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_event_queue_take(&events, &event), SALTS_OK);
  check_equal(event.state, CNET_EVENT_STATE_CLOSED);
  check_equal(cnet_event_queue_release(&events, &event), SALTS_OK);
  check_equal(cnet_session_table_take_terminal(&sessions, session, &terminal), SALTS_OK);
  check_equal(terminal.kind, CNET_SESSION_TERMINAL_CLOSED);
  check_equal(cnet_session_table_recycle(&sessions, session), SALTS_OK);
  check_equal(cnet_owner_release_session(&owner, session), SALTS_OK);

  cnet_owner_test_close_socket(accepted);
  cnet_owner_test_close_socket(listener);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_owner_close(&owner), SALTS_OK);
  check_equal(cnet_owner_destroy(&owner), SALTS_OK);
  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
  mem_destroy(&pool);
}
#endif

static void cnet_owner_test_init_cleanup_after_backend(
    native_io_backend_kind backend_kind) {
#if SIZE_MAX > UINT32_MAX
  cnet_session_table sessions = {0};
  cnet_command_queue commands = {0};
  cnet_event_queue events = {0};
  cnet_owner owner = {0};
  const cnet_command_queue_config command_config = {
      8u, sizeof(cnet_owner_connect_payload)};
  const cnet_event_queue_config event_config = {8u, 2u, 64u};
  const cnet_owner_config owner_config = {
      .backend_kind = backend_kind,
      .connection_capacity = 1u,
      .request_capacity = 4u,
      .completion_batch_capacity = 4u,
      .receive_buffer_bytes = 64u,
      .receive_buffer_count = 1u,
      .write_capacity = (size_t)UINT32_MAX + 1u,
      .max_write_bytes = 256u,
      .sessions = &sessions,
      .commands = &commands,
      .events = &events};

  check_equal(cnet_session_table_init(&sessions, 1u), SALTS_OK);
  check_equal(cnet_command_queue_init(&commands, &command_config), SALTS_OK);
  check_equal(cnet_event_queue_init(&events, &event_config), SALTS_OK);

  /*
   * NativeIO backend construction succeeds first; the oversized write queue
   * then fails deterministically with SALTS_ERANGE. Owner init must clean up
   * the owned backend without recursion and publish no partial owner.
   */
  check_equal(cnet_owner_init(&owner, &owner_config), SALTS_ERANGE);
  check_null(owner.impl);

  check_equal(cnet_event_queue_close(&events), SALTS_OK);
  check_equal(cnet_event_queue_destroy(&events), SALTS_OK);
  check_equal(cnet_command_queue_close(&commands), SALTS_OK);
  check_equal(cnet_command_queue_destroy(&commands), SALTS_OK);
  check_equal(cnet_session_table_destroy(&sessions), SALTS_OK);
#else
  (void)backend_kind;
#endif
}

spec("CNet terminal diagnostic values") {
  static cnet_event_queue queue;
  static cnet_event_view view;
  static bool borrowed;
  before_each() {
    memset(&queue, 0, sizeof(queue)); memset(&view, 0, sizeof(view)); borrowed = false;
  }
  after_each() {
    if (queue.impl) {
      check_equal(cnet_event_queue_close(&queue), SALTS_OK);
      if (borrowed) check_equal(cnet_event_queue_release(&queue, &view), SALTS_OK);
      while (cnet_event_queue_take(&queue, &view) == SALTS_OK)
        check_equal(cnet_event_queue_release(&queue, &view), SALTS_OK);
      check_equal(cnet_event_queue_destroy(&queue), SALTS_OK);
    }
  }
  it("copies failed TLS diagnostics across queue pressure and clears reused slots") {
    const cnet_event_queue_config config = {.capacity = 2u, .data_capacity = 1u, .max_payload_bytes = 64u};
    check_equal(cnet_event_queue_init(&queue, &config), SALTS_OK);
    cnet_event event = {.kind = CNET_EVENT_STATE, .session = {1u, 1u},
        .state = CNET_EVENT_STATE_FAILED, .status = SALTS_ECONNABORTED,
        .stage = CNET_SESSION_STAGE_HANDSHAKE,
        .tls = {CRYPTO_TLS_FAILURE_TRUST_ANCHOR, SIZE_MAX}};
    check_equal(cnet_event_queue_publish(&queue, &event), SALTS_OK);
    event.tls = (crypto_tls_diagnostic){0};
    check_equal(cnet_event_queue_publish(&queue, &event), SALTS_OK);
    check_equal(cnet_event_queue_publish(&queue, &event), SALTS_ENOBUFS);
    check_equal(cnet_event_queue_take(&queue, &view), SALTS_OK); borrowed = true;
    check_equal(view.tls.reason, CRYPTO_TLS_FAILURE_TRUST_ANCHOR);
    check_equal(view.tls.certificate_index, SIZE_MAX);
    check_equal(cnet_event_queue_release(&queue, &view), SALTS_OK); borrowed = false;
    check_equal(cnet_event_queue_publish(&queue, &event), SALTS_OK);
    for (unsigned i = 0u; i < 2u; ++i) {
      check_equal(cnet_event_queue_take(&queue, &view), SALTS_OK); borrowed = true;
      check_equal(view.tls.reason, CRYPTO_TLS_FAILURE_NONE);
      check_equal(cnet_event_queue_release(&queue, &view), SALTS_OK); borrowed = false;
    }
  }
}

spec("CNet owner shard") {
#if defined(CNET_INTERNAL_TESTING)
  it("transfers pending TLS I/O deadlines after the handshake exactly once") {
    check_equal(cnet_owner_test_tls_pending_deadline_rollover(), SALTS_OK);
  }

  it("probes TLS control data only after authentication, even with an active read") {
    check_false(cnet_owner_test_tls_control_probe_allowed(
        false, false, false, 0u));
    check_false(cnet_owner_test_tls_control_probe_allowed(
        false, true, false, 0u));
    check_true(cnet_owner_test_tls_control_probe_allowed(
        true, false, false, 0u));
    check_true(cnet_owner_test_tls_control_probe_allowed(
        true, true, false, 0u));
    check_false(cnet_owner_test_tls_control_probe_allowed(
        true, true, true, 0u));
    check_false(cnet_owner_test_tls_control_probe_allowed(
        true, true, false, 1u));
  }

  it("schedules first direct TLS receive despite an active NativeIO read") {
    /* Reproduce the immediate/coalesced app-data handoff missed by the
     * original direct admission guard. A live native TLS_READ owns a
     * different buffer and MUST NOT suppress provider ring progression. */
    check_true(cnet_owner_test_receive_direct_should_rearm(true, true, 0u));
    check_true(cnet_owner_test_receive_direct_should_rearm(true, false, 0u));
    check_false(cnet_owner_test_receive_direct_should_rearm(true, true, 1u));
    /* Plain TCP still relies on its one existing NativeIO read. */
    check_false(cnet_owner_test_receive_direct_should_rearm(false, true, 0u));
    check_true(cnet_owner_test_receive_direct_should_rearm(false, false, 0u));
    check_false(cnet_owner_test_receive_direct_should_rearm(false, false, 1u));
  }

  it("drains buffered TLS input despite an active handshake-era NativeIO read") {
    /* TLS private ring/plaintext is independent of the in-flight recv buffer.
     * Receive admission must pump it without submitting a duplicate read. */
    check_true(cnet_owner_test_can_progress_receive(true, true, false, 1u));
    check_true(cnet_owner_test_can_progress_receive(true, false, false, 1u));
    check_false(cnet_owner_test_can_progress_receive(false, true, false, 1u));
    check_true(cnet_owner_test_can_progress_receive(false, false, false, 1u));
    check_false(cnet_owner_test_can_progress_receive(true, true, false, 0u));
    check_false(cnet_owner_test_can_progress_receive(true, true, true, 1u));
  }

  it("attributes a late TLS read/write completion after authentication") {
    check_equal(cnet_owner_test_tls_completion_stage(
                    false, false, CNET_SESSION_STAGE_HANDSHAKE),
                CNET_SESSION_STAGE_HANDSHAKE);
    check_equal(cnet_owner_test_tls_completion_stage(
                    false, true, CNET_SESSION_STAGE_HANDSHAKE),
                CNET_SESSION_STAGE_HANDSHAKE);
    check_equal(cnet_owner_test_tls_completion_stage(
                    true, false, CNET_SESSION_STAGE_HANDSHAKE),
                CNET_SESSION_STAGE_READ);
    check_equal(cnet_owner_test_tls_completion_stage(
                    true, true, CNET_SESSION_STAGE_HANDSHAKE),
                CNET_SESSION_STAGE_WRITE);
    check_equal(cnet_owner_test_tls_completion_stage(
                    true, false, CNET_SESSION_STAGE_READ),
                CNET_SESSION_STAGE_READ);
  }

  it("resumes TLS1.3 provider-owned partial records without a second header") {
    const uint8_t record[10] = {
        0x17, 0x03, 0x03, 0x00, 0x05, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
    bool ready = true;
    /* A fresh ring must wait for the complete authenticated record. */
    check_equal(cnet_test_tls_receive_record_gate(0u, record, 7u, &ready),
                SALTS_OK);
    check_false(ready);
    check_equal(cnet_test_tls_receive_record_gate(0u, record, sizeof(record),
                                                   &ready), SALTS_OK);
    check_true(ready);
    /* Once the provider has consumed the header, the remaining bytes are
     * ciphertext payload, NOT a second record header. */
    check_equal(cnet_test_tls_receive_record_gate(1u, record + 5, 2u, &ready),
                SALTS_OK);
    check_true(ready);
    check_equal(cnet_test_tls_receive_record_gate(2u, record + 5, 2u, &ready),
                SALTS_OK);
    check_true(ready);
    check_equal(cnet_test_tls_receive_record_gate(2u, record, 0u, &ready),
                SALTS_OK);
    check_false(ready);
    /* Provider-buffered plaintext may be delivered without more ciphertext. */
    check_equal(cnet_test_tls_receive_record_gate(3u, record, 0u, &ready),
                SALTS_OK);
    check_true(ready);
    check_equal(cnet_test_tls_receive_record_gate(4u, record, 0u, &ready),
                SALTS_EINVAL);
  }

  it("uses caller-owned network byte order for IPv4 and IPv6 resolver ports") {
    cnet_owner_test_requested_port_byte_order();
  }
#endif
  it("cleans up an owned backend when later owner initialization fails") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    check_equal(cnet_module_init(), SALTS_OK);
    for (size_t index = 0u; index < count; ++index)
      cnet_owner_test_init_cleanup_after_backend(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("owns a TCP session from command admission through terminal recycle") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_tcp(backends[index], false, CNET_OWNER_TEST_NO_TIMEOUT);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("owns the resolve to TCP connect state transition") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_tcp(backends[index], true, CNET_OWNER_TEST_NO_TIMEOUT);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

#if defined(_WIN32)
  it("rejects bound non-listening IPv4 ports through real IOCP and retires every request") {
    check_equal(cnet_module_init(), SALTS_OK);
    cnet_owner_test_refused_connect_win32(false);
    cnet_owner_test_refused_connect_win32(true);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }
#endif

#if defined(CNET_INTERNAL_TESTING) && defined(CNET_INTERNAL_PROFILING)
  it("resubmits retained vector partial writes through the same logical request") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    check_equal(cnet_module_init(), SALTS_OK);
    for (size_t index = 0u; index < count; ++index)
      cnet_owner_test_retained_vector_partial_send(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }
#endif

#if defined(CNET_INTERNAL_TESTING)
  it("does not resubmit a partial success after the write deadline expired") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    check_equal(cnet_module_init(), SALTS_OK);
    for (size_t index = 0u; index < count; ++index)
      cnet_owner_test_expired_partial_send(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("releases retained vector ownership when a partial send deadline expires") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    check_equal(cnet_module_init(), SALTS_OK);
    for (size_t index = 0u; index < count; ++index) {
      cnet_owner_test_expired_partial_vector_send(backends[index], false, false);
      cnet_owner_test_expired_partial_vector_send(backends[index], true, false);
      cnet_owner_test_expired_partial_vector_send(backends[index], true, true);
    }
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("closes after a final send while its receive terminal awaits batch routing") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    check_equal(cnet_module_init(), SALTS_OK);
    for (size_t index = 0u; index < count; ++index)
      cnet_owner_test_close_observed_receive(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("keeps a direct request owned when cancellation reports already terminal") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index) cnet_owner_test_cancel_ealready(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

#if defined(__linux__)
  it("settles a real VSOCK connect after an EALREADY close cancellation") {
    check_equal(cnet_module_init(), SALTS_OK);
    cnet_owner_test_vsock_cancel_ealready();
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }
#endif
#endif

  it("publishes handshaking before a local TLS initialization failure") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_start_tls_init_failure(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("times out one pending read through the owner deadline queue") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_tcp(backends[index], false, CNET_OWNER_TEST_READ_TIMEOUT);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("keeps an expired connect terminal when a native success is already pending") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_tcp(backends[index], false, CNET_OWNER_TEST_CONNECT_TIMEOUT);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("expires resolution before accepting a late resolver result") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_tcp(backends[index], true, CNET_OWNER_TEST_CONNECT_TIMEOUT);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("keeps an expired write terminal when a native success is already pending") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_tcp(backends[index], false, CNET_OWNER_TEST_WRITE_TIMEOUT);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("contains resolver failure in one session and reports its stage") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_resolve_failure(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("owns a connected UDP session through bidirectional datagrams and terminal recycle") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_udp(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("owns a platform byte-pipe session through bidirectional bytes and terminal recycle") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      if (native_io_backend_kind_supports_pipe(backends[index]))
        cnet_owner_test_pipe(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("reports a named platform pipe open failure at the connect stage") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      if (native_io_backend_kind_supports_pipe(backends[index]))
        cnet_owner_test_pipe_open_failure(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }

  it("routes VSOCK explicitly and rejects unsupported socket policy at the connect stage") {
    native_io_backend_kind backends[CNET_OWNER_TEST_MAX_BACKENDS];
    const size_t count = cnet_owner_test_backends(backends);
    size_t index;
    check_equal(cnet_module_init(), SALTS_OK);
    for (index = 0u; index < count; ++index)
      cnet_owner_test_vsock_rejected_policy(backends[index]);
    check_equal(cnet_module_shutdown(), SALTS_OK);
  }
}
