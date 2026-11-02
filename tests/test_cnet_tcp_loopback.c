/*
 * Real loopback TCP CNet integration, independent of the former Salts binary.
 * One caller owns the CNet client and listener. The native peer owns its
 * blocking socket. The received mem_slice_t deliberately survives stop/destroy.
 */
#include <tinytest.h>
#include <cnet/cnet.h>
#include <clock.h>
#include <thread.h>
#include <error_codes.h>
#include <cmeta_buffer.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef SOCKET test_socket;
#  define TEST_INVALID_SOCKET INVALID_SOCKET
static void test_close_socket(test_socket s) {
  if (s != TEST_INVALID_SOCKET) (void)closesocket(s);
}
static int test_recv_timeout(test_socket s) {
  DWORD timeout = 4000;
  return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
}
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
typedef int test_socket;
#  define TEST_INVALID_SOCKET (-1)
static void test_close_socket(test_socket s) {
  if (s != TEST_INVALID_SOCKET) (void)close(s);
}
static int test_recv_timeout(test_socket s) {
  struct timeval timeout = {4, 0};
  return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}
#endif

/* Defined in a separate shared module, linked to the installed Core owner. */
extern mem_pool_t *saltscore_owner_probe_pool(void);
extern const void *saltscore_owner_probe_thread(void);
extern void saltscore_owner_probe_release(mem_slice_t *slice);

typedef struct tcp_probe {
  unsigned connected;
  unsigned terminal;
  unsigned failed;
  unsigned sent;
  unsigned owned_received;
  unsigned borrowed_received;
  size_t last_send_bytes;
  mem_slice_t owned_slice;
} tcp_probe;

static void on_state(void *user, cnet_connection connection,
                     cnet_connection_state state, const cnet_error *error) {
  tcp_probe *p = (tcp_probe *)user;
  (void)connection;
  if (state == CNET_CONNECTION_CONNECTED) ++p->connected;
  if (state == CNET_CONNECTION_FAILED || error != NULL) ++p->failed;
  if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED)
    ++p->terminal;
}
static void on_borrowed(void *user, cnet_connection connection,
                        const cnet_receive_view *value) {
  tcp_probe *p = (tcp_probe *)user;
  (void)connection;
  (void)value;
  ++p->borrowed_received;
}
static void on_owned(void *user, cnet_connection connection,
                     mem_slice_t slice, cnet_message_kind kind) {
  tcp_probe *p = (tcp_probe *)user;
  (void)connection;
  if (kind != CNET_MESSAGE_BYTES || slice.buffer == NULL ||
      slice.data == NULL || slice.length != 1u ||
      p->owned_slice.buffer != NULL) {
    ++p->failed;
    mem_slice_release(&slice);
    return;
  }
  p->owned_slice = slice; /* Own exactly one backing reference until cleanup. */
  ++p->owned_received;
}
static void on_sent(void *user, cnet_connection connection, size_t length) {
  tcp_probe *p = (tcp_probe *)user;
  (void)connection;
  ++p->sent;
  p->last_send_bytes = length;
}

static native_io_backend_kind backend_kind(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#else
  return NATIVE_IO_BACKEND_EPOLL;
#endif
}

static cnet_client_config client_config(void) {
  cnet_client_config config = {0};
  config.backend = backend_kind();
  config.connection_capacity = 2u;
  config.command_capacity = 8u;
  config.request_capacity = 4u;
  config.completion_batch_capacity = 4u;
  config.event_capacity = 8u;
  config.max_send_bytes = 256u;
  config.receive_buffer_bytes = 256u;
  return config;
}

static int poll_until(cnet_client *client, unsigned *counter, unsigned expected) {
  uint64_t deadline = cmeta_monotonic_ms() + 5000u;
  while (*counter < expected && cmeta_monotonic_ms() < deadline) {
    size_t events = 0u;
    const int status = cnet_client_poll(client, 10u, &events);
    if (status != SALTS_OK) return status;
  }
  return *counter >= expected ? SALTS_OK : SALTS_ETIMEDOUT;
}

#define VERIFY(expr) do {                                                    \
    if (!(expr)) {                                                           \
      fprintf(stderr, "CNet TCP loopback failure at line %d: %s\n",          \
              __LINE__, #expr);                                               \
      result = __LINE__;                                                     \
      goto cleanup;                                                          \
    }                                                                        \
  } while (0)

static int saltscore_original_entry_test_cnet_tcp_loopback_c(void) {
  cnet_client client = {0};
  cnet_listener listener = {0};
  const cnet_client_config config = client_config();
  const cnet_listener_config listener_config = {
      backend_kind(), "127.0.0.1", 0u, 2u};
  tcp_probe probe = {0};
  cnet_observer observer = {on_state, on_borrowed, &probe, on_sent};
  cnet_connection connection = {0};
  test_socket peer = TEST_INVALID_SOCKET;
  struct sockaddr_in remote;
  uint16_t port = 0u;
  uint8_t incoming = 0x7bu;
  uint8_t outgoing = 0u;
  mem_buffer_t *pending = NULL;
  int client_live = 0, listener_live = 0;
  int ready = 0, result = 0;

  VERIFY(cnet_listener_init(&listener, &listener_config) == SALTS_OK);
  listener_live = 1;
  VERIFY(cnet_listener_port(&listener, &port) == SALTS_OK && port != 0u);
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  client_live = 1;
  peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  VERIFY(peer != TEST_INVALID_SOCKET);
  VERIFY(test_recv_timeout(peer) == 0);
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  remote.sin_port = htons(port);
  VERIFY(connect(peer, (const struct sockaddr *)&remote,
                 (int)sizeof(remote)) == 0);
  VERIFY(cnet_listener_wait(&listener, 5000u, &ready) == SALTS_OK &&
         ready == 1);
  VERIFY(cnet_listener_accept(&listener, &client, &observer,
                              &connection) == SALTS_OK);
  VERIFY(connection.slot != 0u && connection.generation != 0u);
  VERIFY(poll_until(&client, &probe.connected, 1u) == SALTS_OK);
  VERIFY(probe.failed == 0u && probe.terminal == 0u);

  VERIFY(cnet_set_receive_slice_handler(&client, connection,
                                       on_owned, &probe) == SALTS_OK);
  VERIFY(cnet_receive(&client, connection, 1u) == SALTS_OK);
  VERIFY(send(peer, (const char *)&incoming, 1, 0) == 1);
  VERIFY(poll_until(&client, &probe.owned_received, 1u) == SALTS_OK);
  VERIFY(probe.owned_slice.buffer != NULL &&
         probe.owned_slice.length == 1u &&
         probe.owned_slice.data[0] == incoming &&
         probe.borrowed_received == 0u && probe.failed == 0u);
  /* This slice was created by the CNet DSO; compare with the executable and
   * an independently loaded module on this same live OS thread. */
  VERIFY(mem_buffer_pool(probe.owned_slice.buffer) == mem_global());
  VERIFY(saltscore_owner_probe_pool() == mem_global());
  VERIFY(saltscore_owner_probe_thread() == cmeta_thread_current_token());

  pending = mem_get_buffer(mem_global(), 1u);
  VERIFY(pending != NULL);
  *mem_buffer_data(pending) = 0xa5;
  mem_set_used(pending, 1u);
  VERIFY(cnet_send_buffer(&client, connection, pending) == SALTS_OK);
  mem_buffer_release(pending); /* CNet must retain until terminal send. */
  pending = NULL;
  VERIFY(poll_until(&client, &probe.sent, 1u) == SALTS_OK);
  VERIFY(probe.last_send_bytes == 1u && probe.failed == 0u);
  VERIFY(recv(peer, (char *)&outgoing, 1, 0) == 1 &&
         outgoing == 0xa5u);

  VERIFY(cnet_close(&client, connection) == SALTS_OK);
  VERIFY(poll_until(&client, &probe.terminal, 1u) == SALTS_OK);
  VERIFY(probe.terminal == 1u && probe.failed == 0u &&
         probe.owned_received == 1u && probe.sent == 1u);

  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  client_live = 0;
  /* Borrowed callbacks do not outlive poll; retained slices do. */
  VERIFY(probe.owned_slice.buffer != NULL &&
         probe.owned_slice.data[0] == incoming);
  VERIFY(cnet_listener_close(&listener) == SALTS_OK);
  VERIFY(cnet_listener_destroy(&listener) == SALTS_OK);
  listener_live = 0;

cleanup:
  if (pending) mem_buffer_release(pending);
  if (client_live) {
    (void)cnet_client_stop(&client, 3000u);
    (void)cnet_client_destroy(&client);
  }
  if (listener_live) {
    (void)cnet_listener_close(&listener);
    (void)cnet_listener_destroy(&listener);
  }
  test_close_socket(peer);
  /* Last release deliberately occurs in another DLL/DSO after CNet destroy. */
  if (probe.owned_slice.buffer) saltscore_owner_probe_release(&probe.owned_slice);
  return result;
}

spec("CNet real TCP loopback and retained slice") {
  it("preserves the real owner lifecycle and original failure code") {
    const int result = saltscore_original_entry_test_cnet_tcp_loopback_c();
    check(result == 0, "native integration returned %d", result);
  }
}
