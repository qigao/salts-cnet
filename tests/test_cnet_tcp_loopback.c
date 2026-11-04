/*
 * Real local TCP/IPC CNet integration, independent of the former Salts binary.
 * One caller owns each CNet client and listener; TCP peers use native blocking
 * sockets. The received mem_slice_t deliberately survives stop/destroy.
 */
#include <tinytest.h>
#include <cnet/cnet.h>
#include <cnet/client_pool.h>
#include <cnet/managed_dial.h>
#include <cnet/ipc.h>
#include <cnet/sg_host.h>
#include <clock.h>
#include <thread.h>
#include <platform_atomic.h>
#include <error_codes.h>
#include <cmeta_buffer.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
typedef SOCKET test_socket;
#  define TEST_INVALID_SOCKET INVALID_SOCKET
static void test_close_socket(test_socket s) {
  if (s != TEST_INVALID_SOCKET) (void)closesocket(s);
}
static int test_recv_timeout(test_socket s) {
  DWORD timeout = 4000;
  return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
}
static int test_nonblocking(test_socket s) {
  u_long enabled = 1u;
  return ioctlsocket(s, FIONBIO, &enabled);
}
static int test_blocking(test_socket s) {
  u_long enabled = 0u;
  return ioctlsocket(s, FIONBIO, &enabled);
}
static bool test_would_block(void) {
  return WSAGetLastError() == WSAEWOULDBLOCK;
}
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
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
static int test_nonblocking(test_socket s) {
  const int flags = fcntl(s, F_GETFL, 0);
  return flags < 0 ? -1 : fcntl(s, F_SETFL, flags | O_NONBLOCK);
}
static int test_blocking(test_socket s) {
  const int flags = fcntl(s, F_GETFL, 0);
  return flags < 0 ? -1 : fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
}
static bool test_would_block(void) {
  return errno == EAGAIN || errno == EWOULDBLOCK;
}
#endif

/* Defined in a separate shared module, linked to the installed Core owner. */
extern mem_pool_t *saltscore_owner_probe_pool(void);
extern const void *saltscore_owner_probe_thread(void);
extern void saltscore_owner_probe_release(mem_slice_t *slice);

typedef struct tcp_probe {
  unsigned completed;
  cnet_send_result completion;
  unsigned completions_at_terminal;
  unsigned connected;
  unsigned terminal;
  unsigned failed;
  unsigned sent;
  unsigned sends_at_terminal;
  int last_error_status;
  char failure_stage[32];
  unsigned owned_received;
  unsigned borrowed_received;
  unsigned borrowed_bytes;
  unsigned recycled;
  unsigned char borrowed_data[8];
  size_t last_send_bytes;
  size_t send_sizes[4];
  mem_slice_t owned_slice;
} tcp_probe;

static void on_state(void *user, cnet_connection connection,
                     cnet_connection_state state, const cnet_error *error) {
  tcp_probe *p = (tcp_probe *)user;
  (void)connection;
  if (error != NULL) {
    p->last_error_status = error->status;
    (void)snprintf(p->failure_stage, sizeof(p->failure_stage), "%s", error->stage != NULL ? error->stage : "");
  }
  if (state == CNET_CONNECTION_CONNECTED) ++p->connected;
  if (state == CNET_CONNECTION_FAILED || error != NULL) ++p->failed;
  if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
    p->completions_at_terminal = p->completed;
    p->sends_at_terminal = p->sent;
    ++p->terminal;
  }
}
static void on_borrowed(void *user, cnet_connection connection,
                        const cnet_receive_view *value) {
  tcp_probe *p = (tcp_probe *)user;
  (void)connection;
  if (value == NULL || value->kind != CNET_MESSAGE_BYTES || value->data == NULL ||
      value->size == 0u || value->size > sizeof(p->borrowed_data) - p->borrowed_bytes) {
    ++p->failed;
    return;
  }
  memcpy(p->borrowed_data + p->borrowed_bytes, value->data, value->size);
  p->borrowed_bytes += (unsigned)value->size;
  ++p->borrowed_received;
}
static void on_recycled(void *user) {
  ++((tcp_probe *)user)->recycled;
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
static void on_operation(void *user, const cnet_send_result *result) {
  tcp_probe *p = user;
  ++p->completed;
  p->completion = *result;
}
typedef struct resource_probe { size_t allocated, released, buffers, freed_buffers; } resource_probe;
static void *probe_allocate(void *user, size_t bytes) {
  resource_probe *p = user;
  void *memory = malloc(bytes);
  if (memory != NULL) ++p->allocated;
  return memory;
}
static void probe_deallocate(void *user, void *memory, size_t bytes) {
  resource_probe *p = user;
  (void)bytes;
  ++p->released;
  free(memory);
}
static void probe_buffer_free(void *memory, void *user) {
  ++((resource_probe *)user)->freed_buffers;
  free(memory);
}
static int probe_send_admit(void *user, const cnet_send_usage *total,
                            const cnet_send_usage *connection, size_t bytes, size_t backing) {
  (void)user; (void)connection; (void)bytes; (void)backing;
  return total->operations == 0u ? SALTS_OK : SALTS_ENOBUFS;
}
static int probe_send_pause(void *user, const cnet_send_usage *total,
                            const cnet_send_usage *connection, size_t bytes, size_t backing) {
  (void)user; (void)total; (void)connection; (void)bytes; (void)backing;
  return SALTS_ENOBUFS;
}
static int probe_buffer(void *user, size_t bytes, mem_buffer_t **out) {
  void *data = malloc(bytes);
  *out = NULL;
  if (data == NULL) return SALTS_ENOMEM;
  *out = mem_wrap_external(data, bytes, probe_buffer_free, user);
  if (*out == NULL) { free(data); return SALTS_ENOMEM; }
  ++((resource_probe *)user)->buffers;
  return SALTS_OK;
}

static void on_sent(void *user, cnet_connection connection, size_t length) {
  tcp_probe *p = (tcp_probe *)user;
  (void)connection;
  if (p->sent < sizeof(p->send_sizes) / sizeof(p->send_sizes[0]))
    p->send_sizes[p->sent] = length;
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

static int saltscore_original_entry_test_cnet_tcp_loopback_c(unsigned scenario) {
  const bool custom = scenario != 0u;
  cnet_client client = {0};
  cnet_listener listener = {0};
  cnet_client_config config = client_config();
  resource_probe resources = {0};
  cnet_operation operation = {0};
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

  if (custom) {
    config.resources.storage = (cnet_allocator){probe_allocate, probe_deallocate, &resources};
    config.resources.receive = (cnet_buffer_provider){probe_buffer, &resources};
    pending = mem_get_buffer(mem_global(), 1u);
    VERIFY(pending != NULL);
    switch (scenario) {
      case 1u: config.send_limits.connection_bytes = 1u; break;
      case 2u: config.send_limits.connection_operations = 1u; break;
      case 3u: config.send_limits.bytes = 1u; break;
      case 4u: config.send_limits.backing_bytes = mem_buffer_capacity(pending); break;
      case 5u: config.send_limits.connection_backing_bytes = mem_buffer_capacity(pending); break;
      case 6u: config.send_limits.operations = 1u; break;
      case 7u: config.send_admission = (cnet_send_admission_policy){probe_send_admit, NULL}; break;
    }
  }
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
  VERIFY(custom ? mem_is_external(probe.owned_slice.buffer) :
         mem_buffer_pool(probe.owned_slice.buffer) == mem_global());
  VERIFY(saltscore_owner_probe_pool() == mem_global());
  VERIFY(saltscore_owner_probe_thread() == cmeta_thread_current_token());

  if (pending == NULL) pending = mem_get_buffer(mem_global(), 1u);
  VERIFY(pending != NULL);
  *mem_buffer_data(pending) = 0xa5;
  mem_set_used(pending, 1u);
  if (custom) {
    mem_slice_t slice = mem_slice(pending, 0u, 1u);
    const cnet_send_options options = {&slice, 1u, false, on_operation, &probe};
    cnet_admission_limit limit = CNET_LIMIT_NONE;
    int admitted = cnet_send(&client, connection, &options, &operation, &limit);
    mem_slice_release(&slice);
    VERIFY(admitted == SALTS_OK && operation.id != 0u && probe.completed == 0u);
    cnet_send_usage usage = {0};
    VERIFY(cnet_client_send_usage(&client, connection, &usage) == SALTS_OK && usage.bytes == 1u);
    static const cnet_admission_limit expected_limits[] = {CNET_LIMIT_NONE,
        CNET_LIMIT_CONNECTION_BYTES, CNET_LIMIT_CONNECTION_OPERATIONS, CNET_LIMIT_BYTES,
        CNET_LIMIT_BACKING_BYTES, CNET_LIMIT_CONNECTION_BACKING_BYTES, CNET_LIMIT_OPERATIONS,
        CNET_LIMIT_POLICY};
    cnet_operation rejected = {0};
    slice = mem_slice(pending, 0u, 1u);
    admitted = cnet_send(&client, connection, &options, &rejected, &limit);
    mem_slice_release(&slice);
    VERIFY(admitted == SALTS_ENOBUFS && rejected.id == 0u &&
           limit == expected_limits[scenario] && mem_buffer_ref_count(pending) == 2u);
    if (scenario == 7u) {
      const cnet_send_admission_policy paused = {probe_send_pause, NULL};
      VERIFY(cnet_client_set_send_admission(&client, &paused) == SALTS_OK);
    }
  } else VERIFY(cnet_send_buffer(&client, connection, pending) == SALTS_OK);
  mem_buffer_release(pending); /* CNet must retain until terminal send. */
  pending = NULL;
  VERIFY(poll_until(&client, &probe.sent, 1u) == SALTS_OK);
  VERIFY(probe.last_send_bytes == 1u && probe.failed == 0u);
  if (custom) {
    cnet_send_usage usage = {0};
    VERIFY(probe.completed == 1u && probe.completion.operation.id == operation.id &&
           probe.completion.status == SALTS_OK);
    VERIFY(cnet_client_send_usage(&client, connection, &usage) == SALTS_OK && usage.operations == 0u);
  }
  VERIFY(recv(peer, (char *)&outgoing, 1, 0) == 1 &&
         outgoing == 0xa5u);

  if (scenario == 7u) {
    /* Replacement while the first send was live did not revoke its terminal.
     * The replacement still governs new admission after that send settles. */
    pending = mem_get_buffer(mem_global(), 1u);
    VERIFY(pending != NULL);
    *mem_buffer_data(pending) = 0x5a;
    mem_set_used(pending, 1u);
    mem_slice_t slice = mem_slice(pending, 0u, 1u);
    const cnet_send_options options = {&slice, 1u, false, on_operation, &probe};
    cnet_operation next = {0};
    cnet_admission_limit limit = CNET_LIMIT_NONE;
    int status = cnet_send(&client, connection, &options, &next, &limit);
    mem_slice_release(&slice);
    VERIFY(status == SALTS_ENOBUFS && next.id == 0u && limit == CNET_LIMIT_POLICY);
    const cnet_send_admission_policy normal = {0};
    VERIFY(cnet_client_set_send_admission(&client, &normal) == SALTS_OK);
    slice = mem_slice(pending, 0u, 1u);
    status = cnet_send(&client, connection, &options, &next, &limit);
    mem_slice_release(&slice);
    VERIFY(status == SALTS_OK && next.id != operation.id);
    mem_buffer_release(pending);
    pending = NULL;
    VERIFY(poll_until(&client, &probe.sent, 2u) == SALTS_OK);
    VERIFY(probe.completed == 2u && probe.completion.operation.id == next.id &&
           probe.completion.status == SALTS_OK);
    cnet_send_usage usage = {0};
    VERIFY(cnet_client_send_usage(&client, connection, &usage) == SALTS_OK &&
           usage.operations == 0u && usage.bytes == 0u && usage.backing_bytes == 0u);
    VERIFY(recv(peer, (char *)&outgoing, 1, 0) == 1 && outgoing == 0x5au);
  }

  VERIFY(cnet_close(&client, connection) == SALTS_OK);
  VERIFY(poll_until(&client, &probe.terminal, 1u) == SALTS_OK);
  VERIFY(probe.terminal == 1u && probe.failed == 0u &&
         probe.owned_received == 1u && probe.sent == (scenario == 7u ? 2u : 1u));

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
  if (custom && (resources.allocated == 0u || resources.allocated != resources.released ||
                 resources.buffers == 0u || resources.buffers != resources.freed_buffers))
    if (result == 0) result = __LINE__;
  return result;
}


/*
 * M2: the existing native CNet TCP owner carries small control data, a
 * full 32-range retained vector, then a final write/close on one persistent
 * connection. The real OS peer checks bytes rather than assuming a CNet
 * on_send terminal proves remote application receipt.
 *
 * This intentionally does not claim kernel zero-copy, partial-native-write
 * occurrence, or new fairness/backpressure scheduling.
 */
enum {
  STREAM_BULK_SEGMENTS = CNET_RETAINED_VECTOR_MAX,
  STREAM_BULK_SEGMENT_BYTES = 512,
  STREAM_BULK_BYTES = STREAM_BULK_SEGMENTS * STREAM_BULK_SEGMENT_BYTES
};

static int test_recv_exact(test_socket peer, unsigned char *output, size_t count) {
  size_t done = 0u;
  while (done < count) {
    const size_t remain = count - done;
    const int chunk = (int)(remain > 4096u ? 4096u : remain);
    const int read_bytes = recv(peer, (char *)output + done, chunk, 0);
    if (read_bytes <= 0) return -1;
    done += (size_t)read_bytes;
  }
  return 0;
}

static int saltscore_native_entry_test_cnet_tcp_stream_bulk(void) {
  static const unsigned char first[] = {'C','T','R','L','-','0','1'};
  static const unsigned char last[] = {'F','I','N','!','!'};
  cnet_client client = {0};
  cnet_listener listener = {0};
  cnet_client_config config = client_config();
  const cnet_listener_config listener_config = {
      backend_kind(), "127.0.0.1", 0u, 2u};
  tcp_probe probe = {0};
  cnet_observer observer = {on_state, on_borrowed, &probe, on_sent};
  cnet_connection connection = {0};
  test_socket peer = TEST_INVALID_SOCKET;
  struct sockaddr_in remote;
  mem_buffer_t *control = NULL, *bulk = NULL, *final = NULL, *oversized = NULL;
  mem_slice_t ranges[STREAM_BULK_SEGMENTS] = {{0}};
  unsigned char received[sizeof(first) + STREAM_BULK_BYTES];
  unsigned char last_received[sizeof(last)] = {0};
  size_t count = 0u;
  uint16_t port = 0u;
  uint64_t nodelay = 0u;
  int ready = 0, result = 0;
  int client_live = 0, listener_live = 0;

  config.max_send_bytes = STREAM_BULK_BYTES;
  config.command_capacity = 16u;
  config.request_capacity = 8u;
  config.completion_batch_capacity = 8u;
  config.event_capacity = 16u;

  VERIFY(cnet_listener_init(&listener, &listener_config) == SALTS_OK);
  listener_live = 1;
  VERIFY(cnet_listener_port(&listener, &port) == SALTS_OK && port != 0u);
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  client_live = 1;
  /* Direct accept preserves listener policy; client future-connection options
   * apply to dialed sockets and explicit detached-stream adoption instead. */
  VERIFY(cnet_listener_tcp_option_set(&listener, CNET_TCP_SOCKET_NODELAY, 1u) == SALTS_OK);
  peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  VERIFY(peer != TEST_INVALID_SOCKET);
  VERIFY(test_recv_timeout(peer) == 0);
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  remote.sin_port = htons(port);
  VERIFY(connect(peer, (const struct sockaddr *)&remote, (int)sizeof(remote)) == 0);
  VERIFY(cnet_listener_wait(&listener, 5000u, &ready) == SALTS_OK && ready == 1);
  VERIFY(cnet_listener_accept(&listener, &client, &observer, &connection) == SALTS_OK);
  VERIFY(poll_until(&client, &probe.connected, 1u) == SALTS_OK);
  VERIFY(probe.failed == 0u && probe.terminal == 0u);
  VERIFY(cnet_connection_tcp_option_get(&client, connection,
                                        CNET_TCP_SOCKET_NODELAY, &nodelay) == SALTS_OK);
  VERIFY(nodelay == 1u);

  /* The Owner hard limit rejects an oversized logical write without retaining
   * the caller's buffer or changing the live connection's send state. */
  oversized = mem_get_buffer(mem_global(), STREAM_BULK_BYTES + 1u);
  VERIFY(oversized != NULL);
  mem_set_used(oversized, STREAM_BULK_BYTES + 1u);
  VERIFY(mem_buffer_ref_count(oversized) == 1u);
  VERIFY(cnet_send_buffer(&client, connection, oversized) == SALTS_EMSGSIZE);
  VERIFY(mem_buffer_ref_count(oversized) == 1u);
  mem_buffer_release(oversized);
  oversized = NULL;

  control = mem_get_buffer(mem_global(), sizeof(first));
  VERIFY(control != NULL);
  memcpy(mem_buffer_data(control), first, sizeof(first));
  mem_set_used(control, sizeof(first));
  VERIFY(cnet_send_buffer(&client, connection, control) == SALTS_OK);
  mem_buffer_release(control);
  control = NULL;

  bulk = mem_get_buffer(mem_global(), STREAM_BULK_BYTES);
  VERIFY(bulk != NULL);
  for (size_t i = 0u; i < STREAM_BULK_BYTES; ++i)
    mem_buffer_data(bulk)[i] = (char)((i * 29u + 3u) & 0xffu);
  mem_set_used(bulk, STREAM_BULK_BYTES);
  for (size_t i = 0u; i < STREAM_BULK_SEGMENTS; ++i) {
    ranges[i] = mem_slice(bulk, i * STREAM_BULK_SEGMENT_BYTES,
                          STREAM_BULK_SEGMENT_BYTES);
    VERIFY(ranges[i].buffer == bulk && ranges[i].length == STREAM_BULK_SEGMENT_BYTES);
    ++count;
  }
  VERIFY(cnet_send_slicev(&client, connection, ranges, count) == SALTS_OK);
  for (size_t i = 0u; i < count; ++i) mem_slice_release(&ranges[i]);
  count = 0u;
  mem_buffer_release(bulk); /* CNet retains the backing until the real terminal. */
  bulk = NULL;

  VERIFY(poll_until(&client, &probe.sent, 2u) == SALTS_OK);
  VERIFY(probe.sent == 2u && probe.send_sizes[0] == sizeof(first) &&
         probe.send_sizes[1] == STREAM_BULK_BYTES &&
         probe.failed == 0u && probe.terminal == 0u);
  VERIFY(test_recv_exact(peer, received, sizeof(received)) == 0);
  VERIFY(memcmp(received, first, sizeof(first)) == 0);
  for (size_t i = 0u; i < STREAM_BULK_BYTES; ++i)
    VERIFY(received[sizeof(first) + i] == (unsigned char)((i * 29u + 3u) & 0xffu));

  /* This was a persistent connection: the two successful writes did not
   * close it. The final retained send closes only after its own terminal. */
  final = mem_get_buffer(mem_global(), sizeof(last));
  VERIFY(final != NULL);
  memcpy(mem_buffer_data(final), last, sizeof(last));
  mem_set_used(final, sizeof(last));
  VERIFY(cnet_send_buffer_and_close(&client, connection, final) == SALTS_OK);
  mem_buffer_release(final);
  final = NULL;
  VERIFY(poll_until(&client, &probe.terminal, 1u) == SALTS_OK);
  VERIFY(probe.sent == 3u && probe.send_sizes[2] == sizeof(last) &&
         probe.terminal == 1u && probe.failed == 0u);
  VERIFY(test_recv_exact(peer, last_received, sizeof(last_received)) == 0);
  VERIFY(memcmp(last_received, last, sizeof(last)) == 0);
  {
    unsigned char byte = 0u;
    VERIFY(recv(peer, (char *)&byte, 1, 0) == 0); /* Real remote TCP FIN. */
  }
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  client_live = 0;
  VERIFY(cnet_listener_close(&listener) == SALTS_OK);
  VERIFY(cnet_listener_destroy(&listener) == SALTS_OK);
  listener_live = 0;

cleanup:
  for (size_t i = 0u; i < count; ++i) mem_slice_release(&ranges[i]);
  if (oversized) mem_buffer_release(oversized);
  if (control) mem_buffer_release(control);
  if (bulk) mem_buffer_release(bulk);
  if (final) mem_buffer_release(final);
  if (client_live) {
    (void)cnet_client_stop(&client, 5000u);
    (void)cnet_client_destroy(&client);
  }
  if (listener_live) {
    (void)cnet_listener_close(&listener);
    (void)cnet_listener_destroy(&listener);
  }
  test_close_socket(peer);
  return result;
}

static test_socket test_native_listener(uint16_t *port) {
  struct sockaddr_in address = {0};
#if defined(_WIN32)
  int address_size = (int)sizeof(address);
#else
  socklen_t address_size = (socklen_t)sizeof(address);
#endif
  test_socket listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listener == TEST_INVALID_SOCKET) return TEST_INVALID_SOCKET;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(listener, (const struct sockaddr *)&address, (int)sizeof(address)) != 0 ||
      listen(listener, 1) != 0 ||
      getsockname(listener, (struct sockaddr *)&address, &address_size) != 0) {
    test_close_socket(listener);
    return TEST_INVALID_SOCKET;
  }
  *port = ntohs(address.sin_port);
  return listener;
}

static int invalid_pool_choice(void *user, const cnet_pool_candidate *candidates,
                               size_t count, uint64_t sequence, size_t *out) {
  (void)user; (void)candidates; (void)sequence; *out = count; return SALTS_OK;
}
static int guarded_pool_choice(void *user, const cnet_pool_candidate *candidates,
                               size_t count, uint64_t sequence, size_t *out) {
  cnet_pool_snapshot snapshot;
  if (cnet_pool_get_snapshot(user, &snapshot) != SALTS_EBUSY) return SALTS_EPROTO;
  return cnet_pool_select_least_used(NULL, candidates, count, sequence, out);
}
static int pool_acquire_rejected(cnet_client_pool *pool, const cnet_pool_key *key,
                                 int expected_status) {
  cnet_pool_lease lease = {UINTPTR_MAX, UINT64_MAX, UINT64_MAX, SIZE_MAX};
  cnet_managed_connection managed = {UINTPTR_MAX, UINT64_MAX, UINT64_MAX, SIZE_MAX};
  const int status = cnet_pool_try_acquire(pool, key, NULL, &lease, &managed);
  const int rejected = status == expected_status &&
      lease.pool == 0u && lease.incarnation == 0u &&
      lease.generation == 0u && lease.slot == 0u &&
      managed.manager == 0u && managed.incarnation == 0u &&
      managed.generation == 0u && managed.slot == 0u;
  if (status == SALTS_OK) (void)cnet_pool_release(pool, lease);
  return rejected;
}

/* One issuing thread owns Client, Manager and Pool. The native TCP peer uses a
 * one-byte READY/request/reply protocol. The host binds READY only after the
 * peer's greeting; transport CONNECTED is insufficient. One physical slot and
 * one protocol slot bound reuse. Leases survive transport terminal until the
 * host releases them; Manager's context hold outlives those pool obligations. */
static int saltscore_native_entry_test_cnet_pool_reuse(unsigned close_mode) {
  cnet_client client = {0};
  cnet_manager manager = {0};
  cnet_client_pool pool = {0};
  cnet_client_config config = client_config();
  const cnet_manager_config manager_config = {
      sizeof(cnet_manager_config), CNET_MANAGER_VERSION, &client, 1u, 1u};
  const cnet_pool_config pool_config = {
      sizeof(cnet_pool_config), CNET_CLIENT_POOL_VERSION, &manager, 11u, 1u, 1u, 2u};
  tcp_probe probe = {0};
  const cnet_manager_attachment attachment = {
      {on_state, on_borrowed, &probe, on_sent}, on_recycled, true};
  cnet_pool_key key = {
      .size = sizeof(cnet_pool_key), .version = CNET_CLIENT_POOL_VERSION,
      .runtime_id = 1u, .owner_id = 11u, .peer_generation = 1u,
      .authority_id = 17u, .transport_id = 1u, .protocol_id = 23u, .session_id = 29u};
  cnet_pool_key incompatible = {0};
  uint64_t *key_fields[] = {
      &incompatible.runtime_id, &incompatible.owner_id, &incompatible.endpoint_id,
      &incompatible.peer_generation, &incompatible.authority_id, &incompatible.transport_id,
      &incompatible.tls_trust_id, &incompatible.tls_sni_id, &incompatible.client_identity_id,
      &incompatible.alpn_id, &incompatible.protocol_id, &incompatible.session_id};
  cnet_managed_connection managed = {0}, leased = {0};
  cnet_pool_connection physical = {0}, replacement = {0};
  cnet_pool_lease lease = {0}, stale_lease = {0};
  cnet_connection connection = {0};
  cnet_connect_options connect_options = {0};
  cnet_manager_entry entry = {0};
  cnet_manager_snapshot manager_snapshot = {0};
  cnet_pool_snapshot pool_snapshot = {0};
  test_socket listener = TEST_INVALID_SOCKET, peer = TEST_INVALID_SOCKET;
  mem_buffer_t *pending = NULL;
  char uri[80];
  uint16_t port = 0u;
  unsigned char byte = 0x52u;
  size_t work = 0u;
  int result = 0;
  int client_live = 0, manager_live = 0, pool_live = 0;

  config.connect_timeout_ms = 3000u;
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  client_live = 1;
  listener = test_native_listener(&port);
  VERIFY(listener != TEST_INVALID_SOCKET && port != 0u);
  key.endpoint_id = port;
  VERIFY(snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", (unsigned)port) > 0);
  connect_options.uri = uri;
  VERIFY(cnet_manager_init(&manager, &manager_config) == SALTS_OK);
  manager_live = 1;
  VERIFY(cnet_pool_init(&pool, &pool_config) == SALTS_OK);
  pool_live = 1;
  VERIFY(cnet_pool_reserve_connecting(&pool, &key, &physical) == SALTS_OK);
  VERIFY(cnet_manager_reserve(&manager, &attachment, &managed) == SALTS_OK);
  VERIFY(pool_acquire_rejected(&pool, &key, SALTS_ENOBUFS));
  VERIFY(cnet_manager_connect(&manager, managed, &connect_options, &connection) == SALTS_OK);
  VERIFY(cnet_pool_bind_ready(&pool, physical, managed, 1u) == SALTS_EBUSY);
  VERIFY(poll_until(&client, &probe.connected, 1u) == SALTS_OK);
  VERIFY(probe.connected == 1u && probe.terminal == 0u && probe.failed == 0u);
  peer = accept(listener, NULL, NULL);
  VERIFY(peer != TEST_INVALID_SOCKET);
  VERIFY(test_recv_timeout(peer) == 0);
  test_close_socket(listener);
  listener = TEST_INVALID_SOCKET;
  VERIFY(cnet_manager_lookup(&manager, managed, &entry) == SALTS_OK);
  VERIFY(entry.state == CNET_MANAGER_BOUND);
  /* The host has not yet published application READY, despite TCP CONNECTED. */
  VERIFY(pool_acquire_rejected(&pool, &key, SALTS_ENOBUFS));
  VERIFY(cnet_pool_get_snapshot(&pool, &pool_snapshot) == SALTS_OK);
  VERIFY(pool_snapshot.connecting == 1u && pool_snapshot.ready == 0u &&
         pool_snapshot.active_leases == 0u);
  VERIFY(cnet_receive(&client, connection, 1u) == SALTS_OK);
  VERIFY(send(peer, (const char *)&byte, 1, 0) == 1);
  VERIFY(poll_until(&client, &probe.borrowed_bytes, 1u) == SALTS_OK);
  VERIFY(probe.borrowed_bytes == 1u && probe.borrowed_data[0] == 0x52u);
  VERIFY(cnet_pool_bind_ready(&pool, physical, managed, 1u) == SALTS_OK);
  VERIFY(cnet_pool_get_snapshot(&pool, &pool_snapshot) == SALTS_OK);
  VERIFY(pool_snapshot.connecting == 0u && pool_snapshot.ready == 1u &&
         pool_snapshot.physical_in_use == 1u);
  /* Sealing new Manager reservations alone must preserve existing reuse. */
  VERIFY(cnet_manager_seal(&manager) == SALTS_OK);

  /* Each changed identity must deny reuse. Optional security IDs remain zero
   * for this plaintext recipe; setting one is a different key, not TLS proof. */
  for (size_t i = 0u; i < sizeof(key_fields) / sizeof(key_fields[0]); ++i) {
    incompatible = key;
    ++*key_fields[i];
    VERIFY(pool_acquire_rejected(&pool, &incompatible,
                                 i == 1u ? SALTS_EINVAL : SALTS_ENOBUFS));
  }

  const cnet_pool_selection_policy invalid_selection = {invalid_pool_choice, NULL};
  const cnet_pool_selection_policy guarded_selection = {guarded_pool_choice, &pool};
  VERIFY(cnet_pool_set_selection(&pool, &invalid_selection) == SALTS_OK);
  VERIFY(pool_acquire_rejected(&pool, &key, SALTS_EINVAL));
  VERIFY(cnet_pool_set_selection(&pool, &guarded_selection) == SALTS_OK);
  for (unsigned exchange = 0u; exchange < 2u; ++exchange) {
    VERIFY(cnet_pool_try_acquire(&pool, &key, NULL, &lease, &leased) == SALTS_OK);
    VERIFY(leased.manager == managed.manager && leased.incarnation == managed.incarnation &&
           leased.generation == managed.generation && leased.slot == managed.slot);
    VERIFY(cnet_manager_lookup(&manager, leased, &entry) == SALTS_OK);
    VERIFY(entry.state == CNET_MANAGER_BOUND && entry.connection.slot == connection.slot &&
           entry.connection.generation == connection.generation);
    VERIFY(pool_acquire_rejected(&pool, &key, SALTS_ENOBUFS));
    if (exchange != 0u) {
      VERIFY(lease.slot == stale_lease.slot && lease.generation > stale_lease.generation);
      VERIFY(cnet_pool_release(&pool, stale_lease) == SALTS_ENOENT);
    }
    pending = mem_get_buffer(mem_global(), 1u);
    VERIFY(pending != NULL);
    *mem_buffer_data(pending) = (char)(0xa1u + exchange);
    mem_set_used(pending, 1u);
    VERIFY(cnet_send_buffer(&client, entry.connection, pending) == SALTS_OK);
    mem_buffer_release(pending);
    pending = NULL;
    VERIFY(poll_until(&client, &probe.sent, exchange + 1u) == SALTS_OK);
    VERIFY(recv(peer, (char *)&byte, 1, 0) == 1 && byte == 0xa1u + exchange);
    /* A local send terminal does not release the application's request lease. */
    VERIFY(cnet_pool_get_snapshot(&pool, &pool_snapshot) == SALTS_OK);
    VERIFY(pool_snapshot.active_leases == 1u);
    VERIFY(pool_acquire_rejected(&pool, &key, SALTS_ENOBUFS));
    byte = (unsigned char)(0x11u + exchange);
    VERIFY(cnet_receive(&client, entry.connection, 1u) == SALTS_OK);
    VERIFY(send(peer, (const char *)&byte, 1, 0) == 1);
    VERIFY(poll_until(&client, &probe.borrowed_bytes, exchange + 2u) == SALTS_OK);
    VERIFY(probe.borrowed_bytes == exchange + 2u &&
           probe.borrowed_data[exchange + 1u] == byte);
    VERIFY(probe.connected == 1u && probe.terminal == 0u && probe.failed == 0u);
    if (exchange == 0u) {
      stale_lease = lease;
      VERIFY(cnet_pool_release(&pool, lease) == SALTS_OK);
      lease = (cnet_pool_lease){0};
    }
  }

  VERIFY(cnet_pool_terminal(&pool, physical) == SALTS_EBUSY);
  if (close_mode == 0u) {
    VERIFY(cnet_pool_begin_drain(&pool, physical) == SALTS_OK);
    VERIFY(pool_acquire_rejected(&pool, &key, SALTS_ENOBUFS));
    VERIFY(cnet_close(&client, connection) == SALTS_OK);
  } else {
    /* Leave a real lease slot available: rejection must come from transport
     * closure, not from lease exhaustion or an explicit pool drain. */
    VERIFY(cnet_pool_release(&pool, lease) == SALTS_OK);
    lease = (cnet_pool_lease){0};
    if (close_mode == 1u) {
      VERIFY(cnet_close(&client, connection) == SALTS_OK);
    } else if (close_mode == 2u) {
      pending = mem_get_buffer(mem_global(), 1u);
      VERIFY(pending != NULL);
      *mem_buffer_data(pending) = 0xf1u;
      mem_set_used(pending, 1u);
      VERIFY(cnet_send_buffer_and_close(&client, connection, pending) == SALTS_OK);
      mem_buffer_release(pending);
      pending = NULL;
    } else if (close_mode == 3u) {
      VERIFY(cnet_manager_request_close(&manager) == SALTS_OK);
    } else {
      VERIFY(cnet_connection_shutdown(&client, connection, CNET_TCP_SHUTDOWN_SEND) == SALTS_OK);
    }
    VERIFY(probe.terminal == 0u);
    VERIFY(cnet_manager_lookup(&manager, managed, &entry) == SALTS_OK &&
           entry.state == CNET_MANAGER_BOUND);
    VERIFY(pool_acquire_rejected(&pool, &key, SALTS_ENOBUFS));
    VERIFY(cnet_pool_get_snapshot(&pool, &pool_snapshot) == SALTS_OK &&
           pool_snapshot.draining == 1u && pool_snapshot.ready == 0u &&
           pool_snapshot.physical_in_use == 1u && pool_snapshot.active_leases == 0u);
    VERIFY(cnet_pool_terminal(&pool, physical) == SALTS_EBUSY);
    if (close_mode == 3u) VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK && work == 1u);
    if (close_mode == 4u) VERIFY(cnet_close(&client, connection) == SALTS_OK);
  }
  VERIFY(poll_until(&client, &probe.terminal, 1u) == SALTS_OK);
  VERIFY(probe.terminal == 1u && probe.failed == 0u && probe.sent == (close_mode == 2u ? 3u : 2u));
  if (close_mode == 2u) VERIFY(recv(peer, (char *)&byte, 1, 0) == 1 && byte == 0xf1u);
  VERIFY(recv(peer, (char *)&byte, 1, 0) == 0);
  VERIFY(cnet_manager_lookup(&manager, managed, &entry) == SALTS_OK);
  VERIFY(entry.state == CNET_MANAGER_RETIRED && entry.context_held);
  VERIFY(cnet_pool_terminal(&pool, physical) == SALTS_OK);
  VERIFY(cnet_pool_get_snapshot(&pool, &pool_snapshot) == SALTS_OK);
  if (close_mode == 0u) {
    VERIFY(pool_snapshot.physical_in_use == 1u && pool_snapshot.active_leases == 1u &&
           pool_snapshot.terminal_waiting_for_leases == 1u && !pool_snapshot.drained);
    VERIFY(cnet_pool_destroy(&pool) == SALTS_EBUSY);
  } else VERIFY(pool_snapshot.drained && pool_snapshot.physical_in_use == 0u);
  VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK);
  VERIFY(probe.recycled == 0u);
  if (lease.slot != 0u) {
    VERIFY(cnet_pool_release(&pool, lease) == SALTS_OK);
    VERIFY(cnet_pool_release(&pool, lease) == SALTS_ENOENT);
  }
  lease = (cnet_pool_lease){0};
  VERIFY(cnet_pool_get_snapshot(&pool, &pool_snapshot) == SALTS_OK);
  VERIFY(pool_snapshot.drained && pool_snapshot.physical_in_use == 0u &&
         pool_snapshot.active_leases == 0u);
  /* Recycle only the pool reservation, without dialing another TCP socket. */
  VERIFY(cnet_pool_reserve_connecting(&pool, &key, &replacement) == SALTS_OK);
  VERIFY(replacement.slot == physical.slot && replacement.generation > physical.generation);
  VERIFY(cnet_pool_terminal(&pool, physical) == SALTS_ENOENT);
  VERIFY(cnet_pool_terminal(&pool, replacement) == SALTS_OK);
  VERIFY(cnet_pool_seal(&pool) == SALTS_OK);
  VERIFY(pool_acquire_rejected(&pool, &key, SALTS_ESHUTDOWN));
  VERIFY(cnet_pool_destroy(&pool) == SALTS_OK);
  pool_live = 0;
  VERIFY(cnet_manager_release_context(&manager, managed) == SALTS_OK);
  VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK);
  VERIFY(probe.recycled == 1u);
  VERIFY(cnet_manager_get_snapshot(&manager, &manager_snapshot) == SALTS_OK);
  VERIFY(manager_snapshot.drained);
  VERIFY(cnet_manager_destroy(&manager) == SALTS_OK);
  manager_live = 0;
  test_close_socket(peer);
  peer = TEST_INVALID_SOCKET;
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  client_live = 0;

cleanup:
  if (pending) mem_buffer_release(pending);
  test_close_socket(peer);
  test_close_socket(listener);
  if (manager_live) {
    (void)cnet_manager_request_close(&manager);
    (void)cnet_manager_advance(&manager, 1u, &work);
  }
  if (client_live) (void)cnet_client_stop(&client, 3000u);
  if (pool_live) {
    if (lease.slot != 0u) (void)cnet_pool_release(&pool, lease);
    if (physical.slot != 0u) (void)cnet_pool_terminal(&pool, physical);
    if (replacement.slot != 0u) (void)cnet_pool_terminal(&pool, replacement);
    (void)cnet_pool_destroy(&pool);
  }
  if (manager_live) {
    if (managed.slot != 0u) (void)cnet_manager_release_context(&manager, managed);
    (void)cnet_manager_advance(&manager, 1u, &work);
    (void)cnet_manager_destroy(&manager);
  }
  if (client_live) (void)cnet_client_destroy(&client);
  return result;
}

/* Host protocol reservations are real, bounded slots, independent of the
 * pool's advertised capacity. Tokens are transmitted to native peers and held
 * until explicit lease release. Both providers share slots but own distinct
 * release counters; their callback storage outlives every lease and terminal. */
typedef struct pool_protocol_bank {
  cnet_client_pool *pool;
  cnet_managed_connection managed[2];
  uint64_t tokens[2][2], next_token;
  size_t capacity[2], attempts, attempted_mask;
  int reject_status;
  unsigned errors;
} pool_protocol_bank;
typedef struct pool_protocol_provider {
  pool_protocol_bank *bank;
  size_t acquired, released, last_index;
  uint64_t last_token;
  cnet_pool_protocol_ops *rebind;
  void *next_user;
  bool rebind_on_full;
} pool_protocol_provider;

static int composition_reserve(void *user, cnet_managed_connection managed, uint64_t *out) {
  pool_protocol_provider *provider = user;
  pool_protocol_bank *bank = provider->bank;
  cnet_pool_snapshot snapshot;
  *out = 0u;
  ++bank->attempts;
  if (cnet_pool_get_snapshot(bank->pool, &snapshot) != SALTS_EBUSY) {
    ++bank->errors;
    return SALTS_EPROTO;
  }
  if (bank->reject_status != SALTS_OK) return bank->reject_status;
  for (size_t i = 0u; i < 2u; ++i) {
    const cnet_managed_connection expected = bank->managed[i];
    if (managed.manager != expected.manager || managed.incarnation != expected.incarnation ||
        managed.generation != expected.generation || managed.slot != expected.slot) continue;
    bank->attempted_mask |= (size_t)1u << i;
    for (size_t j = 0u; j < bank->capacity[i]; ++j) {
      if (bank->tokens[i][j] != 0u) continue;
      *out = bank->tokens[i][j] = ++bank->next_token;
      provider->last_token = *out;
      provider->last_index = i;
      ++provider->acquired;
      /* A host can prepare its next binding during reservation. The accepted
       * token must keep the provider that actually admitted this acquire. */
      if (provider->rebind != NULL) {
        provider->rebind->user = provider->next_user;
        provider->rebind = NULL;
      }
      return SALTS_OK;
    }
    if (provider->rebind_on_full && provider->rebind != NULL) {
      provider->rebind->user = provider->next_user;
      provider->rebind = NULL;
    }
    return SALTS_ENOBUFS;
  }
  ++bank->errors;
  return SALTS_ENOENT;
}

static void composition_release(void *user, uint64_t token) {
  pool_protocol_provider *provider = user;
  pool_protocol_bank *bank = provider->bank;
  cnet_pool_snapshot snapshot;
  if (cnet_pool_get_snapshot(bank->pool, &snapshot) != SALTS_EBUSY) ++bank->errors;
  for (size_t i = 0u; i < 2u; ++i) {
    for (size_t j = 0u; j < 2u; ++j) {
      if (token != 0u && bank->tokens[i][j] == token) {
        bank->tokens[i][j] = 0u;
        ++provider->released;
        return;
      }
    }
  }
  ++bank->errors;
}

static int composition_pause(void *user, const cnet_pool_candidate *candidates,
                               size_t count, uint64_t sequence, size_t *out) {
  const cnet_pool_selection_policy normal = {0};
  (void)candidates; (void)count; (void)sequence;
  *out = SIZE_MAX;
  return cnet_pool_set_selection(user, &normal) == SALTS_EBUSY ? SALTS_EBUSY : SALTS_EPROTO;
}

typedef struct pool_selection_probe {
  cnet_client_pool *pool;
  size_t index, calls;
  int status;
} pool_selection_probe;

static int composition_select_probe(void *user, const cnet_pool_candidate *candidates,
                                     size_t count, uint64_t sequence, size_t *out) {
  pool_selection_probe *probe = user;
  (void)candidates; (void)count; (void)sequence;
  ++probe->calls;
  *out = probe->index;
  if (cnet_pool_seal(probe->pool) != SALTS_EBUSY) return SALTS_EPROTO;
  return probe->status;
}

static int composition_exchange(cnet_client *client, cnet_connection connection,
                                  tcp_probe *probe, test_socket peer, uint64_t token) {
  int result = 0;
  const unsigned sent = probe->sent, received = probe->borrowed_bytes;
  unsigned char byte = 0u, reply = (unsigned char)(token | 0x80u);
  mem_buffer_t *buffer = mem_get_buffer(mem_global(), 1u);
  VERIFY(buffer != NULL && token != 0u && token < 0x80u);
  *mem_buffer_data(buffer) = (unsigned char)token;
  mem_set_used(buffer, 1u);
  VERIFY(cnet_send_buffer(client, connection, buffer) == SALTS_OK);
  mem_buffer_release(buffer);
  buffer = NULL;
  VERIFY(poll_until(client, &probe->sent, sent + 1u) == SALTS_OK);
  VERIFY(recv(peer, (char *)&byte, 1, 0) == 1 && byte == token);
  VERIFY(cnet_receive(client, connection, 1u) == SALTS_OK);
  VERIFY(send(peer, (const char *)&reply, 1, 0) == 1);
  VERIFY(poll_until(client, &probe->borrowed_bytes, received + 1u) == SALTS_OK);
  VERIFY(probe->borrowed_data[received] == reply && probe->failed == 0u);
cleanup:
  if (buffer != NULL) mem_buffer_release(buffer);
  return result;
}

static int saltscore_native_entry_test_cnet_pool_composition(void) {
  cnet_client client = {0};
  cnet_manager manager = {0};
  cnet_client_pool pool = {0};
  cnet_client_config config = client_config();
  const cnet_manager_config manager_config = {
      sizeof(cnet_manager_config), CNET_MANAGER_VERSION, &client, 2u, 2u};
  const cnet_pool_config pool_config = {
      sizeof(cnet_pool_config), CNET_CLIENT_POOL_VERSION, &manager, 11u, 2u, 2u, 4u};
  pool_protocol_bank bank = {.pool = &pool, .capacity = {1u, 1u}};
  pool_protocol_provider providers[2] = {{.bank = &bank}, {.bank = &bank}};
  cnet_pool_protocol_ops protocol = {composition_reserve, composition_release, &providers[0]};
  const cnet_pool_selection_policy first = {cnet_pool_select_first, NULL};
  const cnet_pool_selection_policy round_robin = {cnet_pool_select_round_robin, NULL};
  const cnet_pool_selection_policy least_used = {cnet_pool_select_least_used, NULL};
  const cnet_pool_selection_policy paused = {composition_pause, &pool};
  cnet_pool_key key = {.size = sizeof(cnet_pool_key), .version = CNET_CLIENT_POOL_VERSION,
      .runtime_id = 1u, .owner_id = 11u, .authority_id = 17u, .transport_id = 1u, .protocol_id = 23u};
  cnet_pool_connection physical[2] = {{0}, {0}};
  cnet_connection connections[2] = {{0}, {0}};
  cnet_pool_lease leases[4] = {{0}}, rejected = {0}, stale = {0};
  cnet_managed_connection leased = {0};
  cnet_pool_snapshot snapshot = {0};
  tcp_probe probes[2] = {{0}, {0}};
  test_socket listener = TEST_INVALID_SOCKET, peers[2] = {TEST_INVALID_SOCKET, TEST_INVALID_SOCKET};
  uint16_t port = 0u;
  unsigned char byte = 0x52u;
  char uri[80];
  size_t work = 0u;
  int result = 0;
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  listener = test_native_listener(&port);
  VERIFY(listener != TEST_INVALID_SOCKET && port != 0u);
  key.endpoint_id = port;
  VERIFY(snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", (unsigned)port) > 0);
  VERIFY(cnet_manager_init(&manager, &manager_config) == SALTS_OK);
  VERIFY(cnet_pool_init(&pool, &pool_config) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    const cnet_manager_attachment attachment = {
        {on_state, on_borrowed, &probes[i], on_sent}, on_recycled, true};
    const cnet_connect_options options = {.uri = uri};
    VERIFY(cnet_pool_reserve_connecting(&pool, &key, &physical[i]) == SALTS_OK);
    VERIFY(cnet_manager_reserve(&manager, &attachment, &bank.managed[i]) == SALTS_OK);
    VERIFY(cnet_manager_connect(&manager, bank.managed[i], &options, &connections[i]) == SALTS_OK);
    VERIFY(poll_until(&client, &probes[i].connected, 1u) == SALTS_OK);
    peers[i] = accept(listener, NULL, NULL);
    VERIFY(peers[i] != TEST_INVALID_SOCKET && test_recv_timeout(peers[i]) == 0);
    VERIFY(cnet_receive(&client, connections[i], 1u) == SALTS_OK);
    VERIFY(send(peers[i], (const char *)&byte, 1, 0) == 1);
    VERIFY(poll_until(&client, &probes[i].borrowed_bytes, 1u) == SALTS_OK);
    VERIFY(probes[i].borrowed_data[0] == byte);
    VERIFY(cnet_pool_bind_ready(&pool, physical[i], bank.managed[i], 2u) == SALTS_OK);
  }
  /* Selection cannot publish a bad/filtered/repeated index, and a hard error
   * from either callback must leave both leases and real protocol slots free. */
  pool_selection_probe selection_probe = {.pool = &pool};
  const cnet_pool_selection_policy custom = {composition_select_probe, &selection_probe};
  VERIFY(cnet_pool_set_selection(&pool, &custom) == SALTS_OK);
  for (unsigned negative = 0u; negative < 4u; ++negative) {
    cnet_pool_key requested = key;
    const size_t attempts_before = bank.attempts;
    selection_probe.calls = 0u;
    selection_probe.status = negative == 0u ? SALTS_EIO : SALTS_OK;
    selection_probe.index = negative == 1u ? 2u : 0u;
    if (negative == 2u) ++requested.authority_id;
    if (negative == 3u) bank.capacity[0] = 0u;
    rejected = (cnet_pool_lease){1u, 1u, 1u, 1u};
    leased = (cnet_managed_connection){1u, 1u, 1u, 1u};
    VERIFY(cnet_pool_try_acquire(&pool, &requested, &protocol, &rejected, &leased) ==
           (negative == 0u ? SALTS_EIO : SALTS_EINVAL));
    VERIFY(rejected.pool == 0u && rejected.incarnation == 0u && rejected.generation == 0u && rejected.slot == 0u);
    VERIFY(leased.manager == 0u && leased.incarnation == 0u && leased.generation == 0u && leased.slot == 0u);
    VERIFY(selection_probe.calls == (negative == 3u ? 2u : 1u));
    VERIFY(bank.attempts == attempts_before + (negative == 3u ? 1u : 0u));
    VERIFY(providers[0].acquired == 0u && providers[0].released == 0u &&
           providers[1].acquired == 0u && providers[1].released == 0u);
    VERIFY(cnet_pool_get_snapshot(&pool, &snapshot) == SALTS_OK &&
           snapshot.active_leases == 0u && snapshot.ready == 2u && snapshot.physical_in_use == 2u);
    VERIFY(bank.tokens[0][0] == 0u && bank.tokens[0][1] == 0u &&
           bank.tokens[1][0] == 0u && bank.tokens[1][1] == 0u);
    bank.capacity[0] = 1u;
  }
  VERIFY(cnet_pool_set_selection(&pool, &first) == SALTS_OK);
  bank.reject_status = SALTS_EIO;
  const size_t hard_error_attempts = bank.attempts;
  VERIFY(cnet_pool_try_acquire(&pool, &key, &protocol, &rejected, &leased) == SALTS_EIO);
  VERIFY(bank.attempts == hard_error_attempts + 1u && rejected.slot == 0u && leased.slot == 0u);
  VERIFY(cnet_pool_get_snapshot(&pool, &snapshot) == SALTS_OK && snapshot.active_leases == 0u && snapshot.ready == 2u);
  VERIFY(providers[0].acquired == 0u && providers[0].released == 0u);
  bank.reject_status = SALTS_OK;
  for (size_t i = 0u; i < 2u; ++i) {
    VERIFY(cnet_pool_set_selection(&pool, i == 0u ? &first : &round_robin) == SALTS_OK);
    if (i == 1u) {
      providers[0].rebind = &protocol;
      providers[0].next_user = &providers[1];
    }
    VERIFY(cnet_pool_try_acquire(&pool, &key, &protocol, &leases[i], &leased) == SALTS_OK);
    VERIFY(providers[0].last_index == i && leased.slot == bank.managed[i].slot);
    if (i == 1u) VERIFY(protocol.user == &providers[1] && providers[1].acquired == 0u);
    VERIFY(composition_exchange(&client, connections[i], &probes[i], peers[i], providers[0].last_token) == 0);
  }
  VERIFY(cnet_pool_set_selection(&pool, &first) == SALTS_OK);
  size_t attempts = bank.attempts;
  bank.attempted_mask = 0u;
  VERIFY(cnet_pool_try_acquire(&pool, &key, &protocol, &rejected, &leased) == SALTS_ENOBUFS);
  VERIFY(rejected.pool == 0u && rejected.slot == 0u && leased.manager == 0u && leased.slot == 0u);
  VERIFY(bank.attempts == attempts + 2u && bank.attempted_mask == 3u && providers[0].released == 0u);
  VERIFY(cnet_pool_get_snapshot(&pool, &snapshot) == SALTS_OK && snapshot.active_leases == 2u);
  stale = leases[1];
  VERIFY(cnet_pool_release(&pool, leases[1]) == SALTS_OK);
  VERIFY(providers[0].released == 1u && providers[1].released == 0u);
  leases[1] = (cnet_pool_lease){0};
  protocol.user = &providers[1];
  for (size_t j = 1u; j < 4u; ++j) {
    const size_t expected = j == 2u ? 0u : 1u;
    if (j == 2u) bank.capacity[0] = bank.capacity[1] = 2u;
    attempts = bank.attempts;
    bank.attempted_mask = 0u;
    if (j == 1u) {
      providers[1].rebind = &protocol;
      providers[1].next_user = &providers[0];
      providers[1].rebind_on_full = true;
    }
    VERIFY(cnet_pool_set_selection(&pool, j < 3u ? &first : &least_used) == SALTS_OK);
    VERIFY(cnet_pool_try_acquire(&pool, &key, &protocol, &leases[j], &leased) == SALTS_OK);
    if (j == 1u) {
      VERIFY(bank.attempts == attempts + 2u && bank.attempted_mask == 3u);
      VERIFY(protocol.user == &providers[0] && providers[1].acquired == 1u && providers[0].acquired == 2u);
      protocol.user = &providers[1];
    }
    VERIFY(providers[1].last_index == expected && leased.slot == bank.managed[expected].slot);
    VERIFY(composition_exchange(&client, connections[expected], &probes[expected], peers[expected],
                                providers[1].last_token) == 0);
  }
  attempts = bank.attempts;
  VERIFY(cnet_pool_try_acquire(&pool, &key, &protocol, &rejected, &leased) == SALTS_ENOBUFS);
  VERIFY(bank.attempts == attempts && rejected.slot == 0u && leased.slot == 0u);
  VERIFY(cnet_pool_release(&pool, stale) == SALTS_ENOENT && providers[0].released == 1u);

  VERIFY(cnet_pool_begin_drain(&pool, physical[0]) == SALTS_OK);
  VERIFY(cnet_close(&client, connections[0]) == SALTS_OK);
  VERIFY(poll_until(&client, &probes[0].terminal, 1u) == SALTS_OK);
  VERIFY(cnet_pool_terminal(&pool, physical[0]) == SALTS_OK);
  VERIFY(cnet_pool_get_snapshot(&pool, &snapshot) == SALTS_OK && snapshot.active_leases == 4u &&
         snapshot.terminal_waiting_for_leases == 1u && snapshot.physical_in_use == 2u);
  VERIFY(providers[0].released == 1u && providers[1].released == 0u);
  protocol.user = &providers[0]; /* Live leases must retain provider B's copied binding. */
  VERIFY(cnet_pool_set_selection(&pool, &paused) == SALTS_OK);
  VERIFY(cnet_pool_release(&pool, leases[2]) == SALTS_OK);
  leases[2] = (cnet_pool_lease){0};
  VERIFY(cnet_pool_try_acquire(&pool, &key, &protocol, &rejected, &leased) == SALTS_EBUSY);
  VERIFY(bank.attempts == attempts && rejected.slot == 0u && leased.slot == 0u);
  VERIFY(cnet_pool_release(&pool, leases[0]) == SALTS_OK);
  leases[0] = (cnet_pool_lease){0};
  VERIFY(providers[0].released == 2u && providers[1].released == 1u);
  VERIFY(cnet_pool_get_snapshot(&pool, &snapshot) == SALTS_OK && snapshot.physical_in_use == 1u);
  VERIFY(cnet_pool_release(&pool, leases[1]) == SALTS_OK);
  leases[1] = (cnet_pool_lease){0};
  VERIFY(cnet_pool_set_selection(&pool, &round_robin) == SALTS_OK);
  VERIFY(cnet_pool_try_acquire(&pool, &key, &protocol, &leases[0], &leased) == SALTS_OK);
  VERIFY(providers[0].last_index == 1u && leased.slot == bank.managed[1].slot);
  VERIFY(composition_exchange(&client, connections[1], &probes[1], peers[1], providers[0].last_token) == 0);
  VERIFY(cnet_pool_seal(&pool) == SALTS_OK);
  VERIFY(cnet_pool_try_acquire(&pool, &key, &protocol, &rejected, &leased) == SALTS_ESHUTDOWN);
  VERIFY(cnet_close(&client, connections[1]) == SALTS_OK);
  VERIFY(poll_until(&client, &probes[1].terminal, 1u) == SALTS_OK);
  VERIFY(cnet_pool_terminal(&pool, physical[1]) == SALTS_OK);
  VERIFY(cnet_pool_destroy(&pool) == SALTS_EBUSY);
  for (size_t i = 0u; i < 4u; ++i) {
    if (leases[i].slot == 0u) continue;
    VERIFY(cnet_pool_release(&pool, leases[i]) == SALTS_OK);
    leases[i] = (cnet_pool_lease){0};
  }
  VERIFY(providers[0].acquired == 3u && providers[0].released == 3u &&
         providers[1].acquired == 3u && providers[1].released == 3u && bank.errors == 0u);
  VERIFY(cnet_pool_get_snapshot(&pool, &snapshot) == SALTS_OK && snapshot.drained);
  VERIFY(cnet_pool_destroy(&pool) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    VERIFY(bank.tokens[i][0] == 0u && bank.tokens[i][1] == 0u);
    VERIFY(probes[i].terminal == 1u && probes[i].failed == 0u);
    VERIFY(recv(peers[i], (char *)&byte, 1, 0) == 0);
    VERIFY(cnet_manager_release_context(&manager, bank.managed[i]) == SALTS_OK);
  }
  VERIFY(cnet_manager_advance(&manager, 2u, &work) == SALTS_OK && work == 2u);
  VERIFY(probes[0].recycled == 1u && probes[1].recycled == 1u);
  VERIFY(cnet_manager_destroy(&manager) == SALTS_OK);
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
cleanup:
  test_close_socket(listener);
  for (size_t i = 0u; i < 2u; ++i) test_close_socket(peers[i]);
  if (pool.impl != NULL) {
    if (rejected.slot != 0u) (void)cnet_pool_release(&pool, rejected);
    for (size_t i = 0u; i < 4u; ++i)
      if (leases[i].slot != 0u) (void)cnet_pool_release(&pool, leases[i]);
  }
  if (manager.impl != NULL) {
    (void)cnet_manager_request_close(&manager);
    (void)cnet_manager_advance(&manager, 2u, &work);
  }
  if (client.impl != NULL) (void)cnet_client_stop(&client, 3000u);
  if (pool.impl != NULL) {
    for (size_t i = 0u; i < 2u; ++i)
      if (physical[i].slot != 0u) (void)cnet_pool_terminal(&pool, physical[i]);
    (void)cnet_pool_destroy(&pool);
  }
  if (manager.impl != NULL) {
    for (size_t i = 0u; i < 2u; ++i)
      if (bank.managed[i].slot != 0u) (void)cnet_manager_release_context(&manager, bank.managed[i]);
    (void)cnet_manager_advance(&manager, 2u, &work);
    (void)cnet_manager_destroy(&manager);
  }
  if (client.impl != NULL) (void)cnet_client_destroy(&client);
  return result;
}

typedef struct dial_admission_probe {
  cnet_managed_dial *dial;
  unsigned calls;
  int decision, recursive_seal;
} dial_admission_probe;

static int dial_admit_probe(void *user) {
  dial_admission_probe *probe = user;
  ++probe->calls;
  probe->recursive_seal = cnet_managed_dial_seal(probe->dial);
  return probe->decision;
}

/* Two same-thread clients deliberately have overlapping public handle values.
 * Manager/Dial must use the exact same wrapper, not merely a live client or a
 * matching thread. A gate defers without an attempt; accepted work drains via
 * the original Manager, while the independent native peer remains usable. */
static int saltscore_native_entry_test_cnet_dial_owner(void) {
  cnet_client clients[2] = {{0}, {0}};
  cnet_manager manager = {0};
  cnet_managed_dial dial = {0};
  cnet_client_config config = client_config();
  const cnet_manager_config manager_config = {
      sizeof(cnet_manager_config), CNET_MANAGER_VERSION, &clients[0], 1u, 1u};
  tcp_probe probes[2] = {{0}, {0}};
  resource_probe storage = {0};
  dial_admission_probe admission = {.dial = &dial, .decision = SALTS_ENOBUFS};
  tcp_probe retired_probe = {0};
  cnet_managed_connection retired = {0};
  const cnet_manager_attachment retired_attachment = {
      {on_state, NULL, &retired_probe, NULL}, on_recycled, true};
  cnet_managed_dial_snapshot snapshot = {0};
  cnet_manager_snapshot manager_snapshot = {0};
  cnet_connection neighbor = {0};
  test_socket listener = TEST_INVALID_SOCKET, peers[2] = {TEST_INVALID_SOCKET, TEST_INVALID_SOCKET};
  uint16_t port = 0u;
  unsigned char byte = 0x52u;
  char uri[80];
  uint64_t wait_ms = UINT64_MAX;
  size_t work = 0u;
  int result = 0;
  config.connection_capacity = 1u;
  VERIFY(cnet_client_init(&clients[0], &config) == SALTS_OK);
  VERIFY(cnet_client_init(&clients[1], &config) == SALTS_OK);
  VERIFY(cnet_manager_init(&manager, &manager_config) == SALTS_OK);
  listener = test_native_listener(&port);
  VERIFY(listener != TEST_INVALID_SOCKET && port != 0u);
  VERIFY(snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", (unsigned)port) > 0);
  const cnet_connect_options neighbor_options = {
      .uri = uri, .observer = {on_state, on_borrowed, &probes[1], on_sent}};
  VERIFY(cnet_connect(&clients[1], &neighbor_options, &neighbor) == SALTS_OK);
  VERIFY(poll_until(&clients[1], &probes[1].connected, 1u) == SALTS_OK);
  peers[1] = accept(listener, NULL, NULL);
  VERIFY(peers[1] != TEST_INVALID_SOCKET && test_recv_timeout(peers[1]) == 0);

  cnet_managed_dial_config dial_config = {
      .size = sizeof(cnet_managed_dial_config), .version = CNET_MANAGED_DIAL_VERSION,
      .manager = &manager, .client = &clients[1],
      .connection = {.uri = uri, .observer = {on_state, on_borrowed, &probes[0], on_sent}},
      .recovery = {.size = sizeof(cnet_reconnect_config), .version = CNET_RECOVERY_POLICY_VERSION,
          .max_attempts = 2u, .deadline_ms = cmeta_monotonic_ms() + 5000u,
          .initial_backoff_ms = 1u, .maximum_backoff_ms = 8u, .jitter_seed = 7u},
      .recovery_episode_ms = 5000u,
      .storage = {probe_allocate, probe_deallocate, &storage}};
  VERIFY(cnet_managed_dial_init(&dial, &dial_config) == SALTS_EINVAL);
  VERIFY(dial.impl == NULL && storage.allocated == 0u && storage.released == 0u);
  VERIFY(cnet_managed_dial_init_admitted(&dial, &dial_config, dial_admit_probe, &admission) == SALTS_EINVAL);
  VERIFY(dial.impl == NULL && storage.allocated == 0u && admission.calls == 0u);
  VERIFY(cnet_manager_get_snapshot(&manager, &manager_snapshot) == SALTS_OK && manager_snapshot.drained);
  VERIFY(composition_exchange(&clients[1], neighbor, &probes[1], peers[1], 1u) == 0);

  dial_config.client = &clients[0];
  VERIFY(cnet_managed_dial_init_admitted(&dial, &dial_config, dial_admit_probe, &admission) == SALTS_OK);
  /* Connection credits return on cancel, but the sole record remains borrowed
   * through context release and a later bounded Manager advance. Neither phase
   * may invoke admission or consume/seal the Dial's recovery episode. */
  VERIFY(cnet_manager_reserve(&manager, &retired_attachment, &retired) == SALTS_OK);
  VERIFY(cnet_manager_cancel(&manager, retired) == SALTS_OK);
  VERIFY(cnet_manager_get_snapshot(&manager, &manager_snapshot) == SALTS_OK &&
         manager_snapshot.reserved == 0u && manager_snapshot.bound == 0u &&
         manager_snapshot.retired == 1u && manager_snapshot.context_holds == 1u);
  admission.decision = SALTS_OK;
  VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_ENOBUFS);
  VERIFY(wait_ms == 0u && admission.calls == 0u);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK &&
         snapshot.recovery.attempts == 0u && snapshot.recovery.generation == 0u &&
         !snapshot.recovery.sealed && snapshot.managed.slot == 0u);
  VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK && work == 0u);
  VERIFY(retired_probe.recycled == 0u);
  VERIFY(cnet_manager_release_context(&manager, retired) == SALTS_OK);
  VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_ENOBUFS);
  VERIFY(wait_ms == 0u && admission.calls == 0u);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK &&
         snapshot.recovery.attempts == 0u && snapshot.recovery.generation == 0u &&
         !snapshot.recovery.sealed && snapshot.managed.slot == 0u);
  VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK && work == 1u);
  VERIFY(retired_probe.recycled == 1u);
  retired = (cnet_managed_connection){0};
  admission.decision = SALTS_ENOBUFS;
  VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_ENOBUFS);
  VERIFY(wait_ms == 0u && admission.calls == 1u && admission.recursive_seal == SALTS_EBUSY);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK &&
         snapshot.recovery.attempts == 0u && snapshot.managed.slot == 0u &&
         snapshot.connection.slot == 0u && !snapshot.stopping);
  admission.decision = SALTS_OK;
  VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_OK);
  VERIFY(admission.calls == 2u && admission.recursive_seal == SALTS_EBUSY);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK && snapshot.recovery.attempts == 1u);
  VERIFY(cnet_managed_dial_protocol_ready(&dial, snapshot.recovery_ticket, cmeta_monotonic_ms()) == SALTS_EBUSY);
  VERIFY(poll_until(&clients[0], &probes[0].connected, 1u) == SALTS_OK);
  peers[0] = accept(listener, NULL, NULL);
  VERIFY(peers[0] != TEST_INVALID_SOCKET && test_recv_timeout(peers[0]) == 0);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK &&
         snapshot.recovery.awaiting_protocol && !snapshot.recovery.protocol_ready);
  VERIFY(snapshot.connection.slot == neighbor.slot && snapshot.connection.generation == neighbor.generation);
  VERIFY(cnet_receive(&clients[0], snapshot.connection, 1u) == SALTS_OK);
  VERIFY(send(peers[0], (const char *)&byte, 1, 0) == 1);
  VERIFY(poll_until(&clients[0], &probes[0].borrowed_bytes, 1u) == SALTS_OK && probes[0].borrowed_data[0] == byte);
  VERIFY(cnet_managed_dial_protocol_ready(&dial, snapshot.recovery_ticket, cmeta_monotonic_ms()) == SALTS_OK);
  VERIFY(composition_exchange(&clients[0], snapshot.connection, &probes[0], peers[0], 2u) == 0);
  VERIFY(cnet_managed_dial_seal(&dial) == SALTS_OK);
  VERIFY(cnet_managed_dial_seal(&dial) == SALTS_OK);
  VERIFY(cnet_managed_dial_destroy(&dial) == SALTS_EBUSY);
  VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_ESHUTDOWN && wait_ms == 0u);
  VERIFY(poll_until(&clients[0], &probes[0].terminal, 1u) == SALTS_OK);
  VERIFY(probes[0].terminal == 1u && probes[0].failed == 0u && probes[1].terminal == 0u);
  VERIFY(recv(peers[0], (char *)&byte, 1, 0) == 0);
  VERIFY(cnet_managed_dial_destroy(&dial) == SALTS_EBUSY);
  VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK && work == 1u);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK &&
         snapshot.stopping && snapshot.recovery.sealed && snapshot.managed.slot == 0u && snapshot.connection.slot == 0u);
  VERIFY(cnet_managed_dial_destroy(&dial) == SALTS_OK);
  VERIFY(storage.allocated == 2u && storage.released == 2u);
  VERIFY(cnet_manager_destroy(&manager) == SALTS_OK);
  VERIFY(cnet_client_stop(&clients[0], 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&clients[0]) == SALTS_OK);
  VERIFY(composition_exchange(&clients[1], neighbor, &probes[1], peers[1], 3u) == 0);
  VERIFY(cnet_close(&clients[1], neighbor) == SALTS_OK);
  VERIFY(poll_until(&clients[1], &probes[1].terminal, 1u) == SALTS_OK);
  VERIFY(probes[1].terminal == 1u && probes[1].failed == 0u && recv(peers[1], (char *)&byte, 1, 0) == 0);
  VERIFY(cnet_client_stop(&clients[1], 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&clients[1]) == SALTS_OK);
cleanup:
  test_close_socket(listener);
  for (size_t i = 0u; i < 2u; ++i) test_close_socket(peers[i]);
  if (dial.impl != NULL) (void)cnet_managed_dial_seal(&dial);
  if (manager.impl != NULL) {
    if (retired.slot != 0u) (void)cnet_manager_release_context(&manager, retired);
    (void)cnet_manager_request_close(&manager);
    (void)cnet_manager_advance(&manager, 1u, &work);
  }
  for (size_t i = 0u; i < 2u; ++i)
    if (clients[i].impl != NULL) (void)cnet_client_stop(&clients[i], 3000u);
  if (manager.impl != NULL) (void)cnet_manager_advance(&manager, 1u, &work);
  if (dial.impl != NULL) (void)cnet_managed_dial_destroy(&dial);
  if (manager.impl != NULL) (void)cnet_manager_destroy(&manager);
  for (size_t i = 0u; i < 2u; ++i)
    if (clients[i].impl != NULL) (void)cnet_client_destroy(&clients[i]);
  return result;
}

typedef struct dial_recovery_probe {
  cnet_managed_dial *dial;
  cnet_reconnect_failure_kind decision;
  unsigned calls;
  int recursive_advance, recursive_seal;
} dial_recovery_probe;

static cnet_reconnect_failure_kind dial_classify_probe(
    void *user, cnet_connection_state state, const cnet_error *error) {
  dial_recovery_probe *probe = user;
  uint64_t wait = 0u;
  (void)state;
  (void)error;
  ++probe->calls;
  probe->recursive_advance = cnet_managed_dial_advance(probe->dial, cmeta_monotonic_ms(), &wait);
  probe->recursive_seal = cnet_managed_dial_seal(probe->dial);
  return probe->decision;
}

/* Three real TCP incarnations: pre-READY loss, READY loss, security stop.
 * Only explicit protocol readiness resets attempts; every replacement waits
 * for terminal and Manager recycle, and stale identities never gain authority. */
static int saltscore_native_entry_test_cnet_dial_recovery(void) {
  cnet_client client = {0};
  cnet_manager manager = {0};
  cnet_managed_dial dial = {0};
  cnet_client_config config = client_config();
  const cnet_manager_config manager_config = {
      sizeof(cnet_manager_config), CNET_MANAGER_VERSION, &client, 1u, 1u};
  tcp_probe probe = {0};
  dial_recovery_probe classifier = {.dial = &dial, .decision = CNET_RECONNECT_TRANSIENT};
  cnet_managed_dial_snapshot snapshot = {0};
  cnet_reconnect_ticket old_ticket = {0};
  cnet_connection old_connection = {0};
  cnet_manager_entry entry = {0};
  test_socket listener = TEST_INVALID_SOCKET, peer = TEST_INVALID_SOCKET;
  uint16_t port = 0u;
  char uri[80];
  uint64_t wait_ms = UINT64_MAX, initial_deadline = cmeta_monotonic_ms() + 5000u;
  size_t work = 0u;
  int result = 0;
  config.connection_capacity = 1u;
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  VERIFY(cnet_manager_init(&manager, &manager_config) == SALTS_OK);
  listener = test_native_listener(&port);
  VERIFY(listener != TEST_INVALID_SOCKET && port != 0u);
  VERIFY(snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", (unsigned)port) > 0);
  const cnet_managed_dial_config dial_config = {
      .size = sizeof(cnet_managed_dial_config), .version = CNET_MANAGED_DIAL_VERSION,
      .manager = &manager, .client = &client,
      .connection = {.uri = uri, .observer = {on_state, on_borrowed, &probe, on_sent}},
      .recovery = {.size = sizeof(cnet_reconnect_config), .version = CNET_RECOVERY_POLICY_VERSION,
          .max_attempts = 2u, .deadline_ms = initial_deadline,
          .backoff = {cnet_backoff_fixed, NULL}},
      .recovery_episode_ms = 10000u, .classify = dial_classify_probe, .classify_user = &classifier};
  VERIFY(cnet_managed_dial_init(&dial, &dial_config) == SALTS_OK);
  for (unsigned round = 0u; round < 3u; ++round) {
    const unsigned char greeting = (unsigned char)(0x61u + round);
    VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_OK);
    VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK &&
           snapshot.recovery.in_flight && snapshot.recovery.attempts == (round == 1u ? 2u : 1u));
    if (round != 0u) {
      VERIFY(snapshot.connection.slot == old_connection.slot && snapshot.connection.generation > old_connection.generation);
      VERIFY(snapshot.recovery_ticket.generation > old_ticket.generation);
      VERIFY(cnet_managed_dial_protocol_ready(&dial, old_ticket, cmeta_monotonic_ms()) == SALTS_ENOENT);
      VERIFY(cnet_receive(&client, old_connection, 1u) == SALTS_ENOENT);
    }
    VERIFY(poll_until(&client, &probe.connected, round + 1u) == SALTS_OK);
    peer = accept(listener, NULL, NULL);
    VERIFY(peer != TEST_INVALID_SOCKET && test_recv_timeout(peer) == 0);
    VERIFY(cnet_receive(&client, snapshot.connection, 1u) == SALTS_OK);
    VERIFY(send(peer, (const char *)&greeting, 1, 0) == 1);
    const unsigned target = probe.borrowed_bytes + 1u;
    VERIFY(poll_until(&client, &probe.borrowed_bytes, target) == SALTS_OK && probe.borrowed_data[target - 1u] == greeting);
    VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK && snapshot.recovery.awaiting_protocol);
    if (round == 1u) {
      VERIFY(cnet_managed_dial_protocol_ready(&dial, snapshot.recovery_ticket, cmeta_monotonic_ms()) == SALTS_OK);
      VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK &&
             snapshot.recovery.protocol_ready && snapshot.recovery.attempts == 0u);
      VERIFY(composition_exchange(&client, snapshot.connection, &probe, peer, 2u) == 0);
    }
    if (round == 2u) classifier.decision = CNET_RECONNECT_SECURITY;
    old_ticket = snapshot.recovery_ticket;
    old_connection = snapshot.connection;
    VERIFY(cnet_receive(&client, snapshot.connection, 1u) == SALTS_OK);
    test_close_socket(peer);
    peer = TEST_INVALID_SOCKET;
    VERIFY(poll_until(&client, &probe.terminal, round + 1u) == SALTS_OK);
    VERIFY(probe.failed == 0u && classifier.calls == round + 1u &&
           classifier.recursive_advance == SALTS_EBUSY && classifier.recursive_seal == SALTS_EBUSY);
    VERIFY(cnet_manager_lookup(&manager, snapshot.managed, &entry) == SALTS_OK && entry.state == CNET_MANAGER_RETIRED);
    VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_EBUSY && wait_ms == 0u);
    VERIFY(cnet_managed_dial_destroy(&dial) == SALTS_EBUSY);
    VERIFY(cnet_managed_dial_get_snapshot(&dial, &snapshot) == SALTS_OK &&
           !snapshot.recovery.in_flight && !snapshot.recovery.awaiting_protocol && !snapshot.recovery.protocol_ready &&
           snapshot.recovery.sealed == (round == 2u));
    if (round == 0u) VERIFY(snapshot.recovery.deadline_ms == initial_deadline && snapshot.recovery.attempts == 1u);
    else VERIFY(snapshot.recovery.deadline_ms > initial_deadline && snapshot.recovery.attempts == (round == 1u ? 0u : 1u));
    VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK && work == 1u);
    VERIFY(cnet_managed_dial_protocol_ready(&dial, old_ticket, cmeta_monotonic_ms()) == SALTS_ENOENT);
  }
  VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_ESHUTDOWN && wait_ms == 0u);
  VERIFY(cnet_managed_dial_seal(&dial) == SALTS_OK);
  VERIFY(cnet_managed_dial_destroy(&dial) == SALTS_OK);
  VERIFY(cnet_manager_destroy(&manager) == SALTS_OK);
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
cleanup:
  test_close_socket(peer);
  test_close_socket(listener);
  if (dial.impl != NULL) (void)cnet_managed_dial_seal(&dial);
  if (manager.impl != NULL) {
    (void)cnet_manager_request_close(&manager);
    (void)cnet_manager_advance(&manager, 1u, &work);
  }
  if (client.impl != NULL) (void)cnet_client_stop(&client, 3000u);
  if (manager.impl != NULL) (void)cnet_manager_advance(&manager, 1u, &work);
  if (dial.impl != NULL) (void)cnet_managed_dial_destroy(&dial);
  if (manager.impl != NULL) (void)cnet_manager_destroy(&manager);
  if (client.impl != NULL) (void)cnet_client_destroy(&client);
  return result;
}

/* Protocol authority cannot revive a transport whose close has already been
 * admitted, even before the Manager receives its terminal notification. */
static int saltscore_native_entry_test_cnet_dial_ready(unsigned close_mode) {
  cnet_client client = {0};
  cnet_manager manager = {0};
  cnet_managed_dial dial = {0};
  cnet_client_config config = client_config();
  const cnet_manager_config manager_config = {
      sizeof(cnet_manager_config), CNET_MANAGER_VERSION, &client, 1u, 1u};
  tcp_probe probe = {0};
  cnet_managed_dial_snapshot before = {0}, after = {0};
  cnet_manager_entry entry = {0};
  test_socket listener = TEST_INVALID_SOCKET, peer = TEST_INVALID_SOCKET;
  mem_buffer_t *final = NULL;
  uint16_t port = 0u;
  unsigned char byte = 0x6au;
  char uri[80];
  uint64_t wait_ms = UINT64_MAX;
  size_t work = 0u;
  int result = 0;
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  VERIFY(cnet_manager_init(&manager, &manager_config) == SALTS_OK);
  listener = test_native_listener(&port);
  VERIFY(listener != TEST_INVALID_SOCKET && port != 0u);
  VERIFY(snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", (unsigned)port) > 0);
  const cnet_managed_dial_config dial_config = {
      .size = sizeof(cnet_managed_dial_config), .version = CNET_MANAGED_DIAL_VERSION,
      .manager = &manager, .client = &client,
      .connection = {.uri = uri, .observer = {on_state, on_borrowed, &probe, on_sent}},
      .recovery = {.size = sizeof(cnet_reconnect_config), .version = CNET_RECOVERY_POLICY_VERSION,
          .max_attempts = 2u, .deadline_ms = cmeta_monotonic_ms() + 5000u,
          .initial_backoff_ms = 1u, .maximum_backoff_ms = 8u},
      .recovery_episode_ms = 5000u};
  VERIFY(cnet_managed_dial_init(&dial, &dial_config) == SALTS_OK);
  VERIFY(cnet_managed_dial_advance(&dial, cmeta_monotonic_ms(), &wait_ms) == SALTS_OK);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &before) == SALTS_OK);
  VERIFY(cnet_managed_dial_protocol_ready(&dial, before.recovery_ticket, cmeta_monotonic_ms()) == SALTS_EBUSY);
  VERIFY(poll_until(&client, &probe.connected, 1u) == SALTS_OK);
  peer = accept(listener, NULL, NULL);
  VERIFY(peer != TEST_INVALID_SOCKET && test_recv_timeout(peer) == 0);
  VERIFY(cnet_receive(&client, before.connection, 1u) == SALTS_OK);
  VERIFY(send(peer, (const char *)&byte, 1, 0) == 1);
  VERIFY(poll_until(&client, &probe.borrowed_bytes, 1u) == SALTS_OK && probe.borrowed_data[0] == byte);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &before) == SALTS_OK &&
         before.recovery.awaiting_protocol && before.recovery.attempts == 1u);
  if (close_mode == 0u) {
    VERIFY(cnet_managed_dial_protocol_ready(&dial, before.recovery_ticket, cmeta_monotonic_ms()) == SALTS_OK);
    VERIFY(cnet_managed_dial_get_snapshot(&dial, &after) == SALTS_OK &&
           after.recovery.protocol_ready && after.recovery.attempts == 0u);
    VERIFY(cnet_managed_dial_protocol_ready(&dial, before.recovery_ticket, cmeta_monotonic_ms()) == SALTS_EALREADY);
    VERIFY(composition_exchange(&client, before.connection, &probe, peer, 3u) == 0);
    VERIFY(cnet_close(&client, before.connection) == SALTS_OK);
  } else {
    if (close_mode == 1u) VERIFY(cnet_close(&client, before.connection) == SALTS_OK);
    else if (close_mode == 2u) {
      final = mem_get_buffer(mem_global(), 1u);
      VERIFY(final != NULL);
      *mem_buffer_data(final) = 0xf2u;
      mem_set_used(final, 1u);
      VERIFY(cnet_send_buffer_and_close(&client, before.connection, final) == SALTS_OK);
      mem_buffer_release(final);
      final = NULL;
    } else if (close_mode == 3u) VERIFY(cnet_manager_request_close(&manager) == SALTS_OK);
    else VERIFY(cnet_connection_shutdown(&client, before.connection, CNET_TCP_SHUTDOWN_SEND) == SALTS_OK);
    VERIFY(probe.terminal == 0u);
    VERIFY(cnet_manager_lookup(&manager, before.managed, &entry) == SALTS_OK && entry.state == CNET_MANAGER_BOUND);
    VERIFY(cnet_managed_dial_protocol_ready(&dial, before.recovery_ticket, cmeta_monotonic_ms()) == SALTS_ESHUTDOWN);
    VERIFY(cnet_managed_dial_get_snapshot(&dial, &after) == SALTS_OK &&
           after.recovery.awaiting_protocol && !after.recovery.protocol_ready &&
           after.recovery.attempts == 1u && !after.recovery.sealed &&
           after.recovery.generation == before.recovery.generation &&
           after.recovery.deadline_ms == before.recovery.deadline_ms);
    if (close_mode == 3u) VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK && work == 1u);
    if (close_mode == 4u) VERIFY(cnet_close(&client, before.connection) == SALTS_OK);
  }
  VERIFY(poll_until(&client, &probe.terminal, 1u) == SALTS_OK);
  VERIFY(probe.terminal == 1u && probe.failed == 0u);
  if (close_mode == 2u) VERIFY(recv(peer, (char *)&byte, 1, 0) == 1 && byte == 0xf2u && probe.sent == 1u);
  VERIFY(recv(peer, (char *)&byte, 1, 0) == 0);
  VERIFY(cnet_managed_dial_get_snapshot(&dial, &after) == SALTS_OK && after.recovery.sealed && !after.recovery.protocol_ready);
  if (close_mode != 0u) VERIFY(after.recovery.attempts == 1u && after.recovery.deadline_ms == before.recovery.deadline_ms);
  VERIFY(cnet_managed_dial_seal(&dial) == SALTS_OK);
  VERIFY(cnet_managed_dial_destroy(&dial) == SALTS_EBUSY);
  VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK && work == 1u);
  VERIFY(cnet_managed_dial_destroy(&dial) == SALTS_OK);
  VERIFY(cnet_manager_destroy(&manager) == SALTS_OK);
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
cleanup:
  if (final != NULL) mem_buffer_release(final);
  test_close_socket(peer);
  test_close_socket(listener);
  if (dial.impl != NULL) (void)cnet_managed_dial_seal(&dial);
  if (manager.impl != NULL) {
    (void)cnet_manager_request_close(&manager);
    (void)cnet_manager_advance(&manager, 1u, &work);
  }
  if (client.impl != NULL) (void)cnet_client_stop(&client, 3000u);
  if (manager.impl != NULL) (void)cnet_manager_advance(&manager, 1u, &work);
  if (dial.impl != NULL) (void)cnet_managed_dial_destroy(&dial);
  if (manager.impl != NULL) (void)cnet_manager_destroy(&manager);
  if (client.impl != NULL) (void)cnet_client_destroy(&client);
  return result;
}

/* Saturate the production retained-write admission bound before progressing
 * NativeIO. This is queue-capacity backpressure, not a forced partial kernel
 * write. A rejected FINAL must not retain backing or seal send/receive admission.
 * After real terminals return credits, retry that same immutable final buffer.
 * Repeat on the only connection slot to exercise stale public generations. */
static int saltscore_native_entry_test_cnet_send_backpressure(void) {
  cnet_client client = {0};
  cnet_listener listener = {0};
  cnet_client_config config = client_config();
  const cnet_listener_config listener_config = {
      backend_kind(), "127.0.0.1", 0u, 2u};
  tcp_probe probe = {0};
  const cnet_observer observer = {on_state, on_borrowed, &probe, on_sent};
  cnet_connection connection = {0}, stale_connection = {0};
  test_socket peer = TEST_INVALID_SOCKET;
  struct sockaddr_in remote = {0};
  mem_buffer_t *pending = NULL, *late = NULL;
  uint16_t port = 0u;
  int client_live = 0, listener_live = 0;
  int ready = 0, result = 0;

  config.connection_capacity = 1u;
  config.command_capacity = 2u; /* Also the retained write-slot capacity. */
  VERIFY(cnet_listener_init(&listener, &listener_config) == SALTS_OK);
  listener_live = 1;
  VERIFY(cnet_listener_port(&listener, &port) == SALTS_OK && port != 0u);
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  client_live = 1;
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  remote.sin_port = htons(port);

  for (unsigned round = 0u; round < 2u; ++round) {
    const unsigned char expected[] = {
        'A', (unsigned char)('0' + round), 'B', 'b', '2', 'F', 'I', 'N', '!'};
    unsigned char received[sizeof(expected)] = {0};
    unsigned char incoming = (unsigned char)(0x70u + round);
    size_t events = 0u;
    probe = (tcp_probe){0};
    peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    VERIFY(peer != TEST_INVALID_SOCKET);
    VERIFY(test_recv_timeout(peer) == 0);
    VERIFY(connect(peer, (const struct sockaddr *)&remote, (int)sizeof(remote)) == 0);
    VERIFY(cnet_listener_wait(&listener, 5000u, &ready) == SALTS_OK && ready == 1);
    VERIFY(cnet_listener_accept(&listener, &client, &observer, &connection) == SALTS_OK);
    VERIFY(poll_until(&client, &probe.connected, 1u) == SALTS_OK);
    VERIFY(probe.connected == 1u && probe.terminal == 0u && probe.failed == 0u);
    if (round != 0u)
      VERIFY(connection.slot == stale_connection.slot &&
             connection.generation != stale_connection.generation);

    for (size_t write = 0u; write < 2u; ++write) {
      const size_t bytes = write == 0u ? 2u : 3u;
      const size_t offset = write == 0u ? 0u : 2u;
      pending = mem_get_buffer(mem_global(), bytes);
      VERIFY(pending != NULL);
      memcpy(mem_buffer_data(pending), expected + offset, bytes);
      mem_set_used(pending, bytes);
      if (round != 0u) {
        VERIFY(cnet_send_buffer(&client, stale_connection, pending) == SALTS_ENOENT);
        VERIFY(mem_buffer_ref_count(pending) == 1u);
      }
      VERIFY(cnet_send_buffer(&client, connection, pending) == SALTS_OK);
      VERIFY(mem_buffer_ref_count(pending) == 2u);
      mem_buffer_release(pending);
      pending = NULL;
    }
    VERIFY(probe.sent == 0u); /* Admission is not a NativeIO send terminal. */
    pending = mem_get_buffer(mem_global(), 4u);
    VERIFY(pending != NULL);
    memcpy(mem_buffer_data(pending), expected + 5u, 4u);
    mem_set_used(pending, 4u);
    VERIFY(cnet_send_buffer(&client, connection, pending) == SALTS_ENOBUFS);
    VERIFY(mem_buffer_ref_count(pending) == 1u);
    VERIFY(cnet_send_buffer_and_close(&client, connection, pending) == SALTS_ENOBUFS);
    VERIFY(mem_buffer_ref_count(pending) == 1u);
    VERIFY(probe.sent == 0u && probe.terminal == 0u && probe.failed == 0u);

    /* Rejected FINAL leaves the connection open, including receive admission. */
    VERIFY(cnet_receive(&client, connection, 1u) == SALTS_OK);
    VERIFY(send(peer, (const char *)&incoming, 1, 0) == 1);
    VERIFY(poll_until(&client, &probe.sent, 2u) == SALTS_OK);
    VERIFY(poll_until(&client, &probe.borrowed_bytes, 1u) == SALTS_OK);
    VERIFY(probe.sent == 2u && probe.send_sizes[0] == 2u && probe.send_sizes[1] == 3u);
    VERIFY(probe.borrowed_bytes == 1u && probe.borrowed_data[0] == incoming);
    VERIFY(probe.failed == 0u && probe.terminal == 0u);
    VERIFY(test_recv_exact(peer, received, 5u) == 0);
    VERIFY(memcmp(received, expected, 5u) == 0);

    VERIFY(cnet_send_buffer_and_close(&client, connection, pending) == SALTS_OK);
    VERIFY(mem_buffer_ref_count(pending) == 2u);
    mem_buffer_release(pending);
    pending = NULL;
    late = mem_get_buffer(mem_global(), 1u);
    VERIFY(late != NULL);
    *mem_buffer_data(late) = 0xee;
    mem_set_used(late, 1u);
    VERIFY(cnet_send_buffer(&client, connection, late) == SALTS_EBUSY);
    VERIFY(mem_buffer_ref_count(late) == 1u);
    VERIFY(cnet_receive(&client, connection, 1u) == SALTS_EBUSY);
    VERIFY(poll_until(&client, &probe.terminal, 1u) == SALTS_OK);
    VERIFY(probe.sent == 3u && probe.send_sizes[2] == 4u &&
           probe.terminal == 1u && probe.failed == 0u);
    VERIFY(test_recv_exact(peer, received + 5u, 4u) == 0);
    VERIFY(memcmp(received, expected, sizeof(expected)) == 0);
    VERIFY(recv(peer, (char *)&incoming, 1, 0) == 0);
    VERIFY(cnet_send_buffer(&client, connection, late) == SALTS_ENOENT);
    VERIFY(mem_buffer_ref_count(late) == 1u);
    mem_buffer_release(late);
    late = NULL;
    VERIFY(cnet_client_poll(&client, 0u, &events) == SALTS_OK);
    VERIFY(probe.connected == 1u && probe.sent == 3u &&
           probe.terminal == 1u && probe.failed == 0u);
    stale_connection = connection;
    test_close_socket(peer);
    peer = TEST_INVALID_SOCKET;
  }
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  client_live = 0;
  VERIFY(cnet_listener_close(&listener) == SALTS_OK);
  VERIFY(cnet_listener_destroy(&listener) == SALTS_OK);
  listener_live = 0;

cleanup:
  if (pending) mem_buffer_release(pending);
  if (late) mem_buffer_release(late);
  test_close_socket(peer);
  if (client_live) {
    (void)cnet_client_stop(&client, 3000u);
    (void)cnet_client_destroy(&client);
  }
  if (listener_live) {
    (void)cnet_listener_close(&listener);
    (void)cnet_listener_destroy(&listener);
  }
  return result;
}

static int observe_external_one(native_io_backend *backend, native_io_completion *completion) {
  const uint64_t deadline = cmeta_monotonic_ms() + 5000u;
  while (cmeta_monotonic_ms() < deadline) {
    size_t count = 0u;
    const int status = native_io_backend_observe(backend, completion, 1u, 10u, &count);
    if (status == SALTS_OK && count == 1u) return SALTS_OK;
    if (status != SALTS_OK && status != SALTS_ETIMEDOUT) return status;
  }
  return SALTS_ETIMEDOUT;
}

/* The host is the only NativeIO observer. An observed completion ends the
 * native borrow, but CNet still retains its request/backing until routing.
 * Round 0 holds a real successful send terminal across close/cancel; round 1
 * cancels a genuinely pending receive, then holds that cancellation terminal.
 * The separate prefix case holds one real native vector terminal for a still
 * incomplete logical write. Close must discard its unsent ranges after routing.
 * No path may destroy early, publish twice, or close the borrowed backend. */
static int saltscore_native_entry_test_cnet_external_cancel_drain(bool prefix_only) {
  enum { PREFIX_SEGMENTS = NATIVE_IO_VECTOR_MAX + 1u, PREFIX_SEGMENT_BYTES = 512u,
         PREFIX_STRIDE = PREFIX_SEGMENT_BYTES + 3u,
         PREFIX_BYTES = PREFIX_SEGMENTS * PREFIX_SEGMENT_BYTES };
  cnet_client client = {0};
  cnet_listener listener = {0};
  native_io_backend backend = {0};
  cnet_client_config config = client_config();
  const native_io_backend_config backend_config = {backend_kind(), 2u, 4u, 4u};
  const cnet_listener_config listener_config = {backend_kind(), "127.0.0.1", 0u, 2u};
  tcp_probe probe = {0};
  const cnet_observer observer = {on_state, on_borrowed, &probe, on_sent};
  cnet_connection connection = {0}, previous = {0};
  cnet_external_request_snapshot requests[4] = {{0}};
  native_io_completion held = {0}, stale = {0};
  native_io_backend_stats stats = {0};
  mem_buffer_t *pending = NULL;
  mem_slice_t ranges[PREFIX_SEGMENTS] = {{0}};
  size_t range_count = 0u;
  unsigned char prefix_received[PREFIX_BYTES];
  test_socket peer = TEST_INVALID_SOCKET;
  struct sockaddr_in remote = {0};
  const unsigned char expected[] = {0x31u, 0x72u, 0xa4u, 0xffu};
  unsigned char received[sizeof(expected)] = {0};
  uint16_t port = 0u;
  size_t events = 0u, count = 0u;
  uint64_t submitted_before_route = 0u;
  cnet_operation operation = {0};
  bool consumed = false, held_live = false;
  int client_live = 0, listener_live = 0, backend_live = 0;
  int ready = 0, result = 0;

  config.connection_capacity = 1u;
  if (prefix_only) config.max_send_bytes = PREFIX_BYTES;
  VERIFY(cnet_listener_init(&listener, &listener_config) == SALTS_OK);
  listener_live = 1;
  VERIFY(cnet_listener_port(&listener, &port) == SALTS_OK && port != 0u);
  VERIFY(native_io_backend_init(&backend, &backend_config) == SALTS_OK);
  backend_live = 1;
  VERIFY(cnet_client_init_external(&client, &config, &backend) == SALTS_OK);
  client_live = 1;
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  remote.sin_port = htons(port);

  for (unsigned round = prefix_only ? 2u : 0u; round < (prefix_only ? 3u : 2u); ++round) {
    probe = (tcp_probe){0};
    peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    VERIFY(peer != TEST_INVALID_SOCKET);
    VERIFY(test_recv_timeout(peer) == 0);
    VERIFY(connect(peer, (const struct sockaddr *)&remote, (int)sizeof(remote)) == 0);
    VERIFY(cnet_listener_wait(&listener, 5000u, &ready) == SALTS_OK && ready == 1);
    VERIFY(cnet_listener_accept(&listener, &client, &observer, &connection) == SALTS_OK);
    VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
    VERIFY(probe.connected == 1u && probe.terminal == 0u && probe.failed == 0u);
    if (round == 0u) {
      pending = mem_get_buffer(mem_global(), sizeof(expected));
      VERIFY(pending != NULL);
      memcpy(mem_buffer_data(pending), expected, sizeof(expected));
      mem_set_used(pending, sizeof(expected));
      VERIFY(cnet_send_buffer(&client, connection, pending) == SALTS_OK);
      VERIFY(mem_buffer_ref_count(pending) == 2u);
    } else if (round == 1u) {
      VERIFY(connection.slot == previous.slot && connection.generation != previous.generation);
      VERIFY(cnet_receive(&client, connection, 1u) == SALTS_OK);
    } else {
      /* More nonadjacent ranges than one native vector can hold force a real
       * prefix completion even when IOCP buffers each submitted write in full.
       * No kernel short write or injected completion is needed for this race. */
      VERIFY(PREFIX_SEGMENTS <= CNET_RETAINED_VECTOR_MAX);
      pending = mem_get_buffer(mem_global(), PREFIX_SEGMENTS * PREFIX_STRIDE);
      VERIFY(pending != NULL);
      mem_set_used(pending, PREFIX_SEGMENTS * PREFIX_STRIDE);
      for (size_t i = 0u; i < PREFIX_SEGMENTS; ++i) {
        for (size_t j = 0u; j < PREFIX_SEGMENT_BYTES; ++j)
          mem_buffer_data(pending)[i * PREFIX_STRIDE + j] =
              (char)(((i * PREFIX_SEGMENT_BYTES + j) * 29u + 3u) & 0xffu);
        ranges[i] = mem_slice(pending, i * PREFIX_STRIDE, PREFIX_SEGMENT_BYTES);
        VERIFY(ranges[i].buffer == pending && ranges[i].length == PREFIX_SEGMENT_BYTES);
        ++range_count;
      }
      const cnet_send_options options = {ranges, range_count, false, on_operation, &probe};
      VERIFY(cnet_send(&client, connection, &options, &operation, NULL) == SALTS_OK);
      VERIFY(operation.id != 0u && probe.completed == 0u);
      for (size_t i = 0u; i < range_count; ++i) mem_slice_release(&ranges[i]);
      range_count = 0u;
      VERIFY(mem_buffer_ref_count(pending) == 2u);
    }
    VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
    VERIFY(cnet_client_external_request_snapshots(&client, connection,
                                                  requests, 4u, &count) == SALTS_OK);
    VERIFY(count == 1u && requests[0].operation_kind ==
           (round == 1u ? NATIVE_IO_OPERATION_STREAM_RECV : NATIVE_IO_OPERATION_STREAM_SEND));
    if (round != 1u) {
      VERIFY(observe_external_one(&backend, &held) == SALTS_OK);
      held_live = true;
      VERIFY(held.kind == NATIVE_IO_COMPLETION_OK && held.status == SALTS_OK &&
             (round == 0u ? held.bytes == sizeof(expected) : held.bytes > 0u && held.bytes < PREFIX_BYTES));
      VERIFY(held.request.slot == requests[0].request.slot &&
             held.request.generation == requests[0].request.generation);
      VERIFY(native_io_backend_get_stats(&backend, &stats));
      VERIFY(stats.active_requests == 0u);
      VERIFY(mem_buffer_ref_count(pending) == 2u && probe.sent == 0u);
    } else {
      /* Replay a real old completion while the reused connection has a live
       * native read. Both request and connection generations must stay intact. */
      VERIFY(cnet_client_route_external_completion(&client, &stale, &consumed, &events) == SALTS_OK);
      VERIFY(!consumed && probe.sent == 0u && probe.terminal == 0u);
      VERIFY(native_io_backend_get_stats(&backend, &stats));
      VERIFY(stats.active_requests == 1u);
    }

    VERIFY(cnet_close(&client, connection) == SALTS_OK);
    VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
    VERIFY(probe.terminal == 0u && probe.sent == 0u && probe.failed == 0u);
    VERIFY(cnet_client_stop_external(&client) == SALTS_EBUSY);
    VERIFY(cnet_client_destroy(&client) == SALTS_EBUSY);
    if (round != 1u) {
      VERIFY(mem_buffer_ref_count(pending) == 2u);
    } else {
      VERIFY(observe_external_one(&backend, &held) == SALTS_OK);
      held_live = true;
      VERIFY(held.kind == NATIVE_IO_COMPLETION_CANCELLED && held.bytes == 0u);
    }
    VERIFY(cnet_client_external_request_snapshots(&client, connection,
                                                  requests, 4u, &count) == SALTS_OK);
    VERIFY(count == 1u && held.request.slot == requests[0].request.slot &&
           held.request.generation == requests[0].request.generation);
    VERIFY(probe.terminal == 0u && probe.borrowed_received == 0u);
    VERIFY(cnet_client_stop_external(&client) == SALTS_EBUSY);
    VERIFY(cnet_client_destroy(&client) == SALTS_EBUSY);
    VERIFY(native_io_backend_get_stats(&backend, &stats));
    submitted_before_route = stats.submitted;
    {
      const int status = cnet_client_route_external_completion(&client, &held, &consumed, &events);
      held_live = !consumed;
      VERIFY(status == SALTS_OK);
    }
    VERIFY(consumed);
    if (round == 2u) {
      VERIFY(native_io_backend_get_stats(&backend, &stats));
      VERIFY(stats.submitted == submitted_before_route && stats.active_requests == 0u);
    }
    if (probe.failed != 0u || probe.terminal != 1u ||
        probe.sent != (round == 0u ? 1u : 0u))
      fprintf(stderr, "external close round %u: terminal=%u failed=%u sent=%u status=%d\n",
              round, probe.terminal, probe.failed, probe.sent, probe.last_error_status);
    VERIFY(probe.terminal == 1u && probe.failed == 0u &&
           probe.sent == (round == 0u ? 1u : 0u) &&
           probe.sends_at_terminal == probe.sent && probe.borrowed_received == 0u);
    if (round == 2u) {
      cnet_send_usage usage = {0};
      VERIFY(probe.completed == 1u && probe.completions_at_terminal == 1u &&
             probe.completion.operation.id == operation.id && probe.completion.status == SALTS_ECANCELED);
      VERIFY(cnet_client_send_usage(&client, (cnet_connection){0}, &usage) == SALTS_OK &&
             usage.operations == 0u && usage.bytes == 0u && usage.backing_bytes == 0u);
    }
    if (round != 1u) {
      VERIFY(mem_buffer_ref_count(pending) == 1u);
      if (round == 0u) {
        VERIFY(test_recv_exact(peer, received, sizeof(received)) == 0);
        VERIFY(memcmp(received, expected, sizeof(expected)) == 0);
      } else {
        VERIFY(test_recv_exact(peer, prefix_received, held.bytes) == 0);
        for (size_t i = 0u; i < held.bytes; ++i)
          VERIFY(prefix_received[i] == (unsigned char)((i * 29u + 3u) & 0xffu));
      }
      mem_buffer_release(pending);
      pending = NULL;
      stale = held;
    }
    {
      unsigned char byte = 0u;
      VERIFY(recv(peer, (char *)&byte, 1, 0) == 0);
    }
    VERIFY(cnet_client_route_external_completion(&client, &held, &consumed, &events) == SALTS_OK);
    VERIFY(!consumed);
    VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
    VERIFY(probe.terminal == 1u && probe.failed == 0u &&
           probe.sent == (round == 0u ? 1u : 0u));
    VERIFY(native_io_backend_get_stats(&backend, &stats));
    VERIFY(stats.active_requests == 0u && stats.endpoint_count == 0u && stats.admission_open);
    previous = connection;
    test_close_socket(peer);
    peer = TEST_INVALID_SOCKET;
  }
  VERIFY(cnet_client_stop_external(&client) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  client_live = 0;
  VERIFY(native_io_backend_get_stats(&backend, &stats));
  VERIFY(stats.admission_open && stats.active_requests == 0u && stats.endpoint_count == 0u);
  VERIFY(native_io_backend_wake(&backend) == SALTS_OK);
  VERIFY(native_io_backend_close(&backend) == SALTS_OK);
  VERIFY(native_io_backend_destroy(&backend) == SALTS_OK);
  backend_live = 0;
  VERIFY(cnet_listener_close(&listener) == SALTS_OK);
  VERIFY(cnet_listener_destroy(&listener) == SALTS_OK);
  listener_live = 0;

cleanup:
  for (size_t i = 0u; i < range_count; ++i) mem_slice_release(&ranges[i]);
  test_close_socket(peer);
  if (client_live) {
    const uint64_t deadline = cmeta_monotonic_ms() + 3000u;
    if (held_live) {
      (void)cnet_client_route_external_completion(&client, &held, &consumed, &events);
      held_live = !consumed;
    }
    if (connection.slot != 0u) (void)cnet_close(&client, connection);
    while (cmeta_monotonic_ms() < deadline) {
      native_io_completion completions[4];
      const int stop_status = cnet_client_stop_external(&client);
      if (stop_status == SALTS_OK || stop_status == SALTS_EALREADY) break;
      (void)cnet_client_advance_external(&client, &events);
      count = 0u;
      (void)native_io_backend_observe(&backend, completions, 4u, 10u, &count);
      for (size_t i = 0u; i < count; ++i)
        (void)cnet_client_route_external_completion(&client, &completions[i], &consumed, &events);
    }
    (void)cnet_client_destroy(&client);
  }
  if (pending) mem_buffer_release(pending);
  if (backend_live) {
    (void)native_io_backend_close(&backend);
    (void)native_io_backend_destroy(&backend);
  }
  if (listener_live) {
    (void)cnet_listener_close(&listener);
    (void)cnet_listener_destroy(&listener);
  }
  return result;
}

/* One host owns client/backend and a native peer. Four nonadjacent ranges
 * share one immutable backing; a final byte follows in the two-slot FIFO.
 * The peer pauses reads until a real native send stalls. The backing stays
 * retained until successful drain or until close's actual terminal is routed.
 * POSIX must report a short native write. IOCP may buffer the first write;
 * cancellation replenishes at most four writes until a real send stays pending.
 * The success case instead holds a full terminal without claiming pressure.
 * Peer reads resume nonblocking on this same host, without a second observer. */
enum { PRESSURE_SEGMENTS = 4, PRESSURE_SEGMENT_BYTES = 2 * 1024 * 1024,
       PRESSURE_BYTES = PRESSURE_SEGMENTS * PRESSURE_SEGMENT_BYTES, PRESSURE_GAP = 67 };

static unsigned char pressure_byte(size_t offset) {
  return (unsigned char)((offset * 29u + (offset / PRESSURE_SEGMENT_BYTES) * 17u + 3u) & 0xffu);
}

static int saltscore_native_entry_test_cnet_kernel_pressure(bool cancel) {
  cnet_client client = {0};
  cnet_listener listener = {0};
  native_io_backend backend = {0};
  cnet_client_config config = client_config();
  const native_io_backend_config backend_config = {backend_kind(), 2u, 4u, 4u};
  const cnet_listener_config listener_config = {backend_kind(), "127.0.0.1", 0u, 2u};
  tcp_probe probe = {0};
  const cnet_observer observer = {on_state, on_borrowed, &probe, on_sent};
  cnet_connection connection = {0};
  native_io_backend_stats stats = {0};
  cnet_external_request_snapshot requests[4] = {{0}};
  native_io_completion held = {0};
  mem_buffer_t *bulk = NULL, *final = NULL;
  mem_slice_t ranges[PRESSURE_SEGMENTS] = {{0}};
  test_socket peer = TEST_INVALID_SOCKET;
  struct sockaddr_in remote = {0};
  unsigned char received[65536];
  uint16_t port = 0u;
  uint64_t send_buffer = 0u, deadline;
  size_t events = 0u, count = 0u, range_count = 0u, native_bytes = 0u, peer_bytes = 0u;
  unsigned primed = 0u, empty_observations = 0u;
  bool consumed = false, held_live = false, stalled = false, buffered = false, eof = false;
  int client_live = 0, listener_live = 0, backend_live = 0, ready = 0, result = 0;
  int peer_buffer = 65536;

  config.connection_capacity = 1u;
  config.command_capacity = 2u;
  config.max_send_bytes = PRESSURE_BYTES;
  VERIFY(cnet_listener_init(&listener, &listener_config) == SALTS_OK);
  listener_live = 1;
  VERIFY(cnet_listener_port(&listener, &port) == SALTS_OK && port != 0u);
  VERIFY(cnet_listener_tcp_option_set(&listener, CNET_TCP_SOCKET_SEND_BUFFER_BYTES, 4096u) == SALTS_OK);
  VERIFY(cnet_listener_tcp_option_set(&listener, CNET_TCP_SOCKET_NODELAY, 1u) == SALTS_OK);
  VERIFY(native_io_backend_init(&backend, &backend_config) == SALTS_OK);
  backend_live = 1;
  VERIFY(cnet_client_init_external(&client, &config, &backend) == SALTS_OK);
  client_live = 1;
  peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  VERIFY(peer != TEST_INVALID_SOCKET);
  /* Pin a finite receive window before connect; loopback autotuning can
   * otherwise absorb even this large write without a paused-peer stall. */
  VERIFY(setsockopt(peer, SOL_SOCKET, SO_RCVBUF, (const char *)&peer_buffer,
                     (int)sizeof(peer_buffer)) == 0);
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  remote.sin_port = htons(port);
  VERIFY(connect(peer, (const struct sockaddr *)&remote, (int)sizeof(remote)) == 0);
  VERIFY(cnet_listener_wait(&listener, 5000u, &ready) == SALTS_OK && ready == 1);
  VERIFY(cnet_listener_accept(&listener, &client, &observer, &connection) == SALTS_OK);
  VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
  VERIFY(probe.connected == 1u && probe.failed == 0u);
  VERIFY(cnet_connection_tcp_option_get(&client, connection, CNET_TCP_SOCKET_SEND_BUFFER_BYTES,
                                         &send_buffer) == SALTS_OK);
  VERIFY(send_buffer != 0u && send_buffer < PRESSURE_BYTES);

  bulk = mem_get_buffer(mem_global(), PRESSURE_BYTES + PRESSURE_SEGMENTS * PRESSURE_GAP);
  final = mem_get_buffer(mem_global(), 1u);
  VERIFY(bulk != NULL && final != NULL);
  mem_set_used(bulk, PRESSURE_BYTES + PRESSURE_SEGMENTS * PRESSURE_GAP);
  for (size_t i = 0u; i < PRESSURE_SEGMENTS; ++i) {
    const size_t offset = i * (PRESSURE_SEGMENT_BYTES + PRESSURE_GAP);
    for (size_t j = 0u; j < PRESSURE_SEGMENT_BYTES; ++j)
      mem_buffer_data(bulk)[offset + j] = (char)pressure_byte(i * PRESSURE_SEGMENT_BYTES + j);
    ranges[i] = mem_slice(bulk, offset, PRESSURE_SEGMENT_BYTES);
    VERIFY(ranges[i].buffer == bulk && ranges[i].length == PRESSURE_SEGMENT_BYTES);
    ++range_count;
  }
  VERIFY(cnet_send_slicev(&client, connection, ranges, range_count) == SALTS_OK);
  for (size_t i = 0u; i < range_count; ++i) mem_slice_release(&ranges[i]);
  range_count = 0u;
  *mem_buffer_data(final) = (char)0xee;
  mem_set_used(final, 1u);
  /* A final-send admission seals public close too. The cancellation case
   * therefore queues an ordinary tail, which explicit close may discard. */
#if defined(_WIN32)
  if (!cancel)
#endif
  {
    VERIFY((cancel ? cnet_send_buffer(&client, connection, final)
                   : cnet_send_buffer_and_close(&client, connection, final)) == SALTS_OK);
  }
  VERIFY(mem_buffer_ref_count(bulk) == 2u);

  /* No peer reads yet. A short native completion advances only its prefix;
   * the timeout gate requires one still-active NativeIO send, not a full queue. */
  deadline = cmeta_monotonic_ms() + 5000u;
  while (!stalled && cmeta_monotonic_ms() < deadline) {
    VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
    count = 0u;
    const int status = native_io_backend_observe(&backend, &held, 1u,
#if defined(_WIN32)
                                                 cancel ? 25u :
#endif
                                                 1u, &count);
    held_live = count == 1u;
    VERIFY(status == SALTS_OK || status == SALTS_ETIMEDOUT);
    if (held_live) {
      empty_observations = 0u;
      VERIFY(held.kind == NATIVE_IO_COMPLETION_OK && held.status == SALTS_OK && held.bytes > 0u);
#if defined(_WIN32)
      if (held.bytes == PRESSURE_BYTES - native_bytes) {
        if (cancel) {
          VERIFY(primed < 4u);
          const int routed = cnet_client_route_external_completion(&client, &held, &consumed, &events);
          held_live = !consumed;
          VERIFY(routed == SALTS_OK && consumed);
          ++primed;
          VERIFY(probe.sent == primed && mem_buffer_ref_count(bulk) == 1u);
          for (size_t i = 0u; i < PRESSURE_SEGMENTS; ++i) {
            ranges[i] = mem_slice(bulk, i * (PRESSURE_SEGMENT_BYTES + PRESSURE_GAP), PRESSURE_SEGMENT_BYTES);
            VERIFY(ranges[i].buffer == bulk);
            ++range_count;
          }
          VERIFY(cnet_send_slicev(&client, connection, ranges, range_count) == SALTS_OK);
          for (size_t i = 0u; i < range_count; ++i) mem_slice_release(&ranges[i]);
          range_count = 0u;
          native_bytes = 0u;
          continue;
        }
        buffered = true;
        break; /* Full IOCP terminal is held, not a Windows pressure claim. */
      }
#endif
      VERIFY(held.bytes < PRESSURE_BYTES - native_bytes);
      native_bytes += held.bytes;
      const int routed = cnet_client_route_external_completion(&client, &held, &consumed, &events);
      held_live = !consumed;
      VERIFY(routed == SALTS_OK && consumed);
    } else if (status == SALTS_ETIMEDOUT) {
      ++empty_observations;
#if defined(_WIN32)
      stalled = !cancel || empty_observations >= 2u;
#else
      stalled = empty_observations >= 1u;
#endif
    }
    VERIFY(probe.sent == primed && probe.terminal == 0u && probe.failed == 0u);
    VERIFY(mem_buffer_ref_count(bulk) == 2u);
  }
  VERIFY((stalled || buffered) && native_bytes < PRESSURE_BYTES);
#if defined(_WIN32)
  if (cancel) {
    VERIFY(stalled && !held_live && !buffered && empty_observations >= 2u);
    VERIFY(cnet_send_buffer(&client, connection, final) == SALTS_OK);
  }
#endif
#if !defined(_WIN32)
  VERIFY(native_bytes > 0u); /* An actual short sendmsg/writev terminal. */
#endif
  VERIFY(cnet_client_external_request_snapshots(&client, connection, requests, 4u, &count) == SALTS_OK);
  VERIFY(count == 1u && requests[0].operation_kind == NATIVE_IO_OPERATION_STREAM_SEND);
  VERIFY(native_io_backend_get_stats(&backend, &stats));
  VERIFY(stats.active_requests == (buffered ? 0u : 1u) && stats.endpoint_count == 1u && stats.admission_open);
  VERIFY(probe.sent == primed && probe.terminal == 0u && probe.failed == 0u);
  VERIFY(mem_buffer_ref_count(bulk) == 2u && mem_buffer_ref_count(final) == 2u);

  if (cancel) {
    const uint64_t submitted_before_close = stats.submitted;
    VERIFY(cnet_close(&client, connection) == SALTS_OK);
    VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
    VERIFY(probe.sent == primed && probe.terminal == 0u && probe.failed == 0u);
    VERIFY(mem_buffer_ref_count(bulk) == 2u);
    VERIFY(cnet_client_stop_external(&client) == SALTS_EBUSY);
    VERIFY(cnet_client_destroy(&client) == SALTS_EBUSY);
    VERIFY(observe_external_one(&backend, &held) == SALTS_OK);
    held_live = true;
#if defined(_WIN32)
    VERIFY(held.kind == NATIVE_IO_COMPLETION_CANCELLED && held.status == SALTS_ECANCELED && held.bytes == 0u);
#else
    VERIFY((held.kind == NATIVE_IO_COMPLETION_CANCELLED && held.status == SALTS_ECANCELED &&
             held.bytes == 0u) ||
             (held.kind == NATIVE_IO_COMPLETION_OK && held.status == SALTS_OK &&
              held.bytes > 0u && held.bytes < PRESSURE_BYTES - native_bytes));
#endif
    VERIFY(mem_buffer_ref_count(bulk) == 2u && probe.terminal == 0u);
    const int routed = cnet_client_route_external_completion(&client, &held, &consumed, &events);
    held_live = !consumed;
    VERIFY(routed == SALTS_OK && consumed);
    VERIFY(probe.sent == primed && probe.terminal == 1u && probe.sends_at_terminal == primed && probe.failed == 0u);
    VERIFY(cnet_client_route_external_completion(&client, &held, &consumed, &events) == SALTS_OK);
    VERIFY(!consumed && probe.terminal == 1u && probe.sent == primed);
    VERIFY(native_io_backend_get_stats(&backend, &stats) && stats.active_requests == 0u &&
             stats.submitted == submitted_before_close);
#if defined(_WIN32)
    VERIFY(stats.cancelled == 1u);
#endif
  } else {
    VERIFY(test_nonblocking(peer) == 0);
    if (held_live) {
      native_bytes += held.bytes;
      const int routed = cnet_client_route_external_completion(&client, &held, &consumed, &events);
      held_live = !consumed;
      VERIFY(routed == SALTS_OK && consumed);
    }
    deadline = cmeta_monotonic_ms() + 15000u;
    while ((!eof || probe.terminal == 0u) && cmeta_monotonic_ms() < deadline) {
      VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
      count = 0u;
      const int status = native_io_backend_observe(&backend, &held, 1u, 0u, &count);
      held_live = count == 1u;
      VERIFY(status == SALTS_OK || status == SALTS_ETIMEDOUT);
      if (held_live) {
        VERIFY(held.kind == NATIVE_IO_COMPLETION_OK && held.status == SALTS_OK && held.bytes > 0u);
        VERIFY(held.bytes <= PRESSURE_BYTES + 1u - native_bytes);
        native_bytes += held.bytes;
        const int routed = cnet_client_route_external_completion(&client, &held, &consumed, &events);
        held_live = !consumed;
        VERIFY(routed == SALTS_OK && consumed);
      }
      for (size_t pass = 0u; !eof && pass < 64u; ++pass) {
        const int bytes = recv(peer, (char *)received, (int)sizeof(received), 0);
        if (bytes < 0) { VERIFY(test_would_block()); break; }
        if (bytes == 0) { eof = true; break; }
        VERIFY((size_t)bytes <= PRESSURE_BYTES + 1u - peer_bytes);
        for (int i = 0; i < bytes; ++i) {
          const size_t offset = peer_bytes + (size_t)i;
          VERIFY(received[i] == (offset < PRESSURE_BYTES ? pressure_byte(offset) : 0xeeu));
        }
        peer_bytes += (size_t)bytes;
      }
      VERIFY(probe.failed == 0u);
    }
    VERIFY(eof && peer_bytes == PRESSURE_BYTES + 1u && native_bytes == PRESSURE_BYTES + 1u);
    VERIFY(probe.sent == 2u && probe.send_sizes[0] == PRESSURE_BYTES && probe.send_sizes[1] == 1u &&
             probe.terminal == 1u && probe.sends_at_terminal == 2u && probe.failed == 0u);
  }
  VERIFY(mem_buffer_ref_count(bulk) == 1u && mem_buffer_ref_count(final) == 1u);
  test_close_socket(peer);
  peer = TEST_INVALID_SOCKET;
  VERIFY(cnet_client_stop_external(&client) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  client_live = 0;
  VERIFY(native_io_backend_get_stats(&backend, &stats));
  VERIFY(stats.active_requests == 0u && stats.endpoint_count == 0u && stats.admission_open);
  VERIFY(native_io_backend_close(&backend) == SALTS_OK);
  VERIFY(native_io_backend_destroy(&backend) == SALTS_OK);
  backend_live = 0;
  VERIFY(cnet_listener_close(&listener) == SALTS_OK);
  VERIFY(cnet_listener_destroy(&listener) == SALTS_OK);
  listener_live = 0;

cleanup:
  test_close_socket(peer);
  if (client_live) {
    const uint64_t cleanup_deadline = cmeta_monotonic_ms() + 3000u;
    if (held_live) (void)cnet_client_route_external_completion(&client, &held, &consumed, &events);
    if (connection.slot != 0u) (void)cnet_close(&client, connection);
    while (cmeta_monotonic_ms() < cleanup_deadline) {
      native_io_completion completions[4];
      const int stopped = cnet_client_stop_external(&client);
      if (stopped == SALTS_OK || stopped == SALTS_EALREADY) break;
      (void)cnet_client_advance_external(&client, &events);
      count = 0u;
      (void)native_io_backend_observe(&backend, completions, 4u, 10u, &count);
      for (size_t i = 0u; i < count; ++i)
        (void)cnet_client_route_external_completion(&client, &completions[i], &consumed, &events);
    }
    (void)cnet_client_destroy(&client);
  }
  for (size_t i = 0u; i < range_count; ++i) mem_slice_release(&ranges[i]);
  if (bulk) mem_buffer_release(bulk);
  if (final) mem_buffer_release(final);
  if (backend_live) {
    (void)native_io_backend_close(&backend);
    (void)native_io_backend_destroy(&backend);
  }
  if (listener_live) {
    (void)cnet_listener_close(&listener);
    (void)cnet_listener_destroy(&listener);
  }
  return result;
}

static int progress_ipc_pair(cnet_ipc_listener *listener, cnet_client *client,
                             cnet_client *server) {
  size_t events = 0u;
  int status = cnet_ipc_listener_advance(listener, 1u, &events);
  if (status == SALTS_OK) status = cnet_client_poll(client, 1u, &events);
  if (status == SALTS_OK) status = cnet_client_poll(server, 1u, &events);
  return status;
}

/* One thread owns the listener and both production clients. IPC is AF_UNIX
 * on POSIX and an overlapped named pipe on Windows. Detachment transfers one
 * resource; failed admission must consume/close it, while the established
 * neighbor survives. Receive demand bounds events without assuming framing. */
static int saltscore_native_entry_test_cnet_ipc_lifetime(bool pipe_dial) {
  cnet_client client = {0}, server = {0};
  cnet_ipc_listener listener = {0};
  cnet_client_config client_cfg = client_config(), server_cfg = client_config();
  cnet_ipc_listener_config listener_cfg = {
      sizeof(cnet_ipc_listener_config), CNET_IPC_VERSION, backend_kind(), NULL,
      1u, 2u, 256u, 256u};
  tcp_probe outbound = {0}, inbound = {0}, rejected = {0};
  cnet_observer outbound_observer = {on_state, on_borrowed, &outbound, on_sent};
  const cnet_observer inbound_observer = {on_state, on_borrowed, &inbound, on_sent};
  cnet_connect_options options = {0};
  cnet_stream_socket_options socket_options = CNET_STREAM_SOCKET_OPTIONS_INIT;
  int *tcp_only_options[] = {&socket_options.nodelay, &socket_options.keepalive,
                             &socket_options.linger};
  cnet_connection connection = {0}, accepted_connection = {0}, rejected_connection = {0};
  cnet_connection rejected_adoption = {17u, 19u};
  cnet_ipc_accepted accepted = {0};
  mem_buffer_t *pending = NULL;
  mem_slice_t ranges[2] = {{0}};
  char *directory = NULL;
  char uri[256], dial_uri[256];
  uint64_t deadline, option_value = UINT64_MAX;
  size_t events = 0u;
  bool stopped = false;
  int result = 0, client_live = 0, server_live = 0, listener_live = 0;
  const unsigned char request[] = {'i', 'p', 'c'};
  const unsigned char response[] = {'d', 'o', 'n', 'e'};

  directory = tt_make_temp_dir("cnetipc");
  VERIFY(directory != NULL);
#if defined(_WIN32)
  {
    const char *name = directory;
    for (const char *cursor = directory; *cursor != '\0'; ++cursor)
      if (*cursor == '/' || *cursor == '\\') name = cursor + 1;
    VERIFY(snprintf(uri, sizeof(uri), "ipc://%s", name) > 0);
  }
#else
  VERIFY(snprintf(uri, sizeof(uri), "ipc://%s/peer", directory) > 0);
#endif
  listener_cfg.uri = uri;
  VERIFY(snprintf(dial_uri, sizeof(dial_uri), "%s%s",
                   pipe_dial ? "pipe://" : "ipc://", uri + sizeof("ipc://") - 1u) > 0);
  server_cfg.connection_capacity = 1u;
  VERIFY(cnet_client_init(&client, &client_cfg) == SALTS_OK);
  client_live = 1;
  VERIFY(cnet_client_init(&server, &server_cfg) == SALTS_OK);
  server_live = 1;
  VERIFY(cnet_ipc_listener_init(&listener, &listener_cfg) == SALTS_OK);
  listener_live = 1;
  VERIFY(cnet_ipc_listener_advance(&listener, 1u, &events) == SALTS_OK);
  options.uri = dial_uri;
  options.observer = outbound_observer;
  for (size_t i = 0u; i < 5u; ++i) {
    socket_options = (cnet_stream_socket_options)CNET_STREAM_SOCKET_OPTIONS_INIT;
    if (i < 3u) *tcp_only_options[i] = 1;
    else if (i == 3u) socket_options.receive_buffer_bytes = 1024u;
    else socket_options.send_buffer_bytes = 1024u;
    VERIFY(cnet_client_set_stream_socket_options(&client, &socket_options) == SALTS_OK);
    VERIFY(cnet_connect(&client, &options, &rejected_adoption) == SALTS_ENOTSUP);
    VERIFY(rejected_adoption.slot == 0u && rejected_adoption.generation == 0u);
    VERIFY(outbound.connected == 0u && outbound.terminal == 0u);
  }
  socket_options = (cnet_stream_socket_options)CNET_STREAM_SOCKET_OPTIONS_INIT;
  VERIFY(cnet_client_set_stream_socket_options(&client, &socket_options) == SALTS_OK);
  VERIFY(cnet_connect(&client, &options, &connection) == SALTS_OK);
  deadline = cmeta_monotonic_ms() + 5000u;
  while (accepted.kind == CNET_IPC_RESOURCE_NONE && cmeta_monotonic_ms() < deadline) {
    int status;
    VERIFY(progress_ipc_pair(&listener, &client, &server) == SALTS_OK);
    status = cnet_ipc_listener_accept_detached(&listener, &accepted);
    VERIFY(status == SALTS_OK || status == SALTS_ENOENT);
  }
#if defined(_WIN32)
  VERIFY(accepted.kind == CNET_IPC_RESOURCE_PIPE);
#else
  VERIFY(accepted.kind == CNET_IPC_RESOURCE_SOCKET);
#endif
  VERIFY(cnet_client_adopt_ipc(&server, &accepted, &inbound_observer,
                              &accepted_connection) == SALTS_OK);
  VERIFY(accepted.kind == CNET_IPC_RESOURCE_NONE && accepted.native_handle == 0u);
  VERIFY(cnet_client_adopt_ipc(&server, &accepted, &inbound_observer,
                              &rejected_adoption) == SALTS_EINVAL);
  VERIFY(rejected_adoption.slot == 0u && rejected_adoption.generation == 0u);
  VERIFY(cnet_ipc_accepted_close(&accepted) == SALTS_EALREADY);
  deadline = cmeta_monotonic_ms() + 5000u;
  while ((!outbound.connected || !inbound.connected) && cmeta_monotonic_ms() < deadline)
    VERIFY(progress_ipc_pair(&listener, &client, &server) == SALTS_OK);
  VERIFY(outbound.connected == 1u && inbound.connected == 1u);
  VERIFY(cnet_connection_tcp_option_get(&client, connection, CNET_TCP_SOCKET_NODELAY,
                                        &option_value) == SALTS_ENOTSUP);
  VERIFY(option_value == 0u);
  VERIFY(cnet_connection_tcp_option_set(&client, connection,
                                        CNET_TCP_SOCKET_KEEPALIVE_ENABLED, 1u) == SALTS_ENOTSUP);
  VERIFY(cnet_connection_tcp_option_set(&server, accepted_connection,
                                        CNET_TCP_SOCKET_NODELAY, 1u) == SALTS_ENOTSUP);
  VERIFY(cnet_connection_shutdown(&client, connection, CNET_TCP_SHUTDOWN_SEND) == SALTS_ENOTSUP);

  /* A second real peer fills no extra final-owner slot. Rejection consumes the
   * detached resource and closes that peer without disturbing the first. */
  options.observer = (cnet_observer){on_state, on_borrowed, &rejected, on_sent};
  VERIFY(cnet_ipc_listener_advance(&listener, 1u, &events) == SALTS_OK);
  VERIFY(cnet_connect(&client, &options, &rejected_connection) == SALTS_OK);
  deadline = cmeta_monotonic_ms() + 5000u;
  while ((accepted.kind == CNET_IPC_RESOURCE_NONE || !rejected.connected) &&
         cmeta_monotonic_ms() < deadline) {
    VERIFY(progress_ipc_pair(&listener, &client, &server) == SALTS_OK);
    if (accepted.kind == CNET_IPC_RESOURCE_NONE) {
      const int status = cnet_ipc_listener_accept_detached(&listener, &accepted);
      VERIFY(status == SALTS_OK || status == SALTS_ENOENT);
    }
  }
  VERIFY(accepted.kind != CNET_IPC_RESOURCE_NONE && rejected.connected == 1u);
  VERIFY(cnet_client_adopt_ipc(&server, &accepted, &inbound_observer,
                              &rejected_adoption) == SALTS_ENOBUFS);
  VERIFY(accepted.kind == CNET_IPC_RESOURCE_NONE && accepted.native_handle == 0u);
  VERIFY(rejected_adoption.slot == 0u && rejected_adoption.generation == 0u);
  VERIFY(cnet_ipc_accepted_close(&accepted) == SALTS_EALREADY);
  VERIFY(cnet_receive(&client, rejected_connection, 1u) == SALTS_OK);
  deadline = cmeta_monotonic_ms() + 5000u;
  while (!rejected.terminal && cmeta_monotonic_ms() < deadline)
    VERIFY(progress_ipc_pair(&listener, &client, &server) == SALTS_OK);
  VERIFY(rejected.terminal == 1u && rejected.failed == 0u && rejected.sent == 0u);
  VERIFY(outbound.terminal == 0u && inbound.terminal == 0u);

  VERIFY(cnet_receive(&server, accepted_connection, sizeof(request) + 1u) == SALTS_OK);
  VERIFY(cnet_receive(&client, connection, sizeof(response) + 1u) == SALTS_OK);
  pending = mem_get_buffer(mem_global(), sizeof(request));
  VERIFY(pending != NULL);
  memcpy(mem_buffer_data(pending), request, sizeof(request));
  mem_set_used(pending, sizeof(request));
  ranges[0] = mem_slice(pending, 0u, 1u);
  ranges[1] = mem_slice(pending, 1u, 2u);
  VERIFY(ranges[0].buffer == pending && ranges[1].buffer == pending);
#if defined(_WIN32)
  /* Named-pipe vectors are unsupported; prove rejection without a retained
   * backing, then independently exercise the supported buffer-send API. */
  VERIFY(cnet_send_slicev(&client, connection, ranges, 2u) == SALTS_ENOTSUP);
  VERIFY(mem_buffer_ref_count(pending) == 3u);
  mem_slice_release(&ranges[0]);
  mem_slice_release(&ranges[1]);
  VERIFY(mem_buffer_ref_count(pending) == 1u);
  VERIFY(cnet_send_buffer(&client, connection, pending) == SALTS_OK);
#else
  VERIFY(cnet_send_slicev(&client, connection, ranges, 2u) == SALTS_OK);
  VERIFY(mem_buffer_ref_count(pending) == 4u);
  mem_slice_release(&ranges[0]);
  mem_slice_release(&ranges[1]);
#endif
  VERIFY(mem_buffer_ref_count(pending) == 2u);
  mem_buffer_release(pending);
  pending = NULL;
  deadline = cmeta_monotonic_ms() + 5000u;
  while ((outbound.sent < 1u || inbound.borrowed_bytes < sizeof(request)) &&
         cmeta_monotonic_ms() < deadline)
    VERIFY(progress_ipc_pair(&listener, &client, &server) == SALTS_OK);
  VERIFY(outbound.sent == 1u && outbound.last_send_bytes == sizeof(request));
  VERIFY(inbound.borrowed_bytes == sizeof(request) &&
         memcmp(inbound.borrowed_data, request, sizeof(request)) == 0);
  VERIFY(outbound.failed == 0u && inbound.failed == 0u &&
         outbound.terminal == 0u && inbound.terminal == 0u);
  pending = mem_get_buffer(mem_global(), sizeof(response));
  VERIFY(pending != NULL);
  memcpy(mem_buffer_data(pending), response, sizeof(response));
  mem_set_used(pending, sizeof(response));
  VERIFY(cnet_send_buffer_and_close(&server, accepted_connection, pending) == SALTS_OK);
  mem_buffer_release(pending);
  pending = NULL;
  deadline = cmeta_monotonic_ms() + 5000u;
  while ((!outbound.terminal || !inbound.terminal) && cmeta_monotonic_ms() < deadline)
    VERIFY(progress_ipc_pair(&listener, &client, &server) == SALTS_OK);
  VERIFY(inbound.sent == 1u && inbound.last_send_bytes == sizeof(response) &&
         inbound.sends_at_terminal == 1u);
  VERIFY(outbound.borrowed_bytes == sizeof(response) &&
         memcmp(outbound.borrowed_data, response, sizeof(response)) == 0);
  VERIFY(outbound.terminal == 1u && inbound.terminal == 1u &&
         outbound.failed == 0u && inbound.failed == 0u);
  VERIFY(progress_ipc_pair(&listener, &client, &server) == SALTS_OK);
  VERIFY(outbound.sent == 1u && inbound.sent == 1u &&
         outbound.terminal == 1u && inbound.terminal == 1u && rejected.terminal == 1u);
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  client_live = 0;
  VERIFY(cnet_client_stop(&server, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&server) == SALTS_OK);
  server_live = 0;
  deadline = cmeta_monotonic_ms() + 5000u;
  while (!stopped && cmeta_monotonic_ms() < deadline) {
    const int status = cnet_ipc_listener_stop(&listener, &stopped);
    VERIFY(status == SALTS_OK || status == SALTS_EBUSY);
    if (!stopped) VERIFY(cnet_ipc_listener_advance(&listener, 1u, &events) == SALTS_OK);
  }
  VERIFY(stopped);
  VERIFY(cnet_ipc_listener_destroy(&listener) == SALTS_OK);
  listener_live = 0;
  VERIFY(tt_remove_tree(directory) == 0);
  free(directory);
  directory = NULL;

cleanup:
  mem_slice_release(&ranges[0]);
  mem_slice_release(&ranges[1]);
  if (pending) mem_buffer_release(pending);
  if (accepted.kind != CNET_IPC_RESOURCE_NONE) (void)cnet_ipc_accepted_close(&accepted);
  if (client_live) {
    (void)cnet_client_stop(&client, 3000u);
    (void)cnet_client_destroy(&client);
  }
  if (server_live) {
    (void)cnet_client_stop(&server, 3000u);
    (void)cnet_client_destroy(&server);
  }
  if (listener_live) {
    deadline = cmeta_monotonic_ms() + 3000u;
    while (!stopped && cmeta_monotonic_ms() < deadline) {
      (void)cnet_ipc_listener_stop(&listener, &stopped);
      if (!stopped) (void)cnet_ipc_listener_advance(&listener, 1u, &events);
    }
    (void)cnet_ipc_listener_destroy(&listener);
  }
  if (directory) {
    (void)tt_remove_tree(directory);
    free(directory);
  }
  return result;
}

#if !defined(_WIN32)
static int fifo_peer_read_exact(int descriptor, unsigned char *output, size_t size) {
  const uint64_t deadline = cmeta_monotonic_ms() + 5000u;
  size_t done = 0u;
  while (done < size && cmeta_monotonic_ms() < deadline) {
    struct pollfd ready = {descriptor, POLLIN, 0};
    const int status = poll(&ready, 1u, 10);
    ssize_t bytes;
    if (status < 0 && errno == EINTR) continue;
    if (status < 0) return SALTS_EIO;
    if (status == 0) continue;
    bytes = read(descriptor, output + done, size - done);
    if (bytes < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    if (bytes <= 0) return SALTS_EIO;
    done += (size_t)bytes;
  }
  return done == size ? SALTS_OK : SALTS_ETIMEDOUT;
}

/* The native peer owns the opposite ends of two real FIFOs. A temporary read
 * descriptor only lets the peer open .rx before CNet connects; it is closed
 * immediately and never receives payload. CNet owns .rx read/.tx write for
 * its whole generation. No AF_UNIX/TCP substitution or vector flattening. */
static int saltscore_native_entry_test_cnet_fifo_lifetime(void) {
  cnet_client client = {0};
  const cnet_client_config config = client_config();
  tcp_probe probe = {0};
  cnet_connect_options options = {0};
  cnet_connection connection = {0}, rejected = {17u, 19u};
  cnet_stream_socket_options socket_options = CNET_STREAM_SOCKET_OPTIONS_INIT;
  int *tcp_only_options[] = {&socket_options.nodelay, &socket_options.keepalive,
                             &socket_options.linger};
  char *directory = NULL;
  char base[256], read_path[260], write_path[260], uri[264];
  int peer_read = -1, peer_write = -1, bootstrap_read = -1;
  int client_live = 0, result = 0;
  mem_buffer_t *pending = NULL;
  mem_slice_t ranges[3] = {{0}};
  unsigned char received[3] = {0};
  const unsigned char reply[] = {'a', 'c', 'k'};
  uint64_t option_value = UINT64_MAX;
  size_t events = 0u;

  directory = tt_make_temp_dir("cnetfifo");
  VERIFY(directory != NULL);
  VERIFY(snprintf(base, sizeof(base), "%s/stream", directory) > 0);
  VERIFY(snprintf(read_path, sizeof(read_path), "%s.rx", base) > 0);
  VERIFY(snprintf(write_path, sizeof(write_path), "%s.tx", base) > 0);
  VERIFY(snprintf(uri, sizeof(uri), "pipe://%s", base) > 0);
  VERIFY(mkfifo(read_path, 0600) == 0 && mkfifo(write_path, 0600) == 0);
  peer_read = open(write_path, O_RDONLY | O_NONBLOCK);
  VERIFY(peer_read >= 0);
  bootstrap_read = open(read_path, O_RDONLY | O_NONBLOCK);
  VERIFY(bootstrap_read >= 0);
  peer_write = open(read_path, O_WRONLY | O_NONBLOCK);
  VERIFY(peer_write >= 0);
  VERIFY(close(bootstrap_read) == 0);
  bootstrap_read = -1;
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  client_live = 1;
  options.uri = uri;
  options.observer = (cnet_observer){on_state, on_borrowed, &probe, on_sent};
  for (size_t i = 0u; i < 5u; ++i) {
    socket_options = (cnet_stream_socket_options)CNET_STREAM_SOCKET_OPTIONS_INIT;
    if (i < 3u) *tcp_only_options[i] = 1;
    else if (i == 3u) socket_options.receive_buffer_bytes = 1024u;
    else socket_options.send_buffer_bytes = 1024u;
    VERIFY(cnet_client_set_stream_socket_options(&client, &socket_options) == SALTS_OK);
    VERIFY(cnet_connect(&client, &options, &rejected) == SALTS_ENOTSUP);
    VERIFY(rejected.slot == 0u && rejected.generation == 0u);
    VERIFY(probe.connected == 0u && probe.terminal == 0u);
  }
  socket_options = (cnet_stream_socket_options)CNET_STREAM_SOCKET_OPTIONS_INIT;
  VERIFY(cnet_client_set_stream_socket_options(&client, &socket_options) == SALTS_OK);
  VERIFY(cnet_connect(&client, &options, &connection) == SALTS_OK);
  VERIFY(poll_until(&client, &probe.connected, 1u) == SALTS_OK);
  VERIFY(probe.connected == 1u && probe.failed == 0u && probe.terminal == 0u);
  VERIFY(cnet_connection_tcp_option_get(&client, connection, CNET_TCP_SOCKET_NODELAY,
                                        &option_value) == SALTS_ENOTSUP);
  VERIFY(option_value == 0u);
  VERIFY(cnet_connection_tcp_option_set(&client, connection,
                                        CNET_TCP_SOCKET_KEEPALIVE_ENABLED, 1u) == SALTS_ENOTSUP);
  VERIFY(cnet_connection_shutdown(&client, connection, CNET_TCP_SHUTDOWN_SEND) == SALTS_ENOTSUP);
  pending = mem_get_buffer(mem_global(), 5u);
  VERIFY(pending != NULL);
  memcpy(mem_buffer_data(pending), "v-e-c", 5u);
  mem_set_used(pending, 5u);
  for (size_t i = 0u; i < 3u; ++i) {
    ranges[i] = mem_slice(pending, i * 2u, 1u);
    VERIFY(ranges[i].buffer == pending);
  }
  VERIFY(cnet_send_slicev(&client, connection, ranges, 3u) == SALTS_OK);
  VERIFY(mem_buffer_ref_count(pending) == 5u);
  for (size_t i = 0u; i < 3u; ++i) mem_slice_release(&ranges[i]);
  VERIFY(mem_buffer_ref_count(pending) == 2u);
  mem_buffer_release(pending);
  pending = NULL;
  VERIFY(poll_until(&client, &probe.sent, 1u) == SALTS_OK);
  VERIFY(probe.sent == 1u && probe.last_send_bytes == 3u);
  VERIFY(fifo_peer_read_exact(peer_read, received, sizeof(received)) == SALTS_OK);
  VERIFY(memcmp(received, "vec", sizeof(received)) == 0);
  VERIFY(cnet_receive(&client, connection, sizeof(reply) + 1u) == SALTS_OK);
  VERIFY(write(peer_write, reply, sizeof(reply)) == (ssize_t)sizeof(reply));
  VERIFY(poll_until(&client, &probe.borrowed_bytes, sizeof(reply)) == SALTS_OK);
  VERIFY(probe.borrowed_bytes == sizeof(reply) &&
         memcmp(probe.borrowed_data, reply, sizeof(reply)) == 0);
  VERIFY(probe.terminal == 0u && probe.failed == 0u);
  pending = mem_get_buffer(mem_global(), 3u);
  VERIFY(pending != NULL);
  memcpy(mem_buffer_data(pending), "end", 3u);
  mem_set_used(pending, 3u);
  VERIFY(cnet_send_buffer_and_close(&client, connection, pending) == SALTS_OK);
  mem_buffer_release(pending);
  pending = NULL;
  VERIFY(poll_until(&client, &probe.terminal, 1u) == SALTS_OK);
  VERIFY(probe.sent == 2u && probe.sends_at_terminal == 2u &&
         probe.terminal == 1u && probe.failed == 0u);
  VERIFY(fifo_peer_read_exact(peer_read, received, sizeof(received)) == SALTS_OK);
  VERIFY(memcmp(received, "end", sizeof(received)) == 0);
  VERIFY(read(peer_read, received, 1u) == 0);
  VERIFY(cnet_client_poll(&client, 0u, &events) == SALTS_OK);
  VERIFY(probe.sent == 2u && probe.terminal == 1u && probe.failed == 0u);
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  client_live = 0;
  VERIFY(close(peer_read) == 0);
  peer_read = -1;
  VERIFY(close(peer_write) == 0);
  peer_write = -1;
  VERIFY(tt_remove_tree(directory) == 0);
  free(directory);
  directory = NULL;

cleanup:
  for (size_t i = 0u; i < 3u; ++i) mem_slice_release(&ranges[i]);
  if (pending) mem_buffer_release(pending);
  if (client_live) {
    (void)cnet_client_stop(&client, 3000u);
    (void)cnet_client_destroy(&client);
  }
  if (bootstrap_read >= 0) (void)close(bootstrap_read);
  if (peer_read >= 0) (void)close(peer_read);
  if (peer_write >= 0) (void)close(peer_write);
  if (directory) {
    (void)tt_remove_tree(directory);
    free(directory);
  }
  return result;
}
#endif

enum { SG_CASE_START, SG_CASE_STEP, SG_CASE_CLOSE_BULK, SG_CASE_CHECK_BORROW,
       SG_CASE_FINAL_CONTROL, SG_CASE_FINISH, SG_CASE_CLEANUP,
       SG_CASE_LOAD, SG_CASE_NEXT_CONTROL, SG_CASE_FINISH_LOAD,
       SG_CASE_TLS_STEP, SG_CASE_TLS_RELEASE,
       SG_BULK_BYTES = 32768, SG_LOAD_OPERATIONS = 8, SG_CONTROL_EXCHANGES = 8,
       SG_CONTROL_PROGRESS_BOUND = 256 };

typedef struct sg_owner_case {
  cnet_listener listener;
  cnet_client clients[2];
  cnet_connection connections[2];
  tcp_probe probes[2];
  mem_buffer_t *pending[2];
  test_socket peers[2];
  native_io_backend *backend;
  native_io_sharded_host_lease lease;
  const void *thread;
  size_t shard, owner_count, observations;
  int command, failure;
  bool host_active;
  bool sustained;
  size_t bulk_admitted, saturated_rounds;
  bool tls_failure;
  cnet_tls_server tls_server;
  /* Optional mixed-ownership case. Owner retains the receive byte/address
   * until SG terminal+finalize; main owns only the unassociated UDP peer.
   * Two sequential admissions (success, then cancellation) reuse one endpoint.
   * All counters/storage are accessed across the same submit/wait boundary. */
  bool mixed, sg_active, injected_unknown;
  test_socket sg_socket, sg_peer;
  struct sockaddr_in sg_address, sg_from;
  native_io_sharded_endpoint sg_endpoint;
  native_io_sharded_request sg_request;
  unsigned char sg_byte;
  size_t sg_terminals, sg_finalized, sg_routed;
} sg_owner_case;

static void sg_case_terminal(native_io_sharded_context *context,
                             const native_io_sharded_completion *completion, void *user) {
  sg_owner_case *owner = user;
  native_io_sharded_completion recursive;
  size_t count = 99u;
  const bool first = owner->sg_terminals == 0u;
  if (native_io_sharded_context_shard(context) != owner->shard ||
      cmeta_thread_current_token() != owner->thread || !owner->sg_active ||
      owner->sg_terminals != owner->sg_finalized || !completion->sharded_owned ||
      completion->request.native_request.slot != owner->sg_request.native_request.slot ||
      completion->request.native_request.generation != owner->sg_request.native_request.generation ||
      completion->user_data != (uintptr_t)&owner->probes[1] ||
      (first && (completion->kind != NATIVE_IO_COMPLETION_OK ||
                 completion->status != SALTS_OK || completion->bytes != 1u ||
                 owner->sg_byte != (unsigned char)(0xa0u + owner->shard))) ||
      (!first && (completion->kind != NATIVE_IO_COMPLETION_CANCELLED ||
                  completion->status != SALTS_ECANCELED || completion->bytes != 0u)) ||
      native_io_sharded_context_observe_host(context, owner->lease, &recursive,
                                              1u, 0u, &count) != SALTS_EBUSY || count != 0u) {
    if (owner->failure == 0) owner->failure = __LINE__;
  }
  ++owner->sg_terminals;
}

static void sg_case_finalize(void *user) {
  sg_owner_case *owner = user;
  if (cmeta_thread_current_token() != owner->thread || !owner->sg_active ||
      owner->sg_terminals != owner->sg_finalized + 1u) {
    if (owner->failure == 0) owner->failure = __LINE__;
  }
  ++owner->sg_finalized;
  owner->sg_active = false;
}

static int sg_case_submit_owned(native_io_sharded_context *context, sg_owner_case *owner) {
  const native_io_sharded_operation operation = {
      NATIVE_IO_OPERATION_UDP_RECV_FROM, owner->sg_endpoint, &owner->sg_byte, 1u,
      (uintptr_t)&owner->probes[1], &owner->sg_from, sizeof(owner->sg_from), 0u};
  const native_io_sharded_ownership ownership = {sg_case_terminal, sg_case_finalize, owner};
  const int status = native_io_sharded_context_submit_owned(context, &operation, &ownership,
                                                            &owner->sg_request);
  if (status == SALTS_OK) owner->sg_active = true;
  return status;
}

static int sg_case_release_owned(native_io_sharded_context *context, sg_owner_case *owner) {
  if (owner->sg_active) return SALTS_EBUSY;
  test_close_socket(owner->sg_socket);
  owner->sg_socket = TEST_INVALID_SOCKET;
  if (native_io_sharded_endpoint_valid(owner->sg_endpoint)) {
    const int status = native_io_sharded_context_release_socket(context, owner->sg_endpoint);
    if (status != SALTS_OK) return status;
    owner->sg_endpoint = (native_io_sharded_endpoint){0};
  }
  return SALTS_OK;
}

static bool sg_case_quiescent(void *user) {
  const sg_owner_case *owner = user;
  return owner->clients[0].impl == NULL && owner->clients[1].impl == NULL &&
         owner->pending[0] == NULL && owner->pending[1] == NULL &&
         !owner->sg_active && !native_io_sharded_endpoint_valid(owner->sg_endpoint);
}

/* Exactly one host observe per bounded progress task; route the whole returned
 * batch even if an earlier client advance failed. Main never observes NativeIO. */
static int sg_case_progress(native_io_sharded_context *context, sg_owner_case *owner) {
  cnet_client *clients[2];
  size_t client_count = 0u, events = 0u, count = 0u, accepts = 0u, sharded = 0u;
  native_io_sharded_completion completions[9] = {0};
  int first = SALTS_OK, status;
  for (size_t i = 0u; i < 2u; ++i) {
    if (owner->clients[i].impl == NULL) continue;
    clients[client_count++] = &owner->clients[i];
    status = cnet_client_advance_external(&owner->clients[i], &events);
    if (first == SALTS_OK && status != SALTS_OK) first = status;
  }
  ++owner->observations;
  status = native_io_sharded_context_observe_host(context, owner->lease,
                                                  completions + 1u, 8u, 1u, &count);
  if (status == SALTS_ETIMEDOUT) status = SALTS_OK;
  if (status == SALTS_OK) {
    const cnet_sg_host_routes routes = {
        sizeof(cnet_sg_host_routes), CNET_SG_HOST_ROUTING_VERSION, NULL, clients, client_count};
    size_t expected_sharded = 0u;
    for (size_t i = 1u; i <= count; ++i)
      if (completions[i].sharded_owned) ++expected_sharded;
    /* Deliberately malformed request identity, not a fabricated I/O success.
     * Prepend it once to a real batch with a CNet completion. Every observed
     * event follows it exactly once; EPROTO must not abandon that remainder. */
    const bool inject = owner->mixed && !owner->injected_unknown && count > expected_sharded;
    completions[0].kind = NATIVE_IO_COMPLETION_OK;
    status = cnet_sg_host_route_batch(completions + (inject ? 0u : 1u),
                                      count + (inject ? 1u : 0u), &routes, &accepts, &sharded);
    if (inject && status == SALTS_EPROTO) {
      owner->injected_unknown = true;
      status = SALTS_OK;
    } else if (inject && status == SALTS_OK) {
      status = SALTS_EPROTO;
    }
    owner->sg_routed += sharded;
    if (status == SALTS_OK && (accepts != 0u || sharded != expected_sharded ||
                               (!owner->mixed && sharded != 0u))) status = SALTS_EPROTO;
  }
  return first == SALTS_OK ? status : first;
}

static void sg_case_cleanup(native_io_sharded_context *context, sg_owner_case *owner) {
  const uint64_t deadline = cmeta_monotonic_ms() + 3000u;
  if (owner->sg_active) (void)native_io_sharded_context_cancel(context, owner->sg_request);
  for (size_t i = 0u; i < 2u; ++i)
    if (owner->clients[i].impl != NULL && owner->connections[i].slot != 0u)
      (void)cnet_close(&owner->clients[i], owner->connections[i]);
  while ((owner->clients[0].impl != NULL || owner->clients[1].impl != NULL || owner->sg_active) &&
         cmeta_monotonic_ms() < deadline) {
    for (size_t i = 0u; i < 2u; ++i) {
      if (owner->clients[i].impl == NULL) continue;
      const int status = cnet_client_stop_external(&owner->clients[i]);
      if (status == SALTS_OK || status == SALTS_EALREADY)
        (void)cnet_client_destroy(&owner->clients[i]);
    }
    if (owner->host_active &&
        (owner->clients[0].impl != NULL || owner->clients[1].impl != NULL || owner->sg_active))
      (void)sg_case_progress(context, owner);
  }
  (void)sg_case_release_owned(context, owner);
  for (size_t i = 0u; i < 2u; ++i) {
    if (owner->pending[i]) mem_buffer_release(owner->pending[i]);
    owner->pending[i] = NULL;
  }
  (void)cnet_tls_server_destroy(&owner->tls_server);
  if (owner->host_active &&
      native_io_sharded_context_release_host(context, owner->lease) == SALTS_OK) {
    owner->host_active = false;
    owner->backend = NULL;
  }
  if (owner->listener.impl != NULL) {
    (void)cnet_listener_close(&owner->listener);
    (void)cnet_listener_destroy(&owner->listener);
  }
}

/* Owner state lives on main's heap until all accepted SG tasks and the runtime
 * are destroyed. Main reads/mutates it only between submit+wait boundaries.
 * Clients, backend, lease and listeners are touched only on their fixed shard;
 * unassociated native peer sockets transfer to main after startup completes. */
static void sg_case_task(native_io_sharded_context *context, void *user) {
  sg_owner_case *owner = user;
  size_t events = 0u;
  native_io_backend_stats stats = {0};
#define SG_REQUIRE(expr) do { if (!(expr)) {                                    \
    if (owner->failure == 0) owner->failure = __LINE__; return;                 \
  } } while (0)
  SG_REQUIRE(native_io_sharded_context_shard(context) == owner->shard);
  if (owner->thread == NULL) owner->thread = cmeta_thread_current_token();
  SG_REQUIRE(owner->thread == cmeta_thread_current_token());
  if (owner->command == SG_CASE_CLEANUP) {
    sg_case_cleanup(context, owner);
  } else if (owner->command == SG_CASE_START) {
    cnet_client_config config = client_config();
    const cnet_listener_config listener_config = {backend_kind(), "127.0.0.1", 0u, 2u};
    struct sockaddr_in remote = {0};
    native_io_sharded_completion completion;
    native_io_sharded_host_lease wrong;
    uint16_t port = 0u;
    size_t count = 0u;
    config.connection_capacity = 1u;
    config.max_send_bytes = SG_BULK_BYTES;
    if (owner->tls_failure) {
      const cnet_tls_server_config tls_config = {
          .size = sizeof(cnet_tls_server_config), .cert_file = CORE_TLS_TEST_P384_LEAF,
          .key_file = CORE_TLS_TEST_P384_KEY};
      config.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
      config.tls_handshake_timeout_ms = 2500u;
      SG_REQUIRE(cnet_tls_server_init(&owner->tls_server, &tls_config) == SALTS_OK);
    }
    SG_REQUIRE(native_io_sharded_context_acquire_host(context, sg_case_quiescent, owner,
                                                      &owner->lease, &owner->backend) == SALTS_OK);
    owner->host_active = true;
    SG_REQUIRE(owner->lease.owner_shard == owner->shard && owner->lease.generation != 0u);
    SG_REQUIRE(native_io_sharded_context_observe(context, &completion, 1u, 0u, &count) == SALTS_EPERM);
    SG_REQUIRE(count == 0u);
    wrong = owner->lease;
    if (owner->owner_count > 1u)
      wrong.owner_shard = (uint32_t)((owner->shard + 1u) % owner->owner_count);
    else
      ++wrong.generation;
    SG_REQUIRE(native_io_sharded_context_observe_host(context, wrong, &completion,
                                                      1u, 0u, &count) == SALTS_EPERM);
    SG_REQUIRE(count == 0u);
    SG_REQUIRE(cnet_listener_init(&owner->listener, &listener_config) == SALTS_OK);
    SG_REQUIRE(cnet_listener_port(&owner->listener, &port) == SALTS_OK && port != 0u);
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    remote.sin_port = htons(port);
    for (size_t i = 0u; i < 2u; ++i) {
      int ready = 0;
      const cnet_observer observer = {on_state, on_borrowed, &owner->probes[i], on_sent};
      SG_REQUIRE(cnet_client_init_external(&owner->clients[i], &config, owner->backend) == SALTS_OK);
      owner->peers[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      SG_REQUIRE(owner->peers[i] != TEST_INVALID_SOCKET);
      SG_REQUIRE(test_recv_timeout(owner->peers[i]) == 0);
      SG_REQUIRE(connect(owner->peers[i], (const struct sockaddr *)&remote, (int)sizeof(remote)) == 0);
      SG_REQUIRE(cnet_listener_wait(&owner->listener, 5000u, &ready) == SALTS_OK && ready == 1);
      if (owner->tls_failure && i == 0u) {
        SG_REQUIRE(cnet_listener_accept_tls(&owner->listener, &owner->clients[i], &owner->tls_server,
                                             &observer, &owner->connections[i]) == SALTS_OK);
        /* The admitted session retains the context until its true terminal. */
        SG_REQUIRE(cnet_tls_server_destroy(&owner->tls_server) == SALTS_OK);
      } else {
        SG_REQUIRE(cnet_listener_accept(&owner->listener, &owner->clients[i], &observer,
                                        &owner->connections[i]) == SALTS_OK);
      }
      SG_REQUIRE(cnet_client_advance_external(&owner->clients[i], &events) == SALTS_OK);
      SG_REQUIRE(owner->probes[i].connected == (owner->tls_failure && i == 0u ? 0u : 1u) &&
                 owner->probes[i].failed == 0u);
      if (owner->sustained && i == 1u) {
        const int enabled = 1;
        SG_REQUIRE(cnet_connection_tcp_option_set(&owner->clients[i], owner->connections[i],
                                                   CNET_TCP_SOCKET_NODELAY, 1u) == SALTS_OK);
        SG_REQUIRE(setsockopt(owner->peers[i], IPPROTO_TCP, TCP_NODELAY,
                              (const char *)&enabled, sizeof(enabled)) == 0);
      }
      const size_t bytes = i == 0u ? SG_BULK_BYTES : 1u;
      owner->pending[i] = mem_get_buffer(mem_global(), bytes);
      SG_REQUIRE(owner->pending[i] != NULL);
      for (size_t j = 0u; j < bytes; ++j)
        mem_buffer_data(owner->pending[i])[j] =
            (char)(i == 0u ? (j * 29u + 3u + owner->shard * 17u) & 0xffu : 0x60u + owner->shard);
      mem_set_used(owner->pending[i], bytes);
      SG_REQUIRE(cnet_send_buffer(&owner->clients[i], owner->connections[i], owner->pending[i]) ==
                 (owner->tls_failure && i == 0u ? SALTS_EBUSY : SALTS_OK));
      if (owner->tls_failure && i == 0u) SG_REQUIRE(mem_buffer_ref_count(owner->pending[i]) == 1u);
      if (i == 0u && owner->sustained) {
        owner->bulk_admitted = 1u; /* One immutable source, retained per admitted write. */
      } else {
        mem_buffer_release(owner->pending[i]);
        owner->pending[i] = NULL;
      }
    }
    SG_REQUIRE(cnet_receive(&owner->clients[1], owner->connections[1], 1u) == SALTS_OK);
    if (owner->mixed) {
#if defined(_WIN32)
      int address_size = (int)sizeof(owner->sg_address);
#else
      socklen_t address_size = (socklen_t)sizeof(owner->sg_address);
#endif
      owner->sg_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      SG_REQUIRE(owner->sg_socket != TEST_INVALID_SOCKET);
      owner->sg_address.sin_family = AF_INET;
      owner->sg_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      SG_REQUIRE(bind(owner->sg_socket, (const struct sockaddr *)&owner->sg_address,
                        (int)sizeof(owner->sg_address)) == 0);
      SG_REQUIRE(getsockname(owner->sg_socket, (struct sockaddr *)&owner->sg_address,
                              &address_size) == 0);
      SG_REQUIRE(native_io_sharded_context_attach_socket(context, (uintptr_t)owner->sg_socket,
                                                          &owner->sg_endpoint) == SALTS_OK);
      owner->sg_peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      SG_REQUIRE(owner->sg_peer != TEST_INVALID_SOCKET);
      SG_REQUIRE(sg_case_submit_owned(context, owner) == SALTS_OK);
      SG_REQUIRE(owner->sg_active && owner->sg_terminals == 0u && owner->sg_finalized == 0u);
    }
    SG_REQUIRE(native_io_sharded_context_release_host(context, owner->lease) == SALTS_EBUSY);
  } else if (owner->command == SG_CASE_LOAD) {
    cnet_send_usage usage = {0};
    bool full = false;
    SG_REQUIRE(owner->sustained && owner->pending[0] != NULL);
    SG_REQUIRE(sg_case_progress(context, owner) == SALTS_OK);
    /* Replenish only after one complete observe/route pass. Never spin inside
     * callbacks; the fixed WriteQueue owns all accepted immutable references. */
    for (size_t i = 0u; i <= SG_LOAD_OPERATIONS; ++i) {
      const int status = cnet_send_buffer(&owner->clients[0], owner->connections[0], owner->pending[0]);
      if (status == SALTS_ENOBUFS) { full = true; break; }
      SG_REQUIRE(status == SALTS_OK);
      ++owner->bulk_admitted;
    }
    SG_REQUIRE(full);
    ++owner->saturated_rounds;
    SG_REQUIRE(cnet_client_send_usage(&owner->clients[0], owner->connections[0], &usage) == SALTS_OK);
    SG_REQUIRE(usage.operations == SG_LOAD_OPERATIONS && usage.bytes == SG_LOAD_OPERATIONS * SG_BULK_BYTES);
    SG_REQUIRE(owner->probes[0].failed == 0u && owner->probes[1].failed == 0u &&
               owner->probes[0].terminal == 0u && owner->probes[1].terminal == 0u);
  } else if (owner->command == SG_CASE_NEXT_CONTROL) {
    SG_REQUIRE(owner->sustained && owner->probes[1].borrowed_bytes < SG_CONTROL_EXCHANGES);
    owner->pending[1] = mem_get_buffer(mem_global(), 1u);
    SG_REQUIRE(owner->pending[1] != NULL);
    *mem_buffer_data(owner->pending[1]) = (unsigned char)(0x60u + owner->shard);
    mem_set_used(owner->pending[1], 1u);
    SG_REQUIRE(cnet_receive(&owner->clients[1], owner->connections[1], 1u) == SALTS_OK);
    SG_REQUIRE(cnet_send_buffer(&owner->clients[1], owner->connections[1], owner->pending[1]) == SALTS_OK);
    mem_buffer_release(owner->pending[1]);
    owner->pending[1] = NULL;
  } else if (owner->command == SG_CASE_FINISH_LOAD) {
    native_io_backend *backend = owner->backend;
    SG_REQUIRE(owner->sustained && owner->saturated_rounds >= SG_CONTROL_EXCHANGES);
    SG_REQUIRE(owner->probes[0].sent == owner->bulk_admitted && owner->bulk_admitted > SG_LOAD_OPERATIONS);
    SG_REQUIRE(owner->probes[1].sent == SG_CONTROL_EXCHANGES &&
               owner->probes[1].borrowed_bytes == SG_CONTROL_EXCHANGES);
    SG_REQUIRE(mem_buffer_ref_count(owner->pending[0]) == 1u);
    SG_REQUIRE(native_io_sharded_context_release_host(context, owner->lease) == SALTS_EBUSY);
    sg_case_cleanup(context, owner);
    SG_REQUIRE(owner->clients[0].impl == NULL && owner->clients[1].impl == NULL && !owner->host_active);
    SG_REQUIRE(owner->probes[0].terminal == 1u && owner->probes[1].terminal == 1u &&
               owner->probes[0].failed == 0u && owner->probes[1].failed == 0u);
    SG_REQUIRE(native_io_backend_get_stats(backend, &stats) && stats.active_requests == 0u && stats.endpoint_count == 0u);
  } else if (owner->command == SG_CASE_TLS_STEP) {
    SG_REQUIRE(owner->tls_failure);
    SG_REQUIRE(sg_case_progress(context, owner) == SALTS_OK);
    SG_REQUIRE(owner->probes[0].failed <= 1u && owner->probes[0].connected == 0u &&
               owner->probes[0].sent == 0u && owner->probes[0].borrowed_bytes == 0u &&
               owner->probes[1].failed == 0u);
  } else if (owner->command == SG_CASE_TLS_RELEASE) {
    SG_REQUIRE(owner->tls_failure && owner->probes[0].terminal == 1u && owner->probes[0].failed == 1u);
    SG_REQUIRE(owner->probes[0].last_error_status != SALTS_OK &&
               owner->probes[0].last_error_status != SALTS_ETIMEDOUT &&
               strcmp(owner->probes[0].failure_stage, "handshake") == 0);
    SG_REQUIRE(cnet_client_stop_external(&owner->clients[0]) == SALTS_OK);
    SG_REQUIRE(cnet_client_destroy(&owner->clients[0]) == SALTS_OK);
    SG_REQUIRE(owner->probes[1].borrowed_bytes == 1u && owner->probes[1].terminal == 0u);
    SG_REQUIRE(native_io_backend_get_stats(owner->backend, &stats) && stats.active_requests == 0u &&
               stats.endpoint_count == 1u && stats.admission_open);
    SG_REQUIRE(native_io_sharded_context_release_host(context, owner->lease) == SALTS_EBUSY);
  } else if (owner->command == SG_CASE_STEP) {
    SG_REQUIRE(sg_case_progress(context, owner) == SALTS_OK);
    SG_REQUIRE(owner->probes[0].failed == 0u && owner->probes[1].failed == 0u);
  } else if (owner->command == SG_CASE_CLOSE_BULK) {
    SG_REQUIRE(owner->probes[0].sent == 1u && owner->probes[0].last_send_bytes == SG_BULK_BYTES);
    SG_REQUIRE(owner->probes[1].sent == 1u && owner->probes[1].last_send_bytes == 1u);
    SG_REQUIRE(cnet_close(&owner->clients[0], owner->connections[0]) == SALTS_OK);
    SG_REQUIRE(cnet_client_advance_external(&owner->clients[0], &events) == SALTS_OK);
    SG_REQUIRE(owner->probes[0].terminal == 1u && owner->probes[0].sends_at_terminal == 1u);
    SG_REQUIRE(cnet_client_stop_external(&owner->clients[0]) == SALTS_OK);
    SG_REQUIRE(cnet_client_destroy(&owner->clients[0]) == SALTS_OK);
    SG_REQUIRE(native_io_sharded_context_release_host(context, owner->lease) == SALTS_EBUSY);
  } else if (owner->command == SG_CASE_CHECK_BORROW) {
    SG_REQUIRE(owner->clients[0].impl == NULL && owner->clients[1].impl != NULL);
    SG_REQUIRE(owner->probes[1].borrowed_bytes == 0u && owner->probes[1].terminal == 0u);
    SG_REQUIRE(native_io_backend_get_stats(owner->backend, &stats));
    SG_REQUIRE(stats.active_requests == 1u && stats.endpoint_count == (owner->mixed ? 2u : 1u) &&
                 stats.admission_open);
    if (owner->mixed) {
      SG_REQUIRE(owner->sg_terminals == 1u && owner->sg_finalized == 1u && owner->sg_routed == 1u);
      SG_REQUIRE(owner->injected_unknown && !owner->sg_active);
      SG_REQUIRE(sg_case_submit_owned(context, owner) == SALTS_OK);
      SG_REQUIRE(native_io_sharded_context_cancel(context, owner->sg_request) == SALTS_OK);
      SG_REQUIRE(owner->sg_active && owner->sg_terminals == 1u && owner->sg_finalized == 1u);
    }
  } else if (owner->command == SG_CASE_FINAL_CONTROL) {
    if (owner->mixed)
      SG_REQUIRE(!owner->sg_active && owner->sg_terminals == 2u &&
                   owner->sg_finalized == 2u && owner->sg_routed == 2u);
    SG_REQUIRE(owner->probes[1].borrowed_bytes == 1u &&
               owner->probes[1].borrowed_data[0] == (unsigned char)(0xc0u + owner->shard));
    owner->pending[1] = mem_get_buffer(mem_global(), 1u);
    SG_REQUIRE(owner->pending[1] != NULL);
    *mem_buffer_data(owner->pending[1]) = (char)(0xe0u + owner->shard);
    mem_set_used(owner->pending[1], 1u);
    SG_REQUIRE(cnet_send_buffer_and_close(&owner->clients[1], owner->connections[1],
                                          owner->pending[1]) == SALTS_OK);
    mem_buffer_release(owner->pending[1]);
    owner->pending[1] = NULL;
  } else if (owner->command == SG_CASE_FINISH) {
    if (owner->tls_failure) {
      SG_REQUIRE(owner->probes[0].connected == 0u && owner->probes[0].sent == 0u &&
                 owner->probes[0].terminal == 1u && owner->probes[0].failed == 1u);
    } else {
      SG_REQUIRE(owner->probes[0].connected == 1u && owner->probes[0].sent == 1u &&
                 owner->probes[0].terminal == 1u && owner->probes[0].failed == 0u);
    }
    SG_REQUIRE(owner->probes[1].connected == 1u && owner->probes[1].sent == 2u &&
               owner->probes[1].terminal == 1u && owner->probes[1].sends_at_terminal == 2u &&
               owner->probes[1].failed == 0u && owner->observations != 0u);
    SG_REQUIRE(cnet_client_stop_external(&owner->clients[1]) == SALTS_OK);
    SG_REQUIRE(cnet_client_destroy(&owner->clients[1]) == SALTS_OK);
    SG_REQUIRE(sg_case_release_owned(context, owner) == SALTS_OK);
    if (owner->mixed)
      SG_REQUIRE(owner->sg_terminals == 2u && owner->sg_finalized == 2u && owner->sg_routed == 2u);
    SG_REQUIRE(native_io_backend_get_stats(owner->backend, &stats));
    SG_REQUIRE(stats.active_requests == 0u && stats.endpoint_count == 0u && stats.admission_open);
    SG_REQUIRE(native_io_sharded_context_release_host(context, owner->lease) == SALTS_OK);
    owner->host_active = false;
    owner->backend = NULL;
    SG_REQUIRE(cnet_listener_close(&owner->listener) == SALTS_OK);
    SG_REQUIRE(cnet_listener_destroy(&owner->listener) == SALTS_OK);
  }
#undef SG_REQUIRE
}

static int sg_case_run_all(native_io_sharded *runtime, sg_owner_case *owners,
                            size_t count, int command) {
  int first = SALTS_OK;
  for (size_t i = 0u; i < count; ++i) {
    const native_io_sharded_task task = {sg_case_task, NULL, NULL, &owners[i]};
    owners[i].command = command;
    const int status = native_io_sharded_submit_to(runtime, i, &task);
    if (first == SALTS_OK && status != SALTS_OK) first = status;
  }
  const int waited = native_io_sharded_wait(runtime);
  if (first == SALTS_OK && waited != SALTS_OK) first = waited;
  if (command != SG_CASE_CLEANUP) {
    for (size_t i = 0u; i < count; ++i) {
      if (owners[i].failure == 0) continue;
      fprintf(stderr, "SG owner %zu/%zu failed at source line %d\n", i, count, owners[i].failure);
      if (first == SALTS_OK) first = SALTS_EIO;
    }
  }
  return first;
}

static int saltscore_native_entry_test_cnet_sg_owners(size_t owner_count, bool mixed) {
  native_io_sharded *runtime = NULL;
  const native_io_sharded_config config = {owner_count, 8u, {backend_kind(), 4u, 8u, 8u}};
  sg_owner_case *owners = NULL;
  unsigned char *received = NULL;
  native_io_sharded_stats stats = NATIVE_IO_SHARDED_STATS_V1_INITIALIZER;
  uint64_t deadline;
  bool complete;
  int result = 0;
  owners = calloc(owner_count, sizeof(*owners));
  VERIFY(owners != NULL);
  for (size_t i = 0u; i < owner_count; ++i) {
    owners[i].shard = i;
    owners[i].owner_count = owner_count;
    owners[i].mixed = mixed;
    owners[i].peers[0] = owners[i].peers[1] = TEST_INVALID_SOCKET;
    owners[i].sg_socket = owners[i].sg_peer = TEST_INVALID_SOCKET;
  }
  received = malloc(SG_BULK_BYTES);
  VERIFY(received != NULL);
  VERIFY(native_io_sharded_create(&config, &runtime) == SALTS_OK);
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_START) == SALTS_OK);
  if (mixed) {
    for (size_t i = 0u; i < owner_count; ++i) {
      const unsigned char byte = (unsigned char)(0xa0u + i);
      VERIFY(sendto(owners[i].sg_peer, (const char *)&byte, 1, 0,
                      (const struct sockaddr *)&owners[i].sg_address,
                      (int)sizeof(owners[i].sg_address)) == 1);
    }
  }
  for (size_t i = 0u; i < owner_count; ++i)
    for (size_t j = 0u; j < i; ++j)
      VERIFY(owners[i].thread != owners[j].thread && owners[i].backend != owners[j].backend);
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_EBUSY);
  deadline = cmeta_monotonic_ms() + 5000u;
  do {
    VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_STEP) == SALTS_OK);
    complete = true;
    for (size_t i = 0u; i < owner_count; ++i)
      complete = complete && owners[i].probes[0].sent == 1u && owners[i].probes[1].sent == 1u &&
                 (!mixed || owners[i].sg_finalized == 1u);
  } while (!complete && cmeta_monotonic_ms() < deadline);
  VERIFY(complete);
  for (size_t i = 0u; i < owner_count; ++i) {
    VERIFY(test_recv_exact(owners[i].peers[0], received, SG_BULK_BYTES) == 0);
    for (size_t j = 0u; j < SG_BULK_BYTES; ++j)
      VERIFY(received[j] == (unsigned char)((j * 29u + 3u + i * 17u) & 0xffu));
    VERIFY(test_recv_exact(owners[i].peers[1], received, 1u) == 0);
    VERIFY(received[0] == (unsigned char)(0x60u + i));
  }
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_CLOSE_BULK) == SALTS_OK);
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_EBUSY);
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_CHECK_BORROW) == SALTS_OK);
  for (size_t i = 0u; i < owner_count; ++i) {
    unsigned char byte = (unsigned char)(0xc0u + i);
    VERIFY(recv(owners[i].peers[0], (char *)received, 1, 0) == 0);
    VERIFY(send(owners[i].peers[1], (const char *)&byte, 1, 0) == 1);
  }
  deadline = cmeta_monotonic_ms() + 5000u;
  do {
    VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_STEP) == SALTS_OK);
    complete = true;
    for (size_t i = 0u; i < owner_count; ++i)
      complete = complete && owners[i].probes[1].borrowed_bytes == 1u &&
                 (!mixed || owners[i].sg_finalized == 2u);
  } while (!complete && cmeta_monotonic_ms() < deadline);
  VERIFY(complete);
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_FINAL_CONTROL) == SALTS_OK);
  deadline = cmeta_monotonic_ms() + 5000u;
  do {
    VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_STEP) == SALTS_OK);
    complete = true;
    for (size_t i = 0u; i < owner_count; ++i)
      complete = complete && owners[i].probes[1].terminal == 1u;
  } while (!complete && cmeta_monotonic_ms() < deadline);
  VERIFY(complete);
  for (size_t i = 0u; i < owner_count; ++i) {
    VERIFY(test_recv_exact(owners[i].peers[1], received, 1u) == 0);
    VERIFY(received[0] == (unsigned char)(0xe0u + i));
    VERIFY(recv(owners[i].peers[1], (char *)received, 1, 0) == 0);
    for (size_t j = 0u; j < 2u; ++j) {
      test_close_socket(owners[i].peers[j]);
      owners[i].peers[j] = TEST_INVALID_SOCKET;
    }
  }
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_FINISH) == SALTS_OK);
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_OK);
  VERIFY(native_io_sharded_wait(runtime) == SALTS_OK);
  VERIFY(native_io_sharded_get_stats(runtime, &stats));
  VERIFY(stats.shard_count == owner_count && stats.active_command_slots == 0u && !stats.accepting);
  VERIFY(native_io_sharded_destroy(runtime) == SALTS_OK);
  runtime = NULL;

cleanup:
  if (owners != NULL) {
    for (size_t i = 0u; i < owner_count; ++i) {
      test_close_socket(owners[i].sg_peer);
      owners[i].sg_peer = TEST_INVALID_SOCKET;
      for (size_t j = 0u; j < 2u; ++j) {
        test_close_socket(owners[i].peers[j]);
        owners[i].peers[j] = TEST_INVALID_SOCKET;
      }
    }
  }
  if (runtime != NULL) {
    (void)sg_case_run_all(runtime, owners, owner_count, SG_CASE_CLEANUP);
    if (native_io_sharded_destroy(runtime) == SALTS_OK) runtime = NULL;
  }
  /* Preserve callback storage on a failing runtime teardown instead of leaving
   * a borrowed host-quiescence pointer dangling. The failing test reports it. */
  if (runtime == NULL) free(owners);
  free(received);
  return result;
}

/* Main owns unassociated native peers between SG submit/wait boundaries.
 * Bound peer work per turn too, so an always-readable bulk stream cannot
 * starve the control peer in the test driver itself. */
static int sg_load_read_bulk(sg_owner_case *owner, size_t *received) {
  unsigned char bytes[SG_BULK_BYTES];
  for (size_t pass = 0u; pass < SG_LOAD_OPERATIONS; ++pass) {
    const int count = (int)recv(owner->peers[0], (char *)bytes, sizeof(bytes), 0);
    if (count < 0 && test_would_block()) return SALTS_OK;
    if (count <= 0) return SALTS_EIO;
    for (int j = 0; j < count; ++j)
      if (bytes[j] != (unsigned char)(((*received + (size_t)j) * 29u + 3u + owner->shard * 17u) & 0xffu))
        return SALTS_EPROTO;
    *received += (size_t)count;
    if (*received > owner->bulk_admitted * SG_BULK_BYTES) return SALTS_EPROTO;
  }
  return SALTS_OK;
}

static int saltscore_native_entry_test_cnet_sg_sustained(size_t owner_count) {
  native_io_sharded *runtime = NULL;
  const native_io_sharded_config config = {owner_count, 8u, {backend_kind(), 4u, 8u, 8u}};
  sg_owner_case *owners = NULL;
  size_t received[4] = {0};
  native_io_sharded_stats stats = NATIVE_IO_SHARDED_STATS_V1_INITIALIZER;
  int result = 0;
  VERIFY(owner_count == 1u || owner_count == 2u || owner_count == 4u);
  owners = calloc(owner_count, sizeof(*owners));
  VERIFY(owners != NULL);
  for (size_t i = 0u; i < owner_count; ++i) {
    owners[i].shard = i;
    owners[i].owner_count = owner_count;
    owners[i].sustained = true;
    owners[i].peers[0] = owners[i].peers[1] = TEST_INVALID_SOCKET;
    owners[i].sg_socket = owners[i].sg_peer = TEST_INVALID_SOCKET;
  }
  VERIFY(native_io_sharded_create(&config, &runtime) == SALTS_OK);
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_START) == SALTS_OK);
  for (size_t i = 0u; i < owner_count; ++i) {
    VERIFY(test_nonblocking(owners[i].peers[0]) == 0 && test_nonblocking(owners[i].peers[1]) == 0);
    for (size_t j = 0u; j < i; ++j)
      VERIFY(owners[i].thread != owners[j].thread && owners[i].backend != owners[j].backend);
  }
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_EBUSY);
  for (unsigned exchange = 0u; exchange < SG_CONTROL_EXCHANGES; ++exchange) {
    bool request_seen[4] = {false}, reply_sent[4] = {false}, complete = false;
    if (exchange != 0u)
      VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_NEXT_CONTROL) == SALTS_OK);
    /* The bound counts existing host observe/route turns, not elapsed latency
     * or a guarantee about arbitrary OS scheduling and offered workloads. */
    for (size_t round = 0u; round < SG_CONTROL_PROGRESS_BOUND && !complete; ++round) {
      VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_LOAD) == SALTS_OK);
      complete = true;
      for (size_t i = 0u; i < owner_count; ++i) {
        unsigned char byte = 0u;
        const unsigned char reply = (unsigned char)(0xc0u + exchange + i * SG_CONTROL_EXCHANGES);
        VERIFY(sg_load_read_bulk(&owners[i], &received[i]) == SALTS_OK);
        if (!request_seen[i]) {
          const int count = (int)recv(owners[i].peers[1], (char *)&byte, 1, 0);
          VERIFY(count == 1 || (count < 0 && test_would_block()));
          if (count == 1) {
            VERIFY(byte == (unsigned char)(0x60u + i));
            request_seen[i] = true;
          }
        }
        if (request_seen[i] && !reply_sent[i]) {
          const int count = (int)send(owners[i].peers[1], (const char *)&reply, 1, 0);
          VERIFY(count == 1 || (count < 0 && test_would_block()));
          reply_sent[i] = count == 1;
        }
        if (owners[i].probes[1].borrowed_bytes == exchange + 1u)
          VERIFY(owners[i].probes[1].borrowed_data[exchange] == reply);
        complete = complete && reply_sent[i] && owners[i].probes[1].borrowed_bytes == exchange + 1u &&
                   owners[i].probes[1].sent == exchange + 1u;
        VERIFY(owners[i].bulk_admitted > owners[i].probes[0].sent);
      }
    }
    if (!complete) {
      for (size_t i = 0u; i < owner_count; ++i)
        fprintf(stderr, "SG control exchange %u owner %zu/%zu: request=%d reply=%d sent=%u received=%u bulk=%u/%zu observations=%zu\n",
                exchange, i, owner_count, (int)request_seen[i], (int)reply_sent[i],
                owners[i].probes[1].sent, owners[i].probes[1].borrowed_bytes,
                owners[i].probes[0].sent, owners[i].bulk_admitted, owners[i].observations);
    }
    VERIFY(complete);
  }
  /* Stop replenishment, then observe every admitted bulk terminal and read
   * every actual peer byte before closing either client or releasing storage. */
  const uint64_t deadline = cmeta_monotonic_ms() + 5000u;
  bool drained = false;
  do {
    VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_STEP) == SALTS_OK);
    drained = true;
    for (size_t i = 0u; i < owner_count; ++i) {
      VERIFY(sg_load_read_bulk(&owners[i], &received[i]) == SALTS_OK);
      drained = drained && owners[i].probes[0].sent == owners[i].bulk_admitted &&
                received[i] == owners[i].bulk_admitted * SG_BULK_BYTES;
    }
  } while (!drained && cmeta_monotonic_ms() < deadline);
  VERIFY(drained);
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_EBUSY);
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_FINISH_LOAD) == SALTS_OK);
  for (size_t i = 0u; i < owner_count; ++i) {
    for (size_t j = 0u; j < 2u; ++j) {
      unsigned char byte;
      VERIFY(test_blocking(owners[i].peers[j]) == 0);
      VERIFY(recv(owners[i].peers[j], (char *)&byte, 1, 0) == 0);
    }
  }
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_OK);
  VERIFY(native_io_sharded_wait(runtime) == SALTS_OK);
  VERIFY(native_io_sharded_get_stats(runtime, &stats) && stats.active_command_slots == 0u && !stats.accepting);
  VERIFY(native_io_sharded_destroy(runtime) == SALTS_OK);
  runtime = NULL;
cleanup:
  if (owners != NULL) {
    for (size_t i = 0u; i < owner_count; ++i)
      for (size_t j = 0u; j < 2u; ++j) {
        test_close_socket(owners[i].peers[j]);
        owners[i].peers[j] = TEST_INVALID_SOCKET;
      }
  }
  if (runtime != NULL) {
    (void)sg_case_run_all(runtime, owners, owner_count, SG_CASE_CLEANUP);
    if (native_io_sharded_destroy(runtime) == SALTS_OK) runtime = NULL;
  }
  if (runtime == NULL) free(owners);
  return result;
}

/* A native peer sends an invalid TLS record after its plain TCP neighbor has
 * already made progress. Failure is real parser/handshake admission, not a
 * fabricated NativeIO completion or a certificate-authentication claim. */
static int saltscore_native_entry_test_cnet_sg_tls_failure(size_t owner_count) {
  native_io_sharded *runtime = NULL;
  const native_io_sharded_config config = {owner_count, 8u, {backend_kind(), 4u, 8u, 8u}};
  const unsigned char malformed_record[] = {0x7fu, 0x03u, 0x03u, 0x00u, 0x01u, 0x00u};
  sg_owner_case *owners = NULL;
  native_io_sharded_stats stats = NATIVE_IO_SHARDED_STATS_V1_INITIALIZER;
  unsigned char bytes[256];
  uint64_t deadline;
  bool complete;
  int result = 0;
  owners = calloc(owner_count, sizeof(*owners));
  VERIFY(owners != NULL);
  for (size_t i = 0u; i < owner_count; ++i) {
    owners[i].shard = i;
    owners[i].owner_count = owner_count;
    owners[i].tls_failure = true;
    owners[i].peers[0] = owners[i].peers[1] = TEST_INVALID_SOCKET;
    owners[i].sg_socket = owners[i].sg_peer = TEST_INVALID_SOCKET;
  }
  VERIFY(native_io_sharded_create(&config, &runtime) == SALTS_OK);
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_START) == SALTS_OK);
  for (size_t i = 0u; i < owner_count; ++i)
    for (size_t j = 0u; j < i; ++j)
      VERIFY(owners[i].thread != owners[j].thread && owners[i].backend != owners[j].backend);
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_EBUSY);
  deadline = cmeta_monotonic_ms() + 5000u;
  do {
    VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_TLS_STEP) == SALTS_OK);
    complete = true;
    for (size_t i = 0u; i < owner_count; ++i) {
      VERIFY(owners[i].probes[0].terminal == 0u);
      complete = complete && owners[i].probes[1].sent == 1u;
    }
  } while (!complete && cmeta_monotonic_ms() < deadline);
  VERIFY(complete);
  for (size_t i = 0u; i < owner_count; ++i) {
    const unsigned char reply = (unsigned char)(0xc0u + i);
    VERIFY(test_recv_exact(owners[i].peers[1], bytes, 1u) == 0 && bytes[0] == (unsigned char)(0x60u + i));
    VERIFY(send(owners[i].peers[0], (const char *)malformed_record, sizeof(malformed_record), 0) == sizeof(malformed_record));
    VERIFY(send(owners[i].peers[1], (const char *)&reply, 1, 0) == 1);
  }
  deadline = cmeta_monotonic_ms() + 5000u;
  do {
    VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_TLS_STEP) == SALTS_OK);
    complete = true;
    for (size_t i = 0u; i < owner_count; ++i)
      complete = complete && owners[i].probes[0].terminal == 1u && owners[i].probes[1].borrowed_bytes == 1u;
  } while (!complete && cmeta_monotonic_ms() < deadline);
  VERIFY(complete);
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_TLS_RELEASE) == SALTS_OK);
  for (size_t i = 0u; i < owner_count; ++i) {
    size_t wire_bytes = 0u;
    int count;
    /* Drain any fatal handshake alert before requiring EOF. No handshake
     * ciphertext is interpreted as successful CNet application delivery. */
    do {
      count = (int)recv(owners[i].peers[0], (char *)bytes, sizeof(bytes), 0);
      VERIFY(count >= 0);
      wire_bytes += (size_t)count;
      VERIFY(wire_bytes <= CNET_TLS_MIN_IO_BUFFER_BYTES);
    } while (count != 0);
    VERIFY(owners[i].probes[0].borrowed_bytes == 0u && owners[i].probes[0].sent == 0u);
  }
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_EBUSY);
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_FINAL_CONTROL) == SALTS_OK);
  deadline = cmeta_monotonic_ms() + 5000u;
  do {
    VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_TLS_STEP) == SALTS_OK);
    complete = true;
    for (size_t i = 0u; i < owner_count; ++i)
      complete = complete && owners[i].probes[1].terminal == 1u;
  } while (!complete && cmeta_monotonic_ms() < deadline);
  VERIFY(complete);
  for (size_t i = 0u; i < owner_count; ++i) {
    VERIFY(test_recv_exact(owners[i].peers[1], bytes, 1u) == 0 && bytes[0] == (unsigned char)(0xe0u + i));
    VERIFY(recv(owners[i].peers[1], (char *)bytes, 1, 0) == 0);
  }
  VERIFY(sg_case_run_all(runtime, owners, owner_count, SG_CASE_FINISH) == SALTS_OK);
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_OK);
  VERIFY(native_io_sharded_wait(runtime) == SALTS_OK);
  VERIFY(native_io_sharded_get_stats(runtime, &stats) && stats.active_command_slots == 0u && !stats.accepting);
  VERIFY(native_io_sharded_destroy(runtime) == SALTS_OK);
  runtime = NULL;
cleanup:
  if (owners != NULL) {
    for (size_t i = 0u; i < owner_count; ++i)
      for (size_t j = 0u; j < 2u; ++j) {
        test_close_socket(owners[i].peers[j]);
        owners[i].peers[j] = TEST_INVALID_SOCKET;
      }
  }
  if (runtime != NULL) {
    (void)sg_case_run_all(runtime, owners, owner_count, SG_CASE_CLEANUP);
    if (native_io_sharded_destroy(runtime) == SALTS_OK) runtime = NULL;
  }
  if (runtime == NULL) free(owners);
  return result;
}

enum { MATCHED_BYTES = 32768, MATCHED_MAX_OPERATIONS = 2048 };
typedef enum matched_mode { MATCHED_CNET, MATCHED_CALLBACK, MATCHED_NATIVEIO } matched_mode;
typedef struct matched_fixture {
  tcp_probe io;
  resource_probe storage;
  cnet_listener listener;
  cnet_client client;
  native_io_backend backend;
  cnet_connection connection;
  test_socket peer;
  test_socket raw_listener, raw_socket;
  native_io_endpoint raw_endpoint;
  native_io_request raw_request;
  matched_mode mode;
  bool raw_retained;
  size_t raw_offset, raw_chunk;
  mem_buffer_t *source;
  size_t window, calls, offered, completed;
  uint64_t starts[MATCHED_MAX_OPERATIONS], latency[MATCHED_MAX_OPERATIONS];
} matched_fixture;
typedef struct matched_result {
  uint64_t elapsed_ns, cpu_ns, p50_ns, p95_ns, p99_ns, drain_ns;
  uint64_t native_submissions;
  size_t bytes, rejected, peak_bytes, peak_backing, allocations, policy_calls;
} matched_result;

static size_t matched_size(size_t index) { return index % 8u == 0u ? 1u : MATCHED_BYTES; }
static const char *matched_name(matched_mode mode) {
  return mode == MATCHED_NATIVEIO ? "nativeio" : mode == MATCHED_CALLBACK ? "callback" : "native";
}
static void matched_state(void *user, cnet_connection connection, cnet_connection_state state,
                            const cnet_error *error) {
  on_state(&((matched_fixture *)user)->io, connection, state, error);
}
static void matched_sent(void *user, cnet_connection connection, size_t bytes) {
  matched_fixture *f = user;
  (void)connection;
  if (f->completed >= f->offered || f->completed >= MATCHED_MAX_OPERATIONS ||
      bytes != matched_size(f->completed)) { ++f->io.failed; return; }
  f->latency[f->completed] = cmeta_hrtime() - f->starts[f->completed];
  ++f->completed;
}
static int matched_admit(void *user, const cnet_send_usage *total,
                           const cnet_send_usage *connection, size_t bytes, size_t backing) {
  matched_fixture *f = user;
  (void)backing;
  ++f->calls;
  return total->operations < f->window && connection->operations < f->window &&
         bytes <= f->window * MATCHED_BYTES - total->bytes ? SALTS_OK : SALTS_ENOBUFS;
}
static int matched_cpu_ns(uint64_t *out) {
#if defined(_WIN32)
  FILETIME created, exited, kernel, user;
  if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return SALTS_EIO;
  *out = ((((uint64_t)kernel.dwHighDateTime << 32u) | kernel.dwLowDateTime) +
          (((uint64_t)user.dwHighDateTime << 32u) | user.dwLowDateTime)) * UINT64_C(100);
#else
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0) return SALTS_EIO;
  *out = ((uint64_t)usage.ru_utime.tv_sec + (uint64_t)usage.ru_stime.tv_sec) * UINT64_C(1000000000) +
         ((uint64_t)usage.ru_utime.tv_usec + (uint64_t)usage.ru_stime.tv_usec) * UINT64_C(1000);
#endif
  return SALTS_OK;
}
static int matched_compare_ns(const void *a, const void *b) {
  const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}

static int matched_raw_submit(matched_fixture *f) {
  const size_t remaining = matched_size(f->completed) - f->raw_offset;
  const native_io_buffer_span span = {mem_buffer_data(f->source) + f->raw_offset,
      remaining < f->raw_chunk ? remaining : f->raw_chunk};
  const native_io_vector_operation operation = {NATIVE_IO_OPERATION_STREAM_SEND,
      f->raw_endpoint, &span, 1u, f->completed + 1u};
  return native_io_backend_submit_vector(&f->backend, &operation, &f->raw_request);
}
static int matched_offer(matched_fixture *f, const mem_slice_t *slice) {
  if (f->mode != MATCHED_NATIVEIO) return cnet_send_slice(&f->client, f->connection, slice);
  if (f->raw_retained) return SALTS_ENOBUFS;
  mem_buffer_retain(f->source);
  f->raw_retained = true;
  f->raw_offset = 0u;
  const int status = matched_raw_submit(f);
  if (status != SALTS_OK) { f->raw_retained = false; mem_buffer_release(f->source); }
  return status;
}
static int matched_usage(matched_fixture *f, cnet_send_usage *out) {
  if (f->mode != MATCHED_NATIVEIO) return cnet_client_send_usage(&f->client, f->connection, out);
  *out = (cnet_send_usage){0};
  if (f->raw_retained)
    *out = (cnet_send_usage){1u, matched_size(f->completed), mem_buffer_capacity(f->source)};
  return SALTS_OK;
}
static int matched_raw_route(matched_fixture *f, const native_io_completion *completion) {
  if (!f->raw_retained || !native_io_request_valid(f->raw_request) ||
      completion->endpoint.slot != f->raw_endpoint.slot ||
      completion->endpoint.generation != f->raw_endpoint.generation ||
      completion->request.slot != f->raw_request.slot ||
      completion->request.generation != f->raw_request.generation ||
      completion->user_data != f->completed + 1u) return SALTS_EPROTO;
  f->raw_request = (native_io_request){0}; /* This actual observe retired the native borrow. */
  if (completion->kind != NATIVE_IO_COMPLETION_OK || completion->status != SALTS_OK)
    return completion->status < SALTS_OK ? completion->status : SALTS_EIO;
  const size_t logical_bytes = matched_size(f->completed);
  const size_t remaining = logical_bytes - f->raw_offset;
  const size_t submitted_bytes = remaining < f->raw_chunk ? remaining : f->raw_chunk;
  if (completion->bytes == 0u || completion->bytes > submitted_bytes) return SALTS_EPROTO;
  f->raw_offset += completion->bytes;
  if (f->raw_offset != logical_bytes) return matched_raw_submit(f);
  mem_buffer_release(f->source);
  f->raw_retained = false;
  matched_sent(f, (cnet_connection){0}, logical_bytes);
  return SALTS_OK;
}

/* Setup/warm-up and close are outside this measured transfer. Both modes
 * include the same bounded host/peer progress and exact byte checks. */
static int matched_transfer(matched_fixture *f, size_t operations, matched_result *out) {
  unsigned char bytes[65536];
  size_t received = 0u, expected = 0u, events = 0u, receive_operation = 0u, receive_offset = 0u;
  const size_t allocations = f->storage.allocated, calls = f->calls;
  native_io_backend_stats before, after;
  if (!native_io_backend_get_stats(&f->backend, &before) || before.active_requests != 0u) return SALTS_EBUSY;
  uint64_t cpu_start, cpu_end;
  const uint64_t start = cmeta_hrtime(), deadline = start + UINT64_C(10000000000);
  *out = (matched_result){0};
  f->offered = f->completed = 0u;
  if (operations == 0u || operations > MATCHED_MAX_OPERATIONS || matched_cpu_ns(&cpu_start) != SALTS_OK)
    return SALTS_EINVAL;
  for (size_t i = 0u; i < operations; ++i) expected += matched_size(i);
  while ((f->completed != operations || received != expected) && cmeta_hrtime() < deadline) {
    while (f->offered < operations && f->offered - f->completed < f->window) {
      mem_slice_t slice = mem_slice(f->source, 0u, matched_size(f->offered));
      f->starts[f->offered] = cmeta_hrtime();
      const int status = matched_offer(f, &slice);
      mem_slice_release(&slice);
      if (status != SALTS_OK) return status;
      ++f->offered;
    }
    cnet_send_usage usage = {0};
    if (matched_usage(f, &usage) != SALTS_OK) return SALTS_EIO;
    if (usage.bytes > out->peak_bytes) out->peak_bytes = usage.bytes;
    if (usage.backing_bytes > out->peak_backing) out->peak_backing = usage.backing_bytes;
    if (f->window == 8u && f->offered < operations && usage.operations == f->window) {
      const unsigned references = mem_buffer_ref_count(f->source);
      mem_slice_t slice = mem_slice(f->source, 0u, matched_size(f->offered));
      const int status = matched_offer(f, &slice);
      mem_slice_release(&slice);
      if (status != SALTS_ENOBUFS || mem_buffer_ref_count(f->source) != references) return SALTS_EPROTO;
      ++out->rejected;
    }
    if (f->mode != MATCHED_NATIVEIO && cnet_client_advance_external(&f->client, &events) != SALTS_OK)
      return SALTS_EIO;
    native_io_completion completions[4];
    size_t count = 0u;
    const int status = native_io_backend_observe(&f->backend, completions, 4u, 0u, &count);
    if (status != SALTS_OK && status != SALTS_ETIMEDOUT) return status;
    int route_status = SALTS_OK;
    for (size_t i = 0u; i < count; ++i) {
      bool consumed = false;
      const int routed = f->mode == MATCHED_NATIVEIO ? matched_raw_route(f, &completions[i])
          : cnet_client_route_external_completion(&f->client, &completions[i], &consumed, &events);
      if (f->mode == MATCHED_NATIVEIO) consumed = routed == SALTS_OK;
      if ((routed != SALTS_OK || !consumed) && route_status == SALTS_OK)
        route_status = routed != SALTS_OK ? routed : SALTS_EPROTO;
    }
    if (route_status != SALTS_OK) return route_status;
    for (size_t pass = 0u; pass < 16u; ++pass) {
      const int count_read = (int)recv(f->peer, (char *)bytes, sizeof(bytes), 0);
      if (count_read < 0 && test_would_block()) break;
      if (count_read <= 0 || (size_t)count_read > expected - received) return SALTS_EIO;
      for (int i = 0; i < count_read; ++i) {
        if (receive_operation >= operations ||
            bytes[i] != (unsigned char)((0x5au + receive_offset * 29u) & 0xffu)) return SALTS_EPROTO;
        if (++receive_offset == matched_size(receive_operation)) { ++receive_operation; receive_offset = 0u; }
      }
      received += (size_t)count_read;
    }
    if (f->io.failed != 0u || f->io.terminal != 0u) return SALTS_EPROTO;
  }
  out->elapsed_ns = cmeta_hrtime() - start;
  if (matched_cpu_ns(&cpu_end) != SALTS_OK || cpu_end < cpu_start) return SALTS_EIO;
  out->cpu_ns = cpu_end - cpu_start;
  if (f->completed != operations || received != expected || receive_operation != operations || receive_offset != 0u)
    return SALTS_ETIMEDOUT;
  cnet_send_usage usage = {0};
  if (matched_usage(f, &usage) != SALTS_OK || usage.operations != 0u ||
      usage.bytes != 0u || usage.backing_bytes != 0u || mem_buffer_ref_count(f->source) != 1u) return SALTS_EPROTO;
  if (!native_io_backend_get_stats(&f->backend, &after) || after.active_requests != 0u) return SALTS_EBUSY;
  out->native_submissions = after.submitted - before.submitted;
  out->allocations = f->storage.allocated - allocations;
  out->policy_calls = f->calls - calls;
  out->bytes = expected;
  qsort(f->latency, operations, sizeof(f->latency[0]), matched_compare_ns);
  out->p50_ns = f->latency[(operations * 50u + 99u) / 100u - 1u];
  out->p95_ns = f->latency[(operations * 95u + 99u) / 100u - 1u];
  out->p99_ns = f->latency[(operations * 99u + 99u) / 100u - 1u];
  return SALTS_OK;
}

static int matched_sample(matched_mode mode, size_t window, size_t operations, bool report,
                             unsigned repetition, size_t raw_chunk) {
  matched_fixture *f = calloc(1u, sizeof(*f));
  cnet_client_config config = client_config();
  const native_io_backend_config backend_config = {backend_kind(), 2u, 4u, 4u};
  const cnet_listener_config listener_config = {backend_kind(), "127.0.0.1", 0u, 2u};
  matched_result warm, measured;
  struct sockaddr_in remote = {0};
  native_io_backend_stats stats;
  uint16_t port = 0u;
  size_t events = 0u;
  int ready = 0, result = 0, transfer_status = SALTS_EIO;
  if (f == NULL) return __LINE__;
  f->peer = f->raw_listener = f->raw_socket = TEST_INVALID_SOCKET;
  f->window = window;
  f->mode = mode;
  f->raw_chunk = raw_chunk;
  config.connection_capacity = 1u;
  config.max_send_bytes = MATCHED_BYTES;
  config.send_limits.operations = window;
  config.resources.storage = (cnet_allocator){probe_allocate, probe_deallocate, &f->storage};
  const cnet_observer observer = {matched_state, NULL, f, matched_sent};
  VERIFY(window == 1u || window == 8u);
  VERIFY(mode != MATCHED_NATIVEIO || (window == 1u && raw_chunk > 0u && raw_chunk <= MATCHED_BYTES));
  if (mode == MATCHED_NATIVEIO) {
    VERIFY(native_io_backend_init(&f->backend, &backend_config) == SALTS_OK);
    f->raw_listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    VERIFY(f->raw_listener != TEST_INVALID_SOCKET);
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    VERIFY(bind(f->raw_listener, (const struct sockaddr *)&remote, sizeof(remote)) == 0);
    VERIFY(listen(f->raw_listener, 2) == 0);
#if defined(_WIN32)
    int address_size = sizeof(remote);
#else
    socklen_t address_size = sizeof(remote);
#endif
    VERIFY(getsockname(f->raw_listener, (struct sockaddr *)&remote, &address_size) == 0);
    f->peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    VERIFY(f->peer != TEST_INVALID_SOCKET && test_recv_timeout(f->peer) == 0);
    VERIFY(connect(f->peer, (const struct sockaddr *)&remote, sizeof(remote)) == 0);
    f->raw_socket = accept(f->raw_listener, NULL, NULL);
    VERIFY(f->raw_socket != TEST_INVALID_SOCKET && test_nonblocking(f->raw_socket) == 0);
    const int enabled = 1;
    VERIFY(setsockopt(f->raw_socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&enabled, sizeof(enabled)) == 0);
    VERIFY(native_io_backend_attach_socket(&f->backend, (uintptr_t)f->raw_socket, &f->raw_endpoint) == SALTS_OK);
    VERIFY(native_io_backend_endpoint_supports_vector_write(&f->backend, f->raw_endpoint));
    test_close_socket(f->raw_listener);
    f->raw_listener = TEST_INVALID_SOCKET;
  } else {
    VERIFY(cnet_listener_init(&f->listener, &listener_config) == SALTS_OK);
    VERIFY(cnet_listener_port(&f->listener, &port) == SALTS_OK);
    VERIFY(native_io_backend_init(&f->backend, &backend_config) == SALTS_OK);
    VERIFY(cnet_client_init_external(&f->client, &config, &f->backend) == SALTS_OK);
    f->peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    VERIFY(f->peer != TEST_INVALID_SOCKET && test_recv_timeout(f->peer) == 0);
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    remote.sin_port = htons(port);
    VERIFY(connect(f->peer, (const struct sockaddr *)&remote, sizeof(remote)) == 0);
    VERIFY(cnet_listener_wait(&f->listener, 5000u, &ready) == SALTS_OK && ready == 1);
    VERIFY(cnet_listener_accept(&f->listener, &f->client, &observer, &f->connection) == SALTS_OK);
    VERIFY(cnet_client_advance_external(&f->client, &events) == SALTS_OK && f->io.connected == 1u);
    VERIFY(cnet_connection_tcp_option_set(&f->client, f->connection, CNET_TCP_SOCKET_NODELAY, 1u) == SALTS_OK);
    VERIFY(cnet_listener_close(&f->listener) == SALTS_OK);
    VERIFY(cnet_listener_destroy(&f->listener) == SALTS_OK);
  }
  VERIFY(test_nonblocking(f->peer) == 0);
  if (mode == MATCHED_CALLBACK) {
    const cnet_send_admission_policy policy = {matched_admit, f};
    VERIFY(cnet_set_send_admission(&f->client, f->connection, &policy) == SALTS_OK);
  }
  f->source = mem_get_buffer(mem_global(), MATCHED_BYTES);
  VERIFY(f->source != NULL);
  for (size_t i = 0u; i < MATCHED_BYTES; ++i)
    mem_buffer_data(f->source)[i] = (char)((0x5au + i * 29u) & 0xffu);
  mem_set_used(f->source, MATCHED_BYTES);
  VERIFY(matched_transfer(f, report ? 64u : 8u, &warm) == SALTS_OK);
  if (report) {
    const size_t expected_bytes = operations / 8u * (7u * MATCHED_BYTES + 1u);
    benchmark_io("matched TCP admission transfer", 1, operations, expected_bytes) {
      transfer_status = matched_transfer(f, operations, &measured);
    }
  } else transfer_status = matched_transfer(f, operations, &measured);
  VERIFY(transfer_status == SALTS_OK && measured.elapsed_ns != 0u && measured.allocations == 0u);
  VERIFY(measured.policy_calls == (mode == MATCHED_CALLBACK ? operations : 0u));
  VERIFY((window == 8u) == (measured.rejected != 0u));
  VERIFY(measured.native_submissions >= operations);
  if (mode == MATCHED_NATIVEIO && raw_chunk < MATCHED_BYTES) VERIFY(measured.native_submissions > operations);
  const uint64_t drain_start = cmeta_hrtime();
  if (mode == MATCHED_NATIVEIO) {
    VERIFY(!f->raw_retained && !native_io_request_valid(f->raw_request));
    test_close_socket(f->raw_socket);
    f->raw_socket = TEST_INVALID_SOCKET;
    VERIFY(native_io_backend_release_socket(&f->backend, f->raw_endpoint) == SALTS_OK);
    f->raw_endpoint = (native_io_endpoint){0};
  } else {
    VERIFY(cnet_close(&f->client, f->connection) == SALTS_OK);
    VERIFY(cnet_client_advance_external(&f->client, &events) == SALTS_OK &&
             f->io.terminal == 1u && f->io.failed == 0u);
  }
  VERIFY(test_blocking(f->peer) == 0);
  unsigned char byte;
  VERIFY(recv(f->peer, (char *)&byte, 1u, 0) == 0);
  VERIFY(native_io_backend_get_stats(&f->backend, &stats) && stats.active_requests == 0u && stats.endpoint_count == 0u);
  measured.drain_ns = cmeta_hrtime() - drain_start;
  test_close_socket(f->peer);
  f->peer = TEST_INVALID_SOCKET;
  if (mode != MATCHED_NATIVEIO) {
    VERIFY(cnet_client_stop_external(&f->client) == SALTS_OK);
    VERIFY(cnet_client_destroy(&f->client) == SALTS_OK);
  }
  VERIFY(native_io_backend_close(&f->backend) == SALTS_OK && native_io_backend_destroy(&f->backend) == SALTS_OK);
  VERIFY(f->storage.allocated == f->storage.released && mem_buffer_ref_count(f->source) == 1u);
  if (report) {
    printf("CNET_POLICY_CSV,%s,%u,%zu,%zu,%zu,%llu,%llu,%llu,%llu,%llu,%zu,%zu,%zu,%zu,%zu,%zu,%llu,%llu\n",
      matched_name(mode), repetition, window, operations, measured.bytes,
      (unsigned long long)measured.elapsed_ns, (unsigned long long)measured.cpu_ns,
      (unsigned long long)measured.p50_ns, (unsigned long long)measured.p95_ns, (unsigned long long)measured.p99_ns,
      measured.rejected, measured.peak_bytes, measured.peak_backing, mem_buffer_capacity(f->source),
      measured.allocations, measured.policy_calls, (unsigned long long)measured.drain_ns,
      (unsigned long long)measured.native_submissions);
  }
cleanup:
  test_close_socket(f->peer);
  test_close_socket(f->raw_listener);
  if (native_io_request_valid(f->raw_request)) {
    (void)native_io_backend_cancel(&f->backend, f->raw_request);
    native_io_completion completion;
    if (observe_external_one(&f->backend, &completion) == SALTS_OK &&
        completion.request.slot == f->raw_request.slot && completion.request.generation == f->raw_request.generation)
      f->raw_request = (native_io_request){0};
  }
  if (!native_io_request_valid(f->raw_request)) {
    if (f->raw_retained) { mem_buffer_release(f->source); f->raw_retained = false; }
    test_close_socket(f->raw_socket);
    f->raw_socket = TEST_INVALID_SOCKET;
    if (native_io_endpoint_valid(f->raw_endpoint))
      (void)native_io_backend_release_socket(&f->backend, f->raw_endpoint);
  }
  if (f->client.impl != NULL) {
    const uint64_t deadline = cmeta_monotonic_ms() + 3000u;
    while (cnet_client_stop_external(&f->client) == SALTS_EBUSY && cmeta_monotonic_ms() < deadline) {
      native_io_completion completions[4];
      size_t count = 0u;
      (void)cnet_client_advance_external(&f->client, &events);
      (void)native_io_backend_observe(&f->backend, completions, 4u, 10u, &count);
      for (size_t i = 0u; i < count; ++i) {
        bool consumed;
        (void)cnet_client_route_external_completion(&f->client, &completions[i], &consumed, &events);
      }
    }
    (void)cnet_client_destroy(&f->client);
  }
  (void)cnet_listener_close(&f->listener);
  (void)cnet_listener_destroy(&f->listener);
  if (f->client.impl == NULL && !native_io_request_valid(f->raw_request)) {
    (void)native_io_backend_close(&f->backend);
    (void)native_io_backend_destroy(&f->backend);
    if (f->backend.impl == NULL && f->listener.impl == NULL) {
      if (f->source) mem_buffer_release(f->source);
      free(f);
      return result;
    }
  }
  return result != 0 ? result : __LINE__; /* Preserve live callback/native storage on failed cleanup. */
}

enum { MIXED_EXCHANGES = 4096 };
typedef enum mixed_profile { MIXED_STEADY, MIXED_STALLED, MIXED_PARTITION } mixed_profile;
typedef struct mixed_fixture {
  matched_fixture lanes[2]; /* bulk, control; both borrow backend below */
  native_io_backend backend;
  cnet_listener listener;
  matched_mode mode;
  native_io_request raw_receive;
  unsigned char raw_reply[256];
  bool raw_stopping;
  bool stalled;
  size_t bulk_bytes, observed_count;
  int observe_status;
  uint64_t send_buffer, peer_buffer;
  size_t bulk_window, bulk_admitted, bulk_received, control_done, target;
  bool control_active, request_seen, reply_sent;
  unsigned char reply;
  uint64_t control_start, rtt[MIXED_EXCHANGES];
} mixed_fixture;
typedef struct mixed_result {
  const char *stage;
  native_io_request stalled_request;
  uint64_t elapsed_ns, cpu_ns, p50_ns, p95_ns, p99_ns, bulk_drain_ns, close_ns, native_submissions;
  size_t bulk_bytes, bulk_admitted, rounds, rejected, allocations, receives, calls;
  size_t peak_bytes, peak_backing;
  uint64_t prime_ns, prime_submissions, resume_submissions;
  size_t empty_observations, resume_bytes;
} mixed_result;

static int mixed_receive_buffer(void *user, size_t bytes, mem_buffer_t **out) {
  resource_probe *p = user;
  *out = mem_get_buffer(mem_global(), bytes);
  if (*out == NULL) return SALTS_ENOMEM;
  ++p->buffers; /* Pool acquisitions, not a claim about malloc calls. */
  return SALTS_OK;
}
static void mixed_bulk_sent(void *user, cnet_connection connection, size_t size) {
  mixed_fixture *f = user;
  if (size != f->bulk_bytes) ++f->lanes[0].io.failed;
  on_sent(&f->lanes[0].io, connection, size);
}
static void mixed_bulk_state(void *user, cnet_connection connection, cnet_connection_state state,
                               const cnet_error *error) {
  on_state(&((mixed_fixture *)user)->lanes[0].io, connection, state, error);
}
static int mixed_admit(void *user, const cnet_send_usage *total,
                         const cnet_send_usage *connection, size_t bytes, size_t backing) {
  matched_fixture *lane = user;
  (void)backing;
  ++lane->calls;
  const size_t limit = lane->window * mem_buffer_used(lane->source);
  return total->operations < lane->window && connection->operations < lane->window &&
      total->bytes <= limit && bytes <= limit - total->bytes ? SALTS_OK : SALTS_ENOBUFS;
}
static void mixed_control_state(void *user, cnet_connection connection, cnet_connection_state state,
                                  const cnet_error *error) {
  on_state(&((mixed_fixture *)user)->lanes[1].io, connection, state, error);
}
static void mixed_control_sent(void *user, cnet_connection connection, size_t size) {
  mixed_fixture *f = user;
  if (size != 1u) ++f->lanes[1].io.failed;
  on_sent(&f->lanes[1].io, connection, size);
}
static void mixed_reply_received(mixed_fixture *f, const void *data, size_t size) {
  if (!f->control_active || f->control_done >= f->target || data == NULL || size != 1u ||
      *(const unsigned char *)data != (unsigned char)(0xc0u + f->control_done)) {
    ++f->lanes[1].io.failed;
    return;
  }
  f->rtt[f->control_done++] = cmeta_hrtime() - f->control_start;
}
static void mixed_control_receive(void *user, cnet_connection connection, const cnet_receive_view *view) {
  mixed_fixture *f = user;
  (void)connection;
  if (view == NULL || view->kind != CNET_MESSAGE_BYTES) { ++f->lanes[1].io.failed; return; }
  mixed_reply_received(f, view->data, view->size);
}
static int mixed_raw_submit(mixed_fixture *f, size_t index) {
  matched_fixture *lane = &f->lanes[index];
  const size_t remaining = mem_buffer_used(lane->source) - lane->raw_offset;
  const native_io_buffer_span span = {mem_buffer_data(lane->source) + lane->raw_offset,
      remaining < lane->raw_chunk ? remaining : lane->raw_chunk};
  const native_io_vector_operation operation = {NATIVE_IO_OPERATION_STREAM_SEND,
      lane->raw_endpoint, &span, 1u, index + 1u};
  return native_io_backend_submit_vector(&f->backend, &operation, &lane->raw_request);
}
static int mixed_offer(mixed_fixture *f, size_t index) {
  matched_fixture *lane = &f->lanes[index];
  if (f->mode != MATCHED_NATIVEIO)
    return cnet_send_buffer(&lane->client, lane->connection, lane->source);
  if (f->raw_stopping) return SALTS_ESHUTDOWN;
  if (lane->raw_retained) return SALTS_ENOBUFS;
  lane->raw_offset = 0u;
  mem_buffer_retain(lane->source);
  lane->raw_retained = true;
  const int status = mixed_raw_submit(f, index);
  if (status != SALTS_OK) { lane->raw_retained = false; mem_buffer_release(lane->source); }
  return status;
}
static int mixed_usage(mixed_fixture *f, size_t index, cnet_send_usage *out) {
  matched_fixture *lane = &f->lanes[index];
  if (f->mode != MATCHED_NATIVEIO)
    return cnet_client_send_usage(&lane->client, lane->connection, out);
  *out = (cnet_send_usage){0};
  if (lane->raw_retained)
    *out = (cnet_send_usage){1u, mem_buffer_used(lane->source), mem_buffer_capacity(lane->source)};
  return SALTS_OK;
}
static bool mixed_raw_matches(const native_io_completion *completion,
                               native_io_endpoint endpoint, native_io_request request) {
  return native_io_request_valid(request) &&
      completion->endpoint.slot == endpoint.slot && completion->endpoint.generation == endpoint.generation &&
      completion->request.slot == request.slot && completion->request.generation == request.generation;
}
static int mixed_raw_route(mixed_fixture *f, const native_io_completion *completion) {
  if (mixed_raw_matches(completion, f->lanes[1].raw_endpoint, f->raw_receive)) {
    f->raw_receive = (native_io_request){0};
    if (completion->user_data != 3u) return SALTS_EPROTO;
    if (f->raw_stopping) return SALTS_OK;
    if (completion->kind != NATIVE_IO_COMPLETION_OK || completion->status != SALTS_OK || completion->bytes != 1u)
      return SALTS_EIO;
    mixed_reply_received(f, f->raw_reply, completion->bytes);
    return SALTS_OK;
  }
  for (size_t index = 0u; index < 2u; ++index) {
    matched_fixture *lane = &f->lanes[index];
    if (!mixed_raw_matches(completion, lane->raw_endpoint, lane->raw_request)) continue;
    lane->raw_request = (native_io_request){0}; /* Real observation ended the native borrow. */
    if (!lane->raw_retained || completion->user_data != index + 1u) return SALTS_EPROTO;
    const size_t size = mem_buffer_used(lane->source), remaining = size - lane->raw_offset;
    const size_t submitted = remaining < lane->raw_chunk ? remaining : lane->raw_chunk;
    int status = SALTS_OK;
    if (!f->raw_stopping) {
      if (completion->kind != NATIVE_IO_COMPLETION_OK || completion->status != SALTS_OK ||
          completion->bytes == 0u || completion->bytes > submitted) status = SALTS_EIO;
      else {
        lane->raw_offset += completion->bytes;
        if (lane->raw_offset != size) {
          status = mixed_raw_submit(f, index);
          if (status == SALTS_OK) return SALTS_OK;
        }
      }
    }
    mem_buffer_release(lane->source);
    lane->raw_retained = false;
    if (status == SALTS_OK && !f->raw_stopping) {
      if (index == 0u) mixed_bulk_sent(f, (cnet_connection){0}, size);
      else mixed_control_sent(f, (cnet_connection){0}, size);
    }
    return status;
  }
  return SALTS_EPROTO;
}
static int mixed_arm_control(mixed_fixture *f) {
  if (f->mode != MATCHED_NATIVEIO)
    return cnet_receive(&f->lanes[1].client, f->lanes[1].connection, 1u);
  if (native_io_request_valid(f->raw_receive)) return SALTS_EBUSY;
  const native_io_operation operation = {.kind = NATIVE_IO_OPERATION_STREAM_RECV,
      .endpoint = f->lanes[1].raw_endpoint, .buffer = f->raw_reply,
      .length = sizeof(f->raw_reply), .user_data = 3u};
  return native_io_backend_submit(&f->backend, &operation, &f->raw_receive);
}
static int mixed_progress(mixed_fixture *f, uint32_t wait_ms) {
  int first_error = SALTS_OK;
  size_t events = 0u;
  for (size_t i = 0u; i < 2u; ++i) {
    if (f->lanes[i].client.impl == NULL) continue;
    const int status = cnet_client_advance_external(&f->lanes[i].client, &events);
    if (status != SALTS_OK && first_error == SALTS_OK) first_error = status;
  }
  native_io_completion completions[4];
  size_t count = 0u;
  const int status = native_io_backend_observe(&f->backend, completions, 4u, wait_ms, &count);
  f->observe_status = status;
  f->observed_count = count;
  if (status != SALTS_OK && status != SALTS_ETIMEDOUT && first_error == SALTS_OK) first_error = status;
  for (size_t i = 0u; i < count; ++i) {
    if (f->mode == MATCHED_NATIVEIO) {
      const int routed = mixed_raw_route(f, &completions[i]);
      if (routed != SALTS_OK && first_error == SALTS_OK) first_error = routed;
      continue;
    }
    bool consumed = false;
    for (size_t j = 0u; j < 2u && !consumed; ++j) {
      if (f->lanes[j].client.impl == NULL) continue;
      const int routed = cnet_client_route_external_completion(&f->lanes[j].client,
                                                               &completions[i], &consumed, &events);
      if (routed != SALTS_OK && first_error == SALTS_OK) first_error = routed;
    }
    if (!consumed && first_error == SALTS_OK) first_error = SALTS_EPROTO;
  }
  return first_error;
}
static int mixed_read_bulk(mixed_fixture *f) {
  unsigned char bytes[65536];
  for (size_t pass = 0u; pass < 16u; ++pass) {
    const int count = (int)recv(f->lanes[0].peer, (char *)bytes, sizeof(bytes), 0);
    if (count < 0 && test_would_block()) return SALTS_OK;
    if (count <= 0 || (size_t)count > f->bulk_admitted * f->bulk_bytes - f->bulk_received) return SALTS_EIO;
    for (int i = 0; i < count; ++i)
      if (bytes[i] != (unsigned char)((0x5au + ((f->bulk_received + (size_t)i) % f->bulk_bytes) * 29u) & 0xffu))
        return SALTS_EPROTO;
    f->bulk_received += (size_t)count;
  }
  return SALTS_OK;
}
static int mixed_pending_bulk(mixed_fixture *f, native_io_request *out) {
  if (f->mode == MATCHED_NATIVEIO) {
    if (!f->lanes[0].raw_retained || !native_io_request_valid(f->lanes[0].raw_request)) return SALTS_EPROTO;
    *out = f->lanes[0].raw_request;
    return SALTS_OK;
  }
  cnet_external_request_snapshot request[2];
  size_t count = 0u;
  const int status = cnet_client_external_request_snapshots(&f->lanes[0].client,
      f->lanes[0].connection, request, 2u, &count);
  if (status != SALTS_OK) return status;
  if (count != 1u || request[0].operation_kind != NATIVE_IO_OPERATION_STREAM_SEND ||
      !native_io_request_valid(request[0].request)) return SALTS_EPROTO;
  *out = request[0].request;
  return SALTS_OK;
}
static int mixed_stall_bulk(mixed_fixture *f, mixed_result *out) {
  native_io_backend_stats before, after;
  native_io_request previous = {0};
  const uint64_t start = cmeta_hrtime(), deadline = cmeta_monotonic_ms() + 5000u;
  if (!native_io_backend_get_stats(&f->backend, &before) || before.active_requests != 0u) return SALTS_EBUSY;
  while (cmeta_monotonic_ms() < deadline) {
    if (f->lanes[0].io.sent == f->bulk_admitted) {
      /* IOCP may complete whole buffered writes without a peer read. Prime
       * at most four, retaining the same immutable source for each new write. */
      if (f->bulk_admitted == 5u) return SALTS_ENOBUFS;
      if (mem_buffer_ref_count(f->lanes[0].source) != 1u) return SALTS_EPROTO;
      const int offered = mixed_offer(f, 0u);
      if (offered != SALTS_OK) return offered;
      ++f->bulk_admitted;
    }
    const int progress = mixed_progress(f, 25u);
    if (progress != SALTS_OK) return progress;
    if (f->observe_status != SALTS_ETIMEDOUT || f->observed_count != 0u) {
      out->empty_observations = 0u;
      previous = (native_io_request){0};
      continue;
    }
    native_io_request pending;
    cnet_send_usage usage;
    if (mixed_pending_bulk(f, &pending) != SALTS_OK ||
        mixed_usage(f, 0u, &usage) != SALTS_OK || usage.operations != 1u ||
        f->lanes[0].io.sent + 1u != f->bulk_admitted || mem_buffer_ref_count(f->lanes[0].source) != 2u ||
        !native_io_backend_get_stats(&f->backend, &after) || after.active_requests != 1u)
      return SALTS_EPROTO;
    if (out->empty_observations != 0u &&
        (pending.slot != previous.slot || pending.generation != previous.generation)) return SALTS_EPROTO;
    previous = pending;
    if (++out->empty_observations == 2u) {
      out->prime_ns = cmeta_hrtime() - start;
      out->prime_submissions = after.submitted - before.submitted;
      return SALTS_OK;
    }
  }
  return SALTS_ETIMEDOUT;
}
static int mixed_control_offer(mixed_fixture *f) {
  matched_fixture *control = &f->lanes[1];
  if (f->control_active || f->control_done == f->target) return SALTS_OK;
  if (control->io.sent != f->control_done || mem_buffer_ref_count(control->source) != 1u) return SALTS_EPROTO;
  *mem_buffer_data(control->source) = (char)(0x40u + f->control_done);
  f->request_seen = f->reply_sent = false;
  f->control_active = true;
  int status = mixed_arm_control(f);
  if (status != SALTS_OK) return status;
  f->control_start = cmeta_hrtime();
  return mixed_offer(f, 1u);
}
static int mixed_control_peer(mixed_fixture *f) {
  matched_fixture *control = &f->lanes[1];
  if (f->control_active && !f->request_seen) {
    unsigned char request;
    const int count = (int)recv(control->peer, (char *)&request, 1u, 0);
    if (count != 1 && !(count < 0 && test_would_block())) return SALTS_EIO;
    if (count == 1) {
      if (request != (unsigned char)(0x40u + f->control_done)) return SALTS_EPROTO;
      f->reply = (unsigned char)(request + 0x80u);
      f->request_seen = true;
    }
  }
  if (f->request_seen && !f->reply_sent) {
    const int count = (int)send(control->peer, (const char *)&f->reply, 1u, 0);
    if (count != 1 && !(count < 0 && test_would_block())) return SALTS_EIO;
    f->reply_sent = count == 1;
  }
  if (f->control_active && f->reply_sent && control->io.sent == f->control_done) f->control_active = false;
  return SALTS_OK;
}
static int mixed_phase(mixed_fixture *f, size_t exchanges, mixed_result *out) {
  matched_fixture *bulk = &f->lanes[0], *control = &f->lanes[1];
  native_io_backend_stats before, after;
  uint64_t cpu_start, cpu_end;
  size_t allocations = bulk->storage.allocated + control->storage.allocated;
  size_t receives = control->storage.buffers, calls = bulk->calls + control->calls;
  native_io_request stalled_request = {0};
  if (exchanges == 0u || exchanges > MIXED_EXCHANGES ||
      !native_io_backend_get_stats(&f->backend, &before) || before.active_requests != 0u) return SALTS_EINVAL;
  *out = (mixed_result){0};
  out->stage = "preparation";
  f->bulk_admitted = f->bulk_received = f->control_done = 0u;
  bulk->io.sent = control->io.sent = 0u;
  f->target = exchanges;
  f->control_active = false;
  if (f->stalled) {
    const int status = mixed_stall_bulk(f, out);
    if (status != SALTS_OK) return status;
    if (mixed_pending_bulk(f, &stalled_request) != SALTS_OK ||
        !native_io_backend_get_stats(&f->backend, &before)) return SALTS_EPROTO;
    out->stalled_request = stalled_request;
    allocations = bulk->storage.allocated + control->storage.allocated;
    receives = control->storage.buffers;
    calls = bulk->calls + control->calls;
  }
  if (matched_cpu_ns(&cpu_start) != SALTS_OK) return SALTS_EIO;
  out->stage = "control";
  const uint64_t start = cmeta_hrtime(), deadline = start + UINT64_C(10000000000);
  while ((f->control_done != exchanges || control->io.sent != exchanges) && cmeta_hrtime() < deadline) {
    while (!f->stalled && f->bulk_admitted - bulk->io.sent < f->bulk_window) {
      const int status = mixed_offer(f, 0u);
      if (status != SALTS_OK) return status;
      ++f->bulk_admitted;
    }
    if (f->bulk_window == 8u) {
      const unsigned references = mem_buffer_ref_count(bulk->source);
      if (mixed_offer(f, 0u) != SALTS_ENOBUFS ||
          mem_buffer_ref_count(bulk->source) != references) return SALTS_EPROTO;
      ++out->rejected;
    }
    if (mixed_control_offer(f) != SALTS_OK) return SALTS_EIO;
    cnet_send_usage usage[2] = {{0}};
    for (size_t i = 0u; i < 2u; ++i)
      if (mixed_usage(f, i, &usage[i]) != SALTS_OK) return SALTS_EIO;
    if (usage[0].operations != f->bulk_window) return SALTS_EPROTO;
    const size_t bytes = usage[0].bytes + usage[1].bytes;
    const size_t backing = usage[0].backing_bytes + usage[1].backing_bytes;
    if (bytes > out->peak_bytes) out->peak_bytes = bytes;
    if (backing > out->peak_backing) out->peak_backing = backing;
    const int progress = mixed_progress(f, 0u);
    if (progress != SALTS_OK) return progress;
    ++out->rounds;
    if (!f->stalled && mixed_read_bulk(f) != SALTS_OK) return SALTS_EIO;
    if (mixed_control_peer(f) != SALTS_OK) return SALTS_EIO;
    if (f->bulk_window == 8u &&
        (mixed_usage(f, 0u, &usage[0]) != SALTS_OK || usage[0].operations == 0u))
      return SALTS_EPROTO;
    if (bulk->io.failed != 0u || control->io.failed != 0u || bulk->io.terminal != 0u || control->io.terminal != 0u)
      return SALTS_EPROTO;
  }
  const uint64_t stop = cmeta_hrtime();
  out->elapsed_ns = stop - start;
  if (matched_cpu_ns(&cpu_end) != SALTS_OK || cpu_end < cpu_start) return SALTS_EIO;
  out->cpu_ns = cpu_end - cpu_start;
  if (f->control_done != exchanges || control->io.sent != exchanges || f->control_active) return SALTS_ETIMEDOUT;
  if (!native_io_backend_get_stats(&f->backend, &after)) return SALTS_EIO;
  out->native_submissions = after.submitted - before.submitted;
  out->bulk_bytes = f->bulk_received;
  out->bulk_admitted = f->bulk_admitted;
  out->allocations = bulk->storage.allocated + control->storage.allocated - allocations;
  out->receives = control->storage.buffers - receives;
  out->calls = bulk->calls + control->calls - calls;
  if (f->stalled) {
    out->stage = "stalled-request";
    native_io_request pending;
    if (mixed_pending_bulk(f, &pending) != SALTS_OK || pending.slot != stalled_request.slot ||
        pending.generation != stalled_request.generation || after.active_requests != 1u ||
        f->bulk_received != 0u || bulk->io.sent + 1u != f->bulk_admitted ||
        mem_buffer_ref_count(bulk->source) != 2u || out->native_submissions != 2u * exchanges)
      return SALTS_EPROTO;
  }
  /* Seal replenishment, then drain every admitted write and actual peer byte. */
  const uint64_t resume_start = f->stalled ? cmeta_hrtime() : stop;
  out->stage = "resume";
  const uint64_t resume_submissions = after.submitted;
  while ((bulk->io.sent != f->bulk_admitted || f->bulk_received != f->bulk_admitted * f->bulk_bytes) &&
         cmeta_hrtime() < deadline) {
    if (mixed_progress(f, 0u) != SALTS_OK || mixed_read_bulk(f) != SALTS_OK) return SALTS_EIO;
  }
  if (bulk->io.sent != f->bulk_admitted || f->bulk_received != f->bulk_admitted * f->bulk_bytes) return SALTS_ETIMEDOUT;
  out->bulk_drain_ns = cmeta_hrtime() - resume_start;
  out->resume_bytes = f->bulk_received - out->bulk_bytes;
  out->stage = "settlement";
  for (size_t i = 0u; i < 2u; ++i) {
    cnet_send_usage usage;
    if (mixed_usage(f, i, &usage) != SALTS_OK ||
        usage.operations != 0u || usage.bytes != 0u || usage.backing_bytes != 0u ||
        mem_buffer_ref_count(f->lanes[i].source) != 1u) return SALTS_EPROTO;
  }
  if (!native_io_backend_get_stats(&f->backend, &after) || after.active_requests != 0u) return SALTS_EBUSY;
  out->resume_submissions = after.submitted - resume_submissions;
  qsort(f->rtt, exchanges, sizeof(f->rtt[0]), matched_compare_ns);
  out->p50_ns = f->rtt[(exchanges * 50u + 99u) / 100u - 1u];
  out->p95_ns = f->rtt[(exchanges * 95u + 99u) / 100u - 1u];
  out->p99_ns = f->rtt[(exchanges * 99u + 99u) / 100u - 1u];
  return SALTS_OK;
}
static int mixed_socket_buffer(test_socket socket_value, int option, uint64_t *out) {
  int bytes = 0;
#if defined(_WIN32)
  int size = sizeof(bytes);
#else
  socklen_t size = sizeof(bytes);
#endif
  if (getsockopt(socket_value, SOL_SOCKET, option, (char *)&bytes, &size) != 0 || bytes <= 0)
    return SALTS_EIO;
  *out = (uint64_t)bytes;
  return SALTS_OK;
}
static int mixed_sample(matched_mode mode, size_t bulk_window, size_t exchanges, bool report,
                          unsigned repetition, size_t raw_chunk, mixed_profile profile) {
  mixed_fixture *f = calloc(1u, sizeof(*f));
  const bool stalled = profile == MIXED_STALLED;
  const native_io_backend_config backend_config = {backend_kind(), profile == MIXED_PARTITION ? 4u : 2u, 8u, 4u};
  const cnet_listener_config listener_config = {backend_kind(), "127.0.0.1", 0u, 2u};
  struct sockaddr_in remote = {0};
  mixed_result warm = {0}, measured = {0};
  native_io_backend_stats stats;
  uint16_t port;
  int ready = 0, result = 0, measured_status = SALTS_EIO;
  size_t events = 0u;
  if (f == NULL) return __LINE__;
  f->mode = mode;
  f->stalled = stalled;
  f->bulk_bytes = stalled ? PRESSURE_BYTES : MATCHED_BYTES;
  for (size_t i = 0u; i < 2u; ++i)
    f->lanes[i].peer = f->lanes[i].raw_socket = f->lanes[i].raw_listener = TEST_INVALID_SOCKET;
  f->bulk_window = bulk_window;
  VERIFY(bulk_window == 1u || bulk_window == 8u);
  VERIFY(!stalled || bulk_window == 1u);
  VERIFY(mode != MATCHED_NATIVEIO || (bulk_window == 1u && raw_chunk > 0u && raw_chunk <= f->bulk_bytes));
  VERIFY(native_io_backend_init(&f->backend, &backend_config) == SALTS_OK);
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (mode == MATCHED_NATIVEIO) {
    test_socket *listener = &f->lanes[0].raw_listener;
    *listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    VERIFY(*listener != TEST_INVALID_SOCKET);
    VERIFY(bind(*listener, (const struct sockaddr *)&remote, sizeof(remote)) == 0 && listen(*listener, 2) == 0);
#if defined(_WIN32)
    int address_size = sizeof(remote);
#else
    socklen_t address_size = sizeof(remote);
#endif
    VERIFY(getsockname(*listener, (struct sockaddr *)&remote, &address_size) == 0);
  } else {
    VERIFY(cnet_listener_init(&f->listener, &listener_config) == SALTS_OK);
    VERIFY(cnet_listener_port(&f->listener, &port) == SALTS_OK);
    if (stalled) VERIFY(cnet_listener_tcp_option_set(&f->listener, CNET_TCP_SOCKET_SEND_BUFFER_BYTES, 4096u) == SALTS_OK);
    remote.sin_port = htons(port);
  }
  for (size_t i = 0u; i < 2u; ++i) {
    matched_fixture *lane = &f->lanes[i];
    cnet_client_config config = client_config();
    const cnet_observer observer = i == 0u ? (cnet_observer){mixed_bulk_state, NULL, f, mixed_bulk_sent}
        : (cnet_observer){mixed_control_state, mixed_control_receive, f, mixed_control_sent};
    lane->window = i == 0u ? bulk_window : 1u;
    lane->raw_chunk = i == 0u ? raw_chunk : 1u;
    config.connection_capacity = 1u;
    if (profile == MIXED_PARTITION) config.completion_batch_capacity = 2u;
    config.max_send_bytes = i == 0u ? f->bulk_bytes : 1u;
    config.send_limits.operations = lane->window;
    config.resources.storage = (cnet_allocator){probe_allocate, probe_deallocate, &lane->storage};
    config.resources.receive = (cnet_buffer_provider){mixed_receive_buffer, &lane->storage};
    if (mode != MATCHED_NATIVEIO)
      VERIFY(cnet_client_init_external(&lane->client, &config, &f->backend) == SALTS_OK);
    lane->peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    VERIFY(lane->peer != TEST_INVALID_SOCKET && test_recv_timeout(lane->peer) == 0);
    const int enabled = 1;
    if (stalled && i == 0u) {
      const int receive_bytes = 65536;
      VERIFY(setsockopt(lane->peer, SOL_SOCKET, SO_RCVBUF, (const char *)&receive_bytes, sizeof(receive_bytes)) == 0);
    }
    VERIFY(setsockopt(lane->peer, IPPROTO_TCP, TCP_NODELAY, (const char *)&enabled, sizeof(enabled)) == 0);
    VERIFY(connect(lane->peer, (const struct sockaddr *)&remote, sizeof(remote)) == 0);
    if (mode == MATCHED_NATIVEIO) {
      lane->raw_socket = accept(f->lanes[0].raw_listener, NULL, NULL);
      VERIFY(lane->raw_socket != TEST_INVALID_SOCKET && test_nonblocking(lane->raw_socket) == 0);
      VERIFY(setsockopt(lane->raw_socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&enabled, sizeof(enabled)) == 0);
      if (stalled) {
        const int send_bytes = 4096;
        VERIFY(setsockopt(lane->raw_socket, SOL_SOCKET, SO_SNDBUF, (const char *)&send_bytes, sizeof(send_bytes)) == 0);
        if (i == 0u) VERIFY(mixed_socket_buffer(lane->raw_socket, SO_SNDBUF, &f->send_buffer) == SALTS_OK);
      }
      VERIFY(native_io_backend_attach_socket(&f->backend, (uintptr_t)lane->raw_socket, &lane->raw_endpoint) == SALTS_OK);
      VERIFY(native_io_backend_endpoint_supports_vector_write(&f->backend, lane->raw_endpoint));
    } else {
      VERIFY(cnet_listener_wait(&f->listener, 5000u, &ready) == SALTS_OK && ready == 1);
      VERIFY(cnet_listener_accept(&f->listener, &lane->client, &observer, &lane->connection) == SALTS_OK);
      VERIFY(cnet_client_advance_external(&lane->client, &events) == SALTS_OK && lane->io.connected == 1u);
      VERIFY(cnet_connection_tcp_option_set(&lane->client, lane->connection, CNET_TCP_SOCKET_NODELAY, 1u) == SALTS_OK);
      if (stalled && i == 0u)
        VERIFY(cnet_connection_tcp_option_get(&lane->client, lane->connection,
            CNET_TCP_SOCKET_SEND_BUFFER_BYTES, &f->send_buffer) == SALTS_OK);
    }
    VERIFY(test_nonblocking(lane->peer) == 0);
    if (mode == MATCHED_CALLBACK) {
      const cnet_send_admission_policy policy = {mixed_admit, lane};
      VERIFY(cnet_set_send_admission(&lane->client, lane->connection, &policy) == SALTS_OK);
    }
    if (stalled && i == 0u) VERIFY(mixed_socket_buffer(lane->peer, SO_RCVBUF, &f->peer_buffer) == SALTS_OK);
    const size_t bytes = i == 0u ? f->bulk_bytes : 1u;
    lane->source = mem_get_buffer(mem_global(), bytes);
    VERIFY(lane->source != NULL);
    for (size_t j = 0u; j < bytes; ++j) mem_buffer_data(lane->source)[j] = (char)((0x5au + j * 29u) & 0xffu);
    mem_set_used(lane->source, bytes);
  }
  if (mode == MATCHED_NATIVEIO) {
    test_close_socket(f->lanes[0].raw_listener);
    f->lanes[0].raw_listener = TEST_INVALID_SOCKET;
  } else VERIFY(cnet_listener_close(&f->listener) == SALTS_OK && cnet_listener_destroy(&f->listener) == SALTS_OK);
  VERIFY(native_io_backend_get_stats(&f->backend, &stats) && stats.endpoint_count == 2u && stats.active_requests == 0u);
  VERIFY(!stalled || (f->send_buffer > 0u && f->send_buffer < f->bulk_bytes && f->peer_buffer < f->bulk_bytes));
  VERIFY(mixed_phase(f, 8u, &warm) == SALTS_OK);
  if (report) {
    benchmark_ops("independent control RTT under bulk", 1, exchanges) {
      measured_status = mixed_phase(f, exchanges, &measured);
    }
  } else measured_status = mixed_phase(f, exchanges, &measured);
  if (measured_status != SALTS_OK) {
    native_io_backend_stats diagnostic = {0};
    native_io_request pending = {0};
    const int pending_status = mixed_pending_bulk(f, &pending);
    (void)native_io_backend_get_stats(&f->backend, &diagnostic);
    fprintf(stderr, "mixed phase mode=%s stalled=%u stage=%s status=%d control=%zu/%u bulk=%u/%zu bytes=%zu refs=%u native=%llu active=%zu pending=%d/%u/%u expected=%u/%u empty=%zu observe=%d/%zu\n",
        matched_name(mode), (unsigned)stalled, measured.stage ? measured.stage : "entry", measured_status,
        f->control_done, f->lanes[1].io.sent, f->lanes[0].io.sent, f->bulk_admitted,
        f->bulk_received, mem_buffer_ref_count(f->lanes[0].source),
        (unsigned long long)measured.native_submissions, diagnostic.active_requests,
        pending_status, pending.slot, pending.generation,
        measured.stalled_request.slot, measured.stalled_request.generation, measured.empty_observations,
        f->observe_status, f->observed_count);
  }
  VERIFY(measured_status == SALTS_OK && measured.elapsed_ns != 0u);
  VERIFY(measured.calls == (mode == MATCHED_CALLBACK ? (stalled ? 0u : measured.bulk_admitted) + exchanges : 0u));
  VERIFY((bulk_window == 8u) == (measured.rejected != 0u));
  if (mode == MATCHED_NATIVEIO && !stalled) {
    VERIFY(measured.native_submissions >= measured.bulk_admitted + 2u * exchanges);
    if (raw_chunk < MATCHED_BYTES)
      VERIFY(measured.native_submissions > measured.bulk_admitted + 2u * exchanges);
  }
  const uint64_t close_start = cmeta_hrtime();
  for (size_t i = 0u; i < 2u; ++i) {
    matched_fixture *lane = &f->lanes[i];
    unsigned char byte;
    if (mode == MATCHED_NATIVEIO) {
      VERIFY(!lane->raw_retained && !native_io_request_valid(lane->raw_request) &&
               !native_io_request_valid(f->raw_receive));
      test_close_socket(lane->raw_socket);
      lane->raw_socket = TEST_INVALID_SOCKET;
      VERIFY(native_io_backend_release_socket(&f->backend, lane->raw_endpoint) == SALTS_OK);
      lane->raw_endpoint = (native_io_endpoint){0};
    } else {
      VERIFY(cnet_close(&lane->client, lane->connection) == SALTS_OK);
      VERIFY(cnet_client_advance_external(&lane->client, &events) == SALTS_OK && lane->io.terminal == 1u && lane->io.failed == 0u);
    }
    VERIFY(test_blocking(lane->peer) == 0 && recv(lane->peer, (char *)&byte, 1u, 0) == 0);
  }
  VERIFY(native_io_backend_get_stats(&f->backend, &stats) && stats.active_requests == 0u && stats.endpoint_count == 0u);
  measured.close_ns = cmeta_hrtime() - close_start;
  for (size_t i = 0u; i < 2u; ++i) {
    test_close_socket(f->lanes[i].peer);
    f->lanes[i].peer = TEST_INVALID_SOCKET;
    if (mode != MATCHED_NATIVEIO) {
      VERIFY(cnet_client_stop_external(&f->lanes[i].client) == SALTS_OK);
      VERIFY(cnet_client_destroy(&f->lanes[i].client) == SALTS_OK);
    }
    VERIFY(f->lanes[i].storage.allocated == f->lanes[i].storage.released);
  }
  VERIFY(native_io_backend_close(&f->backend) == SALTS_OK && native_io_backend_destroy(&f->backend) == SALTS_OK);
  if (report && stalled) {
    printf("CNET_STALLED_CSV,%s,%u,%zu,%zu,%zu,%llu,%llu,%zu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%llu,%llu,%llu\n",
      matched_name(mode), repetition, exchanges, f->bulk_bytes, measured.bulk_admitted,
      (unsigned long long)measured.prime_submissions, (unsigned long long)measured.prime_ns, measured.empty_observations,
      (unsigned long long)f->send_buffer, (unsigned long long)f->peer_buffer,
      (unsigned long long)measured.elapsed_ns, (unsigned long long)measured.cpu_ns,
      (unsigned long long)measured.p50_ns, (unsigned long long)measured.p95_ns, (unsigned long long)measured.p99_ns,
      (unsigned long long)measured.native_submissions, measured.bulk_bytes, measured.rounds, measured.calls,
      measured.allocations, measured.receives, measured.peak_bytes, measured.peak_backing,
      mem_buffer_capacity(f->lanes[0].source) + mem_buffer_capacity(f->lanes[1].source), measured.resume_bytes,
      (unsigned long long)measured.bulk_drain_ns, (unsigned long long)measured.resume_submissions,
      (unsigned long long)measured.close_ns);
  } else if (report) {
    printf("%s,%s,%u,%zu,%zu,%llu,%llu,%llu,%llu,%llu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%llu,%llu,%llu,%zu\n",
      profile == MIXED_PARTITION ? "CNET_SINGLE_OWNER_CSV" : "CNET_MIXED_CSV",
      matched_name(mode), repetition, bulk_window, exchanges,
      (unsigned long long)measured.elapsed_ns, (unsigned long long)measured.cpu_ns,
      (unsigned long long)measured.p50_ns, (unsigned long long)measured.p95_ns, (unsigned long long)measured.p99_ns,
      measured.bulk_bytes, measured.bulk_admitted, measured.rounds, measured.rejected, measured.calls,
      measured.allocations, measured.receives, measured.peak_bytes, measured.peak_backing,
      mem_buffer_capacity(f->lanes[0].source) + mem_buffer_capacity(f->lanes[1].source),
      (unsigned long long)measured.native_submissions, (unsigned long long)measured.bulk_drain_ns,
      (unsigned long long)measured.close_ns, warm.receives);
  }
cleanup:
  for (size_t i = 0u; i < 2u; ++i) test_close_socket(f->lanes[i].peer);
  if (mode == MATCHED_NATIVEIO && f->backend.impl != NULL) {
    f->raw_stopping = true;
    for (size_t i = 0u; i < 2u; ++i)
      if (native_io_request_valid(f->lanes[i].raw_request))
        (void)native_io_backend_cancel(&f->backend, f->lanes[i].raw_request);
    if (native_io_request_valid(f->raw_receive)) (void)native_io_backend_cancel(&f->backend, f->raw_receive);
    const uint64_t deadline = cmeta_monotonic_ms() + 3000u;
    while ((native_io_request_valid(f->raw_receive) || native_io_request_valid(f->lanes[0].raw_request) ||
            native_io_request_valid(f->lanes[1].raw_request)) && cmeta_monotonic_ms() < deadline)
      (void)mixed_progress(f, 10u);
    for (size_t i = 0u; i < 2u; ++i) {
      matched_fixture *lane = &f->lanes[i];
      test_close_socket(lane->raw_listener);
      if (native_io_request_valid(lane->raw_request) || (i == 1u && native_io_request_valid(f->raw_receive))) continue;
      if (lane->raw_retained) { mem_buffer_release(lane->source); lane->raw_retained = false; }
      test_close_socket(lane->raw_socket);
      lane->raw_socket = TEST_INVALID_SOCKET;
      if (native_io_endpoint_valid(lane->raw_endpoint) &&
          native_io_backend_release_socket(&f->backend, lane->raw_endpoint) == SALTS_OK)
        lane->raw_endpoint = (native_io_endpoint){0};
    }
  }
  if (f->backend.impl != NULL) {
    const uint64_t deadline = cmeta_monotonic_ms() + 3000u;
    bool stopped = false;
    while (!stopped && cmeta_monotonic_ms() < deadline) {
      stopped = true;
      for (size_t i = 0u; i < 2u; ++i)
        if (f->lanes[i].client.impl != NULL && cnet_client_stop_external(&f->lanes[i].client) != SALTS_OK) stopped = false;
      if (!stopped) (void)mixed_progress(f, 10u);
    }
  }
  for (size_t i = 0u; i < 2u; ++i) if (f->lanes[i].client.impl != NULL) (void)cnet_client_destroy(&f->lanes[i].client);
  (void)cnet_listener_close(&f->listener);
  (void)cnet_listener_destroy(&f->listener);
  if (f->lanes[0].client.impl == NULL && f->lanes[1].client.impl == NULL &&
      !native_io_request_valid(f->raw_receive) && !native_io_request_valid(f->lanes[0].raw_request) &&
      !native_io_request_valid(f->lanes[1].raw_request)) {
    (void)native_io_backend_close(&f->backend);
    (void)native_io_backend_destroy(&f->backend);
    if (f->backend.impl == NULL && f->listener.impl == NULL) {
      for (size_t i = 0u; i < 2u; ++i) if (f->lanes[i].source) mem_buffer_release(f->lanes[i].source);
      free(f);
      return result;
    }
  }
  return result != 0 ? result : __LINE__;
}

enum { FIXED_START, FIXED_RUN, FIXED_CLOSE, FIXED_CLEANUP };
typedef struct fixed_shared {
  salts_atomic32 ready, bulk_running, stop, abort;
  salts_atomic64 stop_ns;
} fixed_shared;
typedef struct fixed_owner {
  mixed_fixture io;
  fixed_shared *shared;
  native_io_backend *backend;
  native_io_sharded_host_lease lease;
  const void *thread;
  mixed_result measured;
  uint64_t start_ns, stop_ns, close_start_ns, close_end_ns;
  size_t role, exchanges, physical_bytes;
  int command, failure;
  bool host_active;
} fixed_owner;

#define FIXED_REQUIRE(expr) do { if (!(expr)) return __LINE__; } while (0)
static bool fixed_quiescent(void *user) {
  const fixed_owner *owner = user;
  const matched_fixture *lane = &owner->io.lanes[owner->role];
  return lane->client.impl == NULL && lane->source == NULL &&
      !native_io_request_valid(lane->raw_request) && !native_io_request_valid(owner->io.raw_receive) &&
      !native_io_endpoint_valid(lane->raw_endpoint);
}
static int fixed_progress(native_io_sharded_context *context, fixed_owner *owner, uint32_t wait_ms) {
  mixed_fixture *f = &owner->io;
  matched_fixture *lane = &f->lanes[owner->role];
  if (owner->thread != cmeta_thread_current_token() ||
      native_io_sharded_context_shard(context) != owner->role) return SALTS_EPERM;
  size_t events = 0u, count = 0u;
  int first = lane->client.impl == NULL ? SALTS_OK : cnet_client_advance_external(&lane->client, &events);
  native_io_sharded_completion completions[2];
  int status = native_io_sharded_context_observe_host(context, owner->lease, completions, 2u, wait_ms, &count);
  if (status != SALTS_OK && status != SALTS_ETIMEDOUT && first == SALTS_OK) first = status;
  if (f->mode == MATCHED_NATIVEIO) {
    for (size_t i = 0u; i < count; ++i) {
      const native_io_sharded_completion *c = &completions[i];
      if (c->sharded_owned || c->request.owner_identity != owner->lease.owner_identity ||
          c->endpoint.owner_identity != owner->lease.owner_identity ||
          c->request.owner_shard != owner->role || c->endpoint.owner_shard != owner->role) {
        if (first == SALTS_OK) first = SALTS_EPROTO;
        continue;
      }
      /* Preserve the actual observed native identity/result; this is the
       * same SG wrapper boundary used by CNet's host router. */
      const native_io_completion native = {.request = c->request.native_request,
          .endpoint = c->endpoint.native_endpoint, .kind = c->kind, .bytes = c->bytes,
          .status = c->status, .native_status = c->native_status,
          .user_data = c->user_data, .address_length = c->address_length};
      status = mixed_raw_route(f, &native);
      if (status != SALTS_OK && first == SALTS_OK) first = status;
    }
  } else {
    cnet_client *client = &lane->client;
    const cnet_sg_host_routes routes = {sizeof(cnet_sg_host_routes), CNET_SG_HOST_ROUTING_VERSION,
        NULL, &client, 1u};
    size_t accepts = 0u, sharded = 0u;
    status = cnet_sg_host_route_batch(completions, count, &routes, &accepts, &sharded);
    if (status == SALTS_OK && (accepts != 0u || sharded != 0u)) status = SALTS_EPROTO;
    if (status != SALTS_OK && first == SALTS_OK) first = status;
  }
  return first;
}
static int fixed_setup(native_io_sharded_context *context, fixed_owner *owner) {
  mixed_fixture *f = &owner->io;
  matched_fixture *lane = &f->lanes[owner->role];
  struct sockaddr_in remote = {0};
  const cnet_listener_config listener_config = {backend_kind(), "127.0.0.1", 0u, 2u};
  cnet_client_config config = client_config();
  const cnet_observer observer = owner->role == 0u
      ? (cnet_observer){mixed_bulk_state, NULL, f, mixed_bulk_sent}
      : (cnet_observer){mixed_control_state, mixed_control_receive, f, mixed_control_sent};
  const size_t bytes = owner->role == 0u ? MATCHED_BYTES : 1u;
  size_t events = 0u;
  uint16_t port = 0u;
  int ready = 0;
  FIXED_REQUIRE(native_io_sharded_context_acquire_host(context, fixed_quiescent, owner,
      &owner->lease, &owner->backend) == SALTS_OK);
  owner->host_active = true;
  f->backend = *owner->backend; /* Borrow; only the SG runtime destroys it. */
  f->bulk_bytes = MATCHED_BYTES;
  lane->window = owner->role == 0u ? f->bulk_window : 1u;
  lane->raw_chunk = bytes;
  config.connection_capacity = 1u;
  config.completion_batch_capacity = 2u;
  config.max_send_bytes = bytes;
  config.send_limits.operations = lane->window;
  config.resources.storage = (cnet_allocator){probe_allocate, probe_deallocate, &lane->storage};
  config.resources.receive = (cnet_buffer_provider){mixed_receive_buffer, &lane->storage};
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (f->mode == MATCHED_NATIVEIO) {
    lane->raw_listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    FIXED_REQUIRE(lane->raw_listener != TEST_INVALID_SOCKET);
    FIXED_REQUIRE(bind(lane->raw_listener, (const struct sockaddr *)&remote, sizeof(remote)) == 0);
    FIXED_REQUIRE(listen(lane->raw_listener, 2) == 0);
#if defined(_WIN32)
    int size = sizeof(remote);
#else
    socklen_t size = sizeof(remote);
#endif
    FIXED_REQUIRE(getsockname(lane->raw_listener, (struct sockaddr *)&remote, &size) == 0);
  } else {
    FIXED_REQUIRE(cnet_listener_init(&f->listener, &listener_config) == SALTS_OK);
    FIXED_REQUIRE(cnet_listener_port(&f->listener, &port) == SALTS_OK);
    remote.sin_port = htons(port);
    FIXED_REQUIRE(cnet_client_init_external(&lane->client, &config, owner->backend) == SALTS_OK);
  }
  lane->peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  FIXED_REQUIRE(lane->peer != TEST_INVALID_SOCKET && test_recv_timeout(lane->peer) == 0);
  const int enabled = 1;
  FIXED_REQUIRE(setsockopt(lane->peer, IPPROTO_TCP, TCP_NODELAY, (const char *)&enabled, sizeof(enabled)) == 0);
  FIXED_REQUIRE(connect(lane->peer, (const struct sockaddr *)&remote, sizeof(remote)) == 0);
  if (f->mode == MATCHED_NATIVEIO) {
    lane->raw_socket = accept(lane->raw_listener, NULL, NULL);
    FIXED_REQUIRE(lane->raw_socket != TEST_INVALID_SOCKET && test_nonblocking(lane->raw_socket) == 0);
    FIXED_REQUIRE(setsockopt(lane->raw_socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&enabled, sizeof(enabled)) == 0);
    FIXED_REQUIRE(native_io_backend_attach_socket(owner->backend, (uintptr_t)lane->raw_socket, &lane->raw_endpoint) == SALTS_OK);
    FIXED_REQUIRE(native_io_backend_endpoint_supports_vector_write(owner->backend, lane->raw_endpoint));
    test_close_socket(lane->raw_listener);
    lane->raw_listener = TEST_INVALID_SOCKET;
  } else {
    FIXED_REQUIRE(cnet_listener_wait(&f->listener, 5000u, &ready) == SALTS_OK && ready == 1);
    FIXED_REQUIRE(cnet_listener_accept(&f->listener, &lane->client, &observer, &lane->connection) == SALTS_OK);
    FIXED_REQUIRE(cnet_client_advance_external(&lane->client, &events) == SALTS_OK && lane->io.connected == 1u);
    FIXED_REQUIRE(cnet_connection_tcp_option_set(&lane->client, lane->connection, CNET_TCP_SOCKET_NODELAY, 1u) == SALTS_OK);
    FIXED_REQUIRE(cnet_listener_close(&f->listener) == SALTS_OK && cnet_listener_destroy(&f->listener) == SALTS_OK);
    if (f->mode == MATCHED_CALLBACK) {
      const cnet_send_admission_policy policy = {mixed_admit, lane};
      FIXED_REQUIRE(cnet_set_send_admission(&lane->client, lane->connection, &policy) == SALTS_OK);
    }
  }
  FIXED_REQUIRE(test_nonblocking(lane->peer) == 0);
  lane->source = mem_get_buffer(mem_global(), bytes);
  FIXED_REQUIRE(lane->source != NULL);
  for (size_t i = 0u; i < bytes; ++i) mem_buffer_data(lane->source)[i] = (char)((0x5au + i * 29u) & 0xffu);
  mem_set_used(lane->source, bytes);
  owner->physical_bytes = mem_buffer_capacity(lane->source);
  native_io_backend_stats stats;
  FIXED_REQUIRE(native_io_backend_get_stats(owner->backend, &stats) && stats.endpoint_count == 1u && stats.active_requests == 0u);
  return 0;
}
static int fixed_aborted(fixed_owner *owner) {
  uint32_t aborted = 0u;
  if (salts_atomic32_load(&owner->shared->abort, SALTS_MEMORY_ACQUIRE, &aborted) != SALTS_OK)
    return SALTS_EIO;
  return aborted ? SALTS_ECANCELED : SALTS_OK;
}
static int fixed_phase(native_io_sharded_context *context, fixed_owner *owner) {
  mixed_fixture *f = &owner->io;
  matched_fixture *lane = &f->lanes[owner->role];
  mixed_result *out = &owner->measured;
  native_io_backend_stats before, after;
  uint64_t cpu_start = 0u, cpu_end = 0u;
  uint32_t ready = 0u, signal = 0u;
  const size_t allocations = lane->storage.allocated, receives = lane->storage.buffers, calls = lane->calls;
  const uint64_t gate_deadline = cmeta_monotonic_ms() + 5000u;
  FIXED_REQUIRE(native_io_backend_get_stats(owner->backend, &before) && before.active_requests == 0u);
  *out = (mixed_result){0};
  lane->io.sent = 0u;
  f->bulk_admitted = f->bulk_received = f->control_done = 0u;
  f->target = owner->exchanges;
  f->control_active = false;
  FIXED_REQUIRE(salts_atomic32_fetch_add(&owner->shared->ready, 1u, SALTS_MEMORY_ACQ_REL, &ready) == SALTS_OK && ready < 2u);
  do {
    FIXED_REQUIRE(fixed_aborted(owner) == SALTS_OK && cmeta_monotonic_ms() < gate_deadline);
    FIXED_REQUIRE(salts_atomic32_load(&owner->shared->ready, SALTS_MEMORY_ACQUIRE, &ready) == SALTS_OK);
    if (ready != 2u) cmeta_thread_yield();
  } while (ready != 2u);
  if (owner->role == 1u) {
    do {
      FIXED_REQUIRE(fixed_aborted(owner) == SALTS_OK && cmeta_monotonic_ms() < gate_deadline);
      FIXED_REQUIRE(salts_atomic32_load(&owner->shared->bulk_running, SALTS_MEMORY_ACQUIRE, &signal) == SALTS_OK);
      if (!signal) cmeta_thread_yield();
    } while (!signal);
    FIXED_REQUIRE(matched_cpu_ns(&cpu_start) == SALTS_OK);
  }
  owner->start_ns = cmeta_hrtime();
  const uint64_t deadline = owner->start_ns + UINT64_C(10000000000);
  bool published = false;
  while (cmeta_hrtime() < deadline) {
    FIXED_REQUIRE(fixed_aborted(owner) == SALTS_OK);
    if (owner->role == 0u) {
      FIXED_REQUIRE(salts_atomic32_load(&owner->shared->stop, SALTS_MEMORY_ACQUIRE, &signal) == SALTS_OK);
      if (signal) break;
      while (f->bulk_admitted - lane->io.sent < f->bulk_window) {
        FIXED_REQUIRE(mixed_offer(f, 0u) == SALTS_OK);
        ++f->bulk_admitted;
      }
      if (f->bulk_window == 8u) {
        const unsigned references = mem_buffer_ref_count(lane->source);
        FIXED_REQUIRE(mixed_offer(f, 0u) == SALTS_ENOBUFS && mem_buffer_ref_count(lane->source) == references);
        ++out->rejected;
      }
    } else FIXED_REQUIRE(mixed_control_offer(f) == SALTS_OK);
    cnet_send_usage usage;
    FIXED_REQUIRE(mixed_usage(f, owner->role, &usage) == SALTS_OK);
    if (usage.bytes > out->peak_bytes) out->peak_bytes = usage.bytes;
    if (usage.backing_bytes > out->peak_backing) out->peak_backing = usage.backing_bytes;
    FIXED_REQUIRE(fixed_progress(context, owner, 0u) == SALTS_OK);
    ++out->rounds;
    FIXED_REQUIRE(lane->io.failed == 0u && lane->io.terminal == 0u);
    if (owner->role == 0u) {
      FIXED_REQUIRE(mixed_read_bulk(f) == SALTS_OK);
      if (!published && f->bulk_received != 0u) {
        FIXED_REQUIRE(salts_atomic32_store(&owner->shared->bulk_running, 1u, SALTS_MEMORY_RELEASE) == SALTS_OK);
        published = true;
      }
      if (f->bulk_window == 8u) {
        FIXED_REQUIRE(mixed_usage(f, 0u, &usage) == SALTS_OK && usage.operations != 0u);
      }
    } else {
      FIXED_REQUIRE(mixed_control_peer(f) == SALTS_OK);
      if (f->control_done == owner->exchanges && lane->io.sent == owner->exchanges && !f->control_active) break;
    }
  }
  owner->stop_ns = cmeta_hrtime();
  FIXED_REQUIRE(owner->stop_ns < deadline);
  out->elapsed_ns = owner->stop_ns - owner->start_ns;
  if (owner->role == 1u) {
    FIXED_REQUIRE(f->control_done == owner->exchanges && lane->io.sent == owner->exchanges && !f->control_active);
    FIXED_REQUIRE(matched_cpu_ns(&cpu_end) == SALTS_OK && cpu_end >= cpu_start);
    out->cpu_ns = cpu_end - cpu_start;
    FIXED_REQUIRE(salts_atomic64_store(&owner->shared->stop_ns, owner->stop_ns, SALTS_MEMORY_RELEASE) == SALTS_OK);
    FIXED_REQUIRE(salts_atomic32_store(&owner->shared->stop, 1u, SALTS_MEMORY_RELEASE) == SALTS_OK);
    qsort(f->rtt, owner->exchanges, sizeof(f->rtt[0]), matched_compare_ns);
    out->p50_ns = f->rtt[(owner->exchanges * 50u + 99u) / 100u - 1u];
    out->p95_ns = f->rtt[(owner->exchanges * 95u + 99u) / 100u - 1u];
    out->p99_ns = f->rtt[(owner->exchanges * 99u + 99u) / 100u - 1u];
  } else {
    uint64_t control_stop;
    FIXED_REQUIRE(published && signal != 0u);
    FIXED_REQUIRE(salts_atomic64_load(&owner->shared->stop_ns, SALTS_MEMORY_ACQUIRE, &control_stop) == SALTS_OK && owner->stop_ns >= control_stop);
    out->bulk_bytes = f->bulk_received;
    out->bulk_admitted = f->bulk_admitted;
  }
  FIXED_REQUIRE(native_io_backend_get_stats(owner->backend, &after));
  out->native_submissions = after.submitted - before.submitted;
  out->calls = lane->calls - calls;
  out->allocations = lane->storage.allocated - allocations;
  out->receives = lane->storage.buffers - receives;
  if (owner->role == 0u) {
    while ((lane->io.sent != f->bulk_admitted || f->bulk_received != f->bulk_admitted * MATCHED_BYTES) && cmeta_hrtime() < deadline) {
      FIXED_REQUIRE(fixed_progress(context, owner, 0u) == SALTS_OK && mixed_read_bulk(f) == SALTS_OK);
    }
    FIXED_REQUIRE(lane->io.sent == f->bulk_admitted && f->bulk_received == f->bulk_admitted * MATCHED_BYTES);
    out->bulk_drain_ns = cmeta_hrtime() - owner->stop_ns;
  } else FIXED_REQUIRE(out->native_submissions == 2u * owner->exchanges);
  cnet_send_usage usage;
  FIXED_REQUIRE(mixed_usage(f, owner->role, &usage) == SALTS_OK && usage.operations == 0u && usage.bytes == 0u && usage.backing_bytes == 0u);
  FIXED_REQUIRE(mem_buffer_ref_count(lane->source) == 1u && native_io_backend_get_stats(owner->backend, &after) && after.active_requests == 0u);
  FIXED_REQUIRE(out->calls == (f->mode == MATCHED_CALLBACK ? (owner->role == 0u ? f->bulk_admitted : owner->exchanges) : 0u));
  return 0;
}
static int fixed_close(native_io_sharded_context *context, fixed_owner *owner, bool graceful) {
  mixed_fixture *f = &owner->io;
  matched_fixture *lane = &f->lanes[owner->role];
  size_t events = 0u;
  const uint64_t deadline = cmeta_monotonic_ms() + 3000u;
  if (!graceful) {
    test_close_socket(lane->peer);
    lane->peer = TEST_INVALID_SOCKET;
  }
  owner->close_start_ns = cmeta_hrtime();
  if (f->mode == MATCHED_NATIVEIO) {
    f->raw_stopping = true;
    if (native_io_request_valid(lane->raw_request)) (void)native_io_backend_cancel(owner->backend, lane->raw_request);
    if (native_io_request_valid(f->raw_receive)) (void)native_io_backend_cancel(owner->backend, f->raw_receive);
    while ((native_io_request_valid(lane->raw_request) || native_io_request_valid(f->raw_receive)) && cmeta_monotonic_ms() < deadline)
      (void)fixed_progress(context, owner, 10u);
    FIXED_REQUIRE(!native_io_request_valid(lane->raw_request) && !native_io_request_valid(f->raw_receive));
    if (lane->raw_retained) { mem_buffer_release(lane->source); lane->raw_retained = false; }
    test_close_socket(lane->raw_socket);
    lane->raw_socket = TEST_INVALID_SOCKET;
    if (native_io_endpoint_valid(lane->raw_endpoint)) {
      FIXED_REQUIRE(native_io_backend_release_socket(owner->backend, lane->raw_endpoint) == SALTS_OK);
      lane->raw_endpoint = (native_io_endpoint){0};
    }
  } else if (lane->client.impl != NULL) {
    if (graceful) {
      FIXED_REQUIRE(cnet_close(&lane->client, lane->connection) == SALTS_OK);
      FIXED_REQUIRE(cnet_client_advance_external(&lane->client, &events) == SALTS_OK && lane->io.terminal == 1u && lane->io.failed == 0u);
    } else {
      while (cnet_client_stop_external(&lane->client) == SALTS_EBUSY && cmeta_monotonic_ms() < deadline)
        (void)fixed_progress(context, owner, 10u);
    }
  }
  if (graceful) {
    unsigned char byte;
    FIXED_REQUIRE(test_blocking(lane->peer) == 0 && recv(lane->peer, (char *)&byte, 1u, 0) == 0);
    native_io_backend_stats stats;
    FIXED_REQUIRE(native_io_backend_get_stats(owner->backend, &stats) && stats.active_requests == 0u && stats.endpoint_count == 0u);
  }
  owner->close_end_ns = cmeta_hrtime();
  test_close_socket(lane->peer);
  lane->peer = TEST_INVALID_SOCKET;
  test_close_socket(lane->raw_listener);
  lane->raw_listener = TEST_INVALID_SOCKET;
  if (lane->client.impl != NULL) {
    FIXED_REQUIRE(cnet_client_stop_external(&lane->client) == SALTS_OK);
    FIXED_REQUIRE(cnet_client_destroy(&lane->client) == SALTS_OK);
  }
  if (lane->source != NULL) {
    FIXED_REQUIRE(mem_buffer_ref_count(lane->source) == 1u);
    mem_buffer_release(lane->source);
    lane->source = NULL;
  }
  FIXED_REQUIRE(lane->storage.allocated == lane->storage.released);
  if (f->listener.impl != NULL)
    FIXED_REQUIRE(cnet_listener_close(&f->listener) == SALTS_OK && cnet_listener_destroy(&f->listener) == SALTS_OK);
  if (owner->host_active) {
    FIXED_REQUIRE(native_io_sharded_context_release_host(context, owner->lease) == SALTS_OK);
    owner->host_active = false;
    owner->backend = NULL;
    f->backend = (native_io_backend){0};
  }
  return 0;
}
static void fixed_task(native_io_sharded_context *context, void *user) {
  fixed_owner *owner = user;
  int status = 0;
  if (owner->thread == NULL) owner->thread = cmeta_thread_current_token();
  if (owner->thread != cmeta_thread_current_token() || native_io_sharded_context_shard(context) != owner->role) status = __LINE__;
  else if (owner->command == FIXED_START) status = fixed_setup(context, owner);
  else if (owner->command == FIXED_RUN) status = fixed_phase(context, owner);
  else status = fixed_close(context, owner, owner->command == FIXED_CLOSE);
  if (status != 0) {
    if (owner->failure == 0) owner->failure = status;
    (void)salts_atomic32_store(&owner->shared->abort, 1u, SALTS_MEMORY_RELEASE);
  }
}
static void fixed_cancel(void *user, int status) {
  fixed_owner *owner = user;
  owner->failure = status;
  (void)salts_atomic32_store(&owner->shared->abort, 1u, SALTS_MEMORY_RELEASE);
}
static int fixed_run(native_io_sharded *runtime, fixed_owner *owners, int command) {
  int first = SALTS_OK;
  for (size_t i = 0u; i < 2u; ++i) {
    owners[i].command = command;
    const native_io_sharded_task task = {fixed_task, fixed_cancel, NULL, &owners[i]};
    const int status = native_io_sharded_submit_to(runtime, i, &task);
    if (status != SALTS_OK) {
      if (first == SALTS_OK) first = status;
      (void)salts_atomic32_store(&owners[i].shared->abort, 1u, SALTS_MEMORY_RELEASE);
    }
  }
  const int waited = native_io_sharded_wait(runtime);
  if (first == SALTS_OK) first = waited;
  for (size_t i = 0u; i < 2u; ++i) if (owners[i].failure != 0 && command != FIXED_CLEANUP) {
    fprintf(stderr, "Fixed Owner %zu failed at %d\n", i, owners[i].failure);
    if (first == SALTS_OK) first = SALTS_EIO;
  }
  return first;
}
static int fixed_reset(fixed_shared *shared) {
  FIXED_REQUIRE(salts_atomic32_store(&shared->ready, 0u, SALTS_MEMORY_RELEASE) == SALTS_OK);
  FIXED_REQUIRE(salts_atomic32_store(&shared->bulk_running, 0u, SALTS_MEMORY_RELEASE) == SALTS_OK);
  FIXED_REQUIRE(salts_atomic32_store(&shared->stop, 0u, SALTS_MEMORY_RELEASE) == SALTS_OK);
  FIXED_REQUIRE(salts_atomic64_store(&shared->stop_ns, 0u, SALTS_MEMORY_RELEASE) == SALTS_OK);
  return 0;
}
#undef FIXED_REQUIRE

typedef struct fixed_pair { fixed_shared shared; fixed_owner owners[2]; } fixed_pair;
static int fixed_sample(matched_mode mode, size_t window, size_t exchanges, bool report, unsigned repetition) {
  fixed_pair *pair = calloc(1u, sizeof(*pair));
  native_io_sharded *runtime = NULL;
  const native_io_sharded_config config = {2u, 8u, {backend_kind(), 2u, 4u, 2u}};
  native_io_sharded_stats stats = NATIVE_IO_SHARDED_STATS_V1_INITIALIZER;
  int result = 0;
  VERIFY(pair != NULL);
  VERIFY(window == 1u || window == 8u);
  VERIFY(mode != MATCHED_NATIVEIO || window == 1u);
  VERIFY(exchanges > 0u && exchanges <= MIXED_EXCHANGES);
  VERIFY(salts_atomic32_init(&pair->shared.ready, 0u) == SALTS_OK);
  VERIFY(salts_atomic32_init(&pair->shared.bulk_running, 0u) == SALTS_OK);
  VERIFY(salts_atomic32_init(&pair->shared.stop, 0u) == SALTS_OK);
  VERIFY(salts_atomic32_init(&pair->shared.abort, 0u) == SALTS_OK);
  VERIFY(salts_atomic64_init(&pair->shared.stop_ns, 0u) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    fixed_owner *owner = &pair->owners[i];
    owner->role = i;
    owner->shared = &pair->shared;
    owner->io.mode = mode;
    owner->io.bulk_window = window;
    for (size_t j = 0u; j < 2u; ++j)
      owner->io.lanes[j].peer = owner->io.lanes[j].raw_socket = owner->io.lanes[j].raw_listener = TEST_INVALID_SOCKET;
  }
  VERIFY(native_io_sharded_create(&config, &runtime) == SALTS_OK);
  VERIFY(fixed_run(runtime, pair->owners, FIXED_START) == SALTS_OK);
  VERIFY(pair->owners[0].thread != pair->owners[1].thread &&
      pair->owners[0].backend != pair->owners[1].backend &&
      pair->owners[0].io.backend.impl != pair->owners[1].io.backend.impl);
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_EBUSY);
  for (size_t i = 0u; i < 2u; ++i) pair->owners[i].exchanges = 8u;
  VERIFY(fixed_run(runtime, pair->owners, FIXED_RUN) == SALTS_OK);
  VERIFY(fixed_reset(&pair->shared) == 0);
  for (size_t i = 0u; i < 2u; ++i) pair->owners[i].exchanges = exchanges;
  int measured_status = SALTS_EIO;
  if (report) {
    benchmark_ops("two fixed SG Owners control exchanges", 1, exchanges) {
      measured_status = fixed_run(runtime, pair->owners, FIXED_RUN);
    }
  } else measured_status = fixed_run(runtime, pair->owners, FIXED_RUN);
  VERIFY(measured_status == SALTS_OK);
  const mixed_result bulk = pair->owners[0].measured, control = pair->owners[1].measured;
  const int64_t start_skew = (int64_t)pair->owners[0].start_ns - (int64_t)pair->owners[1].start_ns;
  const uint64_t stop_lag = pair->owners[0].stop_ns - pair->owners[1].stop_ns;
  const size_t physical = pair->owners[0].physical_bytes + pair->owners[1].physical_bytes;
  VERIFY(bulk.bulk_bytes > 0u && bulk.bulk_admitted > 0u && bulk.elapsed_ns != 0u && control.elapsed_ns != 0u);
  VERIFY((window == 8u) == (bulk.rejected != 0u));
  VERIFY(pair->owners[0].thread != pair->owners[1].thread && pair->owners[0].backend != pair->owners[1].backend);
  VERIFY(fixed_run(runtime, pair->owners, FIXED_CLOSE) == SALTS_OK);
  const uint64_t close_start = pair->owners[0].close_start_ns < pair->owners[1].close_start_ns
      ? pair->owners[0].close_start_ns : pair->owners[1].close_start_ns;
  const uint64_t close_end = pair->owners[0].close_end_ns > pair->owners[1].close_end_ns
      ? pair->owners[0].close_end_ns : pair->owners[1].close_end_ns;
  VERIFY(native_io_sharded_get_stats(runtime, &stats) && stats.active_command_slots == 0u &&
      stats.completed_tasks == stats.submitted_tasks && stats.cancelled_tasks == 0u);
  VERIFY(native_io_sharded_shutdown(runtime) == SALTS_OK && native_io_sharded_wait(runtime) == SALTS_OK);
  VERIFY(native_io_sharded_destroy(runtime) == SALTS_OK);
  runtime = NULL;
  if (report) {
    printf("CNET_FIXED_OWNERS_CSV,%s,%u,%zu,%zu,%llu,%llu,%llu,%llu,%llu,%zu,%llu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%llu,%llu,%llu,%llu,%lld,%llu\n",
      matched_name(mode), repetition, window, exchanges,
      (unsigned long long)control.elapsed_ns, (unsigned long long)control.cpu_ns,
      (unsigned long long)control.p50_ns, (unsigned long long)control.p95_ns, (unsigned long long)control.p99_ns,
      bulk.bulk_bytes, (unsigned long long)bulk.elapsed_ns, bulk.bulk_admitted, bulk.rounds, control.rounds,
      bulk.rejected, bulk.calls + control.calls, bulk.allocations + control.allocations,
      control.receives, bulk.peak_bytes + control.peak_bytes, bulk.peak_backing + control.peak_backing, physical,
      (unsigned long long)bulk.native_submissions, (unsigned long long)control.native_submissions,
      (unsigned long long)bulk.bulk_drain_ns, (unsigned long long)(close_end - close_start),
      (long long)start_skew, (unsigned long long)stop_lag);
  }
cleanup:
  if (runtime != NULL && pair != NULL) {
    (void)salts_atomic32_store(&pair->shared.abort, 1u, SALTS_MEMORY_RELEASE);
    (void)fixed_run(runtime, pair->owners, FIXED_CLEANUP);
    if (native_io_sharded_shutdown(runtime) == SALTS_OK && native_io_sharded_wait(runtime) == SALTS_OK &&
        native_io_sharded_destroy(runtime) == SALTS_OK) runtime = NULL;
  }
  if (runtime == NULL) free(pair);
  else if (result == 0) result = __LINE__; /* Preserve all live host/atomic storage. */
  return result;
}

typedef struct phase_probe {
  cnet_client *client;
  cnet_connection connection;
  tcp_probe io;
  unsigned evaluated, callback_checks;
  size_t total_operations, connection_operations;
  int decision, policy_reentry, callback_mutation, wrong_owner;
  int wrong_manager_owner;
  size_t wrong_manager_allocated, wrong_manager_released;
  bool wrong_manager_published;
} phase_probe;

static int phase_evaluate(void *user, const cnet_send_usage *total,
                          const cnet_send_usage *connection, size_t bytes, size_t backing) {
  phase_probe *p = user;
  const cnet_send_admission_policy empty = {0};
  (void)bytes; (void)backing;
  ++p->evaluated;
  p->total_operations = total->operations;
  p->connection_operations = connection->operations;
  p->policy_reentry = cnet_set_send_admission(p->client, p->connection, &empty);
  return p->decision;
}

static void phase_state(void *user, cnet_connection connection,
                         cnet_connection_state state, const cnet_error *error) {
  phase_probe *p = user;
  const cnet_send_admission_policy empty = {0};
  on_state(&p->io, connection, state, error);
  if (cnet_set_send_admission(p->client, connection, &empty) != SALTS_EBUSY)
    ++p->io.failed;
  ++p->callback_checks;
}

static void phase_complete(void *user, const cnet_send_result *result) {
  phase_probe *p = user;
  const cnet_send_admission_policy empty = {0};
  on_operation(&p->io, result);
  p->callback_mutation = cnet_set_send_admission(p->client, result->connection, &empty);
}

static void phase_wrong_owner(void *user) {
  phase_probe *p = user;
  const cnet_send_admission_policy empty = {0};
  p->wrong_owner = cnet_set_send_admission(p->client, p->connection, &empty);
  cnet_manager manager = {0};
  resource_probe storage = {0};
  const cnet_manager_config config = {
      .size = sizeof(cnet_manager_config), .version = CNET_MANAGER_VERSION,
      .client = p->client, .record_capacity = 1u, .connection_capacity = 1u,
      .storage = {probe_allocate, probe_deallocate, &storage}};
  p->wrong_manager_owner = cnet_manager_init(&manager, &config);
  p->wrong_manager_published = manager.impl != NULL;
  if (manager.impl != NULL) (void)cnet_manager_destroy(&manager);
  p->wrong_manager_allocated = storage.allocated;
  p->wrong_manager_released = storage.released;
}

static int saltscore_native_entry_test_cnet_connection_phases(void) {
  cnet_client client = {0};
  cnet_listener listener = {0};
  cnet_client_config config = client_config();
  const cnet_listener_config listener_config = {backend_kind(), "127.0.0.1", 0u, 2u};
  const cnet_send_admission_policy empty = {0}, pause = {probe_send_pause, NULL};
  phase_probe phases[2] = {{0}, {0}};
  test_socket peers[2] = {TEST_INVALID_SOCKET, TEST_INVALID_SOCKET};
  cmeta_thread_t thread = NULL;
  mem_buffer_t *buffer = NULL;
  mem_slice_t slice = {0};
  cnet_operation operation = {0};
  cnet_admission_limit limit = CNET_LIMIT_NONE;
  struct sockaddr_in remote = {0};
  uint16_t port = 0u;
  unsigned char received = 0u;
  int result = 0, ready = 0;
  config.send_limits.connection_operations = 1u;
  VERIFY(cnet_client_init(&client, &config) == SALTS_OK);
  VERIFY(cnet_listener_init(&listener, &listener_config) == SALTS_OK);
  VERIFY(cnet_listener_port(&listener, &port) == SALTS_OK);
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  remote.sin_port = htons(port);
  for (size_t i = 0u; i < 2u; ++i) {
    phase_probe *p = &phases[i];
    p->client = &client;
    p->decision = i == 0u ? SALTS_ENOBUFS : SALTS_OK;
    cnet_observer observer = {phase_state, NULL, p, NULL};
    cnet_send_admission_policy policy = {phase_evaluate, p};
    peers[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    VERIFY(peers[i] != TEST_INVALID_SOCKET && test_recv_timeout(peers[i]) == 0);
    VERIFY(connect(peers[i], (const struct sockaddr *)&remote, (int)sizeof(remote)) == 0);
    VERIFY(cnet_listener_wait(&listener, 5000u, &ready) == SALTS_OK && ready == 1);
    VERIFY(cnet_listener_accept(&listener, &client, &observer, &p->connection) == SALTS_OK);
    /* Bind before the first CONNECTED notification; the binding is copied. */
    VERIFY(cnet_set_send_admission(&client, p->connection, &policy) == SALTS_OK);
    policy = empty;
    VERIFY(poll_until(&client, &p->io.connected, 1u) == SALTS_OK);
  }
  VERIFY(cmeta_thread_create(&thread, phase_wrong_owner, &phases[0]) == SALTS_OK);
  VERIFY(cmeta_thread_join(&thread) == SALTS_OK);
  cmeta_thread_destroy(&thread);
  VERIFY(phases[0].wrong_owner == SALTS_EPERM);
  VERIFY(phases[0].wrong_manager_owner == SALTS_EPERM && !phases[0].wrong_manager_published);
  VERIFY(phases[0].wrong_manager_allocated == 0u && phases[0].wrong_manager_released == 0u);
  const cnet_send_admission_policy invalid = {NULL, &phases[0]};
  VERIFY(cnet_set_send_admission(&client, phases[0].connection, &invalid) == SALTS_EINVAL);
  VERIFY(cnet_set_send_admission(&client, phases[0].connection, NULL) == SALTS_EINVAL);
  VERIFY(cnet_set_send_admission(&client, (cnet_connection){0}, &empty) == SALTS_ENOENT);
  buffer = mem_get_buffer(mem_global(), 1u);
  VERIFY(buffer != NULL);
  *mem_buffer_data(buffer) = 0x69u;
  mem_set_used(buffer, 1u);
  slice = mem_slice(buffer, 0u, 1u);
  cnet_send_options options = {&slice, 1u, false, phase_complete, &phases[0]};
  operation.id = UINT64_MAX;
  VERIFY(cnet_send(&client, phases[0].connection, &options, &operation, &limit) == SALTS_ENOBUFS);
  VERIFY(operation.id == 0u && limit == CNET_LIMIT_CONNECTION_POLICY &&
         mem_buffer_ref_count(buffer) == 2u && phases[0].io.completed == 0u);
  VERIFY(phases[0].evaluated == 1u && phases[0].policy_reentry == SALTS_EINVAL);

  /* First phase now allows admission. Switch again with a live retained send. */
  VERIFY(cnet_set_send_admission(&client, phases[0].connection, &empty) == SALTS_OK);
  VERIFY(cnet_send(&client, phases[0].connection, &options, &operation, &limit) == SALTS_OK);
  const uint64_t first_operation = operation.id;
  VERIFY(cnet_set_send_admission(&client, phases[0].connection, &pause) == SALTS_OK);
  VERIFY(cnet_send(&client, phases[0].connection, &options, &operation, &limit) == SALTS_ENOBUFS);
  VERIFY(limit == CNET_LIMIT_CONNECTION_OPERATIONS && operation.id == 0u);
  options.user = &phases[1];
  VERIFY(cnet_send(&client, phases[1].connection, &options, &operation, &limit) == SALTS_OK);
  VERIFY(phases[1].evaluated == 1u && phases[1].total_operations == 1u &&
         phases[1].connection_operations == 0u && phases[1].policy_reentry == SALTS_EINVAL);
  const unsigned gate_calls = phases[1].evaluated;
  VERIFY(cnet_send(&client, phases[1].connection, &options, &operation, &limit) == SALTS_ENOBUFS);
  VERIFY(limit == CNET_LIMIT_CONNECTION_OPERATIONS && phases[1].evaluated == gate_calls);
  mem_slice_release(&slice);
  mem_buffer_release(buffer);
  buffer = NULL;
  for (size_t i = 0u; i < 2u; ++i) {
    VERIFY(poll_until(&client, &phases[i].io.completed, 1u) == SALTS_OK);
    VERIFY(phases[i].io.completion.status == SALTS_OK &&
           phases[i].callback_mutation == SALTS_EBUSY);
    VERIFY(recv(peers[i], (char *)&received, 1, 0) == 1 && received == 0x69u);
  }
  VERIFY(phases[0].io.completion.operation.id == first_operation);
  cnet_send_usage usage = {0};
  VERIFY(cnet_client_send_usage(&client, (cnet_connection){0}, &usage) == SALTS_OK &&
         usage.operations == 0u && usage.bytes == 0u && usage.backing_bytes == 0u);

  buffer = mem_get_buffer(mem_global(), 1u);
  VERIFY(buffer != NULL);
  *mem_buffer_data(buffer) = 0x96u;
  mem_set_used(buffer, 1u);
  slice = mem_slice(buffer, 0u, 1u);
  VERIFY(cnet_client_set_send_admission(&client, &pause) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    options.user = &phases[i];
    VERIFY(cnet_send(&client, phases[i].connection, &options, &operation, &limit) == SALTS_ENOBUFS);
    VERIFY(limit == CNET_LIMIT_POLICY && operation.id == 0u && mem_buffer_ref_count(buffer) == 2u);
  }
  VERIFY(phases[1].evaluated == gate_calls);
  VERIFY(cnet_client_set_send_admission(&client, &empty) == SALTS_OK);
  options.user = &phases[0];
  VERIFY(cnet_send(&client, phases[0].connection, &options, &operation, &limit) == SALTS_ENOBUFS);
  VERIFY(limit == CNET_LIMIT_CONNECTION_POLICY && mem_buffer_ref_count(buffer) == 2u);

  /* Close a gated generation and reuse only its slot while its neighbor lives. */
  const cnet_connection stale = phases[0].connection;
  VERIFY(cnet_close(&client, stale) == SALTS_OK);
  VERIFY(cnet_set_send_admission(&client, stale, &empty) == SALTS_ESHUTDOWN);
  VERIFY(poll_until(&client, &phases[0].io.terminal, 1u) == SALTS_OK);
  VERIFY(recv(peers[0], (char *)&received, 1, 0) == 0);
  test_close_socket(peers[0]);
  peers[0] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  VERIFY(peers[0] != TEST_INVALID_SOCKET && test_recv_timeout(peers[0]) == 0);
  VERIFY(connect(peers[0], (const struct sockaddr *)&remote, (int)sizeof(remote)) == 0);
  VERIFY(cnet_listener_wait(&listener, 5000u, &ready) == SALTS_OK && ready == 1);
  const cnet_observer observer = {phase_state, NULL, &phases[0], NULL};
  VERIFY(cnet_listener_accept(&listener, &client, &observer, &phases[0].connection) == SALTS_OK);
  VERIFY(phases[0].connection.slot == stale.slot && phases[0].connection.generation != stale.generation);
  VERIFY(cnet_set_send_admission(&client, stale, &pause) == SALTS_ENOENT);
  VERIFY(poll_until(&client, &phases[0].io.connected, 2u) == SALTS_OK);
  options.close_after_send = true;
  for (size_t i = 0u; i < 2u; ++i) {
    options.user = &phases[i];
    VERIFY(cnet_send(&client, phases[i].connection, &options, &operation, &limit) == SALTS_OK);
    VERIFY(cnet_set_send_admission(&client, phases[i].connection, &empty) == SALTS_ESHUTDOWN);
  }
  VERIFY(phases[0].evaluated == 1u && phases[1].evaluated == gate_calls + 1u);
  mem_slice_release(&slice);
  mem_buffer_release(buffer);
  buffer = NULL;
  for (size_t i = 0u; i < 2u; ++i) {
    VERIFY(poll_until(&client, &phases[i].io.terminal, i == 0u ? 2u : 1u) == SALTS_OK);
    VERIFY(phases[i].io.failed == 0u && phases[i].io.completed == 2u &&
           phases[i].io.completions_at_terminal == 2u && phases[i].io.completion.status == SALTS_OK);
    VERIFY(phases[i].callback_checks >= 2u && phases[i].callback_mutation == SALTS_EBUSY);
    VERIFY(recv(peers[i], (char *)&received, 1, 0) == 1 && received == 0x96u);
    VERIFY(recv(peers[i], (char *)&received, 1, 0) == 0);
    VERIFY(cnet_set_send_admission(&client, phases[i].connection, &empty) == SALTS_ENOENT);
  }
  VERIFY(cnet_client_stop(&client, 5000u) == SALTS_OK);
  VERIFY(cnet_set_send_admission(&client, phases[0].connection, &empty) == SALTS_ESHUTDOWN);
  VERIFY(cnet_client_destroy(&client) == SALTS_OK);
  VERIFY(cnet_listener_close(&listener) == SALTS_OK);
  VERIFY(cnet_listener_destroy(&listener) == SALTS_OK);
cleanup:
  if (thread != NULL) { (void)cmeta_thread_join(&thread); cmeta_thread_destroy(&thread); }
  mem_slice_release(&slice);
  if (buffer != NULL) mem_buffer_release(buffer);
  for (size_t i = 0u; i < 2u; ++i) test_close_socket(peers[i]);
  if (client.impl != NULL) { (void)cnet_client_stop(&client, 3000u); (void)cnet_client_destroy(&client); }
  if (listener.impl != NULL) { (void)cnet_listener_close(&listener); (void)cnet_listener_destroy(&listener); }
  return result;
}

spec("CNet real TCP loopback and retained slice") {
  for (size_t depth = 1u; depth <= 8u; depth *= 8u) {
    for (unsigned composed = 0u; composed < 2u; ++composed) {
      it("keeps independent control replies and complete bulk drain at depth %zu with callback %u", depth, composed) {
        const int result = mixed_sample(composed != 0u ? MATCHED_CALLBACK : MATCHED_CNET,
                                        depth, 8u, false, 0u, MATCHED_BYTES, MIXED_STEADY);
        check(result == 0, "mixed bulk/control transfer returned %d", result);
      }
    }
  }
  for (size_t chunk = 4096u; chunk <= MATCHED_BYTES; chunk *= 8u) {
    it("drains direct NativeIO bulk/control with native send bound %zu", chunk) {
      const int result = mixed_sample(MATCHED_NATIVEIO, 1u, 8u, false, 0u, chunk, MIXED_STEADY);
      check(result == 0, "direct mixed bulk/control transfer returned %d", result);
    }
  }
  for (unsigned mode = 0u; mode < 3u; ++mode) {
    it("progresses control while a real kernel bulk send is stalled with mode %u", mode) {
      const int result = mixed_sample((matched_mode)mode, 1u, 8u, false, 0u, PRESSURE_BYTES, MIXED_STALLED);
      check(result == 0, "kernel-stalled mixed transfer returned %d", result);
    }
  }
  for (size_t depth = 1u; depth <= 8u; depth *= 8u) {
    for (unsigned mode = 0u; mode < (depth == 1u ? 3u : 2u); ++mode) {
      it("drains paired single/two fixed Owner workloads at depth %zu mode %u", depth, mode) {
        check_equal(mixed_sample((matched_mode)mode, depth, 8u, false, 0u, MATCHED_BYTES, MIXED_PARTITION), 0);
        check_equal(fixed_sample((matched_mode)mode, depth, 8u, false, 0u), 0);
      }
    }
  }
  if (getenv("SALTSCORE_CNET_OWNERS_BENCHMARK") != NULL) {
    it("measures one and two fixed Owners with matched aggregate resources") {
      check_equal(getenv("SALTSCORE_CNET_OWNERS_BENCHMARK"), "1");
      printf("CNET_SINGLE_OWNER_CSV,mode,repeat,bulk_depth,exchanges,elapsed_ns,cpu_ns,p50_rtt_ns,p95_rtt_ns,p99_rtt_ns,bulk_peer_bytes,bulk_admitted,host_rounds,rejected,policy_calls,storage_allocations,receive_acquires,peak_logical_bytes,peak_backing_bytes,physical_source_bytes,native_submissions,bulk_drain_ns,close_ns,warm_receive_acquires\n");
      printf("CNET_FIXED_OWNERS_CSV,mode,repeat,bulk_depth,exchanges,control_elapsed_ns,process_cpu_ns,p50_rtt_ns,p95_rtt_ns,p99_rtt_ns,bulk_peer_bytes,bulk_elapsed_ns,bulk_admitted,bulk_host_rounds,control_host_rounds,rejected,policy_calls,storage_allocations,receive_acquires,peak_logical_bound,peak_backing_bound,physical_source_bytes,bulk_native_submissions,control_native_submissions,bulk_drain_ns,close_ns,bulk_start_minus_control_ns,stop_observation_lag_ns\n");
      for (unsigned repetition = 0u; repetition < 5u; ++repetition)
        for (size_t depth = 1u; depth <= 8u; depth *= 8u)
          for (unsigned order = 0u; order < (depth == 1u ? 3u : 2u); ++order) {
            const matched_mode mode = (matched_mode)((repetition + order) % (depth == 1u ? 3u : 2u));
            for (unsigned topology = 0u; topology < 2u; ++topology) {
              const bool two = ((repetition + order + topology) & 1u) != 0u;
              const int result = two ? fixed_sample(mode, depth, MIXED_EXCHANGES, true, repetition)
                  : mixed_sample(mode, depth, MIXED_EXCHANGES, true, repetition, MATCHED_BYTES, MIXED_PARTITION);
              check(result == 0, "fixed Owner benchmark returned %d", result);
            }
          }
    }
  }
  if (getenv("SALTSCORE_CNET_STALLED_BENCHMARK") != NULL) {
    it("measures control RTT during a verified kernel bulk stall") {
      check_equal(getenv("SALTSCORE_CNET_STALLED_BENCHMARK"), "1");
      printf("CNET_STALLED_CSV,mode,repeat,exchanges,bulk_write_bytes,prime_admitted,prime_native_submissions,prime_ns,empty_observations,send_buffer_bytes,peer_receive_buffer_bytes,control_elapsed_ns,control_cpu_ns,p50_rtt_ns,p95_rtt_ns,p99_rtt_ns,control_native_submissions,bulk_peer_bytes_during_control,host_rounds,control_policy_calls,storage_allocations,receive_acquires,peak_logical_bytes,peak_backing_bytes,physical_source_bytes,resume_bytes,resume_ns,resume_native_submissions,close_ns\n");
      for (unsigned repetition = 0u; repetition < 5u; ++repetition)
        for (unsigned order = 0u; order < 3u; ++order) {
          const matched_mode mode = (matched_mode)((repetition + order) % 3u);
          const int result = mixed_sample(mode, 1u, MIXED_EXCHANGES, true, repetition, PRESSURE_BYTES, MIXED_STALLED);
          check(result == 0, "stalled benchmark returned %d", result);
        }
    }
  }
  if (getenv("SALTSCORE_CNET_MIXED_BENCHMARK") != NULL) {
    it("measures independent control RTT with sustained bulk") {
      check_equal(getenv("SALTSCORE_CNET_MIXED_BENCHMARK"), "1");
      printf("CNET_MIXED_CSV,mode,repeat,bulk_depth,exchanges,elapsed_ns,cpu_ns,p50_rtt_ns,p95_rtt_ns,p99_rtt_ns,bulk_peer_bytes,bulk_admitted,host_rounds,rejected,policy_calls,storage_allocations,receive_acquires,peak_logical_bytes,peak_backing_bytes,physical_source_bytes,native_submissions,bulk_drain_ns,close_ns,warm_receive_acquires\n");
      for (unsigned repetition = 0u; repetition < 5u; ++repetition)
        for (size_t depth = 1u; depth <= 8u; depth *= 8u)
          for (unsigned order = 0u; order < (depth == 1u ? 3u : 2u); ++order) {
            const matched_mode mode = (matched_mode)((repetition + order) % (depth == 1u ? 3u : 2u));
            const int result = mixed_sample(mode, depth, MIXED_EXCHANGES, true, repetition, MATCHED_BYTES, MIXED_STEADY);
            check(result == 0, "mixed benchmark returned %d", result);
          }
    }
  }
  for (size_t window = 1u; window <= 8u; window *= 8u) {
    for (unsigned composed = 0u; composed < 2u; ++composed) {
      it("drains matched retained TCP transfers at window %zu with callback %u", window, composed) {
        const int result = matched_sample(composed != 0u ? MATCHED_CALLBACK : MATCHED_CNET,
                                          window, 16u, false, 0u, MATCHED_BYTES);
        check(result == 0, "matched measurement correctness returned %d", result);
      }
    }
  }
  for (size_t chunk = 4096u; chunk <= MATCHED_BYTES; chunk *= 8u) {
    it("drains direct NativeIO logical writes through real native submissions bounded to %zu bytes", chunk) {
      const int result = matched_sample(MATCHED_NATIVEIO, 1u, 16u, false, 0u, chunk);
      check(result == 0, "direct NativeIO transfer returned %d", result);
    }
  }
  if (getenv("SALTSCORE_CNET_POLICY_BENCHMARK") != NULL) {
    it("measures matched direct NativeIO and CNet TCP admission") {
      check_equal(getenv("SALTSCORE_CNET_POLICY_BENCHMARK"), "1");
      printf("CNET_POLICY_CSV,mode,repeat,window,operations,bytes,elapsed_ns,cpu_ns,p50_ns,p95_ns,p99_ns,rejected,peak_logical_bytes,peak_accounted_backing_bytes,physical_source_bytes,storage_allocations,policy_calls,drain_ns,native_submissions\n");
      for (unsigned repetition = 0u; repetition < 5u; ++repetition)
        for (size_t window = 1u; window <= 8u; window *= 8u)
          for (unsigned order = 0u; order < (window == 1u ? 3u : 2u); ++order) {
            const matched_mode mode = (matched_mode)((repetition + order) % (window == 1u ? 3u : 2u));
            const int result = matched_sample(mode, window, MATCHED_MAX_OPERATIONS, true, repetition, MATCHED_BYTES);
            check(result == 0, "matched benchmark returned %d", result);
          }
    }
  }
  it("changes one connection phase without bypassing client budgets or leaking into reused slots") {
    const int result = saltscore_native_entry_test_cnet_connection_phases();
    check(result == 0, "native connection phases returned %d", result);
  }
  it("preserves the real owner lifecycle and original failure code") {
    const int result = saltscore_original_entry_test_cnet_tcp_loopback_c(0u);
    check(result == 0, "native integration returned %d", result);
  }
  for (unsigned scenario = 1u; scenario <= 7u; ++scenario) {
    it("uses custom providers and settles send admission policy %u", scenario) {
      const int result = saltscore_original_entry_test_cnet_tcp_loopback_c(scenario);
      check(result == 0, "custom policy integration returned %d", result);
    }
  }
  it("keeps TCP persistent through small and retained-vector bulk, then final close") {
    const int result = saltscore_native_entry_test_cnet_tcp_stream_bulk();
    check(result == 0, "native stream transfer returned %d", result);
  }
  it("leases one exact-key TCP connection only after protocol READY and drains retained leases") {
    const int result = saltscore_native_entry_test_cnet_pool_reuse(0u);
    check(result == 0, "native pool reuse returned %d", result);
  }
  for (unsigned close_mode = 1u; close_mode <= 4u; ++close_mode) {
    it("rejects pool reuse before transport terminal after close mode %u", close_mode) {
      const int result = saltscore_native_entry_test_cnet_pool_reuse(close_mode);
      check(result == 0, "native pool close admission returned %d", result);
    }
  }
  it("switches pool selectors across real connections without losing protocol token authority") {
    const int result = saltscore_native_entry_test_cnet_pool_composition();
    check(result == 0, "native pool policy composition returned %d", result);
  }
  it("rejects a foreign Dial client and stops only its Manager-owned connection") {
    const int result = saltscore_native_entry_test_cnet_dial_owner();
    check(result == 0, "native Dial owner returned %d", result);
  }
  it("recovers real TCP incarnations across handshake loss and READY loss, then seals on security failure") {
    const int result = saltscore_native_entry_test_cnet_dial_recovery();
    check(result == 0, "native Dial recovery returned %d", result);
  }
  for (unsigned close_mode = 0u; close_mode <= 4u; ++close_mode) {
    it("admits Dial protocol READY only on a live transport, close mode %u", close_mode) {
      const int result = saltscore_native_entry_test_cnet_dial_ready(close_mode);
      check(result == 0, "native Dial READY returned %d", result);
    }
  }
  it("recovers bounded send credits after rejected FINAL and rejects stale connection generations") {
    const int result = saltscore_native_entry_test_cnet_send_backpressure();
    check(result == 0, "native send backpressure returned %d", result);
  }
  it("holds external close obligations until real success or cancellation completions are routed") {
    const int result = saltscore_native_entry_test_cnet_external_cancel_drain(false);
    check(result == 0, "native external cancellation drain returned %d", result);
  }
  it("closes after an observed vector prefix without submitting its unsent remainder") {
    const int result = saltscore_native_entry_test_cnet_external_cancel_drain(true);
    check(result == 0, "native observed-prefix close returned %d", result);
  }
  it("drains large retained noncontiguous TCP ranges in FIFO order through final send and FIN") {
    const int result = saltscore_native_entry_test_cnet_kernel_pressure(false);
    check(result == 0, "native kernel-pressure drain returned %d", result);
  }
  it("holds a kernel-stalled retained vector until close's real completion is routed") {
    const int result = saltscore_native_entry_test_cnet_kernel_pressure(true);
    check(result == 0, "native kernel-pressure cancellation returned %d", result);
  }
  it("adopts local IPC once, consumes rejected children and drains retained request/reply") {
    const int result = saltscore_native_entry_test_cnet_ipc_lifetime(false);
    check(result == 0, "native IPC lifetime returned %d", result);
  }
  it("rejects TCP-only pipe policy and drains retained native pipe transfer") {
#if defined(_WIN32)
    const int result = saltscore_native_entry_test_cnet_ipc_lifetime(true);
#else
    const int result = saltscore_native_entry_test_cnet_fifo_lifetime();
#endif
    check(result == 0, "native pipe lifetime returned %d", result);
  }
  for (size_t owners = 1u; owners <= 4u; owners *= 2u) {
    it("keeps control exchanges progressing under sustained bounded bulk on %zu SG Owners", owners) {
      const int result = saltscore_native_entry_test_cnet_sg_sustained(owners);
      check(result == 0, "native SG sustained progress returned %d", result);
    }
    it("isolates TLS handshake failure and drains its surviving neighbor on %zu SG Owners", owners) {
      const int result = saltscore_native_entry_test_cnet_sg_tls_failure(owners);
      check(result == 0, "native SG TLS failure returned %d", result);
    }
    it("isolates bulk/control clients and drains %zu fixed SG Owners", owners) {
      const int result = saltscore_native_entry_test_cnet_sg_owners(owners, false);
      check(result == 0, "SG %zu-owner integration returned %d", owners, result);
    }
    it("settles SG-owned I/O once and drains CNet after a route error on %zu Owners", owners) {
      const int result = saltscore_native_entry_test_cnet_sg_owners(owners, true);
      check(result == 0, "SG %zu-owner mixed routing returned %d", owners, result);
    }
  }
}
