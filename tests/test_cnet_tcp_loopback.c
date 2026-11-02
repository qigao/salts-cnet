/*
 * Real local TCP/IPC CNet integration, independent of the former Salts binary.
 * One caller owns each CNet client and listener; TCP peers use native blocking
 * sockets. The received mem_slice_t deliberately survives stop/destroy.
 */
#include <tinytest.h>
#include <cnet/cnet.h>
#include <cnet/client_pool.h>
#include <cnet/ipc.h>
#include <clock.h>
#include <thread.h>
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
  unsigned sends_at_terminal;
  int last_error_status;
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
  if (error != NULL) p->last_error_status = error->status;
  if (state == CNET_CONNECTION_CONNECTED) ++p->connected;
  if (state == CNET_CONNECTION_FAILED || error != NULL) ++p->failed;
  if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
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
static int saltscore_native_entry_test_cnet_pool_reuse(void) {
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

  /* Each changed identity must deny reuse. Optional security IDs remain zero
   * for this plaintext recipe; setting one is a different key, not TLS proof. */
  for (size_t i = 0u; i < sizeof(key_fields) / sizeof(key_fields[0]); ++i) {
    incompatible = key;
    ++*key_fields[i];
    VERIFY(pool_acquire_rejected(&pool, &incompatible,
                                 i == 1u ? SALTS_EINVAL : SALTS_ENOBUFS));
  }

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
  VERIFY(cnet_pool_begin_drain(&pool, physical) == SALTS_OK);
  VERIFY(pool_acquire_rejected(&pool, &key, SALTS_ENOBUFS));
  VERIFY(cnet_close(&client, connection) == SALTS_OK);
  VERIFY(poll_until(&client, &probe.terminal, 1u) == SALTS_OK);
  VERIFY(probe.terminal == 1u && probe.failed == 0u && probe.sent == 2u);
  VERIFY(recv(peer, (char *)&byte, 1, 0) == 0);
  VERIFY(cnet_manager_lookup(&manager, managed, &entry) == SALTS_OK);
  VERIFY(entry.state == CNET_MANAGER_RETIRED && entry.context_held);
  VERIFY(cnet_pool_terminal(&pool, physical) == SALTS_OK);
  VERIFY(cnet_pool_get_snapshot(&pool, &pool_snapshot) == SALTS_OK);
  VERIFY(pool_snapshot.physical_in_use == 1u && pool_snapshot.active_leases == 1u &&
         pool_snapshot.terminal_waiting_for_leases == 1u && !pool_snapshot.drained);
  VERIFY(cnet_pool_destroy(&pool) == SALTS_EBUSY);
  VERIFY(cnet_manager_advance(&manager, 1u, &work) == SALTS_OK);
  VERIFY(probe.recycled == 0u);
  VERIFY(cnet_pool_release(&pool, lease) == SALTS_OK);
  VERIFY(cnet_pool_release(&pool, lease) == SALTS_ENOENT);
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
 * Neither path may destroy early, publish twice, or close the borrowed backend. */
static int saltscore_native_entry_test_cnet_external_cancel_drain(void) {
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
  test_socket peer = TEST_INVALID_SOCKET;
  struct sockaddr_in remote = {0};
  const unsigned char expected[] = {0x31u, 0x72u, 0xa4u, 0xffu};
  unsigned char received[sizeof(expected)] = {0};
  uint16_t port = 0u;
  size_t events = 0u, count = 0u;
  bool consumed = false, held_live = false;
  int client_live = 0, listener_live = 0, backend_live = 0;
  int ready = 0, result = 0;

  config.connection_capacity = 1u;
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

  for (unsigned round = 0u; round < 2u; ++round) {
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
    } else {
      VERIFY(connection.slot == previous.slot && connection.generation != previous.generation);
      VERIFY(cnet_receive(&client, connection, 1u) == SALTS_OK);
    }
    VERIFY(cnet_client_advance_external(&client, &events) == SALTS_OK);
    VERIFY(cnet_client_external_request_snapshots(&client, connection,
                                                  requests, 4u, &count) == SALTS_OK);
    VERIFY(count == 1u && requests[0].operation_kind ==
           (round == 0u ? NATIVE_IO_OPERATION_STREAM_SEND : NATIVE_IO_OPERATION_STREAM_RECV));
    if (round == 0u) {
      VERIFY(observe_external_one(&backend, &held) == SALTS_OK);
      held_live = true;
      VERIFY(held.kind == NATIVE_IO_COMPLETION_OK && held.status == SALTS_OK &&
             held.bytes == sizeof(expected));
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
    if (round == 0u) {
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
    {
      const int status = cnet_client_route_external_completion(&client, &held, &consumed, &events);
      held_live = !consumed;
      VERIFY(status == SALTS_OK);
    }
    VERIFY(consumed);
    if (probe.failed != 0u || probe.terminal != 1u ||
        probe.sent != (round == 0u ? 1u : 0u))
      fprintf(stderr, "external close round %u: terminal=%u failed=%u sent=%u status=%d\n",
              round, probe.terminal, probe.failed, probe.sent, probe.last_error_status);
    VERIFY(probe.terminal == 1u && probe.failed == 0u &&
           probe.sent == (round == 0u ? 1u : 0u) &&
           probe.sends_at_terminal == probe.sent && probe.borrowed_received == 0u);
    if (round == 0u) {
      VERIFY(mem_buffer_ref_count(pending) == 1u);
      VERIFY(test_recv_exact(peer, received, sizeof(received)) == 0);
      VERIFY(memcmp(received, expected, sizeof(expected)) == 0);
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
static int saltscore_native_entry_test_cnet_ipc_lifetime(void) {
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
  char uri[256];
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
  server_cfg.connection_capacity = 1u;
  VERIFY(cnet_client_init(&client, &client_cfg) == SALTS_OK);
  client_live = 1;
  VERIFY(cnet_client_init(&server, &server_cfg) == SALTS_OK);
  server_live = 1;
  VERIFY(cnet_ipc_listener_init(&listener, &listener_cfg) == SALTS_OK);
  listener_live = 1;
  VERIFY(cnet_ipc_listener_advance(&listener, 1u, &events) == SALTS_OK);
  options.uri = uri;
  options.observer = outbound_observer;
  for (size_t i = 0u; i < sizeof(tcp_only_options) / sizeof(tcp_only_options[0]); ++i) {
    socket_options = (cnet_stream_socket_options)CNET_STREAM_SOCKET_OPTIONS_INIT;
    *tcp_only_options[i] = 1;
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

spec("CNet real TCP loopback and retained slice") {
  it("preserves the real owner lifecycle and original failure code") {
    const int result = saltscore_original_entry_test_cnet_tcp_loopback_c();
    check(result == 0, "native integration returned %d", result);
  }
  it("keeps TCP persistent through small and retained-vector bulk, then final close") {
    const int result = saltscore_native_entry_test_cnet_tcp_stream_bulk();
    check(result == 0, "native stream transfer returned %d", result);
  }
  it("leases one exact-key TCP connection only after protocol READY and drains retained leases") {
    const int result = saltscore_native_entry_test_cnet_pool_reuse();
    check(result == 0, "native pool reuse returned %d", result);
  }
  it("recovers bounded send credits after rejected FINAL and rejects stale connection generations") {
    const int result = saltscore_native_entry_test_cnet_send_backpressure();
    check(result == 0, "native send backpressure returned %d", result);
  }
  it("holds external close obligations until real success or cancellation completions are routed") {
    const int result = saltscore_native_entry_test_cnet_external_cancel_drain();
    check(result == 0, "native external cancellation drain returned %d", result);
  }
  it("adopts local IPC once, consumes rejected children and drains retained request/reply") {
    const int result = saltscore_native_entry_test_cnet_ipc_lifetime();
    check(result == 0, "native IPC lifetime returned %d", result);
  }
}
