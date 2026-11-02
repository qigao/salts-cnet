/*
 * Real loopback TCP CNet integration, independent of the former Salts binary.
 * One caller owns the CNet client and listener. The native peer owns its
 * blocking socket. The received mem_slice_t deliberately survives stop/destroy.
 */
#include <tinytest.h>
#include <cnet/cnet.h>
#include <cnet/client_pool.h>
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
  if (state == CNET_CONNECTION_CONNECTED) ++p->connected;
  if (state == CNET_CONNECTION_FAILED || error != NULL) ++p->failed;
  if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED)
    ++p->terminal;
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
}
