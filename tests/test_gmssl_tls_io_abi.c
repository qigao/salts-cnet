/* Provider ABI and real paired CipherBIO TLS close semantics.
 * CNet/NativeIO and independent-peer conformance have separate formal tests.
 * This executable links the actual pinned GmSSL provider. */
#include <tinytest.h>
#include <crypto/tls_close.h>
#include <crypto/cipher_bio.h>
#include <crypto/tls_stream.h>
#include <gmssl/tls.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <native_io.h>
#include <clock.h>
#include <cmeta_buffer.h>
#include <error_codes.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET native_tls_socket;
#define NATIVE_TLS_INVALID INVALID_SOCKET
static void native_tls_socket_close(native_tls_socket s) { if (s != INVALID_SOCKET) (void)closesocket(s); }
static int native_tls_nonblocking(native_tls_socket s) { u_long on = 1u; return ioctlsocket(s, FIONBIO, &on); }
static bool native_tls_would_block(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <unistd.h>
typedef int native_tls_socket;
#define NATIVE_TLS_INVALID (-1)
static void native_tls_socket_close(native_tls_socket s) { if (s >= 0) (void)close(s); }
static int native_tls_nonblocking(native_tls_socket s) {
  const int flags = fcntl(s, F_GETFL, 0);
  return flags < 0 ? -1 : fcntl(s, F_SETFL, flags | O_NONBLOCK);
}
static bool native_tls_would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

static crypto_tls_stream_context *stream_context[2];
static crypto_tls_stream *stream_pair[2];

static void transfer_stream_cipher(unsigned from, unsigned to) {
  uint8_t wire[32768];
  size_t size = 0u;
  int result = crypto_tls_stream_take_cipher(stream_pair[from], wire, sizeof(wire), &size);
  check(result == CRYPTO_TLS_STREAM_OK || result == CRYPTO_TLS_STREAM_ENOENT);
  if (size != 0u)
    check_equal(crypto_tls_stream_feed_cipher(stream_pair[to], wire, size),
                CRYPTO_TLS_STREAM_OK);
}

spec("Opaque Crypto streams retain policy and bounded storage") {
  before_each() {
    memset(stream_context, 0, sizeof(stream_context));
    memset(stream_pair, 0, sizeof(stream_pair));
  }
  after_each() {
    for (unsigned i = 0; i < 2u; ++i) {
      crypto_tls_stream_destroy(stream_pair[i]);
      crypto_tls_stream_context_release(stream_context[i]);
    }
  }
  for (unsigned version = 0; version < 2u; ++version) {
    it("TLS1.%u survives creator release and preserves authenticated shutdown", version + 2u) {
      char alpn_name[] = "stream-test";
      const char *alpn[] = {alpn_name};
      crypto_tls_stream_client_config client = {sizeof(client)};
      crypto_tls_stream_server_config server = {sizeof(server)};
      crypto_tls_stream_protocol_version protocol = version
          ? CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3 : CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2;
      bool complete[2] = {false, false};
      client.ca_file = CRYPTO_CLOSE_TEST_CA;
      client.server_name = "localhost";
      client.alpn_protocols = alpn;
      client.alpn_protocol_count = 1u;
      server.cert_file = CRYPTO_CLOSE_TEST_SERVER_CERT;
      server.key_file = CRYPTO_CLOSE_TEST_SERVER_KEY;
      server.alpn_protocols = alpn;
      server.alpn_protocol_count = 1u;
      check_equal(crypto_tls_stream_client_context_create(&client, &stream_context[0]),
                  CRYPTO_TLS_STREAM_OK);
      check_equal(crypto_tls_stream_server_context_create(&server, &stream_context[1]),
                  CRYPTO_TLS_STREAM_OK);
      memset(alpn_name, 'x', sizeof(alpn_name) - 1u); /* policy must own its copy */
      check_equal(crypto_tls_stream_create(stream_context[0], true, "localhost",
                    32768u, &stream_pair[0]), CRYPTO_TLS_STREAM_EINVAL);
      check_null(stream_pair[0]);
      check_equal(crypto_tls_stream_create(stream_context[0], false, "localhost",
                    SIZE_MAX, &stream_pair[0]), CRYPTO_TLS_STREAM_ERANGE);
      check_null(stream_pair[0]);
      for (unsigned i = 0; i < 2u; ++i) {
        check_equal(crypto_tls_stream_create(stream_context[i], i != 0u,
                      i == 0u ? "localhost" : NULL, 32768u, &stream_pair[i]),
                    CRYPTO_TLS_STREAM_OK);
        crypto_tls_stream_context_release(stream_context[i]);
        stream_context[i] = NULL; /* stream's retained context is now the only owner */
        check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], protocol, protocol),
                    CRYPTO_TLS_STREAM_OK);
        check_not_null(crypto_tls_stream_read_buffer(stream_pair[i]));
        check_not_null(crypto_tls_stream_write_buffer(stream_pair[i]));
        check_not_equal(crypto_tls_stream_read_buffer(stream_pair[i]),
                        crypto_tls_stream_write_buffer(stream_pair[i]));
      }
      for (unsigned step = 0; step < 128u && !(complete[0] && complete[1]); ++step) {
        for (unsigned i = 0; i < 2u; ++i) {
          check_equal(crypto_tls_stream_handshake(stream_pair[i], &complete[i]), CRYPTO_TLS_STREAM_OK);
          if (step == 0u)
            check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], protocol, protocol),
                        CRYPTO_TLS_STREAM_EINVAL);
          transfer_stream_cipher(i, 1u - i);
        }
      }
      check(complete[0] && complete[1]);
      for (unsigned i = 0; i < 2u; ++i) {
        const unsigned char *selected = NULL;
        size_t size = 0u;
        check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], protocol, protocol),
                    CRYPTO_TLS_STREAM_EINVAL);
        check_equal(crypto_tls_stream_get_negotiated_alpn(stream_pair[i], &selected, &size),
                    CRYPTO_TLS_STREAM_OK);
        check_equal(size, sizeof("stream-test") - 1u);
        check_equal(selected, "stream-test", size);
      }
      {
        uint8_t overflow[32769] = {0};
        size_t capacity = crypto_tls_stream_cipher_input_capacity(stream_pair[1]);
        check_equal(crypto_tls_stream_feed_cipher(stream_pair[1], overflow, sizeof(overflow)),
                    CRYPTO_TLS_STREAM_ENOBUFS);
        check_equal(crypto_tls_stream_cipher_input_capacity(stream_pair[1]), capacity);
      }
      {
        const uint8_t payload[] = "retained-policy";
        uint8_t received[32] = {0};
        size_t size = 0u;
        bool written = false, peer_closed = false;
        check_equal(crypto_tls_stream_write(stream_pair[0], payload, sizeof(payload), &written),
                    CRYPTO_TLS_STREAM_OK);
        check_true(written);
        transfer_stream_cipher(0, 1);
        check_equal(crypto_tls_stream_read(stream_pair[1], received, sizeof(received), &size, &peer_closed),
                    CRYPTO_TLS_STREAM_OK);
        check_false(peer_closed);
        check_equal(size, sizeof(payload));
        check_equal(received, payload, size);
      }
      {
        bool generated = false, peer = false, pending = false;
        check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
        check_true(generated);
        check_false(peer);
        transfer_stream_cipher(0, 1);
        check_equal(crypto_tls_stream_probe_peer_close(stream_pair[1], &peer, &pending), CRYPTO_TLS_STREAM_OK);
        check_true(peer);
        check_false(pending);
        check_equal(crypto_tls_stream_shutdown(stream_pair[1], &generated, &peer), CRYPTO_TLS_STREAM_OK);
        check_true(generated);
        check_true(peer);
        transfer_stream_cipher(1, 0);
        check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
        check_true(peer);
      }
    }
  }
}

typedef struct tls_io_probe {
  size_t sent;
  size_t received;
} tls_io_probe;

static tls_ret_t reject_send(void *ctx, const void *data, size_t length, int flags) {
  tls_io_probe *p = (tls_io_probe *)ctx;
  (void)data;
  (void)length;
  (void)flags;
  if (!p) return TLS_ERROR_SYSCALL;
  ++p->sent;
  return TLS_ERROR_SEND_AGAIN;
}
static tls_ret_t reject_receive(void *ctx, void *data, size_t length, int flags) {
  tls_io_probe *p = (tls_io_probe *)ctx;
  (void)data;
  (void)length;
  (void)flags;
  if (!p) return TLS_ERROR_SYSCALL;
  ++p->received;
  return TLS_ERROR_RECV_AGAIN;
}
static int saltscore_legacy_entry_test_gmssl_tls_io_abi_c(void) {
  TLS_CONNECT connection = {0};
  TLS_IO io = {0};
  tls_io_probe probe = {0};
  unsigned char payload = 0x5au;

  if (sizeof(TLS_CTX) != tls_ctx_sizeof() ||
      sizeof(TLS_CONNECT) != tls_connect_sizeof()) {
    fprintf(stderr, "GmSSL provider public TLS structures differ from runtime ABI\n");
    return 1;
  }
  io.user = &probe;
  io.send = reject_send;
  io.recv = reject_receive;
  if (tls_set_io(&connection, &io) != 1) {
    fprintf(stderr, "Pinned GmSSL external I/O setter failed\n");
    return 2;
  }
  if (tls_io_send(&connection, &payload, sizeof payload, 0) >= 0 ||
      tls_io_recv(&connection, &payload, sizeof payload, 0) >= 0 ||
      probe.sent != 1u || probe.received != 1u) {
    fprintf(stderr, "GmSSL external I/O did not preserve send/recv retry\n");
    return 3;
  }
  return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("GmSSL TLS IO callback ABI") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_gmssl_tls_io_abi_c();
    check(result == 0, "original native contract returned %d", result);
  }
}

spec("Crypto versioned peer close_notify facade") {
  it("rejects absent and malformed output without falsifying evidence") {
    uint32_t peer = UINT32_C(0xfeedbeef);
    check(crypto_tls_close_abi_version() == CRYPTO_TLS_CLOSE_ABI_VERSION,
          "close extension API version changed");
    check(crypto_tls_session_peer_close_notify_v1_4(NULL, &peer)
          == CRYPTO_TLS_INVALID_ARGUMENT,
          "NULL TLS session must be rejected");
    check(peer == UINT32_C(0xfeedbeef),
          "invalid session must not modify peer-alert evidence");
    check(crypto_tls_session_peer_close_notify_v1_4(NULL, NULL)
          == CRYPTO_TLS_INVALID_ARGUMENT,
          "NULL peer-alert output must be rejected");
  }
}

static int64_t would_block_write(
    void *user, const uint8_t *bytes, size_t length)
{
  (void)user;
  (void)bytes;
  (void)length;
  return CRYPTO_TLS_IO_AGAIN;
}

static int64_t would_block_read(
    void *user, uint8_t *bytes, size_t capacity)
{
  (void)user;
  (void)bytes;
  (void)capacity;
  return CRYPTO_TLS_IO_AGAIN;
}

spec("Crypto close_notify read-only ownership") {
  it("does not forge peer alerts before handshake or on cancel") {
    crypto_tls_provider *provider = NULL;
    crypto_tls_session *session = NULL;
    crypto_tls_session_options options = {0};
    crypto_tls_io io = {0};
    crypto_tls_result create_result;
    uint32_t observed = UINT32_C(0xfeedbeef);
    uint32_t count = 0u;

    options.struct_size = (uint32_t)sizeof(options);
    options.protocol = CRYPTO_TLS_1_3;
    options.role = CRYPTO_TLS_SERVER;
    options.certificate_file = CRYPTO_CLOSE_TEST_SERVER_CERT;
    options.private_key_file = CRYPTO_CLOSE_TEST_SERVER_KEY;
    io.struct_size = (uint32_t)sizeof(io);
    io.read = would_block_read;
    io.write = would_block_write;
    check(crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION, &provider)
          == CRYPTO_TLS_OK && provider != NULL,
          "cannot create real Crypto TLS provider");
    if (provider != NULL) {
      create_result = crypto_tls_session_create(
          provider, &options, &io, &session);
      check(create_result == CRYPTO_TLS_OK && session != NULL,
            "cannot create real pinned TLS server association: %d",
            (int)create_result);
      if (session != NULL) {
        check(crypto_tls_session_peer_close_notify_v1_4(session, &observed)
              == CRYPTO_TLS_AGAIN && observed == UINT32_C(0xfeedbeef),
              "uncompleted handshake must leave peer evidence unchanged");
        check(crypto_tls_provider_session_count(provider, &count)
              == CRYPTO_TLS_OK && count == 1u,
              "provider must retain its live session");
        check(crypto_tls_provider_destroy(&provider) == CRYPTO_TLS_BUSY
              && provider != NULL,
              "cannot destroy provider while its native session is live");
        check(crypto_tls_session_cancel(session) == CRYPTO_TLS_OK,
              "session cancel failed");
        check(crypto_tls_session_peer_close_notify_v1_4(session, &observed)
              == CRYPTO_TLS_CANCELLED
              && observed == UINT32_C(0xfeedbeef),
              "cancel must not create authenticated peer alert");
        check(crypto_tls_session_destroy(&session) == CRYPTO_TLS_OK
              && session == NULL,
              "destroy must wait for a quiescent session");
      }
      check(crypto_tls_provider_destroy(&provider) == CRYPTO_TLS_OK
            && provider == NULL,
            "provider cleanup failed after session teardown");
    }
  }
}

static crypto_tls_provider *close_provider;
static crypto_tls_session *close_session[2];
static crypto_tls_cipher_bio *close_bio[2];
static bool close_io_leased[2];

static void transfer_close_cipher(unsigned from, unsigned to) {
  uint8_t wire[32768];
  size_t size = 0u;
  crypto_tls_result result = crypto_tls_cipher_bio_take_cipher(
      close_bio[from], wire, sizeof(wire), &size);
  check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
  if (size != 0u)
    check_equal(crypto_tls_cipher_bio_feed_cipher(close_bio[to], wire, size),
                CRYPTO_TLS_OK);
}

static void establish_close_pair(crypto_tls_protocol protocol) {
  bool complete[2] = {false, false};
  for (unsigned i = 0u; i < 2u; ++i) {
    crypto_tls_session_options options = {0};
    crypto_tls_io io = {0};
    options.struct_size = sizeof(options);
    options.protocol = protocol;
    options.role = i == 0u ? CRYPTO_TLS_CLIENT : CRYPTO_TLS_SERVER;
    if (i == 0u) {
      options.hostname = "localhost";
      options.ca_file = CRYPTO_CLOSE_TEST_CA;
    } else {
      options.certificate_file = CRYPTO_CLOSE_TEST_SERVER_CERT;
      options.private_key_file = CRYPTO_CLOSE_TEST_SERVER_KEY;
    }
    check_equal(crypto_tls_cipher_bio_create(32768u, &close_bio[i]), CRYPTO_TLS_OK);
    io.struct_size = sizeof(io);
    check_equal(crypto_tls_cipher_bio_acquire_io(close_bio[i], &io), CRYPTO_TLS_OK);
    close_io_leased[i] = true;
    check_equal(crypto_tls_session_create(close_provider, &options, &io,
                                         &close_session[i]), CRYPTO_TLS_OK);
  }
  for (unsigned step = 0u; step < 128u && !(complete[0] && complete[1]); ++step) {
    for (unsigned i = 0u; i < 2u; ++i) {
      if (!complete[i]) {
        crypto_tls_result result = crypto_tls_session_handshake(close_session[i]);
        check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
        complete[i] = result == CRYPTO_TLS_OK;
      }
      transfer_close_cipher(i, 1u - i);
    }
  }
  check(complete[0] && complete[1], "real paired TLS handshake must finish");
}

spec("Crypto authenticated close evidence after real handshake") {
  before_each() {
    close_provider = NULL;
    memset(close_session, 0, sizeof(close_session));
    memset(close_bio, 0, sizeof(close_bio));
    memset(close_io_leased, 0, sizeof(close_io_leased));
    check_equal(crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION,
                                          &close_provider), CRYPTO_TLS_OK);
  }
  after_each() {
    for (unsigned i = 0u; i < 2u; ++i) {
      if (close_session[i])
        check_equal(crypto_tls_session_destroy(&close_session[i]), CRYPTO_TLS_OK);
      if (close_io_leased[i])
        check_equal(crypto_tls_cipher_bio_release_io(close_bio[i]), CRYPTO_TLS_OK);
      if (close_bio[i])
        check_equal(crypto_tls_cipher_bio_destroy(&close_bio[i]), CRYPTO_TLS_OK);
    }
    if (close_provider)
      check_equal(crypto_tls_provider_destroy(&close_provider), CRYPTO_TLS_OK);
  }
  for (unsigned version = 0u; version < 2u; ++version) {
    const crypto_tls_protocol protocol = version ? CRYPTO_TLS_1_3 : CRYPTO_TLS_1_2;
    const char *modes[] = {"reciprocal", "EOF", "truncated", "corrupted", "cancelled"};
    for (unsigned mode = 0u; mode < 5u; ++mode) {
      it("TLS1.%u %s cannot forge peer consent", version + 2u, modes[mode]) {
        uint8_t wire[32768], plaintext[32];
        size_t wire_size = 0u, size = 0u;
        uint32_t received = 99u;
        crypto_tls_result result;
        establish_close_pair(protocol);
        result = crypto_tls_session_shutdown(close_session[0]);
        check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
        check_equal(crypto_tls_session_peer_close_notify_v1_4(
                        close_session[0], &received), CRYPTO_TLS_OK);
        check_equal(received, 0u); /* Local alert is not peer evidence. */
        check_equal(crypto_tls_cipher_bio_take_cipher(
                        close_bio[0], wire, sizeof(wire), &wire_size), CRYPTO_TLS_OK);
        check(wire_size > 5u);
        if (mode != 1u) {
          if (mode == 2u) --wire_size;
          if (mode == 3u) wire[wire_size - 1u] ^= 1u;
          check_equal(crypto_tls_cipher_bio_feed_cipher(
                          close_bio[1], wire, wire_size), CRYPTO_TLS_OK);
        }
        if (mode == 1u || mode == 2u)
          check_equal(crypto_tls_cipher_bio_end_input(close_bio[1]), CRYPTO_TLS_OK);
        if (mode == 4u)
          check_equal(crypto_tls_session_cancel(close_session[1]), CRYPTO_TLS_OK);
        result = crypto_tls_session_receive(close_session[1], plaintext,
                                             sizeof(plaintext), &size);
        check_equal(size, 0u);
        received = 99u;
        check_equal(crypto_tls_session_peer_close_notify_v1_4(
                        close_session[1], &received),
                    mode == 4u ? CRYPTO_TLS_CANCELLED : CRYPTO_TLS_OK);
        check_equal(received, mode == 4u ? 99u : mode == 0u ? 1u : 0u);
        if (mode == 0u) {
          result = crypto_tls_session_shutdown(close_session[1]);
          check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
          transfer_close_cipher(1u, 0u);
          result = crypto_tls_session_shutdown(close_session[0]);
          check_equal(result, CRYPTO_TLS_OK);
          check_equal(crypto_tls_session_peer_close_notify_v1_4(
                          close_session[0], &received), CRYPTO_TLS_OK);
          check_equal(received, 1u);
        } else {
          check(result < CRYPTO_TLS_OK, "invalid closure must terminate");
          check_equal(crypto_tls_session_receive(close_session[1], plaintext,
                          sizeof(plaintext), &size), result);
          check_equal(crypto_tls_session_shutdown(close_session[1]), result);
        }
      }
    }
  }
}

/* Same production primitives as CNet, in this separate formal executable.
 * See docs/CNET-NATIVE-TLS-BENCHMARK.md. No CNet linkage or application FIFO. */
enum { NATIVE_TLS_BYTES = 32768, NATIVE_TLS_WRITES = 2048,
       NATIVE_TLS_IO = CRYPTO_TLS_STREAM_MIN_IO_BUFFER_BYTES };
typedef struct native_tls_end {
  native_io_backend backend;
  native_io_endpoint endpoint;
  native_io_request read, write, connect;
  native_tls_socket socket;
  crypto_tls_stream_context *context;
  crypto_tls_stream *stream;
  size_t read_size, wire_size, wire_offset, submitted;
  bool connected, ready, peer_closed, notify_generated, drained;
  char version[24], cipher[128];
} native_tls_end;
typedef struct native_tls_fixture {
  native_tls_end ends[2];
  native_tls_socket listener;
  struct sockaddr_in address;
  mem_buffer_t *source;
  size_t chunk, offered, completed, received, receive_offset, target;
  size_t continuations;
  bool retained, accepted, closing, stopping;
  unsigned char plaintext[NATIVE_TLS_BYTES];
  uint64_t starts[NATIVE_TLS_WRITES], latency[NATIVE_TLS_WRITES];
} native_tls_fixture;
typedef struct native_tls_result {
  uint64_t elapsed, cpu, p50, p95, p99, submissions;
  size_t bytes, peak_bytes, peak_backing, continuations;
} native_tls_result;
static size_t native_tls_size(size_t index) { return index % 8u == 0u ? 1u : NATIVE_TLS_BYTES; }
static native_io_backend_kind native_tls_backend(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#else
  return NATIVE_IO_BACKEND_EPOLL;
#endif
}
static int native_tls_cpu(uint64_t *out) {
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
static int native_tls_compare(const void *a, const void *b) {
  const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}
static bool native_tls_matches(native_io_request a, native_io_request b) {
  return native_io_request_valid(a) && a.slot == b.slot && a.generation == b.generation;
}
static int native_tls_offer(native_tls_fixture *f) {
  if (f->retained) return SALTS_ENOBUFS;
  if (f->closing || !f->ends[0].ready || !f->ends[1].ready) return SALTS_EBUSY;
  if (f->offered >= f->target) return SALTS_EINVAL;
  mem_buffer_retain(f->source);
  f->retained = true;
  f->accepted = false;
  ++f->offered;
  return SALTS_OK;
}
static int native_tls_flush(native_tls_fixture *f, native_tls_end *end) {
  end->drained = false;
  if (native_io_request_valid(end->write)) return SALTS_OK;
  if (end->wire_offset == end->wire_size) {
    end->wire_offset = end->wire_size = 0u;
    const int status = crypto_tls_stream_take_cipher(end->stream,
        crypto_tls_stream_write_buffer(end->stream), NATIVE_TLS_IO, &end->wire_size);
    if (status == CRYPTO_TLS_STREAM_ENOENT) { end->drained = true; return SALTS_OK; }
    if (status != CRYPTO_TLS_STREAM_OK || end->wire_size == 0u) return SALTS_EPROTO;
  }
  const size_t remaining = end->wire_size - end->wire_offset;
  end->submitted = remaining < f->chunk ? remaining : f->chunk;
  const native_io_operation operation = {.kind = NATIVE_IO_OPERATION_STREAM_SEND,
      .endpoint = end->endpoint,
      .buffer = (unsigned char *)crypto_tls_stream_write_buffer(end->stream) + end->wire_offset,
      .length = end->submitted, .user_data = 2u};
  return native_io_backend_submit(&end->backend, &operation, &end->write);
}
static int native_tls_pump(native_tls_fixture *f, size_t index) {
  native_tls_end *end = &f->ends[index];
  if (!end->stream || f->stopping) return SALTS_OK;
  int status;
  if (!end->ready) {
    status = crypto_tls_stream_handshake(end->stream, &end->ready);
    if (status != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
  } else if (f->closing) {
    if (index == 1u && !end->peer_closed) {
      bool plaintext_pending = false;
      status = crypto_tls_stream_probe_peer_close(end->stream, &end->peer_closed, &plaintext_pending);
      if (status != CRYPTO_TLS_STREAM_OK || plaintext_pending) return SALTS_EPROTO;
    }
    if (index == 0u || end->peer_closed) {
      bool generated = false, received = false;
      status = crypto_tls_stream_shutdown(end->stream, &generated, &received);
      if (status != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
      end->notify_generated |= generated;
      end->peer_closed |= received;
    }
  } else {
    if (index == 0u && f->retained && !f->accepted) {
      status = crypto_tls_stream_write(end->stream, mem_buffer_data(f->source),
          native_tls_size(f->completed), &f->accepted);
      if (status != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
    }
    if (index == 1u && f->received < f->target) {
      size_t bytes = 0u;
      bool peer_closed = false;
      status = crypto_tls_stream_read(end->stream, f->plaintext, sizeof(f->plaintext), &bytes, &peer_closed);
      if (status != CRYPTO_TLS_STREAM_OK || peer_closed) return SALTS_EPROTO;
      for (size_t i = 0u; i < bytes; ++i) {
        if (f->received >= f->target || f->plaintext[i] !=
            (unsigned char)((0x5au + f->receive_offset * 29u) & 0xffu)) return SALTS_EPROTO;
        if (++f->receive_offset == native_tls_size(f->received)) {
          ++f->received;
          f->receive_offset = 0u;
        }
      }
    }
  }
  status = native_tls_flush(f, end);
  if (status != SALTS_OK) return status;
  if (index == 0u && f->retained && f->accepted && end->drained) {
    if (f->completed >= f->offered || mem_buffer_ref_count(f->source) != 2u) return SALTS_EPROTO;
    f->latency[f->completed] = cmeta_hrtime() - f->starts[f->completed];
    ++f->completed;
    f->retained = false;
    mem_buffer_release(f->source);
  }
  if (!native_io_request_valid(end->read) && !(f->closing && end->peer_closed)) {
    const size_t capacity = crypto_tls_stream_cipher_input_capacity(end->stream);
    if (capacity != 0u) {
      end->read_size = capacity < NATIVE_TLS_IO ? capacity : NATIVE_TLS_IO;
      const native_io_operation operation = {.kind = NATIVE_IO_OPERATION_STREAM_RECV,
          .endpoint = end->endpoint, .buffer = crypto_tls_stream_read_buffer(end->stream),
          .length = end->read_size, .user_data = 1u};
      return native_io_backend_submit(&end->backend, &operation, &end->read);
    }
  }
  return SALTS_OK;
}
static int native_tls_route(native_tls_fixture *f, native_tls_end *end, const native_io_completion *c) {
  if (c->endpoint.slot != end->endpoint.slot || c->endpoint.generation != end->endpoint.generation)
    return SALTS_EPROTO;
  if (native_tls_matches(end->connect, c->request)) {
    end->connect = (native_io_request){0};
    if (f->stopping) return c->user_data == 3u ? SALTS_OK : SALTS_EPROTO;
    if (c->user_data != 3u || c->kind != NATIVE_IO_COMPLETION_OK || c->status != SALTS_OK)
      return SALTS_EIO;
    end->connected = true;
    return SALTS_OK;
  }
  const bool read = native_tls_matches(end->read, c->request);
  if (!read && !native_tls_matches(end->write, c->request)) return SALTS_EPROTO;
  if (read) end->read = (native_io_request){0};
  else end->write = (native_io_request){0};
  if (c->user_data != (read ? 1u : 2u)) return SALTS_EPROTO;
  if (f->stopping) return SALTS_OK; /* Actual observation retired the borrow. */
  if (c->kind != NATIVE_IO_COMPLETION_OK || c->status != SALTS_OK || c->bytes == 0u)
    return SALTS_EIO;
  if (read) {
    if (c->bytes > end->read_size || crypto_tls_stream_feed_cipher(end->stream,
          crypto_tls_stream_read_buffer(end->stream), c->bytes) != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
  } else {
    if (c->bytes > end->submitted || c->bytes > end->wire_size - end->wire_offset) return SALTS_EPROTO;
    end->wire_offset += c->bytes;
    if (end->wire_offset < end->wire_size) ++f->continuations;
  }
  return SALTS_OK;
}
static int native_tls_progress(native_tls_fixture *f) {
  int first = SALTS_OK;
  for (size_t i = 0u; i < 2u; ++i) {
    native_tls_end *end = &f->ends[i];
    if (end->backend.impl == NULL) continue;
    int status = native_tls_pump(f, i);
    if (status != SALTS_OK && first == SALTS_OK) first = status;
    native_io_completion completions[4];
    size_t count = 0u;
    status = native_io_backend_observe(&end->backend, completions, 4u, 0u, &count);
    if (status != SALTS_OK && status != SALTS_ETIMEDOUT && first == SALTS_OK) first = status;
    for (size_t j = 0u; j < count; ++j) {
      status = native_tls_route(f, end, &completions[j]);
      if (status != SALTS_OK && first == SALTS_OK) first = status;
    }
  }
  return first;
}
static int native_tls_transfer(native_tls_fixture *f, size_t operations, bool check_full, native_tls_result *out) {
  native_io_backend_stats before[2], after[2];
  uint64_t cpu_start, cpu_end;
  const size_t continuations = f->continuations;
  if (operations == 0u || operations > NATIVE_TLS_WRITES || operations % 8u != 0u || f->retained)
    return SALTS_EINVAL;
  *out = (native_tls_result){0};
  f->target = operations;
  f->offered = f->completed = f->received = f->receive_offset = 0u;
  for (size_t i = 0u; i < 2u; ++i)
    if (!native_io_backend_get_stats(&f->ends[i].backend, &before[i])) return SALTS_EIO;
  if (native_tls_cpu(&cpu_start) != SALTS_OK) return SALTS_EIO;
  const uint64_t start = cmeta_hrtime(), deadline = start + UINT64_C(20000000000);
  while ((f->completed != operations || f->received != operations) && cmeta_hrtime() < deadline) {
    if (!f->retained && f->offered < operations) {
      f->starts[f->offered] = cmeta_hrtime();
      if (native_tls_offer(f) != SALTS_OK) return SALTS_EPROTO;
      if (check_full && (native_tls_offer(f) != SALTS_ENOBUFS ||
          mem_buffer_ref_count(f->source) != 2u)) return SALTS_EPROTO;
    }
    if (f->retained) {
      const size_t bytes = native_tls_size(f->completed);
      if (bytes > out->peak_bytes) out->peak_bytes = bytes;
      out->peak_backing = mem_buffer_capacity(f->source);
    }
    const int status = native_tls_progress(f);
    if (status != SALTS_OK) return status;
  }
  out->elapsed = cmeta_hrtime() - start;
  if (native_tls_cpu(&cpu_end) != SALTS_OK || cpu_end < cpu_start) return SALTS_EIO;
  out->cpu = cpu_end - cpu_start;
  out->continuations = f->continuations - continuations;
  if (f->completed != operations || f->received != operations || f->receive_offset || f->retained ||
      mem_buffer_ref_count(f->source) != 1u) return SALTS_EPROTO;
  for (size_t i = 0u; i < 2u; ++i) {
    if (!native_io_backend_get_stats(&f->ends[i].backend, &after[i])) return SALTS_EIO;
    out->submissions += after[i].submitted - before[i].submitted;
  }
  out->bytes = operations / 8u * (7u * NATIVE_TLS_BYTES + 1u);
  qsort(f->latency, operations, sizeof(f->latency[0]), native_tls_compare);
  out->p50 = f->latency[(operations * 50u + 99u) / 100u - 1u];
  out->p95 = f->latency[(operations * 95u + 99u) / 100u - 1u];
  out->p99 = f->latency[(operations * 99u + 99u) / 100u - 1u];
  return SALTS_OK;
}
static bool native_tls_pending(native_tls_fixture *f) {
  for (size_t i = 0u; i < 2u; ++i)
    if (native_io_request_valid(f->ends[i].read) || native_io_request_valid(f->ends[i].write) ||
        native_io_request_valid(f->ends[i].connect)) return true;
  return false;
}
static int native_tls_drain(native_tls_fixture *f) {
  f->stopping = true;
  for (size_t i = 0u; i < 2u; ++i) {
    native_tls_end *end = &f->ends[i];
    if (native_io_request_valid(end->read)) (void)native_io_backend_cancel(&end->backend, end->read);
    if (native_io_request_valid(end->write)) (void)native_io_backend_cancel(&end->backend, end->write);
    if (native_io_request_valid(end->connect)) (void)native_io_backend_cancel(&end->backend, end->connect);
  }
  const uint64_t deadline = cmeta_monotonic_ms() + 3000u;
  int first = SALTS_OK;
  while (native_tls_pending(f) && cmeta_monotonic_ms() < deadline) {
    const int status = native_tls_progress(f);
    if (status != SALTS_OK && first == SALTS_OK) first = status;
  }
  return native_tls_pending(f) ? SALTS_ETIMEDOUT : first;
}
#define NATIVE_TLS_REQUIRE(expr) do { if (!(expr)) { \
  fprintf(stderr, "Native TLS benchmark failed at %d: %s\n", __LINE__, #expr); \
  result = __LINE__; goto cleanup; } } while (0)

static int native_tls_sample(bool report, unsigned repetition, size_t chunk) {
  native_tls_fixture *f = calloc(1u, sizeof(*f));
  int result = 0, transfer_status = SALTS_EIO;
  native_tls_result warm, measured;
  const size_t operations = report ? NATIVE_TLS_WRITES : 16u;
  uint64_t handshake_ns = 0u, close_ns = 0u;
  if (!f) return __LINE__;
  f->listener = NATIVE_TLS_INVALID;
  for (size_t i = 0u; i < 2u; ++i) f->ends[i].socket = NATIVE_TLS_INVALID;
  f->chunk = chunk;
  const native_io_backend_config cfg = {native_tls_backend(), 2u, 8u, 4u};
  const crypto_tls_stream_client_config client_cfg = {
      .size = sizeof(crypto_tls_stream_client_config), .ca_file = CRYPTO_NATIVE_BENCH_CA,
      .server_name = "localhost"};
  const crypto_tls_stream_server_config server_cfg = {
      .size = sizeof(crypto_tls_stream_server_config), .cert_file = CRYPTO_NATIVE_BENCH_CERT,
      .key_file = CRYPTO_NATIVE_BENCH_KEY};
  NATIVE_TLS_REQUIRE(chunk > 0u && chunk <= NATIVE_TLS_IO);
  for (size_t i = 0u; i < 2u; ++i)
    NATIVE_TLS_REQUIRE(native_io_backend_init(&f->ends[i].backend, &cfg) == SALTS_OK);
  f->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  NATIVE_TLS_REQUIRE(f->listener != NATIVE_TLS_INVALID && native_tls_nonblocking(f->listener) == 0);
  f->address.sin_family = AF_INET;
  f->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  NATIVE_TLS_REQUIRE(bind(f->listener, (const struct sockaddr *)&f->address, sizeof(f->address)) == 0);
  NATIVE_TLS_REQUIRE(listen(f->listener, 2) == 0);
#if defined(_WIN32)
  int address_size = sizeof(f->address);
#else
  socklen_t address_size = sizeof(f->address);
#endif
  NATIVE_TLS_REQUIRE(getsockname(f->listener, (struct sockaddr *)&f->address, &address_size) == 0);
  f->ends[0].socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  NATIVE_TLS_REQUIRE(f->ends[0].socket != NATIVE_TLS_INVALID && native_tls_nonblocking(f->ends[0].socket) == 0);
  NATIVE_TLS_REQUIRE(native_io_backend_attach_socket(&f->ends[0].backend,
      (uintptr_t)f->ends[0].socket, &f->ends[0].endpoint) == SALTS_OK);
  const native_io_operation connect = {.kind = NATIVE_IO_OPERATION_STREAM_CONNECT,
      .endpoint = f->ends[0].endpoint, .address = &f->address,
      .address_capacity = sizeof(f->address), .address_length = sizeof(f->address), .user_data = 3u};
  NATIVE_TLS_REQUIRE(native_io_backend_submit(&f->ends[0].backend, &connect, &f->ends[0].connect) == SALTS_OK);
  uint64_t deadline = cmeta_monotonic_ms() + 5000u;
  while ((!f->ends[0].connected || !f->ends[1].connected) && cmeta_monotonic_ms() < deadline) {
    if (!f->ends[1].connected) {
      f->ends[1].socket = accept(f->listener, NULL, NULL);
      if (f->ends[1].socket != NATIVE_TLS_INVALID) {
        NATIVE_TLS_REQUIRE(native_tls_nonblocking(f->ends[1].socket) == 0);
        NATIVE_TLS_REQUIRE(native_io_backend_attach_socket(&f->ends[1].backend,
            (uintptr_t)f->ends[1].socket, &f->ends[1].endpoint) == SALTS_OK);
        f->ends[1].connected = true;
      } else NATIVE_TLS_REQUIRE(native_tls_would_block());
    }
    NATIVE_TLS_REQUIRE(native_tls_progress(f) == SALTS_OK);
  }
  NATIVE_TLS_REQUIRE(f->ends[0].connected && f->ends[1].connected);
  native_tls_socket_close(f->listener);
  f->listener = NATIVE_TLS_INVALID;
  NATIVE_TLS_REQUIRE(crypto_tls_stream_client_context_create(&client_cfg, &f->ends[0].context) == CRYPTO_TLS_STREAM_OK);
  NATIVE_TLS_REQUIRE(crypto_tls_stream_server_context_create(&server_cfg, &f->ends[1].context) == CRYPTO_TLS_STREAM_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    const int enabled = 1;
    NATIVE_TLS_REQUIRE(setsockopt(f->ends[i].socket, IPPROTO_TCP, TCP_NODELAY,
                                  (const char *)&enabled, sizeof(enabled)) == 0);
    NATIVE_TLS_REQUIRE(crypto_tls_stream_create(f->ends[i].context, i == 1u,
        i == 0u ? "localhost" : NULL, NATIVE_TLS_IO, &f->ends[i].stream) == CRYPTO_TLS_STREAM_OK);
  }
  f->source = mem_get_buffer(mem_global(), NATIVE_TLS_BYTES);
  NATIVE_TLS_REQUIRE(f->source != NULL);
  for (size_t i = 0u; i < NATIVE_TLS_BYTES; ++i)
    mem_buffer_data(f->source)[i] = (char)((0x5au + i * 29u) & 0xffu);
  mem_set_used(f->source, NATIVE_TLS_BYTES);
  NATIVE_TLS_REQUIRE(native_tls_offer(f) == SALTS_EBUSY && mem_buffer_ref_count(f->source) == 1u);
  const uint64_t handshake_start = cmeta_hrtime();
  deadline = cmeta_monotonic_ms() + 7000u;
  while ((!f->ends[0].ready || !f->ends[1].ready || !f->ends[0].drained || !f->ends[1].drained) &&
         cmeta_monotonic_ms() < deadline)
    NATIVE_TLS_REQUIRE(native_tls_progress(f) == SALTS_OK);
  handshake_ns = cmeta_hrtime() - handshake_start;
  for (size_t i = 0u; i < 2u; ++i) {
    native_tls_end *end = &f->ends[i];
    size_t size;
    NATIVE_TLS_REQUIRE(end->ready && end->drained && crypto_tls_stream_handshake_complete(end->stream));
    NATIVE_TLS_REQUIRE(crypto_tls_stream_negotiated_version(end->stream, end->version,
                        sizeof(end->version), &size) == CRYPTO_TLS_STREAM_OK);
    NATIVE_TLS_REQUIRE(crypto_tls_stream_negotiated_cipher(end->stream, end->cipher,
                        sizeof(end->cipher), &size) == CRYPTO_TLS_STREAM_OK);
    NATIVE_TLS_REQUIRE(strcmp(end->version, "TLSv1.3") == 0 || strcmp(end->version, "TLSv1.2") == 0);
    NATIVE_TLS_REQUIRE(end->cipher[0] != '\0');
  }
  NATIVE_TLS_REQUIRE(strcmp(f->ends[0].version, f->ends[1].version) == 0 &&
                     strcmp(f->ends[0].cipher, f->ends[1].cipher) == 0);
  NATIVE_TLS_REQUIRE(native_tls_transfer(f, report ? 64u : 8u, !report, &warm) == SALTS_OK);
  if (report) {
    benchmark_io("direct NativeIO retained TLS transfer", 1, operations,
                 operations / 8u * (7u * NATIVE_TLS_BYTES + 1u)) {
      transfer_status = native_tls_transfer(f, operations, false, &measured);
    }
  } else transfer_status = native_tls_transfer(f, operations, true, &measured);
  NATIVE_TLS_REQUIRE(transfer_status == SALTS_OK && measured.elapsed != 0u && measured.submissions > 0u);
  if (chunk < NATIVE_TLS_IO) NATIVE_TLS_REQUIRE(measured.continuations > 0u);
  const uint64_t close_start = cmeta_hrtime();
  f->closing = true;
  deadline = cmeta_monotonic_ms() + 7000u;
  while ((!f->ends[0].peer_closed || !f->ends[1].peer_closed || !f->ends[0].notify_generated ||
          !f->ends[1].notify_generated || !f->ends[0].drained || !f->ends[1].drained) &&
         cmeta_monotonic_ms() < deadline)
    NATIVE_TLS_REQUIRE(native_tls_progress(f) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i)
    NATIVE_TLS_REQUIRE(f->ends[i].peer_closed && f->ends[i].notify_generated && f->ends[i].drained);
  NATIVE_TLS_REQUIRE(native_tls_drain(f) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    native_tls_end *end = &f->ends[i];
    native_io_backend_stats stats;
    NATIVE_TLS_REQUIRE(native_io_backend_get_stats(&end->backend, &stats) && stats.active_requests == 0u);
    native_tls_socket_close(end->socket);
    end->socket = NATIVE_TLS_INVALID;
    NATIVE_TLS_REQUIRE(native_io_backend_release_socket(&end->backend, end->endpoint) == SALTS_OK);
    end->endpoint = (native_io_endpoint){0};
    NATIVE_TLS_REQUIRE(native_io_backend_get_stats(&end->backend, &stats) && stats.endpoint_count == 0u);
  }
  close_ns = cmeta_hrtime() - close_start;
  if (report) printf("CNET_TLS_CSV,nativeio,%u,1,%zu,%s,%s,%llu,%zu,%llu,%llu,%llu,%llu,%llu,0,0,0,0,%zu,%zu,%zu,%llu,%llu\n",
      repetition, operations, f->ends[0].version, f->ends[0].cipher, (unsigned long long)handshake_ns,
      measured.bytes, (unsigned long long)measured.elapsed, (unsigned long long)measured.cpu,
      (unsigned long long)measured.p50, (unsigned long long)measured.p95, (unsigned long long)measured.p99,
      measured.peak_bytes, measured.peak_backing, mem_buffer_capacity(f->source),
      (unsigned long long)measured.submissions, (unsigned long long)close_ns);
cleanup:
  native_tls_socket_close(f->listener);
  if (native_tls_drain(f) == SALTS_OK) {
    bool released = true;
    for (size_t i = 0u; i < 2u; ++i) {
      native_tls_end *end = &f->ends[i];
      native_tls_socket_close(end->socket);
      end->socket = NATIVE_TLS_INVALID;
      if (native_io_endpoint_valid(end->endpoint) &&
          native_io_backend_release_socket(&end->backend, end->endpoint) != SALTS_OK) released = false;
      (void)native_io_backend_close(&end->backend);
      if (native_io_backend_destroy(&end->backend) != SALTS_OK && end->backend.impl != NULL) released = false;
    }
    if (released) {
      for (size_t i = 0u; i < 2u; ++i) {
        crypto_tls_stream_destroy(f->ends[i].stream);
        crypto_tls_stream_context_release(f->ends[i].context);
      }
      if (f->retained) mem_buffer_release(f->source);
      if (f->source) mem_buffer_release(f->source);
      free(f);
      return result;
    }
  }
  return result ? result : __LINE__; /* Keep live stream/native backing. */
}
#undef NATIVE_TLS_REQUIRE

spec("Production Crypto TLS over direct NativeIO") {
  for (unsigned bound = 0u; bound < 2u; ++bound) {
    it("drains direct TLS with native write bound %u", bound ? 4096u : NATIVE_TLS_IO) {
      const int result = native_tls_sample(false, 0u, bound ? 4096u : NATIVE_TLS_IO);
      check(result == 0, "direct TLS transfer returned %d", result);
    }
  }
  if (getenv("SALTSCORE_NATIVE_TLS_BENCHMARK") != NULL) {
    it("uses the explicit direct TLS benchmark switch") {
      check_equal(getenv("SALTSCORE_NATIVE_TLS_BENCHMARK"), "1");
    }
    if (strcmp(getenv("SALTSCORE_NATIVE_TLS_BENCHMARK"), "1") == 0)
    for (unsigned repetition = 0u; repetition < 5u; ++repetition) {
      it("measures direct NativeIO TLS transfer repetition %u", repetition) {
        const int result = native_tls_sample(true, repetition, NATIVE_TLS_IO);
        check(result == 0, "direct TLS benchmark returned %d", result);
      }
    }
  }
}
