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
