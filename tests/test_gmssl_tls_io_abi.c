/* Provider-only ABI / external I/O contract.
 * This is not a network handshake, peer auth or CNet runtime conformance.
 * The test links the actual pinned GmSSL provider from the CNet feature. */
#include <tinytest.h>
#include <crypto/tls_close.h>
#include <gmssl/tls.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

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
