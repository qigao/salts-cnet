/* Provider-only ABI / external I/O contract.
 * This is not a network handshake, peer auth or CNet runtime conformance.
 * The test links the actual pinned GmSSL provider from the CNet feature. */
#include <tinytest.h>
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
