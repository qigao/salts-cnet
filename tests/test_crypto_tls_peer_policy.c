/* Real production Crypto stream handshake; bounded in-memory ciphertext
 * transport. Independent Go certificate/CRL fixtures drive this formal peer.
 * This executable owns Crypto once and never links the CNet shared owner. */
#include <crypto/sm2_crl.h>
#include <stdio.h>
#include <stdlib.h>
#include "tls_peer_policy_probe.h"

typedef struct revocation_probe {
  peer_policy_probe base;
  salts_crypto_sm2_cert_span issuer;
  salts_crypto_sm2_crl_policy crl;
  int64_t now;
  bool allow_after_rejection;
} revocation_probe;

static int check_revocation(void *ctx,
    const crypto_tls_stream_peer_certificate_chain *chain, bool peer_is_server,
    crypto_tls_stream_security_profile profile) {
  revocation_probe *p = ctx;
  int result = peer_policy_check(&p->base, chain, peer_is_server, profile);
  if (result != 0) return result;
  if (p->allow_after_rejection) return 0;
  /* The explicit issuer is the same direct trust anchor configured below.
   * The peer chain alone is never used to infer trust in an issuer. */
  salts_crypto_sm2_cert_span cert = {chain->certificates[0].data,
                                    chain->certificates[0].size};
  return salts_crypto_sm2_check_crl(&cert, &p->issuer, p->now, &p->crl);
}
static size_t read_file(const char *path, uint8_t *buffer, size_t capacity) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) return 0u;
  size_t size = fread(buffer, 1u, capacity, file);
  bool valid = !ferror(file) && fgetc(file) == EOF && !ferror(file);
  fclose(file);
  return valid ? size : 0u;
}
static int transfer(crypto_tls_stream *from, crypto_tls_stream *to) {
  uint8_t bytes[4096];
  size_t size = 0u;
  size_t capacity = crypto_tls_stream_cipher_input_capacity(to);
  if (capacity == 0u) return CRYPTO_TLS_STREAM_OK;
  if (capacity > sizeof(bytes)) capacity = sizeof(bytes);
  int result = crypto_tls_stream_take_cipher(from, bytes, capacity, &size);
  if (result == CRYPTO_TLS_STREAM_ENOENT) return CRYPTO_TLS_STREAM_OK;
  if (result != CRYPTO_TLS_STREAM_OK) return result;
  return crypto_tls_stream_feed_cipher(to, bytes, size);
}

#define REQUIRE(condition) do { if (!(condition)) { \
  fprintf(stderr, "TLS revocation assertion at line %d: %s\n", __LINE__, #condition); \
  result = 1; goto cleanup; } } while (0)

int main(int argc, char **argv) {
  if (argc != 14 || strcmp(argv[1], "--shangmi-revocation") != 0) return 2;
  uint8_t issuer[CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_BYTES];
  uint8_t crl[SALTS_CRYPTO_SM2_CRL_MAX_BYTES];
  revocation_probe p = {0};
  const bool peer_is_server = strcmp(argv[8], "client") == 0;
  const bool accept = strcmp(argv[12], "accept") == 0;
  const bool wrong_name = strcmp(argv[13], "wrong-name") == 0;
  crypto_tls_stream_context *client_context = NULL, *server_context = NULL;
  crypto_tls_stream *client = NULL, *server = NULL;
  bool client_complete = false, server_complete = false;
  int client_status = 0, server_status = 0, result = 0;
  peer_policy_init(&p.base, peer_is_server);
  p.base.profile = CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13;
  p.issuer = (salts_crypto_sm2_cert_span){issuer, read_file(argv[9], issuer, sizeof(issuer))};
  p.crl = (salts_crypto_sm2_crl_policy){crl, read_file(argv[10], crl, sizeof(crl)),
      "1234567812345678", 16u, 42u, 3600u};
  p.now = strtoll(argv[11], NULL, 10);
  REQUIRE(p.issuer.size != 0u && p.crl.size != 0u && p.now > 0);
  crypto_tls_stream_peer_policy policy = peer_policy_descriptor(&p.base);
  policy.check = check_revocation;
  policy.context = &p;
  crypto_tls_stream_client_config cc = {.size = sizeof(cc),
      .ca_file = argv[2], .cert_file = argv[6], .key_file = argv[7],
      .security_profile = p.base.profile, .peer_policy = peer_is_server ? &policy : NULL};
  crypto_tls_stream_server_config sc = {.size = sizeof(sc),
      .ca_file = argv[3], .cert_file = argv[4], .key_file = argv[5],
      .client_auth = CRYPTO_TLS_STREAM_CLIENT_AUTH_REQUIRED,
      .security_profile = p.base.profile, .peer_policy = peer_is_server ? NULL : &policy};
  REQUIRE(crypto_tls_stream_client_context_create(&cc, &client_context) == 0);
  REQUIRE(crypto_tls_stream_server_context_create(&sc, &server_context) == 0);
  REQUIRE(crypto_tls_stream_create(client_context, false, wrong_name ? "127.0.0.2" : "localhost",
      CRYPTO_TLS_STREAM_MIN_IO_BUFFER_BYTES, &client) == 0);
  REQUIRE(crypto_tls_stream_create(server_context, true, NULL,
      CRYPTO_TLS_STREAM_MIN_IO_BUFFER_BYTES, &server) == 0);
  memset(&policy, 0, sizeof(policy));
  crypto_tls_stream_context_release(client_context); client_context = NULL;
  crypto_tls_stream_context_release(server_context); server_context = NULL;
  REQUIRE(atomic_load(&p.base.releases) == 0u);
  for (unsigned step = 0u; step < 10000u; ++step) {
    client_status = crypto_tls_stream_handshake(client, &client_complete);
    if (client_status != 0) break;
    REQUIRE(transfer(client, server) == 0);
    server_status = crypto_tls_stream_handshake(server, &server_complete);
    if (server_status != 0) break;
    REQUIRE(transfer(server, client) == 0);
    if (client_complete && server_complete) break;
  }
  if (accept) {
    REQUIRE(client_status == 0 && server_status == 0 && client_complete && server_complete);
    bool sent = false, closed = false;
    uint8_t received = 0u;
    size_t size = 0u;
    REQUIRE(crypto_tls_stream_write(client, "F", 1u, &sent) == 0 && sent);
    REQUIRE(transfer(client, server) == 0);
    REQUIRE(crypto_tls_stream_read(server, &received, 1u, &size, &closed) == 0);
    REQUIRE(size == 1u && received == 'F' && !closed);
    /* Repeated completed handshakes never re-run admission. */
    REQUIRE(crypto_tls_stream_handshake(client, &client_complete) == 0 && client_complete);
    REQUIRE(crypto_tls_stream_handshake(server, &server_complete) == 0 && server_complete);
  } else {
    crypto_tls_stream *rejected = peer_is_server ? client : server;
    REQUIRE((peer_is_server ? client_status : server_status) == CRYPTO_TLS_STREAM_ECONNABORTED);
    REQUIRE(!crypto_tls_stream_handshake_complete(rejected));
    /* A later policy decision cannot resurrect an already rejected stream. */
    p.allow_after_rejection = true;
    bool complete = true, closed = false;
    uint8_t byte = 0u;
    size_t size = 0u;
    for (unsigned retry = 0u; retry < 3u; ++retry) {
      REQUIRE(crypto_tls_stream_handshake(rejected, &complete) == CRYPTO_TLS_STREAM_ECONNABORTED);
      REQUIRE(!complete);
    }
    REQUIRE(crypto_tls_stream_write(rejected, "F", 1u, &complete) == CRYPTO_TLS_STREAM_ENOTCONN);
    REQUIRE(crypto_tls_stream_read(rejected, &byte, 1u, &size, &closed) == CRYPTO_TLS_STREAM_ENOTCONN);
  }
  REQUIRE(atomic_load(&p.base.calls) == (wrong_name ? 0u : 1u));
cleanup:
  crypto_tls_stream_destroy(client);
  crypto_tls_stream_destroy(server);
  crypto_tls_stream_context_release(client_context);
  crypto_tls_stream_context_release(server_context);
  if (!result && !peer_policy_finished(&p.base, wrong_name ? 0u : 1u)) result = 1;
  return result;
}
