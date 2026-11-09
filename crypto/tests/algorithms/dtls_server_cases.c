#include "../../src/crypto_dtls_client.h"
#include "../../src/crypto_dtls_server.h"
#define TINYTEST_NO_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tinytest.h>
static int references, public_release_reentry;
static crypto_dtls_listener *public_listener;
static int data(void *, const uint8_t *, size_t);
static size_t fixture(const char *, uint8_t *, size_t);
static void retain(void *p) {
  (void)p;
  ++references;
}
static void release(void *p) {
  (void)p;
  --references;
  if (public_listener) {
    public_release_reentry = crypto_dtls_listener_destroy(public_listener);
    public_listener = NULL;
  }
}
static int policy(void *p,
                  const crypto_tls_stream_peer_certificate_chain *chain,
                  bool server, crypto_tls_stream_security_profile profile) {
  (void)p;
  return !chain->count || server ||
         profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD;
}

static int opaque_data(void *p, crypto_dtls_stream *s, const uint8_t *bytes,
                       size_t n) {
  (void)s;
  return data(p, bytes, n);
}
spec("Opaque DTLS listener cookie admission and stream leases") {
  static crypto_dtls_listener *listener;
  static crypto_dtls_stream *client, *streams[2];
  static uint8_t cert[4096], key[4096], reply[60], saved[1200];
  static crypto_tls_data roots;
  static crypto_tls_credentials credentials;
  static crypto_dtls_listener_config config;
  static crypto_tls_stream_peer_policy pp;
  static const uint8_t peer[] = {4, 1, 0xbb, 127, 0, 0, 1};
  before_each() {
    listener = NULL;
    client = NULL;
    memset(streams, 0, sizeof(streams));
    references = 0;
    public_listener = NULL;
    public_release_reentry = 0;
    size_t cn = fixture("SALTS_DTLS_EC_CERT", cert, sizeof(cert)),
           kn = fixture("SALTS_DTLS_EC_KEY", key, sizeof(key));
    roots = (crypto_tls_data){cert, cn, CRYPTO_TLS_ENCODING_DER};
    credentials = (crypto_tls_credentials){
        .size = sizeof(credentials),
        .certificate_chain = roots,
        .private_key = {key, kn, CRYPTO_TLS_ENCODING_DER}};
    pp = (crypto_tls_stream_peer_policy){policy,
                                         retain,
                                         release,
                                         NULL,
                                         CRYPTO_TLS_PEER_POLICY_STANDARD,
                                         CRYPTO_TLS_PEER_POLICY_CLIENT};
    config = (crypto_dtls_listener_config){
        &credentials, &roots, &pp,   "localhost", 9u,
        "test",       4u,     1000u, true,        false};
  }
  after_each() {
    for (size_t i = 0; i < 3u; ++i) {
      crypto_dtls_stream *s = i < 2u ? streams[i] : client;
      if (s) {
        crypto_dtls_stream_info info;
        check_equal(crypto_dtls_stream_get_info(s, &info), 0);
        check_equal(crypto_dtls_stream_abort(s), 0);
        if (info.pending_send)
          check_true(crypto_dtls_stream_sent(s, 10u, false) < 0);
        check_equal(crypto_dtls_stream_destroy(s), 0);
      }
    }
    if (listener)
      check_equal(crypto_dtls_listener_destroy(listener), 0);
    memset(key, 0, sizeof(key));
    check_equal(references, 0);
  }
  it("gates before stream publication and retains shared identity until both "
     "owners drain") {
    crypto_dtls_listener *invalid = (crypto_dtls_listener *)1;
    check_equal(crypto_dtls_listener_create(NULL, &invalid),
                SALTS_CRYPTO_EINVAL);
    check_null(invalid);
    config.cookie_lifetime_ms = 0u;
    check_equal(crypto_dtls_listener_create(&config, &listener),
                SALTS_CRYPTO_EINVAL);
    check_null(listener);
    check_equal(references, 0);
    config.cookie_lifetime_ms = 1000u;
    check_equal(crypto_dtls_listener_create(&config, &listener), 0);
    check_equal(references, 1);
    crypto_dtls_stream_config cc = {.roots = roots,
                                    .server_name = "localhost",
                                    .server_name_size = 9u,
                                    .alpn = "test",
                                    .alpn_size = 4u,
                                    .on_data = opaque_data};
    check_equal(crypto_dtls_stream_create(&cc, &client), 0);
    const uint8_t *wire;
    size_t n, reply_size = 99u;
    bool verified = true;
    check_equal(crypto_dtls_stream_next(client, 0u, &wire, &n), 0);
    check_equal(crypto_dtls_listener_gate(
                    listener, peer, sizeof(peer), listener, 1u, 0u, reply,
                    sizeof(reply), &reply_size, &verified),
                SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_listener_gate(listener, peer, sizeof(peer), "bad",
                                          3u, 0u, reply, sizeof(reply),
                                          &reply_size, &verified),
                CRYPTO_DTLS_DROP);
    check_equal(reply_size, 0u);
    check_false(verified);
    check_equal(crypto_dtls_stream_accept(listener, peer, sizeof(peer), wire, n,
                                          0u, opaque_data, NULL, &streams[0]),
                CRYPTO_DTLS_DROP);
    check_null(streams[0]);
    check_equal(crypto_dtls_listener_gate(listener, peer, sizeof(peer), wire, n,
                                          0u, reply, sizeof(reply), &reply_size,
                                          &verified),
                0);
    check_false(verified);
    check_equal(reply_size, 60u);
    check_equal(crypto_dtls_stream_sent(client, 0u, true), 0);
    check_equal(crypto_dtls_stream_receive(client, 0u, reply, reply_size), 0);
    check_equal(crypto_dtls_stream_next(client, 10u, &wire, &n), 0);
    uint8_t other[sizeof(peer)];
    memcpy(other, peer, sizeof(peer));
    other[2] ^= 1u;
    check_equal(crypto_dtls_stream_accept(listener, other, sizeof(other), wire,
                                          n, 10u, opaque_data, NULL,
                                          &streams[0]),
                CRYPTO_DTLS_DROP);
    check_null(streams[0]);
    check_equal(crypto_dtls_listener_gate(listener, peer, sizeof(peer), wire, n,
                                          10u, (void *)wire, n, &reply_size,
                                          &verified),
                SALTS_CRYPTO_EINVAL);
    for (size_t i = 0; i < 2u; ++i)
      check_equal(crypto_dtls_stream_accept(listener, peer, sizeof(peer), wire,
                                            n, 10u, opaque_data, NULL,
                                            &streams[i]),
                  0);
    check_equal(crypto_dtls_listener_destroy(listener), CRYPTO_DTLS_BUSY);
    check_equal(crypto_dtls_stream_destroy(streams[0]), 0);
    streams[0] = NULL;
    check_equal(crypto_dtls_listener_destroy(listener), CRYPTO_DTLS_BUSY);
    const uint8_t *pending;
    size_t pending_size;
    check_equal(
        crypto_dtls_stream_next(streams[1], 10u, &pending, &pending_size), 0);
    memcpy(saved, pending, pending_size);
    check_equal(crypto_dtls_stream_abort(streams[1]), 0);
    check_equal(pending, saved, pending_size);
    check_equal(crypto_dtls_stream_destroy(streams[1]), CRYPTO_DTLS_BUSY);
    check_true(crypto_dtls_stream_sent(streams[1], 10u, false) < 0);
    check_equal(crypto_dtls_stream_destroy(streams[1]), 0);
    streams[1] = NULL;
    public_listener = listener;
    check_equal(crypto_dtls_listener_destroy(listener), 0);
    listener = NULL;
    check_equal(public_release_reentry, SALTS_CRYPTO_ESTATE);
    check_equal(references, 0);
  }
}
static int data(void *p, const uint8_t *bytes, size_t n) {
  (void)p;
  (void)bytes;
  (void)n;
  return 0;
}
static int zero_memory(const void *p, size_t n) {
  const uint8_t *v = p;
  unsigned all = 0;
  while (n--)
    all |= *v++;
  return !all;
}
static size_t fixture(const char *name, uint8_t *out, size_t cap) {
  const char *path = getenv(name);
  check_true(path != NULL);
  FILE *file = path ? fopen(path, "rb") : NULL;
  check_true(file != NULL);
  size_t n = 0;
  if (file) {
    n = fread(out, 1u, cap, file);
    check_true(!ferror(file));
    check_equal(fgetc(file), EOF);
    check_equal(fclose(file), 0);
  }
  return n;
}
spec("Private DTLS server cookie admission and context leases") {
  static crypto_dtls_server_context ctx;
  static crypto_dtls_server servers[2];
  static crypto_dtls_client client;
  static uint8_t cert[4096], key[4096], wrong[4096], hello[1200],
      snapshot[1200];
  static size_t cert_size, key_size, hello_size;
  static crypto_tls_credentials credentials;
  static crypto_tls_data roots;
  static crypto_dtls_server_config config;
  static const uint8_t address[] = {4, 127, 0, 0, 1, 1, 0xbb};
  static crypto_tls_stream_peer_policy peer_policy;
  before_each() {
    memset(&ctx, 0, sizeof(ctx));
    memset(servers, 0, sizeof(servers));
    memset(&client, 0, sizeof(client));
    references = 0;
    cert_size = fixture("SALTS_DTLS_EC_CERT", cert, sizeof(cert));
    key_size = fixture("SALTS_DTLS_EC_KEY", key, sizeof(key));
    credentials = (crypto_tls_credentials){
        .size = sizeof(credentials),
        .certificate_chain = {cert, cert_size, CRYPTO_TLS_ENCODING_DER},
        .private_key = {key, key_size, CRYPTO_TLS_ENCODING_DER}};
    roots = (crypto_tls_data){cert, cert_size, CRYPTO_TLS_ENCODING_DER};
    peer_policy =
        (crypto_tls_stream_peer_policy){policy,
                                        retain,
                                        release,
                                        NULL,
                                        CRYPTO_TLS_PEER_POLICY_STANDARD,
                                        CRYPTO_TLS_PEER_POLICY_CLIENT};
    config = (crypto_dtls_server_config){&credentials, &roots, &peer_policy,
                                         "localhost",  9u,     "test",
                                         4u,           1000u,  true};
  }
  after_each() {
    if (client.pending) {
      check_equal(crypto_dtls_client_abort(&client), 0);
      check_true(crypto_dtls_client_sent(&client, client.last_now, false) < 0);
    }
    check_equal(crypto_dtls_client_clear(&client), 0);
    for (size_t i = 0; i < 2u; ++i) {
      if (servers[i].pending) {
        check_equal(crypto_dtls_server_abort(&servers[i]), 0);
        check_true(crypto_dtls_server_sent(&servers[i], servers[i].last_now,
                                           false) < 0);
      }
      check_equal(crypto_dtls_server_clear(&servers[i]), 0);
    }
    check_equal(crypto_dtls_server_context_clear(&ctx), 0);
    check_equal(references, 0);
  }
  before_each() {
    /* One bounded post-cookie ClientHello; no trust bypass enters production.
     */
    check_equal(crypto_dtls_server_context_init(&ctx, &config), 0);
    check_equal(references, 1);
    crypto_dtls_client_config cc = {cert, cert_size, "localhost", 9u,  "test",
                                    4u,   NULL,      data,        NULL};
    check_equal(crypto_dtls_client_init(&client, &cc), 0);
    const uint8_t *wire;
    size_t n, reply_size;
    uint8_t reply[60];
    crypto_dtls_cookie_result gate;
    check_equal(crypto_dtls_client_next(&client, 0u, &wire, &n), 0);
    check_equal(crypto_dtls_cookie_gate(&ctx.cookie, address, sizeof(address),
                                        wire, n, 10u, reply, sizeof(reply),
                                        &reply_size, &gate),
                0);
    check_true(!gate.address_verified);
    check_equal(reply_size, 60u);
    check_equal(crypto_dtls_client_sent(&client, 0u, true), 0);
    check_equal(crypto_dtls_client_receive(&client, 10u, reply, reply_size), 0);
    check_equal(crypto_dtls_client_next(&client, 10u, &wire, &n), 0);
    hello_size = n;
    memcpy(hello, wire, n);
    check_equal(crypto_dtls_client_sent(&client, 10u, true), 0);
  }
  it("rejects invalid or address-mismatched cookies without a stream lease or "
     "ephemeral state") {
    memcpy(snapshot, hello, hello_size);
    hello[92] ^= 1u;
    check_equal(crypto_dtls_server_accept(&servers[0], &ctx, address,
                                          sizeof(address), hello, hello_size,
                                          10u, data, NULL),
                CRYPTO_DTLS_SERVER_DROP);
    check_true(zero_memory(&servers[0], sizeof(servers[0])));
    check_equal(atomic_load(&ctx.leases), 0u);
    memcpy(hello, snapshot, hello_size);
    uint8_t changed[sizeof(address)];
    memcpy(changed, address, sizeof(address));
    changed[6] ^= 1u;
    check_equal(crypto_dtls_server_accept(&servers[0], &ctx, changed,
                                          sizeof(changed), hello, hello_size,
                                          10u, data, NULL),
                CRYPTO_DTLS_SERVER_DROP);
    check_equal(atomic_load(&ctx.leases), 0u);
    check_equal(crypto_dtls_server_accept(&servers[0], &ctx, address,
                                          sizeof(address), hello, hello_size,
                                          9u, data, NULL),
                SALTS_CRYPTO_ESTATE);
    check_true(zero_memory(&servers[0], sizeof(servers[0])));
  }
  it("keeps immutable credentials and policy alive until both stream owners "
     "clear") {
    for (size_t i = 0; i < 2u; ++i)
      check_equal(crypto_dtls_server_accept(&servers[i], &ctx, address,
                                            sizeof(address), hello, hello_size,
                                            10u, data, NULL),
                  0);
    check_equal(atomic_load(&ctx.leases), 2u);
    check_equal(references, 1);
    check_not_equal(servers[0].server_random, servers[1].server_random, 32u);
    check_equal(crypto_dtls_server_context_clear(&ctx),
                CRYPTO_DTLS_SERVER_BUSY);
    check_equal(crypto_dtls_server_clear(&servers[0]), 0);
    check_equal(atomic_load(&ctx.leases), 1u);
    check_equal(crypto_dtls_server_context_clear(&ctx),
                CRYPTO_DTLS_SERVER_BUSY);
    check_equal(crypto_dtls_server_clear(&servers[1]), 0);
    check_equal(atomic_load(&ctx.leases), 0u);
    check_equal(crypto_dtls_server_context_clear(&ctx), 0);
    check_equal(references, 0);
  }
  it("preserves a pending wire through abort and defers stream/context "
     "reclamation until terminal") {
    check_equal(crypto_dtls_server_accept(&servers[0], &ctx, address,
                                          sizeof(address), hello, hello_size,
                                          10u, data, NULL),
                0);
    const uint8_t *wire;
    size_t n;
    check_equal(crypto_dtls_server_next(&servers[0], 10u, &wire, &n), 0);
    size_t saved = n;
    memcpy(snapshot, wire, n);
    check_equal(crypto_dtls_server_clear(&servers[0]), CRYPTO_DTLS_SERVER_BUSY);
    check_equal(crypto_dtls_server_context_clear(&ctx),
                CRYPTO_DTLS_SERVER_BUSY);
    check_equal(crypto_dtls_server_receive(&servers[0], 10u, hello, hello_size),
                CRYPTO_DTLS_SERVER_BUSY);
    check_equal(crypto_dtls_server_abort(&servers[0]), 0);
    check_equal(wire, snapshot, saved);
    check_true(zero_memory(&servers[0].secrets, sizeof(servers[0].secrets)));
    check_equal(crypto_dtls_server_clear(&servers[0]), CRYPTO_DTLS_SERVER_BUSY);
    check_equal(crypto_dtls_server_sent(&servers[0], 11u, true),
                SALTS_CRYPTO_ESTATE);
    check_equal(crypto_dtls_server_clear(&servers[0]), 0);
    check_equal(crypto_dtls_server_context_clear(&ctx), 0);
  }
  it("rejects an incompatible key or client-auth policy before retaining a new "
     "context") {
    check_equal(crypto_dtls_server_context_clear(&ctx), 0);
    const size_t n = fixture("SALTS_DTLS_RSA_KEY", wrong, sizeof(wrong));
    credentials.private_key.data = wrong;
    credentials.private_key.size = n;
    check_true(crypto_dtls_server_context_init(&ctx, &config) < 0);
    check_true(zero_memory(&ctx, sizeof(ctx)));
    check_equal(references, 0);
    credentials.private_key.data = key;
    credentials.private_key.size = key_size;
    config.require_client_certificate = false;
    check_equal(crypto_dtls_server_context_init(&ctx, &config),
                SALTS_CRYPTO_EINVAL);
    check_equal(references, 0);
  }
}
