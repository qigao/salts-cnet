/*
 * Public CNet/NativeIO real-TCP TLS acceptance and negative trust gate.
 * Certificate fixtures are exact copies of original Salts TLS conformance
 * corpus. No TLS implementation/type is accessed directly in this file.
 */
#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <cnet/cnet.h>
#include <cnet/client_pool.h>
#include <clock.h>
#include <error_codes.h>
#include <cmeta_buffer.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/resource.h>
#endif
#include "tls_mixed_workload.h"
#include "cnet_tls_memory_test.h"

#ifndef CORE_TLS_TEST_P384_CA
#error CORE_TLS_TEST_P384_CA is required
#endif
#ifndef CORE_TLS_TEST_P384_WRONG_CA
#error CORE_TLS_TEST_P384_WRONG_CA is required
#endif
#ifndef CORE_TLS_TEST_P384_LEAF
#error CORE_TLS_TEST_P384_LEAF is required
#endif
#ifndef CORE_TLS_TEST_P384_KEY
#error CORE_TLS_TEST_P384_KEY is required
#endif
#ifndef CORE_TLS_TEST_EXTERNAL_CA
#error CORE_TLS_TEST_EXTERNAL_CA is required
#endif

enum {
  TLS_STREAM_SEGMENTS = CNET_RETAINED_VECTOR_MAX,
  TLS_STREAM_SEGMENT_BYTES = 1024,
  TLS_STREAM_BULK_BYTES = TLS_STREAM_SEGMENTS * TLS_STREAM_SEGMENT_BYTES,
  TLS_STREAM_CONTROL_BYTES = 7,
  TLS_STREAM_FINAL_BYTES = 5,
  TLS_STREAM_TOTAL_BYTES = TLS_STREAM_CONTROL_BYTES + TLS_STREAM_BULK_BYTES +
                           TLS_STREAM_FINAL_BYTES
};

typedef struct tls_probe {
  cnet_client *client;
  cnet_connection connection;
  unsigned connected_count;
  unsigned terminal_count;
  unsigned failed;
  unsigned handshaking_count;
  int last_connection_state;
  int last_error_status;
  int last_native_status;
  unsigned sent_count;
  unsigned received_count;
  unsigned char received_byte;
  bool stream_transfer;
  bool pool_reuse;
  unsigned recycled_count;
  const unsigned char *expected_stream;
  size_t expected_stream_size;
  size_t stream_received;
  size_t send_sizes[3];
  unsigned sends_at_terminal;
  /* Python ssl peer sends a complete two-byte TLS application record. */
  bool expect_python_ok_record;
  unsigned receive_limit; /* zero keeps the ordinary single-record contract */
  int tls_version_status;
  int tls_cipher_status;
  char tls_version[24];
  char tls_cipher[128];
  char failure_stage[32];
  crypto_tls_diagnostic tls_diagnostic;
} tls_probe;

static void state_callback(void *user, cnet_connection connection,
                           cnet_connection_state state, const cnet_error *error) {
  tls_probe *p = (tls_probe *)user;
  p->connection = connection;
  p->last_connection_state = (int)state;
  if (error != NULL) {
    /* Numeric terminal metadata only: never print credential material. */
    p->last_error_status = error->status;
    p->last_native_status = error->native_status;
    p->tls_diagnostic = error->tls;
  }
  if (state == CNET_CONNECTION_TLS_HANDSHAKING)
    ++p->handshaking_count;
  if (state == CNET_CONNECTION_CONNECTED) {
    ++p->connected_count;
    size_t version_size = 0u, cipher_size = 0u;
    p->tls_version_status = cnet_tls_negotiated_version(
        p->client, connection, p->tls_version, sizeof(p->tls_version),
        &version_size);
    p->tls_cipher_status = cnet_tls_negotiated_cipher(
        p->client, connection, p->tls_cipher, sizeof(p->tls_cipher),
        &cipher_size);
  } else if (state == CNET_CONNECTION_FAILED || state == CNET_CONNECTION_CLOSED) {
    p->sends_at_terminal = p->sent_count;
    ++p->terminal_count;
    if (state == CNET_CONNECTION_FAILED || error != NULL) {
      ++p->failed;
      if (error && error->stage) {
        const size_t n = strlen(error->stage);
        if (n >= sizeof(p->failure_stage)) {
          ++p->failed;
        } else {
          memcpy(p->failure_stage, error->stage, n + 1u);
        }
      }
    }
  }
}
static void receive_callback(void *user, cnet_connection connection,
                             const cnet_receive_view *view) {
  tls_probe *p = (tls_probe *)user;
  (void)connection;
  if (view == NULL || view->kind != CNET_MESSAGE_BYTES ||
      view->data == NULL ||
      (!p->stream_transfer && !p->pool_reuse &&
       p->received_count >= (p->receive_limit ? p->receive_limit : 1u)) ||
      (p->pool_reuse && (p->terminal_count != 0u || p->received_count >= 3u))) {
    ++p->failed;
    return;
  }
  if (p->stream_transfer) {
    /* TLS records and receive callbacks do not preserve logical write sizes. */
    if (p->terminal_count != 0u || p->expected_stream == NULL ||
        view->size == 0u || p->stream_received > p->expected_stream_size ||
        view->size > p->expected_stream_size - p->stream_received ||
        memcmp(view->data, p->expected_stream + p->stream_received,
               view->size) != 0) {
      ++p->failed;
      return;
    }
    p->stream_received += view->size;
    ++p->received_count;
    return;
  }
  if (p->expect_python_ok_record) {
    /* Receive demand counts events, not bytes. The independent Python ssl
     * server sends exactly "ok" in one authenticated application record. */
    if (view->size != 2u || memcmp(view->data, "ok", 2u) != 0) {
      ++p->failed;
      return;
    }
  } else if (view->size != 1u) {
    ++p->failed;
    return;
  }
  p->received_byte = *(const unsigned char *)view->data;
  ++p->received_count;
}
static void send_callback(void *user, cnet_connection connection, size_t size) {
  tls_probe *p = (tls_probe *)user;
  (void)connection;
  if (p->stream_transfer) {
    if (p->terminal_count != 0u ||
        p->sent_count >= sizeof(p->send_sizes) / sizeof(p->send_sizes[0]))
      ++p->failed;
    else
      p->send_sizes[p->sent_count] = size;
  } else if (size != 1u) ++p->failed;
  ++p->sent_count;
}
static void recycle_callback(void *user) {
  ++((tls_probe *)user)->recycled_count;
}

static int send_byte(cnet_client *client, cnet_connection connection, unsigned char value) {
  mem_buffer_t *buffer = mem_get_buffer(mem_global(), 1u);
  int status;
  if (buffer == NULL) return SALTS_ENOMEM;
  *mem_buffer_data(buffer) = (char)value;
  mem_set_used(buffer, 1u);
  status = cnet_send_buffer(client, connection, buffer);
  mem_buffer_release(buffer);
  return status;
}

static int tls_pool_acquire_rejected(cnet_client_pool *pool, const cnet_pool_key *key) {
  cnet_pool_lease lease = {UINTPTR_MAX, UINT64_MAX, UINT64_MAX, SIZE_MAX};
  cnet_managed_connection managed = {UINTPTR_MAX, UINT64_MAX, UINT64_MAX, SIZE_MAX};
  const int status = cnet_pool_try_acquire(pool, key, NULL, &lease, &managed);
  const int rejected = status == SALTS_ENOBUFS &&
      lease.pool == 0u && lease.incarnation == 0u && lease.generation == 0u && lease.slot == 0u &&
      managed.manager == 0u && managed.incarnation == 0u &&
      managed.generation == 0u && managed.slot == 0u;
  if (status == SALTS_OK) (void)cnet_pool_release(pool, lease);
  return rejected;
}

static cnet_client_config config(void) {
  cnet_client_config result = {0};
#if defined(_WIN32)
  result.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  result.backend = NATIVE_IO_BACKEND_KQUEUE;
#else
  result.backend = NATIVE_IO_BACKEND_EPOLL;
#endif
  result.connection_capacity = 2u;
  result.command_capacity = 16u;
  result.request_capacity = 8u;
  result.completion_batch_capacity = 8u;
  result.event_capacity = 16u;
  result.max_send_bytes = 1024u;
  result.receive_buffer_bytes = 1024u;
  result.connect_timeout_ms = 2000u;
  result.read_timeout_ms = 2000u;
  result.write_timeout_ms = 2000u;
  result.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
  result.tls_handshake_timeout_ms = 2500u;
  return result;
}

static int drive(cnet_client *client, cnet_client *server,
                 cnet_listener *listener, cnet_tls_server *context,
                 tls_probe *server_probe, bool *accepted) {
  size_t events = 0u;
  int ready = 0;
  int status = cnet_client_poll(client, 1u, &events);
  if (status != SALTS_OK) return status;
  if (!*accepted) {
    status = cnet_listener_wait(listener, 0u, &ready);
    if (status != SALTS_OK) return status;
    if (ready) {
      const cnet_observer observer = {
          state_callback, receive_callback, server_probe, send_callback};
      status = cnet_listener_accept_tls(
          listener, server, context, &observer, &server_probe->connection);
      if (status != SALTS_OK) return status;
      *accepted = true;
    }
  }
  return cnet_client_poll(server, 1u, &events);
}

#define REQUIRE(expr) do {                                                    \
  if (!(expr)) {                                                              \
    fprintf(stderr, "CNet TLS case %s failed at %d: %s\n",                    \
            label, __LINE__, #expr);                                          \
    result = 1;                                                               \
    goto cleanup;                                                             \
  }                                                                           \
} while (0)

#include "tls_memory_inputs.h"

typedef struct tls_case_options {
  const char *label;
  const char *ca_file;
  const char *verified_hostname;
  bool expect_success;
  bool expect_server_rejection;
  const char *server_ca_file;
  const char *server_cert_file;
  const char *server_key_file;
  const char *client_cert_file;
  const char *client_key_file;
  cnet_tls_security_profile security_profile;
  const char *expected_server_fingerprint;
  const char *expected_client_fingerprint;
  const char *expected_server_binding;
  const cnet_tls_peer_policy *client_peer_policy;
  const cnet_tls_peer_policy *server_peer_policy;
  bool release_tls_context_early;
  cnet_tls_peer_policy *release_peer_policy;
  bool stream_transfer;
  bool pool_reuse;
  cnet_tls_protocol_version client_minimum, client_maximum;
  cnet_tls_protocol_version server_minimum, server_maximum;
  const char *expected_version;
  crypto_tls_failure_reason expected_failure;
  uint32_t client_depth, server_depth;
  const cnet_tls_cipher_suite *client_ciphers, *server_ciphers;
  size_t client_cipher_count, server_cipher_count;
  const char *expected_cipher;
  const cnet_tls_signature_scheme *client_signatures, *server_signatures;
  size_t client_signature_count, server_signature_count;
  const cnet_tls_signature_scheme *client_certificate_signatures, *server_certificate_signatures;
  size_t client_certificate_signature_count, server_certificate_signature_count;
} tls_case_options;

static int run_case(const tls_case_options *options) {
  const char *label = options->label;
  const bool should_verify = options->expect_success;
  cnet_client client = {0};
  cnet_client server = {0};
  cnet_listener listener = {0};
  cnet_tls_server tls_server = {0};
  cnet_manager manager = {0};
  cnet_client_pool pool = {0};
  cnet_managed_connection managed = {0}, leased = {0};
  cnet_pool_connection physical = {0};
  cnet_pool_lease lease = {0}, stale_lease = {0};
  cnet_pool_key pool_key = {
      .size = sizeof(cnet_pool_key), .version = CNET_CLIENT_POOL_VERSION,
      .runtime_id = 1u, .owner_id = 11u, .peer_generation = 1u,
      .authority_id = 17u, .transport_id = 2u, .tls_trust_id = 19u,
      .tls_sni_id = 23u, .protocol_id = 29u, .session_id = 31u};
  const cnet_manager_config manager_cfg = {
      sizeof(cnet_manager_config), CNET_MANAGER_VERSION, &client, 1u, 1u};
  const cnet_pool_config pool_cfg = {
      sizeof(cnet_pool_config), CNET_CLIENT_POOL_VERSION, &manager, 11u, 1u, 1u, 2u};
  cnet_client_config client_cfg = config();
  const cnet_client_config server_cfg = config();
  const cnet_listener_config listener_cfg = {
      client_cfg.backend, "127.0.0.1", 0u, 2u};
  cnet_tls_cipher_suite client_ciphers[CRYPTO_TLS_CIPHER_SUITE_MAX_COUNT] = {0};
  cnet_tls_cipher_suite server_ciphers[CRYPTO_TLS_CIPHER_SUITE_MAX_COUNT] = {0};
  if (options->client_cipher_count > CRYPTO_TLS_CIPHER_SUITE_MAX_COUNT ||
      options->server_cipher_count > CRYPTO_TLS_CIPHER_SUITE_MAX_COUNT) return 2;
  if (options->client_cipher_count) memcpy(client_ciphers, options->client_ciphers,
      options->client_cipher_count * sizeof(*client_ciphers));
  if (options->server_cipher_count) memcpy(server_ciphers, options->server_ciphers,
      options->server_cipher_count * sizeof(*server_ciphers));
  cnet_tls_signature_scheme client_certificate_signatures[CRYPTO_TLS_SIGNATURE_MAX_COUNT] = {0};
  cnet_tls_signature_scheme server_certificate_signatures[CRYPTO_TLS_SIGNATURE_MAX_COUNT] = {0};
  if (options->client_certificate_signature_count > CRYPTO_TLS_SIGNATURE_MAX_COUNT ||
      options->server_certificate_signature_count > CRYPTO_TLS_SIGNATURE_MAX_COUNT) return 2;
  if (options->client_certificate_signature_count) memcpy(client_certificate_signatures, options->client_certificate_signatures,
      options->client_certificate_signature_count * sizeof(*client_certificate_signatures));
  if (options->server_certificate_signature_count) memcpy(server_certificate_signatures, options->server_certificate_signatures,
      options->server_certificate_signature_count * sizeof(*server_certificate_signatures));
  cnet_tls_signature_scheme client_signatures[CRYPTO_TLS_SIGNATURE_MAX_COUNT] = {0};
  cnet_tls_signature_scheme server_signatures[CRYPTO_TLS_SIGNATURE_MAX_COUNT] = {0};
  if (options->client_signature_count > CRYPTO_TLS_SIGNATURE_MAX_COUNT ||
      options->server_signature_count > CRYPTO_TLS_SIGNATURE_MAX_COUNT) return 2;
  if (options->client_signature_count) memcpy(client_signatures, options->client_signatures,
      options->client_signature_count * sizeof(*client_signatures));
  if (options->server_signature_count) memcpy(server_signatures, options->server_signatures,
      options->server_signature_count * sizeof(*server_signatures));
  const cnet_tls_server_config server_tls_cfg = {
      .size = sizeof(cnet_tls_server_config),
      .cert_file = options->server_cert_file != NULL
                       ? options->server_cert_file : CORE_TLS_TEST_P384_LEAF,
      .key_file = options->server_key_file != NULL
                      ? options->server_key_file : CORE_TLS_TEST_P384_KEY,
      .ca_file = options->server_ca_file,
      .client_auth = options->server_ca_file != NULL
                         ? CNET_TLS_CLIENT_AUTH_REQUIRED
                         : CNET_TLS_CLIENT_AUTH_NONE,
      .security_profile = options->security_profile,
      .peer_policy = options->server_peer_policy,
      .minimum_version = options->server_minimum, .maximum_version = options->server_maximum,
      .verification_depth = options->server_depth,
      .cipher_suites = options->server_cipher_count ? server_ciphers : NULL,
      .cipher_suite_count = options->server_cipher_count,
      .signature_algorithms = options->server_signature_count ? server_signatures : NULL,
      .signature_algorithm_count = options->server_signature_count,
      .certificate_signature_algorithms = options->server_certificate_signature_count ? server_certificate_signatures : NULL,
      .certificate_signature_algorithm_count = options->server_certificate_signature_count};
  const cnet_tls_client_config client_tls_cfg = {
      .size = sizeof(cnet_tls_client_config),
      .ca_file = options->ca_file,
      .cert_file = options->client_cert_file,
      .key_file = options->client_key_file,
      .server_name = options->verified_hostname,
      .security_profile = options->security_profile,
      .peer_policy = options->client_peer_policy,
      .minimum_version = options->client_minimum, .maximum_version = options->client_maximum,
      .verification_depth = options->client_depth,
      .cipher_suites = options->client_cipher_count ? client_ciphers : NULL,
      .cipher_suite_count = options->client_cipher_count,
      .signature_algorithms = options->client_signature_count ? client_signatures : NULL,
      .signature_algorithm_count = options->client_signature_count,
      .certificate_signature_algorithms = options->client_certificate_signature_count ? client_certificate_signatures : NULL,
      .certificate_signature_algorithm_count = options->client_certificate_signature_count};
  tls_probe client_probe = {0}, server_probe = {0};
  cnet_connect_options connect_options = {0};
  cnet_connection outbound = {0};
  bool tls_live = false, client_live = false;
  bool server_live = false, listener_live = false, accepted = false;
  bool manager_live = false, pool_live = false;
  char uri[80] = {0};
  uint16_t port = 0u;
  uint64_t deadline;
  int result = 0;
  mem_buffer_t *outgoing = NULL;
  mem_buffer_t *bulk = NULL;
  mem_slice_t ranges[TLS_STREAM_SEGMENTS] = {{0}};
  size_t range_count = 0u;
  unsigned char expected_stream[TLS_STREAM_TOTAL_BYTES];
  size_t management_work = 0u;

  client_probe.client = &client;
  server_probe.client = &server;
  client_probe.pool_reuse = options->pool_reuse;
  server_probe.pool_reuse = options->pool_reuse;
  if (options->stream_transfer) {
    client_cfg.max_send_bytes = TLS_STREAM_BULK_BYTES;
    client_probe.stream_transfer = true;
    server_probe.stream_transfer = true;
    server_probe.expected_stream = expected_stream;
    server_probe.expected_stream_size = sizeof(expected_stream);
    memcpy(expected_stream, "CTRL-01", TLS_STREAM_CONTROL_BYTES);
    for (size_t i = 0u; i < TLS_STREAM_BULK_BYTES; ++i)
      expected_stream[TLS_STREAM_CONTROL_BYTES + i] =
          (unsigned char)((i * 29u + 3u) & 0xffu);
    memcpy(expected_stream + TLS_STREAM_CONTROL_BYTES + TLS_STREAM_BULK_BYTES,
           "FIN!!", TLS_STREAM_FINAL_BYTES);
  }
  REQUIRE(tls_test_server_init(&tls_server, &server_tls_cfg) == SALTS_OK);
  tls_live = true;
  REQUIRE(cnet_client_init(&client, &client_cfg) == SALTS_OK);
  client_live = true;
  REQUIRE(cnet_client_init(&server, &server_cfg) == SALTS_OK);
  server_live = true;
  REQUIRE(cnet_listener_init(&listener, &listener_cfg) == SALTS_OK);
  listener_live = true;
  REQUIRE(cnet_listener_port(&listener, &port) == SALTS_OK && port != 0u);
  REQUIRE(snprintf(uri, sizeof(uri), "tls://127.0.0.1:%u",
                   (unsigned int)port) > 0);
  connect_options = (cnet_connect_options){
      .uri = uri,
      .observer = {state_callback, receive_callback, &client_probe, send_callback},
      .tls = &client_tls_cfg};
  if (options->pool_reuse) {
    const cnet_manager_attachment attachment = {
        {state_callback, receive_callback, &client_probe, send_callback},
        recycle_callback, false};
    pool_key.endpoint_id = port;
    REQUIRE(cnet_manager_init(&manager, &manager_cfg) == SALTS_OK);
    manager_live = true;
    REQUIRE(cnet_pool_init(&pool, &pool_cfg) == SALTS_OK);
    pool_live = true;
    REQUIRE(cnet_pool_reserve_connecting(&pool, &pool_key, &physical) == SALTS_OK);
    REQUIRE(cnet_manager_reserve(&manager, &attachment, &managed) == SALTS_OK);
    REQUIRE(tls_pool_acquire_rejected(&pool, &pool_key));
    REQUIRE(cnet_manager_connect(&manager, managed, &connect_options, &outbound) == SALTS_OK);
  } else {
    REQUIRE(tls_test_connect(&client, &connect_options, &outbound) == SALTS_OK);
  }
  /* Context admission must consume both lists before progress; the server
   * also creates its stream later, from this already admitted context. */
  memset(client_ciphers, 0, sizeof(client_ciphers));
  memset(server_ciphers, 0, sizeof(server_ciphers));
  memset(client_certificate_signatures, 0, sizeof(client_certificate_signatures));
  memset(server_certificate_signatures, 0, sizeof(server_certificate_signatures));
  memset(client_signatures, 0, sizeof(client_signatures));
  memset(server_signatures, 0, sizeof(server_signatures));
  if (options->release_peer_policy != NULL) {
    options->release_peer_policy->release(options->release_peer_policy->context);
    memset(options->release_peer_policy, 0, sizeof(*options->release_peer_policy));
  }
  if (options->stream_transfer) {
    outgoing = mem_get_buffer(mem_global(), TLS_STREAM_CONTROL_BYTES);
    REQUIRE(outgoing != NULL);
    memcpy(mem_buffer_data(outgoing), expected_stream, TLS_STREAM_CONTROL_BYTES);
    mem_set_used(outgoing, TLS_STREAM_CONTROL_BYTES);
    /* Admission before the verified Channel READY gate retains no payload. */
    REQUIRE(cnet_send_buffer(&client, outbound, outgoing) == SALTS_EBUSY);
    REQUIRE(mem_buffer_ref_count(outgoing) == 1u);
    REQUIRE(client_probe.sent_count == 0u && server_probe.received_count == 0u);
    mem_buffer_release(outgoing);
    outgoing = NULL;
  }

  deadline = cmeta_monotonic_ms() + 7000u;
  while (cmeta_monotonic_ms() < deadline) {
    if (should_verify) {
      if (client_probe.connected_count && server_probe.connected_count) break;
      if (client_probe.terminal_count || server_probe.terminal_count) break;
    } else if (options->expect_server_rejection) {
      if (server_probe.terminal_count) break;
    } else if (client_probe.terminal_count) break;
    REQUIRE(drive(&client, &server, &listener, &tls_server,
                  &server_probe, &accepted) == SALTS_OK);
    if (accepted && tls_live && options->release_tls_context_early) {
      REQUIRE(cnet_tls_server_destroy(&tls_server) == SALTS_OK);
      tls_live = false;
    }
  }

  REQUIRE(accepted);
  if (!should_verify) {
    const tls_probe *rejected = options->expect_server_rejection ? &server_probe : &client_probe;
    if (options->expected_failure != CRYPTO_TLS_FAILURE_NONE) {
      if (rejected->tls_diagnostic.reason != options->expected_failure)
        fprintf(stderr, "TLS diagnostic: actual=%d expected=%d status=%d\n",
            rejected->tls_diagnostic.reason, options->expected_failure, rejected->last_error_status);
      REQUIRE(rejected->tls_diagnostic.reason == options->expected_failure);
      REQUIRE(rejected->tls_diagnostic.certificate_index ==
          (options->expected_failure == CRYPTO_TLS_FAILURE_IDENTITY ? 0u : SIZE_MAX));
    }
    /* A rejection must never deliver plaintext or publish a verified
     * server connection. Only the handshake-owning side determines rejection. */
    REQUIRE(client_probe.received_count == 0u);
    REQUIRE(server_probe.received_count == 0u);
    REQUIRE(client_probe.sent_count == 0u);
    REQUIRE(server_probe.sent_count == 0u);
    if (options->expect_server_rejection) {
      REQUIRE(server_probe.terminal_count == 1u);
      REQUIRE(server_probe.failed != 0u);
      REQUIRE(server_probe.last_error_status != SALTS_ETIMEDOUT);
      REQUIRE(server_probe.connected_count == 0u);
      REQUIRE(strcmp(server_probe.failure_stage, "handshake") == 0);
    } else {
      REQUIRE(client_probe.terminal_count == 1u);
      REQUIRE(client_probe.failed != 0u);
      REQUIRE(client_probe.last_error_status != SALTS_ETIMEDOUT);
      REQUIRE(client_probe.connected_count == 0u);
      REQUIRE(strcmp(client_probe.failure_stage, "handshake") == 0);
    }
  } else {
    char fingerprint[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY] = {0};
    REQUIRE(client_probe.connected_count == 1u);
    REQUIRE(server_probe.connected_count == 1u);
    REQUIRE(client_probe.failed == 0u && server_probe.failed == 0u);
    REQUIRE(client_probe.tls_version_status == SALTS_OK);
    REQUIRE(server_probe.tls_version_status == SALTS_OK);
    if (options->expected_version) {
      REQUIRE(strcmp(client_probe.tls_version, options->expected_version) == 0);
      REQUIRE(strcmp(server_probe.tls_version, options->expected_version) == 0);
    }
    REQUIRE(client_probe.tls_cipher_status == SALTS_OK);
    REQUIRE(strlen(client_probe.tls_cipher) != 0u);
    if (options->expected_cipher) {
      REQUIRE(strcmp(client_probe.tls_cipher, options->expected_cipher) == 0);
      REQUIRE(strcmp(server_probe.tls_cipher, options->expected_cipher) == 0);
    }
    REQUIRE(strcmp(client_probe.tls_version, "TLSv1.3") == 0 ||
            strcmp(client_probe.tls_version, "TLSv1.2") == 0);
    REQUIRE(cnet_tls_peer_certificate_sha256(&client, outbound,
                                             fingerprint) == SALTS_OK);
    REQUIRE(strlen(fingerprint) == 64u);
    if (options->expected_server_fingerprint != NULL)
      REQUIRE(strcmp(fingerprint, options->expected_server_fingerprint) == 0);
    if (options->security_profile == CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13) {
      REQUIRE(strcmp(client_probe.tls_version, "TLSv1.3") == 0 &&
              strcmp(server_probe.tls_version, "TLSv1.3") == 0);
      REQUIRE(strcmp(client_probe.tls_cipher, "TLS_SM4_GCM_SM3") == 0 &&
              strcmp(server_probe.tls_cipher, "TLS_SM4_GCM_SM3") == 0);
    }
    {
      uint8_t client_binding[CNET_TLS_SERVER_END_POINT_MAX_BYTES];
      uint8_t server_binding[CNET_TLS_SERVER_END_POINT_MAX_BYTES];
      size_t client_size = 0u, server_size = 0u;
      REQUIRE(cnet_tls_server_end_point_binding(&client, outbound,
          client_binding, sizeof(client_binding), &client_size) == SALTS_OK);
      REQUIRE(cnet_tls_server_end_point_binding(&server, server_probe.connection,
          server_binding, sizeof(server_binding), &server_size) == SALTS_OK);
      REQUIRE(client_size != 0u && client_size == server_size);
      REQUIRE(memcmp(client_binding, server_binding, client_size) == 0);
      if (options->expected_server_binding != NULL) {
        static const char hex[] = "0123456789abcdef";
        char encoded[65] = {0};
        REQUIRE(client_size == 32u);
        for (size_t i = 0u; i < client_size; ++i) {
          encoded[2u * i] = hex[client_binding[i] >> 4];
          encoded[2u * i + 1u] = hex[client_binding[i] & 15u];
        }
        REQUIRE(strcmp(encoded, options->expected_server_binding) == 0);
      }
    }
    if (options->server_ca_file != NULL) {
      char client_certificate_hash[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY] = {0};
      REQUIRE(cnet_tls_peer_certificate_sha256(
          &server, server_probe.connection, client_certificate_hash) == SALTS_OK);
      REQUIRE(strlen(client_certificate_hash) == 64u);
      if (options->expected_client_fingerprint != NULL)
        REQUIRE(strcmp(client_certificate_hash, options->expected_client_fingerprint) == 0);
    }
    if (options->pool_reuse) {
      cnet_pool_snapshot snapshot = {0};
      cnet_pool_key incompatible = {0};
      uint64_t *security_fields[] = {
          &incompatible.tls_trust_id, &incompatible.tls_sni_id,
          &incompatible.client_identity_id, &incompatible.alpn_id,
          &incompatible.protocol_id, &incompatible.session_id};
      /* TLS trust/DNS verification is complete, but the host has not yet
       * observed this application's READY greeting. Pool does not infer it. */
      REQUIRE(tls_pool_acquire_rejected(&pool, &pool_key));
      REQUIRE(cnet_pool_get_snapshot(&pool, &snapshot) == SALTS_OK);
      REQUIRE(snapshot.connecting == 1u && snapshot.ready == 0u);
      REQUIRE(cnet_receive(&client, outbound, 1u) == SALTS_OK);
      REQUIRE(send_byte(&server, server_probe.connection, 0x52u) == SALTS_OK);
      deadline = cmeta_monotonic_ms() + 7000u;
      while ((client_probe.received_count < 1u || server_probe.sent_count < 1u) &&
             !client_probe.terminal_count && !server_probe.terminal_count &&
             cmeta_monotonic_ms() < deadline)
        REQUIRE(drive(&client, &server, &listener, &tls_server,
                      &server_probe, &accepted) == SALTS_OK);
      REQUIRE(client_probe.received_count == 1u && client_probe.received_byte == 0x52u);
      REQUIRE(server_probe.sent_count == 1u);
      REQUIRE(client_probe.failed == 0u && server_probe.failed == 0u);
      REQUIRE(cnet_pool_bind_ready(&pool, physical, managed, 1u) == SALTS_OK);
      for (size_t i = 0u; i < sizeof(security_fields) / sizeof(security_fields[0]); ++i) {
        incompatible = pool_key;
        ++*security_fields[i];
        REQUIRE(tls_pool_acquire_rejected(&pool, &incompatible));
      }
      /* One Owner thread progresses both real TLS endpoints. A lease reserves
       * one application request slot and is released only after its peer reply.
       * All buffers are released by the caller immediately after admission. */
      for (unsigned exchange = 0u; exchange < 2u; ++exchange) {
        cnet_manager_entry entry = {0};
        char current_fingerprint[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY] = {0};
        REQUIRE(cnet_pool_try_acquire(&pool, &pool_key, NULL, &lease, &leased) == SALTS_OK);
        REQUIRE(leased.manager == managed.manager && leased.incarnation == managed.incarnation &&
                leased.generation == managed.generation && leased.slot == managed.slot);
        REQUIRE(cnet_manager_lookup(&manager, leased, &entry) == SALTS_OK);
        REQUIRE(entry.state == CNET_MANAGER_BOUND && entry.connection.slot == outbound.slot &&
                entry.connection.generation == outbound.generation);
        REQUIRE(tls_pool_acquire_rejected(&pool, &pool_key));
        if (exchange != 0u) {
          REQUIRE(lease.slot == stale_lease.slot && lease.generation > stale_lease.generation);
          REQUIRE(cnet_pool_release(&pool, stale_lease) == SALTS_ENOENT);
        }
        REQUIRE(cnet_receive(&server, server_probe.connection, 1u) == SALTS_OK);
        REQUIRE(send_byte(&client, entry.connection, (unsigned char)(0x41u + exchange)) == SALTS_OK);
        deadline = cmeta_monotonic_ms() + 7000u;
        while ((server_probe.received_count < exchange + 1u ||
                client_probe.sent_count < exchange + 1u) &&
               !client_probe.terminal_count && !server_probe.terminal_count &&
               cmeta_monotonic_ms() < deadline)
          REQUIRE(drive(&client, &server, &listener, &tls_server,
                        &server_probe, &accepted) == SALTS_OK);
        REQUIRE(server_probe.received_count == exchange + 1u &&
                server_probe.received_byte == 0x41u + exchange);
        REQUIRE(client_probe.sent_count == exchange + 1u);
        REQUIRE(cnet_pool_get_snapshot(&pool, &snapshot) == SALTS_OK);
        REQUIRE(snapshot.active_leases == 1u && snapshot.physical_in_use == 1u);
        REQUIRE(tls_pool_acquire_rejected(&pool, &pool_key));
        REQUIRE(cnet_receive(&client, entry.connection, 1u) == SALTS_OK);
        REQUIRE(send_byte(&server, server_probe.connection, (unsigned char)(0x61u + exchange)) == SALTS_OK);
        deadline = cmeta_monotonic_ms() + 7000u;
        while ((client_probe.received_count < exchange + 2u ||
                server_probe.sent_count < exchange + 2u) &&
               !client_probe.terminal_count && !server_probe.terminal_count &&
               cmeta_monotonic_ms() < deadline)
          REQUIRE(drive(&client, &server, &listener, &tls_server,
                        &server_probe, &accepted) == SALTS_OK);
        REQUIRE(client_probe.received_count == exchange + 2u &&
                client_probe.received_byte == 0x61u + exchange);
        REQUIRE(server_probe.sent_count == exchange + 2u);
        REQUIRE(client_probe.connected_count == 1u && server_probe.connected_count == 1u &&
                client_probe.terminal_count == 0u && server_probe.terminal_count == 0u &&
                client_probe.failed == 0u && server_probe.failed == 0u);
        REQUIRE(cnet_tls_peer_certificate_sha256(&client, entry.connection,
                                                 current_fingerprint) == SALTS_OK);
        REQUIRE(strcmp(current_fingerprint, fingerprint) == 0);
        stale_lease = lease;
        REQUIRE(cnet_pool_release(&pool, lease) == SALTS_OK);
        lease = (cnet_pool_lease){0};
      }
      REQUIRE(cnet_pool_terminal(&pool, physical) == SALTS_EBUSY);
      REQUIRE(cnet_pool_begin_drain(&pool, physical) == SALTS_OK);
      REQUIRE(tls_pool_acquire_rejected(&pool, &pool_key));
      REQUIRE(cnet_close(&client, outbound) == SALTS_OK);
    } else if (options->stream_transfer) {
      /* Two Owners progress on this one issuing thread. Each accepted logical
       * write retains immutable backing until its terminal. The receiver checks
       * all plaintext independently of local send completion. One demand per
       * possible byte bounds callbacks without assuming TLS record boundaries. */
      REQUIRE(cnet_receive(&server, server_probe.connection,
                           sizeof(expected_stream)) == SALTS_OK);
      outgoing = mem_get_buffer(mem_global(), TLS_STREAM_BULK_BYTES + 1u);
      REQUIRE(outgoing != NULL);
      mem_set_used(outgoing, TLS_STREAM_BULK_BYTES + 1u);
      REQUIRE(cnet_send_buffer(&client, outbound, outgoing) == SALTS_EMSGSIZE);
      REQUIRE(mem_buffer_ref_count(outgoing) == 1u);
      mem_buffer_release(outgoing);
      outgoing = NULL;

      outgoing = mem_get_buffer(mem_global(), TLS_STREAM_CONTROL_BYTES);
      REQUIRE(outgoing != NULL);
      memcpy(mem_buffer_data(outgoing), expected_stream, TLS_STREAM_CONTROL_BYTES);
      mem_set_used(outgoing, TLS_STREAM_CONTROL_BYTES);
      REQUIRE(cnet_send_buffer(&client, outbound, outgoing) == SALTS_OK);
      mem_buffer_release(outgoing);
      outgoing = NULL;

      /* Gaps prevent contiguous-range merging: every retained span must pass
       * through TLS in order, and the peer must never receive the gap bytes.
       * Total plaintext also exceeds the configured minimum TLS IO buffer. */
      bulk = mem_get_buffer(mem_global(),
          TLS_STREAM_SEGMENTS * (TLS_STREAM_SEGMENT_BYTES + 1u));
      REQUIRE(bulk != NULL);
      memset(mem_buffer_data(bulk), 0xd9,
             TLS_STREAM_SEGMENTS * (TLS_STREAM_SEGMENT_BYTES + 1u));
      mem_set_used(bulk, TLS_STREAM_SEGMENTS * (TLS_STREAM_SEGMENT_BYTES + 1u));
      for (size_t i = 0u; i < TLS_STREAM_SEGMENTS; ++i) {
        const size_t offset = i * (TLS_STREAM_SEGMENT_BYTES + 1u);
        memcpy(mem_buffer_data(bulk) + offset,
               expected_stream + TLS_STREAM_CONTROL_BYTES + i * TLS_STREAM_SEGMENT_BYTES,
               TLS_STREAM_SEGMENT_BYTES);
        ranges[i] = mem_slice(bulk, offset, TLS_STREAM_SEGMENT_BYTES);
        REQUIRE(ranges[i].buffer == bulk &&
                ranges[i].length == TLS_STREAM_SEGMENT_BYTES);
        ++range_count;
      }
      REQUIRE(cnet_send_slicev(&client, outbound, ranges, range_count) == SALTS_OK);
      REQUIRE(mem_buffer_ref_count(bulk) == range_count + 2u);
      for (size_t i = 0u; i < range_count; ++i) mem_slice_release(&ranges[i]);
      range_count = 0u;
      REQUIRE(mem_buffer_ref_count(bulk) == 2u);
      mem_buffer_release(bulk);
      bulk = NULL;

      deadline = cmeta_monotonic_ms() + 7000u;
      while ((client_probe.sent_count < 2u ||
              server_probe.stream_received < TLS_STREAM_CONTROL_BYTES + TLS_STREAM_BULK_BYTES) &&
             !client_probe.terminal_count && !server_probe.terminal_count &&
             !client_probe.failed && !server_probe.failed &&
             cmeta_monotonic_ms() < deadline)
        REQUIRE(drive(&client, &server, &listener, &tls_server,
                      &server_probe, &accepted) == SALTS_OK);
      REQUIRE(client_probe.sent_count == 2u);
      REQUIRE(client_probe.send_sizes[0] == TLS_STREAM_CONTROL_BYTES &&
              client_probe.send_sizes[1] == TLS_STREAM_BULK_BYTES);
      REQUIRE(server_probe.stream_received == TLS_STREAM_CONTROL_BYTES + TLS_STREAM_BULK_BYTES);
      REQUIRE(client_probe.terminal_count == 0u && server_probe.terminal_count == 0u);
      REQUIRE(client_probe.failed == 0u && server_probe.failed == 0u);

      outgoing = mem_get_buffer(mem_global(), TLS_STREAM_FINAL_BYTES);
      REQUIRE(outgoing != NULL);
      memcpy(mem_buffer_data(outgoing),
             expected_stream + TLS_STREAM_CONTROL_BYTES + TLS_STREAM_BULK_BYTES,
             TLS_STREAM_FINAL_BYTES);
      mem_set_used(outgoing, TLS_STREAM_FINAL_BYTES);
      REQUIRE(cnet_send_buffer_and_close(&client, outbound, outgoing) == SALTS_OK);
      mem_buffer_release(outgoing);
      outgoing = NULL;
    } else {
      REQUIRE(cnet_receive(&server, server_probe.connection, 1u) == SALTS_OK);

      outgoing = mem_get_buffer(mem_global(), 1u);
      REQUIRE(outgoing != NULL);
      *mem_buffer_data(outgoing) = 0x46;
      mem_set_used(outgoing, 1u);
      REQUIRE(cnet_send_buffer(&client, outbound, outgoing) == SALTS_OK);
      mem_buffer_release(outgoing);
      outgoing = NULL;
      deadline = cmeta_monotonic_ms() + 7000u;
      while ((server_probe.received_count < 1u ||
              client_probe.sent_count < 1u) &&
             !client_probe.terminal_count && !server_probe.terminal_count &&
             cmeta_monotonic_ms() < deadline)
        REQUIRE(drive(&client, &server, &listener, &tls_server,
                      &server_probe, &accepted) == SALTS_OK);
      REQUIRE(server_probe.received_count == 1u);
      REQUIRE(server_probe.received_byte == 0x46);
      REQUIRE(client_probe.sent_count == 1u);
      REQUIRE(client_probe.failed == 0u && server_probe.failed == 0u);

      if (options->security_profile == CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13) {
        REQUIRE(cnet_receive(&client, outbound, 1u) == SALTS_OK);
        REQUIRE(send_byte(&server, server_probe.connection, 0x47u) == SALTS_OK);
        deadline = cmeta_monotonic_ms() + 7000u;
        while ((!client_probe.received_count || !server_probe.sent_count) &&
               !client_probe.terminal_count && !server_probe.terminal_count &&
               cmeta_monotonic_ms() < deadline)
          REQUIRE(drive(&client, &server, &listener, &tls_server,
                        &server_probe, &accepted) == SALTS_OK);
        REQUIRE(client_probe.received_count == 1u && client_probe.received_byte == 0x47u);
        REQUIRE(server_probe.sent_count == 1u && client_probe.failed == 0u && server_probe.failed == 0u);
      }
      REQUIRE(cnet_close(&client, outbound) == SALTS_OK);
    }
    deadline = cmeta_monotonic_ms() + 7000u;
    while ((!client_probe.terminal_count || !server_probe.terminal_count) &&
           cmeta_monotonic_ms() < deadline)
      REQUIRE(drive(&client, &server, &listener, &tls_server,
                    &server_probe, &accepted) == SALTS_OK);
    REQUIRE(client_probe.terminal_count == 1u);
    REQUIRE(server_probe.terminal_count == 1u);
    REQUIRE(client_probe.failed == 0u && server_probe.failed == 0u);
    if (options->pool_reuse) {
      cnet_pool_snapshot pool_snapshot = {0};
      cnet_manager_snapshot manager_snapshot = {0};
      REQUIRE(client_probe.sent_count == 2u && server_probe.sent_count == 3u);
      REQUIRE(client_probe.received_count == 3u && server_probe.received_count == 2u);
      REQUIRE(client_probe.sends_at_terminal == 2u && server_probe.sends_at_terminal == 3u);
      REQUIRE(client_probe.last_connection_state == CNET_CONNECTION_CLOSED &&
              server_probe.last_connection_state == CNET_CONNECTION_CLOSED);
      REQUIRE(drive(&client, &server, &listener, &tls_server,
                    &server_probe, &accepted) == SALTS_OK);
      REQUIRE(client_probe.terminal_count == 1u && server_probe.terminal_count == 1u &&
              client_probe.connected_count == 1u && server_probe.connected_count == 1u &&
              client_probe.sent_count == 2u && server_probe.sent_count == 3u &&
              client_probe.failed == 0u && server_probe.failed == 0u);
      REQUIRE(cnet_pool_terminal(&pool, physical) == SALTS_OK);
      REQUIRE(cnet_pool_get_snapshot(&pool, &pool_snapshot) == SALTS_OK);
      REQUIRE(pool_snapshot.drained && pool_snapshot.active_leases == 0u);
      REQUIRE(cnet_pool_destroy(&pool) == SALTS_OK);
      pool_live = false;
      REQUIRE(cnet_manager_advance(&manager, 1u, &management_work) == SALTS_OK);
      REQUIRE(client_probe.recycled_count == 1u);
      REQUIRE(cnet_manager_get_snapshot(&manager, &manager_snapshot) == SALTS_OK);
      REQUIRE(manager_snapshot.drained);
      REQUIRE(cnet_manager_destroy(&manager) == SALTS_OK);
      manager_live = false;
    }
    if (options->stream_transfer) {
      REQUIRE(client_probe.sent_count == 3u && client_probe.sends_at_terminal == 3u);
      REQUIRE(client_probe.send_sizes[2] == TLS_STREAM_FINAL_BYTES);
      REQUIRE(server_probe.stream_received == sizeof(expected_stream));
      REQUIRE(client_probe.last_connection_state == CNET_CONNECTION_CLOSED &&
              server_probe.last_connection_state == CNET_CONNECTION_CLOSED);
      /* Drain any late native completions before checking callback uniqueness. */
      REQUIRE(drive(&client, &server, &listener, &tls_server,
                    &server_probe, &accepted) == SALTS_OK);
      REQUIRE(client_probe.sent_count == 3u && client_probe.terminal_count == 1u &&
              server_probe.terminal_count == 1u &&
              client_probe.connected_count == 1u && server_probe.connected_count == 1u &&
              client_probe.failed == 0u && server_probe.failed == 0u);
    }
    if (options->stream_transfer || options->pool_reuse) {
      REQUIRE(cnet_client_stop(&client, 5000u) == SALTS_OK);
      REQUIRE(cnet_client_destroy(&client) == SALTS_OK);
      client_live = false;
      REQUIRE(cnet_client_stop(&server, 5000u) == SALTS_OK);
      REQUIRE(cnet_client_destroy(&server) == SALTS_OK);
      server_live = false;
      REQUIRE(cnet_listener_close(&listener) == SALTS_OK);
      REQUIRE(cnet_listener_destroy(&listener) == SALTS_OK);
      listener_live = false;
      REQUIRE(cnet_tls_server_destroy(&tls_server) == SALTS_OK);
      tls_live = false;
    }
  }
  if (options->security_profile == CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13 && client_live) {
    REQUIRE(cnet_client_stop(&client, 5000u) == SALTS_OK);
    REQUIRE(cnet_client_stop(&server, 5000u) == SALTS_OK);
    REQUIRE(client_probe.terminal_count == 1u && server_probe.terminal_count == 1u);
    REQUIRE(cnet_client_destroy(&client) == SALTS_OK);
    client_live = false;
    REQUIRE(cnet_client_destroy(&server) == SALTS_OK);
    server_live = false;
    REQUIRE(cnet_listener_close(&listener) == SALTS_OK);
    REQUIRE(cnet_listener_destroy(&listener) == SALTS_OK);
    listener_live = false;
    REQUIRE(cnet_tls_server_destroy(&tls_server) == SALTS_OK);
    tls_live = false;
  }

cleanup:
  for (size_t i = 0u; i < range_count; ++i) mem_slice_release(&ranges[i]);
  if (bulk) mem_buffer_release(bulk);
  if (outgoing) mem_buffer_release(outgoing);
  if (accepted && !server_probe.terminal_count && server_live)
    (void)cnet_close(&server, server_probe.connection);
  if (listener_live) {
    (void)cnet_listener_close(&listener);
    (void)cnet_listener_destroy(&listener);
  }
  if (manager_live) {
    (void)cnet_manager_request_close(&manager);
    (void)cnet_manager_advance(&manager, 1u, &management_work);
  }
  if (client_live) {
    (void)cnet_client_stop(&client, 5000u);
  }
  if (pool_live) {
    if (lease.slot != 0u) (void)cnet_pool_release(&pool, lease);
    if (physical.slot != 0u) (void)cnet_pool_terminal(&pool, physical);
    (void)cnet_pool_destroy(&pool);
  }
  if (manager_live) {
    (void)cnet_manager_advance(&manager, 1u, &management_work);
    (void)cnet_manager_destroy(&manager);
  }
  if (client_live) {
    (void)cnet_client_destroy(&client);
  }
  if (server_live) {
    (void)cnet_client_stop(&server, 5000u);
    (void)cnet_client_destroy(&server);
  }
  if (tls_live) (void)cnet_tls_server_destroy(&tls_server);
  return result;
}


/*
 * Native, production Salts::CNet client to independent Python ssl or GoTLCP
 * server. The peer fixes TLS1.2/TLS1.3 or TLCP and supplies the same valid X.509
 * leaf for both SAN-positive and SAN-negative controls. This mode never
 * imports the alternate test-only CNet TLS facade or its Provider.
 */
static int run_python_ssl_server(const char *port_text,
                                 const char *protocol,
                                 const char *identity,
                                 const char *trust_ca,
                                 bool expect_success,
                                 const char *client_cert,
                                 const char *client_key,
                                 const char *expected_server_sha256,
                                 cnet_tls_peer_policy *owned_policy) {
  const char *label = "production CNet -> independent secure stream peer";
  const bool tlcp = strcmp(protocol, "tlcp") == 0;
  const bool key_update_exchange = strcmp(protocol, "shangmi13-update") == 0;
  const bool peer_limit = strncmp(protocol, "shangmi13-limit", 15u) == 0;
  const bool peer_limit_failure = peer_limit && strstr(protocol, "fail") != NULL;
  const bool local_rotation = strncmp(protocol, "shangmi13-rotate", 15u) == 0;
  const uint32_t rotation_limit = strcmp(protocol, "shangmi13-rotate1") == 0 ? 1u :
      strcmp(protocol, "shangmi13-rotate2") == 0 ? 2u :
      strcmp(protocol, "shangmi13-rotatemax") == 0 ? CNET_TLS_KEY_UPDATE_RECORD_LIMIT_MAX : 0u;
  const unsigned rounds = local_rotation ? 5u : (key_update_exchange || peer_limit) ? 2u : 1u;
  const bool shangmi = strcmp(protocol, "shangmi13") == 0 || key_update_exchange || local_rotation || peer_limit;
  const bool approved_identity = expect_success;
  const char *expected_version = strcmp(protocol, "tls12") == 0
                                     ? "TLSv1.2" : tlcp ? "TLCPv1.1" : "TLSv1.3";
  char *end = NULL;
  unsigned long port = strtoul(port_text, &end, 10);
  cnet_client client = {0};
  cnet_connection outbound = {0};
  tls_probe probe = {0};
  cnet_connect_options connect_options = {0};
  cnet_client_config client_cfg = config();
  const bool version_range = getenv("SALTS_TEST_TLS_CLIENT_RANGE") != NULL;
  const cnet_tls_cipher_suite range_ciphers[] = {CRYPTO_TLS_CIPHER_AES_128_GCM_SHA256,
      CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256, CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256};
  const cnet_tls_cipher_suite peer_ciphers[] = {
      tlcp ? CRYPTO_TLS_CIPHER_TLCP_ECC_SM4_GCM_SM3 : shangmi ? CRYPTO_TLS_CIPHER_SM4_GCM_SM3 :
      strcmp(protocol, "tls12") == 0 ? CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256 : CRYPTO_TLS_CIPHER_AES_128_GCM_SHA256,
      CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256};
  const cnet_tls_signature_scheme rsa_signatures[] = {
      CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256, CRYPTO_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256};
  const bool separate_cert = getenv("SALTS_TEST_TLS_SEPARATE_CERT_SIGNATURES") != NULL;
  const bool rsa_only = getenv("SALTS_TEST_TLS_CLIENT_RSA_ONLY") != NULL;
  const cnet_tls_signature_scheme sm2_signature = CRYPTO_TLS_SIGNATURE_SM2_SM3;
  const cnet_tls_client_config tls_config = {
      .size = sizeof(cnet_tls_client_config),
      /* The existing external peer CLI uses "-" only for the independent
       * Windows native system-root negative. NULL enables the production
       * CNet system trust path, with no test-only TLS provider. */
      .ca_file = strcmp(trust_ca, "-") == 0 ? NULL : trust_ca,
      .server_name = identity,
      .cert_file = client_cert,
      .key_file = client_key,
      .security_profile = tlcp ? CNET_TLS_SECURITY_PROFILE_TLCP11 :
          shangmi ? CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13 : CNET_TLS_SECURITY_PROFILE_STANDARD,
      .signature_algorithms = tlcp || shangmi ? &sm2_signature : separate_cert ? rsa_signatures + 1u : rsa_only ? rsa_signatures : NULL,
      .signature_algorithm_count = tlcp || shangmi || separate_cert ? 1u : rsa_only ? (strcmp(protocol, "tls12") == 0 ? 1u : 2u) : 0u,
      .certificate_signature_algorithms = separate_cert ? rsa_signatures : NULL,
      .certificate_signature_algorithm_count = separate_cert ? 1u : 0u,
      .cipher_suites = version_range ? range_ciphers : peer_ciphers,
      .cipher_suite_count = version_range ? 3u : !tlcp && !shangmi && strcmp(protocol, "tls12") == 0 ? 2u : 1u,
      .peer_policy = owned_policy, .key_update_record_limit = rotation_limit,
      /* TLCP's two leaves do not consume issuer depth. Exercise the smallest
       * explicit bound with independent dual-certificate peers. */
      .verification_depth = tlcp ? 1u : 0u,
      .peer_key_update_limit = peer_limit && strcmp(protocol, "shangmi13-limit-off") != 0 ? 2u : 0u,
      .minimum_version = !version_range && !tlcp && !shangmi ? (strcmp(protocol, "tls12") == 0 ? 12 : 13) : 0,
      .maximum_version = !version_range && !tlcp && !shangmi ? (strcmp(protocol, "tls12") == 0 ? 12 : 13) : 0};
  char uri[96] = {0};
  bool initialized = false;
  mem_buffer_t *outgoing = NULL;
  uint64_t deadline;
  size_t events = 0u;
  int result = 0;

  if (end == port_text || *end != '\0' || port == 0u || port > 65535u ||
      (strcmp(protocol, "tls12") != 0 && strcmp(protocol, "tls13") != 0 && !tlcp && !shangmi) ||
      trust_ca == NULL || trust_ca[0] == '\0' ||
      (strcmp(identity, "localhost") != 0 &&
       strcmp(identity, "wrong.example") != 0 &&
       strcmp(identity, "127.0.0.1") != 0 &&
       strcmp(identity, "127.0.0.2") != 0 &&
       strcmp(identity, "::1") != 0 &&
       strcmp(identity, "::2") != 0))
    return 2;

  probe.client = &client;
  probe.expect_python_ok_record = true;
  probe.receive_limit = rounds;
  REQUIRE(cnet_client_init(&client, &client_cfg) == SALTS_OK);
  initialized = true;
  REQUIRE(snprintf(uri, sizeof(uri), "tls://127.0.0.1:%lu", port) > 0);
  connect_options = (cnet_connect_options){
      .uri = uri,
      .observer = {state_callback, receive_callback, &probe, send_callback},
      .tls = &tls_config};
  REQUIRE(tls_test_connect(&client, &connect_options, &outbound) == SALTS_OK);

  if (owned_policy != NULL) {
    owned_policy->release(owned_policy->context);
    memset(owned_policy, 0, sizeof(*owned_policy));
  }
  deadline = cmeta_monotonic_ms() + 9000u;
  while (!probe.connected_count && !probe.terminal_count &&
         cmeta_monotonic_ms() < deadline)
    REQUIRE(cnet_client_poll(&client, 1u, &events) == SALTS_OK);

  if (!approved_identity) {
    /* This must be a post-TCP handshake authentication rejection, not
     * a timeout, refused connect, or successful encrypted connection. */
    REQUIRE(probe.terminal_count == 1u);
    REQUIRE(probe.failed != 0u);
    REQUIRE(probe.last_error_status != SALTS_ETIMEDOUT);
    REQUIRE(probe.connected_count == 0u);
    REQUIRE(probe.received_count == 0u && probe.sent_count == 0u);
    REQUIRE(strcmp(probe.failure_stage, "handshake") == 0);
  } else {
    char digest[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY] = {0};
    REQUIRE(probe.connected_count == 1u && probe.failed == 0u);
    REQUIRE(probe.tls_version_status == SALTS_OK);
    REQUIRE(strcmp(probe.tls_version, expected_version) == 0);
    REQUIRE(probe.tls_cipher_status == SALTS_OK);
    REQUIRE(probe.tls_cipher[0] != '\0');
    if (tlcp) REQUIRE(strcmp(probe.tls_cipher, "TLS_ECC_SM4_GCM_SM3") == 0);
    if (shangmi) REQUIRE(strcmp(probe.tls_cipher, "TLS_SM4_GCM_SM3") == 0);
    REQUIRE(cnet_tls_peer_certificate_sha256(&client, outbound, digest) == SALTS_OK);
    REQUIRE(strlen(digest) == 64u);
    if (expected_server_sha256 != NULL)
      REQUIRE(strcmp(digest, expected_server_sha256) == 0);
    REQUIRE(cnet_receive(&client, outbound, 1u) == SALTS_OK);

    outgoing = mem_get_buffer(mem_global(), 1u);
    REQUIRE(outgoing != NULL);
    *mem_buffer_data(outgoing) = 0x46u;
    mem_set_used(outgoing, 1u);
    REQUIRE(cnet_send_buffer(&client, outbound, outgoing) == SALTS_OK);
    mem_buffer_release(outgoing);
    outgoing = NULL;
    deadline = cmeta_monotonic_ms() + 9000u;
    while ((!probe.received_count || !probe.sent_count) &&
           !probe.terminal_count && cmeta_monotonic_ms() < deadline)
      REQUIRE(cnet_client_poll(&client, 1u, &events) == SALTS_OK);
    /* Independent Python ssl writes "ok" over the negotiated record;
     * one receive-event credit must deliver that complete record. The
     * peer waits for our authenticated shutdown after BOTH local events. */
    if (probe.received_count != 1u || probe.received_byte != 'o' || probe.failed)
      fprintf(stderr, "Python TLS success data received=%u byte=%u sent=%u terminal=%u failed=%u status=%d native=%d stage=%s\n",
              probe.received_count, (unsigned)probe.received_byte, probe.sent_count, probe.terminal_count,
              probe.failed, probe.last_error_status, probe.last_native_status, probe.failure_stage);
    REQUIRE(probe.received_count == 1u && probe.received_byte == 'o' &&
            probe.failed == 0u);
    REQUIRE(probe.sent_count == 1u && probe.failed == 0u);
    for (unsigned round = 2u; round <= rounds; ++round) {
      /* Each round forces a distinct application record across local or
       * peer-requested rotations; completion counts exclude control records. */
      REQUIRE(cnet_receive(&client, outbound, 1u) == SALTS_OK);
      REQUIRE(send_byte(&client, outbound, 0x46u) == SALTS_OK);
      deadline = cmeta_monotonic_ms() + 9000u;
      while ((probe.received_count != round || probe.sent_count != round) &&
             !probe.terminal_count && cmeta_monotonic_ms() < deadline)
        REQUIRE(cnet_client_poll(&client, 1u, &events) == SALTS_OK);
      if (peer_limit_failure) {
        REQUIRE(probe.terminal_count == 1u && probe.failed == 1u);
        REQUIRE(probe.received_count == 1u && probe.sent_count >= 1u && probe.sent_count <= 2u);
        REQUIRE(probe.last_error_status == SALTS_EPROTO && strcmp(probe.failure_stage, "read") == 0);
        REQUIRE(probe.last_connection_state == CNET_CONNECTION_FAILED);
        goto cleanup;
      }
      REQUIRE(probe.received_count == round && probe.sent_count == round && probe.failed == 0u);
    }
    REQUIRE(cnet_close(&client, outbound) == SALTS_OK);
    deadline = cmeta_monotonic_ms() + 9000u;
    while (!probe.terminal_count && cmeta_monotonic_ms() < deadline)
      REQUIRE(cnet_client_poll(&client, 1u, &events) == SALTS_OK);
    REQUIRE(probe.terminal_count == 1u && probe.failed == 0u &&
            probe.last_connection_state == CNET_CONNECTION_CLOSED);
    REQUIRE(cnet_client_poll(&client, 0u, &events) == SALTS_OK);
    REQUIRE(probe.terminal_count == 1u && probe.sent_count == rounds &&
            probe.received_count == rounds && probe.failed == 0u);
  }

cleanup:
  if (outgoing != NULL) mem_buffer_release(outgoing);
  if (initialized) {
    const int stop_status = cnet_client_stop(&client, 5000u);
    const int destroy_status = cnet_client_destroy(&client);
    if (stop_status != SALTS_OK || destroy_status != SALTS_OK ||
        probe.terminal_count != 1u) result = 1;
  }
  return result;
}


/*
 * Production CNet server against a separate Python ssl or GoTLCP
 * client. The server retains exactly one Salts::CNet native owner; Python
 * supplies ephemeral client credentials and pins TLS 1.2 or TLS 1.3.
 * Port handoff is a private test file to avoid any extra server/consumer app.
 */
/* Hold only a real NativeIO success after admitting the authenticated reply.
 * The peer sends nothing further until raw EOF. Route EOF first, then the
 * retained completion, so scheduling cannot hide the SEND/FAILED race. */
typedef struct tls_eof_race {
  native_io_backend backend;
  native_io_completion write;
  bool held;
  bool delayed_write;
  bool routed_eof;
} tls_eof_race;

static int tls_eof_race_progress(cnet_client *client, tls_eof_race *race,
                                 bool hold_write, size_t *events) {
  native_io_completion completions[8];
  size_t count = 0u;
  int status = cnet_client_advance_external(client, events);
  if (status != SALTS_OK) return status;
  status = native_io_backend_observe(&race->backend, completions, 8u, 1u, &count);
  if (status != SALTS_OK && status != SALTS_ETIMEDOUT) return status;
  int first_error = SALTS_OK;
  size_t held_index = SIZE_MAX;
  /* Observe the complete batch before routing: EOF may precede the already
   * successful write in the same batch. Hold that write in either order. */
  if (hold_write && !race->routed_eof) {
    for (size_t i = 0u; i < count; ++i) {
      if (completions[i].kind != NATIVE_IO_COMPLETION_OK) continue;
      if (race->held) { first_error = SALTS_EPROTO; continue; }
      race->write = completions[i];
      race->held = true;
      race->delayed_write = true;
      held_index = i;
    }
  }
  for (size_t i = 0u; i < count; ++i) {
    bool consumed = false;
    if (i == held_index) continue;
    if (completions[i].kind == NATIVE_IO_COMPLETION_EOF)
      fprintf(stderr, "TLS_EOF_ORDER eof=%u:%u endpoint=%u:%u\n",
          completions[i].request.slot, completions[i].request.generation,
          completions[i].endpoint.slot, completions[i].endpoint.generation);
    status = cnet_client_route_external_completion(client, &completions[i], &consumed, events);
    if ((status != SALTS_OK || !consumed) && first_error == SALTS_OK)
      first_error = status != SALTS_OK ? status : SALTS_EPROTO;
    if (completions[i].kind == NATIVE_IO_COMPLETION_EOF) race->routed_eof = true;
  }
  if (race->held && (race->routed_eof || !hold_write)) {
    bool consumed = false;
    fprintf(stderr, "TLS_EOF_ORDER write=%u:%u endpoint=%u:%u bytes=%zu eof_first=%u\n",
        race->write.request.slot, race->write.request.generation,
        race->write.endpoint.slot, race->write.endpoint.generation,
        race->write.bytes, (unsigned)race->routed_eof);
    status = cnet_client_route_external_completion(client, &race->write, &consumed, events);
    if (consumed) race->held = false;
    if ((status != SALTS_OK || !consumed) && first_error == SALTS_OK)
      first_error = status != SALTS_OK ? status : SALTS_EPROTO;
  }
  return first_error;
}

static int run_python_ssl_client(const char *port_path,
                                 const char *ca_file,
                                 const char *cert_file,
                                 const char *key_file,
                                 const char *protocol,
                                 const char *outcome,
                                 const char *expected_client_sha256) {
  const char *label = "production CNet <- independent secure stream peer";
  const bool tlcp = strcmp(protocol, "tlcp") == 0;
  const bool shangmi = strcmp(protocol, "shangmi13") == 0 ||
      strcmp(protocol, "shangmi13-mtls") == 0;
  const bool server_auth_only = tlcp || strcmp(protocol, "shangmi13") == 0;
  const char *expected_version = strcmp(protocol, "12") == 0
                                     ? "TLSv1.2" : tlcp ? "TLCPv1.1" : "TLSv1.3";
  const bool expect_idle_read_timeout = strcmp(outcome, "idle") == 0;
  const bool local_rotation = strncmp(outcome, "rotate", 6u) == 0;
  const bool peer_limit = strncmp(outcome, "limit", 5u) == 0;
  const bool peer_limit_failure = peer_limit && strstr(outcome, "fail") != NULL;
  const uint32_t rotation_limit = strcmp(outcome, "rotate1") == 0 ? 1u :
      strcmp(outcome, "rotate2") == 0 ? 2u :
      strcmp(outcome, "rotatemax") == 0 ? CNET_TLS_KEY_UPDATE_RECORD_LIMIT_MAX : 0u;
  const unsigned rounds = local_rotation ? 5u : peer_limit && !peer_limit_failure ? 2u : 1u;
  const bool expect_orderly_close = strcmp(outcome, "close") == 0 || local_rotation || (peer_limit && !peer_limit_failure);
  const bool expect_local_peer_close = strcmp(outcome, "localclose") == 0;
  const bool expect_final_send_close = strcmp(outcome, "sendclose") == 0;
  const bool expect_gated_receive = strcmp(outcome, "gated") == 0;
  const bool expect_incomplete_send = strcmp(outcome, "race-eof-pending") == 0;
  const bool expect_eof_race = strcmp(outcome, "race-eof") == 0 || expect_incomplete_send;
  const unsigned expected_sends = expect_incomplete_send ? 0u : 1u;
  const size_t response_size = expect_incomplete_send ? 65536u : 1u;
  const bool expect_invalid_close = peer_limit_failure || strcmp(outcome, "eof") == 0 ||
      strcmp(outcome, "keyupdate-fail") == 0 ||
      strcmp(outcome, "truncated") == 0 || strcmp(outcome, "badalert") == 0 ||
      strcmp(outcome, "fatal") == 0 || expect_eof_race;
  const bool should_verify =
      strcmp(outcome, "accept") == 0 || expect_idle_read_timeout ||
      expect_orderly_close || expect_local_peer_close ||
      expect_final_send_close || expect_gated_receive || expect_invalid_close;
  cnet_client server = {0};
  tls_eof_race race = {0};
  cnet_listener listener = {0};
  cnet_tls_server tls_server = {0};
  tls_probe probe = {0};
  cnet_client_config client_cfg = config();
  const cnet_listener_config listener_cfg = {
      client_cfg.backend, "127.0.0.1", 0u, 2u};
  const cnet_tls_cipher_suite peer_ciphers[] = {
      tlcp ? CRYPTO_TLS_CIPHER_TLCP_ECC_SM4_GCM_SM3 : shangmi ? CRYPTO_TLS_CIPHER_SM4_GCM_SM3 :
      strcmp(protocol, "12") == 0 ? CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256 : CRYPTO_TLS_CIPHER_AES_128_GCM_SHA256,
      CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256};
  const cnet_tls_signature_scheme sm2_signature = CRYPTO_TLS_SIGNATURE_SM2_SM3;
  const cnet_tls_signature_scheme rsa_signatures[] = {CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256,
      CRYPTO_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256};
  const cnet_tls_server_config tls_cfg = {
      .size = sizeof(cnet_tls_server_config),
      .cert_file = cert_file,
      .key_file = key_file,
      .ca_file = server_auth_only ? NULL : ca_file,
      .client_auth = server_auth_only ? CNET_TLS_CLIENT_AUTH_NONE : CNET_TLS_CLIENT_AUTH_REQUIRED,
      .security_profile = tlcp ? CNET_TLS_SECURITY_PROFILE_TLCP11 :
          shangmi ? CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13 : CNET_TLS_SECURITY_PROFILE_STANDARD,
      .signature_algorithms = tlcp || shangmi ? &sm2_signature : rsa_signatures,
      .signature_algorithm_count = tlcp || shangmi || strcmp(protocol, "12") == 0 ? 1u : 2u,
      .cipher_suites = peer_ciphers,
      .cipher_suite_count = !tlcp && !shangmi && strcmp(protocol, "12") == 0 ? 2u : 1u,
      .key_update_record_limit = rotation_limit,
      .peer_key_update_limit = peer_limit && strcmp(outcome, "limit-off") != 0 ? 2u : 0u,
      .minimum_version = !tlcp && !shangmi ? (strcmp(protocol, "12") == 0 ? 12 : 13) : 0,
      .maximum_version = !tlcp && !shangmi ? (strcmp(protocol, "12") == 0 ? 12 : 13) : 0};
  bool tls_live = false, server_live = false, listener_live = false;
  bool accepted = false, armed = false, response_sent = false;
  bool local_close_started = false;
  bool send_marker_published = false;
  bool gated_ready_published = false;
  unsigned responses_admitted = 0u;
  unsigned polls_after_receive_admission = 0u;
  mem_buffer_t *outgoing = NULL;
  FILE *port_file = NULL;
  uint16_t port = 0u;
  uint64_t deadline;
  size_t events = 0u;
  int result = 0;

  if (port_path == NULL || !*port_path || ca_file == NULL ||
      cert_file == NULL || key_file == NULL ||
      (strcmp(protocol, "12") != 0 && strcmp(protocol, "13") != 0 && !tlcp && !shangmi) ||
      (!should_verify && strcmp(outcome, "reject") != 0))
    return 2;
  probe.client = &server;
  probe.receive_limit = rounds;
  if (expect_incomplete_send) client_cfg.max_send_bytes = response_size;
  REQUIRE(tls_test_server_init(&tls_server, &tls_cfg) == SALTS_OK);
  tls_live = true;
  if (expect_eof_race) {
    const native_io_backend_config backend_cfg = {
        client_cfg.backend, client_cfg.connection_capacity * 2u,
        client_cfg.request_capacity, client_cfg.completion_batch_capacity};
    REQUIRE(native_io_backend_init(&race.backend, &backend_cfg) == SALTS_OK);
    REQUIRE(cnet_client_init_external(&server, &client_cfg, &race.backend) == SALTS_OK);
  } else REQUIRE(cnet_client_init(&server, &client_cfg) == SALTS_OK);
  server_live = true;
  REQUIRE(cnet_listener_init(&listener, &listener_cfg) == SALTS_OK);
  listener_live = true;
  REQUIRE(cnet_listener_port(&listener, &port) == SALTS_OK && port != 0u);
  /* Only the test driver knows this private path; publish after bind. */
  port_file = fopen(port_path, "wb");
  REQUIRE(port_file != NULL);
  REQUIRE(fprintf(port_file, "%u\n", (unsigned int)port) > 0);
  REQUIRE(fclose(port_file) == 0);
  port_file = NULL;

  deadline = cmeta_monotonic_ms() + 15000u;
  while (cmeta_monotonic_ms() < deadline) {
    int ready = 0;
    if (!accepted) {
      REQUIRE(cnet_listener_wait(&listener, 0u, &ready) == SALTS_OK);
      if (ready) {
        const cnet_observer observer = {
            state_callback, receive_callback, &probe, send_callback};
        REQUIRE(cnet_listener_accept_tls(
            &listener, &server, &tls_server, &observer,
            &probe.connection) == SALTS_OK);
        accepted = true;
        if (getenv("SALTS_TEST_TLS_ALT_CERT")) {
          REQUIRE(cnet_tls_server_destroy(&tls_server) == SALTS_OK);
          tls_live = false; /* Accepted stream retains the selected identity set. */
        }
      }
    }
    REQUIRE((expect_eof_race
        ? tls_eof_race_progress(&server, &race, response_sent, &events)
        : cnet_client_poll(&server, 1u, &events)) == SALTS_OK);
    if (!should_verify && probe.terminal_count) break;
    if (should_verify && probe.connected_count && !armed) {
      char fingerprint[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY] = {0};
      REQUIRE(probe.connected_count == 1u && probe.failed == 0u);
      REQUIRE(probe.tls_version_status == SALTS_OK);
      REQUIRE(strcmp(probe.tls_version, expected_version) == 0);
      REQUIRE(probe.tls_cipher_status == SALTS_OK);
      REQUIRE(probe.tls_cipher[0] != '\0');
      if (shangmi) REQUIRE(strcmp(probe.tls_cipher, "TLS_SM4_GCM_SM3") == 0);
      if (server_auth_only) {
        REQUIRE(strcmp(probe.tls_cipher, tlcp ? "TLS_ECC_SM4_GCM_SM3" : "TLS_SM4_GCM_SM3") == 0);
        REQUIRE(cnet_tls_peer_certificate_sha256(
            &server, probe.connection, fingerprint) == SALTS_ENOENT);
      } else {
        REQUIRE(cnet_tls_peer_certificate_sha256(
          &server, probe.connection, fingerprint) == SALTS_OK);
        REQUIRE(strlen(fingerprint) == 64u);
        REQUIRE(expected_client_sha256 != NULL &&
              strlen(expected_client_sha256) == 64u &&
              strcmp(fingerprint, expected_client_sha256) == 0);
      }
      REQUIRE(cnet_receive(&server, probe.connection, 1u) == SALTS_OK);
      armed = true;
    }
    if (expect_gated_receive && armed && !gated_ready_published) {
      /* The next poll has processed the receive command on the production
       * CNet Owner before the independent peer sends its first app record.
       * This specifically tests the already-armed NativeIO TLS_READ path. */
      ++polls_after_receive_admission;
      if (polls_after_receive_admission >= 2u) {
        char ready_path[1024];
        FILE *ready_marker;
        const int name_size =
            snprintf(ready_path, sizeof(ready_path), "%s.ready", port_path);
        REQUIRE(name_size > 0 && (size_t)name_size < sizeof(ready_path));
        ready_marker = fopen(ready_path, "wb");
        REQUIRE(ready_marker != NULL);
        REQUIRE(fputs("ready\\n", ready_marker) >= 0);
        REQUIRE(fclose(ready_marker) == 0);
        gated_ready_published = true;
      }
    }
    if (should_verify && !expect_idle_read_timeout &&
        probe.received_count > responses_admitted && probe.sent_count == responses_admitted) {
      REQUIRE(probe.received_count == responses_admitted + 1u && probe.received_byte == 0x46u);
      REQUIRE(probe.failed == 0u);
      outgoing = mem_get_buffer(mem_global(), response_size);
      REQUIRE(outgoing != NULL);
      memset(mem_buffer_data(outgoing), 0x47, response_size);
      mem_set_used(outgoing, response_size);
      /* The retained FINAL send must use the same authenticated reciprocal
       * shutdown as explicit cnet_close. Its public send-success callback
       * proves data completion, NOT that TLS close_notify was exchanged. */
      REQUIRE((expect_final_send_close
                   ? cnet_send_buffer_and_close(&server, probe.connection, outgoing)
                   : cnet_send_buffer(&server, probe.connection, outgoing)) == SALTS_OK);
      mem_buffer_release(outgoing);
      outgoing = NULL;
      response_sent = true;
      ++responses_admitted;
      if (responses_admitted < rounds)
        REQUIRE(cnet_receive(&server, probe.connection, 1u) == SALTS_OK);
    }
    if (((expect_invalid_close && !expect_eof_race) || strcmp(outcome, "accept") == 0) &&
        response_sent && probe.sent_count && !send_marker_published) {
      /*
       * Isolate authenticated-reply completion from the separate
       * post-authenticated invalid-close gate. An independent Python peer
       * must not inject EOF/bad alert until production CNet has actually
       * published the SEND event for G; ciphertext reception alone is not
       * that guarantee. The negative case still requires a real FAILED
       * terminal after the peer's invalid close.
       */
      char send_ready_path[1024];
      FILE *send_ready;
      int name_bytes;
      REQUIRE(probe.failed == 0u && probe.sent_count == 1u);
      name_bytes = snprintf(send_ready_path, sizeof(send_ready_path),
                            "%s.sent", port_path);
      REQUIRE(name_bytes > 0 && (size_t)name_bytes < sizeof(send_ready_path));
      send_ready = fopen(send_ready_path, "wb");
      REQUIRE(send_ready != NULL);
      REQUIRE(fputs("sent\\n", send_ready) >= 0);
      REQUIRE(fclose(send_ready) == 0);
      send_marker_published = true;
    }
    if (expect_local_peer_close && response_sent &&
        probe.sent_count && !local_close_started) {
      /* Native application-initiated shutdown can race the Python peer's
       * close_notify after it receives the authenticated response G.
       * At this point CNet can also own a background NativeIO TLS_READ.
       * Do not release that lease or its buffers until the real terminal. */
      char close_ready_path[1024];
      FILE *close_ready;
      int close_name_bytes;
      REQUIRE(probe.failed == 0u && probe.connected_count == 1u);
      REQUIRE(cnet_close(&server, probe.connection) == SALTS_OK);
      local_close_started = true;
      /* The Python peer must not win the race *before* native CNet has
       * accepted local close. It still sends its reciprocal close_notify
       * while NativeIO cancellation and encrypted shutdown are pending. */
      close_name_bytes =
          snprintf(close_ready_path, sizeof(close_ready_path),
                   "%s.localclose", port_path);
      REQUIRE(close_name_bytes > 0 &&
              (size_t)close_name_bytes < sizeof(close_ready_path));
      close_ready = fopen(close_ready_path, "wb");
      REQUIRE(close_ready != NULL);
      REQUIRE(fputs("accepted\n", close_ready) >= 0);
      REQUIRE(fclose(close_ready) == 0);
    }
    /* A successful app echo cannot substitute for reciprocal close_notify
     * or for exact NativeIO request retirement. */
    if (should_verify && !expect_orderly_close && !expect_local_peer_close &&
        !expect_final_send_close && !expect_invalid_close &&
        response_sent && probe.sent_count) break;
    if (probe.terminal_count) break;
  }

  REQUIRE(accepted);
  if (probe.failed || probe.connected_count != 1u) {
    fprintf(stderr, "CNET_TLS_TERMINAL protocol=%s expected=%s connected=%u "
                    "terminal=%u failed=%u status=%d stage=%s received=%u sent=%u\n",
            protocol, outcome, probe.connected_count, probe.terminal_count,
            probe.failed, probe.last_error_status, probe.failure_stage,
            probe.received_count, probe.sent_count);
  }
  if (expect_invalid_close) {
    REQUIRE(!expect_eof_race || (race.delayed_write && race.routed_eof && !race.held));
    REQUIRE(armed && probe.connected_count == 1u);
    REQUIRE(probe.received_count == 1u && probe.received_byte == 0x46u);
    REQUIRE(response_sent && probe.sent_count == expected_sends);
    REQUIRE(probe.terminal_count == 1u && probe.failed == 1u);
    REQUIRE(probe.sends_at_terminal == expected_sends);
    REQUIRE(probe.last_connection_state == CNET_CONNECTION_FAILED);
    REQUIRE(probe.last_error_status == SALTS_ECONNABORTED ||
            probe.last_error_status == SALTS_EPROTO);
    REQUIRE(strcmp(probe.failure_stage, "read") == 0);
    if (peer_limit_failure) REQUIRE(probe.last_error_status == SALTS_EPROTO);
    if (expect_eof_race) {
      bool consumed = true;
      REQUIRE(cnet_client_route_external_completion(
          &server, &race.write, &consumed, &events) == SALTS_OK);
      REQUIRE(!consumed); /* The old native generation cannot send twice. */
    }
    for (unsigned index = 0u; index < 2u; ++index) {
      REQUIRE((expect_eof_race
          ? tls_eof_race_progress(&server, &race, false, &events)
          : cnet_client_poll(&server, 0u, &events)) == SALTS_OK);
      REQUIRE(probe.terminal_count == 1u);
      REQUIRE(probe.received_count == 1u && probe.sent_count == expected_sends);
    }
  } else if (expect_orderly_close || expect_local_peer_close || expect_final_send_close) {
    /* Python ssl.unwrap() requires a real authenticated reciprocal
     * close_notify for both explicit cnet_close and retained final send.
     * TCP EOF, SEND callback or local ciphertext flush are insufficient.
     * Complete the NativeIO TLS_READ lease and publish exactly one CLOSED. */
    REQUIRE(!expect_local_peer_close || local_close_started);
    REQUIRE(armed && probe.connected_count == 1u);
    REQUIRE(probe.received_count == rounds && probe.received_byte == 0x46u);
    REQUIRE(response_sent && probe.sent_count == rounds);
    REQUIRE(probe.terminal_count == 1u && probe.failed == 0u);
    REQUIRE(probe.last_connection_state == CNET_CONNECTION_CLOSED);
    /* Drain one more zero-wait owner cycle. A cancel-vs-success native
     * completion must not publish a second callback after CLOSED. */
    for (unsigned index = 0u; index < 2u; ++index) {
      REQUIRE(cnet_client_poll(&server, 0u, &events) == SALTS_OK);
      REQUIRE(probe.terminal_count == 1u);
      REQUIRE(probe.received_count == rounds && probe.sent_count == rounds);
    }
  } else if (expect_idle_read_timeout) {
    /* A real, authenticated idle peer keeps TCP open while CNet owns a
     * post-handshake TLS_READ. Never accept a late socket EOF or handshake
     * failure as proof of READ timeout; all public identity checks above
     * must already have passed before receive demand was armed. */
    REQUIRE(armed && probe.connected_count == 1u);
    REQUIRE(probe.terminal_count == 1u && probe.failed == 1u);
    REQUIRE(probe.last_error_status == SALTS_ETIMEDOUT);
    REQUIRE(strcmp(probe.failure_stage, "read") == 0);
    REQUIRE(probe.received_count == 0u && probe.sent_count == 0u);
    REQUIRE(!response_sent);
  } else if (should_verify) {
    if (expect_gated_receive) REQUIRE(gated_ready_published);
    if (probe.connected_count != 1u || probe.failed != 0u) {
      /* Log only stable public CNet state on a real TLS/mTLS failure.
       * A peer TLS 1.3 timeout must not hide whether NativeIO accepted
       * TCP, published HANDSHAKING or emitted a terminal callback. */
      fprintf(stderr,
              "CNET_MTLS_PHASE protocol=%s expected=%s accepted=%u "
              "handshaking=%u connected=%u terminal=%u failed=%u "
              "last_state=%d status=%d native_status=%d stage=%s "
              "polled_events=%zu armed=%u reply_sent=%u "
              "plaintext_events=%u send_events=%u\n",
              protocol, outcome, accepted ? 1u : 0u,
              probe.handshaking_count, probe.connected_count,
              probe.terminal_count, probe.failed,
              probe.last_connection_state, probe.last_error_status,
              probe.last_native_status,
              probe.failure_stage[0] != '\0' ? probe.failure_stage : "none",
              events, armed ? 1u : 0u, response_sent ? 1u : 0u,
              probe.received_count, probe.sent_count);
    }
    REQUIRE(probe.connected_count == 1u && probe.failed == 0u);
    REQUIRE(armed && response_sent && probe.sent_count == 1u);
    REQUIRE(probe.received_count == 1u && probe.received_byte == 0x46u);
  } else {
    /* A bad peer may never publish an authenticated connection or plaintext.
     * This must be a TLS handshake failure, not a timeout or socket refusal. */
    REQUIRE(probe.terminal_count == 1u);
    REQUIRE(probe.failed != 0u && probe.connected_count == 0u);
    REQUIRE(probe.last_error_status != SALTS_ETIMEDOUT);
    REQUIRE(probe.sent_count == 0u && probe.received_count == 0u);
    REQUIRE(strcmp(probe.failure_stage, "handshake") == 0);
  }

cleanup:
  if (outgoing != NULL) mem_buffer_release(outgoing);
  if (port_file != NULL) (void)fclose(port_file);
  if (accepted && !probe.terminal_count && server_live)
    (void)cnet_close(&server, probe.connection);
  if (listener_live) {
    (void)cnet_listener_close(&listener);
    (void)cnet_listener_destroy(&listener);
  }
  if (server_live) {
    int stop_status;
    if (expect_eof_race) {
      const uint64_t stop_deadline = cmeta_monotonic_ms() + 5000u;
      do {
        (void)tls_eof_race_progress(&server, &race, false, &events);
        stop_status = cnet_client_stop_external(&server);
      } while (stop_status == SALTS_EBUSY && cmeta_monotonic_ms() < stop_deadline);
    } else stop_status = cnet_client_stop(&server, 5000u);
    const int destroy_status = cnet_client_destroy(&server);
    if (stop_status != SALTS_OK || destroy_status != SALTS_OK) result = 1;
  }
  if (race.backend.impl != NULL) {
    if (native_io_backend_close(&race.backend) != SALTS_OK ||
        native_io_backend_destroy(&race.backend) != SALTS_OK) result = 1;
  }
  if (tls_live) (void)cnet_tls_server_destroy(&tls_server);
  if (result == 0)
    printf("PASS production NativeIO CNet server / TLS%s / %s\n",
           protocol, outcome);
  return result;
}

static int reject_tlcp_identity(const char *cert_file, const char *key_file) {
  const char *label = "TLCP rejects invalid local dual identity";
  cnet_tls_server server = {0};
  const cnet_tls_server_config cfg = {
      .size = sizeof(cfg), .cert_file = cert_file, .key_file = key_file,
      .client_auth = CNET_TLS_CLIENT_AUTH_NONE,
      .security_profile = CNET_TLS_SECURITY_PROFILE_TLCP11};
  int result = 0;
  REQUIRE(tls_test_server_init(&server, &cfg) == SALTS_EIO);
  REQUIRE(server.impl == NULL);
cleanup:
  (void)cnet_tls_server_destroy(&server);
  return result;
}

#include "tls_cipher_policy_cases.h"
#include "tls_signature_policy_cases.h"
#include "tls_server_identity_cases.h"
#include "tls_peer_policy_cases.h"
#include "tls_sm2_crl_policy_cases.h"

/* Independent Go envelopes exercise both context roles without opening sockets.
 * Inputs are erased on return; any admitted failure must publish no context. */
static int run_encrypted_credential_admission(const char *ca, const char *cert,
    const char *key, bool accept, int expected) {
  const char *label = "independent encrypted PKCS8 admission";
  tls_test_memory *m = calloc(1u, sizeof(*m));
  cnet_tls_client client = {0};
  cnet_tls_server server = {0};
  int result = 0;
  REQUIRE(m != NULL);
  REQUIRE(tls_test_prepare(m, ca, cert, key, false) == SALTS_OK);
  cnet_tls_client_config cc = {.size = sizeof(cc), .ca_data = &m->ca, .credentials = &m->credentials};
  cnet_tls_server_config sc = {.size = sizeof(sc), .credentials = &m->credentials};
  REQUIRE(cnet_tls_client_init(&client, &cc) == expected);
  REQUIRE(cnet_tls_server_init(&server, &sc) == expected);
  REQUIRE((client.impl != NULL) == accept && (server.impl != NULL) == accept);
cleanup:
  tls_test_memory_free(m);
  if (cnet_tls_client_destroy(&client) != SALTS_OK) result = 1;
  if (cnet_tls_server_destroy(&server) != SALTS_OK) result = 1;
  return result;
}

static int saltscore_original_entry_test_cnet_tls_ca_san_c(int argc, char **argv) {
  if (argc == 6 && strcmp(argv[1], "--encrypted-credential-admission") == 0) {
    const bool accept = strcmp(argv[5], "accept") == 0;
    if (!accept && strcmp(argv[5], "reject") != 0 && strcmp(argv[5], "range") != 0) return 2;
    return run_encrypted_credential_admission(argv[2], argv[3], argv[4], accept,
        accept ? SALTS_OK : strcmp(argv[5], "range") == 0 ? SALTS_ERANGE : SALTS_EIO);
  }
  if (argc == 10 && strcmp(argv[1], "--tls-client-identities") == 0) {
    if (strcmp(argv[8], "accept") != 0 && strcmp(argv[8], "reject") != 0) return 2;
    return run_python_ssl_server(argv[2], argv[3], argv[4], argv[5],
        strcmp(argv[8], "accept") == 0, argv[6], argv[7], argv[9], NULL);
  }
  if (argc == 9 && strcmp(argv[1], "--tlcp-crl-policy") == 0)
    return run_cnet_tlcp_crl_policy_case(argv);
  if (argc == 14 && strcmp(argv[1], "--shangmi-crl-policy") == 0)
    return run_cnet_crl_policy_case(argv);
  if (argc == 9 && strcmp(argv[1], "--shangmi-required-server") == 0) {
    if (strcmp(argv[7], "accept") != 0 && strcmp(argv[7], "reject") != 0) return 2;
    return run_python_ssl_server(argv[2], "shangmi13", argv[3], argv[4],
        strcmp(argv[7], "accept") == 0, argv[5], argv[6], argv[8], NULL);
  }
  if (argc == 8 && strcmp(argv[1], "--shangmi-required-client") == 0)
    return run_python_ssl_client(argv[2], argv[3], argv[4], argv[5], "shangmi13-mtls", argv[6], argv[7]);
  if ((argc == 12 && strcmp(argv[1], "--shangmi-mtls") == 0) ||
      (argc == 16 && (strcmp(argv[1], "--depth-mtls") == 0 || strcmp(argv[1], "--signature-mtls") == 0))) {
    const bool success = strcmp(argv[8], "accept") == 0;
    const bool policy_client = strcmp(argv[8], "reject-policy-client") == 0;
    const bool policy_server = strcmp(argv[8], "reject-policy-server") == 0;
    const bool server_rejection = strcmp(argv[8], "reject-server") == 0 || policy_server;
    if ((!success && !server_rejection && !policy_client && strcmp(argv[8], "reject-client") != 0) ||
        ((strcmp(argv[6], "-") == 0) != (strcmp(argv[7], "-") == 0))) return 2;
    tls_case_options mtls = {
        .label = "production CNet ShangMi REQUIRED-mTLS",
        .ca_file = argv[2], .server_ca_file = argv[3],
        .server_cert_file = argv[4], .server_key_file = argv[5],
        .client_cert_file = strcmp(argv[6], "-") == 0 ? NULL : argv[6],
        .client_key_file = strcmp(argv[7], "-") == 0 ? NULL : argv[7],
        .verified_hostname = "localhost", .expect_success = success,
        .expect_server_rejection = server_rejection,
        .security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13,
        .expected_server_fingerprint = argv[9], .expected_client_fingerprint = argv[10],
        .expected_server_binding = argv[11]};
    if (argc == 16) {
      if ((strcmp(argv[12], "0") && strcmp(argv[12], "1")) ||
          (strcmp(argv[13], "0") && strcmp(argv[13], "12") && strcmp(argv[13], "13")) ||
          strlen(argv[14]) != 1u || argv[14][0] < '0' || argv[14][0] > '5' ||
          strlen(argv[15]) != 1u || argv[15][0] < '0' || argv[15][0] > '5') return 2;
      mtls.security_profile = (cnet_tls_security_profile)(argv[12][0] - '0');
      mtls.client_minimum = mtls.client_maximum = mtls.server_minimum = mtls.server_maximum =
          (cnet_tls_protocol_version)atoi(argv[13]);
      if (strcmp(argv[1], "--signature-mtls") == 0) {
        const cnet_tls_signature_scheme ecdsa[] = {CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256};
        const cnet_tls_signature_scheme rsa[] = {CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256,
            CRYPTO_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256};
        const cnet_tls_signature_scheme sm2[] = {CRYPTO_TLS_SIGNATURE_SM2_SM3};
        const cnet_tls_signature_scheme ecdsa_ca[] = {CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
            CRYPTO_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384};
        unsigned client_mode = (unsigned)(argv[14][0] - '0'), server_mode = (unsigned)(argv[15][0] - '0');
        if (client_mode > 4u || server_mode > 4u) return 2;
        mtls.client_signatures = client_mode == 1u ? ecdsa : client_mode == 2u ? rsa : client_mode == 3u ? sm2 : client_mode == 4u ? ecdsa_ca : NULL;
        mtls.server_signatures = server_mode == 1u ? ecdsa : server_mode == 2u ? rsa : server_mode == 3u ? sm2 : server_mode == 4u ? ecdsa_ca : NULL;
        mtls.client_signature_count = client_mode ? (client_mode == 4u || (client_mode == 2u && mtls.client_maximum != 12) ? 2u : 1u) : 0u;
        mtls.server_signature_count = server_mode ? (server_mode == 4u || (server_mode == 2u && mtls.server_maximum != 12) ? 2u : 1u) : 0u;
        mtls.release_tls_context_early = true;
        if (mtls.security_profile == CNET_TLS_SECURITY_PROFILE_STANDARD) mtls.expected_server_binding = NULL;
        return run_case(&mtls);
      }
      mtls.client_depth = (uint32_t)(argv[14][0] - '0');
      mtls.server_depth = (uint32_t)(argv[15][0] - '0');
      mtls.release_tls_context_early = true;
      mtls.expected_failure = success ? CRYPTO_TLS_FAILURE_NONE : CRYPTO_TLS_FAILURE_DEPTH;
      if (mtls.security_profile == CNET_TLS_SECURITY_PROFILE_STANDARD) mtls.expected_server_binding = NULL;
      return run_case(&mtls);
    }
    return success || policy_client || policy_server
        ? run_mutual_peer_policy_case(&mtls, policy_client, policy_server) : run_case(&mtls);
  }
  if (argc == 6 && strcmp(argv[1], "--shangmi-client") == 0)
    return run_python_ssl_client(argv[2], "-", argv[3], argv[4], "shangmi13", argv[5], "-");
  if (argc == 4 && strcmp(argv[1], "--reject-tlcp-identity") == 0)
    return reject_tlcp_identity(argv[2], argv[3]);
  if (argc == 6 && strcmp(argv[1], "--gotlcp-client") == 0)
    return run_python_ssl_client(argv[2], "-", argv[3], argv[4], "tlcp", argv[5], "-");
  if (argc == 9 && strcmp(argv[1], "--python-ssl-client") == 0)
    return run_python_ssl_client(
        argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]);
  if (argc == 5 && strcmp(argv[1], "--external-san") == 0)
    return run_python_ssl_server(
        argv[2], argv[3], argv[4], CORE_TLS_TEST_EXTERNAL_CA,
        strcmp(argv[4], "localhost") == 0, NULL, NULL, NULL, NULL);
  if (argc == 7 && strcmp(argv[1], "--external-ip-san") == 0) {
    if (strcmp(argv[6], "accept") != 0 && strcmp(argv[6], "reject") != 0)
      return 2;
    return run_python_ssl_server(
        argv[2], argv[3], argv[4], argv[5],
        strcmp(argv[6], "accept") == 0, NULL, NULL, NULL, NULL);
  }
  int result;
  if (argc == 8 && strcmp(argv[1], "--required-mtls") == 0) {
    const bool expect_success = strcmp(argv[7], "accept") == 0;
    const bool expect_rejection = strcmp(argv[7], "reject") == 0;
    if (!expect_success && !expect_rejection) return 2;
    if ((strcmp(argv[5], "-") == 0) != (strcmp(argv[6], "-") == 0))
      return 2;
    const cnet_tls_signature_scheme rsa_signatures[] = {CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256,
        CRYPTO_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256};
    const tls_case_options required_mtls = {
        .label = "production CNet REQUIRED-mTLS",
        .client_signatures = rsa_signatures, .server_signatures = rsa_signatures,
        .client_signature_count = 2u, .server_signature_count = 2u,
        .ca_file = argv[2],
        .verified_hostname = "localhost",
        .expect_success = expect_success,
        .expect_server_rejection = expect_rejection,
        .server_ca_file = argv[2],
        .server_cert_file = argv[3],
        .server_key_file = argv[4],
        .client_cert_file = strcmp(argv[5], "-") == 0 ? NULL : argv[5],
        .client_key_file = strcmp(argv[6], "-") == 0 ? NULL : argv[6]};
    return run_case(&required_mtls);
  }
  if (argc != 1) return 2;
  result = run_client_identity_cases();
  if (result != 0) return result;
  result = run_server_identity_cases();
  if (result) return result;
  result = run_signature_policy_cases();
  if (result) return result;
  result = run_cipher_policy_cases();
  if (result) return result;
  result = run_peer_policy_cases();
  if (result) return result;
  const tls_case_options trusted = {
      .label = "trusted CA + correct DNS",
      .ca_file = CORE_TLS_TEST_P384_CA,
      .verified_hostname = "localhost",
      .expect_success = true};
  result = run_case(&trusted);
  if (result) return result;
  for (unsigned client_mode = 0u; client_mode < 3u; ++client_mode) {
    for (unsigned server_mode = 0u; server_mode < 3u; ++server_mode) {
      const bool mismatch = client_mode && server_mode && client_mode != server_mode;
      tls_case_options versions = trusted;
      versions.label = "configured TLS protocol intersection";
      versions.client_minimum = client_mode == 2u ? 13 : 0;
      versions.client_maximum = client_mode == 1u ? 12 : 0;
      versions.server_minimum = server_mode == 2u ? 13 : 0;
      versions.server_maximum = server_mode == 1u ? 12 : 0;
      versions.expect_success = !mismatch;
      versions.expected_version = client_mode == 1u || server_mode == 1u ? "TLSv1.2" : "TLSv1.3";
      result = run_case(&versions);
      if (result) return result;
    }
  }
  const tls_case_options wrong_ca = {
      .label = "wrong trusted root",
      .expected_failure = CRYPTO_TLS_FAILURE_TRUST_ANCHOR,
      .ca_file = CORE_TLS_TEST_P384_WRONG_CA,
      .verified_hostname = "localhost"};
  result = run_case(&wrong_ca);
  if (result) return result;
  const tls_case_options wrong_san = {
      .label = "wrong DNS SAN",
      /* Unmatched SNI is rejected before a certificate. Depending on which
       * terminal arrives first, the client observes peer alert or TCP close. */
      .ca_file = CORE_TLS_TEST_P384_CA,
      .verified_hostname = "wrong.example"};
  result = run_case(&wrong_san);
  if (result) return result;
  const tls_case_options wrong_ip = {
      .label = "wrong IP SAN",
      .expected_failure = CRYPTO_TLS_FAILURE_IDENTITY,
      .ca_file = CORE_TLS_TEST_P384_CA,
      .verified_hostname = "127.0.0.2"};
  return run_case(&wrong_ip);
}

/* Production TLS policy comparison. See docs/CNET-TLS-BENCHMARK.md for the
 * ownership, offering, timing and metric scopes. No direct Crypto linkage. */
enum { TLS_BENCH_BYTES = 32768, TLS_BENCH_WRITES = 2048 };
typedef struct tls_bench_storage { size_t allocated, released, receives; } tls_bench_storage;
typedef struct tls_bench_fixture tls_bench_fixture;
typedef struct tls_bench_end {
  cnet_client client;
  native_io_backend backend;
  tls_probe state;
  tls_bench_storage storage;
  tls_bench_fixture *fixture;
} tls_bench_end;
struct tls_bench_fixture {
  tls_mixed_lane *mixed; /* Borrowed parent workload; alive through disposal. */
  tls_bench_end ends[2];
  cnet_listener listener;
  cnet_tls_server context;
  mem_buffer_t *source;
  size_t window, offered, completed, received, receive_offset, target, calls;
  size_t receive_credits;
  uint64_t starts[TLS_BENCH_WRITES], latency[TLS_BENCH_WRITES];
};
typedef struct tls_bench_result {
  uint64_t elapsed, cpu, p50, p95, p99, submissions;
  size_t bytes, rejected, peak_bytes, peak_backing, allocations, receives, calls;
} tls_bench_result;

static size_t tls_bench_size(size_t index) { return index % 8u == 0u ? 1u : TLS_BENCH_BYTES; }
static void *tls_bench_allocate(void *user, size_t bytes) {
  void *out = malloc(bytes);
  if (out != NULL) ++((tls_bench_storage *)user)->allocated;
  return out;
}
static void tls_bench_free(void *user, void *memory, size_t bytes) {
  (void)bytes;
  ++((tls_bench_storage *)user)->released;
  free(memory);
}
static int tls_bench_buffer(void *user, size_t bytes, mem_buffer_t **out) {
  *out = mem_get_buffer(mem_global(), bytes);
  if (*out == NULL) return SALTS_ENOMEM;
  ++((tls_bench_storage *)user)->receives;
  return SALTS_OK;
}
static void tls_bench_state(void *user, cnet_connection connection,
                            cnet_connection_state state, const cnet_error *error) {
  state_callback(&((tls_bench_end *)user)->state, connection, state, error);
}
static void tls_bench_sent(void *user, cnet_connection connection, size_t bytes) {
  tls_bench_end *end = user;
  tls_bench_fixture *f = end->fixture;
  (void)connection;
  if (f->mixed) {
    if (end->state.terminal_count) f->mixed->owner->error = SALTS_EPROTO;
    else { tls_mixed_sent(f->mixed, end == &f->ends[0] ? 0u : 1u, bytes); ++end->state.sent_count; }
    return;
  }
  if (end != &f->ends[0] || end->state.terminal_count != 0u ||
      f->completed >= f->offered || bytes != tls_bench_size(f->completed)) {
    ++end->state.failed;
    return;
  }
  f->latency[f->completed] = cmeta_hrtime() - f->starts[f->completed];
  ++f->completed;
  ++end->state.sent_count;
}
static void tls_bench_received(void *user, cnet_connection connection,
                               const cnet_receive_view *view) {
  tls_bench_end *end = user;
  tls_bench_fixture *f = end->fixture;
  (void)connection;
  if (f->mixed) {
    if (!view || view->kind != CNET_MESSAGE_BYTES || end->state.terminal_count)
      f->mixed->owner->error = SALTS_EPROTO;
    else {
      tls_mixed_received(f->mixed, end == &f->ends[0] ? 0u : 1u, view->data, view->size);
      ++end->state.received_count;
    }
    return;
  }
  if (end != &f->ends[1] || end->state.terminal_count != 0u || view == NULL ||
      view->kind != CNET_MESSAGE_BYTES || view->data == NULL || view->size == 0u) {
    ++end->state.failed;
    return;
  }
  const unsigned char *bytes = view->data;
  for (size_t i = 0u; i < view->size; ++i) {
    if (f->received >= f->target || bytes[i] !=
        (unsigned char)((0x5au + f->receive_offset * 29u) & 0xffu)) {
      ++end->state.failed;
      return;
    }
    if (++f->receive_offset == tls_bench_size(f->received)) {
      ++f->received;
      f->receive_offset = 0u;
    }
  }
  ++end->state.received_count;
}
static int tls_bench_admit(void *user, const cnet_send_usage *total,
                            const cnet_send_usage *connection, size_t bytes, size_t backing) {
  tls_bench_fixture *f = user;
  const size_t logical = f->window * TLS_BENCH_BYTES;
  const size_t retained = f->window * mem_buffer_capacity(f->source);
  ++f->calls;
  return total->operations < f->window && connection->operations < f->window &&
      total->bytes <= logical && bytes <= logical - total->bytes &&
      total->backing_bytes <= retained && backing <= retained - total->backing_bytes
      ? SALTS_OK : SALTS_ENOBUFS;
}
static int tls_bench_mixed_admit(void *user, const cnet_send_usage *total,
                                 const cnet_send_usage *connection, size_t bytes, size_t backing) {
  tls_bench_end *end = user;
  tls_bench_fixture *f = end->fixture;
  const size_t index = end == &f->ends[0] ? 0u : 1u;
  mem_buffer_t *source = f->mixed->source[index];
  const size_t logical = f->window * mem_buffer_used(source);
  const size_t retained = f->window * mem_buffer_capacity(source);
  ++f->calls;
  return total->operations < f->window && connection->operations < f->window &&
      total->bytes <= logical && bytes <= logical - total->bytes &&
      total->backing_bytes <= retained && backing <= retained - total->backing_bytes
      ? SALTS_OK : SALTS_ENOBUFS;
}
static int tls_bench_cpu(uint64_t *out) {
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
static int tls_bench_compare(const void *a, const void *b) {
  const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}
static int tls_bench_progress(tls_bench_fixture *f) {
  int first = SALTS_OK;
  for (size_t e = 0u; e < 2u; ++e) {
    tls_bench_end *end = &f->ends[e];
    if (end->client.impl == NULL) continue;
    native_io_completion completions[4];
    size_t events = 0u, count = 0u;
    int status = cnet_client_advance_external(&end->client, &events);
    if (status != SALTS_OK && first == SALTS_OK) first = status;
    status = native_io_backend_observe(&end->backend, completions, 4u, 0u, &count);
    if (status != SALTS_OK && status != SALTS_ETIMEDOUT && first == SALTS_OK) first = status;
    /* Route the entire observed batch even if an earlier completion fails. */
    for (size_t i = 0u; i < count; ++i) {
      bool consumed = false;
      status = cnet_client_route_external_completion(&end->client, &completions[i], &consumed, &events);
      if ((status != SALTS_OK || !consumed) && first == SALTS_OK)
        first = status != SALTS_OK ? status : SALTS_EPROTO;
    }
  }
  return first;
}
static int tls_bench_transfer(tls_bench_fixture *f, size_t operations, tls_bench_result *out) {
  native_io_backend_stats before[2], after[2];
  size_t allocations = 0u, receives = 0u;
  const size_t calls = f->calls;
  uint64_t cpu_start, cpu_end;
  if (operations == 0u || operations > TLS_BENCH_WRITES || operations % 8u != 0u) return SALTS_EINVAL;
  *out = (tls_bench_result){0};
  f->offered = f->completed = f->received = f->receive_offset = 0u;
  f->target = operations;
  for (size_t e = 0u; e < 2u; ++e) {
    if (!native_io_backend_get_stats(&f->ends[e].backend, &before[e])) return SALTS_EIO;
    allocations += f->ends[e].storage.allocated;
    receives += f->ends[e].storage.receives;
  }
  if (tls_bench_cpu(&cpu_start) != SALTS_OK) return SALTS_EIO;
  const uint64_t start = cmeta_hrtime(), deadline = start + UINT64_C(20000000000);
  while ((f->completed != operations || f->received != operations) && cmeta_hrtime() < deadline) {
    while (f->offered < operations && f->offered - f->completed < f->window) {
      mem_slice_t slice = mem_slice(f->source, 0u, tls_bench_size(f->offered));
      f->starts[f->offered] = cmeta_hrtime();
      const int status = cnet_send_slice(&f->ends[0].client, f->ends[0].state.connection, &slice);
      mem_slice_release(&slice);
      if (status != SALTS_OK) return status;
      ++f->offered;
    }
    cnet_send_usage usage;
    if (cnet_client_send_usage(&f->ends[0].client, f->ends[0].state.connection, &usage) != SALTS_OK ||
        usage.operations != f->offered - f->completed ||
        mem_buffer_ref_count(f->source) != 1u + usage.operations) return SALTS_EPROTO;
    if (usage.bytes > out->peak_bytes) out->peak_bytes = usage.bytes;
    if (usage.backing_bytes > out->peak_backing) out->peak_backing = usage.backing_bytes;
    if (f->window == 8u && f->offered < operations && usage.operations == f->window) {
      const unsigned references = mem_buffer_ref_count(f->source);
      mem_slice_t slice = mem_slice(f->source, 0u, tls_bench_size(f->offered));
      const int status = cnet_send_slice(&f->ends[0].client, f->ends[0].state.connection, &slice);
      mem_slice_release(&slice);
      if (status != SALTS_ENOBUFS || mem_buffer_ref_count(f->source) != references) return SALTS_EPROTO;
      ++out->rejected;
    }
    /* Keep at most one unconsumed callback credit, across phase boundaries. */
    if (f->receive_credits == f->ends[1].state.received_count) {
      if (cnet_receive(&f->ends[1].client, f->ends[1].state.connection, 1u) != SALTS_OK)
        return SALTS_EIO;
      ++f->receive_credits;
    }
    const int status = tls_bench_progress(f);
    if (status != SALTS_OK) return status;
    for (size_t e = 0u; e < 2u; ++e)
      if (f->ends[e].state.failed || f->ends[e].state.terminal_count) return SALTS_EPROTO;
  }
  out->elapsed = cmeta_hrtime() - start;
  if (tls_bench_cpu(&cpu_end) != SALTS_OK || cpu_end < cpu_start) return SALTS_EIO;
  out->cpu = cpu_end - cpu_start;
  if (f->completed != operations || f->received != operations || f->receive_offset != 0u) return SALTS_ETIMEDOUT;
  cnet_send_usage usage;
  if (cnet_client_send_usage(&f->ends[0].client, f->ends[0].state.connection, &usage) != SALTS_OK ||
      usage.operations || usage.bytes || usage.backing_bytes || mem_buffer_ref_count(f->source) != 1u)
    return SALTS_EPROTO;
  for (size_t e = 0u; e < 2u; ++e) {
    if (!native_io_backend_get_stats(&f->ends[e].backend, &after[e])) return SALTS_EIO;
    out->submissions += after[e].submitted - before[e].submitted;
    out->allocations += f->ends[e].storage.allocated;
    out->receives += f->ends[e].storage.receives;
  }
  out->allocations -= allocations;
  out->receives -= receives;
  out->calls = f->calls - calls;
  out->bytes = operations / 8u * (7u * TLS_BENCH_BYTES + 1u);
  qsort(f->latency, operations, sizeof(f->latency[0]), tls_bench_compare);
  out->p50 = f->latency[(operations * 50u + 99u) / 100u - 1u];
  out->p95 = f->latency[(operations * 95u + 99u) / 100u - 1u];
  out->p99 = f->latency[(operations * 99u + 99u) / 100u - 1u];
  return SALTS_OK;
}

static int tls_bench_setup(tls_bench_fixture *f, bool callback, size_t window, uint64_t *handshake_ns) {
  const char *label = "TLS pair setup";
  int result = 0;
  uint16_t port = 0u;
  f->window = window;
  cnet_client_config cfg = config();
  cfg.connection_capacity = 1u;
  cfg.completion_batch_capacity = 4u;
  cfg.max_send_bytes = f->mixed && !f->mixed->bulk ? 1u : TLS_BENCH_BYTES;
  cfg.receive_buffer_bytes = TLS_BENCH_BYTES;
  cfg.read_timeout_ms = cfg.write_timeout_ms = 0u;
  cfg.send_limits.operations = window;
  const native_io_backend_config backend_cfg = {cfg.backend, 2u, 8u, 4u};
  const cnet_listener_config listener_cfg = {cfg.backend, "127.0.0.1", 0u, 2u};
  const cnet_tls_server_config server_cfg = {
      .size = sizeof(cnet_tls_server_config), .cert_file = CORE_TLS_TEST_P384_LEAF,
      .key_file = CORE_TLS_TEST_P384_KEY};
  const cnet_tls_client_config tls_cfg = {
      .size = sizeof(cnet_tls_client_config), .ca_file = CORE_TLS_TEST_P384_CA,
      .server_name = "localhost"};
  REQUIRE(window == 1u || window == 8u);
  REQUIRE(tls_test_server_init(&f->context, &server_cfg) == SALTS_OK);
  for (size_t e = 0u; e < 2u; ++e) {
    tls_bench_end *end = &f->ends[e];
    end->fixture = f;
    end->state.client = &end->client;
    cfg.resources.storage = (cnet_allocator){tls_bench_allocate, tls_bench_free, &end->storage};
    cfg.resources.receive = (cnet_buffer_provider){tls_bench_buffer, &end->storage};
    REQUIRE(native_io_backend_init(&end->backend, &backend_cfg) == SALTS_OK);
    REQUIRE(cnet_client_init_external(&end->client, &cfg, &end->backend) == SALTS_OK);
  }
  REQUIRE(cnet_listener_init(&f->listener, &listener_cfg) == SALTS_OK);
  REQUIRE(cnet_listener_port(&f->listener, &port) == SALTS_OK && port != 0u);
  f->source = f->mixed ? f->mixed->source[0] : mem_get_buffer(mem_global(), TLS_BENCH_BYTES);
  REQUIRE(f->source != NULL);
  if (!f->mixed) {
    for (size_t i = 0u; i < TLS_BENCH_BYTES; ++i)
      mem_buffer_data(f->source)[i] = (char)((0x5au + i * 29u) & 0xffu);
    mem_set_used(f->source, TLS_BENCH_BYTES);
  }
  char uri[80];
  REQUIRE(snprintf(uri, sizeof(uri), "tls://127.0.0.1:%u", (unsigned)port) > 0);
  const cnet_connect_options connect = {.uri = uri, .tls = &tls_cfg,
      .observer = {tls_bench_state, tls_bench_received, &f->ends[0], tls_bench_sent}};
  const uint64_t handshake_start = cmeta_hrtime();
  REQUIRE(tls_test_connect(&f->ends[0].client, &connect, &f->ends[0].state.connection) == SALTS_OK);
  REQUIRE(cnet_send_buffer(&f->ends[0].client, f->ends[0].state.connection, f->source) == SALTS_EBUSY);
  REQUIRE(mem_buffer_ref_count(f->source) == 1u);
  bool accepted = false;
  uint64_t deadline = cmeta_monotonic_ms() + 7000u;
  while ((!f->ends[0].state.connected_count || !f->ends[1].state.connected_count) &&
         cmeta_monotonic_ms() < deadline) {
    int ready = 0;
    if (!accepted) {
      REQUIRE(cnet_listener_wait(&f->listener, 0u, &ready) == SALTS_OK);
      if (ready) {
        const cnet_observer observer = {tls_bench_state, tls_bench_received, &f->ends[1], tls_bench_sent};
        REQUIRE(cnet_listener_accept_tls(&f->listener, &f->ends[1].client, &f->context,
                                        &observer, &f->ends[1].state.connection) == SALTS_OK);
        accepted = true;
      }
    }
    REQUIRE(tls_bench_progress(f) == SALTS_OK);
    REQUIRE(!f->ends[0].state.failed && !f->ends[1].state.failed);
  }
  *handshake_ns = cmeta_hrtime() - handshake_start;
  for (size_t e = 0u; e < 2u; ++e) {
    tls_probe *p = &f->ends[e].state;
    REQUIRE(p->connected_count == 1u && p->terminal_count == 0u);
    REQUIRE(p->tls_version_status == SALTS_OK && p->tls_cipher_status == SALTS_OK);
    REQUIRE(strcmp(p->tls_version, "TLSv1.3") == 0 || strcmp(p->tls_version, "TLSv1.2") == 0);
    REQUIRE(p->tls_cipher[0] != '\0');
    REQUIRE(cnet_connection_tcp_option_set(&f->ends[e].client, p->connection,
                                          CNET_TCP_SOCKET_NODELAY, 1u) == SALTS_OK);
  }
  REQUIRE(strcmp(f->ends[0].state.tls_version, f->ends[1].state.tls_version) == 0);
  REQUIRE(strcmp(f->ends[0].state.tls_cipher, f->ends[1].state.tls_cipher) == 0);
  REQUIRE(cnet_listener_close(&f->listener) == SALTS_OK && cnet_listener_destroy(&f->listener) == SALTS_OK);
  if (callback) {
    if (f->mixed) {
      for (size_t e = 0u; e < 2u; ++e) if (f->mixed->source[e]) {
        const cnet_send_admission_policy policy = {tls_bench_mixed_admit, &f->ends[e]};
        REQUIRE(cnet_set_send_admission(&f->ends[e].client, f->ends[e].state.connection, &policy) == SALTS_OK);
      }
    } else {
      const cnet_send_admission_policy policy = {tls_bench_admit, f};
      REQUIRE(cnet_set_send_admission(&f->ends[0].client, f->ends[0].state.connection, &policy) == SALTS_OK);
    }
  }
  return SALTS_OK;
cleanup:
  return result;
}

static int tls_bench_close(tls_bench_fixture *f, uint64_t *close_ns) {
  const char *label = "TLS pair close";
  int result = 0;
  uint64_t deadline;
  const uint64_t close_start = cmeta_hrtime();
  REQUIRE(cnet_close(&f->ends[0].client, f->ends[0].state.connection) == SALTS_OK);
  deadline = cmeta_monotonic_ms() + 7000u;
  while ((!f->ends[0].state.terminal_count || !f->ends[1].state.terminal_count) && cmeta_monotonic_ms() < deadline)
    REQUIRE(tls_bench_progress(f) == SALTS_OK);
  REQUIRE(tls_bench_progress(f) == SALTS_OK);
  for (size_t e = 0u; e < 2u; ++e) {
    tls_bench_end *end = &f->ends[e];
    native_io_backend_stats stats;
    REQUIRE(end->state.terminal_count == 1u && end->state.failed == 0u &&
            end->state.last_connection_state == CNET_CONNECTION_CLOSED);
    REQUIRE(cnet_client_stop_external(&end->client) == SALTS_OK);
    REQUIRE(native_io_backend_get_stats(&end->backend, &stats) && stats.active_requests == 0u && stats.endpoint_count == 0u);
  }
  *close_ns = cmeta_hrtime() - close_start;
  for (size_t e = 0u; e < 2u; ++e) {
    tls_bench_end *end = &f->ends[e];
    REQUIRE(cnet_client_destroy(&end->client) == SALTS_OK);
    REQUIRE(end->storage.allocated == end->storage.released);
    REQUIRE(native_io_backend_close(&end->backend) == SALTS_OK && native_io_backend_destroy(&end->backend) == SALTS_OK);
  }
  return SALTS_OK;
cleanup:
  return result;
}

static bool tls_bench_dispose(tls_bench_fixture *f) {
  (void)cnet_listener_close(&f->listener);
  (void)cnet_listener_destroy(&f->listener);
  for (size_t e = 0u; e < 2u; ++e)
    if (f->ends[e].client.impl != NULL)
      (void)cnet_close(&f->ends[e].client, f->ends[e].state.connection);
  const uint64_t cleanup_deadline = cmeta_monotonic_ms() + 3000u;
  bool stopped = false;
  do {
    stopped = true;
    for (size_t e = 0u; e < 2u; ++e) {
      if (f->ends[e].client.impl != NULL) {
        const int status = cnet_client_stop_external(&f->ends[e].client);
        if (status != SALTS_OK && status != SALTS_EALREADY) stopped = false;
      }
    }
    if (!stopped) (void)tls_bench_progress(f);
  } while (!stopped && cmeta_monotonic_ms() < cleanup_deadline);
  if (stopped) {
    for (size_t e = 0u; e < 2u; ++e) {
      (void)cnet_client_destroy(&f->ends[e].client);
      (void)native_io_backend_close(&f->ends[e].backend);
      (void)native_io_backend_destroy(&f->ends[e].backend);
    }
    (void)cnet_tls_server_destroy(&f->context);
    if (f->ends[0].client.impl == NULL && f->ends[1].client.impl == NULL &&
        f->ends[0].backend.impl == NULL && f->ends[1].backend.impl == NULL &&
        f->listener.impl == NULL && f->context.impl == NULL) {
      if (f->source && !f->mixed) mem_buffer_release(f->source);
      f->source = NULL;
      return true;
    }
  }
  return false; /* Retain live callback/native storage. */
}

static int tls_bench_sample(bool callback, size_t window, bool report, unsigned repetition) {
  const char *label = "TLS policy benchmark";
  tls_bench_fixture *f = calloc(1u, sizeof(*f));
  int result = 0, transfer_status = SALTS_EIO;
  uint64_t handshake_ns = 0u, close_ns = 0u;
  tls_bench_result warm, measured;
  const size_t operations = report ? TLS_BENCH_WRITES : 16u;
  if (f == NULL) return __LINE__;
  REQUIRE(tls_bench_setup(f, callback, window, &handshake_ns) == SALTS_OK);
  REQUIRE(tls_bench_transfer(f, report ? 64u : 8u, &warm) == SALTS_OK);
  if (report) {
    benchmark_io("retained TLS policy transfer", 1, operations,
                 operations / 8u * (7u * TLS_BENCH_BYTES + 1u)) {
      transfer_status = tls_bench_transfer(f, operations, &measured);
    }
  } else transfer_status = tls_bench_transfer(f, operations, &measured);
  REQUIRE(transfer_status == SALTS_OK && measured.elapsed != 0u && measured.allocations == 0u);
  REQUIRE(measured.calls == (callback ? operations : 0u));
  REQUIRE((window == 8u) == (measured.rejected != 0u));
  REQUIRE(tls_bench_close(f, &close_ns) == SALTS_OK);
  REQUIRE(f->ends[0].state.sent_count == (report ? 64u : 8u) + operations);
  REQUIRE(f->ends[0].state.sends_at_terminal == f->ends[0].state.sent_count);
  REQUIRE(mem_buffer_ref_count(f->source) == 1u);
  if (report) printf("CNET_TLS_CSV,%s,%u,%zu,%zu,%s,%s,%llu,%zu,%llu,%llu,%llu,%llu,%llu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%llu,%llu\n",
      callback ? "callback" : "native", repetition, window, operations,
      f->ends[0].state.tls_version, f->ends[0].state.tls_cipher, (unsigned long long)handshake_ns,
      measured.bytes, (unsigned long long)measured.elapsed, (unsigned long long)measured.cpu,
      (unsigned long long)measured.p50, (unsigned long long)measured.p95, (unsigned long long)measured.p99,
      measured.rejected, measured.calls, measured.allocations, measured.receives,
      measured.peak_bytes, measured.peak_backing, mem_buffer_capacity(f->source),
      (unsigned long long)measured.submissions, (unsigned long long)close_ns);
cleanup:
  if (tls_bench_dispose(f)) { free(f); return result; }
  return result != 0 ? result : __LINE__;
}

typedef struct tls_mixed_cnet_fixture {
  tls_mixed_state state;
  tls_bench_fixture pair[2];
  size_t initialized;
} tls_mixed_cnet_fixture;
static int tls_mixed_cnet_send(void *user, size_t lane, size_t end, mem_buffer_t *source) {
  tls_bench_end *e = &((tls_mixed_cnet_fixture *)user)->pair[lane].ends[end];
  return cnet_send_buffer(&e->client, e->state.connection, source);
}
static int tls_mixed_cnet_receive(void *user, size_t lane, size_t end) {
  tls_bench_end *e = &((tls_mixed_cnet_fixture *)user)->pair[lane].ends[end];
  return cnet_receive(&e->client, e->state.connection, 1u);
}
static int tls_mixed_cnet_progress(void *user, size_t lane) {
  tls_bench_fixture *p = &((tls_mixed_cnet_fixture *)user)->pair[lane];
  const int status = tls_bench_progress(p);
  if (status != SALTS_OK) return status;
  for (size_t e = 0u; e < 2u; ++e)
    if (p->ends[e].state.failed || p->ends[e].state.terminal_count) return SALTS_EPROTO;
  return SALTS_OK;
}
static int tls_mixed_cnet_snapshot(void *user, tls_mixed_stats *out) {
  tls_mixed_cnet_fixture *f = user;
  *out = (tls_mixed_stats){0};
  for (size_t i = 0u; i < 2u; ++i) {
    out->policy_calls += f->pair[i].calls;
    for (size_t e = 0u; e < 2u; ++e) {
      tls_bench_end *end = &f->pair[i].ends[e];
      native_io_backend_stats stats;
      cnet_send_usage usage;
      if (!native_io_backend_get_stats(&end->backend, &stats) ||
          cnet_client_send_usage(&end->client, end->state.connection, &usage) != SALTS_OK) return SALTS_EIO;
      out->native_submissions[i] += stats.submitted;
      out->usage[i][e] = (tls_mixed_usage){usage.operations, usage.bytes, usage.backing_bytes};
      out->allocations += end->storage.allocated;
      out->receives += end->storage.receives;
    }
  }
  return SALTS_OK;
}
static int tls_mixed_cnet_sample(bool callback, size_t window, bool report, unsigned repetition) {
  const char *label = "independent TLS bulk/control";
  tls_mixed_cnet_fixture *f = calloc(1u, sizeof(*f));
  int result = 0, phase_status = SALTS_EIO;
  uint64_t handshake_ns, close_ns[2] = {0};
  tls_mixed_result warm, measured;
  crypto_tls_test_memory_stats start_memory, setup_memory, closing_memory, end_memory, setup_delta, close_delta;
  const size_t exchanges = report ? TLS_MIXED_EXCHANGES : 8u;
  if (!f) return __LINE__;
  REQUIRE(cnet_test_tls_memory_snapshot(&start_memory));
  REQUIRE(tls_mixed_init(&f->state, window) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    f->pair[i].mixed = &f->state.lane[i];
    ++f->initialized;
    REQUIRE(tls_bench_setup(&f->pair[i], callback, f->state.lane[i].window, &handshake_ns) == SALTS_OK);
  }
  REQUIRE(strcmp(f->pair[0].ends[0].state.tls_version, f->pair[1].ends[0].state.tls_version) == 0);
  REQUIRE(strcmp(f->pair[0].ends[0].state.tls_cipher, f->pair[1].ends[0].state.tls_cipher) == 0);
  f->state.tls13 = strcmp(f->pair[0].ends[0].state.tls_version, "TLSv1.3") == 0;
  REQUIRE(cnet_test_tls_memory_snapshot(&setup_memory));
  REQUIRE(tls_mixed_memory_delta(&start_memory, &setup_memory, &setup_delta) == SALTS_OK);
  REQUIRE(setup_delta.allocation_calls > 0u && setup_delta.requested_bytes > 0u && setup_delta.failures == 0u);
  const tls_mixed_ops ops = {f, tls_mixed_cnet_send, tls_mixed_cnet_receive,
      tls_mixed_cnet_progress, tls_mixed_cnet_snapshot, cnet_test_tls_memory_snapshot};
  REQUIRE(tls_mixed_phase(&f->state, &ops, 8u, &warm) == SALTS_OK);
  if (report) {
    benchmark_ops("independent TLS control RTT under bulk", 1, exchanges) {
      phase_status = tls_mixed_phase(&f->state, &ops, exchanges, &measured);
    }
  } else phase_status = tls_mixed_phase(&f->state, &ops, exchanges, &measured);
  if (phase_status != SALTS_OK) fprintf(stderr, "TLS mixed phase status=%d callback=%u depth=%zu\n",
                                       phase_status, (unsigned)callback, window);
  REQUIRE(phase_status == SALTS_OK);
  REQUIRE(measured.calls == (callback ? measured.bulk_admitted + 2u * exchanges : 0u));
  REQUIRE(cnet_test_tls_memory_snapshot(&closing_memory));
  for (size_t i = 0u; i < 2u; ++i) REQUIRE(tls_bench_close(&f->pair[i], &close_ns[i]) == SALTS_OK);
  if (report) tls_mixed_print(callback ? "callback" : "native", repetition, &f->state, &measured,
      close_ns[0] + close_ns[1], f->pair[0].ends[0].state.tls_version, f->pair[0].ends[0].state.tls_cipher);
cleanup:;
  bool quiet = true;
  for (size_t i = 0u; i < f->initialized; ++i) if (!tls_bench_dispose(&f->pair[i])) quiet = false;
  if (quiet && result == 0) {
    if (!cnet_test_tls_memory_snapshot(&end_memory) ||
        tls_mixed_memory_delta(&closing_memory, &end_memory, &close_delta) != SALTS_OK ||
        close_delta.failures || close_delta.releases == 0u) result = __LINE__;
    else if (report) {
      const char *mode = callback ? "callback" : "native";
      tls_mixed_memory_print(mode, repetition, window, "setup", &setup_delta);
      tls_mixed_memory_print(mode, repetition, window, "warm", &warm.memory);
      tls_mixed_memory_print(mode, repetition, window, "warm_drain", &warm.drain_memory);
      tls_mixed_memory_print(mode, repetition, window, "transfer", &measured.memory);
      tls_mixed_memory_print(mode, repetition, window, "drain", &measured.drain_memory);
      tls_mixed_memory_print(mode, repetition, window, "close_destroy", &close_delta);
    }
  }
  if (quiet) { tls_mixed_release(&f->state); free(f); return result; }
  return result ? result : __LINE__; /* Parent callback/source state remains live. */
}

/* Preserve original real peer / module argument delivery and all cleanup.
 * TinyTest owns the process result, while the original integration executes. */
static int saltscore_original_argc;
static char **saltscore_original_argv;

spec("CNet real TLS CA SAN mTLS Python peer interoperability") {
  it("preserves the real native integration and external peer contract") {
    const int result = saltscore_original_entry_test_cnet_tls_ca_san_c(saltscore_original_argc, saltscore_original_argv);
    check(result == 0, "native integration returned %d", result);
  }
  if (saltscore_original_argc == 1) {
    for (unsigned scenario = 0u; scenario < 4u; ++scenario) {
      it("drains independent TLS bulk/control scenario %u", scenario) {
        const int result = tls_mixed_cnet_sample((scenario & 1u) != 0u, scenario < 2u ? 1u : 8u, false, 0u);
        check(result == 0, "TLS mixed correctness returned %d", result);
      }
    }
    const char *mixed_measure = getenv("SALTSCORE_CNET_TLS_MIXED_BENCHMARK");
    if (mixed_measure != NULL) {
      it("uses the explicit CNet TLS mixed benchmark switch") { check_equal(mixed_measure, "1"); }
      if (strcmp(mixed_measure, "1") == 0)
        for (unsigned repetition = 0u; repetition < 5u; ++repetition)
          for (unsigned position = 0u; position < 4u; ++position) {
            const unsigned scenario = (position + repetition) % 4u;
            it("measures mixed TLS control, repetition %u scenario %u", repetition, scenario) {
              const int result = tls_mixed_cnet_sample((scenario & 1u) != 0u, scenario < 2u ? 1u : 8u, true, repetition);
              check(result == 0, "TLS mixed sample returned %d", result);
            }
          }
    }
    for (unsigned scenario = 0u; scenario < 4u; ++scenario) {
      it("drains verified retained TLS policy traffic, scenario %u", scenario) {
        const int result = tls_bench_sample((scenario & 1u) != 0u, scenario < 2u ? 1u : 8u, false, 0u);
        check(result == 0, "TLS policy correctness returned %d", result);
      }
    }
    const char *measure = getenv("SALTSCORE_CNET_TLS_BENCHMARK");
    if (measure != NULL) {
      it("uses the explicit CNet TLS benchmark switch") {
        check_equal(measure, "1");
      }
    }
    if (measure != NULL && strcmp(measure, "1") == 0) {
      printf("CNET_TLS_CSV,mode,repeat,window,operations,version,cipher,handshake_ns,bytes,elapsed_ns,cpu_ns,p50_send_ns,p95_send_ns,p99_send_ns,rejected,policy_calls,storage_allocations,receive_acquires,peak_logical_bytes,peak_backing_bytes,physical_source_bytes,native_submissions,close_ns\n");
      for (unsigned repetition = 0u; repetition < 5u; ++repetition) {
        for (unsigned position = 0u; position < 4u; ++position) {
          const unsigned scenario = (position + repetition) % 4u;
          it("measures verified TLS policy traffic, repetition %u scenario %u", repetition, scenario) {
            const int result = tls_bench_sample((scenario & 1u) != 0u, scenario < 2u ? 1u : 8u, true, repetition);
            check(result == 0, "TLS policy sample returned %d", result);
          }
        }
      }
    }
    it("retains TLS small and bulk writes through FIFO terminals and final close") {
      const tls_case_options stream = {
          .label = "persistent TLS retained-vector bulk and final close",
          .ca_file = CORE_TLS_TEST_P384_CA,
          .verified_hostname = "localhost",
          .expect_success = true,
          .stream_transfer = true};
      const int result = run_case(&stream);
      check(result == 0, "native TLS stream transfer returned %d", result);
    }
    it("reuses verified TLS only after protocol READY with an exact security key") {
      const tls_case_options pooled = {
          .label = "TLS protocol READY and exact security-key pool reuse",
          .ca_file = CORE_TLS_TEST_P384_CA,
          .verified_hostname = "localhost",
          .expect_success = true,
          .pool_reuse = true};
      const int result = run_case(&pooled);
      check(result == 0, "native TLS pool reuse returned %d", result);
    }
  }
}

int main(int argc, char **argv) {
  /* Keep peer protocol arguments intact; also expose TinyTest's standard
   * case filter for interleaved project-owned benchmark collection. */
  const bool filter = argc > 1 &&
      (strcmp(argv[1], "--filter") == 0 || strcmp(argv[1], "-f") == 0);
  saltscore_original_argc = filter ? 1 : argc;
  saltscore_original_argv = argv;
  char *runner_argv[] = {argv[0]};
  return ttest_main__(filter ? argc : 1, filter ? argv : runner_argv, TTEST_INVOKE_SPEC_ADAPTER__,
                      TT_USE_COLOR != 0, TT_USE_TAP != 0,
                      TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
}
