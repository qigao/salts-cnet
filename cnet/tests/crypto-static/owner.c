/* SPDX-License-Identifier: Apache-2.0
 * Real ORIGINAL CNet client / Owner command+event runtime with
 * ONE sole static Salts::Crypto archive in the final executable.
 * Both peers are real CNet clients using native platform NativeIO.
 * Public factory fallback is explicitly disabled: only exact test-private
 * verified CA/hostname and one TLS protocol are admitted.
 */
#include "public_context.h"
#include "cnet_crypto_owner_admission.h"
#include <cnet/cnet.h>
#include <crypto/tls.h>
#include <crypto/tls_auth.h>
#include <crypto/cipher_bio.h>
#include <memory/buffer.h>
#include <salts/clock.h>
#include <salts/error_codes.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(CNET_M6_BUILD_SHARED)
#include <stdatomic.h>
#include <threads/threads.h>
#endif

#ifndef SDK_CA_FILE
#error SDK_CA_FILE is required
#endif
#ifndef SDK_SERVER_CERT_FILE
#error SDK_SERVER_CERT_FILE is required
#endif
#ifndef SDK_SERVER_KEY_FILE
#error SDK_SERVER_KEY_FILE is required
#endif

enum { APP_TIMEOUT_MS = 15000, MAX_POLL = 24000 };

typedef struct observed_peer {
    size_t connected;
    size_t terminal;
    size_t failed;
    size_t sent;
    size_t plaintext_received;
    size_t borrowed_received;
    cnet_error last_error;
    char failure_stage[32]; /* owned copy of a callback-borrowed stage */
    mem_slice_t retained;
} observed_peer;

/* Callback error stage strings are borrowed for the duration of poll.
 * Never keep their raw pointers across the NativeIO Owner terminal.
 */
static void remember_terminal_error(observed_peer *peer,
                                   const cnet_error *error)
{
    size_t n;
    if (!peer || !error) return;
    peer->last_error = *error;
    peer->last_error.stage = NULL;
    if (!error->stage) return;
    for (n = 0u; n < sizeof(peer->failure_stage) &&
                  error->stage[n]; ++n) {}
    if (n == sizeof(peer->failure_stage)) {
        peer->failed++;
        return;
    }
    memcpy(peer->failure_stage, error->stage, n + 1u);
    peer->last_error.stage = peer->failure_stage;
}

static void on_state(void *user, cnet_connection handle,
                     cnet_connection_state state, const cnet_error *error)
{
    observed_peer *peer = (observed_peer *)user;
    (void)handle;
    if (state == CNET_CONNECTION_CONNECTED) peer->connected++;
    if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED)
        peer->terminal++;
    if (state == CNET_CONNECTION_FAILED || error) {
        peer->failed++;
        if (error) remember_terminal_error(peer, error);
    }
}

static void on_borrowed(void *user, cnet_connection handle,
                        const cnet_receive_view *view)
{
    observed_peer *peer = (observed_peer *)user;
    (void)handle; (void)view;
    peer->borrowed_received++;
}

static void on_owned(void *user, cnet_connection handle,
                     mem_slice_t slice, cnet_message_kind kind)
{
    observed_peer *peer = (observed_peer *)user;
    (void)handle;
    if (kind != CNET_MESSAGE_BYTES || !slice.buffer || !slice.data ||
        peer->retained.buffer != NULL) {
        peer->failed++;
        mem_slice_release(&slice);
        return;
    }
    peer->retained = slice; /* move-owned; caller releases after client destroy */
    peer->plaintext_received++;
}

static void on_sent(void *user, cnet_connection handle, size_t sent)
{
    observed_peer *peer = (observed_peer *)user;
    (void)handle;
    if (!sent) peer->failed++;
    peer->sent++;
}

static native_io_backend_kind current_native_kind(void)
{
#if defined(_WIN32)
    return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
    return NATIVE_IO_BACKEND_KQUEUE;
#else
    return NATIVE_IO_BACKEND_EPOLL;
#endif
}

static cnet_client_config client_config(void)
{
    cnet_client_config c = {0};
    c.backend = current_native_kind();
    c.connection_capacity = 4u;
    c.command_capacity = 32u;
    c.request_capacity = 16u;
    c.completion_batch_capacity = 16u;
    c.event_capacity = 32u;
    c.max_send_bytes = 1024u;
    c.receive_buffer_bytes = 4096u;
    c.tls_io_buffer_bytes = CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY;
    c.tls_handshake_timeout_ms = APP_TIMEOUT_MS;
    return c;
}

static int pump(cnet_client *dialer, cnet_client *acceptor)
{
    size_t events = 0u;
    if (cnet_client_poll(dialer, 1u, &events) != SALTS_OK) return -1;
    if (cnet_client_poll(acceptor, 1u, &events) != SALTS_OK) return -2;
    return 0;
}

#define CHECK(x) do { \
    if (!(x)) { \
        fprintf(stderr,"CNet full original Crypto TLS Owner failure line %d: %s\\n", \
                __LINE__, #x); \
        goto done; \
    } \
} while (0)

/* Admission must be strict at the existing PUBLIC CNet policy boundary.
 * A rejected descriptor remains untouched; no caller-owned files, sessions
 * or NativeIO requests are borrowed before explicit policy acceptance.
 */
static int check_m5_policy_admission(void)
{
    cnet_tls_client_config client = {0};
    cnet_tls_server_config server = {0};
    crypto_tls_session_options out = {0}, marker = {0};
    size_t capacity = CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY;
    char too_long[CRYPTO_TLS_AUTH_MAX_PATH_BYTES + 2u];
    int rc = 1;
#define ADMIT_TEST(x) do { \
    if (!(x)) { \
        fprintf(stderr, "M5 CNet policy admission failed line %d: %s\\n", __LINE__, #x); \
        goto done; \
    } \
} while (0)

    client.size = sizeof(client);
    client.server_name = "localhost";
    client.ca_file = SDK_CA_FILE;
    client.cert_file = SDK_SERVER_CERT_FILE;
    client.key_file = SDK_SERVER_KEY_FILE;
    server.size = sizeof(server);
    server.client_auth = CNET_TLS_CLIENT_AUTH_REQUIRED;
    server.cert_file = SDK_SERVER_CERT_FILE;
    server.key_file = SDK_SERVER_KEY_FILE;
    server.ca_file = SDK_CA_FILE;
    out.struct_size = UINT32_C(0xdead0102);
    marker = out;
    ADMIT_TEST(cnet_crypto_owner_admit_client(
        &client, "localhost", CRYPTO_TLS_1_2, capacity,
        CNET_CRYPTO_OWNER_TEST_ONLY, &out) == SALTS_OK);
    ADMIT_TEST(out.role == CRYPTO_TLS_CLIENT && out.ca_file == SDK_CA_FILE);
    out = marker;
    ADMIT_TEST(cnet_crypto_owner_admit_server(
        &server, CRYPTO_TLS_1_3, capacity, CNET_CRYPTO_OWNER_TEST_ONLY,
        &out) == SALTS_OK);
    ADMIT_TEST(out.role == CRYPTO_TLS_SERVER && out.protocol == CRYPTO_TLS_1_3);

    out = marker;
    client.key_file = NULL;
    ADMIT_TEST(cnet_crypto_owner_admit_client(
        &client, "localhost", CRYPTO_TLS_1_2, capacity,
        CNET_CRYPTO_OWNER_TEST_ONLY, &out) == SALTS_EINVAL);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);
    client.key_file = SDK_SERVER_KEY_FILE;
    client.ca_file = NULL;
    ADMIT_TEST(cnet_crypto_owner_admit_client(
        &client, "localhost", CRYPTO_TLS_1_2, capacity,
        CNET_CRYPTO_OWNER_TEST_ONLY, &out) == SALTS_ENOTSUP);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);
    client.ca_file = SDK_CA_FILE;
    client.ca_path = "/tmp/must-not-use-trust-dir";
    ADMIT_TEST(cnet_crypto_owner_admit_client(
        &client, "localhost", CRYPTO_TLS_1_2, capacity,
        CNET_CRYPTO_OWNER_TEST_ONLY, &out) == SALTS_ENOTSUP);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);
    client.ca_path = NULL;
    client.security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13;
    ADMIT_TEST(cnet_crypto_owner_admit_client(
        &client, "localhost", CRYPTO_TLS_1_3, capacity,
        CNET_CRYPTO_OWNER_TEST_ONLY, &out) == SALTS_ENOTSUP);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);
    client.security_profile = CNET_TLS_SECURITY_PROFILE_STANDARD;
    ADMIT_TEST(cnet_crypto_owner_admit_client(
        &client, "localhost", CRYPTO_TLS_1_2, capacity,
        CNET_CRYPTO_OWNER_PRODUCTION, &out) == SALTS_ENOTSUP);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);
    memset(too_long, 'X', sizeof(too_long));
    too_long[sizeof(too_long) - 1u] = '\0';
    client.cert_file = too_long;
    ADMIT_TEST(cnet_crypto_owner_admit_client(
        &client, "localhost", CRYPTO_TLS_1_2, capacity,
        CNET_CRYPTO_OWNER_TEST_ONLY, &out) == SALTS_EINVAL);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);

    out = marker;
    server.ca_file = NULL;
    ADMIT_TEST(cnet_crypto_owner_admit_server(
        &server, CRYPTO_TLS_1_2, capacity, CNET_CRYPTO_OWNER_TEST_ONLY,
        &out) == SALTS_ENOTSUP);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);
    server.ca_file = SDK_CA_FILE;
    server.ca_path = "/tmp/must-not-use-trust-dir";
    ADMIT_TEST(cnet_crypto_owner_admit_server(
        &server, CRYPTO_TLS_1_2, capacity, CNET_CRYPTO_OWNER_TEST_ONLY,
        &out) == SALTS_ENOTSUP);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);
    server.ca_path = NULL;
    server.security_profile = CNET_TLS_SECURITY_PROFILE_TLCP11;
    ADMIT_TEST(cnet_crypto_owner_admit_server(
        &server, CRYPTO_TLS_1_2, capacity, CNET_CRYPTO_OWNER_TEST_ONLY,
        &out) == SALTS_ENOTSUP);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);
    server.security_profile = CNET_TLS_SECURITY_PROFILE_STANDARD;
    ADMIT_TEST(cnet_crypto_owner_admit_server(
        &server, CRYPTO_TLS_1_2, capacity, CNET_CRYPTO_OWNER_PRODUCTION,
        &out) == SALTS_ENOTSUP);
    ADMIT_TEST(memcmp(&out, &marker, sizeof(out)) == 0);

    rc = 0;
done:
#undef ADMIT_TEST
    return rc;
}

typedef struct m5_mtls_case {
    const char *ca, *server_cert, *server_key;
    const char *client_cert, *client_key;
    bool expect_accept;
} m5_mtls_case;

/* The original CNet clients and NativeIO Owners remain unchanged.
 * Python-generated file fixtures remain alive until full owner teardown.
 */
#if defined(CNET_M6_BUILD_SHARED)
/* Both independent CNet workers must have already submitted real native
 * TCP/TLS connection commands before either enters the handshake pump.
 * This proves the test exercises simultaneous native transport admission,
 * rather than sequentially running two already-passed M5 single-owner tests.
 */
static atomic_uint m6_native_tls_ready = 0u;

static int m6_parallel_native_tls_gate(void)
{
    const unsigned ticket = atomic_fetch_add_explicit(
        &m6_native_tls_ready, 1u, memory_order_acq_rel);
    if ((ticket & 1u) != 0u) return SALTS_OK;
    const uint64_t deadline = monotonic_ms() + UINT64_C(5000);
    while (atomic_load_explicit(&m6_native_tls_ready,
                                memory_order_acquire) <= ticket) {
        if (monotonic_ms() >= deadline) return SALTS_ETIMEDOUT;
        sync_thread_yield();
    }
    return SALTS_OK;
}
#endif

static int run_protocol(crypto_tls_provider *borrowed_provider,
                        uint32_t protocol, bool with_alpn,
                        const m5_mtls_case *mtls)
{
    crypto_tls_provider *provider = borrowed_provider;
    const bool owns_provider = borrowed_provider == NULL;
    cnet_tls_client profile = {0};
    cnet_tls_server identity = {0};
    cnet_tls_client_config client_policy = {0};
    cnet_tls_server_config server_policy = {0};
    cnet_client dialer = {0}, acceptor = {0};
    cnet_listener listener = {0};
    observed_peer client_seen = {0}, server_seen = {0};
    cnet_connection dialed = {0}, accepted = {0};
    cnet_observer client_observer = {on_state, on_borrowed,
                                     &client_seen, on_sent};
    cnet_observer server_observer = {on_state, on_borrowed,
                                     &server_seen, on_sent};
    const cnet_client_config options = client_config();
    cnet_listener_config listen_cfg = {current_native_kind(),
                                       "127.0.0.1", 0u, 4u};
    static const uint8_t PAYLOAD[] =
        "Original CNet Owner / Crypto opaque TLS and retained NativeIO completion";
    mem_buffer_t *send_backing = NULL;
    char uri[128], version[32], cipher[128], fingerprint[80];
    char selected_alpn[256] = {0};
    unsigned char client_binding[CNET_TLS_CHANNEL_BINDING_BYTES] = {0};
    unsigned char server_binding[CNET_TLS_CHANNEL_BINDING_BYTES] = {0};
    uint16_t port = 0u;
    size_t name_size = 0u;
    uint64_t deadline;
    int listener_live = 0, dialer_live = 0, acceptor_live = 0;
    int rc = 1, listener_ready = 0, poll_rc, status;
    unsigned poll_count;
    const char *expected_version =
        protocol == CRYPTO_TLS_1_2 ? "TLSv1.2" : "TLSv1.3";
    char client_h2[] = "h2", client_http[] = "http/1.1";
    char server_h2[] = "h2";
    const char *const client_offers[] = {client_h2, client_http};
    const char *const server_offers[] = {server_h2};

    if (owns_provider) {
        CHECK(crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION, &provider)
              == CRYPTO_TLS_OK);
    }
    client_policy.size = sizeof(client_policy);
    client_policy.ca_file = mtls ? mtls->ca : SDK_CA_FILE;
    client_policy.server_name = "localhost";
    if (mtls != NULL) {
        client_policy.cert_file = mtls->client_cert;
        client_policy.key_file = mtls->client_key;
    }
    server_policy.size = sizeof(server_policy);
    server_policy.cert_file = mtls ? mtls->server_cert : SDK_SERVER_CERT_FILE;
    server_policy.key_file = mtls ? mtls->server_key : SDK_SERVER_KEY_FILE;
    if (mtls != NULL) {
        server_policy.client_auth = CNET_TLS_CLIENT_AUTH_REQUIRED;
        server_policy.ca_file = mtls->ca;
    }
    if (with_alpn) {
        client_policy.alpn_protocols = client_offers;
        client_policy.alpn_protocol_count = 2u;
        server_policy.alpn_protocols = server_offers;
        server_policy.alpn_protocol_count = 1u;
    }

    CHECK(cnet_crypto_test_bind_client(
        &profile, provider, &client_policy, "localhost", protocol,
        CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY) == SALTS_OK);
    CHECK(cnet_crypto_test_bind_server(
        &identity, provider, &server_policy, protocol,
        CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY) == SALTS_OK);
    if (with_alpn) {
        /* Reusable client/server policies are synchronously consumed.
         * Force mutation before original CNet Owner admits the TCP session;
         * selected ALPN must still be h2, not x2.
         */
        client_h2[0] = 'x';
        client_http[0] = 'x';
        server_h2[0] = 'x';
    }
    CHECK(cnet_listener_init(&listener, &listen_cfg) == SALTS_OK);
    listener_live = 1;
    CHECK(cnet_listener_port(&listener, &port) == SALTS_OK && port != 0u);
    CHECK(cnet_client_init(&dialer, &options) == SALTS_OK);
    dialer_live = 1;
    CHECK(cnet_client_init(&acceptor, &options) == SALTS_OK);
    acceptor_live = 1;
    CHECK(snprintf(uri, sizeof(uri), "tls://127.0.0.1:%u",
                   (unsigned)port) > 0);
    {
        cnet_connect_options connect = {0};
        connect.uri = uri;
        connect.tls_client = &profile;
        connect.observer = client_observer;
        CHECK(cnet_connect(&dialer, &connect, &dialed) == SALTS_OK);
    }
#if defined(CNET_M6_BUILD_SHARED)
    if (borrowed_provider != NULL) {
        CHECK(m6_parallel_native_tls_gate() == SALTS_OK);
        /* This private gate intentionally blocks two actual cnet_connect
         * admissions before original Owner pumping. The independent plugin
         * loader now attempts cross-plugin release of both ACTIVE leases
         * while their real CNet worker operations are still in flight.
         * It does NOT claim a TLS callback has fired yet.
         */
        extern int cnet_m6_test_native_admission_wait(void);
        CHECK(cnet_m6_test_native_admission_wait() == SALTS_OK);
    }
#endif

    deadline = monotonic_ms() + APP_TIMEOUT_MS;
    for (poll_count = 0u; poll_count < MAX_POLL &&
         monotonic_ms() < deadline; ++poll_count) {
        CHECK(pump(&dialer, &acceptor) == 0);
        if (!accepted.slot) {
            listener_ready = 0;
            status = cnet_listener_wait(&listener, 1u, &listener_ready);
            CHECK(status == SALTS_OK || status == SALTS_ETIMEDOUT);
            if (status == SALTS_OK && listener_ready) {
                CHECK(cnet_listener_accept_tls(
                    &listener, &acceptor, &identity, &server_observer,
                    &accepted) == SALTS_OK);
                CHECK(accepted.slot && accepted.generation);
            }
        }
        if (mtls != NULL && !mtls->expect_accept) {
            if (accepted.slot && server_seen.failed != 0u) break;
        } else {
            CHECK(!client_seen.failed && !server_seen.failed);
            if (accepted.slot && client_seen.connected == 1u &&
                server_seen.connected == 1u) break;
        }
    }
    if (mtls != NULL && !mtls->expect_accept) {
        CHECK(accepted.slot && accepted.generation);
        CHECK(server_seen.connected == 0u);
        CHECK(server_seen.failed == 1u && server_seen.terminal == 1u);
        CHECK(server_seen.last_error.stage != NULL &&
              strcmp(server_seen.last_error.stage, "handshake") == 0);
        CHECK(client_seen.sent == 0u && server_seen.plaintext_received == 0u
              && client_seen.plaintext_received == 0u);
        rc = 0;
        goto done;
    }
    CHECK(client_seen.connected == 1u && server_seen.connected == 1u);
    CHECK(!client_seen.failed && !server_seen.failed);
    CHECK(accepted.slot != 0u);

    memset(version, 0, sizeof(version));
    memset(cipher, 0, sizeof(cipher));
    memset(fingerprint, 0, sizeof(fingerprint));
    CHECK(cnet_tls_negotiated_version(&dialer, dialed, version,
           sizeof(version), &name_size) == SALTS_OK);
    CHECK(strcmp(version, expected_version) == 0);
    CHECK(cnet_tls_negotiated_cipher(&dialer, dialed, cipher,
           sizeof(cipher), &name_size) == SALTS_OK && name_size > 0u);
    if (with_alpn) {
        CHECK(cnet_tls_negotiated_alpn(
            &dialer, dialed, selected_alpn, sizeof(selected_alpn),
            &name_size) == SALTS_OK);
        CHECK(name_size == 2u && strcmp(selected_alpn, "h2") == 0);
        CHECK(cnet_tls_negotiated_alpn(
            &acceptor, accepted, selected_alpn, sizeof(selected_alpn),
            &name_size) == SALTS_OK);
        CHECK(name_size == 2u && strcmp(selected_alpn, "h2") == 0);
        CHECK(cnet_tls_negotiated_alpn(
            &dialer, dialed, selected_alpn, 2u, &name_size)
            == SALTS_EMSGSIZE && name_size == 0u);
    } else {
        CHECK(cnet_tls_negotiated_alpn(
            &dialer, dialed, selected_alpn, sizeof(selected_alpn),
            &name_size) == SALTS_ENOENT && name_size == 0u);
    }
    CHECK(cnet_tls_peer_certificate_sha256(
        &dialer, dialed, fingerprint) == SALTS_OK);
    CHECK(strlen(fingerprint) == 64u);
    CHECK(cnet_tls_export_channel_binding(
          &dialer, dialed, client_binding) == SALTS_OK);
    CHECK(cnet_tls_export_channel_binding(
          &acceptor, accepted, server_binding) == SALTS_OK);
    CHECK(memcmp(client_binding, server_binding,
                 sizeof(client_binding)) == 0);

    CHECK(cnet_set_receive_slice_handler(&acceptor, accepted,
           on_owned, &server_seen) == SALTS_OK);
    CHECK(cnet_receive(&acceptor, accepted, sizeof(PAYLOAD)) == SALTS_OK);
    send_backing = mem_get_buffer(mem_global(), sizeof(PAYLOAD));
    CHECK(send_backing != NULL);
    memcpy(mem_buffer_data(send_backing), PAYLOAD, sizeof(PAYLOAD));
    mem_set_used(send_backing, sizeof(PAYLOAD));
    CHECK(cnet_send_buffer(&dialer, dialed, send_backing) == SALTS_OK);
    mem_buffer_release(send_backing); /* CNet owns ref until terminal */
    send_backing = NULL;

    deadline = monotonic_ms() + APP_TIMEOUT_MS;
    for (poll_count = 0u; poll_count < MAX_POLL &&
         monotonic_ms() < deadline; ++poll_count) {
        CHECK(pump(&dialer, &acceptor) == 0);
        CHECK(!client_seen.failed && !server_seen.failed);
        if (client_seen.sent == 1u &&
            server_seen.plaintext_received == 1u) break;
    }
    CHECK(client_seen.sent == 1u && server_seen.plaintext_received == 1u);
    CHECK(server_seen.retained.buffer != NULL);
    CHECK(server_seen.retained.length == sizeof(PAYLOAD));
    CHECK(memcmp(server_seen.retained.data, PAYLOAD, sizeof(PAYLOAD)) == 0);
    CHECK(mem_buffer_pool(server_seen.retained.buffer) == mem_global());

    CHECK(cnet_close(&dialer, dialed) == SALTS_OK);
    CHECK(cnet_close(&acceptor, accepted) == SALTS_OK);
    deadline = monotonic_ms() + APP_TIMEOUT_MS;
    for (poll_count = 0u; poll_count < MAX_POLL &&
         monotonic_ms() < deadline; ++poll_count) {
        poll_rc = pump(&dialer, &acceptor);
        CHECK(poll_rc == 0);
        if (client_seen.terminal >= 1u && server_seen.terminal >= 1u)
            break;
    }
    CHECK(client_seen.terminal >= 1u && server_seen.terminal >= 1u);
    CHECK(!client_seen.failed && !server_seen.failed);
    rc = 0;
done:
    if (send_backing) mem_buffer_release(send_backing);
    if (dialer_live) {
        if (cnet_client_stop(&dialer, 5000u) != SALTS_OK) rc = 1;
        if (cnet_client_destroy(&dialer) != SALTS_OK) rc = 1;
    }
    if (acceptor_live) {
        if (cnet_client_stop(&acceptor, 5000u) != SALTS_OK) rc = 1;
        if (cnet_client_destroy(&acceptor) != SALTS_OK) rc = 1;
    }
    if (listener_live) {
        if (cnet_listener_close(&listener) != SALTS_OK) rc = 1;
        if (cnet_listener_destroy(&listener) != SALTS_OK) rc = 1;
    }
    /* The CNet DSO and both Owner objects are already destroyed. Their
     * separately retained Core mem_slice must still be valid and releasable.
     */
    if (server_seen.retained.buffer) {
        if (server_seen.retained.length != sizeof(PAYLOAD) ||
            memcmp(server_seen.retained.data, PAYLOAD,
                   sizeof(PAYLOAD)) != 0)
            rc = 1;
        mem_slice_release(&server_seen.retained);
    }
    if (cnet_tls_client_destroy(&profile) != SALTS_OK ||
        cnet_tls_server_destroy(&identity) != SALTS_OK)
        rc = 1;
    if (owns_provider && provider &&
        crypto_tls_provider_destroy(&provider) != CRYPTO_TLS_OK)
        rc = 1;
    if (rc) fprintf(stderr,
        "Original CNet TLS Owner 0x%x failed client_state=%zu/%zu/%zu"
        " server_state=%zu/%zu/%zu sender=%zu received=%zu error=%d stage=%s\\n",
        protocol, client_seen.connected, client_seen.terminal,
        client_seen.failed, server_seen.connected, server_seen.terminal,
        server_seen.failed, client_seen.sent, server_seen.plaintext_received,
        client_seen.last_error.status,
        client_seen.last_error.stage ? client_seen.last_error.stage : "(none)");
    else printf("Original CNet Owner + sole static Crypto TLS 0x%x native"
                " handshake/callback/slice/exporter/close PASS\\n", protocol);
    return rc;
}


#if defined(CNET_M6_BUILD_SHARED)
/* Reuse the SAME original CNet/NativeIO TLS1.2/1.3 M5 acceptance,
 * with an explicitly BORROWED Provider from the sole shared CNet DLL.
 * TLS/transport states are owned and torn down by each worker thread.
 * No TLS implementation nor trust fallback is introduced here.
 */
int cnet_m6_original_owner_mtls_case(
    crypto_tls_provider *shared_provider, uint32_t protocol,
    const char *ca, const char *server_cert, const char *server_key,
    const char *client_cert, const char *client_key, bool expect_accept)
{
    m5_mtls_case fixture = {0};
    if (shared_provider == NULL || ca == NULL || server_cert == NULL ||
        server_key == NULL ||
        (protocol != CRYPTO_TLS_1_2 && protocol != CRYPTO_TLS_1_3) ||
        ((client_cert == NULL) != (client_key == NULL)))
        return SALTS_EINVAL;
    fixture.ca = ca;
    fixture.server_cert = server_cert;
    fixture.server_key = server_key;
    fixture.client_cert = client_cert;
    fixture.client_key = client_key;
    fixture.expect_accept = expect_accept;
    return run_protocol(shared_provider, protocol, false, &fixture) == 0
        ? SALTS_OK : SALTS_EIO;
}
#else
/* Independent OpenSSL 3 server is launched in ANOTHER PROCESS by Python.
 * It presents the exact trusted 'localhost' certificate irrespective of
 * client SNI. A wrong.example failure can then only be counted when the
 * original CNet client rejects authentication, never a GmSSL server-side
 * SNI filter in the same local static-provider test pair.
 */
static void external_state(void *user, cnet_connection handle,
                           cnet_connection_state state,
                           const cnet_error *error)
{
    observed_peer *p = (observed_peer *)user;
    (void)handle;
    if (state == CNET_CONNECTION_CONNECTED) ++p->connected;
    if (state == CNET_CONNECTION_FAILED) ++p->failed;
    if (state == CNET_CONNECTION_FAILED ||
        state == CNET_CONNECTION_CLOSED) ++p->terminal;
    if (error != NULL) remember_terminal_error(p, error);
}

static int run_external_san(unsigned port, uint32_t protocol, bool accept_peer)
{
    crypto_tls_provider *provider = NULL;
    cnet_tls_client profile = {0};
    cnet_tls_client_config tls_policy = {0};
    cnet_client dialer = {0};
    cnet_connection connection = {0};
    observed_peer observed = {0};
    mem_buffer_t *request = NULL;
    cnet_observer callbacks = {external_state, on_borrowed,
                               &observed, on_sent};
    const cnet_client_config options = client_config();
    const char *hostname = accept_peer ? "localhost" : "wrong.example";
    char uri[96];
    uint64_t deadline = 0u;
    int rc = 1, dialer_live = 0;
    size_t events = 0u;

    CHECK(crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION, &provider)
          == CRYPTO_TLS_OK && provider != NULL);
    tls_policy.size = sizeof(tls_policy);
    tls_policy.ca_file = SDK_CA_FILE; /* correct authority in BOTH cases */
    tls_policy.server_name = hostname;
    CHECK(cnet_crypto_test_bind_client(
        &profile, provider, &tls_policy, hostname, protocol,
        CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY) == SALTS_OK);
    CHECK(cnet_client_init(&dialer, &options) == SALTS_OK);
    dialer_live = 1;
    CHECK(snprintf(uri, sizeof(uri), "tls://127.0.0.1:%u", port) > 0);
    {
        cnet_connect_options connect = {0};
        connect.uri = uri;
        connect.tls_client = &profile;
        connect.observer = callbacks;
        CHECK(cnet_connect(&dialer, &connect, &connection) == SALTS_OK);
    }
    deadline = monotonic_ms() + APP_TIMEOUT_MS;
    for (; monotonic_ms() < deadline; ) {
        CHECK(cnet_client_poll(&dialer, 2u, &events) == SALTS_OK);
        if (observed.connected || observed.failed) break;
    }
    if (accept_peer) {
        static const uint8_t ready[] = {'o', 'k'};
        CHECK(observed.connected == 1u && observed.failed == 0u);
        /* TCP/TLS CONNECTED is not proof that our encrypted Finished
         * reached the independent OpenSSL peer. Wait for actual SERVER
         * APPLICATION DATA, emitted only AFTER Python SSL handshake().
         * Keep real IOCP/epoll/kqueue active until this terminal evidence.
         */
        CHECK(cnet_set_receive_slice_handler(
            &dialer, connection, on_owned, &observed) == SALTS_OK);
        CHECK(cnet_receive(&dialer, connection, sizeof(ready)) == SALTS_OK);
        deadline = monotonic_ms() + APP_TIMEOUT_MS;
        while (monotonic_ms() < deadline &&
               observed.retained.buffer == NULL) {
            CHECK(cnet_client_poll(&dialer, 2u, &events) == SALTS_OK);
        }
        CHECK(observed.plaintext_received == 1u &&
              observed.retained.buffer != NULL &&
              observed.retained.length == sizeof(ready) &&
              memcmp(observed.retained.data, ready, sizeof(ready)) == 0);
        /* The independent peer requires one application byte followed by
         * authenticated EOF. Admission retains this immutable byte until the
         * final send settles; keep polling through the close terminal.
         */
        request = mem_get_buffer(mem_global(), 1u);
        CHECK(request != NULL);
        *(uint8_t *)mem_buffer_data(request) = 'F';
        mem_set_used(request, 1u);
        CHECK(cnet_send_buffer_and_close(&dialer, connection, request)
              == SALTS_OK);
        mem_buffer_release(request);
        request = NULL;
        deadline = monotonic_ms() + APP_TIMEOUT_MS;
        while (monotonic_ms() < deadline && observed.terminal == 0u) {
            CHECK(cnet_client_poll(&dialer, 2u, &events) == SALTS_OK);
        }
        CHECK(observed.sent == 1u && observed.terminal == 1u &&
              observed.failed == 0u);
    } else {
        CHECK(observed.connected == 0u && observed.failed >= 1u);
    }
    rc = 0;
done:
    if (dialer_live) {
        if (cnet_client_stop(&dialer, 5000u) != SALTS_OK) rc = 1;
        if (cnet_client_destroy(&dialer) != SALTS_OK) rc = 1;
    }
    if (request != NULL) mem_buffer_release(request);
    /* Deliberately keep the Core-owned slice through client destruction. */
    if (observed.retained.buffer != NULL)
        mem_slice_release(&observed.retained);
    if (cnet_tls_client_destroy(&profile) != SALTS_OK) rc = 1;
    if (provider && crypto_tls_provider_destroy(&provider) != CRYPTO_TLS_OK)
        rc = 1;
    if (rc)
        fprintf(stderr,
            "OpenSSL independent peer / static CNet client TLS0x%x %s"
            " failed: connected=%zu failed=%zu terminal=%zu"
            " status=%d stage=%s\n",
            protocol, hostname, observed.connected, observed.failed,
            observed.terminal, observed.last_error.status,
            observed.last_error.stage ? observed.last_error.stage : "(none)");
    return rc;
}

static int external_main(int argc, char **argv)
{
    char *end = NULL;
    unsigned long port;
    uint32_t protocol;
    bool accept_peer;
    if (argc != 5 || strcmp(argv[1], "--external-san") != 0)
        return 2;
    port = strtoul(argv[2], &end, 10);
    if (argv[2][0] == '\0' || end == argv[2] || *end != '\0' ||
        port == 0ul || port > 65535ul)
        return 2;
    if (strcmp(argv[3], "tls12") == 0) protocol = CRYPTO_TLS_1_2;
    else if (strcmp(argv[3], "tls13") == 0) protocol = CRYPTO_TLS_1_3;
    else return 2;
    if (strcmp(argv[4], "localhost") == 0) accept_peer = true;
    else if (strcmp(argv[4], "wrong.example") == 0) accept_peer = false;
    else return 2;
    return run_external_san((unsigned)port, protocol, accept_peer);
}

int main(int argc, char **argv)
{
    if (argc == 9 && strcmp(argv[1], "--mtls") == 0) {
        m5_mtls_case m = {0};
        uint32_t protocol;
        if (strcmp(argv[2], "12") == 0) protocol = CRYPTO_TLS_1_2;
        else if (strcmp(argv[2], "13") == 0) protocol = CRYPTO_TLS_1_3;
        else return 2;
        m.ca = argv[3]; m.server_cert = argv[4]; m.server_key = argv[5];
        m.client_cert = strcmp(argv[6], "-") == 0 ? NULL : argv[6];
        m.client_key = strcmp(argv[7], "-") == 0 ? NULL : argv[7];
        m.expect_accept = strcmp(argv[8], "accept") == 0;
        if (!m.expect_accept && strcmp(argv[8], "reject") != 0) return 2;
        return run_protocol(NULL, protocol, false, &m);
    }
    if (argc != 1) return external_main(argc, argv);
    if (check_m5_policy_admission() != 0) return 3;
    cnet_tls_client dummy = {0};
    cnet_tls_client_config default_policy = {0};
    default_policy.size = sizeof(default_policy);
    if (cnet_tls_client_init(&dummy, &default_policy) != SALTS_ENOTSUP ||
        dummy.impl != NULL)
        return 2; /* Never admit implicit root stores/default TLS range. */
    if (run_protocol(NULL, CRYPTO_TLS_1_2, false, NULL) != 0) return 1;
    if (run_protocol(NULL, CRYPTO_TLS_1_2, true, NULL) != 0) return 1;
    if (run_protocol(NULL, CRYPTO_TLS_1_3, false, NULL) != 0) return 1;
    if (run_protocol(NULL, CRYPTO_TLS_1_3, true, NULL) != 0) return 1;
    return 0;
}
#endif /* original CNet M5 executable / shared DLL M6 test selection */
