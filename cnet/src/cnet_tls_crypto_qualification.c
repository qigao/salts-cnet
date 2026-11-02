/* SPDX-License-Identifier: Apache-2.0
 * PRIVATE, TEST-ONLY candidate CNet TLS state backed by the installed,
 * sole STATIC Salts::Crypto archive and bounded CipherBIO.
 *
 * This file intentionally does not replace cnet/src/cnet_tls.c, does not
 * compile into Salts::CNet and never imports <gmssl/...>. Missing
 * semantic parity is returned as ENOTSUP, never fabricated from GmSSL
 * internals or silently reduced to a raw socket close.
 */
#include "cnet_tls_crypto_qualification.h"
#include "cnet_crypto_owner_admission.h"

#include <crypto/tls_ext.h>
#include <crypto/tls_auth.h>
#include <crypto/tls_peer.h>
#include <error_codes.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { CNET_CRYPTO_PATH_BYTES = 4096u };

struct cnet_tls_context {
    atomic_uint references;
    crypto_tls_provider *provider; /* borrowed; host keeps it alive */
    crypto_tls_session_options options;
    crypto_tls_auth_options_v1_3 auth;
    bool has_auth;
    size_t capacity;
    bool server;
    char hostname[CNET_TLS_SERVER_NAME_CAPACITY];
    char ca_file[CNET_CRYPTO_PATH_BYTES];
    char cert_file[CNET_CRYPTO_PATH_BYTES];
    char key_file[CNET_CRYPTO_PATH_BYTES];
    char key_password[CRYPTO_TLS_AUTH_MAX_PASSWORD_BYTES + 1u];
    size_t alpn_count;
    char alpn_storage[CRYPTO_TLS_ALPN_MAX_PROTOCOLS][CRYPTO_TLS_ALPN_MAX_NAME_BYTES + 1u];
    const char *alpn_names[CRYPTO_TLS_ALPN_MAX_PROTOCOLS];
};

typedef struct cnet_crypto_state {
    crypto_tls_session *session;
    crypto_tls_cipher_bio *bio;
    crypto_tls_io io;
    unsigned char *plaintext; /* never aliases NativeIO's receive lease */
    size_t plaintext_capacity;
    size_t plaintext_offset, plaintext_size;
    const unsigned char *write_source;
    size_t write_size, write_offset;
    uint32_t protocol;
    bool io_leased, handshake_started;
} cnet_crypto_state;

static cnet_crypto_state *get_engine(const cnet_tls_state *state)
{
    return state != NULL ? (cnet_crypto_state *)state->engine : NULL;
}

#if defined(CNET_CRYPTO_QUALIFICATION_TRACE)
#include <stdio.h>
/* TEST-ONLY numeric state diagnostics, bounded globally; never print
 * plaintext, records, keys, certificates, peer identity or buffers.
 */
/* C11 permits constant static initialization of an atomic integer.
 * MSVC /experimental:c11atomics rejects ATOMIC_VAR_INIT() here with C2099;
 * direct scalar initialization preserves the same 100-event bound.
 */
static atomic_uint crypto_test_log_remaining = 100u;
static void crypto_test_diag(
    const char *phase, const cnet_tls_state *state, int result,
    size_t count)
{
    unsigned remaining =
        atomic_load_explicit(&crypto_test_log_remaining, memory_order_relaxed);
    while (remaining != 0u &&
           !atomic_compare_exchange_weak_explicit(
               &crypto_test_log_remaining, &remaining, remaining - 1u,
               memory_order_relaxed, memory_order_relaxed)) {}
    if (remaining != 0u) {
        const cnet_crypto_state *eng = get_engine(state);
        crypto_tls_cipher_bio_snapshot snap = {0};
        int snapshot_ok = 0;
        if (eng && eng->bio) {
            snap.struct_size = sizeof(snap);
            snapshot_ok =
                crypto_tls_cipher_bio_get_snapshot(eng->bio, &snap)
                    == CRYPTO_TLS_OK;
        }
        fprintf(stderr,
          "CNET_CRYPTO_TEST_DIAG phase=%s server=%d handshake=%d"
          " tls_write_pending=%d write_offset=%zu write_total=%zu"
          " cipher_in=%zu cipher_out=%zu snapshot_ok=%d result=%d count=%zu\n",
          phase, state != NULL && state->server,
          state != NULL && state->handshake_complete,
          eng != NULL && eng->write_source != NULL,
          eng ? eng->write_offset : 0u, eng ? eng->write_size : 0u,
          snapshot_ok ? snap.input_pending : 0u,
          snapshot_ok ? snap.output_pending : 0u,
          snapshot_ok, result, count);
    }
}
#define CRYPTO_TEST_DIAG(phase, state, result, count) crypto_test_diag((phase), (state), (int)(result), (count))
#else
#define CRYPTO_TEST_DIAG(phase, state, result, count) ((void)0)
#endif

static int crypto_error(crypto_tls_result status)
{
    /* The additive CipherBIO CAPACITY code is intentionally not in the
     * original Crypto TLS enum. Avoid a non-enumerator switch case under
     * strict -Werror=switch while preserving all-or-nothing backpressure.
     */
    if (status == CRYPTO_TLS_BIO_CAPACITY) return SALTS_ENOBUFS;
    switch (status) {
    case CRYPTO_TLS_OK: return SALTS_OK;
    case CRYPTO_TLS_AGAIN: return SALTS_OK;
    case CRYPTO_TLS_BUSY: return SALTS_EBUSY;
    case CRYPTO_TLS_CANCELLED: return SALTS_ECANCELED;
    case CRYPTO_TLS_INVALID_ARGUMENT: return SALTS_EINVAL;
    case CRYPTO_TLS_OUT_OF_MEMORY: return SALTS_ENOMEM;
    case CRYPTO_TLS_CLOSED: return SALTS_ECONNABORTED;
    default: return SALTS_EPROTO;
    }
}

static void checked_copy(char *to, size_t capacity, const char *source)
{
    size_t bytes = strlen(source) + 1u; /* validated by admission first */
    if (bytes <= capacity)
        memcpy(to, source, bytes);
}

static int new_context(crypto_tls_provider *provider,
                       const crypto_tls_session_options *options,
                       const crypto_tls_auth_options_v1_3 *auth,
                       size_t cipher_capacity,
                       const char *const *alpn_names, size_t alpn_count,
                       cnet_tls_context **out_context)
{
    cnet_tls_context *ctx;
    size_t i;
    if (out_context == NULL || options == NULL || provider == NULL)
        return SALTS_EINVAL;
    *out_context = NULL;
    ctx = (cnet_tls_context *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) return SALTS_ENOMEM;
    atomic_init(&ctx->references, 1u);
    ctx->provider = provider;
    ctx->capacity = cipher_capacity;
    ctx->server = options->role == CRYPTO_TLS_SERVER;
    ctx->options = *options;
    if (options->hostname != NULL) {
        checked_copy(ctx->hostname, sizeof(ctx->hostname), options->hostname);
        ctx->options.hostname = ctx->hostname;
    }
    if (options->ca_file != NULL) {
        checked_copy(ctx->ca_file, sizeof(ctx->ca_file), options->ca_file);
        ctx->options.ca_file = ctx->ca_file;
    }
    if (options->certificate_file != NULL) {
        checked_copy(ctx->cert_file, sizeof(ctx->cert_file),
                     options->certificate_file);
        ctx->options.certificate_file = ctx->cert_file;
    }
    if (options->private_key_file != NULL) {
        checked_copy(ctx->key_file, sizeof(ctx->key_file),
                     options->private_key_file);
        ctx->options.private_key_file = ctx->key_file;
    }
    if (options->private_key_password != NULL) {
        checked_copy(ctx->key_password, sizeof(ctx->key_password),
                     options->private_key_password);
        ctx->options.private_key_password = ctx->key_password;
    }
    /* The public context MUST own every borrowed path/password before
     * the NativeIO Owner admits the first connection. The Crypto v1.3
     * constructor consumes these pointers synchronously in state_init().
     */
    if (auth != NULL) {
        ctx->auth = *auth;
        ctx->has_auth = true;
        if (auth->client_ca_file != NULL) {
            checked_copy(ctx->ca_file, sizeof(ctx->ca_file),
                         auth->client_ca_file);
            ctx->auth.client_ca_file = ctx->ca_file;
        }
        if (auth->client_certificate_file != NULL) {
            checked_copy(ctx->cert_file, sizeof(ctx->cert_file),
                         auth->client_certificate_file);
            ctx->auth.client_certificate_file = ctx->cert_file;
        }
        if (auth->client_private_key_file != NULL) {
            checked_copy(ctx->key_file, sizeof(ctx->key_file),
                         auth->client_private_key_file);
            ctx->auth.client_private_key_file = ctx->key_file;
        }
        if (auth->client_private_key_password != NULL) {
            checked_copy(ctx->key_password, sizeof(ctx->key_password),
                         auth->client_private_key_password);
            ctx->auth.client_private_key_password = ctx->key_password;
        }
    }
    if (alpn_count > CRYPTO_TLS_ALPN_MAX_PROTOCOLS ||
        (alpn_count != 0u && alpn_names == NULL)) {
        free(ctx);
        return SALTS_EINVAL;
    }
    /* Borrowed policy input ends here; reusable context owns its ALPN text. */
    for (i = 0u; i < alpn_count; ++i) {
        size_t length = strlen(alpn_names[i]);
        if (length == 0u || length > CRYPTO_TLS_ALPN_MAX_NAME_BYTES) {
            free(ctx);
            return SALTS_EINVAL;
        }
        memcpy(ctx->alpn_storage[i], alpn_names[i], length + 1u);
        ctx->alpn_names[i] = ctx->alpn_storage[i];
    }
    ctx->alpn_count = alpn_count;
    *out_context = ctx;
    return SALTS_OK;
}

int cnet_crypto_tls_test_client_context(
    crypto_tls_provider *provider, const cnet_tls_client_config *policy,
    const char *effective_dns_name, uint32_t exact_protocol,
    size_t cipher_capacity, cnet_tls_context **out_context)
{
    crypto_tls_session_options options = {0};
    crypto_tls_auth_options_v1_3 auth = {0};
    const crypto_tls_auth_options_v1_3 *selected_auth = NULL;
    int status;
    if (out_context == NULL) return SALTS_EINVAL;
    *out_context = NULL;
    if (provider == NULL) return SALTS_EINVAL;
    status = cnet_crypto_owner_admit_client(
        policy, effective_dns_name, exact_protocol, cipher_capacity,
        CNET_CRYPTO_OWNER_TEST_ONLY, &options);
    if (status != SALTS_OK) return status;
    if (policy->cert_file != NULL) {
        auth.struct_size = (uint32_t)sizeof(auth);
        auth.client_auth = CRYPTO_TLS_CLIENT_AUTH_NONE;
        auth.client_certificate_file = policy->cert_file;
        auth.client_private_key_file = policy->key_file;
        auth.client_private_key_password = policy->key_password;
        selected_auth = &auth;
    }
    return new_context(provider, &options, selected_auth, cipher_capacity,
                       policy->alpn_protocols, policy->alpn_protocol_count,
                       out_context);
}

int cnet_crypto_tls_test_server_context(
    crypto_tls_provider *provider, const cnet_tls_server_config *policy,
    uint32_t exact_protocol, size_t cipher_capacity,
    cnet_tls_context **out_context)
{
    crypto_tls_session_options options = {0};
    crypto_tls_auth_options_v1_3 auth = {0};
    const crypto_tls_auth_options_v1_3 *selected_auth = NULL;
    int status;
    if (out_context == NULL) return SALTS_EINVAL;
    *out_context = NULL;
    if (provider == NULL) return SALTS_EINVAL;
    status = cnet_crypto_owner_admit_server(
        policy, exact_protocol, cipher_capacity,
        CNET_CRYPTO_OWNER_TEST_ONLY, &options);
    if (status != SALTS_OK) return status;
    if (policy->client_auth == CNET_TLS_CLIENT_AUTH_REQUIRED) {
        auth.struct_size = (uint32_t)sizeof(auth);
        auth.client_auth = CRYPTO_TLS_CLIENT_AUTH_REQUIRED;
        auth.client_ca_file = policy->ca_file;
        selected_auth = &auth;
    }
    return new_context(provider, &options, selected_auth, cipher_capacity,
                       policy->alpn_protocols, policy->alpn_protocol_count,
                       out_context);
}

const char *cnet_crypto_tls_test_context_server_name(
    const cnet_tls_context *ctx)
{
    return ctx != NULL && !ctx->server && ctx->options.hostname != NULL
        ? ctx->options.hostname : NULL;
}

void cnet_tls_context_retain(cnet_tls_context *ctx)
{
    if (ctx != NULL)
        (void)atomic_fetch_add_explicit(
            &ctx->references, 1u, memory_order_relaxed);
}

void cnet_tls_context_release(cnet_tls_context *ctx)
{
    if (ctx != NULL &&
        atomic_fetch_sub_explicit(&ctx->references, 1u,
                                  memory_order_acq_rel) == 1u) {
        volatile char *wipe = (volatile char *)ctx->key_password;
        size_t i;
        for (i = 0u; i < sizeof(ctx->key_password); ++i) wipe[i] = 0;
        free(ctx);
    }
}

/* A success transfers exactly one caller-owned context reference to state.
 * On any error the context remains caller-owned and state remains zero.
 */
int cnet_tls_state_init(cnet_tls_state *state, cnet_tls_context *ctx,
                        bool server, const char *server_name,
                        size_t io_buffer_bytes)
{
    cnet_crypto_state *eng = NULL;
    unsigned char *read_buffer = NULL, *write_buffer = NULL;
    crypto_tls_result result;
    if (state == NULL || ctx == NULL || state->engine != NULL ||
        state->context != NULL || ctx->server != server ||
        io_buffer_bytes < CNET_TLS_MIN_IO_BUFFER_BYTES ||
        io_buffer_bytes > ctx->capacity)
        return SALTS_EINVAL;
    if (!server &&
        (server_name == NULL ||
         strcmp(server_name, ctx->options.hostname) != 0))
        return SALTS_EINVAL;

    eng = (cnet_crypto_state *)calloc(1u, sizeof(*eng));
    read_buffer = (unsigned char *)malloc(io_buffer_bytes);
    write_buffer = (unsigned char *)malloc(io_buffer_bytes);
    if (eng == NULL || read_buffer == NULL || write_buffer == NULL) {
        free(write_buffer);
        free(read_buffer);
        free(eng);
        return SALTS_ENOMEM;
    }
    eng->plaintext = (unsigned char *)malloc(io_buffer_bytes);
    if (eng->plaintext == NULL) goto failed;
    eng->plaintext_capacity = io_buffer_bytes;
    eng->protocol = ctx->options.protocol;
    result = crypto_tls_cipher_bio_create(ctx->capacity, &eng->bio);
    if (result != CRYPTO_TLS_OK) goto failed;
    result = crypto_tls_cipher_bio_acquire_io(eng->bio, &eng->io);
    if (result != CRYPTO_TLS_OK) goto failed;
    eng->io_leased = true;
    result = ctx->has_auth
        ? crypto_tls_session_create_auth_v1_3(
            ctx->provider, &ctx->options, &ctx->auth, &eng->io, &eng->session)
        : crypto_tls_session_create(
            ctx->provider, &ctx->options, &eng->io, &eng->session);
    if (result != CRYPTO_TLS_OK) goto failed;
    if (ctx->alpn_count != 0u) {
        if (crypto_tls_extension_abi_version() != CRYPTO_TLS_EXTENSION_ABI_VERSION)
            goto failed;
        result = crypto_tls_session_set_alpn_v1_1(
            eng->session, ctx->alpn_names, ctx->alpn_count);
        if (result != CRYPTO_TLS_OK) goto failed;
    }

    state->engine = eng;
    state->context = ctx;
    state->read_buffer = read_buffer;
    state->write_buffer = write_buffer;
    state->io_buffer_bytes = io_buffer_bytes;
    state->server = server;
    return SALTS_OK;

failed:
    if (eng != NULL) {
        if (eng->session != NULL)
            (void)crypto_tls_session_destroy(&eng->session);
        if (eng->io_leased)
            (void)crypto_tls_cipher_bio_release_io(eng->bio);
        if (eng->bio != NULL)
            (void)crypto_tls_cipher_bio_destroy(&eng->bio);
        free(eng->plaintext);
    }
    free(write_buffer);
    free(read_buffer);
    free(eng);
    return SALTS_EIO;
}

/* Caller must already have observed all terminal NativeIO completions,
 * stopped TLS callback entrants, and quiesced the single Owner. Since the
 * historic API is void, on an unexpected BUSY result we fail closed by
 * retaining the engine rather than risking freeing live callback storage.
 */
void cnet_tls_state_destroy(cnet_tls_state *state)
{
    cnet_crypto_state *eng = get_engine(state);
    cnet_tls_context *ctx;
    if (state == NULL || eng == NULL) return;
    if (crypto_tls_session_destroy(&eng->session) != CRYPTO_TLS_OK)
        return;
    if (eng->io_leased &&
        crypto_tls_cipher_bio_release_io(eng->bio) != CRYPTO_TLS_OK)
        return;
    eng->io_leased = false;
    if (crypto_tls_cipher_bio_destroy(&eng->bio) != CRYPTO_TLS_OK)
        return;
    ctx = state->context;
    free(eng->plaintext);
    free(eng);
    free(state->read_buffer);
    free(state->write_buffer);
    memset(state, 0, sizeof(*state));
    cnet_tls_context_release(ctx);
}

int cnet_tls_handshake(cnet_tls_state *state, bool *out_complete)
{
    cnet_crypto_state *eng = get_engine(state);
    crypto_tls_result result;
    if (eng == NULL || out_complete == NULL) return SALTS_EINVAL;
    *out_complete = state->handshake_complete;
    if (state->handshake_complete) return SALTS_OK;
    eng->handshake_started = true;
    result = crypto_tls_session_handshake(eng->session);
    if (result == CRYPTO_TLS_OK) {
        if (state->server && state->context->has_auth &&
            state->context->auth.client_auth == CRYPTO_TLS_CLIENT_AUTH_REQUIRED) {
            uint32_t authenticated = 0u;
            if (crypto_tls_session_client_authenticated_v1_3(
                    eng->session, &authenticated) != CRYPTO_TLS_OK
                || authenticated != 1u)
                return SALTS_EPROTO; /* NEVER publish CONNECTED */
        }
        if (state->context->alpn_count != 0u) {
            crypto_tls_session_info_v1_1 info = {0};
            info.struct_size = (uint32_t)sizeof(info);
            if (crypto_tls_session_get_info_v1_1(eng->session, &info) != CRYPTO_TLS_OK ||
                info.alpn_size > CRYPTO_TLS_ALPN_MAX_NAME_BYTES ||
                info.alpn_size >= sizeof(state->negotiated_alpn))
                return SALTS_EPROTO;
            if (info.alpn_size != 0u) {
                memcpy(state->negotiated_alpn, info.alpn, info.alpn_size);
                state->negotiated_alpn[info.alpn_size] = '\0';
                state->negotiated_alpn_size = info.alpn_size;
            }
        }
        CRYPTO_TEST_DIAG("handshake_complete", state, result, 0u);
        state->handshake_complete = true;
        *out_complete = true;
        return SALTS_OK;
    }
    if (result == CRYPTO_TLS_AGAIN) return SALTS_OK;
    return crypto_error(result);
}

bool cnet_tls_state_handshake_complete(const cnet_tls_state *state)
{
    return state != NULL && state->handshake_complete;
}

int cnet_tls_state_set_protocol_range(cnet_tls_state *state,
                                      cnet_tls_protocol_version min,
                                      cnet_tls_protocol_version max)
{
    cnet_crypto_state *eng = get_engine(state);
    const uint32_t requested =
        min == CNET_TLS_PROTOCOL_VERSION_1_2 &&
        max == CNET_TLS_PROTOCOL_VERSION_1_2 ? CRYPTO_TLS_1_2 :
        min == CNET_TLS_PROTOCOL_VERSION_1_3 &&
        max == CNET_TLS_PROTOCOL_VERSION_1_3 ? CRYPTO_TLS_1_3 : 0u;
    if (eng == NULL) return SALTS_EINVAL;
    if (eng->handshake_started || state->handshake_complete)
        return SALTS_EBUSY;
    /* Default/range semantics cannot be honestly represented by this
     * explicit one-version Crypto session. No implicit downgrade.
     */
    return requested != 0u && requested == eng->protocol
               ? SALTS_OK : SALTS_ENOTSUP;
}

void *cnet_tls_state_read_buffer(cnet_tls_state *state)
{
    return state != NULL ? state->read_buffer : NULL;
}

void *cnet_tls_state_write_buffer(cnet_tls_state *state)
{
    return state != NULL ? state->write_buffer : NULL;
}

size_t cnet_tls_state_io_buffer_bytes(const cnet_tls_state *state)
{
    return state != NULL ? state->io_buffer_bytes : 0u;
}

size_t cnet_tls_cipher_input_capacity(const cnet_tls_state *state)
{
    cnet_crypto_state *eng = get_engine(state);
    crypto_tls_cipher_bio_snapshot snap = {0};
    if (eng == NULL) return 0u;
    snap.struct_size = (uint32_t)sizeof(snap);
    if (crypto_tls_cipher_bio_get_snapshot(eng->bio, &snap) != CRYPTO_TLS_OK
        || snap.input_pending > snap.capacity)
        return 0u;
    return snap.capacity - snap.input_pending;
}

int cnet_tls_feed_cipher(cnet_tls_state *state, const void *data, size_t size)
{
    cnet_crypto_state *eng = get_engine(state);
    if (eng == NULL || data == NULL || size == 0u)
        return SALTS_EINVAL;
    {
        crypto_tls_result result = crypto_tls_cipher_bio_feed_cipher(
            eng->bio, (const uint8_t *)data, size);
        CRYPTO_TEST_DIAG("cipher_feed", state, result, size);
        return crypto_error(result);
    }
}

int cnet_tls_take_cipher(cnet_tls_state *state, void *buffer,
                         size_t capacity, size_t *out_size)
{
    cnet_crypto_state *eng = get_engine(state);
    crypto_tls_result result;
    if (out_size == NULL) return SALTS_EINVAL;
    *out_size = 0u;
    if (eng == NULL || buffer == NULL || capacity == 0u)
        return SALTS_EINVAL;
    result = crypto_tls_cipher_bio_take_cipher(
        eng->bio, (uint8_t *)buffer, capacity, out_size);
    if (result == CRYPTO_TLS_OK && *out_size != 0u)
        CRYPTO_TEST_DIAG("cipher_take", state, result, *out_size);
    if (result == CRYPTO_TLS_AGAIN) return SALTS_ENOENT;
    return crypto_error(result);
}

int cnet_tls_write(cnet_tls_state *state, const void *data,
                   size_t size, bool *out_complete)
{
    cnet_crypto_state *eng = get_engine(state);
    if (out_complete == NULL) return SALTS_EINVAL;
    *out_complete = false;
    if (eng == NULL || data == NULL || size == 0u) return SALTS_EINVAL;
    if (!state->handshake_complete || state->close_notify_started)
        return SALTS_ENOTCONN;
    CRYPTO_TEST_DIAG("write_begin", state, 0, size);
    if (eng->write_source == NULL) {
        eng->write_source = (const unsigned char *)data;
        eng->write_size = size;
        eng->write_offset = 0u;
    } else if (eng->write_source != data || eng->write_size != size)
        return SALTS_EBUSY;

    while (eng->write_offset < eng->write_size) {
        size_t accepted = 0u;
        size_t remaining = eng->write_size - eng->write_offset;
        crypto_tls_result result = crypto_tls_session_send(
            eng->session, eng->write_source + eng->write_offset,
            remaining, &accepted);
        if (result == CRYPTO_TLS_AGAIN) {
            CRYPTO_TEST_DIAG("write_again", state, result, remaining);
            return SALTS_OK;
        }
        if (result != CRYPTO_TLS_OK) {
            CRYPTO_TEST_DIAG("write_error", state, result, remaining);
            return crypto_error(result);
        }
        if (!accepted || accepted > remaining) return SALTS_EPROTO;
        eng->write_offset += accepted;
    }
    eng->write_source = NULL;
    eng->write_size = 0u;
    eng->write_offset = 0u;
    *out_complete = true;
    CRYPTO_TEST_DIAG("write_complete", state, 0, size);
    return SALTS_OK;
}

static int consume_plaintext(cnet_crypto_state *eng, void *data,
                             size_t capacity, size_t *out_size)
{
    size_t available, copy_size;
    if (eng->plaintext_size == eng->plaintext_offset)
        return SALTS_ENOENT;
    available = eng->plaintext_size - eng->plaintext_offset;
    copy_size = available < capacity ? available : capacity;
    memcpy(data, eng->plaintext + eng->plaintext_offset, copy_size);
    eng->plaintext_offset += copy_size;
    if (eng->plaintext_offset == eng->plaintext_size) {
        eng->plaintext_offset = 0u;
        eng->plaintext_size = 0u;
    }
    *out_size = copy_size;
    return SALTS_OK;
}

static int refill_plaintext(cnet_crypto_state *eng)
{
    crypto_tls_cipher_bio_snapshot snapshot = {0};
    size_t received = 0u;
    crypto_tls_result result;

    /* A CNet Owner no-demand probe is NOT permission to begin a new
     * underlying GmSSL receive when the input BIO has zero ciphertext.
     * GmSSL TLS1.2 forbids starting a send while its recv_state is pending.
     * Entering recv on an empty ring would leave that state waiting for
     * input from a peer that is itself waiting for our application send.
     *
     * Private plaintext scratch is >= 17KiB, exceeding one complete TLS
     * application record's 16KiB plaintext budget. A previous successful
     * refill consumes that complete record into eng->plaintext before any
     * no-input return here, so this guard does not discard plaintext.
     * If a partial TLS ciphertext record was already consumed internally,
     * the next NativeIO receive completion will add input and re-drive it.
     */
    snapshot.struct_size = (uint32_t)sizeof(snapshot);
    if (crypto_tls_cipher_bio_get_snapshot(eng->bio, &snapshot)
        != CRYPTO_TLS_OK || snapshot.input_pending > snapshot.capacity)
        return SALTS_EPROTO;
    if (snapshot.input_pending == 0u) {
        CRYPTO_TEST_DIAG("probe_no_cipher", NULL, CRYPTO_TLS_AGAIN, 0u);
        return SALTS_ENOENT;
    }
    result = crypto_tls_session_receive(
        eng->session, eng->plaintext, eng->plaintext_capacity, &received);
    if (result == CRYPTO_TLS_AGAIN) return SALTS_ENOENT;
    /* Crypto TLS's CLOSED may mean raw transport closure; it is not
     * independently proven authenticated close_notify. Never convert
     * this into CNet's peer_closed=true.
     */
    if (result == CRYPTO_TLS_CLOSED) return SALTS_ECONNABORTED;
    if (result != CRYPTO_TLS_OK) return crypto_error(result);
    if (!received || received > eng->plaintext_capacity)
        return SALTS_EPROTO;
    eng->plaintext_offset = 0u;
    eng->plaintext_size = received;
    return SALTS_OK;
}

int cnet_tls_read(cnet_tls_state *state, void *buffer, size_t capacity,
                  size_t *out_size, bool *out_peer_closed)
{
    cnet_crypto_state *eng = get_engine(state);
    int status;
    if (out_size == NULL || out_peer_closed == NULL) return SALTS_EINVAL;
    *out_size = 0u;
    *out_peer_closed = false;
    if (eng == NULL || buffer == NULL || !capacity) return SALTS_EINVAL;
    if (!state->handshake_complete) return SALTS_ENOTCONN;
    if (eng->write_source != NULL) return SALTS_OK;
    if (eng->plaintext_size == 0u) {
        status = refill_plaintext(eng);
        if (status == SALTS_ENOENT) return SALTS_OK;
        if (status != SALTS_OK) return status;
    }
    return consume_plaintext(eng, buffer, capacity, out_size);
}

int cnet_tls_probe_peer_close(cnet_tls_state *state, bool *out_peer_closed,
                              bool *out_plaintext_pending)
{
    cnet_crypto_state *eng = get_engine(state);
    int status;
    if (out_peer_closed == NULL || out_plaintext_pending == NULL)
        return SALTS_EINVAL;
    *out_peer_closed = false;
    *out_plaintext_pending = false;
    if (eng == NULL) return SALTS_EINVAL;
    if (!state->handshake_complete) return SALTS_ENOTCONN;
    if (eng->plaintext_size > eng->plaintext_offset) {
        *out_plaintext_pending = true;
        return SALTS_OK;
    }
    if (eng->write_source != NULL) return SALTS_OK;
    status = refill_plaintext(eng);
    if (status == SALTS_ENOENT) return SALTS_OK;
    if (status != SALTS_OK) return status;
    *out_plaintext_pending = true;
    return SALTS_OK;
}

int cnet_tls_shutdown(cnet_tls_state *state, bool *out_notify_generated,
                      bool *out_peer_notify_received)
{
    cnet_crypto_state *eng = get_engine(state);
    crypto_tls_cipher_bio_snapshot before = {0}, after = {0};
    crypto_tls_result result;
    if (state == NULL || out_notify_generated == NULL ||
        out_peer_notify_received == NULL || eng == NULL)
        return SALTS_EINVAL;
    *out_notify_generated = state->close_notify_started;
    /* This test-only Crypto v1.0 TLS API has no authenticated
     * peer-close-notify inspection. Do not convert CRYPTO_TLS_CLOSED,
     * transport EOF, or a locally queued shutdown into peer consent.
     * Production CNet's direct TLS owner uses tls_get_peer_close_notify().
     * The deferred capability gap belongs to production Provider #81.
     */
    *out_peer_notify_received = false;
    if (!state->handshake_complete) return SALTS_ENOTCONN;
    if (eng->write_source != NULL) return SALTS_EBUSY;

    /* CNet's close contract is "close_notify ciphertext was generated",
     * NOT "GmSSL has received the peer close_notify". The backend can
     * successfully enqueue the complete outbound alert and then return
     * CRYPTO_TLS_AGAIN while awaiting the peer's reciprocal alert.
     *
     * Once queued, the CNet Owner holds the exact ciphertext via NativeIO
     * until a real matching write terminal, then finalizes the session.
     * The sticky flag prevents a second tls_shutdown from waiting for a
     * peer alert after that write has completed.
     */
    if (state->close_notify_started) {
        CRYPTO_TEST_DIAG("shutdown_sticky", state, 0, 1u);
        return SALTS_OK;
    }

    before.struct_size = (uint32_t)sizeof(before);
    if (crypto_tls_cipher_bio_get_snapshot(eng->bio, &before) != CRYPTO_TLS_OK
        || before.output_pending > before.capacity)
        return SALTS_EPROTO;
    if (before.output_pending != 0u) {
        /* Drain pre-existing application ciphertext FIRST. Otherwise a
         * partially admitted close_notify could masquerade as a complete
         * fatal/close Alert when the bounded BIO has little free space.
         */
        CRYPTO_TEST_DIAG("shutdown_drain_prior_cipher", state, 0,
                         before.output_pending);
        return SALTS_OK;
    }

    CRYPTO_TEST_DIAG("shutdown_begin", state, 0, 0u);
    result = crypto_tls_session_shutdown(eng->session);
    after.struct_size = (uint32_t)sizeof(after);
    if (crypto_tls_cipher_bio_get_snapshot(eng->bio, &after) != CRYPTO_TLS_OK
        || after.output_pending > after.capacity)
        return SALTS_EPROTO;
    /* A genuine TLS close_notify record was enqueued into the EMPTY,
     * >=17 KiB output BIO. We never infer authenticated peer closure
     * from TCP EOF or from CRYPTO_TLS_CLOSED.
     */
    if (after.output_pending > before.output_pending)
        state->close_notify_started = true;
    *out_notify_generated = state->close_notify_started;
    CRYPTO_TEST_DIAG("shutdown_result", state, result,
                     after.output_pending);

    if (result == CRYPTO_TLS_AGAIN)
        return SALTS_OK; /* alert is queued; peer's alert may be pending */
    if (result == CRYPTO_TLS_OK && state->close_notify_started)
        return SALTS_OK;
    /* Do not report successful terminal close if the backend generated
     * no TLS alert, even if its internal shutdown says "complete".
     */
    return result == CRYPTO_TLS_OK ? SALTS_EPROTO : crypto_error(result);
}

int cnet_crypto_tls_test_transport_eof(cnet_tls_state *state)
{
    cnet_crypto_state *eng = get_engine(state);
    return eng == NULL ? SALTS_EINVAL :
        crypto_error(crypto_tls_cipher_bio_end_input(eng->bio));
}

int cnet_tls_get_negotiated_alpn(const cnet_tls_state *state,
                                 const unsigned char **out_data,
                                 size_t *out_size)
{
    if (out_data == NULL || out_size == NULL) return SALTS_EINVAL;
    *out_data = NULL;
    *out_size = 0u;
    if (get_engine(state) == NULL) return SALTS_EINVAL;
    if (!state->handshake_complete) return SALTS_ENOTCONN;
    if (state->negotiated_alpn_size == 0u) return SALTS_ENOENT;
    *out_data = state->negotiated_alpn; /* bounded state-owned borrow */
    *out_size = state->negotiated_alpn_size;
    return SALTS_OK;
}

static int inspected(const cnet_tls_state *state,
                     crypto_tls_session_info_v1_1 *info)
{
    cnet_crypto_state *eng = get_engine(state);
    if (eng == NULL || !state->handshake_complete)
        return SALTS_ENOTCONN;
    memset(info, 0, sizeof(*info));
    info->struct_size = (uint32_t)sizeof(*info);
    if (crypto_tls_extension_abi_version() != CRYPTO_TLS_EXTENSION_ABI_VERSION)
        return SALTS_ENOTSUP;
    return crypto_error(crypto_tls_session_get_info_v1_1(eng->session, info));
}

static int copy_name(const cnet_tls_state *state, const char *value,
                     char *buffer, size_t capacity, size_t *out_size)
{
    size_t length;
    if (out_size == NULL || buffer == NULL || capacity == 0u)
        return SALTS_EINVAL;
    *out_size = 0u;
    buffer[0] = '\0';
    if (state == NULL || !state->handshake_complete)
        return SALTS_ENOTCONN;
    if (value == NULL || !value[0]) return SALTS_ENOENT;
    length = strlen(value);
    if (capacity <= length) return SALTS_EMSGSIZE;
    memcpy(buffer, value, length + 1u);
    *out_size = length;
    return SALTS_OK;
}

int cnet_tls_state_negotiated_version(const cnet_tls_state *state,
                                      char *buffer, size_t capacity,
                                      size_t *out_size)
{
    crypto_tls_session_info_v1_1 info;
    const char *name;
    int status = inspected(state, &info);
    if (status != SALTS_OK) {
        if (out_size != NULL) *out_size = 0u;
        if (buffer != NULL && capacity != 0u) buffer[0] = '\0';
        return status; /* never downgrade unsupported ABI to ENOENT */
    }
    name = info.protocol == CRYPTO_TLS_1_2 ? "TLSv1.2" :
           info.protocol == CRYPTO_TLS_1_3 ? "TLSv1.3" : NULL;
    return name == NULL ? SALTS_EPROTO :
           copy_name(state, name, buffer, capacity, out_size);
}

int cnet_tls_state_negotiated_cipher(const cnet_tls_state *state,
                                     char *buffer, size_t capacity,
                                     size_t *out_size)
{
    crypto_tls_session_info_v1_1 info;
    int status = inspected(state, &info);
    if (status != SALTS_OK) {
        if (out_size != NULL) *out_size = 0u;
        if (buffer != NULL && capacity != 0u) buffer[0] = '\0';
        return status; /* never downgrade unsupported ABI to ENOENT */
    }
    return copy_name(state, info.cipher_name, buffer, capacity, out_size);
}

int cnet_tls_state_peer_certificate_sha256(
    const cnet_tls_state *state,
    char buffer[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[CRYPTO_TLS_PEER_SHA256_BYTES];
    crypto_tls_result result;
    cnet_crypto_state *eng = get_engine(state);
    if (buffer == NULL || state == NULL) return SALTS_EINVAL;
    buffer[0] = '\0';
    if (eng == NULL || !state->handshake_complete)
        return SALTS_ENOTCONN;
    if (crypto_tls_peer_abi_version() != CRYPTO_TLS_PEER_ABI_VERSION)
        return SALTS_ENOTSUP;
    result = crypto_tls_session_peer_sha256_v1_2(eng->session, digest);
    if (result == CRYPTO_TLS_PEER_CERT_ABSENT) return SALTS_ENOENT;
    if (result != CRYPTO_TLS_OK) return crypto_error(result);
    for (size_t i = 0u; i < sizeof(digest); ++i) {
        buffer[i * 2u] = hex[digest[i] >> 4u];
        buffer[i * 2u + 1u] = hex[digest[i] & 0x0fu];
    }
    buffer[sizeof(digest) * 2u] = '\0';
    memset(digest, 0, sizeof(digest));
    return SALTS_OK;
}

/* Missing RFC5929 per-signature certificate-digest selection, parser and
 * verified close-notify introspection stay fail-closed. */
int cnet_tls_server_end_point_binding_from_certificate(
    const uint8_t *certificate, size_t certificate_size,
    uint8_t *output, size_t capacity, size_t *out_size)
{
    if (output == NULL || out_size == NULL || !capacity ||
        certificate == NULL || !certificate_size)
        return SALTS_EINVAL;
    memset(output, 0, capacity < CNET_TLS_SERVER_END_POINT_MAX_BYTES ?
           capacity : CNET_TLS_SERVER_END_POINT_MAX_BYTES);
    *out_size = 0u;
    return SALTS_ENOTSUP;
}

int cnet_tls_state_server_end_point_binding(const cnet_tls_state *state,
                                            uint8_t *output, size_t capacity,
                                            size_t *out_size)
{
    if (output == NULL || out_size == NULL || !capacity)
        return SALTS_EINVAL;
    memset(output, 0, capacity < CNET_TLS_SERVER_END_POINT_MAX_BYTES ?
           capacity : CNET_TLS_SERVER_END_POINT_MAX_BYTES);
    *out_size = 0u;
    return get_engine(state) == NULL ? SALTS_ENOTCONN : SALTS_ENOTSUP;
}

int cnet_tls_peer_certificate_chain_parse(
    const uint8_t *data, size_t size, cnet_tls_peer_certificate_chain *out)
{
    if (out == NULL) return SALTS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (data == NULL || !size) return SALTS_ENOENT;
    return SALTS_ENOTSUP;
}

int cnet_tls_state_peer_certificate_chain(const cnet_tls_state *state,
                                          cnet_tls_peer_certificate_chain *out)
{
    if (out == NULL) return SALTS_EINVAL;
    memset(out, 0, sizeof(*out));
    return get_engine(state) == NULL ? SALTS_ENOTCONN : SALTS_ENOTSUP;
}

int cnet_tls_state_export_channel_binding(
    const cnet_tls_state *state,
    uint8_t output[CNET_TLS_CHANNEL_BINDING_BYTES])
{
    cnet_crypto_state *eng = get_engine(state);
    crypto_tls_result result;
    if (output == NULL) return SALTS_EINVAL;
    memset(output, 0, CNET_TLS_CHANNEL_BINDING_BYTES);
    if (eng == NULL || !state->handshake_complete) return SALTS_ENOTCONN;
    if (crypto_tls_peer_abi_version() != CRYPTO_TLS_PEER_ABI_VERSION)
        return SALTS_ENOTSUP;
    result = crypto_tls_session_export_v1_2(
        eng->session, "EXPORTER-Channel-Binding", NULL, 0u, 1u,
        output, CNET_TLS_CHANNEL_BINDING_BYTES);
    if (result != CRYPTO_TLS_OK) {
        memset(output, 0, CNET_TLS_CHANNEL_BINDING_BYTES);
        return crypto_error(result);
    }
    return SALTS_OK;
}
