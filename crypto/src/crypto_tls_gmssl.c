/* SPDX-License-Identifier: Apache-2.0
 * Private GmSSL 3.2 adapter; never included in the installed SDK.
 */
#include <crypto/tls.h>
#include <crypto/tls_ext.h>
#include <crypto/tls_peer.h>
#include <crypto/tls_auth.h>
#include <crypto/tls_close.h>
#include <gmssl/tls.h>
#include <gmssl/x509_cer.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef CRYPTO_TLS_PRIVATE_TEST_HANDSHAKE_TRACE
#include <stdio.h>
#endif

struct crypto_tls_provider {
    atomic_uint sessions;
};

struct crypto_tls_session {
    crypto_tls_provider *owner;
    atomic_flag in_use;
    atomic_bool cancelled;
    int context_initialized;
    int connection_initialized;
    int handshake_started;
    int auth_required;
    int auth_configured;
    int auth_verified;
    uint32_t auth_protocol;
    crypto_tls_result terminal_handshake_error;
    crypto_tls_result terminal_io_error;
    /* Serialized by in_use; an AGAIN send owns the provider record scratch
     * until the identical range is retried successfully or the session ends. */
    const uint8_t *pending_send;
    size_t pending_send_size;
    int shutdown_started;
    int alpn_configured;
    size_t alpn_count;
    char alpn_storage[CRYPTO_TLS_ALPN_MAX_PROTOCOLS][
        CRYPTO_TLS_ALPN_MAX_NAME_BYTES + 1u];
    char *alpn_names[CRYPTO_TLS_ALPN_MAX_PROTOCOLS];
    crypto_tls_io transport;
    TLS_CTX context;
    TLS_CONNECT connection;
};

/* Only the adapter owns raw TLS_CTX, TLS_CONNECT and callback state. */
static tls_ret_t bridge_send(void *user, const void *bytes, size_t len, int flags)
{
    crypto_tls_session *s = (crypto_tls_session *)user;
    int64_t n;
    (void)flags;
    if (!s || !bytes || !len || !s->transport.write
        || atomic_load_explicit(&s->cancelled, memory_order_acquire))
        return TLS_ERROR_SYSCALL;
    n = s->transport.write(s->transport.user, (const uint8_t *)bytes, len);
    if (n == CRYPTO_TLS_IO_AGAIN) return TLS_ERROR_SEND_AGAIN;
    if (n == 0) return TLS_ERROR_TCP_CLOSED;
    if (n <= 0 || (uint64_t)n > (uint64_t)len || n > INT_MAX)
        return TLS_ERROR_SYSCALL;
    return (tls_ret_t)n;
}

static tls_ret_t bridge_recv(void *user, void *bytes, size_t len, int flags)
{
    crypto_tls_session *s = (crypto_tls_session *)user;
    int64_t n;
    (void)flags;
    if (!s || !bytes || !len || !s->transport.read
        || atomic_load_explicit(&s->cancelled, memory_order_acquire))
        return TLS_ERROR_SYSCALL;
    n = s->transport.read(s->transport.user, (uint8_t *)bytes, len);
    if (n == CRYPTO_TLS_IO_AGAIN) return TLS_ERROR_RECV_AGAIN;
    if (n == 0) return TLS_ERROR_TCP_CLOSED;
    if (n <= 0 || (uint64_t)n > (uint64_t)len || n > INT_MAX)
        return TLS_ERROR_SYSCALL;
    return (tls_ret_t)n;
}

static crypto_tls_result lock_session(crypto_tls_session *s)
{
    if (!s) return CRYPTO_TLS_INVALID_ARGUMENT;
    if (atomic_flag_test_and_set_explicit(&s->in_use, memory_order_acquire))
        return CRYPTO_TLS_BUSY;
    return CRYPTO_TLS_OK;
}

static void unlock_session(crypto_tls_session *s)
{
    atomic_flag_clear_explicit(&s->in_use, memory_order_release);
}

static crypto_tls_result map_backend_result(int result)
{
    if (result == 1) return CRYPTO_TLS_OK;
    if (result == TLS_ERROR_SEND_AGAIN || result == TLS_ERROR_RECV_AGAIN)
        return CRYPTO_TLS_AGAIN;
    if (result == TLS_ERROR_TCP_CLOSED) return CRYPTO_TLS_CLOSED;
    return CRYPTO_TLS_BACKEND_ERROR;
}

/* A record/transport failure is terminal even if a later backend shutdown
 * would report local completion. Authenticated peer close remains readable
 * while permitting the one reciprocal outbound alert. */
static crypto_tls_result record_io_result(crypto_tls_session *s, int result)
{
    crypto_tls_result status = map_backend_result(result);
    int received = 0;
    if (result == 0 || result == TLS_ERROR_TCP_CLOSED) {
        if (tls_get_peer_close_notify(&s->connection, &received) != 1)
            status = CRYPTO_TLS_BACKEND_ERROR;
        else if (received == 1)
            return CRYPTO_TLS_CLOSED;
    }
    if (status < CRYPTO_TLS_OK) s->terminal_io_error = status;
    return status;
}

#ifdef CRYPTO_TLS_PRIVATE_TEST_HANDSHAKE_TRACE
/* Private test build only: publish ONLY state/type/length metadata.
 * Never log peer bytes, nonces, certificates, transcript, keys, or alerts.
 * This is not a public API or a production logging facility.
 */
static void trace_server_handshake_failure(const TLS_CONNECT *c, int ret)
{
    size_t available = c->recordlen;
    unsigned type = 0u, version = 0u, handshake_type = 0u;
    size_t declared_record = 0u, handshake_length = 0u;
    if (c->is_client) return;
    if (available >= 5u && available <= sizeof(c->record)) {
        type = c->record[0];
        version = ((unsigned)c->record[1] << 8) | c->record[2];
        declared_record = ((size_t)c->record[3] << 8) | c->record[4];
        if (type == TLS_record_handshake && available >= 9u) {
            handshake_type = c->record[5];
            handshake_length = ((size_t)c->record[6] << 16) |
                ((size_t)c->record[7] << 8) | c->record[8];
        }
    }
    fprintf(stderr,
        "CRYPTO_TLS_PRIVATE_HANDSHAKE_DIAG ret=%d state=%d"
        " recordlen=%zu record_offset=%zu type=%u version=%u"
        " wire_payload=%zu handshake_type=%u handshake_body=%zu"
        " available_body=%zu\n",
        ret, c->handshake_state, available, c->record_offset, type,
        version, declared_record, handshake_type, handshake_length,
        available >= 9u ? available - 9u : 0u);
}
#endif

/* TLS1.2 server keeps the client's validated chain in client_certs, while
 * TLS1.3 uses peer_cert_chain. GmSSL has already verified trust, clientAuth
 * EKU and CertificateVerify before reporting handshake completion.
 */
static crypto_tls_result completed_handshake(crypto_tls_session *s)
{
    int complete = 0, verify = -1, ret;
    const uint8_t *chain = NULL;
    size_t chain_len = 0u;
    if (s->terminal_handshake_error != CRYPTO_TLS_OK)
        return s->terminal_handshake_error;
    if (tls_get_handshake_complete(&s->connection, &complete) != 1)
        return CRYPTO_TLS_BACKEND_ERROR;
    if (!complete) return CRYPTO_TLS_AGAIN;
    if (!s->auth_required || s->auth_verified) return CRYPTO_TLS_OK;
    if (s->auth_protocol == CRYPTO_TLS_1_2) {
        chain = s->connection.client_certs;
        chain_len = s->connection.client_certs_len;
        ret = chain_len ? 1 : 0;
    } else {
        ret = tls_get_peer_certificate_chain(
            &s->connection, &chain, &chain_len);
    }
    if (ret != 1 || !chain || !chain_len
        || chain_len > CRYPTO_TLS_PEER_CHAIN_MAX_BYTES
        || tls_get_verify_result(&s->connection, &verify) != 1
        || verify != X509_verify_ok) {
        s->terminal_handshake_error = CRYPTO_TLS_AUTH_REJECTED;
        return CRYPTO_TLS_AUTH_REJECTED;
    }
    s->auth_verified = 1;
    return CRYPTO_TLS_OK;
}

uint32_t crypto_tls_abi_version(void)
{
    return CRYPTO_TLS_ABI_VERSION;
}

crypto_tls_result crypto_tls_provider_create(
    uint32_t requested_abi, crypto_tls_provider **out_provider)
{
    crypto_tls_provider *p;
    if (!out_provider) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_provider = NULL;
    if (requested_abi != CRYPTO_TLS_ABI_VERSION)
        return CRYPTO_TLS_INVALID_ARGUMENT;
    p = (crypto_tls_provider *)calloc(1, sizeof(*p));
    if (!p) return CRYPTO_TLS_OUT_OF_MEMORY;
    atomic_init(&p->sessions, 0u);
    *out_provider = p;
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_provider_destroy(crypto_tls_provider **provider)
{
    crypto_tls_provider *p;
    if (!provider || !*provider) return CRYPTO_TLS_INVALID_ARGUMENT;
    p = *provider;
    if (atomic_load_explicit(&p->sessions, memory_order_acquire))
        return CRYPTO_TLS_BUSY;
    *provider = NULL;
    free(p);
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_provider_session_count(
    crypto_tls_provider *provider, uint32_t *out_count)
{
    if (!provider || !out_count) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_count = atomic_load_explicit(&provider->sessions, memory_order_acquire);
    return CRYPTO_TLS_OK;
}

static int valid_options(const crypto_tls_session_options *o)
{
    if (!o || o->struct_size != sizeof(*o) || o->reserved_flags != 0
        || (o->protocol != CRYPTO_TLS_1_2 && o->protocol != CRYPTO_TLS_1_3)
        || (o->role != CRYPTO_TLS_CLIENT && o->role != CRYPTO_TLS_SERVER)
        || o->verify_depth > TLS_MAX_VERIFY_DEPTH)
        return 0;
    if (o->role == CRYPTO_TLS_CLIENT) {
        if (!o->ca_file || !o->ca_file[0] || !o->hostname
            || !o->hostname[0] || strlen(o->hostname) >= 256)
            return 0;
    } else {
        if (!o->certificate_file || !o->certificate_file[0]
            || !o->private_key_file || !o->private_key_file[0])
            return 0;
    }
    return 1;
}

/* Strict additive authentication configuration. The legacy struct stays
 * layout-identical; strings are borrowed only until create returns.
 */
static int bounded_text(const char *text, size_t maximum, int allow_empty)
{
    size_t i;
    if (!text) return 0;
    for (i = 0u; i <= maximum; ++i) {
        if (text[i] == '\0') return allow_empty || i != 0u;
    }
    return 0;
}

static int valid_auth_options(
    const crypto_tls_session_options *o,
    const crypto_tls_auth_options_v1_3 *a)
{
    /* The legacy v1.0 validator uses strlen(hostname). The additive
     * bounded v1.3 entry MUST check the client hostname before entering
     * that validator; otherwise a nonterminated hostname could trigger an
     * unbounded scan, contradicting the new API's 255-byte admission.
     */
    if (!o || o->struct_size != sizeof(*o)
        || (o->role == CRYPTO_TLS_CLIENT &&
            !bounded_text(o->hostname, 255u, 0)))
        return 0;
    if (!valid_options(o) || !a || a->struct_size != sizeof(*a)
        || a->reserved_flags || a->reserved
        || (a->client_auth != CRYPTO_TLS_CLIENT_AUTH_NONE
            && a->client_auth != CRYPTO_TLS_CLIENT_AUTH_REQUIRED))
        return 0;
    if (o->role == CRYPTO_TLS_CLIENT) {
        if (a->client_auth != CRYPTO_TLS_CLIENT_AUTH_NONE
            || a->client_ca_file || o->certificate_file
            || o->private_key_file || o->private_key_password
            || (!!a->client_certificate_file != !!a->client_private_key_file)
            || (a->client_private_key_password && !a->client_private_key_file)
            || !bounded_text(o->hostname, 255u, 0)
            || !bounded_text(o->ca_file, CRYPTO_TLS_AUTH_MAX_PATH_BYTES, 0))
            return 0;
        if (a->client_certificate_file
            && (!bounded_text(a->client_certificate_file,
                    CRYPTO_TLS_AUTH_MAX_PATH_BYTES, 0)
                || !bounded_text(a->client_private_key_file,
                    CRYPTO_TLS_AUTH_MAX_PATH_BYTES, 0)))
            return 0;
    } else {
        if (o->ca_file || a->client_certificate_file
            || a->client_private_key_file || a->client_private_key_password
            || !bounded_text(o->certificate_file,
                CRYPTO_TLS_AUTH_MAX_PATH_BYTES, 0)
            || !bounded_text(o->private_key_file,
                CRYPTO_TLS_AUTH_MAX_PATH_BYTES, 0))
            return 0;
        if (a->client_auth == CRYPTO_TLS_CLIENT_AUTH_REQUIRED) {
            if (!bounded_text(a->client_ca_file,
                    CRYPTO_TLS_AUTH_MAX_PATH_BYTES, 0))
                return 0;
        } else if (a->client_ca_file) return 0;
        if (o->private_key_password && !bounded_text(
                o->private_key_password, CRYPTO_TLS_AUTH_MAX_PASSWORD_BYTES, 1))
            return 0;
    }
    if (a->client_private_key_password && !bounded_text(
            a->client_private_key_password, CRYPTO_TLS_AUTH_MAX_PASSWORD_BYTES, 1))
        return 0;
    return 1;
}

uint32_t crypto_tls_auth_abi_version(void)
{
    return CRYPTO_TLS_AUTH_ABI_VERSION;
}

static crypto_tls_result create_session_impl(
    crypto_tls_provider *provider, const crypto_tls_session_options *options,
    const crypto_tls_auth_options_v1_3 *auth,
    const crypto_tls_io *io, crypto_tls_session **out_session)
{
    crypto_tls_session *s;
    TLS_IO callbacks;
    int cipher;
    int group = TLS_curve_secp256r1;
    int signatures[2];
    size_t sig_count;
    int depth;
    const char *identity_cert;
    const char *identity_key;
    const char *identity_password;
    const char *verification_ca;
    if (!out_session) return CRYPTO_TLS_INVALID_ARGUMENT;
    if (!provider || !valid_options(options)
        || !io || io->struct_size != sizeof(*io) || io->reserved != 0
        || !io->read || !io->write)
        return CRYPTO_TLS_INVALID_ARGUMENT;

    s = (crypto_tls_session *)calloc(1, sizeof(*s));
    if (!s) return CRYPTO_TLS_OUT_OF_MEMORY;
    atomic_flag_clear(&s->in_use);
    atomic_init(&s->cancelled, 0);
    s->owner = provider;
    s->transport = *io;
    s->auth_required = auth && options->role == CRYPTO_TLS_SERVER
        && auth->client_auth == CRYPTO_TLS_CLIENT_AUTH_REQUIRED;
    /* Also seal client-identity sessions on fatal handshake failure.
     * A rejected client certificate or verified server trust failure must
     * never be retried on the same native TLS association.
     */
    s->auth_configured = s->auth_required ||
        (auth && options->role == CRYPTO_TLS_CLIENT
         && auth->client_certificate_file != NULL);
    s->auth_protocol = options->protocol;
    identity_cert = auth && options->role == CRYPTO_TLS_CLIENT
        ? auth->client_certificate_file : options->certificate_file;
    identity_key = auth && options->role == CRYPTO_TLS_CLIENT
        ? auth->client_private_key_file : options->private_key_file;
    identity_password = auth && options->role == CRYPTO_TLS_CLIENT
        ? auth->client_private_key_password : options->private_key_password;
    verification_ca = s->auth_required
        ? auth->client_ca_file : options->ca_file;
    depth = options->verify_depth ? (int)options->verify_depth : TLS_DEFAULT_VERIFY_DEPTH;
    cipher = options->protocol == CRYPTO_TLS_1_3
        ? TLS_cipher_aes_128_gcm_sha256
        : TLS_cipher_ecdhe_rsa_with_aes_128_gcm_sha256;
    signatures[0] = options->protocol == CRYPTO_TLS_1_3
        ? TLS_sig_rsa_pss_rsae_sha256 : TLS_sig_rsa_pkcs1_sha256;
    signatures[1] = TLS_sig_rsa_pkcs1_sha256;
    sig_count = options->protocol == CRYPTO_TLS_1_3 ? 2u : 1u;

    if (tls_ctx_init(&s->context, (int)options->protocol,
            (int)options->role) != 1)
        goto fail;
    s->context_initialized = 1;
    if (tls_ctx_set_cipher_suites(&s->context, &cipher, 1u) != 1
        || tls_ctx_set_supported_groups(&s->context, &group, 1u) != 1
        || tls_ctx_set_signature_algorithms(&s->context, signatures, sig_count) != 1)
        goto fail;
    /* RFC 5746 secure renegotiation *signaling* on the initial TLS 1.2
     * server handshake. Independent OpenSSL3 clients send
     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV and require an empty
     * renegotiation_info response. GmSSL's known-good native CLI enables
     * tls12_ctx_set_renegotiation_info() before tls_init(), but the
     * opaque server adapter previously omitted it.
     *
     * This DOES NOT allow application-triggered renegotiation. Keep the
     * original signature, transcript/Finished checks and CA/SAN policy.
     */
    if (options->role == CRYPTO_TLS_SERVER
        && options->protocol == CRYPTO_TLS_1_2
        && tls12_ctx_set_renegotiation_info(&s->context, 1) != 1)
        goto fail;
    /* RFC 8446 section 5.1 optional compatibility ChangeCipherSpec.
     * OpenSSL3 middlebox-mode clients may send a one-byte dummy CCS
     * after ClientHello. Accept ONLY a correctly framed CCS using GmSSL's
     * existing validated optional-record reader; never treat a Finished
     * or unexpected encrypted record as a CCS, and never bypass MAC
     * or transcript authentication. This is not TLS 1.2 renegotiation.
     */
    if (options->role == CRYPTO_TLS_SERVER
        && options->protocol == CRYPTO_TLS_1_3
        && tls13_ctx_set_accept_change_cipher_spec(&s->context, 1) != 1)
        goto fail;
    /* Both trust and certificate-request policy precede tls_init(). */
    if (verification_ca && verification_ca[0]
        && tls_ctx_set_ca_certificates(&s->context, verification_ca, depth) != 1)
        goto fail;
    if (s->auth_required
        && (tls_ctx_enable_certificate_request(&s->context, 1) != 1
            || tls_ctx_enable_client_certificate_optional(&s->context, 0) != 1))
        goto fail;
    if (identity_cert && identity_key
        && tls_ctx_set_certificate_and_key(&s->context,
            identity_cert, identity_key,
            identity_password ? identity_password : "") != 1)
        goto fail;

    if (tls_init(&s->connection, &s->context) != 1) goto fail;
    s->connection_initialized = 1;
    if (options->role == CRYPTO_TLS_CLIENT
        && (tls_set_hostname(&s->connection, options->hostname) != 1
            || tls_set_server_name(&s->connection) != 1))
        goto fail;
    callbacks.user = s;
    callbacks.send = bridge_send;
    callbacks.recv = bridge_recv;
    if (tls_set_io(&s->connection, &callbacks) != 1)
        goto fail;

    if (atomic_fetch_add_explicit(&provider->sessions, 1u, memory_order_acq_rel)
        == UINT_MAX) {
        atomic_fetch_sub_explicit(&provider->sessions, 1u, memory_order_acq_rel);
        goto fail;
    }
    *out_session = s;
    return CRYPTO_TLS_OK;

fail:
    if (s->connection_initialized) tls_cleanup(&s->connection);
    if (s->context_initialized) tls_ctx_cleanup(&s->context);
    free(s);
    return CRYPTO_TLS_BACKEND_ERROR;
}

/* v1.0 output remains NULL on failure; v1.3 leaves it unchanged. */
crypto_tls_result crypto_tls_session_create(
    crypto_tls_provider *provider, const crypto_tls_session_options *options,
    const crypto_tls_io *io, crypto_tls_session **out_session)
{
    if (!out_session) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_session = NULL;
    return create_session_impl(provider, options, NULL, io, out_session);
}

crypto_tls_result crypto_tls_session_create_auth_v1_3(
    crypto_tls_provider *provider, const crypto_tls_session_options *options,
    const crypto_tls_auth_options_v1_3 *auth,
    const crypto_tls_io *io, crypto_tls_session **out_session)
{
    if (!out_session || !valid_auth_options(options, auth))
        return CRYPTO_TLS_INVALID_ARGUMENT;
    return create_session_impl(provider, options, auth, io, out_session);
}

crypto_tls_result crypto_tls_session_handshake(crypto_tls_session *s)
{
    crypto_tls_result status = lock_session(s);
    int result;
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_CANCELLED;
    } else {
        status = completed_handshake(s);
        if (status == CRYPTO_TLS_AGAIN) {
            /* Admission is serialized by in_use; reject ALPN mutation after
             * any TLS handshake I/O has started, even if it later fails.
             */
            s->handshake_started = 1;
#ifdef CRYPTO_TLS_PRIVATE_TEST_HANDSHAKE_TRACE
            int observed_state_before = s->connection.handshake_state;
#endif
            result = tls_do_handshake(&s->connection);
#ifdef CRYPTO_TLS_PRIVATE_TEST_HANDSHAKE_TRACE
            if (!s->connection.is_client) {
                int after = s->connection.handshake_state;
                if (after != observed_state_before || result != TLS_ERROR_RECV_AGAIN) {
                    fprintf(stderr,
                        "CRYPTO_TLS_PRIVATE_STATE protocol=%d before=%d after=%d result=%d\n",
                        s->connection.protocol, observed_state_before, after, result);
                }
            }
#endif
#ifdef CRYPTO_TLS_PRIVATE_TEST_HANDSHAKE_TRACE
            if (result != 1 &&
                result != TLS_ERROR_SEND_AGAIN &&
                result != TLS_ERROR_RECV_AGAIN)
                trace_server_handshake_failure(&s->connection, result);
#endif
            status = map_backend_result(result);
            if (status == CRYPTO_TLS_OK)
                status = completed_handshake(s);
            if (s->auth_configured &&
                (status == CRYPTO_TLS_BACKEND_ERROR
                    || status == CRYPTO_TLS_CLOSED))
                s->terminal_handshake_error = status;
        }
        if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
            status = CRYPTO_TLS_CANCELLED;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_client_authenticated_v1_3(
    crypto_tls_session *s, uint32_t *out_authenticated)
{
    crypto_tls_result status;
    if (!out_authenticated) return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (!s->auth_required) {
        status = CRYPTO_TLS_INVALID_ARGUMENT;
    } else if (atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_CANCELLED;
    } else {
        status = completed_handshake(s);
        if (status == CRYPTO_TLS_OK && !s->auth_verified)
            status = CRYPTO_TLS_AUTH_REJECTED;
        if (status == CRYPTO_TLS_OK) *out_authenticated = 1u;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_send(
    crypto_tls_session *s, const uint8_t *data, size_t len, size_t *out_sent)
{
    crypto_tls_result status;
    size_t n = 0;
    if (!out_sent) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_sent = 0;
    if (!data || !len) return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
        status = CRYPTO_TLS_CANCELLED;
    else if (s->terminal_io_error != CRYPTO_TLS_OK)
        status = s->terminal_io_error;
    else if (s->shutdown_started)
        status = CRYPTO_TLS_CLOSED;
    else if (s->pending_send &&
        (s->pending_send != data || s->pending_send_size != len))
        status = CRYPTO_TLS_BUSY;
    else if ((status = completed_handshake(s)) == CRYPTO_TLS_OK) {
        status = record_io_result(s, tls_send(&s->connection, data, len, &n));
        if (status == CRYPTO_TLS_AGAIN) {
            s->pending_send = data;
            s->pending_send_size = len;
        } else {
            s->pending_send = NULL;
            s->pending_send_size = 0u;
        }
        if (status == CRYPTO_TLS_OK) {
            if (!n || n > len)
                status = s->terminal_io_error = CRYPTO_TLS_BACKEND_ERROR;
            else *out_sent = n;
        }
        if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
            status = CRYPTO_TLS_CANCELLED;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_receive(
    crypto_tls_session *s, uint8_t *data, size_t capacity,
    size_t *out_received)
{
    crypto_tls_result status;
    size_t n = 0;
    if (!out_received) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_received = 0;
    if (!data || !capacity) return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
        status = CRYPTO_TLS_CANCELLED;
    else if (s->terminal_io_error != CRYPTO_TLS_OK)
        status = s->terminal_io_error;
    else if (s->pending_send)
        status = CRYPTO_TLS_BUSY;
    else if ((status = completed_handshake(s)) == CRYPTO_TLS_OK) {
        int peer_closed = 0;
        if (tls_get_peer_close_notify(&s->connection, &peer_closed) != 1)
            status = s->terminal_io_error = CRYPTO_TLS_BACKEND_ERROR;
        else if (peer_closed == 1)
            status = CRYPTO_TLS_CLOSED;
        else
            status = record_io_result(s, tls_recv(&s->connection, data, capacity, &n));
        if (status == CRYPTO_TLS_OK) {
            if (!n || n > capacity)
                status = s->terminal_io_error = CRYPTO_TLS_BACKEND_ERROR;
            else *out_received = n;
        }
        if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
            status = CRYPTO_TLS_CANCELLED;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_shutdown(crypto_tls_session *s)
{
    crypto_tls_result status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
        status = CRYPTO_TLS_CANCELLED;
    else if (s->terminal_io_error != CRYPTO_TLS_OK)
        status = s->terminal_io_error;
    else if (s->pending_send)
        status = CRYPTO_TLS_BUSY;
    else if (s->auth_configured &&
        s->terminal_handshake_error != CRYPTO_TLS_OK)
        status = s->terminal_handshake_error;
    else {
        s->shutdown_started = 1;
        status = record_io_result(s, tls_shutdown(&s->connection));
        if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
            status = CRYPTO_TLS_CANCELLED;
    }
    unlock_session(s);
    return status;
}

uint32_t crypto_tls_close_abi_version(void)
{
    return CRYPTO_TLS_CLOSE_ABI_VERSION;
}

crypto_tls_result crypto_tls_session_peer_close_notify_v1_4(
    crypto_tls_session *s, uint32_t *out_received)
{
    crypto_tls_result status;
    if (!out_received) return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_CANCELLED;
    } else {
        /* This flag is set by GmSSL ONLY while handling a successfully
         * authenticated/decrypted TLS 1.2 or 1.3 peer alert. Never derive
         * evidence from a local send, return code, TCP EOF or shutdown_state.
         * completed_handshake also rejects unverified client authentication.
         */
        status = completed_handshake(s);
        if (status == CRYPTO_TLS_OK) {
            int received = 0;
            if (tls_get_peer_close_notify(&s->connection, &received) != 1)
                status = CRYPTO_TLS_BACKEND_ERROR;
            else if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
                status = CRYPTO_TLS_CANCELLED;
            else
                *out_received = received == 1 ? 1u : 0u;
        }
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_cancel(crypto_tls_session *s)
{
    if (!s) return CRYPTO_TLS_INVALID_ARGUMENT;
    atomic_store_explicit(&s->cancelled, 1, memory_order_release);
    return CRYPTO_TLS_OK;
}

/* Additive v1.1 extension; the v1 ABI marker remains unchanged. */
uint32_t crypto_tls_extension_abi_version(void)
{
    return CRYPTO_TLS_EXTENSION_ABI_VERSION;
}

crypto_tls_result crypto_tls_get_features_v1_1(uint64_t *out_features)
{
    if (!out_features) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_features =
        CRYPTO_TLS_FEATURE_TLS12_ECDHE_RSA |
        CRYPTO_TLS_FEATURE_TLS13_RSA_PSS |
        CRYPTO_TLS_FEATURE_EXPLICIT_CA_FILE |
        CRYPTO_TLS_FEATURE_DNS_SAN |
        CRYPTO_TLS_FEATURE_TEXT_ALPN |
        CRYPTO_TLS_FEATURE_SESSION_INFO;
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_session_set_alpn_v1_1(
    crypto_tls_session *s, const char *const *names, size_t count)
{
    crypto_tls_result status;
    size_t i, j, wire_total = 0u;
    size_t lengths[CRYPTO_TLS_ALPN_MAX_PROTOCOLS] = {0};
    if (!names || !count || count > CRYPTO_TLS_ALPN_MAX_PROTOCOLS)
        return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;

    if (s->handshake_started || s->alpn_configured
        || atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_INVALID_ARGUMENT;
        goto finished;
    }

    /* Full validation before modifying the native TLS_CTX borrowed list. */
    for (i = 0u; i < count; ++i) {
        size_t len = 0u;
        if (!names[i]) {
            status = CRYPTO_TLS_INVALID_ARGUMENT;
            goto finished;
        }
        while (len <= CRYPTO_TLS_ALPN_MAX_NAME_BYTES && names[i][len])
            ++len;
        if (!len || len > CRYPTO_TLS_ALPN_MAX_NAME_BYTES
            || wire_total > 128u - (len + 1u)) {
            status = CRYPTO_TLS_INVALID_ARGUMENT;
            goto finished;
        }
        for (j = 0u; j < len; ++j) {
            unsigned char c = (unsigned char)names[i][j];
            if (c < 0x21u || c > 0x7eu) {
                status = CRYPTO_TLS_INVALID_ARGUMENT;
                goto finished;
            }
        }
        for (j = 0u; j < i; ++j) {
            if (lengths[j] == len && memcmp(names[i], names[j], len) == 0) {
                status = CRYPTO_TLS_INVALID_ARGUMENT;
                goto finished;
            }
        }
        lengths[i] = len;
        wire_total += len + 1u;
    }

    for (i = 0u; i < count; ++i) {
        memcpy(s->alpn_storage[i], names[i], lengths[i]);
        s->alpn_storage[i][lengths[i]] = '\0';
        s->alpn_names[i] = s->alpn_storage[i];
    }
    /* The GmSSL setter borrows both the char** and its strings. Both live
     * inside the opaque session; no stack pointer or caller buffer escapes.
     */
    if (tls_ctx_set_application_layer_protocol_negotiation(
            &s->context, s->alpn_names, count) != 1) {
        status = CRYPTO_TLS_BACKEND_ERROR;
        goto finished;
    }
    s->alpn_count = count;
    s->alpn_configured = 1;
    status = CRYPTO_TLS_OK;
finished:
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_get_info_v1_1(
    crypto_tls_session *s, crypto_tls_session_info_v1_1 *out_info)
{
    crypto_tls_session_info_v1_1 temp;
    crypto_tls_result status;
    const char *cipher_name = NULL;
    const char *selected = NULL;
    int protocol = 0, cipher = 0, ret;
    size_t i, cipher_len = 0u, selected_len = 0u;
    int found = 0;
    if (!out_info || out_info->struct_size != sizeof(*out_info))
        return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_CANCELLED;
        goto finished;
    }
    status = completed_handshake(s);
    if (status != CRYPTO_TLS_OK) goto finished;

    if (tls_get_negotiated_protocol(&s->connection, &protocol) != 1
        || (protocol != TLS_protocol_tls12 && protocol != TLS_protocol_tls13)
        || tls_get_negotiated_cipher_suite(&s->connection, &cipher) != 1
        || cipher <= 0
        || tls_get_negotiated_cipher_name(&s->connection, &cipher_name) != 1
        || !cipher_name) {
        status = CRYPTO_TLS_BACKEND_ERROR;
        goto finished;
    }
    while (cipher_len < CRYPTO_TLS_CIPHER_NAME_CAPACITY &&
           cipher_name[cipher_len]) ++cipher_len;
    if (!cipher_len || cipher_len >= CRYPTO_TLS_CIPHER_NAME_CAPACITY) {
        status = CRYPTO_TLS_BACKEND_ERROR;
        goto finished;
    }

    memset(&temp, 0, sizeof(temp));
    temp.struct_size = sizeof(temp);
    temp.protocol = (uint32_t)protocol;
    temp.cipher_suite = (uint32_t)cipher;
    memcpy(temp.cipher_name, cipher_name, cipher_len);
    temp.cipher_name[cipher_len] = '\0';

    ret = tls_get_selected_alpn(&s->connection, &selected, &selected_len);
    if (ret < 0) {
        status = CRYPTO_TLS_BACKEND_ERROR;
        goto finished;
    }
    if (ret == 1) {
        if (!selected || !selected_len
            || selected_len > CRYPTO_TLS_ALPN_MAX_NAME_BYTES) {
            status = CRYPTO_TLS_BACKEND_ERROR;
            goto finished;
        }
        for (i = 0; i < s->alpn_count; ++i) {
            if (strlen(s->alpn_storage[i]) == selected_len
                && memcmp(s->alpn_storage[i], selected, selected_len) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            /* A selected protocol must come from this session's owned
             * offered list, never an untracked backend/caller pointer.
             */
            status = CRYPTO_TLS_BACKEND_ERROR;
            goto finished;
        }
        memcpy(temp.alpn, selected, selected_len);
        temp.alpn[selected_len] = '\0';
        temp.alpn_size = (uint32_t)selected_len;
    }
    *out_info = temp;
    status = CRYPTO_TLS_OK;
finished:
    unlock_session(s);
    return status;
}

/* Independent additive TLS v1.2 peer and exporter ABI. */
uint32_t crypto_tls_peer_abi_version(void)
{
    return CRYPTO_TLS_PEER_ABI_VERSION;
}

crypto_tls_result crypto_tls_peer_features_v1_2(uint64_t *out_features)
{
    if (!out_features) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_features =
        CRYPTO_TLS_PEER_FEATURE_DER_CHAIN_COPY |
        CRYPTO_TLS_PEER_FEATURE_CERT_SHA256 |
        CRYPTO_TLS_PEER_FEATURE_TLS_EXPORTER;
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_session_copy_peer_chain_v1_2(
    crypto_tls_session *s, uint8_t *out, size_t capacity, size_t *out_size)
{
    crypto_tls_result status;
    const uint8_t *chain = NULL;
    size_t length = 0u;
    int ret;

    if (!out_size || (!out && capacity))
        return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_CANCELLED;
        goto finished;
    }
    status = completed_handshake(s);
    if (status != CRYPTO_TLS_OK) goto finished;
    ret = tls_get_peer_certificate_chain(&s->connection, &chain, &length);
    if (ret == 0) {
        status = CRYPTO_TLS_PEER_CERT_ABSENT;
        goto finished;
    }
    if (ret != 1 || !chain || !length
        || length > CRYPTO_TLS_PEER_CHAIN_MAX_BYTES) {
        status = CRYPTO_TLS_BACKEND_ERROR;
        goto finished;
    }
    if (!out && capacity == 0u) {
        *out_size = length;
        status = CRYPTO_TLS_OK;
        goto finished;
    }
    if (capacity < length) {
        /* Only the required size changes on a buffer-too-small error. */
        *out_size = length;
        status = CRYPTO_TLS_PEER_BUFFER_TOO_SMALL;
        goto finished;
    }
    memcpy(out, chain, length);
    *out_size = length;
    status = CRYPTO_TLS_OK;
finished:
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_peer_sha256_v1_2(
    crypto_tls_session *s, uint8_t out[CRYPTO_TLS_PEER_SHA256_BYTES])
{
    crypto_tls_result status;
    uint8_t digest[CRYPTO_TLS_PEER_SHA256_BYTES] = {0};
    size_t i;
    int ret;
    if (!out) return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_CANCELLED;
        goto finished;
    }
    status = completed_handshake(s);
    if (status != CRYPTO_TLS_OK) goto finished;
    ret = tls_get_peer_certificate_sha256(&s->connection, digest);
    if (ret == 0) {
        status = CRYPTO_TLS_PEER_CERT_ABSENT;
        goto finished;
    }
    if (ret != 1) {
        status = CRYPTO_TLS_BACKEND_ERROR;
        goto finished;
    }
    memcpy(out, digest, sizeof(digest));
    status = CRYPTO_TLS_OK;
finished:
    {
        volatile uint8_t *wipe = digest;
        for (i = 0u; i < sizeof(digest); ++i) wipe[i] = 0u;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_export_v1_2(
    crypto_tls_session *s, const char *label,
    const uint8_t *context, size_t context_len, uint32_t use_context,
    uint8_t *out, size_t out_len)
{
    crypto_tls_result status;
    uint8_t material[CRYPTO_TLS_EXPORTER_MAX_BYTES] = {0};
    size_t label_len = 0u, i;

    if (!out || !label || !out_len
        || out_len > CRYPTO_TLS_EXPORTER_MAX_BYTES
        || context_len > CRYPTO_TLS_EXPORTER_MAX_CONTEXT_BYTES
        || (context_len && !context) || use_context > 1u)
        return CRYPTO_TLS_INVALID_ARGUMENT;
    /* Bounded readable label, no embedded controls or non-ASCII values. */
    while (label_len <= CRYPTO_TLS_EXPORTER_MAX_LABEL_BYTES &&
           label[label_len]) {
        unsigned char byte = (unsigned char)label[label_len];
        if (byte < 0x21u || byte > 0x7eu)
            return CRYPTO_TLS_INVALID_ARGUMENT;
        ++label_len;
    }
    if (!label_len || label_len > CRYPTO_TLS_EXPORTER_MAX_LABEL_BYTES)
        return CRYPTO_TLS_INVALID_ARGUMENT;

    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_CANCELLED;
        goto finished;
    }
    status = completed_handshake(s);
    if (status != CRYPTO_TLS_OK) goto finished;

    if (tls_export_keying_material(
            &s->connection, material, out_len, label,
            context, context_len, (int)use_context) != 1) {
        status = CRYPTO_TLS_BACKEND_ERROR;
        goto finished;
    }
    memcpy(out, material, out_len);
    status = CRYPTO_TLS_OK;
finished:
    {
        volatile uint8_t *wipe = material;
        for (i = 0u; i < sizeof(material); ++i) wipe[i] = 0u;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_destroy(crypto_tls_session **session)
{
    crypto_tls_session *s;
    crypto_tls_result status;
    if (!session || !*session) return CRYPTO_TLS_INVALID_ARGUMENT;
    s = *session;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    atomic_store_explicit(&s->cancelled, 1, memory_order_release);
    if (s->connection_initialized) tls_cleanup(&s->connection);
    if (s->context_initialized) tls_ctx_cleanup(&s->context);
    atomic_fetch_sub_explicit(&s->owner->sessions, 1u, memory_order_acq_rel);
    *session = NULL;
    free(s);
    return CRYPTO_TLS_OK;
}
