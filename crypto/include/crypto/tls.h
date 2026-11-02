/* SPDX-License-Identifier: Apache-2.0
 * Versioned, provider-neutral C11 TLS interface.
 * This public header NEVER includes GmSSL headers or exposes TLS_CTX/TLS_CONNECT.
 */
#ifndef CRYPTO_TLS_H_INCLUDED
#define CRYPTO_TLS_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_TLS_API

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_TLS_ABI_VERSION UINT32_C(0x00010000)

typedef struct crypto_tls_provider crypto_tls_provider;
typedef struct crypto_tls_session crypto_tls_session;

/* No fallback and no automatic trust relaxation on any negative result. */
typedef enum crypto_tls_result {
    CRYPTO_TLS_OK = 0,
    CRYPTO_TLS_AGAIN = 1,
    CRYPTO_TLS_INVALID_ARGUMENT = -1,
    CRYPTO_TLS_OUT_OF_MEMORY = -2,
    CRYPTO_TLS_BACKEND_ERROR = -3,
    CRYPTO_TLS_BUSY = -4,
    CRYPTO_TLS_CANCELLED = -5,
    CRYPTO_TLS_CLOSED = -6
} crypto_tls_result;

/* CLOSED alone does not authenticate a peer close_notify; use tls_close.h.
 * A fatal record error or transport EOF remains terminal across subsequent
 * send/receive/shutdown calls. A verified peer alert still permits sending
 * the reciprocal alert through shutdown. */

typedef enum crypto_tls_role {
    CRYPTO_TLS_SERVER = 0,
    CRYPTO_TLS_CLIENT = 1
} crypto_tls_role;

typedef enum crypto_tls_protocol {
    CRYPTO_TLS_1_2 = 0x0303,
    CRYPTO_TLS_1_3 = 0x0304
} crypto_tls_protocol;

/* Callbacks return bytes (1..len), 0 for transport EOF, -1 for would-block
 * or -2 for fatal transport error. Never return more than len.
 * The callback user pointer and all pointed-to data remain borrowed.
 * A callback may request cancellation but may not recursively drive the
 * same session. No socket is owned or closed by the Crypto Provider. */
#define CRYPTO_TLS_IO_AGAIN INT64_C(-1)
#define CRYPTO_TLS_IO_ERROR INT64_C(-2)

typedef int64_t (*crypto_tls_write_fn)(
    void *user, const uint8_t *bytes, size_t len);
typedef int64_t (*crypto_tls_read_fn)(
    void *user, uint8_t *bytes, size_t capacity);

typedef struct crypto_tls_io {
    uint32_t struct_size;
    uint32_t reserved;
    void *user;
    crypto_tls_write_fn write;
    crypto_tls_read_fn read;
} crypto_tls_io;

typedef struct crypto_tls_session_options {
    uint32_t struct_size;
    uint32_t protocol;        /* crypto_tls_protocol; TLS 1.2/1.3 only */
    uint32_t role;            /* crypto_tls_role */
    uint32_t verify_depth;    /* 0 = default 4; valid range 1..5 */
    const char *hostname;     /* mandatory for client; SAN verified */
    const char *ca_file;      /* mandatory for client; no implicit system CA */
    const char *certificate_file; /* mandatory for server */
    const char *private_key_file; /* mandatory for server */
    const char *private_key_password; /* NULL is equivalent to "" */
    uint32_t reserved_flags;  /* must be zero */
} crypto_tls_session_options;

CRYPTO_TLS_API uint32_t crypto_tls_abi_version(void);

/* Closing a provider while it still owns sessions returns BUSY and leaves
 * the handle unchanged. Caller must serialize provider open/close vs new
 * sessions; the implementation does not guarantee safety after free. */
CRYPTO_TLS_API crypto_tls_result crypto_tls_provider_create(
    uint32_t requested_abi, crypto_tls_provider **out_provider);
CRYPTO_TLS_API crypto_tls_result crypto_tls_provider_destroy(
    crypto_tls_provider **provider);
CRYPTO_TLS_API crypto_tls_result crypto_tls_provider_session_count(
    crypto_tls_provider *provider, uint32_t *out_count);

/* Each live session is owned by one caller at a time: overlapping drive,
 * send, receive, shutdown or destroy returns BUSY. cancel() may be invoked
 * from another thread or from a transport callback. Destruction must be
 * retried after in-flight operations have returned; never race it with a
 * fresh entry on the same pointer. */
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_create(
    crypto_tls_provider *provider,
    const crypto_tls_session_options *options,
    const crypto_tls_io *io,
    crypto_tls_session **out_session);
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_handshake(
    crypto_tls_session *session);
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_send(
    crypto_tls_session *session, const uint8_t *data,
    size_t len, size_t *out_sent);
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_receive(
    crypto_tls_session *session, uint8_t *data,
    size_t capacity, size_t *out_received);
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_shutdown(
    crypto_tls_session *session);
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_cancel(
    crypto_tls_session *session);
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_destroy(
    crypto_tls_session **session);

#ifdef __cplusplus
}
#endif
#endif
