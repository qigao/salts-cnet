/* SPDX-License-Identifier: Apache-2.0
 * Bounded, CNet-style ciphertext BIO for the opaque Crypto C11 TLS API.
 *
 * This host-side helper does not link/contain GmSSL or TLS key material.
 * The parent owner drives TLS + NativeIO completions on ONE thread.
 * Only cancel() is callable concurrently. A completed/cancelled NativeIO
 * operation must relinquish borrowed buffers before destroying this BIO.
 */
#ifndef CRYPTO_TLS_CIPHER_BIO_H_INCLUDED
#define CRYPTO_TLS_CIPHER_BIO_H_INCLUDED

#include <crypto/export.h>

#include <crypto/tls.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_tls_cipher_bio crypto_tls_cipher_bio;

#define CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY ((size_t)(17u * 1024u))
#define CRYPTO_TLS_CIPHER_BIO_MAX_CAPACITY ((size_t)(1024u * 1024u))

/* Distinguish an all-or-nothing input admission refusal from an active
 * TLS operation's CRYPTO_TLS_BUSY. No data is copied on BIO_CAPACITY.
 */
#define CRYPTO_TLS_BIO_CAPACITY ((crypto_tls_result)-9)

typedef struct crypto_tls_cipher_bio_snapshot {
    uint32_t struct_size;
    uint32_t input_eof;
    size_t capacity;
    size_t input_pending;
    size_t output_pending;
} crypto_tls_cipher_bio_snapshot;

/* BIO owns two private, fixed-capacity ciphertext rings. No native
 * handles, sockets, plaintext or GmSSL state are allocated by this module.
 */
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_create(
    size_t capacity, crypto_tls_cipher_bio **out_bio);

/* Borrowed IO descriptor for exactly one Crypto TLS session. Bind BEFORE
 * session_create(); release only AFTER the session was destroyed and all
 * TLS drives have returned. Underlying user pointer and callbacks remain
 * stable; rebind while leased returns BUSY.
 *
 * destroy() MUST return BUSY for any outstanding descriptor lease, even
 * after cancel. Host must quiesce both TLS owner and NativeIO completions.
 */
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_acquire_io(
    crypto_tls_cipher_bio *bio, crypto_tls_io *out_io);
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_release_io(
    crypto_tls_cipher_bio *bio);

/* CNet cnet_tls_feed_cipher equivalent. All-or-nothing admission: the
 * entire size is copied, or BIO_CAPACITY with unchanged input ring.
 * Caller retains its source bytes only until this call returns.
 * Valid only on the single TLS/NativeIO Owner thread. */
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_feed_cipher(
    crypto_tls_cipher_bio *bio, const uint8_t *cipher, size_t size);

/* CNet cnet_tls_take_cipher equivalent. Returns up to capacity bytes in
 * FIFO order; AGAIN/empty sets out_size=0 and changes no output bytes.
 * Caller owns the copied data and must retain any NativeIO send backing
 * until its terminal completion before reusing/freeing it. */
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_take_cipher(
    crypto_tls_cipher_bio *bio, uint8_t *cipher, size_t capacity,
    size_t *out_size);

/* NativeIO receive EOF. Already queued ciphertext is still readable; when
 * its input ring drains, the TLS read callback returns 0 for transport EOF.
 * This does NOT fabricate a TLS close_notify or claim authenticated close.
 */
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_end_input(
    crypto_tls_cipher_bio *bio);

/* Atomic cancellation flag: may be invoked from a different thread or
 * TLS callback. All subsequent IO callbacks return IO_ERROR; it never
 * destroys TLS state or borrowed NativeIO buffers.
 */
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_cancel(
    crypto_tls_cipher_bio *bio);

/* Owner-thread snapshot. The provided struct_size must match exactly.
 * Unchanged on failure. Capacity is per direction, not combined.
 */
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_get_snapshot(
    const crypto_tls_cipher_bio *bio,
    crypto_tls_cipher_bio_snapshot *out_snapshot);

/* Fail closed while a TLS IO lease or a callback remains in-flight.
 * Caller must separately synchronize ALL potential entrants, including
 * another thread that could still call cancel() using this pointer.
 * The function cannot make arbitrary stale caller pointers safe.
 */
SALTS_CRYPTO_EXPORT
crypto_tls_result crypto_tls_cipher_bio_destroy(
    crypto_tls_cipher_bio **bio);

#ifdef __cplusplus
}
#endif
#endif
