/* SPDX-License-Identifier: Apache-2.0
 * Additive opaque TLS v1.4 authenticated peer close_notify status.
 * Never infer this flag from transport EOF or a locally generated alert.
 */
#ifndef CRYPTO_TLS_CLOSE_H_INCLUDED
#define CRYPTO_TLS_CLOSE_H_INCLUDED

#include <crypto/tls.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_TLS_CLOSE_ABI_VERSION UINT32_C(0x00010004)

CRYPTO_TLS_API uint32_t crypto_tls_close_abi_version(void);

/* Returns the backend's authenticated/decrypted peer close_notify evidence.
 * On success, *out_received is 0 or 1. On error, output remains unchanged.
 * CRYPTO_TLS_AGAIN means the handshake is not completed. Concurrent drive
 * returns BUSY; cancelled sessions return CANCELLED. This is observational:
 * it never drives I/O, flushes alerts, or changes ownership. The result is
 * not a synonym for CRYPTO_TLS_CLOSED or a TCP half-close.
 */
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_peer_close_notify_v1_4(
    crypto_tls_session *session, uint32_t *out_received);

#ifdef __cplusplus
}
#endif
#endif
