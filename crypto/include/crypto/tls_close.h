/* SPDX-License-Identifier: Apache-2.0
 * Additive, provider-neutral v1.4 authenticated peer close_notify report.
 *
 * No TLS_CONNECT/GmSSL backend state or borrowed pointers escape this API.
 * This interface does NOT alter the original crypto_tls_session ABI marker,
 * the session options layout, or GmSSL's public source ABI.
 */
#ifndef CRYPTO_TLS_CLOSE_H_INCLUDED
#define CRYPTO_TLS_CLOSE_H_INCLUDED

#include <crypto/tls.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_TLS_CLOSE_ABI_VERSION UINT32_C(0x00010004)

CRYPTO_TLS_API uint32_t crypto_tls_close_abi_version(void);

/* Read only after the real peer Finished/authenticated handshake.
 * OK writes 0 or 1 into *out_received: 1 means the backend successfully
 * authenticated, decrypted and parsed the PEER's close_notify alert.
 * A locally generated alert, transport EOF, fatal alert, a CLOSED result
 * or a partial TLS record can NEVER establish this bit.
 *
 * Returns AGAIN while handshaking, CANCELLED after cancellation, BUSY
 * during a concurrent drive operation. All errors, including NULL session,
 * leave the caller-owned output unchanged. No transport I/O occurs here.
 * Callers must serialize lifetime against session_destroy().
 */
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_peer_close_notify_v1_4(
    crypto_tls_session *session, uint32_t *out_received);

#ifdef __cplusplus
}
#endif
#endif /* CRYPTO_TLS_CLOSE_H_INCLUDED */
