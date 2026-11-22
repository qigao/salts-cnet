/* SPDX-License-Identifier: Apache-2.0
 * Additive TLS v1.1 capability/ALPN/inspection extension.
 * TLS v1.0 ABI remains CRYPTO_TLS_ABI_VERSION, unchanged and linkable.
 * No GmSSL types or backend pointers cross this boundary.
 */
#ifndef CRYPTO_TLS_EXT_H_INCLUDED
#define CRYPTO_TLS_EXT_H_INCLUDED

#include <crypto/tls.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_TLS_EXTENSION_ABI_VERSION UINT32_C(0x00010001)
#define CRYPTO_TLS_ALPN_MAX_PROTOCOLS 8u
#define CRYPTO_TLS_ALPN_MAX_NAME_BYTES 127u
#define CRYPTO_TLS_CIPHER_NAME_CAPACITY 128u

/* Bits deliberately exclude: system CA stores/path, ALPN arbitrary binary
 * labels, certificate-chain/exporter/peer fingerprint APIs, client mTLS,
 * TLCP, ShangMi and DTLS. Future features must be explicitly admitted.
 */
#define CRYPTO_TLS_FEATURE_TLS12_ECDHE_RSA  (UINT64_C(1) << 0)
#define CRYPTO_TLS_FEATURE_TLS13_RSA_PSS    (UINT64_C(1) << 1)
#define CRYPTO_TLS_FEATURE_EXPLICIT_CA_FILE (UINT64_C(1) << 2)
#define CRYPTO_TLS_FEATURE_DNS_SAN          (UINT64_C(1) << 3)
#define CRYPTO_TLS_FEATURE_TEXT_ALPN        (UINT64_C(1) << 4)
#define CRYPTO_TLS_FEATURE_SESSION_INFO     (UINT64_C(1) << 5)
/* X.509 certificate signatures using RSAE, MGF1-SHA256 and a 32-byte salt. */
#define CRYPTO_TLS_FEATURE_X509_RSA_PSS_SHA256 (UINT64_C(1) << 6)
/* TLS 1.2 certificate signatures using a P-384 issuer and SHA-512. */
#define CRYPTO_TLS_FEATURE_TLS12_X509_ECDSA_P384_SHA512 (UINT64_C(1) << 7)

/* Output is fully owned by the caller, and is unchanged on non-OK results. */
typedef struct crypto_tls_session_info_v1_1 {
    uint32_t struct_size;
    uint32_t protocol;       /* CRYPTO_TLS_1_2 or CRYPTO_TLS_1_3 */
    uint32_t cipher_suite;   /* IANA numeric cipher suite ID */
    uint32_t alpn_size;      /* 0 when no ALPN selected */
    char cipher_name[CRYPTO_TLS_CIPHER_NAME_CAPACITY];
    char alpn[CRYPTO_TLS_ALPN_MAX_NAME_BYTES + 1u];
} crypto_tls_session_info_v1_1;

/* A host must independently admit the v1.1 extension before using it.
 * The original crypto_tls_abi_version() stays 0x00010000 by design.
 */
CRYPTO_TLS_API uint32_t crypto_tls_extension_abi_version(void);

/* Exact feature bitmap for THIS shipped backend/profile configuration;
 * unsupported capabilities are never emulated through an OpenSSL fallback.
 */
CRYPTO_TLS_API crypto_tls_result crypto_tls_get_features_v1_1(
    uint64_t *out_features);

/* Configure text ALPN labels once, before ANY handshake attempt.
 * The API deep-copies 1..8 borrowed NUL-terminated printable ASCII names
 * of length 1..127, total wire payload bounded to 128 bytes. The
 * resulting strings remain owned by the session until quiescent destroy;
 * never borrowed from caller storage once this function returns.
 * Reconfiguration or use after handshake start fails closed.
 */
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_set_alpn_v1_1(
    crypto_tls_session *session,
    const char *const *protocol_names, size_t count);

/* Only valid after authenticated handshake. On AGAIN / CANCELLED / BUSY /
 * any error, out_info is left unchanged. All inspection uses private GmSSL
 * getters and copies data; no GmSSL string pointer escapes the DLL.
 */
CRYPTO_TLS_API crypto_tls_result crypto_tls_session_get_info_v1_1(
    crypto_tls_session *session, crypto_tls_session_info_v1_1 *out_info);

#ifdef __cplusplus
}
#endif
#endif
