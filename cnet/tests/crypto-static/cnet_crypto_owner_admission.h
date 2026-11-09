/* SPDX-License-Identifier: Apache-2.0
 * PRIVATE / QUALIFICATION-ONLY CNet policy -> opaque Crypto TLS admission.
 *
 * This header is never installed, never linked into saltscore_cnet, and
 * never enables a fallback or changes the production GmSSL backend.
 * It consumes the actual public CNet TLS configs, not a surrogate struct.
 */
#ifndef CNET_CRYPTO_OWNER_ADMISSION_H
#define CNET_CRYPTO_OWNER_ADMISSION_H

#include <cnet/cnet.h>
#include <crypto/tls.h>
#include <crypto/cipher_bio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cnet_crypto_owner_use {
    /* Exact Crypto TLS protocol, explicit file CA and no optional CNet features. */
    CNET_CRYPTO_OWNER_TEST_ONLY = 1,
    /* Deliberately unadmitted until full CNet feature + lifecycle parity. */
    CNET_CRYPTO_OWNER_PRODUCTION = 2
} cnet_crypto_owner_use;

/* Options borrow config strings. The owning CNet Owner must retain its
 * accepted snapshot through session_create, not borrow caller stack state.
 * out_options is unchanged on any rejection. There is NO implicit system
 * trust, protocol fallback, ALPN, client mTLS or ShangMi/TLCP fallback.
 *
 * source_identity is the effective URI/SNI name after CNet admission;
 * when config.server_name is set, it must exactly match source_identity.
 * IP literal verification is NOT yet supported by this candidate.
 */
int cnet_crypto_owner_admit_client(const cnet_tls_client_config *config,
                                   const char *source_identity,
                                   uint32_t exact_protocol,
                                   size_t cipher_capacity,
                                   cnet_crypto_owner_use use,
                                   crypto_tls_session_options *out_options);

int cnet_crypto_owner_admit_server(const cnet_tls_server_config *config,
                                   uint32_t exact_protocol,
                                   size_t cipher_capacity,
                                   cnet_crypto_owner_use use,
                                   crypto_tls_session_options *out_options);

#ifdef __cplusplus
}
#endif
#endif
