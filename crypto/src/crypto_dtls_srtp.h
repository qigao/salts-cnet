#ifndef CRYPTO_DTLS_SRTP_INTERNAL_H
#define CRYPTO_DTLS_SRTP_INTERNAL_H

#include <crypto/dtls_stream.h>

enum { CRYPTO_DTLS_EXT_USE_SRTP = 14 };

size_t dtls_srtp_extension(uint8_t *out, unsigned profiles);
uint16_t dtls_srtp_select(const uint8_t *, size_t, unsigned profiles,
                                bool server_hello);
bool dtls_srtp_fingerprint(const uint8_t *chain, size_t chain_size,
                                 const uint8_t expected[32]);

#endif
