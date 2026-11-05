#ifndef CRYPTO_TLS_CREDENTIALS_INTERNAL_H
#define CRYPTO_TLS_CREDENTIALS_INTERNAL_H
#include <crypto/tls_stream.h>
#include <gmssl/tls.h>
int crypto_tls_memory_validate(const crypto_tls_data *ca,
    const crypto_tls_credentials *credentials, bool tlcp_server);
int crypto_tls_memory_trust(TLS_CTX *tls, const crypto_tls_data *ca);
int crypto_tls_memory_identity(TLS_CTX *tls, const crypto_tls_credentials *credentials);
#endif
