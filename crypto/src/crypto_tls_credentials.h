#ifndef CRYPTO_TLS_CREDENTIALS_INTERNAL_H
#define CRYPTO_TLS_CREDENTIALS_INTERNAL_H
#include <crypto/tls_stream.h>
#include <gmssl/tls.h>
int crypto_tls_memory_validate(const crypto_tls_data *ca,
    const crypto_tls_credentials *credentials, bool tlcp_server);
int crypto_tls_memory_trust(TLS_CTX *tls, const crypto_tls_data *ca);
int crypto_tls_memory_identity(TLS_CTX *tls, const crypto_tls_credentials *credentials);
int crypto_tls_pbes2_decrypt(const unsigned char *algorithm, size_t algorithm_size,
    const unsigned char *ciphertext, size_t ciphertext_size,
    const crypto_tls_password *password, unsigned char *out, size_t capacity,
    size_t *out_size, uint32_t *work_budget);
int crypto_tls_memory_decode_key(const crypto_tls_data *input, const crypto_tls_password *password,
    unsigned char *out, size_t capacity, size_t *out_size, uint32_t *work_budget);
#endif
