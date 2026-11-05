/* Bounded, provider-neutral inputs consumed during TLS context creation. */
#ifndef CRYPTO_TLS_CREDENTIALS_H
#define CRYPTO_TLS_CREDENTIALS_H
#include <stddef.h>

typedef enum crypto_tls_encoding {
  CRYPTO_TLS_ENCODING_DER = 1,
  CRYPTO_TLS_ENCODING_PEM = 2
} crypto_tls_encoding;

typedef struct crypto_tls_data {
  const void *data;
  size_t size;
  crypto_tls_encoding encoding;
} crypto_tls_data;

enum {
  CRYPTO_TLS_TRUST_INPUT_MAX_BYTES = 1024 * 1024,
  CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES = 16 * 1024,
  CRYPTO_TLS_CERTIFICATE_CHAIN_DER_MAX_BYTES = 8192 - 3,
  CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES = 8192
};

/** Chain: concatenated DER certificates or CERTIFICATE PEM blocks, leaf first.
 * Key: one unencrypted PKCS#8 PrivateKeyInfo, DER or PRIVATE KEY PEM.
 * RSA and EC SM2/P-256 keys are supported. No PKCS#12, encrypted PKCS#8,
 * standalone PKCS#1/SEC1, PEM headers or trailing non-whitespace text.
 * TLCP server chain contains signing leaf, encryption leaf, then issuers;
 * private_key is the signing key and encryption_key is mandatory.
 * Other profiles require encryption_key to be all-zero.
 *
 * All descriptors and bytes are immutable borrows only during context init.
 * Success owns independent certificate/key state; failure publishes nothing.
 * Caller can erase/free input on return. Internal decoded keys are erased on
 * every path. No temporary files or input pointers are retained. */
typedef struct crypto_tls_credentials {
  size_t size;
  crypto_tls_data certificate_chain;
  crypto_tls_data private_key;
  crypto_tls_data encryption_key;
} crypto_tls_credentials;
#endif
