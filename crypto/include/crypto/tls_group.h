#ifndef CRYPTO_TLS_GROUP_H
#define CRYPTO_TLS_GROUP_H

/** Closed set of key-exchange groups implemented by the current provider.
 * These are key exchange, not certificate/signature curves. */
typedef enum crypto_tls_group {
  CRYPTO_TLS_GROUP_SECP256R1 = 0x0017,
  CRYPTO_TLS_GROUP_SM2P256V1 = 0x0029
} crypto_tls_group;
enum { CRYPTO_TLS_GROUP_MAX_COUNT = 2 };

#endif
