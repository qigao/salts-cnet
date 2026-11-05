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

/* NULL/0 selects plaintext. Non-NULL selects encrypted PKCS#8, including an
 * empty password. Bytes are not NUL-terminated; embedded NULs are significant. */
typedef struct crypto_tls_password {
  const void *data;
  size_t size;
} crypto_tls_password;

enum {
  CRYPTO_TLS_TRUST_INPUT_MAX_BYTES = 1024 * 1024,
  CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES = 16 * 1024,
  CRYPTO_TLS_CERTIFICATE_CHAIN_DER_MAX_BYTES = 8192 - 3,
  CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES = 8192,
  CRYPTO_TLS_PASSWORD_MAX_BYTES = 1024,
  CRYPTO_TLS_PKCS8_MIN_ITERATIONS = 10000,
  CRYPTO_TLS_PKCS8_MAX_ITERATIONS = 1000000
};

/** Chain: concatenated DER certificates or CERTIFICATE PEM blocks, leaf first.
 * Key: one PKCS#8 PrivateKeyInfo, DER or PRIVATE KEY PEM. A non-NULL password
 * selects EncryptedPrivateKeyInfo / ENCRYPTED PRIVATE KEY PEM: PBES2 with
 * explicit PBKDF2-HMAC-SM3 / SM4-CBC or PBKDF2-HMAC-SHA256 / AES-256-CBC.
 * Salt is 8..64 bytes, IV is 16 bytes, optional key length is absent or the
 * cipher key size (16 or 32); iterations use MIN..MAX_ITERATIONS above.
 * No implicit PRF or other PRF/cipher combinations. CBC does not authenticate
 * the envelope; decrypted key/identity binding remains mandatory.
 * RSA and EC SM2/P-256 keys are supported. No PKCS#12, other PBES schemes,
 * standalone PKCS#1/SEC1, PEM headers or trailing non-whitespace text.
 * TLCP server chain contains signing leaf, encryption leaf, then issuers;
 * private_key is the signing key and encryption_key is mandatory.
 * Other profiles require encryption_key and its password to be all-zero.
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
  crypto_tls_password private_key_password;
  crypto_tls_password encryption_key_password;
} crypto_tls_credentials;

enum {
  CRYPTO_TLS_IDENTITY_MAX_COUNT = 4,
  CRYPTO_TLS_SERVER_IDENTITY_MAX_COUNT = CRYPTO_TLS_IDENTITY_MAX_COUNT,
  CRYPTO_TLS_CLIENT_IDENTITY_MAX_COUNT = CRYPTO_TLS_IDENTITY_MAX_COUNT
};

/* One TLS identity: either file chain/key/password or memory credentials.
 * Inputs are borrowed only during context creation. TLCP uses the existing
 * dual-certificate/dual-key contract for each identity. */
typedef struct crypto_tls_server_identity {
  size_t size;
  const char *cert_file;
  const char *key_file;
  const char *key_password;
  const crypto_tls_credentials *credentials;
} crypto_tls_server_identity;
typedef crypto_tls_server_identity crypto_tls_identity;
typedef crypto_tls_identity crypto_tls_client_identity;
#endif
