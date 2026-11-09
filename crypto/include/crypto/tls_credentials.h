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

typedef struct crypto_tls_credential_object crypto_tls_credential_object;
typedef enum crypto_tls_credential_kind {
  CRYPTO_TLS_CREDENTIAL_SINGLE = 0,
  CRYPTO_TLS_CREDENTIAL_TLCP_SERVER = 1
} crypto_tls_credential_kind;

enum {
  CRYPTO_TLS_TRUST_INPUT_MAX_BYTES = 1024 * 1024,
  CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES = 16 * 1024,
  CRYPTO_TLS_CERTIFICATE_CHAIN_DER_MAX_BYTES = 8192 - 3,
  CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES = 8192,
  CRYPTO_TLS_PKCS12_MAX_BYTES = 64 * 1024,
  CRYPTO_TLS_PASSWORD_MAX_BYTES = 1024,
  CRYPTO_TLS_PKCS8_MIN_ITERATIONS = 10000,
  CRYPTO_TLS_PKCS8_MAX_ITERATIONS = 1000000
};

/** Chain: concatenated DER certificates or CERTIFICATE PEM blocks, leaf first.
 * Key: one PKCS#8 PrivateKeyInfo, DER or PRIVATE KEY PEM. A non-NULL password
 * selects EncryptedPrivateKeyInfo / ENCRYPTED PRIVATE KEY PEM: PBES2 with
 * explicit PBKDF2-HMAC-SM3 / SM4-CBC or PBKDF2-HMAC-SHA2 with AES-128/192/256-CBC.
 * SHA2 selects SHA224, SHA256, SHA384, SHA512, SHA512/224 or SHA512/256 by OID.
 * Salt is 8..64 bytes, IV is 16 bytes, optional key length is absent or the
 * cipher key size (16, 24 or 32 bytes); iterations use MIN..MAX_ITERATIONS above.
 * No implicit PRF or other PRF/cipher combinations. CBC does not authenticate
 * the envelope; decrypted key/identity binding remains mandatory.
 * RSA and EC SM2/P-256 keys are supported. No PKCS#12, other PBES schemes,
 * standalone PKCS#1/SEC1, PEM headers or trailing non-whitespace text.
 * PKCS#12 uses the separate authenticated object constructor below.
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
  /** Optional immutable credential object, mutually exclusive with every raw
   * input above. Borrowed during initialization; the new context owns its
   * independent provider key state and does not borrow object storage. */
  const crypto_tls_credential_object *object;
} crypto_tls_credentials;

#ifdef __cplusplus
extern "C" {
#endif
/** Decode/decrypt and bind a bounded identity once. The result owns immutable
 * DER and one reference, retains no password/input, and may be shared across
 * concurrent context initializations while a reference remains held. It checks
 * key/chain formats and binding, not peer trust or certificate validity.
 * SINGLE accepts one RSA/SM2/P256 identity; TLCP_SERVER requires the dual-key
 * contract. No file access. EINVAL: descriptor/conflict/kind; ERANGE: bounds;
 * EIO: decoding/decryption/binding; ENOMEM: allocation. out must own no reference
 * on entry and be disjoint from every input descriptor/byte span. Alias errors
 * return EINVAL preserving all storage; other failures set *out=NULL.
 * Use {.size=sizeof(crypto_tls_credentials), .object=object} in TLS configs. */
int crypto_tls_credential_object_create(const crypto_tls_credentials *input,
    crypto_tls_credential_kind kind, crypto_tls_credential_object **out);
/** Import a password-authenticated DER PFX v3 into an immutable identity.
 * The password is non-NULL UTF-8 text (empty and embedded NUL are significant);
 * integrity uses BMPString+terminator, so non-BMP characters are rejected.
 * Requires SHA2 or SM3 MAC, 8..64-byte salt and MIN..MAX_ITERATIONS. Safe contents use
 * Data or PBES2 EncryptedData; keys use KeyBag or PBES2 ShroudedKeyBag with the
 * same finite PRF/cipher policy above. No legacy PBE/SHA1 MAC or unauthenticated
 * import. MAC is verified before decryption. At most 8 safes/32 bags/16 certs/
 * 2 keys and 2,000,000 total KDF iterations; identity DER bounds still apply.
 * SINGLE requires one key and one unambiguous chain; TLCP_SERVER requires both
 * role-specific SM2 keys. Certificate bags may be unordered. Duplicates,
 * unrelated/ambiguous certificates, unsupported bag/attribute types and nested
 * safes fail; localKeyId/friendlyName never override cryptographic key binding.
 * Supplied issuer links must verify; SM2 links use the standard default ID.
 * This imports identity material, not trust. No file access. Error/ownership
 * contract matches create; ENOTSUP denotes unsupported algorithm/content type.
 * On success caller may erase the PFX and password immediately. */
int crypto_tls_credential_object_from_pkcs12(const crypto_tls_data *input,
    const crypto_tls_password *password, crypto_tls_credential_kind kind,
    crypto_tls_credential_object **out);
/** Retain an existing live object; EINVAL for NULL, ERANGE on reference overflow. */
int crypto_tls_credential_object_retain(crypto_tls_credential_object *object);
/** Release one reference; NULL is allowed. Last release erases private material.
 * Release cannot race an initialization that only borrows this reference. */
void crypto_tls_credential_object_release(crypto_tls_credential_object *object);
#ifdef __cplusplus
}
#endif

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
