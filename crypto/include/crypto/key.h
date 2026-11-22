#ifndef CRYPTO_KEY_H_INCLUDED
#define CRYPTO_KEY_H_INCLUDED

#include <crypto/export.h>

#include <crypto/symmetric.h>
#include <crypto/ecdsa.h>
#include <crypto/ed25519.h>
#include <crypto/ed448.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct salts_crypto_key salts_crypto_key;
typedef struct salts_crypto_bytes { const uint8_t *data; size_t size; } salts_crypto_bytes;
typedef enum salts_crypto_key_kind {
  SALTS_CRYPTO_KEY_RSA = 1, SALTS_CRYPTO_KEY_EC,
  SALTS_CRYPTO_KEY_ED25519, SALTS_CRYPTO_KEY_ED448
} salts_crypto_key_kind;
typedef enum salts_crypto_signature {
  SALTS_CRYPTO_RSA_PKCS1 = 1, SALTS_CRYPTO_RSA_PSS,
  SALTS_CRYPTO_ECDSA, SALTS_CRYPTO_EDDSA
} salts_crypto_signature;

/** Imports copy all input bytes. On success *output is an immutable owned key;
 * on failure it is NULL (EINVAL, ENOMEM, ERANDOM or ECRYPTO). The caller destroys
 * it after all synchronous/concurrent readers return. Destruction wipes secrets.
 * RSA accepts n/e and optional d; CRT values, if complete, are consistency-checked.
 * EC public input is SEC1 compressed/uncompressed, private input a scalar.
 * EdDSA private input is a seed. Supplied public/private components must agree.
 * PEM supports SPKI public keys, PKCS8 and traditional RSA/EC private keys.
 * This entry imports unencrypted PEM; encrypted PKCS8 has explicit APIs below.
 * Example: salts_crypto_key_from_pem(pem, length, 1, &key); ...;
 *          salts_crypto_key_destroy(key);
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_key_from_rsa(salts_crypto_bytes n, salts_crypto_bytes e, salts_crypto_bytes d,
    salts_crypto_bytes p, salts_crypto_bytes q, salts_crypto_bytes dp,
    salts_crypto_bytes dq, salts_crypto_bytes qi, salts_crypto_key **output);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_from_ec(salts_crypto_ec_curve curve, salts_crypto_bytes public_key,
    salts_crypto_bytes private_key, salts_crypto_key **output);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_from_ed(salts_crypto_key_kind kind, salts_crypto_bytes public_key,
    salts_crypto_bytes private_key, salts_crypto_key **output);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_from_pem(const void *pem, size_t size, int private_key, salts_crypto_key **output);
/** SPKI public / PKCS8 private DER. Same copying/error contract as PEM import. */
SALTS_CRYPTO_EXPORT
int salts_crypto_key_from_der(const void *der, size_t size, int private_key, salts_crypto_key **output);
/** Bounded DER/PEM export, caller-owned output disjoint from key/output_size.
 * NULL output with capacity==0 queries the required byte count. Otherwise
 * insufficient capacity is EINVAL, output unchanged, *output_size=0. PEM has
 * LF line endings and no terminating NUL. Private export requires a private
 * key; RSA additionally requires the complete CRT tuple at import. Temporary
 * secrets are wiped. Example: key_to_der(key,0,NULL,0,&n); allocate n; export.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_key_to_der(const salts_crypto_key *key, int private_key,
    uint8_t *output, size_t capacity, size_t *output_size);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_to_pem(const salts_crypto_key *key, int private_key,
    char *output, size_t capacity, size_t *output_size);

#define SALTS_CRYPTO_KEY_DER_MAX_SIZE 8192U
#define SALTS_CRYPTO_KEY_ITERATIONS_MIN 10000U
/** Encrypted PKCS8: PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC, random 16-byte
 * salt and IV. Export iterations are explicit, 10000..INT_MAX. Import requires
 * a ceiling in that range; encoded work exceeding it is rejected before KDF.
 * Import accepts 8..64-byte salts for existing OpenSSL files; export uses 16.
 * Password is a borrowed byte span (embedded NUL and zero length allowed).
 * DER is bounded to KEY_DER_MAX_SIZE+256; PEM to 16384 bytes. Output handles
 * are NULL on failure. Invalid format/profile/ceiling is EINVAL; wrong password
 * or invalid decrypted material is EVERIFY; native failure is ECRYPTO/ERANDOM.
 * Export uses the query/capacity contract above. Queries perform no RNG/KDF.
 * Export destinations are disjoint from passwords; length/handle output
 * pointers must be disjoint from every input and output buffer.
 * Caller owns/wipes exported private material; no password is retained.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_key_to_encrypted_der(const salts_crypto_key *key,
    const void *password, size_t password_size, uint32_t iterations,
    uint8_t *output, size_t capacity, size_t *output_size);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_to_encrypted_pem(const salts_crypto_key *key,
    const void *password, size_t password_size, uint32_t iterations,
    char *output, size_t capacity, size_t *output_size);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_from_encrypted_der(const void *der, size_t size,
    const void *password, size_t password_size, uint32_t max_iterations,
    salts_crypto_key **output);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_from_encrypted_pem(const void *pem, size_t size,
    const void *password, size_t password_size, uint32_t max_iterations,
    salts_crypto_key **output);
SALTS_CRYPTO_EXPORT
void salts_crypto_key_destroy(salts_crypto_key *key);
SALTS_CRYPTO_EXPORT
salts_crypto_key_kind salts_crypto_key_type(const salts_crypto_key *key);
SALTS_CRYPTO_EXPORT
size_t salts_crypto_key_signature_size(const salts_crypto_key *key);
/** Message signatures, caller-owned output. Capacity is at least signature_size.
 * PSS signing uses digest-length salt; verification accepts any encoded salt.
 * RSA hashes SHA256/384/512; ECDSA uses the selected hash with the imported curve.
 * EdDSA ignores hash. Failure leaves *size zero; invalid signatures return EVERIFY.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_key_sign(const salts_crypto_key *key, salts_crypto_signature scheme,
    salts_crypto_hash hash, const void *message, size_t message_size,
    uint8_t *signature, size_t capacity, size_t *size);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_verify(const salts_crypto_key *key, salts_crypto_signature scheme,
    salts_crypto_hash hash, const void *message, size_t message_size,
    const uint8_t *signature, size_t size);
/** RSA OAEP with empty label, MGF1 uses hash. Caller owns disjoint input/output
 * and output_size. Decrypt exposes no plaintext on failure (EVERIFY); key/size
 * errors return EINVAL. Encrypt output needs key_signature_size bytes.
 */
SALTS_CRYPTO_EXPORT
int salts_crypto_key_oaep_encrypt(const salts_crypto_key *key, salts_crypto_hash hash,
    const uint8_t *input, size_t size, uint8_t *output, size_t capacity, size_t *output_size);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_oaep_decrypt(const salts_crypto_key *key, salts_crypto_hash hash,
    const uint8_t *input, size_t size, uint8_t *output, size_t capacity, size_t *output_size);

/** Explicit OAEP label (borrowed/disjoint); otherwise the same contract and
 * result codes as the empty-label operations. MGF1 uses the selected hash. */
SALTS_CRYPTO_EXPORT
int salts_crypto_key_oaep_encrypt_with_label(const salts_crypto_key *key, salts_crypto_hash hash,
    const void *label, size_t label_size, const uint8_t *input, size_t size,
    uint8_t *output, size_t capacity, size_t *output_size);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_oaep_decrypt_with_label(const salts_crypto_key *key, salts_crypto_hash hash,
    const void *label, size_t label_size, const uint8_t *input, size_t size,
    uint8_t *output, size_t capacity, size_t *output_size);

#define SALTS_CRYPTO_PSS_SALT_AUTO SIZE_MAX
/** RSA-PSS with SHA256/384/512; MGF1 uses the same hash. Signing requires an
 * explicit salt byte count (zero allowed), bounded by the modulus/hash.
 * Verify accepts an exact count or PSS_SALT_AUTO. Inputs/outputs follow the
 * key_sign/verify contracts; invalid sizes/parameters return EINVAL, bad
 * signatures EVERIFY, and backend failure ECRYPTO. Example: sign(...,32,...)
 * and verify(...,32,...) enforce a 32-byte salt for SHA256. */
SALTS_CRYPTO_EXPORT
int salts_crypto_key_pss_sign(const salts_crypto_key *key, salts_crypto_hash hash,
    size_t salt_size, const void *message, size_t message_size,
    uint8_t *signature, size_t capacity, size_t *size);
SALTS_CRYPTO_EXPORT
int salts_crypto_key_pss_verify(const salts_crypto_key *key, salts_crypto_hash hash,
    size_t salt_size, const void *message, size_t message_size,
    const uint8_t *signature, size_t size);

#ifdef __cplusplus
}
#endif

#endif
