#ifndef SALTS_CRYPTO_SM2_KEYS_H
#define SALTS_CRYPTO_SM2_KEYS_H
#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM2_SPKI_SIZE 91u
#define SALTS_CRYPTO_SM2_PKCS8_MAX_SIZE 150u
#define SALTS_CRYPTO_SM2_ENCRYPTED_PKCS8_MAX_SIZE 320u
#define SALTS_CRYPTO_SM2_KEY_PASSWORD_MAX_SIZE 1024u
#define SALTS_CRYPTO_SM2_KEY_ITERATIONS_MIN 10000u
#define SALTS_CRYPTO_SM2_KEY_ITERATIONS_MAX 16777215u

/* Synchronous, allocation-free DER key containers. No borrowed output, file
 * access, trust establishment or PEM conversion. Caller owns/erases private
 * keys and unencrypted PKCS#8. All outputs must be disjoint from inputs and
 * other outputs. Export requires the respective MAX_SIZE (SPKI: SIZE), even
 * when the encoding is shorter; no size query. written must be separate.
 * Invalid pointer/size/capacity/overlap/policy arguments preserve outputs.
 * After admission, malformed encodings/invalid keys return EVERIFY and erase
 * the fixed-size output (export also sets written=0). Internal/RNG failures
 * likewise erase outputs. Bytes beyond the documented size are untouched.
 * Single caller owns each output during a call; no mutable global state.
 */
int salts_crypto_sm2_spki_export(const uint8_t public_key[65],
    void *der, size_t capacity, size_t *written);
int salts_crypto_sm2_spki_import(const void *der, size_t size,
    uint8_t public_key[65]);

/* PrivateKeyInfo version 0, id-ecPublicKey + curveSM2, ECPrivateKey version 1.
 * Export includes inner named curve and uncompressed public key. Import also
 * accepts their omission, but validates them against the outer curve and
 * derived key when present. Attributes, other curves/versions, compressed
 * points, extra/trailing values and noncanonical DER are rejected.
 * Scalars [1,N-1] are supported; N-1 remains invalid for SM2 signing.
 */
int salts_crypto_sm2_pkcs8_export(const uint8_t private_key[32],
    void *der, size_t capacity, size_t *written);
int salts_crypto_sm2_pkcs8_import(const void *der, size_t size,
    uint8_t private_key[32]);

/* EncryptedPrivateKeyInfo: PBES2, explicit PBKDF2-HMAC-SM3, SM4-CBC with
 * PKCS#7 padding. Export draws fresh 16-byte salt and IV from the provider
 * CSPRNG. Import accepts salt 16..64, absent or 16-byte keyLength, and absent
 * or NULL PRF parameters. Missing PRF (which means SHA1) is rejected.
 * Password is 1..1024 opaque bytes, including embedded NUL; no normalization.
 * iterations and max_iterations must be within MIN..MAX. Import rejects a
 * document exceeding max_iterations BEFORE KDF work. Choose an application
 * work budget; MAX is a format ceiling, not a recommended work factor.
 * All decrypted material remains private until complete key validation.
 * CBC password protection is NOT authenticated storage: successful import
 * does not establish provenance/integrity. Protect stored files separately
 * and bind imported public keys to the application's trusted identity.
 * Do not expose this synchronous, variable-time file import as a remote
 * password/decryption oracle. Certificate trust remains a separate workflow.
 */
int salts_crypto_sm2_pkcs8_encrypt(const uint8_t private_key[32],
    const void *password, size_t password_size, uint32_t iterations,
    void *der, size_t capacity, size_t *written);
int salts_crypto_sm2_pkcs8_decrypt(const void *der, size_t size,
    const void *password, size_t password_size, uint32_t max_iterations,
    uint8_t private_key[32]);

#ifdef __cplusplus
}
#endif
#endif
