#ifndef SALTS_CRYPTO_SM9_H
#define SALTS_CRYPTO_SM9_H
#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM9_SIGNATURE_SIZE 104u
#define SALTS_CRYPTO_SM9_CIPHERTEXT_MAX_SIZE 367u
#define SALTS_CRYPTO_SM9_PLAINTEXT_MAX_SIZE 255u
#define SALTS_CRYPTO_SM9_KEM_MAX_SIZE 1024u
#define SALTS_CRYPTO_SM9_ID_MAX_SIZE 8191u

typedef enum salts_crypto_sm9_purpose {
  SALTS_CRYPTO_SM9_SIGN = 1,
  SALTS_CRYPTO_SM9_ENCRYPT = 2,
  SALTS_CRYPTO_SM9_EXCHANGE = 3
} salts_crypto_sm9_purpose;

/* Canonical uncompressed point octets, independent of native provider layout.
 * These structs contain PRIVATE key material. Keep them in protected storage;
 * clear every owned copy after use. Signing/encryption use separate masters. */
typedef struct salts_crypto_sm9_sign_key {
  uint8_t private_point[65];
  uint8_t master_public[129];
} salts_crypto_sm9_sign_key;
typedef struct salts_crypto_sm9_enc_key {
  uint8_t private_point[129];
  uint8_t master_public[65];
} salts_crypto_sm9_enc_key;

/* Master secret is a 32-byte big-endian scalar in [1,N-1]. Public output is
 * 129 bytes for SIGN, 65 for ENCRYPT/EXCHANGE. Use separate masters for each
 * purpose. Identity is explicit, 1..8191 bytes.
 * Output ranges must be disjoint from all inputs and each other. Invalid
 * pointers/lengths/overlap leave outputs untouched. Once processing begins,
 * failures erase output key/signature buffers and facade-owned working state.
 * Caller remains responsible for erasing the master secret itself. */
int salts_crypto_sm9_master_generate(salts_crypto_sm9_purpose purpose,
    uint8_t secret[32], void *public_key, size_t capacity);
int salts_crypto_sm9_master_public(salts_crypto_sm9_purpose purpose,
    const uint8_t secret[32], void *public_key, size_t capacity);
int salts_crypto_sm9_sign_extract(const uint8_t master[32],
    const void *identity, size_t identity_size, salts_crypto_sm9_sign_key *key);
int salts_crypto_sm9_enc_extract(const uint8_t master[32],
    const void *identity, size_t identity_size, salts_crypto_sm9_enc_key *key);
void salts_crypto_sm9_sign_key_clear(salts_crypto_sm9_sign_key *key);
void salts_crypto_sm9_enc_key_clear(salts_crypto_sm9_enc_key *key);

/* SM9 signatures use canonical GM/T 0080 DER { OCTET STRING h, BIT STRING S }.
 * Sign hashes the message internally; do not pass a digest in its place.
 * All imported points are canonical, finite and in the prime-order subgroup. */
int salts_crypto_sm9_sign(const salts_crypto_sm9_sign_key *key,
    const void *message, size_t size, uint8_t signature[104]);
int salts_crypto_sm9_verify(const uint8_t master_public[129],
    const void *identity, size_t identity_size, const void *message, size_t size,
    const void *signature, size_t signature_size);

/* SM9 XOR encryption with SM3(C2 || K2) authentication, canonical GM/T 0080
 * DER { INTEGER 0, BIT STRING C1, OCTET STRING C3, OCTET STRING C2 }.
 * Plaintext length 1..255; required capacities: encrypt 367, decrypt 255.
 * written must not overlap any buffer. After admission, failure erases the
 * maximum-size output and sets written=0. Plaintext is copied only after
 * authentication succeeds. Invalid cipher/identity returns EVERIFY. */
int salts_crypto_sm9_encrypt(const uint8_t master_public[65],
    const void *identity, size_t identity_size, const void *plaintext, size_t size,
    void *ciphertext, size_t capacity, size_t *written);
int salts_crypto_sm9_decrypt(const salts_crypto_sm9_enc_key *key,
    const void *identity, size_t identity_size, const void *ciphertext, size_t size,
    void *plaintext, size_t capacity, size_t *written);

/* KEM capsule is an uncompressed 65-byte G1 point, secret length 1..1024.
 * KEM does not authenticate the sender or provide key confirmation: a changed
 * identity or valid capsule can derive a different secret successfully.
 * The enclosing protocol must authenticate/confirm before using that secret. */
int salts_crypto_sm9_encapsulate(const uint8_t master_public[65],
    const void *identity, size_t identity_size, void *secret, size_t secret_size,
    uint8_t capsule[65]);
int salts_crypto_sm9_decapsulate(const salts_crypto_sm9_enc_key *key,
    const void *identity, size_t identity_size, const uint8_t capsule[65],
    void *secret, size_t secret_size);

#ifdef __cplusplus
}
#endif
#endif
