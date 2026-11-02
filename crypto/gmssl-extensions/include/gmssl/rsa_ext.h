#ifndef GMSSL_RSA_EXT_H
#define GMSSL_RSA_EXT_H

#include <gmssl/rsa.h>
#include <gmssl/rsa_components.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RSA_HASH_SHA1 = 1,
    RSA_HASH_SHA256,
    RSA_HASH_SHA384,
    RSA_HASH_SHA512
} RSA_HASH;

/* Verify PSS with any salt length permitted by the encoded message. Signing
 * requires an explicit salt length, including zero. MGF1 uses the same hash.
 * SHA-1 is supported only for OAEP interoperability, not signatures. */
#define RSA_PSS_SALT_AUTO SIZE_MAX

/* All buffers remain caller-owned. Keys must satisfy rsa.h's size constraints.
 * diglen must equal the selected hash's size. Output may overlap byte inputs;
 * output length pointers must be disjoint from all inputs/outputs and keys.
 * Sign/encrypt: 1 success, -1 invalid argument or operational failure.
 * Verify: 1 valid, 0 invalid signature, -1 invalid argument/operational failure.
 * Decrypt: 1 success, 0 any ciphertext/decoding/private-operation failure or
 * insufficient plaintext capacity, -1 invalid key/hash/buffer/label arguments.
 * Failure leaves the output buffer unchanged and sets its length to zero.
 * No encoded plaintext, partial plaintext or padding detail is returned.
 * For example, after validating/importing key and hashing the message:
 *   uint8_t sig[RSA_MAX_MODULUS_SIZE]; size_t siglen = 0;
 *   int rc = rsa_sign_pss_digest(&key, RSA_HASH_SHA384, hash384, 48, 48,
 *       sig, sizeof(sig), &siglen);
 * Only rc == 1 admits sig[0..siglen). The caller wipes its private key with
 * rsa_private_key_cleanup when finished. These APIs do not import/own keys.
 */
int rsa_sign_pkcs1_v15_digest(const RSA_PRIVATE_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, uint8_t *sig, size_t sigmax, size_t *siglen);
int rsa_verify_pkcs1_v15_digest(const RSA_PUBLIC_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, const uint8_t *sig, size_t siglen);
int rsa_sign_pss_digest(const RSA_PRIVATE_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen,
    uint8_t *sig, size_t sigmax, size_t *siglen);
int rsa_verify_pss_digest(const RSA_PUBLIC_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen,
    const uint8_t *sig, size_t siglen);
int rsa_oaep_encrypt(const RSA_PUBLIC_KEY *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen,
    uint8_t *out, size_t outmax, size_t *outlen);
int rsa_oaep_decrypt(const RSA_PRIVATE_KEY *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen,
    uint8_t *out, size_t outmax, size_t *outlen);

/* Component-key variants have the same encoding, ownership and error contracts. */
int rsa_components_sign_pkcs1_v15_digest(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, uint8_t *sig, size_t sigmax, size_t *siglen);
int rsa_components_verify_pkcs1_v15_digest(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, const uint8_t *sig, size_t siglen);
int rsa_components_sign_pss_digest(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen, uint8_t *sig, size_t sigmax, size_t *siglen);
int rsa_components_verify_pss_digest(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen, const uint8_t *sig, size_t siglen);
int rsa_components_oaep_encrypt(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t *outlen);
int rsa_components_oaep_decrypt(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t *outlen);

#ifdef __cplusplus
}
#endif
#endif
