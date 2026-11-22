#ifndef CRYPTO_SYMMETRIC_H_INCLUDED
#define CRYPTO_SYMMETRIC_H_INCLUDED

#include <crypto/status.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum salts_crypto_hash {
  SALTS_CRYPTO_SHA1 = 1,
  SALTS_CRYPTO_SHA256 = 2,
  SALTS_CRYPTO_SHA384 = 3,
  SALTS_CRYPTO_SHA512 = 4
} salts_crypto_hash;

/** Caller-owned buffers; NULL inputs are allowed only with zero length.
 * Digest/HMAC output_size must be disjoint from all buffers. They set it to
 * zero on failure. EINVAL preserves output; provider failure returns ECRYPTO.
 * The digest/HMAC output may overlap inputs; PBKDF2 output must be disjoint.
 * SHA-1 exists for protocol interoperability. New signatures should use SHA-2.
 * Example: salts_crypto_digest(SALTS_CRYPTO_SHA384, data, size, out, 48, &n).
 */
int salts_crypto_digest(salts_crypto_hash hash, const void *data, size_t size,
    uint8_t *output, size_t capacity, size_t *output_size);
int salts_crypto_hmac(salts_crypto_hash hash, const void *key, size_t key_size,
    const void *data, size_t size, uint8_t *output, size_t capacity, size_t *output_size);
int salts_crypto_pbkdf2(salts_crypto_hash hash, const void *password, size_t password_size,
    const void *salt, size_t salt_size, uint32_t iterations, uint8_t *output, size_t size);

typedef struct salts_crypto_digest_ctx salts_crypto_digest_ctx;
typedef struct salts_crypto_hmac_ctx salts_crypto_hmac_ctx;
/** Exclusive mutable streams. Creation sets *output=NULL on failure and copies
 * HMAC keys; ENOMEM reports allocation failure. Inputs are borrowed per call.
 * Destroy wipes/releases storage (NULL is valid); handles must not be copied.
 * Update/final after finalization/provider failure return ESTATE. EINVAL leaves
 * active state and output unchanged, except *output_size=0. Final buffers and
 * output_size must be disjoint from the handle and each other. A stream admits
 * at most (UINT64_MAX/8 - 144) message bytes; excess is EINVAL before consumption.
 * Example: create(SHA256,&ctx); update(ctx,part,n); final(ctx,out,32,&n);
 *          destroy(ctx). No operation is safe concurrently with mutation.
 */
int salts_crypto_digest_create(salts_crypto_hash hash, salts_crypto_digest_ctx **output);
int salts_crypto_digest_update(salts_crypto_digest_ctx *ctx, const void *data, size_t size);
int salts_crypto_digest_final(salts_crypto_digest_ctx *ctx, uint8_t *output,
    size_t capacity, size_t *output_size);
void salts_crypto_digest_destroy(salts_crypto_digest_ctx *ctx);
int salts_crypto_hmac_create(salts_crypto_hash hash, const void *key, size_t key_size,
    salts_crypto_hmac_ctx **output);
int salts_crypto_hmac_update(salts_crypto_hmac_ctx *ctx, const void *data, size_t size);
int salts_crypto_hmac_final(salts_crypto_hmac_ctx *ctx, uint8_t *output,
    size_t capacity, size_t *output_size);
void salts_crypto_hmac_destroy(salts_crypto_hmac_ctx *ctx);

/** RFC 5869. Extract permits output to overlap inputs; output_size is disjoint.
 * Expand requires PRK length >= HashLen, size <= 255*HashLen, and disjoint input
 * and output spans. NULL input is valid only for zero length. Zero expand length
 * permits NULL output. EINVAL preserves output; provider failure clears it.
 * Example: extract(SHA256,salt,sn,ikm,in,prk,32,&n); expand(...,prk,n,...).
 */
int salts_crypto_hkdf_extract(salts_crypto_hash hash, const void *salt, size_t salt_size,
    const void *input, size_t size, uint8_t *output, size_t capacity, size_t *output_size);
int salts_crypto_hkdf_expand(salts_crypto_hash hash, const void *prk, size_t prk_size,
    const void *info, size_t info_size, uint8_t *output, size_t size);
/** CSPRNG; ERANDOM clears the requested output range. Zero length is valid. */
int salts_crypto_random(void *output, size_t size);
/** Wipes caller-owned memory. NULL is valid only for size zero. */
void salts_crypto_clear(void *data, size_t size);
/** Constant-time comparison for equal public lengths; OK/EVERIFY/EINVAL. */
int salts_crypto_equal(const void *a, const void *b, size_t size);

/** AES-GCM: keys 16/24/32 bytes; nonempty IV; tags 1..16 bytes. All buffers
 * belong to the caller. input/output may be identical or disjoint; other
 * ranges must be disjoint. Capacity must cover size. EINVAL leaves output
 * unchanged. Authentication failure returns EVERIFY without plaintext output.
 * GCM nonce uniqueness and tag length selection belong to the protocol caller.
 * Example: use a fresh 12-byte IV and 16-byte tag for each JWE encryption.
 */
int salts_crypto_aes_gcm_encrypt(const uint8_t *key, size_t key_size,
    const uint8_t *iv, size_t iv_size, const void *aad, size_t aad_size,
    const uint8_t *input, size_t size, uint8_t *output, size_t capacity,
    uint8_t *tag, size_t tag_size);
int salts_crypto_aes_gcm_decrypt(const uint8_t *key, size_t key_size,
    const uint8_t *iv, size_t iv_size, const void *aad, size_t aad_size,
    const uint8_t *input, size_t size, const uint8_t *tag, size_t tag_size,
    uint8_t *output, size_t capacity);

typedef enum salts_crypto_aes_mode {
  SALTS_CRYPTO_AES_CBC = 1,
  SALTS_CRYPTO_AES_CTR = 2
} salts_crypto_aes_mode;
/** Unauthenticated one-shot AES, 16/24/32-byte keys. decrypt is exactly 0 or 1.
 * CBC requires size%16==0 and performs no padding. CTR handles arbitrary bytes
 * identically in both directions, rejecting 128-bit counter exhaustion. IV is
 * a borrowed immutable 16-byte span; input/output are identical or disjoint,
 * all other spans are disjoint. Capacity >= size; NULL data/output only if
 * size==0. EINVAL preserves output, ECRYPTO clears output. No partial state is
 * retained. The caller owns authentication, padding and IV/nonce uniqueness.
 * Example: aes_crypt(AES_CBC,0,key,32,iv,blocks,n,out,n).
 */
int salts_crypto_aes_crypt(salts_crypto_aes_mode mode, int decrypt,
    const uint8_t *key, size_t key_size, const uint8_t iv[16],
    const uint8_t *input, size_t size, uint8_t *output, size_t capacity);

/**
 * RFC 3394 AES Key Wrap using a 16/24/32-byte key-encryption key.
 * Input is at least 16 bytes and a multiple of 8; output requires size + 8.
 * Buffers belong to the caller and may overlap. output_size must not overlap
 * any buffer. Returns OK or EINVAL; *output_size is zero on failure.
 */
int salts_crypto_aes_key_wrap(const uint8_t *key, size_t key_size,
                              const uint8_t *input, size_t input_size,
                              uint8_t *output, size_t capacity, size_t *output_size);

/**
 * Unwraps RFC 3394 ciphertext (at least 24 bytes, a multiple of 8).
 * Output requires input_size - 8 bytes. Same ownership/alias contract as wrap.
 * Invalid arguments return EINVAL without changing output. Integrity failure
 * returns EVERIFY, clears the candidate plaintext, and sets *output_size to 0.
 */
int salts_crypto_aes_key_unwrap(const uint8_t *key, size_t key_size,
                                const uint8_t *input, size_t input_size,
                                uint8_t *output, size_t capacity, size_t *output_size);


#define SALTS_CRYPTO_MD5_DIGEST_SIZE 16U
/** Legacy HTTP Digest interoperability. NULL data is valid only for size zero.
 * The caller owns the 16-byte output; errors preserve it for invalid input.
 * MD5 must not be used to design new authentication or signature protocols. */
int salts_crypto_md5(const void *data, size_t size, uint8_t output[SALTS_CRYPTO_MD5_DIGEST_SIZE]);

/** Legacy protocol HMAC-MD5 (for example, SNMPv3 USM). The caller owns the
 * 16-byte output. NULL inputs require zero length. Invalid arguments return
 * EINVAL without modifying the output.
 * Example: salts_crypto_hmac_md5(key, key_size, packet, size, mac).
 */
int salts_crypto_hmac_md5(const void *key, size_t key_size, const void *data,
                          size_t size, uint8_t output[SALTS_CRYPTO_MD5_DIGEST_SIZE]);

#define SALTS_CRYPTO_DES_BLOCK_SIZE 8U
#define SALTS_CRYPTO_AES128_BLOCK_SIZE 16U

/** Legacy protocol privacy operations. Pass decrypt=0 to encrypt or 1 to
 * decrypt. DES-CBC accepts whole 8-byte blocks. AES-128-CFB128 accepts any
 * length. The caller owns all buffers and handles padding where required.
 * Input and output may be identical or disjoint, and output must be disjoint
 * from the key and IV. NULL input/output requires zero length. EINVAL leaves
 * output unchanged. Backend errors return ECRYPTO and clear the output.
 * Example: salts_crypto_aes128_cfb_crypt(0, key, iv, in, size, out, capacity).
 */
int salts_crypto_des_cbc_crypt(int decrypt,
    const uint8_t key[SALTS_CRYPTO_DES_BLOCK_SIZE], const uint8_t iv[SALTS_CRYPTO_DES_BLOCK_SIZE],
    const void *input, size_t size, void *output, size_t capacity);
int salts_crypto_aes128_cfb_crypt(int decrypt,
    const uint8_t key[SALTS_CRYPTO_AES128_BLOCK_SIZE], const uint8_t iv[SALTS_CRYPTO_AES128_BLOCK_SIZE],
    const void *input, size_t size, void *output, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
