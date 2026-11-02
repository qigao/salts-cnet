#ifndef GMSSL_RSA_COMPONENTS_H
#define GMSSL_RSA_COMPONENTS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Additive key ABI for JOSE consumers. Unlike rsa.h, it admits non-aligned
 * moduli and n/e/d private keys. Canonical unsigned big-endian components:
 * modulus 512..8192 bits, odd exponent 3..2^33-1, optional 0 < d < n.
 * All storage is caller-owned, immutable during operations, and wiped with
 * rsa_components_cleanup. Import commits only after successful validation.
 */
#define RSA_COMPONENTS_MAX_SIZE 1024
typedef struct {
    size_t size;
    uint8_t n[RSA_COMPONENTS_MAX_SIZE];
    uint8_t d[RSA_COMPONENTS_MAX_SIZE];
    uint64_t e;
    int has_private;
} RSA_COMPONENTS;
int rsa_components_import(RSA_COMPONENTS *key,
    const uint8_t *n, size_t nlen, const uint8_t *e, size_t elen,
    const uint8_t *d, size_t dlen);
void rsa_components_cleanup(RSA_COMPONENTS *key);
/* Validates a complete optional CRT tuple against n/e/d; 1 valid, -1 invalid. */
int rsa_components_check_crt(const RSA_COMPONENTS *key,
    const uint8_t *p, size_t plen, const uint8_t *q, size_t qlen,
    const uint8_t *dp, size_t dplen, const uint8_t *dq, size_t dqlen,
    const uint8_t *qi, size_t qilen);
/* Raw representative operations: inlen == key->size, input < n. Output may
 * alias input, but neither may alias key/outlen. 1 succeeds; -1 fails with
 * outlen zero and output unchanged. Private operations use fresh random base
 * blinding and verify the result before release. No unblinded fallback.
 */
int rsa_components_public(const RSA_COMPONENTS *key, const uint8_t *in, size_t inlen,
    uint8_t *out, size_t capacity, size_t *outlen);
int rsa_components_private(const RSA_COMPONENTS *key, const uint8_t *in, size_t inlen,
    uint8_t *out, size_t capacity, size_t *outlen);
#ifdef __cplusplus
}
#endif
#endif
