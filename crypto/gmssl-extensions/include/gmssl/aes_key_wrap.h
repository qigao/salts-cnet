#ifndef GMSSL_AES_KEY_WRAP_H
#define GMSSL_AES_KEY_WRAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 3394 with the default integrity value (no RFC 5649 padding).
 * KEK length is 16, 24 or 32 bytes. Plaintext length is a multiple of 8,
 * at least 16. Wrap requires inlen + 8 output bytes; unwrap inlen - 8.
 * Buffers are caller-owned. Input/output may overlap; outlen must not overlap
 * any buffer. Returns 1 on success, -1 on invalid arguments or unwrap failure.
 * *outlen is zero on failure. Invalid arguments leave output unchanged;
 * integrity failure clears the candidate plaintext. No heap allocation.
 */
int aes_key_wrap(const uint8_t *kek, size_t keklen,
    const uint8_t *in, size_t inlen,
    uint8_t *out, size_t outmax, size_t *outlen);
int aes_key_unwrap(const uint8_t *kek, size_t keklen,
    const uint8_t *in, size_t inlen,
    uint8_t *out, size_t outmax, size_t *outlen);

#ifdef __cplusplus
}
#endif
#endif
