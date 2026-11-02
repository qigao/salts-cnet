/*
 * Legacy DES-CBC compatibility primitive for the private GmSSL vcpkg provider.
 *
 * DES is retained only for protocol compatibility. Do not use it for new
 * security designs.
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef GMSSL_DES_H
#define GMSSL_DES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DES_KEY_SIZE 8u
#define DES_BLOCK_SIZE 8u

int des_cbc_encrypt(const uint8_t key[DES_KEY_SIZE],
                    const uint8_t iv[DES_BLOCK_SIZE],
                    const uint8_t *in, size_t inlen, uint8_t *out);
int des_cbc_decrypt(const uint8_t key[DES_KEY_SIZE],
                    const uint8_t iv[DES_BLOCK_SIZE],
                    const uint8_t *in, size_t inlen, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* GMSSL_DES_H */
