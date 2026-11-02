/*
 * Legacy MD5 compatibility primitive for the private GmSSL vcpkg provider.
 *
 * MD5 is retained only for protocol compatibility. Do not use it for new
 * security designs.
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef GMSSL_MD5_H
#define GMSSL_MD5_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MD5_DIGEST_SIZE 16u
#define MD5_BLOCK_SIZE 64u

typedef struct {
    uint32_t state[4];
    uint64_t nbytes;
    uint8_t block[MD5_BLOCK_SIZE];
    size_t num;
} MD5_CTX;

void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t datalen);
void md5_finish(MD5_CTX *ctx, uint8_t dgst[MD5_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* GMSSL_MD5_H */
