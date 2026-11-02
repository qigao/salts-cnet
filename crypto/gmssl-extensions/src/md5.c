/*
 * Legacy MD5 compatibility primitive for the private GmSSL vcpkg provider.
 *
 * MD5 is retained only for protocol compatibility. Do not use it for new
 * security designs.
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <gmssl/md5.h>

#include <string.h>

#define MD5_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))
#define MD5_ROTL32(x, n) (((x) << (n)) | ((x) >> (32u - (n))))
#define MD5_STEP(fn, a, b, c, d, x, t, s)                                \
    do {                                                                  \
        (a) += fn((b), (c), (d)) + (x) + UINT32_C(t);                    \
        (a) = MD5_ROTL32((a), (s));                                       \
        (a) += (b);                                                       \
    } while (0)

static uint32_t md5_load_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static void md5_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void md5_transform(MD5_CTX *ctx, const uint8_t block[MD5_BLOCK_SIZE])
{
    uint32_t x[16];
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    size_t i;

    for (i = 0; i < 16; ++i) {
        x[i] = md5_load_le32(block + 4u * i);
    }

    MD5_STEP(MD5_F, a, b, c, d, x[0], 0xd76aa478, 7);
    MD5_STEP(MD5_F, d, a, b, c, x[1], 0xe8c7b756, 12);
    MD5_STEP(MD5_F, c, d, a, b, x[2], 0x242070db, 17);
    MD5_STEP(MD5_F, b, c, d, a, x[3], 0xc1bdceee, 22);
    MD5_STEP(MD5_F, a, b, c, d, x[4], 0xf57c0faf, 7);
    MD5_STEP(MD5_F, d, a, b, c, x[5], 0x4787c62a, 12);
    MD5_STEP(MD5_F, c, d, a, b, x[6], 0xa8304613, 17);
    MD5_STEP(MD5_F, b, c, d, a, x[7], 0xfd469501, 22);
    MD5_STEP(MD5_F, a, b, c, d, x[8], 0x698098d8, 7);
    MD5_STEP(MD5_F, d, a, b, c, x[9], 0x8b44f7af, 12);
    MD5_STEP(MD5_F, c, d, a, b, x[10], 0xffff5bb1, 17);
    MD5_STEP(MD5_F, b, c, d, a, x[11], 0x895cd7be, 22);
    MD5_STEP(MD5_F, a, b, c, d, x[12], 0x6b901122, 7);
    MD5_STEP(MD5_F, d, a, b, c, x[13], 0xfd987193, 12);
    MD5_STEP(MD5_F, c, d, a, b, x[14], 0xa679438e, 17);
    MD5_STEP(MD5_F, b, c, d, a, x[15], 0x49b40821, 22);

    MD5_STEP(MD5_G, a, b, c, d, x[1], 0xf61e2562, 5);
    MD5_STEP(MD5_G, d, a, b, c, x[6], 0xc040b340, 9);
    MD5_STEP(MD5_G, c, d, a, b, x[11], 0x265e5a51, 14);
    MD5_STEP(MD5_G, b, c, d, a, x[0], 0xe9b6c7aa, 20);
    MD5_STEP(MD5_G, a, b, c, d, x[5], 0xd62f105d, 5);
    MD5_STEP(MD5_G, d, a, b, c, x[10], 0x02441453, 9);
    MD5_STEP(MD5_G, c, d, a, b, x[15], 0xd8a1e681, 14);
    MD5_STEP(MD5_G, b, c, d, a, x[4], 0xe7d3fbc8, 20);
    MD5_STEP(MD5_G, a, b, c, d, x[9], 0x21e1cde6, 5);
    MD5_STEP(MD5_G, d, a, b, c, x[14], 0xc33707d6, 9);
    MD5_STEP(MD5_G, c, d, a, b, x[3], 0xf4d50d87, 14);
    MD5_STEP(MD5_G, b, c, d, a, x[8], 0x455a14ed, 20);
    MD5_STEP(MD5_G, a, b, c, d, x[13], 0xa9e3e905, 5);
    MD5_STEP(MD5_G, d, a, b, c, x[2], 0xfcefa3f8, 9);
    MD5_STEP(MD5_G, c, d, a, b, x[7], 0x676f02d9, 14);
    MD5_STEP(MD5_G, b, c, d, a, x[12], 0x8d2a4c8a, 20);

    MD5_STEP(MD5_H, a, b, c, d, x[5], 0xfffa3942, 4);
    MD5_STEP(MD5_H, d, a, b, c, x[8], 0x8771f681, 11);
    MD5_STEP(MD5_H, c, d, a, b, x[11], 0x6d9d6122, 16);
    MD5_STEP(MD5_H, b, c, d, a, x[14], 0xfde5380c, 23);
    MD5_STEP(MD5_H, a, b, c, d, x[1], 0xa4beea44, 4);
    MD5_STEP(MD5_H, d, a, b, c, x[4], 0x4bdecfa9, 11);
    MD5_STEP(MD5_H, c, d, a, b, x[7], 0xf6bb4b60, 16);
    MD5_STEP(MD5_H, b, c, d, a, x[10], 0xbebfbc70, 23);
    MD5_STEP(MD5_H, a, b, c, d, x[13], 0x289b7ec6, 4);
    MD5_STEP(MD5_H, d, a, b, c, x[0], 0xeaa127fa, 11);
    MD5_STEP(MD5_H, c, d, a, b, x[3], 0xd4ef3085, 16);
    MD5_STEP(MD5_H, b, c, d, a, x[6], 0x04881d05, 23);
    MD5_STEP(MD5_H, a, b, c, d, x[9], 0xd9d4d039, 4);
    MD5_STEP(MD5_H, d, a, b, c, x[12], 0xe6db99e5, 11);
    MD5_STEP(MD5_H, c, d, a, b, x[15], 0x1fa27cf8, 16);
    MD5_STEP(MD5_H, b, c, d, a, x[2], 0xc4ac5665, 23);

    MD5_STEP(MD5_I, a, b, c, d, x[0], 0xf4292244, 6);
    MD5_STEP(MD5_I, d, a, b, c, x[7], 0x432aff97, 10);
    MD5_STEP(MD5_I, c, d, a, b, x[14], 0xab9423a7, 15);
    MD5_STEP(MD5_I, b, c, d, a, x[5], 0xfc93a039, 21);
    MD5_STEP(MD5_I, a, b, c, d, x[12], 0x655b59c3, 6);
    MD5_STEP(MD5_I, d, a, b, c, x[3], 0x8f0ccc92, 10);
    MD5_STEP(MD5_I, c, d, a, b, x[10], 0xffeff47d, 15);
    MD5_STEP(MD5_I, b, c, d, a, x[1], 0x85845dd1, 21);
    MD5_STEP(MD5_I, a, b, c, d, x[8], 0x6fa87e4f, 6);
    MD5_STEP(MD5_I, d, a, b, c, x[15], 0xfe2ce6e0, 10);
    MD5_STEP(MD5_I, c, d, a, b, x[6], 0xa3014314, 15);
    MD5_STEP(MD5_I, b, c, d, a, x[13], 0x4e0811a1, 21);
    MD5_STEP(MD5_I, a, b, c, d, x[4], 0xf7537e82, 6);
    MD5_STEP(MD5_I, d, a, b, c, x[11], 0xbd3af235, 10);
    MD5_STEP(MD5_I, c, d, a, b, x[2], 0x2ad7d2bb, 15);
    MD5_STEP(MD5_I, b, c, d, a, x[9], 0xeb86d391, 21);

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;

    memset(x, 0, sizeof(x));
}

void md5_init(MD5_CTX *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = UINT32_C(0x67452301);
    ctx->state[1] = UINT32_C(0xefcdab89);
    ctx->state[2] = UINT32_C(0x98badcfe);
    ctx->state[3] = UINT32_C(0x10325476);
}

void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t datalen)
{
    size_t n;

    if (datalen == 0u) {
        return;
    }

    ctx->nbytes += (uint64_t)datalen;

    if (ctx->num != 0u) {
        n = MD5_BLOCK_SIZE - ctx->num;
        if (n > datalen) {
            n = datalen;
        }
        memcpy(ctx->block + ctx->num, data, n);
        ctx->num += n;
        data += n;
        datalen -= n;
        if (ctx->num == MD5_BLOCK_SIZE) {
            md5_transform(ctx, ctx->block);
            ctx->num = 0u;
        }
    }

    while (datalen >= MD5_BLOCK_SIZE) {
        md5_transform(ctx, data);
        data += MD5_BLOCK_SIZE;
        datalen -= MD5_BLOCK_SIZE;
    }

    if (datalen != 0u) {
        memcpy(ctx->block, data, datalen);
        ctx->num = datalen;
    }
}

void md5_finish(MD5_CTX *ctx, uint8_t dgst[MD5_DIGEST_SIZE])
{
    uint64_t bits = ctx->nbytes * UINT64_C(8);
    size_t n = ctx->num;
    size_t i;

    ctx->block[n++] = 0x80u;
    if (n > 56u) {
        memset(ctx->block + n, 0, MD5_BLOCK_SIZE - n);
        md5_transform(ctx, ctx->block);
        n = 0u;
    }

    memset(ctx->block + n, 0, 56u - n);
    for (i = 0; i < 8u; ++i) {
        ctx->block[56u + i] = (uint8_t)(bits >> (8u * i));
    }
    md5_transform(ctx, ctx->block);

    for (i = 0; i < 4u; ++i) {
        md5_store_le32(dgst + 4u * i, ctx->state[i]);
    }
}
