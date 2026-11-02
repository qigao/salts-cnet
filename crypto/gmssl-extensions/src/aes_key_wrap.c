#include <gmssl/aes_key_wrap.h>
#include <gmssl/aes.h>
#include <gmssl/mem.h>
#include <string.h>

static const uint8_t wrap_iv[8] = {
    0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6
};

static void wrap_xor_counter(uint8_t a[8], uint64_t counter)
{
    size_t j;
    for (j = 8; j > 0; --j) {
        a[j - 1] ^= (uint8_t)counter;
        counter >>= 8;
    }
}

int aes_key_wrap(const uint8_t *kek, size_t keklen,
    const uint8_t *in, size_t inlen,
    uint8_t *out, size_t outmax, size_t *outlen)
{
    AES_KEY key;
    uint8_t block[16];
    size_t n, i, j;
    if (outlen) *outlen = 0;
    if (!kek || !in || !out || !outlen ||
        (keklen != 16 && keklen != 24 && keklen != 32) ||
        inlen < 16 || inlen % 8 || inlen > SIZE_MAX - 8 ||
        outmax < inlen + 8 || inlen / 8 > UINT64_MAX / 6) return -1;
    if (aes_set_encrypt_key(&key, kek, keklen) != 1) {
        gmssl_secure_clear(&key, sizeof(key));
        return -1;
    }
    n = inlen / 8;
    memmove(out + 8, in, inlen);
    memcpy(out, wrap_iv, 8);
    for (j = 0; j < 6; ++j) {
        for (i = 1; i <= n; ++i) {
            memcpy(block, out, 8);
            memcpy(block + 8, out + i * 8, 8);
            aes_encrypt(&key, block, block);
            wrap_xor_counter(block, (uint64_t)n * j + i);
            memcpy(out, block, 8);
            memcpy(out + i * 8, block + 8, 8);
        }
    }
    *outlen = inlen + 8;
    gmssl_secure_clear(block, sizeof(block));
    gmssl_secure_clear(&key, sizeof(key));
    return 1;
}

int aes_key_unwrap(const uint8_t *kek, size_t keklen,
    const uint8_t *in, size_t inlen,
    uint8_t *out, size_t outmax, size_t *outlen)
{
    AES_KEY key;
    uint8_t block[16], a[8];
    size_t n, i, j;
    int ret;
    if (outlen) *outlen = 0;
    if (!kek || !in || !out || !outlen ||
        (keklen != 16 && keklen != 24 && keklen != 32) ||
        inlen < 24 || inlen % 8 || outmax < inlen - 8 ||
        (inlen - 8) / 8 > UINT64_MAX / 6) return -1;
    if (aes_set_decrypt_key(&key, kek, keklen) != 1) {
        gmssl_secure_clear(&key, sizeof(key));
        return -1;
    }
    n = inlen / 8 - 1;
    memcpy(a, in, 8);
    memmove(out, in + 8, inlen - 8);
    for (j = 6; j > 0; --j) {
        for (i = n; i > 0; --i) {
            memcpy(block, a, 8);
            wrap_xor_counter(block, (uint64_t)n * (j - 1) + i);
            memcpy(block + 8, out + (i - 1) * 8, 8);
            aes_decrypt(&key, block, block);
            memcpy(a, block, 8);
            memcpy(out + (i - 1) * 8, block + 8, 8);
        }
    }
    ret = gmssl_secure_memcmp(a, wrap_iv, 8) == 0 ? 1 : -1;
    if (ret == 1) *outlen = inlen - 8;
    else gmssl_secure_clear(out, inlen - 8);
    gmssl_secure_clear(a, sizeof(a));
    gmssl_secure_clear(block, sizeof(block));
    gmssl_secure_clear(&key, sizeof(key));
    return ret;
}
