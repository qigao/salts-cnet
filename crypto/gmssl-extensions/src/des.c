/*
 * Legacy DES-CBC compatibility primitive for the private GmSSL vcpkg provider.
 *
 * DES is retained only for protocol compatibility. Do not use it for new
 * security designs.
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <gmssl/des.h>
#include <gmssl/mem.h>

#include <string.h>

static const uint8_t des_ip[64] = {
  58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
  62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
  57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};

static const uint8_t des_fp[64] = {
  40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
  38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
  36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};

static const uint8_t des_e[48] = {
  32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
  12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,
  24,25,24,25,26,27,28,29,28,29,30,31,32,1
};

static const uint8_t des_p[32] = {
  16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
  2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
};

static const uint8_t des_pc1[56] = {
  57,49,41,33,25,17,9,1,58,50,42,34,26,18,
  10,2,59,51,43,35,27,19,11,3,60,52,44,36,
  63,55,47,39,31,23,15,7,62,54,46,38,30,22,
  14,6,61,53,45,37,29,21,13,5,28,20,12,4
};

static const uint8_t des_pc2[48] = {
  14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
  26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
  51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
};

static const uint8_t des_shifts[16] = {
  1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

static const uint8_t des_sbox[8][64] = {
  {
    14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
    0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
    4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
    15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
  },
  {
    15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
    3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
    0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
    13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
  },
  {
    10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
    13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
    13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
  },
  {
    7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
    13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
    10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
  },
  {
    2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
    14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
    4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
    11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
  },
  {
    12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
    10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
    9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
    4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
  },
  {
    4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
    13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
    1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
    6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
  },
  {
    13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
    1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
    7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
    2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
  }
};

static uint64_t des_load_be64(const uint8_t input[DES_BLOCK_SIZE])
{
  uint64_t value = 0;
  size_t i;
  for (i = 0; i < DES_BLOCK_SIZE; ++i) {
    value = (value << 8) | input[i];
  }
  return value;
}

static void des_store_be64(uint8_t output[DES_BLOCK_SIZE], uint64_t value)
{
  size_t i;
  for (i = DES_BLOCK_SIZE; i > 0; --i) {
    output[i - 1] = (uint8_t)value;
    value >>= 8;
  }
}

static uint64_t des_permute(uint64_t input, const uint8_t *table,
                            size_t output_bits, unsigned input_bits)
{
  uint64_t output = 0;
  size_t i;
  for (i = 0; i < output_bits; ++i) {
    output = (output << 1) |
             ((input >> (input_bits - table[i])) & UINT64_C(1));
  }
  return output;
}

static uint32_t des_rotate28(uint32_t value, unsigned shift)
{
  value &= UINT32_C(0x0fffffff);
  return ((value << shift) | (value >> (28u - shift))) &
         UINT32_C(0x0fffffff);
}

static void des_make_subkeys(const uint8_t key[DES_KEY_SIZE],
                             uint64_t subkeys[16])
{
  uint64_t permuted = des_permute(des_load_be64(key), des_pc1, 56u, 64u);
  uint32_t left = (uint32_t)(permuted >> 28);
  uint32_t right = (uint32_t)permuted & UINT32_C(0x0fffffff);
  size_t i;

  for (i = 0; i < 16u; ++i) {
    left = des_rotate28(left, des_shifts[i]);
    right = des_rotate28(right, des_shifts[i]);
    subkeys[i] = des_permute(((uint64_t)left << 28) | right,
                             des_pc2, 48u, 56u);
  }
}

static uint32_t des_feistel(uint32_t right, uint64_t subkey)
{
  uint64_t expanded = des_permute(right, des_e, 48u, 32u) ^ subkey;
  uint32_t substituted = 0;
  size_t i;

  for (i = 0; i < 8u; ++i) {
    uint8_t six = (uint8_t)((expanded >> (42u - 6u * i)) & UINT64_C(0x3f));
    unsigned row = ((six & 0x20u) >> 4u) | (six & 0x01u);
    unsigned column = (six >> 1u) & 0x0fu;
    substituted = (substituted << 4) | des_sbox[i][row * 16u + column];
  }

  return (uint32_t)des_permute(substituted, des_p, 32u, 32u);
}

static uint64_t des_crypt_block(uint64_t block, const uint64_t subkeys[16],
                                int decrypt)
{
  uint64_t permuted = des_permute(block, des_ip, 64u, 64u);
  uint32_t left = (uint32_t)(permuted >> 32);
  uint32_t right = (uint32_t)permuted;
  size_t i;

  for (i = 0; i < 16u; ++i) {
    uint32_t next = left ^
        des_feistel(right, subkeys[decrypt ? (15u - i) : i]);
    left = right;
    right = next;
  }

  return des_permute(((uint64_t)right << 32) | left, des_fp, 64u, 64u);
}

int des_cbc_encrypt(const uint8_t key[DES_KEY_SIZE],
                    const uint8_t iv[DES_BLOCK_SIZE],
                    const uint8_t *in, size_t inlen, uint8_t *out)
{
  uint64_t subkeys[16];
  uint64_t previous;
  size_t offset;

  if (!key || !iv || (inlen % DES_BLOCK_SIZE) != 0u ||
      (inlen != 0u && (!in || !out))) {
    return -1;
  }

  des_make_subkeys(key, subkeys);
  previous = des_load_be64(iv);

  for (offset = 0u; offset < inlen; offset += DES_BLOCK_SIZE) {
    uint64_t block = des_load_be64(in + offset) ^ previous;
    uint64_t encrypted = des_crypt_block(block, subkeys, 0);
    des_store_be64(out + offset, encrypted);
    previous = encrypted;
  }

  gmssl_secure_clear(subkeys, sizeof(subkeys));
  return 1;
}

int des_cbc_decrypt(const uint8_t key[DES_KEY_SIZE],
                    const uint8_t iv[DES_BLOCK_SIZE],
                    const uint8_t *in, size_t inlen, uint8_t *out)
{
  uint64_t subkeys[16];
  uint64_t previous;
  size_t offset;

  if (!key || !iv || (inlen % DES_BLOCK_SIZE) != 0u ||
      (inlen != 0u && (!in || !out))) {
    return -1;
  }

  des_make_subkeys(key, subkeys);
  previous = des_load_be64(iv);

  for (offset = 0u; offset < inlen; offset += DES_BLOCK_SIZE) {
    uint64_t encrypted = des_load_be64(in + offset);
    uint64_t decrypted = des_crypt_block(encrypted, subkeys, 1) ^ previous;
    des_store_be64(out + offset, decrypted);
    previous = encrypted;
  }

  gmssl_secure_clear(subkeys, sizeof(subkeys));
  return 1;
}
