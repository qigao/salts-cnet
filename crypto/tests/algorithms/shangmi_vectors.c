#include <crypto/sm3.h>
#include <crypto/sm2.h>
#include <crypto/zuc.h>
#include <crypto/sm4.h>
#include <tinytest.h>
#include <string.h>

static int matches_hex(const uint8_t *bytes, size_t size, const char *hex) {
  static const char alphabet[] = "0123456789abcdef";
  if (strlen(hex) != size * 2u) return 0;
  for (size_t i = 0; i < size; ++i)
    if (alphabet[bytes[i] >> 4u] != hex[2u*i] || alphabet[bytes[i] & 15u] != hex[2u*i+1u]) return 0;
  return 1;
}

static const uint8_t sm4_key[16] = {
  0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};

spec("Public ShangMi algorithms") {
  it("verifies the existing fixed SM2 fixture through the public facade") {
    /* Same fixed key/signature as the provider qualification fixture. */
    const uint8_t pub[65] = {0x04,0x47,0xd8,0x09,0x76,0x9c,0x27,0xd8,0xce,0xae,0x28,0x68,0x51,0xd1,0x1d,0x42,0x24,0x63,0xf0,0x2b,0x84,0x88,0xed,0xaa,0xb4,0xcb,0xe7,0x64,0xf2,0xb0,0xf6,0x7e,0xd4,0xfb,0xc7,0xef,0x9a,0xd7,0x29,0x2c,0xcc,0x25,0x6c,0x58,0x3b,0x22,0x85,0x81,0xa4,0x5e,0x17,0x34,0x17,0xee,0xa7,0x7a,0x22,0xbd,0xb8,0x66,0xb0,0xb6,0x64,0xae,0x19};
    uint8_t signature[64] = {0x79,0xc5,0xcf,0xfc,0x33,0xa5,0xd8,0x34,0x6a,0x9a,0xb0,0xd7,0xe3,0xda,0xdb,0xcb,0x79,0x64,0xee,0x0e,0x4d,0x6d,0xfd,0xf6,0xbc,0x53,0x2a,0x58,0xb6,0xa9,0xd1,0xb9,0xb4,0xd5,0x28,0xe4,0x8e,0x3a,0x52,0x96,0xd0,0xb2,0xe7,0x2f,0xa9,0xe1,0xd1,0x55,0x6f,0x94,0xc6,0xf0,0xd1,0xae,0x7a,0x5e,0x42,0x2d,0x28,0xb6,0x1d,0xfa,0x6e,0x79};
    const char message[] = "CNet-ShangMi-SM2-KAT-v1";
    check_equal(salts_crypto_sm2_verify(pub, SALTS_CRYPTO_SM2_DEFAULT_ID, 16u,
        message, sizeof(message)-1u, signature), SALTS_CRYPTO_OK);
    signature[0] ^= 1u;
    check_equal(salts_crypto_sm2_verify(pub, SALTS_CRYPTO_SM2_DEFAULT_ID, 16u,
        message, sizeof(message)-1u, signature), SALTS_CRYPTO_EVERIFY);
  }
  it("matches ZUC128 and ZUC256 keystream vectors including partial final words") {
    const uint8_t key[32] = {0}, iv[23] = {0}, plain[17] = {0};
    uint8_t cipher[17], restored[17];
    check_equal(salts_crypto_zuc_crypt(SALTS_CRYPTO_ZUC128, key, 16u, iv, 16u, plain, 8u, cipher, 17u), SALTS_CRYPTO_OK);
    check_true(matches_hex(cipher, 8u, "27bede74018082da"));
    check_equal(salts_crypto_zuc_crypt(SALTS_CRYPTO_ZUC256, key, 32u, iv, 23u, plain, 17u, cipher, 17u), SALTS_CRYPTO_OK);
    check_true(matches_hex(cipher, 17u, "58d03ad62e032ce2dafc683a39bdcb0352"));
    check_equal(salts_crypto_zuc_crypt(SALTS_CRYPTO_ZUC256, key, 32u, iv, 23u, cipher, 17u, restored, 17u), SALTS_CRYPTO_OK);
    check_equal(restored, plain, sizeof(plain));
    check_equal(salts_crypto_zuc_crypt(SALTS_CRYPTO_ZUC256, key, 16u, iv, 23u, plain, 17u, cipher, 17u), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_zuc_crypt(SALTS_CRYPTO_ZUC128, key, 16u, iv, 16u, plain, 8189u, cipher, 8189u), SALTS_CRYPTO_EINVAL);
  }
  it("matches ZUC256 MAC vectors and verifies all supported tag lengths") {
    const uint8_t key[32] = {0}, iv[23] = {0};
    uint8_t message[50] = {0}, tag[16], tail_tag[16];
    const size_t sizes[] = {4u, 8u, 16u};
    const char *expected[] = {"9b972a74", "673e54990034d38c", "d85e54bbcb9600967084c952a1654b26"};
    for (size_t i = 0; i < 3u; ++i) {
      check_equal(salts_crypto_zuc_mac(SALTS_CRYPTO_ZUC256, key, 32u, iv, 23u, message, 400u, tag, sizes[i]), SALTS_CRYPTO_OK);
      check_true(matches_hex(tag, sizes[i], expected[i]));
      check_equal(salts_crypto_zuc_verify(SALTS_CRYPTO_ZUC256, key, 32u, iv, 23u, message, 400u, tag, sizes[i]), SALTS_CRYPTO_OK);
      tag[sizes[i]-1u] ^= 1u;
      check_equal(salts_crypto_zuc_verify(SALTS_CRYPTO_ZUC256, key, 32u, iv, 23u, message, 400u, tag, sizes[i]), SALTS_CRYPTO_EVERIFY);
    }
    check_equal(salts_crypto_zuc_mac(SALTS_CRYPTO_ZUC128, key, 16u, iv, 16u, message, 1u, tag, 4u), SALTS_CRYPTO_OK);
    /* 3GPP 128-EIA3 all-zero key/IV, one zero bit. */
    check_true(matches_hex(tag, 4u, "c8a9595e"));
    message[0] = 0x7f;
    check_equal(salts_crypto_zuc_mac(SALTS_CRYPTO_ZUC128, key, 16u, iv, 16u, message, 1u, tail_tag, 4u), SALTS_CRYPTO_OK);
    check_equal(tag, tail_tag, 4u);
    check_equal(salts_crypto_zuc_mac(SALTS_CRYPTO_ZUC128, key, 16u, iv, 16u, message, 400u, tag, 8u), SALTS_CRYPTO_EINVAL);
  }
  it("rejects oversized SM3 input without returning a digest of a shorter message") {
    uint8_t out[32], snapshot[32];
    memset(out, 0xa5, sizeof(out)); memcpy(snapshot, out, sizeof(out));
    check_equal(salts_crypto_sm3("x", (size_t)(UINT64_MAX / 8u + 1u), out), SALTS_CRYPTO_EINVAL);
    check_equal(out, snapshot, sizeof(out));
    check_equal(salts_crypto_hmac_sm3("k", 1u, "x", (size_t)(UINT64_MAX / 8u), out), SALTS_CRYPTO_EINVAL);
    check_equal(out, snapshot, sizeof(out));
    check_equal(salts_crypto_hmac_sm3("k", (size_t)(UINT64_MAX / 8u + 1u), NULL, 0u, out), SALTS_CRYPTO_EINVAL);
    check_equal(out, snapshot, sizeof(out));
  }
  it("derives the standard curveSM2 generator and binds signatures to identity and message") {
    uint8_t secret[32] = {0}, pub[65], signature[64], bad[65] = {4};
    secret[31] = 1u;
    check_equal(salts_crypto_sm2_public_key(secret, pub), SALTS_CRYPTO_OK);
    /* GB/T 32918.5 curveSM2 generator, also RFC 8998 section 3.2.1. */
    check_true(matches_hex(pub, sizeof(pub), "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"));
    check_equal(salts_crypto_sm2_sign(secret, "Alice", 5u, "message", 7u, signature), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_verify(pub, "Alice", 5u, "message", 7u, signature), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_verify(pub, "Bob", 3u, "message", 7u, signature), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm2_verify(pub, "Alice", 5u, "messagE", 7u, signature), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm2_verify(bad, "Alice", 5u, "message", 7u, signature), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_sign(secret, NULL, 0u, "message", 7u, signature), SALTS_CRYPTO_EINVAL);
    memset(secret, 0, sizeof(secret));
    check_equal(salts_crypto_sm2_public_key(secret, pub), SALTS_CRYPTO_EINVAL);
    memset(secret, 0xff, sizeof(secret));
    check_equal(salts_crypto_sm2_public_key(secret, pub), SALTS_CRYPTO_EINVAL);
  }
  it("authenticates maximum-size SM2 ciphertext and rejects malformed encodings") {
    uint8_t secret[32], pub[65], plain[255], restored[255], cipher[367], zeros[255] = {0};
    size_t encrypted = 0, decrypted = 0;
    for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)i;
    check_equal(salts_crypto_sm2_keygen(secret, pub), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_encrypt(pub, plain, sizeof(plain), cipher, sizeof(cipher), &encrypted), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_decrypt(secret, cipher, encrypted, restored, sizeof(restored), &decrypted), SALTS_CRYPTO_OK);
    check_equal(decrypted, sizeof(plain));
    check_equal(restored, plain, sizeof(plain));
    cipher[encrypted - 1u] ^= 1u;
    check_equal(salts_crypto_sm2_decrypt(secret, cipher, encrypted, restored, sizeof(restored), &decrypted), SALTS_CRYPTO_EVERIFY);
    check_equal(decrypted, 0u); check_equal(restored, zeros, sizeof(restored));
    cipher[encrypted - 1u] ^= 1u;
    check_equal(salts_crypto_sm2_decrypt(secret, cipher, encrypted - 1u, restored, sizeof(restored), &decrypted), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm2_encrypt(pub, plain, sizeof(plain), cipher, 365u, &encrypted), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_encrypt(pub, plain, 0u, cipher, sizeof(cipher), &encrypted), SALTS_CRYPTO_EINVAL);
    memset(secret, 0, sizeof(secret));
  }
  it("matches the SM3 abc vector across fragmented streaming and rejects reuse") {
    salts_crypto_sm3_ctx_t ctx = {0};
    uint8_t digest[32], single[32], cleared[sizeof(ctx)];
    memset(cleared, 0, sizeof(cleared));
    check_equal(salts_crypto_sm3_update(&ctx, "a", 1u), SALTS_CRYPTO_ESTATE);
    check_equal(salts_crypto_sm3_init(&ctx), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm3_update(&ctx, "a", 1u), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm3_update(&ctx, NULL, 0u), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm3_update(&ctx, "bc", 2u), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm3_final(&ctx, ctx.bytes), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm3_final(&ctx, digest), SALTS_CRYPTO_OK);
    check_true(matches_hex(digest, sizeof(digest), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"));
    check_equal(ctx.bytes, cleared, sizeof(ctx));
    check_equal(salts_crypto_sm3_final(&ctx, digest), SALTS_CRYPTO_ESTATE);
    check_equal(salts_crypto_sm3("abc", 3u, single), SALTS_CRYPTO_OK);
    check_equal(single, digest, sizeof(single));
    check_equal(salts_crypto_sm3(NULL, 1u, single), SALTS_CRYPTO_EINVAL);
  }
  it("matches HMAC/HKDF/PBKDF2 independent vectors through public APIs") {
    uint8_t key[20], mac[32], prk[32], out[32], snapshot[32];
    salts_crypto_sm3_ctx_t ctx = {0};
    memset(key, 0x0b, sizeof(key));
    check_equal(salts_crypto_hmac_sm3_init(&ctx, key, sizeof(key)), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm3_update(&ctx, "Hi ", 3u), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm3_update(&ctx, "There", 5u), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm3_final(&ctx, mac), SALTS_CRYPTO_OK);
    check_true(matches_hex(mac, 32u, "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"));
    check_equal(salts_crypto_hkdf_sm3_extract("salt", 4u, "input key material", 18u, prk), SALTS_CRYPTO_OK);
    check_true(matches_hex(prk, 32u, "8f09fbbd810b19aefe363b296b6865686a3e2c9b2edaa6d310df72d029b5077b"));
    check_equal(salts_crypto_hkdf_sm3_expand(prk, "context", 7u, out, sizeof(out)), SALTS_CRYPTO_OK);
    check_true(matches_hex(out, 32u, "181ad115657b29aa306ec15487f83d95f6a9e123b78de5fa2c2a4d6a299ec653"));
    memcpy(snapshot, prk, sizeof(prk));
    check_equal(salts_crypto_hkdf_sm3_expand(prk, NULL, 0u, prk, 32u), SALTS_CRYPTO_EINVAL);
    check_equal(prk, snapshot, sizeof(prk));
    check_equal(salts_crypto_hkdf_sm3_expand(prk, NULL, 0u, out, 8161u), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_pbkdf2_sm3("password", 8u, "salt", 4u, 10000u, out, 32u), SALTS_CRYPTO_OK);
    /* Python hashlib/OpenSSL independent PBKDF2-HMAC-SM3 reference. */
    check_true(matches_hex(out, 32u, "738c8c432372d98a73350bc252209e4cf2acdde7cc816730b9812bdfd55c1265"));
    memcpy(snapshot, out, sizeof(out));
    check_equal(salts_crypto_pbkdf2_sm3("password", 8u, "salt", 4u, 0u, out, 32u), SALTS_CRYPTO_EINVAL);
    check_equal(out, snapshot, sizeof(out));
  }
  it("matches the SM4 block standard and independent CBC/CTR/CFB/OFB vectors") {
    uint8_t out[32], plain[32], restored[32], iv[16];
    static const struct { salts_crypto_sm4_mode mode; const char *cipher; } vectors[] = {
      {SALTS_CRYPTO_SM4_CBC, "2677f46b09c122cc975533105bd4a22ad9ee98830e69745c9827f934a19621f8"},
      {SALTS_CRYPTO_SM4_CTR, "06999e6239a36eaa2284fd89eda5f7657f161f5854b6ea16c28809fe9d1db305"},
      {SALTS_CRYPTO_SM4_CFB128, "06999e6239a36eaa2284fd89eda5f765cab243c911b87479b3c487b45ecea658"},
      {SALTS_CRYPTO_SM4_OFB, "06999e6239a36eaa2284fd89eda5f765e3fe505fa3964c6a7946f68fc13ef63f"}
    };
    check_equal(salts_crypto_sm4_crypt(SALTS_CRYPTO_SM4_ECB, 0, sm4_key, 16u, NULL, sm4_key, 16u, out, sizeof(out)), SALTS_CRYPTO_OK);
    check_true(matches_hex(out, 16u, "681edf34d206965e86b3e94f536e4246"));
    for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(iv); ++i) iv[i] = (uint8_t)i;
    /* CBC/CTR/CFB128/OFB outputs generated independently with Python
     * cryptography's SM4 implementation, using these exact key/IV/inputs. */
    for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); ++i) {
      check_equal(salts_crypto_sm4_crypt(vectors[i].mode, 0, sm4_key, 16u, iv, plain, 32u, out, 32u), SALTS_CRYPTO_OK);
      check_true(matches_hex(out, 32u, vectors[i].cipher));
      check_equal(salts_crypto_sm4_crypt(vectors[i].mode, 1, sm4_key, 16u, iv, out, 32u, restored, 32u), SALTS_CRYPTO_OK);
      check_equal(restored, plain, 32u);
    }
    memset(iv, 0xff, sizeof(iv));
    memset(out, 0xa5, sizeof(out));
    check_equal(salts_crypto_sm4_crypt(SALTS_CRYPTO_SM4_CTR, 0, sm4_key, 16u, iv, plain, 17u, out, 32u), SALTS_CRYPTO_EINVAL);
    check_equal(out[0], 0xa5u);
    check_equal(salts_crypto_sm4_crypt(SALTS_CRYPTO_SM4_CBC, 0, sm4_key, 16u, iv, plain, 17u, out, 32u), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm4_crypt(SALTS_CRYPTO_SM4_ECB, 0, sm4_key, 16u, NULL, plain, 16u, plain, 32u), SALTS_CRYPTO_EINVAL);
  }
  it("preserves partial-segment CFB and ciphertext-stealing XTS lengths") {
    uint8_t key[32], iv[16] = {0}, plain[47], cipher[47], restored[47];
    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i*3u);
    const salts_crypto_sm4_mode modes[] = {SALTS_CRYPTO_SM4_CFB8, SALTS_CRYPTO_SM4_CFB64, SALTS_CRYPTO_SM4_CFB128, SALTS_CRYPTO_SM4_XTS};
    for (size_t i = 0; i < sizeof(modes)/sizeof(modes[0]); ++i) {
      size_t kn = modes[i] == SALTS_CRYPTO_SM4_XTS ? 32u : 16u;
      check_equal(salts_crypto_sm4_crypt(modes[i], 0, key, kn, iv, plain, 47u, cipher, 47u), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm4_crypt(modes[i], 1, key, kn, iv, cipher, 47u, restored, 47u), SALTS_CRYPTO_OK);
      check_equal(restored, plain, 47u);
    }
    memset(key, 0, sizeof(key));
    check_equal(salts_crypto_sm4_crypt(SALTS_CRYPTO_SM4_XTS, 0, key, 32u, iv, plain, 47u, cipher, 47u), SALTS_CRYPTO_EINVAL);
  }
  for (unsigned mode = SALTS_CRYPTO_SM4_GCM; mode <= SALTS_CRYPTO_SM4_CCM; ++mode) {
    it("authenticates SM4 AEAD mode %u before publishing usable plaintext", mode) {
      const uint8_t iv[12] = {0x00,0x00,0x12,0x34,0x56,0x78,0x00,0x00,0x00,0x00,0xab,0xcd};
      const uint8_t aad[20] = {0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2};
      const uint8_t fill[] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0xee,0xaa};
      uint8_t plain[64], cipher[64], restored[64], tag[16], zeros[64] = {0};
      for (size_t i = 0; i < 64u; ++i) plain[i] = fill[i/8u];
      check_equal(salts_crypto_sm4_aead_encrypt((salts_crypto_sm4_aead)mode, sm4_key, iv, 12u, aad, 20u, plain, 64u, cipher, 64u, tag, 16u), SALTS_CRYPTO_OK);
      if (mode == SALTS_CRYPTO_SM4_GCM) {
        /* RFC 8998 Appendix A.1. */
        check_true(matches_hex(cipher, 64u, "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d"));
        check_true(matches_hex(tag, 16u, "83de3541e4c2b58177e065a9bf7b62ec"));
      } else {
        /* RFC 8998 Appendix A.2. */
        check_true(matches_hex(cipher, 64u, "48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b"));
        check_true(matches_hex(tag, 16u, "16842d4fa186f56ab33256971fa110f4"));
      }
      check_equal(salts_crypto_sm4_aead_decrypt((salts_crypto_sm4_aead)mode, sm4_key, iv, 12u, aad, 20u, cipher, 64u, tag, 16u, restored, 64u), SALTS_CRYPTO_OK);
      check_equal(restored, plain, 64u);
      tag[0] ^= 1u;
      check_equal(salts_crypto_sm4_aead_decrypt((salts_crypto_sm4_aead)mode, sm4_key, iv, 12u, aad, 20u, cipher, 64u, tag, 16u, restored, 64u), SALTS_CRYPTO_EVERIFY);
      check_equal(restored, zeros, 64u);
      check_equal(salts_crypto_sm4_aead_encrypt((salts_crypto_sm4_aead)mode, sm4_key, iv, 12u, NULL, 0u, NULL, 0u, NULL, 0u, tag, 16u), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm4_aead_decrypt((salts_crypto_sm4_aead)mode, sm4_key, iv, 12u, NULL, 0u, NULL, 0u, tag, 16u, NULL, 0u), SALTS_CRYPTO_OK);
    }
  }
}
