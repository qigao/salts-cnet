#include <crypto/symmetric.h>
#include <crypto/key.h>
#include <crypto/sha256.h>
#include <tinytest.h>
#include <stdio.h>
#include <string.h>

static void from_hex(uint8_t *output, size_t size, const char *hex) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < size; ++i) {
    const char *hi = strchr(digits, hex[2u*i]);
    const char *lo = strchr(digits, hex[2u*i+1u]);
    output[i] = (uint8_t)(((hi-digits)<<4) | (lo-digits));
  }
}

spec("Crypto public primitives") {
  static salts_crypto_key *private_key, *public_key;
  static FILE *fixture;
  before_each() { private_key = NULL; public_key = NULL; fixture = NULL; }
  after_each() {
    salts_crypto_key_destroy(private_key);
    salts_crypto_key_destroy(public_key);
    if (fixture) fclose(fixture);
  }

  it("matches MD5 and SHA-1 interoperability vectors and SHA-256 streaming") {
    uint8_t output[64], expected[64]; size_t n = 99;
    from_hex(expected, 16, "900150983cd24fb0d6963f7d28e17f72");
    check_equal(salts_crypto_md5("abc", 3, output), SALTS_CRYPTO_OK);
    check_equal(output, expected, 16);
    from_hex(expected, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    check_equal(salts_crypto_digest(SALTS_CRYPTO_SHA1, "abc", 3, output, sizeof(output), &n), SALTS_CRYPTO_OK);
    check_equal(n, 20u); check_equal(output, expected, 20);
    from_hex(expected, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_equal(salts_crypto_digest(SALTS_CRYPTO_SHA256, "abc", 3, output, sizeof(output), &n), SALTS_CRYPTO_OK);
    check_equal(n, 32u); check_equal(output, expected, 32);
    salts_crypto_sha256_ctx_t context;
    check_equal(salts_crypto_sha256_init(&context), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sha256_update(&context, "a", 1), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sha256_update(&context, "bc", 2), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sha256_final(&context, output), SALTS_CRYPTO_OK);
    check_equal(output, expected, 32);
    check_equal(salts_crypto_sha256_update(&context, "x", 1), SALTS_CRYPTO_ESTATE);
    check_equal(salts_crypto_sha256_final(&context, output), SALTS_CRYPTO_ESTATE);
    check_equal(salts_crypto_digest((salts_crypto_hash)99, "abc", 3, output, sizeof(output), &n), SALTS_CRYPTO_EINVAL);
    check_equal(n, 0u);
  }

  it("accepts empty protocol inputs and rejects nonempty NULL buffers") {
    uint8_t output[32], expected[32]; size_t n;
    from_hex(expected, 16, "d41d8cd98f00b204e9800998ecf8427e");
    check_equal(salts_crypto_md5(NULL, 0, output), SALTS_CRYPTO_OK);
    check_equal(output, expected, 16);
    from_hex(expected, 20, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    check_equal(salts_crypto_digest(SALTS_CRYPTO_SHA1, NULL, 0, output, sizeof(output), &n), SALTS_CRYPTO_OK);
    check_equal(n, 20u); check_equal(output, expected, 20);
    from_hex(expected, 32, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    check_equal(salts_crypto_hmac(SALTS_CRYPTO_SHA256, NULL, 0, NULL, 0, output, sizeof(output), &n), SALTS_CRYPTO_OK);
    check_equal(n, 32u); check_equal(output, expected, 32);
    check_equal(salts_crypto_equal(NULL, NULL, 0), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_equal(NULL, output, 1), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_random(NULL, 0), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_random(NULL, 1), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_digest(SALTS_CRYPTO_SHA1, NULL, 1, output, sizeof(output), &n), SALTS_CRYPTO_EINVAL);
    check_equal(n, 0u);
  }

  it("matches SHA-384 and SHA-512 without mixing backend context layouts") {
    uint8_t output[64], expected[64]; size_t n;
    from_hex(expected, 48, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    check_equal(salts_crypto_digest(SALTS_CRYPTO_SHA384, "abc", 3, output, sizeof(output), &n), SALTS_CRYPTO_OK);
    check_equal(n, 48u); check_equal(output, expected, 48);
    from_hex(expected, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    check_equal(salts_crypto_digest(SALTS_CRYPTO_SHA512, "abc", 3, output, sizeof(output), &n), SALTS_CRYPTO_OK);
    check_equal(n, 64u); check_equal(output, expected, 64);
  }

  it("matches RFC 2202 HMAC-MD5 for short and long keys") {
    uint8_t key[80], output[16], expected[16];
    memset(key, 0x0b, 16);
    from_hex(expected, sizeof(expected), "9294727a3638bb1c13f48ef8158bfc9d");
    check_equal(salts_crypto_hmac_md5(key, 16, "Hi There", 8, output), SALTS_CRYPTO_OK);
    check_equal(output, expected, sizeof(output));
    memset(key, 0xaa, sizeof(key));
    const char message[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    from_hex(expected, sizeof(expected), "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
    check_equal(salts_crypto_hmac_md5(key, sizeof(key), message, sizeof(message) - 1, output), SALTS_CRYPTO_OK);
    check_equal(output, expected, sizeof(output));
    check_equal(salts_crypto_hmac_md5(NULL, 1, message, sizeof(message) - 1, output), SALTS_CRYPTO_EINVAL);
    check_equal(output, expected, sizeof(output));
  }

  it("matches the DES-CBC vector and decrypts in place") {
    uint8_t key[8], iv[8], output[24], expected[24];
    const char plaintext[] = "Now is the time for all ";
    from_hex(key, sizeof(key), "0123456789abcdef");
    from_hex(iv, sizeof(iv), "1234567890abcdef");
    from_hex(expected, sizeof(expected), "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6");
    check_equal(salts_crypto_des_cbc_crypt(0, key, iv, plaintext, sizeof(output), output, sizeof(output)), SALTS_CRYPTO_OK);
    check_equal(output, expected, sizeof(output));
    check_equal(salts_crypto_des_cbc_crypt(1, key, iv, output, sizeof(output), output, sizeof(output)), SALTS_CRYPTO_OK);
    check_equal(output, plaintext, sizeof(output));
    check_equal(salts_crypto_des_cbc_crypt(0, key, iv, plaintext, sizeof(output) - 1, output, sizeof(output)), SALTS_CRYPTO_EINVAL);
    check_equal(output, plaintext, sizeof(output));
  }

  it("matches NIST AES-128-CFB128 across a partial final block") {
    uint8_t key[16], iv[16], plain[23], expected[23], output[24];
    from_hex(key, sizeof(key), "2b7e151628aed2a6abf7158809cf4f3c");
    from_hex(iv, sizeof(iv), "000102030405060708090a0b0c0d0e0f");
    from_hex(plain, sizeof(plain), "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac");
    from_hex(expected, sizeof(expected), "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a9");
    check_equal(salts_crypto_aes128_cfb_crypt(0, key, iv, plain, sizeof(plain), output, sizeof(output)), SALTS_CRYPTO_OK);
    check_equal(output, expected, sizeof(expected));
    check_equal(salts_crypto_aes128_cfb_crypt(1, key, iv, output, sizeof(plain), output + 1, sizeof(output) - 1), SALTS_CRYPTO_EINVAL);
    check_equal(output, expected, sizeof(expected));
    check_equal(salts_crypto_aes128_cfb_crypt(1, key, iv, output, sizeof(plain), output, sizeof(output)), SALTS_CRYPTO_OK);
    check_equal(output, plain, sizeof(plain));
  }

  it("matches RFC 4231 HMAC and RFC 6070 PBKDF2 and rejects zero iterations") {
    uint8_t key[20], output[64], expected[32]; size_t n;
    memset(key, 0x0b, sizeof(key));
    from_hex(expected, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    check_equal(salts_crypto_hmac(SALTS_CRYPTO_SHA256, key, sizeof(key), "Hi There", 8, output, sizeof(output), &n), SALTS_CRYPTO_OK);
    check_equal(n, 32u); check_equal(output, expected, 32);
    from_hex(expected, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    check_equal(salts_crypto_pbkdf2(SALTS_CRYPTO_SHA1, "password", 8, "salt", 4, 1, output, 20), SALTS_CRYPTO_OK);
    check_equal(output, expected, 20);
    memset(output, 0xa5, sizeof(output));
    check_equal(salts_crypto_pbkdf2(SALTS_CRYPTO_SHA256, "password", 8, "salt", 4, 0, output, 32), SALTS_CRYPTO_EINVAL);
    check_equal(output[0], 0xa5);
  }

  it("matches NIST AES-GCM and rejects modified authentication tags") {
    uint8_t key[16] = {0}, iv[12] = {0}, plain[16] = {0}, cipher[16], output[16], tag[16], expected[16];
    check_equal(salts_crypto_aes_gcm_encrypt(key, 16, iv, 12, NULL, 0, plain, 16, cipher, 16, tag, 16), SALTS_CRYPTO_OK);
    from_hex(expected, 16, "0388dace60b6a392f328c2b971b2fe78"); check_equal(cipher, expected, 16);
    from_hex(expected, 16, "ab6e47d42cec13bdf53a67b21257bddf"); check_equal(tag, expected, 16);
    check_equal(salts_crypto_aes_gcm_decrypt(key, 16, iv, 12, NULL, 0, cipher, 16, tag, 16, output, 16), SALTS_CRYPTO_OK);
    check_equal(output, plain, 16);
    memset(output, 0xa5, sizeof(output)); tag[0] ^= 1;
    check_equal(salts_crypto_aes_gcm_decrypt(key, 16, iv, 12, NULL, 0, cipher, 16, tag, 16, output, 16), SALTS_CRYPTO_EVERIFY);
    memset(expected, 0xa5, sizeof(expected)); check_equal(output, expected, 16);
  }

  it("matches RFC 3394 key wrap and erases a failed unwrap candidate") {
    uint8_t key[16], plain[16], cipher[24], output[16], expected[24]; size_t n;
    from_hex(key, 16, "000102030405060708090a0b0c0d0e0f");
    from_hex(plain, 16, "00112233445566778899aabbccddeeff");
    from_hex(expected, 24, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
    check_equal(salts_crypto_aes_key_wrap(key, 16, plain, 16, cipher, 24, &n), SALTS_CRYPTO_OK);
    check_equal(n, 24u); check_equal(cipher, expected, 24);
    check_equal(salts_crypto_aes_key_unwrap(key, 16, cipher, 24, output, 16, &n), SALTS_CRYPTO_OK);
    check_equal(n, 16u); check_equal(output, plain, 16);
    cipher[0] ^= 1; memset(output, 0xa5, 16);
    check_equal(salts_crypto_aes_key_unwrap(key, 16, cipher, 24, output, 16, &n), SALTS_CRYPTO_EVERIFY);
    check_equal(n, 0u); memset(expected, 0, 16); check_equal(output, expected, 16);
  }

  it("matches the RFC 8032 Ed25519 empty-message vector") {
    uint8_t seed[32], pub[32], signature[64], expected[64];
    from_hex(seed, 32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    from_hex(expected, 32, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    check_equal(salts_crypto_ed25519_public_key(seed, pub), SALTS_CRYPTO_OK);
    check_equal(pub, expected, 32);
    from_hex(expected, 64, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    check_equal(salts_crypto_ed25519_sign(seed, NULL, 0, signature), SALTS_CRYPTO_OK);
    check_equal(signature, expected, 64);
    check_equal(salts_crypto_ed25519_verify(pub, NULL, 0, signature), SALTS_CRYPTO_OK);
    signature[0] ^= 1;
    check_equal(salts_crypto_ed25519_verify(pub, NULL, 0, signature), SALTS_CRYPTO_EVERIFY);
  }

  it("copies keys and supports all four existing JOSE ECDSA curves") {
    const size_t sizes[] = {32, 48, 66, 32};
    const salts_crypto_hash hashes[] = {SALTS_CRYPTO_SHA256, SALTS_CRYPTO_SHA384, SALTS_CRYPTO_SHA512, SALTS_CRYPTO_SHA256};
    for (int curve = SALTS_CRYPTO_EC_P256; curve <= SALTS_CRYPTO_EC_SECP256K1; ++curve) {
      uint8_t scalar[66] = {0}, pub[132], signature[132];
      const size_t n = sizes[curve-1]; size_t written;
      scalar[n-1] = 1;
      check_equal(salts_crypto_ecdsa_public_key((salts_crypto_ec_curve)curve, scalar, n, pub, 2*n), SALTS_CRYPTO_OK);
      salts_crypto_bytes bytes = {scalar, n}, empty = {0};
      check_equal(salts_crypto_key_from_ec((salts_crypto_ec_curve)curve, empty, bytes, &private_key), SALTS_CRYPTO_OK);
      salts_crypto_clear(scalar, sizeof(scalar));
      check_equal(salts_crypto_key_sign(private_key, SALTS_CRYPTO_ECDSA, hashes[curve-1], "message", 7, signature, sizeof(signature), &written), SALTS_CRYPTO_OK);
      check_equal(written, 2*n);
      check_equal(salts_crypto_ecdsa_verify((salts_crypto_ec_curve)curve, pub, 2*n, "message", 7, signature, written), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_key_verify(private_key, SALTS_CRYPTO_ECDSA, hashes[curve-1], "modified", 8, signature, written), SALTS_CRYPTO_EVERIFY);
      salts_crypto_key_destroy(private_key); private_key = NULL;
    }
  }

  it("imports PKCS8 RSA keys for PKCS1, PSS and OAEP without backend headers") {
    char pem[4096]; uint8_t signature[512], cipher[512], output[512]; size_t n, written;
    fixture = fopen(CRYPTO_JOSE_RSA_FIXTURE, "rb"); check_not_null(fixture);
    n = fread(pem, 1, sizeof(pem), fixture); check_true(feof(fixture));
    fclose(fixture); fixture = NULL;
    check_equal(salts_crypto_key_from_pem(pem, n, 1, &private_key), SALTS_CRYPTO_OK);
    salts_crypto_clear(pem, sizeof(pem));
    check_equal(salts_crypto_key_type(private_key), SALTS_CRYPTO_KEY_RSA);
    check_equal(salts_crypto_key_signature_size(private_key), 256u);
    for (int hash = SALTS_CRYPTO_SHA256; hash <= SALTS_CRYPTO_SHA512; ++hash) {
      for (int scheme = SALTS_CRYPTO_RSA_PKCS1; scheme <= SALTS_CRYPTO_RSA_PSS; ++scheme) {
        check_equal(salts_crypto_key_sign(private_key, (salts_crypto_signature)scheme, (salts_crypto_hash)hash, "message", 7, signature, sizeof(signature), &n), SALTS_CRYPTO_OK);
        check_equal(salts_crypto_key_verify(private_key, (salts_crypto_signature)scheme, (salts_crypto_hash)hash, "message", 7, signature, n), SALTS_CRYPTO_OK);
        check_equal(salts_crypto_key_verify(private_key, (salts_crypto_signature)scheme, (salts_crypto_hash)hash, "modified", 8, signature, n), SALTS_CRYPTO_EVERIFY);
      }
      check_equal(salts_crypto_key_oaep_encrypt(private_key, (salts_crypto_hash)hash, (const uint8_t *)"secret", 6, cipher, sizeof(cipher), &n), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_key_oaep_decrypt(private_key, (salts_crypto_hash)hash, cipher, n, output, sizeof(output), &written), SALTS_CRYPTO_OK);
      check_equal(written, 6u); check_equal(output, "secret", 6);
      cipher[0] ^= 1;
      check_not_equal(salts_crypto_key_oaep_decrypt(private_key, (salts_crypto_hash)hash, cipher, n, output, sizeof(output), &written), SALTS_CRYPTO_OK);
      check_equal(written, 0u);
    }
    check_equal(salts_crypto_key_from_pem("invalid", 7, 1, &public_key), SALTS_CRYPTO_EINVAL);
    check_null(public_key);
  }
}
