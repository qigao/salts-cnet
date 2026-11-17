#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <crypto/symmetric.h>
#include <crypto/key.h>
#include <stdio.h>
#include <string.h>

static void decode_hex(uint8_t *out, size_t size, const char *hex) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < size; ++i)
    out[i] = (uint8_t)((strchr(digits, hex[2*i]) - digits) * 16 + strchr(digits, hex[2*i+1]) - digits);
}

spec("Crypto streaming, HKDF and AES modes") {
  static salts_crypto_digest_ctx *digest;
  static salts_crypto_hmac_ctx *mac;
  before_each() { digest = NULL; mac = NULL; }
  after_each() { salts_crypto_digest_destroy(digest); salts_crypto_hmac_destroy(mac); }

  it("streams every hash and HMAC across empty and split updates, copying the key") {
    uint8_t out[64], expected[64], key[131]; size_t n, en;
    for (int hash = SALTS_CRYPTO_SHA1; hash <= SALTS_CRYPTO_SHA512; ++hash) {
      memset(key, 0xaa, sizeof(key));
      check_equal(salts_crypto_digest_create((salts_crypto_hash)hash, &digest), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_hmac_create((salts_crypto_hash)hash, key, sizeof(key), &mac), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_hmac((salts_crypto_hash)hash, key, sizeof(key), "abc", 3, expected, sizeof(expected), &en), SALTS_CRYPTO_OK);
      memset(key, 0, sizeof(key));
      check_equal(salts_crypto_digest_update(digest, NULL, 0), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_digest_update(digest, "a", 1), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_digest_update(digest, "bc", 2), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_hmac_update(mac, "ab", 2), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_hmac_update(mac, NULL, 0), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_hmac_update(mac, "c", 1), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_hmac_final(mac, out, sizeof(out), &n), SALTS_CRYPTO_OK);
      check_equal(n, en); check_equal(out, expected, n);
      check_equal(salts_crypto_digest((salts_crypto_hash)hash, "abc", 3, expected, sizeof(expected), &en), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_digest_final(digest, out, sizeof(out), &n), SALTS_CRYPTO_OK);
      check_equal(n, en); check_equal(out, expected, n);
      check_equal(salts_crypto_digest_update(digest, NULL, 0), SALTS_CRYPTO_ESTATE);
      check_equal(salts_crypto_hmac_final(mac, out, sizeof(out), &n), SALTS_CRYPTO_ESTATE);
      check_equal(n, 0u);
      salts_crypto_digest_destroy(digest); digest = NULL;
      salts_crypto_hmac_destroy(mac); mac = NULL;
    }
  }

  it("preserves active state and output after invalid updates and short final buffers") {
    uint8_t out[64], expected[64]; size_t n, en;
    check_equal(salts_crypto_digest_create(SALTS_CRYPTO_SHA256, &digest), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_hmac_create(SALTS_CRYPTO_SHA256, NULL, 0, &mac), SALTS_CRYPTO_OK);
    {
      salts_crypto_hmac_ctx *rejected = mac;
      check_equal(salts_crypto_hmac_create(SALTS_CRYPTO_SHA256, NULL, SIZE_MAX, &rejected), SALTS_CRYPTO_EINVAL);
      check_null(rejected);
    }
    check_equal(salts_crypto_digest_update(digest, NULL, 1), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_hmac_update(mac, "x", SIZE_MAX), SALTS_CRYPTO_EINVAL);
    memset(out, 0xa5, sizeof(out));
    check_equal(salts_crypto_digest_final(digest, out, 31, &n), SALTS_CRYPTO_EINVAL);
    check_equal(n, 0u); check_equal(out[0], 0xa5);
    check_equal(salts_crypto_digest_final(digest, out, sizeof(out), &n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_digest(SALTS_CRYPTO_SHA256, NULL, 0, expected, sizeof(expected), &en), SALTS_CRYPTO_OK);
    check_equal(out, expected, n);
    check_equal(salts_crypto_hmac_final(mac, out, 31, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_hmac_final(mac, out, sizeof(out), &n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_hmac(SALTS_CRYPTO_SHA256, NULL, 0, NULL, 0, expected, sizeof(expected), &en), SALTS_CRYPTO_OK);
    check_equal(out, expected, n);
  }

  it("matches RFC5869 case 1 and rejects the expand boundary before writing") {
    uint8_t ikm[22], salt[13], info[10], prk[32], expected[42], out[8161]; size_t n;
    memset(ikm, 0x0b, sizeof(ikm));
    for (size_t i = 0; i < sizeof(salt); ++i) salt[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(info); ++i) info[i] = (uint8_t)(0xf0+i);
    check_equal(salts_crypto_hkdf_extract(SALTS_CRYPTO_SHA256, salt, sizeof(salt), ikm, sizeof(ikm), prk, sizeof(prk), &n), SALTS_CRYPTO_OK);
    decode_hex(expected, 32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    check_equal(n, 32u); check_equal(prk, expected, 32);
    check_equal(salts_crypto_hkdf_expand(SALTS_CRYPTO_SHA256, prk, n, info, sizeof(info), out, 42), SALTS_CRYPTO_OK);
    decode_hex(expected, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    check_equal(out, expected, 42);
    check_equal(salts_crypto_hkdf_expand(SALTS_CRYPTO_SHA256, prk, n, NULL, 0, out, 8160), SALTS_CRYPTO_OK);
    out[0] = 0xa5;
    check_equal(salts_crypto_hkdf_expand(SALTS_CRYPTO_SHA256, prk, n, NULL, 0, out, 8161), SALTS_CRYPTO_EINVAL);
    check_equal(out[0], 0xa5);
    check_equal(salts_crypto_hkdf_expand(SALTS_CRYPTO_SHA256, prk, 31, NULL, 0, out, 1), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_hkdf_expand(SALTS_CRYPTO_SHA256, prk, n, NULL, 0, NULL, 0), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_hkdf_extract(SALTS_CRYPTO_SHA256, NULL, 0, NULL, 0, prk, sizeof(prk), &n), SALTS_CRYPTO_OK);
  }

  it("rejects overlapping mutable spans without consuming the stream or input") {
    uint8_t bytes[64], iv[16] = {0}, key[16] = {0}; size_t n;
    memset(bytes, 0xa5, sizeof(bytes));
    check_equal(salts_crypto_digest_create(SALTS_CRYPTO_SHA256, &digest), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_digest_update(digest, digest, 1), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_digest_final(digest, (uint8_t *)digest, 32, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_digest_update(digest, "abc", 3), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_digest_final(digest, bytes, sizeof(bytes), &n), SALTS_CRYPTO_OK);
    check_equal(n, 32u);
    check_equal(salts_crypto_hkdf_expand(SALTS_CRYPTO_SHA256, bytes, 32, NULL, 0, bytes, 32), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_aes_crypt(SALTS_CRYPTO_AES_CBC, 0, key, sizeof(key), iv,
        bytes, 16, bytes + 1, 16), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_aes_crypt(SALTS_CRYPTO_AES_CTR, 0, key, sizeof(key), iv,
        bytes, 16, iv, 16), SALTS_CRYPTO_EINVAL);
    check_equal(iv[0], 0);
  }

  it("matches NIST SP800-38A AES CBC/CTR vectors including identical buffers") {
    uint8_t key[16], iv[16], original_iv[16], plain[64], out[64], expected[64];
    decode_hex(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
    decode_hex(plain, 64, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    for (int mode = SALTS_CRYPTO_AES_CBC; mode <= SALTS_CRYPTO_AES_CTR; ++mode) {
      decode_hex(iv, 16, mode == SALTS_CRYPTO_AES_CBC ? "000102030405060708090a0b0c0d0e0f" : "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
      memcpy(original_iv, iv, 16);
      decode_hex(expected, 64, mode == SALTS_CRYPTO_AES_CBC ?
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7" :
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
      check_equal(salts_crypto_aes_crypt((salts_crypto_aes_mode)mode, 0, key, 16, iv, plain, 64, out, 64), SALTS_CRYPTO_OK);
      check_equal(out, expected, 64); check_equal(iv, original_iv, 16);
      check_equal(salts_crypto_aes_crypt((salts_crypto_aes_mode)mode, 1, key, 16, iv, out, 64, out, 64), SALTS_CRYPTO_OK);
      check_equal(out, plain, 64);
    }
    memset(iv, 0xff, 16); memset(out, 0xa5, 64);
    check_equal(salts_crypto_aes_crypt(SALTS_CRYPTO_AES_CTR, 0, key, 16, iv, plain, 17, out, 64), SALTS_CRYPTO_EINVAL);
    check_equal(out[0], 0xa5);
    check_equal(salts_crypto_aes_crypt(SALTS_CRYPTO_AES_CTR, 0, key, 16, iv, plain, 15, out, 64), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_aes_crypt(SALTS_CRYPTO_AES_CBC, 0, key, 16, iv, plain, 15, out, 64), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_aes_crypt(SALTS_CRYPTO_AES_CBC, 2, key, 16, iv, plain, 16, out, 64), SALTS_CRYPTO_EINVAL);
  }

  it("matches NIST AES192 and AES256 CBC/CTR first-block vectors") {
    uint8_t key[32], plain[16], iv[16], expected[16], out[16];
    decode_hex(plain, 16, "6bc1bee22e409f96e93d7e117393172a");
    for (int bits = 192; bits <= 256; bits += 64) {
      size_t size = (size_t)bits / 8;
      decode_hex(key, size, bits == 192 ? "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" :
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
      for (int mode = SALTS_CRYPTO_AES_CBC; mode <= SALTS_CRYPTO_AES_CTR; ++mode) {
        decode_hex(iv, 16, mode == SALTS_CRYPTO_AES_CBC ? "000102030405060708090a0b0c0d0e0f" : "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        decode_hex(expected, 16, mode == SALTS_CRYPTO_AES_CBC ?
          (bits == 192 ? "4f021db243bc633d7178183a9fa071e8" : "f58c4c04d6e5f1ba779eabfb5f7bfbd6") :
          (bits == 192 ? "1abc932417521ca24f2b0459fe7e6e0b" : "601ec313775789a5b7a7f504bbf3d228"));
        check_equal(salts_crypto_aes_crypt((salts_crypto_aes_mode)mode, 0, key, size, iv, plain, 16, out, 16), SALTS_CRYPTO_OK);
        check_equal(out, expected, 16);
      }
    }
  }
}

spec("Crypto public key lifecycle and explicit RSA parameters") {
  static salts_crypto_key *key, *copy;
  static FILE *file;
  static char pem[4096];
  static size_t pem_size;
  before_each() {
    key = NULL; copy = NULL; file = NULL;
    file = fopen(CRYPTO_JOSE_RSA_FIXTURE, "rb"); check_not_null(file);
    pem_size = fread(pem, 1, sizeof(pem), file); check_true(feof(file));
    fclose(file); file = NULL;
    check_equal(salts_crypto_key_from_pem(pem, pem_size, 1, &key), SALTS_CRYPTO_OK);
  }
  after_each() {
    if (file) fclose(file);
    salts_crypto_key_destroy(key); salts_crypto_key_destroy(copy);
    salts_crypto_clear(pem, sizeof(pem));
  }

  it("exports canonical RSA PKCS8 PEM matching the independent fixture and SPKI DER") {
    char out[4096], canonical[4096]; uint8_t der[8192], signature[512]; size_t n, required, en = 0;
    for (size_t i = 0; i < pem_size; ++i) if (pem[i] != '\r') canonical[en++] = pem[i];
    check_equal(salts_crypto_key_to_pem(key, 1, NULL, 0, &required), SALTS_CRYPTO_OK);
    check_equal(required, en);
    check_equal(salts_crypto_key_to_pem(key, 1, out, sizeof(out), &n), SALTS_CRYPTO_OK);
    check_equal(n, en); check_equal(out, canonical, n);
    check_equal(salts_crypto_key_to_der(key, 0, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_from_der(der, n, 0, &copy), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_sign(key, SALTS_CRYPTO_RSA_PSS, SALTS_CRYPTO_SHA256, "abc", 3, signature, sizeof(signature), &n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_verify(copy, SALTS_CRYPTO_RSA_PSS, SALTS_CRYPTO_SHA256, "abc", 3, signature, n), SALTS_CRYPTO_OK);
    memset(out, 0xa5, sizeof(out));
    check_equal(salts_crypto_key_to_pem(key, 1, out, required - 1, &n), SALTS_CRYPTO_EINVAL);
    check_equal(n, 0u); check_equal((uint8_t)out[0], 0xa5);
    check_equal(salts_crypto_key_to_der(copy, 1, der, sizeof(der), &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_key_to_der(key, 0, (uint8_t *)key, 1, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_key_type(key), SALTS_CRYPTO_KEY_RSA);
  }

  it("exports and reimports all supported EC and EdDSA key kinds") {
    uint8_t scalar[66] = {0}, der[1024], first[1024]; size_t n, fn;
    salts_crypto_bytes empty = {0}, secret;
    salts_crypto_key_destroy(key); key = NULL;
    for (int kind = 1; kind <= 6; ++kind) {
      size_t sn = kind == 2 ? 48 : kind == 3 ? 66 : kind == 6 ? 57 : 32;
      memset(scalar, 0, sizeof(scalar)); scalar[sn-1] = 1;
      secret.data = scalar; secret.size = sn;
      if (kind <= 4) check_equal(salts_crypto_key_from_ec((salts_crypto_ec_curve)kind, empty, secret, &key), SALTS_CRYPTO_OK);
      else check_equal(salts_crypto_key_from_ed(kind == 5 ? SALTS_CRYPTO_KEY_ED25519 : SALTS_CRYPTO_KEY_ED448, empty, secret, &key), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_key_to_der(key, 1, der, sizeof(der), &n), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_key_from_der(der, n, 1, &copy), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_key_to_der(key, 0, first, sizeof(first), &fn), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_key_to_der(copy, 0, der, sizeof(der), &n), SALTS_CRYPTO_OK);
      check_equal(n, fn); check_equal(der, first, n);
      salts_crypto_key_destroy(key); key = NULL; salts_crypto_key_destroy(copy); copy = NULL;
    }
  }

  it("imports encrypted PKCS8 with byte passwords and rejects wrong passwords and excess work") {
    char encoded[4096]; uint8_t der[4096], signature[512]; size_t n, dn, required;
    static const uint8_t password[] = {'a',0,'b'};
    check_equal(salts_crypto_key_to_encrypted_pem(key, password, sizeof(password), 10000, NULL, 0, &required), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_to_encrypted_pem(key, password, sizeof(password), 10000, encoded, sizeof(encoded), &n), SALTS_CRYPTO_OK);
    check_equal(n, required);
    check_equal(salts_crypto_key_from_encrypted_pem(encoded, n, password, sizeof(password), 10000, &copy), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_sign(copy, SALTS_CRYPTO_RSA_PSS, SALTS_CRYPTO_SHA256, "abc", 3, signature, sizeof(signature), &dn), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_verify(key, SALTS_CRYPTO_RSA_PSS, SALTS_CRYPTO_SHA256, "abc", 3, signature, dn), SALTS_CRYPTO_OK);
    salts_crypto_key_destroy(copy); copy = NULL;
    check_equal(salts_crypto_key_from_encrypted_pem(encoded, n, "wrong", 5, 10000, &copy), SALTS_CRYPTO_EVERIFY);
    check_null(copy);
    check_equal(salts_crypto_key_to_encrypted_der(key, password, sizeof(password), 10001, der, sizeof(der), &dn), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_from_encrypted_der(der, dn, password, sizeof(password), 10000, &copy), SALTS_CRYPTO_EINVAL);
    check_null(copy);
    der[dn-1] ^= 0x80;
    check_equal(salts_crypto_key_from_encrypted_der(der, dn, password, sizeof(password), 10001, &copy), SALTS_CRYPTO_EVERIFY);
    check_null(copy);
  }

  it("reads the independently encoded OpenSSL AES256/PBKDF2 PKCS8 fixture") {
    char encrypted[4096]; uint8_t signature[512]; size_t n, written;
    /* Same fixed test key as jose-rsa-private.pem; this public fixture is
     * generated with openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256
     * -iter 10000 -passout pass:crypto-fixture. */
    file = fopen(CRYPTO_RSA_ENCRYPTED_FIXTURE, "rb"); check_not_null(file);
    n = fread(encrypted, 1, sizeof(encrypted), file); check_true(feof(file));
    fclose(file); file = NULL;
    check_equal(salts_crypto_key_from_encrypted_pem(encrypted, n, "crypto-fixture", 14, 10000, &copy), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_sign(copy, SALTS_CRYPTO_RSA_PKCS1, SALTS_CRYPTO_SHA256, "fixture", 7, signature, sizeof(signature), &written), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_verify(key, SALTS_CRYPTO_RSA_PKCS1, SALTS_CRYPTO_SHA256, "fixture", 7, signature, written), SALTS_CRYPTO_OK);
  }

  it("enforces PSS salt length and OAEP labels while preserving existing defaults") {
    uint8_t signature[512], cipher[512], plain[512]; size_t n, pn;
    check_equal(salts_crypto_key_pss_sign(key, SALTS_CRYPTO_SHA256, 0, "abc", 3, signature, sizeof(signature), &n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_pss_verify(key, SALTS_CRYPTO_SHA256, 0, "abc", 3, signature, n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_pss_verify(key, SALTS_CRYPTO_SHA256, 32, "abc", 3, signature, n), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_key_pss_verify(key, SALTS_CRYPTO_SHA256, SALTS_CRYPTO_PSS_SALT_AUTO, "abc", 3, signature, n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_pss_sign(key, SALTS_CRYPTO_SHA256, 223, "abc", 3, signature, sizeof(signature), &n), SALTS_CRYPTO_EINVAL);
    check_equal(n, 0u);
    check_equal(salts_crypto_key_oaep_encrypt_with_label(key, SALTS_CRYPTO_SHA256, "label", 5, (const uint8_t *)"secret", 6, cipher, sizeof(cipher), &n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_key_oaep_decrypt_with_label(key, SALTS_CRYPTO_SHA256, "label", 5, cipher, n, plain, sizeof(plain), &pn), SALTS_CRYPTO_OK);
    check_equal(pn, 6u); check_equal(plain, "secret", 6);
    memset(plain, 0xa5, sizeof(plain));
    check_equal(salts_crypto_key_oaep_decrypt(key, SALTS_CRYPTO_SHA256, cipher, n, plain, sizeof(plain), &pn), SALTS_CRYPTO_EVERIFY);
    check_equal(pn, 0u); check_equal(plain[0], 0xa5);
  }
}
