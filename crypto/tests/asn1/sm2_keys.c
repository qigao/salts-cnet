#include <crypto/sm2_keys.h>
#include <crypto/sm2.h>
#include <gmssl/sm2.h>
#include <gmssl/rand.h>
#include <gmssl/pkcs8.h>
#include <gmssl/oid.h>
#include <tinytest.h>
#include <string.h>

/* RNG override is confined to this formal executable. The independent Python
 * test links the unmodified production RNG and exercises randomized exports. */
static unsigned rng_calls, rng_fail_at;
int rand_bytes(uint8_t *out, size_t n) {
  ++rng_calls;
  if (rng_calls == rng_fail_at) { memset(out, 0xcc, n); return -1; }
  for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)(i + rng_calls);
  return 1;
}
static int filled(const void *data, size_t n, uint8_t value) {
  const uint8_t *p = data;
  for (size_t i = 0; i < n; ++i) if (p[i] != value) return 0;
  return 1;
}
static const uint8_t key_one[32] = {[31] = 1};
static const uint8_t password[] = {'p', 0, 'a', 's', 's'};

spec("SM2 strict key containers and password protection") {
  before_each() { rng_calls = 0; rng_fail_at = 0; }
  it("round trips public and private keys and matches GmSSL native DER") {
    uint8_t der[151], native_der[151], out[32], pub[65], imported[65]; size_t n = 0, nn = 0;
    SM2_KEY native = {0}; sm2_z256_t d = {1,0,0,0}; uint8_t *p = native_der;
    check_equal(sm2_key_set_private_key(&native, d), 1);
    check_equal(salts_crypto_sm2_public_key(key_one, pub), SALTS_CRYPTO_OK);
    memset(der, 0xa5, sizeof(der));
    check_equal(salts_crypto_sm2_pkcs8_export(key_one, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    check_equal(n, (size_t)150); check_equal(der[150], 0xa5);
    check_equal(sm2_private_key_info_to_der(&native, &p, &nn), 1);
    check_equal(n, nn); check_equal(der, native_der, n);
    check_equal(salts_crypto_sm2_pkcs8_import(der, n, out), SALTS_CRYPTO_OK);
    check_equal(out, key_one, sizeof(out));
    check_equal(salts_crypto_sm2_spki_export(pub, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    check_equal(n, (size_t)91);
    p = native_der; nn = 0;
    check_equal(sm2_public_key_info_to_der(&native, &p, &nn), 1);
    check_equal(n, nn); check_equal(der, native_der, n);
    check_equal(salts_crypto_sm2_spki_import(der, n, imported), SALTS_CRYPTO_OK);
    check_equal(imported, pub, sizeof(pub));
  }
  it("admits N-1 exchange keys but rejects zero, out of range and inconsistent private keys") {
    const uint8_t nm1[32] = {0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0x72,0x03,0xdf,0x6b,0x21,0xc6,0x05,0x2b,0x53,0xbb,0xf4,0x09,0x39,0xd5,0x41,0x22};
    uint8_t der[151], raw[32], out[33]; size_t n;
    check_equal(salts_crypto_sm2_pkcs8_export(nm1, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_pkcs8_import(der, n, out), SALTS_CRYPTO_OK);
    check_equal(out, nm1, 32);
    for (unsigned i = 0; i < 2; ++i) {
      memset(raw, i ? 0xff : 0, sizeof(raw)); memset(der, 0xa5, sizeof(der)); n = 99;
      check_equal(salts_crypto_sm2_pkcs8_export(raw, der, sizeof(der), &n), SALTS_CRYPTO_EVERIFY);
      check_true(filled(der, 150, 0)); check_equal(der[150], 0xa5); check_equal(n, (size_t)0);
    }
    check_equal(salts_crypto_sm2_pkcs8_export(key_one, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    const size_t mutations[] = {5, 26, 33, 67, 79, 84, 85, 149};
    for (size_t i = 0; i < sizeof(mutations)/sizeof(mutations[0]); ++i) {
      der[mutations[i]] ^= 1u; memset(out, 0xa5, sizeof(out));
      check_equal(salts_crypto_sm2_pkcs8_import(der, n, out), SALTS_CRYPTO_EVERIFY);
      check_true(filled(out, 32, 0)); check_equal(out[32], 0xa5); der[mutations[i]] ^= 1u;
    }
    for (size_t i = 1; i < n; ++i) {
      memset(out, 0xa5, sizeof(out));
      check_equal(salts_crypto_sm2_pkcs8_import(der, i, out), SALTS_CRYPTO_EVERIFY);
      check_true(filled(out, 32, 0));
    }
    der[1] = 0x80; /* Indefinite length is never admitted as DER. */
    check_equal(salts_crypto_sm2_pkcs8_import(der, n, out), SALTS_CRYPTO_EVERIFY);
  }
  it("rejects wrong-curve, off-curve, infinity and noncanonical SPKI points") {
    uint8_t pub[65], der[91], out[66]; size_t n;
    check_equal(salts_crypto_sm2_public_key(key_one, pub), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_spki_export(pub, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    const size_t mutations[] = {22, 25, 26, 90};
    for (size_t i = 0; i < sizeof(mutations)/sizeof(mutations[0]); ++i) {
      der[mutations[i]] ^= 1u; memset(out, 0xa5, sizeof(out));
      check_equal(salts_crypto_sm2_spki_import(der, n, out), SALTS_CRYPTO_EVERIFY);
      check_true(filled(out, 65, 0)); check_equal(out[65], 0xa5); der[mutations[i]] ^= 1u;
    }
    memset(pub, 0, sizeof(pub)); pub[0] = 4;
    check_equal(salts_crypto_sm2_spki_export(pub, der, sizeof(der), &n), SALTS_CRYPTO_EVERIFY);
    memset(pub+1, 0xff, 32);
    check_equal(salts_crypto_sm2_spki_export(pub, der, sizeof(der), &n), SALTS_CRYPTO_EVERIFY);
    check_true(filled(der, sizeof(der), 0));
  }
  it("preserves outputs on capacity, overlap, password and policy admission errors") {
    uint8_t der[321], raw[32]; size_t n = 99;
    memset(der, 0xa5, sizeof(der)); memset(raw, 0xa5, sizeof(raw));
    check_equal(salts_crypto_sm2_pkcs8_export(key_one, der, 149, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_export(der, der, 150, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_export(key_one, der, 150, (size_t *)(void *)der), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_import(der, 151, raw), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_import(der, 150, der+20), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, password, sizeof(password), 9999, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, password, sizeof(password), 16777216, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, password, 0, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, password, 1025, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, der, 5, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, password, 5, 10000, der, 319, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_decrypt(der, 321, password, 5, 10000, raw), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_decrypt(der, 320, raw, 5, 10000, raw), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_decrypt(der, 320, password, 5, 9999, raw), SALTS_CRYPTO_EINVAL);
    check_true(filled(der, sizeof(der), 0xa5)); check_true(filled(raw, sizeof(raw), 0xa5));
    check_equal(n, (size_t)99); check_equal(rng_calls, 0u);
  }
  it("erases failed exports when either salt or IV generation fails") {
    uint8_t der[321]; size_t n;
    for (unsigned i = 1; i <= 2; ++i) {
      rng_calls = 0; rng_fail_at = i; n = 99; memset(der, 0xa5, sizeof(der));
      check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, password, sizeof(password), 10000,
          der, sizeof(der), &n), SALTS_CRYPTO_ERANDOM);
      check_equal(rng_calls, i); check_equal(n, (size_t)0);
      check_true(filled(der, 320, 0)); check_equal(der[320], 0xa5);
    }
  }
  it("round trips binary and maximum passwords and erases rejected plaintext") {
    uint8_t der[321], raw[33], long_password[1024]; size_t n;
    memset(long_password, 0x5a, sizeof(long_password));
    for (unsigned i = 0; i < 2; ++i) {
      const void *pw = i ? (const void *)long_password : (const void *)password;
      size_t pn = i ? sizeof(long_password) : sizeof(password);
      memset(der, 0xa5, sizeof(der));
      check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, pw, pn, 10000, der, sizeof(der), &n), SALTS_CRYPTO_OK);
      check_equal(der[320], 0xa5);
      check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n, pw, pn, 10000, raw), SALTS_CRYPTO_OK);
      check_equal(raw, key_one, 32);
      memset(raw, 0xa5, sizeof(raw));
      check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n, "wrong", 5, 10000, raw), SALTS_CRYPTO_EVERIFY);
      check_true(filled(raw, 32, 0)); check_equal(raw[32], 0xa5);
      der[n-1u] ^= 0xff;
      check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n, pw, pn, 10000, raw), SALTS_CRYPTO_EVERIFY);
      check_true(filled(raw, 32, 0));
    }
  }
  it("interoperates both directions with the installed GmSSL PKCS8 workflow") {
    uint8_t der[320], raw[32]; size_t n = 0, remaining; const uint8_t *p, *attrs; size_t an;
    SM2_KEY native = {0}; sm2_z256_t d = {1,0,0,0}; uint8_t *write = der;
    check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, "password", 8, 10000, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    p = der; remaining = n;
    check_equal(sm2_private_key_info_decrypt_from_der(&native, &attrs, &an, "password", &p, &remaining), 1);
    check_equal(remaining, (size_t)0); sm2_z256_to_bytes(native.private_key, raw);
    check_equal(raw, key_one, 32);
    check_equal(sm2_key_set_private_key(&native, d), 1); n = 0;
    check_equal(sm2_private_key_info_encrypt_to_der(&native, "password", &write, &n), 1);
    check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n, "password", 8, 65536, raw), SALTS_CRYPTO_OK);
    check_equal(raw, key_one, 32);
    memset(raw, 0xa5, sizeof(raw));
    check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n, "password", 8, 65535, raw), SALTS_CRYPTO_EVERIFY);
    check_true(filled(raw, sizeof(raw), 0));
  }
  it("rejects unsupported PRF, cipher, key length, salt, IV and iteration declarations before decrypting") {
    uint8_t der[400], raw[32], salt[65] = {0}, iv[17] = {0}, cipher[176] = {0};
    const struct invalid { int iter, keylen, prf; size_t sn, ivn, cn; } cases[] = {
      {9999,16,OID_hmac_sm3,16,16,160}, {16777216,16,OID_hmac_sm3,16,16,160},
      {10001,16,OID_hmac_sm3,16,16,160}, {10000,15,OID_hmac_sm3,16,16,160},
      {10000,16,-1,16,16,160}, {10000,16,OID_hmac_sm3,15,16,160},
      {10000,16,OID_hmac_sm3,16,16,159}, {10000,16,OID_hmac_sm3,16,16,176},
      {10000,16,OID_hmac_sm3,16,16,0}
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
      const struct invalid *c = &cases[i]; uint8_t *p = der; size_t n = 0;
      check_equal(pkcs8_enced_private_key_info_to_der(salt, c->sn, c->iter, c->keylen, c->prf,
          OID_sm4_cbc, iv, c->ivn, cipher, c->cn, &p, &n), 1);
      memset(raw, 0xa5, sizeof(raw));
      check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n, password, sizeof(password), 10000, raw), SALTS_CRYPTO_EVERIFY);
      check_true(filled(raw, sizeof(raw), 0));
    }
    size_t n;
    check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, password, sizeof(password), 10000, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    /* Mutate known algorithm OID bytes without changing container lengths. */
    const uint8_t patterns[][11] = {
      {6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,13},
      {6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,12},
      {6,9,0x2a,0x81,0x1c,0xcf,0x55,1,0x83,0x11,2},
      {6,8,0x2a,0x81,0x1c,0xcf,0x55,1,0x68,2,0}
    };
    for (size_t j = 0; j < 4; ++j) {
      size_t width = j == 3 ? 10 : 11, at = n;
      for (size_t i = 0; i+width <= n; ++i)
        if (!memcmp(der+i, patterns[j], width)) { at = i+width-1; break; }
      check_true(at < n);
      if (at < n) {
        der[at] ^= 1;
        check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n, password, sizeof(password), 10000, raw), SALTS_CRYPTO_EVERIFY);
        check_true(filled(raw, sizeof(raw), 0)); der[at] ^= 1;
      }
    }
    for (size_t i = 1; i < n; ++i) {
      check_equal(salts_crypto_sm2_pkcs8_decrypt(der, i, password, sizeof(password), 10000, raw), SALTS_CRYPTO_EVERIFY);
    }
    der[n] = 0;
    check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n+1, password, sizeof(password), 10000, raw), SALTS_CRYPTO_EVERIFY);
  }
  it("round trips AES256 binary and maximum passwords without cross-profile admission") {
    uint8_t der[321], raw[33], long_password[1024]; size_t n;
    memset(long_password, 0x5a, sizeof(long_password));
    for (unsigned i = 0; i < 2u; ++i) {
      const void *pw = i ? (const void *)long_password : (const void *)password;
      size_t pn = i ? sizeof(long_password) : sizeof(password);
      memset(der, 0xa5, sizeof(der)); memset(raw, 0xa5, sizeof(raw));
      check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, pw, pn, 10000, der, sizeof(der), &n), SALTS_CRYPTO_OK);
      check_equal(der[320], 0xa5);
      check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, n, pw, pn, 10000, raw), SALTS_CRYPTO_OK);
      check_equal(raw, key_one, 32); check_equal(raw[32], 0xa5);
      check_equal(salts_crypto_sm2_pkcs8_decrypt(der, n, pw, pn, 10000, raw), SALTS_CRYPTO_EVERIFY);
      check_true(filled(raw, 32u, 0)); check_equal(raw[32], 0xa5);
      check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, n, "wrong", 5u, 10000, raw), SALTS_CRYPTO_EVERIFY);
      check_true(filled(raw, 32u, 0));
      der[n-1u] ^= 0xffu;
      check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, n, pw, pn, 10000, raw), SALTS_CRYPTO_EVERIFY);
      check_true(filled(raw, 32u, 0));
      check_equal(salts_crypto_sm2_pkcs8_encrypt(key_one, pw, pn, 10000, der, sizeof(der), &n), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, n, pw, pn, 10000, raw), SALTS_CRYPTO_EVERIFY);
      check_true(filled(raw, 32u, 0));
    }
  }
  it("preserves AES256 outputs for invalid pointers, capacities, overlaps and work policies") {
    uint8_t der[321], raw[32]; size_t n = 99u;
    memset(der, 0xa5, sizeof(der)); memset(raw, 0xa5, sizeof(raw));
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(NULL, password, 5, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, NULL, 5, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 0, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 1025, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 5, 9999, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 5, 16777216, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 5, 10000, der, 319, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(der, password, 5, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, der, 5, 10000, der, 320, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 5, 10000, der, 320, (size_t *)(void *)der), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, 321, password, 5, 10000, raw), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, 320, raw, 5, 10000, raw), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, 320, password, 5, 9999, raw), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, 320, password, 5, 10000, der+20), SALTS_CRYPTO_EINVAL);
    check_true(filled(der, sizeof(der), 0xa5)); check_true(filled(raw, sizeof(raw), 0xa5));
    check_equal(n, (size_t)99u); check_equal(rng_calls, 0u);
  }
  it("erases AES256 exports on invalid keys or either failed random draw") {
    uint8_t der[321], zero[32] = {0}; size_t n = 99u;
    memset(der, 0xa5, sizeof(der));
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(zero, password, 5, 10000, der, 320, &n), SALTS_CRYPTO_EVERIFY);
    check_true(filled(der, 320u, 0)); check_equal(der[320], 0xa5); check_equal(n, (size_t)0u);
    check_equal(rng_calls, 0u);
    for (unsigned i = 1u; i <= 2u; ++i) {
      rng_calls = 0u; rng_fail_at = i; n = 99u; memset(der, 0xa5, sizeof(der));
      check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 5, 10000, der, 320, &n), SALTS_CRYPTO_ERANDOM);
      check_equal(rng_calls, i); check_equal(n, (size_t)0u);
      check_true(filled(der, 320u, 0)); check_equal(der[320], 0xa5);
    }
  }
  it("rejects every truncated AES256 envelope and preserves the output guard") {
    uint8_t der[321], raw[33]; size_t n;
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 5, 10000, der, 320, &n), SALTS_CRYPTO_OK);
    for (size_t i = 1u; i < n; ++i) {
      memset(raw, 0xa5, sizeof(raw));
      check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, i, password, 5, 10000, raw), SALTS_CRYPTO_EVERIFY);
      check_true(filled(raw, 32u, 0)); check_equal(raw[32], 0xa5);
    }
    der[n] = 0u;
    check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, n+1u, password, 5, 10000, raw), SALTS_CRYPTO_EVERIFY);
    check_true(filled(raw, 32u, 0));
  }
  it("enforces the AES256 import work budget before admitting a valid higher-cost key") {
    uint8_t der[320], raw[33]; size_t n;
    check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key_one, password, 5, 10001, der, sizeof(der), &n), SALTS_CRYPTO_OK);
    memset(raw, 0xa5, sizeof(raw));
    check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, n, password, 5, 10000, raw), SALTS_CRYPTO_EVERIFY);
    check_true(filled(raw, 32u, 0)); check_equal(raw[32], 0xa5);
    check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, n, password, 5, 10001, raw), SALTS_CRYPTO_OK);
    check_equal(raw, key_one, 32u); check_equal(raw[32], 0xa5);
  }
}
