#include <crypto/sm9.h>
#include <tinytest.h>
#include <string.h>

/* GB/T 38635 examples (signature A, KEM C, encryption D), also independently
 * exercised by emmansun/gmsm v0.41.1 internal/sm9/sm9_test.go. */
static const char *sign_master_hex = "000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4";
static const char *enc_master_hex = "0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22";
static int decode_hex(uint8_t *out, size_t n, const char *hex) {
  const char *digits = "0123456789abcdef";
  if (strlen(hex) != 2u*n) return 0;
  for (size_t i = 0; i < n; ++i)
    out[i] = (uint8_t)(((strchr(digits, hex[2u*i]) - digits) << 4) |
        (strchr(digits, hex[2u*i+1u]) - digits));
  return 1;
}
#define unhex(out, hex) check_true(decode_hex(out, sizeof(out), hex))
static int is_zero(const void *p, size_t n) {
  const uint8_t *bytes = p;
  unsigned bits = 0;
  for (size_t i = 0; i < n; ++i) bits |= bytes[i];
  return bits == 0;
}

spec("SM9 public identity-based cryptography") {
  it("derives the published signing key and verifies the independent fixed signature") {
    uint8_t master[32], expected_ds[65], signature[104], pub[129], generated[104];
    salts_crypto_sm9_sign_key key;
    unhex(master, sign_master_hex);
    unhex(expected_ds, "04a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa6982078559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3");
    unhex(signature, "30660420823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb0342000473bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05");
    check_equal(salts_crypto_sm9_sign_extract(master, "Alice", 5u, &key), SALTS_CRYPTO_OK);
    check_equal(key.private_point, expected_ds, sizeof(expected_ds));
    check_equal(salts_crypto_sm9_master_public(SALTS_CRYPTO_SM9_SIGN, master, pub, sizeof(pub)), SALTS_CRYPTO_OK);
    check_equal(pub, key.master_public, sizeof(pub));
    check_equal(salts_crypto_sm9_verify(pub, "Alice", 5u, "Chinese IBS standard", 20u, signature, sizeof(signature)), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_verify(pub, "alice", 5u, "Chinese IBS standard", 20u, signature, sizeof(signature)), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm9_verify(pub, "Alice", 5u, "Chinese IBE standard", 20u, signature, sizeof(signature)), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm9_sign(&key, NULL, 0u, generated), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_verify(pub, "Alice", 5u, NULL, 0u, generated, sizeof(generated)), SALTS_CRYPTO_OK);
    signature[38] = 1u; /* unused BIT STRING bits */
    check_equal(salts_crypto_sm9_verify(pub, "Alice", 5u, "Chinese IBS standard", 20u, signature, sizeof(signature)), SALTS_CRYPTO_EVERIFY);
    memset(key.private_point, 0, sizeof(key.private_point));
    memset(generated, 0xa5, sizeof(generated));
    check_equal(salts_crypto_sm9_sign(&key, "x", 1u, generated), SALTS_CRYPTO_EINVAL);
    check_true(is_zero(generated, sizeof(generated)));
    salts_crypto_sm9_sign_key_clear(&key);
    check_true(is_zero(&key, sizeof(key)));
  }
  it("matches the independent master, extracted encryption key and KEM secret") {
    uint8_t master[32], expected_pub[65], expected_de[129], capsule[65], secret[32], expected[32];
    salts_crypto_sm9_enc_key key;
    unhex(master, enc_master_hex);
    unhex(expected_pub, "04787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1");
    unhex(expected_de, "0494736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1");
    unhex(capsule, "041edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c");
    unhex(expected, "4ff5cf86d2ad40c8f4bac98d76abdbde0c0e2f0a829d3f911ef5b2bce0695480");
    check_equal(salts_crypto_sm9_enc_extract(master, "Bob", 3u, &key), SALTS_CRYPTO_OK);
    check_equal(key.master_public, expected_pub, sizeof(expected_pub));
    check_equal(key.private_point, expected_de, sizeof(expected_de));
    check_equal(salts_crypto_sm9_decapsulate(&key, "Bob", 3u, capsule, secret, sizeof(secret)), SALTS_CRYPTO_OK);
    check_equal(secret, expected, sizeof(secret));
    check_equal(salts_crypto_sm9_decapsulate(&key, "bob", 3u, capsule, secret, sizeof(secret)), SALTS_CRYPTO_OK);
    check_true(memcmp(secret, expected, sizeof(secret)) != 0); /* KEM is not authentication. */
    capsule[0] = 0;
    check_equal(salts_crypto_sm9_decapsulate(&key, "Bob", 3u, capsule, secret, sizeof(secret)), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(secret, sizeof(secret)));
    salts_crypto_sm9_enc_key_clear(&key);
    check_true(is_zero(&key, sizeof(key)));
  }
  it("decrypts the standard XOR cipher and rejects tampering before exposing plaintext") {
    uint8_t master[32], cipher[129], out[255], bad[130];
    salts_crypto_sm9_enc_key key;
    size_t written = 99;
    unhex(master, enc_master_hex);
    unhex(cipher, "307f020100034200042445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac00420ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f36704141b5f5b0e951489682f3e64e1378cdd5da9513b1c");
    check_equal(salts_crypto_sm9_enc_extract(master, "Bob", 3u, &key), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_decrypt(&key, "Bob", 3u, cipher, sizeof(cipher), out, sizeof(out), &written), SALTS_CRYPTO_OK);
    check_equal(written, 20u);
    check_equal(out, "Chinese IBE standard", 20u);
    /* Nonminimal long-form encoding of a length below 128 is forbidden DER. */
    bad[0] = 0x30; bad[1] = 0x81; memcpy(bad + 2u, cipher + 1u, sizeof(cipher)-1u);
    check_equal(salts_crypto_sm9_decrypt(&key, "Bob", 3u, bad, sizeof(bad), out, sizeof(out), &written), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(out, sizeof(out)));
    const size_t offsets[] = {4u, 7u, 8u, 75u, 128u};
    for (size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); ++i) {
      memcpy(bad, cipher, sizeof(cipher)); bad[offsets[i]] ^= 1u;
      memset(out, 0xa5, sizeof(out)); written = 99;
      check_equal(salts_crypto_sm9_decrypt(&key, "Bob", 3u, bad, sizeof(cipher), out, sizeof(out), &written), SALTS_CRYPTO_EVERIFY);
      check_equal(written, 0u); check_true(is_zero(out, sizeof(out)));
    }
    memcpy(bad, cipher, sizeof(cipher)); bad[129] = 0;
    check_equal(salts_crypto_sm9_decrypt(&key, "Bob", 3u, bad, sizeof(bad), out, sizeof(out), &written), SALTS_CRYPTO_EVERIFY);
    check_equal(salts_crypto_sm9_decrypt(&key, "Rob", 3u, cipher, sizeof(cipher), out, sizeof(out), &written), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(out, sizeof(out)));
    salts_crypto_sm9_enc_key_clear(&key);
  }
  it("round trips boundary lengths and KEM, rejecting alias and undersized output without writes") {
    uint8_t master[32], pub[65], cipher[367], plain[255], out[255], capsule[65], secret[1024], restored[1024];
    salts_crypto_sm9_enc_key key;
    size_t written = 0, plain_size = 0;
    memset(plain, 0x42, sizeof(plain));
    check_equal(salts_crypto_sm9_master_generate(SALTS_CRYPTO_SM9_ENCRYPT, master, pub, sizeof(pub)), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_enc_extract(master, "Bob", 3u, &key), SALTS_CRYPTO_OK);
    const size_t lengths[] = {1u, 127u, 255u};
    for (size_t i = 0; i < 3u; ++i) {
      check_equal(salts_crypto_sm9_encrypt(pub, "Bob", 3u, plain, lengths[i], cipher, sizeof(cipher), &written), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm9_decrypt(&key, "Bob", 3u, cipher, written, out, sizeof(out), &plain_size), SALTS_CRYPTO_OK);
      check_equal(plain_size, lengths[i]); check_equal(out, plain, plain_size);
    }
    check_equal(salts_crypto_sm9_encapsulate(pub, "Bob", 3u, secret, sizeof(secret), capsule), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_decapsulate(&key, "Bob", 3u, capsule, restored, sizeof(restored)), SALTS_CRYPTO_OK);
    check_equal(secret, restored, sizeof(secret));
    memset(cipher, 0xa5, sizeof(cipher)); written = 9;
    check_equal(salts_crypto_sm9_encrypt(pub, "Bob", 3u, plain, 1u, cipher, 366u, &written), SALTS_CRYPTO_EINVAL);
    check_equal(written, 9u); check_equal(cipher[0], 0xa5u);
    check_equal(salts_crypto_sm9_encrypt(pub, "Bob", 3u, cipher, 1u, cipher, sizeof(cipher), &written), SALTS_CRYPTO_EINVAL);
    check_equal(cipher[0], 0xa5u);
    check_equal(salts_crypto_sm9_encrypt(pub, "Bob", 3u, plain, 1u, cipher, sizeof(cipher), (size_t *)cipher), SALTS_CRYPTO_EINVAL);
    check_equal(cipher[0], 0xa5u);
    check_equal(salts_crypto_sm9_encapsulate(pub, "Bob", 3u, secret, 0u, capsule), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm9_encapsulate(pub, "Bob", 3u, secret, 1025u, capsule), SALTS_CRYPTO_EINVAL);
    memset(master, 0, sizeof(master));
    check_equal(salts_crypto_sm9_enc_extract(master, "Bob", 3u, &key), SALTS_CRYPTO_EINVAL);
    check_true(is_zero(&key, sizeof(key)));
    memset(master, 0xff, sizeof(master));
    check_equal(salts_crypto_sm9_master_public(SALTS_CRYPTO_SM9_ENCRYPT, master, pub, sizeof(pub)), SALTS_CRYPTO_EINVAL);
    check_true(is_zero(pub, sizeof(pub)));
  }
}
