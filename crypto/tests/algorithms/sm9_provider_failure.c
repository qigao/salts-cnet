#include <crypto/sm9.h>
#include <gmssl/sm9.h>
#include <gmssl/rand.h>
#include <tinytest.h>
#include <string.h>

/* This executable alone resolves the static provider's RNG symbol. No crypto
 * implementation is copied; production and the public vector executable keep
 * the real RNG. Scalars are supplied in the provider's native limb layout. */
static unsigned calls, zeros;
static int fail_rng;
static sm9_z256_t chosen;
int rand_bytes(uint8_t *out, size_t n) {
  ++calls;
  if (fail_rng || n != sizeof(chosen)) return -1;
  if (zeros) { --zeros; memset(out, 0, n); }
  else memcpy(out, chosen, n);
  return 1;
}
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

spec("SM9 provider RNG failures and standard nonces") {
  it("rejects an on-curve G2 point outside the prime-order subgroup") {
    uint8_t point[129], master[32] = {0}, sig[104], capsule[65] = {4}, secret[32];
    SM9_Z256_TWIST_POINT native, multiple;
    salts_crypto_sm9_sign_key sign_key;
    salts_crypto_sm9_enc_key enc_key;
    /* x=1, y=a+b*u solves y^2=x^3+5*u, u^2=-2; no cofactor clearing.
     * Verify both fixture properties so malformed-point rejection cannot mask
     * an absent subgroup check. */
    unhex(point, "04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010453e9be88d22ccfe209a420669cac8b9ec1fccf14061eb8bd714e6a1f6a3ee179a8eb911912ef24a4a0796b7a21a0935854b7cb00ee547f244a76f4c3718630");
    check_equal(sm9_z256_twist_point_from_uncompressed_octets(&native, point), 1);
    check_equal(sm9_z256_twist_point_is_on_curve(&native), 1);
    sm9_z256_twist_point_mul(&multiple, sm9_z256_order(), &native);
    check_equal(sm9_z256_twist_point_is_at_infinity(&multiple), 0);
    master[31] = 1;
    check_equal(salts_crypto_sm9_sign_extract(master, "Alice", 5u, &sign_key), SALTS_CRYPTO_OK);
    memcpy(sign_key.master_public, point, sizeof(point)); memset(sig, 0xa5, sizeof(sig));
    check_equal(salts_crypto_sm9_sign(&sign_key, "x", 1u, sig), SALTS_CRYPTO_EINVAL);
    check_true(is_zero(sig, sizeof(sig)));
    check_equal(salts_crypto_sm9_enc_extract(master, "Bob", 3u, &enc_key), SALTS_CRYPTO_OK);
    memcpy(capsule, enc_key.master_public, sizeof(capsule));
    memcpy(enc_key.private_point, point, sizeof(point)); memset(secret, 0xa5, sizeof(secret));
    check_equal(salts_crypto_sm9_decapsulate(&enc_key, "Bob", 3u, capsule, secret, sizeof(secret)), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(secret, sizeof(secret)));
    salts_crypto_sm9_sign_key_clear(&sign_key); salts_crypto_sm9_enc_key_clear(&enc_key);
  }
  it("rejects a recipient whose identity and master scalar cancel to infinity") {
    sm9_z256_t h, zero = {0}, scalar;
    uint8_t master[32], pub[65], capsule[65], secret[32];
    salts_crypto_sm9_enc_key key;
    sm9_z256_hash1(h, "Bob", 3u, SM9_HID_ENC);
    sm9_z256_modn_sub(scalar, zero, h); sm9_z256_to_bytes(scalar, master);
    check_equal(salts_crypto_sm9_master_public(SALTS_CRYPTO_SM9_ENCRYPT, master, pub, sizeof(pub)), SALTS_CRYPTO_OK);
    memset(&key, 0xa5, sizeof(key));
    check_equal(salts_crypto_sm9_enc_extract(master, "Bob", 3u, &key), SALTS_CRYPTO_ECRYPTO);
    check_true(is_zero(&key, sizeof(key)));
    calls = 0; fail_rng = 1;
    check_equal(salts_crypto_sm9_encapsulate(pub, "Bob", 3u, secret, sizeof(secret), capsule), SALTS_CRYPTO_ECRYPTO);
    check_equal(calls, 0u); check_true(is_zero(secret, sizeof(secret))); check_true(is_zero(capsule, sizeof(capsule)));
  }
  it("retries a zero signing nonce and emits the published signature") {
    uint8_t master[32], nonce[32], sig[104], expected[104];
    salts_crypto_sm9_sign_key key;
    unhex(master, "000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4");
    unhex(nonce, "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe");
    unhex(expected, "30660420823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb0342000473bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05");
    check_equal(salts_crypto_sm9_sign_extract(master, "Alice", 5u, &key), SALTS_CRYPTO_OK);
    sm9_z256_from_bytes(chosen, nonce); calls = 0; zeros = 1; fail_rng = 0;
    check_equal(salts_crypto_sm9_sign(&key, "Chinese IBS standard", 20u, sig), SALTS_CRYPTO_OK);
    check_equal(calls, 2u); check_equal(sig, expected, sizeof(sig));
    fail_rng = 1; memset(sig, 0xa5, sizeof(sig));
    check_equal(salts_crypto_sm9_sign(&key, "x", 1u, sig), SALTS_CRYPTO_ECRYPTO);
    check_true(is_zero(sig, sizeof(sig)));
    fail_rng = 0; zeros = 129; calls = 0;
    check_equal(salts_crypto_sm9_sign(&key, "x", 1u, sig), SALTS_CRYPTO_ECRYPTO);
    check_equal(calls, 128u); check_true(is_zero(sig, sizeof(sig)));
    salts_crypto_sm9_sign_key_clear(&key);
  }
  it("emits the standard XOR ciphertext and erases outputs on RNG failure") {
    uint8_t master[32], pub[65], nonce[32], cipher[367], expected[129], secret[32], capsule[65];
    size_t written = 0;
    unhex(master, "0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22");
    unhex(nonce, "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c");
    unhex(expected, "307f020100034200042445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac00420ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f36704141b5f5b0e951489682f3e64e1378cdd5da9513b1c");
    check_equal(salts_crypto_sm9_master_public(SALTS_CRYPTO_SM9_ENCRYPT, master, pub, sizeof(pub)), SALTS_CRYPTO_OK);
    sm9_z256_from_bytes(chosen, nonce); zeros = 0; calls = 0; fail_rng = 0;
    check_equal(salts_crypto_sm9_encrypt(pub, "Bob", 3u, "Chinese IBE standard", 20u, cipher, sizeof(cipher), &written), SALTS_CRYPTO_OK);
    check_equal(written, sizeof(expected)); check_equal(cipher, expected, sizeof(expected));
    fail_rng = 1; memset(cipher, 0xa5, sizeof(cipher)); written = 99;
    check_equal(salts_crypto_sm9_encrypt(pub, "Bob", 3u, "x", 1u, cipher, sizeof(cipher), &written), SALTS_CRYPTO_ECRYPTO);
    check_equal(written, 0u); check_true(is_zero(cipher, sizeof(cipher)));
    fail_rng = 0; zeros = 1;
    memset(secret, 0xa5, sizeof(secret)); memset(capsule, 0xa5, sizeof(capsule));
    check_equal(salts_crypto_sm9_encapsulate(pub, "Bob", 3u, secret, sizeof(secret), capsule), SALTS_CRYPTO_ECRYPTO);
    check_true(is_zero(secret, sizeof(secret))); check_true(is_zero(capsule, sizeof(capsule)));
  }
}
