#include <crypto/sm2_exchange.h>
#include <gmssl/sm2.h>
#include <gmssl/rand.h>
#include <tinytest.h>
#include <string.h>

/* Only this formal executable resolves the static provider RNG symbol. Native
 * arithmetic is still the installed GmSSL archive; production RNG is unchanged. */
static sm2_z256_t chosen;
static unsigned calls, zeros;
static int fail_rng;
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
  for (size_t i = 0; i < n; ++i) {
    const char *hi = strchr(digits, hex[2u*i]), *lo = strchr(digits, hex[2u*i+1u]);
    if (!hi || !lo) return 0;
    out[i] = (uint8_t)(((hi-digits) << 4) | (lo-digits));
  }
  return 1;
}
#define unhex(out, hex) check_true(decode_hex(out, sizeof(out), hex))
static int is_zero(const void *p, size_t n) {
  const uint8_t *bytes = p; unsigned bits = 0;
  for (size_t i = 0; i < n; ++i) bits |= bytes[i];
  return bits == 0;
}

spec("SM2 exchange vectors and provider failure paths") {
  before_each() { calls = 0; zeros = 0; fail_rng = 0; memset(chosen, 0, sizeof(chosen)); chosen[0] = 1; }
  it("matches GB/T 32918.5 Annex B shares, session key and both confirmation values") {
    /* Official parameters/vector: gmbz.org.cn/upload/2018-07-24/1532401863206085511.pdf */
    uint8_t ak[32], bk[32], ap[65], bp[65], nonce[32], ra[65], rb[65], sa[32], sb[32];
    uint8_t expected_ra[65], expected_rb[65], expected_sa[32], expected_sb[32], expected_key[16], ka[1024], kb[1024];
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0}; size_t an, bn;
    const char id[] = "1234567812345678";
    unhex(ak, "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029");
    unhex(bk, "785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5");
    unhex(expected_ra, "0464ced1bdbc99d590049b434d0fd73428cf608a5db8fe5ce07f15026940bae40e376629c7ab21e7db260922499ddb118f07ce8eaae3e7720afef6a5cc062070c0");
    unhex(expected_rb, "04acc27688a6f7b706098bc91ff3ad1bff7dc2802cdb14ccccdb0a90471f9bd7072fedac0494b2ffc4d6853876c79b8f301c6573ad0aa50f39fc87181e1a1b46fe");
    unhex(expected_sb, "d3a0fe15dee185ceae907a6b595cc32a266ed7b3367e9983a896dc32fa20f8eb");
    unhex(expected_sa, "18c7894b3816df16cf07b05c5ec0bef5d655d58f779cc1b400a4f3884644db88");
    unhex(expected_key, "6c89347354de2484c60b4ab1fde4c6e5");
    check_equal(salts_crypto_sm2_public_key(ak, ap), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_public_key(bk, bp), SALTS_CRYPTO_OK);
    const size_t lengths[] = {16u, 1u};
    for (size_t i = 0; i < 2u; ++i) {
      unhex(nonce, "d4de15474db74d06491c440d305e012400990f3e390c7e87153c12db2ea60bb3");
      sm2_z256_from_bytes(chosen, nonce); zeros = 1; calls = 0;
      check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, id, 16u, id, 16u, lengths[i], ra), SALTS_CRYPTO_OK);
      check_equal(calls, 2u); check_equal(ra, expected_ra, sizeof(ra));
      unhex(nonce, "7e07124814b309489125eaed101113164ebf0f3458c5bd88335c1f9d596243d6");
      sm2_z256_from_bytes(chosen, nonce);
      check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, id, 16u, id, 16u, lengths[i], ra, rb, sb), SALTS_CRYPTO_OK);
      check_equal(rb, expected_rb, sizeof(rb)); check_equal(sb, expected_sb, sizeof(sb));
      check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, ka, sizeof(ka), &an), SALTS_CRYPTO_OK);
      check_equal(sa, expected_sa, sizeof(sa)); check_equal(an, lengths[i]); check_equal(ka, expected_key, an);
      check_equal(salts_crypto_sm2_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_OK);
      check_equal(bn, lengths[i]); check_equal(kb, expected_key, bn);
      check_true(is_zero(&a, sizeof(a))); check_true(is_zero(&b, sizeof(b)));
    }
  }
  it("matches independent gmsm non-default-identity key material") {
    /* emmansun/gmsm v0.41.1 sm2/sm2_keyexchange_test.go TestKeyExchangeSample. */
    uint8_t ak[32], bk[32], ap[65], bp[65], nonce[32], ra[65], rb[65], sa[32], sb[32], ka[1024], kb[1024], expected[48];
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0}; size_t an, bn;
    unhex(ak, "e04c3fd77408b56a648ad439f673511a2ae248def3bab26bdfc9cdbd0ae9607e");
    unhex(bk, "7a1136f60d2c5531447e5a3093078c2a505abf74f33aefed927ac0a5b27e7dd7");
    unhex(expected, "1ad809ebc56ddda532020c352e1e60b121ebeb7b4e632db4dd90a362cf844f8bba85140e30984ddb581199bf5a9dda22");
    check_equal(salts_crypto_sm2_public_key(ak, ap), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_public_key(bk, bp), SALTS_CRYPTO_OK);
    unhex(nonce, "6fe0bac5b09d3ab10f724638811c34464790520e4604e71e6cb0e5310623b5b1"); sm2_z256_from_bytes(chosen, nonce);
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "Alice", 5u, "Bob", 3u, 48u, ra), SALTS_CRYPTO_OK);
    unhex(nonce, "d0233bdbb0b8a7bfe1aab66132ef06fc4efaedd5d5000692bc21185242a31f6f"); sm2_z256_from_bytes(chosen, nonce);
    check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, "Alice", 5u, "Bob", 3u, 48u, ra, rb, sb), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, ka, sizeof(ka), &an), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_OK);
    check_equal(an, 48u); check_equal(bn, 48u); check_equal(ka, expected, 48u); check_equal(kb, expected, 48u);
  }
  it("erases admitted outputs on RNG failure and bounds zero-nonce exhaustion") {
    uint8_t key[32] = {0}, pub[65], ra[65], rb[65], sb[32]; key[31] = 1;
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0};
    check_equal(salts_crypto_sm2_public_key(key, pub), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_start(&a, key, pub, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_OK);
    fail_rng = 1; memset(rb, 0xa5, sizeof(rb)); memset(sb, 0xa5, sizeof(sb));
    check_equal(salts_crypto_sm2_exchange_respond(&b, key, pub, "A", 1u, "B", 1u, 16u, ra, rb, sb), SALTS_CRYPTO_ERANDOM);
    check_true(is_zero(&b, sizeof(b))); check_true(is_zero(rb, sizeof(rb))); check_true(is_zero(sb, sizeof(sb)));
    check_equal(salts_crypto_sm2_exchange_start(&a, key, pub, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_ERANDOM);
    check_true(is_zero(&a, sizeof(a))); check_true(is_zero(ra, sizeof(ra)));
    fail_rng = 0; zeros = 129; calls = 0;
    check_equal(salts_crypto_sm2_exchange_start(&a, key, pub, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_ERANDOM);
    check_equal(calls, 128u); check_true(is_zero(&a, sizeof(a))); check_true(is_zero(ra, sizeof(ra)));
  }
  it("rejects zero combined scalars and infinity sums even with valid individual points") {
    sm2_z256_t x, negative, zero = {0}; SM2_Z256_POINT point, sum;
    uint8_t key[32] = {0}, pub[65], special[32], badpub[65], ra[65], sb[32] = {0}, sa[32], out[1024], xbytes[32] = {0};
    salts_crypto_sm2_exchange_ctx a = {0}; size_t n;
    key[31] = 1; check_equal(salts_crypto_sm2_public_key(key, pub), SALTS_CRYPTO_OK);
    memcpy(xbytes + 16u, pub + 17u, 16u); xbytes[16] |= 0x80u;
    sm2_z256_from_bytes(x, xbytes); sm2_z256_modn_sub(negative, zero, x); sm2_z256_to_bytes(negative, special);
    /* chosen r=1 and d=-xbar(G): t=d+xbar(G)*r=0. */
    check_equal(salts_crypto_sm2_exchange_start(&a, special, pub, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_ERANDOM);
    check_equal(calls, 128u); check_true(is_zero(&a, sizeof(a))); check_true(is_zero(ra, sizeof(ra)));
    check_equal(salts_crypto_sm2_public_key(special, badpub), SALTS_CRYPTO_OK);
    check_equal(sm2_z256_point_from_bytes(&point, pub + 1u), 1);
    sm2_z256_point_mul(&sum, x, &point); sm2_z256_point_mul_generator(&point, negative);
    sm2_z256_point_add(&sum, &sum, &point); check_equal(sm2_z256_point_is_at_infinity(&sum), 1);
    chosen[0] = 2;
    check_equal(salts_crypto_sm2_exchange_start(&a, key, badpub, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, pub, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(&a, sizeof(a))); check_true(is_zero(out, sizeof(out))); check_true(is_zero(sa, sizeof(sa))); check_equal(n, 0u);
  }
  it("admits the exchange-specific private scalar N-1") {
    uint8_t ak[32], ap[65], bk[32] = {0}, bp[65], ra[65], rb[65], sa[32], sb[32], ka[1024], kb[1024];
    uint8_t signature[64]; salts_crypto_sm2_exchange_ctx a = {0}, b = {0}; size_t an, bn;
    sm2_z256_to_bytes(sm2_z256_order_minus_one(), ak);
    check_equal(salts_crypto_sm2_public_key(ak, ap), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_sign(ak, "A", 1u, "x", 1u, signature), SALTS_CRYPTO_EINVAL);
    check_true(is_zero(signature, sizeof(signature)));
    bk[31] = 1; check_equal(salts_crypto_sm2_public_key(bk, bp), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_OK);
    chosen[0] = 2;
    check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, "A", 1u, "B", 1u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, ka, sizeof(ka), &an), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_OK);
    check_equal(an, 16u); check_equal(bn, 16u); check_equal(ka, kb, 16u);
  }
}
