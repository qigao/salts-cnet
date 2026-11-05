#include <crypto/sm2_exchange.h>
#include <tinytest.h>
#include <string.h>

static int is_zero(const void *p, size_t n) {
  const uint8_t *bytes = p; unsigned bits = 0;
  for (size_t i = 0; i < n; ++i) bits |= bytes[i];
  return bits == 0;
}
static int keys(uint8_t a[32], uint8_t ap[65], uint8_t b[32], uint8_t bp[65]) {
  memset(a, 0, 32u); memset(b, 0, 32u); a[31] = 1; b[31] = 2;
  return salts_crypto_sm2_public_key(a, ap) == SALTS_CRYPTO_OK &&
      salts_crypto_sm2_public_key(b, bp) == SALTS_CRYPTO_OK;
}

spec("SM2 authenticated key agreement") {
  it("confirms both peers, consumes inputs synchronously and clears one-shot state") {
    uint8_t ak[32], ap[65], bk[32], bp[65], ra[65], rb[65], sa[32], sb[32], ka[1024], kb[1024];
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0}; size_t an, bn;
    check_true(keys(ak, ap, bk, bp));
    const size_t sizes[] = {16u, 48u, 1024u};
    for (size_t i = 0; i < 3u; ++i) {
      char aid[] = "Alice", bid[] = "Bob"; uint8_t borrowed[65]; memcpy(borrowed, bp, sizeof(bp));
      check_equal(salts_crypto_sm2_exchange_start(&a, ak, borrowed, aid, 5u, bid, 3u, sizes[i], ra), SALTS_CRYPTO_OK);
      memset(aid, 0, sizeof(aid)); memset(bid, 0, sizeof(bid)); memset(borrowed, 0, sizeof(borrowed));
      check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, "Alice", 5u, "Bob", 3u, sizes[i], ra, rb, sb), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, ka, sizeof(ka), &an), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm2_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_OK);
      check_equal(an, sizes[i]); check_equal(bn, sizes[i]); check_equal(ka, kb, an);
      check_true(is_zero(&a, sizeof(a))); check_true(is_zero(&b, sizeof(b)));
      check_equal(salts_crypto_sm2_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_ESTATE);
      check_equal(bn, 0u); check_true(is_zero(kb, sizeof(kb)));
    }
  }
  it("supports the maximum explicit identity length without retaining identity buffers") {
    uint8_t ak[32], ap[65], bk[32], bp[65], ra[65], rb[65], sa[32], sb[32], ka[1024], kb[1024];
    uint8_t aid[8191], bid[8191];
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0}; size_t an, bn;
    check_true(keys(ak, ap, bk, bp)); memset(aid, 'A', sizeof(aid)); memset(bid, 'B', sizeof(bid));
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, aid, sizeof(aid), bid, sizeof(bid), 32u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, aid, sizeof(aid), bid, sizeof(bid), 32u, ra, rb, sb), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, ka, sizeof(ka), &an), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_OK);
    check_equal(an, 32u); check_equal(bn, 32u); check_equal(ka, kb, 32u);
  }
  it("rejects either forged confirmation without exposing key material") {
    uint8_t ak[32], ap[65], bk[32], bp[65], ra[65], rb[65], sa[32], sb[32], out[1024];
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0}; size_t n;
    check_true(keys(ak, ap, bk, bp));
    for (unsigned party = 0; party < 2; ++party) {
      check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, "Alice", 5u, "Bob", 3u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
      if (!party) {
        sb[0] ^= 1u; memset(out, 0xa5, sizeof(out)); memset(sa, 0xa5, sizeof(sa)); n = 99;
        check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
        check_true(is_zero(out, sizeof(out))); check_true(is_zero(sa, sizeof(sa))); check_equal(n, 0u);
        check_true(is_zero(&a, sizeof(a))); salts_crypto_sm2_exchange_clear(&b);
      } else {
        check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_OK);
        sa[31] ^= 1u; memset(out, 0xa5, sizeof(out)); n = 99;
        check_equal(salts_crypto_sm2_exchange_finish_responder(&b, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
        check_true(is_zero(out, sizeof(out))); check_true(is_zero(&b, sizeof(b))); check_equal(n, 0u);
      }
    }
  }
  it("binds both identities and static public keys into the exchange") {
    uint8_t ak[32], ap[65], bk[32], bp[65], ra[65], rb[65], sa[32], sb[32], out[1024];
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0}; size_t n;
    check_true(keys(ak, ap, bk, bp));
    for (unsigned mismatch = 0; mismatch < 3; ++mismatch) {
      check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm2_exchange_respond(&b, bk, mismatch == 2 ? bp : ap,
          mismatch == 0 ? "alice" : "Alice", 5u, mismatch == 1 ? "bob" : "Bob", 3u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
      check_true(is_zero(out, sizeof(out))); check_true(is_zero(&a, sizeof(a))); salts_crypto_sm2_exchange_clear(&b);
    }
  }
  it("rejects invalid scalars, noncanonical points and bad shares with output erasure") {
    uint8_t ak[32], ap[65], bk[32], bp[65], bad[65] = {4}, ra[65], rb[65], sa[32], sb[32], out[1024];
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0}; size_t n;
    check_true(keys(ak, ap, bk, bp));
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bad, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_EINVAL);
    check_true(is_zero(&a, sizeof(a))); check_true(is_zero(ra, sizeof(ra)));
    memset(bad + 1u, 0xff, 64u);
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bad, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_EINVAL);
    memset(ak, 0, sizeof(ak));
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_EINVAL);
    memset(ak, 0xff, sizeof(ak));
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_EINVAL);
    check_true(keys(ak, ap, bk, bp));
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, "A", 1u, "B", 1u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
    rb[0] = 0;
    check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(out, sizeof(out))); check_true(is_zero(sa, sizeof(sa))); check_true(is_zero(&a, sizeof(a)));
    ra[0] = 0;
    check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, "A", 1u, "B", 1u, 16u, ra, rb, sb), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(&b, sizeof(b))); check_true(is_zero(rb, sizeof(rb))); check_true(is_zero(sb, sizeof(sb)));
  }
  it("preserves live state on admission errors and rejects phase errors and replay") {
    uint8_t ak[32], ap[65], bk[32], bp[65], ra[65], rb[65], sa[32], sb[32], out[1024];
    salts_crypto_sm2_exchange_ctx a = {0}, b = {0}, before; size_t n = 99;
    check_true(keys(ak, ap, bk, bp));
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_OK);
    before = a; /* Read-only snapshot, never used as another live owner. */
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 8192u, "B", 1u, 16u, ra), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 1025u, ra), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 0u, ra), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 16u, a.bytes), SALTS_CRYPTO_EINVAL);
    check_equal(&a, &before, sizeof(a));
    check_equal(salts_crypto_sm2_exchange_respond(&b, bk, ap, "A", 1u, "B", 1u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
    memset(out, 0xa5, sizeof(out));
    check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, out, 1023u, &n), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), (size_t *)out), SALTS_CRYPTO_EINVAL);
    check_equal(&a, &before, sizeof(a)); check_equal(n, 99u); check_equal(out[0], 0xa5u);
    check_equal(salts_crypto_sm2_exchange_finish_responder(&a, sb, out, sizeof(out), &n), SALTS_CRYPTO_ESTATE);
    check_true(is_zero(&a, sizeof(a))); check_true(is_zero(out, sizeof(out))); check_equal(n, 0u);
    check_equal(salts_crypto_sm2_exchange_start(&a, ak, bp, "A", 1u, "B", 1u, 16u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm2_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(&a, sizeof(a))); check_true(is_zero(out, sizeof(out)));
    salts_crypto_sm2_exchange_clear(&b); salts_crypto_sm2_exchange_clear(&before);
    check_true(is_zero(&b, sizeof(b))); check_true(is_zero(&before, sizeof(before)));
  }
}
