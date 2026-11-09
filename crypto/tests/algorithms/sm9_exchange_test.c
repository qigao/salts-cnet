#include <crypto/sm9_exchange.h>
#include <tinytest.h>
#include <string.h>

static int is_zero(const void *p, size_t n) {
  const uint8_t *bytes = p;
  unsigned bits = 0;
  for (size_t i = 0; i < n; ++i) bits |= bytes[i];
  return bits == 0;
}
static int keys(salts_crypto_sm9_exchange_key *a, salts_crypto_sm9_exchange_key *b) {
  uint8_t master[32] = {0}; master[31] = 1;
  return salts_crypto_sm9_exchange_extract(master, "Alice", 5u, a) == SALTS_CRYPTO_OK &&
      salts_crypto_sm9_exchange_extract(master, "Bob", 3u, b) == SALTS_CRYPTO_OK;
}

spec("SM9 mutually confirmed key exchange") {
  it("supports maximum-length identities with a generated exchange master") {
    uint8_t master[32], pub[65], aid[255], bid[255], ra[65], rb[65], sa[32], sb[32], ka[1024], kb[1024];
    salts_crypto_sm9_exchange_key ak, bk;
    salts_crypto_sm9_exchange_ctx a = {0}, b = {0}; size_t an, bn;
    memset(aid, 'A', sizeof(aid)); memset(bid, 'B', sizeof(bid));
    check_equal(salts_crypto_sm9_master_generate(SALTS_CRYPTO_SM9_EXCHANGE, master, pub, sizeof(pub)), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_extract(master, aid, sizeof(aid), &ak), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_extract(master, bid, sizeof(bid), &bk), SALTS_CRYPTO_OK);
    check_equal(ak.master_public, pub, sizeof(pub)); check_equal(bk.master_public, pub, sizeof(pub));
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, aid, sizeof(aid), bid, sizeof(bid), 32u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_respond(&b, &bk, aid, sizeof(aid), bid, sizeof(bid), 32u, ra, rb, sb), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, ka, sizeof(ka), &an), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_OK);
    check_equal(an, 32u); check_equal(bn, 32u); check_equal(ka, kb, 32u);
    salts_crypto_sm9_exchange_key_clear(&ak); salts_crypto_sm9_exchange_key_clear(&bk);
  }
  it("uses owned identities, confirms both peers and erases one-shot contexts") {
    salts_crypto_sm9_exchange_key ak, bk;
    salts_crypto_sm9_exchange_ctx a = {0}, b = {0};
    uint8_t ra[65], rb[65], sa[32], sb[32], ka[1024], kb[1024];
    size_t an, bn;
    check_true(keys(&ak, &bk));
    const size_t sizes[] = {16u, 32u, 1024u};
    for (size_t i = 0; i < 3u; ++i) {
      char aid[] = "Alice", bid[] = "Bob";
      check_equal(salts_crypto_sm9_exchange_start(&a, &ak, aid, 5u, bid, 3u, sizes[i], ra), SALTS_CRYPTO_OK);
      memset(aid, 0, sizeof(aid)); memset(bid, 0, sizeof(bid));
      check_equal(salts_crypto_sm9_exchange_respond(&b, &bk, "Alice", 5u, "Bob", 3u, sizes[i], ra, rb, sb), SALTS_CRYPTO_OK);
      check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, ka, sizeof(ka), &an), SALTS_CRYPTO_OK);
      check_equal(an, sizes[i]); check_true(is_zero(&a, sizeof(a)));
      check_equal(salts_crypto_sm9_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_OK);
      check_equal(bn, sizes[i]); check_equal(ka, kb, an); check_true(is_zero(&b, sizeof(b)));
      check_equal(salts_crypto_sm9_exchange_finish_responder(&b, sa, kb, sizeof(kb), &bn), SALTS_CRYPTO_ESTATE);
      check_equal(bn, 0u); check_true(is_zero(kb, sizeof(kb)));
    }
    salts_crypto_sm9_exchange_key_clear(&ak); salts_crypto_sm9_exchange_key_clear(&bk);
    check_true(is_zero(&ak, sizeof(ak))); check_true(is_zero(&bk, sizeof(bk)));
  }
  it("rejects a forged responder confirmation without releasing a key or confirmation") {
    salts_crypto_sm9_exchange_key ak, bk;
    salts_crypto_sm9_exchange_ctx a = {0}, b = {0};
    uint8_t ra[65], rb[65], sa[32], sb[32], secret[1024]; size_t n = 99;
    check_true(keys(&ak, &bk));
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_respond(&b, &bk, "Alice", 5u, "Bob", 3u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
    sb[0] ^= 1u; memset(secret, 0xa5, sizeof(secret)); memset(sa, 0xa5, sizeof(sa));
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, secret, sizeof(secret), &n), SALTS_CRYPTO_EVERIFY);
    check_equal(n, 0u); check_true(is_zero(secret, sizeof(secret))); check_true(is_zero(sa, sizeof(sa)));
    check_true(is_zero(&a, sizeof(a)));
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, secret, sizeof(secret), &n), SALTS_CRYPTO_ESTATE);
    salts_crypto_sm9_exchange_clear(&b); check_true(is_zero(&b, sizeof(b)));
  }
  it("rejects a forged initiator confirmation and wrong-role calls") {
    salts_crypto_sm9_exchange_key ak, bk;
    salts_crypto_sm9_exchange_ctx a = {0}, b = {0};
    uint8_t ra[65], rb[65], sa[32] = {0}, sb[32], secret[1024]; size_t n = 99;
    check_true(keys(&ak, &bk));
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_finish_responder(&a, sa, secret, sizeof(secret), &n), SALTS_CRYPTO_ESTATE);
    check_true(is_zero(&a, sizeof(a))); check_true(is_zero(secret, sizeof(secret))); check_equal(n, 0u);
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_respond(&b, &bk, "Alice", 5u, "Bob", 3u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, secret, sizeof(secret), &n), SALTS_CRYPTO_OK);
    sa[31] ^= 1u; memset(secret, 0xa5, sizeof(secret));
    check_equal(salts_crypto_sm9_exchange_finish_responder(&b, sa, secret, sizeof(secret), &n), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(&b, sizeof(b))); check_true(is_zero(secret, sizeof(secret))); check_equal(n, 0u);
  }
  it("binds the private key to the declared identity, master and exchange purpose") {
    salts_crypto_sm9_exchange_key ak, bk, wrong;
    salts_crypto_sm9_enc_key enc;
    salts_crypto_sm9_exchange_ctx a = {0}, b = {0};
    uint8_t master[32] = {0}, ra[65], rb[65], sa[32], sb[32], out[1024]; size_t n;
    check_true(keys(&ak, &bk)); master[31] = 1;
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_EINVAL);
    check_true(is_zero(&a, sizeof(a))); check_true(is_zero(ra, sizeof(ra)));
    check_equal(salts_crypto_sm9_enc_extract(master, "Alice", 5u, &enc), SALTS_CRYPTO_OK);
    memcpy(wrong.private_point, enc.private_point, sizeof(wrong.private_point));
    memcpy(wrong.master_public, enc.master_public, sizeof(wrong.master_public));
    check_equal(salts_crypto_sm9_exchange_start(&a, &wrong, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
    /* B was given a different initiator identity: its own key is still valid. */
    check_equal(salts_crypto_sm9_exchange_respond(&b, &bk, "alice", 5u, "Bob", 3u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(out, sizeof(out))); salts_crypto_sm9_exchange_clear(&b);
    wrong = ak; memcpy(wrong.master_public, ra, sizeof(ra));
    check_equal(salts_crypto_sm9_exchange_start(&a, &wrong, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_EINVAL);
  }
  it("rejects malformed shares and preserves state on invalid output admission") {
    salts_crypto_sm9_exchange_key ak, bk;
    salts_crypto_sm9_exchange_ctx a = {0}, b = {0}, before;
    uint8_t ra[65], rb[65], sa[32], sb[32], out[1024]; size_t n = 99;
    check_true(keys(&ak, &bk));
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
    before = a; /* Read-only test snapshot, never used as a second owner. */
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 0u, ra), SALTS_CRYPTO_EINVAL);
    check_equal(&a, &before, sizeof(a));
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 1025u, ra), SALTS_CRYPTO_EINVAL);
    check_equal(&a, &before, sizeof(a));
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 256u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_EINVAL);
    check_equal(&a, &before, sizeof(a));
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 16u, a.bytes), SALTS_CRYPTO_EINVAL);
    check_equal(&a, &before, sizeof(a));
    check_equal(salts_crypto_sm9_exchange_respond(&b, &bk, "Alice", 5u, "Bob", 3u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
    memset(out, 0xa5, sizeof(out));
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, out, 1023u, &n), SALTS_CRYPTO_EINVAL);
    check_equal(&a, &before, sizeof(a)); check_equal(n, 99u); check_equal(out[0], 0xa5u);
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), (size_t *)out), SALTS_CRYPTO_EINVAL);
    check_equal(&a, &before, sizeof(a)); check_equal(out[0], 0xa5u);
    rb[0] = 0;
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(&a, sizeof(a))); check_true(is_zero(out, sizeof(out))); check_true(is_zero(sa, sizeof(sa)));
    ra[0] = 0;
    check_equal(salts_crypto_sm9_exchange_respond(&b, &bk, "Alice", 5u, "Bob", 3u, 16u, ra, rb, sb), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(&b, sizeof(b))); check_true(is_zero(rb, sizeof(rb))); check_true(is_zero(sb, sizeof(sb)));
    salts_crypto_sm9_exchange_clear(&before);
  }
  it("rejects a confirmation replayed into a fresh initiator exchange") {
    salts_crypto_sm9_exchange_key ak, bk;
    salts_crypto_sm9_exchange_ctx a = {0}, b = {0};
    uint8_t ra[65], rb[65], sa[32], sb[32], out[1024]; size_t n;
    check_true(keys(&ak, &bk));
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_respond(&b, &bk, "Alice", 5u, "Bob", 3u, 16u, ra, rb, sb), SALTS_CRYPTO_OK);
    /* Restart explicitly abandons the old initiator nonce and transcript. */
    check_equal(salts_crypto_sm9_exchange_start(&a, &ak, "Alice", 5u, "Bob", 3u, 16u, ra), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sm9_exchange_finish_initiator(&a, rb, sb, sa, out, sizeof(out), &n), SALTS_CRYPTO_EVERIFY);
    check_true(is_zero(out, sizeof(out))); check_true(is_zero(&a, sizeof(a)));
    salts_crypto_sm9_exchange_clear(&b);
  }
}
