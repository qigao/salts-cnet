#include <gmssl/rsa.h>
#include <gmssl/rsa_components.h>
#include <gmssl/bn.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <string.h>

/* Private-operation workspace is bounded by the existing RSA key ABI. Reuse
 * GmSSL's fixed-width add/subtract/multiply primitives. Reduction, selection
 * and exponentiation below have schedules determined by public buffer widths,
 * rather than secret exponent bits or intermediate carries. */
#define RSA_CT_WORDS (RSA_COMPONENTS_MAX_SIZE / 4)
typedef struct {
    uint32_t modulus[RSA_CT_WORDS + 1];
    uint32_t product[2 * RSA_CT_WORDS + 2];
    uint32_t quotient[2 * RSA_CT_WORDS + 2];
    uint32_t remainder[RSA_CT_WORDS + 1];
    uint32_t difference[RSA_CT_WORDS + 1];
    uint32_t accumulator[RSA_CT_WORDS];
    uint32_t multiplied[RSA_CT_WORDS];
} RSA_CT_MATH;

static void rsa_ct_select(uint32_t *out, const uint32_t *yes,
    const uint32_t *no, uint32_t choose_yes, size_t words)
{
    volatile uint32_t mask = 0u - choose_yes;
    size_t i;
    for (i = 0; i < words; ++i)
        out[i] = (yes[i] & mask) | (no[i] & ~mask);
}

/* Returns one iff subtraction was selected; a and p have words limbs. */
static uint32_t rsa_ct_reduce_once(uint32_t *a, const uint32_t *p,
    uint32_t *difference, size_t words)
{
    uint32_t take = 1u + (uint32_t)bn_sub(difference, a, p, words);
    rsa_ct_select(a, difference, a, take, words);
    return take;
}

static void rsa_ct_shift_bit(uint32_t *a, uint32_t bit, size_t words)
{
    size_t i;
    for (i = 0; i < words; ++i) {
        uint32_t next = a[i] >> 31;
        a[i] = (a[i] << 1) | bit;
        bit = next;
    }
}

/* u = floor(2^(64*k) / p), for a normalized, nonzero k-limb modulus. */
static void rsa_ct_reciprocal(uint32_t *u, const uint32_t *p, size_t k,
    RSA_CT_MATH *w)
{
    size_t bit = 64 * k;
    memset(u, 0, (k + 1) * sizeof(*u));
    memset(w->remainder, 0, (k + 1) * sizeof(uint32_t));
    memcpy(w->modulus, p, k * sizeof(uint32_t));
    w->modulus[k] = 0;
    for (;;) {
        uint32_t take;
        rsa_ct_shift_bit(w->remainder, (uint32_t)(bit == 64 * k), k + 1);
        take = rsa_ct_reduce_once(w->remainder, w->modulus, w->difference, k + 1);
        if (bit / 32 <= k) u[bit / 32] |= take << (bit % 32);
        if (bit == 0) break;
        --bit;
    }
}

static void rsa_ct_from_bytes(uint32_t *r, const uint8_t *in, size_t inlen,
    const uint32_t *p, size_t k, RSA_CT_MATH *w)
{
    size_t i;
    unsigned bit;
    memset(w->remainder, 0, (k + 1) * sizeof(uint32_t));
    memcpy(w->modulus, p, k * sizeof(uint32_t));
    w->modulus[k] = 0;
    for (i = 0; i < inlen; ++i) {
        for (bit = 8; bit > 0; --bit) {
            rsa_ct_shift_bit(w->remainder, (in[i] >> (bit - 1)) & 1u, k + 1);
            rsa_ct_reduce_once(w->remainder, w->modulus, w->difference, k + 1);
        }
    }
    memcpy(r, w->remainder, k * sizeof(uint32_t));
}

/* Barrett reduction, with both bounded correction subtractions always
 * performed. The underlying GmSSL multiplications use fixed limb loops. */
static void rsa_ct_mul(uint32_t *r, const uint32_t *a, const uint32_t *b,
    const uint32_t *p, const uint32_t *u, size_t k, RSA_CT_MATH *w)
{
    memcpy(w->modulus, p, k * sizeof(uint32_t));
    w->modulus[k] = 0;
    bn_mul(w->product, a, b, k);
    w->product[2 * k] = 0;
    bn_mul(w->quotient, w->product + k - 1, u, k + 1);
    bn_mul_lo(w->remainder, w->quotient + k + 1, w->modulus, k + 1);
    bn_sub(w->remainder, w->product, w->remainder, k + 1);
    rsa_ct_reduce_once(w->remainder, w->modulus, w->difference, k + 1);
    rsa_ct_reduce_once(w->remainder, w->modulus, w->difference, k + 1);
    memcpy(r, w->remainder, k * sizeof(uint32_t));
}

static void rsa_ct_exp(uint32_t *r, const uint32_t *a,
    const uint32_t *exponent, size_t exponent_words,
    const uint32_t *p, const uint32_t *u, size_t k, RSA_CT_MATH *w)
{
    size_t word;
    unsigned bit;
    bn_set_word(w->accumulator, 1, k);
    for (word = exponent_words; word > 0; --word) {
        for (bit = 32; bit > 0; --bit) {
            rsa_ct_mul(w->accumulator, w->accumulator, w->accumulator, p, u, k, w);
            rsa_ct_mul(w->multiplied, w->accumulator, a, p, u, k, w);
            rsa_ct_select(w->accumulator, w->multiplied, w->accumulator,
                (exponent[word - 1] >> (bit - 1)) & 1u, k);
        }
    }
    memcpy(r, w->accumulator, k * sizeof(uint32_t));
}

/* Encryption also handles secret encoded messages. Use the same fixed-width
 * multiply/reduce schedule rather than a multiplier that branches on input
 * bits. Signature verification shares this implementation. */
int rsa_public_key_operation(const RSA_PUBLIC_KEY *key,
    const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t *outlen)
{
    struct {
        RSA_CT_MATH math;
        uint32_t n[RSA_CT_WORDS], base[RSA_CT_WORDS], result[RSA_CT_WORDS];
        uint32_t reciprocal[RSA_CT_WORDS + 1];
    } w = {0};
    size_t k;
    int ret = -1;
    if (outlen) *outlen = 0;
    if (!key || !in || !out || !outlen ||
        key->modulus_size < RSA_MIN_MODULUS_SIZE ||
        key->modulus_size > RSA_MAX_MODULUS_SIZE || (key->modulus_size & 3u) ||
        inlen != key->modulus_size || outmax < inlen || !key->modulus[0] ||
        !(key->modulus[inlen - 1] & 1u) ||
        key->public_exponent < 3 || !(key->public_exponent & 1u)) goto end;
    if (memcmp(in, key->modulus, inlen) >= 0) goto end;
    k = inlen / 4;
    bn_from_bytes(w.n, k, key->modulus);
    bn_from_bytes(w.base, k, in);
    rsa_ct_reciprocal(w.reciprocal, w.n, k, &w.math);
    rsa_ct_exp(w.result, w.base, &key->public_exponent, 1,
        w.n, w.reciprocal, k, &w.math);
    bn_to_bytes(w.result, k, out);
    *outlen = inlen;
    ret = 1;
end:
    gmssl_secure_clear(&w, sizeof(w));
    return ret;
}

static int rsa_ct_prime(uint32_t *result, const uint8_t *in, size_t inlen,
    const uint8_t *prime, const uint8_t *private_exponent, uint32_t e,
    size_t k, RSA_CT_MATH *math)
{
    struct {
        uint32_t p[RSA_CT_WORDS], d[RSA_CT_WORDS];
        uint32_t reciprocal[RSA_CT_WORDS + 1];
        uint32_t r[RSA_CT_WORDS], inverse[RSA_CT_WORDS];
        uint32_t base[RSA_CT_WORDS], factor[RSA_CT_WORDS];
        uint32_t pm1[RSA_CT_WORDS], random[RSA_CT_WORDS];
        uint32_t exponent[2 * RSA_CT_WORDS];
        uint8_t bytes[RSA_MAX_PRIME_SIZE];
    } w = {0};
    size_t i;
    unsigned attempt;
    uint64_t carry = 0;
    int ret = -1;

    bn_from_bytes(w.p, k, prime);
    bn_from_bytes(w.d, k, private_exponent);
    rsa_ct_reciprocal(w.reciprocal, w.p, k, math);

    /* Independent base and 128-bit exponent blinding on each CRT branch.
     * Zero random factors are retried with a hard bound; RNG failure never
     * falls back to an unblinded operation. */
    for (attempt = 0; attempt < 8; ++attempt) {
        if (rand_bytes(w.bytes, k * 4) != 1) goto end;
        rsa_ct_from_bytes(w.r, w.bytes, k * 4, w.p, k, math);
        if (!bn_is_zero(w.r, k)) break;
    }
    if (attempt == 8) goto end;
    bn_set_word(w.factor, 2, k);
    bn_sub(w.pm1, w.p, w.factor, k);
    rsa_ct_exp(w.inverse, w.r, w.pm1, k, w.p, w.reciprocal, k, math);
    rsa_ct_exp(w.factor, w.r, &e, 1, w.p, w.reciprocal, k, math);
    rsa_ct_from_bytes(w.base, in, inlen, w.p, k, math);
    rsa_ct_mul(w.base, w.base, w.factor, w.p, w.reciprocal, k, math);

    if (rand_bytes(w.bytes, 16) != 1) goto end;
    w.bytes[0] |= 0x80;
    bn_from_bytes(w.random, 4, w.bytes);
    bn_set_word(w.factor, 1, k);
    bn_sub(w.pm1, w.p, w.factor, k);
    bn_mul(w.exponent, w.pm1, w.random, k);
    for (i = 0; i < k + 4; ++i) {
        carry += (uint64_t)w.exponent[i] + (i < k ? w.d[i] : 0u);
        w.exponent[i] = (uint32_t)carry;
        carry >>= 32;
    }
    rsa_ct_exp(result, w.base, w.exponent, k + 4, w.p, w.reciprocal, k, math);
    rsa_ct_mul(result, result, w.inverse, w.p, w.reciprocal, k, math);
    ret = 1;
end:
    gmssl_secure_clear(&w, sizeof(w));
    return ret;
}

static void rsa_ct_half(uint32_t *a, uint32_t carry, size_t k)
{
    while (k) {
        uint32_t next = a[--k] & 1u;
        a[k] = (a[k] >> 1) | (carry << 31);
        carry = next;
    }
}

static void rsa_ct_mod_half(uint32_t *a, const uint32_t *n, uint32_t *tmp, size_t k)
{
    uint32_t odd = a[0] & 1u;
    uint32_t carry = (uint32_t)bn_add(tmp, a, n, k);
    rsa_ct_select(a, tmp, a, odd, k);
    rsa_ct_half(a, carry & odd, k);
}

static void rsa_ct_mod_sub(uint32_t *r, const uint32_t *a, const uint32_t *b,
    const uint32_t *n, uint32_t *tmp, size_t k)
{
    uint32_t borrow = (uint32_t)bn_sub(r, a, b, k) & 1u;
    bn_add(tmp, r, n, k);
    rsa_ct_select(r, tmp, r, borrow, k);
}

/* Bounded binary extended GCD for an odd modulus. Maintain u = x*a (mod n)
 * and v = y*a (mod n). Each selected step halves an even operand or an odd
 * difference, decreasing the sum of operand bit lengths until one is zero.
 * All four candidates are computed each round; 2*32*k rounds suffice. This
 * keeps inversion of the fresh random blinding factor independent of its bits.
 */
static int rsa_ct_inverse(uint32_t *out, const uint32_t *a, const uint32_t *n, size_t k)
{
    struct {
        uint32_t u[RSA_CT_WORDS], v[RSA_CT_WORDS], x[RSA_CT_WORDS], y[RSA_CT_WORDS];
        uint32_t uh[RSA_CT_WORDS], vh[RSA_CT_WORDS], ud[RSA_CT_WORDS], vd[RSA_CT_WORDS];
        uint32_t xh[RSA_CT_WORDS], yh[RSA_CT_WORDS], xd[RSA_CT_WORDS], yd[RSA_CT_WORDS];
        uint32_t tmp[RSA_CT_WORDS];
    } w = {0};
    size_t step;
    int ret = -1;
    memcpy(w.u, a, k * 4);
    memcpy(w.v, n, k * 4);
    w.x[0] = 1;
    for (step = 0; step < 64 * k; ++step) {
        uint32_t uodd = w.u[0] & 1u, vodd = w.v[0] & 1u;
        uint32_t borrow = (uint32_t)bn_sub(w.ud, w.u, w.v, k) & 1u;
        uint32_t cu = 1u ^ uodd, cv = uodd & (1u ^ vodd);
        uint32_t cd = uodd & vodd & (1u ^ borrow), ce = uodd & vodd & borrow;
        bn_sub(w.vd, w.v, w.u, k);
        memcpy(w.uh, w.u, k * 4); memcpy(w.vh, w.v, k * 4);
        rsa_ct_half(w.uh, 0, k); rsa_ct_half(w.vh, 0, k);
        rsa_ct_half(w.ud, 0, k); rsa_ct_half(w.vd, 0, k);
        memcpy(w.xh, w.x, k * 4); memcpy(w.yh, w.y, k * 4);
        rsa_ct_mod_sub(w.xd, w.x, w.y, n, w.tmp, k);
        rsa_ct_mod_sub(w.yd, w.y, w.x, n, w.tmp, k);
        rsa_ct_mod_half(w.xh, n, w.tmp, k); rsa_ct_mod_half(w.yh, n, w.tmp, k);
        rsa_ct_mod_half(w.xd, n, w.tmp, k); rsa_ct_mod_half(w.yd, n, w.tmp, k);
        rsa_ct_select(w.u, w.uh, w.u, cu, k); rsa_ct_select(w.x, w.xh, w.x, cu, k);
        rsa_ct_select(w.v, w.vh, w.v, cv, k); rsa_ct_select(w.y, w.yh, w.y, cv, k);
        rsa_ct_select(w.u, w.ud, w.u, cd, k); rsa_ct_select(w.x, w.xd, w.x, cd, k);
        rsa_ct_select(w.v, w.vd, w.v, ce, k); rsa_ct_select(w.y, w.yd, w.y, ce, k);
    }
    if (bn_is_one(w.u, k)) { memcpy(out, w.x, k * 4); ret = 1; }
    else if (bn_is_one(w.v, k)) { memcpy(out, w.y, k * 4); ret = 1; }
    gmssl_secure_clear(&w, sizeof(w));
    return ret;
}

static int rsa_components_valid(const RSA_COMPONENTS *key)
{
    return key && key->size >= 64 && key->size <= RSA_COMPONENTS_MAX_SIZE &&
        key->n[0] && (key->size != 64 || (key->n[0] & 0x80u)) &&
        (key->n[key->size - 1] & 1u) && key->e >= 3 &&
        key->e <= UINT64_C(0x1ffffffff) && (key->e & 1u);
}

void rsa_components_cleanup(RSA_COMPONENTS *key)
{
    if (key) gmssl_secure_clear(key, sizeof(*key));
}

int rsa_components_import(RSA_COMPONENTS *key,
    const uint8_t *n, size_t nlen, const uint8_t *e, size_t elen,
    const uint8_t *d, size_t dlen)
{
    RSA_COMPONENTS candidate = {0};
    size_t i;
    int ret = -1;
    if (!key || !n || !e || !elen || elen > 5 || nlen < 64 ||
        nlen > RSA_COMPONENTS_MAX_SIZE || !n[0] || !e[0] ||
        (dlen && (!d || !d[0] || dlen > nlen))) goto end;
    candidate.size = nlen;
    memcpy(candidate.n, n, nlen);
    for (i = 0; i < elen; ++i) candidate.e = (candidate.e << 8) | e[i];
    if (!rsa_components_valid(&candidate)) goto end;
    if (dlen) {
        memcpy(candidate.d + nlen - dlen, d, dlen);
        if (memcmp(candidate.d, n, nlen) >= 0) goto end;
        candidate.has_private = 1;
    }
    memcpy(key, &candidate, sizeof(candidate));
    ret = 1;
end:
    gmssl_secure_clear(&candidate, sizeof(candidate));
    return ret;
}

static int rsa_components_operation(const RSA_COMPONENTS *key, int private_op,
    const uint8_t *in, size_t inlen, uint8_t *out, size_t capacity, size_t *outlen)
{
    struct {
        RSA_CT_MATH math;
        uint32_t n[RSA_CT_WORDS], base[RSA_CT_WORDS], d[RSA_CT_WORDS], e[2];
        uint32_t r[RSA_CT_WORDS], inverse[RSA_CT_WORDS], factor[RSA_CT_WORDS];
        uint32_t result[RSA_CT_WORDS], check[RSA_CT_WORDS], reciprocal[RSA_CT_WORDS + 1];
        uint8_t bytes[RSA_COMPONENTS_MAX_SIZE], candidate[RSA_COMPONENTS_MAX_SIZE];
    } w = {0};
    size_t k, offset, pos;
    unsigned attempt;
    int ret = -1;
    if (outlen) *outlen = 0;
    if (!rsa_components_valid(key) || !in || !out || !outlen ||
        inlen != key->size || capacity < inlen || (private_op && !key->has_private)) goto end;
    if (memcmp(in, key->n, inlen) >= 0) goto end;
    k = (inlen + 3) / 4;
    offset = 4 * k - inlen;
    memcpy(w.bytes + offset, key->n, inlen); bn_from_bytes(w.n, k, w.bytes);
    memcpy(w.bytes + offset, in, inlen); bn_from_bytes(w.base, k, w.bytes);
    memcpy(w.bytes + offset, key->d, inlen); bn_from_bytes(w.d, k, w.bytes);
    w.e[0] = (uint32_t)key->e; w.e[1] = (uint32_t)(key->e >> 32);
    rsa_ct_reciprocal(w.reciprocal, w.n, k, &w.math);
    if (private_op) {
        for (attempt = 0; attempt < 8; ++attempt) {
            for (pos = 0; pos < inlen;) {
                size_t take = inlen - pos > 256 ? 256 : inlen - pos;
                if (rand_bytes(w.bytes + pos, take) != 1) goto end;
                pos += take;
            }
            rsa_ct_from_bytes(w.r, w.bytes, inlen, w.n, k, &w.math);
            if (rsa_ct_inverse(w.inverse, w.r, w.n, k) == 1) break;
        }
        if (attempt == 8) goto end;
        rsa_ct_mul(w.check, w.r, w.inverse, w.n, w.reciprocal, k, &w.math);
        if (!bn_is_one(w.check, k)) goto end;
        rsa_ct_exp(w.factor, w.r, w.e, 2, w.n, w.reciprocal, k, &w.math);
        rsa_ct_mul(w.base, w.base, w.factor, w.n, w.reciprocal, k, &w.math);
        rsa_ct_exp(w.result, w.base, w.d, k, w.n, w.reciprocal, k, &w.math);
        rsa_ct_mul(w.result, w.result, w.inverse, w.n, w.reciprocal, k, &w.math);
        rsa_ct_exp(w.check, w.result, w.e, 2, w.n, w.reciprocal, k, &w.math);
        bn_to_bytes(w.check, k, w.bytes);
        if (gmssl_secure_memcmp(w.bytes + offset, in, inlen) != 0) goto end;
    } else {
        rsa_ct_exp(w.result, w.base, w.e, 2, w.n, w.reciprocal, k, &w.math);
    }
    bn_to_bytes(w.result, k, w.candidate);
    memcpy(out, w.candidate + offset, inlen);
    *outlen = inlen;
    ret = 1;
end:
    gmssl_secure_clear(&w, sizeof(w));
    return ret;
}

int rsa_components_public(const RSA_COMPONENTS *key, const uint8_t *in, size_t inlen,
    uint8_t *out, size_t capacity, size_t *outlen)
{
    return rsa_components_operation(key, 0, in, inlen, out, capacity, outlen);
}

int rsa_components_private(const RSA_COMPONENTS *key, const uint8_t *in, size_t inlen,
    uint8_t *out, size_t capacity, size_t *outlen)
{
    return rsa_components_operation(key, 1, in, inlen, out, capacity, outlen);
}

static void rsa_component_words(uint32_t *out, size_t words, const uint8_t *in, size_t size)
{
    size_t i;
    memset(out, 0, words * 4);
    for (i = 0; i < size; ++i)
        out[i / 4] |= (uint32_t)in[size - i - 1] << (8 * (i % 4));
}

int rsa_components_check_crt(const RSA_COMPONENTS *key,
    const uint8_t *p, size_t plen, const uint8_t *q, size_t qlen,
    const uint8_t *dp, size_t dplen, const uint8_t *dq, size_t dqlen,
    const uint8_t *qi, size_t qilen)
{
    struct {
        RSA_CT_MATH math;
        uint32_t p[RSA_CT_WORDS], q[RSA_CT_WORDS], modulus[RSA_CT_WORDS];
        uint32_t product[2*RSA_CT_WORDS], expected[2*RSA_CT_WORDS];
        uint32_t exponent[RSA_CT_WORDS], reduced[RSA_CT_WORDS], factor[RSA_CT_WORDS];
        uint32_t reciprocal[RSA_CT_WORDS+1], check[RSA_CT_WORDS];
        uint8_t e[8];
    } w = {0};
    size_t k, kp, kq, i, pass;
    int ret = -1;
    if (!rsa_components_valid(key) || !key->has_private || !p || !q || !dp || !dq || !qi ||
        !plen || !qlen || plen > key->size || qlen > key->size ||
        !dplen || dplen > plen || !dqlen || dqlen > qlen || !qilen || qilen > plen ||
        !p[0] || !q[0] || !(p[plen-1] & 1u) || !(q[qlen-1] & 1u)) goto end;
    k = ((plen > qlen ? plen : qlen) + 3) / 4;
    kp = (plen + 3) / 4; kq = (qlen + 3) / 4;
    rsa_component_words(w.p, k, p, plen); rsa_component_words(w.q, k, q, qlen);
    if (bn_is_one(w.p, k) || bn_is_one(w.q, k) || bn_cmp(w.p, w.q, k) == 0) goto end;
    bn_mul(w.product, w.p, w.q, k);
    if (key->size > 8*k) goto end;
    rsa_component_words(w.expected, 2*k, key->n, key->size);
    if (gmssl_secure_memcmp(w.product, w.expected, 8*k) != 0) goto end;
    for (i = 0; i < 8; ++i) w.e[7-i] = (uint8_t)(key->e >> (8*i));
    for (pass = 0; pass < 2; ++pass) {
        size_t width = pass ? kq : kp;
        const uint32_t *prime = pass ? w.q : w.p;
        bn_set_word(w.factor, 1, width);
        bn_sub(w.modulus, prime, w.factor, width);
        rsa_component_words(w.exponent, width, pass ? dq : dp, pass ? dqlen : dplen);
        rsa_ct_from_bytes(w.reduced, key->d, key->size, w.modulus, width, &w.math);
        if (gmssl_secure_memcmp(w.exponent, w.reduced, 4*width) != 0) goto end;
        rsa_ct_from_bytes(w.factor, w.e, sizeof(w.e), w.modulus, width, &w.math);
        rsa_ct_reciprocal(w.reciprocal, w.modulus, width, &w.math);
        rsa_ct_mul(w.check, w.exponent, w.factor, w.modulus, w.reciprocal, width, &w.math);
        if (!bn_is_one(w.check, width)) goto end;
    }
    rsa_component_words(w.exponent, kp, qi, qilen);
    if (bn_cmp(w.exponent, w.p, kp) >= 0) goto end;
    rsa_ct_from_bytes(w.factor, q, qlen, w.p, kp, &w.math);
    rsa_ct_reciprocal(w.reciprocal, w.p, kp, &w.math);
    rsa_ct_mul(w.check, w.exponent, w.factor, w.p, w.reciprocal, kp, &w.math);
    if (!bn_is_one(w.check, kp)) goto end;
    ret = 1;
end:
    gmssl_secure_clear(&w, sizeof(w));
    return ret;
}

int rsa_private_key_operation(const RSA_PRIVATE_KEY *key,
    const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t *outlen)
{
    struct {
        RSA_CT_MATH math;
        uint32_t p[RSA_CT_WORDS], q[RSA_CT_WORDS], n[RSA_CT_WORDS];
        uint32_t reciprocal[RSA_CT_WORDS + 1];
        uint32_t m1[RSA_CT_WORDS], m2[RSA_CT_WORDS], reduced[RSA_CT_WORDS];
        uint32_t coefficient[RSA_CT_WORDS], h[RSA_CT_WORDS];
        uint32_t product[RSA_CT_WORDS], checked[RSA_CT_WORDS];
        uint8_t candidate[RSA_MAX_MODULUS_SIZE], verification[RSA_MAX_MODULUS_SIZE];
    } w = {0};
    size_t k, i;
    uint32_t borrow;
    uint64_t carry = 0;
    int ret = -1;
    if (outlen) *outlen = 0;
    if (!key || !in || !out || !outlen ||
        key->public_key.modulus_size < RSA_MIN_MODULUS_SIZE ||
        key->public_key.modulus_size > RSA_MAX_MODULUS_SIZE ||
        key->prime_size != key->public_key.modulus_size / 2 ||
        (key->public_key.modulus_size & 7u) || (key->prime_size & 3u) ||
        inlen != key->public_key.modulus_size || outmax < inlen ||
        !key->prime1[0] || !key->prime2[0] || !key->public_key.modulus[0] ||
        !(key->prime1[key->prime_size - 1] & 1u) ||
        !(key->prime2[key->prime_size - 1] & 1u) ||
        !(key->public_key.modulus[inlen - 1] & 1u) ||
        key->public_key.public_exponent < 3 || !(key->public_key.public_exponent & 1u))
        goto end;
    /* Ciphertext and modulus are public. Reject representatives >= n. */
    if (memcmp(in, key->public_key.modulus, inlen) >= 0) goto end;
    k = key->prime_size / 4;
    bn_from_bytes(w.p, k, key->prime1);
    bn_from_bytes(w.q, k, key->prime2);
    bn_from_bytes(w.n, 2*k, key->public_key.modulus);
    bn_from_bytes(w.coefficient, k, key->coefficient);
    if (rsa_ct_prime(w.m1, in, inlen, key->prime1, key->exponent1,
            key->public_key.public_exponent, k, &w.math) != 1 ||
        rsa_ct_prime(w.m2, in, inlen, key->prime2, key->exponent2,
            key->public_key.public_exponent, k, &w.math) != 1) goto end;

    bn_to_bytes(w.m2, k, w.candidate);
    rsa_ct_from_bytes(w.reduced, w.candidate, k * 4, w.p, k, &w.math);
    borrow = (uint32_t)bn_sub(w.h, w.m1, w.reduced, k);
    bn_add(w.reduced, w.h, w.p, k);
    rsa_ct_select(w.h, w.reduced, w.h, borrow & 1u, k);
    rsa_ct_reciprocal(w.reciprocal, w.p, k, &w.math);
    rsa_ct_mul(w.h, w.h, w.coefficient, w.p, w.reciprocal, k, &w.math);
    bn_mul(w.product, w.q, w.h, k);
    for (i = 0; i < 2*k; ++i) {
        carry += (uint64_t)w.product[i] + (i < k ? w.m2[i] : 0u);
        w.product[i] = (uint32_t)carry;
        carry >>= 32;
    }
    if (carry || bn_sub(w.reduced, w.product, w.n, 2*k) == 0) goto end;
    /* Check the CRT result before releasing any plaintext/signature. Use the
     * fixed-schedule path here too: the candidate may be secret plaintext. */
    rsa_ct_reciprocal(w.reciprocal, w.n, 2*k, &w.math);
    rsa_ct_exp(w.checked, w.product, &key->public_key.public_exponent, 1,
        w.n, w.reciprocal, 2*k, &w.math);
    bn_to_bytes(w.checked, 2*k, w.verification);
    if (gmssl_secure_memcmp(w.verification, in, inlen) != 0) goto end;
    bn_to_bytes(w.product, 2*k, w.candidate);
    memcpy(out, w.candidate, inlen);
    *outlen = inlen;
    ret = 1;
end:
    gmssl_secure_clear(&w, sizeof(w));
    return ret;
}
