#include <gmssl/rsa_ext.h>
#include <gmssl/rsa_components.h>
#include <gmssl/digest.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <string.h>

typedef struct {
    const void *context;
    const uint8_t *modulus;
    size_t modulus_size;
    int (*operation)(const void *, const uint8_t *, size_t, uint8_t *, size_t, size_t *);
} RSA_ENCODING_KEY;

/* RFC 8017 sections 7.1, 8.1, 8.2 and 9. No provider key or digest state
 * escapes these bounded, per-call workspaces. */
static const DIGEST *rsa_digest(RSA_HASH hash)
{
    switch (hash) {
    case RSA_HASH_SHA1: return DIGEST_sha1();
    case RSA_HASH_SHA256: return DIGEST_sha256();
    case RSA_HASH_SHA384: return DIGEST_sha384();
    case RSA_HASH_SHA512: return DIGEST_sha512();
    default: return NULL;
    }
}

static int rsa_key_valid(const RSA_ENCODING_KEY *key)
{
    return key && key->modulus_size >= 64 &&
        key->modulus_size <= RSA_COMPONENTS_MAX_SIZE &&
        key->modulus && key->modulus[0] &&
        (key->modulus[key->modulus_size - 1] & 1u) && key->operation;
}

static size_t rsa_bits(const RSA_ENCODING_KEY *key)
{
    uint8_t top = key->modulus[0];
    size_t bits = 8 * (key->modulus_size - 1);
    while (top) { ++bits; top >>= 1; }
    return bits;
}

static int rsa_hash_parts(const DIGEST *md,
    const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
    const uint8_t *c, size_t clen, uint8_t *out)
{
    DIGEST_CTX ctx = {0};
    size_t n = 0;
    int ret = -1;
    if (digest_init(&ctx, md) != 1 ||
        (alen && digest_update(&ctx, a, alen) != 1) ||
        (blen && digest_update(&ctx, b, blen) != 1) ||
        (clen && digest_update(&ctx, c, clen) != 1) ||
        digest_finish(&ctx, out, &n) != 1 || n != md->digest_size) goto end;
    ret = 1;
end:
    gmssl_secure_clear(&ctx, sizeof(ctx));
    return ret;
}

/* XOR MGF1 into an existing buffer. All callers bound n by RSA_COMPONENTS_MAX_SIZE;
 * the four-byte counter therefore cannot overflow. */
static int rsa_mgf_xor(const DIGEST *md, const uint8_t *seed, size_t seedlen,
    uint8_t *out, size_t n)
{
    uint8_t block[DIGEST_MAX_SIZE], count[4];
    uint32_t counter = 0;
    size_t i, take;
    int ret = -1;
    if (n > RSA_COMPONENTS_MAX_SIZE) goto end;
    while (n) {
        count[0] = (uint8_t)(counter >> 24);
        count[1] = (uint8_t)(counter >> 16);
        count[2] = (uint8_t)(counter >> 8);
        count[3] = (uint8_t)counter++;
        if (rsa_hash_parts(md, seed, seedlen, count, sizeof(count), NULL, 0, block) != 1)
            goto end;
        take = n < md->digest_size ? n : md->digest_size;
        for (i = 0; i < take; ++i) out[i] ^= block[i];
        out += take;
        n -= take;
    }
    ret = 1;
end:
    gmssl_secure_clear(block, sizeof(block));
    return ret;
}

static int rsa_v15_encode(RSA_HASH hash, const uint8_t *dig, size_t diglen,
    uint8_t *em, size_t size)
{
    uint8_t prefix[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
        0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
    const DIGEST *md = rsa_digest(hash);
    size_t ps;
    if (!md || hash == RSA_HASH_SHA1 || !dig || diglen != md->digest_size ||
        size < 11 + sizeof(prefix) + diglen) return -1;
    prefix[1] = (uint8_t)(17 + diglen);
    prefix[14] = hash == RSA_HASH_SHA256 ? 1 : hash == RSA_HASH_SHA384 ? 2 : 3;
    prefix[18] = (uint8_t)diglen;
    ps = size - 3 - sizeof(prefix) - diglen;
    em[0] = 0;
    em[1] = 1;
    memset(em + 2, 0xff, ps);
    em[2 + ps] = 0;
    memcpy(em + 3 + ps, prefix, sizeof(prefix));
    memcpy(em + 3 + ps + sizeof(prefix), dig, diglen);
    return 1;
}

static int rsa_sign_pkcs1_v15_digest_core(const RSA_ENCODING_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, uint8_t *sig, size_t sigmax, size_t *siglen)
{
    uint8_t em[RSA_COMPONENTS_MAX_SIZE];
    int ret = -1;
    if (siglen) *siglen = 0;
    if (!key || !rsa_key_valid(key) || !sig || !siglen ||
        sigmax < key->modulus_size) goto end;
    if (rsa_v15_encode(hash, dig, diglen, em, key->modulus_size) != 1) goto end;
    ret = key->operation(key->context, em, key->modulus_size, sig, sigmax, siglen);
end:
    gmssl_secure_clear(em, sizeof(em));
    return ret;
}

static int rsa_verify_pkcs1_v15_digest_core(const RSA_ENCODING_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, const uint8_t *sig, size_t siglen)
{
    uint8_t em[RSA_COMPONENTS_MAX_SIZE], expected[RSA_COMPONENTS_MAX_SIZE];
    size_t n = 0;
    int ret = -1;
    if (!rsa_key_valid(key) || !sig) goto end;
    if (rsa_v15_encode(hash, dig, diglen, expected, key->modulus_size) != 1) goto end;
    ret = 0;
    if (siglen != key->modulus_size || memcmp(sig, key->modulus, siglen) >= 0) goto end;
    if (key->operation(key->context, sig, siglen, em, sizeof(em), &n) != 1) {
        ret = -1;
        goto end;
    }
    ret = n == key->modulus_size && gmssl_secure_memcmp(em, expected, n) == 0;
end:
    gmssl_secure_clear(em, sizeof(em));
    gmssl_secure_clear(expected, sizeof(expected));
    return ret;
}

static int rsa_sign_pss_digest_core(const RSA_ENCODING_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen,
    uint8_t *sig, size_t sigmax, size_t *siglen)
{
    const DIGEST *md = rsa_digest(hash);
    struct {
        uint8_t em[RSA_COMPONENTS_MAX_SIZE], salt[RSA_COMPONENTS_MAX_SIZE];
        uint8_t h[DIGEST_MAX_SIZE];
    } w = {0};
    static const uint8_t zero[8] = {0};
    uint8_t *db;
    size_t bits, len, db_len, offset, filled, take;
    int ret = -1;
    if (siglen) *siglen = 0;
    if (!md || hash == RSA_HASH_SHA1 || !dig || diglen != md->digest_size ||
        !key || !rsa_key_valid(key) || !sig || !siglen ||
        sigmax < key->modulus_size) goto end;
    bits = rsa_bits(key) - 1;
    len = (bits + 7) / 8;
    if (len < diglen + 2 || saltlen > len - diglen - 2) goto end;
    /* Some GmSSL platform RNGs cap a single request at 256 bytes. */
    for (filled = 0; filled < saltlen; filled += take) {
        take = saltlen - filled;
        if (take > 256) take = 256;
        if (rand_bytes(w.salt + filled, take) != 1) goto end;
    }
    if (rsa_hash_parts(md, zero, sizeof(zero), dig, diglen, w.salt, saltlen, w.h) != 1)
        goto end;
    offset = key->modulus_size - len;
    db = w.em + offset;
    db_len = len - diglen - 1;
    db[db_len - saltlen - 1] = 1;
    memcpy(db + db_len - saltlen, w.salt, saltlen);
    if (rsa_mgf_xor(md, w.h, diglen, db, db_len) != 1) goto end;
    db[0] &= (uint8_t)(0xffu >> (8 * len - bits));
    memcpy(db + db_len, w.h, diglen);
    db[len - 1] = 0xbc;
    ret = key->operation(key->context, w.em, key->modulus_size,
        sig, sigmax, siglen);
end:
    gmssl_secure_clear(&w, sizeof(w));
    return ret;
}

static int rsa_verify_pss_digest_core(const RSA_ENCODING_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen,
    const uint8_t *sig, size_t siglen)
{
    const DIGEST *md = rsa_digest(hash);
    uint8_t recovered[RSA_COMPONENTS_MAX_SIZE], h[DIGEST_MAX_SIZE];
    static const uint8_t zero[8] = {0};
    uint8_t *db;
    size_t bits, len, db_len, offset, n = 0, ps, i, unused;
    int ret = -1;
    if (!md || hash == RSA_HASH_SHA1 || !dig || diglen != md->digest_size ||
        !rsa_key_valid(key) || !sig) goto end;
    bits = rsa_bits(key) - 1;
    len = (bits + 7) / 8;
    if (len < diglen + 2 || (saltlen != RSA_PSS_SALT_AUTO && saltlen > len - diglen - 2))
        goto end;
    ret = 0;
    if (siglen != key->modulus_size || memcmp(sig, key->modulus, siglen) >= 0) goto end;
    if (key->operation(key->context, sig, siglen, recovered, sizeof(recovered), &n) != 1) {
        ret = -1;
        goto end;
    }
    if (n != key->modulus_size) goto end;
    offset = n - len;
    for (i = 0; i < offset; ++i) if (recovered[i]) goto end;
    db = recovered + offset;
    db_len = len - diglen - 1;
    unused = 8 * len - bits;
    if (db[len - 1] != 0xbc || (db[0] & (uint8_t)~(0xffu >> unused))) goto end;
    if (rsa_mgf_xor(md, db + db_len, diglen, db, db_len) != 1) { ret = -1; goto end; }
    db[0] &= (uint8_t)(0xffu >> unused);
    /* A signature and its recovered encoding are public, unlike OAEP decode. */
    for (ps = 0; ps < db_len && !db[ps]; ++ps) {}
    if (ps == db_len || db[ps] != 1) goto end;
    n = db_len - ps - 1;
    if (saltlen != RSA_PSS_SALT_AUTO && saltlen != n) goto end;
    if (rsa_hash_parts(md, zero, sizeof(zero), dig, diglen, db + ps + 1, n, h) != 1) {
        ret = -1;
        goto end;
    }
    ret = gmssl_secure_memcmp(h, db + db_len, diglen) == 0;
end:
    gmssl_secure_clear(recovered, sizeof(recovered));
    gmssl_secure_clear(h, sizeof(h));
    return ret;
}

static int rsa_oaep_encrypt_core(const RSA_ENCODING_KEY *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen,
    uint8_t *out, size_t outmax, size_t *outlen)
{
    const DIGEST *md = rsa_digest(hash);
    uint8_t em[RSA_COMPONENTS_MAX_SIZE] = {0};
    uint8_t *seed, *db;
    size_t hlen, db_len, size;
    int ret = -1;
    if (outlen) *outlen = 0;
    if (!md || !rsa_key_valid(key) || (!label && labellen) || (!in && inlen) ||
        !out || !outlen || outmax < key->modulus_size) goto end;
    hlen = md->digest_size;
    size = key->modulus_size;
    if (size < 2 * hlen + 2 || inlen > size - 2 * hlen - 2) goto end;
    seed = em + 1;
    db = seed + hlen;
    db_len = size - hlen - 1;
    if (rsa_hash_parts(md, label, labellen, NULL, 0, NULL, 0, db) != 1) goto end;
    db[db_len - inlen - 1] = 1;
    if (inlen) memcpy(db + db_len - inlen, in, inlen);
    if (rand_bytes(seed, hlen) != 1 ||
        rsa_mgf_xor(md, seed, hlen, db, db_len) != 1 ||
        rsa_mgf_xor(md, db, db_len, seed, hlen) != 1) goto end;
    ret = key->operation(key->context, em, size, out, outmax, outlen);
end:
    gmssl_secure_clear(em, sizeof(em));
    return ret;
}

static uint32_t rsa_byte_equal(uint8_t a, uint8_t b)
{
    return (((uint32_t)(a ^ b)) - 1u) >> 31;
}

static int rsa_oaep_decrypt_core(const RSA_ENCODING_KEY *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen,
    uint8_t *out, size_t outmax, size_t *outlen)
{
    const DIGEST *md = rsa_digest(hash);
    uint8_t em[RSA_COMPONENTS_MAX_SIZE], lhash[DIGEST_MAX_SIZE];
    uint8_t *seed, *db;
    size_t hlen, db_len, n = 0, i, start = 0, mask;
    uint32_t bad, looking = 1;
    int ret = -1;
    if (outlen) *outlen = 0;
    if (!md || !key || !rsa_key_valid(key) || (!label && labellen) ||
        !in || !out || !outlen) goto end;
    hlen = md->digest_size;
    if (key->modulus_size < 2 * hlen + 2) goto end;
    ret = 0;
    if (inlen != key->modulus_size ||
        key->operation(key->context, in, inlen, em, sizeof(em), &n) != 1 ||
        n != inlen) goto end;
    seed = em + 1;
    db = seed + hlen;
    db_len = n - hlen - 1;
    if (rsa_mgf_xor(md, db, db_len, seed, hlen) != 1 ||
        rsa_mgf_xor(md, seed, hlen, db, db_len) != 1 ||
        rsa_hash_parts(md, label, labellen, NULL, 0, NULL, 0, lhash) != 1) goto end;
    bad = em[0];
    for (i = 0; i < hlen; ++i) bad |= db[i] ^ lhash[i];
    /* Examine the full DB with no padding-dependent exit or lookup. Only
     * after all checks pass may the delimiter select a plaintext address. */
    for (i = hlen; i < db_len; ++i) {
        uint32_t is_zero = rsa_byte_equal(db[i], 0);
        uint32_t is_one = rsa_byte_equal(db[i], 1);
        bad |= looking & (1u ^ (is_zero | is_one));
        mask = (size_t)0 - (size_t)(looking & is_one);
        start = (start & ~mask) | ((i + 1) & mask);
        looking &= 1u ^ is_one;
    }
    bad |= looking;
    if (bad || db_len - start > outmax) goto end;
    n = db_len - start;
    if (n) memcpy(out, db + start, n);
    *outlen = n;
    ret = 1;
end:
    gmssl_secure_clear(em, sizeof(em));
    gmssl_secure_clear(lhash, sizeof(lhash));
    return ret;
}

static int rsa_old_public(const void *key, const uint8_t *in, size_t size,
    uint8_t *out, size_t capacity, size_t *outlen) {
    return rsa_public_key_operation(key, in, size, out, capacity, outlen);
}
static int rsa_old_private(const void *key, const uint8_t *in, size_t size,
    uint8_t *out, size_t capacity, size_t *outlen) {
    return rsa_private_key_operation(key, in, size, out, capacity, outlen);
}
static int rsa_new_public(const void *key, const uint8_t *in, size_t size,
    uint8_t *out, size_t capacity, size_t *outlen) {
    return rsa_components_public(key, in, size, out, capacity, outlen);
}
static int rsa_new_private(const void *key, const uint8_t *in, size_t size,
    uint8_t *out, size_t capacity, size_t *outlen) {
    return rsa_components_private(key, in, size, out, capacity, outlen);
}
static RSA_ENCODING_KEY rsa_old_view(const RSA_PUBLIC_KEY *key, const void *context, int priv) {
    RSA_ENCODING_KEY view = {0};
    if (key && key->modulus_size >= RSA_MIN_MODULUS_SIZE && key->modulus_size <= RSA_MAX_MODULUS_SIZE &&
        !(key->modulus_size & 3u) && key->public_exponent >= 3 && (key->public_exponent & 1u)) {
        view.context = context; view.modulus = key->modulus; view.modulus_size = key->modulus_size;
        view.operation = priv ? rsa_old_private : rsa_old_public;
    }
    return view;
}
static RSA_ENCODING_KEY rsa_new_view(const RSA_COMPONENTS *key, int priv) {
    RSA_ENCODING_KEY view = {0};
    if (key && key->size >= 64 && key->size <= RSA_COMPONENTS_MAX_SIZE &&
        (key->size != 64 || (key->n[0] & 0x80u)) && key->e >= 3 &&
        key->e <= UINT64_C(0x1ffffffff) && (key->e & 1u) && (!priv || key->has_private)) {
        view.context = key; view.modulus = key->n; view.modulus_size = key->size;
        view.operation = priv ? rsa_new_private : rsa_new_public;
    }
    return view;
}

int rsa_sign_pkcs1_v15_digest(const RSA_PRIVATE_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, uint8_t *sig, size_t sigmax, size_t *siglen)
{
    RSA_ENCODING_KEY view = rsa_old_view(key ? &key->public_key : NULL, key, 1);
    return rsa_sign_pkcs1_v15_digest_core(&view, hash, dig, diglen, sig, sigmax, siglen);
}

int rsa_components_sign_pkcs1_v15_digest(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, uint8_t *sig, size_t sigmax, size_t *siglen)
{
    RSA_ENCODING_KEY view = rsa_new_view(key, 1);
    return rsa_sign_pkcs1_v15_digest_core(&view, hash, dig, diglen, sig, sigmax, siglen);
}

int rsa_verify_pkcs1_v15_digest(const RSA_PUBLIC_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, const uint8_t *sig, size_t siglen)
{
    RSA_ENCODING_KEY view = rsa_old_view(key, key, 0);
    return rsa_verify_pkcs1_v15_digest_core(&view, hash, dig, diglen, sig, siglen);
}

int rsa_components_verify_pkcs1_v15_digest(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, const uint8_t *sig, size_t siglen)
{
    RSA_ENCODING_KEY view = rsa_new_view(key, 0);
    return rsa_verify_pkcs1_v15_digest_core(&view, hash, dig, diglen, sig, siglen);
}

int rsa_sign_pss_digest(const RSA_PRIVATE_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen, uint8_t *sig, size_t sigmax, size_t *siglen)
{
    RSA_ENCODING_KEY view = rsa_old_view(key ? &key->public_key : NULL, key, 1);
    return rsa_sign_pss_digest_core(&view, hash, dig, diglen, saltlen, sig, sigmax, siglen);
}

int rsa_components_sign_pss_digest(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen, uint8_t *sig, size_t sigmax, size_t *siglen)
{
    RSA_ENCODING_KEY view = rsa_new_view(key, 1);
    return rsa_sign_pss_digest_core(&view, hash, dig, diglen, saltlen, sig, sigmax, siglen);
}

int rsa_verify_pss_digest(const RSA_PUBLIC_KEY *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen, const uint8_t *sig, size_t siglen)
{
    RSA_ENCODING_KEY view = rsa_old_view(key, key, 0);
    return rsa_verify_pss_digest_core(&view, hash, dig, diglen, saltlen, sig, siglen);
}

int rsa_components_verify_pss_digest(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *dig, size_t diglen, size_t saltlen, const uint8_t *sig, size_t siglen)
{
    RSA_ENCODING_KEY view = rsa_new_view(key, 0);
    return rsa_verify_pss_digest_core(&view, hash, dig, diglen, saltlen, sig, siglen);
}

int rsa_oaep_encrypt(const RSA_PUBLIC_KEY *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t *outlen)
{
    RSA_ENCODING_KEY view = rsa_old_view(key, key, 0);
    return rsa_oaep_encrypt_core(&view, hash, label, labellen, in, inlen, out, outmax, outlen);
}

int rsa_components_oaep_encrypt(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t *outlen)
{
    RSA_ENCODING_KEY view = rsa_new_view(key, 0);
    return rsa_oaep_encrypt_core(&view, hash, label, labellen, in, inlen, out, outmax, outlen);
}

int rsa_oaep_decrypt(const RSA_PRIVATE_KEY *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t *outlen)
{
    RSA_ENCODING_KEY view = rsa_old_view(key ? &key->public_key : NULL, key, 1);
    return rsa_oaep_decrypt_core(&view, hash, label, labellen, in, inlen, out, outmax, outlen);
}

int rsa_components_oaep_decrypt(const RSA_COMPONENTS *key, RSA_HASH hash,
    const uint8_t *label, size_t labellen, const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t *outlen)
{
    RSA_ENCODING_KEY view = rsa_new_view(key, 1);
    return rsa_oaep_decrypt_core(&view, hash, label, labellen, in, inlen, out, outmax, outlen);
}
