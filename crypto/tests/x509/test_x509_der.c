/* SPDX-License-Identifier: Apache-2.0
 * Independent source and installed-SDK X.509 structural DER conformance.
 * No OpenSSL/GmSSL in the fixture loader, test executable or implementation.
 */
#include <crypto/x509_der.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef CRYPTO_X509_TEST_P256_PEM
#error "Set CRYPTO_X509_TEST_P256_PEM to the original reviewed PEM fixture"
#endif
#ifndef CRYPTO_X509_TEST_P384_PEM
#error "Set CRYPTO_X509_TEST_P384_PEM to the original reviewed PEM fixture"
#endif

#define REQUIRE(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "%s:%d: FAIL: %s\n", __FILE__, __LINE__, #cond); \
        return 0; \
    } \
} while (0)

static int b64(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Test-only bounded PEM fixture reader; production inspector accepts DER only. */
static int read_cert_fixture(const char *file, uint8_t *der,
                             size_t capacity, size_t *out_size) {
    FILE *in = fopen(file, "rb");
    char pem[8192];
    char *p, *end;
    size_t n, written = 0u;
    uint32_t acc = 0u;
    unsigned bits = 0u;
    if (!in) return 0;
    n = fread(pem, 1u, sizeof(pem) - 1u, in);
    if (ferror(in) || !feof(in)) { fclose(in); return 0; }
    fclose(in);
    pem[n] = '\0';
    p = strstr(pem, "-----BEGIN CERTIFICATE-----");
    end = strstr(pem, "-----END CERTIFICATE-----");
    if (!p || !end || end <= p) return 0;
    p += strlen("-----BEGIN CERTIFICATE-----");
    for (; p < end; ++p) {
        int d;
        unsigned char c = (unsigned char)*p;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        d = b64(c);
        if (d < 0) return 0;
        acc = (acc << 6) | (uint32_t)d;
        bits += 6u;
        if (bits >= 8u) {
            bits -= 8u;
            if (written == capacity) return 0;
            der[written++] = (uint8_t)(acc >> bits);
            acc &= (uint32_t)((1u << bits) - 1u);
        }
    }
    if (bits > 4u || !written || written > CRYPTO_X509_DER_MAX_CERT_BYTES)
        return 0;
    *out_size = written;
    return 1;
}

static int real_certificate(const uint8_t *der, size_t n,
                            crypto_x509_der_view *out) {
    asn1_status s = crypto_x509_der_inspect(der, n, out);
    REQUIRE(s == SALTS_ASN1_OK);
    REQUIRE(out->certificate_der == der && out->certificate_size == n);
    REQUIRE(out->tbs_der && out->tbs_size > 64u);
    REQUIRE(out->version == 2u);
    REQUIRE(out->serial_number && out->serial_number_size > 0u);
    REQUIRE(out->issuer_der && out->issuer_size > 2u);
    REQUIRE(out->subject_der && out->subject_size > 2u);
    REQUIRE(out->validity_der && out->validity_size > 2u);
    REQUIRE(out->spki_der && out->spki_size > 8u);
    REQUIRE(out->signature_algorithm_oid &&
            out->signature_algorithm_oid_size > 2u);
    REQUIRE(out->public_key_algorithm_oid &&
            out->public_key_algorithm_oid_size > 2u);
    REQUIRE(out->signature && out->signature_size > 16u);
    REQUIRE(out->extensions_der && out->extensions_size > 2u);
    REQUIRE(out->spki_der >= der && out->spki_der < der + n);
    REQUIRE(out->signature >= der && out->signature < der + n);
    return 1;
}

static int must_reject_unchanged(const uint8_t *der, size_t n) {
    crypto_x509_der_view marker, before;
    memset(&marker, 0xa5, sizeof(marker));
    before = marker;
    REQUIRE(crypto_x509_der_inspect(der, n, &marker) != SALTS_ASN1_OK);
    REQUIRE(memcmp(&marker, &before, sizeof(marker)) == 0);
    return 1;
}

static int tamper_alg_identifier(uint8_t *buf, size_t n) {
    asn1_reader top, cert, algorithm;
    asn1_tlv root, tbs, alg, oid;
    REQUIRE(asn1_reader_init(&top, buf, n, SALTS_ASN1_DER) == SALTS_ASN1_OK);
    REQUIRE(asn1_reader_next(&top, &root) == SALTS_ASN1_OK);
    REQUIRE(asn1_reader_open_children(&top, &root, &cert) == SALTS_ASN1_OK);
    REQUIRE(asn1_reader_next(&cert, &tbs) == SALTS_ASN1_OK);
    REQUIRE(asn1_reader_next(&cert, &alg) == SALTS_ASN1_OK);
    REQUIRE(asn1_reader_open_children(&cert, &alg, &algorithm) == SALTS_ASN1_OK);
    REQUIRE(asn1_reader_next(&algorithm, &oid) == SALTS_ASN1_OK);
    REQUIRE(oid.content_size > 1u);
    ((uint8_t *)oid.content)[oid.content_size - 1u] ^= 1u;
    return 1;
}

static int negative_cases(const uint8_t *good, size_t n,
                          const crypto_x509_der_view *view) {
    uint8_t bytes[CRYPTO_X509_DER_MAX_CERT_BYTES + 1u];
    crypto_x509_der_view marker, before;
    size_t i;
    static const uint8_t indefinite[] = {0x30u, 0x80u, 0x00u, 0x00u};
    REQUIRE(n > 64u && n < CRYPTO_X509_DER_MAX_CERT_BYTES);
    REQUIRE(must_reject_unchanged(good, n - 1u));
    REQUIRE(must_reject_unchanged(indefinite, sizeof(indefinite)));

    memcpy(bytes, good, n);
    bytes[n] = 0u; /* trailing bytes after one full Certificate */
    REQUIRE(crypto_x509_der_inspect(bytes, n + 1u, &marker) ==
            SALTS_ASN1_TRAILING_DATA);

    memcpy(bytes, good, n);
    bytes[(size_t)(view->serial_number - good)] = 0xffu;
    REQUIRE(must_reject_unchanged(bytes, n)); /* negative serial */

    memcpy(bytes, good, n);
    REQUIRE(tamper_alg_identifier(bytes, n));
    REQUIRE(must_reject_unchanged(bytes, n)); /* outer vs TBSCertificate */

    memcpy(bytes, good, n);
    REQUIRE(view->signature > good);
    bytes[(size_t)(view->signature - good) - 1u] = 8u;
    REQUIRE(must_reject_unchanged(bytes, n)); /* invalid BIT STRING unused bits */

    memcpy(bytes, good, n);
    {
        size_t start = (size_t)(view->validity_der - good);
        size_t end = start + view->validity_size;
        int changed = 0;
        for (i = start; i < end; ++i) {
            if (bytes[i] == 'Z') { bytes[i] = 'X'; changed = 1; break; }
        }
        REQUIRE(changed);
        REQUIRE(must_reject_unchanged(bytes, n)); /* invalid DER time */
    }

    memcpy(bytes, good, n);
    {
        int changed = 0;
        for (i = 0u; i + 5u < n; ++i) {
            if (bytes[i] == 0xa0u && bytes[i + 1u] == 0x03u &&
                bytes[i + 2u] == 0x02u && bytes[i + 3u] == 0x01u &&
                bytes[i + 4u] == 0x02u) {
                bytes[i + 4u] = 0x03u; /* version v4 is forbidden */
                changed = 1; break;
            }
        }
        REQUIRE(changed);
        REQUIRE(must_reject_unchanged(bytes, n));
    }
    memset(&marker, 0xa5, sizeof(marker));
    before = marker;
    REQUIRE(crypto_x509_der_inspect(NULL, 1u, &marker) ==
            SALTS_ASN1_INVALID_ARGUMENT);
    REQUIRE(memcmp(&marker, &before, sizeof(marker)) == 0);
    REQUIRE(crypto_x509_der_inspect(bytes,
        CRYPTO_X509_DER_MAX_CERT_BYTES + 1u, &marker) ==
        SALTS_ASN1_LIMIT_EXCEEDED);
    REQUIRE(memcmp(&marker, &before, sizeof(marker)) == 0);
    return 1;
}

static int concatenated_chain(const uint8_t *a, size_t an,
                              const uint8_t *b, size_t bn) {
    uint8_t chain[CRYPTO_X509_DER_MAX_CHAIN_BYTES + 1u];
    crypto_x509_der_view v, untouched;
    size_t offset = 0u;
    REQUIRE(an + bn < sizeof(chain));
    memcpy(chain, a, an);
    memcpy(chain + an, b, bn);
    REQUIRE(crypto_x509_der_chain_next(chain, an + bn, &offset, &v) ==
            SALTS_ASN1_OK);
    REQUIRE(offset == an && v.certificate_der == chain);
    REQUIRE(crypto_x509_der_chain_next(chain, an + bn, &offset, &v) ==
            SALTS_ASN1_OK);
    REQUIRE(offset == an + bn && v.certificate_der == chain + an);
    untouched = v;
    REQUIRE(crypto_x509_der_chain_next(chain, an + bn, &offset, &v) ==
            SALTS_ASN1_DONE);
    REQUIRE(offset == an + bn && memcmp(&v, &untouched, sizeof(v)) == 0);

    chain[an] = 0xffu;
    offset = an;
    untouched = v;
    REQUIRE(crypto_x509_der_chain_next(chain, an + bn, &offset, &v) !=
            SALTS_ASN1_OK);
    REQUIRE(offset == an && memcmp(&v, &untouched, sizeof(v)) == 0);

    REQUIRE(crypto_x509_der_chain_next(chain, an + bn,
            NULL, &v) == SALTS_ASN1_INVALID_ARGUMENT);
    REQUIRE(crypto_x509_der_chain_next(chain,
            CRYPTO_X509_DER_MAX_CHAIN_BYTES + 1u,
            &offset, &v) == SALTS_ASN1_LIMIT_EXCEEDED);
    return 1;
}

int main(void) {
    uint8_t p256[CRYPTO_X509_DER_MAX_CERT_BYTES];
    uint8_t p384[CRYPTO_X509_DER_MAX_CERT_BYTES];
    size_t n256 = 0u, n384 = 0u;
    crypto_x509_der_view a, b;
    if (!read_cert_fixture(CRYPTO_X509_TEST_P256_PEM, p256, sizeof(p256), &n256)
        || !read_cert_fixture(CRYPTO_X509_TEST_P384_PEM, p384, sizeof(p384), &n384)) {
        fputs("Cannot read exact original PEM certificate fixture\n", stderr);
        return 1;
    }
    if (!real_certificate(p256, n256, &a) ||
        !real_certificate(p384, n384, &b) ||
        !negative_cases(p256, n256, &a) ||
        !concatenated_chain(p256, n256, p384, n384))
        return 1;
    puts("PASS real DER P256/P384 certificates, negative format and TLS chain walk");
    return 0;
}
