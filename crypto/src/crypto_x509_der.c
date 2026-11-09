/* SPDX-License-Identifier: Apache-2.0
 * Pure DER structural inspection. Signature operations and trust/profile
 * decisions belong to separate Crypto APIs; this inspector authenticates nothing.
 */
#include <crypto/x509_der.h>

#include <string.h>

static int tag_is(const asn1_tlv *v, uint8_t cls,
                  uint8_t constructed, uint32_t tag) {
    return v->tag_class == cls && v->constructed == constructed &&
           v->tag_number == tag;
}

static asn1_status required(asn1_reader *r, asn1_tlv *v) {
    asn1_status s = asn1_reader_next(r, v);
    return s == SALTS_ASN1_DONE ? SALTS_ASN1_MALFORMED : s;
}

static asn1_status end_of(asn1_reader *r) {
    asn1_tlv extra;
    asn1_status s = asn1_reader_next(r, &extra);
    return s == SALTS_ASN1_DONE ? SALTS_ASN1_OK :
           s == SALTS_ASN1_OK ? SALTS_ASN1_MALFORMED : s;
}

static const uint8_t *encoded(const asn1_tlv *v) {
    /* The canonical Reader validated encoded_size >= content_size. */
    return v->content - (v->encoded_size - v->content_size);
}

static asn1_status algorithm(
    const asn1_reader *parent, const asn1_tlv *value,
    const uint8_t **oid, size_t *oid_size) {
    asn1_reader r;
    asn1_tlv v;
    asn1_status s;
    if (!tag_is(value, 0u, 1u, 16u)) return SALTS_ASN1_MALFORMED;
    s = asn1_reader_open_children(parent, value, &r);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&r, &v);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&v, 0u, 0u, 6u)) return SALTS_ASN1_MALFORMED;
    *oid = v.content;
    *oid_size = v.content_size;
    /* AlgorithmIdentifier parameters are OPTIONAL, but at most one value.
     * Profile-specific rules (e.g. absent Ed25519 parameters) belong to
     * the Crypto algorithm/profile validation, not this generic inspector. */
    s = asn1_reader_next(&r, &v);
    if (s == SALTS_ASN1_DONE) return SALTS_ASN1_OK;
    if (s != SALTS_ASN1_OK) return s;
    return end_of(&r);
}

static int date_syntax(const asn1_tlv *v) {
    size_t digits, i;
    const uint8_t *p = v->content;
    if (v->tag_class != 0u || v->constructed) return 0;
    if (v->tag_number == 23u) digits = 12u;  /* YYMMDDhhmmssZ */
    else if (v->tag_number == 24u) digits = 14u; /* YYYYMMDDhhmmssZ */
    else return 0;
    if (v->content_size != digits + 1u || p[digits] != 'Z') return 0;
    for (i = 0u; i < digits; ++i)
        if (p[i] < '0' || p[i] > '9') return 0;
    /* RFC5280 canonical DER time field syntax and basic component ranges.
     * Neither chronology nor validity-at-current-time is evaluated here. */
    {
        size_t k = v->tag_number == 23u ? 2u : 4u;
        unsigned month = (unsigned)(p[k] - '0') * 10u + (unsigned)(p[k + 1u] - '0');
        unsigned day = (unsigned)(p[k + 2u] - '0') * 10u + (unsigned)(p[k + 3u] - '0');
        unsigned hour = (unsigned)(p[k + 4u] - '0') * 10u + (unsigned)(p[k + 5u] - '0');
        unsigned min = (unsigned)(p[k + 6u] - '0') * 10u + (unsigned)(p[k + 7u] - '0');
        unsigned sec = (unsigned)(p[k + 8u] - '0') * 10u + (unsigned)(p[k + 9u] - '0');
        if (month < 1u || month > 12u || day < 1u || day > 31u ||
            hour > 23u || min > 59u || sec > 59u) return 0;
    }
    return 1;
}

static asn1_status validity(const asn1_reader *parent,
                                 const asn1_tlv *v) {
    asn1_reader r;
    asn1_tlv time;
    asn1_status s;
    if (!tag_is(v, 0u, 1u, 16u)) return SALTS_ASN1_MALFORMED;
    s = asn1_reader_open_children(parent, v, &r);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&r, &time);
    if (s != SALTS_ASN1_OK) return s;
    if (!date_syntax(&time)) return SALTS_ASN1_MALFORMED;
    s = required(&r, &time);
    if (s != SALTS_ASN1_OK) return s;
    if (!date_syntax(&time)) return SALTS_ASN1_MALFORMED;
    return end_of(&r);
}

static asn1_status spki(
    const asn1_reader *parent, const asn1_tlv *v,
    crypto_x509_der_view *out) {
    asn1_reader r;
    asn1_tlv alg, bits;
    asn1_status s;
    if (!tag_is(v, 0u, 1u, 16u)) return SALTS_ASN1_MALFORMED;
    s = asn1_reader_open_children(parent, v, &r);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&r, &alg);
    if (s != SALTS_ASN1_OK) return s;
    s = algorithm(&r, &alg, &out->public_key_algorithm_oid,
                  &out->public_key_algorithm_oid_size);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&r, &bits);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&bits, 0u, 0u, 3u) ||
        bits.content_size < 2u || bits.content[0] != 0u)
        return SALTS_ASN1_MALFORMED;
    return end_of(&r);
}

static asn1_status extensions(
    const asn1_reader *parent, const asn1_tlv *field,
    crypto_x509_der_view *out) {
    asn1_reader wrapper, entries, attributes;
    asn1_tlv list, ext, oid, value;
    asn1_status s;
    size_t count = 0u, i;
    /* One bounded set of borrowed OIDs, solely for rejecting duplicates. */
    const uint8_t *seen[CRYPTO_X509_DER_MAX_EXTENSIONS];
    size_t lengths[CRYPTO_X509_DER_MAX_EXTENSIONS];
    if (!tag_is(field, 2u, 1u, 3u)) return SALTS_ASN1_MALFORMED;
    s = asn1_reader_open_children(parent, field, &wrapper);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&wrapper, &list);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&list, 0u, 1u, 16u)) return SALTS_ASN1_MALFORMED;
    s = end_of(&wrapper);
    if (s != SALTS_ASN1_OK) return s;
    s = asn1_reader_open_children(&wrapper, &list, &entries);
    if (s != SALTS_ASN1_OK) return s;
    for (;;) {
        s = asn1_reader_next(&entries, &ext);
        if (s == SALTS_ASN1_DONE) break;
        if (s != SALTS_ASN1_OK) return s;
        if (!tag_is(&ext, 0u, 1u, 16u) ||
            count == CRYPTO_X509_DER_MAX_EXTENSIONS)
            return SALTS_ASN1_LIMIT_EXCEEDED;
        s = asn1_reader_open_children(&entries, &ext, &attributes);
        if (s != SALTS_ASN1_OK) return s;
        s = required(&attributes, &oid);
        if (s != SALTS_ASN1_OK) return s;
        if (!tag_is(&oid, 0u, 0u, 6u)) return SALTS_ASN1_MALFORMED;
        for (i = 0u; i < count; ++i)
            if (lengths[i] == oid.content_size &&
                memcmp(seen[i], oid.content, oid.content_size) == 0)
                return SALTS_ASN1_MALFORMED;
        seen[count] = oid.content;
        lengths[count++] = oid.content_size;
        s = required(&attributes, &value);
        if (s != SALTS_ASN1_OK) return s;
        if (tag_is(&value, 0u, 0u, 1u)) {
            /* BOOLEAN DEFAULT FALSE is omitted in canonical X.509 DER. */
            if (value.content_size != 1u || value.content[0] != 0xffu)
                return SALTS_ASN1_MALFORMED;
            s = required(&attributes, &value);
            if (s != SALTS_ASN1_OK) return s;
        }
        if (!tag_is(&value, 0u, 0u, 4u) || value.content_size == 0u)
            return SALTS_ASN1_MALFORMED;
        s = end_of(&attributes);
        if (s != SALTS_ASN1_OK) return s;
    }
    if (!count) return SALTS_ASN1_MALFORMED;
    out->extensions_der = encoded(&list);
    out->extensions_size = list.encoded_size;
    return SALTS_ASN1_OK;
}

static asn1_status parse_tbs(
    const asn1_reader *parent, const asn1_tlv *tbs,
    crypto_x509_der_view *out,
    const uint8_t **tbs_algorithm_der, size_t *tbs_algorithm_size) {
    asn1_reader r, vreader;
    asn1_tlv v, number, serial, alg;
    asn1_status s;
    uint32_t previous_optional = 0u;
    if (!tag_is(tbs, 0u, 1u, 16u)) return SALTS_ASN1_MALFORMED;
    s = asn1_reader_open_children(parent, tbs, &r);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&r, &v);
    if (s != SALTS_ASN1_OK) return s;
    if (tag_is(&v, 2u, 1u, 0u)) {
        s = asn1_reader_open_children(&r, &v, &vreader);
        if (s != SALTS_ASN1_OK) return s;
        s = required(&vreader, &number);
        if (s != SALTS_ASN1_OK) return s;
        if (!tag_is(&number, 0u, 0u, 2u) ||
            number.content_size != 1u ||
            number.content[0] < 1u || number.content[0] > 2u)
            return SALTS_ASN1_MALFORMED;
        out->version = number.content[0];
        s = end_of(&vreader);
        if (s != SALTS_ASN1_OK) return s;
        s = required(&r, &v);
        if (s != SALTS_ASN1_OK) return s;
    }
    serial = v;
    if (!tag_is(&serial, 0u, 0u, 2u) ||
        serial.content_size == 0u || serial.content_size > 20u ||
        (serial.content[0] & 0x80u) != 0u ||
        (serial.content_size == 1u && serial.content[0] == 0u))
        return SALTS_ASN1_MALFORMED;
    out->serial_number = serial.content;
    out->serial_number_size = serial.content_size;

    s = required(&r, &alg);
    if (s != SALTS_ASN1_OK) return s;
    s = algorithm(&r, &alg, &out->signature_algorithm_oid,
                  &out->signature_algorithm_oid_size);
    if (s != SALTS_ASN1_OK) return s;
    *tbs_algorithm_der = encoded(&alg);
    *tbs_algorithm_size = alg.encoded_size;

    s = required(&r, &v);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&v, 0u, 1u, 16u) || v.content_size == 0u)
        return SALTS_ASN1_MALFORMED;
    out->issuer_der = encoded(&v);
    out->issuer_size = v.encoded_size;

    s = required(&r, &v);
    if (s != SALTS_ASN1_OK) return s;
    s = validity(&r, &v);
    if (s != SALTS_ASN1_OK) return s;
    out->validity_der = encoded(&v);
    out->validity_size = v.encoded_size;

    s = required(&r, &v);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&v, 0u, 1u, 16u)) return SALTS_ASN1_MALFORMED;
    out->subject_der = encoded(&v);
    out->subject_size = v.encoded_size;

    s = required(&r, &v);
    if (s != SALTS_ASN1_OK) return s;
    s = spki(&r, &v, out);
    if (s != SALTS_ASN1_OK) return s;
    out->spki_der = encoded(&v);
    out->spki_size = v.encoded_size;

    for (;;) {
        s = asn1_reader_next(&r, &v);
        if (s == SALTS_ASN1_DONE) return SALTS_ASN1_OK;
        if (s != SALTS_ASN1_OK) return s;
        if (v.tag_class != 2u || v.tag_number < 1u ||
            v.tag_number > 3u || v.tag_number <= previous_optional)
            return SALTS_ASN1_MALFORMED;
        previous_optional = v.tag_number;
        if (v.tag_number == 3u) {
            if (out->version != 2u) return SALTS_ASN1_MALFORMED;
            s = extensions(&r, &v, out);
            if (s != SALTS_ASN1_OK) return s;
        } else {
            /* issuerUniqueID/subjectUniqueID are IMPLICIT BIT STRING.
             * They require v2 or newer and MUST have valid unused bits. */
            if (out->version == 0u || v.constructed ||
                v.content_size == 0u || v.content[0] > 7u)
                return SALTS_ASN1_MALFORMED;
            if (v.content_size == 1u && v.content[0] != 0u)
                return SALTS_ASN1_MALFORMED;
            if (v.content_size > 1u && v.content[0] != 0u &&
                (v.content[v.content_size - 1u] &
                 (uint8_t)((1u << v.content[0]) - 1u)) != 0u)
                return SALTS_ASN1_MALFORMED;
        }
    }
}

asn1_status crypto_x509_der_inspect(
    const void *certificate_der, size_t certificate_size,
    crypto_x509_der_view *out) {
    asn1_reader top, cert;
    asn1_tlv root, tbs, outer_alg, signature;
    asn1_status s;
    crypto_x509_der_view value = {0};
    const uint8_t *inner_algorithm = NULL, *oid = NULL;
    size_t inner_algorithm_size = 0u, oid_size = 0u;
    if (!out || !certificate_der || certificate_size == 0u)
        return SALTS_ASN1_INVALID_ARGUMENT;
    if (certificate_size > CRYPTO_X509_DER_MAX_CERT_BYTES)
        return SALTS_ASN1_LIMIT_EXCEEDED;
    s = asn1_validate(certificate_der, certificate_size, SALTS_ASN1_DER);
    if (s != SALTS_ASN1_OK) return s;
    s = asn1_reader_init(&top, certificate_der, certificate_size,
                              SALTS_ASN1_DER);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&top, &root);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&root, 0u, 1u, 16u) ||
        root.encoded_size != certificate_size)
        return SALTS_ASN1_MALFORMED;
    s = asn1_reader_open_children(&top, &root, &cert);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&cert, &tbs);
    if (s != SALTS_ASN1_OK) return s;
    s = parse_tbs(&cert, &tbs, &value, &inner_algorithm,
                  &inner_algorithm_size);
    if (s != SALTS_ASN1_OK) return s;
    value.tbs_der = encoded(&tbs);
    value.tbs_size = tbs.encoded_size;

    s = required(&cert, &outer_alg);
    if (s != SALTS_ASN1_OK) return s;
    s = algorithm(&cert, &outer_alg, &oid, &oid_size);
    if (s != SALTS_ASN1_OK) return s;
    /* RFC 5280 TBSCertificate.signature MUST match Certificate.signatureAlgorithm. */
    if (inner_algorithm_size != outer_alg.encoded_size ||
        memcmp(inner_algorithm, encoded(&outer_alg),
               inner_algorithm_size) != 0)
        return SALTS_ASN1_MALFORMED;

    s = required(&cert, &signature);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&signature, 0u, 0u, 3u) ||
        signature.content_size < 2u || signature.content[0] != 0u)
        return SALTS_ASN1_MALFORMED;
    s = end_of(&cert);
    if (s != SALTS_ASN1_OK) return s;

    value.certificate_der = (const uint8_t *)certificate_der;
    value.certificate_size = certificate_size;
    value.signature = signature.content + 1u;
    value.signature_size = signature.content_size - 1u;
    *out = value;
    return SALTS_ASN1_OK;
}

asn1_status crypto_x509_der_chain_next(
    const void *chain, size_t chain_size, size_t *offset,
    crypto_x509_der_view *out) {
    asn1_reader reader;
    asn1_tlv certificate;
    crypto_x509_der_view value;
    asn1_status s;
    const uint8_t *data = (const uint8_t *)chain;
    size_t position;
    if (!chain || !offset || !out || *offset > chain_size)
        return SALTS_ASN1_INVALID_ARGUMENT;
    if (chain_size > CRYPTO_X509_DER_MAX_CHAIN_BYTES)
        return SALTS_ASN1_LIMIT_EXCEEDED;
    position = *offset;
    if (position == chain_size) return SALTS_ASN1_DONE;
    s = asn1_reader_init(&reader, data + position,
                              chain_size - position, SALTS_ASN1_DER);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&reader, &certificate);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&certificate, 0u, 1u, 16u))
        return SALTS_ASN1_MALFORMED;
    s = crypto_x509_der_inspect(data + position,
                                certificate.encoded_size, &value);
    if (s != SALTS_ASN1_OK) return s;
    *out = value;
    *offset = position + certificate.encoded_size;
    return SALTS_ASN1_OK;
}


/* The legacy SaltsNet X509 parser recognized these OIDs. They are ordinary
 * ASN.1 AlgorithmIdentifier metadata, not evidence of public-key validity. */
asn1_status crypto_x509_der_get_public_key_kind(
    const crypto_x509_der_view *view,
    crypto_x509_der_public_key_kind *out) {
    static const uint8_t rsa[] = {
        0x2au,0x86u,0x48u,0x86u,0xf7u,0x0du,0x01u,0x01u,0x01u
    };
    static const uint8_t ec[] = {0x2au,0x86u,0x48u,0xceu,0x3du,0x02u,0x01u};
    static const uint8_t ed25519[] = {0x2bu,0x65u,0x70u};
    crypto_x509_der_public_key_kind kind = CRYPTO_X509_DER_KEY_UNKNOWN;
    const uint8_t *oid;
    size_t length;
    if (!view || !out || !view->public_key_algorithm_oid ||
        view->public_key_algorithm_oid_size == 0u)
        return SALTS_ASN1_INVALID_ARGUMENT;
    oid = view->public_key_algorithm_oid;
    length = view->public_key_algorithm_oid_size;
    if (length == sizeof(rsa) && memcmp(oid,rsa,sizeof(rsa)) == 0)
        kind = CRYPTO_X509_DER_KEY_RSA;
    else if (length == sizeof(ec) && memcmp(oid,ec,sizeof(ec)) == 0)
        kind = CRYPTO_X509_DER_KEY_EC;
    else if (length == sizeof(ed25519) &&
             memcmp(oid,ed25519,sizeof(ed25519)) == 0)
        kind = CRYPTO_X509_DER_KEY_ED25519;
    *out = kind;
    return SALTS_ASN1_OK;
}

asn1_status crypto_x509_der_common_name(
    const crypto_x509_der_view *view, uint8_t issuer,
    const uint8_t **out_data, size_t *out_size) {
    static const uint8_t cn_oid[] = {0x55u,0x04u,0x03u};
    const uint8_t *name;
    size_t name_size;
    const uint8_t *found = NULL;
    size_t found_size = 0u;
    asn1_reader root_reader, rdns, attributes, fields;
    asn1_tlv root, rdn, attribute, oid, value;
    asn1_status s;
    if (!view || !out_data || !out_size || issuer > 1u)
        return SALTS_ASN1_INVALID_ARGUMENT;
    name = issuer ? view->issuer_der : view->subject_der;
    name_size = issuer ? view->issuer_size : view->subject_size;
    if (!name || name_size == 0u ||
        name_size > CRYPTO_X509_DER_MAX_CERT_BYTES)
        return SALTS_ASN1_INVALID_ARGUMENT;
    s = asn1_reader_init(&root_reader, name, name_size, SALTS_ASN1_DER);
    if (s != SALTS_ASN1_OK) return s;
    s = required(&root_reader, &root);
    if (s != SALTS_ASN1_OK) return s;
    if (!tag_is(&root,0u,1u,16u) || root.encoded_size != name_size)
        return SALTS_ASN1_MALFORMED;
    s = asn1_reader_open_children(&root_reader,&root,&rdns);
    if (s != SALTS_ASN1_OK) return s;
    for (;;) {
        s = asn1_reader_next(&rdns,&rdn);
        if (s == SALTS_ASN1_DONE) break;
        if (s != SALTS_ASN1_OK) return s;
        if (!tag_is(&rdn,0u,1u,17u)) return SALTS_ASN1_MALFORMED;
        s = asn1_reader_open_children(&rdns,&rdn,&attributes);
        if (s != SALTS_ASN1_OK) return s;
        if (attributes.size == 0u) return SALTS_ASN1_MALFORMED;
        for (;;) {
            s = asn1_reader_next(&attributes,&attribute);
            if (s == SALTS_ASN1_DONE) break;
            if (s != SALTS_ASN1_OK) return s;
            if (!tag_is(&attribute,0u,1u,16u))
                return SALTS_ASN1_MALFORMED;
            s = asn1_reader_open_children(
                &attributes,&attribute,&fields);
            if (s != SALTS_ASN1_OK) return s;
            s = required(&fields,&oid);
            if (s != SALTS_ASN1_OK) return s;
            if (!tag_is(&oid,0u,0u,6u)) return SALTS_ASN1_MALFORMED;
            s = required(&fields,&value);
            if (s != SALTS_ASN1_OK) return s;
            s = end_of(&fields);
            if (s != SALTS_ASN1_OK) return s;
            if (oid.content_size == sizeof(cn_oid) &&
                memcmp(oid.content,cn_oid,sizeof(cn_oid)) == 0) {
                if (found || value.tag_class != 0u || value.constructed ||
                    !(value.tag_number == 12u || value.tag_number == 19u ||
                      value.tag_number == 22u) ||
                    !value.content_size)
                    return SALTS_ASN1_MALFORMED;
                found = value.content;
                found_size = value.content_size;
            }
        }
    }
    if (!found) return SALTS_ASN1_DONE;
    *out_data = found;
    *out_size = found_size;
    return SALTS_ASN1_OK;
}
