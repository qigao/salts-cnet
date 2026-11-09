/* RFC 7292 format composition. Canonical TLV parsing belongs to Salts::ASN1;
 * digest, HMAC, PBES2 and key binding belong to the pinned GmSSL provider. */
#include "crypto_tls_credentials.h"
#include "crypto_internal.h"
#include <asn1.h>
#include <gmssl/hmac.h>
#include <gmssl/mem.h>
#include <gmssl/x509_cer.h>
#include <gmssl/x509_ext.h>
#include <stdlib.h>
#include <string.h>

enum { PFX_CERTS = 16, PFX_KEYS = 2, PFX_SAFES = 8, PFX_BAGS = 32,
       PFX_KDF_BUDGET = 2000000 };
static const unsigned char data_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1};
static const unsigned char encrypted_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,6};
static const unsigned char bag_prefix[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,12,10,1};
static const unsigned char cert_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9,22,1};
static const unsigned char attribute_prefix[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9};
typedef struct pfx_view { const unsigned char *data; size_t size; } pfx_view;
typedef struct pfx_material {
  unsigned char certs[CRYPTO_TLS_CERTIFICATE_CHAIN_DER_MAX_BYTES];
  size_t cert_bytes, cert_count;
  pfx_view certificates[PFX_CERTS];
  unsigned char keys[PFX_KEYS][CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES];
  size_t key_sizes[PFX_KEYS], key_count, bag_count;
  uint32_t work_budget;
} pfx_material;

static int done(const asn1_reader *r) { return r->offset == r->size; }
static int take(asn1_reader *r, unsigned cls, unsigned constructed,
    unsigned tag, asn1_tlv *v) {
  return asn1_reader_next(r, v) == SALTS_ASN1_OK &&
      v->tag_class == cls && v->constructed == constructed && v->tag_number == tag;
}
static int open_value(const asn1_reader *parent, const asn1_tlv *v,
    asn1_reader *child) {
  return asn1_reader_open_children(parent, v, child) == SALTS_ASN1_OK;
}
static int enter(asn1_reader *r, unsigned cls, unsigned tag, asn1_reader *child) {
  asn1_tlv v;
  return take(r, cls, 1u, tag, &v) && open_value(r, &v, child);
}
static int root(const void *data, size_t size, asn1_reader *out) {
  asn1_reader r;
  return asn1_reader_init(&r, data, size, SALTS_ASN1_DER) == SALTS_ASN1_OK &&
      enter(&r, 0u, 16u, out) && done(&r);
}
static int is_oid(const asn1_tlv *v, const void *bytes, size_t size) {
  return v->tag_class == 0u && !v->constructed && v->tag_number == 6u &&
      v->content_size == size && !memcmp(v->content, bytes, size);
}
#define OID(v, name) is_oid(v, name, sizeof(name))
static int number(asn1_reader *r, uint32_t *out) {
  asn1_tlv v;
  if (!take(r, 0u, 0u, 2u, &v) || !v.content_size || v.content_size > 4u || (v.content[0] & 128u)) return 0;
  uint32_t n = 0u;
  for (size_t i = 0u; i < v.content_size; ++i) n = (n << 8) | v.content[i];
  *out = n;
  return 1;
}
static int octets(asn1_reader *r, pfx_view *out) {
  asn1_tlv v;
  if (!take(r, 0u, 0u, 4u, &v)) return 0;
  *out = (pfx_view){v.content, v.content_size};
  return 1;
}

/* PFX integrity uses BMPString+terminator; PBES2 still uses the original UTF-8
 * bytes. Reject invalid UTF-8 and non-BMP code points instead of guessing an
 * alternate password representation. Embedded NUL and empty text are exact. */
static int bmp_password(const crypto_tls_password *password, unsigned char *out, size_t *size) {
  const unsigned char *p = password->data;
  size_t n = 0u;
  for (size_t i = 0u; i < password->size;) {
    uint32_t ch = p[i++];
    if (ch >= 128u) {
      unsigned count;
      uint32_t minimum;
      if (ch >= 0xc2u && ch <= 0xdfu) { count = 1u; minimum = 0x80u; ch &= 31u; }
      else if (ch >= 0xe0u && ch <= 0xefu) { count = 2u; minimum = 0x800u; ch &= 15u; }
      else return 0;
      if (count > password->size - i) return 0;
      for (unsigned j = 0u; j < count; ++j) {
        unsigned b = p[i++];
        if ((b & 0xc0u) != 0x80u) return 0;
        ch = (ch << 6) | (b & 63u);
      }
      if (ch < minimum || (ch >= 0xd800u && ch <= 0xdfffu)) return 0;
    }
    out[n++] = (unsigned char)(ch >> 8); out[n++] = (unsigned char)ch;
  }
  out[n++] = 0u; out[n++] = 0u; *size = n;
  return 1;
}

static const DIGEST *mac_digest(const asn1_tlv *oid) {
  static const unsigned char sm3[] = {0x2a,0x81,0x1c,0xcf,0x55,1,0x83,0x11};
  if (OID(oid, sm3)) return DIGEST_sm3();
  static const unsigned char prefix[] = {0x60,0x86,0x48,1,0x65,3,4,2};
  if (oid->content_size != sizeof(prefix) + 1u || memcmp(oid->content, prefix, sizeof(prefix))) return NULL;
  switch (oid->content[sizeof(prefix)]) {
  case 1u: return DIGEST_sha256();
  case 2u: return DIGEST_sha384();
  case 3u: return DIGEST_sha512();
  case 4u: return DIGEST_sha224();
  case 5u: return DIGEST_sha512_224();
  case 6u: return DIGEST_sha512_256();
  default: return NULL;
  }
}

static int authenticate(asn1_reader *pfx, pfx_view auth,
    const crypto_tls_password *password, uint32_t *budget) {
  asn1_reader mac, info, algorithm;
  asn1_tlv oid, null_value;
  pfx_view expected, salt;
  uint32_t iterations = 1u;
  if (!enter(pfx, 0u, 16u, &mac) || !done(pfx) || !enter(&mac, 0u, 16u, &info) ||
      !enter(&info, 0u, 16u, &algorithm) || !take(&algorithm, 0u, 0u, 6u, &oid)) return CRYPTO_TLS_STREAM_EIO;
  const DIGEST *md = mac_digest(&oid);
  if (!md) return CRYPTO_TLS_STREAM_ENOTSUP;
  if ((!done(&algorithm) && (!take(&algorithm, 0u, 0u, 5u, &null_value) || null_value.content_size)) ||
      !done(&algorithm) || !octets(&info, &expected) || !done(&info) ||
      !octets(&mac, &salt) || (!done(&mac) && !number(&mac, &iterations)) || !done(&mac)) return CRYPTO_TLS_STREAM_EIO;
  if (iterations < CRYPTO_TLS_PKCS8_MIN_ITERATIONS || iterations > CRYPTO_TLS_PKCS8_MAX_ITERATIONS ||
      salt.size < 8u || salt.size > 64u || expected.size != md->digest_size) return CRYPTO_TLS_STREAM_EIO;
  if (iterations > *budget) return CRYPTO_TLS_STREAM_ERANGE;
  *budget -= iterations;
  unsigned char bmp[CRYPTO_TLS_PASSWORD_MAX_BYTES * 2u + 2u] = {0};
  unsigned char block[DIGEST_MAX_BLOCK_SIZE], key[DIGEST_MAX_SIZE] = {0}, actual[DIGEST_MAX_SIZE] = {0};
  DIGEST_CTX hash = {0};
  size_t bmp_size = 0u, n = 0u;
  int status = CRYPTO_TLS_STREAM_EIO;
  if (!bmp_password(password, bmp, &bmp_size)) { status = CRYPTO_TLS_STREAM_EINVAL; goto end; }
  /* A MAC key has exactly one digest of output: RFC 7292 B.2's block
   * adjustment is needed only before a second output block, never here. */
  memset(block, 3, md->block_size);
  if (digest_init(&hash, md) != 1 || digest_update(&hash, block, md->block_size) != 1) goto end;
  for (size_t i = 0u; i < md->block_size; ++i) block[i] = salt.data[i % salt.size];
  if (digest_update(&hash, block, md->block_size) != 1) goto end;
  const size_t repeated = ((bmp_size + md->block_size - 1u) / md->block_size) * md->block_size;
  for (size_t offset = 0u; offset < repeated; offset += md->block_size) {
    for (size_t i = 0u; i < md->block_size; ++i) block[i] = bmp[(offset + i) % bmp_size];
    if (digest_update(&hash, block, md->block_size) != 1) goto end;
  }
  if (digest_finish(&hash, key, &n) != 1 || n != md->digest_size) goto end;
  for (uint32_t i = 1u; i < iterations; ++i)
    if (digest_init(&hash, md) != 1 || digest_update(&hash, key, n) != 1 ||
        digest_finish(&hash, key, &n) != 1 || n != md->digest_size) goto end;
  if (hmac(md, key, n, auth.data, auth.size, actual, &n) != 1 || n != expected.size) goto end;
  if (gmssl_secure_memcmp(actual, expected.data, n) == 0) status = CRYPTO_TLS_STREAM_OK;
end:
  gmssl_secure_clear(bmp, sizeof(bmp)); gmssl_secure_clear(block, sizeof(block));
  gmssl_secure_clear(key, sizeof(key)); gmssl_secure_clear(actual, sizeof(actual));
  gmssl_secure_clear(&hash, sizeof(hash));
  return status;
}

/* Attributes are metadata, never authority for key binding. Admit only the two
 * standard bounded attributes; reject duplicates and unsupported attributes. */
static int attributes(asn1_reader *bag) {
  if (done(bag)) return 1;
  asn1_reader set, attribute, values;
  asn1_tlv oid, value;
  unsigned seen = 0u;
  if (!enter(bag, 0u, 17u, &set) || !done(bag) || done(&set)) return 0;
  while (!done(&set)) {
    if (!enter(&set, 0u, 16u, &attribute) || !take(&attribute, 0u, 0u, 6u, &oid) ||
        oid.content_size != sizeof(attribute_prefix) + 1u ||
        memcmp(oid.content, attribute_prefix, sizeof(attribute_prefix))) return 0;
    unsigned type = oid.content[sizeof(attribute_prefix)];
    unsigned bit = type == 20u ? 1u : type == 21u ? 2u : 0u;
    if (!bit || (seen & bit) || !enter(&attribute, 0u, 17u, &values) || !done(&attribute) ||
        !take(&values, 0u, 0u, type == 20u ? 30u : 4u, &value) || !done(&values) ||
        !value.content_size || value.content_size > 1024u) return 0;
    seen |= bit;
  }
  return 1;
}

static int safe_contents(pfx_material *m, pfx_view safe, const crypto_tls_password *password) {
  asn1_reader contents, bag, value, cert;
  asn1_tlv oid, raw;
  if (!root(safe.data, safe.size, &contents)) return CRYPTO_TLS_STREAM_EIO;
  while (!done(&contents)) {
    if (++m->bag_count > PFX_BAGS) return CRYPTO_TLS_STREAM_ERANGE;
    if (!enter(&contents, 0u, 16u, &bag) || !take(&bag, 0u, 0u, 6u, &oid) ||
        !enter(&bag, 2u, 0u, &value)) return CRYPTO_TLS_STREAM_EIO;
    if (oid.content_size != sizeof(bag_prefix) + 1u || memcmp(oid.content, bag_prefix, sizeof(bag_prefix)))
      return CRYPTO_TLS_STREAM_ENOTSUP;
    unsigned type = oid.content[sizeof(bag_prefix)];
    if (type == 1u || type == 2u) {
      if (m->key_count == PFX_KEYS) return CRYPTO_TLS_STREAM_ERANGE;
      const size_t start = value.offset;
      if (!take(&value, 0u, 1u, 16u, &raw) || !done(&value)) return CRYPTO_TLS_STREAM_EIO;
      crypto_tls_data input = {value.data + start, raw.encoded_size, CRYPTO_TLS_ENCODING_DER};
      const crypto_tls_password plain = {0};
      int status = crypto_tls_memory_decode_key(&input, type == 2u ? password : &plain,
          m->keys[m->key_count], sizeof(m->keys[0]), &m->key_sizes[m->key_count], &m->work_budget);
      if (status != 0) return status;
      ++m->key_count;
    } else if (type == 3u) {
      pfx_view bytes;
      if (!enter(&value, 0u, 16u, &cert) || !done(&value) || !take(&cert, 0u, 0u, 6u, &oid) ||
          !OID(&oid, cert_oid) || !enter(&cert, 2u, 0u, &value) || !done(&cert) ||
          !octets(&value, &bytes) || !done(&value) || !bytes.size ||
          asn1_validate(bytes.data, bytes.size, SALTS_ASN1_DER) != SALTS_ASN1_OK) return CRYPTO_TLS_STREAM_EIO;
      if (m->cert_count == PFX_CERTS || bytes.size > sizeof(m->certs) - m->cert_bytes) return CRYPTO_TLS_STREAM_ERANGE;
      for (size_t i = 0u; i < m->cert_count; ++i)
        if (m->certificates[i].size == bytes.size && !memcmp(m->certificates[i].data, bytes.data, bytes.size))
          return CRYPTO_TLS_STREAM_EIO;
      unsigned char *to = m->certs + m->cert_bytes;
      memcpy(to, bytes.data, bytes.size); m->cert_bytes += bytes.size;
      m->certificates[m->cert_count++] = (pfx_view){to, bytes.size};
    } else return CRYPTO_TLS_STREAM_ENOTSUP;
    if (!attributes(&bag)) return CRYPTO_TLS_STREAM_EIO;
  }
  return CRYPTO_TLS_STREAM_OK;
}

static int authenticated_safe(pfx_material *m, pfx_view auth, const crypto_tls_password *password) {
  asn1_reader safes, info, content, encrypted, info_data;
  asn1_tlv oid, algorithm, ciphertext;
  unsigned char *plain = NULL;
  int status = CRYPTO_TLS_STREAM_EIO;
  size_t safe_count = 0u;
  if (!root(auth.data, auth.size, &safes)) return status;
  while (!done(&safes)) {
    if (++safe_count > PFX_SAFES) { status = CRYPTO_TLS_STREAM_ERANGE; goto end; }
    if (!enter(&safes, 0u, 16u, &info) || !take(&info, 0u, 0u, 6u, &oid) ||
        !enter(&info, 2u, 0u, &content) || !done(&info)) goto malformed;
    pfx_view bytes;
    if (OID(&oid, data_oid)) {
      if (!octets(&content, &bytes) || !done(&content)) goto malformed;
      status = safe_contents(m, bytes, password);
    } else if (OID(&oid, encrypted_oid)) {
      uint32_t version;
      if (!enter(&content, 0u, 16u, &encrypted) || !done(&content) ||
          !number(&encrypted, &version) || version != 0u || !enter(&encrypted, 0u, 16u, &info_data) || !done(&encrypted) ||
          !take(&info_data, 0u, 0u, 6u, &oid) || !OID(&oid, data_oid)) goto malformed;
      size_t algorithm_start = info_data.offset;
      if (!take(&info_data, 0u, 1u, 16u, &algorithm) || !take(&info_data, 2u, 0u, 0u, &ciphertext) ||
          !done(&info_data) || !ciphertext.content_size) goto malformed;
      if (!plain) { plain = malloc(CRYPTO_TLS_PKCS12_MAX_BYTES); if (!plain) { status = CRYPTO_TLS_STREAM_ENOMEM; goto end; } }
      size_t plain_size = 0u;
      status = crypto_tls_pbes2_decrypt(info_data.data + algorithm_start, algorithm.encoded_size,
          ciphertext.content, ciphertext.content_size, password, plain, CRYPTO_TLS_PKCS12_MAX_BYTES, &plain_size, &m->work_budget);
      if (status == 0) status = safe_contents(m, (pfx_view){plain, plain_size}, password);
      gmssl_secure_clear(plain, CRYPTO_TLS_PKCS12_MAX_BYTES);
    } else { status = CRYPTO_TLS_STREAM_ENOTSUP; goto end; }
    if (status != 0) goto end;
  }
  status = safe_count ? CRYPTO_TLS_STREAM_OK : CRYPTO_TLS_STREAM_EIO;
  goto end;
malformed:
  status = CRYPTO_TLS_STREAM_EIO;
end:
  if (plain) { gmssl_secure_clear(plain, CRYPTO_TLS_PKCS12_MAX_BYTES); free(plain); }
  return status;
}

static int bound_key(const unsigned char *der, size_t size, const X509_KEY *pub) {
  X509_KEY key = {0};
  const unsigned char *attrs;
  size_t attrs_size;
  int ok;
  if (pub->algor == OID_rsa_encryption) {
    ok = rsa_private_key_info_from_der(&key.rsa_private_key, &attrs, &attrs_size, &der, &size);
    key.algor = OID_rsa_encryption; key.algor_param = OID_undef;
    key.u.rsa_public_key = key.rsa_private_key.public_key; key.has_private_key = 1;
  } else ok = x509_private_key_info_from_der(&key, &attrs, &attrs_size, &der, &size);
  ok = ok == 1 && !size && !attrs_size && x509_public_key_equ(&key, pub) == 1;
  x509_key_cleanup(&key); gmssl_secure_clear(&key, sizeof(key));
  return ok;
}

/* PFX is an identity container, not a trust store. Produce one unambiguous
 * leaf-first chain; reject extras/cross-sign ambiguity rather than selecting a
 * trust path here. Peer trust/path building has its own authority. */
static int publish(pfx_material *m, crypto_tls_credential_kind kind, crypto_tls_credential_object **out) {
  const size_t leaves = kind == CRYPTO_TLS_CREDENTIAL_TLCP_SERVER ? 2u : 1u;
  if (m->key_count != leaves || m->cert_count < leaves) return CRYPTO_TLS_STREAM_EIO;
  size_t selected[PFX_KEYS] = {0}, keys[PFX_KEYS] = {0,1};
  bool used[PFX_CERTS] = {false};
  for (size_t k = 0u; k < leaves; ++k) {
    size_t matches = 0u;
    for (size_t c = 0u; c < m->cert_count; ++c) {
      X509_KEY pub = {0};
      if (x509_cert_get_subject_public_key(m->certificates[c].data, m->certificates[c].size, &pub) != 1)
        return CRYPTO_TLS_STREAM_EIO;
      int equal = bound_key(m->keys[k], m->key_sizes[k], &pub);
      x509_key_cleanup(&pub);
      if (equal) { ++matches; selected[k] = c; }
    }
    if (matches != 1u || used[selected[k]]) return CRYPTO_TLS_STREAM_EIO;
    used[selected[k]] = true;
  }
  if (leaves == 2u) {
    const unsigned char *extensions, *value;
    size_t extensions_size, value_size;
    int critical, bits;
    pfx_view first = m->certificates[selected[0]];
    if (x509_cert_get_exts(first.data, first.size, &extensions, &extensions_size) != 1 ||
        x509_exts_get_ext_by_oid(extensions, extensions_size, OID_ce_key_usage, &critical, &value, &value_size) != 1 ||
        x509_key_usage_from_der(&bits, &value, &value_size) != 1 || value_size) return CRYPTO_TLS_STREAM_EIO;
    if (bits & X509_KU_KEY_ENCIPHERMENT) {
      size_t swap = selected[0]; selected[0] = selected[1]; selected[1] = swap;
      keys[0] = 1u; keys[1] = 0u;
    }
  }
  unsigned char chain[CRYPTO_TLS_CERTIFICATE_CHAIN_DER_MAX_BYTES];
  size_t chain_size = 0u, appended = leaves;
  for (size_t i = 0u; i < leaves; ++i) {
    pfx_view v = m->certificates[selected[i]];
    memcpy(chain + chain_size, v.data, v.size); chain_size += v.size;
  }
  size_t last = selected[0];
  while (appended < m->cert_count) {
    const unsigned char *issuer, *subject;
    size_t issuer_size, subject_size, next = 0u, matches = 0u;
    pfx_view previous = m->certificates[last];
    if (x509_cert_get_issuer(previous.data, previous.size, &issuer, &issuer_size) != 1) return CRYPTO_TLS_STREAM_EIO;
    for (size_t i = 0u; i < m->cert_count; ++i) if (!used[i]) {
      pfx_view candidate = m->certificates[i];
      if (x509_cert_get_subject(candidate.data, candidate.size, &subject, &subject_size) != 1) return CRYPTO_TLS_STREAM_EIO;
      if (issuer_size == subject_size && !memcmp(issuer, subject, issuer_size) &&
          x509_cert_verify_by_ca_cert(previous.data, previous.size, candidate.data, candidate.size,
              SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) == 1) { next = i; ++matches; }
    }
    if (matches != 1u) return CRYPTO_TLS_STREAM_EIO;
    pfx_view v = m->certificates[next];
    if (leaves == 2u && appended == leaves) {
      pfx_view encryption = m->certificates[selected[1]];
      if (x509_cert_verify_by_ca_cert(encryption.data, encryption.size, v.data, v.size,
          SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) return CRYPTO_TLS_STREAM_EIO;
    }
    memcpy(chain + chain_size, v.data, v.size); chain_size += v.size;
    used[next] = true; last = next; ++appended;
  }
  crypto_tls_credentials identity = {.size = sizeof(identity),
      .certificate_chain = {chain, chain_size, CRYPTO_TLS_ENCODING_DER},
      .private_key = {m->keys[keys[0]], m->key_sizes[keys[0]], CRYPTO_TLS_ENCODING_DER}};
  if (leaves == 2u) identity.encryption_key = (crypto_tls_data){m->keys[keys[1]], m->key_sizes[keys[1]], CRYPTO_TLS_ENCODING_DER};
  return crypto_tls_credential_object_create(&identity, kind, out);
}

int crypto_tls_credential_object_from_pkcs12(const crypto_tls_data *input,
    const crypto_tls_password *password, crypto_tls_credential_kind kind,
    crypto_tls_credential_object **out) {
  if (!out) return CRYPTO_TLS_STREAM_EINVAL;
  if ((input && (salts_crypto_overlap(out,sizeof(*out),input,sizeof(*input)) ||
                 salts_crypto_overlap(out,sizeof(*out),input->data,input->size))) ||
      (password && (salts_crypto_overlap(out,sizeof(*out),password,sizeof(*password)) ||
                    salts_crypto_overlap(out,sizeof(*out),password->data,password->size))))
    return CRYPTO_TLS_STREAM_EINVAL;
  *out = NULL;
  if (!input || !input->data || !input->size || input->encoding != CRYPTO_TLS_ENCODING_DER ||
      !password || !password->data ||
      (kind != CRYPTO_TLS_CREDENTIAL_SINGLE && kind != CRYPTO_TLS_CREDENTIAL_TLCP_SERVER)) return CRYPTO_TLS_STREAM_EINVAL;
  if (input->size > CRYPTO_TLS_PKCS12_MAX_BYTES || password->size > CRYPTO_TLS_PASSWORD_MAX_BYTES) return CRYPTO_TLS_STREAM_ERANGE;
  asn1_reader pfx, info, content;
  asn1_tlv oid;
  pfx_view auth;
  uint32_t version;
  if (!root(input->data, input->size, &pfx) || !number(&pfx, &version) || version != 3u ||
      !enter(&pfx, 0u, 16u, &info) || !take(&info, 0u, 0u, 6u, &oid) || !OID(&oid, data_oid) ||
      !enter(&info, 2u, 0u, &content) || !done(&info) || !octets(&content, &auth) || !done(&content))
    return CRYPTO_TLS_STREAM_EIO;
  uint32_t budget = PFX_KDF_BUDGET;
  int status = authenticate(&pfx, auth, password, &budget);
  if (status != 0) return status;
  pfx_material *m = calloc(1u, sizeof(*m));
  if (!m) return CRYPTO_TLS_STREAM_ENOMEM;
  m->work_budget = budget;
  status = authenticated_safe(m, auth, password);
  if (status == 0) status = publish(m, kind, out);
  gmssl_secure_clear(m, sizeof(*m)); free(m);
  return status;
}
