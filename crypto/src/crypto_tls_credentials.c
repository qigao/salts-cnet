#include "crypto_tls_credentials.h"
#include <gmssl/base64.h>
#include <gmssl/mem.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <stdlib.h>
#include <string.h>

static int validate_data(const crypto_tls_data *data, size_t maximum) {
  if (!data || !data->data || !data->size ||
      (data->encoding != CRYPTO_TLS_ENCODING_DER && data->encoding != CRYPTO_TLS_ENCODING_PEM))
    return CRYPTO_TLS_STREAM_EINVAL;
  return data->size > maximum ? CRYPTO_TLS_STREAM_ERANGE : CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_memory_validate(const crypto_tls_data *ca,
    const crypto_tls_credentials *credentials, bool tlcp_server) {
  int status;
  if (ca && (status = validate_data(ca, CRYPTO_TLS_TRUST_INPUT_MAX_BYTES)) != 0) return status;
  if (!credentials) return CRYPTO_TLS_STREAM_OK;
  if (credentials->size != sizeof(*credentials)) return CRYPTO_TLS_STREAM_EINVAL;
  if ((status = validate_data(&credentials->certificate_chain, CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES)) != 0 ||
      (status = validate_data(&credentials->private_key, CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES)) != 0)
    return status;
  if (tlcp_server) return validate_data(&credentials->encryption_key, CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES);
  if (credentials->encryption_key.data || credentials->encryption_key.size || credentials->encryption_key.encoding)
    return CRYPTO_TLS_STREAM_EINVAL;
  return CRYPTO_TLS_STREAM_OK;
}

static bool whitespace(unsigned char ch) {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}
static bool consume(const unsigned char **p, size_t *size, const char *text) {
  size_t n = strlen(text);
  if (*size < n || memcmp(*p, text, n)) return false;
  *p += n; *size -= n;
  return true;
}
static void skip_space(const unsigned char **p, size_t *size) {
  while (*size && whitespace(**p)) { ++*p; --*size; }
}

/* Decode exact PEM objects without FILE streams or implicit NUL termination.
 * Canonical base64 quartets reject misplaced padding and nonzero padding bits. */
static int decode(const crypto_tls_data *input, const char *label, bool multiple,
    unsigned char *out, size_t capacity, size_t *out_size) {
  const unsigned char *p = input->data;
  size_t left = input->size, total = 0u, count = 0u;
  *out_size = 0u;
  if (input->encoding == CRYPTO_TLS_ENCODING_DER) {
    if (left > capacity) return CRYPTO_TLS_STREAM_ERANGE;
    memcpy(out, p, left); *out_size = left; return CRYPTO_TLS_STREAM_OK;
  }
  skip_space(&p, &left);
  while (left) {
    bool padded = false;
    size_t start = total;
    if ((!multiple && count) || !consume(&p, &left, "-----BEGIN ") ||
        !consume(&p, &left, label) || !consume(&p, &left, "-----")) return CRYPTO_TLS_STREAM_EIO;
    for (;;) {
      unsigned char quartet[4], bytes[3], canonical[5];
      size_t n = 3u;
      skip_space(&p, &left);
      if (left && *p == '-') break;
      if (padded) return CRYPTO_TLS_STREAM_EIO;
      for (unsigned i = 0u; i < 4u; ++i) {
        skip_space(&p, &left);
        if (!left) return CRYPTO_TLS_STREAM_EIO;
        quartet[i] = *p++; --left;
      }
      if (quartet[3] == '=') { --n; if (quartet[2] == '=') --n; padded = true; }
      if (base64_decode_block(bytes, quartet, 4) != 3 ||
          base64_encode_block(canonical, bytes, (int)n) != 4 || memcmp(canonical, quartet, 4)) {
        gmssl_secure_clear(bytes, sizeof(bytes));
        return CRYPTO_TLS_STREAM_EIO;
      }
      if (n > capacity - total) { gmssl_secure_clear(bytes, sizeof(bytes)); return CRYPTO_TLS_STREAM_ERANGE; }
      memcpy(out + total, bytes, n); total += n;
      gmssl_secure_clear(bytes, sizeof(bytes));
      gmssl_secure_clear(quartet, sizeof(quartet));
      gmssl_secure_clear(canonical, sizeof(canonical));
    }
    if (multiple) {
      const unsigned char *object = out + start, *cert;
      size_t remaining = total - start, cert_size;
      if (x509_cert_from_der(&cert, &cert_size, &object, &remaining) != 1 || remaining)
        return CRYPTO_TLS_STREAM_EIO;
    }
    if (total == start || !consume(&p, &left, "-----END ") ||
        !consume(&p, &left, label) || !consume(&p, &left, "-----")) return CRYPTO_TLS_STREAM_EIO;
    ++count;
    skip_space(&p, &left);
  }
  if (!count) return CRYPTO_TLS_STREAM_EIO;
  *out_size = total;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_memory_trust(TLS_CTX *tls, const crypto_tls_data *ca) {
  size_t size = 0u;
  unsigned char *der = malloc(ca->size);
  if (!der) return CRYPTO_TLS_STREAM_ENOMEM;
  int status = decode(ca, "CERTIFICATE", true, der, ca->size, &size);
  if (status == 0 && tls_ctx_set_ca_certificates_der(tls, der, size, TLS_DEFAULT_VERIFY_DEPTH) != 1)
    status = CRYPTO_TLS_STREAM_EIO;
  free(der);
  return status;
}

static bool tlcp_roles(const unsigned char *der, size_t size) {
  for (unsigned role = 0u; role < 2u; ++role) {
    const unsigned char *cert, *exts, *usage;
    size_t cert_size, exts_size, usage_size;
    int critical, bits;
    if (x509_cert_from_der(&cert, &cert_size, &der, &size) != 1 ||
        x509_cert_get_exts(cert, cert_size, &exts, &exts_size) != 1 ||
        x509_exts_get_ext_by_oid(exts, exts_size, OID_ce_key_usage, &critical, &usage, &usage_size) != 1 ||
        x509_key_usage_from_der(&bits, &usage, &usage_size) != 1 || usage_size ||
        (role == 0u && (!(bits & X509_KU_DIGITAL_SIGNATURE) || (bits & X509_KU_KEY_ENCIPHERMENT))) ||
        (role == 1u && (!(bits & X509_KU_KEY_ENCIPHERMENT) || (bits & X509_KU_DIGITAL_SIGNATURE)))) return false;
  }
  return true;
}

int crypto_tls_memory_identity(TLS_CTX *tls, const crypto_tls_credentials *credentials) {
  unsigned char certs[CRYPTO_TLS_CERTIFICATE_CHAIN_DER_MAX_BYTES];
  unsigned char key[CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES] = {0};
  unsigned char enc_key[CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES] = {0};
  size_t certs_size = 0u, key_size = 0u, enc_size = 0u;
  int status = decode(&credentials->certificate_chain, "CERTIFICATE", true, certs, sizeof(certs), &certs_size);
  if (status == 0) status = decode(&credentials->private_key, "PRIVATE KEY", false, key, sizeof(key), &key_size);
  if (status == 0 && tls->protocol == TLS_protocol_tlcp) {
    status = decode(&credentials->encryption_key, "PRIVATE KEY", false, enc_key, sizeof(enc_key), &enc_size);
    if (status == 0 && !tlcp_roles(certs, certs_size)) status = CRYPTO_TLS_STREAM_EIO;
  }
  if (status == 0 && tls_ctx_set_certificate_and_keys_der(tls, certs, certs_size, key, key_size,
      enc_size ? enc_key : NULL, enc_size) != 1) status = CRYPTO_TLS_STREAM_EIO;
  gmssl_secure_clear(key, sizeof(key));
  gmssl_secure_clear(enc_key, sizeof(enc_key));
  return status;
}
